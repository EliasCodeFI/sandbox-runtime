//! Cross-broker state DB for `srt-win acl` — refcount additive
//! sandbox-user ACEs (grant ALLOW / stamp DENY) so the LAST broker
//! to release a path can drop the ACE.
//!
//! TWO stores, split by scope and by writer:
//!
//! - SESSION store (`%LOCALAPPDATA%\sandbox-runtime\state.db`,
//!   per-user): brokers / ace_holders / working_aces. These rows
//!   DRIVE ACL mutations on the owning user's files, so they are
//!   only trustworthy while only that user (and admins) can write
//!   them — the directory is stamped real-user-only on every open.
//! - MACHINE state (`HKLM\SOFTWARE\sandbox-runtime` — see
//!   `crate::reg` — plus the `ca\` key material under
//!   `%ProgramData%\sandbox-runtime`): install-owned, admin-written,
//!   read unprivileged. Not this module's concern beyond
//!   [`machine_store_dir`] and the recompose ambient fold-in.
//!
//! ## Disk-is-truth invariant
//!
//! A row is a refcount edge + `file_id` identity check. It NEVER
//! asserts on-disk state. Every add/drop/crash-recover routes
//! through [`recompose_at`], which reads the live `working_aces`
//! rows for the path and converges the on-disk ACEs for the
//! sandbox SID to exactly that set (walk-and-filter, no PROTECTED
//! rewrite, no SD snapshot). A poisoned row therefore degrades to
//! "sandbox user has an extra ACE the user can manually remove",
//! never to attacker-chosen permissions on the user's own files.
//!
//! ## Locking and crash safety
//!
//! Every `acl stamp|grant|restore|revoke|recover` runs under an
//! exclusive file lock on `.acl-init.lock` in the per-user session
//! dir (see `InitMutex::acquire` for why a file lock and not a
//! named mutex). The lock — NOT a DB transaction — serializes
//! whole operations across the user's brokers; the kernel drops it
//! when a holder dies, and crash-recovery runs unconditionally at
//! every acquire.
//!
//! There is deliberately NO single enclosing transaction. Each
//! path's (FS mutation + row change) commits independently so a
//! failure on path Y can't revert path X. The one ordering rule is
//! record-first: upsert, THEN `SetNamedSecurityInfoW`. A crash
//! between leaves a row whose ACE hasn't been written; the next
//! call re-derives and reapplies.
//!
//! ## One converge per path per batch
//!
//! `SetNamedSecurityInfoW` on a directory re-propagates to every
//! unprotected descendant, so a converge of a granted project root
//! costs a walk of the whole tree. One batch routinely touches the
//! same path several times — every deny target adds a `deny_fdc`
//! row on its parent, a placeholder directory carries both
//! `deny_delete` and `deny_fdc` — so the batch loops
//! ([`Locked::apply_aces`], [`Locked::release_aces`], crash
//! recovery) run every per-row step exactly as before (capture,
//! guards, identity gate, row writes) and defer only the
//! [`recompose_at`] to the path's LAST touch in the batch
//! ([`last_touches`]). `recompose_at` reads the rows as they then
//! stand, so the one write lands the same DACL the last of the
//! repeated writes used to; the skipped ones were intermediate
//! states holding a subset of those rows. Record-first is
//! unaffected: a row still always precedes its write, only by more.
//!
//! The converge itself skips the write when the path's DACL is
//! already the composed one AND `converged_dacls` records that our
//! last write of exactly that DACL ran to completion
//! ([`ConvergedLedger`]). That table is the one place a row vouches
//! for disk state, and only ever toward LESS trust: it can veto a
//! skip the live DACL comparison would allow, never grant one the
//! comparison refuses, and a missing, stale or unreadable row means
//! "write".
//!
//! ## Write-intent journal
//!
//! Record-first covers a killed APPLY: the row outlives the unwritten
//! ACE. A killed RELEASE is the mirror case and rows cannot cover it:
//! release drops its `working_aces` row first and walks the tree
//! second, so a broker killed mid-propagation (the caller's timeout
//! on a large tree) leaves descendants still carrying the inherited
//! sandbox ACE with no row anywhere for recovery to find — an ALLOW
//! the next session never revokes. So every real DACL write is
//! bracketed by a `write_intents` row ([`record_write_intent`] before
//! the write, [`clear_write_intent`] once it has returned), and crash
//! recovery re-runs the converge — forced, from the rows as they now
//! stand — for each intent that survived ([`recover_write_intents`]).
//! The journal adds a breadcrumb around the propagation only; no
//! existing ordering changes.

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::{FILETIME, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    WaitForSingleObject,
};

use crate::acl::{self, SbAce};
use crate::path_id::{self, FileId};

/// Holder PID — the LONG-LIVED process that owns a set of stamps
/// (the Node host in production), NOT the ephemeral `srt-win acl`
/// CLI process. Newtype to avoid confusing it with arbitrary PIDs
/// at call sites; the SQLite `brokers.pid` column stores the bare
/// `u32`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HolderPid(pub u32);

impl std::str::FromStr for HolderPid {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u32>().map(HolderPid)
    }
}

/// Per-user session DB (brokers / ace_holders / working_aces).
const SESSION_SCHEMA_VERSION: i64 = 8;

const SESSION_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS brokers (
  pid                 INTEGER PRIMARY KEY,
  process_create_time INTEGER NOT NULL,
  started_at          INTEGER NOT NULL
);
-- Additive explicit ACEs for the sandbox user. kind ∈
-- {'grant','deny','deny_fdc'}: `acl grant` writes ALLOW rows,
-- `acl stamp` writes DENY rows on the target plus a `deny_fdc`
-- row on the parent. Stores no original_sd — restore is a
-- walk-and-filter that drops the SID's ACEs, not a full-SD
-- restore. One row per (path, kind); a path may carry one grant
-- AND one deny (the recompose chokepoint applies both).
-- Refcounted via ace_holders.
CREATE TABLE IF NOT EXISTS working_aces (
  canonical_path TEXT NOT NULL,
  kind           TEXT NOT NULL,
  file_id        BLOB NOT NULL,
  -- The effective mask currently on disk: the MAX across live
  -- holders' want_mask (recomputed on every holder add/drop).
  mask           TEXT NOT NULL,
  PRIMARY KEY (canonical_path, kind)
);
CREATE TABLE IF NOT EXISTS ace_holders (
  canonical_path TEXT    NOT NULL,
  kind           TEXT    NOT NULL,
  pid            INTEGER NOT NULL REFERENCES brokers(pid) ON DELETE CASCADE,
  -- THIS holder's requested mask. The on-disk ACE is the MAX
  -- across live holders; release recomputes it so a holder that
  -- escalated the mask doesn't leave it escalated past its exit.
  want_mask      TEXT    NOT NULL,
  PRIMARY KEY (canonical_path, kind, pid)
);
CREATE INDEX IF NOT EXISTS ace_holders_by_pid ON ace_holders (pid);
-- Filesystem objects `acl stamp` created (empty file at a
-- non-existent deny target + any missing intermediate dirs) so a
-- Deny ACE could be stamped on the exact path. Placeholders are
-- PERMANENT once created (leave-in-place — never deleted by
-- restore/recover, so a user who wrote into one cannot lose data).
-- The record exists so a LATER holder denying the same or a
-- descendant path can discover and hold the full ancestor chain
-- (`Locked::placeholder_ancestors_of`) — otherwise releasing the
-- creating holder would strip intermediates the later holder
-- depends on.
CREATE TABLE IF NOT EXISTS placeholders (
  canonical_path TEXT PRIMARY KEY
);
-- Completion record for the converge's write-skip: the DACL
-- (`acl::dacl_fingerprint`) our last COMPLETED write left on the
-- object `file_id` at this path. Deleted before every write and
-- re-inserted only after it returns, so a write killed
-- mid-propagation leaves no row and the next converge rewrites
-- (re-propagates) instead of trusting a half-walked subtree. Only
-- kept while the path carries sandbox ACEs. Additive (`IF NOT
-- EXISTS`, no schema-version bump): a binary without it neither
-- reads nor needs it.
CREATE TABLE IF NOT EXISTS converged_dacls (
  canonical_path TEXT PRIMARY KEY,
  file_id        BLOB NOT NULL,
  dacl           BLOB NOT NULL
);
-- Write-intent journal: a DACL write on the object `file_id` at this
-- path was started and has not been seen to return. Inserted before
-- every real `SetNamedSecurityInfoW` of a converge, deleted after it
-- succeeds; a surviving row is a propagation that may have been cut
-- short, which crash recovery re-runs from the then-current rows.
-- Keyed by (path, object) so a write on a substituted path cannot
-- overwrite the breadcrumb for the object that was there before.
-- Additive (`IF NOT EXISTS`, no schema-version bump).
CREATE TABLE IF NOT EXISTS write_intents (
  canonical_path TEXT NOT NULL,
  file_id        BLOB NOT NULL,
  PRIMARY KEY (canonical_path, file_id)
);
"#;

/// Outcome of a crash-recovery pass.
#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub dead_brokers: u32,
    /// Orphaned `working_aces` rows whose ACE was revoked.
    pub aces_revoked: u32,
    /// Interrupted DACL writes (`write_intents` rows) whose converge
    /// was re-run to completion.
    pub writes_resumed: u32,
    /// `write_intents` rows still present after this pass (converge
    /// failed or path unreadable — retried by the next pass).
    pub writes_pending: u32,
}

/// RAII guard for the init lock — an exclusive `LockFileEx` range
/// lock on `.acl-init.lock` inside the per-user session dir.
///
/// A FILE lock, not a named mutex, on purpose: the sandbox child
/// shares the broker's Terminal-Services session, and Windows named
/// objects are first-come — a child could CREATE the well-known
/// name before the broker and sit on it (create-first squatting
/// bypasses any DACL we would put on our own object; confirmed
/// empirically — a sandboxed `New-Object Threading.Mutex` held the
/// old `Local\` name and stalled the owner's acl ops for the full
/// timeout). The lock file lives in the session dir, whose DACL
/// excludes the sandbox child, so there is nothing for it to squat;
/// and the kernel releases file locks when the holder dies, which
/// also retires the abandoned-mutex special case (crash recovery
/// runs at every acquire regardless).
struct InitMutex {
    file: std::fs::File,
}
impl Drop for InitMutex {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Storage::FileSystem::UnlockFile;
        unsafe {
            let _ = UnlockFile(HANDLE(self.file.as_raw_handle()), 0, 0, 1, 0);
        }
    }
}

impl InitMutex {
    fn acquire() -> Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Storage::FileSystem::{
            LOCK_FILE_FLAGS, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
        };
        use windows::Win32::System::IO::OVERLAPPED;
        let dir = session_store_dir()?;
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create_dir_all {}", dir.display()))?;
        let path = dir.join(".acl-init.lock");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Never truncate: the file's only role is carrying the
            // kernel byte-range lock; its content is irrelevant.
            .truncate(false)
            .open(&path)
            .with_context(|| format!("open init-lock file {}", path.display()))?;
        // Bounded, not infinite: crash-recovery under this lock is
        // sub-second and real contention is a handful of concurrent
        // acl ops for ONE user, so a minute means a wedged holder —
        // fail the op loudly rather than hang.
        const ACQUIRE_TIMEOUT_MS: u64 = 60_000;
        const POLL_MS: u64 = 100;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(ACQUIRE_TIMEOUT_MS);
        loop {
            let mut ov = OVERLAPPED::default();
            let r = unsafe {
                LockFileEx(
                    HANDLE(file.as_raw_handle()),
                    LOCK_FILE_FLAGS(LOCKFILE_EXCLUSIVE_LOCK.0 | LOCKFILE_FAIL_IMMEDIATELY.0),
                    None,
                    1,
                    0,
                    &mut ov,
                )
            };
            if r.is_ok() {
                return Ok(Self { file });
            }
            if std::time::Instant::now() >= deadline {
                bail!(
                    "init lock {} not acquired within {ACQUIRE_TIMEOUT_MS}ms — \
                     another srt-win/broker is holding it (wedged?)",
                    path.display(),
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(POLL_MS));
        }
    }
}

/// The one seam through which install-time flows (ambient deny
/// stamping/clearing) serialize against this user's brokers —
/// acquire the session init lock without opening the session DB.
pub fn acquire_session_lock() -> Result<impl Drop> {
    InitMutex::acquire()
}

/// Open (creating if needed) the per-user SESSION DB. Stamps the
/// parent directory real-user-only on EVERY open — the session
/// store is the pre-split `%LOCALAPPDATA%` model: rows here are
/// TRUSTED because only the owning user (and admins) can write
/// them, which is exactly why session bookkeeping must not live in
/// the Users-writable machine store.
pub fn open_db() -> Result<Connection> {
    let dir = session_store_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("create_dir_all {}", dir.display()))?;
    // Stamp the directory `(OI)(CI)` real-user-only so the sandbox
    // child cannot tamper with state.db / -wal / -shm. Done on
    // EVERY open, not just first creation: defense-in-depth — the
    // child runs as a different user, but a working-tree grant
    // could otherwise expose this directory if it lives under a
    // granted root. `SetNamedSecurityInfoW` is
    // idempotent, so re-stamping an already-correct dir is a no-op.
    // Best-effort: if it fails we proceed (the `%LOCALAPPDATA%`
    // default DACL already excludes the separate `srt-sandbox`
    // user; the explicit stamp + sandbox-users DENY below is
    // belt-and-braces against a working-tree ALLOW grant covering
    // this directory) and warn so the test harness can assert. We
    // own this directory, so a user-applied custom DACL on it is
    // NOT preserved — it is rewritten on every open by design.
    let dir_str = dir.to_str().ok_or_else(|| {
        anyhow!(
            "state-DB directory path '{}' is not representable as \
             UTF-8 (contains unpaired surrogates); not supported",
            dir.display()
        )
    })?;
    // Include the sandbox-users DENY when the install has
    // provisioned that group. The credential file in this
    // directory is machine-scope DPAPI — readable-by-sandbox =
    // decryptable-by-sandbox — so the DENY is load-bearing once
    // the separate-user runner exists. The lookup distinguishes
    // "group genuinely absent" (install never run / older install
    // → DENY skipped, broker-only allow set still excludes the
    // sandbox user) from a transient SAM/LSA failure — the latter
    // is surfaced rather than silently dropping a security ACE.
    let deny_sid = match crate::sid::lookup_account_sid(crate::user::SANDBOX_GROUP) {
        Ok(s) => Some(s),
        Err(e) => {
            match crate::sid::sid_account_exists("S-1-5-32-545") {
                // BUILTIN\Users always maps; if it does, SAM is up
                // and the sandbox group is genuinely absent.
                Ok(crate::sid::SidExistence::Mapped) => None,
                _ => {
                    eprintln!(
                        "srt-win: WARNING: cannot resolve \
                         '{}' to add the state-dir DENY ACE \
                         ({e:#}); the broker-only allow set \
                         still excludes the sandbox user, but \
                         the explicit DENY is omitted for this \
                         stamp",
                        crate::user::SANDBOX_GROUP,
                    );
                    None
                }
            }
        }
    };
    if let Err(e) = acl::stamp_dir_inheriting(dir_str, deny_sid.as_deref()) {
        eprintln!(
            "srt-win: WARNING: failed to stamp state-DB dir {} \
             broker-only: {e:#}",
            dir.display()
        );
    }
    open_db_at(
        &dir.join("state.db"),
        SESSION_SCHEMA_SQL,
        SESSION_SCHEMA_VERSION,
    )
}

/// Filter on `release_aces` for the deny-ACE lifecycle.
pub const KIND_DENY: &[&str] = &["deny", "deny_fdc", "deny_delete"];
/// Filter on `release_aces` for the grant lifecycle.
pub const KIND_GRANT: &[&str] = &["grant"];

/// `prepare → query_map → collect` with one error context. Shared
/// by every "list of T from one query" site so error plumbing is
/// edited once.
fn query_vec<T, P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    p: P,
    row: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let mut s = conn
        .prepare(sql)
        .with_context(|| format!("prepare: {sql}"))?;
    let it = s
        .query_map(p, row)
        .with_context(|| format!("query: {sql}"))?;
    let mut v = Vec::new();
    for r in it {
        v.push(r.with_context(|| format!("row: {sql}"))?);
    }
    Ok(v)
}

/// Read-only open of the per-user SESSION DB. Returns `None` if it
/// doesn't exist yet. No mutex, no `create_dir_all`, no dir-stamp,
/// no schema apply.
pub fn open_db_ro() -> Result<Option<Connection>> {
    open_ro_at(&session_store_dir()?.join("state.db"))
}

fn open_ro_at(path: &std::path::Path) -> Result<Option<Connection>> {
    let schema_version = SESSION_SCHEMA_VERSION;
    let path = path.to_path_buf();
    // Degrade, don't fail: a garbage/unreadable session DB must read
    // as "nothing recorded" — an Err here would propagate through
    // crash_recovery into every acl op for this user. The RW open
    // path renames a corrupt file away and recreates it.
    match path.try_exists() {
        Ok(false) => return Ok(None),
        Ok(true) => {}
        Err(e) => bail!(
            "cannot determine state-DB presence at {}: {e}",
            path.display()
        ),
    }
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("sqlite open RO {}", path.display()))?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    // Schema-mismatch chokepoint: a v≠SCHEMA_VERSION DB is from an
    // older install whose `sandbox_user` row is stranded. Reading
    // it would surface a stale credential. Return None so
    // `srt-win user status` reports `provisioned=false` and the TS
    // dependency-check tells the user to re-run `srt-win install`
    // (which routes through `open_db_at()` → renames the stale DB
    // to `.bak` and creates fresh) at the start of the session,
    // not mid-exec. Also covers a DB
    // with no schema at all (`open_db_at` crashed between
    // `Connection::open` and `execute_batch(SCHEMA_SQL)`): ver==0
    // and there's no `sandbox_user` row, so "not provisioned yet"
    // is the right answer.
    let ver: i64 = match conn.query_row("PRAGMA user_version", [], |r| r.get(0)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "srt-win: state DB at {} is unreadable ({e}); treating \
                 as not provisioned. Re-run `srt-win install` to \
                 recreate it.",
                path.display(),
            );
            return Ok(None);
        }
    };
    if ver != schema_version {
        if ver != 0 {
            eprintln!(
                "srt-win: state DB at {} is at schema v{ver} \
                 (expected v{schema_version}); treating as not \
                 provisioned. Re-run `srt-win install` to migrate.",
                path.display(),
            );
        }
        return Ok(None);
    }
    Ok(Some(conn))
}

/// Open at an arbitrary path with the given schema + version.
/// Tests use `:memory:`.
pub(crate) fn open_db_at(
    path: &std::path::Path,
    schema_sql: &str,
    schema_version: i64,
) -> Result<Connection> {
    // Schema mismatch → rename + recreate. No ALTER/DROP migration:
    // the old DB is preserved (debugging/recovery) at
    // state.db.v<old>.<ts>.bak alongside `path`, and a fresh DB is
    // created at the expected schema. The next recovery converges
    // from the fresh (empty) rows. A PRE-SPLIT per-user DB carried
    // the DPAPI cred blob in its `sandbox_user` row (machine-scope:
    // readable = decryptable), so the blob is scrubbed from the
    // .bak below before anything else can read it. The .bak keeps
    // its directory's DACL (real-user-only stamp); no per-file
    // stamp.
    if path.exists() {
        let probe = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY);
        if let Ok(c) = probe {
            // A garbage (non-SQLite) file fails the pragma — mark it
            // ver -1 so it takes the rename-away path below instead
            // of reaching the schema apply (which would hard-error
            // forever on a file any local user can plant).
            let ver: i64 = c
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap_or(-1);
            drop(c);
            if ver != 0 && ver != schema_version {
                let dir = path
                    .parent()
                    .ok_or_else(|| anyhow!("state DB path '{}' has no parent", path.display()))?;
                let stem = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("state.db");
                let ts = unix_now();
                let bak = dir.join(format!("{stem}.v{ver}.{ts}.bak"));
                std::fs::rename(path, &bak).map_err(|e| {
                    // SQLite's win32 VFS opens with no
                    // FILE_SHARE_DELETE; another live broker holds
                    // the file → rename fails 32 here where DROP
                    // TABLE under WAL would have succeeded.
                    if e.raw_os_error() == Some(32) {
                        anyhow!(
                            "rename incompatible state DB {} → {}: {e} \
                             — the DB is open in another process \
                             (likely a running srt-win/broker); close \
                             it and retry",
                            path.display(),
                            bak.display()
                        )
                    } else {
                        anyhow::Error::new(e).context(format!(
                            "rename incompatible state DB {} → {}",
                            path.display(),
                            bak.display()
                        ))
                    }
                })?;
                // WAL sidecars too (best-effort — they hold no cred,
                // only journal pages of it).
                for ext in ["-wal", "-shm"] {
                    let p = dir.join(format!("{stem}{ext}"));
                    let to = dir.join(format!("{stem}.v{ver}.{ts}.bak{ext}"));
                    let _ = std::fs::rename(&p, &to);
                }
                // Best-effort cred scrub (pre-split schemas only —
                // absent table/column is fine).
                if let Ok(bc) = Connection::open(&bak) {
                    let _ = bc.execute("UPDATE sandbox_user SET cred = x''", []);
                }
                eprintln!(
                    "srt-win: state DB at schema v{ver} found, expected \
                     v{schema_version}; renamed to {} and created fresh. \
                     Re-run `srt-win install` (and `srt-win user \
                     trust-ca <pem>` if you use TLS termination) to \
                     re-provision. `srt-win acl recover` will sweep \
                     any sandbox-user DENY ACEs from a prior install; \
                     PROTECTED-stamp DACLs from the removed same-user \
                     mode require manual `icacls <path> /reset`.",
                    bak.display(),
                );
            }
        }
    }
    let conn = Connection::open(path).with_context(|| format!("sqlite open {}", path.display()))?;
    // WAL = concurrent readers + single writer + crash safety.
    // `synchronous=NORMAL` is the recommended companion for WAL and
    // is durable across power loss. busy_timeout is belt-and-braces
    // — the named mutex already serializes whole operations across
    // brokers, but a brief contention inside one process (tests)
    // shouldn't error.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.execute_batch(schema_sql).context("apply schema")?;
    conn.pragma_update(None, "user_version", schema_version)?;
    Ok(conn)
}

/// The machine-wide store dir: `%ProgramData%\sandbox-runtime` —
/// since the move of credential/marker/identity/CA-record/ambient
/// state to `HKLM\SOFTWARE\sandbox-runtime` ([`crate::reg`]), this
/// hosts only the managed CA key material (`ca\`), which must stay
/// on the filesystem because the broker's unelevated
/// generate-if-absent self-heal rewrites it. Created (and ACL'd) by
/// the elevated install (`install::provision_machine_store`); a
/// pre-created directory is healed there by taking ownership and
/// rewriting the DACL.
pub fn machine_store_dir() -> Result<PathBuf> {
    state_dir_from_base(std::env::var_os("ProgramData"), "ProgramData")
}

/// The per-user SESSION dir: `%LOCALAPPDATA%\sandbox-runtime` —
/// ACL-bookkeeping state (`state.db`: brokers/holders/working
/// ACEs). Per-user by design: these rows DRIVE ACL mutations on the
/// owning user's files, so they must only be writable by that user
/// (and admins) — in a shared store any local user could seed rows
/// for another user's broker to apply. Stamped real-user-only on
/// every [`open_db`].
pub fn session_store_dir() -> Result<PathBuf> {
    state_dir_from_base(std::env::var_os("LOCALAPPDATA"), "LOCALAPPDATA")
}

/// Errors if `var` (`%ProgramData%`) is unset,
/// empty, or yields a non-absolute path — a relative state dir
/// would put the ACL-protected DB in the CWD and break cross-broker
/// refcounting/recovery.
fn state_dir_from_base(base: Option<std::ffi::OsString>, var: &str) -> Result<PathBuf> {
    let base = base
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("{var} not set or empty"))?;
    let dir = base.join("sandbox-runtime");
    if !dir.is_absolute() {
        bail!(
            "state-DB directory '{}' is not absolute \
             ({var}='{}'); refusing relative state path",
            dir.display(),
            base.display()
        );
    }
    Ok(dir)
}

/// Run `f` under the init mutex with the DB open. Crash recovery is
/// run first. `f` receives a `Locked` view whose mutating methods
/// each autocommit (single-statement) or use their own short
/// transaction — there is NO single enclosing transaction.
///
/// See module doc for the no-enclosing-tx and ordering rationale.
pub fn with_init_lock<R>(
    holder_pid: HolderPid,
    force_recover: bool,
    f: impl FnOnce(&mut Locked) -> Result<R>,
) -> Result<(R, RecoveryReport)> {
    let (_mutex, conn, report) = locked_recovered(force_recover)?;
    let mut locked = Locked { conn, holder_pid };
    let out = f(&mut locked)?;
    Ok((out, report))
}

/// The shared critical-section preamble of [`with_init_lock`] and
/// [`with_install_lock`]: acquire the init mutex, open the DB, run
/// crash recovery. Keep the mutex guard alive for the whole
/// critical section.
fn locked_recovered(force_recover: bool) -> Result<(InitMutex, Connection, RecoveryReport)> {
    let mutex = InitMutex::acquire()?;
    let conn = open_db()?;
    let report = crash_recovery(&conn, force_recover)?;
    Ok((mutex, conn, report))
}

/// View inside `with_init_lock`. Owns the `Connection`; each method
/// commits independently (rusqlite autocommits a lone `execute`).
///
/// `holder_pid` is the LONG-LIVED owner of the stamps — typically
/// the Node host (sandbox-runtime) process, NOT this ephemeral
/// `srt-win acl` process. The CLI exits immediately; keying holders
/// on its PID would let the next acl op's crash-recovery reap it and
/// tear the stamp down. Keying on the caller-supplied holder PID
/// means a stamp persists until that process exits (or explicitly
/// restores), and refcount / crash-recovery track the real session.
pub struct Locked {
    conn: Connection,
    holder_pid: HolderPid,
}

impl Locked {
    /// Record `self.holder_pid` in `brokers`. The row's
    /// `process_create_time` is the HOLDER's, so crash-recovery
    /// checks whether the holder — not this short-lived CLI — is
    /// still alive.
    ///
    /// UPSERT, not `INSERT OR REPLACE`: with `foreign_keys=ON` and
    /// `ace_holders.pid REFERENCES brokers ON DELETE CASCADE`,
    /// REPLACE is a DELETE (cascading away every `ace_holders` row
    /// for this pid) plus a fresh INSERT — so a holder's *second*
    /// `acl stamp`/`grant` would silently drop its first batch's
    /// holds, and the next crash-recovery would strip those ACEs
    /// while the holder's child is still running. `ON CONFLICT DO
    /// UPDATE` updates in place and leaves child rows intact.
    pub fn register_broker(&self) -> Result<()> {
        let ct = pid_create_time(self.holder_pid.0)
            .with_context(|| format!("read create-time of holder pid {}", self.holder_pid.0))?;
        let now = unix_now();
        self.conn
            .execute(
                "INSERT INTO brokers (pid, process_create_time, started_at) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(pid) DO UPDATE SET \
                   process_create_time = excluded.process_create_time, \
                   started_at          = excluded.started_at",
                params![self.holder_pid.0 as i64, ct, now],
            )
            .context("INSERT brokers")?;
        Ok(())
    }

    /// Remove the holder's `brokers` row. CASCADE drops its
    /// `holders` rows.
    pub fn unregister_broker(&self) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM brokers WHERE pid = ?1",
                params![self.holder_pid.0 as i64],
            )
            .context("DELETE brokers")?;
        Ok(())
    }

    /// Register the holder, run `f`, and on per-path failure roll
    /// back any ACEs `f` freshly added (then drop the broker row if
    /// it now holds nothing). All-or-nothing for `apply_aces`.
    fn with_broker_registration(
        &self,
        sandbox_sid: &str,
        f: impl FnOnce(&Self) -> Result<(Vec<AceWitness>, usize)>,
    ) -> Result<(Vec<AceWitness>, usize)> {
        self.register_broker()?;
        let (witnesses, failed) = f(self)?;
        if failed > 0 {
            for w in witnesses.iter().filter(|w| w.holder_added) {
                if let Err(e) = self.release_one_ace(&w.canon, w.ace.kind(), sandbox_sid) {
                    eprintln!(
                        "srt-win: WARNING: rollback {} '{}': {e:#}; \
                         ACE left in place",
                        w.ace.kind(),
                        w.canon
                    );
                }
            }
            if self
                .my_ace_holds(None)
                .map(|h| h.is_empty())
                .unwrap_or(false)
            {
                let _ = self.unregister_broker();
            }
        }
        Ok((witnesses, failed))
    }

    /// Apply additive sandbox-user ACEs on each `(canon, ace)` and
    /// record `self.holder_pid` as a holder. Refcounted: a path
    /// already held by another holder gets its on-disk ACE
    /// re-converged (idempotent) and a holder row added; release
    /// recomputes the effective mask from the remaining holders.
    ///
    /// `Deny` targets implicitly add a `(parent, DenyFdc)` entry so
    /// the sandbox user cannot `del`/`ren` the file via parent-FDC
    /// even when the parent carries an inherited
    /// `BUILTIN\Users:(F)`. Multiple denied siblings under one
    /// parent share the parent's `deny_fdc` row (PK
    /// `(path, kind, pid)` dedupes within one holder; refcount
    /// handles cross-holder).
    ///
    /// Every entry is recorded in order ([`Self::record_ace`]); each
    /// PATH is converged once, when its last entry in the batch has
    /// been recorded (module doc, "One converge per path per
    /// batch"). A failed converge fails every entry recorded on that
    /// path.
    ///
    /// All-or-nothing per batch (via [`Self::with_broker_registration`]).
    pub fn apply_aces(
        &self,
        sandbox_sid: &str,
        targets: &[(String, SbAce)],
    ) -> Result<(Vec<AceWitness>, usize)> {
        self.with_broker_registration(sandbox_sid, |db| {
            let plan = plan_ace_ops(targets);
            let last = last_touches(plan.iter().map(|op| op.canon.as_str()));
            // `done[i]`: op `i` recorded (and, once its path has
            // converged, written). A witness leaves its slot for the
            // caller only as `Some` — i.e. only once converged.
            let mut done: Vec<Option<AceWitness>> = Vec::new();
            done.resize_with(plan.len(), || None);
            // Recorded, converge still owed: path → op indices.
            let mut owed: HashMap<&str, Vec<usize>> = HashMap::new();
            let mut failed = 0usize;
            for (i, op) in plan.iter().enumerate() {
                let canon = op.canon.as_str();
                // Skip the parent-FDC ACE when the file's own
                // Deny failed (e.g. hardlink refuse) — the batch
                // is going to roll back anyway (`failed > 0`),
                // and stamping the parent first just to release
                // it in the same pass wastes a SetSecurityInfo
                // round-trip and clutters the failure output.
                if op.implied_by.is_none_or(|t| done[t].is_some()) {
                    match db.record_ace(canon, op.ace) {
                        Ok(w) => {
                            done[i] = Some(w);
                            owed.entry(canon).or_default().push(i);
                        }
                        Err(e) => {
                            eprintln!("srt-win: {} '{canon}': {e:#}", op.ace.kind());
                            failed += 1;
                        }
                    }
                }
                if last[i]
                    && let Some(ops) = owed.remove(canon)
                    && let Err(e) = recompose_at(&db.conn, canon, sandbox_sid)
                {
                    for k in ops {
                        eprintln!("srt-win: {} '{canon}': {e:#}", plan[k].ace.kind());
                        done[k] = None;
                        failed += 1;
                    }
                }
            }
            Ok((done.into_iter().flatten().collect(), failed))
        })
    }

    /// The record half of a single-ACE converge: capture the path's
    /// identity, run the guards, then the record-first upserts
    /// (holder row plus `working_aces` row). The caller OWES a
    /// [`recompose_at`] on `canon` before its batch ends — a crash
    /// in between leaves a row whose ACE hasn't been written; the
    /// next call re-derives and reapplies. The returned witness is
    /// only handed out of [`Self::apply_aces`] once that converge
    /// has succeeded.
    fn record_ace(&self, canon: &str, want: SbAce) -> Result<AceWitness> {
        let (cur_id, links, is_dir) = path_id::capture_id_and_links(canon)
            .with_context(|| format!("capture file_id+links '{canon}'"))?;
        // Hardlink guard: NTFS hardlinks share one SD across
        // distinct canonical paths, but `ace_holders` is
        // PATH-keyed. A Deny on one alias is invisible to a holder
        // of another — `release_one_ace` on the alias sees
        // remaining=0 and recomposes the SHARED DACL without the
        // deny while the other holder's child is still running.
        // Refuse Deny on multi-link files; Grant is fail-open so
        // an early release is safe, and `DenyFdc` only targets
        // directories.
        if matches!(want, SbAce::Deny(_)) && !is_dir && links > 1 {
            bail!(
                "deny refused: '{canon}' has {links} hardlink(s); \
                 ace_holders rows are path-keyed, so releasing an \
                 alias would prematurely strip the shared deny ACE"
            );
        }
        let prior: Option<Vec<u8>> = self
            .conn
            .prepare_cached(
                "SELECT file_id FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = ?2",
            )?
            .query_row(params![canon, want.kind()], |r| r.get(0))
            .optional()
            .context("SELECT working_aces")?;
        if let Some(fid) = &prior
            && FileId::from_bytes(fid)? != cur_id
        {
            bail!(
                "'{canon}': file_id changed since prior {} — path \
                 was substituted (refusing)",
                want.kind()
            );
        }
        // Holder row first (`want_mask` is THIS holder's request,
        // independent of what other holders want — `effective_ace`
        // computes the MAX). UPSERT so a re-apply at a different
        // mask updates this holder's want. `holder_added` must
        // reflect whether THIS call inserted a NEW (canon, kind,
        // pid) row — NOT whether `working_aces` was empty
        // (`prior.is_none()`): the latter would give a second
        // holder of an already-held path `holder_added=false`,
        // and partial-failure rollback (`with_broker_registration`)
        // would leak its row. SQLite's UPSERT `changes()` returns
        // 1 for both branches, so probe first.
        let already_held: bool = self
            .conn
            .prepare_cached(
                "SELECT 1 FROM ace_holders WHERE \
                 canonical_path = ?1 AND kind = ?2 AND pid = ?3 \
                 LIMIT 1",
            )?
            .exists(params![canon, want.kind(), self.holder_pid.0 as i64])
            .context("SELECT ace_holders (held?)")?;
        self.conn
            .prepare_cached(
                "INSERT INTO ace_holders \
                 (canonical_path, kind, pid, want_mask) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(canonical_path, kind, pid) \
                 DO UPDATE SET want_mask = excluded.want_mask",
            )?
            .execute(params![
                canon,
                want.kind(),
                self.holder_pid.0 as i64,
                want.as_str()
            ])
            .context("UPSERT ace_holders")?;
        let holder_added = !already_held;
        let eff = self.effective_ace(canon, want.kind())?.unwrap_or(want);
        self.conn
            .prepare_cached(
                "INSERT INTO working_aces \
                 (canonical_path, kind, file_id, mask) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(canonical_path, kind) DO UPDATE SET \
                   file_id = excluded.file_id, \
                   mask    = excluded.mask",
            )?
            .execute(params![
                canon,
                want.kind(),
                cur_id.as_bytes().as_slice(),
                eff.as_str()
            ])
            .context("UPSERT working_aces")?;
        Ok(AceWitness {
            canon: canon.to_string(),
            ace: eff,
            already: prior.is_some(),
            holder_added,
            _sealed: (),
        })
    }

    /// `MAX(want_mask)` across live holders of `(canon, kind)`.
    fn effective_ace(&self, canon: &str, kind: &str) -> Result<Option<SbAce>> {
        let masks: Vec<String> = query_vec(
            &self.conn,
            "SELECT want_mask FROM ace_holders \
             WHERE canonical_path = ?1 AND kind = ?2",
            params![canon, kind],
            |r| r.get(0),
        )?;
        masks
            .iter()
            .map(|m| SbAce::parse(kind, m))
            .reduce(|a, b| Ok(a?.max(b?)))
            .transpose()
    }

    /// Release one `(canon, kind)` hold and converge the path —
    /// [`Self::release_row`] plus the [`recompose_at`] it owes. The
    /// single-row form, for rollback; [`Self::release_aces`] batches
    /// the converge per path instead.
    fn release_one_ace(&self, canon: &str, kind: &str, sandbox_sid: &str) -> Result<AceRelease> {
        let (release, converge) = self.release_row(canon, kind, sandbox_sid)?;
        if converge == Converge::Owed {
            recompose_at(&self.conn, canon, sandbox_sid)?;
        }
        Ok(release)
    }

    /// Release one `(canon, kind)` hold; recompute the effective ACE
    /// from the remaining holders (downgrade if this holder was the
    /// one that escalated it; revoke when zero remain).
    /// Identity-validated: if the path now resolves to a different
    /// `file_id`, the row is dropped and the ACE on the foreign
    /// object is NOT touched — except for `Grant`, where we
    /// best-effort `locate_by_file_id` and revoke at the moved path
    /// so the sandbox user does not keep stale access.
    ///
    /// The row half only: when the identity gate matches, the
    /// on-disk converge of `canon` is left to the caller
    /// ([`Converge::Owed`]) so a batch can run it once per path. The
    /// reported [`AceRelease`] is then provisional on that converge
    /// succeeding. A relocated grant is converged here, at the path
    /// it moved to.
    fn release_row(
        &self,
        canon: &str,
        kind: &str,
        sandbox_sid: &str,
    ) -> Result<(AceRelease, Converge)> {
        self.conn
            .prepare_cached(
                "DELETE FROM ace_holders WHERE canonical_path = ?1 \
                 AND kind = ?2 AND pid = ?3",
            )?
            .execute(params![canon, kind, self.holder_pid.0 as i64])
            .context("DELETE ace_holders (self)")?;
        let row: Option<(Vec<u8>, String)> = self
            .conn
            .prepare_cached(
                "SELECT file_id, mask FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = ?2",
            )?
            .query_row(params![canon, kind], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let Some((fid, stored)) = row else {
            return Ok((AceRelease::NoRow, Converge::Done));
        };
        let new_eff = self.effective_ace(canon, kind)?;
        // Row update first (record-first), then converge disk.
        match new_eff {
            Some(e) => self
                .conn
                .execute(
                    "UPDATE working_aces SET mask = ?3 \
                     WHERE canonical_path = ?1 AND kind = ?2",
                    params![canon, kind, e.as_str()],
                )
                .context("UPDATE working_aces (downgrade)")?,
            None => self
                .conn
                .execute(
                    "DELETE FROM working_aces \
                     WHERE canonical_path = ?1 AND kind = ?2",
                    params![canon, kind],
                )
                .context("DELETE working_aces")?,
        };
        let want_id = FileId::from_bytes(&fid)?;
        match identity_gate(canon, want_id) {
            IdGate::Match => Ok((
                match new_eff {
                    Some(e) if e.as_str() == stored => AceRelease::StillHeld,
                    Some(_) => AceRelease::Downgraded,
                    None => AceRelease::Revoked,
                },
                Converge::Owed,
            )),
            IdGate::Mismatch if kind == "grant" => {
                // The granted object moved. The ALLOW ACE travels
                // with the inode → the sandbox user still has
                // access at the new path. Chase by file_id and
                // revoke there (then re-converge if the new path
                // happens to be tracked too). DENY/FDC are left in
                // place on the moved inode (fail-closed).
                let release = match path_id::locate_by_file_id(&want_id) {
                    Some(at) => {
                        eprintln!(
                            "srt-win: grant '{canon}': file_id moved \
                             to '{at}'; revoking there"
                        );
                        recompose_at(&self.conn, &at, sandbox_sid)?;
                        AceRelease::Relocated { moved_to: at }
                    }
                    None => {
                        eprintln!(
                            "srt-win: grant '{canon}': file_id not \
                             found on volume; dropping row"
                        );
                        AceRelease::Missing
                    }
                };
                Ok((release, Converge::Done))
            }
            IdGate::Mismatch => {
                eprintln!(
                    "srt-win: {kind} '{canon}': file_id mismatch — \
                     path substituted; not touching ACE on the \
                     foreign object (fail-closed)"
                );
                Ok((AceRelease::Mismatch, Converge::Done))
            }
            IdGate::Unreadable => {
                eprintln!(
                    "srt-win: {kind} '{canon}': open failed; \
                     dropping row"
                );
                Ok((AceRelease::Missing, Converge::Done))
            }
        }
    }

    /// `(canon, kind)` rows held by this holder, optionally filtered
    /// to one set of kinds.
    fn my_ace_holds(&self, kinds: Option<&[&str]>) -> Result<Vec<(String, String)>> {
        let all: Vec<(String, String)> = query_vec(
            &self.conn,
            "SELECT canonical_path, kind FROM ace_holders \
             WHERE pid = ?1",
            params![self.holder_pid.0 as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(all
            .into_iter()
            .filter(|(_, k)| kinds.is_none_or(|ks| ks.contains(&k.as_str())))
            .collect())
    }

    /// Release every ACE hold of `self.holder_pid` for the given
    /// `kinds` ([`KIND_GRANT`] for `acl revoke`; [`KIND_DENY`] for
    /// `acl restore --sandbox-user-sid`) and unregister if no holds
    /// of any kind remain. Per-path catch-and-continue.
    ///
    /// Every hold's rows are released in order
    /// ([`Self::release_row`], identity gate included); each PATH is
    /// converged once, after its last hold in the batch (module doc,
    /// "One converge per path per batch"). A failed converge fails
    /// every hold released on that path — their rows are gone and
    /// the ACE is left in place, as for a single failed release.
    pub fn release_aces(
        &self,
        sandbox_sid: &str,
        kinds: &[&str],
    ) -> Result<(Vec<(String, AceRelease)>, usize)> {
        let holds = self.my_ace_holds(Some(kinds))?;
        let last = last_touches(holds.iter().map(|(canon, _)| canon.as_str()));
        // Per-hold outcome, in `holds` order; `None` = failed.
        let mut released: Vec<Option<AceRelease>> = vec![None; holds.len()];
        // Rows released, converge still owed: path → hold indices.
        let mut owed: HashMap<&str, Vec<usize>> = HashMap::new();
        let mut failed = 0usize;
        let warn = |kind: &str, canon: &str, e: &anyhow::Error| {
            eprintln!(
                "srt-win: WARNING: release {kind} '{canon}': \
                 {e:#}; ACE left in place"
            );
        };
        for (i, (canon, kind)) in holds.iter().enumerate() {
            match self.release_row(canon, kind, sandbox_sid) {
                Ok((r, converge)) => {
                    released[i] = Some(r);
                    if converge == Converge::Owed {
                        owed.entry(canon.as_str()).or_default().push(i);
                    }
                }
                Err(e) => {
                    warn(kind, canon, &e);
                    failed += 1;
                }
            }
            if last[i]
                && let Some(rows) = owed.remove(canon.as_str())
                && let Err(e) = recompose_at(&self.conn, canon, sandbox_sid)
            {
                for k in rows {
                    warn(&holds[k].1, canon, &e);
                    released[k] = None;
                    failed += 1;
                }
            }
        }
        let out: Vec<(String, AceRelease)> = holds
            .iter()
            .zip(released)
            .filter_map(|((canon, _), r)| Some((canon.clone(), r?)))
            .collect();
        if self
            .my_ace_holds(None)
            .map(|h| h.is_empty())
            .unwrap_or(false)
        {
            self.unregister_broker()?;
        }
        Ok((out, failed))
    }

    /// Record a placeholder component `acl stamp` is about to
    /// create (see the `placeholders` table comment). Idempotent
    /// (`INSERT OR IGNORE`); called intent-first — before the
    /// on-disk create — so a crash between record and create leaves
    /// a harmless orphan row rather than an unrecorded on-disk
    /// component a later holder cannot discover.
    pub fn record_placeholder(&self, canon: &str) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT OR IGNORE INTO placeholders (canonical_path) \
                 VALUES (?1)",
            )?
            .execute(params![canon])
            .with_context(|| format!("INSERT placeholders '{canon}'"))?;
        Ok(())
    }

    /// Every recorded placeholder that is a STRICT ancestor of
    /// `canon` (i.e. `canon` starts with `placeholder || '\'`) —
    /// the discovery half of the full-chain hold (see the
    /// `placeholders` table comment). The table is tiny, so filter
    /// in Rust rather than a `LIKE` pattern that would have to
    /// escape `?`/`_` in canonical paths.
    pub fn placeholder_ancestors_of(&self, canon: &str) -> Result<Vec<String>> {
        let all: Vec<String> = query_vec(
            &self.conn,
            "SELECT canonical_path FROM placeholders",
            [],
            |r| r.get(0),
        )?;
        let cb = canon.as_bytes();
        Ok(all
            .into_iter()
            .filter(|p| cb.get(p.len()) == Some(&b'\\') && canon.starts_with(p.as_str()))
            .collect())
    }
}

/// Read all `working_aces` rows for `canon` and converge the on-disk
/// ACEs for `sandbox_sid` to exactly that set. The single chokepoint
/// for sandbox-user ACE state — every add/drop/crash-recover routes
/// here so a path with both a grant AND a deny (or a parent that is
/// both granted and `deny_fdc`'d) is handled consistently.
fn recompose_at(conn: &Connection, canon: &str, sandbox_sid: &str) -> Result<()> {
    recompose(conn, canon, sandbox_sid, false)
}

/// [`recompose_at`], optionally with the write FORCED (never skipped
/// as already-converged) — the journal recovery's form.
fn recompose(conn: &Connection, canon: &str, sandbox_sid: &str, force_write: bool) -> Result<()> {
    let rows: Vec<(String, String)> = query_vec(
        conn,
        "SELECT kind, mask FROM working_aces \
         WHERE canonical_path = ?1",
        params![canon],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut set = acl::SbAceSet::default();
    for (k, m) in &rows {
        match SbAce::parse(k, m)? {
            SbAce::Grant(g) => set.grant = Some(g),
            SbAce::Deny(d) => set.deny = Some(d),
            SbAce::DenyFdc => set.deny_fdc = true,
            SbAce::DenyDelete => set.deny_delete = true,
        }
    }
    // Install-time ambient write-deny (HKLM AmbientDenies) folds
    // into every converge on the path, so session release/recovery
    // cannot strip it. WriteDeny is the floor: a session's wider
    // ReadDeny wins while its row is held, and the floor returns on
    // release. The registry value is admin-written (HKLM\SOFTWARE
    // default DACL), so the list is trustworthy as read.
    if crate::install::ambient_deny_recorded(canon) {
        set.deny.get_or_insert(acl::DenyMask::WriteDeny);
    }
    // The object the completion record must be about. Unreadable →
    // no identity → no skip (the write below reports the real error).
    let ledger = ConvergedLedger {
        conn,
        canon,
        file_id: path_id::capture_file_id(canon).ok(),
        // A path left with no sandbox ACE needs no record (and the
        // table must not grow with every path ever stamped): it is
        // withdrawn by the write and not restored.
        keep: !set.is_empty(),
        force_write,
    };
    acl::converge_sandbox_aces(canon, sandbox_sid, set, Some(&ledger))
        .with_context(|| format!("recompose '{canon}' ({set:?})"))
}

/// [`acl::WriteLedger`] over `converged_dacls` for one path — see
/// that trait for why the write-skip needs a completion record, and
/// the table comment for its lifecycle.
struct ConvergedLedger<'a> {
    conn: &'a Connection,
    canon: &'a str,
    /// The path's current identity; `None` (unreadable) never
    /// matches and is never recorded.
    file_id: Option<FileId>,
    /// Whether a completed write is worth recording.
    keep: bool,
    /// Never report completion — the write always happens.
    force_write: bool,
}

impl acl::WriteLedger for ConvergedLedger<'_> {
    fn completed(&self, dacl: &[u8]) -> bool {
        if self.force_write {
            return false;
        }
        let Some(id) = self.file_id else {
            return false;
        };
        let row: rusqlite::Result<Option<(Vec<u8>, Vec<u8>)>> = self
            .conn
            .query_row(
                "SELECT file_id, dacl FROM converged_dacls \
                 WHERE canonical_path = ?1",
                params![self.canon],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional();
        // Same object, same DACL. A read error, a malformed blob or
        // a substituted path all read as "not completed".
        matches!(row, Ok(Some((fid, was)))
            if was == dacl && FileId::from_bytes(&fid).is_ok_and(|f| f == id))
    }

    fn begin(&self) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM converged_dacls WHERE canonical_path = ?1",
                params![self.canon],
            )
            .context("DELETE converged_dacls")?;
        // Journal the write (module doc, "Write-intent journal").
        let Some(id) = self.file_id else {
            bail!(
                "'{}': file_id unreadable — cannot journal the DACL write",
                self.canon
            );
        };
        record_write_intent(self.conn, self.canon, &id)?;
        // Never on the recovery replay (`force_write`): a recovery
        // run with the variable still set must be able to finish
        // the write the hook interrupted.
        #[cfg(feature = "test-hooks")]
        if !self.force_write {
            debug_kill_before_write(self.canon);
        }
        Ok(())
    }

    fn complete(&self, dacl: &[u8]) {
        // The write returned: retire its journal row. Best-effort — a
        // row that outlives its write only costs one redundant
        // forced converge at the next recovery.
        if let Some(id) = self.file_id {
            let _ = clear_write_intent(self.conn, self.canon, &id.as_bytes());
        }
        let (true, Some(id)) = (self.keep, self.file_id) else {
            return;
        };
        // Best-effort: without the row the next converge just writes.
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO converged_dacls \
             (canonical_path, file_id, dacl) VALUES (?1, ?2, ?3)",
            params![self.canon, id.as_bytes().as_slice(), dacl],
        );
    }
}

// ─── Write-intent journal ───────────────────────────────────────────

/// Journal a DACL write about to start on the object `id` at `canon`
/// (see the `write_intents` table comment). Autocommitted before the
/// write, like every other row here; idempotent.
fn record_write_intent(conn: &Connection, canon: &str, id: &FileId) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO write_intents (canonical_path, file_id) \
         VALUES (?1, ?2)",
        params![canon, id.as_bytes().as_slice()],
    )
    .with_context(|| format!("INSERT write_intents '{canon}'"))?;
    Ok(())
}

/// Retire the journal row for `(canon, id)` — its write returned, or
/// recovery has dealt with it.
fn clear_write_intent(conn: &Connection, canon: &str, id: &[u8]) -> Result<()> {
    conn.execute(
        "DELETE FROM write_intents \
         WHERE canonical_path = ?1 AND file_id = ?2",
        params![canon, id],
    )
    .with_context(|| format!("DELETE write_intents '{canon}'"))?;
    Ok(())
}

/// Test hook for the journal's smoke row — compiled ONLY under the
/// off-by-default `test-hooks` cargo feature, so no shipped broker
/// contains it. With `SANDBOX_RUNTIME_WIN_DEBUG` set AND
/// `SANDBOX_RUNTIME_WIN_DEBUG_KILL_BEFORE_DACL_WRITE` naming a path
/// suffix, exit hard (no unwinding, like a kill) right after the
/// intent row for a matching path is committed and before its DACL
/// write — the state a broker killed at the start of a propagation
/// leaves behind. Fires at most once per process (it exits) and
/// never on the recovery replay (see the call site).
#[cfg(feature = "test-hooks")]
fn debug_kill_before_write(canon: &str) {
    if std::env::var_os("SANDBOX_RUNTIME_WIN_DEBUG").is_none() {
        return;
    }
    if let Ok(suffix) = std::env::var("SANDBOX_RUNTIME_WIN_DEBUG_KILL_BEFORE_DACL_WRITE")
        && !suffix.is_empty()
        && canon
            .to_ascii_lowercase()
            .ends_with(&suffix.to_ascii_lowercase())
    {
        eprintln!("srt-win: debug: killed before dacl write '{canon}'");
        std::process::exit(86);
    }
}

/// Finish every DACL write the journal shows as started and not
/// returned: re-run the path's converge from the rows that exist NOW
/// (after a killed release: none, so the sandbox ACEs come off the
/// whole subtree), with the write forced. The row goes only once that
/// converge has returned, so a pass that is itself killed, or whose
/// converge fails, leaves it for the next one; re-running a completed
/// converge changes nothing, so the pass is idempotent.
///
/// Path-anchored and fail-closed, as release is: when `canon` is gone
/// or now names a different object the journal row is dropped and
/// nothing is touched — the moved object is NOT chased by file_id
/// (the journal does not know whether a deny was involved, and
/// converging a relocated deny target from its new path's rows would
/// strip the deny). A path that cannot be opened keeps its row for a
/// later pass unless `force` drops it.
fn recover_write_intents(
    conn: &Connection,
    sandbox_sid: &str,
    force: bool,
    report: &mut RecoveryReport,
) -> Result<()> {
    let intents: Vec<(String, Vec<u8>)> = query_vec(
        conn,
        "SELECT canonical_path, file_id FROM write_intents",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    for (canon, fid) in &intents {
        let gate = match FileId::from_bytes(fid) {
            Ok(want) => identity_gate(canon, want),
            // A malformed identity can never match anything.
            Err(_) => IdGate::Mismatch,
        };
        match gate {
            IdGate::Match => match recompose(conn, canon, sandbox_sid, true) {
                Ok(()) => {
                    clear_write_intent(conn, canon, fid)?;
                    report.writes_resumed += 1;
                }
                Err(e) => eprintln!(
                    "srt-win: interrupted DACL write '{canon}': \
                     re-converge failed ({e:#}); will retry"
                ),
            },
            IdGate::Mismatch => {
                eprintln!(
                    "srt-win: interrupted DACL write '{canon}': path \
                     is gone or names a different object; not \
                     touching it (fail-closed), dropping the journal \
                     row"
                );
                clear_write_intent(conn, canon, fid)?;
            }
            IdGate::Unreadable if force => {
                eprintln!(
                    "srt-win: interrupted DACL write '{canon}': \
                     unreadable; dropping the journal row (--force)"
                );
                clear_write_intent(conn, canon, fid)?;
            }
            IdGate::Unreadable => {} // row kept; identity_gate reported
        }
    }
    report.writes_pending = count_write_intents(conn)?;
    Ok(())
}

/// Journal rows outstanding — DACL writes started and not yet seen
/// to return.
fn count_write_intents(conn: &Connection) -> Result<u32> {
    conn.query_row("SELECT count(*) FROM write_intents", [], |r| r.get(0))
        .context("count write_intents")
}

/// Whether a row change still needs its path converged on disk
/// ([`recompose_at`]) by the caller — see [`Locked::release_row`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Converge {
    /// Rows changed and the identity gate matched; the caller must
    /// `recompose_at` the path (once per path per batch suffices).
    Owed,
    /// Nothing left to do on disk at this path.
    Done,
}

/// For a batch that touches `paths[i]` at step `i`: `out[i]` is true
/// iff no LATER step touches the same path — the step after which
/// that path's deferred converge runs (module doc, "One converge per
/// path per batch"). Exactly one `true` per distinct path, so each
/// path is converged once however often the batch touches it.
/// Paths are compared as the DB keys them: exact canonical strings.
fn last_touches<'a>(paths: impl IntoIterator<Item = &'a str>) -> Vec<bool> {
    let paths: Vec<&str> = paths.into_iter().collect();
    let mut seen = HashSet::new();
    let mut last: Vec<bool> = paths.iter().rev().map(|p| seen.insert(*p)).collect();
    last.reverse();
    last
}

/// One step of an [`Locked::apply_aces`] batch.
#[derive(Debug, PartialEq, Eq)]
struct PlannedAce {
    canon: String,
    ace: SbAce,
    /// `Some(i)`: this is the parent-FDC entry implied by step `i`
    /// (a `Deny`/`DenyDelete` target) and is skipped when step `i`
    /// did not go through.
    implied_by: Option<usize>,
}

/// Expand `targets` into the batch's steps, in order: each target,
/// followed — for a `Deny`/`DenyDelete` target with a stampable
/// parent — by the implied `(parent, DenyFdc)`. Repeats are kept:
/// every step still runs its own capture, guards and upserts; only
/// the per-path converge is shared.
fn plan_ace_ops(targets: &[(String, SbAce)]) -> Vec<PlannedAce> {
    let mut plan = Vec::with_capacity(targets.len());
    for (canon, ace) in targets {
        let target = plan.len();
        plan.push(PlannedAce {
            canon: canon.clone(),
            ace: *ace,
            implied_by: None,
        });
        if matches!(ace, SbAce::Deny(_) | SbAce::DenyDelete)
            && let Some(parent) = path_id::canonical_parent_of(canon)
        {
            plan.push(PlannedAce {
                canon: parent,
                ace: SbAce::DenyFdc,
                implied_by: Some(target),
            });
        }
    }
    plan
}

/// Sealed proof that [`Locked::apply_aces`] converged `canon` to
/// carry `ace` for the sandbox user.
#[must_use]
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug)]
pub struct AceWitness {
    pub canon: String,
    pub ace: SbAce,
    /// A row already existed (another holder, or a re-apply).
    pub already: bool,
    pub holder_added: bool,
    _sealed: (),
}

/// Per-path outcome of [`Locked::release_aces`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AceRelease {
    /// ACE removed (last holder); row deleted.
    Revoked,
    /// Other holders remain at the SAME effective mask; ACE
    /// untouched.
    StillHeld,
    /// Other holders remain at a NARROWER mask; ACE re-applied at
    /// the new MAX(want_mask).
    Downgraded,
    /// `file_id` mismatch; for `grant` the ACE was revoked at the
    /// relocated path. Row deleted.
    Relocated { moved_to: String },
    /// `file_id` mismatch — row deleted, ACE on the foreign object
    /// not touched.
    Mismatch,
    /// Path no longer opens — row deleted.
    Missing,
    /// Holder row removed but no `working_aces` row found.
    NoRow,
}

impl AceRelease {
    pub fn as_str(&self) -> &'static str {
        match self {
            AceRelease::Revoked => "revoked",
            AceRelease::StillHeld => "stillHeld",
            AceRelease::Downgraded => "downgraded",
            AceRelease::Relocated { .. } => "relocated",
            AceRelease::Mismatch => "mismatch",
            AceRelease::Missing => "missing",
            AceRelease::NoRow => "noRow",
        }
    }
}

/// Prune dead brokers and revoke any sandbox-user ACEs they orphaned.
///
/// Per-path commit: the dead-broker prune is one short tx (pure DB,
/// CASCADE); then each orphan's (recompose FS mutation + row
/// delete) is committed independently, so a failure on path Y
/// leaves path X's recompose+delete durable. `force` drops journal
/// rows whose path cannot be opened ([`recover_write_intents`]).
fn crash_recovery(conn: &Connection, force: bool) -> Result<RecoveryReport> {
    let mut report = RecoveryReport::default();

    // 1. Find dead brokers.
    let dead: Vec<i64> = query_vec(
        conn,
        "SELECT pid, process_create_time FROM brokers",
        [],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    )?
    .into_iter()
    .filter(|&(pid, ct)| !is_process_alive(pid as u32, ct))
    .map(|(pid, _)| pid)
    .collect();
    // 2. Delete dead brokers in one short tx; CASCADE drops their
    //    holder rows. (No-op if none — but still cheap.)
    if !dead.is_empty() {
        report.dead_brokers = dead.len() as u32;
        let tx = conn
            .unchecked_transaction()
            .context("begin prune-dead tx")?;
        for pid_i in &dead {
            tx.execute("DELETE FROM brokers WHERE pid = ?1", params![pid_i])
                .context("DELETE dead broker")?;
        }
        tx.commit().context("commit prune-dead")?;
    }
    // Even with no dead brokers there can be orphaned ACE rows
    // (a broker that unregistered but crashed before releasing), so
    // always run step 3.

    // 3. Orphaned sandbox-user ACEs: any working_aces row with
    //     zero ace_holders is one whose holder died (CASCADE
    //     dropped the holder row above). Re-converge the path —
    //     `recompose_at` reads the (possibly remaining) rows and
    //     applies exactly that, so a path with one orphaned kind
    //     and one still-held kind keeps the held one. Sandbox SID
    //     comes from `read_setup_info` — when no sandbox user is
    //     provisioned, there are no `working_aces` rows to orphan.
    // Identity comes from the VALIDATED machine-store read (name↔SID
    // + sandbox-group membership against SAM), never from raw rows:
    // the machine DB is Users-writable, and this SID is about to be
    // written into DACLs. No valid identity → skip disk work
    // entirely (the session rows stay put for a later recovery).
    if let Some(sb) = crate::install::read_setup()?.map(|s| s.sandbox_user_sid) {
        let orphan_aces: Vec<(String, String, Vec<u8>)> = query_vec(
            conn,
            "SELECT g.canonical_path, g.kind, g.file_id \
             FROM working_aces g \
             LEFT JOIN ace_holders h \
               ON h.canonical_path = g.canonical_path \
              AND h.kind = g.kind \
             WHERE h.canonical_path IS NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        // One converge per path (module doc): each orphan row is
        // deleted and identity-gated in turn; a path's recompose
        // runs after its LAST orphan row. An early `?` return below
        // can only strand a path that still has an undeleted orphan
        // row (its last touch lies ahead), so the next recovery
        // converges it.
        let last = last_touches(orphan_aces.iter().map(|(canon, ..)| canon.as_str()));
        // Rows deleted + gate matched, converge still owed: path →
        // kinds.
        let mut owed: HashMap<&str, Vec<&str>> = HashMap::new();
        for (i, (canon, kind, fid)) in orphan_aces.iter().enumerate() {
            conn.execute(
                "DELETE FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = ?2",
                params![canon, kind],
            )
            .context("DELETE working_aces (orphan)")?;
            let want = FileId::from_bytes(fid)?;
            match identity_gate(canon, want) {
                IdGate::Match => owed.entry(canon.as_str()).or_default().push(kind.as_str()),
                IdGate::Mismatch if kind == "grant" => {
                    if let Some(at) = path_id::locate_by_file_id(&want) {
                        let _ = recompose_at(conn, &at, &sb);
                    }
                    report.aces_revoked += 1;
                }
                // gone/substituted — nothing on disk to do
                _ => report.aces_revoked += 1,
            }
            if last[i]
                && let Some(kinds) = owed.remove(canon.as_str())
            {
                match recompose_at(conn, canon, &sb) {
                    Ok(()) => report.aces_revoked += kinds.len() as u32,
                    Err(e) => {
                        for kind in kinds {
                            eprintln!(
                                "srt-win: orphaned {kind} '{canon}': \
                                 recompose failed ({e:#})"
                            );
                        }
                    }
                }
            }
        }
    }
    // 4. Interrupted DACL writes (module doc, "Write-intent
    //    journal"). After step 3 on purpose: an orphan converge that
    //    completes on a journaled path retires that row itself, so
    //    the tree is walked once, not twice. Same validated identity
    //    as step 3; without one the rows wait.
    //    The table is empty unless a write was cut short, so the
    //    identity read is only paid for then.
    report.writes_pending = count_write_intents(conn)?;
    if report.writes_pending > 0
        && let Some(sb) = crate::install::read_setup()?.map(|s| s.sandbox_user_sid)
    {
        recover_write_intents(conn, &sb, force, &mut report)?;
    }
    Ok(report)
}

enum IdGate {
    Match,
    Mismatch,
    Unreadable,
}

/// `(path, file_id)` identity check. `path` gone
/// (ERROR_FILE/PATH_NOT_FOUND) or different inode → `Mismatch`;
/// any other open error → `Unreadable` (retryable, not a
/// mismatch).
fn identity_gate(path: &str, expect: FileId) -> IdGate {
    match path_id::capture_file_id(path) {
        Ok(cur) if cur == expect => IdGate::Match,
        Ok(_) => IdGate::Mismatch,
        Err(e) => {
            if path_id::is_not_found(&e) {
                IdGate::Mismatch
            } else {
                eprintln!(
                    "srt-win: '{path}': cannot read file_id ({e:#}); \
                     leaving row (use `acl recover --force`)"
                );
                IdGate::Unreadable
            }
        }
    }
}

/// True if `pid` refers to a live process whose CreationTime
/// matches `expected_create_filetime`. PID-recycle guard.
fn is_process_alive(pid: u32, expected_create_filetime: i64) -> bool {
    if pid == std::process::id() {
        // Don't reap ourselves even if the stored CreationTime is
        // somehow stale.
        return true;
    }
    // SYNCHRONIZE so the WaitForSingleObject(0) signaled-check works.
    let h = match unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION
                | windows::Win32::System::Threading::PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    } {
        Ok(h) if !h.is_invalid() => h,
        // A spurious `Ok` with an invalid handle is "uncertain" —
        // treat as ALIVE, matching the conservative stance below
        // (better to leave a stale row than reap a live broker and
        // restore a file it still holds).
        Ok(_) => return true,
        // Treat as DEAD only on ERROR_INVALID_PARAMETER (87) — the
        // "no such PID" signal. Every other error (ACCESS_DENIED,
        // transient low-memory, etc.) is uncertain → ALIVE, so we
        // never reap (and restore a file still used by) a holder
        // that's actually running.
        Err(e) => {
            return (e.code().0 as u32 & 0xFFFF) != 87;
        }
    };
    let h = crate::util::OwnedHandle(h);
    match process_create_time(h.raw()) {
        Ok(ct) => {
            ct == expected_create_filetime
                // An exited process whose handle is still held
                // elsewhere remains openable with the same
                // CreationTime — without this check it reads as
                // alive forever and is never reaped. Only
                // WAIT_OBJECT_0 (= signaled = exited) is "dead";
                // WAIT_TIMEOUT and WAIT_FAILED are both "alive"
                // (uncertain → ALIVE, matching the conservative
                // stance everywhere else in this function).
                && unsafe { WaitForSingleObject(h.raw(), 0) }
                    != WAIT_OBJECT_0
        }
        // Transient GetProcessTimes failure → uncertain → ALIVE,
        // matching the conservative stance everywhere else (better
        // a stale row than a live holder reaped and its files
        // restored under it).
        Err(_) => true,
    }
}

/// Creation FILETIME (as i64) of an arbitrary PID. Opens the
/// process for limited query; special-cases self to avoid needing
/// OpenProcess rights on our own token.
fn pid_create_time(pid: u32) -> Result<i64> {
    if pid == std::process::id() {
        return process_create_time(unsafe { GetCurrentProcess() });
    }
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .with_context(|| format!("OpenProcess({pid}) for create-time"))?;
    if h.is_invalid() {
        bail!("OpenProcess({pid}) returned invalid handle");
    }
    let h = crate::util::OwnedHandle(h);
    process_create_time(h.raw())
}

/// FILETIME (100-ns since 1601-01-01) → i64 for storage.
fn process_create_time(h: HANDLE) -> Result<i64> {
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(h, &mut create, &mut exit, &mut kernel, &mut user)
            .context("GetProcessTimes")?;
    }
    Ok(((create.dwHighDateTime as i64) << 32) | (create.dwLowDateTime as i64))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_dir_rejects_empty_or_relative() {
        use std::ffi::OsString;
        // Unset or empty → error (var_os returns Some("") for a
        // present-but-empty var, which the old code accepted).
        assert!(state_dir_from_base(None, "ProgramData").is_err());
        assert!(state_dir_from_base(Some(OsString::from("")), "ProgramData").is_err());
        // Relative → error (would put the broker-only-stamped DB
        // in CWD).
        assert!(state_dir_from_base(Some(OsString::from("rel")), "ProgramData").is_err());
        // Absolute → ok.
        let ok = state_dir_from_base(
            Some(OsString::from(r"C:\Users\u\AppData\Local")),
            "ProgramData",
        );
        assert_eq!(
            ok.unwrap(),
            PathBuf::from(r"C:\Users\u\AppData\Local\sandbox-runtime")
        );
    }

    /// Open an in-memory DB and run `f` against a `Locked` view
    /// (autocommit, like production). Skips the named mutex + dir
    /// stamp (those are integration-tested via the G-rows in
    /// smoke-exec.ps1).
    fn with_mem_db<R>(f: impl FnOnce(&mut Locked) -> R) -> R {
        let conn = open_db_at(
            std::path::Path::new(":memory:"),
            SESSION_SCHEMA_SQL,
            SESSION_SCHEMA_VERSION,
        )
        .unwrap();
        let mut db = Locked {
            conn,
            holder_pid: HolderPid(std::process::id()),
        };
        f(&mut db)
    }

    /// Regression: `register_broker` uses ON CONFLICT DO UPDATE,
    /// not INSERT OR REPLACE — the latter would CASCADE-delete
    /// this holder's existing `ace_holders` rows on a second
    /// stamp/grant.
    #[test]
    fn second_register_broker_keeps_existing_holds() {
        with_mem_db(|db| {
            db.register_broker().unwrap();
            // Two holds via direct INSERT (record_ace needs a real
            // file; the CASCADE behavior under test is pure SQL).
            for p in [r"\\?\C:\a", r"\\?\C:\b"] {
                db.conn
                    .execute(
                        "INSERT INTO ace_holders \
                         (canonical_path, kind, pid, want_mask) \
                         VALUES (?1, 'deny', ?2, 'denyRead')",
                        params![p, db.holder_pid.0 as i64],
                    )
                    .unwrap();
            }
            assert_eq!(db.my_ace_holds(None).unwrap().len(), 2);
            // Second batch by the same holder.
            db.register_broker().unwrap();
            // Holds intact (would be 0 with INSERT OR REPLACE).
            assert_eq!(db.my_ace_holds(None).unwrap().len(), 2);
        });
    }

    /// Exactly one converge per distinct path, placed at the path's
    /// final touch — so it sees every row the batch recorded there.
    #[test]
    fn last_touches_marks_one_final_touch_per_path() {
        assert_eq!(last_touches([]), Vec::<bool>::new());
        assert_eq!(last_touches(["a"]), [true]);
        // root touched three times (grant-root FDC from two denied
        // children + a placeholder): only the third converges it.
        assert_eq!(
            last_touches(["f1", "root", "f2", "root", "ph", "root"]),
            [true, false, true, false, true, true],
        );
        // Exact-string identity, as the DB keys paths.
        assert_eq!(last_touches(["A", "a", "A"]), [false, true, true]);
        for seq in [vec!["x", "y", "x", "z", "y", "x"], vec!["p"; 5]] {
            let last = last_touches(seq.iter().copied());
            let distinct: HashSet<&str> = seq.iter().copied().collect();
            assert_eq!(last.iter().filter(|l| **l).count(), distinct.len());
            for (i, p) in seq.iter().enumerate() {
                assert_eq!(last[i], !seq[i + 1..].contains(p), "step {i}");
            }
        }
    }

    /// Batch composition for the session-init shape: a root-level
    /// deny plus a deny under a placeholder directory. The root is
    /// touched twice (parent-FDC of the deny, parent-FDC of the
    /// placeholder) but is converged once, last — after every row
    /// destined for it has been recorded.
    #[test]
    fn plan_ace_ops_implies_parent_fdc_and_coalesces_root() {
        use acl::{DenyMask, GrantMask};
        let root = r"\\?\C:\proj";
        let p = |rel: &str| format!(r"{root}\{rel}");
        let deny = SbAce::Deny(DenyMask::WriteDeny);
        let targets = vec![
            (p(r".claude\settings.json"), deny),
            (p(".claude"), SbAce::DenyDelete),
            (p(".mcp.json"), deny),
            (root.to_string(), SbAce::Grant(GrantMask::Modify)),
        ];
        let plan = plan_ace_ops(&targets);
        let step = |canon: String, ace, implied_by| PlannedAce {
            canon,
            ace,
            implied_by,
        };
        assert_eq!(
            plan,
            [
                step(p(r".claude\settings.json"), deny, None),
                step(p(".claude"), SbAce::DenyFdc, Some(0)),
                step(p(".claude"), SbAce::DenyDelete, None),
                step(root.to_string(), SbAce::DenyFdc, Some(2)),
                step(p(".mcp.json"), deny, None),
                step(root.to_string(), SbAce::DenyFdc, Some(4)),
                // A grant implies no parent entry.
                step(root.to_string(), SbAce::Grant(GrantMask::Modify), None),
            ],
        );
        let last = last_touches(plan.iter().map(|op| op.canon.as_str()));
        assert_eq!(last, [true, false, true, false, true, false, true]);
        // A top-level deny target has no stampable parent.
        let top = plan_ace_ops(&[(r"\\?\C:\x".to_string(), deny)]);
        assert_eq!(top.len(), 1);
    }

    /// The completion record vouches for one (path, object, DACL)
    /// triple, is withdrawn by `begin`, and is not kept for a path
    /// left without sandbox ACEs.
    #[test]
    fn converged_ledger_records_only_completed_writes() {
        use acl::WriteLedger;
        with_mem_db(|db| {
            let id = |n: u8| FileId {
                volume_serial: 7,
                id128: [n; 16],
            };
            let ledger = |canon, n, keep| ConvergedLedger {
                conn: &db.conn,
                canon,
                file_id: Some(id(n)),
                keep,
                force_write: false,
            };
            let (a, b) = (r"\\?\C:\a", r"\\?\C:\b");
            let l = ledger(a, 1, true);
            assert!(!l.completed(b"X"), "no record yet");
            l.begin().unwrap();
            assert!(!l.completed(b"X"), "begun, not completed");
            l.complete(b"X");
            assert!(l.completed(b"X"));
            // Another DACL, another object at the path, another
            // path, or an unreadable identity: not completed.
            assert!(!l.completed(b"Y"));
            assert!(!ledger(a, 2, true).completed(b"X"));
            assert!(!ledger(b, 1, true).completed(b"X"));
            let blind = ConvergedLedger {
                file_id: None,
                ..ledger(a, 1, true)
            };
            assert!(!blind.completed(b"X"));
            // The next write withdraws it; killed before `complete`,
            // it stays withdrawn.
            l.begin().unwrap();
            assert!(!l.completed(b"X"));
            // A converge to "no sandbox ACEs" leaves no row behind.
            l.complete(b"X");
            let gone = ledger(a, 1, false);
            gone.begin().unwrap();
            gone.complete(b"Z");
            assert!(!gone.completed(b"Z") && !l.completed(b"X"));
            blind.complete(b"X");
            assert!(!l.completed(b"X"), "no identity → nothing recorded");
            let rows: i64 = db
                .conn
                .query_row("SELECT count(*) FROM converged_dacls", [], |r| r.get(0))
                .unwrap();
            assert_eq!(rows, 0);
        });
    }

    fn intents(db: &Locked) -> Vec<(String, Vec<u8>)> {
        query_vec(
            &db.conn,
            "SELECT canonical_path, file_id FROM write_intents \
             ORDER BY canonical_path, file_id",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    }

    /// Journal bookkeeping: the row appears at `begin`, survives
    /// until `complete`, is keyed by (path, object), and a forced
    /// ledger never reports completion.
    #[test]
    fn write_intent_brackets_the_write() {
        use acl::WriteLedger;
        with_mem_db(|db| {
            let id = |n: u8| FileId {
                volume_serial: 7,
                id128: [n; 16],
            };
            let ledger = |n, keep, force_write| ConvergedLedger {
                conn: &db.conn,
                canon: r"\\?\C:\a",
                file_id: Some(id(n)),
                keep,
                force_write,
            };
            assert!(intents(db).is_empty());
            // A release-to-empty write (`keep: false`): journaled all
            // the same — it is the case rows cannot cover.
            let l = ledger(1, false, false);
            l.begin().unwrap();
            l.begin().unwrap(); // idempotent
            assert_eq!(
                intents(db),
                [(r"\\?\C:\a".to_string(), id(1).as_bytes().to_vec())],
                "killed here → the intent is what recovery finds",
            );
            // Another object at the same path journals separately and
            // its completion does not retire the first row.
            let other = ledger(2, true, false);
            other.begin().unwrap();
            assert_eq!(intents(db).len(), 2);
            other.complete(b"X");
            assert_eq!(intents(db).len(), 1);
            l.complete(b"");
            assert!(intents(db).is_empty(), "write returned → row retired");
            // Forced: a matching completion record does not count.
            assert!(other.completed(b"X"));
            assert!(!ledger(2, true, true).completed(b"X"));
            // No identity → no journal row possible → no write.
            let blind = ConvergedLedger {
                file_id: None,
                ..ledger(1, true, false)
            };
            assert!(blind.begin().is_err());
        });
    }

    /// Recovery over real paths: a surviving intent on a live
    /// directory is re-converged from the (empty) rows — stripping
    /// the sandbox ACE a killed release left — and retired; an intent
    /// whose path is gone or substituted is dropped untouched; a
    /// second pass finds nothing.
    #[test]
    fn recover_write_intents_finishes_a_killed_release() {
        const FAKE_SB_SID: &str = "S-1-5-32-546";
        let dir = std::env::temp_dir().join(format!("srtwin-intent-{}", std::process::id()));
        let (live, swapped) = (dir.join("live"), dir.join("swapped"));
        std::fs::create_dir_all(&live).unwrap();
        std::fs::create_dir_all(&swapped).unwrap();
        let canon =
            |p: &std::path::Path| path_id::canonicalize_path(p.to_str().unwrap()).unwrap().0;
        let (live, swapped) = (canon(&live), canon(&swapped));
        let gone = format!(r"{live}\never-existed");
        let grant = acl::SbAceSet {
            grant: Some(acl::GrantMask::Modify),
            ..Default::default()
        };
        // The killed release's residue: ACE on disk, no row.
        acl::apply_sandbox_aces(&live, FAKE_SB_SID, grant).unwrap();
        acl::apply_sandbox_aces(&swapped, FAKE_SB_SID, grant).unwrap();
        let sid = crate::sid::sid_bytes(FAKE_SB_SID).unwrap();
        // Any EXPLICIT ACE for the stand-in sandbox SID on `p`.
        let has_ace = |p: &str| {
            let (_sd, dacl) = acl::read_file_dacl(p).unwrap();
            let (explicit, ..) = acl::filter_aces(dacl, |hdr, body| {
                hdr.AceFlags & 0x10 == 0 && acl::ace_sid_is(body, &sid)
            })
            .unwrap();
            !explicit.is_empty()
        };
        assert!(has_ace(&live) && has_ace(&swapped));
        with_mem_db(|db| {
            let live_id = path_id::capture_file_id(&live).unwrap();
            record_write_intent(&db.conn, &live, &live_id).unwrap();
            // `swapped` journaled under another object's identity;
            // `gone` does not exist.
            record_write_intent(&db.conn, &swapped, &live_id).unwrap();
            record_write_intent(&db.conn, &gone, &live_id).unwrap();

            let mut report = RecoveryReport::default();
            recover_write_intents(&db.conn, FAKE_SB_SID, false, &mut report).unwrap();
            assert_eq!((report.writes_resumed, report.writes_pending), (1, 0));
            assert!(intents(db).is_empty());
            assert!(!has_ace(&live), "interrupted release finished");
            assert!(has_ace(&swapped), "substituted path not touched");

            let mut again = RecoveryReport::default();
            recover_write_intents(&db.conn, FAKE_SB_SID, false, &mut again).unwrap();
            assert_eq!((again.writes_resumed, again.writes_pending), (0, 0));
        });
        acl::apply_sandbox_aces(&swapped, FAKE_SB_SID, acl::SbAceSet::default()).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn schema_applies_in_memory() {
        // Session schema: bookkeeping tables only — the setup
        // record lives in the MACHINE schema since the store split.
        with_mem_db(|db| {
            let n: i64 = db
                .conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' \
                     AND name IN ('brokers','working_aces','ace_holders', \
                                  'placeholders','converged_dacls', \
                                  'write_intents','sandbox_user')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                n, 6,
                "session schema: 6 bookkeeping tables, no sandbox_user"
            );
        });
    }

    #[test]
    fn aliveness_self_is_alive() {
        let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
        assert!(is_process_alive(std::process::id(), ct));
        // Same PID, wrong create time would normally be "recycled →
        // dead", but we special-case ourselves.
        assert!(is_process_alive(std::process::id(), ct + 1));
    }

    #[test]
    fn aliveness_bogus_pid_is_dead() {
        // PID 0x7FFF_FFFE is well above any plausible live PID.
        assert!(!is_process_alive(0x7FFF_FFFE, 0));
    }
}
