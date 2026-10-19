//! Write grants kept between sessions, for the write-restricted token.
//!
//! Each write root gets its own capability SID,
//! `S-1-0-1936880739-<a>-<b>-<c>-<d>` (128 random bits; no account can
//! hold it), and its ACEs ([`crate::acl::persistent_aces`]) allow
//! writing only to a token with that SID among its restricting SIDs.
//!
//! A marker under `HKCU\Software\sandbox-runtime\PersistentGrants`
//! lists every root that may carry a grant: added before the first ACE
//! is written, removed only after the ACEs are. While it or the session
//! database lists a root, nothing may run the sandbox account under
//! the ordinary token ([`unrestricted_block_reason`]).

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};

use crate::acl::{self, AceView, PersistentTrustees, PersistentWant, SbAce};
use crate::path_id::{self, FileId, Located};
use crate::reg;
use crate::state_db::Locked;

// ─── Capability SIDs ────────────────────────────────────────────────

/// First sub-authority of every capability SID: ASCII `"srtc"`.
const CAPABILITY_TAG: u32 = 0x7372_7463;

/// What every capability SID starts with — see the module doc.
pub const CAPABILITY_SID_PREFIX: &str = "S-1-0-1936880739-";

/// The capability SID made of `random` (four little-endian `u32`s).
pub fn capability_sid_from(random: [u8; 16]) -> String {
    let mut s = format!("S-1-0-{CAPABILITY_TAG}");
    for c in random.as_chunks::<4>().0 {
        s.push_str(&format!("-{}", u32::from_le_bytes(*c)));
    }
    s
}

/// A fresh capability SID from the system CSPRNG. An RNG failure is
/// an error, never a predictable SID.
pub fn new_capability_sid() -> Result<String> {
    let mut r = [0u8; 16];
    unsafe { BCryptGenRandom(None, &mut r, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
        .ok()
        .context("BCryptGenRandom (capability SID)")?;
    Ok(capability_sid_from(r))
}

/// Whether `sid` is a capability SID in its canonical spelling: the
/// prefix and exactly four decimal `u32` sub-authorities.
pub fn is_capability_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix(CAPABILITY_SID_PREFIX) else {
        return false;
    };
    let mut n = 0;
    rest.split('-').all(|p| {
        n += 1;
        p.parse::<u32>().is_ok_and(|v| v.to_string() == p)
    }) && n == 4
}

// ─── Marker ─────────────────────────────────────────────────────────

const MARKER_KEY: &str = r"Software\sandbox-runtime\PersistentGrants";
const MARKER_ROOTS: &str = "Roots";
const MARKER_EVER: &str = "EverEnabled";

/// One root in the marker: where it was granted and which object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerRoot {
    pub file_id: FileId,
    pub path: String,
}

impl MarkerRoot {
    /// `<48 hex digits of the file id>|<canonical path>`.
    pub fn encode(&self) -> String {
        let hex: String = self
            .file_id
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{hex}|{}", self.path)
    }

    pub fn decode(s: &str) -> Result<Self> {
        let (hex, path) = s
            .split_once('|')
            .filter(|(h, p)| h.len() == 48 && h.is_ascii() && !p.is_empty())
            .ok_or_else(|| anyhow!("malformed persistent-grant marker entry '{s}'"))?;
        let bytes = (0..24)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .with_context(|| format!("malformed persistent-grant marker entry '{s}'"))?;
        Ok(Self {
            file_id: FileId::from_bytes(&bytes)?,
            path: path.to_owned(),
        })
    }
}

/// The marker as read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Marker {
    /// A persistent grant was made at some point and `acl forget
    /// --all` has not completed since.
    pub ever_enabled: bool,
    pub roots: Vec<MarkerRoot>,
}

/// Read the marker. An absent key is the empty marker; anything that
/// cannot be read or parsed is an error, which callers treat as
/// "grants may exist".
pub fn read_marker() -> Result<Marker> {
    let Some(key) = reg::Key::open_hkcu(MARKER_KEY, false)? else {
        return Ok(Marker::default());
    };
    let roots = key
        .get_multi_sz(MARKER_ROOTS)?
        .unwrap_or_default()
        .iter()
        .map(|s| MarkerRoot::decode(s))
        .collect::<Result<_>>()?;
    Ok(Marker {
        ever_enabled: key.get_dword(MARKER_EVER)?.unwrap_or(0) != 0,
        roots,
    })
}

fn write_marker_roots(roots: &[MarkerRoot]) -> Result<()> {
    let key = reg::Key::create_hkcu(MARKER_KEY)?;
    let encoded: Vec<String> = roots.iter().map(MarkerRoot::encode).collect();
    key.set_multi_sz(MARKER_ROOTS, &encoded)
}

/// List `path` (object `file_id`) in the marker, replacing an entry
/// for the same path. `EverEnabled` is set first.
fn marker_add(path: &str, file_id: FileId) -> Result<()> {
    let mut m = read_marker()?;
    reg::Key::create_hkcu(MARKER_KEY)?.set_dword(MARKER_EVER, 1)?;
    let entry = MarkerRoot {
        file_id,
        path: path.to_owned(),
    };
    if m.roots.contains(&entry) {
        return Ok(());
    }
    m.roots.retain(|r| r.path != path);
    m.roots.push(entry);
    write_marker_roots(&m.roots)
}

fn marker_remove(path: &str) -> Result<()> {
    let mut m = read_marker()?;
    if m.roots.iter().any(|r| r.path == path) {
        m.roots.retain(|r| r.path != path);
        write_marker_roots(&m.roots)?;
    }
    Ok(())
}

// ─── Running without the write-restricted token ─────────────────────

/// Root paths the session database records, or `None` if it is
/// missing, unreadable, or has no such table.
fn db_roots_ro() -> Option<Vec<String>> {
    let conn = crate::state_db::open_db_ro().ok()??;
    all_root_paths(&conn).ok()
}

/// Why a command must not run the sandbox account WITHOUT the
/// write-restricted token now; `None` when it may. "Nothing recorded"
/// is accepted only from a store that is there to be read.
pub fn unrestricted_block_reason() -> Option<String> {
    block_reason_from(read_marker(), db_roots_ro)
}

/// [`unrestricted_block_reason`] on what was read: `marker` as
/// [`read_marker`] returned it, `db_roots` as [`db_roots_ro`] does.
/// Every "could not read" refuses.
fn block_reason_from(
    marker: Result<Marker>,
    db_roots: impl FnOnce() -> Option<Vec<String>>,
) -> Option<String> {
    let m = match marker {
        Ok(m) => m,
        Err(e) => {
            return Some(format!(
                "the persistent-grant marker cannot be read ({e:#})"
            ));
        }
    };
    if let Some(r) = m.roots.first() {
        return Some(format!(
            "{} persistent write grant(s) exist (e.g. '{}')",
            m.roots.len(),
            r.path
        ));
    }
    if !m.ever_enabled {
        return None;
    }
    match db_roots() {
        Some(v) if v.is_empty() => None,
        Some(v) => Some(format!(
            "the state database records {} persistent write grant(s) (e.g. '{}')",
            v.len(),
            v[0]
        )),
        None => Some(
            "persistent write grants were made and the state database is missing or \
             unreadable, so where they are cannot be established"
                .to_owned(),
        ),
    }
}

/// `{state, roots, reason?}` for `srt-win user status`: `none` when
/// the ordinary token may be used, `present` when the marker lists
/// roots, `unknown` otherwise.
pub fn status_json() -> serde_json::Value {
    let roots: Vec<String> = read_marker()
        .map(|m| m.roots.into_iter().map(|r| r.path).collect())
        .unwrap_or_default();
    match unrestricted_block_reason() {
        None => serde_json::json!({ "state": "none", "roots": roots }),
        Some(reason) => serde_json::json!({
            "state": if roots.is_empty() { "unknown" } else { "present" },
            "roots": roots,
            "reason": reason,
        }),
    }
}

// ─── Identities ─────────────────────────────────────────────────────

/// The SIDs persistent ACEs are written for.
#[derive(Debug, Clone)]
pub struct Ids {
    /// From the install record (administrator-written). `None` when
    /// nothing is installed: grants cannot be made, and `forget` can
    /// no longer tell the group's ACEs apart.
    pub group_sid: Option<String>,
    pub sandbox_user_sid: Option<String>,
    pub real_user_sid: String,
}

impl Ids {
    pub fn load() -> Result<Self> {
        let setup = crate::install::read_setup()?;
        Ok(Self {
            group_sid: setup.as_ref().map(|s| s.sandbox_group_sid.clone()),
            sandbox_user_sid: setup.map(|s| s.sandbox_user_sid),
            real_user_sid: crate::sid::current_user_sid()?,
        })
    }

    fn trustees(&self) -> PersistentTrustees<'_> {
        PersistentTrustees {
            group_sid: self.group_sid.as_deref(),
            real_user_sid: &self.real_user_sid,
        }
    }
}

// ─── Rows ───────────────────────────────────────────────────────────

fn all_root_paths(conn: &Connection) -> Result<Vec<String>> {
    let mut s = conn.prepare("SELECT canonical_path FROM persistent_roots")?;
    let rows = s.query_map([], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn root_row(conn: &Connection, canon: &str) -> Result<Option<(FileId, String)>> {
    let row: Option<(Vec<u8>, String)> = conn
        .query_row(
            "SELECT file_id, capability_sid FROM persistent_roots \
             WHERE canonical_path = ?1",
            params![canon],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .context("SELECT persistent_roots")?;
    row.map(|(id, sid)| Ok((FileId::from_bytes(&id)?, sid)))
        .transpose()
}

/// The longest of `roots` that is `canon` or a directory above it.
pub fn covering_root<'a>(roots: &'a [String], canon: &str) -> Option<&'a str> {
    roots
        .iter()
        .map(String::as_str)
        .filter(|r| {
            canon == *r
                || (canon.starts_with(r)
                    && (r.ends_with('\\') || canon.as_bytes().get(r.len()) == Some(&b'\\')))
        })
        .max_by_key(|r| r.len())
}

/// The ACEs `canon` (now the object `cur`) is to carry, from the
/// rows. A row recorded for a different object at this path is not
/// applied to the one that is there now.
fn wanted(conn: &Connection, ids: &Ids, canon: &str, cur: FileId) -> Result<Vec<AceView>> {
    let cap = root_row(conn, canon)?
        .filter(|(id, _)| *id == cur)
        .map(|(_, sid)| sid);
    let mut s = conn.prepare_cached(
        "SELECT kind, mask, file_id FROM persistent_denies WHERE canonical_path = ?1",
    )?;
    let rows = s.query_map(params![canon], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let (mut deny, mut deny_fdc, mut deny_delete) = (None, false, false);
    for row in rows {
        let (kind, mask, id) = row?;
        if FileId::from_bytes(&id)? != cur {
            continue;
        }
        match SbAce::parse(&kind, &mask)? {
            SbAce::Deny(d) => deny = Some(d),
            SbAce::DenyFdc => deny_fdc = true,
            SbAce::DenyDelete => deny_delete = true,
            SbAce::Grant(_) => bail!("persistent_denies holds a grant row for '{canon}'"),
        }
    }
    if cap.is_none() && deny.is_none() && !deny_fdc && !deny_delete {
        return Ok(Vec::new());
    }
    let group_sid = ids.group_sid.as_deref().ok_or_else(|| {
        anyhow!("no install record: the sandbox group SID is unknown — run `srt-win install`")
    })?;
    Ok(acl::persistent_aces(&PersistentWant {
        group_sid,
        real_user_sid: &ids.real_user_sid,
        capability_sid: cap.as_deref(),
        deny,
        deny_fdc,
        deny_delete,
    }))
}

/// The wanted ACE list as the text a write record stores.
fn spec_of(want: &[AceView]) -> String {
    want.iter().map(AceView::sddl).collect()
}

// ─── Converge ───────────────────────────────────────────────────────

/// Bring `canon`'s persistent ACEs to what the rows say; returns
/// whether it wrote. The write is skipped only when the ACEs on disk
/// match AND the write record says that exact write completed.
fn converge(conn: &Connection, ids: &Ids, canon: &str) -> Result<bool> {
    let (cur, _links, is_dir) = path_id::capture_id_and_links(canon)?;
    let want = wanted(conn, ids, canon, cur)?;
    let aces = acl::read_aces(canon).with_context(|| format!("read the DACL of '{canon}'"))?;
    let is_root = want.iter().any(|a| is_capability_sid(&a.sid));
    if is_root {
        // An ALLOW for the sandbox user SID would pass both access
        // checks of every session's token.
        if let Some(sb) = &ids.sandbox_user_sid
            && acl::allows_more_than_read(&aces, sb)
        {
            bail!(
                "'{canon}' grants write access to the sandbox user SID (a session without \
                 the write-restricted token holds it); refusing to keep a persistent grant \
                 beside it"
            );
        }
        for ace in acl::owner_write_paths(&aces) {
            eprintln!(
                "srt-win: WARNING: '{canon}' carries {ace}: files the sandbox creates under \
                 it stay writable to sessions of other projects"
            );
        }
    }
    let t = ids.trustees();
    let spec = spec_of(&want);
    let record: Option<(Vec<u8>, String, i64)> = conn
        .query_row(
            "SELECT file_id, spec, done FROM persistent_writes WHERE canonical_path = ?1",
            params![canon],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .context("SELECT persistent_writes")?;
    let same = acl::persistent_on_disk(&aces, &t, is_dir) == acl::comparable(&want, is_dir);
    // Settled: no write is outstanding for this path, and (with ACEs
    // wanted) a write of exactly this list completed on this object.
    let settled = match &record {
        None => want.is_empty(),
        Some((id, s, done)) => {
            *done == 1 && (want.is_empty() || (*s == spec && id.as_slice() == cur.as_bytes()))
        }
    };
    if same && settled {
        if want.is_empty() {
            conn.execute(
                "DELETE FROM persistent_writes WHERE canonical_path = ?1",
                params![canon],
            )?;
        }
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO persistent_writes (canonical_path, file_id, spec, done) \
         VALUES (?1, ?2, ?3, 0) \
         ON CONFLICT(canonical_path) DO UPDATE SET \
           file_id = excluded.file_id, spec = excluded.spec, done = 0",
        params![canon, cur.as_bytes().as_slice(), spec],
    )
    .context("record persistent write intent")?;
    acl::write_persistent_aces(canon, &t, &want)?;
    if want.is_empty() {
        conn.execute(
            "DELETE FROM persistent_writes WHERE canonical_path = ?1",
            params![canon],
        )
    } else {
        conn.execute(
            "UPDATE persistent_writes SET done = 1 WHERE canonical_path = ?1",
            params![canon],
        )
    }
    .context("record persistent write completion")?;
    if std::env::var_os("SANDBOX_RUNTIME_WIN_DEBUG").is_some() {
        eprintln!(
            "srt-win: persistent DACL write '{canon}' ({} ACE(s))",
            want.len()
        );
    }
    Ok(true)
}

/// Crash recovery: finish every DACL write whose record was left at
/// `done = 0`. A record whose path is gone or names another object is
/// dropped; a failure is logged and the record kept.
pub(crate) fn replay_pending(conn: &Connection) {
    let read = || -> Result<Vec<(String, Vec<u8>)>> {
        let mut s =
            conn.prepare("SELECT canonical_path, file_id FROM persistent_writes WHERE done = 0")?;
        let rows = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    };
    let pending = match read() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("srt-win: WARNING: reading pending persistent writes: {e:#}");
            return;
        }
    };
    if pending.is_empty() {
        return;
    }
    let ids = match Ids::load() {
        Ok(ids) => ids,
        Err(e) => {
            eprintln!("srt-win: WARNING: pending persistent writes not replayed: {e:#}");
            return;
        }
    };
    for (canon, id) in pending {
        let stale = match path_id::capture_file_id(&canon) {
            Ok(cur) => cur.as_bytes().as_slice() != id.as_slice(),
            Err(e) => path_id::is_not_found(&e),
        };
        let r = if stale {
            conn.execute(
                "DELETE FROM persistent_writes WHERE canonical_path = ?1",
                params![canon],
            )
            .map(|_| ())
            .map_err(anyhow::Error::from)
        } else {
            converge(conn, &ids, &canon).map(|_| ())
        };
        if let Err(e) = r {
            eprintln!("srt-win: WARNING: replay persistent write '{canon}': {e:#}");
        }
    }
}

// ─── Grant ──────────────────────────────────────────────────────────

/// Outcome of [`apply`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    pub roots: usize,
    /// Paths whose DACL was written.
    pub writes: usize,
    /// Paths found as wanted and left alone.
    pub unchanged: usize,
}

/// Make sure `canon` has a capability SID recorded for the object
/// that is there now, and that the marker lists it.
fn record_root(conn: &Connection, ids: &Ids, canon: &str) -> Result<()> {
    let cur = path_id::capture_file_id(canon)?;
    match root_row(conn, canon)? {
        Some((id, sid)) if id == cur => {
            if !is_capability_sid(&sid) {
                bail!("the state database holds '{sid}' as the capability SID of '{canon}'");
            }
        }
        prior => {
            if prior.is_some() {
                // The path names another object than the one granted:
                // take the grant off that one first.
                forget_one(conn, ids, canon)?;
            }
            let sid = new_capability_sid()?;
            conn.execute(
                "INSERT INTO persistent_roots (canonical_path, file_id, capability_sid) \
                 VALUES (?1, ?2, ?3)",
                params![canon, cur.as_bytes().as_slice(), sid],
            )
            .with_context(|| format!("store the capability SID of '{canon}'"))?;
        }
    }
    // Before any ACE is written — see the module doc.
    marker_add(canon, cur).with_context(|| format!("list '{canon}' in the persistent-grant marker"))
}

fn record_deny(conn: &Connection, canon: &str, ace: SbAce, root: &str) -> Result<()> {
    let id = path_id::capture_file_id(canon)?;
    let prior: Option<(String, Vec<u8>)> = conn
        .query_row(
            "SELECT mask, file_id FROM persistent_denies \
             WHERE canonical_path = ?1 AND kind = ?2",
            params![canon, ace.kind()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .context("SELECT persistent_denies")?;
    // Never narrowed while the object is the same: a deny stays as
    // wide as any session asked for until the root is forgotten.
    let eff = match prior {
        Some((mask, old)) if old.as_slice() == id.as_bytes() => {
            SbAce::parse(ace.kind(), &mask)?.max(ace)
        }
        _ => ace,
    };
    conn.execute(
        "INSERT INTO persistent_denies (canonical_path, kind, file_id, mask, root) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(canonical_path, kind) DO UPDATE SET \
           file_id = excluded.file_id, mask = excluded.mask, root = excluded.root",
        params![
            canon,
            ace.kind(),
            id.as_bytes().as_slice(),
            eff.as_str(),
            root
        ],
    )
    .context("UPSERT persistent_denies")?;
    Ok(())
}

/// Session start with the write-restricted token: record `roots` and
/// the deny targets under them, then converge every path, roots
/// first. Deny targets under no root are returned for per-session use.
pub fn apply(
    db: &Locked,
    ids: &Ids,
    roots: &[String],
    denies: &[(String, SbAce)],
) -> Result<(Applied, Vec<(String, SbAce)>)> {
    let conn = db.conn();
    if ids.group_sid.is_none() {
        bail!("no install record: run `srt-win install`");
    }
    let mut touched: Vec<String> = Vec::new();
    let mut touch = |p: &str| {
        if !touched.iter().any(|t| t == p) {
            touched.push(p.to_owned());
        }
    };
    for root in roots {
        record_root(conn, ids, root)?;
        touch(root);
    }
    let all_roots = all_root_paths(conn)?;
    let mut per_session = Vec::new();
    for (canon, ace) in denies {
        let Some(root) = covering_root(&all_roots, canon) else {
            per_session.push((canon.clone(), *ace));
            continue;
        };
        record_deny(conn, canon, *ace, root)?;
        touch(canon);
        if matches!(ace, SbAce::Deny(_) | SbAce::DenyDelete)
            && let Some(parent) = path_id::canonical_parent_of(canon)
        {
            record_deny(conn, &parent, SbAce::DenyFdc, root)?;
            touch(&parent);
        }
    }
    let mut out = Applied {
        roots: roots.len(),
        ..Default::default()
    };
    for p in &touched {
        if converge(conn, ids, p).with_context(|| format!("persistent grant '{p}'"))? {
            out.writes += 1;
        } else {
            out.unchanged += 1;
        }
    }
    Ok((out, per_session))
}

/// The capability SIDs of `roots`, for the child token. A root with
/// none recorded for the object now at its path is an error: the
/// command must not run with a shorter list than asked.
pub fn capability_sids_for(roots: &[String]) -> Result<Vec<String>> {
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let conn = crate::state_db::open_db_ro()?
        .ok_or_else(|| anyhow!("the state database is missing or unreadable"))?;
    let mut out = Vec::with_capacity(roots.len());
    for raw in roots {
        let (canon, _) =
            path_id::canonicalize_path(raw).map_err(|e| anyhow!("write root '{raw}': {e}"))?;
        let cur = path_id::capture_file_id(&canon)?;
        match root_row(&conn, &canon)? {
            Some((id, sid)) if id == cur && is_capability_sid(&sid) => {
                if !out.contains(&sid) {
                    out.push(sid);
                }
            }
            _ => bail!(
                "write root '{canon}' has no persistent grant recorded for it — \
                 `srt-win acl grant --persistent` it first"
            ),
        }
    }
    Ok(out)
}

// ─── Forget ─────────────────────────────────────────────────────────

/// Per-root outcome of [`forget`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Forgot {
    /// Persistent ACEs were on disk and were removed.
    Removed,
    /// Nothing was on disk; the records are gone.
    Absent,
    /// Could not be completed; the root stays recorded.
    Failed(String),
}

impl Forgot {
    pub fn as_str(&self) -> &'static str {
        match self {
            Forgot::Removed => "removed",
            Forgot::Absent => "absent",
            Forgot::Failed(_) => "failed",
        }
    }
}

/// Remove `canon`'s persistent grant; returns whether any ACE was on
/// disk. The rows are deleted only after every DACL write succeeded,
/// and an object that cannot be located fails the call.
fn forget_one(conn: &Connection, ids: &Ids, canon: &str) -> Result<bool> {
    let here = match path_id::capture_file_id(canon) {
        Ok(id) => Some(id),
        Err(e) if path_id::is_not_found(&e) => None,
        Err(e) => return Err(e.context(format!("open '{canon}'"))),
    };
    // Every object the grant may have been written on.
    let mut granted: Vec<FileId> = Vec::new();
    granted.extend(root_row(conn, canon)?.map(|(id, _)| id));
    for r in read_marker()?.roots {
        if r.path == canon && !granted.contains(&r.file_id) {
            granted.push(r.file_id);
        }
    }
    let tx = conn.unchecked_transaction().context("begin forget tx")?;
    let denies: Vec<String> = {
        let mut s =
            tx.prepare("SELECT DISTINCT canonical_path FROM persistent_denies WHERE root = ?1")?;
        let rows = s.query_map(params![canon], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    tx.execute(
        "DELETE FROM persistent_denies WHERE root = ?1",
        params![canon],
    )?;
    tx.execute(
        "DELETE FROM persistent_roots WHERE canonical_path = ?1",
        params![canon],
    )?;
    // With the rows gone, converging a path strips it (or leaves
    // what another root still records for it).
    let mut removed = false;
    if here.is_some() {
        removed |= converge(&tx, ids, canon)?;
    }
    for id in granted.iter().filter(|id| Some(**id) != here) {
        match path_id::locate_by_file_id(id) {
            Located::At(moved) => removed |= converge(&tx, ids, &moved)?,
            Located::Gone => {}
            Located::Unknown => bail!(
                "the object '{canon}' was granted on is no longer at that path and could \
                 not be located by file id; its ACEs may still be on disk"
            ),
        }
    }
    for d in &denies {
        match path_id::capture_file_id(d) {
            Ok(_) => removed |= converge(&tx, ids, d)?,
            Err(e) if path_id::is_not_found(&e) => {}
            Err(e) => return Err(e.context(format!("open '{d}'"))),
        }
    }
    tx.commit().context("commit forget")?;
    marker_remove(canon)?;
    Ok(removed)
}

/// `acl forget`: remove the persistent grants of `roots`, or with
/// `all` of every root the marker or the database lists; then the
/// marker's `EverEnabled` is cleared once no root is left listed.
pub fn forget(
    db: &Locked,
    ids: &Ids,
    roots: &[String],
    all: bool,
) -> Result<Vec<(String, Forgot)>> {
    let conn = db.conn();
    let mut targets: Vec<String> = roots.to_vec();
    if all {
        targets.extend(read_marker()?.roots.into_iter().map(|r| r.path));
        targets.extend(all_root_paths(conn)?);
    }
    let mut seen = std::collections::HashSet::new();
    targets.retain(|t| seen.insert(t.clone()));
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        let r = match forget_one(conn, ids, &t) {
            Ok(true) => Forgot::Removed,
            Ok(false) => Forgot::Absent,
            Err(e) => {
                eprintln!("srt-win: forget '{t}': {e:#}");
                Forgot::Failed(format!("{e:#}"))
            }
        };
        out.push((t, r));
    }
    if all
        && read_marker()?.roots.is_empty()
        && all_root_paths(conn)?.is_empty()
        && let Some(key) = reg::Key::open_hkcu(MARKER_KEY, true)?
    {
        reg::delete_value(&key, MARKER_EVER)?;
    }
    Ok(out)
}

/// `srt-win uninstall`: forget every persistent grant of the calling
/// user. Does nothing — and creates no state — when none was ever
/// made. Returns how many roots were processed and how many failed.
pub fn forget_everything() -> Result<(usize, usize)> {
    if read_marker().is_ok_and(|m| m == Marker::default()) {
        return Ok((0, 0));
    }
    let ids = Ids::load()?;
    let holder = crate::state_db::HolderPid(std::process::id());
    let (out, _) =
        crate::state_db::with_init_lock(holder, false, |db| forget(db, &ids, &[], true))?;
    let failed = out
        .iter()
        .filter(|(_, r)| matches!(r, Forgot::Failed(_)))
        .count();
    Ok((out.len(), failed))
}

/// For `acl grant` without `--persistent`: refuse while a persistent
/// grant is recorded or a target's DACL cannot be read, and remove a
/// persistent ALLOW found on a target's own DACL (inherited: refuse).
pub fn clear_for_unrestricted_grant(db: &Locked, targets: &[String]) -> Result<()> {
    if let Some(why) = unrestricted_block_reason() {
        bail!(
            "{why}; grants for the ordinary token are refused until `srt-win acl forget \
             --all` has removed them"
        );
    }
    let ids = Ids::load()?;
    for canon in targets {
        match unrecorded_grant_on(acl::read_aces(canon), ids.group_sid.as_deref()) {
            Ok(UnrecordedGrant::None) => {}
            Ok(UnrecordedGrant::Own) => {
                eprintln!("srt-win: '{canon}' carries an unrecorded persistent grant; removing it");
                forget_one(db.conn(), &ids, canon)
                    .with_context(|| format!("remove the persistent grant on '{canon}'"))?;
            }
            Ok(UnrecordedGrant::Inherited) => bail!(
                "'{canon}' inherits a persistent write grant from a directory above it that \
                 is no longer recorded; run `srt-win acl forget <that directory>`"
            ),
            Err(e) => bail!(
                "the access list of '{canon}' cannot be read ({e:#}), so a persistent write \
                 grant on it cannot be ruled out; grants for the ordinary token are refused"
            ),
        }
    }
    Ok(())
}

/// A persistent ALLOW found on a path that no record lists.
#[derive(Debug, PartialEq, Eq)]
enum UnrecordedGrant {
    None,
    /// Written on the path itself: `forget_one` can remove it.
    Own,
    /// Inherited from a directory above: not removable from here.
    Inherited,
}

/// What `aces` (a path's own DACL) says about a persistent ALLOW. A
/// DACL that could not be read is an error, never
/// [`UnrecordedGrant::None`].
fn unrecorded_grant_on(
    aces: Result<Vec<AceView>>,
    group_sid: Option<&str>,
) -> Result<UnrecordedGrant> {
    let aces = aces?;
    let mut grants = aces
        .iter()
        .filter(|a| !a.deny && (group_sid == Some(a.sid.as_str()) || is_capability_sid(&a.sid)))
        .peekable();
    if grants.peek().is_none() {
        return Ok(UnrecordedGrant::None);
    }
    Ok(if grants.any(|a| a.inherited) {
        UnrecordedGrant::Inherited
    } else {
        UnrecordedGrant::Own
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_sid_format() {
        let sid = capability_sid_from([
            1, 0, 0, 0, // 1
            0, 1, 0, 0, // 256
            0xff, 0xff, 0xff, 0xff, // u32::MAX
            0, 0, 0, 0, // 0
        ]);
        assert_eq!(sid, "S-1-0-1936880739-1-256-4294967295-0");
        assert!(sid.starts_with(CAPABILITY_SID_PREFIX));
        assert_eq!(CAPABILITY_TAG.to_be_bytes(), *b"srtc");
        assert!(is_capability_sid(&sid));
        let p = crate::sid::LocalPsid::from_string(&sid).unwrap();
        let b = p.as_bytes();
        assert_eq!((b[0], b[1]), (1, 5));
        assert_eq!(b[2..8], [0u8; 6]);
        assert_eq!(crate::sid::psid_to_string(p.as_psid()).unwrap(), sid);
        assert_eq!(acl::sid_string_from_bytes(b).as_deref(), Some(sid.as_str()));
    }

    #[test]
    fn generated_capability_sids_are_valid_and_distinct() {
        let a = new_capability_sid().unwrap();
        let b = new_capability_sid().unwrap();
        assert!(is_capability_sid(&a), "{a}");
        assert!(is_capability_sid(&b), "{b}");
        assert_ne!(a, b);
    }

    #[test]
    fn only_the_exact_layout_is_a_capability_sid() {
        for not in [
            "S-1-0-0",                           // Nobody
            "S-1-1-0",                           // Everyone
            "S-1-5-12",                          // RESTRICTED
            "S-1-3-4",                           // OWNER RIGHTS
            "S-1-5-32-545",                      // BUILTIN\Users
            "S-1-5-21-1-2-3-1001",               // an account
            "S-1-15-3-1024-1-2-3-4-5-6-7-8",     // a package capability
            "S-1-0-1936880739-1-2-3",            // three random parts
            "S-1-0-1936880739-1-2-3-4-5",        // five
            "S-1-0-1936880739-1-2-3-4294967296", // not a u32
            "S-1-0-1936880739-01-2-3-4",         // not canonical
            "S-1-0-1936880739-1-2-3-",           // empty part
            "S-1-0-1936880738-1-2-3-4",          // another tag
            "S-1-5-1936880739-1-2-3-4",          // another authority
            "s-1-0-1936880739-1-2-3-4",          // not canonical
            "",
        ] {
            assert!(!is_capability_sid(not), "{not}");
        }
        assert!(is_capability_sid("S-1-0-1936880739-1-2-3-4"));
    }

    #[test]
    fn marker_entry_round_trips() {
        let r = MarkerRoot {
            file_id: FileId {
                volume_serial: 0x0123_4567_89ab_cdef,
                id128: *b"0123456789abcdef",
            },
            path: r"\\?\C:\work\a|b".to_owned(),
        };
        let s = r.encode();
        assert_eq!(s.find('|'), Some(48));
        assert_eq!(MarkerRoot::decode(&s).unwrap(), r);
        for bad in ["", "|x", "zz|x", &s[1..], &s[..49]] {
            assert!(MarkerRoot::decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn covering_root_is_the_longest_ancestor() {
        let roots = vec![
            r"\\?\C:\a".to_owned(),
            r"\\?\C:\a\b".to_owned(),
            r"\\?\D:\".to_owned(),
        ];
        let c = |p: &str| covering_root(&roots, p);
        assert_eq!(c(r"\\?\C:\a"), Some(r"\\?\C:\a"));
        assert_eq!(c(r"\\?\C:\a\x"), Some(r"\\?\C:\a"));
        assert_eq!(c(r"\\?\C:\a\b\x\y"), Some(r"\\?\C:\a\b"));
        assert_eq!(c(r"\\?\D:\x"), Some(r"\\?\D:\"));
        // A sibling whose name merely starts with a root's name.
        assert_eq!(c(r"\\?\C:\ab"), None);
        assert_eq!(c(r"\\?\C:\"), None);
    }

    fn marker_with(ever_enabled: bool, roots: &[&str]) -> Marker {
        Marker {
            ever_enabled,
            roots: roots
                .iter()
                .map(|p| MarkerRoot {
                    file_id: FileId::from_bytes(&[0u8; 24]).unwrap(),
                    path: (*p).to_owned(),
                })
                .collect(),
        }
    }

    /// Every store that could not be read refuses the ordinary token.
    #[test]
    fn ordinary_token_is_refused_on_any_read_failure() {
        let no_db = || -> Option<Vec<String>> { panic!("database consulted") };
        assert_eq!(block_reason_from(Ok(Marker::default()), no_db), None);
        let r = block_reason_from(Err(anyhow!("access denied")), no_db).unwrap();
        assert!(r.contains("cannot be read"), "{r}");
        let r = block_reason_from(Ok(marker_with(true, &[r"\\?\C:\a"])), no_db).unwrap();
        assert!(r.contains("1 persistent write grant"), "{r}");
        let ever = || Ok(marker_with(true, &[]));
        assert_eq!(block_reason_from(ever(), || Some(Vec::new())), None);
        let r = block_reason_from(ever(), || Some(vec![r"\\?\C:\b".to_owned()])).unwrap();
        assert!(r.contains("state database records 1"), "{r}");
        let r = block_reason_from(ever(), || None).unwrap();
        assert!(r.contains("missing or unreadable"), "{r}");
    }

    #[test]
    fn unreadable_dacl_is_not_an_absent_grant() {
        const GROUP: &str = "S-1-5-21-1-2-3-1001";
        let cap = capability_sid_from([7; 16]);
        let ace = |sid: &str, deny: bool, inherited: bool| AceView {
            deny,
            inherited,
            flags: 0x3,
            mask: 0x0013_01bf,
            sid: sid.to_owned(),
        };
        let on = |aces: Vec<AceView>| unrecorded_grant_on(Ok(aces), Some(GROUP)).unwrap();
        assert!(unrecorded_grant_on(Err(anyhow!("access denied")), Some(GROUP)).is_err());
        assert_eq!(on(vec![]), UnrecordedGrant::None);
        assert_eq!(
            on(vec![
                ace("S-1-5-32-545", false, true),
                ace(GROUP, true, false)
            ]),
            UnrecordedGrant::None
        );
        assert_eq!(on(vec![ace(GROUP, false, false)]), UnrecordedGrant::Own);
        assert_eq!(on(vec![ace(&cap, false, false)]), UnrecordedGrant::Own);
        assert_eq!(
            on(vec![ace(GROUP, false, false), ace(&cap, false, true)]),
            UnrecordedGrant::Inherited
        );
        // Without an install record only a capability SID can be told apart.
        assert_eq!(
            unrecorded_grant_on(Ok(vec![ace(GROUP, false, false)]), None).unwrap(),
            UnrecordedGrant::None
        );
        assert_eq!(
            unrecorded_grant_on(Ok(vec![ace(&cap, false, true)]), None).unwrap(),
            UnrecordedGrant::Inherited
        );
    }
}
