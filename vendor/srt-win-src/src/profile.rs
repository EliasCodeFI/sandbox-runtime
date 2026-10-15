//! The profile read grant — `srt-win profile grant | forget | status`.
//!
//! Sandboxed commands run as a separate account, and reads are
//! allow-listed, so nothing in the real user's profile is readable to
//! them: a tool installed under the profile does not start, and npm,
//! pip, NuGet, Maven, Gradle and git do not see the user's
//! configuration. This grant makes the profile readable to the
//! sandbox GROUP, except for the credential stores listed in
//! [`crate::profile_plan`]. It is opt-in, written by an explicit run
//! of `profile grant` as the real user (unelevated), and kept until
//! `profile forget` or `uninstall`.
//!
//! [`crate::profile_plan`] decides what each directory gets; this
//! module reads the tree, writes the entries, and keeps the record.
//!
//! ## What is written
//!
//! One ACE per path, for the sandbox group, through the same
//! converge as the kept write grants ([`crate::persist`]), which is
//! also what brackets each DACL write with a record that crash
//! recovery finishes:
//!
//! - excluded path: `(D;OICI;FA)` — written for every exclusion before
//!   the first allow of a run;
//! - container: `(A;;list | traverse | read attributes)`, on the
//!   directory only;
//! - granted directory: `(A;OICI;read + execute)`;
//! - granted file: `(A;;read + execute)`.
//!
//! Nothing grants a write, delete or change-permissions right.
//!
//! ## Links
//!
//! Nothing is written through a reparse point. Every object is opened
//! with `FILE_FLAG_OPEN_REPARSE_POINT`, its attributes are read from
//! that handle, and its DACL is read and written through the same
//! handle. A junction, a symbolic link or a cloud placeholder is
//! skipped and reported, in the profile root and in every container.
//! The handle's final path is compared with the path that was opened,
//! so a directory on the way that was replaced by a link is noticed
//! too. Directories are listed through the handle as well.
//!
//! Below a granted directory the inheriting ACE reaches the existing
//! descendants through the system's own propagation, which runs when
//! a directory's DACL is set. That propagation writes a link's own
//! security descriptor and does not descend into it; the test
//! `inherited_entries_do_not_cross_a_junction` pins this.
//!
//! ## Record
//!
//! Every path written is recorded twice, with the object's file id
//! and what it carries: in the session database (`profile_paths`,
//! which drives the converge) and in the registry marker of the kept
//! grants (`HKCU\Software\sandbox-runtime\PersistentGrants`), which
//! survives the loss of the database. The marker is written before the
//! first ACE of a run, marked incomplete, and again at the end.
//! `profile forget` removes the group's ACEs from exactly the
//! recorded objects, wherever they are now.
//!
//! While a grant is recorded, nothing runs the sandbox account under
//! the ordinary token ([`block_reason`]).

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashSet;
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

use crate::path_id::{self, FileId, Located};
use crate::persist::{self, Ids, OpenObject};
use crate::profile_plan::{self as plan, Entry, Kind, Name, Node, Rules, Tree};
use crate::reg;
use crate::util::{OwnedHandle, pcwstr, wstr};

// ─── Where the profile is ───────────────────────────────────────────

/// The profile and its two application-data folders, as canonical
/// (`\\?\`-prefixed) paths.
#[derive(Debug, Clone)]
pub struct Layout {
    pub profile: String,
    pub roaming: Option<String>,
    pub local: Option<String>,
}

impl Layout {
    /// The calling user's profile, from the known folders. With
    /// `test_profile` — which only a `test-hooks` build can pass —
    /// that directory stands in for the profile, with its `AppData`
    /// folders where they conventionally are.
    pub fn resolve(test_profile: Option<&str>) -> Result<Layout> {
        let canon = |p: &str| -> Result<String> {
            let (c, is_dir) = path_id::canonicalize_path(p)
                .map_err(|e| anyhow!("profile directory '{p}': {e}"))?;
            if !is_dir {
                bail!("'{p}' is not a directory");
            }
            Ok(c)
        };
        if let Some(t) = test_profile {
            let profile = canon(t)?;
            let sub = |rel: &str| canon(&format!("{profile}\\{rel}")).ok();
            return Ok(Layout {
                roaming: sub(r"AppData\Roaming"),
                local: sub(r"AppData\Local"),
                profile,
            });
        }
        use windows::Win32::UI::Shell::{
            FOLDERID_LocalAppData, FOLDERID_Profile, FOLDERID_RoamingAppData,
        };
        Ok(Layout {
            profile: canon(&known_folder(&FOLDERID_Profile)?)?,
            roaming: known_folder(&FOLDERID_RoamingAppData)
                .and_then(|p| canon(&p))
                .ok(),
            local: known_folder(&FOLDERID_LocalAppData)
                .and_then(|p| canon(&p))
                .ok(),
        })
    }

    /// `folder` as components beneath the profile; `None` when it is
    /// not inside it (a redirected folder).
    fn rel(&self, folder: &Option<String>) -> Option<Vec<String>> {
        let f = folder.as_deref()?;
        plan::rel_components(&self.profile, f)
            .ok()
            .filter(|c| !c.is_empty())
    }
}

fn known_folder(id: &windows::core::GUID) -> Result<String> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    let p = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None) }
        .context("SHGetKnownFolderPath")?;
    let s = unsafe { p.to_string() };
    unsafe { CoTaskMemFree(Some(p.0 as *const std::ffi::c_void)) };
    s.context("known-folder path is not valid Unicode")
}

fn join(profile: &str, rel: &[String]) -> String {
    let mut p = profile.trim_end_matches('\\').to_owned();
    for c in rel {
        p.push('\\');
        p.push_str(c);
    }
    p
}

// ─── Opening without following ──────────────────────────────────────

const FILE_LIST_DIRECTORY: u32 = 0x1;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
/// To read and write an object's DACL.
const ACCESS_STAMP: u32 = READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES;
/// To list a directory.
const ACCESS_LIST: u32 = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES;

const ATTR_DIRECTORY: u32 = 0x10;
const ATTR_REPARSE_POINT: u32 = 0x400;
const ATTR_OFFLINE: u32 = 0x1000;
const ATTR_RECALL_ON_OPEN: u32 = 0x4_0000;
const ATTR_RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;

/// Why an object with these attributes is left alone, if it is: a
/// reparse point of any kind redirects or is filled in by something
/// else, and a directory marked offline or recall-on-open is a cloud
/// placeholder whose listing would fetch it.
pub fn skip_reason(attrs: u32, is_dir: bool) -> Option<&'static str> {
    if attrs & ATTR_REPARSE_POINT != 0 {
        return Some("reparse point (junction, symbolic link or placeholder)");
    }
    let cloud = ATTR_OFFLINE | ATTR_RECALL_ON_OPEN | ATTR_RECALL_ON_DATA_ACCESS;
    if is_dir && attrs & cloud != 0 {
        return Some("cloud placeholder directory");
    }
    None
}

/// An object opened by [`open_no_follow`], with what was read from
/// the handle.
struct Opened {
    h: OwnedHandle,
    attrs: u32,
    id: FileId,
    is_dir: bool,
}

impl Opened {
    fn object(&self) -> OpenObject {
        OpenObject {
            handle: self.h.raw(),
            id: self.id,
            is_dir: self.is_dir,
        }
    }
}

/// Open `path` itself: if its last component is a link, the link, not
/// what it points at. Attributes and identity come from the handle.
fn open_no_follow(path: &str, access: u32) -> Result<Opened> {
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle, OPEN_EXISTING,
    };
    let w = wstr(path);
    let h = unsafe {
        CreateFileW(
            pcwstr(&w),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .with_context(|| format!("open '{path}'"))?;
    if h == INVALID_HANDLE_VALUE {
        bail!("open '{path}': invalid handle");
    }
    let h = OwnedHandle(h);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(h.raw(), &mut info) }
        .with_context(|| format!("attributes of '{path}'"))?;
    let id =
        path_id::file_id_from_handle(h.raw()).with_context(|| format!("file id of '{path}'"))?;
    Ok(Opened {
        attrs: info.dwFileAttributes,
        is_dir: info.dwFileAttributes & ATTR_DIRECTORY != 0,
        id,
        h,
    })
}

/// [`open_no_follow`] with the access a DACL read and write needs.
/// A directory is opened with the right to list it as well, which
/// the system uses when it brings the entries below up to date; a
/// file is opened with no data access at all, so a file another
/// process holds open exclusively (a loaded registry hive) can still
/// be reached. Which of the two it is comes from a first open that
/// asks for nothing, and both opens must have reached the same
/// object.
fn open_for_stamp(path: &str) -> Result<Opened> {
    let probe = open_no_follow(path, FILE_READ_ATTRIBUTES)?;
    let o = if probe.is_dir {
        open_no_follow(path, ACCESS_STAMP | FILE_LIST_DIRECTORY)
            .or_else(|_| open_no_follow(path, ACCESS_STAMP))?
    } else {
        open_no_follow(path, ACCESS_STAMP)?
    };
    if o.id != probe.id {
        bail!("'{path}' was replaced while it was being opened");
    }
    Ok(o)
}

/// Fail unless the object behind `o` is where `path` says: a
/// directory on the way that is a link would have taken the open
/// somewhere else.
fn verify_location(o: &Opened, path: &str) -> Result<()> {
    let at =
        path_id::final_path_of(o.h.raw()).with_context(|| format!("final path of '{path}'"))?;
    if at.to_lowercase() != path.to_lowercase() {
        bail!("'{path}' resolves to '{at}': a directory on the way is a link");
    }
    Ok(())
}

/// The entries of the directory open on `h` (which needs
/// `FILE_LIST_DIRECTORY`), without `.` and `..`.
fn list_dir(h: HANDLE) -> Result<Vec<Entry>> {
    use windows::Win32::Foundation::ERROR_NO_MORE_FILES;
    use windows::Win32::Storage::FileSystem::{
        FILE_ID_BOTH_DIR_INFO, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
        GetFileInformationByHandleEx,
    };
    // `u64` elements: the records are 8-byte aligned.
    let mut buf = vec![0u64; 8192];
    let bytes = (buf.len() * size_of::<u64>()) as u32;
    let name_at = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
    let mut class = FileIdBothDirectoryRestartInfo;
    let mut out = Vec::new();
    loop {
        let r = unsafe { GetFileInformationByHandleEx(h, class, buf.as_mut_ptr().cast(), bytes) };
        if let Err(e) = r {
            if e.code() == ERROR_NO_MORE_FILES.into() {
                break;
            }
            return Err(e).context("list directory");
        }
        class = FileIdBothDirectoryInfo;
        let base = buf.as_ptr() as *const u8;
        let mut off = 0usize;
        loop {
            // SAFETY: the call filled the buffer with records linked
            // by `NextEntryOffset`, each within the buffer.
            let info = unsafe { &*(base.add(off) as *const FILE_ID_BOTH_DIR_INFO) };
            let wide =
                |ptr: *const u16, len: usize| unsafe { std::slice::from_raw_parts(ptr, len) };
            let long = wide(
                unsafe { base.add(off + name_at) } as *const u16,
                info.FileNameLength as usize / 2,
            );
            let short_len = (info.ShortNameLength as u8 as usize / 2).min(info.ShortName.len());
            let short = &info.ShortName[..short_len];
            let is_dir = info.FileAttributes & ATTR_DIRECTORY != 0;
            let dots = long == [u16::from(b'.')] || long == [u16::from(b'.'), u16::from(b'.')];
            if !dots {
                let name = String::from_utf16(long);
                out.push(Entry {
                    skip: match &name {
                        Ok(_) => skip_reason(info.FileAttributes, is_dir).map(str::to_owned),
                        Err(_) => Some("name is not valid Unicode".to_owned()),
                    },
                    name: Name {
                        long: name.unwrap_or_else(|_| String::from_utf16_lossy(long)),
                        short: String::from_utf16(short).ok().filter(|s| !s.is_empty()),
                    },
                    is_dir,
                });
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            off += info.NextEntryOffset as usize;
        }
    }
    Ok(out)
}

/// The profile on disk, for [`plan::plan`]. A directory is listed
/// only after it was opened without following a link, found to be a
/// plain directory, and found to be where its path says.
struct DiskTree<'a> {
    profile: &'a str,
}

impl Tree for DiskTree<'_> {
    fn list(&mut self, rel: &[String]) -> std::result::Result<Vec<Entry>, String> {
        let path = join(self.profile, rel);
        (|| -> Result<Vec<Entry>> {
            let o = open_no_follow(&path, ACCESS_LIST)?;
            if let Some(why) = skip_reason(o.attrs, o.is_dir) {
                bail!("{why}");
            }
            if !o.is_dir {
                bail!("not a directory");
            }
            verify_location(&o, &path)?;
            list_dir(o.h.raw())
        })()
        .map_err(|e| format!("{e:#}"))
    }
}

// ─── Record ─────────────────────────────────────────────────────────

const VAL_HEADER: &str = "Profile";
const VAL_EXTRA: &str = "ProfileExtra";
const VAL_PATHS: &str = "ProfilePaths";
const VAL_EXCLUSIONS: &str = "ProfileExclusions";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn file_id_from_hex(s: &str) -> Result<FileId> {
    if s.len() != 48 || !s.is_ascii() {
        bail!("malformed file id '{s}'");
    }
    let bytes = (0..24)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .with_context(|| format!("malformed file id '{s}'"))?;
    FileId::from_bytes(&bytes)
}

/// What a grant was made for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub list_version: u32,
    /// False from before the first ACE of a run until its end, and
    /// when an exclusion could not be written.
    pub complete: bool,
    pub file_id: FileId,
    pub profile: String,
}

impl Header {
    /// `1|<list version>|<complete>|<file id>|<profile path>`.
    fn encode(&self) -> String {
        format!(
            "1|{}|{}|{}|{}",
            self.list_version,
            u8::from(self.complete),
            hex(&self.file_id.as_bytes()),
            self.profile
        )
    }

    fn decode(s: &str) -> Result<Header> {
        let bad = || anyhow!("malformed profile-grant record '{s}'");
        let mut it = s.splitn(5, '|');
        let mut next = || it.next().ok_or_else(bad);
        if next()? != "1" {
            return Err(bad());
        }
        let list_version = next()?.parse().map_err(|_| bad())?;
        let complete = match next()? {
            "0" => false,
            "1" => true,
            _ => return Err(bad()),
        };
        let file_id = file_id_from_hex(next()?)?;
        let profile = next()?.to_owned();
        if profile.is_empty() {
            return Err(bad());
        }
        Ok(Header {
            list_version,
            complete,
            file_id,
            profile,
        })
    }
}

/// One recorded path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    pub path: String,
    pub kind: Kind,
    /// A directory the grant created empty.
    pub created: bool,
    /// `None` between the record and the first open of the object.
    pub file_id: Option<FileId>,
}

impl Recorded {
    /// `<file id or ->|<kind>|<created>|<path>`.
    fn encode(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.file_id
                .map(|id| hex(&id.as_bytes()))
                .unwrap_or_else(|| "-".to_owned()),
            self.kind.as_str(),
            u8::from(self.created),
            self.path
        )
    }

    fn decode(s: &str) -> Result<Recorded> {
        let bad = || anyhow!("malformed profile-grant entry '{s}'");
        let mut it = s.splitn(4, '|');
        let mut next = || it.next().ok_or_else(bad);
        let file_id = match next()? {
            "-" => None,
            h => Some(file_id_from_hex(h)?),
        };
        let kind = Kind::parse(next()?).ok_or_else(bad)?;
        let created = match next()? {
            "0" => false,
            "1" => true,
            _ => return Err(bad()),
        };
        let path = next()?.to_owned();
        if path.is_empty() {
            return Err(bad());
        }
        Ok(Recorded {
            path,
            kind,
            created,
            file_id,
        })
    }
}

/// The registry half of the record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Marker {
    pub header: Option<Header>,
    /// Exclusions added to the built-in list when the grant was made,
    /// as paths beneath the profile. A later run keeps them unless it
    /// is told to replace them.
    pub extra: Vec<String>,
    /// Every exclusion the grant was made with — the built-in list of
    /// the build that made it, at this profile's locations, and
    /// `extra` — as absolute paths, wildcards as written. Whether
    /// each exists is beside the point: this is what must never be
    /// granted, by this grant or by a session on top of it.
    pub exclusions: Vec<String>,
    pub paths: Vec<Recorded>,
}

impl Marker {
    fn is_empty(&self) -> bool {
        self.header.is_none() && self.paths.is_empty()
    }
}

/// The two stores a grant is recorded in. The registry key is a
/// parameter so a test can keep its record apart from the user's.
#[derive(Clone, Copy)]
pub struct Store<'a> {
    pub conn: &'a Connection,
    pub key: &'a str,
}

impl<'a> Store<'a> {
    /// The calling user's record.
    pub fn of(conn: &'a Connection) -> Store<'a> {
        Store {
            conn,
            key: persist::MARKER_KEY,
        }
    }
}

/// Read the marker under `key`. An absent key or value is the empty
/// marker; anything unreadable is an error, which every caller treats
/// as "a grant may exist".
pub fn read_marker_at(key: &str) -> Result<Marker> {
    let Some(k) = reg::Key::open_hkcu(key, false)? else {
        return Ok(Marker::default());
    };
    Ok(Marker {
        header: k
            .get_sz(VAL_HEADER)?
            .map(|s| Header::decode(&s))
            .transpose()?,
        extra: k.get_multi_sz(VAL_EXTRA)?.unwrap_or_default(),
        exclusions: k.get_multi_sz(VAL_EXCLUSIONS)?.unwrap_or_default(),
        paths: k
            .get_multi_sz(VAL_PATHS)?
            .unwrap_or_default()
            .iter()
            .map(|s| Recorded::decode(s))
            .collect::<Result<_>>()?,
    })
}

fn write_marker(key: &str, m: &Marker) -> Result<()> {
    let k = reg::Key::create_hkcu(key)?;
    // The paths first: a marker with paths and no header still reads
    // as "a grant may exist".
    let paths: Vec<String> = m.paths.iter().map(Recorded::encode).collect();
    k.set_multi_sz(VAL_PATHS, &paths)?;
    k.set_multi_sz(VAL_EXTRA, &m.extra)?;
    k.set_multi_sz(VAL_EXCLUSIONS, &m.exclusions)?;
    match &m.header {
        Some(h) => k.set_sz(VAL_HEADER, &h.encode()),
        None => reg::delete_value(&k, VAL_HEADER),
    }
}

fn clear_marker(key: &str) -> Result<()> {
    if let Some(k) = reg::Key::open_hkcu(key, true)? {
        for v in [VAL_HEADER, VAL_EXTRA, VAL_EXCLUSIONS, VAL_PATHS] {
            reg::delete_value(&k, v)?;
        }
    }
    Ok(())
}

/// Whether the session database has the grant's table and a row in
/// it. A database from before the table existed has neither.
pub(crate) fn db_has_rows(conn: &Connection) -> Result<bool> {
    let table: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'profile_paths'")?
        .exists([])?;
    if !table {
        return Ok(false);
    }
    Ok(conn
        .prepare("SELECT 1 FROM profile_paths LIMIT 1")?
        .exists([])?)
}

/// Whether a grant is recorded for the calling user, in either store.
pub(crate) fn recorded(conn: &Connection) -> Result<bool> {
    Ok(db_has_rows(conn)? || !read_marker_at(persist::MARKER_KEY)?.is_empty())
}

/// What the grant recorded for `canon`, if the record is for the
/// object `cur`. Read by the converge of [`crate::persist`].
pub(crate) fn recorded_kind(conn: &Connection, canon: &str, cur: FileId) -> Result<Option<Kind>> {
    let row: Option<(String, Vec<u8>)> = conn
        .prepare_cached("SELECT kind, file_id FROM profile_paths WHERE canonical_path = ?1")?
        .query_row(params![canon], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()
        .context("SELECT profile_paths")?;
    Ok(row
        .filter(|(_, id)| id.as_slice() == cur.as_bytes())
        .and_then(|(kind, _)| Kind::parse(&kind)))
}

fn db_rows(conn: &Connection) -> Result<Vec<Recorded>> {
    let mut s = conn.prepare("SELECT canonical_path, file_id, kind, created FROM profile_paths")?;
    let rows = s.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (path, id, kind, created) = row?;
        out.push(Recorded {
            kind: Kind::parse(&kind)
                .ok_or_else(|| anyhow!("profile_paths holds kind '{kind}' for '{path}'"))?,
            created: created != 0,
            file_id: FileId::from_bytes(&id).ok(),
            path,
        });
    }
    Ok(out)
}

fn upsert_row(
    conn: &Connection,
    path: &str,
    id: Option<FileId>,
    kind: Kind,
    created: bool,
) -> Result<()> {
    let id = id.map(|i| i.as_bytes().to_vec()).unwrap_or_default();
    conn.execute(
        "INSERT INTO profile_paths (canonical_path, file_id, kind, created) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(canonical_path) DO UPDATE SET \
           file_id = excluded.file_id, kind = excluded.kind, \
           created = MAX(profile_paths.created, excluded.created)",
        params![path, id, kind.as_str(), i64::from(created)],
    )
    .context("UPSERT profile_paths")?;
    Ok(())
}

/// The recorded paths of both stores, the database's entry first
/// where both have one (it is the newer).
fn all_recorded(store: &Store<'_>, marker: &Marker) -> Result<Vec<Recorded>> {
    let mut out = db_rows(store.conn)?;
    let mut seen: HashSet<String> = out.iter().map(|r| r.path.to_lowercase()).collect();
    for r in &marker.paths {
        if seen.insert(r.path.to_lowercase()) {
            out.push(r.clone());
        }
    }
    Ok(out)
}

// ─── Running without the write-restricted token ─────────────────────

/// Why a command that runs the sandbox account under the ordinary
/// token must not run now, as far as this grant goes; `None` when it
/// may. A marker that cannot be read refuses, and so do rows the
/// session database still holds after the marker was lost. (A
/// database that is missing or unreadable after any kept grant was
/// made refuses through
/// [`crate::persist::write_grant_block_reason`], which is asked
/// first.)
pub fn block_reason() -> Option<String> {
    block_reason_from(read_marker_at(persist::MARKER_KEY)).or_else(|| {
        let conn = crate::state_db::open_db_ro().ok()??;
        db_has_rows(&conn).unwrap_or(true).then(|| {
            "the state database records paths of a profile read grant that the registry \
             no longer lists"
                .to_owned()
        })
    })
}

fn block_reason_from(marker: Result<Marker>) -> Option<String> {
    match marker {
        Err(e) => Some(format!(
            "the record of the profile read grant cannot be read ({e:#})"
        )),
        Ok(m) if m.is_empty() => None,
        Ok(m) => Some(format!(
            "a profile read grant exists ({} path(s) recorded{})",
            m.paths.len(),
            m.header
                .map(|h| format!(", profile '{}'", h.profile))
                .unwrap_or_default()
        )),
    }
}

/// `{state, reason?}` for `srt-win user status`: `none`, `present`,
/// or `unknown` when the record cannot be read. Registry only.
pub fn brief_status_json() -> serde_json::Value {
    match read_marker_at(persist::MARKER_KEY) {
        Ok(m) if m.is_empty() => serde_json::json!({ "state": "none" }),
        Ok(_) => serde_json::json!({ "state": "present" }),
        Err(e) => serde_json::json!({ "state": "unknown", "reason": format!("{e:#}") }),
    }
}

// ─── Grant ──────────────────────────────────────────────────────────

/// A path with why it was skipped or what failed on it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Item {
    pub path: String,
    pub reason: String,
}

/// Outcome of [`grant`], and the `--json` output of `profile grant`.
#[derive(Debug, Default, serde::Serialize)]
pub struct Report {
    pub profile: String,
    pub list_version: u32,
    /// Every exclusion that is a directory carries its deny. Only a
    /// complete grant is reported as current by `profile status`.
    pub complete: bool,
    pub containers: usize,
    pub granted: usize,
    pub files: usize,
    pub denied: usize,
    /// Excluded directories created empty by this run.
    pub placeholders: usize,
    /// DACLs written by this run, and paths found as wanted.
    pub writes: usize,
    pub unchanged: usize,
    /// Recorded paths that are no longer part of the grant and had
    /// their entry removed.
    pub removed: usize,
    pub skipped: Vec<Item>,
    pub failed: Vec<Item>,
    pub elapsed_ms: u64,
}

enum Stamped {
    Wrote,
    Unchanged,
    Skipped(&'static str),
}

/// Open the node without following a link, check it is still what
/// the plan saw, record it, and converge its ACEs through the handle.
fn stamp(store: &Store<'_>, ids: &Ids, path: &str, node: &Node, created: bool) -> Result<Stamped> {
    let o = open_for_stamp(path)?;
    if let Some(why) = skip_reason(o.attrs, o.is_dir) {
        return Ok(Stamped::Skipped(why));
    }
    if o.is_dir != node.is_dir {
        bail!(
            "is no longer a {}",
            if node.is_dir { "directory" } else { "file" }
        );
    }
    verify_location(&o, path)?;
    upsert_row(store.conn, path, Some(o.id), node.kind, created)?;
    let obj = o.object();
    match persist::converge_on(store.conn, ids, path, Some(&obj)) {
        Ok(true) => Ok(Stamped::Wrote),
        Ok(false) => Ok(Stamped::Unchanged),
        Err(e) => {
            if persist::settled_on_object(store.conn, ids, path, &obj).unwrap_or(false) {
                eprintln!(
                    "srt-win: profile grant: '{path}' carries its entry; not every object \
                     below it could be updated ({e:#})"
                );
                Ok(Stamped::Wrote)
            } else {
                Err(e)
            }
        }
    }
}

/// Take a recorded path out of the grant: remove its row, and the
/// group's ACE from the recorded object — at its path, or wherever
/// its file id is now. `Ok(true)` if an ACE was removed. An object
/// that can be neither found at its path nor located by id is an
/// error and stays recorded.
fn strip(store: &Store<'_>, ids: &Ids, r: &Recorded) -> Result<bool> {
    let here = match open_for_stamp(&r.path) {
        Ok(o) => Some(o),
        Err(e) if path_id::is_not_found(&e) => None,
        Err(e) => return Err(e),
    };
    let mut targets: Vec<(String, Opened)> = Vec::new();
    match (here, r.file_id) {
        (Some(o), Some(id)) if o.id == id => targets.push((r.path.clone(), o)),
        // Never opened after it was recorded: the path is all that
        // identifies it.
        (Some(o), None) => targets.push((r.path.clone(), o)),
        (None, None) => {}
        (_, Some(id)) => match path_id::locate_by_file_id(&id) {
            Located::At(p) => {
                let o = open_for_stamp(&p)?;
                if o.id == id {
                    targets.push((p, o));
                }
            }
            Located::Gone => {}
            Located::Unknown => bail!(
                "the object recorded for '{}' is no longer at that path and could not be \
                 located by file id; its entry may still be on disk",
                r.path
            ),
        },
    }
    let tx = store
        .conn
        .unchecked_transaction()
        .context("begin profile strip")?;
    tx.execute(
        "DELETE FROM profile_paths WHERE canonical_path = ?1",
        params![r.path],
    )?;
    let mut removed = false;
    for (p, o) in &targets {
        let obj = o.object();
        removed |= match persist::converge_on(&tx, ids, p, Some(&obj)) {
            Ok(w) => w,
            Err(e) => {
                if persist::settled_on_object(&tx, ids, p, &obj).unwrap_or(false) {
                    true
                } else {
                    return Err(e);
                }
            }
        };
    }
    tx.commit().context("commit profile strip")?;
    Ok(removed)
}

/// Exclusions added by the caller, as components beneath the
/// profile. A path that exists is resolved first, so a short name or
/// a link names the directory it stands for; one that is not inside
/// the profile is an error.
fn resolve_extra(profile: &str, raw: &[String]) -> Result<Vec<Vec<String>>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    for r in raw {
        let absolute = match plan::rel_components(profile, r) {
            Ok(rel) => join(profile, &rel),
            Err(e) => bail!("--exclude: {e}"),
        };
        let resolved = match path_id::canonicalize_path(&absolute) {
            Ok((c, _)) => c,
            Err(_) => absolute,
        };
        let rel =
            plan::rel_components(profile, &resolved).map_err(|e| anyhow!("--exclude: {e}"))?;
        if rel.is_empty() {
            bail!("--exclude '{r}' is the profile itself");
        }
        if !out.contains(&rel) {
            out.push(rel);
        }
    }
    Ok(out)
}

/// `profile grant`: bring the profile to the plan. The first run
/// writes every entry; a later run (a refresh) writes only what
/// changed — a new child of a container, a path that became or
/// stopped being an exclusion — and reads one DACL per recorded path
/// otherwise.
///
/// Order within a run: the record (marked incomplete), then every
/// exclusion's deny, then the removal of entries that are no longer
/// part of the grant, then the allows, parents first. A failure on
/// one path is reported and the run goes on; the run is complete
/// unless an excluded directory could not be denied or a stale entry
/// could not be removed.
///
/// `extra_raw` adds exclusions to the built-in list. The ones an
/// earlier run recorded stay in force as well — a refresh that names
/// none does not re-admit what an earlier run excluded — unless
/// `replace_extra`, with which `extra_raw` is the whole added list.
pub fn grant(
    store: &Store<'_>,
    ids: &Ids,
    layout: &Layout,
    extra_raw: &[String],
    replace_extra: bool,
    progress: bool,
) -> Result<Report> {
    let started = std::time::Instant::now();
    if ids.group_sid.is_none() {
        bail!("no install record: run `srt-win install`");
    }
    let profile = layout.profile.as_str();
    let root = open_for_stamp(profile)?;
    if let Some(why) = skip_reason(root.attrs, root.is_dir) {
        bail!("the profile directory '{profile}' is a {why}");
    }
    if !root.is_dir {
        bail!("'{profile}' is not a directory");
    }
    let root_id = root.id;
    drop(root);

    let old = read_marker_at(store.key)?;
    let mut extra: Vec<Vec<String>> = if replace_extra {
        Vec::new()
    } else {
        old.extra
            .iter()
            .map(|x| plan::split_path(x))
            .filter(|x| !x.is_empty())
            .collect()
    };
    for x in resolve_extra(profile, extra_raw)? {
        let same = |a: &Vec<String>| {
            a.len() == x.len()
                && a.iter()
                    .zip(&x)
                    .all(|(p, q)| plan::norm_component(p) == plan::norm_component(q))
        };
        if !extra.iter().any(same) {
            extra.push(x);
        }
    }
    let rules = Rules::new(
        layout.rel(&layout.roaming).as_deref(),
        layout.rel(&layout.local).as_deref(),
        &extra,
    );
    let nodes = plan::plan(&mut DiskTree { profile }, &rules)
        .map_err(|e| anyhow!("list the profile directory '{profile}': {e}"))?;

    let mut report = Report {
        profile: profile.to_owned(),
        list_version: plan::LIST_VERSION,
        complete: true,
        ..Default::default()
    };
    let mut planned: Vec<(String, &Node)> = Vec::new();
    for n in &nodes {
        let path = join(profile, &n.rel);
        match n.kind {
            Kind::Skipped => report.skipped.push(Item {
                path,
                reason: n.note.clone().unwrap_or_default(),
            }),
            // Its owner writes its deny; here it is only left out.
            Kind::Denied if !n.stamp => {}
            _ => planned.push((path, n)),
        }
    }
    let planned_keys: HashSet<String> = planned.iter().map(|(p, _)| p.to_lowercase()).collect();

    // The record, before anything is written: every path this run may
    // write, and every path an earlier run recorded.
    let before = all_recorded(store, &old)?;
    if store.key == persist::MARKER_KEY {
        persist::marker_set_ever()?;
    }
    let extra_strings: Vec<String> = extra.iter().map(|x| x.join("\\")).collect();
    let exclusions: Vec<String> = rules
        .spelled()
        .iter()
        .map(|rel| format!("{}\\{rel}", profile.trim_end_matches('\\')))
        .collect();
    let mut header = Header {
        list_version: plan::LIST_VERSION,
        complete: false,
        file_id: root_id,
        profile: profile.to_owned(),
    };
    let mut pre = before.clone();
    let known: HashSet<String> = pre.iter().map(|r| r.path.to_lowercase()).collect();
    for (path, n) in &planned {
        if !known.contains(&path.to_lowercase()) {
            pre.push(Recorded {
                path: path.clone(),
                kind: n.kind,
                created: n.missing,
                file_id: None,
            });
        }
    }
    write_marker(
        store.key,
        &Marker {
            header: Some(header.clone()),
            extra: extra_strings.clone(),
            exclusions: exclusions.clone(),
            paths: pre,
        },
    )?;

    // Excluded directories that are not there yet. Recorded as
    // created before they are, so a run cut short here leaves no
    // empty directory that `profile forget` does not know of.
    let mut created_now: HashSet<&str> = HashSet::new();
    for (path, n) in planned.iter().filter(|(_, n)| n.missing) {
        upsert_row(store.conn, path, None, n.kind, true)?;
        match std::fs::create_dir(path) {
            Ok(()) => {
                report.placeholders += 1;
                created_now.insert(path.as_str());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Someone else made it meanwhile: not ours to remove.
                store.conn.execute(
                    "UPDATE profile_paths SET created = 0 WHERE canonical_path = ?1",
                    params![path],
                )?;
            }
            Err(e) => report.failed.push(Item {
                path: path.clone(),
                reason: format!("create: {e}"),
            }),
        }
    }

    let done = |report: &mut Report, path: &str, n: &Node, r: Result<Stamped>| match r {
        Ok(Stamped::Skipped(why)) => {
            report.skipped.push(Item {
                path: path.to_owned(),
                reason: why.to_owned(),
            });
            false
        }
        Ok(s) => {
            match s {
                Stamped::Wrote => report.writes += 1,
                _ => report.unchanged += 1,
            }
            match n.kind {
                Kind::Container => report.containers += 1,
                Kind::Granted => report.granted += 1,
                Kind::File => report.files += 1,
                Kind::Denied => report.denied += 1,
                Kind::Skipped => {}
            }
            true
        }
        Err(e) => {
            report.failed.push(Item {
                path: path.to_owned(),
                reason: format!("{e:#}"),
            });
            false
        }
    };

    // 1. Every exclusion, before any allow.
    let denies: Vec<&(String, &Node)> = planned
        .iter()
        .filter(|(_, n)| n.kind == Kind::Denied)
        .collect();
    if progress {
        eprintln!(
            "srt-win: profile grant: {} exclusion(s), then {} path(s) to grant",
            denies.len(),
            planned.len() - denies.len()
        );
    }
    for (path, n) in denies {
        let r = stamp(store, ids, path, n, created_now.contains(path.as_str()));
        // An excluded FILE that could not be denied stays unreadable
        // (nothing above it inherits); an excluded directory without
        // its deny leaves the grant incomplete.
        if !done(&mut report, path, n, r) && n.is_dir {
            report.complete = false;
        }
    }

    // 2. Entries of an earlier run that the plan no longer has.
    for r in before
        .iter()
        .filter(|r| !planned_keys.contains(&r.path.to_lowercase()))
    {
        match strip(store, ids, r) {
            Ok(_) => report.removed += 1,
            Err(e) => {
                report.complete = false;
                report.failed.push(Item {
                    path: r.path.clone(),
                    reason: format!("remove stale entry: {e:#}"),
                });
            }
        }
    }

    // 3. The allows, parents first, one top-level item after another.
    let top_total = {
        let mut tops: Vec<String> = planned
            .iter()
            .filter(|(_, n)| n.kind != Kind::Denied)
            .filter_map(|(_, n)| n.rel.first().map(|c| c.to_lowercase()))
            .collect();
        tops.dedup();
        tops.len()
    };
    let (mut top_done, mut top_now): (usize, Option<String>) = (0, None);
    for (path, n) in planned.iter().filter(|(_, n)| n.kind != Kind::Denied) {
        let top = n.rel.first().map(|c| c.to_lowercase());
        if top != top_now {
            if top_now.is_some() {
                top_done += 1;
                if progress {
                    eprintln!(
                        "srt-win: profile grant: {top_done}/{top_total} top-level item(s) done"
                    );
                }
            }
            top_now = top;
        }
        let r = stamp(store, ids, path, n, created_now.contains(path.as_str()));
        if !done(&mut report, path, n, r) {
            // Not granted: take back the record, and whatever part of
            // the entry reached the object.
            let gone = db_rows(store.conn)?
                .into_iter()
                .find(|r| r.path == *path)
                .unwrap_or(Recorded {
                    path: path.clone(),
                    kind: n.kind,
                    created: false,
                    file_id: None,
                });
            if let Err(e) = strip(store, ids, &gone) {
                eprintln!("srt-win: profile grant: '{path}': {e:#}");
            }
        }
    }
    if progress && top_now.is_some() {
        eprintln!(
            "srt-win: profile grant: {}/{top_total} top-level item(s) done",
            top_done + 1
        );
    }

    // The record as it now is.
    header.complete = report.complete;
    let rows = db_rows(store.conn)?;
    let mut paths = rows.clone();
    // A stale entry that could not be removed stays listed.
    let have: HashSet<String> = rows.iter().map(|r| r.path.to_lowercase()).collect();
    for f in &report.failed {
        if let Some(old) = before
            .iter()
            .find(|r| r.path == f.path && !have.contains(&r.path.to_lowercase()))
        {
            paths.push(old.clone());
        }
    }
    write_marker(
        store.key,
        &Marker {
            header: Some(header),
            extra: extra_strings,
            exclusions,
            paths,
        },
    )?;
    report.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(report)
}

// ─── Forget ─────────────────────────────────────────────────────────

/// Outcome of [`forget`], and the `--json` output of `profile forget`.
#[derive(Debug, Default, serde::Serialize)]
pub struct Forgotten {
    /// Paths whose entry was removed, and paths that carried none.
    pub removed: usize,
    pub absent: usize,
    /// Empty directories the grant had created, removed again.
    pub placeholders_removed: usize,
    /// Paths that could not be completed; they stay recorded.
    pub failed: Vec<Item>,
}

/// `profile forget`: remove the group's ACE from every recorded
/// object, the empty directories the grant created, and the record.
/// Every DACL is left as it was, minus this grant's entries. A path
/// that cannot be completed stays recorded, and so the grant still
/// counts as existing.
pub fn forget(store: &Store<'_>, ids: &Ids) -> Result<Forgotten> {
    // Without the install record the group's SID comes from the
    // account database, if the group is still there: its ACEs must be
    // recognised to be removed. If the group is gone, so is every
    // token that could match them.
    let named;
    let ids = if ids.group_sid.is_none() {
        named = Ids {
            group_sid: crate::sid::lookup_account_sid(crate::user::SANDBOX_GROUP).ok(),
            ..ids.clone()
        };
        &named
    } else {
        ids
    };
    let marker = read_marker_at(store.key)?;
    let all = all_recorded(store, &marker)?;
    let mut out = Forgotten::default();
    let mut failed_paths: HashSet<&str> = HashSet::new();
    for r in &all {
        match strip(store, ids, r) {
            Ok(true) => out.removed += 1,
            Ok(false) => out.absent += 1,
            Err(e) => {
                eprintln!("srt-win: profile forget '{}': {e:#}", r.path);
                failed_paths.insert(&r.path);
                out.failed.push(Item {
                    path: r.path.clone(),
                    reason: format!("{e:#}"),
                });
            }
        }
    }
    // Directories the grant created, deepest first, if still the same
    // object and still empty.
    let mut created: Vec<&Recorded> = all
        .iter()
        .filter(|r| r.created && !failed_paths.contains(r.path.as_str()))
        .collect();
    created.sort_by_key(|r| std::cmp::Reverse(r.path.len()));
    for r in created {
        let same = open_no_follow(&r.path, FILE_READ_ATTRIBUTES).is_ok_and(|o| {
            o.is_dir
                && skip_reason(o.attrs, true).is_none()
                && r.file_id.is_none_or(|id| id == o.id)
        });
        if same && std::fs::remove_dir(&r.path).is_ok() {
            out.placeholders_removed += 1;
        }
    }
    if out.failed.is_empty() {
        clear_marker(store.key)?;
        if store.key == persist::MARKER_KEY {
            persist::marker_clear_ever_if_unused(store.conn)?;
        }
    } else {
        write_marker(
            store.key,
            &Marker {
                header: marker.header.map(|h| Header {
                    complete: false,
                    ..h
                }),
                extra: marker.extra,
                exclusions: marker.exclusions,
                paths: all
                    .iter()
                    .filter(|r| failed_paths.contains(r.path.as_str()))
                    .cloned()
                    .collect(),
            },
        )?;
    }
    Ok(out)
}

/// `srt-win uninstall`: forget the calling user's profile grant.
/// Does nothing, and creates no state, when none is recorded.
pub fn forget_everything() -> Result<Option<Forgotten>> {
    let marker_empty = read_marker_at(persist::MARKER_KEY).is_ok_and(|m| m.is_empty());
    let db_empty = match crate::state_db::open_db_ro() {
        Ok(Some(conn)) => db_has_rows(&conn).is_ok_and(|rows| !rows),
        Ok(None) => true,
        Err(_) => false,
    };
    if marker_empty && db_empty {
        return Ok(None);
    }
    let ids = Ids::load()?;
    let holder = crate::state_db::HolderPid(std::process::id());
    let (out, _) =
        crate::state_db::with_init_lock(holder, false, |db| forget(&Store::of(db.conn()), &ids))?;
    Ok(Some(out))
}

// ─── Status ─────────────────────────────────────────────────────────

/// Whether `path` (as a tool would be given it, without the `\\?\`
/// prefix) is a file the grant makes readable: recorded as a granted
/// file, or beneath a recorded granted directory.
fn covered(paths: &[Recorded], path: &str) -> bool {
    let p = path_id::strip_extended_prefix(path).to_lowercase();
    paths.iter().any(|r| {
        let at = path_id::strip_extended_prefix(&r.path).to_lowercase();
        match r.kind {
            Kind::File => at == p,
            Kind::Granted => {
                p.len() > at.len() && p.starts_with(&at) && p.as_bytes()[at.len()] == b'\\'
            }
            _ => false,
        }
    })
}

/// `profile status`: what is recorded, and whether it is a complete
/// grant of the current list for the profile that is there now.
///
/// `state` is `none`; `current`; `outdated` (another list version,
/// another profile directory, or the directory is another object);
/// `incomplete` (a run that did not finish, or that could not write
/// an exclusion); or `unknown` (the record cannot be read). Reads the
/// registry and opens the profile directory; touches nothing below
/// it. With `current`, `env` holds the configuration pointers
/// ([`plan::env_pointers`]) whose files exist and are covered.
pub fn status_json(key: &str, layout: Result<Layout>, with_paths: bool) -> serde_json::Value {
    use serde_json::json;
    let m = match read_marker_at(key) {
        Ok(m) => m,
        Err(e) => return json!({ "state": "unknown", "reason": format!("{e:#}") }),
    };
    if m.is_empty() {
        return json!({ "state": "none", "list_version": plan::LIST_VERSION });
    }
    let count = |k: Kind| m.paths.iter().filter(|r| r.kind == k).count();
    let mut out = json!({
        "list_version": plan::LIST_VERSION,
        "recorded_list_version": m.header.as_ref().map(|h| h.list_version),
        "profile": m.header.as_ref().map(|h| h.profile.as_str()),
        "extra_exclusions": m.extra,
        "exclusions": m.exclusions,
        "containers": count(Kind::Container),
        "granted": count(Kind::Granted),
        "files": count(Kind::File),
        "denied": count(Kind::Denied),
    });
    if with_paths {
        out["paths"] = m
            .paths
            .iter()
            .map(|r| json!({ "path": r.path, "kind": r.kind.as_str() }))
            .collect();
    }
    let (state, reason): (&str, Option<String>) = match (&m.header, &layout) {
        (None, _) => (
            "incomplete",
            Some("paths are recorded without a grant: a removal did not finish".to_owned()),
        ),
        (Some(h), _) if !h.complete => (
            "incomplete",
            Some("the last run did not finish, or could not write an exclusion".to_owned()),
        ),
        (Some(h), _) if h.list_version != plan::LIST_VERSION => (
            "outdated",
            Some(format!(
                "made with list version {}; this build has {}",
                h.list_version,
                plan::LIST_VERSION
            )),
        ),
        (Some(_), Err(e)) => ("unknown", Some(format!("{e:#}"))),
        (Some(h), Ok(l)) if h.profile.to_lowercase() != l.profile.to_lowercase() => (
            "outdated",
            Some(format!(
                "made for '{}'; the profile is '{}'",
                h.profile, l.profile
            )),
        ),
        (Some(h), Ok(l)) => match open_no_follow(&l.profile, FILE_READ_ATTRIBUTES) {
            Ok(o) if o.id == h.file_id => ("current", None),
            Ok(_) => (
                "outdated",
                Some("the profile directory is not the one the grant was made on".to_owned()),
            ),
            Err(e) => ("unknown", Some(format!("{e:#}"))),
        },
    };
    out["state"] = json!(state);
    if let Some(r) = reason {
        out["reason"] = json!(r);
    }
    if let (true, Ok(l)) = (state == "current", &layout) {
        let shown = |p: &str| path_id::strip_extended_prefix(p).to_owned();
        let readable =
            |p: &str| std::fs::metadata(p).is_ok_and(|md| md.is_file()) && covered(&m.paths, p);
        let env: serde_json::Map<String, serde_json::Value> = plan::env_pointers(
            &shown(&l.profile),
            l.roaming.as_deref().map(shown).as_deref(),
            &readable,
        )
        .into_iter()
        .map(|(k, v)| (k.to_owned(), json!(v)))
        .collect();
        out["env"] = serde_json::Value::Object(env);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{self, AceView};

    const TEST_KEY: &str = r"Software\sandbox-runtime\ProfileGrantTest";
    /// Guests stands in for the sandbox group: resolvable, and never
    /// the identity the tests run as.
    const GROUP: &str = "S-1-5-32-546";
    const RX: u32 = 0x0012_00a9;
    const LIST: u32 = 0x0010_00a1;
    const ALL: u32 = 0x001f_01ff;

    fn ids() -> Ids {
        Ids {
            group_sid: Some(GROUP.to_owned()),
            sandbox_user_sid: None,
            real_user_sid: crate::sid::current_user_sid().unwrap(),
        }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("srtwin-profile-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn canon(p: &std::path::Path) -> String {
        path_id::canonicalize_path(p.to_str().unwrap()).unwrap().0
    }

    fn write(p: &std::path::Path, rel: &str) {
        let f = p.join(rel);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, b"x").unwrap();
    }

    fn junction(link: &std::path::Path, target: &std::path::Path) {
        let st = std::process::Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(st.status.success(), "mklink /J: {st:?}");
    }

    /// The group's ACEs on `p`: `(explicit?, deny?, flags, mask)`.
    fn group_aces(p: &std::path::Path) -> Vec<(bool, bool, u8, u32)> {
        acl::read_aces(p.to_str().unwrap())
            .unwrap()
            .into_iter()
            .filter(|a| a.sid == GROUP)
            .map(|a| (!a.inherited, a.deny, a.flags, a.mask))
            .collect()
    }

    fn explicit(p: &std::path::Path) -> Vec<AceView> {
        acl::read_aces(p.to_str().unwrap())
            .unwrap()
            .into_iter()
            .filter(|a| !a.inherited)
            .collect()
    }

    #[test]
    fn record_entries_round_trip() {
        let id = FileId {
            volume_serial: 0x0123_4567_89ab_cdef,
            id128: *b"0123456789abcdef",
        };
        let h = Header {
            list_version: 7,
            complete: true,
            file_id: id,
            profile: r"\\?\C:\Users\a|b".to_owned(),
        };
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
        for bad in ["", "2|7|1|x|p", "1|7|2|x|p", &h.encode()[..20], "1|x"] {
            assert!(Header::decode(bad).is_err(), "{bad}");
        }
        for (kind, created, file_id) in [
            (Kind::Container, false, Some(id)),
            (Kind::Granted, false, Some(id)),
            (Kind::File, false, None),
            (Kind::Denied, true, None),
        ] {
            let r = Recorded {
                path: r"\\?\C:\Users\me\a|b".to_owned(),
                kind,
                created,
                file_id,
            };
            assert_eq!(Recorded::decode(&r.encode()).unwrap(), r);
        }
        for bad in [
            "",
            "-|granted|0|",
            "-|nope|0|p",
            "zz|granted|0|p",
            "-|granted|2|p",
        ] {
            assert!(Recorded::decode(bad).is_err(), "{bad}");
        }
    }

    /// The ordinary token is allowed only on a positive "no grant".
    #[test]
    fn ordinary_token_is_refused_while_a_grant_is_recorded_or_unreadable() {
        assert_eq!(block_reason_from(Ok(Marker::default())), None);
        let r = block_reason_from(Err(anyhow!("access denied"))).unwrap();
        assert!(r.contains("cannot be read"), "{r}");
        let entry = Recorded {
            path: r"\\?\C:\Users\me".to_owned(),
            kind: Kind::Container,
            created: false,
            file_id: None,
        };
        // Paths without a header (a removal that did not finish)
        // refuse as a grant does.
        let r = block_reason_from(Ok(Marker {
            paths: vec![entry.clone()],
            ..Default::default()
        }))
        .unwrap();
        assert!(r.contains("1 path(s)"), "{r}");
        let r = block_reason_from(Ok(Marker {
            header: Some(Header {
                list_version: plan::LIST_VERSION,
                complete: false,
                file_id: FileId::from_bytes(&[0u8; 24]).unwrap(),
                profile: r"\\?\C:\Users\me".to_owned(),
            }),
            ..Default::default()
        }))
        .unwrap();
        assert!(r.contains("profile read grant exists"), "{r}");
    }

    #[test]
    fn links_and_cloud_placeholders_are_recognised_by_attribute() {
        assert_eq!(skip_reason(ATTR_DIRECTORY, true), None);
        assert_eq!(skip_reason(0x20, false), None);
        assert!(skip_reason(ATTR_DIRECTORY | ATTR_REPARSE_POINT, true).is_some());
        assert!(skip_reason(ATTR_REPARSE_POINT, false).is_some());
        for cloud in [
            ATTR_OFFLINE,
            ATTR_RECALL_ON_OPEN,
            ATTR_RECALL_ON_DATA_ACCESS,
        ] {
            assert!(skip_reason(ATTR_DIRECTORY | cloud, true).is_some());
            // A file that is merely not downloaded is an ordinary
            // file as far as its access list goes.
            assert_eq!(skip_reason(cloud, false), None);
        }
    }

    #[test]
    fn a_directory_is_listed_through_its_handle_and_a_junction_is_not_entered() {
        let base = scratch("list");
        let prof = base.join("p");
        let outside = base.join("outside");
        write(&prof, r"sub\f.txt");
        write(&prof, "top.txt");
        write(&outside, "secret.txt");
        junction(&prof.join("j"), &outside);
        let profile = canon(&prof);
        let mut tree = DiskTree { profile: &profile };
        let mut entries = tree.list(&[]).unwrap();
        entries.sort_by(|a, b| a.name.long.cmp(&b.name.long));
        let got: Vec<(&str, bool, bool)> = entries
            .iter()
            .map(|e| (e.name.long.as_str(), e.is_dir, e.skip.is_some()))
            .collect();
        assert_eq!(
            got,
            [
                ("j", true, true),
                ("sub", true, false),
                ("top.txt", false, false)
            ]
        );
        // The junction itself is what gets opened, never its target,
        // and it is not listed.
        let j = open_for_stamp(&format!("{profile}\\j")).unwrap();
        assert!(skip_reason(j.attrs, j.is_dir).is_some());
        assert_ne!(
            j.id,
            path_id::capture_file_id(&canon(&outside)).unwrap(),
            "the open followed the junction"
        );
        assert!(tree.list(&["j".to_owned()]).is_err());
        // A path THROUGH the junction opens the target, and is caught
        // by where the handle says it is.
        let through = format!("{profile}\\j\\secret.txt");
        let o = open_no_follow(&through, ACCESS_STAMP).unwrap();
        assert!(verify_location(&o, &through).is_err());
        let direct = format!("{profile}\\sub");
        let o = open_no_follow(&direct, ACCESS_STAMP).unwrap();
        verify_location(&o, &direct).unwrap();
        std::fs::remove_dir(prof.join("j")).ok();
        std::fs::remove_dir_all(&base).ok();
    }

    /// The system's propagation of an inheriting ACE reaches the
    /// files below the directory and stops at a junction: the target
    /// tree's DACLs are what they were, after the ACE is written and
    /// after it is removed again.
    #[test]
    fn inherited_entries_do_not_cross_a_junction() {
        let base = scratch("junction");
        let granted = base.join("granted");
        let outside = base.join("outside");
        write(&granted, r"inner\f.txt");
        write(&outside, r"deep\secret.txt");
        junction(&granted.join("j"), &outside);
        let targets = [
            outside.clone(),
            outside.join("deep"),
            outside.join(r"deep\secret.txt"),
        ];
        let before: Vec<Vec<AceView>> = targets
            .iter()
            .map(|p| acl::read_aces(p.to_str().unwrap()).unwrap())
            .collect();
        let ids = ids();
        let want = acl::persistent_aces(&acl::PersistentWant {
            group_sid: GROUP,
            real_user_sid: &ids.real_user_sid,
            capability_sid: None,
            deny: None,
            deny_fdc: false,
            deny_delete: false,
            profile: Some(acl::ProfileAce::Granted),
        });
        let g = canon(&granted);
        let o = open_for_stamp(&g).unwrap();
        let target = acl::DaclTarget::Handle(o.h.raw(), &g);
        acl::write_persistent_aces_at(target, &ids.trustees(), &want).unwrap();
        assert_eq!(group_aces(&granted), [(true, false, 0x3, RX)]);
        assert_eq!(
            group_aces(&granted.join(r"inner\f.txt")),
            [(false, false, 0, RX)],
            "the ACE did not reach a file below the granted directory"
        );
        let unchanged = |when: &str| {
            for (p, was) in targets.iter().zip(&before) {
                assert_eq!(
                    &acl::read_aces(p.to_str().unwrap()).unwrap(),
                    was,
                    "{when}: the DACL of {} changed through the junction",
                    p.display()
                );
            }
        };
        unchanged("after the grant");
        acl::write_persistent_aces_at(target, &ids.trustees(), &[]).unwrap();
        assert!(group_aces(&granted.join(r"inner\f.txt")).is_empty());
        unchanged("after the removal");
        drop(o);
        std::fs::remove_dir(granted.join("j")).ok();
        std::fs::remove_dir_all(&base).ok();
    }

    /// A whole grant, refresh and removal on a made-up profile, read
    /// back as DACLs.
    #[test]
    fn grant_refresh_and_forget_on_a_profile_tree() {
        let base = scratch("grant");
        let prof = base.join("profile");
        let outside = base.join("outside");
        for f in [
            r"Documents\a.txt",
            r".ssh\id_ed25519",
            ".npmrc",
            "stray.txt",
            ".netrc",
            r".cargo\credentials.toml",
            r".cargo\config.toml",
            r".cargo\bin\tool.exe",
            r"AppData\Roaming\npm\x.cmd",
            r"AppData\Roaming\Microsoft\Credentials\c",
            r"AppData\Local\Temp\t.tmp",
        ] {
            write(&prof, f);
        }
        write(&outside, "secret.txt");
        junction(&prof.join("link"), &outside);
        junction(&prof.join(r"Documents\inner-link"), &outside);
        let outside_before = explicit(&outside);
        let outside_all = acl::read_aces(outside.to_str().unwrap()).unwrap();

        // What every path the grant will touch carries now.
        let touched = [
            "",
            "Documents",
            ".ssh",
            ".npmrc",
            ".netrc",
            ".cargo",
            r".cargo\credentials.toml",
            r".cargo\config.toml",
            r".cargo\bin",
            "AppData",
            r"AppData\Roaming",
            r"AppData\Roaming\npm",
            r"AppData\Roaming\Microsoft",
            r"AppData\Roaming\Microsoft\Credentials",
            r"AppData\Local",
            r"AppData\Local\Temp",
        ];
        let snapshot =
            || -> Vec<Vec<AceView>> { touched.iter().map(|t| explicit(&prof.join(t))).collect() };
        let pre = snapshot();

        let conn = crate::state_db::open_memory_db_for_tests();
        let store = Store {
            conn: &conn,
            key: TEST_KEY,
        };
        clear_marker(TEST_KEY).unwrap();
        let ids = ids();
        let layout = Layout::resolve(Some(prof.to_str().unwrap())).unwrap();
        let report = grant(&store, &ids, &layout, &[], false, false).unwrap();
        assert!(report.complete, "{report:?}");
        assert!(report.failed.is_empty(), "{report:?}");

        let allow = |inherit: u8, mask: u32| vec![(true, false, inherit, mask)];
        let deny_dir = vec![(true, true, 0x3, ALL)];
        // Containers: one entry, not inherited by anything.
        for c in [
            "",
            ".cargo",
            "AppData",
            r"AppData\Roaming",
            r"AppData\Roaming\Microsoft",
            r"AppData\Local",
        ] {
            assert_eq!(group_aces(&prof.join(c)), allow(0, LIST), "container '{c}'");
        }
        // Granted directories, and a file below one.
        for g in ["Documents", r".cargo\bin", r"AppData\Roaming\npm"] {
            assert_eq!(group_aces(&prof.join(g)), allow(0x3, RX), "granted '{g}'");
        }
        assert_eq!(
            group_aces(&prof.join(r"Documents\a.txt")),
            [(false, false, 0, RX)]
        );
        // Files granted on their own; a file of the root that is not
        // named gets nothing.
        for f in [".npmrc", r".cargo\config.toml"] {
            assert_eq!(group_aces(&prof.join(f)), allow(0, RX), "file '{f}'");
        }
        assert!(group_aces(&prof.join("stray.txt")).is_empty());
        // Exclusions: the deny, and nothing that allows.
        for d in [
            ".ssh",
            r"AppData\Roaming\Microsoft\Credentials",
            r"AppData\Local\Temp",
        ] {
            assert_eq!(group_aces(&prof.join(d)), deny_dir, "excluded '{d}'");
        }
        for f in [".netrc", r".cargo\credentials.toml"] {
            let a = group_aces(&prof.join(f));
            assert!(
                a.len() == 1 && a[0].0 && a[0].1 && a[0].3 == ALL,
                "excluded file '{f}': {a:?}"
            );
        }
        assert_eq!(
            group_aces(&prof.join(r".ssh\id_ed25519")),
            [(false, true, 0, ALL)]
        );
        // An excluded directory that was missing exists now, denied.
        assert!(report.placeholders > 0);
        assert_eq!(group_aces(&prof.join(".aws")), deny_dir);
        // The top-level junction is skipped and reported; neither it
        // nor the one inside a granted directory changed its target.
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.path.to_lowercase().ends_with(r"\link")),
            "{:?}",
            report.skipped
        );
        assert_eq!(explicit(&outside), outside_before);
        assert_eq!(
            acl::read_aces(outside.to_str().unwrap()).unwrap(),
            outside_all
        );
        assert!(group_aces(&outside.join("secret.txt")).is_empty());

        // The invariant on disk: no excluded path has an ancestor in
        // the profile with an allow that inherits.
        for excluded in [
            r".ssh\id_ed25519",
            ".netrc",
            r".cargo\credentials.toml",
            r"AppData\Roaming\Microsoft\Credentials\c",
            r"AppData\Local\Temp\t.tmp",
            r".aws\credentials",
        ] {
            let mut up = prof.join(excluded);
            while up.pop() && up.starts_with(&prof) {
                let inheriting: Vec<_> = group_aces(&up)
                    .into_iter()
                    .filter(|(explicit, deny, flags, _)| *explicit && !*deny && flags & 0x3 != 0)
                    .collect();
                assert!(
                    inheriting.is_empty(),
                    "{} carries an inheriting allow above '{excluded}': {inheriting:?}",
                    up.display()
                );
            }
        }
        // … so an exclusion that is deleted and created again, or
        // replaced by a rename, has no allow of any origin.
        std::fs::remove_dir_all(prof.join(".ssh")).unwrap();
        write(&prof, r".ssh\id_ed25519");
        std::fs::write(prof.join(".netrc.tmp"), b"new").unwrap();
        std::fs::rename(prof.join(".netrc.tmp"), prof.join(".netrc")).unwrap();
        std::fs::write(prof.join(r".cargo\c.tmp"), b"new").unwrap();
        std::fs::rename(
            prof.join(r".cargo\c.tmp"),
            prof.join(r".cargo\credentials.toml"),
        )
        .unwrap();
        for p in [
            ".ssh",
            r".ssh\id_ed25519",
            ".netrc",
            r".cargo\credentials.toml",
        ] {
            assert!(
                !group_aces(&prof.join(p)).iter().any(|a| !a.1),
                "recreated '{p}' is allowed: {:?}",
                group_aces(&prof.join(p))
            );
        }

        // A second run with nothing new on disk but the recreated
        // exclusions: they are denied again, nothing else is written.
        write(&prof, r"NewTop\n.txt");
        assert!(group_aces(&prof.join("NewTop")).is_empty());
        let again = grant(&store, &ids, &layout, &[], false, false).unwrap();
        assert!(again.complete && again.failed.is_empty(), "{again:?}");
        assert_eq!(group_aces(&prof.join("NewTop")), allow(0x3, RX));
        assert_eq!(group_aces(&prof.join(".ssh")), deny_dir);
        assert!(group_aces(&prof.join(".netrc")).iter().all(|a| a.1));
        // .ssh, .netrc, credentials.toml, NewTop.
        assert_eq!(again.writes, 4, "{again:?}");
        let third = grant(&store, &ids, &layout, &[], false, false).unwrap();
        assert_eq!(third.writes, 0, "{third:?}");
        assert_eq!(explicit(&outside), outside_before);

        // The record says so.
        let st = status_json(TEST_KEY, Ok(layout.clone()), true);
        assert_eq!(st["state"], "current", "{st}");
        assert_eq!(
            st["env"]["NPM_CONFIG_USERCONFIG"]
                .as_str()
                .map(str::to_lowercase),
            Some(
                path_id::strip_extended_prefix(&format!("{}\\.npmrc", layout.profile))
                    .to_lowercase()
            )
        );
        assert!(st["paths"].as_array().is_some_and(|p| !p.is_empty()));

        // A new exclusion from configuration turns a granted
        // directory into a denied one in one run.
        let with_extra =
            grant(&store, &ids, &layout, &["NewTop".to_owned()], false, false).unwrap();
        assert!(with_extra.complete, "{with_extra:?}");
        assert_eq!(group_aces(&prof.join("NewTop")), deny_dir);
        assert!(group_aces(&prof.join(r"NewTop\n.txt")).iter().all(|a| a.1));

        // A refresh that names no exclusion keeps the one an earlier
        // run added, and the record lists it with the built-in ones.
        let kept = grant(&store, &ids, &layout, &[], false, false).unwrap();
        assert!(kept.complete, "{kept:?}");
        assert_eq!(kept.writes, 0, "{kept:?}");
        assert_eq!(group_aces(&prof.join("NewTop")), deny_dir);
        let st = status_json(TEST_KEY, Ok(layout.clone()), false);
        assert_eq!(st["extra_exclusions"], serde_json::json!(["NewTop"]));
        let listed: Vec<String> = st["exclusions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_lowercase())
            .collect();
        for want in [
            r"\newtop",
            r"\.ssh",
            r"\appdata\local\temp",
            r"\ntuser.dat*",
        ] {
            let full = format!("{}{want}", layout.profile.to_lowercase());
            assert!(listed.contains(&full), "{full} not in {listed:?}");
        }
        // Naming it again changes nothing; replacing the added list
        // with an empty one is what re-admits it.
        let same = grant(&store, &ids, &layout, &["newtop".to_owned()], false, false).unwrap();
        assert_eq!(same.writes, 0, "{same:?}");
        let replaced = grant(&store, &ids, &layout, &[], true, false).unwrap();
        assert!(replaced.complete, "{replaced:?}");
        assert_eq!(group_aces(&prof.join("NewTop")), allow(0x3, RX));
        assert_eq!(
            status_json(TEST_KEY, Ok(layout.clone()), false)["extra_exclusions"],
            serde_json::json!([])
        );
        // No built-in exclusion went with it.
        assert_eq!(group_aces(&prof.join(".ssh")), deny_dir);

        // Forget: every touched DACL is what it was, the created
        // directories are gone, nothing is recorded.
        let f = forget(&store, &ids).unwrap();
        assert!(f.failed.is_empty(), "{f:?}");
        assert!(f.placeholders_removed > 0, "{f:?}");
        assert!(!prof.join(".aws").exists());
        // `.ssh`, `.netrc` and `credentials.toml` were replaced above;
        // every other touched path is compared with its snapshot.
        for ((t, was), now) in touched.iter().zip(&pre).zip(&snapshot()) {
            if [".ssh", ".netrc", r".cargo\credentials.toml"].contains(t) {
                assert!(group_aces(&prof.join(t)).is_empty(), "'{t}'");
            } else {
                assert_eq!(now, was, "'{t}' after forget");
            }
        }
        assert!(group_aces(&prof.join(r"Documents\a.txt")).is_empty());
        assert!(group_aces(&prof.join("NewTop")).is_empty());
        assert!(read_marker_at(TEST_KEY).unwrap().is_empty());
        assert!(!db_has_rows(&conn).unwrap());
        assert_eq!(status_json(TEST_KEY, Ok(layout), false)["state"], "none");

        std::fs::remove_dir(prof.join("link")).ok();
        std::fs::remove_dir(prof.join(r"Documents\inner-link")).ok();
        std::fs::remove_dir_all(&base).ok();
    }
}
