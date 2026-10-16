//! The pure half of the profile read grant (`srt-win profile …`,
//! [`crate::profile`]): which paths of the real user's profile are
//! never readable, how a name is matched against them, which
//! directories get which kind of entry, and which configuration files
//! an embedder may point a tool at. No Windows call is made here, so
//! every rule in this file is unit-tested without a filesystem.
//!
//! ## The walk rule
//!
//! The walk goes DOWN from the profile root. A directory is one of:
//!
//! - a **container**: it gets one entry that does not inherit
//!   (traverse, list, read attributes), and each of its children is
//!   looked at on its own;
//! - **granted**: it gets one inheriting read + execute entry and is
//!   not descended;
//! - **denied**: a protected exclusion. It gets an inheriting read
//!   deny and is not descended;
//! - **ungranted**: an ungranted-only exclusion (the temporary
//!   directory), or a directory inside one. Nothing is written on it:
//!   no allow of any kind, and no deny. It is descended only to reach
//!   a protected exclusion inside it, which is denied as anywhere
//!   else; nothing else in it is looked at;
//! - **skipped**: a reparse point, a cloud placeholder, or a directory
//!   that could not be opened. Nothing is written on it.
//!
//! A directory is a container exactly when some exclusion could lie
//! beneath it, whether or not that exclusion exists on disk today; the
//! profile root always is one. So no excluded path ever has an
//! ancestor that carries an inheriting allow: an excluded directory or
//! file that is deleted and created again, or replaced by a rename,
//! inherits nothing.
//!
//! ## Two kinds of exclusion
//!
//! A **protected** exclusion is a store of credentials, keys or
//! tokens. It is never granted, it is read-denied, and a session may
//! not grant a path that is it, lies inside it, or lies above it.
//!
//! An **ungranted-only** exclusion is a directory that is not readable
//! by default without being a secret as a whole: the user's temporary
//! directory, which every program writes to and in which sessions and
//! this library routinely stage directories of their own. Nothing in
//! it is granted here and nothing above it carries an inheriting
//! allow, so it is exactly as unreadable as before the grant. It is
//! not denied, so a session can grant a directory inside it; a session
//! grant of the directory itself, or of one above it, would cover
//! everything in it and is refused like one above a protected path.
//!
//! ## Links
//!
//! A junction, a symbolic link or a cloud placeholder is never written
//! on or through. But a link can stand where a rule points: with
//! `.ssh` a link to `dotfiles\.ssh`, skipping the link alone would
//! leave the keys in a `dotfiles` directory that no rule names and
//! that would be granted whole. So a link at or above a path some rule
//! covers is resolved, and if its target lies inside the profile the
//! rules that would have applied beneath the link are applied beneath
//! the target as well ([`plan_resolved`]): the target is denied, or
//! becomes a container with the right children denied. The added
//! rules are recorded with the grant like any other exclusion, in
//! their resolved form — which is the form a session's path is
//! compared in. A target outside the profile gets nothing: nothing
//! there is granted either.
//!
//! A file directly inside a container is readable only if it is
//! granted itself. In the profile root that is the short list in
//! [`READABLE_ROOT_FILES`]: the root is where the registry hives and
//! the dot-files of tools nobody listed live. In every other container
//! each file that is not excluded is granted — a container is a
//! directory that would have been granted whole but for one named
//! item in it (`.cargo`, `.gradle`, `.config\git`), and its remaining
//! files are the configuration the grant is for. The entry sits on the
//! file itself and does not inherit, so a file that replaces it is not
//! readable until the next run.

/// Version of the exclusion list and of the walk rule. A recorded
/// grant made with another version is reported as outdated.
pub const LIST_VERSION: u32 = 3;

/// What a built-in exclusion's path is relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    /// The profile directory.
    Profile,
    /// The roaming application-data known folder.
    Roaming,
    /// The local application-data known folder.
    Local,
}

/// One built-in exclusion. `path` uses `\`; a component that is `*`
/// matches any one name, and a component ending in `*` any name with
/// that prefix.
#[derive(Debug, Clone, Copy)]
pub struct Excl {
    pub base: Base,
    pub path: &'static str,
    /// A directory (denied with an inheriting entry, and created empty
    /// when missing) or a file.
    pub dir: bool,
    /// False for a directory whose deny is written by its owner in
    /// this crate; it is then only kept out of the grant.
    pub stamp: bool,
    /// Ungranted-only (see the module doc): kept out of the grant,
    /// not denied. Every other entry is protected.
    pub ungranted_only: bool,
    /// Create the directory, empty, when it is missing, so the deny
    /// has an object to sit on. Not set for the stores of tools most
    /// profiles do not have: a missing one is covered without it —
    /// nothing above it carries an inheriting allow, and a session
    /// may not grant a path above it.
    pub create: bool,
}

/// A protected directory.
const fn dir(base: Base, path: &'static str) -> Excl {
    Excl {
        base,
        path,
        dir: true,
        stamp: true,
        ungranted_only: false,
        create: true,
    }
}

/// A protected directory that is not created when missing.
const fn store(base: Base, path: &'static str) -> Excl {
    Excl {
        base,
        path,
        dir: true,
        stamp: true,
        ungranted_only: false,
        create: false,
    }
}

/// A protected file.
const fn file(base: Base, path: &'static str) -> Excl {
    Excl {
        base,
        path,
        dir: false,
        stamp: true,
        ungranted_only: false,
        create: false,
    }
}

/// An ungranted-only directory.
const fn ungranted(base: Base, path: &'static str) -> Excl {
    Excl {
        base,
        path,
        dir: true,
        stamp: false,
        ungranted_only: true,
        create: false,
    }
}

use Base::{Local, Profile, Roaming};

/// Every path that is never granted and carries a read deny for the
/// sandbox group. Configuration can add to this list
/// ([`Rules::new`]'s `extra`); nothing removes an entry.
pub const BUILT_IN: &[Excl] = &[
    // Keys and sign-ins kept in dot-directories of the profile.
    dir(Profile, ".ssh"),
    dir(Profile, ".gnupg"),
    dir(Profile, ".aws"),
    dir(Profile, ".azure"),
    dir(Profile, ".kube"),
    dir(Profile, ".docker"),
    dir(Profile, ".terraform.d"),
    dir(Profile, ".wrangler"),
    dir(Profile, ".vercel"),
    dir(Profile, ".netlify"),
    dir(Profile, ".claude"),
    // The same kind of store under the XDG-style `.config`, which
    // tools ported from other systems use on Windows too.
    dir(Profile, r".config\gcloud"),
    dir(Profile, r".config\gh"),
    dir(Profile, r".config\configstore"),
    file(Profile, r".config\git\credentials"),
    // Where those tools keep the same sign-ins when they follow the
    // Windows convention instead.
    dir(Roaming, "gcloud"),
    dir(Roaming, "GitHub CLI"),
    dir(Roaming, "gnupg"),
    dir(Roaming, "com.vercel.cli"),
    dir(Roaming, "netlify"),
    dir(Roaming, "xdg.config"),
    dir(Roaming, "terraform.d"),
    file(Roaming, "terraform.rc"),
    dir(Local, "heroku"),
    // Plaintext token files and directories of further command-line
    // tools, at the locations each uses on Windows and, where the tool
    // also follows the XDG convention, under `.config`.
    store(Local, "github-copilot"),
    store(Profile, r".config\github-copilot"),
    store(Profile, r".config\doctl"),
    store(Roaming, "doctl"),
    store(Profile, r".config\op"),
    file(Profile, r".config\hub"),
    file(Profile, r".gem\credentials"),
    file(Profile, r".pulumi\credentials.json"),
    file(Roaming, r"postgresql\pgpass.conf"),
    file(Profile, ".pgpass"),
    file(Roaming, r"Composer\auth.json"),
    file(Profile, r".composer\auth.json"),
    file(Profile, r".fly\config.yml"),
    file(Profile, ".databrickscfg"),
    file(Profile, ".boto"),
    file(Profile, ".s3cfg"),
    file(Roaming, "s3cmd.ini"),
    store(Profile, ".kaggle"),
    store(Profile, ".snowsql"),
    store(Profile, ".oci"),
    store(Profile, ".bluemix"),
    store(Profile, ".ibmcloud"),
    store(Profile, ".railway"),
    store(Profile, ".supabase"),
    // Package-feed sign-in caches: the token stores of the credential
    // providers, as opposed to the configuration files that name a
    // feed (those are readable — see `READABLE_CONFIG`).
    dir(Local, ".IdentityService"),
    dir(Local, "MicrosoftCredentialProvider"),
    // Credential files.
    file(Profile, ".git-credentials"),
    file(Profile, ".netrc"),
    file(Profile, "_netrc"),
    file(Profile, ".pypirc"),
    file(Profile, ".vault-token"),
    file(Profile, ".terraformrc"),
    file(Profile, r".cargo\credentials"),
    file(Profile, r".cargo\credentials.toml"),
    file(Profile, r".gradle\enterprise\keys.properties"),
    file(Profile, r".gradle\develocity\keys.properties"),
    // The user's registry hives and their logs.
    file(Profile, "NTUSER.DAT*"),
    file(Profile, "ntuser.ini"),
    file(Profile, "ntuser.pol"),
    file(Local, r"Microsoft\Windows\UsrClass.dat*"),
    // Browser profiles: cookies, saved passwords, session storage.
    dir(Local, r"Google\Chrome\User Data"),
    dir(Local, r"Microsoft\Edge\User Data"),
    dir(Local, r"BraveSoftware\Brave-Browser\User Data"),
    dir(Roaming, r"Mozilla\Firefox"),
    dir(Local, r"Mozilla\Firefox"),
    // The other channels of those browsers, the other browsers built
    // on the same engines, and the mail client that shares Firefox's
    // profile layout.
    store(Local, r"Google\Chrome Beta\User Data"),
    store(Local, r"Google\Chrome Dev\User Data"),
    store(Local, r"Google\Chrome SxS\User Data"),
    store(Local, r"Chromium\User Data"),
    store(Local, r"Microsoft\Edge Beta\User Data"),
    store(Local, r"Microsoft\Edge Dev\User Data"),
    store(Local, r"Microsoft\Edge SxS\User Data"),
    store(Local, r"BraveSoftware\Brave-Browser-Beta\User Data"),
    store(Local, r"BraveSoftware\Brave-Browser-Nightly\User Data"),
    store(Local, r"Vivaldi\User Data"),
    store(Local, r"Yandex\YandexBrowser\User Data"),
    store(Roaming, "Opera Software"),
    store(Local, "Opera Software"),
    store(Roaming, r"Mozilla\SeaMonkey"),
    store(Roaming, "Thunderbird"),
    store(Local, "Thunderbird"),
    // Embedded browser profiles of desktop applications.
    dir(Local, r"*\EBWebView"),
    dir(Local, r"Microsoft\*\EBWebView"),
    // Password managers.
    dir(Roaming, "1Password"),
    dir(Local, "1Password"),
    dir(Roaming, "Bitwarden"),
    dir(Roaming, "Bitwarden CLI"),
    dir(Roaming, "KeePass"),
    dir(Roaming, "KeePassXC"),
    // Windows' own per-user secret stores: Credential Manager, the
    // DPAPI master keys, the vault, private-key containers, and the
    // certificate stores. The last hold certificates, not keys, but
    // they name the user's identities and key containers, and nothing
    // run as the sandbox account reads another user's store through
    // the filesystem, so being readable would buy nothing.
    dir(Roaming, r"Microsoft\Credentials"),
    dir(Roaming, r"Microsoft\Protect"),
    dir(Roaming, r"Microsoft\Vault"),
    dir(Roaming, r"Microsoft\Crypto"),
    dir(Roaming, r"Microsoft\SystemCertificates"),
    dir(Local, r"Microsoft\Credentials"),
    dir(Local, r"Microsoft\Protect"),
    dir(Local, r"Microsoft\Vault"),
    dir(Local, r"Microsoft\Crypto"),
    dir(Local, r"Microsoft\SystemCertificates"),
    // Account token caches and web sessions of the signed-in user.
    // The two caches are protected, not merely ungranted: they hold
    // the cookie and history databases and pages fetched with the
    // user's sign-ins, and nothing stages a directory of its own in
    // them that a session would need to read.
    dir(Local, r"Microsoft\IdentityCache"),
    dir(Local, r"Microsoft\TokenBroker"),
    dir(Local, r"Microsoft\OneAuth"),
    dir(Local, r"Microsoft\Windows\INetCookies"),
    dir(Local, r"Microsoft\Windows\INetCache"),
    dir(Local, r"Microsoft\Windows\WebCache"),
    // Private data of packaged applications.
    dir(Local, "Packages"),
    // This library's state directory (the session database; on
    // Windows its CA key is not in the profile at all, but in the
    // machine store under %ProgramData%). Its owner (`state_db`)
    // writes its access list, deny included, on every open.
    Excl {
        base: Local,
        path: "sandbox-runtime",
        dir: true,
        stamp: false,
        ungranted_only: false,
        create: false,
    },
    // UNGRANTED-ONLY. The user's temporary directory: every program
    // of the user drops files there, so none of it is readable by
    // default; sessions and this library stage directories in it and
    // grant those, so it is not denied as a whole.
    ungranted(Local, "Temp"),
];

/// Files in the profile ROOT that are granted by name. Every other
/// file of the root is left unreadable.
///
/// These can hold the sign-in of a private package feed or a git
/// host. They are readable on purpose: a private feed working inside
/// the sandbox is what the grant is for.
pub const READABLE_ROOT_FILES: &[&str] = &[".npmrc", ".gitconfig"];

/// The configuration files that are readable by design although they
/// can hold a feed sign-in, with what reads them. The root files are
/// granted by name ([`READABLE_ROOT_FILES`]); the others are ordinary
/// files of granted directories or of containers. Documentation and
/// tests read this list; the walk does not.
pub const READABLE_CONFIG: &[(Base, &str, &str)] = &[
    (Profile, ".npmrc", "npm"),
    (Profile, ".gitconfig", "git"),
    (Profile, r".config\git\config", "git"),
    (Roaming, r"pip\pip.ini", "pip"),
    (Profile, r"pip\pip.ini", "pip"),
    (Profile, r".config\pip\pip.conf", "pip"),
    (Roaming, r"NuGet\NuGet.Config", "NuGet"),
    (Profile, r".m2\settings.xml", "Maven"),
    (Profile, r".m2\settings-security.xml", "Maven"),
    (Profile, r".gradle\gradle.properties", "Gradle"),
];

// ─── Names ──────────────────────────────────────────────────────────

/// A file name in the form names are compared in: without an
/// alternate-data-stream suffix (`name:stream`), without the trailing
/// dots and spaces Win32 drops when it opens a name, lower-cased.
pub fn norm_component(name: &str) -> String {
    let base = name.split(':').next().unwrap_or("");
    base.trim_end_matches(['.', ' ']).to_lowercase()
}

/// One component of an exclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pat {
    Lit(String),
    Prefix(String),
    Any,
}

impl Pat {
    fn parse(component: &str) -> Pat {
        if component == "*" {
            Pat::Any
        } else if let Some(prefix) = component.strip_suffix('*') {
            Pat::Prefix(norm_component(prefix))
        } else {
            Pat::Lit(norm_component(component))
        }
    }

    /// Whether a normalized name matches. The empty name (`.`, `..`,
    /// or a name of dots and spaces only) matches nothing.
    fn matches(&self, norm: &str) -> bool {
        if norm.is_empty() {
            return false;
        }
        match self {
            Pat::Lit(l) => l == norm,
            Pat::Prefix(p) => norm.starts_with(p.as_str()),
            Pat::Any => true,
        }
    }
}

/// A directory entry's names: the long one and, where the volume
/// keeps them, the 8.3 one. An exclusion matches if either does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub long: String,
    pub short: Option<String>,
}

impl Name {
    pub fn long(name: &str) -> Name {
        Name {
            long: name.to_owned(),
            short: None,
        }
    }

    fn matched_by(&self, pat: &Pat) -> bool {
        pat.matches(&norm_component(&self.long))
            || self
                .short
                .as_deref()
                .is_some_and(|s| pat.matches(&norm_component(s)))
    }
}

/// `path` split into components, either separator, with a `\\?\`
/// prefix and empty components dropped.
pub fn split_path(path: &str) -> Vec<String> {
    let p = path
        .strip_prefix(r"\\?\")
        .or_else(|| path.strip_prefix("//?/"))
        .unwrap_or(path);
    p.split(['\\', '/'])
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The components of `path` beneath `profile`, or why it cannot be an
/// exclusion: it is not inside the profile, or it holds `.`, `..` or
/// a wildcard. A path with no drive or leading separator is taken as
/// relative to the profile. The profile itself gives `Ok(vec![])`.
pub fn rel_components(profile: &str, path: &str) -> Result<Vec<String>, String> {
    let comps = split_path(path);
    let absolute = path.starts_with(['\\', '/']) || comps.first().is_some_and(|c| c.ends_with(':'));
    let rel = if absolute {
        let root = split_path(profile);
        let inside = comps.len() >= root.len()
            && root
                .iter()
                .zip(&comps)
                .all(|(a, b)| a.to_lowercase() == b.to_lowercase());
        if !inside {
            return Err(format!("'{path}' is not inside the profile '{profile}'"));
        }
        comps[root.len()..].to_vec()
    } else {
        comps
    };
    for c in &rel {
        if c == "." || c == ".." || c.contains(['*', '?']) || norm_component(c).is_empty() {
            return Err(format!(
                "'{path}': component '{c}' cannot be part of an exclusion"
            ));
        }
    }
    Ok(rel)
}

// ─── Rules ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Rule {
    pats: Vec<Pat>,
    /// The components as spelled, for creating a missing directory.
    spelled: Vec<String>,
    stamp: bool,
    /// Ungranted-only; otherwise protected.
    ungranted: bool,
    /// A protected built-in directory with no wildcard: created when
    /// missing.
    placeholder: bool,
}

/// The exclusions in force for one profile: the built-in list placed
/// at the profile's known-folder locations, plus what configuration
/// added.
#[derive(Debug, Clone)]
pub struct Rules {
    rules: Vec<Rule>,
}

/// Where the application-data folders are when nothing redirects
/// them. The built-in entries for them always apply here, and also at
/// the known-folder location when that is another directory of the
/// profile.
const CONVENTIONAL_ROAMING: [&str; 2] = ["AppData", "Roaming"];
const CONVENTIONAL_LOCAL: [&str; 2] = ["AppData", "Local"];

impl Rules {
    /// `roaming` and `local` are the known-folder locations as
    /// components beneath the profile, `None` when a folder is not
    /// inside the profile. `extra` are exclusions added by
    /// configuration, as components beneath the profile
    /// ([`rel_components`]); an empty one (the profile itself) is
    /// ignored.
    pub fn new(
        roaming: Option<&[String]>,
        local: Option<&[String]>,
        extra: &[Vec<String>],
    ) -> Rules {
        let mut rules = Vec::new();
        let conventional = |c: &[&str]| c.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        for e in BUILT_IN {
            let mut bases: Vec<Vec<String>> = Vec::new();
            match e.base {
                Base::Profile => bases.push(Vec::new()),
                Base::Roaming => {
                    bases.push(conventional(&CONVENTIONAL_ROAMING));
                    bases.extend(roaming.map(<[String]>::to_vec));
                }
                Base::Local => {
                    bases.push(conventional(&CONVENTIONAL_LOCAL));
                    bases.extend(local.map(<[String]>::to_vec));
                }
            }
            bases.dedup_by(|a, b| {
                a.len() == b.len()
                    && a.iter()
                        .zip(b.iter())
                        .all(|(x, y)| norm_component(x) == norm_component(y))
            });
            for base in bases {
                let mut spelled = base;
                spelled.extend(e.path.split('\\').map(str::to_owned));
                let pats: Vec<Pat> = spelled.iter().map(|c| Pat::parse(c)).collect();
                let wild = pats.iter().any(|p| !matches!(p, Pat::Lit(_)));
                rules.push(Rule {
                    pats,
                    spelled,
                    stamp: e.stamp,
                    ungranted: e.ungranted_only,
                    placeholder: e.dir && e.stamp && e.create && !wild && !e.ungranted_only,
                });
            }
        }
        for x in extra.iter().filter(|x| !x.is_empty()) {
            rules.push(Rule {
                pats: x.iter().map(|c| Pat::Lit(norm_component(c))).collect(),
                spelled: x.clone(),
                stamp: true,
                ungranted: false,
                placeholder: false,
            });
        }
        Rules { rules }
    }

    /// The exclusions of one kind, as written: components beneath
    /// the profile joined by `\\`, wildcards included. Recorded with a
    /// grant, so that what a grant excluded can be read back from its
    /// record rather than from the list of whichever build asks.
    fn spelled_where(&self, ungranted: bool) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in self.rules.iter().filter(|r| r.ungranted == ungranted) {
            let s = r.spelled.join("\\");
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out
    }

    /// The protected exclusions, built-in and added.
    pub fn spelled(&self) -> Vec<String> {
        self.spelled_where(false)
    }

    /// The ungranted-only exclusions.
    pub fn spelled_ungranted(&self) -> Vec<String> {
        self.spelled_where(true)
    }

    fn at_or_beneath(&self, rel: &[Name], ungranted: bool) -> bool {
        self.rules.iter().any(|r| {
            r.ungranted == ungranted
                && r.pats.len() <= rel.len()
                && r.pats.iter().zip(rel).all(|(p, n)| n.matched_by(p))
        })
    }

    /// Whether `rel` (components beneath the profile) is a protected
    /// exclusion or lies beneath one. Matches each rule against the
    /// whole path; the walk matches incrementally and must agree with
    /// this.
    pub fn excludes(&self, rel: &[Name]) -> bool {
        self.at_or_beneath(rel, false)
    }

    /// Whether `rel` is an ungranted-only exclusion or lies beneath
    /// one.
    pub fn ungranted(&self, rel: &[Name]) -> bool {
        self.at_or_beneath(rel, true)
    }

    /// Whether an exclusion of either kind could lie strictly beneath
    /// the directory `rel`, whatever is on disk.
    pub fn could_exclude_beneath(&self, rel: &[Name]) -> bool {
        self.rules.iter().any(|r| {
            r.pats.len() > rel.len() && r.pats.iter().zip(rel).all(|(p, n)| n.matched_by(p))
        })
    }

    fn all(&self) -> Vec<usize> {
        (0..self.rules.len()).collect()
    }
}

// ─── Session grants against a recorded grant ────────────────────────

/// How a path stands to an exclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// The path is the excluded one.
    Equal,
    /// It lies beneath the excluded directory.
    Inside,
    /// The excluded path lies beneath it.
    Above,
}

/// How `path` stands to the recorded exclusion `rule`, both absolute;
/// `rule` may hold the wildcards of the built-in list. `None` when
/// neither contains the other.
pub fn relation(path: &str, rule: &str) -> Option<Relation> {
    let p: Vec<String> = split_path(path).iter().map(|c| norm_component(c)).collect();
    let r: Vec<Pat> = split_path(rule).iter().map(|c| Pat::parse(c)).collect();
    let shared = p.len().min(r.len());
    if !(0..shared).all(|i| r[i].matches(&p[i])) {
        return None;
    }
    Some(match p.len().cmp(&r.len()) {
        std::cmp::Ordering::Equal => Relation::Equal,
        std::cmp::Ordering::Greater => Relation::Inside,
        std::cmp::Ordering::Less => Relation::Above,
    })
}

/// Whether something that exists beneath the directory `path` matches
/// the rest of `rule`, which `path` lies above. `list` gives the entry
/// names of a directory (nothing for a file, a link, or a directory
/// that cannot be read), so the lookup never leaves `path` through a
/// link, and it goes exactly as deep as the rule has components left.
fn matched_beneath(path: &str, rule: &str, list: &dyn Fn(&str) -> Vec<String>) -> bool {
    fn go(dir: &str, rest: &[Pat], list: &dyn Fn(&str) -> Vec<String>) -> bool {
        let Some((first, rest)) = rest.split_first() else {
            return true;
        };
        list(dir).iter().any(|name| {
            first.matches(&norm_component(name))
                && go(
                    &format!("{}\\{name}", dir.trim_end_matches('\\')),
                    rest,
                    list,
                )
        })
    }
    let depth = split_path(path).len();
    let pats: Vec<Pat> = split_path(rule).iter().map(|c| Pat::parse(c)).collect();
    pats.len() > depth && go(path, &pats[depth..], list)
}

/// Why a session must not be granted `path` (canonical) while a
/// profile read grant with these recorded exclusions exists; `None`
/// when it may.
///
/// | path is … | protected | ungranted-only |
/// |---|---|---|
/// | the exclusion | refused (read: unless admitted) | refused |
/// | inside it | refused (read: unless admitted) | allowed |
/// | above it | refused | refused |
///
/// A grant above an exclusion inherits: a store that is deleted and
/// created again beneath it would carry the grant, which the profile
/// grant's own layout never allows. That holds for a rule that names
/// its path outright. A rule with a wildcard (`Local\*\EBWebView`)
/// names no path until something matches it, and read the same way it
/// would make every directory beneath `Local` ungrantable; so `path`
/// counts as above such a rule only while something that exists
/// beneath it matches ([`matched_beneath`], through `list`). The
/// grant's own walk does not make that concession: it treats every
/// such level as a container. `admitted` are the paths the
/// caller explicitly asked to open (`acl grant
/// --allow-profile-exclusion`); they count for a READ grant that is a
/// protected path or lies inside one, and for nothing else — a write
/// grant is never admitted, nor anything above an exclusion.
pub fn session_grant_refusal(
    path: &str,
    write: bool,
    protected: &[String],
    ungranted: &[String],
    admitted: &[String],
    list: &dyn Fn(&str) -> Vec<String>,
) -> Option<String> {
    let what = if write { "write" } else { "read" };
    for u in ungranted {
        if relation(path, u) == Some(Relation::Equal) {
            return Some(format!(
                "a {what} grant on '{path}' would cover everything in it, and it is not \
                 granted as a whole; grant a directory inside it"
            ));
        }
    }
    let is_admitted = !write
        && admitted
            .iter()
            .any(|a| relation(path, a) == Some(Relation::Equal) && !a.contains('*'));
    for r in protected {
        match relation(path, r) {
            None => {}
            Some(Relation::Above) if r.contains('*') && !matched_beneath(path, r, list) => {}
            Some(Relation::Above) => {
                return Some(format!(
                    "a {what} grant on '{path}' would be inherited by the excluded '{r}' \
                     beneath it if that is ever created again; choose a narrower directory"
                ));
            }
            Some(Relation::Equal | Relation::Inside) if is_admitted => {}
            Some(Relation::Equal) => {
                return Some(format!("'{path}' is excluded from reads of the profile"));
            }
            Some(Relation::Inside) => {
                return Some(format!(
                    "'{path}' lies inside '{r}', which is excluded from reads of the profile"
                ));
            }
        }
    }
    for u in ungranted {
        if relation(path, u) == Some(Relation::Above) {
            return Some(format!(
                "a {what} grant on '{path}' would cover everything in '{u}', which is not \
                 granted as a whole; choose a narrower directory"
            ));
        }
    }
    None
}

// ─── Plan ───────────────────────────────────────────────────────────

/// One directory entry as the walk sees it.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: Name,
    pub is_dir: bool,
    /// Set for an entry nothing may be written on or through: a
    /// reparse point or a cloud placeholder.
    pub skip: Option<String>,
    /// The entry is a reparse point: something that may redirect to
    /// another place ([`Tree::resolve_link`]).
    pub link: bool,
}

/// Where a link leads, with every link on the way resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkTarget {
    /// Inside the profile: the target's components beneath it (empty
    /// for the profile directory itself).
    Inside(Vec<String>),
    /// Outside the profile, or nowhere that can be resolved (a
    /// dangling link, a cycle), with a word about it.
    Elsewhere(String),
}

/// What the walk reads the tree through. `list` is called for the
/// root and for every directory about to be treated as a container;
/// an `Err` makes that directory skipped, with the error as reason.
/// `resolve_link` is called for a link that sits where a rule points.
pub trait Tree {
    fn list(&mut self, rel: &[String]) -> Result<Vec<Entry>, String>;
    fn resolve_link(&mut self, rel: &[String]) -> LinkTarget;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Directory: non-inheriting traverse + list + read attributes.
    Container,
    /// Directory: inheriting read + execute; not descended.
    Granted,
    /// File: read + execute on the file itself.
    File,
    /// Protected exclusion: read deny (inheriting on a directory).
    Denied,
    /// An ungranted-only exclusion, or a directory inside one on the
    /// way to a protected path: nothing written, nothing granted.
    Ungranted,
    /// Nothing written.
    Skipped,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Container => "container",
            Kind::Granted => "granted",
            Kind::File => "file",
            Kind::Denied => "denied",
            Kind::Ungranted => "ungranted",
            Kind::Skipped => "skipped",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "container" => Kind::Container,
            "granted" => Kind::Granted,
            "file" => Kind::File,
            "denied" => Kind::Denied,
            "ungranted" => Kind::Ungranted,
            "skipped" => Kind::Skipped,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Components beneath the profile; empty for the root.
    pub rel: Vec<String>,
    pub is_dir: bool,
    pub kind: Kind,
    /// Not on disk: an excluded directory, or a directory on the way
    /// to one, that is to be created empty.
    pub missing: bool,
    /// A denied directory whose deny another part of this crate
    /// writes: recorded as excluded, not written.
    pub stamp: bool,
    /// Why a skipped node was skipped.
    pub note: Option<String>,
}

/// A link the walk met where a rule points: its path, and the rules
/// that matched down to and including its name.
struct LinkHit {
    rel: Vec<String>,
    rules: Vec<usize>,
}

/// What a walk produces.
struct Found {
    nodes: Vec<Node>,
    hits: Vec<LinkHit>,
}

/// How many times the rules may grow by resolving links before the
/// plan gives up: each round resolves the links the previous round's
/// added rules led to, so this bounds the length of a chain of links
/// that each sit beneath the previous one's target.
const MAX_LINK_ROUNDS: usize = 8;

/// The plan for a profile: every node the grant touches or reports,
/// parents before children, in the order the tree listed them.
pub fn plan(tree: &mut dyn Tree, rules: &Rules) -> Result<Vec<Node>, String> {
    plan_resolved(tree, rules).map(|(nodes, _)| nodes)
}

/// [`plan`], with the rules it ended up with: `rules` plus, for every
/// link that sits at or above a path a rule covers and leads into the
/// profile, that rule carried over to the link's target (see the
/// module doc). The returned rules are what the grant records.
///
/// A link that leads to the profile directory itself from a place a
/// rule covers would exclude the whole profile; that is an error, as
/// is a chain of links longer than [`MAX_LINK_ROUNDS`].
pub fn plan_resolved(tree: &mut dyn Tree, rules: &Rules) -> Result<(Vec<Node>, Rules), String> {
    let mut rules = rules.clone();
    for _ in 0..=MAX_LINK_ROUNDS {
        let entries = tree.list(&[])?;
        let mut found = Found {
            nodes: vec![Node {
                rel: Vec::new(),
                is_dir: true,
                kind: Kind::Container,
                missing: false,
                stamp: true,
                note: None,
            }],
            hits: Vec::new(),
        };
        let all = rules.all();
        walk(tree, &rules, &[], entries, &all, false, &mut found);
        let Found { nodes: out, hits } = found;
        let mut grew = false;
        for hit in hits {
            let LinkTarget::Inside(target) = tree.resolve_link(&hit.rel) else {
                continue;
            };
            if target.is_empty() {
                return Err(format!(
                    "'{}' is a link to the profile directory itself and stands where an \
                     exclusion applies; the profile cannot be granted around it",
                    hit.rel.join("\\")
                ));
            }
            let depth = hit.rel.len();
            for i in hit.rules {
                let from = rules.rules[i].clone();
                let mut pats: Vec<Pat> =
                    target.iter().map(|c| Pat::Lit(norm_component(c))).collect();
                pats.extend(from.pats[depth..].iter().cloned());
                let mut spelled = target.clone();
                spelled.extend(from.spelled[depth..].iter().cloned());
                let same = |r: &Rule| r.pats == pats && r.ungranted == from.ungranted;
                if !rules.rules.iter().any(same) {
                    rules.rules.push(Rule {
                        pats,
                        spelled,
                        stamp: true,
                        ungranted: from.ungranted,
                        placeholder: false,
                    });
                    grew = true;
                }
            }
        }
        if !grew {
            return Ok((out, rules));
        }
    }
    Err(format!(
        "links beneath the profile lead on to further links more than {MAX_LINK_ROUNDS} times"
    ))
}

/// Walk one container. `alive` are the rules whose first `rel.len()`
/// components matched the path so far. `bare` is set inside an
/// ungranted-only exclusion: nothing there is granted, and the walk
/// goes on only towards protected paths.
fn walk(
    tree: &mut dyn Tree,
    rules: &Rules,
    rel: &[String],
    entries: Vec<Entry>,
    alive: &[usize],
    bare: bool,
    found: &mut Found,
) {
    let depth = rel.len();
    let node = |name: &str, is_dir: bool, kind: Kind| Node {
        rel: rel.iter().cloned().chain([name.to_owned()]).collect(),
        is_dir,
        kind,
        missing: false,
        stamp: true,
        note: None,
    };
    for e in &entries {
        let name = e.name.long.as_str();
        let next: Vec<usize> = alive
            .iter()
            .copied()
            .filter(|&i| e.name.matched_by(&rules.rules[i].pats[depth]))
            .collect();
        if let Some(why) = &e.skip {
            found.nodes.push(Node {
                note: Some(why.clone()),
                ..node(name, e.is_dir, Kind::Skipped)
            });
            // Nothing is written on it. If rules point at or through
            // it and it leads somewhere, they follow it there.
            if e.link && !next.is_empty() {
                found.hits.push(LinkHit {
                    rel: rel.iter().cloned().chain([name.to_owned()]).collect(),
                    rules: next,
                });
            }
            continue;
        }
        let ending: Vec<&Rule> = next
            .iter()
            .map(|&i| &rules.rules[i])
            .filter(|r| r.pats.len() == depth + 1)
            .collect();
        // A protected rule ending here wins over an ungranted-only one.
        let protected: Vec<&&Rule> = ending.iter().filter(|r| !r.ungranted).collect();
        if !protected.is_empty() {
            found.nodes.push(Node {
                stamp: protected.iter().all(|r| r.stamp),
                ..node(name, e.is_dir, Kind::Denied)
            });
            continue;
        }
        if bare || !ending.is_empty() {
            // An ungranted-only exclusion, or something inside one:
            // no entry of any kind. A directory is entered only if a
            // rule goes on beneath it.
            if !e.is_dir {
                continue;
            }
            let deeper: Vec<usize> = next
                .iter()
                .copied()
                .filter(|&i| rules.rules[i].pats.len() > depth + 1)
                .collect();
            if !deeper.is_empty() {
                let child: Vec<String> = rel.iter().cloned().chain([name.to_owned()]).collect();
                match tree.list(&child) {
                    Ok(children) => {
                        found.nodes.push(node(name, true, Kind::Ungranted));
                        walk(tree, rules, &child, children, &deeper, true, found);
                    }
                    Err(why) => found.nodes.push(Node {
                        note: Some(why),
                        ..node(name, true, Kind::Skipped)
                    }),
                }
            } else if !ending.is_empty() {
                found.nodes.push(node(name, true, Kind::Ungranted));
            }
            continue;
        }
        if !e.is_dir {
            let readable = if depth == 0 {
                let n = norm_component(name);
                READABLE_ROOT_FILES.iter().any(|f| norm_component(f) == n)
            } else {
                true
            };
            if readable {
                found.nodes.push(node(name, false, Kind::File));
            }
            continue;
        }
        if next.is_empty() {
            found.nodes.push(node(name, true, Kind::Granted));
            continue;
        }
        let child: Vec<String> = rel.iter().cloned().chain([name.to_owned()]).collect();
        match tree.list(&child) {
            Ok(children) => {
                found.nodes.push(node(name, true, Kind::Container));
                walk(tree, rules, &child, children, &next, false, found);
            }
            Err(why) => found.nodes.push(Node {
                note: Some(why),
                ..node(name, true, Kind::Skipped)
            }),
        }
    }
    // Excluded directories that are not there yet, and the directories
    // on the way to them: created empty so the deny has an object to
    // sit on. Only where no entry of this container has the name, and
    // never inside an ungranted-only exclusion or through one.
    if bare {
        return;
    }
    let mut made: Vec<String> = Vec::new();
    for &i in alive {
        let r = &rules.rules[i];
        if !r.placeholder {
            continue;
        }
        if entries.iter().any(|e| e.name.matched_by(&r.pats[depth])) {
            continue;
        }
        // The other rules that start with the same missing name share
        // the directories they have in common.
        for end in depth + 1..=r.pats.len() {
            let chain: Vec<String> = rel
                .iter()
                .cloned()
                .chain(r.spelled[depth..end].iter().cloned())
                .collect();
            let key = chain[depth..]
                .iter()
                .map(|c| norm_component(c))
                .collect::<Vec<_>>()
                .join("\\");
            if made.contains(&key) {
                continue;
            }
            made.push(key);
            let last = end == r.pats.len();
            // A shorter rule may end at this directory: then it is the
            // excluded one, and nothing is created beneath it.
            let names: Vec<Name> = chain.iter().map(|c| Name::long(c)).collect();
            if rules.ungranted(&names) {
                break;
            }
            let excluded_here = rules.excludes(&names);
            found.nodes.push(Node {
                rel: chain,
                is_dir: true,
                kind: if last || excluded_here {
                    Kind::Denied
                } else {
                    Kind::Container
                },
                missing: true,
                stamp: true,
                note: None,
            });
            if excluded_here && !last {
                break;
            }
        }
    }
}

// ─── Configuration pointers ─────────────────────────────────────────

/// Environment variables an embedder may set for a sandboxed command
/// so a tool reads the real user's configuration file in place. The
/// sandboxed process has its own profile, and its `USERPROFILE`,
/// `APPDATA` and the like must stay there (tools write caches under
/// them), so each tool is pointed at its one file instead:
///
/// - `NPM_CONFIG_USERCONFIG` — npm's `userconfig` setting; the user
///   `.npmrc`.
/// - `GIT_CONFIG_GLOBAL` — git 2.32 and later read this file as the
///   global configuration, in place of both `.gitconfig` and the XDG
///   file. An embedder that sets its own must not get this one.
/// - `PIP_CONFIG_FILE` — pip loads it in addition to its other
///   configuration files, with the highest precedence among them.
/// - `MAVEN_ARGS` — Maven 3.9 and later prepend it to the command
///   line; `-s` names the user settings file and
///   `-Dsettings.security` the settings-security file. Maven has no
///   variable that names either file directly, and an older Maven
///   ignores this one: there `-s` has to be on the command line.
///
/// NuGet has no variable for its user configuration file: the file
/// has to be named with `--configfile` / `-ConfigFile`, or a
/// `NuGet.Config` placed in or above the project directory. Gradle
/// has none for `gradle.properties` either (`GRADLE_USER_HOME` moves
/// the caches as well, which must not be written in the real
/// profile): its properties have to be passed as
/// `ORG_GRADLE_PROJECT_<name>` variables or `-P` arguments.
///
/// A variable is returned only when `readable` says its file is
/// there and covered by the grant.
pub fn env_pointers(
    profile: &str,
    roaming: Option<&str>,
    readable: &dyn Fn(&str) -> bool,
) -> Vec<(&'static str, String)> {
    let at = |base: &str, rel: &str| format!("{}\\{rel}", base.trim_end_matches('\\'));
    let first = |candidates: &[String]| candidates.iter().find(|p| readable(p)).cloned();
    let mut out = Vec::new();
    if let Some(p) = first(&[at(profile, ".npmrc")]) {
        out.push(("NPM_CONFIG_USERCONFIG", p));
    }
    if let Some(p) = first(&[
        at(profile, ".gitconfig"),
        at(profile, r".config\git\config"),
    ]) {
        out.push(("GIT_CONFIG_GLOBAL", p));
    }
    let mut pip = Vec::new();
    pip.extend(roaming.map(|r| at(r, r"pip\pip.ini")));
    pip.push(at(profile, r"pip\pip.ini"));
    pip.push(at(profile, r".config\pip\pip.conf"));
    if let Some(p) = first(&pip) {
        out.push(("PIP_CONFIG_FILE", p));
    }
    if let Some(settings) = first(&[at(profile, r".m2\settings.xml")]) {
        let mut v = format!("-s \"{settings}\"");
        if let Some(sec) = first(&[at(profile, r".m2\settings-security.xml")]) {
            v.push_str(&format!(" \"-Dsettings.security={sec}\""));
        }
        out.push(("MAVEN_ARGS", v));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// An in-memory tree: path (components joined by `\`, `""` for
    /// the root) → entries.
    #[derive(Default, Clone)]
    struct Mem {
        dirs: BTreeMap<String, Vec<Entry>>,
        unreadable: Vec<String>,
        /// Link path → where it points: a path beneath the profile
        /// (`""` for the profile itself), or `None` for outside it.
        links: BTreeMap<String, Option<String>>,
    }

    fn entry(name: &str, is_dir: bool) -> Entry {
        Entry {
            name: Name::long(name),
            is_dir,
            skip: None,
            link: false,
        }
    }

    impl Mem {
        /// Add `path`; a trailing `\` makes it a directory. Parents
        /// are added as directories.
        fn add(&mut self, path: &str) -> &mut Self {
            let is_dir = path.ends_with('\\');
            let comps = split_path(path);
            for i in 0..comps.len() {
                let parent = comps[..i].join("\\");
                let dir = i + 1 < comps.len() || is_dir;
                let list = self.dirs.entry(parent).or_default();
                if !list.iter().any(|e| e.name.long == comps[i]) {
                    list.push(entry(&comps[i], dir));
                }
                if dir {
                    self.dirs.entry(comps[..=i].join("\\")).or_default();
                }
            }
            self
        }

        fn entry_mut(&mut self, path: &str) -> &mut Entry {
            let comps = split_path(path);
            let parent = comps[..comps.len() - 1].join("\\");
            self.dirs
                .get_mut(&parent)
                .unwrap()
                .iter_mut()
                .find(|e| e.name.long == comps[comps.len() - 1])
                .unwrap()
        }
    }

    impl Mem {
        /// Make the directory `path` a link to `target`.
        fn link(&mut self, path: &str, target: Option<&str>) -> &mut Self {
            if !self.dirs.contains_key(path) {
                self.add(&format!("{path}\\"));
            }
            let e = self.entry_mut(path);
            e.skip = Some("reparse point".into());
            e.link = true;
            self.links
                .insert(path.to_owned(), target.map(str::to_owned));
            self
        }

        /// `path` with every link on the way resolved, as the final
        /// path of a real open is; `None` for outside the profile or
        /// a cycle.
        fn real(&self, path: &str) -> Option<String> {
            let mut cur = path.to_owned();
            for _ in 0..32 {
                let comps = split_path(&cur);
                let hit = (1..=comps.len())
                    .map(|n| comps[..n].join("\\"))
                    .find(|prefix| self.links.contains_key(prefix));
                let Some(prefix) = hit else {
                    return Some(cur);
                };
                let target = self.links[&prefix].clone()?;
                let rest = &cur[prefix.len()..];
                cur = format!("{target}{rest}")
                    .trim_start_matches('\\')
                    .to_owned();
            }
            None
        }
    }

    impl Tree for Mem {
        fn resolve_link(&mut self, rel: &[String]) -> LinkTarget {
            match self.real(&rel.join("\\")) {
                Some(real) => LinkTarget::Inside(split_path(&real)),
                None => LinkTarget::Elsewhere("outside the profile".to_owned()),
            }
        }

        fn list(&mut self, rel: &[String]) -> Result<Vec<Entry>, String> {
            let key = rel.join("\\");
            if self.unreadable.contains(&key) {
                return Err("access denied".to_owned());
            }
            self.dirs
                .get(&key)
                .cloned()
                .ok_or_else(|| format!("no directory '{key}'"))
        }
    }

    fn rules() -> Rules {
        Rules::new(None, None, &[])
    }

    fn kinds(nodes: &[Node]) -> BTreeMap<String, (Kind, bool)> {
        nodes
            .iter()
            .map(|n| (n.rel.join("\\"), (n.kind, n.missing)))
            .collect()
    }

    fn names(rel: &[String]) -> Vec<Name> {
        rel.iter().map(|c| Name::long(c)).collect()
    }

    #[test]
    fn a_profile_is_planned_by_the_walk_rule() {
        let mut t = Mem::default();
        t.add(r"Documents\notes.txt")
            .add(r"source\repo\a.rs")
            .add(".npmrc")
            .add(".gitconfig")
            .add(".netrc")
            .add("NTUSER.DAT")
            .add("ntuser.dat.LOG1")
            .add("stray.txt")
            .add(r".ssh\id_ed25519")
            .add(r".cargo\credentials.toml")
            .add(r".cargo\config.toml")
            .add(r".cargo\bin\rg.exe")
            .add(r".config\git\config")
            .add(r".config\git\credentials")
            .add(r".config\gh\hosts.yml")
            .add(r".config\pip\pip.conf")
            .add(r".m2\settings.xml")
            .add(r"AppData\Roaming\npm\tool.cmd")
            .add(r"AppData\Roaming\Microsoft\Credentials\x")
            .add(r"AppData\Roaming\Microsoft\Windows\Start Menu\a.lnk")
            .add(r"AppData\Local\Temp\t.tmp")
            .add(r"AppData\Local\Programs\Python\python.exe")
            .add(r"AppData\Local\SomeApp\EBWebView\Cookies")
            .add(r"AppData\Local\SomeApp\data.bin")
            .add(r"AppData\LocalLow\x");
        let nodes = plan(&mut t, &rules()).unwrap();
        let k = kinds(&nodes);
        let is = |p: &str, kind: Kind| {
            assert_eq!(k.get(p).map(|v| v.0), Some(kind), "{p}");
        };
        let absent = |p: &str| assert!(!k.contains_key(p), "{p} is in the plan");
        is("", Kind::Container);
        // Ordinary top-level directories are granted whole.
        is("Documents", Kind::Granted);
        is("source", Kind::Granted);
        is(".m2", Kind::Granted);
        absent(r"Documents\notes.txt");
        // Root files: the two named ones, nothing else.
        is(".npmrc", Kind::File);
        is(".gitconfig", Kind::File);
        absent("stray.txt");
        is(".netrc", Kind::Denied);
        is("NTUSER.DAT", Kind::Denied);
        is("ntuser.dat.LOG1", Kind::Denied);
        is(".ssh", Kind::Denied);
        absent(r".ssh\id_ed25519");
        // A directory holding an excluded file is a container; its
        // other files and directories are granted one by one.
        is(".cargo", Kind::Container);
        is(r".cargo\credentials.toml", Kind::Denied);
        is(r".cargo\config.toml", Kind::File);
        is(r".cargo\bin", Kind::Granted);
        is(".config", Kind::Container);
        is(r".config\git", Kind::Container);
        is(r".config\git\config", Kind::File);
        is(r".config\git\credentials", Kind::Denied);
        is(r".config\gh", Kind::Denied);
        is(r".config\pip", Kind::Granted);
        // AppData and the two application-data folders.
        is("AppData", Kind::Container);
        is(r"AppData\Roaming", Kind::Container);
        is(r"AppData\Roaming\npm", Kind::Granted);
        is(r"AppData\Roaming\Microsoft", Kind::Container);
        is(r"AppData\Roaming\Microsoft\Credentials", Kind::Denied);
        is(r"AppData\Roaming\Microsoft\Windows", Kind::Granted);
        is(r"AppData\Local", Kind::Container);
        // The temporary directory: ungranted, not denied, and nothing
        // in it is planned.
        is(r"AppData\Local\Temp", Kind::Ungranted);
        absent(r"AppData\Local\Temp\t.tmp");
        is(r"AppData\Local\Programs", Kind::Container);
        is(r"AppData\Local\Programs\Python", Kind::Granted);
        is(r"AppData\Local\SomeApp", Kind::Container);
        is(r"AppData\Local\SomeApp\EBWebView", Kind::Denied);
        is(r"AppData\Local\SomeApp\data.bin", Kind::File);
        is(r"AppData\LocalLow", Kind::Granted);
        // Missing excluded directories are planned as placeholders,
        // with the directories on the way to them.
        assert_eq!(k.get(".aws"), Some(&(Kind::Denied, true)));
        assert_eq!(k.get(".config\\gcloud"), Some(&(Kind::Denied, true)));
        assert_eq!(
            k.get(r"AppData\Local\Google"),
            Some(&(Kind::Container, true))
        );
        assert_eq!(
            k.get(r"AppData\Local\Google\Chrome\User Data"),
            Some(&(Kind::Denied, true))
        );
        // Nor is a store most profiles do not have created.
        absent(".kaggle");
        absent(r"AppData\Local\Vivaldi");
        absent(r"AppData\Roaming\Thunderbird");
        // A missing excluded FILE gets no placeholder, nor does a
        // wildcard entry.
        absent(".git-credentials");
        absent(r".gradle");
        assert!(!k.keys().any(|p| p.contains('*')));
        // The library's own state directory is excluded and not
        // written; it is not created either.
        absent(r"AppData\Local\sandbox-runtime");
        // Parents come before children.
        for (i, n) in nodes.iter().enumerate() {
            if let Some((_, parent)) = n.rel.split_last() {
                let at = nodes.iter().position(|m| m.rel == parent).unwrap();
                assert!(at < i, "{:?} precedes its parent", n.rel);
            }
        }
    }

    #[test]
    fn the_state_directory_is_excluded_and_left_to_its_owner() {
        let mut t = Mem::default();
        t.add(r"AppData\Local\sandbox-runtime\state.db");
        let nodes = plan(&mut t, &rules()).unwrap();
        let n = nodes
            .iter()
            .find(|n| n.rel.join("\\") == r"AppData\Local\sandbox-runtime")
            .unwrap();
        assert_eq!((n.kind, n.stamp), (Kind::Denied, false));
    }

    /// An ungranted-only directory gets nothing and gives its
    /// children nothing; a protected path inside it is still denied,
    /// and the directories on the way to it get nothing either.
    #[test]
    fn an_ungranted_only_directory_is_left_bare_but_for_protected_paths_inside() {
        let extra = vec![split_path(r"AppData\Local\Temp\app\keys")];
        let rules = Rules::new(None, None, &extra);
        let mut t = Mem::default();
        t.add(r"AppData\Local\Temp\loose.txt")
            .add(r"AppData\Local\Temp\session-1\work\f.txt")
            .add(r"AppData\Local\Temp\app\keys\ca.key")
            .add(r"AppData\Local\Temp\app\other\o.txt")
            .add(r"AppData\Local\Temp\app\a.txt")
            .add(r"AppData\Local\Other\x");
        let nodes = plan(&mut t, &rules).unwrap();
        let k = kinds(&nodes);
        let got: Vec<(&str, Kind)> = k
            .iter()
            .filter(|(p, _)| p.starts_with(r"AppData\Local\Temp"))
            .map(|(p, v)| (p.as_str(), v.0))
            .collect();
        assert_eq!(
            got,
            [
                (r"AppData\Local\Temp", Kind::Ungranted),
                (r"AppData\Local\Temp\app", Kind::Ungranted),
                (r"AppData\Local\Temp\app\keys", Kind::Denied),
            ]
        );
        // A session's own directory in it is not part of the plan: it
        // is the session's to grant.
        assert!(!k.contains_key(r"AppData\Local\Temp\session-1"));
        // It is not created when missing, and nothing is created in
        // or through it.
        let mut t = Mem::default();
        t.add(r"AppData\Local\x");
        let k = kinds(&plan(&mut t, &rules).unwrap());
        assert!(!k.keys().any(|p| p.starts_with(r"AppData\Local\Temp")));
    }

    /// A link where a rule points: the rule follows it to its target.
    #[test]
    fn a_rule_follows_a_link_to_its_target_inside_the_profile() {
        let mut t = Mem::default();
        t.add(r"dotfiles\.ssh\id_ed25519")
            .add(r"dotfiles\.config\gh\hosts.yml")
            .add(r"dotfiles\.config\git\config")
            .add(r"dotfiles\.config\git\credentials")
            .add(r"dotfiles\.config\nvim\init.lua")
            .add(r"dotfiles\README")
            .add(r"Documents\a.txt");
        t.link(".ssh", Some(r"dotfiles\.ssh"))
            .link(".config", Some(r"dotfiles\.config"));
        let (nodes, rules) = plan_resolved(&mut t, &rules()).unwrap();
        let k = kinds(&nodes);
        let is = |p: &str, kind: Kind| assert_eq!(k.get(p).map(|v| v.0), Some(kind), "{p}");
        // The links themselves: nothing written, nothing beneath.
        is(".ssh", Kind::Skipped);
        is(".config", Kind::Skipped);
        // Their targets: what the rules say for the names they have
        // through the links.
        is("dotfiles", Kind::Container);
        is(r"dotfiles\.ssh", Kind::Denied);
        is(r"dotfiles\.config", Kind::Container);
        is(r"dotfiles\.config\gh", Kind::Denied);
        is(r"dotfiles\.config\git", Kind::Container);
        is(r"dotfiles\.config\git\credentials", Kind::Denied);
        is(r"dotfiles\.config\git\config", Kind::File);
        is(r"dotfiles\.config\nvim", Kind::Granted);
        is(r"dotfiles\README", Kind::File);
        is("Documents", Kind::Granted);
        assert!(!k.contains_key(r"dotfiles\.ssh\id_ed25519"));
        // The carried-over rules are part of what is recorded, in
        // their resolved form, and cover paths not there yet.
        let spelled = rules.spelled();
        for want in [
            r"dotfiles\.ssh",
            r"dotfiles\.config\gh",
            r"dotfiles\.config\gcloud",
        ] {
            assert!(
                spelled.iter().any(|s| s == want),
                "{want} not in {spelled:?}"
            );
        }
        assert!(rules.excludes(&names(&split_path(r"dotfiles\.ssh\new-key"))));
        assert!(rules.could_exclude_beneath(&names(&split_path("dotfiles"))));
        // Without the links none of that holds: `dotfiles` is an
        // ordinary directory, granted whole.
        let mut plain = Mem::default();
        plain
            .add(r"dotfiles\.ssh\id_ed25519")
            .add(r"dotfiles\README");
        let k = kinds(&plan(&mut plain, &super::tests::rules()).unwrap());
        assert_eq!(k.get("dotfiles").map(|v| v.0), Some(Kind::Granted));
    }

    #[test]
    fn links_in_chains_upwards_outwards_and_in_circles() {
        // A chain: `.config` → `a\cfg`, and in there `gh` → `b\gh`.
        let mut t = Mem::default();
        t.add(r"a\cfg\other\x")
            .add(r"b\gh\hosts.yml")
            .add(r"b\keep.txt");
        t.link(".config", Some(r"a\cfg"))
            .link(r"a\cfg\gh", Some(r"b\gh"));
        let (nodes, rules) = plan_resolved(&mut t, &rules()).unwrap();
        let k = kinds(&nodes);
        assert_eq!(k.get(r"b\gh").map(|v| v.0), Some(Kind::Denied));
        assert_eq!(k.get("b").map(|v| v.0), Some(Kind::Container));
        assert_eq!(k.get(r"b\keep.txt").map(|v| v.0), Some(Kind::File));
        assert_eq!(k.get(r"a\cfg").map(|v| v.0), Some(Kind::Container));
        assert_eq!(k.get(r"a\cfg\gh").map(|v| v.0), Some(Kind::Skipped));
        assert!(rules.spelled().iter().any(|s| s == r"b\gh"));

        // A link whose target is above it: `.config\gh` → `.config`.
        // The rule for `.config\gh` lands on `.config`, all of it.
        let mut t = Mem::default();
        t.add(r".config\git\config");
        t.link(r".config\gh", Some(".config"));
        let k = kinds(&plan(&mut t, &super::tests::rules()).unwrap());
        assert_eq!(k.get(".config").map(|v| v.0), Some(Kind::Denied));
        assert!(!k.contains_key(r".config\git"));

        // A link out of the profile: skipped, and nothing follows it.
        let mut t = Mem::default();
        t.add(r"Documents\a.txt");
        t.link(".ssh", None);
        let (nodes, rules) = plan_resolved(&mut t, &super::tests::rules()).unwrap();
        let k = kinds(&nodes);
        assert_eq!(k.get(".ssh").map(|v| v.0), Some(Kind::Skipped));
        assert_eq!(k.get("Documents").map(|v| v.0), Some(Kind::Granted));
        assert_eq!(rules.spelled(), super::tests::rules().spelled());

        // A circle of links resolves nowhere: both skipped.
        let mut t = Mem::default();
        t.link(".ssh", Some(".aws")).link(".aws", Some(".ssh"));
        let k = kinds(&plan(&mut t, &super::tests::rules()).unwrap());
        assert_eq!(k.get(".ssh").map(|v| v.0), Some(Kind::Skipped));
        assert_eq!(k.get(".aws").map(|v| v.0), Some(Kind::Skipped));

        // A link no rule points at or through is only skipped.
        let mut t = Mem::default();
        t.add(r"work\x");
        t.link("shortcut", Some("work"));
        let (nodes, rules) = plan_resolved(&mut t, &super::tests::rules()).unwrap();
        assert_eq!(kinds(&nodes).get("work").map(|v| v.0), Some(Kind::Granted));
        assert_eq!(rules.spelled(), super::tests::rules().spelled());

        // An excluded name that leads to the profile directory itself
        // cannot be granted around.
        let mut t = Mem::default();
        t.link(".ssh", Some(""));
        assert!(plan(&mut t, &super::tests::rules()).is_err());

        // A chain longer than the bound is an error, not a partial
        // plan. Each link carries the rest of a long added rule one
        // directory on: `x1` → `h1`, `h1\x2` → `h2`, …
        let hops = MAX_LINK_ROUNDS + 3;
        let long: Vec<String> = (1..=hops + 1).map(|i| format!("x{i}")).collect();
        let chain = |links: usize| {
            let mut t = Mem::default();
            for i in 1..=links {
                let at = if i == 1 {
                    "x1".to_owned()
                } else {
                    format!(r"h{}\x{i}", i - 1)
                };
                t.add(&format!(r"h{i}\keep.txt"));
                t.link(&at, Some(&format!("h{i}")));
            }
            t
        };
        let with_long = Rules::new(None, None, std::slice::from_ref(&long));
        assert!(plan(&mut chain(hops), &with_long).is_err());
        // Within the bound the last target gets the rest of the rule.
        let (nodes, rules) = plan_resolved(&mut chain(3), &with_long).unwrap();
        assert_eq!(kinds(&nodes).get("h3").map(|v| v.0), Some(Kind::Container));
        let rest = long[3..].join("\\");
        assert!(rules.spelled().contains(&format!(r"h3\{rest}")));
    }

    #[test]
    fn reparse_points_and_unreadable_directories_are_skipped_at_every_level() {
        let mut t = Mem::default();
        t.add(r"link\")
            .add(r"OneDrive\")
            .add(r"AppData\Local\junction\")
            .add(r"AppData\Local\app\link.lnk")
            .add(r".config\x\")
            .add(r".ssh\");
        t.entry_mut("link").skip = Some("reparse point".into());
        t.entry_mut("OneDrive").skip = Some("cloud placeholder".into());
        t.entry_mut(r"AppData\Local\junction").skip = Some("reparse point".into());
        t.entry_mut(r"AppData\Local\app\link.lnk").skip = Some("reparse point".into());
        // An excluded name that is a link is skipped too: no deny is
        // written through it.
        t.entry_mut(".ssh").skip = Some("reparse point".into());
        t.unreadable.push(".config".into());
        let nodes = plan(&mut t, &rules()).unwrap();
        let k = kinds(&nodes);
        for p in [
            "link",
            "OneDrive",
            r"AppData\Local\junction",
            r"AppData\Local\app\link.lnk",
            ".ssh",
            ".config",
        ] {
            assert_eq!(k.get(p).map(|v| v.0), Some(Kind::Skipped), "{p}");
        }
        // Nothing beneath a skipped directory is planned, and nothing
        // is created beneath it.
        assert!(!k.keys().any(|p| p.starts_with(r".config\")));
        let skipped: Vec<&Node> = nodes.iter().filter(|n| n.kind == Kind::Skipped).collect();
        assert!(skipped.iter().all(|n| n.note.is_some()));
        // An unreadable root is an error, not an empty plan.
        let mut bad = Mem::default();
        bad.unreadable.push(String::new());
        assert!(plan(&mut bad, &rules()).is_err());
    }

    #[test]
    fn a_name_cannot_be_respelled_past_an_exclusion() {
        let r = rules();
        let ex = |p: &str| r.excludes(&names(&split_path(p)));
        for p in [
            ".ssh",
            ".SSH",
            ".ssh.",
            ".ssh ",
            ".ssh. .",
            ".ssh::$INDEX_ALLOCATION",
            ".ssh:stream",
            r".ssh\id_rsa",
            r".Ssh.\ID_RSA",
            ".netrc::$DATA",
            ".NETRC",
            "NTUSER.DAT",
            "ntuser.dat.LOG2",
            "NTUSER.DAT{guid}.TM.blf",
            r"appdata\roaming\microsoft\CREDENTIALS",
            r"AppData\Local\Anything\EBWebView\Default",
            r"AppData\Local\Microsoft\Olk\EBWebView",
            r"AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1",
            r".cargo\Credentials.TOML",
        ] {
            assert!(ex(p), "{p} is not excluded");
        }
        // The temporary directory is not a protected path; it is an
        // ungranted-only one, with everything in it.
        assert!(!ex(r"AppData\Local\Temp"));
        assert!(!ex(r"AppData\Local\Temp\x\y"));
        for p in [r"AppData\Local\Temp", r"appdata\LOCAL\temp.\x\y"] {
            assert!(r.ungranted(&names(&split_path(p))), "{p}");
        }
        assert!(!r.ungranted(&names(&split_path(r"AppData\Local\Temp2"))));
        assert!(!r.ungranted(&names(&split_path(".ssh"))));
        for p in [
            ".sshx",
            "ssh",
            ".npmrc",
            ".gitconfig",
            r".cargo\config.toml",
            r"Documents\.ssh",
            r"AppData\Local\EBWebView",
            r"AppData\Roaming\npm",
            "..",
            ". .",
        ] {
            assert!(!ex(p), "{p} is excluded");
        }
        // An 8.3 name matches through the entry's short name, in
        // either direction.
        let short = |long: &str, short: &str| Name {
            long: long.to_owned(),
            short: Some(short.to_owned()),
        };
        let r = Rules::new(
            None,
            None,
            &[
                vec!["MYSECR~1".to_owned()],
                vec!["Long Secret Dir".to_owned()],
            ],
        );
        assert!(r.excludes(&[short("My Secrets", "MYSECR~1")]));
        assert!(r.excludes(&[short("Long Secret Dir", "LONGSE~1")]));
        assert!(r.excludes(&[Name::long("LONG SECRET DIR. ")]));
        assert!(!r.excludes(&[short("My Secrets 2", "MYSECR~2")]));
        // … and in the walk.
        let mut t = Mem::default();
        t.add(r"My Secrets\k");
        t.entry_mut("My Secrets").name.short = Some("MYSECR~1".into());
        let k = kinds(&plan(&mut t, &r).unwrap());
        assert_eq!(k.get("My Secrets").map(|v| v.0), Some(Kind::Denied));
    }

    #[test]
    fn exclusion_paths_from_configuration() {
        let profile = r"\\?\C:\Users\me";
        let ok = |p: &str| rel_components(profile, p).unwrap().join("\\");
        assert_eq!(ok(r"C:\Users\me\.myapp"), ".myapp");
        assert_eq!(ok(r"c:/users/ME/.myapp/tokens"), r".myapp\tokens");
        assert_eq!(
            ok(r"\\?\C:\Users\me\AppData\Roaming\MyApp"),
            r"AppData\Roaming\MyApp"
        );
        assert_eq!(ok(r".myapp\"), ".myapp");
        assert_eq!(ok(r"C:\Users\me"), "");
        for bad in [
            r"C:\Users\other\.myapp",
            r"C:\Users\me\..\other",
            r"D:\x",
            r".myapp\*",
            r".\x",
            r"C:\Users\me2",
        ] {
            assert!(rel_components(profile, bad).is_err(), "{bad}");
        }
        // An added exclusion takes effect; the profile itself is not
        // one.
        let r = Rules::new(None, None, &[vec![".myapp".to_owned()], vec![]]);
        assert!(r.excludes(&names(&split_path(r".MyApp\token"))));
        assert!(!r.excludes(&names(&split_path("Documents"))));
        // Nothing configuration passes removes a built-in entry.
        assert!(r.excludes(&names(&split_path(".ssh"))));
        // The list as recorded: the added entry, the built-in ones
        // at their locations, wildcards as written, each once.
        let spelled = r.spelled();
        for want in [
            ".myapp",
            ".ssh",
            r"AppData\Roaming\Microsoft\Credentials",
            r"AppData\Local\*\EBWebView",
            "NTUSER.DAT*",
            r"AppData\Local\sandbox-runtime",
        ] {
            assert_eq!(
                spelled.iter().filter(|s| s.as_str() == want).count(),
                1,
                "{want}"
            );
        }
        // The two kinds are recorded apart.
        assert_eq!(r.spelled_ungranted(), [r"AppData\Local\Temp"]);
        assert!(!spelled.contains(&r"AppData\Local\Temp".to_owned()));
    }

    /// Both spellings of an application-data location are covered:
    /// the conventional one and a known folder that sits elsewhere in
    /// the profile.
    #[test]
    fn application_data_entries_follow_the_known_folders() {
        let moved = ["Data".to_owned(), "Roam".to_owned()];
        let r = Rules::new(Some(&moved), None, &[]);
        let ex = |p: &str| r.excludes(&names(&split_path(p)));
        assert!(ex(r"Data\Roam\Microsoft\Credentials"));
        assert!(ex(r"Data\Roam\gcloud"));
        assert!(ex(r"AppData\Roaming\Microsoft\Credentials"));
        assert!(r.ungranted(&names(&split_path(r"AppData\Local\Temp"))));
        assert!(!ex(r"Data\Roam\npm"));
        // Every built-in entry resolves beneath the profile at the
        // conventional locations, and the list holds the Windows-side
        // stores as well as the dot-directory ones.
        let r = rules();
        for (base, path) in [
            (Roaming, "gcloud"),
            (Roaming, "GitHub CLI"),
            (Roaming, "com.vercel.cli"),
            (Roaming, "netlify"),
            (Local, "heroku"),
            (Local, ".IdentityService"),
            (Local, "MicrosoftCredentialProvider"),
            (Local, r"Microsoft\IdentityCache"),
            (Local, r"Microsoft\TokenBroker"),
            (Local, r"Microsoft\OneAuth"),
            (Local, r"Microsoft\Windows\INetCookies"),
            (Local, r"Microsoft\Windows\UsrClass.dat"),
            (Profile, r".config\gcloud"),
            (Profile, r".config\gh"),
            (Local, r"github-copilot\hosts.json"),
            (Profile, r".config\github-copilot\apps.json"),
            (Profile, r".gem\credentials"),
            (Profile, r".pulumi\credentials.json"),
            (Roaming, r"postgresql\pgpass.conf"),
            (Profile, ".pgpass"),
            (Roaming, r"Composer\auth.json"),
            (Profile, r".composer\auth.json"),
            (Profile, r".config\doctl\config.yaml"),
            (Profile, r".config\hub"),
            (Profile, r".config\op\config"),
            (Profile, r".kaggle\kaggle.json"),
            (Profile, ".databrickscfg"),
            (Profile, r".snowsql\config"),
            (Profile, ".boto"),
            (Profile, ".s3cfg"),
            (Profile, r".oci\config"),
            (Profile, r".fly\config.yml"),
            (Local, r"Google\Chrome Beta\User Data\Default\Cookies"),
            (Local, r"Chromium\User Data"),
            (Local, r"Vivaldi\User Data"),
            (Local, r"Yandex\YandexBrowser\User Data"),
            (Roaming, r"Opera Software\Opera GX Stable"),
            (Roaming, r"Thunderbird\Profiles"),
        ] {
            let prefix = match base {
                Roaming => r"AppData\Roaming\",
                Local => r"AppData\Local\",
                Profile => "",
            };
            let full = format!("{prefix}{path}");
            assert!(r.excludes(&names(&split_path(&full))), "{full}");
        }
        assert!(BUILT_IN.iter().all(|e| !e.path.is_empty()
            && !e.path.starts_with('\\')
            && !e.path.contains('/')
            && !e.path.contains(':')));
        // The tools those stores belong to stay runnable: only the
        // token file is excluded where the tool installs itself
        // beside it.
        for tool in [
            r".pulumi\bin\pulumi.exe",
            r".fly\bin\flyctl.exe",
            r".gem\specs",
        ] {
            assert!(!r.excludes(&names(&split_path(tool))), "{tool}");
        }
        // The readable configuration files are not excluded.
        for (base, path, _) in READABLE_CONFIG {
            let prefix = match base {
                Roaming => r"AppData\Roaming\",
                Local => r"AppData\Local\",
                Profile => "",
            };
            let full = format!("{prefix}{path}");
            assert!(!r.excludes(&names(&split_path(&full))), "{full}");
        }
    }

    /// A small deterministic generator, so the property below needs
    /// no dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    const POOL: &[&str] = &[
        ".ssh",
        ".SSH.",
        ".aws",
        ".config",
        "gcloud",
        "gh",
        "git",
        "credentials",
        "config",
        ".cargo",
        "credentials.toml",
        "AppData",
        "Roaming",
        "Local",
        "Temp",
        "Microsoft",
        "Credentials",
        "Windows",
        "UsrClass.dat",
        "EBWebView",
        "Google",
        "Chrome",
        "User Data",
        "Packages",
        ".npmrc",
        ".netrc",
        "NTUSER.DAT",
        "Documents",
        "src",
        "a",
        "b",
        "c.txt",
        "d.exe",
        ".myapp",
        "tokens",
        "keys",
    ];

    fn random_tree(rng: &mut Rng) -> Mem {
        let mut t = Mem::default();
        t.dirs.entry(String::new()).or_default();
        for _ in 0..rng.below(40) + 5 {
            let depth = rng.below(5) + 1;
            let mut p: Vec<&str> = (0..depth).map(|_| POOL[rng.below(POOL.len())]).collect();
            // Bias towards the places the rules are about.
            match rng.below(4) {
                0 => p.insert(0, "AppData"),
                1 => {
                    p.insert(0, "Local");
                    p.insert(0, "AppData");
                }
                _ => {}
            }
            let mut path = p.join("\\");
            if rng.below(2) == 0 {
                path.push('\\');
            }
            // A name used as a directory earlier stays one.
            let comps = split_path(&path);
            let clash = (0..comps.len()).any(|i| {
                let parent = comps[..i].join("\\");
                let dir = i + 1 < comps.len() || path.ends_with('\\');
                t.dirs
                    .get(&parent)
                    .is_some_and(|l| l.iter().any(|e| e.name.long == comps[i] && e.is_dir != dir))
            });
            if !clash {
                t.add(&path);
            }
        }
        // Some entries are links or cannot be listed.
        let keys: Vec<String> = t.dirs.keys().filter(|k| !k.is_empty()).cloned().collect();
        for k in &keys {
            match rng.below(10) {
                // A link: to another directory of the tree, or out of
                // the profile.
                0 => {
                    let target = match rng.below(4) {
                        0 => None,
                        _ => Some(keys[rng.below(keys.len())].clone()),
                    };
                    t.link(k, target.as_deref());
                }
                1 => t.unreadable.push(k.clone()),
                _ => {}
            }
        }
        t
    }

    /// The invariant, over generated trees: no excluded path — on
    /// disk now or created later — has an ancestor carrying an
    /// inheriting allow, and nothing excluded is granted itself.
    #[test]
    fn no_exclusion_ever_lies_beneath_an_inheriting_allow() {
        let extra = vec![
            vec![".myapp".to_owned(), "tokens".to_owned()],
            vec!["Documents".to_owned(), "a".to_owned()],
            // A protected path inside the ungranted-only directory.
            split_path(r"AppData\Local\Temp\keys"),
        ];
        let rules = Rules::new(None, None, &extra);
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let original = rules;
        for round in 0..600 {
            let mut t = random_tree(&mut rng);
            // The rules as the plan ends up with them: the original
            // ones, and those carried over to the targets of links.
            let (nodes, rules) = plan_resolved(&mut t, &original).unwrap();
            let by_rel: BTreeMap<String, &Node> =
                nodes.iter().map(|n| (n.rel.join("\\"), n)).collect();
            assert_eq!(by_rel.len(), nodes.len(), "round {round}: a path twice");
            for n in &nodes {
                let rel = names(&n.rel);
                let path = n.rel.join("\\");
                match n.kind {
                    Kind::Granted => {
                        // Not excluded, and no exclusion can ever
                        // appear beneath it.
                        assert!(!rules.excludes(&rel), "round {round}: {path}");
                        assert!(
                            !rules.could_exclude_beneath(&rel),
                            "round {round}: an exclusion can lie beneath granted {path}"
                        );
                    }
                    Kind::File => assert!(!rules.excludes(&rel), "round {round}: {path}"),
                    Kind::Denied => assert!(rules.excludes(&rel), "round {round}: {path}"),
                    Kind::Ungranted => {
                        assert!(rules.ungranted(&rel), "round {round}: {path}");
                        assert!(!rules.excludes(&rel), "round {round}: {path}");
                    }
                    Kind::Container | Kind::Skipped => {}
                }
                // Nothing in an ungranted-only directory, or the
                // directory itself, carries an allow of any kind.
                if rules.ungranted(&rel) {
                    assert!(
                        matches!(n.kind, Kind::Ungranted | Kind::Denied | Kind::Skipped),
                        "round {round}: {path} is {:?} inside an ungranted-only directory",
                        n.kind
                    );
                }
                // Every ancestor is a container or, inside an
                // ungranted-only directory, an ungranted one: nothing
                // is planned beneath a granted, denied or skipped
                // directory.
                for up in 1..n.rel.len() {
                    let anc = n.rel[..up].join("\\");
                    let a = by_rel
                        .get(&anc)
                        .unwrap_or_else(|| panic!("round {round}: {path} has no planned parent"));
                    assert!(
                        matches!(a.kind, Kind::Container | Kind::Ungranted),
                        "round {round}: {path} under {anc} ({:?})",
                        a.kind
                    );
                }
                if !n.rel.is_empty() {
                    assert_eq!(by_rel[""].kind, Kind::Container);
                }
            }
            // Links. For every link the walk met, whatever is planned
            // at or beneath its target is looked at under the name it
            // has THROUGH the link, against the rules as written: what
            // is excluded under that name is not granted under its
            // real one, and nothing that could become excluded under
            // that name lies beneath an inheriting allow.
            // (A link INSIDE an ungranted-only directory that no rule
            // points at leads to an ordinary place, like a link inside
            // any directory the grant does not enter: its target is
            // judged by where it really is.)
            for (link, _) in t.links.iter().filter(|(l, _)| {
                let parent = split_path(l);
                by_rel
                    .get(l.as_str())
                    .is_some_and(|n| n.kind == Kind::Skipped)
                    && !original.ungranted(&names(&parent[..parent.len() - 1]))
            }) {
                let Some(target) = t.real(link) else { continue };
                for n in &nodes {
                    let real = n.rel.join("\\");
                    let rest = if real == target {
                        ""
                    } else if let Some(r) = real.strip_prefix(&format!("{target}\\")) {
                        r
                    } else if target.is_empty() {
                        real.as_str()
                    } else {
                        continue;
                    };
                    let alias = names(&split_path(&format!("{link}\\{rest}")));
                    if original.excludes(&alias) {
                        assert!(
                            matches!(n.kind, Kind::Denied | Kind::Skipped),
                            "round {round}: {real} is {:?} though excluded as {link}\\{rest}",
                            n.kind
                        );
                    }
                    if n.kind == Kind::Granted {
                        assert!(
                            !original.could_exclude_beneath(&alias),
                            "round {round}: granted {real} is {link}\\{rest}, beneath which \
                             an exclusion can lie"
                        );
                    }
                    if original.ungranted(&alias) {
                        assert!(
                            matches!(n.kind, Kind::Ungranted | Kind::Denied | Kind::Skipped),
                            "round {round}: {real} is {:?} though ungranted as {link}\\{rest}",
                            n.kind
                        );
                    }
                }
            }
            // Every excluded object on disk whose ancestors were all
            // walked is denied (or skipped as a link).
            for (dir, entries) in &t.dirs {
                let parent = split_path(dir);
                let walked = (0..=parent.len()).all(|up| {
                    by_rel.get(&parent[..up].join("\\")).is_some_and(|n| {
                        matches!(n.kind, Kind::Container | Kind::Ungranted) && !n.missing
                    })
                });
                if !walked {
                    continue;
                }
                for e in entries {
                    let mut rel = parent.clone();
                    rel.push(e.name.long.clone());
                    if rules.excludes(&names(&rel)) {
                        let k = by_rel[&rel.join("\\")].kind;
                        assert!(
                            matches!(k, Kind::Denied | Kind::Skipped),
                            "round {round}: excluded {} planned as {k:?}",
                            rel.join("\\")
                        );
                    }
                }
            }
        }
    }

    /// Deleting an excluded item, or creating one that was not
    /// there, changes no directory from container to granted.
    #[test]
    fn the_containers_do_not_depend_on_what_exists() {
        let rules = rules();
        let mut with = Mem::default();
        with.add(r".config\gcloud\credentials.db")
            .add(r".config\other\x")
            .add(r".cargo\credentials.toml")
            .add(r"AppData\Roaming\Microsoft\Credentials\c")
            .add(r"AppData\Roaming\Microsoft\Other\o");
        let mut without = Mem::default();
        without
            .add(r".config\other\x")
            .add(r".cargo\")
            .add(r"AppData\Roaming\Microsoft\Other\o");
        let a = kinds(&plan(&mut with, &rules).unwrap());
        let b = kinds(&plan(&mut without, &rules).unwrap());
        for p in [
            ".config",
            ".cargo",
            "AppData",
            r"AppData\Roaming",
            r"AppData\Roaming\Microsoft",
        ] {
            assert_eq!(a[p].0, Kind::Container, "{p}");
            assert_eq!(b[p].0, Kind::Container, "{p}");
        }
    }

    #[test]
    fn configuration_pointers_name_only_readable_files() {
        let profile = r"C:\Users\me";
        let roaming = r"C:\Users\me\AppData\Roaming";
        let all = |_: &str| true;
        let got = env_pointers(profile, Some(roaming), &all);
        assert_eq!(
            got,
            vec![
                ("NPM_CONFIG_USERCONFIG", r"C:\Users\me\.npmrc".to_owned()),
                ("GIT_CONFIG_GLOBAL", r"C:\Users\me\.gitconfig".to_owned()),
                (
                    "PIP_CONFIG_FILE",
                    r"C:\Users\me\AppData\Roaming\pip\pip.ini".to_owned()
                ),
                (
                    "MAVEN_ARGS",
                    "-s \"C:\\Users\\me\\.m2\\settings.xml\" \
                     \"-Dsettings.security=C:\\Users\\me\\.m2\\settings-security.xml\""
                        .to_owned()
                ),
            ]
        );
        // Nothing there: nothing returned.
        assert!(env_pointers(profile, Some(roaming), &|_| false).is_empty());
        // Fallbacks: git's XDG file, pip's older and XDG locations,
        // Maven settings without the security file.
        let only =
            |want: &'static [&'static str]| move |p: &str| want.iter().any(|w| p.ends_with(w));
        let got = env_pointers(
            profile,
            Some(roaming),
            &only(&[r".config\git\config", r"me\pip\pip.ini", "settings.xml"]),
        );
        assert_eq!(
            got,
            vec![
                (
                    "GIT_CONFIG_GLOBAL",
                    r"C:\Users\me\.config\git\config".to_owned()
                ),
                ("PIP_CONFIG_FILE", r"C:\Users\me\pip\pip.ini".to_owned()),
                (
                    "MAVEN_ARGS",
                    "-s \"C:\\Users\\me\\.m2\\settings.xml\"".to_owned()
                ),
            ]
        );
        let got = env_pointers(profile, None, &only(&["pip.conf"]));
        assert_eq!(
            got,
            vec![(
                "PIP_CONFIG_FILE",
                r"C:\Users\me\.config\pip\pip.conf".to_owned()
            )]
        );
        // The directory variables that would move a tool's writes
        // into the real profile are never among them.
        for (var, _) in env_pointers(profile, Some(roaming), &all) {
            assert!(
                ![
                    "USERPROFILE",
                    "HOME",
                    "APPDATA",
                    "LOCALAPPDATA",
                    "TEMP",
                    "TMP",
                    "GRADLE_USER_HOME",
                    "CARGO_HOME"
                ]
                .contains(&var)
            );
        }
    }

    #[test]
    fn a_session_grant_is_measured_against_the_recorded_exclusions() {
        let p = |rel: &str| format!(r"\\?\C:\Users\me\{rel}");
        let protected = vec![
            p(".ssh"),
            p(r"AppData\Local\*\EBWebView"),
            p("NTUSER.DAT*"),
            p(r"AppData\Local\Temp\keys"),
        ];
        let ungranted = vec![p(r"AppData\Local\Temp")];
        // What is on disk, for the wildcard rules: `App` has an
        // EBWebView directory, `Tool` and `npm-cache` do not.
        let on_disk = |dir: &str| -> Vec<String> {
            let d = dir.to_lowercase();
            let names: &[&str] = if d.ends_with(r"\appdata\local") {
                &["App", "Tool", "npm-cache", "Temp"]
            } else if d.ends_with(r"\appdata\local\app") {
                &["EBWebView", "data"]
            } else if d.ends_with(r"\appdata\local\tool") {
                &["bin"]
            } else if d.ends_with(r"\appdata") {
                &["Local", "Roaming"]
            } else if d.ends_with(r"\users\me") {
                &["AppData", "Documents"]
            } else {
                &[]
            };
            names.iter().map(|n| (*n).to_owned()).collect()
        };
        let check = |rel: &str, write: bool, admitted: &[String]| {
            session_grant_refusal(&p(rel), write, &protected, &ungranted, admitted, &on_disk)
        };
        let refused = |rel: &str, write: bool| check(rel, write, &[]).is_some();
        for write in [false, true] {
            // Protected: the path, inside it, above it.
            assert!(refused(".ssh", write));
            assert!(refused(r".SSH.\keys", write));
            assert!(refused(r"AppData\Local\App\EBWebView\Default", write));
            assert!(refused("ntuser.dat.LOG1", write));
            assert!(refused(r"AppData\Local\App", write));
            assert!(refused("AppData", write));
            // A wildcard rule refuses a directory above it only while
            // something beneath that directory matches: a tool's own
            // directory under Local with no such child is grantable.
            assert!(!refused(r"AppData\Local\Tool", write));
            assert!(!refused(r"AppData\Local\npm-cache", write));
            assert!(!refused(r"AppData\Local\Tool\bin", write));
            // Ungranted-only: the directory and above it, not inside.
            assert!(refused(r"AppData\Local\Temp", write));
            assert!(refused(r"AppData\Local", write));
            assert!(!refused(r"AppData\Local\Temp\session", write));
            assert!(!refused(r"AppData\Local\Temp\session\work", write));
            // … unless that is a protected path inside it.
            assert!(refused(r"AppData\Local\Temp\keys", write));
            assert!(refused(r"AppData\Local\Temp\keys\sub", write));
            // Unrelated paths.
            assert!(!refused("Documents", write));
            assert!(!refused(".sshx", write));
            assert!(!refused(r"AppData\Local\App\data", write));
        }
        // The profile directory, and everything above it.
        for root in [r"\\?\C:\Users\me", r"\\?\C:\Users", r"\\?\C:\"] {
            for write in [false, true] {
                assert!(
                    session_grant_refusal(root, write, &protected, &ungranted, &[], &on_disk)
                        .is_some(),
                    "{root}"
                );
            }
        }
        // Another drive, another user.
        for other in [r"\\?\D:\work", r"\\?\C:\Users\other\.ssh"] {
            assert_eq!(
                session_grant_refusal(other, true, &protected, &ungranted, &[], &on_disk),
                None
            );
        }
        // An admitted path: a read grant that is a protected path or
        // lies inside one, named exactly. Never a write, never a path
        // above an exclusion, never the ungranted-only directory.
        let ssh = [p(".ssh")];
        assert_eq!(check(".ssh", false, &ssh), None);
        assert!(check(".ssh", true, &ssh).is_some());
        assert!(check(r".ssh\keys", false, &ssh).is_some());
        assert_eq!(check(r".ssh\keys", false, &[p(r".ssh\keys")]), None);
        assert!(check("AppData", false, &[p("AppData")]).is_some());
        let temp = [p(r"AppData\Local\Temp")];
        assert!(check(r"AppData\Local\Temp", false, &temp).is_some());
        // With nothing on disk only the rules that name their path
        // refuse a directory above them; the wildcard ones do not.
        let empty = |_: &str| Vec::new();
        let bare = |rel: &str| {
            session_grant_refusal(&p(rel), true, &protected, &ungranted, &[], &empty).is_some()
        };
        assert!(!bare(r"AppData\Local\App"));
        assert!(bare(r"AppData\Local\App\EBWebView"));
        assert!(bare(r"AppData\Local"));
        assert!(bare(""));
        // The lookup goes no deeper than the rule: `x\y\EBWebView`
        // beneath Local does not make Local's child `x` refused.
        let deep = |dir: &str| -> Vec<String> {
            let d = dir.to_lowercase();
            if d.ends_with(r"\local\x") {
                vec!["y".to_owned()]
            } else if d.ends_with(r"\local\x\y") {
                vec!["EBWebView".to_owned()]
            } else {
                Vec::new()
            }
        };
        assert_eq!(
            session_grant_refusal(
                &p(r"AppData\Local\x"),
                true,
                &protected,
                &ungranted,
                &[],
                &deep
            ),
            None
        );
        // The message for a write root above an exclusion says what
        // to do about it.
        let why = check("AppData", true, &[]).unwrap();
        assert!(why.contains("narrower"), "{why}");
        assert_eq!(relation(&p(".ssh"), &p(".ssh")), Some(Relation::Equal));
        assert_eq!(relation(&p(r".ssh\a"), &p(".ssh")), Some(Relation::Inside));
        assert_eq!(relation(&p(""), &p(".ssh")), Some(Relation::Above));
        assert_eq!(relation(&p("x"), &p(".ssh")), None);
    }

    #[test]
    fn kind_names_round_trip() {
        for k in [
            Kind::Container,
            Kind::Granted,
            Kind::File,
            Kind::Denied,
            Kind::Ungranted,
            Kind::Skipped,
        ] {
            assert_eq!(Kind::parse(k.as_str()), Some(k));
        }
        assert_eq!(Kind::parse("x"), None);
    }
}
