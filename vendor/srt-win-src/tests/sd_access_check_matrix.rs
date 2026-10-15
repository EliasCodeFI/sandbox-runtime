//! Proof that the security descriptors on the WFP BLOCK filters
//! match the token shapes `wfp::install_filters` relies on them to
//! match — and only those.
//!
//! WFP's `ALE_USER_ID` `FWP_MATCH_EQUAL` condition runs `AccessCheck`
//! on the token the connect is attributed to against the filter's
//! SD; the filter matches iff the check grants. This test calls
//! `AccessCheck` directly — no live WFP engine — so it pins the SD
//! semantics independent of the network stack.
//!
//! The sandbox account itself can't be exercised without
//! provisioning it, so the CALLING user stands in for it: the
//! sandbox-user SD is keyed on the caller's own SID wherever a row
//! is about "a token of the sandbox account", and on a SID the
//! caller does not carry wherever a row is about "some other user".
//!
//! | token                                   | sandbox-user SD | anonymous SD |
//! |-----------------------------------------|-----------------|--------------|
//! | sandbox account, plain                  | match           | no match     |
//! | another real user                       | no match        | no match     |
//! | anonymous                               | no match        | match        |
//! | AppContainer of the sandbox account     | match           | —            |
//! | AppContainer of another real user       | no match        | —            |
//! | sandbox account, user SID deny-only     | no match        | no match     |
//! | sandbox account, integrity lowered      | recorded        | no match     |
//!
//! The deny-only row is not what the fence wants — it is what an
//! ALLOW ACE can do. A deny-only SID satisfies no ALLOW ACE, so no
//! descriptor of this shape reaches that token; the row is asserted
//! so the gap stays visible.
//!
//! ## Integrity levels and the generic mapping
//!
//! An access check runs the mandatory integrity check before it reads
//! the DACL. A token whose integrity level is below the descriptor's
//! label (medium when the descriptor has none) keeps only the rights
//! the caller's `GENERIC_MAPPING` files under read and execute. The
//! mapping the filtering engine passes is not something this crate
//! controls, so every row is evaluated under [`STRICT`], which files
//! the requested right under nothing: a grant under it holds under
//! any mapping. The anonymous token is the row this decides — its
//! integrity level is untrusted — and it is why the anonymous SD
//! carries an untrusted-level label.
//!
//! ## The negative-mode descriptor
//!
//! [`sddl_negative`] is the condition of a PERMIT filter: a token it
//! grants keeps its connects, a token it refuses reaches the BLOCK
//! below. Two variants are built, because the test runs as one user:
//!
//!   - keyed on a SID no token here carries ([`FOREIGN_SID`]) — the
//!     calling user is then "some other principal", and its tokens
//!     must be PERMITTED;
//!   - keyed on the calling user's own SID — the calling user is then
//!     the sandbox account, and every token derived from its own must
//!     be REFUSED.
//!
//! | token of another principal                         | permitted |
//! |----------------------------------------------------|-----------|
//! | ordinary (elevated when the test is)               | yes       |
//! | SYSTEM, LOCAL SERVICE, NETWORK SERVICE             | yes       |
//! | user SID deny-only                                 | yes       |
//! | restricted to `[user, Everyone, RESTRICTED]`       | yes       |
//! | restricted to `[Everyone]` / to `[RESTRICTED]`     | yes       |
//! | write-restricted                                   | yes       |
//! | low / untrusted integrity                          | mapping   |
//! | AppContainer, less-privileged AppContainer         | mapping   |
//! | every group deny-only                              | NO        |
//! | restricted to `[user]` / to the null SID           | NO        |
//! | anonymous                                          | NO        |
//!
//! | token of the sandbox account                       | permitted |
//! |----------------------------------------------------|-----------|
//! | ordinary; user SID deny-only; every SID deny-only  | NO        |
//! | restricting SIDs narrowed to `[Everyone]`          | NO        |
//! | low / untrusted integrity; AppContainer            | NO        |
//! | anonymous                                          | NO        |
//!
//! "mapping": the token is below medium integrity, so the answer is
//! the mandatory check's and differs between [`STRICT`] and
//! [`LENIENT`]. Such a row is logged with both answers and NOT
//! asserted ([`expect`]) — which mapping the filtering engine uses is
//! for the smoke rows to measure. The three "NO" rows of the first
//! table are asserted too: they are the tokens of other accounts the
//! negative mode is known to cut off.
//!
//! The service-account tokens are borrowed from running processes
//! ([`account_token`]), which takes an elevated test process. Where
//! one cannot be had the row logs `not obtainable` with the reason
//! and asserts nothing.
//!
//! Each check prints one line to stderr (written past the test
//! harness's capture, so it shows for passing tests too): the token's
//! type, impersonation level and integrity level, the descriptor,
//! and the granted mask and Win32 status under [`STRICT`] and under
//! [`LENIENT`]. Denied under the first and granted under the second
//! means the mandatory check, not the DACL, refused. A failure of the
//! `AccessCheck` call itself is never read as "no match": it panics
//! with the Win32 error.

#![cfg(windows)]

use std::ffi::c_void;
use std::fmt;
use std::io::Write;
use std::mem::size_of;
use windows::Win32::Foundation::{
    CloseHandle, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    HLOCAL, LocalFree,
};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{
    AccessCheck, CREATE_RESTRICTED_TOKEN_FLAGS, CreateRestrictedToken, DuplicateTokenEx,
    GENERIC_MAPPING, GetLengthSid, GetTokenInformation, ImpersonateAnonymousToken,
    IsTokenRestricted, PRIVILEGE_SET, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
    SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation,
    TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_IMPERSONATE,
    TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenGroups, TokenImpersonation,
    TokenImpersonationLevel, TokenIntegrityLevel, TokenIsAppContainer, TokenType, TokenUser,
    WRITE_RESTRICTED,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentThread,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess, OpenProcessToken,
    OpenThreadToken, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOEXW,
    SetThreadToken, TerminateProcess, UpdateProcThreadAttribute,
};
use windows::core::{BOOL, PWSTR};

use srt_win::sid::{LocalPsid, psid_to_string};
use srt_win::util::wstr;
use srt_win::wfp::{sddl_anonymous, sddl_negative, sddl_sandbox_user};

/// `CC` in SDDL is `ADS_RIGHT_DS_CREATE_CHILD` = bit 0. The filters
/// only need a single bit; `AccessCheck` is asked for that bit.
const DESIRED_ACCESS: u32 = 1;

/// Files [`DESIRED_ACCESS`] under no category. A token whose
/// integrity level is below the descriptor's label is then refused
/// whatever the DACL says — the strictest answer any mapping gives.
const STRICT: GENERIC_MAPPING = GENERIC_MAPPING {
    GenericRead: GENERIC_READ.0,
    GenericWrite: GENERIC_WRITE.0,
    GenericExecute: GENERIC_EXECUTE.0,
    GenericAll: GENERIC_ALL.0,
};

/// Files [`DESIRED_ACCESS`] under execute, which a no-write-up label
/// leaves to a token of lower integrity. Diagnostic only: a pair
/// denied under [`STRICT`] and granted under this one was refused by
/// the mandatory integrity check, not by the DACL.
const LENIENT: GENERIC_MAPPING = GENERIC_MAPPING {
    GenericRead: 0,
    GenericWrite: 0,
    GenericExecute: DESIRED_ACCESS,
    GenericAll: DESIRED_ACCESS,
};

/// The anonymous SD without its mandatory label. Logged next to the
/// real one, never asserted: it shows what the label changes.
const ANONYMOUS_LABELLED: &str = "O:LSG:LSD:(A;;CC;;;S-1-5-7)S:(ML;;NW;;;S-1-16-0)";

/// The low mandatory level.
const LOW_INTEGRITY_SID: &str = "S-1-16-4096";

/// The untrusted mandatory level — the lowest.
const UNTRUSTED_INTEGRITY_SID: &str = "S-1-16-0";

const EVERYONE_SID: &str = "S-1-1-0";
const RESTRICTED_SID: &str = "S-1-5-12";
const NULL_SID: &str = "S-1-0-0";

/// `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`: start the process
/// in an AppContainer.
const ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
/// `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY`.
const ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: usize = 0x0002_000F;
/// `PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT`: the
/// AppContainer is a less-privileged one, which ALL APPLICATION
/// PACKAGES does not match.
const ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 1;

/// `SE_GROUP_INTEGRITY`: marks a SID as a token's integrity level.
const SE_GROUP_INTEGRITY: u32 = 0x20;

/// A well-formed RID under `BUILTIN` that maps to nothing — a SID no
/// token here carries.
const FOREIGN_SID: &str = "S-1-5-32-9999";

/// A well-formed AppContainer package SID. It names no installed
/// package; a lowbox token only needs the SID to be of this form.
const PACKAGE_SID: &str = "S-1-15-2-1111-2222-3333-4444-5555-6666-7777";

/// `OBJECT_ATTRIBUTES`, for the one call below that takes it.
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *const c_void,
    attributes: u32,
    security_descriptor: *const c_void,
    security_quality_of_service: *const c_void,
}

// The system call that derives an AppContainer token from an
// existing one. `raw-dylib` so the test links without an import
// library for it.
#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtCreateLowBoxToken(
        token: *mut HANDLE,
        existing_token: HANDLE,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        package_sid: PSID,
        capability_count: u32,
        capabilities: *const SID_AND_ATTRIBUTES,
        handle_count: u32,
        handles: *const HANDLE,
    ) -> i32;
}

fn own_primary_token() -> HANDLE {
    let mut primary = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            &mut primary,
        )
        .expect("OpenProcessToken");
    }
    primary
}

/// Impersonation-level duplicate of `token` — `AccessCheck` requires
/// an impersonation token. Closes `token`.
fn into_impersonation(token: HANDLE) -> HANDLE {
    let mut imp = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut imp,
        )
        .expect("DuplicateTokenEx");
        let _ = CloseHandle(token);
    }
    imp
}

/// The calling process's own token.
fn own_token() -> HANDLE {
    into_impersonation(own_primary_token())
}

/// The anonymous token: what a thread's effective token is after
/// `ImpersonateAnonymousToken`. It is used as opened — an
/// impersonation token already, and `TOKEN_QUERY` is all
/// `AccessCheck` and [`describe`] need.
fn anonymous_token() -> HANDLE {
    let mut tok = HANDLE::default();
    unsafe {
        ImpersonateAnonymousToken(GetCurrentThread()).expect("ImpersonateAnonymousToken");
        // open_as_self: the open is checked against the process
        // token, not the anonymous one the thread now carries (which
        // would be refused).
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut tok);
        RevertToSelf().expect("RevertToSelf");
        opened.expect("OpenThreadToken(anonymous)");
    }
    tok
}

/// The calling process's own token with its integrity level lowered
/// to low. Unlike an AppContainer token it carries no package SID.
fn low_integrity_token() -> HANDLE {
    integrity_token(LOW_INTEGRITY_SID)
}

/// The calling process's own token at the mandatory level `level`
/// (a level no higher than its own: lowering takes no privilege).
fn integrity_token(level: &str) -> HANDLE {
    let tok = own_token();
    let low = LocalPsid::from_string(level).expect("integrity SID");
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: low.as_psid(),
            Attributes: SE_GROUP_INTEGRITY,
        },
    };
    unsafe {
        SetTokenInformation(
            tok,
            TokenIntegrityLevel,
            &label as *const TOKEN_MANDATORY_LABEL as *const c_void,
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(low.as_psid()),
        )
        .expect("SetTokenInformation(TokenIntegrityLevel)");
    }
    tok
}

/// An AppContainer (lowbox) token derived from the calling process's
/// token, with no capabilities.
fn appcontainer_token() -> HANDLE {
    let package = LocalPsid::from_string(PACKAGE_SID).expect("package SID");
    let attrs = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: HANDLE::default(),
        object_name: std::ptr::null(),
        attributes: 0,
        security_descriptor: std::ptr::null(),
        security_quality_of_service: std::ptr::null(),
    };
    let primary = own_primary_token();
    let mut lowbox = HANDLE::default();
    unsafe {
        let status = NtCreateLowBoxToken(
            &mut lowbox,
            primary,
            TOKEN_ALL_ACCESS.0,
            &attrs,
            package.as_psid(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
        );
        assert!(status >= 0, "NtCreateLowBoxToken: {status:#010x}");
        let _ = CloseHandle(primary);
    }
    into_impersonation(lowbox)
}

/// A restricted copy of the calling process's token whose user SID
/// is deny-only.
fn deny_only_user_token(me: &str) -> HANDLE {
    let user = LocalPsid::from_string(me).expect("own SID");
    let disable = [SID_AND_ATTRIBUTES {
        Sid: user.as_psid(),
        Attributes: 0,
    }];
    let primary = own_primary_token();
    let mut restricted = HANDLE::default();
    unsafe {
        CreateRestrictedToken(
            primary,
            CREATE_RESTRICTED_TOKEN_FLAGS(0),
            Some(&disable),
            None,
            None,
            &mut restricted,
        )
        .expect("CreateRestrictedToken");
        let _ = CloseHandle(primary);
    }
    into_impersonation(restricted)
}

/// The SIDs of the calling process's token groups, without the entry
/// that carries its integrity level.
fn own_group_sids() -> Vec<String> {
    let tok = own_primary_token();
    let mut len = 0u32;
    unsafe {
        // Sizing call: fails, and says how much room is needed.
        let _ = GetTokenInformation(tok, TokenGroups, None, 0, &mut len);
        // u64 elements: the buffer holds a struct with pointers.
        let mut buf = vec![0u64; (len as usize).div_ceil(8) + 1];
        GetTokenInformation(
            tok,
            TokenGroups,
            Some(buf.as_mut_ptr() as *mut c_void),
            size_of_val(buf.as_slice()) as u32,
            &mut len,
        )
        .expect("GetTokenInformation(TokenGroups)");
        let groups = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        let entries =
            std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize);
        let sids = entries
            .iter()
            .filter(|g| g.Attributes & SE_GROUP_INTEGRITY == 0)
            .map(|g| psid_to_string(g.Sid).expect("group SID"))
            .collect();
        let _ = CloseHandle(tok);
        sids
    }
}

/// A restricted copy of the calling process's token: every SID in
/// `deny_only` made deny-only, and `restricting` as its restricting
/// SIDs (none when empty).
fn restricted_token(
    deny_only: &[String],
    restricting: &[&str],
    flags: CREATE_RESTRICTED_TOKEN_FLAGS,
) -> HANDLE {
    let parse = |s: &str| LocalPsid::from_string(s).unwrap_or_else(|e| panic!("SID {s}: {e:#}"));
    let deny_sids: Vec<LocalPsid> = deny_only.iter().map(|s| parse(s)).collect();
    let restrict_sids: Vec<LocalPsid> = restricting.iter().map(|s| parse(s)).collect();
    let attrs = |sids: &[LocalPsid]| -> Vec<SID_AND_ATTRIBUTES> {
        sids.iter()
            .map(|s| SID_AND_ATTRIBUTES {
                Sid: s.as_psid(),
                Attributes: 0,
            })
            .collect()
    };
    let deny = attrs(&deny_sids);
    let restrict = attrs(&restrict_sids);
    let primary = own_primary_token();
    let mut restricted = HANDLE::default();
    unsafe {
        CreateRestrictedToken(
            primary,
            flags,
            (!deny.is_empty()).then_some(deny.as_slice()),
            None,
            (!restrict.is_empty()).then_some(restrict.as_slice()),
            &mut restricted,
        )
        .unwrap_or_else(|e| {
            panic!(
                "CreateRestrictedToken(deny-only {deny_only:?}, restricting {restricting:?}): {e}"
            )
        });
        let _ = CloseHandle(primary);
    }
    into_impersonation(restricted)
}

/// A copy of the calling process's token with the user SID and every
/// group deny-only.
fn deny_all_token(me: &str) -> HANDLE {
    let mut all = vec![me.to_string()];
    all.extend(own_group_sids());
    restricted_token(&all, &[], CREATE_RESTRICTED_TOKEN_FLAGS(0))
}

/// A copy of the calling process's token with `restricting` as its
/// restricting SIDs.
fn restricting_token(restricting: &[&str]) -> HANDLE {
    restricted_token(&[], restricting, CREATE_RESTRICTED_TOKEN_FLAGS(0))
}

/// The user SID of `token`, or the error reading it.
fn token_user(token: HANDLE) -> Result<String, String> {
    // u64 elements: the buffer starts with a struct holding a pointer.
    let mut buf = [0u64; 16];
    let mut len = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            size_of_val(&buf) as u32,
            &mut len,
        )
        .map_err(|e| format!("<{e}>"))?;
        // TOKEN_USER starts with the user's SID_AND_ATTRIBUTES.
        let user = &*(buf.as_ptr() as *const SID_AND_ATTRIBUTES);
        psid_to_string(user.Sid).map_err(|e| format!("<{e:#}>"))
    }
}

/// An impersonation copy of the token of some running process whose
/// user is `account` (a SID), or why none could be had. Opening
/// another account's process and duplicating its token takes an
/// elevated caller; the processes are tried in snapshot order until
/// one gives its token up.
fn account_token(account: &str) -> Result<HANDLE, String> {
    let mut why = "no process of that account was found".to_string();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| format!("CreateToolhelp32Snapshot: {e}"))?;
        let mut pe = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = None;
        let mut more = Process32FirstW(snap, &mut pe).is_ok();
        while more && found.is_none() {
            let pid = pe.th32ProcessID;
            more = Process32NextW(snap, &mut pe).is_ok();
            let Ok(process) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
                continue;
            };
            let mut tok = HANDLE::default();
            let opened = OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut tok);
            if let Err(e) = opened {
                // Query alone, to say whether this was a process of
                // the account whose token would not open further.
                let mut query = HANDLE::default();
                if OpenProcessToken(process, TOKEN_QUERY, &mut query).is_ok() {
                    if token_user(query).as_deref() == Ok(account) {
                        why = format!("pid {pid}: its token opens for query only ({e})");
                    }
                    let _ = CloseHandle(query);
                }
                let _ = CloseHandle(process);
                continue;
            }
            let _ = CloseHandle(process);
            if token_user(tok).as_deref() == Ok(account) {
                let mut imp = HANDLE::default();
                match DuplicateTokenEx(
                    tok,
                    TOKEN_QUERY | TOKEN_IMPERSONATE,
                    None,
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut imp,
                ) {
                    Ok(()) => found = Some(imp),
                    Err(e) => why = format!("pid {pid}: DuplicateTokenEx: {e}"),
                }
            }
            let _ = CloseHandle(tok);
        }
        let _ = CloseHandle(snap);
        found.ok_or(why)
    }
}

/// Tokens of SYSTEM, LOCAL SERVICE and NETWORK SERVICE, each borrowed
/// from a running process of that account ([`account_token`]), or the
/// reason it could not be.
///
/// SYSTEM first, with the debug privilege enabled if the caller holds
/// it. The two service accounts are then looked for while the thread
/// impersonates SYSTEM, since a service's token need not open for an
/// administrator; if SYSTEM could not be had, or could not be
/// impersonated, they are looked for as the caller.
fn service_account_tokens() -> Vec<(&'static str, Result<HANDLE, String>)> {
    let _ = srt_win::util::enable_privilege("SeDebugPrivilege");
    let system = account_token("S-1-5-18");
    let as_system = match &system {
        Ok(tok) => unsafe { SetThreadToken(None, Some(*tok)) }.is_ok(),
        Err(_) => false,
    };
    let local_service = account_token("S-1-5-19");
    let network_service = account_token("S-1-5-20");
    if as_system {
        unsafe { RevertToSelf().expect("RevertToSelf") };
    }
    log(&format!(
        "service-account tokens looked for {}",
        if as_system {
            "while impersonating SYSTEM"
        } else {
            "as the calling user"
        }
    ));
    vec![
        ("SYSTEM", system),
        ("LOCAL SERVICE", local_service),
        ("NETWORK SERVICE", network_service),
    ]
}

/// The token of a less-privileged AppContainer process of the calling
/// user, or why one could not be had.
///
/// Unlike an ordinary AppContainer token this cannot be derived from
/// an existing token: what makes it less-privileged is an attribute
/// the system sets when it creates the process. So a process is
/// created suspended in such a container, its token copied, and the
/// process ended without ever running.
fn less_privileged_appcontainer_token() -> Result<HANDLE, String> {
    let package = LocalPsid::from_string(PACKAGE_SID).map_err(|e| format!("{e:#}"))?;
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: package.as_psid(),
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let policy = ALL_APPLICATION_PACKAGES_OPT_OUT;
    let system_root = std::env::var("SystemRoot").map_err(|e| format!("SystemRoot: {e}"))?;
    let mut cmdline = wstr(&format!(r"{system_root}\System32\cmd.exe"));
    unsafe {
        let mut size = 0usize;
        // Sizing call: fails, and says how much room is needed.
        let _ = InitializeProcThreadAttributeList(None, 2, None, &mut size);
        if size == 0 {
            return Err("InitializeProcThreadAttributeList gave no size".to_string());
        }
        let mut storage = vec![0u8; size];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr() as *mut c_void);
        InitializeProcThreadAttributeList(Some(list), 2, None, &mut size)
            .map_err(|e| format!("InitializeProcThreadAttributeList: {e}"))?;
        let token = (|| -> Result<HANDLE, String> {
            UpdateProcThreadAttribute(
                list,
                0,
                ATTRIBUTE_SECURITY_CAPABILITIES,
                Some(&capabilities as *const SECURITY_CAPABILITIES as *const c_void),
                size_of::<SECURITY_CAPABILITIES>(),
                None,
                None,
            )
            .map_err(|e| format!("UpdateProcThreadAttribute(security capabilities): {e}"))?;
            UpdateProcThreadAttribute(
                list,
                0,
                ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                Some(&policy as *const u32 as *const c_void),
                size_of::<u32>(),
                None,
                None,
            )
            .map_err(|e| format!("UpdateProcThreadAttribute(all-packages policy): {e}"))?;
            let mut startup = STARTUPINFOEXW::default();
            startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup.lpAttributeList = list;
            let mut pi = PROCESS_INFORMATION::default();
            CreateProcessW(
                None,
                Some(PWSTR(cmdline.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                None,
                None,
                &startup.StartupInfo,
                &mut pi,
            )
            .map_err(|e| format!("CreateProcessW in a less-privileged AppContainer: {e}"))?;
            let mut primary = HANDLE::default();
            let opened = OpenProcessToken(pi.hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &mut primary);
            // The process was only ever a way to get its token.
            let _ = TerminateProcess(pi.hProcess, 0);
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
            opened.map_err(|e| format!("OpenProcessToken(child): {e}"))?;
            let mut imp = HANDLE::default();
            let dup = DuplicateTokenEx(
                primary,
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                None,
                SecurityImpersonation,
                TokenImpersonation,
                &mut imp,
            );
            let _ = CloseHandle(primary);
            dup.map_err(|e| format!("DuplicateTokenEx(child token): {e}"))?;
            Ok(imp)
        })();
        DeleteProcThreadAttributeList(list);
        token
    }
}

/// One `u32`-sized token property, or the error reading it.
fn token_u32(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<u32, String> {
    let mut value = 0u32;
    let mut len = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(&mut value as *mut u32 as *mut c_void),
            size_of::<u32>() as u32,
            &mut len,
        )
    }
    .map(|()| value)
    .map_err(|e| format!("<{e}>"))
}

/// The token's integrity level as a string SID, or the error reading
/// it.
fn token_integrity(token: HANDLE) -> Result<String, String> {
    // u64 elements: the buffer starts with a struct holding a pointer.
    let mut buf = [0u64; 16];
    let mut len = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut c_void),
            size_of_val(&buf) as u32,
            &mut len,
        )
        .map_err(|e| format!("<{e}>"))?;
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        psid_to_string(label.Label.Sid).map_err(|e| format!("<{e:#}>"))
    }
}

/// The token properties an access check depends on besides its SIDs:
/// type (1 primary, 2 impersonation), impersonation level and
/// integrity level. A property that cannot be read is shown as its
/// error.
fn describe(token: HANDLE) -> String {
    let show = |r: Result<String, String>| r.unwrap_or_else(|e| e);
    let level = token_u32(token, TokenImpersonationLevel).map(|l| {
        match l {
            0 => "anonymous",
            1 => "identification",
            2 => "impersonation",
            3 => "delegation",
            _ => "unknown",
        }
        .to_string()
    });
    format!(
        "type={} level={} integrity={} user={} restricted={} appcontainer={}",
        show(token_u32(token, TokenType).map(|t| t.to_string())),
        show(level),
        show(token_integrity(token)),
        show(token_user(token)),
        unsafe { IsTokenRestricted(token) }.is_ok(),
        show(token_u32(token, TokenIsAppContainer).map(|v| (v != 0).to_string())),
    )
}

/// What one `AccessCheck` call answered.
struct Verdict {
    granted: bool,
    mask: u32,
    /// The Win32 status the call left behind: the reason, when it
    /// did not grant.
    status: u32,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.granted {
            write!(f, "GRANTED mask={:#x}", self.mask)
        } else {
            write!(f, "DENIED mask={:#x} win32={}", self.mask, self.status)
        }
    }
}

/// `AccessCheck(token, SD-from-sddl, DESIRED_ACCESS)` under `mapping`.
///
/// "Did not grant" and "the call failed" are different answers. The
/// first is returned. The second — a token that is not an
/// impersonation token or is below identification level, a
/// descriptor with no owner or group — panics with the Win32 error.
fn access_check(row: &str, token: HANDLE, sddl: &str, mapping: &GENERIC_MAPPING) -> Verdict {
    let w = wstr(sddl);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows::core::PCWSTR(w.as_ptr()),
            1, // SDDL_REVISION_1
            &mut psd,
            None,
        )
        .unwrap_or_else(|e| panic!("[{row}] SDDL {sddl} does not convert: {e}"));
    }
    let mut priv_set = PRIVILEGE_SET::default();
    let mut priv_set_len = size_of::<PRIVILEGE_SET>() as u32;
    let mut mask: u32 = 0;
    let mut granted = BOOL(0);
    let (r, status) = unsafe {
        let r = AccessCheck(
            psd,
            token,
            DESIRED_ACCESS,
            mapping,
            Some(&mut priv_set),
            &mut priv_set_len,
            &mut mask,
            &mut granted,
        );
        // Read before anything else can overwrite it.
        let status = GetLastError().0;
        let _ = LocalFree(Some(HLOCAL(psd.0)));
        (r, status)
    };
    if let Err(e) = r {
        panic!(
            "[{row}] AccessCheck itself failed — an API error, not a denial: {e} \
             (win32={status}); token {{{}}}, sd {sddl}",
            describe(token)
        );
    }
    Verdict {
        granted: granted.as_bool(),
        mask,
        status,
    }
}

/// One line to stderr. Straight to the stream: the test harness
/// captures the print macros and drops what a passing test printed.
fn log(line: &str) {
    let _ = std::io::stderr().write_all(format!("sd_access_check_matrix: {line}\n").as_bytes());
}

/// Whether `token` matches the descriptor `sddl`, under [`STRICT`]
/// and under [`LENIENT`]. Logs the pair with both answers.
fn check_both(row: &str, token: HANDLE, sddl: &str) -> (bool, bool) {
    let strict = access_check(row, token, sddl, &STRICT);
    let lenient = access_check(row, token, sddl, &LENIENT);
    log(&format!(
        "[{row}] token {{{}}} sd {sddl}: {strict}; lenient mapping: {lenient}",
        describe(token)
    ));
    (strict.granted, lenient.granted)
}

/// Whether `token` matches the descriptor `sddl` under [`STRICT`].
/// Logs the pair, with the answer under [`LENIENT`] beside it.
fn check(row: &str, token: HANDLE, sddl: &str) -> bool {
    check_both(row, token, sddl).0
}

/// A row of the negative-mode tables: `token` is `permitted` by the
/// descriptor `sddl`, or is not. Asserted when [`STRICT`] and
/// [`LENIENT`] agree. When they disagree the answer is the mandatory
/// integrity check's and depends on a mapping only the filtering
/// engine knows; the row is then logged as such and nothing is
/// asserted.
fn expect(row: &str, token: HANDLE, sddl: &str, permitted: bool) {
    let word = |b: bool| if b { "PERMITTED" } else { "NOT PERMITTED" };
    let (strict, lenient) = check_both(row, token, sddl);
    if strict != lenient {
        log(&format!(
            "[{row}] MAPPINGS DISAGREE: strict={}, lenient={}; wanted {} — logged, not asserted",
            word(strict),
            word(lenient),
            word(permitted)
        ));
        return;
    }
    log(&format!("[{row}] {} under both mappings", word(strict)));
    assert_eq!(
        strict,
        permitted,
        "[{row}] expected {}, got {} under both mappings; token {{{}}}, sd {sddl}",
        word(permitted),
        word(strict),
        describe(token)
    );
}

fn close(token: HANDLE) {
    unsafe {
        let _ = CloseHandle(token);
    }
}

#[test]
fn plain_tokens() {
    let tok = own_token();
    let me = srt_win::sid::current_user_sid().unwrap();

    // SD keyed on THIS token's user SID → GRANT (i.e. block-user
    // would fire — the sandbox user is fenced).
    assert!(
        check("plain / sandbox-user SD", tok, &sddl_sandbox_user(&me)),
        "sandbox-user SD keyed on own user SID must match own token"
    );
    // SD keyed on a SID this token does NOT carry → DENY (i.e. the
    // BLOCK does NOT match the broker / services / any other user →
    // falls through to default-permit). The package ACEs on the SD
    // must not change that: a token outside an AppContainer carries
    // neither package SID.
    assert!(
        !check(
            "plain / sandbox-user SD of another user",
            tok,
            &sddl_sandbox_user(FOREIGN_SID)
        ),
        "sandbox-user SD keyed on a foreign SID must NOT match own token"
    );
    // A real user's own token is not the anonymous token. The label
    // on the anonymous SD lets every token past the mandatory check,
    // so this is the DACL's answer.
    assert!(
        !check("plain / anonymous SD", tok, &sddl_anonymous()),
        "anonymous SD must NOT match a real user's token"
    );
    close(tok);
}

#[test]
fn anonymous_token_matches_only_the_anonymous_sd() {
    let tok = anonymous_token();
    let me = srt_win::sid::current_user_sid().unwrap();

    // Logged, not asserted. The anonymous token's integrity level is
    // untrusted, so against the filter's unlabelled descriptor the
    // result depends on the generic mapping the checker passes: the
    // strict mapping here refuses it, the lenient one grants it. The
    // filtering engine's own mapping is not visible from here; the
    // smoke rows that connect under the anonymous token are the
    // measurement. The labelled row shows the DACL itself is right.
    let _ = check("anonymous / anonymous SD", tok, &sddl_anonymous());
    let _ = check(
        "anonymous / anonymous SD with an untrusted label",
        tok,
        ANONYMOUS_LABELLED,
    );
    // Why the anonymous BLOCK exists: the sandbox-user SD does not
    // reach a thread of the sandbox account once it impersonates
    // anonymous.
    assert!(
        !check("anonymous / sandbox-user SD", tok, &sddl_sandbox_user(&me)),
        "sandbox-user SD does not match the anonymous token"
    );
    close(tok);
}

#[test]
fn appcontainer_token_of_the_sandbox_account_matches() {
    let tok = appcontainer_token();
    let me = srt_win::sid::current_user_sid().unwrap();

    assert!(
        check(
            "AppContainer / sandbox-user SD",
            tok,
            &sddl_sandbox_user(&me)
        ),
        "sandbox-user SD must match an AppContainer token of that user"
    );
    // Why the package ACEs exist: the user ACE alone satisfies only
    // the user half of an AppContainer token's access check.
    assert!(
        !check(
            "AppContainer / user-only SD",
            tok,
            &format!("O:LSG:LSD:(A;;CC;;;{me})")
        ),
        "a user-only SD must NOT match an AppContainer token"
    );
    // The package ACEs grant nothing by themselves: an AppContainer
    // token of another user still fails the user half.
    assert!(
        !check(
            "AppContainer / sandbox-user SD of another user",
            tok,
            &sddl_sandbox_user(FOREIGN_SID)
        ),
        "sandbox-user SD keyed on a foreign SID must NOT match an AppContainer token"
    );
    close(tok);
}

#[test]
fn deny_only_user_sid_is_not_matched() {
    let me = srt_win::sid::current_user_sid().unwrap();
    let tok = deny_only_user_token(&me);

    // The gap, pinned: a deny-only SID satisfies no ALLOW ACE, and
    // the token carries neither package SID nor ANONYMOUS LOGON.
    assert!(
        !check("deny-only / sandbox-user SD", tok, &sddl_sandbox_user(&me)),
        "an ALLOW ACE does not match a deny-only user SID"
    );
    assert!(
        !check("deny-only / anonymous SD", tok, &sddl_anonymous()),
        "anonymous SD must NOT match a deny-only token of a real user"
    );
    close(tok);
}

#[test]
fn lowered_integrity_token_of_the_sandbox_account() {
    let tok = low_integrity_token();
    let me = srt_win::sid::current_user_sid().unwrap();

    // Logged, not asserted. The sandbox-user SD has no label, so for
    // a token below medium integrity the answer is the mandatory
    // check's and turns on the generic mapping: this row shows it
    // under both. Whether the sandbox-user BLOCK reaches such a token
    // is therefore the filtering engine's mapping to decide, which
    // this test cannot observe.
    let _ = check(
        "low integrity / sandbox-user SD",
        tok,
        &sddl_sandbox_user(&me),
    );

    // These hold under any mapping: neither DACL names this token.
    assert!(
        !check(
            "low integrity / sandbox-user SD of another user",
            tok,
            &sddl_sandbox_user(FOREIGN_SID)
        ),
        "sandbox-user SD keyed on a foreign SID must NOT match a low-integrity token"
    );
    assert!(
        !check("low integrity / anonymous SD", tok, &sddl_anonymous()),
        "anonymous SD must NOT match a low-integrity token of a real user"
    );
    close(tok);
}

// ────────────────────── negative-mode descriptor ──────────────────────

/// The negative descriptor with the calling user as "some other
/// principal": the sandbox account is a SID no token here carries.
fn negative_for_others() -> String {
    sddl_negative(FOREIGN_SID)
}

#[test]
fn negative_sd_permits_ordinary_tokens_of_other_principals() {
    let me = srt_win::sid::current_user_sid().unwrap();
    let sd = negative_for_others();

    // The calling user's own token — elevated when the test is; the
    // logged integrity level says which.
    let tok = own_token();
    expect("negative / own token", tok, &sd, true);
    close(tok);

    // The user SID deny-only: Everyone is still enabled.
    let tok = deny_only_user_token(&me);
    expect("negative / user SID deny-only", tok, &sd, true);
    close(tok);

    // Restricted tokens: granted through the ordinary SIDs AND
    // through a restricting SID the descriptor allows.
    let tok = restricting_token(&[&me, EVERYONE_SID, RESTRICTED_SID]);
    expect(
        "negative / restricted to [user, Everyone, RESTRICTED]",
        tok,
        &sd,
        true,
    );
    close(tok);
    let tok = restricting_token(&[EVERYONE_SID]);
    expect("negative / restricted to [Everyone]", tok, &sd, true);
    close(tok);
    // What the RESTRICTED ACE is for.
    let tok = restricting_token(&[RESTRICTED_SID]);
    expect("negative / restricted to [RESTRICTED]", tok, &sd, true);
    close(tok);

    let tok = restricted_token(&[], &[&me, EVERYONE_SID, RESTRICTED_SID], WRITE_RESTRICTED);
    expect(
        "negative / write-restricted to [user, Everyone, RESTRICTED]",
        tok,
        &sd,
        true,
    );
    close(tok);
}

#[test]
fn negative_sd_and_service_account_tokens() {
    let sd = negative_for_others();
    for (name, token) in service_account_tokens() {
        let row = format!("negative / {name}");
        match token {
            Ok(tok) => {
                expect(&row, tok, &sd, true);
                close(tok);
            }
            Err(why) => log(&format!("[{row}] not obtainable: {why}")),
        }
    }
}

#[test]
fn negative_sd_and_tokens_below_medium_integrity() {
    let sd = negative_for_others();
    // Each of these is PERMITTED by the DACL and sits below the
    // medium level an unlabelled descriptor is given, so the two
    // mappings are expected to disagree and the rows to be logged.
    for (name, level) in [
        ("low integrity", LOW_INTEGRITY_SID),
        ("untrusted integrity", UNTRUSTED_INTEGRITY_SID),
    ] {
        let tok = integrity_token(level);
        expect(&format!("negative / {name}"), tok, &sd, true);
        close(tok);
    }

    let tok = appcontainer_token();
    expect("negative / AppContainer", tok, &sd, true);
    close(tok);

    match less_privileged_appcontainer_token() {
        Ok(tok) => {
            expect("negative / less-privileged AppContainer", tok, &sd, true);
            // Logged only: whether the token really is a
            // less-privileged one. ALL APPLICATION PACKAGES alone
            // grants an ordinary AppContainer and not this.
            let _ = check_both(
                "less-privileged AppContainer / Everyone + ALL APPLICATION PACKAGES only",
                tok,
                "O:LSG:LSD:(A;;CC;;;S-1-1-0)(A;;CC;;;S-1-15-2-1)",
            );
            close(tok);
        }
        Err(why) => log(&format!(
            "[negative / less-privileged AppContainer] not obtainable: {why}"
        )),
    }
}

/// Tokens of OTHER accounts that the negative descriptor turns away:
/// what installing the negative mode costs. Asserted, so the list in
/// `sddl_negative`'s documentation stays true.
#[test]
fn negative_sd_cuts_off_these_tokens_of_other_principals() {
    let me = srt_win::sid::current_user_sid().unwrap();
    let sd = negative_for_others();

    // Everyone deny-only, and nothing else the descriptor lists
    // enabled.
    let tok = deny_all_token(&me);
    expect("negative / every SID deny-only", tok, &sd, false);
    close(tok);

    // Restricting SIDs the descriptor cannot list (a user's own SID)
    // or does not (the null SID).
    let tok = restricting_token(&[&me]);
    expect("negative / restricted to [user]", tok, &sd, false);
    close(tok);
    let tok = restricting_token(&[NULL_SID]);
    expect("negative / restricted to [null SID]", tok, &sd, false);
    close(tok);

    // The anonymous token, whoever impersonates it.
    let tok = anonymous_token();
    expect("negative / anonymous", tok, &sd, false);
    close(tok);
}

/// The calling user stands in for the sandbox account: the descriptor
/// DENYs its SID, and no token derived from its own may pass.
#[test]
fn negative_sd_refuses_every_token_of_the_sandbox_account() {
    let me = srt_win::sid::current_user_sid().unwrap();
    let sd = sddl_negative(&me);

    let tok = own_token();
    expect("negative(sandbox) / own token", tok, &sd, false);
    close(tok);

    // The shapes an ALLOW ACE for the account's SID cannot reach.
    let tok = deny_only_user_token(&me);
    expect("negative(sandbox) / user SID deny-only", tok, &sd, false);
    close(tok);
    let tok = deny_all_token(&me);
    expect("negative(sandbox) / every SID deny-only", tok, &sd, false);
    close(tok);
    let tok = restricting_token(&[EVERYONE_SID]);
    expect(
        "negative(sandbox) / restricted to [Everyone]",
        tok,
        &sd,
        false,
    );
    close(tok);
    let tok = restricted_token(&[], &[EVERYONE_SID], WRITE_RESTRICTED);
    expect(
        "negative(sandbox) / write-restricted to [Everyone]",
        tok,
        &sd,
        false,
    );
    close(tok);
    let tok = restricting_token(&[&me, EVERYONE_SID, RESTRICTED_SID]);
    expect(
        "negative(sandbox) / restricted to [user, Everyone, RESTRICTED]",
        tok,
        &sd,
        false,
    );
    close(tok);

    // Lowered integrity: refused by the DENY ACE under the lenient
    // mapping and by the mandatory check under the strict one.
    for (name, level) in [
        ("low integrity", LOW_INTEGRITY_SID),
        ("untrusted integrity", UNTRUSTED_INTEGRITY_SID),
    ] {
        let tok = integrity_token(level);
        expect(&format!("negative(sandbox) / {name}"), tok, &sd, false);
        close(tok);
    }
    let tok = appcontainer_token();
    expect("negative(sandbox) / AppContainer", tok, &sd, false);
    close(tok);

    // The one identity it can assume without its SID.
    let tok = anonymous_token();
    expect("negative(sandbox) / anonymous", tok, &sd, false);
    close(tok);
}
