//! Proof that the security descriptors on the WFP BLOCK filters
//! match the token shapes `wfp::install_filters` relies on them to
//! match — and only those.
//!
//! WFP's `ALE_USER_ID` `FWP_MATCH_EQUAL` condition runs `AccessCheck`
//! on the connecting thread's effective token against the filter's
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
//!
//! The last row is not what the fence wants — it is what an ALLOW
//! ACE can do. A deny-only SID satisfies no ALLOW ACE, so no
//! descriptor of this shape reaches that token; the row is asserted
//! so the gap stays visible.

#![cfg(windows)]

use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::{
    CloseHandle, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, HANDLE,
};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{
    AccessCheck, CREATE_RESTRICTED_TOKEN_FLAGS, CreateRestrictedToken, DuplicateTokenEx,
    GENERIC_MAPPING, ImpersonateAnonymousToken, PRIVILEGE_SET, PSECURITY_DESCRIPTOR, PSID,
    RevertToSelf, SID_AND_ATTRIBUTES, SecurityImpersonation, TOKEN_ALL_ACCESS,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, TokenImpersonation,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};
use windows::core::BOOL;

use srt_win::sid::LocalPsid;
use srt_win::util::wstr;
use srt_win::wfp::{sddl_anonymous, sddl_sandbox_user};

/// `CC` in SDDL is `ADS_RIGHT_DS_CREATE_CHILD` = bit 0. The filters
/// only need a single bit; `AccessCheck` is asked for that bit.
const DESIRED_ACCESS: u32 = 1;

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
/// `ImpersonateAnonymousToken`.
fn anonymous_token() -> HANDLE {
    let mut tok = HANDLE::default();
    unsafe {
        ImpersonateAnonymousToken(GetCurrentThread()).expect("ImpersonateAnonymousToken");
        // open_as_self: the open is checked against the process
        // token, not the anonymous one the thread now carries.
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut tok);
        RevertToSelf().expect("RevertToSelf");
        opened.expect("OpenThreadToken(anonymous)");
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

/// Run `AccessCheck(token, SD-from-sddl, DESIRED_ACCESS)` and return
/// whether it granted.
fn check(token: HANDLE, sddl: &str) -> bool {
    let w = wstr(sddl);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows::core::PCWSTR(w.as_ptr()),
            1, // SDDL_REVISION_1
            &mut psd,
            None,
        )
        .expect("ConvertStringSecurityDescriptorToSecurityDescriptorW");
    }
    // GENERIC_MAPPING is required by the API but irrelevant here:
    // DESIRED_ACCESS has no generic bits set, so MapGenericMask
    // never consults this table.
    let mapping = GENERIC_MAPPING {
        GenericRead: GENERIC_READ.0,
        GenericWrite: GENERIC_WRITE.0,
        GenericExecute: GENERIC_EXECUTE.0,
        GenericAll: GENERIC_ALL.0,
    };
    let mut priv_set = PRIVILEGE_SET::default();
    let mut priv_set_len = size_of::<PRIVILEGE_SET>() as u32;
    let mut granted: u32 = 0;
    let mut status = BOOL(0);
    let r = unsafe {
        AccessCheck(
            psd,
            token,
            DESIRED_ACCESS,
            &mapping,
            Some(&mut priv_set),
            &mut priv_set_len,
            &mut granted,
            &mut status,
        )
    };
    unsafe {
        let _ =
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(psd.0)));
    }
    r.expect("AccessCheck");
    status.as_bool()
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
        check(tok, &sddl_sandbox_user(&me)),
        "sandbox-user SD keyed on own user SID must match own token"
    );
    // SD keyed on a SID this token does NOT carry → DENY (i.e. the
    // BLOCK does NOT match the broker / services / any other user →
    // falls through to default-permit). The package ACEs on the SD
    // must not change that: a token outside an AppContainer carries
    // neither package SID.
    assert!(
        !check(tok, &sddl_sandbox_user(FOREIGN_SID)),
        "sandbox-user SD keyed on a foreign SID must NOT match own token"
    );
    // A real user's own token is not the anonymous token.
    assert!(
        !check(tok, &sddl_anonymous()),
        "anonymous SD must NOT match a real user's token"
    );
    close(tok);
}

#[test]
fn anonymous_token_matches_only_the_anonymous_sd() {
    let tok = anonymous_token();
    let me = srt_win::sid::current_user_sid().unwrap();

    assert!(
        check(tok, &sddl_anonymous()),
        "anonymous SD must match the anonymous token"
    );
    // Why the anonymous BLOCK exists: the sandbox-user SD does not
    // reach a thread of the sandbox account once it impersonates
    // anonymous.
    assert!(
        !check(tok, &sddl_sandbox_user(&me)),
        "sandbox-user SD does not match the anonymous token"
    );
    close(tok);
}

#[test]
fn appcontainer_token_of_the_sandbox_account_matches() {
    let tok = appcontainer_token();
    let me = srt_win::sid::current_user_sid().unwrap();

    assert!(
        check(tok, &sddl_sandbox_user(&me)),
        "sandbox-user SD must match an AppContainer token of that user"
    );
    // Why the package ACEs exist: the user ACE alone satisfies only
    // the user half of an AppContainer token's access check.
    assert!(
        !check(tok, &format!("O:LSG:LSD:(A;;CC;;;{me})")),
        "a user-only SD must NOT match an AppContainer token"
    );
    // The package ACEs grant nothing by themselves: an AppContainer
    // token of another user still fails the user half.
    assert!(
        !check(tok, &sddl_sandbox_user(FOREIGN_SID)),
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
        !check(tok, &sddl_sandbox_user(&me)),
        "an ALLOW ACE does not match a deny-only user SID"
    );
    assert!(!check(tok, &sddl_anonymous()));
    close(tok);
}
