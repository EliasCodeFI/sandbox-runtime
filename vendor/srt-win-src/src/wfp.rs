//! Windows Filtering Platform (WFP) filter management for the
//! sandbox-runtime Windows network fence.
//!
//! ## Design
//!
//! At install time we provision the dedicated `srt-sandbox` local
//! user account ([`crate::user`]) and persist **one machine-wide**
//! filter set — three filters at each of `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
//! and `_V6` (6 total), plus one more per layer when a loopback port
//! range is configured (8 total), all under one persistent sublayer
//! ([`filter_specs`] is the list):
//!
//!   - **PERMIT loopback** (weight [`W_LOOPBACK`]) —
//!     `IP_REMOTE_ADDRESS` is `127.0.0.0/8` (v4) / `::1` (v6) **and**
//!     `IP_REMOTE_PORT` is in `[low, high]` (default 60080–60089). No
//!     user condition. The sandboxed child reaches the host proxies —
//!     which on Windows bind inside this range — but not arbitrary
//!     loopback listeners. (Linux/macOS restrict the child to exactly
//!     the two proxy ports; this range is the closest Windows
//!     analogue without per-`initialize()` admin.)
//!
//!   - **PERMIT loopback range** (weight [`W_LOOPBACK`], optional) —
//!     the same two conditions as the PERMIT above with a second,
//!     configured port range (`srt-win install --loopback-port-range`).
//!     Absent unless configured. It lets the sandboxed child connect
//!     directly to local servers listening inside that range — a
//!     development server, a database, a server another sandboxed
//!     command started. It opens every listener on those loopback
//!     ports, whoever owns it, so [`validate_loopback_port_range`]
//!     bounds what the range may be.
//!
//!   - **BLOCK sandbox user** (weight [`W_BLOCK`]) — `ALE_USER_ID` SD
//!     = [`sddl_sandbox_user`]. Matches only tokens whose user SID is
//!     `<srt-sandbox SID>`. Everyone else (the broker, services,
//!     SYSTEM, the real user) carries a different user SID → no match
//!     → falls through to default-permit. The SD also carries ALLOW
//!     ACEs for the two all-packages SIDs so an AppContainer token
//!     derived from the sandbox account still matches (see
//!     [`sddl_sandbox_user`]).
//!
//!   - **BLOCK anonymous, off-loopback** (weight [`W_BLOCK`]) —
//!     `ALE_USER_ID` SD = [`sddl_anonymous`] **and** `IP_REMOTE_ADDRESS`
//!     outside loopback ([`non_loopback_v4_ranges`] /
//!     [`non_loopback_v6_ranges`]). The identity WFP checks is the
//!     connecting thread's *effective* token, so a sandboxed thread
//!     that impersonates the anonymous token presents `ANONYMOUS
//!     LOGON`, which the sandbox-user SD does not grant. This filter
//!     is what refuses that connect. It is machine-wide — it applies
//!     to ANY thread impersonating anonymous, whoever owns the
//!     process — so it is confined to non-loopback destinations. The
//!     SD carries an untrusted-level mandatory label, because the
//!     anonymous token's integrity level is below the level an
//!     unlabelled descriptor is given (see [`sddl_anonymous`]).
//!
//! ## What the filters do not cover
//!
//!   - A connect to a **loopback** destination made while
//!     impersonating anonymous matches neither BLOCK: local listeners
//!     outside the permitted port ranges are reachable that way.
//!   - A token whose user SID has been made **deny-only**
//!     (`CreateRestrictedToken`) is matched by no ALLOW ACE, so the
//!     sandbox-user BLOCK does not match it. No descriptor can fix
//!     that: the filter set blocks what it can name and permits the
//!     rest. `srt-win wfp verify` probes this shape and reports it as
//!     the [`RESIDUAL_DENY_ONLY`] residual.
//!
//! WFP's `ALE_USER_ID` condition with `FWP_MATCH_EQUAL` evaluates the
//! supplied security descriptor via `AccessCheck` against the
//! connecting token: the filter *matches* iff the check grants
//! access. Keying on the **user SID** means the surrogate-spawn
//! class (schtasks, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, BITS,
//! RunAs="Interactive User" COM) cannot defeat it: a process spawned
//! under `srt-sandbox` by ANY mechanism still has the user SID and
//! still matches the BLOCK.
//!
//! Filters carry a small JSON tag in `providerData` (`{tool, kind,
//! port_range?, user_sid, rev}`) so install/uninstall/status can
//! locate them by enumeration. `rev` is [`FENCE_REVISION`]; a set
//! written by an earlier build lacks it (or the anonymous BLOCK) and
//! reads as `outdated`. The configured loopback range is part of what
//! a session must agree with the install about: it is recorded in the
//! `permit-loopback-range` tags and in the install record, and `wfp
//! verify` / `exec` refuse a session configured with a different one
//! ([`loopback_range_hint`]). BFE enumeration is admin-gated (see
//! [`WfpAccessDenied`]) — `wfp status` returns `cannot-read` for a
//! non-elevated caller; the non-elevated readiness check is `srt-win
//! wfp verify` (a behavioral connect probe).

// The WFP structs are large and partially-initialised; the
// `..Default::default()` struct-update form clippy suggests is
// significantly less readable here than field-by-field assignment.
#![allow(clippy::field_reassign_with_default)]

use crate::util::wstr;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE,
    FWP_BYTE_BLOB, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_FILTER_ENUM_OVERLAPPING,
    FWP_MATCH_EQUAL, FWP_MATCH_RANGE, FWP_RANGE_TYPE, FWP_RANGE0, FWP_SECURITY_DESCRIPTOR_TYPE,
    FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_VALUE0,
    FWP_VALUE0_0, FWPM_ACTION0, FWPM_ACTION0_0, FWPM_CONDITION_ALE_USER_ID,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SUBLAYER_FLAG_PERSISTENT,
    FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteByKey0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0,
};
use windows::core::{GUID, PCWSTR, PWSTR};

/// Default sublayer GUID. Stable so uninstall can find filters from a
/// previous install. Overridable via `--sublayer-guid` so an
/// enterprise that provisions WFP via its own tooling can point us at
/// theirs. {2c5d0ad6-5f3b-4d4e-9b8f-1a3e7c9d0b21}
pub const DEFAULT_SUBLAYER_GUID: GUID = GUID::from_u128(0x2c5d0ad6_5f3b_4d4e_9b8f_1a3e7c9d0b21);

/// Default loopback port range for the PERMIT filter. The JS mux
/// proxy (front-end + http backend) binds inside this range on
/// Windows so the sandboxed child can reach it. Ten ports leaves
/// headroom for both listeners and for `EADDRINUSE` retries.
/// Overridable via `--proxy-port-range`.
pub const DEFAULT_PROXY_PORT_RANGE: (u16, u16) = (60080, 60089);

/// Sanity cap on `--proxy-port-range` width (`high - low`). The
/// range exists to *narrow* loopback exposure relative to a
/// blanket all-of-127/8 PERMIT; an unbounded range would defeat
/// that.
pub const MAX_PROXY_PORT_RANGE_WIDTH: u16 = 64;

/// Most ports a configured loopback range may hold. The range opens
/// every loopback listener on its ports to the sandbox, so it is kept
/// to what a handful of local servers need.
pub const MAX_LOOPBACK_PORT_RANGE_PORTS: u32 = 512;

/// Lowest port a configured loopback range may start at: the
/// well-known ports below it belong to system services.
pub const MIN_LOOPBACK_PORT: u16 = 1024;

/// Ports a configured loopback range may not include: local services
/// that hand whoever connects to them control of the machine, of
/// another account, or of another process. The TypeScript config
/// validation carries the same list
/// (`WINDOWS_LOOPBACK_SENSITIVE_PORTS`).
pub const SENSITIVE_LOOPBACK_PORTS: [(u16, &str); 8] = [
    (2375, "container engine API"),
    (2376, "container engine API (TLS)"),
    (3389, "remote desktop"),
    (5985, "remote management (HTTP)"),
    (5986, "remote management (HTTPS)"),
    (9222, "browser remote debugging"),
    (9229, "JavaScript runtime inspector"),
    (47001, "remote management (compatibility listener)"),
];

// WFP error codes we treat as benign idempotency outcomes.
const FWP_E_ALREADY_EXISTS: u32 = 0x80320009;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x80320003;
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x80320007;
const FWP_E_IN_USE: u32 = 0x8032000A;
// `FwpmEngineOpen0` / `FwpmFilterCreateEnumHandle0` are admin-gated
// by BFE; non-elevated callers get one of these.
const FWP_E_ACCESS_DENIED: u32 = 0x8032_0028;
const ERROR_ACCESS_DENIED: u32 = 5;

use crate::util::OwnedSd;

/// Typed marker for an admin-gated BFE call returning access-denied.
/// `FwpmFilterCreateEnumHandle0` (and on some configurations
/// `FwpmEngineOpen0`) require elevation; a non-elevated `wfp status`
/// hits this. [`filter_status`] downcasts and degrades to
/// `state:"cannot-read"`; the host's behavioral check is `wfp
/// verify`, not the enum.
#[derive(Debug)]
pub struct WfpAccessDenied {
    pub call: &'static str,
    pub rc: u32,
}
impl std::fmt::Display for WfpAccessDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: 0x{:08x} (BFE filter enumeration is admin-only)",
            self.call, self.rc
        )
    }
}
impl std::error::Error for WfpAccessDenied {}

fn is_bfe_access_denied(rc: u32) -> bool {
    rc == ERROR_ACCESS_DENIED || rc == FWP_E_ACCESS_DENIED
}

// ────────────────────── small RAII helpers ──────────────────────

/// Borrow an `OwnedSd` as the `FWP_BYTE_BLOB` shape WFP wants for
/// provider data. The caller must keep `sd` alive for the duration.
fn sd_byte_blob(sd: &OwnedSd) -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: sd.len,
        data: sd.ptr.0 as *mut u8,
    }
}

/// WFP engine handle; closed on drop.
struct EngineHandle(HANDLE);

impl EngineHandle {
    fn open() -> Result<Self> {
        let mut h = HANDLE::default();
        // RPC_C_AUTHN_DEFAULT
        let rc = unsafe { FwpmEngineOpen0(PCWSTR::null(), 0xFFFF_FFFF, None, None, &mut h) };
        if rc != 0 {
            if is_bfe_access_denied(rc) {
                return Err(anyhow::Error::new(WfpAccessDenied {
                    call: "FwpmEngineOpen0",
                    rc,
                }));
            }
            return Err(anyhow!("FwpmEngineOpen0 failed: 0x{rc:08x}"));
        }
        Ok(Self(h))
    }
    fn h(&self) -> HANDLE {
        self.0
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.0);
            }
        }
    }
}

/// Open the engine, run `f` inside one WFP transaction
/// (`FwpmTransactionBegin0` … `Commit0`). Aborts the transaction if
/// `f` returns an error or panics, then closes the engine. Single
/// owner of the txn-envelope shape so the install/uninstall sites
/// can't drift.
fn with_wfp_txn<T>(f: impl FnOnce(&EngineHandle) -> Result<T>) -> Result<T> {
    let engine = EngineHandle::open()?;
    let rc = unsafe { FwpmTransactionBegin0(engine.h(), 0) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionBegin0: 0x{rc:08x}"));
    }
    // Abort-on-unwind: if `f` panics, this guard's Drop aborts the
    // open txn before EngineHandle's Drop closes the session. On
    // the success path we `forget` it after Commit.
    struct AbortOnDrop(HANDLE);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            unsafe {
                let _ = FwpmTransactionAbort0(self.0);
            }
        }
    }
    let abort = AbortOnDrop(engine.h());
    let out = f(&engine)?;
    let rc = unsafe { FwpmTransactionCommit0(engine.h()) };
    if rc != 0 {
        // `abort` drops → Abort0 (no-op after a failed Commit, but
        // harmless).
        return Err(anyhow!("FwpmTransactionCommit0: 0x{rc:08x}"));
    }
    std::mem::forget(abort);
    Ok(out)
}

// ────────────────────── condition builders ──────────────────────

fn fwp_uint64(slot: &mut u64) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT64,
        Anonymous: FWP_VALUE0_0 {
            uint64: slot as *mut u64,
        },
    }
}

fn cond_sd(field_key: GUID, blob: &mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 { sd: blob as *mut _ },
        },
    }
}

fn cond_v4_subnet(field_key: GUID, am: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v4AddrMask: am as *mut _,
            },
        },
    }
}

fn cond_v6_addr(field_key: GUID, addr: &mut FWP_BYTE_ARRAY16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_ARRAY16_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                byteArray16: addr as *mut _,
            },
        },
    }
}

fn fwp_uint16(v: u16) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT16,
        Anonymous: FWP_VALUE0_0 { uint16: v },
    }
}

fn fwp_uint32(v: u32) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT32,
        Anonymous: FWP_VALUE0_0 { uint32: v },
    }
}

/// The caller must keep `addr` alive (and unmoved) for as long as the
/// returned value is in use.
fn fwp_byte_array16(addr: &mut FWP_BYTE_ARRAY16) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_BYTE_ARRAY16_TYPE,
        Anonymous: FWP_VALUE0_0 {
            byteArray16: addr as *mut _,
        },
    }
}

fn cond_range(field_key: GUID, range: &mut FWP_RANGE0) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_RANGE,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_RANGE_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                rangeValue: range as *mut _,
            },
        },
    }
}

/// The two conditions of a loopback PERMIT at one ALE connect layer:
/// the remote address is loopback (`127.0.0.0/8` or `::1`) AND the
/// remote port is in `range`. Shared by the proxy-range PERMIT and
/// the configured-range PERMIT so the two can only differ in their
/// ports. The caller keeps all three referents alive until the filter
/// is added.
fn loopback_permit_conditions(
    v4: bool,
    v4_loop: &mut FWP_V4_ADDR_AND_MASK,
    v6_loop: &mut FWP_BYTE_ARRAY16,
    range: &mut FWP_RANGE0,
) -> [FWPM_FILTER_CONDITION0; 2] {
    let addr = if v4 {
        cond_v4_subnet(FWPM_CONDITION_IP_REMOTE_ADDRESS, v4_loop)
    } else {
        cond_v6_addr(FWPM_CONDITION_IP_REMOTE_ADDRESS, v6_loop)
    };
    [addr, cond_range(FWPM_CONDITION_IP_REMOTE_PORT, range)]
}

// ────────────────────── filter tagging ──────────────────────

/// JSON payload stored in each filter's `providerData` so we can
/// identify our own filters during enumerate/uninstall without fixed
/// filter GUIDs. The optional `port_range` mirrors the
/// `IP_REMOTE_PORT` range condition on `permit-loopback-user` and
/// `permit-loopback-range` so `wfp status` can report both without
/// unsafe condition-walking.
/// `user_sid` is always set on filters this version writes; legacy
/// installs (the discriminator-group filter set this version
/// supersedes) wrote it as `None`, and [`install_filters`]/
/// [`uninstall_filters`] clean those up too.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct FilterTag {
    /// Discriminator: `"srt-win"`. Anything else means the filter
    /// belongs to some other tool that happens to share our sublayer.
    pub tool: String,
    /// `permit-loopback-user` / `permit-loopback-range` /
    /// `block-user` / `block-anonymous`.
    pub kind: String,
    /// `[low, high]` for the two PERMIT kinds; `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_range: Option<[u16; 2]>,
    /// Sandbox user SID. `None` only on legacy installs that predate
    /// the user-SID-keyed design.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_sid: Option<String>,
    /// [`FENCE_REVISION`] of the build that wrote the filter. `None`
    /// on filters written before the revision was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<u32>,
}

impl FilterTag {
    fn user(kind: &str, sid: &str, range: Option<(u16, u16)>) -> Self {
        Self {
            tool: "srt-win".into(),
            kind: kind.into(),
            port_range: range.map(|(l, h)| [l, h]),
            user_sid: Some(sid.into()),
            rev: Some(FENCE_REVISION),
        }
    }
    fn to_blob_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("FilterTag is always serialisable")
    }
}

/// Tag kind of the PERMIT for the proxy port range. (The name is
/// historical; the filter carries no user condition.)
pub(crate) const KIND_PERMIT_PROXY: &str = "permit-loopback-user";
/// Tag kind of the PERMIT for the configured loopback port range.
pub(crate) const KIND_PERMIT_RANGE: &str = "permit-loopback-range";
pub(crate) const KIND_BLOCK_USER: &str = "block-user";
pub(crate) const KIND_BLOCK_ANONYMOUS: &str = "block-anonymous";

/// What one filter of the set matches and does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterShape {
    /// PERMIT: remote address is loopback AND remote port is in the
    /// range.
    PermitLoopback((u16, u16)),
    /// BLOCK: the token is the sandbox account's.
    BlockUser,
    /// BLOCK: the token is anonymous AND the remote address is not
    /// loopback.
    BlockAnonymous,
}

/// One filter of the set, as added at EACH ALE connect layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FilterSpec {
    pub kind: &'static str,
    pub weight: u64,
    pub shape: FilterShape,
}

impl FilterSpec {
    /// The port range recorded in the filter's tag.
    pub(crate) fn port_range(&self) -> Option<(u16, u16)> {
        match self.shape {
            FilterShape::PermitLoopback(r) => Some(r),
            _ => None,
        }
    }
}

/// The filters [`install_filters`] adds at each ALE connect layer.
/// The configured loopback range adds exactly one PERMIT and changes
/// nothing else.
pub(crate) fn filter_specs(
    proxy_range: (u16, u16),
    loopback_range: Option<(u16, u16)>,
) -> Vec<FilterSpec> {
    let permit = |kind, range| FilterSpec {
        kind,
        weight: W_LOOPBACK,
        shape: FilterShape::PermitLoopback(range),
    };
    let mut specs = vec![permit(KIND_PERMIT_PROXY, proxy_range)];
    if let Some(r) = loopback_range {
        specs.push(permit(KIND_PERMIT_RANGE, r));
    }
    specs.push(FilterSpec {
        kind: KIND_BLOCK_USER,
        weight: W_BLOCK,
        shape: FilterShape::BlockUser,
    });
    specs.push(FilterSpec {
        kind: KIND_BLOCK_ANONYMOUS,
        weight: W_BLOCK,
        shape: FilterShape::BlockAnonymous,
    });
    specs
}

/// Number of filters in the set: 3 per layer × v4/v6, plus one per
/// layer when a loopback port range is configured.
pub fn filter_count(loopback_range: Option<(u16, u16)>) -> usize {
    ALE_LAYERS.len() * filter_specs(DEFAULT_PROXY_PORT_RANGE, loopback_range).len()
}

/// Revision of the filter set this build installs and requires.
/// Bumped whenever the set changes in a way an existing install must
/// pick up by re-running `srt-win install`:
///
///   1. loopback PERMIT + sandbox-user BLOCK (unrecorded — filters of
///      this revision carry no `rev`).
///   2. adds the anonymous BLOCK and the all-packages ACEs on the
///      sandbox-user descriptor.
///   3. may carry the configured loopback-range PERMIT, and records
///      that range (or its absence) beside the revision. A set without
///      the PERMIT has the same filters as revision 2; the number
///      moves so that a build which does not know about the range
///      never accepts a set that may carry one.
///      It is also the first revision at which the anonymous BLOCK's
///      descriptor always carries its integrity label
///      ([`sddl_anonymous`]): a revision-2 set may predate the label,
///      and re-running the install rewrites it.
///
/// Recorded twice: in every filter's tag (what an elevated `wfp
/// status` reads) and in the install record (what the non-elevated
/// broker reads — it cannot enumerate filters).
pub const FENCE_REVISION: u32 = 3;

/// What the install record holds in place of a revision once an
/// uninstall has removed the filters but kept the account. Never a
/// revision a filter set carries.
pub const FENCE_REVISION_REMOVED: u32 = 0;

/// Filter kinds that must be present, at [`FENCE_REVISION`], on each
/// ALE connect layer for the fence to be current.
const REQUIRED_BLOCK_KINDS: [&str; 2] = [KIND_BLOCK_USER, KIND_BLOCK_ANONYMOUS];

/// Name of the residual `srt-win wfp verify` reports when a connect
/// made under a copy of the sandbox token whose user SID is deny-only
/// is not blocked. See the module doc.
pub const RESIDUAL_DENY_ONLY: &str = "deny-only-user-sid";

// Filter weights — kept below 2^60 so they stay in WFP's
// "manual weight" class (top 4 bits are auto-classifier). The
// loopback PERMITs must sit **above** the user-SID BLOCK so the
// sandbox user can still reach the host proxies (and, when one is
// configured, the loopback port range). Module-level so
// [`install_filters`] and the const-asserts in `tests` share one
// source of truth.
pub(crate) const W_LOOPBACK: u64 = 0x0F80_0000_0000_0000;
pub(crate) const W_BLOCK: u64 = 0x0F40_0000_0000_0000;

// ────────────────────── filter enumeration ──────────────────────

const ALE_LAYERS: [(GUID, &str); 2] = [
    (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "ale_auth_connect_v4"),
    (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "ale_auth_connect_v6"),
];

/// Walk every filter at the two ALE connect layers under
/// `sublayer` that carries a parseable `srt-win` providerData tag,
/// invoking `f(layer_name, filterKey, &tag)` for each. Owns the
/// enum-handle and per-batch `FwpmFreeMemory0` lifecycle so callers
/// don't duplicate the unsafe FFI walk.
///
/// Errors are propagated (with the enum handle destroyed first) —
/// don't swallow them: inside `install_filters`' txn, a missed enum
/// error would skip stale-filter cleanup and the fresh set would be
/// added on top, growing the filter count every install.
fn for_each_tagged_filter(
    engine: &EngineHandle,
    sublayer: &GUID,
    mut f: impl FnMut(&'static str, GUID, &FilterTag),
) -> Result<()> {
    for (layer, layer_name) in ALE_LAYERS {
        let mut tmpl = FWPM_FILTER_ENUM_TEMPLATE0::default();
        tmpl.layerKey = layer;
        tmpl.enumType = FWP_FILTER_ENUM_OVERLAPPING;
        tmpl.actionMask = 0xFFFF_FFFF;
        let mut h = HANDLE::default();
        let rc = unsafe { FwpmFilterCreateEnumHandle0(engine.h(), Some(&tmpl), &mut h) };
        if rc != 0 {
            if is_bfe_access_denied(rc) {
                return Err(anyhow::Error::new(WfpAccessDenied {
                    call: "FwpmFilterCreateEnumHandle0",
                    rc,
                }));
            }
            return Err(anyhow!(
                "FwpmFilterCreateEnumHandle0({layer_name}): 0x{rc:08x}"
            ));
        }
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut n: u32 = 0;
            let rc = unsafe { FwpmFilterEnum0(engine.h(), h, 256, &mut entries, &mut n) };
            if rc != 0 {
                unsafe {
                    let _ = FwpmFilterDestroyEnumHandle0(engine.h(), h);
                }
                return Err(anyhow!("FwpmFilterEnum0({layer_name}): 0x{rc:08x}"));
            }
            if n == 0 {
                if !entries.is_null() {
                    unsafe {
                        FwpmFreeMemory0(&mut (entries as *mut c_void));
                    }
                }
                break;
            }
            let slice = unsafe { std::slice::from_raw_parts(entries, n as usize) };
            for &fp in slice {
                if fp.is_null() {
                    continue;
                }
                let flt = unsafe { &*fp };
                if &flt.subLayerKey != sublayer {
                    continue;
                }
                if flt.providerData.size == 0 || flt.providerData.data.is_null() {
                    continue;
                }
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        flt.providerData.data,
                        flt.providerData.size as usize,
                    )
                };
                if let Ok(tag) = serde_json::from_slice::<FilterTag>(bytes)
                    && tag.tool == "srt-win"
                {
                    // `tag` is owned (parsed from bytes); the
                    // `flt`/`bytes` borrows are released before
                    // FwpmFreeMemory0 below, so no FFI lifetime
                    // hazard for the closure.
                    f(layer_name, flt.filterKey, &tag);
                }
            }
            unsafe {
                FwpmFreeMemory0(&mut (entries as *mut c_void));
            }
            if (n as usize) < 256 {
                break;
            }
        }
        unsafe {
            let _ = FwpmFilterDestroyEnumHandle0(engine.h(), h);
        }
    }
    Ok(())
}

/// Delete every srt-win-tagged filter under `sublayer`. Returns the
/// number deleted. Does not delete the sublayer itself.
fn delete_tagged_filters(engine: &EngineHandle, sublayer: &GUID) -> Result<usize> {
    // Collect across both layers, then delete. Deletion is by global
    // filterKey GUID inside one txn, so per-layer ordering is not
    // load-bearing.
    let mut to_delete: Vec<GUID> = Vec::new();
    for_each_tagged_filter(engine, sublayer, |_, key, _| {
        to_delete.push(key);
    })?;
    let mut deleted = 0usize;
    for key in to_delete {
        let rc = unsafe { FwpmFilterDeleteByKey0(engine.h(), &key) };
        if rc == 0 {
            deleted += 1;
        } else if rc != FWP_E_FILTER_NOT_FOUND {
            return Err(anyhow!("FwpmFilterDeleteByKey0({key:?}): 0x{rc:08x}"));
        }
    }
    Ok(deleted)
}

// ────────────────────── install / uninstall ──────────────────────

#[allow(clippy::too_many_arguments)]
fn add_filter(
    engine: HANDLE,
    sublayer: &GUID,
    layer: GUID,
    name: &str,
    weight: u64,
    action: FWP_ACTION_TYPE,
    conditions: &mut [FWPM_FILTER_CONDITION0],
    tag_bytes: &mut [u8],
) -> Result<()> {
    let mut name_w = wstr(name);
    let mut desc_w = wstr("sandbox-runtime WFP filter");
    let mut weight_slot = weight;
    let mut filter = FWPM_FILTER0::default();
    // filterKey left zeroed → WFP assigns a fresh GUID. We identify
    // our filters via providerData, not by fixed key.
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: PWSTR(name_w.as_mut_ptr()),
        description: PWSTR(desc_w.as_mut_ptr()),
    };
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = layer;
    filter.subLayerKey = *sublayer;
    filter.weight = fwp_uint64(&mut weight_slot);
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition = if conditions.is_empty() {
        std::ptr::null_mut()
    } else {
        conditions.as_mut_ptr()
    };
    filter.action = FWPM_ACTION0 {
        r#type: action,
        Anonymous: FWPM_ACTION0_0 {
            filterType: GUID::zeroed(),
        },
    };
    filter.providerData = FWP_BYTE_BLOB {
        size: tag_bytes.len() as u32,
        data: tag_bytes.as_mut_ptr(),
    };
    let rc = unsafe { FwpmFilterAdd0(engine, &filter, None, None) };
    if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
        return Err(anyhow!("FwpmFilterAdd0({name}): 0x{rc:08x}"));
    }
    Ok(())
}

// SDDL builder for the `ALE_USER_ID` security descriptor.
//
// Carries `O:LS G:LS` (owner + primary group = LocalService).
// WFP's kernel-side ALE_USER_ID match doesn't require the primary
// group to be set, but user-mode `AccessCheck` — which
// `tests/sd_access_check_matrix.rs` uses to prove this SD does
// what we claim — returns ERROR_INVALID_SECURITY_DESCR for an SD
// with no `G:`. The group's value is irrelevant to DACL
// evaluation; LS is just a stable, always-present principal.

/// SDDL for the sandbox-user BLOCK filter — ALLOW `<sandbox_user_sid>`
/// plus ALLOW for ALL APPLICATION PACKAGES (`S-1-15-2-1`) and ALL
/// RESTRICTED APPLICATION PACKAGES (`S-1-15-2-2`).
///
/// The user ACE matches iff the connecting token carries that SID
/// **enabled**, which for a *user* SID means "is that user". The
/// broker, services, and every other process carry a different user
/// SID → no match → fall through to default-permit.
///
/// The two package ACEs exist for AppContainer tokens. The access
/// check of such a token has two halves that must BOTH grant: the
/// ordinary one over the user and group SIDs, and one over the
/// package and capability SIDs. With the user ACE alone, an
/// AppContainer process started under the sandbox account passes the
/// first half and fails the second, so the BLOCK would not match it.
/// The package ACEs supply the second half. They grant nothing by
/// themselves: a token outside an AppContainer does not carry either
/// SID, and an AppContainer token of any OTHER user still fails the
/// first half.
///
/// Unlike [`sddl_anonymous`] this descriptor carries no mandatory
/// label: a process of the sandbox account runs at medium integrity,
/// the level an unlabelled descriptor is given. A copy of its token
/// with the integrity level lowered is below that level; whether the
/// BLOCK still matches it is measured by the fence probe
/// ([`crate::probe`]), which requires it to.
pub fn sddl_sandbox_user(sid: &str) -> String {
    format!("O:LSG:LSD:(A;;CC;;;{sid})(A;;CC;;;S-1-15-2-1)(A;;CC;;;S-1-15-2-2)")
}

/// SDDL for the anonymous BLOCK filter — ALLOW `ANONYMOUS LOGON`
/// (`S-1-5-7`). Matches the anonymous token and nothing else: no
/// other token carries that SID.
///
/// The descriptor carries no mandatory label. The anonymous token's
/// integrity level is untrusted, below the medium level an
/// unlabelled descriptor is given, so whether this ACE is reached
/// depends on how the engine's own access check treats the match
/// right for a lower-integrity token. This crate cannot read that
/// from the descriptor; the fence probe measures it on every verify
/// by connecting under the anonymous token.
pub fn sddl_anonymous() -> String {
    "O:LSG:LSD:(A;;CC;;;S-1-5-7)".to_string()
}

// "Not loopback" for the anonymous BLOCK.
//
// The engine offers three ways to say it, and only one fits:
//
//   - A negative match on the address (`FWP_MATCH_NOT_EQUAL`) is
//     defined for sortable value types only. The loopback v4 prefix is
//     an address-and-mask value, which is not sortable, so `!= 127/8`
//     cannot be written.
//   - The loopback FLAG (`FWP_CONDITION_FLAG_IS_LOOPBACK`, none-set)
//     is true for every connect that stays on the machine, including
//     one to the machine's own LAN address. That is a wider exemption
//     than "the loopback addresses", and it would leave nothing on
//     the machine that could show the filter working: every
//     off-loopback destination a readiness probe can reach without an
//     external host is one of the machine's own addresses.
//   - A RANGE match on the address is a positive match over a sortable
//     type (a v4 address is a `UINT32`, a v6 address a 16-byte array),
//     and conditions on the same field are OR'ed. The complement of
//     loopback is two ranges per family — below it and above it.
//
// So the filter carries two `IP_REMOTE_ADDRESS` range conditions per
// layer. They are disjoint from the loopback PERMIT's destinations by
// construction, and the PERMIT and the sandbox-user BLOCK are added
// exactly as before, so loopback handling for the sandbox account is
// unchanged.

/// The IPv4 addresses outside `127.0.0.0/8`, as inclusive
/// host-byte-order ranges.
pub(crate) const fn non_loopback_v4_ranges() -> [(u32, u32); 2] {
    [(0x0000_0000, 0x7EFF_FFFF), (0x8000_0000, 0xFFFF_FFFF)]
}

/// The IPv6 addresses other than `::1`, as inclusive network-order
/// ranges.
pub(crate) const fn non_loopback_v6_ranges() -> [([u8; 16], [u8; 16]); 2] {
    let zero = [0u8; 16];
    let mut two = [0u8; 16];
    two[15] = 2;
    [(zero, zero), (two, [0xFF; 16])]
}

/// Install (or refresh) the filter set under `sublayer`:
/// [`filter_specs`] at each of the v4/v6 ALE-connect layers
/// ([`filter_count`] total) — see the module doc for the design.
///
/// Idempotent: any existing srt-win-tagged filters under `sublayer`
/// — including legacy discriminator-group-keyed filters from a
/// pre-separate-user install, and a loopback-range PERMIT for a range
/// that is no longer configured — are deleted first, then a fresh set
/// is added, all inside one WFP transaction.
pub fn install_filters(
    sublayer: &GUID,
    sandbox_user_sid: &str,
    port_range: (u16, u16),
    loopback_range: Option<(u16, u16)>,
) -> Result<()> {
    debug_assert!(port_range.0 <= port_range.1);
    debug_assert!(loopback_range.is_none_or(|(lo, hi)| lo <= hi));
    let specs = filter_specs(port_range, loopback_range);
    let sd_user = OwnedSd::from_sddl(&sddl_sandbox_user(sandbox_user_sid))
        .context("build sandbox-user SD")?;
    let sd_anon = OwnedSd::from_sddl(&sddl_anonymous()).context("build anonymous SD")?;

    with_wfp_txn(|engine| {
        // Sublayer (idempotent). Display name identifies the owning
        // tool, not the user.
        let mut sl_name = wstr("srt-win");
        let mut sl_desc = wstr("sandbox-runtime WFP sublayer (sandbox-user fence)");
        let sl = FWPM_SUBLAYER0 {
            subLayerKey: *sublayer,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(sl_name.as_mut_ptr()),
                description: PWSTR(sl_desc.as_mut_ptr()),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: std::ptr::null_mut(),
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            weight: 0x8000,
        };
        let rc = unsafe { FwpmSubLayerAdd0(engine.h(), &sl, None) };
        if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
            return Err(anyhow!("FwpmSubLayerAdd0: 0x{rc:08x}"));
        }

        // Idempotency + migration: drop EVERY stale srt-win filter
        // (both this version's user-keyed shape and any legacy
        // group-keyed filters from a prior install) before
        // re-adding. Inside the transaction so a crash leaves the
        // previous state intact.
        delete_tagged_filters(engine, sublayer)?;

        let mut sd_user_blob = sd_byte_blob(&sd_user);
        let mut v4_loop = FWP_V4_ADDR_AND_MASK {
            addr: 0x7F00_0000,
            mask: 0xFF00_0000,
        };
        let mut v6_loop = FWP_BYTE_ARRAY16 {
            byteArray16: [0; 16],
        };
        v6_loop.byteArray16[15] = 1;

        // Range endpoints for the anonymous BLOCK. The v6 endpoints
        // are passed by pointer, so they live here, outside the loop,
        // for the whole transaction.
        let mut sd_anon_blob = sd_byte_blob(&sd_anon);
        let mut v4_out = non_loopback_v4_ranges().map(|(lo, hi)| FWP_RANGE0 {
            valueLow: fwp_uint32(lo),
            valueHigh: fwp_uint32(hi),
        });
        let mut v6_ends = non_loopback_v6_ranges().map(|(lo, hi)| {
            (
                FWP_BYTE_ARRAY16 { byteArray16: lo },
                FWP_BYTE_ARRAY16 { byteArray16: hi },
            )
        });
        let [(a_lo, a_hi), (b_lo, b_hi)] = &mut v6_ends;
        let mut v6_out = [
            FWP_RANGE0 {
                valueLow: fwp_byte_array16(a_lo),
                valueHigh: fwp_byte_array16(a_hi),
            },
            FWP_RANGE0 {
                valueLow: fwp_byte_array16(b_lo),
                valueHigh: fwp_byte_array16(b_hi),
            },
        ];

        for (layer, label) in [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "v4"),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "v6"),
        ] {
            let v4 = label == "v4";
            for spec in &specs {
                let name = format!("srt-win-{label}-{}", spec.kind);
                let mut tag =
                    FilterTag::user(spec.kind, sandbox_user_sid, spec.port_range()).to_blob_bytes();
                match spec.shape {
                    // PERMIT loopback ∩ port-range (no user
                    // condition).
                    FilterShape::PermitLoopback((lo, hi)) => {
                        let mut ports = FWP_RANGE0 {
                            valueLow: fwp_uint16(lo),
                            valueHigh: fwp_uint16(hi),
                        };
                        let mut c =
                            loopback_permit_conditions(v4, &mut v4_loop, &mut v6_loop, &mut ports);
                        add_filter(
                            engine.h(),
                            sublayer,
                            layer,
                            &name,
                            spec.weight,
                            FWP_ACTION_PERMIT,
                            &mut c,
                            &mut tag,
                        )?;
                    }
                    FilterShape::BlockUser => {
                        let mut c = [cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_user_blob)];
                        add_filter(
                            engine.h(),
                            sublayer,
                            layer,
                            &name,
                            spec.weight,
                            FWP_ACTION_BLOCK,
                            &mut c,
                            &mut tag,
                        )?;
                    }
                    // The two address ranges share a field key and
                    // are therefore OR'ed with each other, then
                    // AND'ed with the user condition.
                    FilterShape::BlockAnonymous => {
                        let [out_a, out_b] = if v4 { &mut v4_out } else { &mut v6_out };
                        let mut c = [
                            cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_anon_blob),
                            cond_range(FWPM_CONDITION_IP_REMOTE_ADDRESS, out_a),
                            cond_range(FWPM_CONDITION_IP_REMOTE_ADDRESS, out_b),
                        ];
                        add_filter(
                            engine.h(),
                            sublayer,
                            layer,
                            &name,
                            spec.weight,
                            FWP_ACTION_BLOCK,
                            &mut c,
                            &mut tag,
                        )?;
                    }
                }
            }
        }
        Ok(())
    })
}

/// Remove every srt-win-tagged filter under `sublayer`, then attempt
/// to delete the sublayer itself (best-effort; `FWP_E_IN_USE` means
/// foreign filters are still under it).
pub fn uninstall_filters(sublayer: &GUID) -> Result<usize> {
    with_wfp_txn(|engine| {
        let n = delete_tagged_filters(engine, sublayer)?;
        let rc = unsafe { FwpmSubLayerDeleteByKey0(engine.h(), sublayer) };
        if rc != 0
            && rc != FWP_E_SUBLAYER_NOT_FOUND
            && rc != FWP_E_FILTER_NOT_FOUND
            && rc != FWP_E_IN_USE
        {
            return Err(anyhow!("FwpmSubLayerDeleteByKey0: 0x{rc:08x}"));
        }
        Ok(n)
    })
}

/// Status of the WFP fence under `sublayer` — see
/// [`classify_fence`] for `absent` / `installed` / `outdated`.
/// `port_range` is read from the first `permit-loopback-user` tag,
/// `loopback_port_range` from the first `permit-loopback-range` tag
/// (`null` when the set carries none).
///
/// `cannot-read` is the graceful-degrade state when BFE
/// enumeration is admin-gated ([`WfpAccessDenied`]). The
/// non-elevated readiness check is `srt-win wfp verify` (a
/// behavioral probe — spawns the runner as the sandbox user and
/// expects WSAEACCES on a direct connect), not this enum.
#[derive(Debug, Serialize)]
pub struct WfpStatus {
    pub state: &'static str,
    pub filters: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_range: Option<[u16; 2]>,
    /// The configured loopback port range the installed set opens, or
    /// `null` for none. Read off the filters by an elevated caller;
    /// a non-elevated one (`cannot-read`) gets the install record's.
    pub loopback_port_range: Option<[u16; 2]>,
    /// Sandbox-user SID read from the first user-keyed tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_sid: Option<String>,
    /// Populated on `cannot-read` and on `outdated`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// What to tell the operator when the fence is not at
/// [`FENCE_REVISION`]. One wording for `wfp status`, `wfp verify`
/// and `exec`.
pub fn outdated_hint(have: Option<u32>) -> String {
    if have == Some(FENCE_REVISION_REMOVED) {
        return "the network fence on this machine is not installed (its \
                filters were removed by an uninstall) — re-run `srt-win \
                install` (one UAC prompt)"
            .to_string();
    }
    // What the installed revision is missing.
    let gained = match have {
        Some(r) if r >= 2 => "which records the loopback port range the filters open",
        _ => "which also blocks connects made while impersonating the anonymous token",
    };
    let have = match have {
        Some(r) => format!("revision {r}"),
        None => "an unrecorded earlier revision".to_string(),
    };
    format!(
        "the network fence on this machine is out of date ({have}; \
         this build requires revision {FENCE_REVISION}, {gained}) — \
         re-run `srt-win install` (one UAC prompt)"
    )
}

/// `LOW-HIGH`, or `none`.
pub fn fmt_loopback_range(r: Option<(u16, u16)>) -> String {
    match r {
        Some((lo, hi)) => format!("{lo}-{hi}"),
        None => "none".to_string(),
    }
}

/// What to tell the operator when the loopback port range the session
/// is configured with is not the one the installed filter set opens.
/// One wording for `wfp status`, `wfp verify` and `exec`. Names the
/// install command that makes the machine match the session.
pub fn loopback_range_hint(
    installed: Option<(u16, u16)>,
    configured: Option<(u16, u16)>,
) -> String {
    let flag = match configured {
        Some((lo, hi)) => format!(" --loopback-port-range {lo}-{hi}"),
        None => String::new(),
    };
    format!(
        "the network fence on this machine does not match this \
         session's loopback port range (installed: {}; configured: \
         {}) — re-run `srt-win install{flag} --force` (one UAC prompt)",
        fmt_loopback_range(installed),
        fmt_loopback_range(configured),
    )
}

/// What to tell the operator when the install record and the session
/// agree on a loopback port range but a connect to a listener inside
/// it was blocked: the filters in place are not the ones recorded.
pub fn loopback_range_closed_hint(configured: (u16, u16)) -> String {
    format!(
        "the network fence on this machine does not open the \
         configured loopback port range {}-{} (a connect to a loopback \
         listener inside it was blocked) — re-run `srt-win install \
         --loopback-port-range {}-{} --force` (one UAC prompt)",
        configured.0, configured.1, configured.0, configured.1,
    )
}

/// Classify an enumerated filter set, given `(layer, tag)` for every
/// srt-win filter under the sublayer.
///
///   - `absent` — no `block-user` filter at all.
///   - `installed` — every [`REQUIRED_BLOCK_KINDS`] filter is present
///     at [`FENCE_REVISION`] on BOTH ALE connect layers.
///   - `outdated` — anything in between: a set written by an earlier
///     build (no `rev`, no anonymous BLOCK), or one missing a layer.
///     Also a set whose loopback-range PERMITs do not form one range:
///     present on one layer only, written at another revision, or
///     disagreeing about the ports.
///
/// Extra filters are ignored, so enterprise tooling that adds its own
/// under the same sublayer does not break detection.
pub(crate) fn classify_fence(tags: &[(&str, FilterTag)]) -> &'static str {
    if !tags.iter().any(|(_, t)| t.kind == "block-user") {
        return "absent";
    }
    let current = ALE_LAYERS.iter().all(|(_, layer)| {
        REQUIRED_BLOCK_KINDS.iter().all(|kind| {
            tags.iter()
                .any(|(l, t)| l == layer && t.kind == *kind && t.rev == Some(FENCE_REVISION))
        })
    });
    let ranges: Vec<&(&str, FilterTag)> = tags
        .iter()
        .filter(|(_, t)| t.kind == KIND_PERMIT_RANGE)
        .collect();
    let range_whole = ranges.is_empty()
        || (ranges[0].1.port_range.is_some()
            && ranges.iter().all(|(_, t)| {
                t.rev == Some(FENCE_REVISION) && t.port_range == ranges[0].1.port_range
            })
            && ALE_LAYERS
                .iter()
                .all(|(_, layer)| ranges.iter().any(|(l, _)| l == layer)));
    if current && range_whole {
        "installed"
    } else {
        "outdated"
    }
}

/// Fold the install record's loopback port range into an enumerated
/// status. `recorded` is `None` when the machine has no install
/// record, `Some(range)` when it has one.
///
/// A non-elevated caller (`cannot-read`) has only the record, so it
/// reports the record's range. An elevated caller that enumerated an
/// `installed` set whose range differs from the record's reports
/// `outdated`: the non-elevated broker would otherwise hold sessions
/// to a range the filters do not have.
pub fn apply_recorded_loopback_range(
    mut st: WfpStatus,
    recorded: Option<Option<(u16, u16)>>,
) -> WfpStatus {
    let Some(recorded) = recorded else {
        return st;
    };
    let as_tag = recorded.map(|(lo, hi)| [lo, hi]);
    match st.state {
        "cannot-read" => st.loopback_port_range = as_tag,
        "installed" if st.loopback_port_range != as_tag => {
            st.state = "outdated";
            st.hint = Some(format!(
                "the filters open loopback port range {} but the \
                 install record says {} — re-run `srt-win install` \
                 (one UAC prompt)",
                fmt_loopback_range(st.loopback_port_range.map(|[lo, hi]| (lo, hi))),
                fmt_loopback_range(recorded),
            ));
        }
        _ => {}
    }
    st
}

/// Fold the install record's fence revision into an enumerated
/// status. `record` is `None` when the machine has no install record
/// at all, `Some(rev)` when it has one (`rev` itself is `None` for a
/// record written before the revision was kept).
///
/// A non-elevated caller cannot enumerate filters (`cannot-read`), so
/// the record is its only way to learn that the install predates this
/// build (`outdated`) or that an uninstall removed the filters
/// (`absent`); and an elevated caller that enumerated a
/// current-looking set under one sublayer still must not report
/// `installed` while the record says otherwise (`outdated`). Only a
/// record at [`FENCE_REVISION`] leaves `installed` or `cannot-read`
/// standing.
pub fn apply_recorded_revision(mut st: WfpStatus, record: Option<Option<u32>>) -> WfpStatus {
    if let Some(rev) = record
        && rev != Some(FENCE_REVISION)
        && matches!(st.state, "installed" | "cannot-read")
    {
        let removed = rev == Some(FENCE_REVISION_REMOVED);
        st.state = if removed && st.state == "cannot-read" {
            "absent"
        } else {
            "outdated"
        };
        st.hint = Some(outdated_hint(rev));
    }
    st
}

/// Live BFE enumeration. Admin-gated — a non-elevated caller gets
/// `state:"cannot-read"` (not an error) so `wfp status` exits 0
/// with a hint pointing at `wfp verify`. Elevated callers
/// (`install`'s early-return, the smoke scripts) get the real
/// per-filter counts.
pub fn filter_status(sublayer: &GUID) -> Result<WfpStatus> {
    let engine = match EngineHandle::open() {
        Ok(e) => e,
        Err(e) if e.downcast_ref::<WfpAccessDenied>().is_some() => {
            return Ok(cannot_read(e));
        }
        Err(e) => return Err(e),
    };
    let mut tags: Vec<(&'static str, FilterTag)> = Vec::new();
    let mut port_range: Option<[u16; 2]> = None;
    let mut loopback_port_range: Option<[u16; 2]> = None;
    let mut user_sid: Option<String> = None;
    let enum_result = for_each_tagged_filter(&engine, sublayer, |layer, _, tag| {
        if user_sid.is_none() {
            user_sid.clone_from(&tag.user_sid);
        }
        if tag.kind == KIND_PERMIT_PROXY {
            port_range = tag.port_range;
        }
        if tag.kind == KIND_PERMIT_RANGE && loopback_port_range.is_none() {
            loopback_port_range = tag.port_range;
        }
        tags.push((layer, tag.clone()));
    });
    if let Err(e) = enum_result {
        if e.downcast_ref::<WfpAccessDenied>().is_some() {
            return Ok(cannot_read(e));
        }
        return Err(e);
    }
    let state = classify_fence(&tags);
    Ok(WfpStatus {
        state,
        filters: tags.len(),
        port_range,
        loopback_port_range,
        user_sid,
        hint: (state == "outdated").then(|| {
            // The oldest revision present is the one worth naming.
            outdated_hint(tags.iter().map(|(_, t)| t.rev).min().flatten())
        }),
    })
}

fn cannot_read(e: anyhow::Error) -> WfpStatus {
    WfpStatus {
        state: "cannot-read",
        filters: 0,
        port_range: None,
        loopback_port_range: None,
        user_sid: None,
        hint: Some(format!(
            "{e}; elevation required for filter enum — run `srt-win \
             wfp verify` for a behavioral check"
        )),
    }
}

/// Parse a `--proxy-port-range LOW-HIGH` argument. Both ends are
/// inclusive. Validates `low <= high` and width `<=
/// MAX_PROXY_PORT_RANGE_WIDTH`.
pub fn parse_port_range(s: &str) -> Result<(u16, u16)> {
    let (lo, hi) = parse_low_high(s)?;
    if lo == 0 {
        // Port 0 is "any" at bind time and never appears as a
        // remote port, so it's a dead slot in the range.
        return Err(anyhow!("low port must be >= 1"));
    }
    if lo > hi {
        return Err(anyhow!("low ({lo}) > high ({hi})"));
    }
    if hi - lo > MAX_PROXY_PORT_RANGE_WIDTH {
        return Err(anyhow!(
            "range too wide ({} ports); max width {}",
            hi - lo + 1,
            MAX_PROXY_PORT_RANGE_WIDTH + 1
        ));
    }
    Ok((lo, hi))
}

/// Check a configured loopback port range (both ends inclusive):
///
///   - `low <= high`;
///   - at most [`MAX_LOOPBACK_PORT_RANGE_PORTS`] ports;
///   - `low >=` [`MIN_LOOPBACK_PORT`];
///   - no port in common with `proxy_range` (the proxy PERMIT already
///     covers those, and the fence probe relies on telling the two
///     apart) — skipped when the caller does not know the proxy range;
///   - no port of [`SENSITIVE_LOOPBACK_PORTS`].
pub fn validate_loopback_port_range(
    (lo, hi): (u16, u16),
    proxy_range: Option<(u16, u16)>,
) -> Result<()> {
    if lo > hi {
        return Err(anyhow!("low ({lo}) > high ({hi})"));
    }
    let ports = u32::from(hi - lo) + 1;
    if ports > MAX_LOOPBACK_PORT_RANGE_PORTS {
        return Err(anyhow!(
            "range too wide ({ports} ports); at most {MAX_LOOPBACK_PORT_RANGE_PORTS}"
        ));
    }
    if lo < MIN_LOOPBACK_PORT {
        return Err(anyhow!("low port must be >= {MIN_LOOPBACK_PORT}"));
    }
    if let Some((plo, phi)) = proxy_range
        && lo <= phi
        && plo <= hi
    {
        return Err(anyhow!("range overlaps the proxy port range {plo}-{phi}"));
    }
    if let Some((port, what)) = SENSITIVE_LOOPBACK_PORTS
        .iter()
        .find(|(p, _)| (lo..=hi).contains(p))
    {
        return Err(anyhow!(
            "range includes port {port} ({what}), which must not be \
             reachable from the sandbox"
        ));
    }
    Ok(())
}

/// Parse and validate a `--loopback-port-range LOW-HIGH` argument —
/// see [`validate_loopback_port_range`].
pub fn parse_loopback_port_range(s: &str, proxy_range: Option<(u16, u16)>) -> Result<(u16, u16)> {
    let range = parse_low_high(s)?;
    validate_loopback_port_range(range, proxy_range)?;
    Ok(range)
}

/// Split `LOW-HIGH` into two ports. No range rules.
fn parse_low_high(s: &str) -> Result<(u16, u16)> {
    let (lo_s, hi_s) = s
        .split_once('-')
        .ok_or_else(|| anyhow!("expected LOW-HIGH (e.g. 60080-60089)"))?;
    let lo: u16 = lo_s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid low port '{lo_s}'"))?;
    let hi: u16 = hi_s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid high port '{hi_s}'"))?;
    Ok((lo, hi))
}

/// Parse a `--sublayer-guid` argument. Accepts braced or unbraced
/// canonical form. `GUID::try_from` only takes the unbraced form and
/// returns an unhelpful error on failure, so strip braces and
/// pre-validate the shape for a friendlier message.
pub fn parse_guid(s: &str) -> Result<GUID> {
    let t = s.trim().trim_start_matches('{').trim_end_matches('}');
    // 8-4-4-4-12 hex with hyphens, exactly 36 chars.
    let ok = t.len() == 36
        && t.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    if !ok {
        return Err(anyhow!(
            "invalid GUID '{s}': expected xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        ));
    }
    GUID::try_from(t).map_err(|e| anyhow!("invalid GUID '{s}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SDDL template used by `install_filters` must parse for a
    /// representative SID. Catches template typos without needing a
    /// live WFP engine.
    #[test]
    fn sddl_template_parses() {
        let sd = OwnedSd::from_sddl(&sddl_sandbox_user("S-1-5-32-545")).expect("sddl");
        assert!(!sd.ptr.0.is_null());
        assert!(sd.len > 0);
    }

    #[test]
    fn anonymous_sddl_parses() {
        let sd = OwnedSd::from_sddl(&sddl_anonymous()).expect("sddl");
        assert!(sd.len > 0);
    }

    #[test]
    fn anonymous_sddl_grants_anonymous_logon_only() {
        let s = sddl_anonymous();
        assert!(s.contains("D:(A;;CC;;;S-1-5-7)"));
        assert!(!s.contains("S:("));
        assert!(!s.contains("(D;"));
    }

    #[test]
    fn sandbox_user_sddl_carries_both_package_aces() {
        let s = sddl_sandbox_user("S-1-5-21-1-2-3-1005");
        assert!(s.contains("(A;;CC;;;S-1-5-21-1-2-3-1005)"));
        assert!(s.contains("(A;;CC;;;S-1-15-2-1)"));
        assert!(s.contains("(A;;CC;;;S-1-15-2-2)"));
        // ALLOW only: a DENY ACE in a match descriptor would invert
        // which tokens the filter applies to.
        assert!(!s.contains("(D;"));
    }

    fn in_v4(a: [u8; 4]) -> bool {
        let v = u32::from_be_bytes(a);
        non_loopback_v4_ranges()
            .iter()
            .any(|(lo, hi)| (*lo..=*hi).contains(&v))
    }

    fn in_v6(a: std::net::Ipv6Addr) -> bool {
        let v = a.octets();
        non_loopback_v6_ranges()
            .iter()
            .any(|(lo, hi)| *lo <= v && v <= *hi)
    }

    /// The anonymous BLOCK's address ranges are exactly the
    /// complement of the loopback PERMIT's destinations.
    #[test]
    fn non_loopback_ranges_exclude_only_loopback() {
        for a in [
            [127, 0, 0, 0],
            [127, 0, 0, 1],
            [127, 0, 0, 2],
            [127, 255, 255, 255],
        ] {
            assert!(!in_v4(a), "{a:?} is loopback");
        }
        for a in [
            [0, 0, 0, 0],
            [10, 0, 0, 1],
            [126, 255, 255, 255],
            [128, 0, 0, 0],
            [169, 254, 169, 254],
            [192, 168, 1, 1],
            [255, 255, 255, 255],
        ] {
            assert!(in_v4(a), "{a:?} is not loopback");
        }
        let [(_, a_hi), (b_lo, _)] = non_loopback_v4_ranges();
        assert_eq!(a_hi + 1, 0x7F00_0000);
        assert_eq!(b_lo - 1, 0x7FFF_FFFF);

        assert!(!in_v6(std::net::Ipv6Addr::LOCALHOST));
        for a in ["::", "::2", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1"] {
            assert!(in_v6(a.parse().unwrap()), "{a} is not ::1");
        }
        assert!(in_v6(std::net::Ipv6Addr::from([0xFF; 16])));
    }

    fn tag(kind: &str, rev: Option<u32>) -> FilterTag {
        FilterTag {
            rev,
            ..FilterTag::user(kind, "S-1-5-21-1-2-3-1005", None)
        }
    }

    fn full_set(rev: Option<u32>, kinds: &[&str]) -> Vec<(&'static str, FilterTag)> {
        ALE_LAYERS
            .iter()
            .flat_map(|(_, layer)| kinds.iter().map(move |k| (*layer, tag(k, rev))))
            .collect()
    }

    const ALL_KINDS: [&str; 3] = ["permit-loopback-user", "block-user", "block-anonymous"];

    fn range_tag(range: [u16; 2], rev: Option<u32>) -> FilterTag {
        FilterTag {
            port_range: Some(range),
            ..tag(KIND_PERMIT_RANGE, rev)
        }
    }

    /// A current set plus a loopback-range PERMIT on both layers.
    fn set_with_range(range: [u16; 2]) -> Vec<(&'static str, FilterTag)> {
        let mut set = full_set(Some(FENCE_REVISION), &ALL_KINDS);
        for (_, layer) in ALE_LAYERS {
            set.push((layer, range_tag(range, Some(FENCE_REVISION))));
        }
        set
    }

    #[test]
    fn filter_list_without_a_range_is_the_three_filter_set() {
        let specs = filter_specs((60080, 60089), None);
        assert_eq!(
            specs.iter().map(|s| s.kind).collect::<Vec<_>>(),
            ["permit-loopback-user", "block-user", "block-anonymous"]
        );
        assert_eq!(specs[0].shape, FilterShape::PermitLoopback((60080, 60089)));
        assert_eq!(specs[0].port_range(), Some((60080, 60089)));
        assert_eq!(specs[1].shape, FilterShape::BlockUser);
        assert_eq!(specs[2].shape, FilterShape::BlockAnonymous);
        assert_eq!(specs[1].port_range(), None);
        assert_eq!(filter_count(None), 6);
    }

    #[test]
    fn filter_list_with_a_range_adds_exactly_one_permit() {
        let without = filter_specs((60080, 60089), None);
        let with = filter_specs((60080, 60089), Some((3000, 3099)));
        assert_eq!(
            with.iter().map(|s| s.kind).collect::<Vec<_>>(),
            [
                "permit-loopback-user",
                "permit-loopback-range",
                "block-user",
                "block-anonymous"
            ]
        );
        assert_eq!(filter_count(Some((3000, 3099))), 8);
        // The added filter is a loopback PERMIT over the configured
        // ports, at the weight of the proxy PERMIT: above the BLOCKs.
        let added = with[1];
        assert_eq!(added.shape, FilterShape::PermitLoopback((3000, 3099)));
        assert_eq!(added.weight, W_LOOPBACK);
        assert!(added.weight > W_BLOCK);
        // Everything else is the set without a range, unchanged.
        let rest: Vec<FilterSpec> = with
            .iter()
            .copied()
            .filter(|s| s.kind != KIND_PERMIT_RANGE)
            .collect();
        assert_eq!(rest, without);
        // Only PERMITs carry ports, and only loopback PERMITs exist.
        for s in &with {
            assert_eq!(
                s.port_range().is_some(),
                matches!(s.shape, FilterShape::PermitLoopback(_))
            );
        }
    }

    #[test]
    fn classify_fence_with_a_loopback_range() {
        assert_eq!(classify_fence(&set_with_range([3000, 3099])), "installed");
        // On one layer only.
        let mut half = set_with_range([3000, 3099]);
        let v6 = ALE_LAYERS[1].1;
        half.retain(|(l, t)| !(*l == v6 && t.kind == KIND_PERMIT_RANGE));
        assert_eq!(classify_fence(&half), "outdated");
        // The two layers disagree about the ports.
        let mut split = full_set(Some(FENCE_REVISION), &ALL_KINDS);
        split.push((
            ALE_LAYERS[0].1,
            range_tag([3000, 3099], Some(FENCE_REVISION)),
        ));
        split.push((
            ALE_LAYERS[1].1,
            range_tag([3000, 3100], Some(FENCE_REVISION)),
        ));
        assert_eq!(classify_fence(&split), "outdated");
        // Written at another revision.
        let mut old = full_set(Some(FENCE_REVISION), &ALL_KINDS);
        for (_, layer) in ALE_LAYERS {
            old.push((layer, range_tag([3000, 3099], Some(FENCE_REVISION - 1))));
        }
        assert_eq!(classify_fence(&old), "outdated");
        // A range PERMIT without its ports recorded.
        let mut bare = full_set(Some(FENCE_REVISION), &ALL_KINDS);
        for (_, layer) in ALE_LAYERS {
            bare.push((layer, tag(KIND_PERMIT_RANGE, Some(FENCE_REVISION))));
        }
        assert_eq!(classify_fence(&bare), "outdated");
        // PERMITs alone fence nothing.
        let only: Vec<_> = set_with_range([3000, 3099])
            .into_iter()
            .filter(|(_, t)| t.kind.starts_with("permit"))
            .collect();
        assert_eq!(classify_fence(&only), "absent");
    }

    #[test]
    fn recorded_loopback_range_is_reported_and_compared() {
        let with = |state, range| WfpStatus {
            loopback_port_range: range,
            ..status(state)
        };
        // Non-elevated: the record's range is what gets reported.
        let st = apply_recorded_loopback_range(with("cannot-read", None), Some(Some((3000, 3099))));
        assert_eq!(st.state, "cannot-read");
        assert_eq!(st.loopback_port_range, Some([3000, 3099]));
        // Elevated, filters and record agree.
        for (tags, rec) in [(None, None), (Some([3000, 3099]), Some((3000, 3099)))] {
            let st = apply_recorded_loopback_range(with("installed", tags), Some(rec));
            assert_eq!(st.state, "installed");
            assert_eq!(st.loopback_port_range, tags);
        }
        // Elevated, they disagree — either way round, or on the ports.
        for (tags, rec) in [
            (Some([3000, 3099]), None),
            (None, Some((3000, 3099))),
            (Some([3000, 3099]), Some((3000, 3098))),
        ] {
            let st = apply_recorded_loopback_range(with("installed", tags), Some(rec));
            assert_eq!(st.state, "outdated", "{tags:?} vs {rec:?}");
            assert!(st.hint.unwrap().contains("srt-win install"));
        }
        // No install record, or nothing installed: left alone.
        let st = apply_recorded_loopback_range(with("installed", Some([3000, 3099])), None);
        assert_eq!(st.state, "installed");
        for s in ["absent", "outdated"] {
            let st = apply_recorded_loopback_range(with(s, None), Some(Some((3000, 3099))));
            assert_eq!(st.state, s);
            assert_eq!(st.loopback_port_range, None);
        }
    }

    #[test]
    fn loopback_range_hints_name_the_install_command() {
        let h = loopback_range_hint(None, Some((3000, 3099)));
        assert!(h.contains("installed: none"));
        assert!(h.contains("configured: 3000-3099"));
        assert!(h.contains("srt-win install --loopback-port-range 3000-3099 --force"));
        let h = loopback_range_hint(Some((3000, 3099)), None);
        assert!(h.contains("installed: 3000-3099"));
        assert!(h.contains("configured: none"));
        assert!(h.contains("srt-win install --force"));
        assert!(loopback_range_closed_hint((3000, 3099)).contains("srt-win install"));
    }

    #[test]
    fn outdated_hint_says_what_each_revision_lacks() {
        assert!(outdated_hint(None).contains("anonymous"));
        assert!(outdated_hint(Some(1)).contains("anonymous"));
        let h = outdated_hint(Some(2));
        assert!(h.contains("revision 2") && h.contains("loopback port range"));
        assert!(!h.contains("anonymous"));
    }

    const PROXY: Option<(u16, u16)> = Some(DEFAULT_PROXY_PORT_RANGE);

    #[test]
    fn loopback_port_range_ok() {
        assert_eq!(
            parse_loopback_port_range("3000-3099", PROXY).unwrap(),
            (3000, 3099)
        );
        // One port; the lowest allowed start; exactly the cap.
        assert_eq!(
            parse_loopback_port_range("8080-8080", PROXY).unwrap(),
            (8080, 8080)
        );
        assert_eq!(
            parse_loopback_port_range("1024-1535", PROXY).unwrap(),
            (1024, 1535)
        );
        // Adjacent to the proxy range on either side, not inside it.
        assert!(validate_loopback_port_range((60000, 60079), PROXY).is_ok());
        assert!(validate_loopback_port_range((60090, 60100), PROXY).is_ok());
        // Adjacent to a sensitive port on either side.
        assert!(validate_loopback_port_range((3390, 3400), PROXY).is_ok());
        assert!(validate_loopback_port_range((9223, 9228), PROXY).is_ok());
        // Top of the port space.
        assert!(validate_loopback_port_range((65024, 65535), PROXY).is_ok());
    }

    #[test]
    fn loopback_port_range_rejects() {
        let err = |s: &str| {
            parse_loopback_port_range(s, PROXY)
                .expect_err(s)
                .to_string()
        };
        assert!(err("3099-3000").contains("low"));
        assert!(err("3000-3512").contains("too wide")); // 513 ports
        assert!(err("1023-1100").contains(">= 1024"));
        assert!(err("0-10").contains(">= 1024"));
        assert!(err("3000").contains("LOW-HIGH"));
        assert!(err("a-b").contains("invalid"));
        assert!(err("3000-65536").contains("invalid"));
        // Any port shared with the proxy range, at either end or inside.
        for s in ["60000-60080", "60089-60100", "60082-60085", "60000-60200"] {
            assert!(err(s).contains("proxy port range"), "{s}");
        }
        // The overlap is against the proxy range in use, not the default.
        assert!(validate_loopback_port_range((50000, 50010), Some((50010, 50020))).is_err());
        assert!(validate_loopback_port_range((60080, 60089), Some((50010, 50020))).is_ok());
        // With no proxy range to compare against, only that rule is skipped.
        assert!(validate_loopback_port_range((60080, 60089), None).is_ok());
        assert!(validate_loopback_port_range((3380, 3390), None).is_err());
    }

    #[test]
    fn loopback_port_range_rejects_every_sensitive_port() {
        for (port, what) in SENSITIVE_LOOPBACK_PORTS {
            // Alone, at the low end, at the high end, in the middle.
            for (lo, hi) in [
                (port, port),
                (port, port + 10),
                (port - 10, port),
                (port - 5, port + 5),
            ] {
                let e = validate_loopback_port_range((lo, hi), None)
                    .expect_err("sensitive port accepted")
                    .to_string();
                assert!(e.contains("must not be reachable"), "{e}");
                // A wider range may hold a second listed port; the
                // single-port range names this one.
                if lo == hi {
                    assert!(e.contains(&port.to_string()) && e.contains(what), "{e}");
                }
            }
        }
        for required in [2375, 2376, 3389, 5985, 5986, 9222, 9229] {
            assert!(SENSITIVE_LOOPBACK_PORTS.iter().any(|(p, _)| *p == required));
        }
        // Every listed port is one a range could otherwise hold.
        assert!(
            SENSITIVE_LOOPBACK_PORTS
                .iter()
                .all(|(p, _)| *p >= MIN_LOOPBACK_PORT)
        );
    }

    #[test]
    fn classify_fence_states() {
        assert_eq!(classify_fence(&[]), "absent");
        // Only a PERMIT left behind: nothing is fenced.
        assert_eq!(
            classify_fence(&full_set(Some(FENCE_REVISION), &["permit-loopback-user"])),
            "absent"
        );
        let current = full_set(Some(FENCE_REVISION), &ALL_KINDS);
        assert_eq!(current.len(), filter_count(None));
        assert_eq!(classify_fence(&current), "installed");
        // The set an earlier build wrote: no rev, no anonymous BLOCK.
        assert_eq!(
            classify_fence(&full_set(None, &["permit-loopback-user", "block-user"])),
            "outdated"
        );
        // All three kinds but written at an earlier revision.
        assert_eq!(classify_fence(&full_set(Some(1), &ALL_KINDS)), "outdated");
        // One layer missing its anonymous BLOCK.
        let mut half = current.clone();
        let v6 = ALE_LAYERS[1].1;
        half.retain(|(l, t)| !(*l == v6 && t.kind == "block-anonymous"));
        assert_eq!(classify_fence(&half), "outdated");
        // Foreign extras under the sublayer do not disturb a current set.
        let mut extra = current;
        extra.push((v6, tag("something-else", None)));
        assert_eq!(classify_fence(&extra), "installed");
    }

    fn status(state: &'static str) -> WfpStatus {
        WfpStatus {
            state,
            filters: 0,
            port_range: None,
            loopback_port_range: None,
            user_sid: None,
            hint: None,
        }
    }

    #[test]
    fn recorded_revision_overrides_installed_and_cannot_read() {
        let cur = Some(Some(FENCE_REVISION));
        for s in ["installed", "cannot-read", "absent", "outdated"] {
            assert_eq!(apply_recorded_revision(status(s), cur).state, s);
            // No install record at all: nothing to compare against.
            assert_eq!(apply_recorded_revision(status(s), None).state, s);
        }
        for old in [Some(None), Some(Some(FENCE_REVISION - 1))] {
            for s in ["installed", "cannot-read"] {
                let st = apply_recorded_revision(status(s), old);
                assert_eq!(st.state, "outdated");
                assert!(st.hint.unwrap().contains("srt-win install"));
            }
            assert_eq!(
                apply_recorded_revision(status("absent"), old).state,
                "absent"
            );
        }
    }

    /// After an uninstall that keeps the account, the record is
    /// `FENCE_REVISION_REMOVED`. A caller that cannot enumerate must
    /// then read `absent`; one that still enumerates a set (the reset
    /// landed and the filter removal did not, or another sublayer
    /// holds one) must read `outdated`. Neither may read `installed`.
    #[test]
    fn removed_record_never_reads_as_installed() {
        let removed = Some(Some(FENCE_REVISION_REMOVED));
        let st = apply_recorded_revision(status("cannot-read"), removed);
        assert_eq!(st.state, "absent");
        let hint = st.hint.unwrap();
        assert!(hint.contains("not installed") && hint.contains("srt-win install"));
        assert_eq!(
            apply_recorded_revision(status("installed"), removed).state,
            "outdated"
        );
        assert_eq!(
            apply_recorded_revision(status("absent"), removed).state,
            "absent"
        );
        // Whatever else the record holds, only FENCE_REVISION lets
        // `installed` or `cannot-read` through unchanged.
        for rev in [None, Some(0), Some(1), Some(FENCE_REVISION + 1)] {
            for s in ["installed", "cannot-read"] {
                let got = apply_recorded_revision(status(s), Some(rev)).state;
                assert!(matches!(got, "absent" | "outdated"), "{rev:?}/{s} -> {got}");
            }
        }
        const { assert!(FENCE_REVISION_REMOVED != FENCE_REVISION) };
    }

    #[test]
    fn sddl_rejects_garbage() {
        assert!(OwnedSd::from_sddl("O:LSG:LSD:(A;;CC;;;NOT-A-SID)").is_err());
    }

    #[test]
    fn filter_tag_round_trip() {
        let sid = "S-1-5-21-1-2-3-1005";
        let bk = FilterTag::user("block-user", sid, None);
        assert_eq!(bk.user_sid.as_deref(), Some(sid));
        assert_eq!(bk.port_range, None);
        assert_eq!(bk.rev, Some(FENCE_REVISION));
        let lb = FilterTag::user("permit-loopback-user", sid, Some((60080, 60089)));
        assert_eq!(lb.port_range, Some([60080, 60089]));
        // Round-trips through JSON.
        let back: FilterTag = serde_json::from_slice(&lb.to_blob_bytes()).unwrap();
        assert_eq!(back, lb);
    }

    #[test]
    fn filter_tag_parses_legacy() {
        // A pre-port-range / pre-user-sid tag (the legacy
        // discriminator-group shape) must still parse so
        // uninstall/install can clean it up.
        let legacy = br#"{"tool":"srt-win","kind":"permit-loopback"}"#;
        let t: FilterTag = serde_json::from_slice(legacy).unwrap();
        assert_eq!(t.kind, "permit-loopback");
        assert_eq!(t.port_range, None);
        assert_eq!(t.user_sid, None);
        assert_eq!(t.rev, None);
        // The tag the 4-filter set wrote: a user SID but no rev.
        let prev = br#"{"tool":"srt-win","kind":"block-user","user_sid":"S-1-5-21-1"}"#;
        let t: FilterTag = serde_json::from_slice(prev).unwrap();
        assert_eq!(t.rev, None);
    }

    /// const-assert the weight invariant directly so a reshuffle in
    /// `install_filters` fails to compile here.
    #[test]
    fn weight_invariant() {
        const { assert!(W_LOOPBACK > W_BLOCK) };
    }

    #[test]
    fn parse_port_range_ok() {
        assert_eq!(parse_port_range("60080-60089").unwrap(), (60080, 60089));
        assert_eq!(parse_port_range(" 1 - 1 ").unwrap(), (1, 1));
        assert_eq!(
            parse_port_range("1-65").unwrap(),
            (1, 1 + MAX_PROXY_PORT_RANGE_WIDTH)
        );
    }

    #[test]
    fn parse_port_range_rejects() {
        assert!(parse_port_range("60089-60080").is_err()); // low>high
        assert!(parse_port_range("1-1000").is_err()); // too wide
        assert!(parse_port_range("60080").is_err()); // no dash
        assert!(parse_port_range("a-b").is_err()); // not u16
        assert!(parse_port_range("0-65536").is_err()); // overflow
        assert!(parse_port_range("0-9").is_err()); // port 0
    }

    #[test]
    fn parse_guid_accepts_both_forms() {
        let g1 = parse_guid("2c5d0ad6-5f3b-4d4e-9b8f-1a3e7c9d0b21").unwrap();
        let g2 = parse_guid("{2c5d0ad6-5f3b-4d4e-9b8f-1a3e7c9d0b21}").unwrap();
        assert_eq!(g1, g2);
        assert_eq!(g1, DEFAULT_SUBLAYER_GUID);
    }

    #[test]
    fn parse_guid_rejects_garbage() {
        assert!(parse_guid("not-a-guid").is_err());
    }
}
