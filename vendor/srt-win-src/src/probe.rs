//! The behavioural fence probe behind `srt-win wfp verify`.
//!
//! The runner — a process of the sandbox account — makes one TCP
//! connect per token shape a sandboxed process can present to the
//! filtering engine, and reports each result separately:
//!
//!   - **plain** — its own token, to the loopback probe target: a
//!     loopback port outside the proxy port range and outside the
//!     configured loopback port range. The sandbox-user BLOCK must
//!     refuse it.
//!   - **anonymous** — while impersonating the anonymous token, to an
//!     off-loopback target. The anonymous BLOCK must refuse it.
//!   - **anonymous, loopback** — while impersonating the anonymous
//!     token, to the loopback probe target. No filter covers this
//!     (see the `wfp` module doc), so a connect here is reported as
//!     the [`RESIDUAL_ANONYMOUS_LOOPBACK`] residual. It doubles as the
//!     control for the attempt above: it shows that an anonymous
//!     connect is refused off-loopback because of the filter, not
//!     because impersonating anonymous cannot connect at all.
//!   - **low integrity** and **untrusted integrity** — under a copy
//!     of its own token whose integrity level has been lowered, to the
//!     off-loopback target and to the loopback probe target (two
//!     connects per level). The copy still carries the sandbox
//!     account's SID, so the sandbox-user BLOCK must refuse all four.
//!     They are probed because an access check applies the mandatory
//!     integrity rule before it reads a descriptor's entries, and a
//!     process may lower the integrity level of a copy of its own
//!     token without any privilege.
//!   - **deny-only** — under a restricted copy of its own token whose
//!     user SID is deny-only, to the loopback probe target. A
//!     deny-only SID is matched by no ALLOW ACE, so the filters
//!     cannot be made to refuse it; a connect here is reported as the
//!     [`crate::wfp::RESIDUAL_DENY_ONLY`] residual.
//!
//! With a loopback port range configured (`wfp verify
//! --loopback-port-range`) it makes two more, both under its own
//! token, which show that the range's PERMIT opens what it says and
//! no more:
//!
//!   - **range, off-loopback** — to a NON-loopback address of this
//!     machine on a port inside the range. The PERMIT is for loopback
//!     addresses only, so the sandbox-user BLOCK must refuse it.
//!   - **range, loopback** — to a loopback listener the broker itself
//!     bound on a port inside the range for the duration of the probe.
//!     It must connect; a block here means the filters in place do not
//!     carry the configured range.
//!
//! It also moves the off-loopback half of the lowered-integrity
//! attempts onto that in-range port ([`lowered_off_loopback`]): the
//! address is the same, so nothing is lost, and the attempts then
//! also show that the range's PERMIT stays closed off loopback for a
//! lowered token. (The report is the runner's exit code, and ten
//! three-bit results fill it; aiming the existing attempts at the
//! stricter destination adds the check without another result.)
//!
//! The socket is always created BEFORE the identity is assumed, the
//! way a process trying to get out would do it: only the connect
//! itself runs under the other token.
//!
//! The runner's stdout is the broker's stdout, so the results
//! travel back in the runner's exit code ([`Report::encode`]).

use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, FD_SET, FIONBIO, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IPPROTO_TCP,
    SO_ERROR, SOCK_STREAM, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKET,
    SOCKET_ERROR, SOL_SOCKET, TIMEVAL, WSADATA, WSAEACCES, WSAECONNREFUSED, WSAEWOULDBLOCK,
    WSAGetLastError, WSAStartup, closesocket, connect, getsockopt, ioctlsocket, select, socket,
};
use windows::Win32::Security::{
    CREATE_RESTRICTED_TOKEN_FLAGS, CreateRestrictedToken, DuplicateTokenEx, GetTokenInformation,
    ImpersonateAnonymousToken, RevertToSelf, SID_AND_ATTRIBUTES, SecurityImpersonation,
    TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TokenImpersonation, TokenImpersonationLevel, TokenIntegrityLevel,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
};

/// Name of the residual reported when a connect to a loopback
/// destination made while impersonating the anonymous token is not
/// blocked.
pub const RESIDUAL_ANONYMOUS_LOOPBACK: &str = "anonymous-loopback";

/// The low mandatory level, as the last part of `S-1-16-<n>`.
const IL_LOW: u32 = 0x1000;
/// The untrusted mandatory level — the lowest.
const IL_UNTRUSTED: u32 = 0;

/// How long one connect may take. A refused or filtered connect
/// returns at once; the bound only matters for a destination that
/// does not answer.
const CONNECT_TIMEOUT_SECS: i32 = 4;

/// Result of one connect attempt.
///
/// No outcome is numbered zero, so an exit code whose field bits are
/// all clear is not a report of "everything blocked".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `WSAEACCES` — a BLOCK filter refused the connect.
    Blocked = 1,
    /// The connect completed.
    Connected = 2,
    /// `WSAECONNREFUSED` — nothing was listening, which the
    /// destination can only say once the connect got past the
    /// filters. For the fence this is the same answer as
    /// [`Outcome::Connected`].
    Refused = 3,
    /// Timed out or failed some other way; says nothing about the
    /// fence.
    Unreachable = 4,
    /// The attempt was not made (no target for it).
    Skipped = 5,
    /// The token shape could not be assumed, so no connect was made.
    Error = 6,
}

impl Outcome {
    const ALL: [Outcome; 6] = [
        Outcome::Blocked,
        Outcome::Connected,
        Outcome::Refused,
        Outcome::Unreachable,
        Outcome::Skipped,
        Outcome::Error,
    ];

    fn from_bits(b: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|o| *o as u32 == b)
    }

    /// The word used in `wfp verify`'s JSON.
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Blocked => "blocked",
            Outcome::Connected => "connected",
            Outcome::Refused => "refused",
            Outcome::Unreachable => "unreachable",
            Outcome::Skipped => "skipped",
            Outcome::Error => "error",
        }
    }

    /// Whether the connect got past the filters.
    pub fn passed_fence(self) -> bool {
        matches!(self, Outcome::Connected | Outcome::Refused)
    }
}

/// Every attempt's result. The two `range_*` attempts are
/// [`Outcome::Skipped`] when no loopback port range is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub plain: Outcome,
    pub anonymous: Outcome,
    pub anonymous_loopback: Outcome,
    pub deny_only: Outcome,
    /// Low integrity, to the off-loopback target.
    pub low_integrity: Outcome,
    /// Low integrity, to the loopback target.
    pub low_integrity_loopback: Outcome,
    /// Untrusted integrity, to the off-loopback target.
    pub untrusted_integrity: Outcome,
    /// Untrusted integrity, to the loopback target.
    pub untrusted_integrity_loopback: Outcome,
    /// Own token, to a non-loopback address on a port inside the
    /// configured loopback port range.
    pub range_off_loopback: Outcome,
    /// Own token, to the broker's loopback listener inside the
    /// configured loopback port range.
    pub range_loopback: Outcome,
}

const BITS: u32 = 3;
const MASK: u32 = (1 << BITS) - 1;
/// Number of [`Outcome`] fields in a [`Report`].
const FIELDS: u32 = 10;
/// Marks a runner exit code as an encoded [`Report`]: the bit just
/// above the fields. Above every code the runner exits with for
/// another reason (0, and 1 for its own error path), so an unrelated
/// exit never decodes. With ten three-bit fields this is bit 30 of
/// the 32 an exit code has; a decoded code also has bit 31 clear, so
/// the `0xC000_0000` failure codes a killed process exits with never
/// decode. There is room for no further field at this width.
const REPORT_BASE: u32 = 1 << (FIELDS * BITS);

impl Report {
    fn fields(&self) -> [Outcome; FIELDS as usize] {
        [
            self.plain,
            self.anonymous,
            self.anonymous_loopback,
            self.deny_only,
            self.low_integrity,
            self.low_integrity_loopback,
            self.untrusted_integrity,
            self.untrusted_integrity_loopback,
            self.range_off_loopback,
            self.range_loopback,
        ]
    }

    pub fn encode(&self) -> u32 {
        self.fields()
            .into_iter()
            .enumerate()
            .fold(REPORT_BASE, |code, (i, o)| {
                code | (o as u32) << (i as u32 * BITS)
            })
    }

    pub fn decode(code: u32) -> Option<Self> {
        if code & !(REPORT_BASE - 1) != REPORT_BASE {
            return None;
        }
        let field = |i: u32| Outcome::from_bits((code >> (i * BITS)) & MASK);
        Some(Self {
            plain: field(0)?,
            anonymous: field(1)?,
            anonymous_loopback: field(2)?,
            deny_only: field(3)?,
            low_integrity: field(4)?,
            low_integrity_loopback: field(5)?,
            untrusted_integrity: field(6)?,
            untrusted_integrity_loopback: field(7)?,
            range_off_loopback: field(8)?,
            range_loopback: field(9)?,
        })
    }

    /// The attempts the filters are built to refuse, each with
    /// whether it may have been skipped (the ones aimed at the
    /// off-loopback target, which a machine can lack, and the one
    /// aimed at a port of the loopback range, which need not be
    /// configured).
    fn must_be_blocked(&self) -> [(Outcome, bool); 7] {
        [
            (self.plain, false),
            (self.anonymous, true),
            (self.low_integrity, true),
            (self.low_integrity_loopback, false),
            (self.untrusted_integrity, true),
            (self.untrusted_integrity_loopback, false),
            (self.range_off_loopback, true),
        ]
    }
}

/// `wfp verify` exit code: the fence refused everything it is built
/// to refuse.
pub const EXIT_FENCED: i32 = 0;
/// `wfp verify` exit code: the probe could not tell.
pub const EXIT_INCONCLUSIVE: i32 = 2;
/// `wfp verify` exit code: a connect the fence must refuse got past
/// it.
pub const EXIT_NOT_FENCED: i32 = 3;
/// `wfp verify` / `exec` exit code: the installed filter set is not
/// the one this session requires — the install record says it was
/// written by an earlier build, or (for `exec`) removed by an
/// uninstall, or opens a different loopback port range than the one
/// the session is configured with; or the probe found the configured
/// range closed. The repair is always to re-run the install.
pub const EXIT_FENCE_OUTDATED: i32 = 19;

/// What `wfp verify` concludes from a [`Report`].
#[derive(Debug, PartialEq, Eq)]
pub struct Verdict {
    pub exit: i32,
    /// Named gaps the probe observed that the filters do not close.
    /// Only meaningful with [`EXIT_FENCED`]: the fence is active, and
    /// these are what it leaves open.
    pub residuals: Vec<&'static str>,
}

/// The plain, the off-loopback anonymous, the four lowered-integrity
/// attempts and the off-loopback one at a port of the configured
/// loopback range decide whether the fence is there: any one getting
/// past the filters is a missing fence ([`EXIT_NOT_FENCED`]), and any
/// one that neither got past nor was blocked — the token could not be
/// assumed, the connect timed out — leaves the probe inconclusive. An
/// attempt at an off-loopback target that was skipped (the machine
/// has no such address to aim at, or no range is configured) does not
/// fail the probe.
///
/// With those settled, the attempt at the broker's own listener inside
/// the configured range must connect. Blocked means the filters do not
/// carry the range ([`EXIT_FENCE_OUTDATED`]); skipped (no range
/// configured, or no port of it was free to listen on) does not fail
/// the probe.
///
/// The two remaining attempts never fail it — the filters cannot
/// refuse them — and are reported as residuals instead of passing
/// silently.
pub fn verdict(r: &Report) -> Verdict {
    let must = r.must_be_blocked();
    let exit = if must.iter().any(|(o, _)| o.passed_fence()) {
        EXIT_NOT_FENCED
    } else if must
        .iter()
        .any(|(o, may_skip)| !(*o == Outcome::Blocked || (*may_skip && *o == Outcome::Skipped)))
    {
        EXIT_INCONCLUSIVE
    } else {
        match r.range_loopback {
            Outcome::Connected | Outcome::Skipped => EXIT_FENCED,
            Outcome::Blocked => EXIT_FENCE_OUTDATED,
            _ => EXIT_INCONCLUSIVE,
        }
    };
    let mut residuals = Vec::new();
    if exit == EXIT_FENCED {
        if r.anonymous_loopback.passed_fence() {
            residuals.push(RESIDUAL_ANONYMOUS_LOOPBACK);
        }
        if r.deny_only.passed_fence() {
            residuals.push(crate::wfp::RESIDUAL_DENY_ONLY);
        }
    }
    Verdict { exit, residuals }
}

/// An off-loopback destination on this machine for the anonymous
/// attempt, the lowered-integrity attempts and the off-loopback range
/// attempt: the address the machine would use as the source of an
/// outbound connection, at `port`. Nothing needs to listen there —
/// refused is as good an answer as connected.
///
/// Found by connecting a UDP socket to a documentation address, which
/// selects a route and a source address without sending anything.
/// `None` when the machine has no route off loopback.
pub fn off_loopback_target(port: u16) -> Option<SocketAddr> {
    use std::net::UdpSocket;
    for (bind, toward) in [("0.0.0.0:0", "192.0.2.1:9"), ("[::]:0", "[2001:db8::1]:9")] {
        let Ok(s) = UdpSocket::bind(bind) else {
            continue;
        };
        if s.connect(toward).is_err() {
            continue;
        }
        if let Ok(local) = s.local_addr() {
            let ip = local.ip();
            if !ip.is_loopback() && !ip.is_unspecified() {
                return Some(SocketAddr::new(ip, port));
            }
        }
    }
    None
}

/// A loopback listener on the first port of `range` that is free,
/// for the in-range reachability attempt. Held by the caller (the
/// broker) until the runner has reported, then dropped. A pending
/// connection completes against the listen backlog, so nothing needs
/// to accept. `None` when every port of the range is taken: the probe
/// never aims that attempt at a listener it does not own.
pub fn bind_in_range((lo, hi): (u16, u16)) -> Option<std::net::TcpListener> {
    (lo..=hi).find_map(|p| std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, p)).ok())
}

/// Why `target` cannot serve as the probe's must-be-blocked loopback
/// target with `range` configured, if it cannot: a loopback port
/// inside the range is PERMITted by an intact fence, so a connect
/// there would read as a missing one.
pub fn target_conflicts_with_range(target: &SocketAddr, (lo, hi): (u16, u16)) -> bool {
    target.ip().is_loopback() && (lo..=hi).contains(&target.port())
}

// ────────────────────── the attempts ──────────────────────

/// Reverts the thread to the process token on drop.
struct Reverted;
impl Drop for Reverted {
    fn drop(&mut self) {
        unsafe {
            let _ = RevertToSelf();
        }
    }
}

/// Which token the connect is made under.
#[derive(Debug, Clone, Copy)]
enum Identity {
    Own,
    Anonymous,
    DenyOnlyUser,
    /// A copy of the own token at this mandatory level.
    LoweredIntegrity(u32),
}

/// Check that the thread now carries a token at mandatory level
/// `rid` and at impersonation level. Setting a thread token can
/// succeed and still leave the thread with less than was asked for;
/// a connect made then would say nothing about the token shape under
/// test.
fn confirm_thread_integrity(rid: u32) -> Result<()> {
    let mut tok = HANDLE::default();
    // open_as_self: checked against the process token, not the
    // lowered one the thread carries.
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut tok) }
        .context("OpenThreadToken")?;
    let tok = crate::util::OwnedHandle(tok);
    let mut level = 0u32;
    let mut len = 0u32;
    // u64 elements: the buffer starts with a struct holding a pointer.
    let mut buf = [0u64; 16];
    let integrity = unsafe {
        GetTokenInformation(
            tok.raw(),
            TokenImpersonationLevel,
            Some(&mut level as *mut u32 as *mut std::ffi::c_void),
            size_of::<u32>() as u32,
            &mut len,
        )
        .context("GetTokenInformation(TokenImpersonationLevel)")?;
        GetTokenInformation(
            tok.raw(),
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
            size_of_val(&buf) as u32,
            &mut len,
        )
        .context("GetTokenInformation(TokenIntegrityLevel)")?;
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        crate::sid::psid_to_string(label.Label.Sid)?
    };
    let want = format!("S-1-16-{rid}");
    if level < SecurityImpersonation.0 as u32 || integrity != want {
        return Err(anyhow!(
            "thread token is at impersonation level {level}, integrity {integrity}; \
             wanted level {} or above, integrity {want}",
            SecurityImpersonation.0
        ));
    }
    Ok(())
}

fn assume(id: Identity) -> Result<Option<Reverted>> {
    match id {
        Identity::Own => Ok(None),
        Identity::Anonymous => {
            unsafe { ImpersonateAnonymousToken(GetCurrentThread()) }
                .context("ImpersonateAnonymousToken")?;
            Ok(Some(Reverted))
        }
        Identity::DenyOnlyUser => {
            let user = crate::sid::LocalPsid::from_string(&crate::sid::current_user_sid()?)?;
            let mut own = HANDLE::default();
            let mut restricted = HANDLE::default();
            let mut imp = HANDLE::default();
            let r = (|| -> Result<()> {
                unsafe {
                    OpenProcessToken(
                        GetCurrentProcess(),
                        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                        &mut own,
                    )
                    .context("OpenProcessToken")?;
                    // The user SID in the disable list becomes
                    // deny-only in the new token.
                    let disable = [SID_AND_ATTRIBUTES {
                        Sid: user.as_psid(),
                        Attributes: 0,
                    }];
                    CreateRestrictedToken(
                        own,
                        CREATE_RESTRICTED_TOKEN_FLAGS(0),
                        Some(&disable),
                        None,
                        None,
                        &mut restricted,
                    )
                    .context("CreateRestrictedToken")?;
                    DuplicateTokenEx(
                        restricted,
                        TOKEN_ALL_ACCESS,
                        None,
                        SecurityImpersonation,
                        TokenImpersonation,
                        &mut imp,
                    )
                    .context("DuplicateTokenEx")?;
                    SetThreadToken(None, Some(imp)).context("SetThreadToken")?;
                }
                Ok(())
            })();
            unsafe {
                for h in [own, restricted, imp] {
                    if !h.is_invalid() {
                        let _ = CloseHandle(h);
                    }
                }
            }
            r.map(|()| Some(Reverted))
        }
        Identity::LoweredIntegrity(rid) => {
            let mut own = HANDLE::default();
            let mut imp = HANDLE::default();
            let r = (|| -> Result<Reverted> {
                unsafe {
                    OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut own)
                        .context("OpenProcessToken")?;
                    DuplicateTokenEx(
                        own,
                        TOKEN_ALL_ACCESS,
                        None,
                        SecurityImpersonation,
                        TokenImpersonation,
                        &mut imp,
                    )
                    .context("DuplicateTokenEx")?;
                    // Lowering a token's integrity level takes no
                    // privilege.
                    crate::token::set_il(imp, rid)?;
                    SetThreadToken(None, Some(imp)).context("SetThreadToken")?;
                }
                // From here the thread is impersonating: revert on
                // every path, including a failed confirmation.
                let reverted = Reverted;
                confirm_thread_integrity(rid)?;
                Ok(reverted)
            })();
            unsafe {
                for h in [own, imp] {
                    if !h.is_invalid() {
                        let _ = CloseHandle(h);
                    }
                }
            }
            r.map(Some)
        }
    }
}

struct Sock(SOCKET);
impl Drop for Sock {
    fn drop(&mut self) {
        unsafe {
            let _ = closesocket(self.0);
        }
    }
}

/// Map a Winsock connect error to an outcome. `WSAEACCES` is matched
/// on the raw code: it is what a BLOCK filter at the connect layer
/// produces, and nothing else in this path does.
fn classify_error(code: i32) -> Outcome {
    if code == WSAEACCES.0 {
        Outcome::Blocked
    } else if code == WSAECONNREFUSED.0 {
        Outcome::Refused
    } else {
        Outcome::Unreachable
    }
}

/// Non-blocking connect on an existing socket, waited for up to
/// [`CONNECT_TIMEOUT_SECS`]. Returns the outcome and the Winsock
/// error code behind it (0 for a completed connect).
fn connect_bounded(sock: &Sock, addr: &SocketAddr) -> (Outcome, i32) {
    let rc = unsafe {
        match addr {
            SocketAddr::V4(a) => {
                let sa = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: a.port().to_be(),
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(a.ip().octets()),
                        },
                    },
                    sin_zero: [0; 8],
                };
                connect(
                    sock.0,
                    &sa as *const SOCKADDR_IN as *const SOCKADDR,
                    size_of::<SOCKADDR_IN>() as i32,
                )
            }
            SocketAddr::V6(a) => {
                let sa = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: a.port().to_be(),
                    sin6_flowinfo: a.flowinfo(),
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: a.ip().octets(),
                        },
                    },
                    Anonymous: SOCKADDR_IN6_0 {
                        sin6_scope_id: a.scope_id(),
                    },
                };
                connect(
                    sock.0,
                    &sa as *const SOCKADDR_IN6 as *const SOCKADDR,
                    size_of::<SOCKADDR_IN6>() as i32,
                )
            }
        }
    };
    if rc != SOCKET_ERROR {
        return (Outcome::Connected, 0);
    }
    let err = unsafe { WSAGetLastError() };
    if err != WSAEWOULDBLOCK {
        return (classify_error(err.0), err.0);
    }
    // In progress: writable = connected, exceptional = failed.
    let mut fds = [sock.0; 64];
    fds[0] = sock.0;
    let mut writable = FD_SET {
        fd_count: 1,
        fd_array: fds,
    };
    let mut failed = FD_SET {
        fd_count: 1,
        fd_array: fds,
    };
    let tv = TIMEVAL {
        tv_sec: CONNECT_TIMEOUT_SECS,
        tv_usec: 0,
    };
    let n = unsafe { select(0, None, Some(&mut writable), Some(&mut failed), Some(&tv)) };
    if n <= 0 {
        // 0 = timed out, SOCKET_ERROR = select itself failed.
        return (Outcome::Unreachable, 0);
    }
    let mut so_error: i32 = 0;
    let mut len = size_of::<i32>() as i32;
    let rc = unsafe {
        getsockopt(
            sock.0,
            SOL_SOCKET,
            SO_ERROR,
            windows::core::PSTR(&mut so_error as *mut i32 as *mut u8),
            &mut len,
        )
    };
    if rc == SOCKET_ERROR {
        return (Outcome::Unreachable, unsafe { WSAGetLastError() }.0);
    }
    if so_error == 0 {
        (Outcome::Connected, 0)
    } else {
        (classify_error(so_error), so_error)
    }
}

/// One attempt: create the socket as the process, assume `id`, connect.
fn attempt(name: &str, id: Identity, target: &SocketAddr) -> Outcome {
    let (outcome, detail) = (|| -> Result<(Outcome, String)> {
        let af = match target {
            SocketAddr::V4(_) => AF_INET,
            SocketAddr::V6(_) => AF_INET6,
        };
        let sock = Sock(
            unsafe { socket(af.0 as i32, SOCK_STREAM, IPPROTO_TCP.0) }
                .map_err(|e| anyhow!("socket: {e}"))?,
        );
        let mut nonblocking: u32 = 1;
        if unsafe { ioctlsocket(sock.0, FIONBIO, &mut nonblocking) } == SOCKET_ERROR {
            return Err(anyhow!("ioctlsocket(FIONBIO): {:?}", unsafe {
                WSAGetLastError()
            }));
        }
        let _reverted = match assume(id) {
            Ok(g) => g,
            Err(e) => return Ok((Outcome::Error, format!("{e:#}"))),
        };
        let (o, code) = connect_bounded(&sock, target);
        Ok((o, format!("winsock error {code}")))
    })()
    .unwrap_or_else(|e| (Outcome::Error, format!("{e:#}")));
    // stderr, never stdout: the runner's stdout is the broker's, and
    // the broker prints its own JSON there.
    eprintln!(
        "srt-win: runner: egress probe [{name}] {target}: {} ({detail})",
        outcome.label().to_uppercase(),
    );
    outcome
}

/// The off-loopback target of the lowered-integrity attempts: the
/// one at a port inside the configured loopback range when there is
/// one, else the anonymous attempt's. Both are the same address; the
/// in-range port is the stricter destination, since it is the one a
/// PERMIT names. Shared by the runner, which aims the attempts, and
/// the broker, which reports where they went.
pub fn lowered_off_loopback<T>(range_off_loopback: Option<T>, anonymous: Option<T>) -> Option<T> {
    range_off_loopback.or(anonymous)
}

/// Where each attempt is aimed. `None` skips that attempt.
#[derive(Debug, Clone, Copy, Default)]
pub struct Targets<'a> {
    /// The loopback probe target: outside every permitted port range.
    pub target: &'a str,
    /// Off-loopback, for the attempt made while impersonating the
    /// anonymous token — and for the lowered-integrity attempts when
    /// `range_off_loopback` is `None`.
    pub anonymous: Option<&'a str>,
    /// Off-loopback, at a port inside the configured loopback range.
    /// Also where the lowered-integrity attempts' off-loopback half
    /// goes ([`lowered_off_loopback`]).
    pub range_off_loopback: Option<&'a str>,
    /// The broker's loopback listener inside the configured range.
    pub range_loopback: Option<&'a str>,
}

/// Run every attempt.
pub fn run(targets: Targets<'_>) -> Result<Report> {
    let parse = |s: &str| -> Result<SocketAddr> {
        s.parse()
            .with_context(|| format!("runner: ProbeEgress target '{s}'"))
    };
    let target = parse(targets.target)?;
    let anonymous_target = targets.anonymous.map(parse).transpose()?;
    let range_off_loopback = targets.range_off_loopback.map(parse).transpose()?;
    let range_loopback = targets.range_loopback.map(parse).transpose()?;
    let optional = |name: &str, t: &Option<SocketAddr>| match t {
        Some(t) => attempt(name, Identity::Own, t),
        None => Outcome::Skipped,
    };
    let mut wsa = WSADATA::default();
    let rc = unsafe { WSAStartup(0x0202, &mut wsa) };
    if rc != 0 {
        return Err(anyhow!("WSAStartup: {rc}"));
    }
    let lowered_target = lowered_off_loopback(range_off_loopback, anonymous_target);
    let off_loopback_at = |name: &str, id: Identity, t: &Option<SocketAddr>| match t {
        Some(t) => attempt(name, id, t),
        None => {
            eprintln!(
                "srt-win: runner: egress probe [{name}]: SKIPPED \
                 (no off-loopback target)"
            );
            Outcome::Skipped
        }
    };
    let low = Identity::LoweredIntegrity(IL_LOW);
    let untrusted = Identity::LoweredIntegrity(IL_UNTRUSTED);
    Ok(Report {
        plain: attempt("plain", Identity::Own, &target),
        anonymous: off_loopback_at("anonymous", Identity::Anonymous, &anonymous_target),
        anonymous_loopback: attempt("anonymous, loopback", Identity::Anonymous, &target),
        deny_only: attempt("deny-only user SID", Identity::DenyOnlyUser, &target),
        low_integrity: off_loopback_at("low integrity", low, &lowered_target),
        low_integrity_loopback: attempt("low integrity, loopback", low, &target),
        untrusted_integrity: off_loopback_at("untrusted integrity", untrusted, &lowered_target),
        untrusted_integrity_loopback: attempt("untrusted integrity, loopback", untrusted, &target),
        range_off_loopback: optional("loopback range, off-loopback", &range_off_loopback),
        range_loopback: optional("loopback range, loopback", &range_loopback),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A report with no loopback port range configured: the four
    /// lowered-integrity attempts blocked, the two range attempts
    /// skipped, the rest as given.
    fn report(p: Outcome, a: Outcome, al: Outcome, d: Outcome) -> Report {
        lowered(
            Report {
                plain: p,
                anonymous: a,
                anonymous_loopback: al,
                deny_only: d,
                low_integrity: Outcome::Blocked,
                low_integrity_loopback: Outcome::Blocked,
                untrusted_integrity: Outcome::Blocked,
                untrusted_integrity_loopback: Outcome::Blocked,
                range_off_loopback: Outcome::Skipped,
                range_loopback: Outcome::Skipped,
            },
            [Outcome::Blocked; 4],
        )
    }

    /// `r` with the four lowered-integrity attempts replaced, in
    /// field order.
    fn lowered(r: Report, l: [Outcome; 4]) -> Report {
        Report {
            low_integrity: l[0],
            low_integrity_loopback: l[1],
            untrusted_integrity: l[2],
            untrusted_integrity_loopback: l[3],
            ..r
        }
    }

    /// An otherwise clean report with the two range attempts set.
    fn ranged(off_loopback: Outcome, loopback: Outcome) -> Report {
        Report {
            range_off_loopback: off_loopback,
            range_loopback: loopback,
            ..report(
                Outcome::Blocked,
                Outcome::Blocked,
                Outcome::Blocked,
                Outcome::Blocked,
            )
        }
    }

    #[test]
    fn report_round_trips_every_combination() {
        for p in Outcome::ALL {
            for a in Outcome::ALL {
                for al in Outcome::ALL {
                    for d in Outcome::ALL {
                        // The four lowered-integrity fields take the
                        // same values in a different order, so every
                        // field sees every outcome beside differing
                        // neighbours; the two range fields take every
                        // pair.
                        for ro in Outcome::ALL {
                            for rl in Outcome::ALL {
                                let r = Report {
                                    range_off_loopback: ro,
                                    range_loopback: rl,
                                    ..lowered(report(p, a, al, d), [d, al, a, p])
                                };
                                assert_eq!(Report::decode(r.encode()), Some(r));
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn verdict_with_a_loopback_range() {
        // The range opens loopback and nothing else.
        let v = verdict(&ranged(Blocked, Connected));
        assert_eq!(v.exit, EXIT_FENCED);
        assert!(v.residuals.is_empty());
        // No off-loopback address to aim at, or no free port to
        // listen on: neither fails the probe.
        assert_eq!(verdict(&ranged(Skipped, Connected)).exit, EXIT_FENCED);
        assert_eq!(verdict(&ranged(Blocked, Skipped)).exit, EXIT_FENCED);
        // An in-range port reached off loopback is a missing fence,
        // whatever the listener attempt says.
        for through in [Connected, Refused] {
            for listener in [Connected, Blocked, Skipped, Unreachable] {
                assert_eq!(verdict(&ranged(through, listener)).exit, EXIT_NOT_FENCED);
            }
        }
        // The broker's own in-range listener blocked: the filters do
        // not carry the configured range.
        assert_eq!(verdict(&ranged(Blocked, Blocked)).exit, EXIT_FENCE_OUTDATED);
        // A must-be-blocked attempt getting out outranks that.
        let mut r = ranged(Blocked, Blocked);
        r.plain = Connected;
        assert_eq!(verdict(&r).exit, EXIT_NOT_FENCED);
        // Anything else says nothing either way.
        for odd in [Unreachable, Error] {
            assert_eq!(verdict(&ranged(odd, Connected)).exit, EXIT_INCONCLUSIVE);
        }
        for odd in [Refused, Unreachable, Error] {
            assert_eq!(verdict(&ranged(Blocked, odd)).exit, EXIT_INCONCLUSIVE);
        }
        // Residuals qualify a pass with a range as without one.
        let mut r = ranged(Blocked, Connected);
        r.deny_only = Connected;
        assert_eq!(verdict(&r).residuals, [crate::wfp::RESIDUAL_DENY_ONLY]);
    }

    #[test]
    fn lowered_attempts_go_to_the_in_range_port_when_there_is_one() {
        assert_eq!(
            lowered_off_loopback(Some("10.0.0.5:3000"), Some("10.0.0.5:49999")),
            Some("10.0.0.5:3000")
        );
        assert_eq!(
            lowered_off_loopback(None, Some("10.0.0.5:49999")),
            Some("10.0.0.5:49999")
        );
        assert_eq!(lowered_off_loopback::<&str>(None, None), None);
    }

    #[test]
    fn every_field_fits_below_the_marker_in_an_exit_code() {
        const { assert!(FIELDS * BITS < 31) };
        assert_eq!(REPORT_BASE, 0x4000_0000);
        // The widest report still has bit 31 clear.
        let all_error = Report {
            range_off_loopback: Error,
            range_loopback: Error,
            ..lowered(report(Error, Error, Error, Error), [Error; 4])
        };
        assert_eq!(all_error.encode() >> 31, 0);
        assert_eq!(Report::decode(all_error.encode()), Some(all_error));
    }

    #[test]
    fn probe_target_inside_the_range_is_a_conflict() {
        let t = |s: &str| s.parse::<SocketAddr>().unwrap();
        let range = (3000, 3099);
        for inside in [
            "127.0.0.1:3000",
            "127.0.0.1:3099",
            "127.9.9.9:3050",
            "[::1]:3050",
        ] {
            assert!(target_conflicts_with_range(&t(inside), range), "{inside}");
        }
        for outside in ["127.0.0.1:2999", "127.0.0.1:3100", "[::1]:49152"] {
            assert!(
                !target_conflicts_with_range(&t(outside), range),
                "{outside}"
            );
        }
        // The PERMIT is for loopback addresses: an in-range port
        // elsewhere is still a must-be-blocked destination.
        assert!(!target_conflicts_with_range(&t("192.0.2.7:3050"), range));
    }

    #[test]
    fn unrelated_exit_codes_do_not_decode() {
        // 0 and 1 are the runner's ordinary exits; 2 and 3 were the
        // whole contract of an earlier single-attempt probe, and
        // 0x1000.. that of the four-attempt one.
        for code in [
            0,
            1,
            2,
            3,
            15,
            255,
            0x0FFF,
            0x1000,
            0x2000,
            REPORT_BASE,
            REPORT_BASE - 1,
            REPORT_BASE << 1,
            0xC000_0005,
        ] {
            assert_eq!(Report::decode(code), None, "{code:#x}");
        }
        // In range, but a field holds no outcome.
        assert_eq!(Report::decode(REPORT_BASE | 7), None);
    }

    #[test]
    fn classify_error_codes() {
        assert_eq!(classify_error(10013), Outcome::Blocked);
        assert_eq!(classify_error(10061), Outcome::Refused);
        // ERROR_ACCESS_DENIED is not a filter refusal.
        assert_eq!(classify_error(5), Outcome::Unreachable);
        assert_eq!(classify_error(10060), Outcome::Unreachable);
    }

    use Outcome::*;

    #[test]
    fn verdict_fenced_without_residuals() {
        let v = verdict(&report(Blocked, Blocked, Blocked, Blocked));
        assert_eq!(v.exit, EXIT_FENCED);
        assert!(v.residuals.is_empty());
    }

    #[test]
    fn verdict_names_each_residual() {
        let v = verdict(&report(Blocked, Blocked, Connected, Connected));
        assert_eq!(v.exit, EXIT_FENCED);
        assert_eq!(
            v.residuals,
            [RESIDUAL_ANONYMOUS_LOOPBACK, crate::wfp::RESIDUAL_DENY_ONLY]
        );
        let v = verdict(&report(Blocked, Blocked, Blocked, Refused));
        assert_eq!(v.residuals, [crate::wfp::RESIDUAL_DENY_ONLY]);
        // An attempt that could not be made is not a residual.
        let v = verdict(&report(Blocked, Blocked, Error, Unreachable));
        assert_eq!(v.exit, EXIT_FENCED);
        assert!(v.residuals.is_empty());
    }

    #[test]
    fn verdict_plain_or_anonymous_getting_out_is_not_fenced() {
        for through in [Connected, Refused] {
            assert_eq!(
                verdict(&report(through, Blocked, Blocked, Blocked)).exit,
                EXIT_NOT_FENCED
            );
            let v = verdict(&report(Blocked, through, Connected, Connected));
            assert_eq!(v.exit, EXIT_NOT_FENCED);
            // Residuals qualify a pass; a failure reports none.
            assert!(v.residuals.is_empty());
        }
    }

    #[test]
    fn verdict_lowered_integrity_getting_out_is_not_fenced() {
        let all_blocked = report(Blocked, Blocked, Blocked, Blocked);
        for field in 0..4 {
            for through in [Connected, Refused] {
                let mut l = [Blocked; 4];
                l[field] = through;
                let v = verdict(&lowered(all_blocked, l));
                assert_eq!(v.exit, EXIT_NOT_FENCED, "field {field} {through:?}");
                assert!(v.residuals.is_empty());
            }
        }
    }

    #[test]
    fn verdict_lowered_integrity_not_assumed_is_inconclusive() {
        let all_blocked = report(Blocked, Blocked, Blocked, Blocked);
        for field in 0..4 {
            // A token that could not be assumed is not a block.
            for odd in [Error, Unreachable] {
                let mut l = [Blocked; 4];
                l[field] = odd;
                assert_eq!(
                    verdict(&lowered(all_blocked, l)).exit,
                    EXIT_INCONCLUSIVE,
                    "field {field} {odd:?}"
                );
            }
        }
        // Only the attempts at the off-loopback target can be skipped.
        let v = verdict(&lowered(all_blocked, [Skipped, Blocked, Skipped, Blocked]));
        assert_eq!(v.exit, EXIT_FENCED);
        for loopback in [1, 3] {
            let mut l = [Blocked; 4];
            l[loopback] = Skipped;
            assert_eq!(verdict(&lowered(all_blocked, l)).exit, EXIT_INCONCLUSIVE);
        }
    }

    #[test]
    fn verdict_inconclusive_and_skipped() {
        for odd in [Unreachable, Error, Skipped] {
            assert_eq!(
                verdict(&report(odd, Blocked, Blocked, Blocked)).exit,
                EXIT_INCONCLUSIVE
            );
        }
        for odd in [Unreachable, Error] {
            assert_eq!(
                verdict(&report(Blocked, odd, Blocked, Blocked)).exit,
                EXIT_INCONCLUSIVE
            );
        }
        assert_eq!(
            verdict(&report(Blocked, Skipped, Blocked, Blocked)).exit,
            EXIT_FENCED
        );
    }
}
