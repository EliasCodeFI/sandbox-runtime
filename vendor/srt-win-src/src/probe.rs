//! The behavioural fence probe behind `srt-win wfp verify`.
//!
//! The runner — a process of the sandbox account — makes one TCP
//! connect per token shape a sandboxed process can present to the
//! filtering engine, and reports each result separately:
//!
//!   - **plain** — its own token, to the loopback probe target. The
//!     sandbox-user BLOCK must refuse it.
//!   - **anonymous** — while impersonating the anonymous token, to an
//!     off-loopback target. The anonymous BLOCK must refuse it.
//!   - **anonymous, loopback** — while impersonating the anonymous
//!     token, to the loopback probe target. No filter covers this
//!     (see the `wfp` module doc), so a connect here is reported as
//!     the [`RESIDUAL_ANONYMOUS_LOOPBACK`] residual. It doubles as the
//!     control for the attempt above: it shows that an anonymous
//!     connect is refused off-loopback because of the filter, not
//!     because impersonating anonymous cannot connect at all.
//!   - **deny-only** — under a restricted copy of its own token whose
//!     user SID is deny-only, to the loopback probe target. A
//!     deny-only SID is matched by no ALLOW ACE, so the filters
//!     cannot be made to refuse it; a connect here is reported as the
//!     [`crate::wfp::RESIDUAL_DENY_ONLY`] residual.
//!
//! The socket is always created BEFORE the identity is assumed, the
//! way a process trying to get out would do it: only the connect
//! itself runs under the other token.
//!
//! The runner's stdout is the broker's stdout, so the four results
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
    CREATE_RESTRICTED_TOKEN_FLAGS, CreateRestrictedToken, DuplicateTokenEx,
    ImpersonateAnonymousToken, RevertToSelf, SID_AND_ATTRIBUTES, SecurityImpersonation,
    TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, TokenImpersonation,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, SetThreadToken,
};

/// Name of the residual reported when a connect to a loopback
/// destination made while impersonating the anonymous token is not
/// blocked.
pub const RESIDUAL_ANONYMOUS_LOOPBACK: &str = "anonymous-loopback";

/// How long one connect may take. A refused or filtered connect
/// returns at once; the bound only matters for a destination that
/// does not answer.
const CONNECT_TIMEOUT_SECS: i32 = 4;

/// Result of one connect attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `WSAEACCES` — a BLOCK filter refused the connect.
    Blocked = 0,
    /// The connect completed.
    Connected = 1,
    /// `WSAECONNREFUSED` — nothing was listening, which the
    /// destination can only say once the connect got past the
    /// filters. For the fence this is the same answer as
    /// [`Outcome::Connected`].
    Refused = 2,
    /// Timed out or failed some other way; says nothing about the
    /// fence.
    Unreachable = 3,
    /// The attempt was not made (no target for it).
    Skipped = 4,
    /// The token shape could not be assumed, so no connect was made.
    Error = 5,
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

/// The four attempts' results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub plain: Outcome,
    pub anonymous: Outcome,
    pub anonymous_loopback: Outcome,
    pub deny_only: Outcome,
}

/// Marks a runner exit code as an encoded [`Report`]. Above every
/// code the runner exits with for another reason (0, and 1 for its
/// own error path), so an unrelated exit never decodes.
const REPORT_BASE: u32 = 0x1000;
const BITS: u32 = 3;
const MASK: u32 = (1 << BITS) - 1;

impl Report {
    pub fn encode(&self) -> u32 {
        REPORT_BASE
            | self.plain as u32
            | (self.anonymous as u32) << BITS
            | (self.anonymous_loopback as u32) << (2 * BITS)
            | (self.deny_only as u32) << (3 * BITS)
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
        })
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
/// `wfp verify` / `exec` exit code: the install record says the
/// filter set is not the one this build requires (written by an
/// earlier build, or — for `exec` — removed by an uninstall).
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

/// The plain and the off-loopback anonymous attempts decide the exit
/// code: either one getting past the filters is a missing fence. A
/// skipped anonymous attempt (the machine has no off-loopback address
/// to aim at) does not fail the probe. The two remaining attempts
/// never fail it — the filters cannot refuse them — and are reported
/// as residuals instead of passing silently.
pub fn verdict(r: &Report) -> Verdict {
    let exit = if r.plain.passed_fence() || r.anonymous.passed_fence() {
        EXIT_NOT_FENCED
    } else if r.plain != Outcome::Blocked
        || !matches!(r.anonymous, Outcome::Blocked | Outcome::Skipped)
    {
        EXIT_INCONCLUSIVE
    } else {
        EXIT_FENCED
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

/// Run every attempt. `target` is the loopback probe target;
/// `anonymous_target` the off-loopback one (`None` skips that
/// attempt).
pub fn run(target: &str, anonymous_target: Option<&str>) -> Result<Report> {
    let parse = |s: &str| -> Result<SocketAddr> {
        s.parse()
            .with_context(|| format!("runner: ProbeEgress target '{s}'"))
    };
    let target = parse(target)?;
    let anonymous_target = anonymous_target.map(parse).transpose()?;
    let mut wsa = WSADATA::default();
    let rc = unsafe { WSAStartup(0x0202, &mut wsa) };
    if rc != 0 {
        return Err(anyhow!("WSAStartup: {rc}"));
    }
    Ok(Report {
        plain: attempt("plain", Identity::Own, &target),
        anonymous: match &anonymous_target {
            Some(t) => attempt("anonymous", Identity::Anonymous, t),
            None => {
                eprintln!(
                    "srt-win: runner: egress probe [anonymous]: SKIPPED \
                     (no off-loopback target)"
                );
                Outcome::Skipped
            }
        },
        anonymous_loopback: attempt("anonymous, loopback", Identity::Anonymous, &target),
        deny_only: attempt("deny-only user SID", Identity::DenyOnlyUser, &target),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(p: Outcome, a: Outcome, al: Outcome, d: Outcome) -> Report {
        Report {
            plain: p,
            anonymous: a,
            anonymous_loopback: al,
            deny_only: d,
        }
    }

    #[test]
    fn report_round_trips_every_combination() {
        for p in Outcome::ALL {
            for a in Outcome::ALL {
                for al in Outcome::ALL {
                    for d in Outcome::ALL {
                        let r = report(p, a, al, d);
                        assert_eq!(Report::decode(r.encode()), Some(r));
                    }
                }
            }
        }
    }

    #[test]
    fn unrelated_exit_codes_do_not_decode() {
        // 0 and 1 are the runner's ordinary exits; 2 and 3 were the
        // whole contract of an earlier single-attempt probe.
        for code in [0, 1, 2, 3, 15, 255, 0x0FFF, 0x2000, 0xC000_0005] {
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
