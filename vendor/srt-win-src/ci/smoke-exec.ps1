<#
  Smoke test for `srt-win exec` (the two-hop sandbox-user launch).

  Self-contained: provisions the `srt-sandbox` account + WFP filters
  under a fixed test-only sublayer GUID via `srt-win install`, then
  exercises exec end-to-end. The fixed GUID lets the workflow's
  `if: always()` cleanup step uninstall any leaked filters even if
  this script throws mid-run.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; distinct from srt-win's compile-time
# default and from anything smoke.ps1 uses. Referenced verbatim by
# the workflow's always()-cleanup step.
$Sublayer  = '5b0e64f4-09f1-4c2e-8c97-4d2c0f4e9b7d'
# Loopback PERMIT is scoped to this port range. Anything on
# 127.0.0.1 outside it is BLOCKed. Match srt-win's default but pass
# it explicitly so this script doesn't drift if the default changes.
$PortRange = '60080-60089'
$PortLo    = 60080
$PortHi    = 60089

# Bind a TcpListener on the first free port from $candidates, on
# 127.0.0.1 unless another address is given. Throws if none bind.
function Bind-Listener {
  param([int[]] $Candidates,
        [System.Net.IPAddress] $Address = [System.Net.IPAddress]::Loopback)
  foreach ($p in $Candidates) {
    try {
      $l = [System.Net.Sockets.TcpListener]::new($Address, $p)
      $l.Start()
      return $l
    } catch {
      # port in use — try next
    }
  }
  throw "no free port among: $($Candidates -join ',')"
}

function Run {
  param([string[]] $argv)
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}
function J { param([string[]] $argv) Run $argv | ConvertFrom-Json }

$cmd  = Join-Path $env:SystemRoot 'System32\cmd.exe'
$pwsh = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
# Enable srt-win's per-exec stderr diagnostics (notably the
# self-protect SDDL dump).
$env:SANDBOX_RUNTIME_WIN_DEBUG = '1'
Write-Host "smoke-exec: sublayer=$Sublayer  exe=$Exe"

# CreateProcessWithLogonW routes through the Secondary Logon
# service. GHA runners have it; ensure it's running (idempotent).
try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke-exec: WARNING: Start-Service seclogon: $_"
}

# ── R0b: exec without provisioning → exit 15 ──
$r0b = & $Exe exec -- $cmd /c 'exit 0' 2>&1 | Out-String
if ($LASTEXITCODE -ne 15) {
  throw "R0b: expected exit 15 (not provisioned), got ${LASTEXITCODE}. out: $r0b"
}
if ($r0b -notmatch '(?i)srt-win install') {
  throw "R0b: expected re-run install hint. out: $r0b"
}
Write-Host 'R0b ok: exec exits 15 with install hint when not provisioned'

# Full install under the test sublayer: provisions srt-sandbox +
# sandbox-runtime-users + DPAPI cred + setup marker + the user-SID
# WFP filter pair.
Run @('install',
      '--sublayer-guid',$Sublayer,
      '--proxy-port-range',$PortRange)
$us = J @('user','status')
if (-not $us.user.exists) { throw 'R: srt-sandbox not provisioned' }
$sbSid = $us.marker_user_sid
if (-not $sbSid) { throw 'R: setup marker missing user_sid' }
Write-Host "R: sandbox user provisioned (sid=$sbSid)"

# ── V1: wfp verify — behavioral egress-block probe ──────────────
# The non-elevated readiness check that replaced exec's WFP
# pre-flight. The block-user filter from `install` above fires at
# ALE_AUTH_CONNECT → WSAEACCES → exit 0 + "blocked". stderr (the
# runner's BLOCKED line) flows to the host so it's in the CI log;
# stdout is JUST the JSON line. `--target` is required: bind a
# local listener on an out-of-range loopback port (same shape as
# the product path — `verifyWindowsWfpEgress` does this in TS).
$v1Lsn = Bind-Listener (49990..49999)
$v1Tgt = "127.0.0.1:$($v1Lsn.LocalEndpoint.Port)"
$vout = & $Exe wfp verify --target $v1Tgt
$vexit = $LASTEXITCODE
$v1Lsn.Stop()
Write-Host "V1: wfp verify --target $v1Tgt exit=$vexit stdout='$vout'"
$v = $vout | ConvertFrom-Json

# ── V1c: lowered-integrity copies of the sandbox token are blocked ──
# Same run as V1, checked first so that a failure here is named for
# what it is instead of surfacing as V1's exit code. The runner makes
# four more connects under a copy of its own token whose integrity
# level it has lowered: low and untrusted, each to the off-loopback
# address and to the out-of-range loopback listener. The copy still
# carries the sandbox account's SID, so block-user must refuse every
# one. `error` means the runner could not assume the lowered token;
# that is not a block and fails the row as such.
$loweredFields = 'low_integrity_probe','low_integrity_loopback_probe',
                 'untrusted_integrity_probe','untrusted_integrity_loopback_probe'
foreach ($f in $loweredFields) {
  if ($null -eq $v.PSObject.Properties[$f]) { throw "V1c: wfp verify output lacks '$f': $vout" }
}
$loweredRaw = ($loweredFields | ForEach-Object { "$_=$($v.$_)" }) -join ' '
Write-Host "V1c raw: $loweredRaw (off-loopback target=$($v.anonymous_target))"
$loweredOpen = @($loweredFields | Where-Object { $v.$_ -in 'connected','refused' })
if ($loweredOpen.Count -gt 0) {
  throw "V1c: BYPASS - a connect under a lowered-integrity copy of the sandbox token was NOT blocked " +
        "($($loweredOpen -join ', ')); block-user does not match that token. $loweredRaw exit=$vexit"
}
foreach ($f in $loweredFields) {
  $got = $v.$f
  $offLoopback = $f -notlike '*_loopback_probe'
  if ($got -eq 'error') {
    throw "V1c: $f=error - the runner could not assume the lowered-integrity token (see its stderr line above); " +
          "this is NOT a block. $loweredRaw"
  }
  if ($got -eq 'skipped' -and $offLoopback) {
    Write-Host "V1c note: $f skipped (no off-loopback address on this runner)"
  } elseif ($got -ne 'blocked') {
    throw "V1c: $f expected blocked, got '$got'. $loweredRaw"
  }
}
Write-Host "V1c ok: lowered-integrity connects blocked: $loweredRaw"

if ($vexit -ne 0) {
  throw "V1: wfp verify expected exit 0 (blocked), got $vexit. stdout: $vout"
}
if ($v.egress_probe -ne 'blocked') {
  throw "V1: wfp verify expected egress_probe=blocked, got '$($v.egress_probe)'"
}
Write-Host 'V1 ok: wfp verify reports egress_probe=blocked'

# ── V1b: wfp verify reports each token shape separately ─────────
# Same run as V1. Beside the plain connect the runner tries one
# while impersonating the anonymous token, aimed at this machine's
# own off-loopback address (srt-win picks it; `skipped` when there is
# none), which the anonymous BLOCK must refuse. The two remaining
# attempts are shapes no filter covers; they must be REPORTED, and
# what they report is recorded here, not asserted: a connect is the
# documented residual and is named in `residuals`.
foreach ($f in 'anonymous_probe','anonymous_loopback_probe','deny_only_probe','residuals') {
  if ($null -eq $v.PSObject.Properties[$f]) { throw "V1b: wfp verify output lacks '$f': $vout" }
}
if ($v.anonymous_probe -eq 'skipped') {
  Write-Host 'V1b note: anonymous attempt skipped (no off-loopback address on this runner)'
} elseif ($v.anonymous_probe -ne 'blocked') {
  throw "V1b: anonymous-token connect to $($v.anonymous_target) expected blocked, got '$($v.anonymous_probe)'"
}
foreach ($pair in @(@('anonymous_loopback_probe','anonymous-loopback'), @('deny_only_probe','deny-only-user-sid'))) {
  $got = $v.($pair[0])
  $open = $got -in 'connected','refused'
  if ($open -ne ($v.residuals -contains $pair[1])) {
    throw "V1b: $($pair[0])='$got' but residuals=[$($v.residuals -join ',')] - a connect must be named as '$($pair[1])', and only a connect"
  }
  if ($open) { Write-Host "V1b residual (documented): $($pair[1]) - $($pair[0])=$got" }
  else       { Write-Host "V1b: $($pair[0])=$got (no residual observed)" }
}
Write-Host "V1b ok: anonymous_probe=$($v.anonymous_probe) target=$($v.anonymous_target); residuals=[$($v.residuals -join ',')]"

# Exec helper. Same .exit/.raw/.out shape as before. The broker
# forwards exactly what it is told via --env (it does NOT enumerate
# its own environment), so pass PATH/PATHEXT here — same overlay the
# TS wrapper builds.
#
# Watchdog: the two-hop chain (broker → CPWLW runner → restricted
# child) has no console; a hang anywhere inside it would otherwise
# sit until the GHA job timeout. 30s is generous — every R-row
# payload is sub-second. System.Diagnostics.Process (not the `&`
# call operator or Start-Process) so we get (a) WaitForExit with a
# timeout and (b) per-element ArgumentList quoting that survives
# PATH-with-spaces.
function RExec {
  # 120s: a row that starts Windows PowerShell as the sandbox user can take
  # over 30s on some hosted runner images (powershell.exe is CPU-bound in
  # startup the whole time, then finishes). A limit only matters on a hang.
  param([string[]] $tail, [int] $TimeoutSec = 120)
  $argv = @('exec',
            '--env', "PATH=$($env:PATH)",
            '--env', "PATHEXT=$($env:PATHEXT)") + $tail
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName               = $Exe
  $psi.UseShellExecute        = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.Environment['SANDBOX_RUNTIME_WIN_DEBUG'] = '1'
  foreach ($a in $argv) { $null = $psi.ArgumentList.Add($a) }
  $p  = [System.Diagnostics.Process]::Start($psi)
  # Drain both pipes concurrently so a full pipe buffer can't wedge
  # WaitForExit.
  $so = $p.StandardOutput.ReadToEndAsync()
  $se = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    # Report through the host, not the exception: the error view truncates a
    # long message, and the child's output and the processes it got as far as
    # starting are what say where it stopped.
    $since = $p.StartTime
    Get-CimInstance Win32_Process |
      Where-Object { $_.ProcessId -eq $p.Id -or $_.CreationDate -ge $since } |
      Sort-Object CreationDate |
      ForEach-Object {
        Write-Host ("RExec timeout: proc pid={0} ppid={1} {2} cpu={3:n1}s" -f
          $_.ProcessId, $_.ParentProcessId, $_.Name,
          (($_.UserModeTime + $_.KernelModeTime) / 1e7))
      }
    try { $p.Kill($true) } catch { }
    $p.WaitForExit()
    Write-Host "RExec timeout: argv tail: $($tail -join ' ')"
    Write-Host "RExec timeout: stderr:`n$($se.Result)"
    Write-Host "RExec timeout: stdout:`n$($so.Result)"
    throw "RExec: TIMEOUT after ${TimeoutSec}s (child output above)"
  }
  $exit  = $p.ExitCode
  $raw   = $so.Result + $se.Result
  $lines = $raw -split "`r?`n"
  $child = ($lines | Where-Object { $_ -notmatch '^srt-win:' }) -join "`n"
  return [pscustomobject]@{ exit = $exit; raw = $raw; out = $child }
}

# ── R1: child runs as srt-sandbox ───────────────────────────────
$r = RExec @('--', $cmd, '/c', 'whoami /user /FO CSV /NH')
if ($r.exit -ne 0) { throw "R1: whoami exited $($r.exit). raw: $($r.raw)" }
$row = $r.out | ConvertFrom-Csv -Header Name,SID
if ($row.SID -ne $sbSid) {
  throw "R1: child user SID $($row.SID), expected $sbSid. raw: $($r.raw)"
}
Write-Host "R1 ok: two-hop child runs as srt-sandbox (sid=$($row.SID))"

# ── R2: stdio piped broker ← runner ← child ─────────────────────
$r = RExec @('--', $cmd, '/c', 'echo R2-STDOUT-MARK & echo R2-STDERR-MARK 1>&2')
if ($r.out -notmatch 'R2-STDOUT-MARK') {
  throw "R2: stdout marker missing. raw: $($r.raw)"
}
if ($r.raw -notmatch 'R2-STDERR-MARK') {
  throw "R2: stderr marker missing. raw: $($r.raw)"
}
Write-Host 'R2 ok: stdout+stderr piped through runner to broker'

# ── R3: exit code propagates broker ← runner ← child ────────────
$r = RExec @('--', $cmd, '/c', 'exit 23')
if ($r.exit -ne 23) {
  throw "R3: expected exit 23, got $($r.exit). raw: $($r.raw)"
}
Write-Host 'R3 ok: child exit code propagates through runner'

# ── R4: env-merge — USERPROFILE isolated, PATH overlaid ─────────
# LOGON_WITH_PROFILE gives the runner the sandbox user's profile
# env (USERPROFILE/TEMP under C:\Users\srt-sandbox). The broker's
# PATH is overlaid via the spec so tools resolve. Probe both.
$r = RExec @('--', $cmd, '/c', 'echo UP=%USERPROFILE%& echo PATH=%PATH%')
if ($r.out -notmatch '(?i)UP=.*srt-sandbox') {
  throw "R4: USERPROFILE not isolated to srt-sandbox. out: $($r.out)"
}
if ($r.out -notmatch '(?i)PATH=.*System32') {
  throw "R4: PATH overlay missing System32. out: $($r.out)"
}
Write-Host 'R4 ok: USERPROFILE isolated, broker PATH overlaid'

# ── R4b: --env overlay restores the *_PROXY case-twin ───────────
# The host spawn layer keeps only ONE casing of an env key, but
# Cygwin/MSYS2 children read the lowercase names — so the runner
# appends the missing twin. Passing HTTP_PROXY via --env and
# finding BOTH casings in the child proves the repair.
$r = RExec @('--env', "HTTP_PROXY=http://127.0.0.1:$PortLo",
             '--', $cmd, '/c', 'set http')
if ($r.exit -ne 0) { throw "R4b: 'set http' exited $($r.exit). out: $($r.out)" }
$lines = $r.out -split "`r?`n"
if (-not ($lines | Where-Object { $_ -clike 'http_proxy=*' })) {
  throw "R4b: lowercase http_proxy twin missing in child. out: $($r.out)"
}
if (-not ($lines | Where-Object { $_ -clike 'HTTP_PROXY=*' })) {
  throw "R4b: uppercase HTTP_PROXY missing in child. out: $($r.out)"
}
Write-Host 'R4b ok: runner restores the lowercase twin of overlay-proxy vars'

# ── R5: outbound blocked by block-user filter ───────────────────
# The user-SID WFP filter blocks all srt-sandbox egress except
# in-range loopback. No proxy env in this row, so the child's
# direct curl must fail.
$r = RExec @('--', $cmd, '/c', 'curl -sS -m 5 https://example.com')
if ($r.exit -eq 0) {
  throw "R5: outbound curl succeeded under sandbox " +
        "(block-user not in effect?). out: $($r.out)"
}
Write-Host "R5 ok: outbound blocked for srt-sandbox (curl exit=$($r.exit))"

# ── R5b: in-range loopback permitted ─────────────────────────────
$inRangeR = Bind-Listener ($PortHi..($PortLo+5))
$portInR  = $inRangeR.LocalEndpoint.Port
try {
  # TcpClient, as in R5d/R5e, not Test-NetConnection: the cmdlet loads the
  # NetTCPIP module and falls back to a ping, which roughly doubles the row.
  # This is the first Windows PowerShell started as the sandbox user; log how
  # long it took.
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command',
    "try { `$c = New-Object Net.Sockets.TcpClient; `$c.Connect('127.0.0.1', $portInR); Write-Output CONNECTED } " +
    "catch { Write-Output blocked }")
  Write-Host "R5b: first powershell.exe as srt-sandbox took $([int]$sw.Elapsed.TotalSeconds)s"
  if ($r.out -notmatch 'CONNECTED') {
    throw "R5b: loopback to in-range port $portInR did not succeed. raw: $($r.raw)"
  }
  Write-Host "R5b ok: in-range loopback permitted for srt-sandbox (port=$portInR)"
} finally {
  $inRangeR.Stop()
}

# ── R5c: out-of-range loopback blocked ───────────────────────────
$outRange = Bind-Listener (50000, 50001, 50002, 49999)
$portOut  = $outRange.LocalEndpoint.Port
try {
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command',
    "try { `$c = New-Object Net.Sockets.TcpClient; `$c.Connect('127.0.0.1', $portOut); Write-Output CONNECTED } " +
    "catch { Write-Output blocked }")
  if ($r.out -match 'CONNECTED') {
    throw "R5c: loopback to out-of-range port $portOut succeeded. raw: $($r.raw)"
  }
  # Sanity: prove the listener was actually live (reachable from
  # the unsandboxed broker), so a False isn't just "port closed".
  $bs = (Test-NetConnection 127.0.0.1 -Port $portOut `
         -WarningAction SilentlyContinue).TcpTestSucceeded
  if (-not $bs) {
    throw "R5c: broker-side connect to its own listener on " +
          "$portOut failed — test invalid"
  }
  Write-Host "R5c ok: loopback to out-of-range port $portOut blocked"
} finally {
  $outRange.Stop()
}

# ── R5d: IPv6 loopback out-of-range blocked ──────────────────────
# The WFP fence must cover the v6 layers too: a v4-only filter set
# would leave [::1] as a silent hole to every local service. Real
# listener on [::1], child connect must be denied (an
# AccessDenied/timeout, never a successful connect).
# Ephemeral, not a fixed port: a bind inside one of Windows' per-machine
# excluded port ranges fails with WSAEACCES. Re-draw if the OS hands out a
# port inside the permit range.
do {
  $v6l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::IPv6Loopback, 0)
  $v6l.Start()
  $portV6 = $v6l.LocalEndpoint.Port
  $inPermit = $portV6 -ge $PortLo -and $portV6 -le $PortHi
  if ($inPermit) { $v6l.Stop() }
} while ($inPermit)
try {
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command',
    "try { `$c = New-Object Net.Sockets.TcpClient([Net.Sockets.AddressFamily]::InterNetworkV6); " +
    "`$c.Connect('::1', $portV6); Write-Output CONNECTED } catch { Write-Output blocked }")
  if ($r.out -match 'CONNECTED') {
    throw "R5d: sandboxed connect to [::1]:$portV6 succeeded — v6 fence hole. raw: $($r.raw)"
  }
  Write-Host 'R5d ok: IPv6 loopback out-of-range blocked'
} finally {
  $v6l.Stop()
}

# ── R5e: loopback ALIAS (127.0.0.2) out-of-range blocked ─────────
# 127.0.0.0/8 is all loopback; a filter keyed on 127.0.0.1 alone
# would leave every other alias open. No listener needed — the
# discriminating signal is AccessDenied (WFP) vs ConnectionRefused
# (no filter, nothing listening).
$r = RExec @('--', $pwsh, '-NoProfile', '-Command',
  "try { `$c = New-Object Net.Sockets.TcpClient; `$c.Connect('127.0.0.2', 49998); Write-Output CONNECTED } " +
  "catch { Write-Output ('code=' + `$_.Exception.InnerException.SocketErrorCode) }")
if ($r.out -match 'CONNECTED') {
  throw "R5e: sandboxed connect to 127.0.0.2 succeeded. raw: $($r.raw)"
}
if ($r.out -notmatch 'AccessDenied') {
  throw "R5e: expected AccessDenied (WFP block), got: $($r.raw)"
}
Write-Host 'R5e ok: loopback alias 127.0.0.2 blocked by the fence'

# ── R5g/R5h: connects made while impersonating the anonymous token ──
# The identity the filters check is the connecting THREAD's effective
# token. After ImpersonateAnonymousToken that is ANONYMOUS LOGON,
# which the block-user filter does not match; the block-anonymous
# filter refuses it for every destination outside loopback.
#
# One C# method does socket -> impersonate -> connect -> revert on a
# single thread, with the socket created BEFORE the impersonation and
# the connect made through ws2_32 directly, so nothing but the connect
# itself runs under the anonymous token. It prints one line per
# attempt: CONNECTED, WSA:<code> (10013 = refused by a filter, 10061 =
# refused by the destination, i.e. it got past the filters), or
# IMPERSONATE_FAILED:<gle>.
function AnonProbeScript {
  param([string] $Ip, [int] $Port)
  return @"
`$src = @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
public static class SrtAnon {
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateAnonymousToken(IntPtr thread);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("ws2_32.dll", SetLastError=true)] static extern int connect(IntPtr s, byte[] name, int len);
  public static string Go(string ip, int port, bool anonymous) {
    byte[] a = IPAddress.Parse(ip).GetAddressBytes();
    byte[] sa = new byte[16];
    sa[0] = 2; sa[2] = (byte)(port >> 8); sa[3] = (byte)(port & 0xff);
    Array.Copy(a, 0, sa, 4, 4);
    using (Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
      if (anonymous && !ImpersonateAnonymousToken(GetCurrentThread()))
        return "IMPERSONATE_FAILED:" + Marshal.GetLastWin32Error();
      int rc = connect(s.Handle, sa, sa.Length);
      int err = Marshal.GetLastWin32Error();
      if (anonymous) RevertToSelf();
      return rc == 0 ? "CONNECTED" : "WSA:" + err;
    }
  }
}
'@
Add-Type -TypeDefinition `$src
'PLAIN=' + [SrtAnon]::Go('$Ip', $Port, `$false)
'ANON=' + [SrtAnon]::Go('$Ip', $Port, `$true)
"@
}

# R5g: off-loopback. The destination is one of this runner's own
# addresses with a live listener, so "not blocked" would be an actual
# connect rather than a timeout.
$lanIp = (Get-NetIPAddress -AddressFamily IPv4 -ea SilentlyContinue |
  Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
  Select-Object -First 1).IPAddress
if (-not $lanIp) {
  Write-Host 'R5g SKIPPED: runner has no off-loopback IPv4 address'
} else {
  $lanLsn = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($lanIp), 0)
  $lanLsn.Start()
  $lanPort = $lanLsn.LocalEndpoint.Port
  try {
    # Sanity: the listener is live from the unsandboxed broker.
    $bs = (Test-NetConnection $lanIp -Port $lanPort `
           -WarningAction SilentlyContinue).TcpTestSucceeded
    if (-not $bs) { throw "R5g: broker-side connect to ${lanIp}:$lanPort failed - test invalid" }
    $r = RExec @('--', $pwsh, '-NoProfile', '-Command', (AnonProbeScript $lanIp $lanPort))
    Write-Host "R5g probe output (${lanIp}:$lanPort): $($r.out.Trim() -replace '\s+',' ')"
    if ($r.out -notmatch 'PLAIN=WSA:10013') {
      throw "R5g: plain connect to ${lanIp}:$lanPort expected WSA:10013 (block-user). raw: $($r.raw)"
    }
    if ($r.out -match 'ANON=(CONNECTED|WSA:10061)') {
      throw "R5g: connect to ${lanIp}:$lanPort while impersonating anonymous was NOT blocked - " +
            "block-anonymous not in effect. raw: $($r.raw)"
    }
    if ($r.out -match 'ANON=IMPERSONATE_FAILED:(\d+)') {
      # The restricted child may be refused the anonymous token
      # outright. Then this route does not exist from inside exec;
      # the filter itself is still shown by V1b (unrestricted runner).
      Write-Host "R5g ok: child could not impersonate anonymous (gle=$($Matches[1])); block-anonymous is shown by V1b"
    } elseif ($r.out -match 'ANON=WSA:10013') {
      Write-Host 'R5g ok: off-loopback connect while impersonating anonymous blocked (WSA:10013)'
    } else {
      throw "R5g: expected ANON=WSA:10013. raw: $($r.raw)"
    }
  } finally {
    $lanLsn.Stop()
  }
}

# R5h: the same to an out-of-range LOOPBACK listener. No filter covers
# a loopback connect made while impersonating anonymous, so this row
# RECORDS what happens instead of asserting it: a connect is the
# documented residual. Only the plain half is asserted (R5c's result,
# through this probe).
$anonLb = Bind-Listener (50003, 50004, 50005, 49997)
$anonLbPort = $anonLb.LocalEndpoint.Port
try {
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command', (AnonProbeScript '127.0.0.1' $anonLbPort))
  Write-Host "R5h probe output (127.0.0.1:$anonLbPort): $($r.out.Trim() -replace '\s+',' ')"
  if ($r.out -notmatch 'PLAIN=WSA:10013') {
    throw "R5h: plain connect to out-of-range loopback expected WSA:10013. raw: $($r.raw)"
  }
  if ($r.out -notmatch 'ANON=(\S+)') { throw "R5h: no ANON result. raw: $($r.raw)" }
  $anonLbResult = $Matches[1]
  if ($anonLbResult -eq 'CONNECTED') {
    Write-Host "R5h residual (documented): out-of-range loopback connect while impersonating anonymous CONNECTED"
  } else {
    Write-Host "R5h: out-of-range loopback connect while impersonating anonymous -> $anonLbResult (residual not observed)"
  }
} finally {
  $anonLb.Stop()
}

# ── R5i: a lowered-integrity copy of the child's own token ──────────
# The same question as V1c, asked from inside a sandboxed command. A
# process may lower the integrity level of a copy of its own token
# without any privilege and impersonate it; the copy still carries the
# sandbox account's SID, so block-user must refuse a connect made
# under it.
#
# One C# method does socket -> duplicate token -> set integrity level
# -> impersonate -> connect -> revert on a single thread, with the
# socket created BEFORE the impersonation and the connect made through
# ws2_32 directly. It prints one line per attempt: CONNECTED,
# WSA:<code> (10013 = refused by a filter, 10061 = refused by the
# destination, i.e. it got past the filters), or
# TOKEN_FAILED:<step>:<code> when the lowered token could not be
# assumed (for the `level` step the code is the impersonation level
# the thread ended up with, otherwise the Win32 error).
function LoweredIntegrityProbeScript {
  param([string] $Ip, [int] $Port)
  return @"
`$src = @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
public static class SrtLowIl {
  [StructLayout(LayoutKind.Sequential)] struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
  [StructLayout(LayoutKind.Sequential)] struct TokenMandatoryLabel { public SidAndAttributes Label; }
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenThreadToken(IntPtr thread, uint access, bool openAsSelf, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attrs, int level, int type, out IntPtr dup);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool ConvertStringSidToSidW(string sid, out IntPtr psid);
  [DllImport("advapi32.dll")] static extern int GetLengthSid(IntPtr sid);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool SetTokenInformation(IntPtr token, int cls, ref TokenMandatoryLabel info, int len);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int cls, out int info, int len, out int ret);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool SetThreadToken(IntPtr thread, IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
  [DllImport("ws2_32.dll", SetLastError=true)] static extern int connect(IntPtr s, byte[] name, int len);
  static string Fail(string step) { return "TOKEN_FAILED:" + step + ":" + Marshal.GetLastWin32Error(); }
  // Impersonate a copy of the process token at the integrity level
  // named by sid. Returns null on success.
  static string Assume(string sid) {
    IntPtr own = IntPtr.Zero, dup = IntPtr.Zero, psid = IntPtr.Zero, cur = IntPtr.Zero;
    try {
      // TOKEN_DUPLICATE | TOKEN_QUERY
      if (!OpenProcessToken(GetCurrentProcess(), 0x000A, out own)) return Fail("open");
      // TOKEN_ALL_ACCESS, SecurityImpersonation, TokenImpersonation
      if (!DuplicateTokenEx(own, 0xF01FF, IntPtr.Zero, 2, 2, out dup)) return Fail("duplicate");
      if (!ConvertStringSidToSidW(sid, out psid)) return Fail("sid");
      TokenMandatoryLabel tml = new TokenMandatoryLabel();
      tml.Label.Sid = psid;
      tml.Label.Attributes = 0x20; // SE_GROUP_INTEGRITY
      // 25 = TokenIntegrityLevel
      if (!SetTokenInformation(dup, 25, ref tml, Marshal.SizeOf(tml) + GetLengthSid(psid))) return Fail("set-integrity");
      if (!SetThreadToken(IntPtr.Zero, dup)) return Fail("impersonate");
      // The thread must really be impersonating: a token left at
      // identification level would make the connect say nothing.
      int level, ret;
      // TOKEN_QUERY; 9 = TokenImpersonationLevel
      if (!OpenThreadToken(GetCurrentThread(), 0x0008, true, out cur)) { string f = Fail("open-thread"); RevertToSelf(); return f; }
      if (!GetTokenInformation(cur, 9, out level, 4, out ret)) { string f = Fail("query-level"); RevertToSelf(); return f; }
      if (level < 2) { RevertToSelf(); return "TOKEN_FAILED:level:" + level; }
      return null;
    } finally {
      if (cur != IntPtr.Zero) CloseHandle(cur);
      if (psid != IntPtr.Zero) LocalFree(psid);
      if (dup != IntPtr.Zero) CloseHandle(dup);
      if (own != IntPtr.Zero) CloseHandle(own);
    }
  }
  // An empty integritySid connects under the process's own token.
  public static string Go(string ip, int port, string integritySid) {
    bool lowered = !String.IsNullOrEmpty(integritySid);
    byte[] a = IPAddress.Parse(ip).GetAddressBytes();
    byte[] sa = new byte[16];
    sa[0] = 2; sa[2] = (byte)(port >> 8); sa[3] = (byte)(port & 0xff);
    Array.Copy(a, 0, sa, 4, 4);
    using (Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
      if (lowered) {
        string failed = Assume(integritySid);
        if (failed != null) return failed;
      }
      int rc = connect(s.Handle, sa, sa.Length);
      int err = Marshal.GetLastWin32Error();
      if (lowered) RevertToSelf();
      return rc == 0 ? "CONNECTED" : "WSA:" + err;
    }
  }
}
'@
Add-Type -TypeDefinition `$src
'PLAIN=' + [SrtLowIl]::Go('$Ip', $Port, '')
'LOW=' + [SrtLowIl]::Go('$Ip', $Port, 'S-1-16-4096')
'UNTRUSTED=' + [SrtLowIl]::Go('$Ip', $Port, 'S-1-16-0')
"@
}

# The destination is an out-of-range loopback listener, live from the
# broker, so "not blocked" is an actual connect.
$lowIlLsn = Bind-Listener (50006, 50007, 50008, 49996)
$lowIlPort = $lowIlLsn.LocalEndpoint.Port
try {
  $bs = (Test-NetConnection 127.0.0.1 -Port $lowIlPort `
         -WarningAction SilentlyContinue).TcpTestSucceeded
  if (-not $bs) { throw "R5i: broker-side connect to 127.0.0.1:$lowIlPort failed - test invalid" }
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command', (LoweredIntegrityProbeScript '127.0.0.1' $lowIlPort))
  Write-Host "R5i probe output (127.0.0.1:$lowIlPort): $($r.out.Trim() -replace '\s+',' ')"
  if ($r.out -notmatch 'PLAIN=WSA:10013') {
    throw "R5i: plain connect to out-of-range loopback expected WSA:10013 (block-user). raw: $($r.raw)"
  }
  foreach ($shape in 'LOW','UNTRUSTED') {
    if ($r.out -notmatch "(?m)^$shape=(\S+)") { throw "R5i: no $shape result. raw: $($r.raw)" }
    $got = $Matches[1]
    if ($got -in 'CONNECTED','WSA:10061') {
      throw "R5i: BYPASS - connect under a $shape-integrity copy of the sandboxed child's token was NOT blocked " +
            "($shape=$got); block-user does not match that token. raw: $($r.raw)"
    } elseif ($got -like 'TOKEN_FAILED:*') {
      # Not a block: the child could not assume the token, so this
      # route was not exercised from inside exec. The filter's answer
      # for this shape is V1c's (unrestricted runner).
      Write-Host "R5i NOT EXERCISED: child could not assume the $shape-integrity token ($got); see V1c"
    } elseif ($got -eq 'WSA:10013') {
      Write-Host "R5i ok: connect under a $shape-integrity copy of the child's token blocked (WSA:10013)"
    } else {
      throw "R5i: expected $shape=WSA:10013, got '$got'. raw: $($r.raw)"
    }
  }
} finally {
  $lowIlLsn.Stop()
}

# ── R5f: non-interactive logon types refused for the sandbox account ─
# The SMB redirector dials from kernel mode as SYSTEM, so the
# SID-keyed WFP fence never sees its connects; the fix denies the
# sandbox group every logon type except interactive. LOOPBACK SMB is
# exempt by NTLM loopback-session reuse (no new logon occurs), so the
# CI-provable check is LogonUser itself: type NETWORK/BATCH/SERVICE
# must refuse with 1385 (what any remote server's LSA runs at SMB
# session setup), INTERACTIVE must stay granted (the
# CreateProcessWithLogonW launch depends on it).
$pwPlain = (& $Exe user read-cred).Trim()
if ($LASTEXITCODE -ne 0 -or -not $pwPlain) { throw 'R5f: read-cred failed' }
$lsig = '[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool LogonUserW(string u, string d, string p, uint type, uint prov, out IntPtr tok);'
$lt = Add-Type -MemberDefinition $lsig -Name R5fLogon -Namespace Srt -PassThru
$sbUser = ((& $Exe user status | ConvertFrom-Json).user.name)
foreach ($probe in @(@{n='NETWORK'; t=3; want=$false}, @{n='BATCH'; t=4; want=$false}, @{n='SERVICE'; t=5; want=$false}, @{n='INTERACTIVE'; t=2; want=$true})) {
  $tok = [IntPtr]::Zero
  $ok = [Srt.R5fLogon]::LogonUserW($sbUser, '.', $pwPlain, [uint32]$probe.t, 0, [ref]$tok)
  $gle = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if ($probe.want -and -not $ok) { throw "R5f: $($probe.n) logon REFUSED (gle=$gle) - launch path broken" }
  if (-not $probe.want -and $ok) { throw "R5f: $($probe.n) logon GRANTED - logon-type denial not in effect" }
  if (-not $probe.want -and $gle -ne 1385) { Write-Host "R5f note: $($probe.n) refused with gle=$gle (expected 1385; still refused)" }
}
$pwPlain = $null
Write-Host 'R5f ok: network/batch/service logons refused (1385), interactive granted'

# ── R6: child cannot read the credential key (sandbox DENY) ──────
# The Cred subkey's DACL is the load-bearing gate: machine-scope
# DPAPI means readable = decryptable, and a child that learned its
# own password could CreateProcessWithLogonW itself a fresh logon
# session outside the job/desktop confinement.
$r = RExec @('--', $cmd, '/c', 'reg query HKLM\SOFTWARE\sandbox-runtime\Cred /v Blob')
if ($r.exit -eq 0) {
  throw "R6: child READ the Cred registry key (DENY not in effect?). raw: $($r.raw)"
}
if ($r.raw -notmatch '(?i)access is denied|denied') {
  throw "R6: expected Access is denied. raw: $($r.raw)"
}
Write-Host 'R6 ok: child cannot read the Cred registry key'

# ── R7: cmd.exe /c passthrough — user-quoted payload survives ───
# build_cmdline wraps the post-/c content in ONE outer "…" pair
# for /s to strip; inner content is verbatim. The `&` is inside
# the user's own "…" so cmd treats it literally.
$r = RExec @('--', $cmd, '/d', '/s', '/c', 'echo "x & y"')
if ($r.exit -ne 0) { throw "R7 exited $($r.exit): $($r.out)" }
$got = $r.out.Trim()
if ($got -ne '"x & y"') {
  throw "R7: expected literal '`"x & y`"', got '$got'"
}
Write-Host 'R7 ok: user-quoted payload passes through verbatim'

# ── R7b: cmd metachar passthrough — `&` works as separator ──────
$r = RExec @('--', $cmd, '/d', '/s', '/c', 'echo MARKER & exit 5')
if ($r.exit -ne 5) {
  throw "R7b: expected exit 5 from chained command, got $($r.exit). " +
        "out: $($r.out)"
}
if ($r.out.Trim() -notlike 'MARKER*') {
  throw "R7b: expected MARKER in output. out: $($r.out)"
}
Write-Host 'R7b ok: & chains commands inside sandboxed cmd (passthrough)'

# ── R7c: target_is_cmd recognises trailing-dot cmd.exe. ──────────
$r = RExec @('--', "$cmd.", '/d', '/s', '/c', 'echo MARKER & exit 5')
if ($r.exit -ne 5 -or $r.out.Trim() -notlike 'MARKER*') {
  throw "R7c: trailing-dot cmd.exe. did NOT take the cmd-quoting " +
        "branch (target_is_cmd trim missing). exit=$($r.exit) " +
        "out: $($r.out)"
}
Write-Host 'R7c ok: target_is_cmd recognises trailing-dot cmd.exe.'

# ── R9: child cannot OpenProcess(PROCESS_CREATE_PROCESS) on a ────
#        real-user process (cross-user boundary)
# ── R9b: child cannot OpenProcess(PROCESS_CREATE_PROCESS) on the ─
#        RUNNER (runner self-protect — would let the child
#        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS-spawn under the
#        runner's unrestricted token and escape job/winsta/mitigations)
$hostPid = $PID
$probeR9 = @"
`$sig = '[DllImport("kernel32.dll",SetLastError=true)]public static extern System.IntPtr OpenProcess(uint a,bool b,uint p);'
`$k32 = Add-Type -MemberDefinition `$sig -Name K32R -Namespace W -PassThru
function Probe([string]`$tag, [int]`$targetPid) {
  # 0x0080 = PROCESS_CREATE_PROCESS
  `$h = `$k32::OpenProcess(0x0080, `$false, `$targetPid)
  `$le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if (`$h -ne [System.IntPtr]::Zero) { "OPENED:`$tag pid=`$targetPid" }
  elseif (`$le -eq 5)                { "DENIED:`$tag pid=`$targetPid" }
  else                               { "OTHER:`$tag pid=`$targetPid le=`$le" }
}
`$rp = 0
`$cur = `$PID
for (`$i = 0; `$i -lt 8; `$i++) {
  `$p = Get-CimInstance Win32_Process -Filter "ProcessId=`$cur" -ea SilentlyContinue
  if (-not `$p) { break }
  if (`$p.Name -eq 'srt-win.exe') { `$rp = [int]`$p.ProcessId; break }
  if (-not `$p.ParentProcessId) { break }
  `$cur = `$p.ParentProcessId
}
Probe 'real-user' $hostPid
if (`$rp -eq 0) { 'NORUNNER' } else { Probe 'runner' `$rp }
"@
$r = RExec @('--', $pwsh, '-NoProfile', '-Command', $probeR9)
Write-Host "R9 probe output: $($r.out.Trim())"
if ($r.out -match 'OPENED:real-user') {
  throw "R9: child got PROCESS_CREATE_PROCESS on a real-user " +
        "process (cross-user boundary breached). raw: $($r.raw)"
}
if ($r.out -notmatch 'DENIED:real-user') {
  throw "R9: expected ACCESS_DENIED for real-user target. raw: $($r.raw)"
}
Write-Host 'R9 ok: child denied PROCESS_CREATE_PROCESS on real-user process'
if ($r.out -match 'NORUNNER') {
  throw "R9b: runner discovery failed. raw: $($r.raw)"
}
if ($r.out -match 'OPENED:runner') {
  throw "R9b: child got PROCESS_CREATE_PROCESS on the runner " +
        "(runner self-protect ineffective — sandbox escape). raw: $($r.raw)"
}
if ($r.out -notmatch 'DENIED:runner') {
  throw "R9b: expected ACCESS_DENIED for runner target. raw: $($r.raw)"
}
Write-Host 'R9b ok: child denied PROCESS_CREATE_PROCESS on the runner (self-protect holds)'

# ── R11: child cannot OpenProcess(PROCESS_VM_READ) on a default-DACL ──
#         real-user process (logon-SID strip).
# seclogon stamps the broker's interactive logon SID into the
# runner's token; CreateRestrictedToken disables it so the child
# does NOT match the default per-process logon-session ACE
# (VM_READ|QUERY|TERMINATE) on same-session real-user processes.
# Without the strip the child can ReadProcessMemory the broker's
# browser/shell/host orchestrator. Spawn a fresh victim under the
# broker user so the target is unambiguously default-DACL (no
# harness side effects on its SD).
$victim = Start-Process -FilePath $cmd -ArgumentList '/c','timeout /t 60 >nul' `
            -PassThru -WindowStyle Hidden
try {
  $probeR11 = @"
`$sig = '[DllImport("kernel32.dll",SetLastError=true)]public static extern System.IntPtr OpenProcess(uint a,bool b,uint p);'
`$k32 = Add-Type -MemberDefinition `$sig -Name K32V -Namespace W -PassThru
function Probe([string]`$tag, [uint32]`$mask) {
  `$h = `$k32::OpenProcess(`$mask, `$false, $($victim.Id))
  `$le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if (`$h -ne [System.IntPtr]::Zero) { "OPENED:`$tag" }
  elseif (`$le -eq 5)                { "DENIED:`$tag" }
  else                               { "OTHER:`$tag le=`$le" }
}
# 0x0010 = PROCESS_VM_READ; 0x1000 = PROCESS_QUERY_LIMITED_INFORMATION
Probe 'vm-read'  0x0010
Probe 'query-li' 0x1000
"@
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command', $probeR11)
  Write-Host "R11 probe output: $($r.out.Trim())"
  if ($r.out -match 'OPENED:vm-read') {
    throw "R11: child got PROCESS_VM_READ on a default-DACL " +
          "real-user process (logon-SID not stripped — child " +
          "can ReadProcessMemory the broker's session). raw: $($r.raw)"
  }
  if ($r.out -notmatch 'DENIED:vm-read') {
    throw "R11: expected ACCESS_DENIED for VM_READ. raw: $($r.raw)"
  }
  if ($r.out -match 'OPENED:query-li') {
    throw "R11: child got PROCESS_QUERY_LIMITED_INFORMATION on a " +
          "default-DACL real-user process. raw: $($r.raw)"
  }
  if ($r.out -notmatch 'DENIED:query-li') {
    throw "R11: expected ACCESS_DENIED for QUERY_LIMITED. raw: $($r.raw)"
  }
  Write-Host ('R11 ok: child denied VM_READ + QUERY_LIMITED on ' +
              'default-DACL real-user process (logon-SID stripped)')
} finally {
  try { $victim.Kill() } catch { }
}

# ── R12: child is on the broker-created srt-sb-* desktop ─────────
# The broker creates `WinSta0\srt-sb-<pid>-<rand>` and passes it via
# CreateProcessWithLogonW's lpDesktop; the runner attaches there and
# the lockdown child inherits. If the child reports `Default`, the
# fail-closed assertion in run_lockdown was bypassed and the child
# can WH_KEYBOARD_LL-hook the interactive desktop (the Job's UI
# limits do NOT gate low-level hooks). The child's own
# GetThreadDesktop name is the substantive check (the runner's
# `caller_desk=` debug line is gated on SANDBOX_RUNTIME_WIN_DEBUG
# in the RUNNER's env, which isn't in the --env overlay).
$probeR12 = @"
`$sig = @'
[DllImport("user32.dll")]public static extern System.IntPtr GetThreadDesktop(uint t);
[DllImport("kernel32.dll")]public static extern uint GetCurrentThreadId();
[DllImport("user32.dll",CharSet=CharSet.Unicode)]public static extern bool GetUserObjectInformationW(System.IntPtr h,int i,System.Text.StringBuilder b,uint n,out uint r);
'@
`$u = Add-Type -MemberDefinition `$sig -Name U32D -Namespace W -PassThru
`$d = `$u::GetThreadDesktop(`$u::GetCurrentThreadId())
`$sb = [System.Text.StringBuilder]::new(256); `$r = 0
[void]`$u::GetUserObjectInformationW(`$d, 2, `$sb, 512, [ref]`$r)
"CHILD_DESK=" + `$sb.ToString()
"@
$r = RExec @('--', $pwsh, '-NoProfile', '-Command', $probeR12)
Write-Host "R12 probe output: $($r.out.Trim())"
if ($r.out -notmatch 'CHILD_DESK=srt-sb-') {
  throw "R12: child not on srt-sb-* desktop — desktop isolation " +
        "broken (WH_KEYBOARD_LL keylogging risk). raw: $($r.raw)"
}
if ($r.out -match 'CHILD_DESK=Default') {
  throw "R12: child on Default desktop. raw: $($r.raw)"
}
Write-Host 'R12 ok: child on broker-created srt-sb-* desktop (not Default)'

# ── G-rows: per-session FS access for the sandbox user ──────────
# The sandbox child has NO inherent rights on real-user-owned
# files. `acl grant` adds an inheritable MODIFY_NO_FDC ALLOW ACE
# for <sb-SID> on the working-tree root; `acl stamp
# --sandbox-user-sid <sb>` adds an additive (D;OICI;mask;;;<sb>)
# DENY ACE on a path inside it (plus a parent-FDC DENY). The
# G-rows are the design probe: with grant on the root + DENY on a
# file inside, the child reads siblings but not the denied file
# AND cannot del/ren it (the grant lacks FDC and the parent
# carries an explicit FDC DENY for <sb-SID>).
$gRoot = Join-Path $env:TEMP "srt-gscratch-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $gRoot -Force | Out-Null
# Expand to the long-form path: $env:TEMP on the GHA runner is
# `C:\Users\RUNNER~1\...` (8.3 short name). The grant lands on the
# canonical (long-form) file object regardless, but the CHILD opens
# by the path we pass it — and resolving an 8.3 component requires
# enumerating the parent dir, which srt-sandbox cannot do for the
# real user's profile. Passing the long form lets bypass-traverse
# (SeChangeNotifyPrivilege) reach the file directly without an
# enumerate step.
$k32 = Add-Type -PassThru -Namespace W -Name K -MemberDefinition `
  '[DllImport("kernel32.dll",CharSet=CharSet.Unicode)] public static extern uint GetLongPathName(string s,System.Text.StringBuilder l,uint n);'
$lp  = [System.Text.StringBuilder]::new(1024)
if ($k32::GetLongPathName($gRoot, $lp, 1024) -gt 0) { $gRoot = $lp.ToString() }
$gSub  = Join-Path $gRoot  'sub'
New-Item -ItemType Directory -Path $gSub -Force | Out-Null
$secret  = Join-Path $gSub 'secret.txt'
$sibling = Join-Path $gSub 'sibling.txt'
$subDeny = Join-Path $gRoot 'sub-deny'
New-Item -ItemType Directory -Path $subDeny | Out-Null
$inDeny  = Join-Path $subDeny 'inner.txt'
$inAllow = Join-Path $subDeny 'reallow.txt'
# NOT -NoNewline: RExec concatenates child stdout + broker stderr
# before line-splitting, so a no-newline file body would fuse with
# the first `srt-win:` diag line and survive the `^srt-win:` filter.
'SECRET'  | Set-Content -Encoding ASCII $secret
'SIBLING' | Set-Content -Encoding ASCII $sibling
'INNER'   | Set-Content -Encoding ASCII $inDeny
'REALLOW' | Set-Content -Encoding ASCII $inAllow
Write-Host "G: scratch=$gRoot  sbSid=$sbSid"
function Stdin { param([string[]] $argv, [string] $json)
  $raw = $json | & $Exe @argv 2>&1 | Out-String
  Write-Host -NoNewline $raw
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited ${LASTEXITCODE}: $raw"
  }
}

try {
  # ── G1: working-tree grant — child can list/read/write inside ────
  Stdin @('acl','grant','--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"write`":[`"$($gRoot -replace '\\','\\')`"]}"
  $r = RExec @('--', $cmd, '/c', "type `"$sibling`"")
  if ($r.exit -ne 0 -or $r.out -notmatch 'SIBLING') {
    throw "G1: child read sibling failed. exit=$($r.exit) raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "echo G1-NEW> `"$gSub\new.txt`"")
  if ($r.exit -ne 0 -or -not (Test-Path "$gSub\new.txt")) {
    throw "G1: child write under granted tree failed. raw: $($r.raw)"
  }
  Write-Host 'G1 ok: working-tree MODIFY_NO_FDC grant — child reads + creates inside'

  # ── G2: DENY ACE inside the grant — read denied ──────────────────
  Stdin @('acl','stamp','--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"denyRead`":[`"$($secret -replace '\\','\\')`"]}"
  $r = RExec @('--', $cmd, '/c', "type `"$secret`"")
  if ($r.exit -eq 0 -or $r.out -match 'SECRET') {
    throw "G2: child READ the stamped file. raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "type `"$sibling`"")
  if ($r.out -notmatch 'SIBLING') {
    throw "G2: sibling no longer readable post-stamp. raw: $($r.raw)"
  }
  Write-Host 'G2 ok: DENY ACE + working-tree grant compose — sibling readable, stamped file denied'

  # ── G3: parent-FDC DENY — child cannot del/ren the stamped file ──
  # The stamp adds (D;OICI;FILE_DELETE_CHILD;;;<sb-SID>) on the
  # parent; explicit DENY is evaluated first, so even where the
  # parent inherits an allow-FDC the child has no path through it.
  $r = RExec @('--', $cmd, '/c', "del `"$secret`"")
  if (-not (Test-Path $secret) -or
      (Get-Content -Raw $secret).Trim() -ne 'SECRET') {
    throw "G3: child deleted/altered the stamped file (parent-FDC DENY did not take). raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "ren `"$secret`" gone.txt")
  if (-not (Test-Path $secret) -or (Test-Path "$gSub\gone.txt")) {
    throw "G3: child renamed the stamped file. raw: $($r.raw)"
  }
  Write-Host 'G3 ok: parent-FDC DENY ACE — child cannot del/ren the stamped file'

  # ── G3b: parent-FDC DENY overrides BUILTIN\Users:FA on parent ────
  # The sandbox user is a Users member; without the explicit DENY a
  # parent with Users:(F) would give it FILE_DELETE_CHILD directly
  # (the C:\ProgramData case). The DENY ACE is evaluated before
  # any ALLOW, so the deny still holds.
  $g3bDir  = Join-Path $gRoot 'g3b'
  New-Item -ItemType Directory -Path $g3bDir | Out-Null
  & icacls $g3bDir /grant '*S-1-5-32-545:(OI)(CI)(F)' | Out-Null
  $g3bFile = Join-Path $g3bDir 'sec.txt'
  'G3B' | Set-Content -Encoding ASCII $g3bFile
  Stdin @('acl','stamp','--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"denyRead`":[`"$($g3bFile -replace '\\','\\')`"]}"
  $r = RExec @('--', $cmd, '/c', "del `"$g3bFile`"")
  if (-not (Test-Path $g3bFile) -or
      (Get-Content -Raw $g3bFile).Trim() -ne 'G3B') {
    throw "G3b: child deleted file under Users:FA parent (DENY did not override). raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "type `"$g3bFile`"")
  if ($r.exit -eq 0 -or $r.out -match 'G3B') {
    throw "G3b: child READ file under Users:FA parent. raw: $($r.raw)"
  }
  Write-Host 'G3b ok: parent-FDC DENY overrides inherited BUILTIN\Users:(F) on parent'

  # ── G4: broker (real user) can still read the stamped file ───────
  if ((Get-Content -Raw $secret).Trim() -ne 'SECRET') {
    throw 'G4: broker lost read on the stamped file'
  }
  Write-Host 'G4 ok: real-user trustee keeps full access to stamped file'

  # ── G5: directory deny — (OI)(CI) DENY ACE covers the subtree; ───
  # allowWithinDeny via grant on an inner file.
  Stdin @('acl','stamp','--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"denyRead`":[`"$($subDeny -replace '\\','\\')`"]}"
  Stdin @('acl','grant','--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"read`":[`"$($inAllow -replace '\\','\\')`"]}"
  # Instrumentation: dump exactly what landed on the inner file
  # post dir-stamp + inner-grant. The icacls/SDDL pair shows the
  # explicit srt-sandbox ALLOW ACE alongside the inherited DENY
  # ACE; the child-side `if exist` tells us whether
  # bypass-traverse through the denied dir works. Kept on the
  # success path too — the dump is the proof for the design claim
  # (explicit ALLOW is evaluated before inherited DENY).
  Write-Host "G5 diag: icacls $inAllow ->"
  & icacls $inAllow
  Write-Host "G5 diag: inAllow Sddl=$((Get-Acl $inAllow).Sddl)"
  Write-Host "G5 diag: subDeny Sddl=$((Get-Acl $subDeny).Sddl)"
  $r = RExec @('--', $cmd, '/c',
    "whoami /priv | findstr /i SeChangeNotify")
  Write-Host "G5 diag: child SeChangeNotify=$($r.out)"
  $r = RExec @('--', $cmd, '/c', "type `"$inDeny`"")
  if ($r.exit -eq 0 -or $r.out -match 'INNER') {
    throw "G5: child read file under denied dir. raw: $($r.raw)"
  }
  # Combined probe: echo the path the child sees + if-exist +
  # type-via-builtin + read-via-stdin-redirect (cmd's `<` is a
  # direct CreateFileW(GENERIC_READ) — bypasses any extra path
  # checks `type` might do). Everything goes through one RExec so
  # the throw carries it all.
  $r = RExec @('--', $cmd, '/c',
    ("echo PATH=$inAllow & " +
     "if exist `"$inAllow`" (echo IFEXIST=YES) else (echo IFEXIST=NO) & " +
     "type `"$inAllow`" 2>&1 & echo --- & " +
     "more < `"$inAllow`" 2>&1"))
  if ($r.out -notmatch 'REALLOW') {
    throw ("G5: allowWithinDeny grant on inner file did not take " +
           "effect.`n  child raw: $($r.raw)`n  " +
           "inAllow Sddl: $((Get-Acl $inAllow).Sddl)`n  " +
           "subDeny Sddl: $((Get-Acl $subDeny).Sddl)")
  }
  $r = RExec @('--', $cmd, '/c', "type `"$sibling`"")
  if ($r.out -notmatch 'SIBLING') {
    throw "G5: sibling-of-denied-dir lost access. raw: $($r.raw)"
  }
  Write-Host 'G5 ok: dir-deny (OI)(CI) covers subtree; sibling unaffected; inner grant overrides'

  # ── G6: revoke + restore — child loses access; DACLs round-trip ──
  Run @('acl','revoke','--holder-pid',$PID,
        '--sandbox-user-sid',$sbSid)
  Run @('acl','restore','--holder-pid',$PID,
        '--sandbox-user-sid',$sbSid)
  $post = (Get-Acl $gRoot).Sddl
  if ($post -match [regex]::Escape($sbSid)) {
    throw "G6: srt-sandbox ACE still present on root after revoke: $post"
  }
  $postSub = (Get-Acl $subDeny).Sddl
  if ($postSub -match [regex]::Escape($sbSid)) {
    throw "G6: srt-sandbox ACE still on dir after restore: $postSub"
  }
  $r = RExec @('--', $cmd, '/c', "type `"$sibling`"")
  if ($r.exit -eq 0) {
    throw "G6: child still reads after revoke. raw: $($r.raw)"
  }
  Write-Host 'G6 ok: revoke + restore remove all sb-user ACEs; child loses access'
} finally {
  # Best-effort: don't leak ACEs/stamps if a G-row threw mid-way.
  & $Exe acl revoke  --holder-pid $PID `
        --sandbox-user-sid $sbSid 2>&1 | Out-Null
  & $Exe acl restore --holder-pid $PID `
        --sandbox-user-sid $sbSid 2>&1 | Out-Null
  Remove-Item -Recurse -Force $gRoot -ErrorAction SilentlyContinue
}

# ── U-rows: a fence written by an earlier build ─────────────────
# An install from a build that predates the fence revision record has
# everything this one has EXCEPT the `FenceRevision` value (and the
# filters that came with it). Removing the value reproduces what the
# non-elevated broker can see of such an install — it cannot
# enumerate filters, so the record is what it goes by. The filters
# themselves are left in place: nothing in this script can delete a
# single WFP filter, so the tag-based half of `wfp status` (a set
# missing block-anonymous) is covered by the cargo unit tests only.
$regBase = 'HKLM:\SOFTWARE\sandbox-runtime'
$rev = (Get-ItemProperty $regBase -ea Stop).FenceRevision
if (-not $rev) { throw "U0: install did not record FenceRevision under $regBase" }
$st0 = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($st0.state -ne 'installed' -or $st0.filters -lt 6) {
  throw "U0: fresh install expected installed/>=6 filters, got $($st0.state)/$($st0.filters)"
}
Write-Host "U0 ok: fresh install records FenceRevision=$rev, $($st0.filters) filters"
Remove-ItemProperty $regBase -Name FenceRevision -ea Stop

# U1: status (both forms) reports the fence as out of date, with the repair.
$u1 = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($u1.state -ne 'outdated') { throw "U1: wfp status expected outdated, got '$($u1.state)'" }
if ($u1.hint -notmatch '(?i)srt-win install') { throw "U1: hint lacks the reinstall instruction: $($u1.hint)" }
$u1c = J @('status','--sublayer-guid',$Sublayer)
if ($u1c.wfp.state -ne 'outdated') { throw "U1: status .wfp expected outdated, got '$($u1c.wfp.state)'" }
Write-Host "U1 ok: status reports outdated ($($u1.hint))"

# U2: exec refuses to launch, exit 19, naming the repair.
$r = RExec @('--', $cmd, '/c', 'echo U2-RAN')
if ($r.exit -ne 19) { throw "U2: exec expected exit 19 (fence out of date), got $($r.exit). raw: $($r.raw)" }
if ($r.raw -match 'U2-RAN') { throw "U2: child RAN against an out-of-date fence. raw: $($r.raw)" }
if ($r.raw -notmatch '(?i)out of date' -or $r.raw -notmatch '(?i)srt-win install') {
  throw "U2: exec message lacks 'out of date' / reinstall hint. raw: $($r.raw)"
}
Write-Host 'U2 ok: exec exits 19 with the reinstall hint and does not launch'

# U3: wfp verify refuses likewise, before probing.
$u3Lsn = Bind-Listener (49980..49989)
$u3out = & $Exe wfp verify --target "127.0.0.1:$($u3Lsn.LocalEndpoint.Port)"
$u3exit = $LASTEXITCODE
$u3Lsn.Stop()
if ($u3exit -ne 19) { throw "U3: wfp verify expected exit 19, got $u3exit. out: $u3out" }
if (-not ($u3out | ConvertFrom-Json).outdated) { throw "U3: wfp verify output lacks outdated=true: $u3out" }
Write-Host 'U3 ok: wfp verify exits 19 (outdated)'

# U4: re-running install (same config, no --force) repairs it — it
# must not take the "already installed; no changes" early-out.
Run @('install',
      '--sublayer-guid',$Sublayer,
      '--proxy-port-range',$PortRange)
$u4 = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($u4.state -ne 'installed' -or $u4.filters -ne $st0.filters) {
  throw "U4: after reinstall expected installed/$($st0.filters) filters, got $($u4.state)/$($u4.filters)"
}
if ((Get-ItemProperty $regBase -ea Stop).FenceRevision -ne $rev) {
  throw 'U4: reinstall did not restore FenceRevision'
}
$r = RExec @('--', $cmd, '/c', 'echo U4-RAN')
if ($r.exit -ne 0 -or $r.out -notmatch 'U4-RAN') {
  throw "U4: exec after reinstall failed. exit=$($r.exit) raw: $($r.raw)"
}
Write-Host 'U4 ok: reinstall restores the fence; exec runs again'

# ── L-rows: the configured loopback port range ──────────────────
# `install --loopback-port-range` adds one PERMIT per layer: loopback
# address AND a port inside the range. The rows run the same four
# connects with no range installed (all refused), then with one
# (in-range loopback reachable on 127.0.0.1 and ::1, everything else
# still refused), and show that a session whose range differs from
# the installed one is not launched.
#
# The range sits clear of the proxy range, of every fixed port the
# rows above listen on, and of the dynamic port range (49152 and up),
# where Windows keeps its per-machine excluded ranges and hands out
# ephemeral ports. Each listener still takes the first port of its
# slice that binds.
$LbRange = '41000-41063'
$LbLo    = 41000
$LbHi    = 41063
$LbOther = '42000-42063'

# One raw TCP connect from inside the sandbox. Prints CONNECTED or
# code=<SocketErrorCode> (AccessDenied = refused by a filter).
# $ExecFlags are srt-win's own flags for this exec.
function SbConnect {
  param([string] $Address, [int] $Port, [string[]] $ExecFlags = @())
  $new = if ($Address -match ':') {
    'New-Object Net.Sockets.TcpClient([Net.Sockets.AddressFamily]::InterNetworkV6)'
  } else {
    'New-Object Net.Sockets.TcpClient'
  }
  return RExec ($ExecFlags + @('--', $pwsh, '-NoProfile', '-Command',
    "try { `$c = $new; `$c.Connect('$Address', $Port); Write-Output CONNECTED } " +
    "catch { Write-Output ('code=' + `$_.Exception.InnerException.SocketErrorCode) }"))
}
function Assert-SbRefused {
  param([string] $Row, [string] $Address, [int] $Port, [string[]] $ExecFlags = @())
  $r = SbConnect $Address $Port $ExecFlags
  if ($r.out -match 'CONNECTED') {
    throw "${Row}: sandboxed connect to ${Address}:$Port succeeded. raw: $($r.raw)"
  }
  if ($r.out -notmatch 'AccessDenied') {
    throw "${Row}: expected AccessDenied (WFP block) for ${Address}:$Port, got: $($r.raw)"
  }
}
function Assert-SbConnected {
  param([string] $Row, [string] $Address, [int] $Port, [string[]] $ExecFlags = @())
  $r = SbConnect $Address $Port $ExecFlags
  if ($r.out -notmatch 'CONNECTED') {
    throw "${Row}: sandboxed connect to ${Address}:$Port did not succeed. raw: $($r.raw)"
  }
}

# Start a sandboxed command without waiting for it. Same argv shape
# and environment as RExec; the caller reads .so/.se and waits on .p.
function RExecStart {
  param([string[]] $tail)
  $argv = @('exec',
            '--env', "PATH=$($env:PATH)",
            '--env', "PATHEXT=$($env:PATHEXT)") + $tail
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName               = $Exe
  $psi.UseShellExecute        = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.Environment['SANDBOX_RUNTIME_WIN_DEBUG'] = '1'
  foreach ($a in $argv) { $null = $psi.ArgumentList.Add($a) }
  $p = [System.Diagnostics.Process]::Start($psi)
  return [pscustomobject]@{
    p  = $p
    so = $p.StandardOutput.ReadToEndAsync()
    se = $p.StandardError.ReadToEndAsync()
  }
}

# A server started INSIDE the sandbox on 127.0.0.1:$Port, then one
# connect to it from a second sandboxed command. The server prints
# SERVED once a client is accepted, so a CONNECTED that reached
# anything else does not pass. Returns the client's output and
# whether the server accepted. Listening is not filtered, so the
# server comes up with or without a range installed.
function SbServerRoundTrip {
  param([string] $Row, [int] $Port, [string[]] $ExecFlags = @())
  $srv = RExecStart ($ExecFlags + @('--', $pwsh, '-NoProfile', '-Command',
    "`$l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port); `$l.Start(); " +
    "`$t = `$l.AcceptTcpClientAsync(); " +
    "if (`$t.Wait(240000)) { Write-Output SERVED } else { Write-Output NOCLIENT }; `$l.Stop()"))
  try {
    # Wait for the listener without connecting to it: a connect from
    # here would be the one the server is waiting to accept.
    $deadline = (Get-Date).AddSeconds(120)
    while (-not (Get-NetTCPConnection -State Listen -LocalPort $Port -ea SilentlyContinue)) {
      if ($srv.p.HasExited) {
        throw "${Row}: sandboxed server exited before listening. out: $($srv.so.Result) err: $($srv.se.Result)"
      }
      if ((Get-Date) -gt $deadline) { throw "${Row}: sandboxed server did not listen on $Port within 120s" }
      Start-Sleep -Milliseconds 250
    }
    $client = SbConnect '127.0.0.1' $Port $ExecFlags
    # A refused client leaves the server waiting; do not sit out its
    # timeout.
    $served = $false
    if ($client.out -match 'CONNECTED') {
      if (-not $srv.p.WaitForExit(60000)) { throw "${Row}: sandboxed server did not exit after a client connected" }
      $served = $srv.so.Result -match 'SERVED'
    }
    return [pscustomobject]@{ client = $client; served = $served }
  } finally {
    if (-not $srv.p.HasExited) { try { $srv.p.Kill($true) } catch { } }
  }
}

# A port of the range that binds on this runner right now, for a
# listener that some other process is about to open.
function Free-LbPort {
  param([int[]] $Candidates)
  $l = Bind-Listener $Candidates
  $port = $l.LocalEndpoint.Port
  $l.Stop()
  return $port
}

# L0: no range installed. Live listeners inside the would-be range on
# 127.0.0.1 and ::1, and on a non-loopback address of this runner;
# every sandboxed connect is refused by a filter.
$l0v4 = Bind-Listener ($LbLo..($LbLo + 7))
$l0v6 = Bind-Listener (($LbLo + 8)..($LbLo + 15)) ([System.Net.IPAddress]::IPv6Loopback)
try {
  Assert-SbRefused 'L0' '127.0.0.1' $l0v4.LocalEndpoint.Port
  Assert-SbRefused 'L0' '::1' $l0v6.LocalEndpoint.Port
} finally {
  $l0v4.Stop(); $l0v6.Stop()
}
if (-not $lanIp) {
  Write-Host 'L0 note: no off-loopback IPv4 address on this runner; non-loopback half skipped'
} else {
  $l0lan = Bind-Listener (($LbLo + 16)..($LbLo + 23)) ([System.Net.IPAddress]::Parse($lanIp))
  try { Assert-SbRefused 'L0' $lanIp $l0lan.LocalEndpoint.Port } finally { $l0lan.Stop() }
}
$rt = SbServerRoundTrip 'L0' (Free-LbPort (($LbLo + 24)..($LbLo + 31)))
if ($rt.client.out -match 'CONNECTED' -or $rt.client.out -notmatch 'AccessDenied') {
  throw "L0: connect to a sandbox-started server expected AccessDenied with no range installed. raw: $($rt.client.raw)"
}
Write-Host 'L0 ok: with no range installed, in-range loopback (v4, v6), non-loopback and sandbox-to-sandbox connects are all refused'

# L0b: a session configured with a range the install does not have is
# refused (exit 19) by exec and by wfp verify, naming the reinstall.
$r = RExec @('--loopback-port-range', $LbRange, '--', $cmd, '/c', 'echo L0b-RAN')
if ($r.exit -ne 19) { throw "L0b: exec expected exit 19 (range not installed), got $($r.exit). raw: $($r.raw)" }
if ($r.raw -match 'L0b-RAN') { throw "L0b: child RAN with a range the install lacks. raw: $($r.raw)" }
if ($r.raw -notmatch '(?i)loopback port range' -or $r.raw -notmatch '(?i)srt-win install') {
  throw "L0b: exec message lacks the range / reinstall hint. raw: $($r.raw)"
}
$lvLsn = Bind-Listener (49970..49979)
$lvOut = & $Exe wfp verify --target "127.0.0.1:$($lvLsn.LocalEndpoint.Port)" --loopback-port-range $LbRange
$lvExit = $LASTEXITCODE
$lvLsn.Stop()
if ($lvExit -ne 19) { throw "L0b: wfp verify expected exit 19, got $lvExit. out: $lvOut" }
$lvDoc = $lvOut | ConvertFrom-Json
if (-not $lvDoc.outdated -or $lvDoc.hint -notmatch '(?i)srt-win install') {
  throw "L0b: wfp verify output lacks outdated=true / the reinstall hint: $lvOut"
}
Write-Host 'L0b ok: a session with a range the install lacks is refused (exec 19, wfp verify 19)'

# L0c: ranges install refuses, before changing anything.
foreach ($bad in @(
    @('3099-3000',   'low > high'),
    @('3000-3512',   'more than 512 ports'),
    @('1000-1100',   'starts below 1024'),
    @('60085-60100', 'overlaps the proxy port range'),
    @('3380-3390',   'includes 3389'),
    @('5980-5990',   'includes 5985/5986'),
    @('2370-2380',   'includes 2375/2376'),
    @('9220-9230',   'includes 9222/9229'))) {
  & $Exe install --sublayer-guid $Sublayer --proxy-port-range $PortRange --loopback-port-range $bad[0] --force 2>$null
  if ($LASTEXITCODE -eq 0) { throw "L0c: install accepted --loopback-port-range $($bad[0]) ($($bad[1]))" }
}
$l0c = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($l0c.state -ne 'installed' -or $l0c.filters -ne $st0.filters -or $null -ne $l0c.loopback_port_range) {
  throw "L0c: a refused range changed the install: $($l0c | ConvertTo-Json -Compress)"
}
Write-Host 'L0c ok: install refuses out-of-policy ranges and leaves the fence as it was'

# L1: adding a range to an existing install is a config change:
# refused (13) without --force, applied with it.
& $Exe install --sublayer-guid $Sublayer --proxy-port-range $PortRange --loopback-port-range $LbRange 2>$null
if ($LASTEXITCODE -ne 13) { throw "L1: install with a new range and no --force expected exit 13, got $LASTEXITCODE" }
Run @('install',
      '--sublayer-guid',$Sublayer,
      '--proxy-port-range',$PortRange,
      '--loopback-port-range',$LbRange,
      '--force')
$l1 = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($l1.state -ne 'installed' -or $l1.filters -ne ($st0.filters + 2)) {
  throw "L1: expected installed/$($st0.filters + 2) filters, got $($l1.state)/$($l1.filters)"
}
if (($l1.loopback_port_range -join '-') -ne $LbRange) {
  throw "L1: wfp status loopback_port_range expected $LbRange, got '$($l1.loopback_port_range -join '-')'"
}
if (($l1.port_range -join '-') -ne $PortRange) {
  throw "L1: wfp status port_range changed: '$($l1.port_range -join '-')'"
}
$l1c = J @('status','--sublayer-guid',$Sublayer)
if (($l1c.wfp.loopback_port_range -join '-') -ne $LbRange) {
  throw "L1: status .wfp.loopback_port_range expected $LbRange, got '$($l1c.wfp.loopback_port_range -join '-')'"
}
if ((Get-ItemProperty $regBase -ea Stop).LoopbackPortRange -ne $LbRange) {
  throw 'L1: install did not record LoopbackPortRange'
}
Write-Host "L1 ok: range installed ($LbRange): $($l1.filters) filters, reported by wfp status and status"

$lb = @('--loopback-port-range', $LbRange)

# L2: wfp verify with the range. The plain target is outside both
# ranges and still blocked; a non-loopback address at an in-range
# port is blocked; srt-win's own in-range loopback listener connects.
$l2Lsn = Bind-Listener (49960..49969)
$l2out = & $Exe wfp verify --target "127.0.0.1:$($l2Lsn.LocalEndpoint.Port)" @lb
$l2exit = $LASTEXITCODE
$l2Lsn.Stop()
Write-Host "L2: wfp verify exit=$l2exit stdout='$l2out'"
if ($l2exit -ne 0) { throw "L2: wfp verify with the installed range expected exit 0, got $l2exit" }
$l2 = $l2out | ConvertFrom-Json
if ($l2.egress_probe -ne 'blocked') { throw "L2: out-of-range loopback expected blocked, got '$($l2.egress_probe)'" }
if ($l2.range_loopback_probe -ne 'connected') {
  throw "L2: in-range loopback listener ($($l2.range_loopback_target)) expected connected, got '$($l2.range_loopback_probe)'"
}
if ($l2.range_off_loopback_probe -eq 'skipped') {
  Write-Host 'L2 note: off-loopback range attempt skipped (no off-loopback address on this runner)'
} elseif ($l2.range_off_loopback_probe -ne 'blocked') {
  throw "L2: in-range port on $($l2.range_off_loopback_target) expected blocked, got '$($l2.range_off_loopback_probe)'"
}
# With a range, the lowered-integrity attempts' off-loopback half is
# aimed at the in-range port too, and all four are still blocked.
if ($l2.range_off_loopback_target -and $l2.lowered_integrity_target -ne $l2.range_off_loopback_target) {
  throw "L2: lowered_integrity_target expected $($l2.range_off_loopback_target), got '$($l2.lowered_integrity_target)'"
}
foreach ($f in $loweredFields) {
  $got = $l2.$f
  if ($got -eq 'skipped' -and $f -notlike '*_loopback_probe') {
    Write-Host "L2 note: $f skipped (no off-loopback address on this runner)"
  } elseif ($got -ne 'blocked') {
    throw "L2: $f expected blocked with the range installed, got '$got'. out: $l2out"
  }
}
# A must-be-blocked target inside the range is refused as a usage
# error, not probed.
& $Exe wfp verify --target "127.0.0.1:$LbLo" @lb 2>$null | Out-Null
if ($LASTEXITCODE -ne 1) { throw "L2: wfp verify with an in-range --target expected exit 1, got $LASTEXITCODE" }
Write-Host 'L2 ok: wfp verify probes the range (loopback connected, off-loopback blocked) and refuses an in-range target'

# L3/L4: in-range loopback listeners are reachable on 127.0.0.1 and ::1.
$l3v4 = Bind-Listener ($LbLo..($LbLo + 7))
$l3v6 = Bind-Listener (($LbLo + 8)..($LbLo + 15)) ([System.Net.IPAddress]::IPv6Loopback)
try {
  Assert-SbConnected 'L3' '127.0.0.1' $l3v4.LocalEndpoint.Port $lb
  Write-Host "L3 ok: in-range loopback 127.0.0.1:$($l3v4.LocalEndpoint.Port) reachable"
  Assert-SbConnected 'L4' '::1' $l3v6.LocalEndpoint.Port $lb
  Write-Host "L4 ok: in-range loopback [::1]:$($l3v6.LocalEndpoint.Port) reachable"
} finally {
  $l3v4.Stop(); $l3v6.Stop()
}

# L5: loopback outside both ranges is still refused, on either side
# of the range and on ::1.
$l5ports = @()
foreach ($side in @((($LbLo - 1)..($LbLo - 8)), (($LbHi + 1)..($LbHi + 8)))) {
  $l5 = Bind-Listener $side
  $l5ports += $l5.LocalEndpoint.Port
  try { Assert-SbRefused 'L5' '127.0.0.1' $l5.LocalEndpoint.Port $lb } finally { $l5.Stop() }
}
$l5v6 = Bind-Listener (($LbHi + 9)..($LbHi + 16)) ([System.Net.IPAddress]::IPv6Loopback)
$l5v6port = $l5v6.LocalEndpoint.Port
try { Assert-SbRefused 'L5' '::1' $l5v6port $lb } finally { $l5v6.Stop() }
Write-Host "L5 ok: loopback just outside the range ($($l5ports -join ', '), [::1]:$l5v6port) still refused"

# L6: an in-range port on a NON-loopback address of this machine is
# still refused — the PERMIT is for loopback addresses only.
if (-not $lanIp) {
  Write-Host 'L6 SKIPPED: runner has no off-loopback IPv4 address'
} else {
  $l6 = Bind-Listener (($LbLo + 16)..($LbLo + 23)) ([System.Net.IPAddress]::Parse($lanIp))
  try {
    Assert-SbRefused 'L6' $lanIp $l6.LocalEndpoint.Port $lb
    Write-Host "L6 ok: in-range port on non-loopback ${lanIp}:$($l6.LocalEndpoint.Port) refused"
  } finally {
    $l6.Stop()
  }
}

# L7: a server started by one sandboxed command on an in-range port
# is reachable from a second sandboxed command.
$rt = SbServerRoundTrip 'L7' (Free-LbPort (($LbLo + 24)..($LbLo + 31))) $lb
if ($rt.client.out -notmatch 'CONNECTED' -or -not $rt.served) {
  throw "L7: sandbox-started in-range server not reached from a second sandboxed command (served=$($rt.served)). raw: $($rt.client.raw)"
}
Write-Host 'L7 ok: a sandbox-started server on an in-range port is reachable from a second sandboxed command'

# L8: a session whose range differs from the installed one — none, or
# another — is refused with the reinstall message and launches nothing.
foreach ($case in @(@('none', @()), @($LbOther, @('--loopback-port-range', $LbOther)))) {
  $r = RExec ($case[1] + @('--', $cmd, '/c', 'echo L8-RAN'))
  if ($r.exit -ne 19) { throw "L8: exec configured '$($case[0])' expected exit 19, got $($r.exit). raw: $($r.raw)" }
  if ($r.raw -match 'L8-RAN') { throw "L8: child RAN with a mismatched range ('$($case[0])'). raw: $($r.raw)" }
  if ($r.raw -notmatch '(?i)loopback port range' -or $r.raw -notmatch '(?i)srt-win install') {
    throw "L8: exec message lacks the range / reinstall hint ('$($case[0])'). raw: $($r.raw)"
  }
  $l8Lsn = Bind-Listener (49950..49959)
  $l8args = @('wfp','verify','--target',"127.0.0.1:$($l8Lsn.LocalEndpoint.Port)") + $case[1]
  $l8out = & $Exe @l8args
  $l8exit = $LASTEXITCODE
  $l8Lsn.Stop()
  if ($l8exit -ne 19) { throw "L8: wfp verify configured '$($case[0])' expected exit 19, got $l8exit. out: $l8out" }
  $l8doc = $l8out | ConvertFrom-Json
  if (-not $l8doc.outdated -or $l8doc.hint -notmatch '(?i)srt-win install') {
    throw "L8: wfp verify output lacks outdated=true / the reinstall hint: $l8out"
  }
}
Write-Host 'L8 ok: a session configured with a different range (or none) is refused with the reinstall message'

# L9: removing the range is the install step again. The PERMIT goes,
# the record goes, and the in-range listener is refused once more.
Run @('install',
      '--sublayer-guid',$Sublayer,
      '--proxy-port-range',$PortRange,
      '--force')
$l9 = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($l9.state -ne 'installed' -or $l9.filters -ne $st0.filters -or $null -ne $l9.loopback_port_range) {
  throw "L9: after removing the range expected installed/$($st0.filters) filters/no range, got $($l9 | ConvertTo-Json -Compress)"
}
if ($null -ne (Get-ItemProperty $regBase -ea Stop).PSObject.Properties['LoopbackPortRange']) {
  throw 'L9: LoopbackPortRange still recorded after the range was removed'
}
$l9Lsn = Bind-Listener ($LbLo..($LbLo + 7))
try { Assert-SbRefused 'L9' '127.0.0.1' $l9Lsn.LocalEndpoint.Port } finally { $l9Lsn.Stop() }
Write-Host 'L9 ok: reinstalling without the range closes it again'

# ── teardown ─────────────────────────────────────────────────────
Run @('uninstall','--sublayer-guid',$Sublayer)
$post = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($post.state -ne 'absent') {
  throw "post-uninstall expected absent, got $($post.state)"
}
if ($post.filters -ne 0) {
  throw "post-uninstall expected 0 filters, got $($post.filters)"
}
Write-Host 'smoke-exec: PASS (R0b, V1/V1b/V1c, R1-R7c, R5g/R5h/R5i, R9/R9b, R11, R12, G1-G6/G3b, U0-U4, L0-L9)'
