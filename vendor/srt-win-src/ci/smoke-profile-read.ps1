<#
  Smoke test for the profile read grant
  (`srt-win profile grant | forget | status`, `profile.rs`).

  The grant makes the real user's profile readable to the sandbox
  group, except for the excluded credential stores. This script never
  touches the runner's own profile: it builds a made-up profile tree
  under a scratch root and hands it to `profile grant` through
  `--test-profile`, which exists only in the test-hooks build.

  Two binaries. `$Exe` is the default-feature build: it is the broker
  and runner of every sandboxed command, and runs `profile forget`,
  `uninstall` and the status rows that do not need the override.
  `$HooksExe` (built with `--features test-hooks`) runs `profile
  grant` and `profile status` on the made-up profile, and nothing
  else. Without `$HooksExe` the whole script is SKIPPED, with a
  message: there is no way to run it without the override.

  Sandboxed commands run under the write-restricted token (the
  library's default), with no write root.

  Rows:

    T   a default build refuses `--test-profile` and records nothing.
    G   the grant completes on a tree of a few thousand files; the
        time it took is printed. `profile status` reports it current
        for the made-up profile and outdated for the real one; `user
        status` reports a grant.
    R1  a sandboxed command reads a file under a granted child.
    R2  it runs an .exe from a per-user tool directory on PATH.
    R3  it reads `.npmrc` in the profile root.
    R4  it lists a container, and cannot read a file in the root that
        is not granted by name.
    X   it cannot read a key directory, a credential file in the
        root, a store under AppData\Roaming, or AppData\Local\Temp.
    X2  an exclusion deleted and created again is still unreadable,
        and so is a credential file replaced by write-then-rename
        (in the root and in a container).
    N   a new top-level child is unreadable until `profile grant` is
        run again, and readable after.
    W   it cannot write, create, delete, rename or mkdir under a
        granted child, a container, or the profile root.
    J   a junction inside a granted directory pointing at an excluded
        store, and one pointing outside the profile, cannot be read
        through; the targets' DACLs are unchanged after the grant and
        after a refresh. A top-level junction is skipped and
        reported. (A file symbolic link too, where one can be made.)
    D   a session read deny on the profile directory — stamped on
        every path the grant made readable, as the library does —
        and one on a granted child, deny for that session and are
        gone after it; a deny beneath a granted child needs no more
        than its own path. OBSERVATION: what a deny stamped on the
        profile directory alone leaves readable.
    O   an exec under the ordinary token is refused (exit 20) while
        the grant exists.
    F   `profile forget` (what a session without the option runs
        first): nothing is readable any more, every touched DACL is
        what it was before the grant, the empty directories the grant
        created are gone, nothing is recorded, and the ordinary token
        runs again.
    U   `uninstall` does the same to a grant that is still there.

  A failing row is recorded and the script keeps going; it throws at
  the end if any row failed.

  Self-contained: installs under a fixed test-only sublayer GUID
  (referenced by cleanup.ps1) and uninstalls in `finally`.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe,
  [Parameter(Position = 1)]
  [string] $HooksExe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; referenced by cleanup.ps1.
$Sublayer  = 'e1a47c93-5d28-4b6f-a3c1-7f0e9d2b4a58'
$PortRange = '60080-60089'

if (-not $HooksExe) {
  Write-Host 'smoke-profile-read: SKIPPED — needs the test-hooks build of srt-win (cargo build --features test-hooks) as the second argument: the made-up profile is passed through --test-profile, which only that build has'
  exit 0
}
if (-not (Test-Path $HooksExe)) { throw "test-hooks binary not found: $HooksExe" }
$ExeAbs   = (Resolve-Path $Exe).Path
$HooksAbs = (Resolve-Path $HooksExe).Path
$cmd      = Join-Path $env:SystemRoot 'System32\cmd.exe'
$env:SANDBOX_RUNTIME_WIN_DEBUG = '1'
Write-Host "smoke-profile-read: sublayer=$Sublayer  exe=$ExeAbs  test-hooks exe=$HooksAbs"

$script:Failures = [System.Collections.Generic.List[string]]::new()
function Fail { param([string] $m) Write-Host "FAIL $m"; $script:Failures.Add($m) }
function Ok   { param([string] $m) Write-Host "ok   $m" }

function Run { param([string[]] $argv)
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) { throw "srt-win $($argv -join ' ') exited $LASTEXITCODE" }
}
function J { param([string[]] $argv) Run $argv | ConvertFrom-Json }
function JsonPath { param([string] $p) $p -replace '\\', '\\' }

# Run one of the two binaries; returns exit code, all output, and the
# last output line that parses as a JSON object (or $null).
function Invoke-Srt { param([string] $bin, [string[]] $argv)
  $lines = @(& $bin @argv 2>&1 | ForEach-Object { "$_" })
  $code = $LASTEXITCODE
  $raw = $lines -join "`n"
  Write-Host $raw
  $json = $null
  $line = $lines | Where-Object { $_.TrimStart().StartsWith('{') } | Select-Object -Last 1
  if ($line) { try { $json = $line | ConvertFrom-Json } catch { } }
  return [pscustomobject]@{ exit = $code; raw = $raw; json = $json }
}

# Sandboxed exec under the write-restricted token (or the ordinary one
# with -Ordinary), with `$extraPath` appended to the child's PATH.
function Sb { param([string[]] $tail, [string] $extraPath = '', [switch] $Ordinary, [int] $TimeoutSec = 180)
  $path = $env:PATH
  if ($extraPath) { $path = "$path;$extraPath" }
  $argv = @('exec', '--env', "PATH=$path", '--env', "PATHEXT=$($env:PATHEXT)")
  if (-not $Ordinary) { $argv += '--write-restricted-token' }
  $argv += @('--') + $tail
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName               = $ExeAbs
  $psi.UseShellExecute        = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.Environment['SANDBOX_RUNTIME_WIN_DEBUG'] = '1'
  foreach ($a in $argv) { $null = $psi.ArgumentList.Add($a) }
  $p = [System.Diagnostics.Process]::Start($psi)
  $so = $p.StandardOutput.ReadToEndAsync()
  $se = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    try { $p.Kill($true) } catch { }
    $p.WaitForExit()
    $raw = "TIMEOUT`n" + $so.Result + $se.Result
    return [pscustomobject]@{ exit = -1; raw = $raw; out = $raw }
  }
  $raw   = $so.Result + $se.Result
  $child = (($raw -split "`r?`n") | Where-Object { $_ -notmatch '^srt-win:' }) -join "`n"
  return [pscustomobject]@{ exit = $p.ExitCode; raw = $raw; out = $child }
}
# Whether a sandboxed `type` of `$file` printed `$marker`.
function Sb-Reads { param([string] $file, [string] $marker)
  $r = Sb @($cmd, '/d', '/s', '/c', "type `"$file`"")
  return [pscustomobject]@{ read = ($r.out -match [regex]::Escape($marker)); r = $r }
}
function Expect-Read { param([string] $row, [string] $file, [string] $marker)
  $x = Sb-Reads $file $marker
  if ($x.read) { Ok "${row}: readable: $file" }
  else { Fail "${row}: NOT readable: $file (exit=$($x.r.exit)) raw: $($x.r.raw)  Sddl=$(Sddl $file)" }
}
function Expect-NoRead { param([string] $row, [string] $file, [string] $marker)
  $x = Sb-Reads $file $marker
  if (-not $x.read -and $x.r.exit -ne 0) { Ok "${row}: not readable: $file" }
  else { Fail "${row}: READABLE (or the command did not fail): $file (exit=$($x.r.exit)) raw: $($x.r.raw)  Sddl=$(Sddl $file)" }
}

function Sddl { param([string] $p) (Get-Acl -LiteralPath $p).Sddl }
# The DACL of an SDDL string in a form two of them can be compared in:
# whether it is protected, then its ACEs, sorted.
function DaclOf { param([string] $sd)
  $prot = if ($sd -match 'D:[A-Z]*P[A-Z]*\(') { 'protected' } else { 'inheriting' }
  $aces = @([regex]::Matches($sd, '\([^)]*\)') | ForEach-Object Value | Sort-Object)
  return "$prot $($aces -join '')"
}
function Dacl { param([string] $p) DaclOf (Sddl $p) }
# Give directory `$d` a protected DACL holding exactly `$aces`,
# written whole and read back (see smoke-write-restricted.ps1).
function Set-OnlyAces { param([string] $d, [string[]] $aces)
  $want = "D:PAI$($aces -join '')"
  $sec = [System.Security.AccessControl.DirectorySecurity]::new()
  $sec.SetSecurityDescriptorSddlForm(
    $want, [System.Security.AccessControl.AccessControlSections]::Access)
  $sec.SetAccessRuleProtection($true, $false)
  [System.IO.FileSystemAclExtensions]::SetAccessControl(
    [System.IO.DirectoryInfo]::new($d), $sec)
  $got = Dacl $d
  if ($got -ne (DaclOf $want)) {
    Fail "setup: the DACL of $d is not the one set on it; rows that use it prove less. want: $(DaclOf $want)  got: $got"
  }
}
function Seed { param([string] $rel, [string] $content)
  $f = Join-Path $prof $rel
  New-Item -ItemType Directory -Path (Split-Path $f) -Force | Out-Null
  $content | Set-Content -Encoding ASCII -LiteralPath $f
  return $f
}
# Whether a path's DACL names the sandbox group at all / in an ALLOW.
function Has-Group { param([string] $p) (Sddl $p) -match [regex]::Escape($script:grpSid) }
function Has-GroupAllow { param([string] $p)
  @([regex]::Matches((Sddl $p), '\(A;[^)]*\)') | ForEach-Object Value |
    Where-Object { $_ -match [regex]::Escape($script:grpSid) }).Count -gt 0
}
function Grant { param([string[]] $extra = @())
  Invoke-Srt $HooksAbs (@('profile', 'grant', '--test-profile', $prof, '--json') + $extra)
}
function Status { (Invoke-Srt $HooksAbs @('profile', 'status', '--test-profile', $prof, '--paths')).json }
# A session's deny stamps (`acl grant --persistent` with no roots, as
# initialize() sends them), and their release.
function Session-Deny { param([string[]] $denyRead)
  $json = @{ read = @(); write = @(); denyRead = @($denyRead); denyWrite = @() } |
    ConvertTo-Json -Compress
  $raw = $json | & $Exe acl grant --holder-pid $PID --sandbox-user-sid $sbSid --persistent 2>&1 |
    Out-String
  if ($LASTEXITCODE -ne 0) { Write-Host $raw }
  return $LASTEXITCODE
}
function End-Session {
  & $Exe acl revoke  --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
  & $Exe acl restore --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
}
# The recorded paths a deny on `$d` has to be stamped on: `$d` itself
# and every path the grant made readable at or beneath it.
function Deny-Targets { param([string] $d)
  $key = $d.TrimEnd('\').ToLowerInvariant()
  $out = @($d)
  foreach ($p in (Status).paths) {
    if ($p.kind -eq 'denied') { continue }
    $at = ($p.path -replace '^\\\\\?\\', '').TrimEnd('\').ToLowerInvariant()
    if ($at -ne $key -and $at.StartsWith($key + '\')) { $out += $p.path }
  }
  return $out
}

try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke-profile-read: WARNING: Start-Service seclogon: $_"
}

# Scratch tree at the system-drive root, with a protected DACL written
# whole: Administrators and SYSTEM, inherited by everything below, and
# read for BUILTIN\Users on the root only so a child can be looked up
# by name. Nothing below the root gives the sandbox account anything,
# so whatever it can read there afterwards it reads through the grant.
# This script and the broker run elevated as a member of
# Administrators, which is what lets them seed, grant and clean up.
$root = Join-Path "$env:SystemDrive\" "srt-pr-smoke-$([guid]::NewGuid().ToString('N'))"
$prof = Join-Path $root 'profile'
$outside = Join-Path $root 'outside'

$sbSid = $null
$script:grpSid = $null
try {
  Run @('install', '--sublayer-guid', $Sublayer, '--proxy-port-range', $PortRange)
  $us = J @('user', 'status')
  $sbSid = $us.marker_user_sid
  if (-not $sbSid) { throw 'setup marker missing user_sid' }
  $script:grpSid = $us.user.group_sid
  if (-not $script:grpSid) { throw 'user status missing group_sid' }
  # Grants left by an earlier, interrupted run.
  & $Exe profile forget 2>&1 | Out-Null
  & $Exe acl forget --all 2>&1 | Out-Null

  New-Item -ItemType Directory -Path $root -Force | Out-Null
  Set-OnlyAces $root @('(A;OICI;FA;;;BA)', '(A;OICI;FA;;;SY)', '(A;;0x1200a9;;;BU)')
  New-Item -ItemType Directory -Path $prof, $outside -Force | Out-Null

  # ── The made-up profile ──────────────────────────────────────────
  $note     = Seed 'Documents\note.txt'                         'NOTE-CONTENT'
  $subFile  = Seed 'Documents\sub\deep.txt'                     'DEEP-CONTENT'
  $null     = Seed 'Documents\del.txt'                          'DEL'
  $null     = Seed 'Documents\ren.txt'                          'REN'
  $npmrc    = Seed '.npmrc'                                     'NPMRC-CONTENT'
  $stray    = Seed 'stray.txt'                                  'STRAY-CONTENT'
  $netrc    = Seed '.netrc'                                     'NETRC-CONTENT'
  $sshKey   = Seed '.ssh\id_test'                               'SSH-CONTENT'
  $cargoCr  = Seed '.cargo\credentials.toml'                    'CARGO-CRED-CONTENT'
  $cargoCfg = Seed '.cargo\config.toml'                         'CARGO-CONFIG-CONTENT'
  $credBlob = Seed 'AppData\Roaming\Microsoft\Credentials\blob' 'CRED-CONTENT'
  $npmTool  = Seed 'AppData\Roaming\npm\tool.cmd'               '@echo NPM-TOOL'
  $tempFile = Seed 'AppData\Local\Temp\t.txt'                   'TEMP-CONTENT'
  $toolDir  = Join-Path $prof 'AppData\Local\Programs\MyTool'
  New-Item -ItemType Directory -Path $toolDir -Force | Out-Null
  # cmd.exe under another name: an .exe that exists nowhere else on
  # PATH and can say that it ran.
  Copy-Item $cmd (Join-Path $toolDir 'srtsmoketool.exe')
  # A few thousand files, for the timing line.
  $bulkDirs = 20; $bulkFiles = 150
  foreach ($i in 0..($bulkDirs - 1)) {
    $d = Join-Path $prof ("bulk\d{0:d3}" -f $i)
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    foreach ($k in 0..($bulkFiles - 1)) { [System.IO.File]::WriteAllText((Join-Path $d ("f{0:d3}.txt" -f $k)), 'BULK-CONTENT') }
  }
  $bulkSample = Join-Path $prof 'bulk\d019\f149.txt'
  $secret = Join-Path $outside 'secret.txt'
  'OUTSIDE-CONTENT' | Set-Content -Encoding ASCII -LiteralPath $secret
  # Junctions: one at the top, two inside a directory that will be
  # granted whole.
  $jTop     = Join-Path $prof 'link'
  $jOutside = Join-Path $prof 'Documents\to-outside'
  $jSsh     = Join-Path $prof 'Documents\to-ssh'
  New-Item -ItemType Junction -Path $jTop     -Target $outside               | Out-Null
  New-Item -ItemType Junction -Path $jOutside -Target $outside               | Out-Null
  New-Item -ItemType Junction -Path $jSsh     -Target (Join-Path $prof '.ssh') | Out-Null
  $symFile = Join-Path $prof 'Documents\sym.txt'
  $haveSym = $false
  try {
    New-Item -ItemType SymbolicLink -Path $symFile -Target $secret -ea Stop | Out-Null
    $haveSym = $true
  } catch { Write-Host "J: no file symbolic link on this runner ($_); that part of J is not run" }

  # What every path the grant will write on carries now. `.ssh`,
  # `.netrc` and `.cargo\credentials.toml` are replaced by row X2 and
  # are checked for carrying nothing of the group's instead.
  $touched = @(
    $prof, (Join-Path $prof 'Documents'), $note, $npmrc, (Join-Path $prof '.cargo'), $cargoCfg,
    (Join-Path $prof 'AppData'), (Join-Path $prof 'AppData\Roaming'),
    (Join-Path $prof 'AppData\Roaming\Microsoft'), (Join-Path $prof 'AppData\Roaming\Microsoft\Credentials'),
    $credBlob, (Join-Path $prof 'AppData\Roaming\npm'), $npmTool, (Join-Path $prof 'AppData\Local'),
    (Join-Path $prof 'AppData\Local\Temp'), $tempFile, (Join-Path $prof 'AppData\Local\Programs'),
    $toolDir, (Join-Path $prof 'bulk'), $bulkSample, $stray)
  $replaced = @((Join-Path $prof '.ssh'), $sshKey, $netrc, $cargoCr)
  $pre = @{}
  foreach ($p in $touched) { $pre[$p] = Dacl $p }
  $preOutside = @{ $outside = (Dacl $outside); $secret = (Dacl $secret) }
  function Outside-Unchanged { param([string] $when)
    $bad = @($preOutside.Keys | Where-Object { (Dacl $_) -ne $preOutside[$_] })
    if ($bad.Count -eq 0) { Ok "J: the junction targets outside the profile have their DACLs unchanged $when" }
    else { Fail "J: DACL changed through a junction $when`: $($bad | ForEach-Object { "$_ now $(Sddl $_)" })" }
  }
  function Restored { param([string] $row)
    $bad = @($touched | Where-Object { (Dacl $_) -ne $pre[$_] })
    $left = @($replaced | Where-Object { (Test-Path -LiteralPath $_) -and (Has-Group $_) })
    if ($bad.Count -eq 0 -and $left.Count -eq 0) { Ok "${row}: every touched DACL is what it was before the grant" }
    else {
      Fail ("${row}: DACLs differ from before the grant: " +
            (($bad | ForEach-Object { "$_ was [$($pre[$_])] is [$(Dacl $_)]" }) -join '; ') +
            " still naming the group: $($left -join ', ')")
    }
    $ph = @('.aws', '.gnupg', '.kube', 'AppData\Local\Google', 'AppData\Roaming\gcloud') |
      Where-Object { Test-Path -LiteralPath (Join-Path $prof $_) }
    if (@($ph).Count -eq 0) { Ok "${row}: the empty directories the grant created are gone" }
    else { Fail "${row}: created directories left behind: $($ph -join ', ')" }
    $st = (Invoke-Srt $HooksAbs @('profile', 'status', '--test-profile', $prof)).json
    $reg = Get-ItemProperty 'HKCU:\Software\sandbox-runtime\PersistentGrants' -ErrorAction SilentlyContinue
    if ($st.state -eq 'none' -and -not $reg.Profile -and -not $reg.ProfilePaths) { Ok "${row}: nothing is recorded" }
    else { Fail "${row}: still recorded: state=$($st.state) Profile=$($reg.Profile) paths=$(@($reg.ProfilePaths).Count)" }
  }

  # Before the grant the sandbox reads nothing here.
  Expect-NoRead 'setup' $note 'NOTE-CONTENT'

  # ── T: the override is not in a default build ────────────────────
  $r = Invoke-Srt $ExeAbs @('profile', 'grant', '--test-profile', $prof)
  $st = (Invoke-Srt $ExeAbs @('profile', 'status')).json
  if ($r.exit -ne 0 -and $st.state -eq 'none' -and -not (Has-Group $prof)) {
    Ok 'T: a default build refuses --test-profile and records nothing'
  } else { Fail "T: default build with --test-profile: exit=$($r.exit) state=$($st.state) Sddl=$(Sddl $prof)" }

  # ── G: the grant ─────────────────────────────────────────────────
  $files = $bulkDirs * $bulkFiles
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $g = Grant
  $sw.Stop()
  Write-Host ("G: TIMING: profile grant on a tree with {0} files in {1} directories under one granted child: {2} ms wall, {3} ms reported; {4} DACL write(s)" -f `
    $files, $bulkDirs, $sw.ElapsedMilliseconds, $g.json.elapsed_ms, $g.json.writes)
  if ($g.exit -eq 0 -and $g.json.complete) { Ok "G: grant complete ($($g.json.containers) containers, $($g.json.granted) granted, $($g.json.files) files, $($g.json.denied) excluded, $($g.json.placeholders) created)" }
  else { Fail "G: profile grant exit=$($g.exit) complete=$($g.json.complete) raw: $($g.raw)" }
  if ($g.raw -match 'top-level item\(s\) done') { Ok 'G: progress lines on stderr' }
  else { Fail 'G: no progress line in the output' }
  if (@($g.json.failed).Count -eq 0) { Ok 'G: no path failed' }
  else { Fail "G: failed paths: $($g.json.failed | ConvertTo-Json -Compress)" }
  $st = Status
  if ($st.state -eq 'current' -and $st.env.NPM_CONFIG_USERCONFIG -and @($st.paths).Count -gt 0) {
    Ok "G: status is current for the made-up profile, with NPM_CONFIG_USERCONFIG=$($st.env.NPM_CONFIG_USERCONFIG)"
  } else { Fail "G: status: $($st | ConvertTo-Json -Compress -Depth 4)" }
  $real = (Invoke-Srt $ExeAbs @('profile', 'status')).json
  if ($real.state -eq 'outdated') { Ok 'G: for the real profile the same record is outdated (made for another directory)' }
  else { Fail "G: status for the real profile is '$($real.state)', want outdated" }
  $brief = (J @('user', 'status')).profile_grant
  if ($brief.state -eq 'present') { Ok 'G: user status reports a profile grant' }
  else { Fail "G: user status profile_grant = $($brief | ConvertTo-Json -Compress)" }
  Outside-Unchanged 'after the grant'

  # ── R: what is readable ──────────────────────────────────────────
  Expect-Read 'R1' $note 'NOTE-CONTENT'
  Expect-Read 'R1' $subFile 'DEEP-CONTENT'
  Expect-Read 'R1' $bulkSample 'BULK-CONTENT'
  $r = Sb @($cmd, '/d', '/s', '/c', 'srtsmoketool.exe /d /c echo TOOL-RAN') $toolDir
  if ($r.exit -eq 0 -and $r.out -match 'TOOL-RAN') { Ok 'R2: an .exe in a per-user tool directory on PATH runs' }
  else { Fail "R2: srtsmoketool.exe from $toolDir on PATH: exit=$($r.exit) raw: $($r.raw)" }
  Expect-Read 'R3' $npmrc 'NPMRC-CONTENT'
  Expect-Read 'R3 (a file of a container)' $cargoCfg 'CARGO-CONFIG-CONTENT'
  $r = Sb @($cmd, '/d', '/s', '/c', "dir /b /a `"$prof`"")
  if ($r.exit -eq 0 -and $r.out -match 'Documents' -and $r.out -match 'stray\.txt') { Ok 'R4: the profile directory (a container) can be listed' }
  else { Fail "R4: dir of the profile directory: exit=$($r.exit) raw: $($r.raw)" }
  Expect-NoRead 'R4 (a root file not granted by name)' $stray 'STRAY-CONTENT'

  # ── X: exclusions ────────────────────────────────────────────────
  Expect-NoRead 'X (key directory)' $sshKey 'SSH-CONTENT'
  Expect-NoRead 'X (credential file in the root)' $netrc 'NETRC-CONTENT'
  Expect-NoRead 'X (credential file in a container)' $cargoCr 'CARGO-CRED-CONTENT'
  Expect-NoRead 'X (store under AppData\Roaming)' $credBlob 'CRED-CONTENT'
  Expect-NoRead 'X (AppData\Local\Temp)' $tempFile 'TEMP-CONTENT'
  $r = Sb @($cmd, '/d', '/s', '/c', "dir /b /a `"$(Join-Path $prof '.ssh')`"")
  if ($r.exit -ne 0 -and $r.out -notmatch 'id_test') { Ok 'X: an excluded directory cannot be listed' }
  else { Fail "X: dir of .ssh: exit=$($r.exit) raw: $($r.raw)" }
  # The grant created the missing excluded directories, denied.
  $aws = Join-Path $prof '.aws'
  if ((Test-Path -LiteralPath $aws) -and (Has-Group $aws) -and -not (Has-GroupAllow $aws)) { Ok 'X: a missing excluded directory was created and carries the deny' }
  else { Fail "X: .aws: exists=$(Test-Path -LiteralPath $aws)" }

  # ── X2: an exclusion that is replaced ────────────────────────────
  Remove-Item -Recurse -Force -LiteralPath (Join-Path $prof '.ssh')
  $sshKey = Seed '.ssh\id_test' 'SSH2-CONTENT'
  foreach ($f in @($netrc, $cargoCr)) {
    $tmp = "$f.tmp"
    'REPLACED-CONTENT' | Set-Content -Encoding ASCII -LiteralPath $tmp
    Move-Item -Force -LiteralPath $tmp -Destination $f
  }
  Expect-NoRead 'X2 (key directory deleted and created again)' $sshKey 'SSH2-CONTENT'
  Expect-NoRead 'X2 (root credential file replaced by rename)' $netrc 'REPLACED-CONTENT'
  Expect-NoRead 'X2 (container credential file replaced by rename)' $cargoCr 'REPLACED-CONTENT'
  $allowed = @((Join-Path $prof '.ssh'), $sshKey, $netrc, $cargoCr) | Where-Object { Has-GroupAllow $_ }
  if (@($allowed).Count -eq 0) { Ok 'X2: none of the replaced objects carries an allow for the sandbox group, inherited or its own' }
  else { Fail "X2: an allow for the group on: $($allowed | ForEach-Object { "$_ $(Sddl $_)" })" }

  # ── N: a new top-level child, and the refresh ────────────────────
  $newFile = Seed 'NewTop\n.txt' 'NEWTOP-CONTENT'
  Expect-NoRead 'N (before the refresh)' $newFile 'NEWTOP-CONTENT'
  $g2 = Grant
  if ($g2.exit -eq 0 -and $g2.json.complete) { Ok "N: refresh complete ($($g2.json.writes) DACL write(s), $($g2.json.unchanged) unchanged, $($g2.json.elapsed_ms) ms)" }
  else { Fail "N: refresh exit=$($g2.exit) raw: $($g2.raw)" }
  Expect-Read 'N (after the refresh)' $newFile 'NEWTOP-CONTENT'
  Expect-NoRead 'N (the replaced exclusions after the refresh)' $sshKey 'SSH2-CONTENT'
  Expect-NoRead 'N (the replaced exclusions after the refresh)' $netrc 'REPLACED-CONTENT'
  $g3 = Grant
  if ($g3.exit -eq 0 -and $g3.json.writes -eq 0) { Ok "N: a refresh with nothing new writes no DACL ($($g3.json.elapsed_ms) ms)" }
  else { Fail "N: an idle refresh wrote $($g3.json.writes) DACL(s): $($g3.raw)" }
  Outside-Unchanged 'after the refresh'

  # ── W: nothing is writable ───────────────────────────────────────
  foreach ($case in @(
      @{ tag = 'a granted child'; dir = (Join-Path $prof 'Documents'); keep = 'note.txt'; text = 'NOTE-CONTENT' },
      @{ tag = 'a container';     dir = (Join-Path $prof '.cargo');    keep = 'config.toml'; text = 'CARGO-CONFIG-CONTENT' },
      @{ tag = 'the profile directory'; dir = $prof;                   keep = '.npmrc'; text = 'NPMRC-CONTENT' })) {
    $d = $case.dir
    $keep = Join-Path $d $case.keep
    $line = "echo W>> `"$keep`" & echo N> `"$d\w-new.txt`" & del /q `"$keep`" & ren `"$keep`" w-renamed.txt & mkdir `"$d\w-newdir`" & exit /b 0"
    $r = Sb @($cmd, '/d', '/s', '/c', $line)
    $state = "content=[$((Get-Content -Raw -LiteralPath $keep -ErrorAction SilentlyContinue))] " +
             "new=$(Test-Path -LiteralPath (Join-Path $d 'w-new.txt')) " +
             "renamed=$(Test-Path -LiteralPath (Join-Path $d 'w-renamed.txt')) " +
             "newdir=$(Test-Path -LiteralPath (Join-Path $d 'w-newdir'))"
    $want = "content=[$($case.text)`r`n] new=False renamed=False newdir=False"
    if ($state -eq $want) { Ok "W: no write, create, delete, rename or mkdir in $($case.tag)" }
    else { Fail "W: $($case.tag) changed: $state (want $want). raw: $($r.raw)" }
  }

  # ── J: junctions ─────────────────────────────────────────────────
  Expect-NoRead 'J (through a junction to an excluded store)' (Join-Path $jSsh 'id_test') 'SSH2-CONTENT'
  Expect-NoRead 'J (through a junction to outside the profile)' (Join-Path $jOutside 'secret.txt') 'OUTSIDE-CONTENT'
  Expect-NoRead 'J (through the top-level junction)' (Join-Path $jTop 'secret.txt') 'OUTSIDE-CONTENT'
  if ($haveSym) { Expect-NoRead 'J (through a file symbolic link)' $symFile 'OUTSIDE-CONTENT' }
  $skipped = @($g.json.skipped | Where-Object { $_.path -match '\\link$' })
  if ($skipped.Count -eq 1) { Ok "J: the top-level junction is skipped and reported ($($skipped[0].reason))" }
  else { Fail "J: the top-level junction is not in the skipped list: $($g.json.skipped | ConvertTo-Json -Compress)" }
  $sshDir = Join-Path $prof '.ssh'
  if (-not (Has-GroupAllow $sshDir) -and -not (Has-GroupAllow $sshKey)) { Ok 'J: the excluded store behind a junction carries no allow' }
  else { Fail "J: .ssh carries an allow for the group: $(Sddl $sshDir) / $(Sddl $sshKey)" }

  # ── D: session read denies ───────────────────────────────────────
  # On the profile directory, stamped as the library stamps it.
  $targets = Deny-Targets $prof
  Write-Host "D: a deny on the profile directory is stamped on $($targets.Count) path(s)"
  if ((Session-Deny $targets) -ne 0) { Fail 'D: the session stamps for a deny on the profile directory could not be written' }
  else {
    Expect-NoRead 'D (deny on the profile: granted child)' $note 'NOTE-CONTENT'
    Expect-NoRead 'D (deny on the profile: root file)' $npmrc 'NPMRC-CONTENT'
    Expect-NoRead 'D (deny on the profile: file of a container)' $cargoCfg 'CARGO-CONFIG-CONTENT'
    $r = Sb @($cmd, '/d', '/s', '/c', "dir /b /a `"$prof`"")
    if ($r.exit -ne 0) { Ok 'D: the denied profile directory cannot be listed' }
    else { Fail "D: dir of the denied profile directory: exit=$($r.exit) raw: $($r.raw)" }
  }
  End-Session
  Expect-Read 'D (after the session)' $note 'NOTE-CONTENT'
  Expect-Read 'D (after the session)' $npmrc 'NPMRC-CONTENT'
  # On a granted child.
  $docs = Join-Path $prof 'Documents'
  if ((Session-Deny (Deny-Targets $docs)) -ne 0) { Fail 'D: the session stamp for a deny on a granted child could not be written' }
  else {
    Expect-NoRead 'D (deny on a granted child)' $note 'NOTE-CONTENT'
    Expect-NoRead 'D (deny on a granted child, deeper)' $subFile 'DEEP-CONTENT'
    Expect-Read 'D (deny on a granted child leaves the rest)' $npmrc 'NPMRC-CONTENT'
  }
  End-Session
  Expect-Read 'D (after the session)' $note 'NOTE-CONTENT'
  # Beneath a granted child: its own path is enough.
  $sub = Join-Path $docs 'sub'
  if ((Session-Deny @($sub)) -ne 0) { Fail 'D: the session stamp for a deny beneath a granted child could not be written' }
  else {
    Expect-NoRead 'D (deny beneath a granted child)' $subFile 'DEEP-CONTENT'
    Expect-Read 'D (deny beneath a granted child leaves its siblings)' $note 'NOTE-CONTENT'
  }
  End-Session
  Expect-Read 'D (after the session)' $subFile 'DEEP-CONTENT'
  # OBSERVATION: the deny on the profile directory alone. A granted
  # child's own allow is met before a deny it only inherits, which is
  # why the stamps above go on every granted path.
  if ((Session-Deny @($prof)) -eq 0) {
    $x = Sb-Reads $note 'NOTE-CONTENT'
    Write-Host "D: OBSERVATION: with the deny stamped on the profile directory ONLY, a file under a granted child is $(if ($x.read) { 'still READABLE (so the per-path stamps are needed)' } else { 'not readable' })"
  }
  End-Session

  # ── O: the ordinary token ────────────────────────────────────────
  $r = Sb @($cmd, '/d', '/s', '/c', 'echo ORDINARY-RAN') -Ordinary
  if ($r.exit -eq 20 -and $r.out -notmatch 'ORDINARY-RAN') { Ok 'O: exec under the ordinary token is refused (exit 20) while the grant exists' }
  else { Fail "O: ordinary-token exec with a profile grant: exit=$($r.exit) raw: $($r.raw)" }

  # ── F: profile forget ────────────────────────────────────────────
  # Undo what the rows added, so the comparison is with the tree as it
  # was (NewTop is the grant's to forget like any other child).
  $f = Invoke-Srt $ExeAbs @('profile', 'forget', '--json')
  if ($f.exit -eq 0 -and @($f.json.failed).Count -eq 0) { Ok "F: profile forget ($($f.json.removed) cleared, $($f.json.placeholders_removed) created directories removed)" }
  else { Fail "F: profile forget exit=$($f.exit) raw: $($f.raw)" }
  Expect-NoRead 'F (after forget)' $note 'NOTE-CONTENT'
  Expect-NoRead 'F (after forget)' $npmrc 'NPMRC-CONTENT'
  Expect-NoRead 'F (after forget)' $newFile 'NEWTOP-CONTENT'
  Restored 'F'
  Outside-Unchanged 'after forget'
  $r = Sb @($cmd, '/d', '/s', '/c', 'echo ORDINARY-RAN') -Ordinary
  if ($r.exit -eq 0 -and $r.out -match 'ORDINARY-RAN') { Ok 'F: the ordinary token runs again' }
  else { Fail "F: ordinary-token exec after forget: exit=$($r.exit) raw: $($r.raw)" }

  # ── U: uninstall ─────────────────────────────────────────────────
  $g = Grant
  if ($g.exit -ne 0 -or -not (Has-Group $prof)) { Fail "U: setup — the grant is not there: $($g.raw)" }
  else {
    & $Exe uninstall --sublayer-guid $Sublayer 2>&1 | Out-String | Write-Host
    Restored 'U'
    Outside-Unchanged 'after uninstall'
  }
}
finally {
  & $Exe profile forget 2>&1 | Out-Null
  & $Exe acl forget --all 2>&1 | Out-Null
  if ($sbSid) {
    & $Exe acl revoke  --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
    & $Exe acl restore --holder-pid $PID --sandbox-user-sid $sbSid 2>&1 | Out-Null
  }
  # Junctions first, as links: never through them.
  foreach ($j in @($jTop, $jOutside, $jSsh, $symFile)) {
    if ($j -and (Test-Path -LiteralPath $j)) { [System.IO.Directory]::Exists($j) ? [System.IO.Directory]::Delete($j) : [System.IO.File]::Delete($j) }
  }
  Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
  & $Exe uninstall --sublayer-guid $Sublayer 2>&1 | Out-Null
}

if ($script:Failures.Count -gt 0) {
  Write-Host "smoke-profile-read: $($script:Failures.Count) row(s) FAILED:"
  $script:Failures | ForEach-Object { Write-Host "  - $_" }
  throw "smoke-profile-read: $($script:Failures.Count) row(s) failed"
}
Write-Host 'smoke-profile-read: PASS (T, G, R1-R4, X, X2, N, W, J, D, O, F, U)'
