import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import {
  checkLinuxDependencies,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { quote } from '../../src/utils/shell-quote.js'
import { isLinux } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'

/**
 * The `host` filter holds the rules that reach past the namespaces the
 * sandbox makes — socket(AF_VSOCK), io_uring, and the kernel-keyring calls
 * (a command inherits its caller's session keyring, which no mount or
 * network rule covers) — and every command gets it. `SRT_ALLOW_UNIX_SOCKETS=1`
 * in the helper's OWN environment leaves out only the `unix` filter
 * (socket(AF_UNIX)); the wrap pins the variable itself, so the caller's
 * environment never decides.
 *
 * Every refusal assertion is on the errno: seccomp answers EPERM before the
 * kernel looks at the call, where the unfiltered kernel would answer with a
 * key or socket, ENOKEY, EFAULT or EAFNOSUPPORT.
 */

// Prints `<label>=OK` for a non-negative return, `<label>=<errno name>`
// otherwise. The keyring and io_uring calls go in raw: glibc wraps none of
// them, and the probes must not depend on keyutils being installed.
const ATTEMPT = [
  'import ctypes, errno, platform, socket',
  'libc = ctypes.CDLL(None, use_errno=True)',
  'nrs = {"x86_64": {"add_key": 248, "request_key": 249, "keyctl": 250},',
  '       "aarch64": {"add_key": 217, "request_key": 218, "keyctl": 219}}[platform.machine()]',
  'nrs.update(io_uring_setup=425, io_uring_enter=426, io_uring_register=427)',
  'def attempt(label, fn):',
  '    r = fn()',
  '    print(label + "=" + ("OK" if r >= 0 else errno.errorcode.get(ctypes.get_errno(), "?")))',
  'def sock(label, family, kind):',
  '    try:',
  '        socket.socket(family, kind).close()',
  '        print(label + "=OK")',
  '    except OSError as e:',
  '        print(label + "=" + errno.errorcode.get(e.errno, str(e.errno)))',
]

// KEY_SPEC_PROCESS_KEYRING (-2) dies with the probe; KEYCTL_GET_KEYRING_ID
// is 0 and asks about the session keyring (-3) without creating one.
const KEYRING_ATTEMPTS = [
  ...ATTEMPT,
  'attempt("ADD_KEY", lambda: libc.syscall(ctypes.c_long(nrs["add_key"]),',
  '    b"user", b"srt-host-rules-test", b"x", ctypes.c_size_t(1), ctypes.c_long(-2)))',
  'attempt("REQUEST_KEY", lambda: libc.syscall(ctypes.c_long(nrs["request_key"]),',
  '    b"user", b"srt-host-rules-absent", None, ctypes.c_long(0)))',
  'attempt("KEYCTL", lambda: libc.syscall(ctypes.c_long(nrs["keyctl"]),',
  '    ctypes.c_long(0), ctypes.c_long(-3), ctypes.c_long(0), ctypes.c_long(0), ctypes.c_long(0)))',
].join('\n')

const KEYRINGS_REFUSED = 'ADD_KEY=EPERM\nREQUEST_KEY=EPERM\nKEYCTL=EPERM\n'

// Junk arguments: unfiltered, the kernel answers EFAULT, EBADF and EINVAL
// before any ring exists, so EPERM can only be the filter's.
const IO_URING_ATTEMPTS = [
  ...ATTEMPT,
  'attempt("SETUP", lambda: libc.syscall(ctypes.c_long(nrs["io_uring_setup"]),',
  '    ctypes.c_long(1), None))',
  'attempt("ENTER", lambda: libc.syscall(ctypes.c_long(nrs["io_uring_enter"]),',
  '    ctypes.c_long(-1), ctypes.c_long(0), ctypes.c_long(0), ctypes.c_long(0), None))',
  'attempt("REGISTER", lambda: libc.syscall(ctypes.c_long(nrs["io_uring_register"]),',
  '    ctypes.c_long(-1), ctypes.c_long(0), None, ctypes.c_long(0)))',
].join('\n')

const UNIX_ATTEMPTS = [
  ...ATTEMPT,
  'sock("STREAM", socket.AF_UNIX, socket.SOCK_STREAM)',
  'sock("DGRAM", socket.AF_UNIX, socket.SOCK_DGRAM)',
  'sock("SEQPACKET", socket.AF_UNIX, socket.SOCK_SEQPACKET)',
  'sock("VSOCK", socket.AF_VSOCK, socket.SOCK_STREAM)',
].join('\n')

describe.if(isLinux)('apply-seccomp refuses the host rules', () => {
  let applySeccomp: string

  const underFilter = (script: string, env?: Record<string, string>) =>
    spawnSync(applySeccomp, ['python3', '-c', script], {
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, ...env },
    })

  beforeAll(() => {
    applySeccomp = getApplySeccompBinaryPath()!
    expect(applySeccomp).toBeTruthy()
  })

  it('answers EPERM for each keyring call', () => {
    const r = underFilter(KEYRING_ATTEMPTS)
    expect(r.stdout).toContain(KEYRINGS_REFUSED)
    expect(r.status).toBe(0)
  })

  it('answers EPERM for each io_uring call', () => {
    const r = underFilter(IO_URING_ATTEMPTS)
    expect(r.stdout).toContain('SETUP=EPERM\nENTER=EPERM\nREGISTER=EPERM\n')
    expect(r.status).toBe(0)
  })

  it('SRT_ALLOW_UNIX_SOCKETS=1 on the helper leaves out only the unix filter', () => {
    const r = underFilter(
      [KEYRING_ATTEMPTS, IO_URING_ATTEMPTS, UNIX_ATTEMPTS].join('\n'),
      { SRT_ALLOW_UNIX_SOCKETS: '1' },
    )
    expect(r.stdout).toContain(KEYRINGS_REFUSED)
    expect(r.stdout).toContain('SETUP=EPERM')
    expect(r.stdout).toContain('STREAM=OK')
    expect(r.stdout).toContain('DGRAM=OK')
    expect(r.stdout).toContain('SEQPACKET=OK')
    expect(r.stdout).toContain('VSOCK=EPERM')
    expect(r.status).toBe(0)
  })

  it('any value but 1 keeps the unix filter', () => {
    for (const value of ['0', '', 'true', 'yes']) {
      const r = underFilter(UNIX_ATTEMPTS, { SRT_ALLOW_UNIX_SOCKETS: value })
      expect(r.stdout).toContain('STREAM=EPERM')
      expect(r.status).toBe(0)
    }
  })

  it("removes the variable from the command's environment", () => {
    const r = spawnSync(applySeccomp, ['env'], {
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, SRT_ALLOW_UNIX_SOCKETS: '1' },
    })
    expect(r.stdout).not.toContain('SRT_ALLOW_UNIX_SOCKETS')
    expect(r.status).toBe(0)
  })
})

describe.if(isLinux)('the host rules in the full Linux sandbox', () => {
  beforeAll(async () => {
    expect(checkLinuxDependencies().errors).toEqual([])
    await SandboxManager.reset()
  })

  afterAll(async () => {
    await SandboxManager.reset()
  })

  const wrapDefault = (script: string) =>
    wrapCommandWithSandboxLinux({
      command: quote(['python3', '-c', script]),
      needsNetworkRestriction: false,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
    })

  it('refuses the keyring calls under the default configuration', async () => {
    const wrapped = await wrapDefault(KEYRING_ATTEMPTS)
    const r = await spawnAsync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 15000,
    })
    expect(r.stdout).toContain(KEYRINGS_REFUSED)
    expect(r.status).toBe(0)
  })

  it('is not taken from the caller environment', async () => {
    // A caller with SRT_ALLOW_UNIX_SOCKETS=1 in its own environment opts
    // nothing out: the wrap clears the variable (bwrap --unsetenv) and pins
    // it on the helper's command line.
    const wrapped = await wrapDefault(UNIX_ATTEMPTS)
    const r = await spawnAsync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 15000,
      env: { ...process.env, SRT_ALLOW_UNIX_SOCKETS: '1' },
    })
    expect(r.stdout).toContain('STREAM=EPERM')
    expect(r.stdout).toContain('DGRAM=EPERM')
    expect(r.stdout).toContain('SEQPACKET=EPERM')
    expect(r.stdout).toContain('VSOCK=EPERM')
    expect(r.status).toBe(0)
  })

  it("a key the caller holds is out of the command's reach", async () => {
    // The caller joins a session keyring and leaves a canary in it, the way
    // a login's pam_keyinit does; the sandboxed command inherits that
    // keyring. request_key must answer EPERM — ENOKEY would mean the filter
    // is off and only the canary was missed — and nothing the command does
    // may plant a key the caller would find afterwards.
    const plant = [
      'import ctypes, os, sys',
      'libc = ctypes.CDLL(None, use_errno=True)',
      'import platform',
      'nrs = {"x86_64": (248, 250), "aarch64": (217, 219)}[platform.machine()]',
      'if libc.syscall(ctypes.c_long(nrs[1]), ctypes.c_long(1), b"srt-host-rules-session") < 0:',
      '    sys.exit("could not join a session keyring")',
      'if libc.syscall(ctypes.c_long(nrs[0]), b"user", b"srt-host-rules-canary",',
      '        b"made-up-word", ctypes.c_size_t(12), ctypes.c_long(-3)) < 0:',
      '    sys.exit("could not add the canary")',
      'os.execvp(sys.argv[1], sys.argv[1:])',
    ].join('\n')
    const probe = [
      ...ATTEMPT,
      'attempt("CANARY", lambda: libc.syscall(ctypes.c_long(nrs["request_key"]),',
      '    b"user", b"srt-host-rules-canary", None, ctypes.c_long(0)))',
    ].join('\n')

    const wrapped = await wrapDefault(probe)
    const r = await spawnAsync(
      quote(['python3', '-c', plant, 'sh', '-c', wrapped]),
      { shell: true, encoding: 'utf8', timeout: 15000 },
    )
    expect(r.stdout).toContain('CANARY=EPERM')
    expect(r.status).toBe(0)
  })
})
