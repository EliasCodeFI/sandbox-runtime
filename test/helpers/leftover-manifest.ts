import {
  chmodSync,
  existsSync,
  mkdirSync,
  readlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'

/**
 * What a killed process leaves beside its mount points: the manifest of a wrap
 * that named `paths`, written into `dir` a minute ago by a process that is
 * gone. Only a manifest makes a path a mount point, so this is what tells a
 * leftover from somebody's own file. Returns where it is written.
 */
export function leaveManifestNaming(dir: string, paths: string[]): string {
  // A pid nothing in this PID namespace has.
  let pid = 4194000
  while (existsSync(`/proc/${pid}`)) pid--
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
  const file = join(
    dir,
    `${pid}-${Math.random().toString(16).slice(2).padEnd(16, '0')}.json`,
  )
  writeFileSync(
    file,
    JSON.stringify({
      version: 1,
      pid,
      start: '1',
      ns: readlinkSync('/proc/self/ns/pid'),
      created: Date.now() - 60_000,
      paths,
      sources: [],
    }),
    { mode: 0o600 },
  )
  return file
}
