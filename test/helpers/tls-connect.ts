import { connect, type ConnectionOptions, type TLSSocket } from 'node:tls'

/**
 * `connect` of 'node:tls', with its types. The Bun type package redeclares it
 * in terms of names that @types/node 22 declares in 'tls', not in 'node:tls',
 * so as imported it takes and returns an untyped value.
 */
export const tlsConnect: (
  options: ConnectionOptions,
  secureConnectListener?: () => void,
) => TLSSocket = connect

// This, and the `satisfies ConnectionOptions` in parent-proxy.ts, check
// something only while ConnectionOptions is itself a real type. Should it
// become untyped too, the directive goes unused and the type check fails.
// @ts-expect-error -- 'servernme' is not an option
void ({ servernme: 'proxy.example' } satisfies ConnectionOptions)
