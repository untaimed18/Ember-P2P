import { invoke } from '@tauri-apps/api/core';
import type { EmberDiagnostics, EmberPingResult } from '$lib/types';

/**
 * Fetch a snapshot of the Ember mesh diagnostic counters: EPX events,
 * LowID broker outcomes, native-transport ping counters, session
 * count, and the local Noise X25519 public key. Backs the dev panel
 * at `/dev/ember` and is also useful from devtools when debugging
 * harness flows.
 */
export async function getEmberDiagnostics(): Promise<EmberDiagnostics> {
  return invoke<EmberDiagnostics>('get_ember_diagnostics');
}

/**
 * Send an Ember-native `Ping` to a peer over the Noise transport and
 * await the matching `Pong`. `peerPubkeyHex` is optional — when
 * omitted (or empty) the backend resolves the peer's Noise pubkey
 * from the cache populated by KAD source publishes.
 *
 * Returns a structured result rather than throwing: `success: true`
 * with an `rtt_ms`, or `success: false` with a human-readable
 * `error`. This matches the harness flow where every ping outcome
 * (timeout, no cached pubkey, transport disabled) carries useful
 * information for the user.
 */
export async function emberPingPeer(args: {
  peerIp: string;
  peerPort: number;
  peerPubkeyHex?: string;
  timeoutMs?: number;
}): Promise<EmberPingResult> {
  return invoke<EmberPingResult>('ember_ping_peer', {
    peerIp: args.peerIp,
    peerPort: args.peerPort,
    peerPubkeyHex: args.peerPubkeyHex && args.peerPubkeyHex.length > 0
      ? args.peerPubkeyHex
      : undefined,
    timeoutMs: args.timeoutMs,
  });
}

/**
 * Ask a peer to send its current EPX source/peer payload over the
 * encrypted Noise channel via an `ExchangeRequest`. `peerPubkeyHex` is
 * optional with the same KAD-cache fallback as {@link emberPingPeer}.
 *
 * Resolves once the request is dispatched. The peer's reply
 * (`ExchangeData`) is ingested asynchronously by the network receive
 * loop, so observe `ember_exchange_received` / `ember_peers_known` in
 * {@link getEmberDiagnostics} to confirm the round-trip. Rejects (with a
 * human-readable string) if the transport is disabled or no pubkey can
 * be resolved.
 */
export async function emberRequestSources(args: {
  peerIp: string;
  peerPort: number;
  peerPubkeyHex?: string;
}): Promise<void> {
  return invoke<void>('ember_request_sources', {
    peerIp: args.peerIp,
    peerPort: args.peerPort,
    peerPubkeyHex: args.peerPubkeyHex && args.peerPubkeyHex.length > 0
      ? args.peerPubkeyHex
      : undefined,
  });
}
