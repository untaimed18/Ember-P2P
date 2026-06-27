import { invoke } from '@tauri-apps/api/core';
import type {
  EmberDiagnostics,
  EmberDhtContact,
  EmberDhtFindResult,
  EmberDhtFindValueResult,
  EmberDhtMaintenanceResult,
  EmberDhtPublishResult,
  EmberPingResult,
} from '$lib/types';

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

/**
 * Snapshot the Ember DHT routing table — the contacts this node has
 * learned (from signed PING/PONG traffic) or been seeded with. Backs
 * the contacts table on the `/dev/ember` panel.
 */
export async function getEmberDhtContacts(): Promise<EmberDhtContact[]> {
  return invoke<EmberDhtContact[]>('get_ember_dht_contacts');
}

/**
 * Manually seed an Ember DHT contact. `ed25519PubkeyHex` and
 * `noisePubkeyHex` are the 64-char hex keys shown on the peer's dev
 * panel; the node ID is derived from the Ed25519 key by the backend.
 */
export async function addEmberDhtContact(args: {
  peerIp: string;
  peerPort: number;
  ed25519PubkeyHex: string;
  noisePubkeyHex: string;
}): Promise<void> {
  return invoke('add_ember_dht_contact', {
    peerIp: args.peerIp,
    peerPort: args.peerPort,
    ed25519PubkeyHex: args.ed25519PubkeyHex,
    noisePubkeyHex: args.noisePubkeyHex,
  });
}

/**
 * Send an Ember DHT `PING` and await the `PONG`. Like {@link emberPingPeer}
 * but drives the DHT path, so a successful round trip also seeds both
 * nodes' routing tables. `peerPubkeyHex` is the peer's Noise key;
 * omit it to resolve from the KAD-fed cache.
 */
export async function emberDhtPingPeer(args: {
  peerIp: string;
  peerPort: number;
  peerPubkeyHex?: string;
  timeoutMs?: number;
}): Promise<EmberPingResult> {
  return invoke<EmberPingResult>('ember_dht_ping_peer', {
    peerIp: args.peerIp,
    peerPort: args.peerPort,
    peerPubkeyHex: args.peerPubkeyHex && args.peerPubkeyHex.length > 0
      ? args.peerPubkeyHex
      : undefined,
    timeoutMs: args.timeoutMs,
  });
}

/**
 * Send a single Ember DHT `FIND_NODE` to one peer and return the
 * contacts it answers with (its k closest to `targetHex`). One hop —
 * the iterative multi-hop driver lands in a later slice. `targetHex` is
 * an optional 32-char (16-byte) node ID; omit it to let the backend
 * pick a random target. `peerPubkeyHex` is the peer's Noise key; omit
 * it to resolve from the KAD-fed cache.
 */
export async function emberDhtFindNode(args: {
  peerIp: string;
  peerPort: number;
  targetHex?: string;
  peerPubkeyHex?: string;
  timeoutMs?: number;
}): Promise<EmberDhtFindResult> {
  return invoke<EmberDhtFindResult>('ember_dht_find_node', {
    peerIp: args.peerIp,
    peerPort: args.peerPort,
    targetHex: args.targetHex && args.targetHex.length > 0
      ? args.targetHex
      : undefined,
    peerPubkeyHex: args.peerPubkeyHex && args.peerPubkeyHex.length > 0
      ? args.peerPubkeyHex
      : undefined,
    timeoutMs: args.timeoutMs,
  });
}

/**
 * Run an iterative (multi-hop) Ember DHT lookup for `targetHex`. Unlike
 * {@link emberDhtFindNode} this takes no peer address — it seeds from
 * the local routing table and loops `FIND_NODE` across the closest
 * contacts it learns until the search converges, returning the closest
 * contacts that responded. Seed or DHT-ping at least one contact first.
 * `targetHex` is an optional 32-char (16-byte) node ID; omit it for a
 * random self-style probe.
 */
export async function emberDhtIterativeFindNode(args: {
  targetHex?: string;
  timeoutMs?: number;
}): Promise<EmberDhtFindResult> {
  return invoke<EmberDhtFindResult>('ember_dht_iterative_find_node', {
    targetHex: args.targetHex && args.targetHex.length > 0
      ? args.targetHex
      : undefined,
    timeoutMs: args.timeoutMs,
  });
}

/**
 * Publish a signed keyword record into the Ember DHT. The backend signs
 * the record with this node's identity and `STORE`s it on the closest
 * contacts it knows, returning the DHT key it used and how many nodes
 * acknowledged. `fileHashHex` is optional (32-char/16-byte hex); omit it
 * for a random hash. Seed or DHT-ping at least one contact first.
 */
export async function emberDhtPublishKeyword(args: {
  keyword: string;
  fileName: string;
  fileSize: number;
  fileHashHex?: string;
  timeoutMs?: number;
}): Promise<EmberDhtPublishResult> {
  return invoke<EmberDhtPublishResult>('ember_dht_publish_keyword', {
    keyword: args.keyword,
    fileName: args.fileName,
    fileSize: args.fileSize,
    fileHashHex: args.fileHashHex && args.fileHashHex.length > 0
      ? args.fileHashHex
      : undefined,
    timeoutMs: args.timeoutMs,
  });
}

/**
 * Run an iterative Ember DHT `FIND_VALUE` for `keyword`: the backend
 * drives a multi-hop search that gathers signed records for the
 * keyword's key and returns the ones whose publisher signature verifies.
 * Seeds from the local routing table, so seed/DHT-ping a contact first.
 */
export async function emberDhtFindValue(args: {
  keyword: string;
  timeoutMs?: number;
}): Promise<EmberDhtFindValueResult> {
  return invoke<EmberDhtFindValueResult>('ember_dht_find_value', {
    keyword: args.keyword,
    timeoutMs: args.timeoutMs,
  });
}

/**
 * Force one Ember DHT maintenance cycle (slice 6): refresh stale buckets,
 * liveness-ping stale contacts, and republish locally-stored records. The
 * backend runs this automatically on a timer; this triggers it on demand
 * (ignoring staleness gates) so the effect can be observed immediately.
 * The returned tally is what the cycle initiated — evictions and refresh
 * results land asynchronously and show up in {@link getEmberDiagnostics}.
 */
export async function emberDhtRunMaintenance(): Promise<EmberDhtMaintenanceResult> {
  return invoke<EmberDhtMaintenanceResult>('ember_dht_run_maintenance');
}
