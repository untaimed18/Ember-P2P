import { invoke } from '@tauri-apps/api/core';

/**
 * Per-peer reputation record returned by `get_peer_reputation`.
 *
 * Mirrors the backend `PeerReputationInfo` struct exposed from
 * `network::mod.rs`. `score` is the signed integer the backend uses
 * for ban decisions; positive = reliable, zero = neutral, negative =
 * accumulating bad-behaviour signals. A peer is banned when either
 * `is_banned` flips true OR score crosses the backend's ban
 * threshold — the UI should treat the flag as authoritative.
 *
 * `first_seen` / `last_interaction` are unix epoch seconds, so
 * `last_interaction - first_seen` is the "known-for" duration.
 */
export interface PeerReputationInfo {
  score: number;
  successful_transfers: number;
  failed_transfers: number;
  is_banned: boolean;
  first_seen: number;
  last_interaction: number;
}

/**
 * Aggregate counters from the in-memory `ReputationTracker`. Suitable
 * for a "tracked / banned" row on the statistics or security page.
 */
export interface ReputationStatsInfo {
  tracked_peers: number;
  banned_peers: number;
  /**
   * Total IP addresses in the enforced ban set — manual bans plus the
   * automatic IP bans (request flooding, sustained corruption) that
   * don't go through the per-user-hash reputation tracker. Distinct
   * from `banned_peers`, which only counts reputation-threshold bans.
   */
  banned_ips: number;
}

/**
 * Fetch the reputation record for a specific peer user-hash (32 hex
 * chars). Returns `null` when the tracker has no entry for the peer
 * (e.g. a fresh connection that hasn't logged a success or failure
 * yet).
 *
 * The backend caps tracker size, so very-long-idle entries may have
 * been evicted; callers should treat `null` as "no record" rather
 * than "peer has never been seen".
 */
export async function getPeerReputation(userHashHex: string): Promise<PeerReputationInfo | null> {
  return invoke('get_peer_reputation', { userHashHex });
}

/**
 * Fetch aggregate reputation counters for the statistics / security
 * page. Cheap — reads in-memory counters with no I/O.
 */
export async function getReputationStats(): Promise<ReputationStatsInfo> {
  return invoke('get_reputation_stats');
}

/**
 * Categorise a `PeerReputationInfo.score` into the set of labels the
 * UI renders as a trust badge. The thresholds mirror the backend's
 * `ReputationTracker` notion of "trustworthy" vs "suspect" — kept in
 * this wrapper because the backend doesn't expose them directly and
 * changing them would ripple into too many per-row computations.
 */
export type ReputationLabel = 'banned' | 'trusted' | 'neutral' | 'suspect' | 'unknown';

export function labelForReputation(rep: PeerReputationInfo | null | undefined): ReputationLabel {
  if (!rep) return 'unknown';
  if (rep.is_banned) return 'banned';
  if (rep.score >= 50) return 'trusted';
  if (rep.score <= -20) return 'suspect';
  return 'neutral';
}
