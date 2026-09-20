/**
 * Room rosters, kept outside the Channels page so a room is not only a thing
 * that page can draw.
 *
 * The member list used to be `$state` on `/channels`. That was fine while a
 * room could only ever be on screen there, but it is what made a room
 * unopenable anywhere else: `ChatConversation` needs display labels and
 * mention candidates for a channel, and both are derived from the roster. A
 * store means the chat dock can host a room tab with the same names the page
 * shows, and that leaving `/channels` no longer throws the roster away.
 *
 * Presence is folded in here too, for the same reason. The page's listener
 * only applied deltas to the room it had selected; a room open in the dock
 * while the user is on Library has to keep its dots moving as well.
 */
import { get, writable } from 'svelte/store';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import {
  channelPresenceConfig,
  listChannelMembers,
  type ChannelMemberInfo,
  type ChannelPresenceConfig,
  type ChannelPresenceDelta,
} from '$lib/api/channels';
import { disambiguatedMemberName } from '$lib/utils';
import * as m from '$lib/paraglide/messages';

export type RosterState = {
  members: ChannelMemberInfo[];
  loading: boolean;
  /** Translated message, or null. Held per room so one room's failure does not
   *  read as every room's. */
  error: string | null;
};

const EMPTY: RosterState = { members: [], loading: false, error: null };

/** Keyed by lowercase channel id. */
export const channelRosters = writable<Record<string, RosterState>>({});

/**
 * The windows the presence dots are drawn with, read from the backend rather
 * than declared here: the same numbers decide which members this device
 * gossips to, so a copy in the UI is one that can drift from the protocol.
 */
export const presenceConfig = writable<ChannelPresenceConfig>({
  mesh_fresh_secs: 150,
  dht_fresh_secs: 20 * 60,
  beat_secs: 45,
});

/**
 * Ticks the clock the freshness check reads.
 *
 * Presence is measured against wall-clock, which no amount of roster
 * reactivity advances on its own — without this a member keeps whatever dot
 * they had when the list was last fetched, potentially long past the window.
 */
export const presenceNow = writable(Math.floor(Date.now() / 1000));

export type Presence = 'online' | 'away' | 'offline';

/**
 * Which of three states to draw a member in.
 *
 * `online` is mesh-confirmed: they announced themselves on the live mesh, or
 * we verified a frame they signed, within a few beats. `away` is the DHT
 * backstop — seen this quarter hour, which is the strongest claim a
 * ten-minute republish read by a lossy walk can support. Collapsing the two
 * made the roster wrong in both directions at once: someone sitting quietly
 * had no dot, and someone who had left kept a green one for twenty minutes.
 */
export function presenceOf(
  mem: ChannelMemberInfo,
  nowSecs: number,
  config: ChannelPresenceConfig,
): Presence {
  if (mem.is_self) return 'online';
  if (mem.last_seen <= 0) return 'offline';
  const age = nowSecs - mem.last_seen;
  if (age <= config.mesh_fresh_secs) return 'online';
  if (age <= config.dht_fresh_secs) return 'away';
  return 'offline';
}

/**
 * How many of a roster are actually in the room.
 *
 * Matches what `list_channels` counts on the backend — not banned, and seen
 * inside the DHT window — so the sidebar does not jump when a room is opened
 * and then snap back on the next refresh. The whole roster is the wrong number
 * to show: it includes everyone ever counted present, which in a public room
 * is every visitor it has had.
 */
export function presentCount(
  mems: ChannelMemberInfo[],
  nowSecs: number,
  config: ChannelPresenceConfig,
): number {
  return mems.filter((mem) => !mem.banned && presenceOf(mem, nowSecs, config) !== 'offline').length;
}

/** How this device labels one member in a room: "You", a plain nickname, or a
 *  nickname disambiguated with a key fragment when the room has two of them. */
export function memberLabel(
  mem: { nickname: string; member_pubkey: string; is_self: boolean },
  roster: ChannelMemberInfo[],
): string {
  if (mem.is_self) return m.channels_you();
  return disambiguatedMemberName(
    mem.nickname,
    mem.member_pubkey,
    roster.map((other) => other.nickname),
  );
}

export function rosterOf(channelId: string): RosterState {
  return get(channelRosters)[channelId.toLowerCase()] ?? EMPTY;
}

/** The roster of one room out of a snapshot of them all.
 *
 *  Taking the map rather than reading the store is what lets a component
 *  derive from it: a helper that calls `get()` internally has no dependency
 *  for Svelte to track, so the labels would never refresh when the roster
 *  loaded. */
export function membersIn(
  rosters: Record<string, RosterState>,
  channelId: string | null | undefined,
): ChannelMemberInfo[] {
  if (!channelId) return [];
  return rosters[channelId.toLowerCase()]?.members ?? [];
}

/** Member pubkey → display label, from a roster already in hand. */
export function memberLabelsFrom(roster: ChannelMemberInfo[]): Record<string, string> {
  return Object.fromEntries(roster.map((mem) => [mem.member_pubkey, memberLabel(mem, roster)]));
}

/** Member pubkey → display label, for one room. */
export function memberLabelsFor(channelId: string): Record<string, string> {
  return memberLabelsFrom(rosterOf(channelId).members);
}

/**
 * Handles the composer can complete after `@`.
 *
 * Raw nicknames, not labels: the label map carries display forms — "You", or
 * a disambiguated "Ada (a1b2c3)" — which are right for the roster and wrong to
 * type into a message. Self and banned members are left out; you do not
 * address yourself, and naming someone the room has evicted only invites a
 * reply that will not arrive.
 */
export function mentionCandidatesFrom(roster: ChannelMemberInfo[]): string[] {
  return [
    ...new Set(
      roster
        .filter((mem) => !mem.is_self && !mem.banned && mem.nickname.trim().length > 0)
        .map((mem) => mem.nickname.trim()),
    ),
  ].sort((a, b) => a.localeCompare(b));
}

export function mentionCandidatesFor(channelId: string): string[] {
  return mentionCandidatesFrom(rosterOf(channelId).members);
}

function patch(channelId: string, next: Partial<RosterState>): void {
  const id = channelId.toLowerCase();
  channelRosters.update((cur) => ({
    ...cur,
    [id]: { ...(cur[id] ?? EMPTY), ...next },
  }));
}

/** Per-room fetch generation, so a slow roster read cannot land on top of a
 *  newer one for the same room. Rooms are independent: a reload of room A must
 *  not discard an in-flight read of room B. */
const rosterGen = new Map<string, number>();
let storeEpoch = 0;

/**
 * Load (or reload) one room's roster.
 *
 * Returns the rows so a caller that needs them synchronously — the member
 * count written back to the channels store — does not have to re-read the
 * store and guess whether its own write landed.
 */
export async function loadChannelRoster(channelId: string): Promise<ChannelMemberInfo[] | null> {
  const id = channelId.toLowerCase();
  const gen = (rosterGen.get(id) ?? 0) + 1;
  rosterGen.set(id, gen);
  const epoch = storeEpoch;
  patch(id, { loading: true, error: null });
  try {
    const members = await listChannelMembers(channelId);
    if (epoch !== storeEpoch || rosterGen.get(id) !== gen) return null;
    patch(id, { members, loading: false, error: null });
    return members;
  } catch (e) {
    if (epoch !== storeEpoch || rosterGen.get(id) !== gen) return null;
    patch(id, { loading: false, error: String(e) });
    throw e;
  }
}

/** Drop a room we are no longer in, so its roster cannot be drawn from cache
 *  after a leave and cannot hold members in memory for the session. */
export function clearChannelRoster(channelId: string): void {
  const id = channelId.toLowerCase();
  rosterGen.set(id, (rosterGen.get(id) ?? 0) + 1);
  channelRosters.update((cur) => {
    if (!(id in cur)) return cur;
    const { [id]: _gone, ...rest } = cur;
    return rest;
  });
}

/**
 * Fold rows whose `last_seen` moved into a roster in place.
 *
 * A delta, so a room where somebody is talking does not re-read the whole
 * member list to learn that one number changed. Only ever forward: a late
 * batch must not walk a row back to an older stamp than it already holds.
 *
 * Clamped to wall-clock because not every caller's stamp is already bounded.
 * The backend clamps what it emits, but a live chat line carries the gossip
 * envelope's own timestamp, which a member may legitimately set up to
 * `CHANNEL_GOSSIP_MAX_FUTURE_SKEW_SECS` ahead — and a future stamp keeps the
 * presence dot lit until wall-clock catches up *plus* the freshness window.
 */
export function applyPresenceDelta(
  channelId: string,
  rows: { member_pubkey: string; last_seen: number }[],
): void {
  if (rows.length === 0) return;
  const id = channelId.toLowerCase();
  const current = get(channelRosters)[id];
  if (!current || current.members.length === 0) return;
  const wall = Math.floor(Date.now() / 1000);
  const byKey = new Map(rows.map((row) => [row.member_pubkey.toLowerCase(), row.last_seen]));
  let changed = false;
  const members = current.members.map((mem) => {
    const at = byKey.get(mem.member_pubkey.toLowerCase());
    if (at === undefined) return mem;
    const heard = Math.min(at, wall);
    if (heard <= mem.last_seen) return mem;
    changed = true;
    return { ...mem, last_seen: heard };
  });
  if (!changed) return;
  patch(id, { members });
  presenceNow.set(wall);
}

/**
 * Advance one roster row's last_seen from a live chat line.
 *
 * The backend sends the same fact as a presence delta a moment later, so this
 * only buys the tick in between — but that tick is while the line is appearing
 * on screen, which is exactly when a reader looks across at the member who
 * sent it. Joins and leaves stay with presence ingest.
 */
export function noteMemberHeard(channelId: string, pubkey: string, at: number): void {
  if (!pubkey || at <= 0) return;
  applyPresenceDelta(channelId, [{ member_pubkey: pubkey, last_seen: at }]);
}

let initialized = false;
let unlisteners: UnlistenFn[] = [];
let presenceTicker: ReturnType<typeof setInterval> | null = null;

/** Re-read the freshness windows the dots are drawn with. Best effort: the
 *  defaults above are the shipped constants, so a failure costs accuracy on a
 *  future change rather than a broken roster. */
async function seedPresenceConfig(epoch: number): Promise<void> {
  try {
    const config = await channelPresenceConfig();
    if (epoch === storeEpoch) presenceConfig.set(config);
  } catch (e) {
    console.warn('channelRoster: presence config unavailable, using defaults', e);
  }
}

export async function initChannelRosterStore(): Promise<void> {
  if (initialized) return;
  initialized = true;
  const epoch = storeEpoch;
  const registered: UnlistenFn[] = [];
  try {
    registered.push(
      await listen<ChannelPresenceDelta>('ember:channel-presence', (event) => {
        if (epoch !== storeEpoch) return;
        const id = event.payload?.channel_id;
        if (typeof id !== 'string') return;
        applyPresenceDelta(id, event.payload.members ?? []);
      }),
    );
    registered.push(
      await listen<{ channel_id: string; sender_pubkey?: string; timestamp?: number }>(
        'ember:channel-message',
        (event) => {
          if (epoch !== storeEpoch) return;
          const id = event.payload?.channel_id;
          if (typeof id !== 'string') return;
          noteMemberHeard(id, event.payload.sender_pubkey ?? '', event.payload.timestamp ?? 0);
        },
      ),
    );
    if (epoch !== storeEpoch) {
      for (const off of registered) off();
      return;
    }
    unlisteners = registered;
  } catch (e) {
    for (const off of registered) {
      try {
        off();
      } catch {
        /* ignore */
      }
    }
    initialized = false;
    console.error('channelRoster: failed to register listeners', e);
    throw e;
  }
  // Wall-clock only, so a quiet room's dots still age out. Cheap: one store
  // write a beat, and the dots are the only readers.
  presenceTicker = setInterval(() => {
    presenceNow.set(Math.floor(Date.now() / 1000));
  }, 15_000);
  void seedPresenceConfig(epoch);
}

export function cleanupChannelRosterStore(): void {
  storeEpoch++;
  for (const off of unlisteners) {
    try {
      off();
    } catch (e) {
      console.warn('channelRoster: failed to unlisten', e);
    }
  }
  unlisteners = [];
  initialized = false;
  if (presenceTicker !== null) {
    clearInterval(presenceTicker);
    presenceTicker = null;
  }
  rosterGen.clear();
  channelRosters.set({});
  presenceNow.set(Math.floor(Date.now() / 1000));
}
