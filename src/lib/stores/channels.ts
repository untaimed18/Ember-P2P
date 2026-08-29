import { derived, get, writable } from 'svelte/store';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { listChannels, listChannelTransfers, type ChannelInfo, type ChannelTransferInfo } from '$lib/api/channels';
import { isAppVisible } from '$lib/utils';
import { toast } from '$lib/stores/toast';
import * as m from '$lib/paraglide/messages';

export const channels = writable<ChannelInfo[]>([]);
export const activeChannelId = writable<string | null>(null);

let lastOpenedChannelId: string | null = null;
/** Whether a stash has happened at all, which is not the same as having stashed
 *  a room. Browsing the directory is a selection too, and treating its `null` as
 *  "nothing stashed" let the page's own load step re-open the newest joined room
 *  on the way back — so leaving Channels from the directory and returning landed
 *  the user in a conversation they had deliberately closed. */
let channelSelectionStashed = false;

export function stashActiveChannelOnLeave(): void {
  lastOpenedChannelId = get(activeChannelId);
  channelSelectionStashed = true;
  activeChannelId.set(null);
}

export function restoreActiveChannelOnEnter(): void {
  if (get(activeChannelId) == null && lastOpenedChannelId) {
    activeChannelId.set(lastOpenedChannelId);
  }
}

/** True when the page should leave the selection alone rather than picking a
 *  room for the user. Consumed once: a later visit with no stash of its own is
 *  a fresh arrival, which is exactly when opening the newest room is helpful. */
export function takeStashedChannelSelection(): boolean {
  const stashed = channelSelectionStashed;
  channelSelectionStashed = false;
  return stashed;
}

const CHANNEL_ID_RE = /^[0-9a-f]{32}$/i;
const MEMBER_PUBKEY_RE = /^[0-9a-f]{64}$/i;
const TOAST_GAP_MS = 15_000;
const lastToastAt = new Map<string, number>();

/**
 * Rooms the user has silenced.
 *
 * A device preference rather than room state, so it lives in `localStorage`
 * instead of the channels table: muting is about this machine's notifications,
 * not something the other members should learn or inherit. Deliberately
 * survives `cleanupChannelsStore` — turning Ember off and on again should not
 * un-silence a room.
 *
 * Suppresses the toast only. Unread counts keep accruing, because a muted room
 * is one you want to read later rather than one you want to miss.
 */
const MUTED_KEY = 'ember.channels.muted.v1';

function loadMuted(): string[] {
  if (typeof localStorage === 'undefined') return [];
  try {
    const raw = localStorage.getItem(MUTED_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    // Normalised on the way in: everything else compares against the lowercase
    // hex the backend emits, so a stray uppercase entry would style the badge
    // as muted while the toast still fired.
    return parsed
      .filter((id): id is string => typeof id === 'string' && CHANNEL_ID_RE.test(id))
      .map((id) => id.toLowerCase());
  } catch {
    return [];
  }
}

export const mutedChannels = writable<string[]>(loadMuted());

mutedChannels.subscribe((ids) => {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(MUTED_KEY, JSON.stringify(ids));
  } catch {
    // Quota exceeded / private mode. The mute still holds for this session.
  }
});

export function toggleChannelMute(channelId: string): void {
  const id = channelId.toLowerCase();
  mutedChannels.update((ids) =>
    ids.includes(id) ? ids.filter((existing) => existing !== id) : [...ids, id],
  );
}

/**
 * Sidebar aggregate. Muted rooms are excluded on purpose: the per-room pill
 * still shows their count, because muting means "later" rather than "never",
 * but a silenced room has no business putting a number on the nav rail.
 */
export const totalChannelUnread = derived(
  [channels, mutedChannels],
  ([list, muted]) =>
    list.reduce(
      (sum, channel) =>
        !channel.in_room || channel.deleted || muted.includes(channel.channel_id)
          ? sum
          : sum + Math.max(0, channel.unread),
      0,
    ),
);

/**
 * Public rooms this device has taken off its list.
 *
 * Discover re-gathers every minute and re-adds anything still listed, so
 * dropping the local row does not remove a public room from the list — it
 * came straight back on the next sweep. This is the record of "not
 * interested" that makes the removal stick.
 *
 * A device preference rather than room state, and deliberately *not* the
 * `deleted` flag on the row: that flag is the tombstone `refuse_deleted_channel`
 * reads, and wanting a room off the list is not the same as never wanting back
 * in. Joining clears the entry, and Settings can clear the whole list.
 */
const HIDDEN_KEY = 'ember.channels.hidden.v1';

function loadHidden(): string[] {
  if (typeof localStorage === 'undefined') return [];
  try {
    const raw = localStorage.getItem(HIDDEN_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((id): id is string => typeof id === 'string' && CHANNEL_ID_RE.test(id))
      .map((id) => id.toLowerCase());
  } catch {
    return [];
  }
}

export const hiddenChannels = writable<string[]>(loadHidden());

hiddenChannels.subscribe((ids) => {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(HIDDEN_KEY, JSON.stringify(ids));
  } catch {
    // Quota exceeded / private mode. Holds for this session.
  }
});

export function hideChannel(channelId: string): void {
  const id = channelId.toLowerCase();
  hiddenChannels.update((ids) => (ids.includes(id) ? ids : [...ids, id]));
}

/** Walking back into a room is the clearest possible statement of interest. */
export function unhideChannel(channelId: string): void {
  const id = channelId.toLowerCase();
  hiddenChannels.update((ids) =>
    ids.includes(id) ? ids.filter((existing) => existing !== id) : ids,
  );
}

/**
 * Members this device hides, by Ed25519 pubkey.
 *
 * The only remedy a non-owner has: banning is owner-and-moderator work, so
 * without this an ordinary member has no way to deal with someone tiresome.
 * Keyed on the identity rather than on (room, identity) because the person is
 * the same person in every room, and stored locally because it is a personal
 * preference that nobody else should learn.
 *
 * Purely presentational — their messages still arrive, are still stored, and
 * still count toward unread. Nothing here is a security boundary.
 */
const IGNORED_KEY = 'ember.channels.ignored.v1';
const IGNORED_NAME_MAX = 64;

export interface IgnoredMember {
  pubkey: string;
  name: string;
}

function parseIgnoredEntry(raw: unknown): IgnoredMember | null {
  if (typeof raw === 'string' && MEMBER_PUBKEY_RE.test(raw)) {
    return { pubkey: raw.toLowerCase(), name: '' };
  }
  if (!raw || typeof raw !== 'object' || !('pubkey' in raw)) return null;
  const pk = (raw as { pubkey: unknown }).pubkey;
  if (typeof pk !== 'string' || !MEMBER_PUBKEY_RE.test(pk)) return null;
  const nameRaw = (raw as { name?: unknown }).name;
  const name = typeof nameRaw === 'string' ? nameRaw.trim().slice(0, IGNORED_NAME_MAX) : '';
  return { pubkey: pk.toLowerCase(), name };
}

function loadIgnored(): IgnoredMember[] {
  if (typeof localStorage === 'undefined') return [];
  try {
    const raw = localStorage.getItem(IGNORED_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    const seen = new Set<string>();
    const out: IgnoredMember[] = [];
    for (const item of parsed) {
      const entry = parseIgnoredEntry(item);
      if (!entry || seen.has(entry.pubkey)) continue;
      seen.add(entry.pubkey);
      out.push(entry);
    }
    return out;
  } catch {
    return [];
  }
}

export const ignoredMembers = writable<IgnoredMember[]>(loadIgnored());

/** Pubkeys only — chat filters and member-row checks still compare hex strings. */
export const ignoredMemberKeys = derived(ignoredMembers, (list) =>
  list.map((entry) => entry.pubkey),
);

ignoredMembers.subscribe((entries) => {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(IGNORED_KEY, JSON.stringify(entries));
  } catch {
    // Quota exceeded / private mode. Holds for this session.
  }
});

export function toggleMemberIgnore(memberPubkey: string, name?: string): void {
  const pk = memberPubkey.toLowerCase();
  const label = typeof name === 'string' ? name.trim().slice(0, IGNORED_NAME_MAX) : '';
  ignoredMembers.update((list) =>
    list.some((entry) => entry.pubkey === pk)
      ? list.filter((entry) => entry.pubkey !== pk)
      : [...list, { pubkey: pk, name: label }],
  );
}

/** Drop a room's mute. Used when the owner deletes it, so the preference
 *  list cannot accumulate ids for rooms the user will never see again.
 *  Leave keeps the row (and the mute) because the user can walk back in. */
export function forgetChannelMute(channelId: string): void {
  const id = channelId.toLowerCase();
  mutedChannels.update((ids) =>
    ids.includes(id) ? ids.filter((existing) => existing !== id) : ids,
  );
}

let initialized = false;
let storeEpoch = 0;
let unlisteners: UnlistenFn[] = [];
/** Bumped by every local unread mutation, so `refreshChannels` can tell whether
 *  the snapshot it awaited is still the newest word on the subject. */
let unreadRevision = 0;

/**
 * Ember Transfers this session, keyed by transfer id.
 *
 * Not persisted, because the backend does not persist them either: a
 * transfer belongs to the session that started it. Terminal rows are kept
 * briefly so "complete" or "declined" is actually seen before it vanishes.
 *
 * Lives in the shell store rather than the Channels page so an offer that
 * arrives while the user is on Library still toasts, and so walking back
 * into Channels still shows in-flight rows.
 */
export const channelTransfers = writable<Record<string, ChannelTransferInfo>>({});

const TERMINAL_XFER: ReadonlyArray<ChannelTransferInfo['status']> = [
  'complete',
  'declined',
  'cancelled',
  'stalled',
  'expired',
  'failed',
  'busy',
  'too_large',
  'not_allowed',
  'source_gone',
];

const xferClearTimers = new Map<string, ReturnType<typeof setTimeout>>();

function scheduleXferClear(xferId: string, epoch: number): void {
  const existing = xferClearTimers.get(xferId);
  if (existing) clearTimeout(existing);
  xferClearTimers.set(
    xferId,
    setTimeout(() => {
      xferClearTimers.delete(xferId);
      if (epoch !== storeEpoch) return;
      channelTransfers.update((cur) => {
        if (!(xferId in cur)) return cur;
        const { [xferId]: _done, ...rest } = cur;
        return rest;
      });
    }, 8000),
  );
}

function toastXferOffer(channelId: string): void {
  if (get(activeChannelId) === channelId) return;
  const room = get(channels).find((c) => c.channel_id === channelId);
  toast(
    room
      ? m.channels_xfer_offer_elsewhere({ room: room.name })
      : m.channels_xfer_offer_elsewhere_unknown(),
  );
}

/** Snapshot of transfers already in flight. Live rows win so an offer that
 *  arrived while this call was outstanding is not wiped. */
export async function mergeChannelTransfers(): Promise<void> {
  const epoch = storeEpoch;
  try {
    const list = await listChannelTransfers();
    if (epoch !== storeEpoch) return;
    channelTransfers.update((cur) => ({
      ...Object.fromEntries(list.map((t) => [t.xfer_id, t])),
      ...cur,
    }));
  } catch (e) {
    console.warn('Channels: could not list transfers already in flight', e);
  }
}

export async function refreshChannels(): Promise<void> {
  const revision = unreadRevision;
  const list = await listChannels();
  // The database is authoritative for unread, but only as of the moment it was
  // read. A message arriving — or the user opening a room — while this call was
  // in flight moves the count *after* that snapshot was taken, and a plain
  // `set` then rolled it back: the badge dropped the new line, or came back on
  // a room being read. Keep whatever the local mutation left when one happened.
  if (revision === unreadRevision) {
    channels.set(list);
  } else {
    channels.update((cur) => {
      const local = new Map(cur.map((channel) => [channel.channel_id, channel.unread]));
      return list.map((channel) =>
        local.has(channel.channel_id)
          ? { ...channel, unread: local.get(channel.channel_id) as number }
          : channel,
      );
    });
  }
  const keep = new Set(list.filter((channel) => !channel.deleted).map((channel) => channel.channel_id));
  mutedChannels.update((ids) => {
    const next = ids.filter((id) => keep.has(id));
    return next.length === ids.length ? ids : next;
  });
}

export function replaceChannel(updated: ChannelInfo): void {
  channels.update((list) =>
    list.map((channel) =>
      channel.channel_id === updated.channel_id ? updated : channel,
    ),
  );
}

/** Insert or replace so join can open the room before `list_channels` returns. */
export function upsertChannel(updated: ChannelInfo): void {
  channels.update((list) => {
    const index = list.findIndex((channel) => channel.channel_id === updated.channel_id);
    if (index === -1) return [...list, updated];
    const next = list.slice();
    next[index] = updated;
    return next;
  });
}

export function setChannelInRoom(channelId: string, inRoom: boolean): void {
  channels.update((list) => {
    if (!list.some((channel) => channel.channel_id === channelId && channel.in_room !== inRoom)) {
      return list;
    }
    return list.map((channel) =>
      channel.channel_id === channelId ? { ...channel, in_room: inRoom } : channel,
    );
  });
}

export function setChannelMemberCount(channelId: string, count: number): void {
  channels.update((list) => {
    if (!list.some((channel) => channel.channel_id === channelId && channel.member_count !== count)) {
      return list;
    }
    return list.map((channel) =>
      channel.channel_id === channelId ? { ...channel, member_count: count } : channel,
    );
  });
}

export function clearChannelUnread(channelId: string): void {
  unreadRevision++;
  channels.update((list) => {
    // Hand back the same array when there is nothing to clear. Allocating a
    // fresh one regardless re-invalidated every `$channels` reader, and
    // `ChatConversation` calls this from the same effect that reads the channel
    // it is displaying — so an unconditional copy fed that effect its own
    // output and spun forever. `bumpChannelUnread` already bails this way.
    if (!list.some((channel) => channel.channel_id === channelId && channel.unread !== 0)) {
      return list;
    }
    return list.map((channel) =>
      channel.channel_id === channelId ? { ...channel, unread: 0 } : channel,
    );
  });
}

export function bumpChannelUnread(channelId: string): void {
  if (get(activeChannelId) === channelId) return;
  unreadRevision++;
  channels.update((list) => {
    if (!list.some((channel) => channel.channel_id === channelId && channel.in_room && !channel.deleted)) {
      return list;
    }
    return list.map((channel) =>
      channel.channel_id === channelId
        ? { ...channel, unread: channel.unread + 1 }
        : channel,
    );
  });
}

function validChannelId(raw: unknown): string | null {
  return typeof raw === 'string' && CHANNEL_ID_RE.test(raw) ? raw.toLowerCase() : null;
}

function previewText(raw: unknown): string {
  const text = typeof raw === 'string' ? raw.replace(/\s+/g, ' ').trim() : '';
  if (!text) return '';
  return text.length > 80 ? `${text.slice(0, 77)}…` : text;
}

function maybeToastChannelMessage(channelId: string, message: string, senderPubkey?: string) {
  if (isAppVisible() && get(activeChannelId) === channelId) return;
  if (get(mutedChannels).includes(channelId)) return;
  // Ignoring somebody is presentational, and a toast quoting them is the least
  // ignorable presentation there is: it interrupts whatever page the user is on
  // with the text they asked not to see. The unread count still moves, which is
  // the documented half of the bargain.
  if (senderPubkey && get(ignoredMemberKeys).includes(senderPubkey.toLowerCase())) return;
  const now = Date.now();
  const prev = lastToastAt.get(channelId) ?? 0;
  if (now - prev < TOAST_GAP_MS) return;
  lastToastAt.set(channelId, now);
  const row = get(channels).find((channel) => channel.channel_id === channelId);
  if (row && (!row.in_room || row.deleted)) return;
  const name = row?.name ?? m.nav_channels();
  const preview = previewText(message);
  if (!preview) return;
  toast(m.channels_message_toast({ name, preview }));
}

export async function initChannelsStore() {
  if (initialized) return;
  initialized = true;
  const myEpoch = storeEpoch;
  const registered: UnlistenFn[] = [];
  try {
    registered.push(
      await listen<{
        channel_id: string;
        direction?: string;
        message?: string;
        sender_pubkey?: string;
      }>('ember:channel-message', (event) => {
        const channelId = validChannelId(event.payload?.channel_id);
        if (!channelId) return;
        if (event.payload.direction && event.payload.direction !== 'received') {
          return;
        }
        if (!get(channels).some((channel) => channel.channel_id === channelId)) {
          // No bump afterwards. The row is missing because this is the first
          // line from a room that only just appeared, and the count the fetch
          // brings back is read from the database — which already holds the
          // message that triggered this event. Adding one more counted it twice.
          refreshChannels().catch(() => {});
        } else {
          bumpChannelUnread(channelId);
        }
        maybeToastChannelMessage(
          channelId,
          event.payload.message ?? '',
          event.payload.sender_pubkey,
        );
      }),
    );
    registered.push(
      await listen<{ channel_id: string; successor_id?: string }>('ember:channel-handoff', () => {
        refreshChannels().catch(() => {});
      }),
    );
    registered.push(
      await listen<{
        xfer_id: string;
        channel_id: string;
        peer_pubkey: string;
        name: string;
        size: number;
      }>('ember:xfer-offer', (event) => {
        if (myEpoch !== storeEpoch) return;
        const p = event.payload;
        const channelId = validChannelId(p?.channel_id);
        const xferId = typeof p?.xfer_id === 'string' ? p.xfer_id : '';
        if (!channelId || !xferId) return;
        channelTransfers.update((cur) => ({
          ...cur,
          [xferId]: {
            xfer_id: xferId,
            channel_id: channelId,
            peer_pubkey: p.peer_pubkey,
            direction: 'receive',
            name: p.name,
            size: p.size,
            transferred: 0,
            status: 'awaiting',
          },
        }));
        toastXferOffer(channelId);
      }),
    );
    registered.push(
      await listen<ChannelTransferInfo>('ember:xfer-update', (event) => {
        if (myEpoch !== storeEpoch) return;
        const t = event.payload;
        if (!t?.xfer_id) return;
        channelTransfers.update((cur) => ({ ...cur, [t.xfer_id]: t }));
        if (TERMINAL_XFER.includes(t.status)) {
          scheduleXferClear(t.xfer_id, myEpoch);
        }
      }),
    );
    if (myEpoch !== storeEpoch) {
      for (const fn of registered) fn();
      return;
    }
    unlisteners = registered;
    await refreshChannels().catch(() => {});
    void mergeChannelTransfers();
  } catch (err) {
    for (const fn of registered) {
      try {
        fn();
      } catch {
        /* ignore */
      }
    }
    initialized = false;
    throw err;
  }
}

export function cleanupChannelsStore() {
  storeEpoch++;
  for (const unlisten of unlisteners) {
    try {
      unlisten();
    } catch (e) {
      console.warn('Failed to unlisten channels store listener:', e);
    }
  }
  unlisteners = [];
  initialized = false;
  lastToastAt.clear();
  lastOpenedChannelId = null;
  for (const timer of xferClearTimers.values()) clearTimeout(timer);
  xferClearTimers.clear();
  channelTransfers.set({});
  channels.set([]);
  activeChannelId.set(null);
}
