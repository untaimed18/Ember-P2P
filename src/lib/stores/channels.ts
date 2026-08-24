import { derived, get, writable } from 'svelte/store';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { listChannels, type ChannelInfo } from '$lib/api/channels';
import { isAppVisible } from '$lib/utils';
import { toast } from '$lib/stores/toast';
import * as m from '$lib/paraglide/messages';

export const channels = writable<ChannelInfo[]>([]);
export const activeChannelId = writable<string | null>(null);

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
        muted.includes(channel.channel_id) ? sum : sum + Math.max(0, channel.unread),
      0,
    ),
);

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

function loadIgnored(): string[] {
  if (typeof localStorage === 'undefined') return [];
  try {
    const raw = localStorage.getItem(IGNORED_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((pk): pk is string => typeof pk === 'string' && MEMBER_PUBKEY_RE.test(pk))
      .map((pk) => pk.toLowerCase());
  } catch {
    return [];
  }
}

export const ignoredMembers = writable<string[]>(loadIgnored());

ignoredMembers.subscribe((keys) => {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(IGNORED_KEY, JSON.stringify(keys));
  } catch {
    // Quota exceeded / private mode. Holds for this session.
  }
});

export function toggleMemberIgnore(memberPubkey: string): void {
  const pk = memberPubkey.toLowerCase();
  ignoredMembers.update((keys) =>
    keys.includes(pk) ? keys.filter((existing) => existing !== pk) : [...keys, pk],
  );
}

/** Drop a room's mute when it is left, so the list cannot accumulate ids for
 *  rooms the user will never see again. */
export function forgetChannelMute(channelId: string): void {
  const id = channelId.toLowerCase();
  mutedChannels.update((ids) =>
    ids.includes(id) ? ids.filter((existing) => existing !== id) : ids,
  );
}

let initialized = false;
let storeEpoch = 0;
let unlisteners: UnlistenFn[] = [];

export async function refreshChannels(): Promise<void> {
  const list = await listChannels();
  channels.set(list);
}

export function replaceChannel(updated: ChannelInfo): void {
  channels.update((list) =>
    list.map((channel) =>
      channel.channel_id === updated.channel_id ? updated : channel,
    ),
  );
}

export function clearChannelUnread(channelId: string): void {
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
  channels.update((list) => {
    if (!list.some((channel) => channel.channel_id === channelId)) {
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

function maybeToastChannelMessage(channelId: string, message: string) {
  if (isAppVisible() && get(activeChannelId) === channelId) return;
  if (get(mutedChannels).includes(channelId)) return;
  const now = Date.now();
  const prev = lastToastAt.get(channelId) ?? 0;
  if (now - prev < TOAST_GAP_MS) return;
  lastToastAt.set(channelId, now);
  const name =
    get(channels).find((channel) => channel.channel_id === channelId)?.name ??
    m.nav_channels();
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
      }>('ember:channel-message', (event) => {
        const channelId = validChannelId(event.payload?.channel_id);
        if (!channelId) return;
        if (event.payload.direction && event.payload.direction !== 'received') {
          return;
        }
        if (!get(channels).some((channel) => channel.channel_id === channelId)) {
          refreshChannels()
            .then(() => bumpChannelUnread(channelId))
            .catch(() => {});
        } else {
          bumpChannelUnread(channelId);
        }
        maybeToastChannelMessage(channelId, event.payload.message ?? '');
      }),
    );
    registered.push(
      await listen<{ channel_id: string; successor_id?: string }>('ember:channel-handoff', () => {
        refreshChannels().catch(() => {});
      }),
    );
    if (myEpoch !== storeEpoch) {
      for (const fn of registered) fn();
      return;
    }
    unlisteners = registered;
    await refreshChannels().catch(() => {});
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
  channels.set([]);
  activeChannelId.set(null);
}
