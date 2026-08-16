import { derived, get, writable } from 'svelte/store';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { listChannels, type ChannelInfo } from '$lib/api/channels';
import { isAppVisible } from '$lib/utils';
import { toast } from '$lib/stores/toast';
import * as m from '$lib/paraglide/messages';

export const channels = writable<ChannelInfo[]>([]);
export const activeChannelId = writable<string | null>(null);

export const totalChannelUnread = derived(channels, (list) =>
  list.reduce((sum, channel) => sum + Math.max(0, channel.unread), 0),
);

const CHANNEL_ID_RE = /^[0-9a-f]{32}$/i;
const TOAST_GAP_MS = 15_000;
const lastToastAt = new Map<string, number>();

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
  channels.update((list) =>
    list.map((channel) =>
      channel.channel_id === channelId ? { ...channel, unread: 0 } : channel,
    ),
  );
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
