import { get, writable } from 'svelte/store';
import { listChannels, type ChannelInfo } from '$lib/api/channels';

export const channels = writable<ChannelInfo[]>([]);
export const activeChannelId = writable<string | null>(null);

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
  channels.update((list) =>
    list.map((channel) =>
      channel.channel_id === channelId
        ? { ...channel, unread: channel.unread + 1 }
        : channel,
    ),
  );
}
