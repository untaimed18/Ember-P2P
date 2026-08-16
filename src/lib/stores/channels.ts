import { writable } from 'svelte/store';
import { listChannels, type ChannelInfo } from '$lib/api/channels';

export const channels = writable<ChannelInfo[]>([]);
export const activeChannelId = writable<string | null>(null);

export async function refreshChannels(): Promise<void> {
  const list = await listChannels();
  channels.set(list);
}
