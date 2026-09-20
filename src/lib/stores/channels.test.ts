import { beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import {
  bumpChannelUnread,
  channels,
  cleanupChannelsStore,
  clearChannelUnread,
  mergeChannelUnreadFromSnapshot,
  mutedChannels,
  refreshChannels,
  totalChannelUnread,
} from './channels';
import { listChannels, type ChannelInfo } from '$lib/api/channels';

vi.mock('$lib/api/channels', async () => {
  const actual = await vi.importActual<typeof import('$lib/api/channels')>('$lib/api/channels');
  return {
    ...actual,
    listChannels: vi.fn(),
  };
});

function room(partial: Partial<ChannelInfo> & { channel_id: string }): ChannelInfo {
  return {
    pubkey: 'ab'.repeat(32),
    name: 'Room',
    visibility: 'public',
    is_owner: false,
    topic: '',
    welcome: '',
    joined_at: 0,
    last_active: 0,
    member_count: 1,
    unread: 0,
    successor_id: '',
    predecessor_id: '',
    owner_pubkey: '',
    key_epoch: 0,
    successor_nominee: '',
    claim_after_days: 0,
    key_behind: false,
    can_claim: false,
    you_are_banned: false,
    you_are_moderator: false,
    in_room: true,
    deleted: false,
    invites_owner_only: false,
    slow_mode_secs: 0,
    ...partial,
  } as ChannelInfo;
}

const A = '11'.repeat(16);
const B = '22'.repeat(16);

beforeEach(() => {
  cleanupChannelsStore();
  vi.mocked(listChannels).mockReset();
  channels.set([]);
  mutedChannels.set([]);
});

describe('totalChannelUnread', () => {
  it('adds up the rooms the badge is meant to speak for', () => {
    channels.set([room({ channel_id: A, unread: 2 }), room({ channel_id: B, unread: 3 })]);
    expect(get(totalChannelUnread)).toBe(5);
  });

  it('leaves out a muted room, a left room, and a deleted one', () => {
    channels.set([
      room({ channel_id: A, unread: 2 }),
      room({ channel_id: B, unread: 9 }),
      room({ channel_id: '33'.repeat(16), unread: 4, in_room: false }),
      room({ channel_id: '44'.repeat(16), unread: 8, deleted: true }),
    ]);
    mutedChannels.set([B]);
    // Muting means "later", so the room's own pill keeps its count — but a
    // silenced room has no business putting a number on the nav rail.
    expect(get(totalChannelUnread)).toBe(2);
  });
});

describe('unread counters', () => {
  it('hands back the same array when there is nothing to change', () => {
    // Not a micro-optimisation. `ChatConversation` calls `clearChannelUnread`
    // from the same effect that reads the channel it is displaying, so an
    // unconditional copy fed that effect its own output and span forever.
    channels.set([room({ channel_id: A, unread: 0 })]);
    const before = get(channels);
    clearChannelUnread(A);
    expect(get(channels)).toBe(before);

    clearChannelUnread('99'.repeat(16));
    expect(get(channels)).toBe(before);
  });

  it('replaces the array when a count really moves', () => {
    channels.set([room({ channel_id: A, unread: 3 })]);
    const before = get(channels);
    clearChannelUnread(A);
    expect(get(channels)).not.toBe(before);
    expect(get(channels)[0].unread).toBe(0);
  });

  it('only counts a room this device is actually in', () => {
    channels.set([
      room({ channel_id: A, unread: 0 }),
      room({ channel_id: B, unread: 0, in_room: false }),
    ]);
    bumpChannelUnread(A);
    bumpChannelUnread(B);
    const rooms = get(channels);
    expect(rooms.find((r) => r.channel_id === A)?.unread).toBe(1);
    expect(rooms.find((r) => r.channel_id === B)?.unread).toBe(0);
  });

  it('keeps live unread only on rooms that were touched during a refresh', () => {
    const snapshot = [
      room({ channel_id: A, unread: 4, name: 'Fresh A' }),
      room({ channel_id: B, unread: 7, name: 'Fresh B' }),
    ];
    const current = [
      room({ channel_id: A, unread: 1, name: 'Stale A' }),
      room({ channel_id: B, unread: 9, name: 'Stale B' }),
    ];
    const merged = mergeChannelUnreadFromSnapshot(snapshot, current, [A]);
    expect(merged.find((r) => r.channel_id === A)).toMatchObject({ unread: 1, name: 'Fresh A' });
    expect(merged.find((r) => r.channel_id === B)).toMatchObject({ unread: 7, name: 'Fresh B' });
  });

  it('does not let a stale refresh overwrite a newer one', async () => {
    channels.set([room({ channel_id: A, unread: 0 })]);
    let releaseFirst!: (value: ChannelInfo[]) => void;
    const firstSnap = new Promise<ChannelInfo[]>((resolve) => {
      releaseFirst = resolve;
    });
    vi.mocked(listChannels)
      .mockImplementationOnce(() => firstSnap)
      .mockResolvedValueOnce([room({ channel_id: A, unread: 0, name: 'Fresh' })]);

    const first = refreshChannels();
    bumpChannelUnread(A);
    expect(get(channels)[0].unread).toBe(1);

    await refreshChannels();
    expect(get(channels)[0].unread).toBe(1);
    expect(get(channels)[0].name).toBe('Fresh');

    releaseFirst([room({ channel_id: A, unread: 99, name: 'Stale' })]);
    await first;
    expect(get(channels)[0].unread).toBe(1);
    expect(get(channels)[0].name).toBe('Fresh');
  });
});
