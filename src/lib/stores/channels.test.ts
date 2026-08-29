import { beforeEach, describe, expect, it } from 'vitest';
import { get } from 'svelte/store';
import {
  bumpChannelUnread,
  channels,
  clearChannelUnread,
  mutedChannels,
  totalChannelUnread,
} from './channels';
import type { ChannelInfo } from '$lib/api/channels';

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
});
