import { beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import {
  awaitingChannelOffers,
  bumpChannelUnread,
  channelLineIsStale,
  channelMayAlert,
  channelTransfers,
  claimChannelToastSlot,
  ignoredMembers,
  channelNotifyLevels,
  channels,
  channelUnreadMentions,
  cleanupChannelsStore,
  clearChannelUnread,
  favouriteChannels,
  forgetChannelFavourite,
  loadChannelFavourites,
  loadChannelNotifyLevels,
  mergeChannelUnreadFromSnapshot,
  messageMentionsName,
  notifyLevelOf,
  refreshChannels,
  setChannelNotifyLevel,
  toggleChannelFavourite,
  totalChannelUnread,
  unreadBadgeTone,
} from './channels';
import { listChannels, type ChannelInfo, type ChannelTransferInfo } from '$lib/api/channels';

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
    announce_only: false,
    pinned_msg_ids: [],
    language: '',
    ...partial,
  } as ChannelInfo;
}

const A = '11'.repeat(16);
const B = '22'.repeat(16);

beforeEach(() => {
  cleanupChannelsStore();
  vi.mocked(listChannels).mockReset();
  channels.set([]);
  channelNotifyLevels.set({});
  favouriteChannels.set([]);
  ignoredMembers.set([]);
});

/** A `localStorage` stand-in; the test environment has none. */
function memoryStorage(seed: Record<string, string> = {}) {
  const data = new Map(Object.entries(seed));
  return {
    data,
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => void data.set(key, value),
    removeItem: (key: string) => void data.delete(key),
  };
}

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
    setChannelNotifyLevel(B, 'none');
    // Muting means "later", so the room's own pill keeps its count — but a
    // silenced room has no business putting a number on the nav rail.
    expect(get(totalChannelUnread)).toBe(2);
  });

  it('counts a mentions-only room only while it holds a mention', () => {
    channels.set([room({ channel_id: A, unread: 2 }), room({ channel_id: B, unread: 0 })]);
    setChannelNotifyLevel(B, 'mentions');
    bumpChannelUnread(B);
    expect(get(totalChannelUnread)).toBe(2);
    bumpChannelUnread(B, true);
    expect(get(totalChannelUnread)).toBe(4);
    clearChannelUnread(B);
    expect(get(channelUnreadMentions)).toEqual([]);
    expect(get(totalChannelUnread)).toBe(2);
  });
});

describe('notification levels', () => {
  it('lets a room interrupt according to its level', () => {
    expect(channelMayAlert('all', false)).toBe(true);
    expect(channelMayAlert('mentions', false)).toBe(false);
    expect(channelMayAlert('mentions', true)).toBe(true);
    expect(channelMayAlert('none', true)).toBe(false);
  });

  it('draws the pill loud only where the level would have spoken', () => {
    expect(unreadBadgeTone('all', false)).toBe('loud');
    expect(unreadBadgeTone('mentions', false)).toBe('quiet');
    expect(unreadBadgeTone('mentions', true)).toBe('loud');
    expect(unreadBadgeTone('none', true)).toBe('quiet');
  });

  it('stores only the quiet levels, keyed by lowercase id', () => {
    setChannelNotifyLevel(A.toUpperCase(), 'mentions');
    expect(get(channelNotifyLevels)).toEqual({ [A]: 'mentions' });
    expect(notifyLevelOf(get(channelNotifyLevels), A.toUpperCase())).toBe('mentions');
    setChannelNotifyLevel(A, 'all');
    expect(get(channelNotifyLevels)).toEqual({});
    expect(notifyLevelOf(get(channelNotifyLevels), A)).toBe('all');
    setChannelNotifyLevel('not-a-room', 'none');
    expect(get(channelNotifyLevels)).toEqual({});
  });

  it('turns the old mute list into "nothing" once, then retires it', () => {
    const storage = memoryStorage({
      'ember.channels.muted.v1': JSON.stringify([A.toUpperCase(), B, 'junk', 7]),
    });
    expect(loadChannelNotifyLevels(storage)).toEqual({ [A]: 'none', [B]: 'none' });
    expect(storage.data.has('ember.channels.muted.v1')).toBe(false);
    expect(JSON.parse(storage.data.get('ember.channels.notify.v1') ?? '')).toEqual({
      [A]: 'none',
      [B]: 'none',
    });

    // A room turned back up after the conversion must stay up, even if an
    // older build writes the legacy key again.
    storage.setItem('ember.channels.notify.v1', JSON.stringify({ [B]: 'mentions' }));
    storage.setItem('ember.channels.muted.v1', JSON.stringify([A]));
    expect(loadChannelNotifyLevels(storage)).toEqual({ [B]: 'mentions' });
  });

  it('keeps the old list when the converted one cannot be written', () => {
    const storage = memoryStorage({ 'ember.channels.muted.v1': JSON.stringify([A]) });
    storage.setItem = () => {
      throw new Error('quota');
    };
    expect(loadChannelNotifyLevels(storage)).toEqual({ [A]: 'none' });
    expect(storage.data.has('ember.channels.muted.v1')).toBe(true);
  });

  it('drops malformed stored levels rather than trusting them', () => {
    const storage = memoryStorage({
      'ember.channels.notify.v1': JSON.stringify({ [A]: 'none', [B]: 'loud', junk: 'none' }),
    });
    expect(loadChannelNotifyLevels(storage)).toEqual({ [A]: 'none' });
    expect(loadChannelNotifyLevels(memoryStorage({ 'ember.channels.notify.v1': '{' }))).toEqual({});
    expect(loadChannelNotifyLevels(null)).toEqual({});
  });
});

describe('messageMentionsName', () => {
  it('matches the name as a whole word, with or without @', () => {
    expect(messageMentionsName('hey @Ada, look', 'Ada')).toBe(true);
    expect(messageMentionsName('ada: are you there', 'Ada')).toBe(true);
    expect(messageMentionsName('Adam said hi', 'Ada')).toBe(false);
    expect(messageMentionsName('Canada', 'Ada')).toBe(false);
  });

  it('treats regex characters in the name literally', () => {
    expect(messageMentionsName('ping a.b', 'a.b')).toBe(true);
    expect(messageMentionsName('ping axb', 'a.b')).toBe(false);
  });

  it('never matches an empty name', () => {
    expect(messageMentionsName('anything', '  ')).toBe(false);
  });
});

describe('favourites', () => {
  it('toggles a room in and out, normalised to lowercase', () => {
    toggleChannelFavourite(A.toUpperCase());
    expect(get(favouriteChannels)).toEqual([A]);
    toggleChannelFavourite(A);
    expect(get(favouriteChannels)).toEqual([]);
    toggleChannelFavourite('nope');
    expect(get(favouriteChannels)).toEqual([]);
  });

  it('forgets a room without touching the others', () => {
    favouriteChannels.set([A, B]);
    forgetChannelFavourite(A);
    expect(get(favouriteChannels)).toEqual([B]);
  });

  it('loads a stored list, dropping junk and repeats', () => {
    const storage = memoryStorage({
      'ember.channels.favourites.v1': JSON.stringify([A, A.toUpperCase(), 'x', B]),
    });
    expect(loadChannelFavourites(storage)).toEqual([A, B]);
    expect(loadChannelFavourites(memoryStorage({ 'ember.channels.favourites.v1': 'nope' }))).toEqual([]);
  });

  it('drops rooms the user is no longer in when the list refreshes', async () => {
    favouriteChannels.set([A, B]);
    setChannelNotifyLevel(B, 'none');
    vi.mocked(listChannels).mockResolvedValueOnce([
      room({ channel_id: A }),
      room({ channel_id: B, in_room: false }),
    ]);
    await refreshChannels();
    expect(get(favouriteChannels)).toEqual([A]);
    // Leaving keeps the level: the user can walk back in.
    expect(get(channelNotifyLevels)).toEqual({ [B]: 'none' });
  });
});

describe('handoff carries preferences to the successor', () => {
  const C = '33'.repeat(16);

  it('moves the star and the level once the user is in the new room', async () => {
    favouriteChannels.set([A]);
    setChannelNotifyLevel(A, 'mentions');
    vi.mocked(listChannels).mockResolvedValueOnce([
      room({ channel_id: A, successor_id: B }),
      room({ channel_id: B, predecessor_id: A }),
    ]);
    await refreshChannels();
    expect(get(favouriteChannels)).toEqual([B]);
    expect(get(channelNotifyLevels)).toEqual({ [B]: 'mentions' });

    // Turning the successor back up to All must hold on the next refresh.
    setChannelNotifyLevel(B, 'all');
    vi.mocked(listChannels).mockResolvedValueOnce([
      room({ channel_id: A, successor_id: B }),
      room({ channel_id: B, predecessor_id: A }),
    ]);
    await refreshChannels();
    expect(get(channelNotifyLevels)).toEqual({});
  });

  it('waits while the user has not followed the handoff', async () => {
    favouriteChannels.set([A]);
    setChannelNotifyLevel(A, 'none');
    vi.mocked(listChannels).mockResolvedValueOnce([
      room({ channel_id: A, successor_id: B }),
      room({ channel_id: B, in_room: false }),
    ]);
    await refreshChannels();
    expect(get(favouriteChannels)).toEqual([A]);
    expect(get(channelNotifyLevels)).toEqual({ [A]: 'none' });
  });

  it('keeps a level the successor already has', async () => {
    setChannelNotifyLevel(A, 'none');
    setChannelNotifyLevel(B, 'mentions');
    favouriteChannels.set([A, B, C]);
    vi.mocked(listChannels).mockResolvedValueOnce([
      room({ channel_id: A, successor_id: B }),
      room({ channel_id: B }),
      room({ channel_id: C }),
    ]);
    await refreshChannels();
    expect(get(channelNotifyLevels)).toEqual({ [B]: 'mentions' });
    expect(get(favouriteChannels)).toEqual([B, C]);
  });
});

describe('channel toast pacing', () => {
  it('holds ordinary lines to one toast per room per gap', () => {
    expect(claimChannelToastSlot(A, 'aa', false, 1_000)).toBe(true);
    expect(claimChannelToastSlot(A, 'bb', false, 5_000)).toBe(false);
    expect(claimChannelToastSlot(B, 'bb', false, 5_000)).toBe(true);
    expect(claimChannelToastSlot(A, 'bb', false, 16_000)).toBe(true);
  });

  it('lets a mention through the ordinary gap, but not a flood of them', () => {
    expect(claimChannelToastSlot(A, 'aa', false, 0)).toBe(true);
    expect(claimChannelToastSlot(A, 'bb', true, 1_000)).toBe(true);
    // Another member inside the short per-room gap waits.
    expect(claimChannelToastSlot(A, 'cc', true, 2_000)).toBe(false);
    expect(claimChannelToastSlot(A, 'cc', true, 4_500)).toBe(true);
    // The same member naming the user again waits the full gap.
    expect(claimChannelToastSlot(A, 'bb', true, 8_000)).toBe(false);
    expect(claimChannelToastSlot(A, 'bb', true, 12_000)).toBe(false);
    expect(claimChannelToastSlot(A, 'bb', true, 16_500)).toBe(true);
  });

  it('bounds a single member replying every second', () => {
    let shown = 0;
    for (let t = 0; t < 60_000; t += 1_000) {
      if (claimChannelToastSlot(A, 'aa', true, t)) shown++;
    }
    expect(shown).toBe(4);
  });

  it('restarts the ordinary gap after a mention', () => {
    expect(claimChannelToastSlot(A, 'aa', true, 0)).toBe(true);
    expect(claimChannelToastSlot(A, 'bb', false, 5_000)).toBe(false);
  });
});

describe('channelLineIsStale', () => {
  const now = 1_800_000_000_000;
  const secs = now / 1000;

  it('keeps lines sent in the last two minutes live', () => {
    expect(channelLineIsStale(secs, now)).toBe(false);
    expect(channelLineIsStale(secs - 119, now)).toBe(false);
    // A sender whose clock runs ahead is still somebody talking now.
    expect(channelLineIsStale(secs + 30, now)).toBe(false);
  });

  it('quiets history that catch-up serves on reconnect', () => {
    expect(channelLineIsStale(secs - 121, now)).toBe(true);
    expect(channelLineIsStale(secs - 86_400, now)).toBe(true);
  });

  it('treats a line without a usable stamp as live', () => {
    expect(channelLineIsStale(undefined, now)).toBe(false);
    expect(channelLineIsStale('1700000000', now)).toBe(false);
    expect(channelLineIsStale(Number.NaN, now)).toBe(false);
  });
});

describe('awaitingChannelOffers', () => {
  const PEER = 'ee'.repeat(32);
  const offer = (xfer_id: string, channel_id: string, extra: Partial<ChannelTransferInfo> = {}) =>
    ({
      xfer_id,
      channel_id,
      peer_pubkey: PEER,
      direction: 'receive',
      name: 'f.txt',
      size: 1,
      transferred: 0,
      status: 'awaiting',
      ...extra,
    }) as ChannelTransferInfo;

  it('counts only offers the toast would have announced', () => {
    channelTransfers.set({
      x1: offer('x1', A),
      x2: offer('x2', B),
      x3: offer('x3', A, { status: 'active' }),
      x4: offer('x4', A, { direction: 'send' }),
    });
    expect(get(awaitingChannelOffers)).toBe(2);
    setChannelNotifyLevel(B, 'none');
    expect(get(awaitingChannelOffers)).toBe(1);
    // Mentions-only still hears an offer: it is addressed to the user alone.
    setChannelNotifyLevel(A, 'mentions');
    expect(get(awaitingChannelOffers)).toBe(1);
  });

  it('leaves out offers from a member ignored in that room', () => {
    channelTransfers.set({ x1: offer('x1', A), x2: offer('x2', B) });
    ignoredMembers.set([{ pubkey: PEER, name: '', rooms: [A] }]);
    expect(get(awaitingChannelOffers)).toBe(1);
    ignoredMembers.set([{ pubkey: PEER, name: '' }]);
    expect(get(awaitingChannelOffers)).toBe(0);
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
