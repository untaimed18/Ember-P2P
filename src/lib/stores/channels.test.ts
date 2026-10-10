import { beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import {
  awaitingChannelOffers,
  bumpChannelUnread,
  carriedChannels,
  channelLineIsStale,
  channelMayAlert,
  channelTransfers,
  claimChannelToastSlot,
  ignoredMembers,
  channelNotifyLevels,
  channels,
  channelSnoozes,
  channelUnreadMentions,
  cleanupChannelsStore,
  clearChannelUnread,
  effectiveNotifyLevels,
  endChannelSnooze,
  expireChannelSnoozes,
  favouriteChannels,
  forgetChannelFavourite,
  initChannelsStore,
  loadChannelFavourites,
  loadChannelNotifyLevels,
  mergeChannelUnreadFromSnapshot,
  mergeTransferSnapshot,
  messageMentionsName,
  notifyLevelOf,
  parseChannelSnoozes,
  refreshChannels,
  replaceChannel,
  setChannelNotifyLevel,
  snoozeChannel,
  snoozedUntil,
  snoozeEnd,
  toggleChannelFavourite,
  totalChannelUnread,
  unreadBadgeTone,
  unreadIdsToPreserve,
  xferNeedsConsent,
  xferStartsAsking,
} from './channels';
import {
  getChannelMessages,
  listChannels,
  listChannelTransfers,
  type ChannelInfo,
  type ChannelMessageInfo,
  type ChannelTransferInfo,
} from '$lib/api/channels';
import { appSettings } from '$lib/stores/settings';
import type { AppSettings } from '$lib/types';
import { toast } from '$lib/stores/toast';
import { notify } from '$lib/notifications';

vi.mock('$lib/api/channels', async () => {
  const actual = await vi.importActual<typeof import('$lib/api/channels')>('$lib/api/channels');
  return {
    ...actual,
    listChannels: vi.fn(),
    listChannelTransfers: vi.fn(async () => []),
    getChannelMessages: vi.fn(async () => []),
  };
});

/** Handlers `initChannelsStore` registered, by event name. */
const eventHandlers = new Map<string, (event: { payload: unknown }) => void>();

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => {
    eventHandlers.set(name, handler);
    return () => eventHandlers.delete(name);
  }),
}));

vi.mock('$lib/stores/toast', () => ({ toast: vi.fn() }));
vi.mock('$lib/notifications', () => ({ notify: vi.fn(async () => {}) }));

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
    newer_lines: 0,
    newer_key: false,
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
  channelSnoozes.set({});
  favouriteChannels.set([]);
  carriedChannels.set([]);
  ignoredMembers.set([]);
  vi.mocked(toast).mockClear();
  vi.mocked(notify).mockClear();
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

  // The copy marks the old room's copied lines read, so a moved room only
  // counts what arrived after it moved — or everything, when nothing was
  // copied because the user had joined the successor on their own.
  it('still counts what a moved room holds unread', () => {
    channels.set([
      room({ channel_id: A, unread: 2, successor_id: B }),
      room({ channel_id: B, unread: 3, predecessor_id: A }),
    ]);
    expect(get(totalChannelUnread)).toBe(5);
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

  it('moves the star and copies the level once the user is in the new room', async () => {
    favouriteChannels.set([A]);
    setChannelNotifyLevel(A, 'mentions');
    vi.mocked(listChannels).mockResolvedValueOnce([
      room({ channel_id: A, successor_id: B }),
      room({ channel_id: B, predecessor_id: A }),
    ]);
    await refreshChannels();
    expect(get(favouriteChannels)).toEqual([B]);
    // The old room keeps its level: members who have not followed still talk there.
    expect(get(channelNotifyLevels)).toEqual({ [A]: 'mentions', [B]: 'mentions' });

    // Turning the successor back up to All must hold on the next refresh.
    setChannelNotifyLevel(B, 'all');
    vi.mocked(listChannels).mockResolvedValueOnce([
      room({ channel_id: A, successor_id: B }),
      room({ channel_id: B, predecessor_id: A }),
    ]);
    await refreshChannels();
    expect(get(channelNotifyLevels)).toEqual({ [A]: 'mentions' });
    expect(get(carriedChannels)).toEqual([A]);
  });

  it('carries an unread mention to the successor holding the copied line', async () => {
    setChannelNotifyLevel(A, 'mentions');
    channels.set([room({ channel_id: A, unread: 1 })]);
    channelUnreadMentions.set([A]);
    vi.mocked(listChannels).mockResolvedValueOnce([
      room({ channel_id: A, unread: 0, successor_id: B }),
      room({ channel_id: B, unread: 1, predecessor_id: A }),
    ]);
    await refreshChannels();
    expect(get(channelUnreadMentions)).toEqual([B]);
    expect(get(totalChannelUnread)).toBe(1);
  });

  it('forgets the carried mark with the room it names', async () => {
    carriedChannels.set([A]);
    vi.mocked(listChannels).mockResolvedValueOnce([room({ channel_id: B })]);
    await refreshChannels();
    expect(get(carriedChannels)).toEqual([]);
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
    expect(get(channelNotifyLevels)).toEqual({ [A]: 'none', [B]: 'mentions' });
    expect(get(favouriteChannels)).toEqual([B, C]);
  });
});

describe('message toasts', () => {
  const deliver = (channelId: string) =>
    eventHandlers.get('ember:channel-message')?.({
      payload: {
        channel_id: channelId,
        direction: 'received',
        message: 'hello there',
        sender_pubkey: 'ee'.repeat(32),
      },
    });

  // A room whose handoff the user has not followed is the room they stand in,
  // and its copied level (not its move) decides whether it interrupts.
  it('still announces a line in a room that moved to a successor', async () => {
    vi.mocked(listChannels).mockResolvedValue([
      room({ channel_id: A, successor_id: B }),
      room({ channel_id: B, predecessor_id: A }),
    ]);
    await initChannelsStore();
    deliver(A);
    expect(toast).toHaveBeenCalledTimes(1);
    expect(get(channels).find((r) => r.channel_id === A)?.unread).toBe(1);
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

describe('transfer snapshots', () => {
  const PEER = 'ee'.repeat(32);
  const offer = (extra: Partial<ChannelTransferInfo> = {}) =>
    ({
      xfer_id: 'x1',
      channel_id: A,
      peer_pubkey: PEER,
      direction: 'receive',
      name: 'report.pdf.exe',
      size: 1,
      transferred: 0,
      status: 'awaiting',
      ...extra,
    }) as ChannelTransferInfo;

  it('keeps a snapshot-only field while live fields win', () => {
    const merged = mergeTransferSnapshot(
      { x1: offer({ status: 'active', transferred: 5 }) },
      [offer({ risky: true }), offer({ xfer_id: 'x2' })],
    );
    expect(merged.x1).toMatchObject({ status: 'active', transferred: 5, risky: true });
    expect(merged.x2).toMatchObject({ xfer_id: 'x2', status: 'awaiting' });
  });

  it('reads risky from an offer, and asks the snapshot when the offer lacks it', async () => {
    vi.mocked(listChannels).mockResolvedValue([]);
    await initChannelsStore();
    const onOffer = eventHandlers.get('ember:xfer-offer');
    vi.mocked(listChannelTransfers).mockClear();
    onOffer?.({ payload: { ...offer(), xfer_id: 'x1', risky: true } });
    expect(get(channelTransfers).x1.risky).toBe(true);
    expect(vi.mocked(listChannelTransfers)).not.toHaveBeenCalled();

    vi.mocked(listChannelTransfers).mockResolvedValueOnce([offer({ xfer_id: 'x2', risky: true })]);
    onOffer?.({ payload: { ...offer(), xfer_id: 'x2' } });
    expect('risky' in get(channelTransfers).x2).toBe(false);
    await vi.waitFor(() => expect(get(channelTransfers).x2.risky).toBe(true));
  });
});

describe('xferNeedsConsent', () => {
  const sent = (extra: Partial<ChannelTransferInfo> = {}) =>
    ({
      xfer_id: 'x1',
      channel_id: A,
      peer_pubkey: 'ee'.repeat(32),
      direction: 'send',
      name: 'f.txt',
      size: 1,
      transferred: 0,
      status: 'offered',
      ...extra,
    }) as ChannelTransferInfo;

  it('asks only about an unanswered offer this user sent', () => {
    expect(xferNeedsConsent(sent({ awaiting_consent: true }))).toBe(true);
    expect(xferNeedsConsent(sent())).toBe(false);
    expect(xferNeedsConsent(sent({ awaiting_consent: false }))).toBe(false);
    expect(xferNeedsConsent(sent({ awaiting_consent: true, status: 'active' }))).toBe(false);
    expect(xferNeedsConsent(sent({ awaiting_consent: true, direction: 'receive' }))).toBe(false);
  });

  it('puts the question up once, however often it is repeated', () => {
    const asking = sent({ awaiting_consent: true });
    expect(xferStartsAsking(undefined, asking)).toBe(true);
    expect(xferStartsAsking(sent(), asking)).toBe(true);
    expect(xferStartsAsking(asking, asking)).toBe(false);
    expect(xferStartsAsking(asking, sent())).toBe(false);
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
    // The second snapshot starts after the bump, so the database it reads
    // already holds the line that caused it.
    vi.mocked(listChannels)
      .mockImplementationOnce(() => firstSnap)
      .mockResolvedValueOnce([room({ channel_id: A, unread: 1, name: 'Fresh' })]);

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

  it('preserves a bump only past the snapshot start, and a clear regardless', () => {
    const dirty = new Map([
      [A, { rev: 2, cleared: false }],
      [B, { rev: 5, cleared: false }],
      ['33'.repeat(16), { rev: 1, cleared: true }],
    ]);
    expect(unreadIdsToPreserve(dirty, 3)).toEqual([B, '33'.repeat(16)]);
    expect(unreadIdsToPreserve(dirty, 5)).toEqual(['33'.repeat(16)]);
  });

  it('does not count a line twice when its bump lands after the snapshot that holds it', async () => {
    channels.set([room({ channel_id: A, unread: 1 })]);
    bumpChannelUnread(A);
    expect(get(channels)[0].unread).toBe(2);
    vi.mocked(listChannels).mockResolvedValueOnce([room({ channel_id: A, unread: 1 })]);
    await refreshChannels();
    expect(get(channels)[0].unread).toBe(1);
  });

  it('keeps a clear over a snapshot taken before the mark-read landed', async () => {
    channels.set([room({ channel_id: A, unread: 3 })]);
    clearChannelUnread(A);
    vi.mocked(listChannels).mockResolvedValueOnce([room({ channel_id: A, unread: 3 })]);
    await refreshChannels();
    expect(get(channels)[0].unread).toBe(0);
  });

  it('keeps live unread and the roster count when a command hands back a row', () => {
    channels.set([room({ channel_id: A, unread: 0, member_count: 4, topic: 'old' })]);
    bumpChannelUnread(A);
    replaceChannel(room({ channel_id: A, unread: 9, member_count: 1, topic: 'new' }));
    expect(get(channels)[0]).toMatchObject({ unread: 1, member_count: 4, topic: 'new' });
  });

  it('settles an overtaken refresh only once the newer one has landed', async () => {
    channels.set([]);
    let releaseSecond!: (value: ChannelInfo[]) => void;
    const secondSnap = new Promise<ChannelInfo[]>((resolve) => {
      releaseSecond = resolve;
    });
    vi.mocked(listChannels)
      .mockResolvedValueOnce([])
      .mockImplementationOnce(() => secondSnap);

    let firstSettled = false;
    const first = refreshChannels().then(() => {
      firstSettled = true;
    });
    const second = refreshChannels();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(firstSettled).toBe(false);

    releaseSecond([room({ channel_id: A, name: 'New room' })]);
    await first;
    expect(get(channels).map((r) => r.name)).toEqual(['New room']);
    await second;
  });
});

describe('snooze', () => {
  it('silences a room like "Nothing" and keeps its own level underneath', () => {
    setChannelNotifyLevel(A, 'mentions');
    channels.set([room({ channel_id: A, unread: 2 }), room({ channel_id: B, unread: 3 })]);
    channelUnreadMentions.set([A]);
    expect(get(totalChannelUnread)).toBe(5);
    snoozeChannel(A.toUpperCase(), '1h');
    expect(snoozedUntil(get(channelSnoozes), A)).not.toBeNull();
    expect(notifyLevelOf(get(effectiveNotifyLevels), A)).toBe('none');
    expect(notifyLevelOf(get(channelNotifyLevels), A)).toBe('mentions');
    expect(get(totalChannelUnread)).toBe(3);
    endChannelSnooze(A);
    expect(notifyLevelOf(get(effectiveNotifyLevels), A)).toBe('mentions');
    expect(get(totalChannelUnread)).toBe(5);
  });

  it('holds back a file offer while it lasts', () => {
    channelTransfers.set({
      x: {
        xfer_id: 'x',
        channel_id: A,
        peer_pubkey: 'ee'.repeat(32),
        direction: 'receive',
        name: 'f',
        size: 1,
        transferred: 0,
        status: 'awaiting',
      } as ChannelTransferInfo,
    });
    expect(get(awaitingChannelOffers)).toBe(1);
    snoozeChannel(A, '8h');
    expect(get(awaitingChannelOffers)).toBe(0);
  });

  it('ends by itself once the time is up', () => {
    const now = Date.now();
    channelSnoozes.set({ [A]: now - 1, [B]: now + 60_000 });
    expireChannelSnoozes(now);
    expect(get(channelSnoozes)).toEqual({ [B]: now + 60_000 });
  });

  it('runs "until tomorrow" to the coming morning', () => {
    const evening = new Date(2026, 9, 5, 21, 30);
    expect(new Date(snoozeEnd('tomorrow', evening))).toEqual(new Date(2026, 9, 6, 8, 0));
    // Past midnight, "tomorrow" still means the morning about to come.
    const smallHours = new Date(2026, 9, 6, 1, 15);
    expect(new Date(snoozeEnd('tomorrow', smallHours))).toEqual(new Date(2026, 9, 6, 8, 0));
    expect(snoozeEnd('1h', evening)).toBe(evening.getTime() + 3_600_000);
  });

  it('drops stored snoozes that are over, malformed or implausibly long', () => {
    const now = 1_000_000;
    const raw = JSON.stringify({
      [A.toUpperCase()]: now + 5,
      [B]: now - 5,
      ['33'.repeat(16)]: now + 30 * 24 * 3_600_000,
      junk: now + 5,
      ['44'.repeat(16)]: 'soon',
    });
    expect(parseChannelSnoozes(raw, now)).toEqual({ [A]: now + 5 });
    expect(parseChannelSnoozes('{', now)).toEqual({});
  });

  it('is forgotten with a room that is gone', async () => {
    snoozeChannel(A, '1h');
    snoozeChannel(B, '1h');
    vi.mocked(listChannels).mockResolvedValueOnce([room({ channel_id: B, in_room: false })]);
    await refreshChannels();
    expect(Object.keys(get(channelSnoozes))).toEqual([B]);
  });
});

describe('mention flags after a restart', () => {
  const line = (partial: Partial<ChannelMessageInfo>): ChannelMessageInfo =>
    ({
      id: 1,
      sender_pubkey: 'ee'.repeat(32),
      direction: 'received',
      message: '',
      timestamp: 0,
      read: false,
      edited_at: 0,
      msg_id: '',
      delivery: 'delivered',
      reply_to: null,
      reply_to_me: false,
      reply_parent: null,
      reply_parent_deleted: false,
      ...partial,
    }) as ChannelMessageInfo;
  const C = '33'.repeat(16);

  it('flags the rooms whose unread lines name or answer the user', async () => {
    appSettings.set({ channel_username: 'Ada', nickname: '' } as AppSettings);
    vi.mocked(listChannels).mockResolvedValue([
      room({ channel_id: A, unread: 2 }),
      room({ channel_id: B, unread: 1 }),
      room({ channel_id: C, unread: 3 }),
      room({ channel_id: '44'.repeat(16), unread: 0 }),
    ]);
    vi.mocked(getChannelMessages).mockImplementation(async (id: string) => {
      if (id === A) return [line({ message: 'morning @Ada' }), line({ message: 'hi' })];
      if (id === B) return [line({ message: 'unrelated', reply_to_me: true })];
      // Read already, and the user's own line: neither is a mention waiting.
      return [
        line({ message: 'Ada?', read: true }),
        line({ message: 'Ada', direction: 'sent' }),
      ];
    });
    await initChannelsStore();
    await vi.waitFor(() => expect([...get(channelUnreadMentions)].sort()).toEqual([A, B]));
    expect(vi.mocked(getChannelMessages)).toHaveBeenCalledTimes(3);
    expect(vi.mocked(getChannelMessages)).toHaveBeenCalledWith(A, 2);
    appSettings.set(null);
  });
});
