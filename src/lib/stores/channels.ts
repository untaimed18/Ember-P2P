import { derived, get, writable } from 'svelte/store';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import {
  getChannelMessages,
  listChannels,
  listChannelTransfers,
  type ChannelInfo,
  type ChannelMessageInfo,
  type ChannelTransferInfo,
} from '$lib/api/channels';
import { isAppVisible } from '$lib/utils';
import { appSettings } from '$lib/stores/settings';
import { toast } from '$lib/stores/toast';
import { notify } from '$lib/notifications';
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
/** Lines that name the user get their own, shorter per-room gap: answering
 *  them is the point, but exempting them outright let any member flood
 *  toasts by mentioning or replying over and over. */
const MENTION_TOAST_GAP_MS = 3_000;
/** A line sent longer ago than this is history arriving, not somebody talking
 *  now: catch-up re-serves a room's recent past through the same event as live
 *  chat, and on reconnect every reply and mention in it would interrupt at once.
 *  Generous enough for clock skew and a slow mesh. */
const LIVE_LINE_MAX_AGE_MS = 2 * 60_000;
const lastToastAt = new Map<string, number>();
const lastMentionToastAt = new Map<string, number>();
/** Keyed `room:sender`. One member naming the user repeatedly still waits
 *  the full gap between toasts; a second member is not held up by the first. */
const lastMentionToastFrom = new Map<string, number>();

type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

function browserStorage(): StorageLike | null {
  return typeof localStorage === 'undefined' ? null : localStorage;
}

/** A stored list of room ids. Normalised on the way in: everything else
 *  compares against the lowercase hex the backend emits, so a stray uppercase
 *  entry would style a badge one way while the toast went the other. */
function parseChannelIds(raw: string | null): string[] {
  if (!raw) return [];
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) return [];
  return [
    ...new Set(
      parsed
        .filter((id): id is string => typeof id === 'string' && CHANNEL_ID_RE.test(id))
        .map((id) => id.toLowerCase()),
    ),
  ];
}

/**
 * How loudly a room may interrupt: every message, only lines that name you,
 * or nothing at all.
 *
 * A device preference rather than room state, so it lives in `localStorage`
 * instead of the channels table: it is about this machine's notifications,
 * not something the other members should learn or inherit. Deliberately
 * survives `cleanupChannelsStore` — turning Ember off and on again should not
 * un-silence a room.
 *
 * Governs toasts, desktop notifications and how the unread pill is drawn.
 * Unread counts keep accruing at every level, because a quiet room is one you
 * want to read later rather than one you want to miss.
 */
export type ChannelNotifyLevel = 'all' | 'mentions' | 'none';
type QuietLevel = Exclude<ChannelNotifyLevel, 'all'>;

/** Only the quiet rooms are stored; a room with no entry hears everything. */
const NOTIFY_KEY = 'ember.channels.notify.v1';
/** The on/off mute this replaced, a list of ids that all meant `none`. */
const LEGACY_MUTED_KEY = 'ember.channels.muted.v1';

function parseNotifyLevels(raw: string): Record<string, QuietLevel> {
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  const out: Record<string, QuietLevel> = {};
  for (const [key, level] of Object.entries(parsed)) {
    if (!CHANNEL_ID_RE.test(key) || (level !== 'mentions' && level !== 'none')) continue;
    out[key.toLowerCase()] = level;
  }
  return out;
}

/**
 * Read the stored levels, converting the old mute list the first time.
 *
 * The legacy key is consulted only while the new one is absent, and dropped
 * once its contents are safely written under the new name — so a room muted
 * before this existed stays silent, and a later "All messages" is not undone
 * by the old list being read again. If the write fails the old list is left
 * where it is and the conversion simply runs again next launch.
 */
export function loadChannelNotifyLevels(
  storage: StorageLike | null = browserStorage(),
): Record<string, QuietLevel> {
  if (!storage) return {};
  try {
    const raw = storage.getItem(NOTIFY_KEY);
    if (raw !== null) return parseNotifyLevels(raw);
    const legacyRaw = storage.getItem(LEGACY_MUTED_KEY);
    if (legacyRaw === null) return {};
    let legacy: string[] = [];
    try {
      legacy = parseChannelIds(legacyRaw);
    } catch {
      // Unreadable: nothing to carry over, but still worth retiring the key.
    }
    const levels: Record<string, QuietLevel> = Object.fromEntries(
      legacy.map((id) => [id, 'none' as const]),
    );
    try {
      storage.setItem(NOTIFY_KEY, JSON.stringify(levels));
      storage.removeItem(LEGACY_MUTED_KEY);
    } catch {
      /* Quota exceeded / private mode. */
    }
    return levels;
  } catch {
    return {};
  }
}

export const channelNotifyLevels = writable<Record<string, QuietLevel>>(loadChannelNotifyLevels());

channelNotifyLevels.subscribe((levels) => {
  const storage = browserStorage();
  if (!storage) return;
  try {
    storage.setItem(NOTIFY_KEY, JSON.stringify(levels));
  } catch {
    // Quota exceeded / private mode. The level still holds for this session.
  }
});

export function notifyLevelOf(
  levels: Record<string, QuietLevel>,
  channelId: string,
): ChannelNotifyLevel {
  return levels[channelId.toLowerCase()] ?? 'all';
}

export function setChannelNotifyLevel(channelId: string, level: ChannelNotifyLevel): void {
  const id = channelId.toLowerCase();
  if (!CHANNEL_ID_RE.test(id)) return;
  channelNotifyLevels.update((levels) => {
    if ((levels[id] ?? 'all') === level) return levels;
    const { [id]: _previous, ...rest } = levels;
    return level === 'all' ? rest : { ...rest, [id]: level };
  });
}

/**
 * Rooms silenced for a while, by when the silence ends (milliseconds).
 *
 * Laid over the level rather than replacing it, so the room goes back to
 * whatever the user had chosen once the time is up, with nothing to undo.
 * While it lasts the room behaves exactly as "Nothing" does. Kept across a
 * restart, but not in backups: an hour's quiet restored a week later would
 * already be over.
 */
const SNOOZE_KEY = 'ember.channels.snooze.v1';
/** Longest delay `setTimeout` takes before it fires at once instead. */
const MAX_TIMER_MS = 2 ** 31 - 1;
/** No choice snoozes for longer; a stored value past this is not one we wrote. */
const MAX_SNOOZE_MS = 7 * 24 * 60 * 60_000;

export type SnoozeChoice = '1h' | '8h' | 'tomorrow';

export function parseChannelSnoozes(raw: string | null, now: number): Record<string, number> {
  if (!raw) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return {};
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  const out: Record<string, number> = {};
  for (const [key, until] of Object.entries(parsed)) {
    if (!CHANNEL_ID_RE.test(key) || typeof until !== 'number' || !Number.isFinite(until)) continue;
    if (until <= now || until > now + MAX_SNOOZE_MS) continue;
    out[key.toLowerCase()] = until;
  }
  return out;
}

export function loadChannelSnoozes(
  storage: StorageLike | null = browserStorage(),
  now = Date.now(),
): Record<string, number> {
  if (!storage) return {};
  try {
    return parseChannelSnoozes(storage.getItem(SNOOZE_KEY), now);
  } catch {
    return {};
  }
}

export const channelSnoozes = writable<Record<string, number>>(loadChannelSnoozes());

let snoozeTimer: ReturnType<typeof setTimeout> | null = null;

/** Drop every snooze that has run out. */
export function expireChannelSnoozes(now = Date.now()): void {
  channelSnoozes.update((cur) => {
    if (!Object.values(cur).some((until) => until <= now)) return cur;
    return Object.fromEntries(Object.entries(cur).filter(([, until]) => until > now));
  });
}

channelSnoozes.subscribe((snoozes) => {
  const storage = browserStorage();
  if (storage) {
    try {
      if (Object.keys(snoozes).length === 0) storage.removeItem(SNOOZE_KEY);
      else storage.setItem(SNOOZE_KEY, JSON.stringify(snoozes));
    } catch {
      // Quota exceeded / private mode. The snooze still holds for this session.
    }
  }
  if (snoozeTimer) {
    clearTimeout(snoozeTimer);
    snoozeTimer = null;
  }
  const ends = Object.values(snoozes);
  if (ends.length === 0) return;
  // The earliest end only; expiring it writes the store, which lands back here
  // and schedules the next. A delay past the timer's ceiling re-arms on firing.
  const wait = Math.min(Math.max(0, Math.min(...ends) - Date.now()), MAX_TIMER_MS);
  snoozeTimer = setTimeout(() => {
    snoozeTimer = null;
    expireChannelSnoozes();
  }, wait);
});

/** When a snooze picked now would end. "Tomorrow" is 8 in the morning, and a
 *  choice made in the small hours means the coming morning, not the next. */
export function snoozeEnd(choice: SnoozeChoice, now = new Date()): number {
  if (choice === '1h') return now.getTime() + 60 * 60_000;
  if (choice === '8h') return now.getTime() + 8 * 60 * 60_000;
  const morning = new Date(now);
  morning.setHours(8, 0, 0, 0);
  if (now.getHours() >= 4) morning.setDate(morning.getDate() + 1);
  return morning.getTime();
}

export function snoozeChannel(channelId: string, choice: SnoozeChoice): void {
  const id = channelId.toLowerCase();
  if (!CHANNEL_ID_RE.test(id)) return;
  const until = snoozeEnd(choice);
  channelSnoozes.update((cur) => ({ ...cur, [id]: until }));
}

export function endChannelSnooze(channelId: string): void {
  const id = channelId.toLowerCase();
  channelSnoozes.update((cur) => {
    if (!(id in cur)) return cur;
    const { [id]: _ended, ...rest } = cur;
    return rest;
  });
}

/** When a room's snooze ends, or null if it is not snoozed. */
export function snoozedUntil(snoozes: Record<string, number>, channelId: string): number | null {
  return snoozes[channelId.toLowerCase()] ?? null;
}

/** The levels as they apply right now: a snoozed room is "Nothing". What the
 *  alerts, badges and pills read; the room's own choice stays in
 *  `channelNotifyLevels` for the menu to show. */
export function applySnoozes(
  levels: Record<string, QuietLevel>,
  snoozes: Record<string, number>,
): Record<string, QuietLevel> {
  const ids = Object.keys(snoozes);
  if (ids.length === 0) return levels;
  const out = { ...levels };
  for (const id of ids) out[id] = 'none';
  return out;
}

export const effectiveNotifyLevels = derived(
  [channelNotifyLevels, channelSnoozes],
  ([levels, snoozes]) => applySnoozes(levels, snoozes),
);

/** Whether a received line may interrupt — toast or desktop notification. */
export function channelMayAlert(level: ChannelNotifyLevel, mentionsMe: boolean): boolean {
  return level === 'all' || (level === 'mentions' && mentionsMe);
}

/**
 * How a room's unread pill is drawn.
 *
 * `loud` is the accent pill and counts toward the nav rail; `quiet` is the
 * grey one and does not. A mentions-only room goes loud only while it holds a
 * line that names you, which is the one thing its owner asked to hear about.
 * "Nothing" stays quiet even then — it is a request for silence, not a filter.
 */
export function unreadBadgeTone(
  level: ChannelNotifyLevel,
  hasUnreadMention: boolean,
): 'loud' | 'quiet' {
  if (level === 'all') return 'loud';
  return level === 'mentions' && hasUnreadMention ? 'loud' : 'quiet';
}

/**
 * Rooms holding an unread line that names this user.
 *
 * Not stored: the database counts unread but keeps no record of which of
 * those lines were mentions, so `rebuildUnreadMentions` works it out again
 * from the unread lines themselves at startup.
 */
export const channelUnreadMentions = writable<string[]>([]);

/** The same match `ChatConversation` highlights with: the name as a whole
 *  word, case-insensitive, `@` optional. Compiled once per name. */
let mentionCache: { name: string; pattern: RegExp | null } = { name: '', pattern: null };

export function messageMentionsName(message: string, name: string): boolean {
  const trimmed = name.trim();
  if (!trimmed || !message) return false;
  if (mentionCache.name !== trimmed) {
    const escaped = trimmed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    let pattern: RegExp | null = null;
    try {
      pattern = new RegExp(`(^|[^\\p{L}\\p{N}])${escaped}([^\\p{L}\\p{N}]|$)`, 'iu');
    } catch {
      pattern = null;
    }
    mentionCache = { name: trimmed, pattern };
  }
  return mentionCache.pattern?.test(message) ?? false;
}

function myChannelName(): string {
  const settings = get(appSettings);
  return settings?.channel_username || settings?.nickname || '';
}

/**
 * Sidebar aggregate: the rooms whose pill is loud. A quiet room keeps its
 * count on its own pill, because quiet means "later" rather than "never", but
 * has no business putting a number on the nav rail.
 */
export const totalChannelUnread = derived(
  [channels, effectiveNotifyLevels, channelUnreadMentions],
  ([list, levels, mentioned]) =>
    list.reduce(
      (sum, channel) =>
        !channel.in_room
        || channel.deleted
        || unreadBadgeTone(
          notifyLevelOf(levels, channel.channel_id),
          mentioned.includes(channel.channel_id),
        ) === 'quiet'
          ? sum
          : sum + Math.max(0, channel.unread),
      0,
    ),
);

/**
 * Joined rooms the user pinned to the top of "Your rooms".
 *
 * Local and per device like the levels above. Only rooms the user is in can
 * be favourites, so leaving one drops it — `refreshChannels` prunes anything
 * the database no longer has the user standing in.
 */
const FAVOURITES_KEY = 'ember.channels.favourites.v1';

export function loadChannelFavourites(storage: StorageLike | null = browserStorage()): string[] {
  if (!storage) return [];
  try {
    return parseChannelIds(storage.getItem(FAVOURITES_KEY));
  } catch {
    return [];
  }
}

export const favouriteChannels = writable<string[]>(loadChannelFavourites());

favouriteChannels.subscribe((ids) => {
  const storage = browserStorage();
  if (!storage) return;
  try {
    storage.setItem(FAVOURITES_KEY, JSON.stringify(ids));
  } catch {
    // Quota exceeded / private mode. Holds for this session.
  }
});

export function toggleChannelFavourite(channelId: string): void {
  const id = channelId.toLowerCase();
  if (!CHANNEL_ID_RE.test(id)) return;
  favouriteChannels.update((ids) =>
    ids.includes(id) ? ids.filter((existing) => existing !== id) : [...ids, id],
  );
}

export function forgetChannelFavourite(channelId: string): void {
  const id = channelId.toLowerCase();
  favouriteChannels.update((ids) =>
    ids.includes(id) ? ids.filter((existing) => existing !== id) : ids,
  );
}

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
 * Stored locally because it is a personal preference nobody else should learn.
 *
 * Scope is per entry. An entry with no rooms is global — the person is the
 * same person everywhere, which is the right default for someone following
 * you around. An entry naming rooms is hidden only in those: a member who is
 * tiresome in one room may be a moderator you need to read in another, and
 * having to choose between reading them everywhere and nowhere is what made
 * the global-only list too blunt to use.
 *
 * Purely presentational — their messages still arrive, are still stored, and
 * still count toward unread. Nothing here is a security boundary.
 */
const IGNORED_KEY = 'ember.channels.ignored.v1';
const IGNORED_NAME_MAX = 64;

export interface IgnoredMember {
  pubkey: string;
  name: string;
  /**
   * Lowercase channel ids this applies to, or undefined for everywhere.
   *
   * Undefined rather than an empty array for "global" so an entry written by
   * a build that predates room scope keeps meaning what it meant: the key has
   * not changed, and every stored entry was global when it was written. An
   * empty array would be ambiguous with "scoped to nothing", so `setIgnoreRooms`
   * drops an entry rather than storing one.
   */
  rooms?: string[];
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
  const roomsRaw = (raw as { rooms?: unknown }).rooms;
  if (!Array.isArray(roomsRaw)) return { pubkey: pk.toLowerCase(), name };
  const rooms = [
    ...new Set(
      roomsRaw
        .filter((id): id is string => typeof id === 'string' && CHANNEL_ID_RE.test(id))
        .map((id) => id.toLowerCase()),
    ),
  ];
  // A stored entry scoped to nothing would hide the member in no room at all,
  // which is the same as not being on the list. Treat it as global rather than
  // keeping a row that does nothing and cannot be reached from the UI.
  return rooms.length > 0
    ? { pubkey: pk.toLowerCase(), name, rooms }
    : { pubkey: pk.toLowerCase(), name };
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

/**
 * Pubkeys ignored everywhere — chat filters and member-row checks still
 * compare hex strings.
 *
 * Global entries only. Callers that know which room they are drawing should
 * use {@link ignoredKeysForChannel} instead, or a member muted in one room
 * would vanish from every other.
 */
export const ignoredMemberKeys = derived(ignoredMembers, (list) =>
  list.filter((entry) => entry.rooms === undefined).map((entry) => entry.pubkey),
);

/** Pubkeys hidden in one room: the global entries plus that room's own. */
export function ignoredKeysForChannel(
  list: IgnoredMember[],
  channelId: string | null | undefined,
): string[] {
  const id = (channelId ?? '').toLowerCase();
  return list
    .filter((entry) => entry.rooms === undefined || (!!id && entry.rooms.includes(id)))
    .map((entry) => entry.pubkey);
}

/** Whether this member is hidden in the given room (or anywhere, with no room). */
export function isMemberIgnored(
  list: IgnoredMember[],
  memberPubkey: string,
  channelId?: string | null,
): boolean {
  const pk = memberPubkey.toLowerCase();
  const id = (channelId ?? '').toLowerCase();
  return list.some(
    (entry) =>
      entry.pubkey === pk
      && (entry.rooms === undefined || (!!id && entry.rooms.includes(id))),
  );
}

/** How this member is hidden, for a menu that has to name the next action. */
export function ignoreScopeFor(
  list: IgnoredMember[],
  memberPubkey: string,
  channelId: string | null | undefined,
): 'none' | 'room' | 'global' {
  const pk = memberPubkey.toLowerCase();
  const entry = list.find((row) => row.pubkey === pk);
  if (!entry) return 'none';
  if (entry.rooms === undefined) return 'global';
  const id = (channelId ?? '').toLowerCase();
  return !!id && entry.rooms.includes(id) ? 'room' : 'none';
}

ignoredMembers.subscribe((entries) => {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(IGNORED_KEY, JSON.stringify(entries));
  } catch {
    // Quota exceeded / private mode. Holds for this session.
  }
});

/**
 * Turn ignoring on or off everywhere.
 *
 * Also the Settings undo, which is why it clears a room-scoped entry too:
 * that list is the only place a scoped ignore from a room the user has since
 * left can still be reached.
 */
export function toggleMemberIgnore(memberPubkey: string, name?: string): void {
  const pk = memberPubkey.toLowerCase();
  const label = typeof name === 'string' ? name.trim().slice(0, IGNORED_NAME_MAX) : '';
  ignoredMembers.update((list) =>
    list.some((entry) => entry.pubkey === pk)
      ? list.filter((entry) => entry.pubkey !== pk)
      : [...list, { pubkey: pk, name: label }],
  );
}

/**
 * Ignore everywhere, widening a room-scoped entry rather than replacing it.
 *
 * Never a toggle: the menu offers this beside a room-scoped ignore, and
 * {@link toggleMemberIgnore} would read an existing entry as "turn it off" —
 * so asking to hide someone in more places un-hid them in the rooms they were
 * already hidden in. A stored name survives when this call has none to give.
 */
export function ignoreMemberEverywhere(memberPubkey: string, name?: string): void {
  const pk = memberPubkey.toLowerCase();
  const label = typeof name === 'string' ? name.trim().slice(0, IGNORED_NAME_MAX) : '';
  ignoredMembers.update((list) => {
    const existing = list.find((entry) => entry.pubkey === pk);
    if (!existing) return [...list, { pubkey: pk, name: label }];
    if (existing.rooms === undefined && (!label || existing.name === label)) return list;
    const widened: IgnoredMember = { pubkey: pk, name: label || existing.name };
    return list.map((entry) => (entry.pubkey === pk ? widened : entry));
  });
}

/**
 * Turn ignoring on or off for one room, leaving the other rooms alone.
 *
 * Escalating rather than narrowing: asking to ignore someone in a room while
 * they are already ignored everywhere is not a request to start reading them
 * elsewhere, so a global entry is left as it is. Un-ignoring the last room
 * drops the entry instead of storing an empty scope.
 */
export function toggleMemberIgnoreInChannel(
  memberPubkey: string,
  channelId: string,
  name?: string,
): void {
  const pk = memberPubkey.toLowerCase();
  const id = channelId.toLowerCase();
  if (!CHANNEL_ID_RE.test(id)) return;
  const label = typeof name === 'string' ? name.trim().slice(0, IGNORED_NAME_MAX) : '';
  ignoredMembers.update((list) => {
    const existing = list.find((entry) => entry.pubkey === pk);
    if (!existing) return [...list, { pubkey: pk, name: label, rooms: [id] }];
    if (existing.rooms === undefined) return list;
    const rooms = existing.rooms.includes(id)
      ? existing.rooms.filter((room) => room !== id)
      : [...existing.rooms, id];
    if (rooms.length === 0) return list.filter((entry) => entry.pubkey !== pk);
    return list.map((entry) => (entry.pubkey === pk ? { ...entry, rooms } : entry));
  });
}

/** Drop a deleted room from every scoped entry, so the preference list cannot
 *  accumulate ids for rooms the user will never see again. An entry left with
 *  no rooms goes with it. Mirrors {@link forgetChannelNotifyLevel}. */
export function forgetChannelIgnores(channelId: string): void {
  const id = channelId.toLowerCase();
  ignoredMembers.update((list) => {
    let changed = false;
    const next: IgnoredMember[] = [];
    for (const entry of list) {
      if (entry.rooms === undefined || !entry.rooms.includes(id)) {
        next.push(entry);
        continue;
      }
      changed = true;
      const rooms = entry.rooms.filter((room) => room !== id);
      if (rooms.length > 0) next.push({ ...entry, rooms });
    }
    return changed ? next : list;
  });
}

/** Drop a room's notification level. Used when the room is deleted or removed
 *  from the list, so the preference cannot accumulate ids for rooms the user
 *  will never see again. Leave keeps the row (and the level) because the user
 *  can walk back in. */
export function forgetChannelNotifyLevel(channelId: string): void {
  setChannelNotifyLevel(channelId, 'all');
  endChannelSnooze(channelId);
}

let initialized = false;
let storeEpoch = 0;
let unlisteners: UnlistenFn[] = [];
/** Bumped by every local unread mutation, so `refreshChannels` can tell whether
 *  the snapshot it awaited is still the newest word on the subject. */
let unreadRevision = 0;
/** Rooms whose unread was changed locally since it was last taken from the
 *  database. A global revision used to keep *every* room's local count when
 *  any one of them moved during a refresh — so a bump in room A left room B
 *  holding a stale badge (or hiding a new one) until the next clean fetch. */
const unreadDirty = new Map<string, number>();
/** Bumped at the start of every `refreshChannels`. A later start invalidates
 *  an earlier snapshot so two overlapping fetches cannot apply out of order:
 *  the older one would see a dirty flag the newer one already consumed and
 *  write a stale unread back over a live bump. */
let refreshGen = 0;

function touchUnread(channelId: string): void {
  unreadRevision++;
  unreadDirty.set(channelId, unreadRevision);
}

/** Apply a `list_channels` snapshot, keeping live unread only on rooms that
 *  were mutated locally while (or just before) that snapshot was in flight. */
export function mergeChannelUnreadFromSnapshot(
  snapshot: ChannelInfo[],
  current: ChannelInfo[],
  dirtyIds: Iterable<string>,
): ChannelInfo[] {
  const preserve = new Set(dirtyIds);
  if (preserve.size === 0) return snapshot;
  const local = new Map(current.map((channel) => [channel.channel_id, channel.unread]));
  return snapshot.map((channel) =>
    preserve.has(channel.channel_id) && local.has(channel.channel_id)
      ? { ...channel, unread: local.get(channel.channel_id) as number }
      : channel,
  );
}

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

/** Whether an incoming offer may interrupt from this room. The toast and the
 *  nav badge both ask, so a room set to "Nothing" or an ignored sender cannot
 *  put a number on the rail that the toast was not allowed to announce. */
function offerMayAlert(
  levels: Record<string, QuietLevel>,
  ignored: IgnoredMember[],
  channelId: string,
  peerPubkey?: string,
): boolean {
  // A file offer is addressed to this user alone, so a mentions-only room
  // lets it through the way it would a line naming them.
  if (notifyLevelOf(levels, channelId) === 'none') return false;
  return !peerPubkey || !isMemberIgnored(ignored, peerPubkey, channelId);
}

/** How many incoming Ember Transfer offers are still waiting for a decision
 *  and are allowed to say so. */
export const awaitingChannelOffers = derived(
  [channelTransfers, effectiveNotifyLevels, ignoredMembers],
  ([xfers, levels, ignored]) =>
    Object.values(xfers).filter(
      (xfer) =>
        xfer.direction === 'receive'
        && xfer.status === 'awaiting'
        && offerMayAlert(levels, ignored, xfer.channel_id, xfer.peer_pubkey),
    ).length,
);

/** A file this user offered that nobody has said they could read, so the room
 *  asks whether to send the standard offer. Only a send can ask. */
export function xferNeedsConsent(xfer: ChannelTransferInfo): boolean {
  return xfer.direction === 'send' && xfer.status === 'offered' && xfer.awaiting_consent === true;
}

/** Whether an update puts that question up, rather than repeating it. */
export function xferStartsAsking(
  prior: ChannelTransferInfo | undefined,
  next: ChannelTransferInfo,
): boolean {
  return xferNeedsConsent(next) && !(prior && xferNeedsConsent(prior));
}

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

function toastXferOffer(channelId: string, peerPubkey?: string): void {
  if (isAppVisible() && (channelIsOnScreen(channelId) || get(activeChannelId) === channelId)) {
    return;
  }
  if (!offerMayAlert(get(effectiveNotifyLevels), get(ignoredMembers), channelId, peerPubkey)) return;
  const room = get(channels).find((c) => c.channel_id === channelId);
  toast(
    room
      ? m.channels_xfer_offer_elsewhere({ room: room.name })
      : m.channels_xfer_offer_elsewhere_unknown(),
  );
}

/** The question about a standard offer, for a user who is not looking at the
 *  room it is in. No room setting holds it back: it is about the user's own
 *  file, and unanswered the offer expires unseen by a 1.6 recipient. */
function toastXferConsent(channelId: string): void {
  if (isAppVisible() && (channelIsOnScreen(channelId) || get(activeChannelId) === channelId)) {
    return;
  }
  const room = get(channels).find((c) => c.channel_id === channelId);
  toast(
    room
      ? m.channels_xfer_no_reply_elsewhere({ room: room.name })
      : m.channels_xfer_no_reply_elsewhere_unknown(),
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

/**
 * Rooms whose notification level and mention flag were already carried to
 * the room they handed off to. Kept on the device beside the levels, and like
 * them survives `cleanupChannelsStore`.
 */
const CARRIED_KEY = 'ember.channels.carried.v1';

export function loadCarriedChannels(storage: StorageLike | null = browserStorage()): string[] {
  if (!storage) return [];
  try {
    return parseChannelIds(storage.getItem(CARRIED_KEY));
  } catch {
    return [];
  }
}

export const carriedChannels = writable<string[]>(loadCarriedChannels());

carriedChannels.subscribe((ids) => {
  const storage = browserStorage();
  if (!storage) return;
  try {
    storage.setItem(CARRIED_KEY, JSON.stringify(ids));
  } catch {
    // Quota exceeded / private mode. Holds for this session.
  }
});

/**
 * Bring a room's star, notification level, snooze and mention flag to the
 * room it handed off to.
 *
 * All are keyed by room id, and an ownership handoff carries the conversation
 * to a new id — so the star was pruned once the user left the old room, and
 * the level sat on an id nothing reads any more. Waits until the user is in
 * the successor, because a star is only kept for rooms they stand in.
 *
 * The star moves. The level is copied, because the old room still hears from
 * members who have not followed, and a room the user muted must not start
 * speaking up for them. Copied once: "All messages" is stored as no entry, so
 * copying on every refresh would carry the old level back over a successor the
 * user had since turned up to All. A level the successor already has was set
 * there on purpose and wins.
 */
function carryPrefsToSuccessors(list: ChannelInfo[]): void {
  const standingIn = new Set(
    list.filter((channel) => channel.in_room && !channel.deleted).map((channel) => channel.channel_id),
  );
  const moves = list.flatMap((channel) => {
    const next = channel.successor_id.toLowerCase();
    return next && next !== channel.channel_id && standingIn.has(next)
      ? [[channel.channel_id, next] as const]
      : [];
  });
  if (moves.length === 0) return;
  let favourites = get(favouriteChannels);
  let levels = get(channelNotifyLevels);
  let snoozes = get(channelSnoozes);
  let mentioned = get(channelUnreadMentions);
  let carried = get(carriedChannels);
  for (const [from, to] of moves) {
    if (favourites.includes(from)) {
      favourites = favourites.filter((id) => id !== from);
      if (!favourites.includes(to)) favourites = [...favourites, to];
    }
    if (carried.includes(from)) continue;
    carried = [...carried, from];
    if (from in levels && !(to in levels)) levels = { ...levels, [to]: levels[from] };
    if (from in snoozes && !(to in snoozes)) snoozes = { ...snoozes, [to]: snoozes[from] };
    if (mentioned.includes(from) && !mentioned.includes(to)) mentioned = [...mentioned, to];
  }
  if (favourites !== get(favouriteChannels)) favouriteChannels.set(favourites);
  if (levels !== get(channelNotifyLevels)) channelNotifyLevels.set(levels);
  if (snoozes !== get(channelSnoozes)) channelSnoozes.set(snoozes);
  if (mentioned !== get(channelUnreadMentions)) channelUnreadMentions.set(mentioned);
  if (carried !== get(carriedChannels)) carriedChannels.set(carried);
}

let latestRefresh: Promise<void> | null = null;

/** Resolves once the store holds a snapshot at least as new as this call. */
export function refreshChannels(): Promise<void> {
  const refresh = refreshChannelsOnce();
  latestRefresh = refresh;
  return refresh;
}

async function refreshChannelsOnce(): Promise<void> {
  const epoch = storeEpoch;
  const startRev = unreadRevision;
  const gen = ++refreshGen;
  const list = await listChannels();
  // A newer refresh already started — or the store was torn down — while this
  // snapshot was in flight. Applying it now would undo that newer merge, and
  // if the newer pass had already dropped a dirty flag, a stale unread could
  // land on a room the user just read or a bump that just arrived.
  if (epoch !== storeEpoch) return;
  // Settled by the newer pass instead: a caller awaiting this one for a room
  // that only just appeared (the toast that names it) would otherwise read a
  // list still without that room.
  if (gen !== refreshGen) return latestRefresh ?? undefined;
  // The database is authoritative for unread, but only as of the moment it was
  // read. A message arriving — or the user opening a room — while this call was
  // in flight moves *that room's* count after the snapshot, and a plain `set`
  // then rolled it back. Keep the live count only on rooms that actually
  // moved; every other room takes the snapshot so a bump in one room cannot
  // freeze badges everywhere else.
  channels.update((cur) => mergeChannelUnreadFromSnapshot(list, cur, unreadDirty.keys()));
  for (const [id, rev] of [...unreadDirty]) {
    if (rev <= startRev) unreadDirty.delete(id);
  }
  carryPrefsToSuccessors(list);
  const keep = new Set(list.filter((channel) => !channel.deleted).map((channel) => channel.channel_id));
  const levels = get(channelNotifyLevels);
  if (Object.keys(levels).some((id) => !keep.has(id))) {
    channelNotifyLevels.set(
      Object.fromEntries(Object.entries(levels).filter(([id]) => keep.has(id))),
    );
  }
  const snoozes = get(channelSnoozes);
  if (Object.keys(snoozes).some((id) => !keep.has(id))) {
    channelSnoozes.set(Object.fromEntries(Object.entries(snoozes).filter(([id]) => keep.has(id))));
  }
  const carried = get(carriedChannels);
  if (carried.some((id) => !keep.has(id))) {
    carriedChannels.set(carried.filter((id) => keep.has(id)));
  }
  // Pruned against the snapshot rather than on each leave, so walking out by
  // any route drops the star with it, and a leave that failed and rolled back
  // keeps it.
  const standingIn = new Set(
    list.filter((channel) => channel.in_room && !channel.deleted).map((channel) => channel.channel_id),
  );
  const favourites = get(favouriteChannels);
  if (favourites.some((id) => !standingIn.has(id))) {
    favouriteChannels.set(favourites.filter((id) => standingIn.has(id)));
  }
  const unreadNow = new Map(get(channels).map((channel) => [channel.channel_id, channel.unread]));
  const mentioned = get(channelUnreadMentions);
  if (mentioned.some((id) => !standingIn.has(id) || !unreadNow.get(id))) {
    channelUnreadMentions.set(mentioned.filter((id) => standingIn.has(id) && !!unreadNow.get(id)));
  }
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
  // Written only when there is something to drop, for the same reason as the
  // same-array return below: this runs inside a component effect.
  if (get(channelUnreadMentions).includes(channelId)) {
    channelUnreadMentions.update((ids) => ids.filter((id) => id !== channelId));
  }
  channels.update((list) => {
    // Hand back the same array when there is nothing to clear. Allocating a
    // fresh one regardless re-invalidated every `$channels` reader, and
    // `ChatConversation` calls this from the same effect that reads the channel
    // it is displaying — so an unconditional copy fed that effect its own
    // output and spun forever. `bumpChannelUnread` already bails this way.
    if (!list.some((channel) => channel.channel_id === channelId && channel.unread !== 0)) {
      return list;
    }
    touchUnread(channelId);
    return list.map((channel) =>
      channel.channel_id === channelId ? { ...channel, unread: 0 } : channel,
    );
  });
}

/**
 * Rooms currently drawn on screen, by channel id.
 *
 * `activeChannelId` is the Channels page's *selection*, which is not the same
 * question once a room can also be open in the dock while the user is on
 * Library. Each mounted `ChatConversation` adds itself here, so "is the reader
 * looking at this room" has one answer however many surfaces can show it.
 */
const visibleChannels = new Map<string, number>();

/** Mark a room as on screen. Returns the undo, so a caller can hand it
 *  straight to an effect's cleanup. */
export function noteChannelOnScreen(channelId: string): () => void {
  const id = channelId.toLowerCase();
  // Counted rather than a set: the page and the dock can legitimately show
  // the same room at once, and the first to unmount must not speak for both.
  visibleChannels.set(id, (visibleChannels.get(id) ?? 0) + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    const left = (visibleChannels.get(id) ?? 1) - 1;
    if (left > 0) visibleChannels.set(id, left);
    else visibleChannels.delete(id);
  };
}

function channelIsOnScreen(channelId: string): boolean {
  return visibleChannels.has(channelId.toLowerCase());
}

export function bumpChannelUnread(channelId: string, mentionsMe = false): void {
  if (isAppVisible() && channelIsOnScreen(channelId)) return;
  if (isAppVisible() && get(activeChannelId) === channelId) return;
  let bumped = false;
  channels.update((list) => {
    if (!list.some((channel) => channel.channel_id === channelId && channel.in_room && !channel.deleted)) {
      return list;
    }
    bumped = true;
    touchUnread(channelId);
    return list.map((channel) =>
      channel.channel_id === channelId
        ? { ...channel, unread: channel.unread + 1 }
        : channel,
    );
  });
  if (bumped && mentionsMe) noteUnreadMention(channelId);
}

/** Flag a room's unread as including a mention, if it has unread to flag. */
function noteUnreadMention(channelId: string): void {
  if (get(channelUnreadMentions).includes(channelId)) return;
  const row = get(channels).find((channel) => channel.channel_id === channelId);
  if (!row || !row.in_room || row.deleted || row.unread <= 0) return;
  channelUnreadMentions.update((ids) => [...ids, channelId]);
}

function validChannelId(raw: unknown): string | null {
  return typeof raw === 'string' && CHANNEL_ID_RE.test(raw) ? raw.toLowerCase() : null;
}

function previewText(raw: unknown): string {
  const text = typeof raw === 'string' ? raw.replace(/\s+/g, ' ').trim() : '';
  if (!text) return '';
  return text.length > 80 ? `${text.slice(0, 77)}…` : text;
}

/** Whether a received line names this user, or replies to them, from someone
 *  they have not hidden in that room — an ignored member cannot make a quiet
 *  room loud. */
function receivedMentionsMe(
  channelId: string,
  message: string,
  senderPubkey?: string,
  replyToMe = false,
): boolean {
  if (senderPubkey && isMemberIgnored(get(ignoredMembers), senderPubkey, channelId)) return false;
  return replyToMe || messageMentionsName(message, myChannelName());
}

/**
 * Whether a received line may interrupt now, recording it if so.
 *
 * Ordinary lines share one slot per room. A line addressed to the user is let
 * through the ordinary gap — that is the one it must not swallow — but still
 * waits out a short per-room gap and a full-length one per sender, so a member
 * cannot turn replies into a toast flood. Either kind restarts the ordinary
 * gap, so chatter straight after a mention does not toast on top of it.
 */
export function claimChannelToastSlot(
  channelId: string,
  senderPubkey: string | undefined,
  mentionsMe: boolean,
  now = Date.now(),
): boolean {
  if (mentionsMe) {
    const fromKey = `${channelId}:${(senderPubkey ?? '').toLowerCase()}`;
    if (now - (lastMentionToastAt.get(channelId) ?? -Infinity) < MENTION_TOAST_GAP_MS) return false;
    if (now - (lastMentionToastFrom.get(fromKey) ?? -Infinity) < TOAST_GAP_MS) return false;
    lastMentionToastAt.set(channelId, now);
    lastMentionToastFrom.set(fromKey, now);
  } else if (now - (lastToastAt.get(channelId) ?? -Infinity) < TOAST_GAP_MS) {
    return false;
  }
  lastToastAt.set(channelId, now);
  return true;
}

/** Whether a received line, stamped `sentAtSecs` (the author's signed send
 *  time, Unix seconds), is too old to interrupt for. A missing or malformed
 *  stamp is treated as live, as every line was before the check existed. */
export function channelLineIsStale(sentAtSecs: unknown, now = Date.now()): boolean {
  if (typeof sentAtSecs !== 'number' || !Number.isFinite(sentAtSecs)) return false;
  return now - sentAtSecs * 1000 > LIVE_LINE_MAX_AGE_MS;
}

function maybeToastChannelMessage(
  channelId: string,
  message: string,
  senderPubkey?: string,
  mentionsMe = false,
  sentAtSecs?: number,
) {
  // Ahead of the pacing slot, so a burst of history does not use it up and
  // swallow the first live line after it. Unread and mention flags have
  // already moved by now; only the interruption is skipped.
  if (channelLineIsStale(sentAtSecs)) return;
  // Whether the user already has this room on screen. No longer an early
  // return: it still suppresses the in-app toast, but it used to suppress the
  // desktop notification with it, and `isAppVisible` answers this far too
  // loosely for that — a window sitting behind an editor counts as watched,
  // which is precisely when a desktop notification is the point. `notify`
  // applies its own visible-*and*-focused test.
  const roomOnScreen =
    isAppVisible() && (channelIsOnScreen(channelId) || get(activeChannelId) === channelId);
  if (!channelMayAlert(notifyLevelOf(get(effectiveNotifyLevels), channelId), mentionsMe)) return;
  // Ignoring somebody is presentational, and a toast quoting them is the least
  // ignorable presentation there is: it interrupts whatever page the user is on
  // with the text they asked not to see. The unread count still moves, which is
  // the documented half of the bargain. Scoped per room, so someone hidden in
  // one room can still interrupt from another — which is the point of scoping.
  if (senderPubkey && isMemberIgnored(get(ignoredMembers), senderPubkey, channelId)) return;
  if (!claimChannelToastSlot(channelId, senderPubkey, mentionsMe)) return;
  const row = get(channels).find((channel) => channel.channel_id === channelId);
  if (row && (!row.in_room || row.deleted)) return;
  const name = row?.name ?? m.nav_channels();
  const preview = previewText(message);
  if (!preview) return;
  if (!roomOnScreen) toast(m.channels_message_toast({ name, preview }));
  // Past every suppression that governs *what* may be said — muted room,
  // ignored member, a room that is gone, the per-room gap — so a desktop
  // notification still cannot carry something the in-app toast refused. The one
  // it no longer inherits is `roomOnScreen`, which is about whether the user is
  // already looking rather than about the message. The notification's own
  // category switch is off by default; see `notify_channel_message`.
  void notify('channel_message', name, preview);
}

/** Most unread lines read back per room when the mention flags are rebuilt. */
const MENTION_REBUILD_ROWS = 200;
/** How long the rebuild waits for settings, which carry the name to match. */
const MENTION_REBUILD_SETTINGS_WAIT_MS = 30_000;

function settingsArrived(): Promise<boolean> {
  if (get(appSettings)) return Promise.resolve(true);
  return new Promise((resolve) => {
    let unsubscribe: (() => void) | null = null;
    const timer = setTimeout(() => {
      unsubscribe?.();
      resolve(false);
    }, MENTION_REBUILD_SETTINGS_WAIT_MS);
    unsubscribe = appSettings.subscribe((settings) => {
      if (!settings) return;
      clearTimeout(timer);
      // Not from inside the first call, which runs before `unsubscribe` is set.
      queueMicrotask(() => unsubscribe?.());
      resolve(true);
    });
  });
}

/**
 * Work out again which rooms hold an unread mention, once at startup.
 *
 * The database counts unread lines but keeps no record of which named the
 * user, so after a restart every "@" was gone and a mentions-only room's
 * backlog drew quiet. The newest unread lines are read back and matched the
 * way a live one is, which gives the flag back to the rooms that earned it.
 */
async function rebuildUnreadMentions(epoch: number): Promise<void> {
  if (!(await settingsArrived()) || epoch !== storeEpoch) return;
  const rooms = get(channels).filter((room) => room.in_room && !room.deleted && room.unread > 0);
  for (const room of rooms) {
    if (epoch !== storeEpoch) return;
    if (get(channelUnreadMentions).includes(room.channel_id)) continue;
    let rows: ChannelMessageInfo[];
    try {
      rows = await getChannelMessages(room.channel_id, Math.min(room.unread, MENTION_REBUILD_ROWS));
    } catch {
      continue;
    }
    if (epoch !== storeEpoch) return;
    const named = rows.some(
      (row) =>
        row.direction === 'received'
        && !row.read
        && receivedMentionsMe(room.channel_id, row.message, row.sender_pubkey, row.reply_to_me),
    );
    // Rechecks the room still has unread, so one opened meanwhile is skipped.
    if (named) noteUnreadMention(room.channel_id);
  }
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
        reply_to_me?: boolean;
        /** The author's signed send time, Unix seconds. */
        timestamp?: number;
      }>('ember:channel-message', (event) => {
        const channelId = validChannelId(event.payload?.channel_id);
        if (!channelId) return;
        if (event.payload.direction && event.payload.direction !== 'received') {
          return;
        }
        const sentAt = event.payload.timestamp;
        if (!get(channels).some((channel) => channel.channel_id === channelId)) {
          // No bump afterwards. The row is missing because this is the first
          // line from a room that only just appeared, and the count the fetch
          // brings back is read from the database — which already holds the
          // message that triggered this event. Adding one more counted it twice.
          //
          // Toasting waits for the fetch rather than racing it: the row is what
          // carries the room's name, so announcing the message first named it
          // "Channels" — the nav label — for the one line where the user has the
          // least idea which room just spoke.
          const message = event.payload.message ?? '';
          const sender = event.payload.sender_pubkey;
          const replyToMe = event.payload.reply_to_me === true;
          refreshChannels()
            .catch(() => {})
            .then(() => {
              const mentionsMe = receivedMentionsMe(channelId, message, sender, replyToMe);
              if (mentionsMe) noteUnreadMention(channelId);
              maybeToastChannelMessage(channelId, message, sender, mentionsMe, sentAt);
            });
          return;
        }
        const message = event.payload.message ?? '';
        const sender = event.payload.sender_pubkey;
        const mentionsMe = receivedMentionsMe(
          channelId,
          message,
          sender,
          event.payload.reply_to_me === true,
        );
        bumpChannelUnread(channelId, mentionsMe);
        maybeToastChannelMessage(channelId, message, sender, mentionsMe, sentAt);
      }),
    );
    // The Channels page registers a handoff listener too, and when it is mounted
    // both fire — two `list_channels` for one event. Kept anyway: a handoff moves
    // rooms and ownership whether or not that page is on screen, and this is the
    // only listener that runs when it is not, so the sidebar's unread total and the
    // room list would otherwise sit stale until the next visit. An ownership
    // handoff is rare; a wrong list is not worth the saving.
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
        toastXferOffer(channelId, p.peer_pubkey);
      }),
    );
    registered.push(
      await listen<ChannelTransferInfo>('ember:xfer-update', (event) => {
        if (myEpoch !== storeEpoch) return;
        const t = event.payload;
        if (!t?.xfer_id) return;
        const prior = get(channelTransfers)[t.xfer_id];
        channelTransfers.update((cur) => ({ ...cur, [t.xfer_id]: t }));
        if (xferStartsAsking(prior, t)) {
          const channelId = validChannelId(t.channel_id);
          if (channelId) toastXferConsent(channelId);
        }
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
    void rebuildUnreadMentions(myEpoch);
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
  unreadRevision = 0;
  refreshGen = 0;
  unreadDirty.clear();
  visibleChannels.clear();
  lastToastAt.clear();
  lastMentionToastAt.clear();
  lastMentionToastFrom.clear();
  lastOpenedChannelId = null;
  // Cleared with the room it refers to. Left standing, the next visit read as
  // "the user had something open, leave their selection alone" while the room
  // itself had just been nulled — so they arrived at an empty directory instead
  // of the newest joined room a fresh arrival is meant to open.
  channelSelectionStashed = false;
  for (const timer of xferClearTimers.values()) clearTimeout(timer);
  xferClearTimers.clear();
  channelTransfers.set({});
  channelUnreadMentions.set([]);
  channels.set([]);
  activeChannelId.set(null);
}
