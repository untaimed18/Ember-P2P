import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import type { RoomDmThread } from '$lib/api/roomDm';

const role = vi.hoisted(() => ({ chat: false }));
const bus = vi.hoisted(() => ({
  handlers: new Map<string, (event: { payload: unknown }) => unknown>(),
  emitted: [] as Array<[string, unknown]>,
}));
const backend = vi.hoisted(() => ({
  threads: [] as unknown[],
  calls: [] as Array<[string, unknown]>,
}));

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(async (cmd: string, args?: unknown) => {
    backend.calls.push([cmd, args]);
    return cmd === 'list_room_dm_threads' ? structuredClone(backend.threads) : undefined;
  }),
}));
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (name: string, fn: (event: { payload: unknown }) => unknown) => {
    bus.handlers.set(name, fn);
    return () => bus.handlers.delete(name);
  }),
  emit: vi.fn(async (name: string, payload?: unknown) => {
    bus.emitted.push([name, payload]);
  }),
}));
vi.mock('$lib/windowRole', async (importOriginal) => ({
  ...(await importOriginal<typeof import('$lib/windowRole')>()),
  isChatWindow: () => role.chat,
}));
vi.mock('$lib/stores/channels', () => ({
  ignoreMemberEverywhere: vi.fn(),
  pushIgnoredNow: vi.fn(async () => {}),
}));

const MEMBER = 'ab'.repeat(32);

function thread(overrides: Partial<RoomDmThread> = {}): RoomDmThread {
  return {
    member_pubkey: MEMBER,
    name: 'Lin',
    state: 'request',
    peer_state: '',
    channel_id: 'c0'.repeat(16),
    updated_at: 1,
    unread: 1,
    last_text: 'hi',
    last_at: 1,
    can_send: true,
    is_friend: false,
    ...overrides,
  };
}

function storage(): Storage {
  const data = new Map<string, string>();
  return {
    get length() {
      return data.size;
    },
    clear: () => data.clear(),
    getItem: (key) => data.get(key) ?? null,
    key: (i) => [...data.keys()][i] ?? null,
    removeItem: (key) => void data.delete(key),
    setItem: (key, value) => void data.set(key, String(value)),
  };
}

/** A fresh store and toast queue, as a new window has them. */
async function load() {
  vi.resetModules();
  const store = await import('./roomDm');
  const toast = await import('./toast');
  const m = await import('$lib/paraglide/messages');
  await store.initRoomDmStore();
  return { ...store, ...toast, m };
}

function sent(cmd: string) {
  return backend.calls.filter(([name]) => name === cmd);
}

/** Let the expiry's chain of awaits run out. */
async function settle() {
  for (let i = 0; i < 20; i++) await Promise.resolve();
}

// Every test re-imports the store and the compiled message catalog, all ten
// locales of it. Transforming them the first time takes longer than a test's
// own timeout on a loaded machine, so it is paid once here instead.
beforeAll(async () => {
  await import('./roomDm');
  await import('./toast');
  await import('$lib/paraglide/messages');
}, 60_000);

beforeEach(() => {
  vi.useFakeTimers();
  vi.stubGlobal('sessionStorage', storage());
  role.chat = false;
  bus.handlers.clear();
  bus.emitted = [];
  backend.threads = [thread()];
  backend.calls = [];
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('held private-message answers, main window', () => {
  it('hides a declined request at once and sends the decline only when the toast goes', async () => {
    const s = await load();
    expect(get(s.dmRequests).map((t) => t.member_pubkey)).toEqual([MEMBER]);

    s.declineDmRequest(MEMBER.toUpperCase(), 'Lin');
    expect(get(s.dmRequests)).toEqual([]);
    expect(get(s.dmAnswersHeld).get(MEMBER)).toBe('decline');
    expect(get(s.toasts).map((t) => t.message)).toEqual([s.m.channels_dm_declined_toast({ name: 'Lin' })]);
    expect(sent('answer_room_dm_request')).toEqual([]);

    backend.threads = [thread()];
    await vi.advanceTimersByTimeAsync(8000);
    await settle();
    expect(sent('answer_room_dm_request')).toEqual([['answer_room_dm_request', { member: MEMBER, accept: false }]]);
    expect(get(s.dmAnswersHeld).size).toBe(0);
  });

  it('shows the request again and sends nothing when Undo is taken', async () => {
    const s = await load();
    s.declineDmRequest(MEMBER, 'Lin');
    expect(s.runLatestUndo()).toBe(true);
    expect(get(s.dmRequests).map((t) => t.member_pubkey)).toEqual([MEMBER]);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(sent('answer_room_dm_request')).toEqual([]);
  });

  // Navigating away from Channels and back remounts the page; the hold is
  // the store's, so the banner stays hidden.
  it('keeps the hold for a page that mounts later, and does not hold twice', async () => {
    const s = await load();
    s.declineDmRequest(MEMBER, 'Lin');
    s.declineDmRequest(MEMBER, 'Lin');
    expect(get(s.toasts)).toHaveLength(1);
    expect(get(s.dmRequests)).toEqual([]);
  });

  it('drops a held decline without a word when the request is accepted', async () => {
    const s = await load();
    s.declineDmRequest(MEMBER, 'Lin');
    s.cancelHeldDmAnswer(MEMBER);
    await settle();
    expect(get(s.toasts)).toEqual([]);
    expect(get(s.dmAnswersHeld).size).toBe(0);
    await vi.advanceTimersByTimeAsync(10_000);
    await settle();
    expect(sent('answer_room_dm_request')).toEqual([]);
  });

  it('sends nothing when the request was answered elsewhere before the toast went', async () => {
    const s = await load();
    const channels = await import('$lib/stores/channels');
    const other = 'cd'.repeat(32);
    backend.threads = [thread(), thread({ member_pubkey: other })];
    await s.refreshDmThreads();
    s.declineDmRequest(MEMBER, 'Lin');
    s.ignoreDmRequester(other, 'Ola');
    // Accepted from another surface meanwhile.
    backend.threads = [thread({ state: 'open' }), thread({ member_pubkey: other, state: 'open' })];
    await vi.advanceTimersByTimeAsync(8000);
    await settle();
    expect(sent('answer_room_dm_request')).toEqual([]);
    expect(sent('drop_room_dm_request')).toEqual([]);
    expect(channels.ignoreMemberEverywhere).not.toHaveBeenCalled();
    expect(get(s.toasts)).toEqual([]);
  });

  it('ignores everywhere when an Ignore toast goes', async () => {
    const s = await load();
    const channels = await import('$lib/stores/channels');
    vi.mocked(channels.ignoreMemberEverywhere).mockClear();
    s.ignoreDmRequester(MEMBER, 'Lin');
    expect(get(s.dmAnswersHeld).get(MEMBER)).toBe('ignore');
    await vi.advanceTimersByTimeAsync(8000);
    await settle();
    expect(channels.ignoreMemberEverywhere).toHaveBeenCalledWith(MEMBER, 'Lin');
    expect(sent('drop_room_dm_request')).toEqual([['drop_room_dm_request', { member: MEMBER }]]);
  });

  it('never starts the toast with an empty name', async () => {
    const s = await load();
    s.ignoreDmRequester(MEMBER, '  ');
    expect(get(s.toasts)[0].message).toBe(s.m.channels_dm_ignoring_toast({ name: s.m.channels_dm_someone() }));
  });

  // Quitting commits whatever an Undo still holds.
  it('sends a held answer when the toasts are flushed for exit', async () => {
    const s = await load();
    const pending: boolean[] = [];
    s.onPendingUndoChange((p) => pending.push(p));
    s.declineDmRequest(MEMBER, 'Lin');
    expect(pending.at(-1)).toBe(true);
    await s.flushToastActions();
    s.onPendingUndoChange(null);
    expect(sent('answer_room_dm_request')).toEqual([['answer_room_dm_request', { member: MEMBER, accept: false }]]);
    expect(pending.at(-1)).toBe(false);
  });

  it('sends an answer a reload cut off', async () => {
    let s = await load();
    s.declineDmRequest(MEMBER, 'Lin');
    // The document goes without any toast expiring.
    s = await load();
    await settle();
    expect(sent('answer_room_dm_request')).toEqual([['answer_room_dm_request', { member: MEMBER, accept: false }]]);
    expect(sessionStorage.getItem('ember.roomDm.held.v1')).toBeNull();
  });

  it('holds a Decline for the chat window until that window says', async () => {
    const s = await load();
    await bus.handlers.get('ember-ui:dm-hold')?.({ payload: { member: MEMBER, name: 'Lin' } });
    expect(get(s.dmAnswersHeld).get(MEMBER)).toBe('decline');
    expect(bus.emitted.at(-1)).toEqual(['ember-ui:dm-held', { held: [{ member: MEMBER, kind: 'decline' }] }]);
    // Its own countdown is only a backstop for a window that never answers.
    await vi.advanceTimersByTimeAsync(8000);
    expect(sent('answer_room_dm_request')).toEqual([]);

    await bus.handlers.get('ember-ui:dm-unhold')?.({ payload: { member: MEMBER, commit: true } });
    await settle();
    expect(sent('answer_room_dm_request')).toHaveLength(1);
    expect(bus.emitted.at(-1)).toEqual(['ember-ui:dm-held', { held: [] }]);
  });

  it('takes a chat window Decline back on its Undo, and sends one whose window closed', async () => {
    const s = await load();
    const hold = bus.handlers.get('ember-ui:dm-hold');
    await hold?.({ payload: { member: MEMBER, name: 'Lin' } });
    await bus.handlers.get('ember-ui:dm-unhold')?.({ payload: { member: MEMBER, commit: false } });
    await settle();
    expect(get(s.dmAnswersHeld).size).toBe(0);
    expect(sent('answer_room_dm_request')).toEqual([]);

    await hold?.({ payload: { member: MEMBER, name: 'Lin' } });
    await bus.handlers.get('ember:chat-window-closed')?.({ payload: null });
    await settle();
    expect(sent('answer_room_dm_request')).toHaveLength(1);
  });
});

describe('held private-message answers, chat window', () => {
  beforeEach(() => {
    role.chat = true;
  });

  it('hands a Decline to the main window and only asks it to send', async () => {
    const s = await load();
    s.declineDmRequest(MEMBER, 'Lin');
    expect(get(s.dmRequests)).toEqual([]);
    expect(bus.emitted.at(-1)).toEqual(['ember-ui:dm-hold', { member: MEMBER, name: 'Lin' }]);
    // The main window says it holds it.
    await bus.handlers.get('ember-ui:dm-held')?.({ payload: { held: [{ member: MEMBER, kind: 'decline' }] } });

    await vi.advanceTimersByTimeAsync(8000);
    await settle();
    expect(bus.emitted.at(-1)).toEqual(['ember-ui:dm-unhold', { member: MEMBER, commit: true }]);
    expect(sent('answer_room_dm_request')).toEqual([]);
    // Still hidden until the main window is done.
    expect(get(s.dmAnswersHeld).get(MEMBER)).toBe('decline');
    await bus.handlers.get('ember-ui:dm-held')?.({ payload: { held: [] } });
    await settle();
    expect(get(s.dmAnswersHeld).size).toBe(0);
  });

  it('closes its toast when the main window settles the answer first', async () => {
    const s = await load();
    s.declineDmRequest(MEMBER, 'Lin');
    const held = bus.handlers.get('ember-ui:dm-held');
    await held?.({ payload: { held: [{ member: MEMBER, kind: 'decline' }] } });
    // Undone from the main window's toast.
    await held?.({ payload: { held: [] } });
    await settle();
    expect(get(s.toasts)).toEqual([]);
    expect(get(s.dmAnswersHeld).size).toBe(0);
    const emittedAfter = bus.emitted.length;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(bus.emitted.slice(emittedAfter)).toEqual([]);
  });

  it('answers from here when the main window never took the Decline', async () => {
    const s = await load();
    s.declineDmRequest(MEMBER, 'Lin');
    await vi.advanceTimersByTimeAsync(8000);
    await settle();
    expect(sent('answer_room_dm_request')).toEqual([['answer_room_dm_request', { member: MEMBER, accept: false }]]);
    expect(get(s.dmAnswersHeld).size).toBe(0);
  });

  it('tells the main window to drop a held answer when the request is accepted here', async () => {
    const s = await load();
    await bus.handlers.get('ember-ui:dm-held')?.({ payload: { held: [{ member: MEMBER, kind: 'ignore' }] } });
    expect(get(s.dmAnswersHeld).get(MEMBER)).toBe('ignore');
    s.cancelHeldDmAnswer(MEMBER);
    expect(bus.emitted.at(-1)).toEqual(['ember-ui:dm-unhold', { member: MEMBER, commit: false }]);
  });
});
