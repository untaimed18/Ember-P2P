import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const events = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => {
    events.set(name, handler);
    return () => events.delete(name);
  }),
}));
vi.mock('$lib/notifications', () => ({ notify: vi.fn(async () => {}) }));
vi.mock('$lib/stores/toast', () => ({ addToast: vi.fn(), toast: vi.fn() }));

import { invoke } from '@tauri-apps/api/core';
import * as m from '$lib/paraglide/messages';
import { addToast, toast } from '$lib/stores/toast';
import { initSilentUpdate, type SilentUpdatePhase, type SilentUpdateStatus } from './silentUpdate';

const invokeMock = vi.mocked(invoke);

function status(phase: SilentUpdatePhase): SilentUpdateStatus {
  return {
    supported: true,
    unsupportedReason: null,
    enabled: true,
    phase,
    version: '1.8.0',
    countdownEndsAt: phase === 'countdown' ? 1_790_000_060_000 : null,
    postponedUntil: null,
    lastSuccess: null,
    waitingLong: false,
    prepareFailed: false,
  };
}

function emit(name: string, payload: unknown) {
  const handler = events.get(name);
  if (!handler) throw new Error(`nothing listens for ${name}`);
  handler({ payload });
}

const publish = (phase: SilentUpdatePhase) => emit('ember:silent-update', status(phase));

let stop: () => void = () => {};

beforeEach(async () => {
  vi.stubGlobal('document', {
    visibilityState: 'visible',
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  });
  vi.mocked(addToast).mockClear();
  vi.mocked(toast).mockClear();
  invokeMock.mockReset();
  invokeMock.mockResolvedValue(status('waiting'));
  stop = await initSilentUpdate();
});

afterEach(() => {
  stop();
  vi.unstubAllGlobals();
});

describe('leaving the countdown', () => {
  it('says Ember is busy again only when the backend says activity ended it', () => {
    publish('countdown');
    // What waking from sleep looks like: the countdown is simply gone.
    publish('waiting');
    expect(toast).not.toHaveBeenCalled();

    publish('countdown');
    emit('ember:silent-update-busy', null);
    publish('waiting');
    expect(toast).toHaveBeenCalledTimes(1);
    expect(toast).toHaveBeenCalledWith(m.silent_update_aborted());
  });

  it('warns, and keeps warning, when the install fails before Ember closed', () => {
    publish('countdown');
    publish('installing');
    publish('held');
    expect(addToast).toHaveBeenCalledWith('warning', m.silent_update_failed({ version: '1.8.0' }), 0);
  });

  it('treats Skip this version as the answer it is, not a failure', () => {
    publish('countdown');
    publish('held');
    expect(addToast).not.toHaveBeenCalled();
    expect(toast).not.toHaveBeenCalled();
  });
});
