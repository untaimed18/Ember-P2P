import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';

vi.mock('@tauri-apps/api/core', () => ({
  Channel: class {},
  invoke: vi.fn(),
}));
vi.mock('@tauri-apps/plugin-process', () => ({ relaunch: vi.fn() }));

import { invoke } from '@tauri-apps/api/core';
import {
  applyBackgroundCheckResult,
  checkUpdateHandoff,
  installUpdate,
  loadLastBackgroundCheckResult,
  updater,
  type SecureUpdateCheckResult,
} from './updater';

const invokeMock = vi.mocked(invoke);
const storage = new Map<string, string>();

const IDLE = get(updater);

function found(version: string): SecureUpdateCheckResult {
  return {
    update: { version, securityEpoch: 1, notes: null, date: null },
    pendingRetained: true,
  };
}

const NOTHING: SecureUpdateCheckResult = { update: null, pendingRetained: false };

/** Make the next `invoke` hang until the returned function settles it. */
function holdNextInvoke(): (value: unknown) => void {
  let settle: (value: unknown) => void = () => {};
  invokeMock.mockImplementation(
    () =>
      new Promise<unknown>((resolve) => {
        settle = resolve;
      }) as Promise<never>,
  );
  return (value) => settle(value);
}

beforeEach(() => {
  storage.clear();
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => storage.get(k) ?? null,
    setItem: (k: string, v: string) => void storage.set(k, v),
    removeItem: (k: string) => void storage.delete(k),
  });
  updater.set({ ...IDLE });
  invokeMock.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('applyBackgroundCheckResult', () => {
  it('offers an update the backend found', async () => {
    await applyBackgroundCheckResult(found('9.9.9'));
    const s = get(updater);
    expect(s.phase).toBe('available');
    expect(s.version).toBe('9.9.9');
  });

  it('stays quiet when the backend found nothing, even if the check failed', async () => {
    await applyBackgroundCheckResult({ ...NOTHING, error: 'offline' });
    const s = get(updater);
    expect(s.phase).toBe('idle');
    expect(s.error).toBeNull();
  });

  it('leaves an installed update waiting for its restart alone', async () => {
    updater.set({ ...IDLE, phase: 'ready', version: '9.9.8' });
    await applyBackgroundCheckResult(found('9.9.9'));
    expect(get(updater).phase).toBe('ready');
    expect(get(updater).version).toBe('9.9.8');
  });

  it('holds a result that arrives during the hand-off query and keeps the recovery offer', async () => {
    const resolveHandoff = holdNextInvoke();
    const handoff = checkUpdateHandoff();

    // Arrives while the hand-off query is still in flight.
    await applyBackgroundCheckResult(found('9.9.9'));
    expect(get(updater).phase).toBe('idle');

    resolveHandoff({ version: '9.9.9', securityEpoch: 1, attemptedAt: 0, installerReady: true });
    await handoff;
    await vi.waitFor(() => expect(get(updater).phase).toBe('stalled'));
    expect(get(updater).version).toBe('9.9.9');
  });

  it('applies a held result once a hand-off query finds nothing', async () => {
    const resolveHandoff = holdNextInvoke();
    const handoff = checkUpdateHandoff();
    await applyBackgroundCheckResult(found('9.9.9'));

    resolveHandoff(null);
    await handoff;
    await vi.waitFor(() => expect(get(updater).phase).toBe('available'));
  });
});

describe('loadLastBackgroundCheckResult', () => {
  it('offers an update the backend found before this window was listening', async () => {
    invokeMock.mockResolvedValueOnce(found('9.9.9'));
    await loadLastBackgroundCheckResult();
    expect(invokeMock).toHaveBeenCalledWith('get_last_update_check_result');
    expect(get(updater).phase).toBe('available');
    expect(get(updater).version).toBe('9.9.9');
  });

  it('does nothing before the first check or when the backend cannot answer', async () => {
    invokeMock.mockResolvedValueOnce(null);
    await loadLastBackgroundCheckResult();
    expect(get(updater)).toEqual(IDLE);

    invokeMock.mockRejectedValueOnce(new Error('ipc'));
    await loadLastBackgroundCheckResult();
    expect(get(updater)).toEqual(IDLE);
  });
});

type ProgressChannel = { onmessage: (event: unknown) => void };

describe('installUpdate', () => {
  it('starts the count again when a second download starts', async () => {
    await applyBackgroundCheckResult(found('9.9.9'));
    const seen: Array<[string, number]> = [];
    invokeMock.mockImplementationOnce((async (_cmd: string, args: { onEvent: ProgressChannel }) => {
      const send = (event: unknown) => {
        args.onEvent.onmessage(event);
        const s = get(updater);
        seen.push([s.phase, s.downloaded]);
      };
      // A background download it waited on, then the copy it staged.
      send({ event: 'Started', data: { contentLength: 100 } });
      send({ event: 'Progress', data: { chunkLength: 60 } });
      send({ event: 'Started', data: { contentLength: 100 } });
      send({ event: 'Progress', data: { chunkLength: 100 } });
      send({ event: 'Finished' });
    }) as never);
    await installUpdate();
    expect(seen).toEqual([
      ['downloading', 0],
      ['downloading', 60],
      ['downloading', 0],
      ['downloading', 100],
      ['installing', 100],
    ]);
    expect(get(updater).phase).toBe('ready');
  });
});

describe('an install that stopped the network', () => {
  it('keeps saying to restart Ember when the next automatic check arrives', async () => {
    await applyBackgroundCheckResult(found('9.9.9'));
    invokeMock.mockRejectedValueOnce(
      JSON.stringify({
        __coded: true,
        code: 'updater_install_failed_services_stopped',
        message: 'restart Ember to resume transfers',
      }),
    );
    await installUpdate();
    const failed = get(updater);
    expect(failed.phase).toBe('error');

    await applyBackgroundCheckResult(found('9.9.9'));
    expect(get(updater)).toEqual(failed);
  });
});
