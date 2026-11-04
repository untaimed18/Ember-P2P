import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('$lib/stores/toast', () => ({ flushToastActionsBeforeExit: vi.fn(async () => {}) }));

import { invoke } from '@tauri-apps/api/core';
import { flushToastActionsBeforeExit } from '$lib/stores/toast';
import { finishRequestedQuit } from './settings';

const invokeMock = vi.mocked(invoke);

describe('finishRequestedQuit', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    vi.mocked(flushToastActionsBeforeExit).mockClear();
  });

  // The popped-out chat can emit the quit request too; it must not cost the
  // user the Undo on actions they already chose.
  it('commits nothing when no exit is waiting on the window', async () => {
    invokeMock.mockResolvedValueOnce(false);
    await finishRequestedQuit();
    expect(flushToastActionsBeforeExit).not.toHaveBeenCalled();
    expect(invokeMock.mock.calls.map(([command]) => command)).toEqual(['quit_flush_pending']);
  });

  it('sends pending Undo actions, then finishes an exit the backend started', async () => {
    invokeMock.mockResolvedValueOnce(true).mockResolvedValueOnce(undefined);
    await finishRequestedQuit();
    expect(flushToastActionsBeforeExit).toHaveBeenCalledOnce();
    expect(invokeMock.mock.calls.map(([command]) => command)).toEqual([
      'quit_flush_pending',
      'finish_requested_quit',
    ]);
    expect(vi.mocked(flushToastActionsBeforeExit).mock.invocationCallOrder[0]).toBeLessThan(
      invokeMock.mock.invocationCallOrder[1],
    );
  });
});
