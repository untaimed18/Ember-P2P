import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AppSettings } from '$lib/types';

// The policy is what is under test; the OS call is not. Mocked at the module
// boundary so a suppressed notification is observable as "the command was never
// invoked" rather than as an absence of side effects nobody can see.
vi.mock('$lib/api/system', () => ({
  showNotification: vi.fn(async () => {}),
  getRuntimeStatus: vi.fn(async () => ({})),
}));

const { showNotification } = await import('$lib/api/system');
const { appSettings } = await import('$lib/stores/settings');
const { notify, shouldNotify, resetNotificationThrottleForTest } = await import(
  './notifications'
);

const sendMock = vi.mocked(showNotification);

/** Only the fields the policy reads; the rest of `AppSettings` is irrelevant. */
function settingsWith(patch: Partial<AppSettings> = {}): AppSettings {
  return {
    notifications_enabled: true,
    notifications_only_when_unfocused: true,
    notify_download_complete: true,
    notify_download_failed: true,
    notify_friend_online: true,
    notify_friend_message: true,
    notify_friend_request: true,
    notify_channel_message: true,
    ...patch,
  } as AppSettings;
}

/** Pretend Ember has the user's attention. The node test environment has no
 *  `document`, which the policy reads as "not focused" — the common case. */
function focusEmber() {
  (globalThis as { document?: unknown }).document = {
    visibilityState: 'visible',
    hasFocus: () => true,
  };
}

function blurEmber() {
  delete (globalThis as { document?: unknown }).document;
}

beforeEach(() => {
  sendMock.mockClear();
  resetNotificationThrottleForTest();
  blurEmber();
  appSettings.set(settingsWith());
});

afterEach(() => {
  blurEmber();
  appSettings.set(null);
});

describe('shouldNotify', () => {
  it('stays silent until the settings have loaded', () => {
    appSettings.set(null);
    expect(shouldNotify('download_complete')).toBe(false);
  });

  it('honors the master switch', () => {
    appSettings.set(settingsWith({ notifications_enabled: false }));
    expect(shouldNotify('download_complete')).toBe(false);
    expect(shouldNotify('friend_message')).toBe(false);
  });

  it('honors each category on its own', () => {
    appSettings.set(settingsWith({ notify_channel_message: false }));
    expect(shouldNotify('channel_message')).toBe(false);
    expect(shouldNotify('friend_message')).toBe(true);
  });

  it('suppresses while Ember is focused, unless the user opted out', () => {
    focusEmber();
    expect(shouldNotify('friend_message')).toBe(false);

    appSettings.set(settingsWith({ notifications_only_when_unfocused: false }));
    expect(shouldNotify('friend_message')).toBe(true);
  });

  it('notifies for a visible-but-unfocused window', () => {
    // A window sitting behind the editor on a second monitor is not being
    // watched, even though `visibilityState` still says "visible".
    (globalThis as { document?: unknown }).document = {
      visibilityState: 'visible',
      hasFocus: () => false,
    };
    expect(shouldNotify('friend_message')).toBe(true);
  });
});

describe('notify', () => {
  it('sends when the policy allows it', async () => {
    await notify('download_complete', 'Download finished', 'movie.mkv');
    expect(sendMock).toHaveBeenCalledTimes(1);
    expect(sendMock).toHaveBeenCalledWith('Download finished', 'movie.mkv');
  });

  it('drops a repeat of the same notification', async () => {
    await notify('friend_message', 'Ana', 'hello');
    await notify('friend_message', 'Ana', 'hello');
    expect(sendMock).toHaveBeenCalledTimes(1);

    // A genuinely different message from the same friend still gets through.
    await notify('friend_message', 'Ana', 'are you there?');
    expect(sendMock).toHaveBeenCalledTimes(2);
  });

  it('stops a burst rather than stacking a queue drain on the desktop', async () => {
    for (let i = 0; i < 12; i++) {
      await notify('download_complete', 'Download finished', `file-${i}.bin`);
    }
    expect(sendMock.mock.calls.length).toBeLessThanOrEqual(4);
    expect(sendMock.mock.calls.length).toBeGreaterThan(0);
  });

  it('never sends a title-less notification', async () => {
    await notify('download_complete', '   ', 'body only');
    expect(sendMock).not.toHaveBeenCalled();
  });

  it('does not throw when the OS refuses', async () => {
    sendMock.mockRejectedValueOnce('the shell said no');
    await expect(notify('friend_online', 'Ana is online')).resolves.toBeUndefined();
  });

  /// A shell that refuses once will refuse every time, and each attempt costs an
  /// IPC round trip from an event handler whose real job is updating a store.
  it('gives up after a delivery failure', async () => {
    sendMock.mockRejectedValueOnce('the shell said no');
    await notify('friend_online', 'first');
    expect(sendMock).toHaveBeenCalledTimes(1);

    await notify('friend_online', 'second');
    expect(sendMock).toHaveBeenCalledTimes(1);
  });

  /// The backend's own burst ceiling says nothing about whether the OS works,
  /// so hitting it must not switch notifications off for the session.
  it('keeps trying after the backend rate-limits one', async () => {
    sendMock.mockRejectedValueOnce(
      JSON.stringify({
        __coded: true,
        code: 'notification_rate_limited',
        message: 'Too many notifications at once',
      }),
    );
    await notify('friend_online', 'first');
    expect(sendMock).toHaveBeenCalledTimes(1);

    await notify('friend_online', 'second');
    expect(sendMock).toHaveBeenCalledTimes(2);
  });
});
