import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AppSettings } from '$lib/types';

// emberd's build: notifications are the browser's, never the desktop's.
vi.mock('$lib/runtime', () => ({ isServer: true }));
vi.mock('$lib/api/system', () => ({
  showNotification: vi.fn(async () => {}),
  getRuntimeStatus: vi.fn(async () => ({})),
}));

const { showNotification } = await import('$lib/api/system');
const { appSettings } = await import('$lib/stores/settings');
const { notify, browserNotificationState, askForBrowserNotifications, resetNotificationThrottleForTest } = await import(
  './notifications'
);

/** The browser's Notification, recording what it was asked to show. */
class FakeNotification {
  static permission: NotificationPermission = 'default';
  static requestPermission = vi.fn(async () => FakeNotification.permission);
  static shown: FakeNotification[] = [];
  onclick: (() => void) | null = null;
  closed = false;
  constructor(
    public title: string,
    public options: NotificationOptions,
  ) {
    FakeNotification.shown.push(this);
  }
  close() {
    this.closed = true;
  }
}

const focus = vi.fn();

function servedSecurely(secure: boolean) {
  vi.stubGlobal('window', { isSecureContext: secure, focus });
}

beforeEach(() => {
  FakeNotification.permission = 'default';
  FakeNotification.shown = [];
  FakeNotification.requestPermission.mockClear();
  focus.mockClear();
  vi.mocked(showNotification).mockClear();
  vi.stubGlobal('Notification', FakeNotification);
  servedSecurely(true);
  resetNotificationThrottleForTest();
  appSettings.set({
    notifications_enabled: true,
    notifications_only_when_unfocused: false,
    notify_download_complete: true,
  } as AppSettings);
});

afterEach(() => {
  vi.unstubAllGlobals();
  appSettings.set(null);
});

describe('emberd in the browser', () => {
  it('shows nothing until the browser is allowed to', async () => {
    await notify('download_complete', 'Download complete', 'film.mkv');
    expect(FakeNotification.shown).toHaveLength(0);
    FakeNotification.permission = 'denied';
    await notify('download_complete', 'Download complete', 'film.mkv');
    expect(FakeNotification.shown).toHaveLength(0);
    expect(showNotification).not.toHaveBeenCalled();
  });

  it('shows it in the browser once allowed, cut to what a notification holds', async () => {
    FakeNotification.permission = 'granted';
    await notify('download_complete', `  ${'T'.repeat(200)}  `, 'b'.repeat(500));
    expect(showNotification).not.toHaveBeenCalled();
    expect(FakeNotification.shown).toHaveLength(1);
    const [shown] = FakeNotification.shown;
    expect(shown.title).toBe('T'.repeat(120));
    expect(shown.options.body).toBe('b'.repeat(300));
    expect(shown.options.icon).toBe('/icon.png');
    shown.onclick?.();
    expect(focus).toHaveBeenCalled();
    expect(shown.closed).toBe(true);
  });

  it('keeps the same rules as the desktop', async () => {
    FakeNotification.permission = 'granted';
    appSettings.set({ notifications_enabled: true, notify_download_complete: false } as AppSettings);
    await notify('download_complete', 'Download complete', 'film.mkv');
    expect(FakeNotification.shown).toHaveLength(0);
    appSettings.set({ notifications_enabled: true, notify_download_complete: true } as AppSettings);
    await notify('download_complete', 'Download complete', 'film.mkv');
    await notify('download_complete', 'Download complete', 'film.mkv');
    expect(FakeNotification.shown).toHaveLength(1);
  });

  it('cannot ask over plain HTTP from another computer', async () => {
    servedSecurely(false);
    FakeNotification.permission = 'granted';
    expect(browserNotificationState()).toBe('unsupported');
    await expect(askForBrowserNotifications()).resolves.toBe('unsupported');
    expect(FakeNotification.requestPermission).not.toHaveBeenCalled();
    await notify('download_complete', 'Download complete', 'film.mkv');
    expect(FakeNotification.shown).toHaveLength(0);
  });

  it('asks the browser, and reports what it answered', async () => {
    FakeNotification.requestPermission.mockImplementationOnce(async () => 'granted');
    await expect(askForBrowserNotifications()).resolves.toBe('granted');
    expect(FakeNotification.requestPermission).toHaveBeenCalledTimes(1);
  });
});
