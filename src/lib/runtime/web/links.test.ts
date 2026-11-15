import { afterEach, describe, expect, it, vi } from 'vitest';
import { openInNewTab } from './links';

describe('opening a link from emberd', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('opens the tab during the click, and points it at web addresses only', async () => {
    const tab = { opener: {} as unknown, location: { replace: vi.fn() }, close: vi.fn() };
    const open = vi.fn(() => tab);
    vi.stubGlobal('window', { open });

    const opening = openInNewTab(Promise.resolve('https://www.emberp2p.org/'));
    expect(open).toHaveBeenCalledTimes(1);
    await opening;
    expect(tab.opener).toBeNull();
    expect(tab.location.replace).toHaveBeenCalledWith('https://www.emberp2p.org/');

    await expect(openInNewTab(Promise.resolve('javascript:alert(1)'))).rejects.toThrow();
    expect(tab.close).toHaveBeenCalledTimes(1);

    await expect(openInNewTab(Promise.reject('refused'))).rejects.toBe('refused');
    expect(tab.close).toHaveBeenCalledTimes(2);
    expect(tab.location.replace).toHaveBeenCalledTimes(1);
  });

  it('still opens the address when the browser blocked the early tab', async () => {
    const open = vi.fn<(url?: string, target?: string, features?: string) => null>(() => null);
    vi.stubGlobal('window', { open });
    await openInNewTab(Promise.resolve('http://example.test/'));
    expect(open).toHaveBeenLastCalledWith('http://example.test/', '_blank', 'noopener,noreferrer');
  });
});
