import { describe, expect, it } from 'vitest';
import { render } from 'svelte/server';
import RoomLibraryBrowser from './RoomLibraryBrowser.svelte';
import RoomLibrarySettingsDialog from './RoomLibrarySettingsDialog.svelte';

const text = (body: string) => body.replace(/<!--[^>]*-->/g, '').replace(/ class="svelte-[\w-]+"/g, '');

describe('room library dialogs', () => {
  it('draw nothing while closed', () => {
    const browser = render(RoomLibraryBrowser, {
      props: { open: false, channelId: 'ab', memberPubkey: 'cd', memberName: 'Ann' },
    });
    const settings = render(RoomLibrarySettingsDialog, { props: { open: false, channelId: 'ab' } });
    expect(text(browser.body)).not.toContain('role="dialog"');
    expect(text(settings.body)).not.toContain('role="dialog"');
  });

  it('open on a named dialog that is loading', () => {
    const browser = text(
      render(RoomLibraryBrowser, {
        props: { open: true, channelId: 'ab', memberPubkey: 'cd', memberName: 'Ann <b>' },
      }).body,
    );
    expect(browser).toContain('role="dialog"');
    expect(browser).toContain('Ann &lt;b>');
    expect(browser).not.toContain('<b>');
    expect(browser).toContain('type="search"');

    const settings = text(render(RoomLibrarySettingsDialog, { props: { open: true, channelId: 'ab' } }).body);
    expect(settings).toContain('role="dialog"');
    expect(settings).toContain('aria-labelledby="room-library-title"');
  });
});
