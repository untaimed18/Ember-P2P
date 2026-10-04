// "Offer to add copied eD2K links": when the window gains focus with links on
// the clipboard, a toast offers to open Add links with them in it.
//
// Read on focus only, never on a timer: copying a link in the browser and
// switching to Ember is the moment the offer is for, and a clipboard read
// while Ember is in the background would watch everything else the user copies.

import { get, writable } from 'svelte/store';
import { goto } from '$app/navigation';
import * as m from '$lib/paraglide/messages';
import { readClipboardText } from '$lib/api/system';
import { parseEd2kLinks } from '$lib/api/search';
import { appSettings } from '$lib/stores/settings';
import { addActionToast } from '$lib/stores/toast';
import { isOwnClipboardText } from '$lib/clipboardOwn';

/** Set when the Transfers page should open Add links, which fills itself
 *  from the clipboard. */
export const addLinksRequested = writable(false);

/** Focus and visibility both fire when the window comes back. */
const SETTLE_MS = 250;

let lastOffered: string | null = null;
let checking = false;

async function check(): Promise<void> {
  if (checking || !get(appSettings)?.watch_clipboard_links) return;
  checking = true;
  try {
    const text = (await readClipboardText())?.trim();
    // The same text is offered once, whatever the answer was.
    if (!text || text === lastOffered || isOwnClipboardText(text)) return;
    if (!/ed2k:\/\/\|file\|/i.test(text)) return;
    lastOffered = text;
    const batch = await parseEd2kLinks(text);
    if (batch.links.length === 0) return;
    addActionToast(
      'info',
      m.clipboard_links_found(),
      {
        label: m.clipboard_links_add(),
        run: () => {
          addLinksRequested.set(true);
          void goto('/transfers');
        },
      },
      () => {},
    );
  } catch (e: unknown) {
    console.warn('clipboard watch: could not read the clipboard', e);
  } finally {
    checking = false;
  }
}

/** Start watching. Returns the stop function. */
export function startClipboardWatch(): () => void {
  let timer: number | undefined;
  const schedule = () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => void check(), SETTLE_MS);
  };
  const onVisibility = () => {
    if (document.visibilityState === 'visible') schedule();
  };
  window.addEventListener('focus', schedule);
  document.addEventListener('visibilitychange', onVisibility);
  return () => {
    window.clearTimeout(timer);
    window.removeEventListener('focus', schedule);
    document.removeEventListener('visibilitychange', onVisibility);
  };
}
