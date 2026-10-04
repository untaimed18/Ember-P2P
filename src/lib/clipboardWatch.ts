// "Offer to add copied eD2K links": when the window gains focus with links on
// the clipboard, a toast offers to open Add links with them in it.
//
// Read on focus only, never on a timer: copying a link in the browser and
// switching to Ember is the moment the offer is for, and a clipboard read
// while Ember is in the background would watch everything else the user copies.

import { get, writable } from 'svelte/store';
import { goto } from '$app/navigation';
import { page } from '$app/stores';
import * as m from '$lib/paraglide/messages';
import { readClipboardText } from '$lib/api/system';
import { distinctLinks, parseEd2kLinks } from '$lib/api/search';
import { libraryHashesAmong } from '$lib/api/sharing';
import { appSettings } from '$lib/stores/settings';
import { transfers } from '$lib/stores/transfers';
import { addActionToast } from '$lib/stores/toast';
import { isOwnClipboardText } from '$lib/clipboardOwn';
import { plural } from '$lib/plural';

/** The links the Transfers page should open Add links with: the text that was
 *  offered, not whatever the clipboard holds by the time the page is up. */
export const addLinksRequested = writable<string | null>(null);

/** Focus and visibility both fire when the window comes back. */
const SETTLE_MS = 250;
/** As much as Add links accepts; a larger clipboard would open it empty. */
export const MAX_LINKS_TEXT_BYTES = 256 * 1024;

let lastOffered: string | null = null;
let checking = false;

/** How many of the clipboard's files are neither on the transfer list nor in
 *  the library: offering to add a file already there ends in "already listed". */
async function newFileCount(text: string): Promise<number> {
  const batch = await parseEd2kLinks(text);
  const hashes = distinctLinks(batch.links).map((link) => link.hash.toLowerCase());
  if (hashes.length === 0) return 0;
  const listed = new Set(get(transfers).map((t) => t.file_hash.toLowerCase()));
  const fresh = hashes.filter((hash) => !listed.has(hash));
  if (fresh.length === 0) return 0;
  try {
    const owned = await libraryHashesAmong(fresh);
    return fresh.filter((hash) => !owned.has(hash)).length;
  } catch (e) {
    console.warn('clipboard watch: could not check the library', e);
    return fresh.length;
  }
}

async function check(): Promise<void> {
  if (checking || !get(appSettings)?.watch_clipboard_links) return;
  checking = true;
  try {
    const text = (await readClipboardText())?.trim();
    // The same text is offered once, whatever the answer was.
    if (!text || text === lastOffered || isOwnClipboardText(text)) return;
    if (!/ed2k:\/\/\|file\|/i.test(text)) return;
    lastOffered = text;
    if (new TextEncoder().encode(text).length > MAX_LINKS_TEXT_BYTES) return;
    const count = await newFileCount(text);
    if (count === 0) return;
    addActionToast(
      'info',
      plural(count, {
        one: m.clipboard_links_found_one,
        other: () => m.clipboard_links_found_other({ count }),
      }),
      {
        label: m.clipboard_links_add(),
        run: () => {
          // Asked for only once Transfers is reached: a navigation the
          // unsaved-changes prompt held back must not leave the request to
          // open Add links the next time the page is visited.
          void goto('/transfers')
            .then(() => {
              if (get(page).url.pathname.startsWith('/transfers')) addLinksRequested.set(text);
            })
            .catch((e: unknown) => console.warn('clipboard watch: could not open Transfers', e));
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
