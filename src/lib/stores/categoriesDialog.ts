import { writable } from 'svelte/store';

/** Set by a page that offers "Edit categories…" but does not own the dialog
 *  (the Library); the Transfers page opens it on arrival and clears this. */
export const categoriesDialogRequested = writable(false);
