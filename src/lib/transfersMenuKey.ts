/** Where the keyboard focus is when the menu key (or Shift+F10) is pressed on
 *  the Transfers page. */
export interface MenuKeyFocus {
  /** The download row that holds focus or the control focused inside it. */
  focusRowId: string | null;
  /** Focus is somewhere in the downloads table's pane. */
  inDownloadsTable: boolean;
  /** Focus is on nothing in particular (the page body), as after clicking a
   *  row, which takes no focus of its own. */
  onPage: boolean;
  /** The highlighted download, else the last one ticked, when it is listed. */
  currentId: string | null;
}

/** The download whose menu the key opens, or `null` to leave the key to the
 *  browser: focus is on some other control, or no row is highlighted. Never
 *  just the first row. */
export function menuKeyDownloadId(focus: MenuKeyFocus): string | null {
  if (focus.focusRowId) return focus.focusRowId;
  if (focus.inDownloadsTable || focus.onPage) return focus.currentId;
  return null;
}
