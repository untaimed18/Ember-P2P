// Downloads waiting behind an Undo toast to be cancelled, by file hash.
//
// Starting one of them again (pasting its link, a search hit, a collection)
// takes it back instead: the row returns with its progress, rather than the
// start finding the hidden row "already queued" and the cancel then removing
// it a few seconds later.

const pending = new Map<string, () => Promise<void>>();

function key(hash: string): string {
  return hash.trim().toLowerCase();
}

export function holdPendingCancel(hash: string, takeBack: () => Promise<void>): void {
  pending.set(key(hash), takeBack);
}

/** Release `hash`, only while it still holds this `takeBack`: the same file
 *  cancelled again since is another toast's to release. */
export function releasePendingCancel(hash: string, takeBack: () => Promise<void>): void {
  if (pending.get(key(hash)) === takeBack) pending.delete(key(hash));
}

/** Take back every pending cancel among `hashes`. Never throws: the start that
 *  asked goes ahead either way. */
export async function takeBackPendingCancels(hashes: Iterable<string>): Promise<void> {
  const found: (() => Promise<void>)[] = [];
  for (const hash of hashes) {
    const takeBack = pending.get(key(hash));
    if (!takeBack) continue;
    pending.delete(key(hash));
    found.push(takeBack);
  }
  const results = await Promise.allSettled(found.map((fn) => fn()));
  for (const r of results) {
    if (r.status === 'rejected') console.warn('transfers: could not take back a pending cancel', r.reason);
  }
}
