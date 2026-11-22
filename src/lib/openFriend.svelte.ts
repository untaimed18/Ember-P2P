import type { FriendInfo } from '$lib/api/friends';

/**
 * The friend a dialog is open for, kept as the friends list has them now: the
 * list's newer copy of them replaces the one the dialog was opened with, and
 * the dialog closes when they leave the list.
 *
 * Construct it while the component initialises: it sets up its own effect.
 */
export class OpenFriend {
  /** Held as the list's own object, which is what it is compared with:
   *  `$state` would wrap it in a proxy that is never that object, and each
   *  look at the list would put up another, without end. */
  current = $state.raw<FriendInfo | null>(null);

  constructor(list: () => FriendInfo[]) {
    $effect(() => {
      const open = this.current;
      if (!open) return;
      const fresh = list().find((f) => f.user_hash === open.user_hash);
      if (!fresh) this.current = null;
      else if (fresh !== open) this.current = fresh;
    });
  }
}
