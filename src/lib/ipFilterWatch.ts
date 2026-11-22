import * as m from '$lib/paraglide/messages';
import { downloadAndLoadIpfilter, getIpFilterStats, type IpFilterApplyResult } from '$lib/api/security';
import { getSettings } from '$lib/api/settings';
import { translateError } from '$lib/i18n';
import { setAppSettings } from '$lib/stores/settings';
import { addActionToast, removeToast, toast, toastError } from '$lib/stores/toast';

/** How often the filter is looked at, and how many looks in a row must find it
 *  on with no list before that is a failed load rather than one under way: a
 *  list loads in seconds at startup, and these come to a minute, as in the
 *  connection doctor. */
const WATCH_MS = 30_000;
const LOOKS_TO_WARN = 3;

/** What loading a list did, in words. */
export function ipFilterApplyMessage(result: IpFilterApplyResult): string {
  switch (result.outcome) {
    case 'applied':
      return m.security_ipfilter_applied({ entries: result.entryCount });
    case 'failed':
      return m.security_ipfilter_live_reload_failed({ entries: result.entryCount });
    default:
      return m.security_ipfilter_live_reload_deferred({ entries: result.entryCount });
  }
}

/** Download the default list and load it, then say how that went: the fix for
 *  a filter that is on with no list, and so blocks every peer. Resolves once
 *  it is over, failed or not. */
export async function downloadDefaultIpFilter(): Promise<void> {
  try {
    const result = await downloadAndLoadIpfilter();
    (result.outcome === 'failed' ? toastError : toast)(ipFilterApplyMessage(result));
  } catch (e) {
    toastError(translateError(e, m.error_operation_failed()));
    return;
  }
  try {
    setAppSettings(await getSettings());
  } catch {
    // The Settings page reads them again when it opens.
  }
}

/** While the IP filter is on with no list in place, say so wherever the user
 *  is, with the fix one click away: failing closed, it blocks every peer, and
 *  otherwise only the Security page said why nothing connected. Dismissed, it
 *  stays away until the filter has been fixed and fails again. For the main
 *  window. Returns the stop. */
export function startIpFilterWatch(): () => void {
  let stopped = false;
  let looks = 0;
  let toastId: number | null = null;
  let dismissed = false;
  /** The notice's download is under way: it comes back, if it must, once
   *  that is over, not while a large list is still downloading. */
  let fixing = false;

  const hide = () => {
    if (toastId === null) return;
    const id = toastId;
    toastId = null;
    removeToast(id);
  };

  const show = () => {
    if (toastId !== null || dismissed || fixing) return;
    toastId = addActionToast(
      'warning',
      m.ipfilter_watch_blocking(),
      {
        label: m.security_download_ipfilter(),
        run: () => {
          toastId = null;
          fixing = true;
          void downloadDefaultIpFilter().finally(() => {
            fixing = false;
            void look();
          });
        },
      },
      () => {
        if (toastId === null) return;
        toastId = null;
        dismissed = true;
      },
      0,
    );
  };

  async function look() {
    let blocking: boolean;
    try {
      // In the order the ranges are kept, so the page asked for costs no sort.
      const stats = await getIpFilterStats({ sort: 'range', sortAsc: true, limit: 1 });
      blocking = stats.enabled && !stats.ranges_ready;
    } catch {
      // The network task is busy or starting: the next look asks again.
      return;
    }
    if (stopped) return;
    looks = blocking ? looks + 1 : 0;
    if (looks >= LOOKS_TO_WARN) {
      show();
    } else if (!blocking) {
      hide();
      dismissed = false;
    }
  }

  const timer = setInterval(() => void look(), WATCH_MS);
  void look();
  return () => {
    stopped = true;
    clearInterval(timer);
    hide();
  };
}
