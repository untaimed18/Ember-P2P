import * as m from '$lib/paraglide/messages';
import type { StartDownloadResponse } from '$lib/types';

/** What to say of a download that was already in the list: where it is. A
 *  feed's is on the Feeds page, not in Transfers. */
export function alreadyQueuedText(res: Pick<StartDownloadResponse, 'in_feed'>, name?: string): string {
  if (res.in_feed) return name ? m.feeds_already_downloading_name({ name }) : m.feeds_already_downloading();
  return name ? m.search_already_queued_name({ name }) : m.search_already_in_queue();
}
