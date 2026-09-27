/**
 * Translated stand-ins for the English sentences a few Tauri commands still
 * return on success. Only the numbers in those sentences are taken; everything
 * the user reads comes from the message catalog.
 */
import * as m from '$lib/paraglide/messages';
import { plural } from '$lib/plural';
import { formatNumber } from '$lib/utils';

/**
 * The integers in `text`, when it holds exactly `expected` of them.
 *
 * Demanding the exact count means a reworded reply that gains or loses a number
 * yields `null`, and so a count-free message, rather than numbers attached to
 * the wrong labels.
 */
export function countsIn(text: string, expected: number): number[] | null {
  const found = text.match(/\d+/g);
  if (!found || found.length !== expected) return null;
  return found.map(Number);
}

/**
 * `download_server_met` replies "Downloaded server.met: A added, U updated,
 * F filtered, D dropped at capacity"; the counts are read in that order.
 */
export function serverMetDownloadedText(reply: string): string {
  const counts = countsIn(reply, 4);
  if (!counts) return m.servers_met_updated();
  const [added, updated, filtered, dropped] = counts.map(formatNumber);
  return m.servers_met_downloaded({ added, updated, filtered, dropped });
}

/** `kad_bootstrap_url` replies "Loaded N contacts from nodes.dat". */
export function kadNodesLoadedText(reply: string): string {
  const counts = countsIn(reply, 1);
  if (!counts) return m.kad_bootstrap_url_loaded();
  const [count] = counts;
  return plural(count, {
    one: m.kad_bootstrap_url_loaded_one,
    other: () => m.kad_bootstrap_url_loaded_other({ count: formatNumber(count) }),
  });
}
