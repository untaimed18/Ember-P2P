import type { ServerInfo } from '$lib/types';

/** `EMULE_SUNRISE_*` in `network/ed2k/server_list.rs`. */
const EMULE_SUNRISE_IP = '176.123.5.89';
const EMULE_SUNRISE_PORT = 4725;
const EMULE_SUNRISE_NAME = 'eMule Sunrise';

/** The Servers page counts a server with this many failed attempts as failed. */
const FAILED_SERVER_FAILS = 3;

/** The server most likely to answer, for Connect with no row picked.
 *
 *  The last server logged in to (`get_last_server`) while it is still listed,
 *  then the High priority servers, then eMule Sunrise, then the other Normal
 *  ones; within each, fewest failures then most users. Low is never chosen
 *  for you. A server that has failed repeatedly is passed over while any
 *  other is left, and when none is, the one with the fewest failures then
 *  most users is offered rather than nothing. Startup auto-connect
 *  (`resolve_auto_connect_target`) has rules of its own. */
export function pickBestServer(
  servers: readonly ServerInfo[],
  last: { ip: string; port: number } | null = null,
): ServerInfo | null {
  const usable = (s: ServerInfo) => s.priority !== 'low' && s.fail_count < FAILED_SERVER_FAILS;
  const lastServer = last && servers.find((s) => s.ip === last.ip && s.port === last.port);
  if (lastServer && usable(lastServer)) return lastServer;
  const sunrise =
    servers.find((s) => s.ip === EMULE_SUNRISE_IP && s.port === EMULE_SUNRISE_PORT) ??
    servers.find((s) => s.name.toLowerCase() === EMULE_SUNRISE_NAME.toLowerCase());
  const rank = (s: ServerInfo) => (s.priority === 'high' ? 0 : s === sunrise ? 1 : 2);
  const likelier = (a: ServerInfo, b: ServerInfo) =>
    a.fail_count - b.fail_count || b.user_count - a.user_count;
  let best: ServerInfo | null = null;
  let leastFailed: ServerInfo | null = null;
  for (const s of servers) {
    if (s.priority === 'low') continue;
    if (!leastFailed || likelier(s, leastFailed) < 0) leastFailed = s;
    if (usable(s) && (!best || (rank(s) - rank(best) || likelier(s, best)) < 0)) best = s;
  }
  return best ?? leastFailed;
}
