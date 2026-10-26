/**
 * Order two Library counts the Requests, Accepted and Transferred columns show
 * as "session (all time)": by the all-time total, then this session's.
 *
 * The all-time figure already includes the session, as eMule's `known.met`
 * counters do, so sorting by the session alone put nearly every file at 0
 * right after a restart. A file with no all-time record yet counts its session
 * figure as its total.
 */
export function compareAllTime(
  aSession: number,
  aAllTime: number,
  bSession: number,
  bAllTime: number,
): number {
  return Math.max(aAllTime, aSession) - Math.max(bAllTime, bSession) || aSession - bSession;
}
