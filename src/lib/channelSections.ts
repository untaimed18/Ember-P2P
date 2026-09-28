/** The two parts of the Channels directory, in the order they are drawn. */
export interface RoomSections<T> {
  yours: T[];
  discover: T[];
}

/**
 * Split an already-ranked room list into the rooms this device is in and the
 * ones it could join.
 *
 * Mixing the two let a small room the user actually belongs to sink beneath
 * strangers' large ones. Each part keeps the ranking it was handed, and
 * favourites lead "Your rooms" in that same order rather than in the order
 * they were starred, so pinning a room never reshuffles the others.
 */
export function sectionRooms<T extends { channel_id: string; in_room: boolean }>(
  ranked: readonly T[],
  favourites: readonly string[],
): RoomSections<T> {
  const pinned = new Set(favourites);
  const starred: T[] = [];
  const rest: T[] = [];
  const discover: T[] = [];
  for (const row of ranked) {
    if (!row.in_room) discover.push(row);
    else if (pinned.has(row.channel_id)) starred.push(row);
    else rest.push(row);
  }
  return { yours: [...starred, ...rest], discover };
}

interface RankableRoom {
  channel_id: string;
  name: string;
  in_room: boolean;
  member_count: number;
  roster_count: number;
}

/**
 * Largest rooms first, then by name, then by id so equal rooms hold still.
 *
 * A joined room is sized by its whole roster rather than by who is present:
 * the present count moves as people come and go, which reshuffled the list
 * under the pointer and made Alt+↑/↓ land somewhere new each time. A room
 * this device is not in has no roster here, so it takes the directory's
 * figure, falling back to the row's own when the directory had none.
 */
export function rankRooms<T extends RankableRoom>(
  rows: readonly T[],
  directoryCounts: ReadonlyMap<string, number | null>,
): T[] {
  const size = (row: T) =>
    row.in_room ? row.roster_count : directoryCounts.get(row.channel_id) ?? row.member_count;
  return rows
    .map((row) => ({ row, size: size(row) }))
    .sort(
      (a, b) =>
        b.size - a.size
        || a.row.name.localeCompare(b.row.name)
        || a.row.channel_id.localeCompare(b.row.channel_id),
    )
    .map(({ row }) => row);
}

/**
 * The row Enter in the room search opens.
 *
 * A row the user arrowed to wins. Without one, the first row stands in only
 * once something has been typed and only if it is a room the user is already
 * in: joining a public room is a choice, and the first Discover row is merely
 * whatever happened to rank highest.
 */
export function searchEnterTarget<T extends { in_room: boolean }>(
  rows: readonly T[],
  highlighted: T | null,
  query: string,
): T | null {
  if (highlighted) return highlighted;
  const first = rows[0];
  return query.trim() && first?.in_room ? first : null;
}

/** Where a highlight kept by room id sits in the rows as drawn now; -1 when
 *  nothing is highlighted or the room has left the list. */
export function highlightIndex<T extends { channel_id: string }>(
  rows: readonly T[],
  id: string | null,
): number {
  return id === null ? -1 : rows.findIndex((row) => row.channel_id === id);
}

/**
 * The next position in a wrapping cycle of `length` items.
 *
 * `current` outside the list means nothing is selected yet, so the first step
 * lands on whichever end the direction points away from.
 */
export function cycleIndex(current: number, length: number, step: 1 | -1): number {
  if (length <= 0) return -1;
  if (current < 0 || current >= length) return step > 0 ? 0 : length - 1;
  return (current + step + length) % length;
}
