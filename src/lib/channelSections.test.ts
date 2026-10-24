import { describe, expect, it } from 'vitest';
import {
  cycleIndex,
  highlightIndex,
  rankRooms,
  searchEnterTarget,
  sectionRooms,
} from './channelSections';

const row = (channel_id: string, in_room: boolean) => ({ channel_id, in_room });

const ranked = (
  channel_id: string,
  in_room: boolean,
  sizes: { present?: number; roster?: number; name?: string } = {},
) => ({
  channel_id,
  in_room,
  name: sizes.name ?? channel_id,
  member_count: sizes.present ?? 0,
  roster_count: sizes.roster ?? 0,
});

describe('rankRooms', () => {
  it('sizes joined rooms by the whole roster, not who is present', () => {
    const rows = [
      ranked('busy-now', true, { present: 9, roster: 10 }),
      ranked('quiet-now', true, { present: 1, roster: 40 }),
    ];
    expect(rankRooms(rows, new Map()).map((r) => r.channel_id)).toEqual(['quiet-now', 'busy-now']);
  });

  it('holds its order as people come and go', () => {
    const before = [
      ranked('a', true, { present: 5, roster: 20 }),
      ranked('b', true, { present: 1, roster: 12 }),
    ];
    const after = [
      ranked('a', true, { present: 1, roster: 20 }),
      ranked('b', true, { present: 12, roster: 12 }),
    ];
    const order = (rows: typeof before) => rankRooms(rows, new Map()).map((r) => r.channel_id);
    expect(order(after)).toEqual(order(before));
  });

  it('sizes Discover rooms by the directory, falling back to the row', () => {
    const rows = [
      ranked('listed', false, { present: 0 }),
      ranked('unsized', false, { present: 3 }),
      ranked('mine', true, { present: 1, roster: 4 }),
    ];
    const counts = new Map<string, number | null>([
      ['listed', 7],
      ['unsized', null],
    ]);
    expect(rankRooms(rows, counts).map((r) => r.channel_id)).toEqual(['listed', 'mine', 'unsized']);
  });

  it('breaks ties by name, then by id', () => {
    const rows = [
      ranked('2', true, { roster: 3, name: 'Beta' }),
      ranked('9', true, { roster: 3, name: 'Alpha' }),
      ranked('1', true, { roster: 3, name: 'Alpha' }),
    ];
    expect(rankRooms(rows, new Map()).map((r) => r.channel_id)).toEqual(['1', '9', '2']);
  });
});

describe('searchEnterTarget', () => {
  const joined = row('joined', true);
  const publicRoom = row('public', false);

  it('opens whatever the user arrowed to, Discover rooms included', () => {
    expect(searchEnterTarget([joined, publicRoom], publicRoom, '')).toBe(publicRoom);
  });

  it('never joins a Discover room the user did not pick', () => {
    expect(searchEnterTarget([publicRoom, joined], null, 'pub')).toBeNull();
  });

  it('opens the first joined match only once something is typed', () => {
    expect(searchEnterTarget([joined, publicRoom], null, '')).toBeNull();
    expect(searchEnterTarget([joined, publicRoom], null, '   ')).toBeNull();
    expect(searchEnterTarget([joined, publicRoom], null, 'jo')).toBe(joined);
  });

  it('has nothing to open in an empty list', () => {
    expect(searchEnterTarget([], null, 'x')).toBeNull();
  });
});

describe('highlightIndex', () => {
  it('follows the room as the rows around it reorder', () => {
    const rows = [row('a', true), row('b', false), row('c', false)];
    expect(highlightIndex(rows, 'b')).toBe(1);
    const reordered = [row('c', false), row('new', false), row('a', true), row('b', false)];
    expect(highlightIndex(reordered, 'b')).toBe(3);
  });

  it('reports nothing for no highlight or a room that left the list', () => {
    expect(highlightIndex([row('a', true)], null)).toBe(-1);
    expect(highlightIndex([row('a', true)], 'gone')).toBe(-1);
  });
});

describe('sectionRooms', () => {
  it('splits joined rooms from Discover, keeping the ranking in each', () => {
    const ranked = [row('big', false), row('mine', true), row('mid', false), row('small', true)];
    const { yours, discover } = sectionRooms(ranked, []);
    expect(yours.map((r) => r.channel_id)).toEqual(['mine', 'small']);
    expect(discover.map((r) => r.channel_id)).toEqual(['big', 'mid']);
  });

  it('puts favourites first in ranked order, not starred order', () => {
    const ranked = [row('a', true), row('b', true), row('c', true), row('d', true)];
    const { yours } = sectionRooms(ranked, ['d', 'b']);
    expect(yours.map((r) => r.channel_id)).toEqual(['b', 'd', 'a', 'c']);
  });

  it('ignores a favourite for a room the user is not in', () => {
    const { yours, discover } = sectionRooms([row('a', false), row('b', true)], ['a']);
    expect(yours.map((r) => r.channel_id)).toEqual(['b']);
    expect(discover.map((r) => r.channel_id)).toEqual(['a']);
  });

  it('hands back empty sections for an empty list', () => {
    expect(sectionRooms([], ['a'])).toEqual({ yours: [], yoursPublic: [], yoursPrivate: [], discover: [] });
  });

  it('puts joined public rooms before joined private ones, favourites leading each', () => {
    const room = (channel_id: string, visibility: string) => ({ channel_id, in_room: true, visibility });
    const ranked = [room('p1', 'private'), room('a', 'public'), room('p2', 'private'), room('b', 'public')];
    const { yours, yoursPublic, yoursPrivate } = sectionRooms(ranked, ['p2', 'b']);
    expect(yoursPublic.map((r) => r.channel_id)).toEqual(['b', 'a']);
    expect(yoursPrivate.map((r) => r.channel_id)).toEqual(['p2', 'p1']);
    expect(yours.map((r) => r.channel_id), 'the order the list draws them').toEqual(['b', 'a', 'p2', 'p1']);
  });

  it('counts a room of unknown visibility as public', () => {
    const { yoursPublic, yoursPrivate } = sectionRooms([{ channel_id: 'x', in_room: true, visibility: 'later' }], []);
    expect(yoursPublic.map((r) => r.channel_id)).toEqual(['x']);
    expect(yoursPrivate).toEqual([]);
  });
});

describe('cycleIndex', () => {
  it('wraps both ways', () => {
    expect(cycleIndex(2, 3, 1)).toBe(0);
    expect(cycleIndex(0, 3, -1)).toBe(2);
    expect(cycleIndex(1, 3, 1)).toBe(2);
  });

  it('starts from the end the step points away from when nothing is selected', () => {
    expect(cycleIndex(-1, 4, 1)).toBe(0);
    expect(cycleIndex(-1, 4, -1)).toBe(3);
    expect(cycleIndex(9, 4, 1)).toBe(0);
  });

  it('has nowhere to go in an empty list', () => {
    expect(cycleIndex(0, 0, 1)).toBe(-1);
  });
});
