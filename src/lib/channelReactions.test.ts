import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  CURATED_REACTIONS,
  QUICK_REACTIONS,
  REACTION_CURATED_MAX,
  REACTION_GRID_COLUMNS,
  coalesceRefresh,
  curatedReaction,
  formatReactors,
  gridMove,
  isCuratedReaction,
  mergeReactionTallies,
  resolvePickerPlacement,
  visibleReactors,
} from './channelReactions';
import {
  REACTION_DOWN,
  REACTION_HEART,
  REACTION_NONE,
  REACTION_UP,
  type ChannelReactionInfo,
} from './api/channels';

describe('curated reactions', () => {
  it('keeps the codes v1.6 draws on the marks it draws them as', () => {
    expect(curatedReaction(REACTION_UP)?.emoji).toBe('\u{1F44D}');
    expect(curatedReaction(REACTION_DOWN)?.emoji).toBe('\u{1F44E}');
    expect(curatedReaction(REACTION_HEART)?.emoji).toBe('\u{2764}\u{FE0F}');
  });

  it('numbers every code once, contiguously from 1, with a distinct emoji and a name', () => {
    const codes = CURATED_REACTIONS.map((r) => r.code);
    expect(codes).toEqual(Array.from({ length: REACTION_CURATED_MAX }, (_, i) => i + 1));
    expect(new Set(CURATED_REACTIONS.map((r) => r.emoji)).size).toBe(CURATED_REACTIONS.length);
    for (const reaction of CURATED_REACTIONS) {
      expect(reaction.label().length, `code ${reaction.code}`).toBeGreaterThan(0);
    }
  });

  it('matches the highest code the backend accepts and counts', () => {
    const rust = readFileSync(
      fileURLToPath(new URL('../../src-tauri/src/network/ember/channel.rs', import.meta.url)),
      'utf8',
    );
    const found = rust.match(/pub const REACTION_CURATED_MAX: u8 = (\d+);/);
    expect(found, 'REACTION_CURATED_MAX not found in channel.rs').not.toBeNull();
    expect(Number(found![1])).toBe(REACTION_CURATED_MAX);
  });

  it('draws nothing for a withdrawal or a code from a newer build', () => {
    expect(isCuratedReaction(REACTION_NONE)).toBe(false);
    expect(isCuratedReaction(REACTION_CURATED_MAX + 1)).toBe(false);
    expect(isCuratedReaction(255)).toBe(false);
    expect(curatedReaction(200)).toBeUndefined();
  });

  it('offers the three original reactions as quick picks', () => {
    expect([...QUICK_REACTIONS].sort()).toEqual([REACTION_UP, REACTION_DOWN, REACTION_HEART].sort());
    expect(CURATED_REACTIONS.length % REACTION_GRID_COLUMNS).toBe(0);
  });
});

describe('formatReactors', () => {
  const others = (n: number) => (n === 1 ? '1 other' : `${n} others`);
  const fmt = (names: string[], total: number, max?: number) =>
    formatReactors(names, total, { locale: 'en', others, max });

  it('names up to the limit', () => {
    expect(fmt(['Ada'], 1)).toBe('Ada');
    expect(fmt(['Ada', 'Bo'], 2)).toBe('Ada and Bo');
    expect(fmt(['Ada', 'Bo', 'Cy'], 3)).toBe('Ada, Bo, and Cy');
  });

  it('names a single leftover instead of writing "and 1 other"', () => {
    expect(fmt(['Ada', 'Bo', 'Cy', 'Di'], 4)).toBe('Ada, Bo, Cy, and Di');
  });

  it('sums the rest into "others"', () => {
    expect(fmt(['Ada', 'Bo', 'Cy', 'Di', 'Ed'], 5)).toBe('Ada, Bo, Cy, and 2 others');
  });

  it('counts from the total when the backend sent fewer names than reacted', () => {
    expect(fmt(['Ada', 'Bo'], 40)).toBe('Ada, Bo, and 38 others');
    expect(fmt(['You', 'Ada', 'Bo', 'Cy'], 4, 2)).toBe('You, Ada, and 2 others');
    expect(fmt(['Ada', 'Bo', 'Cy'], 4)).toBe('Ada, Bo, Cy, and 1 other');
  });

  it('follows the locale for the list itself', () => {
    expect(formatReactors(['Ada', 'Bo'], 2, { locale: 'de', others })).toBe('Ada und Bo');
  });

  it('is empty when nobody reacted', () => {
    expect(fmt([], 0)).toBe('');
  });

  it('gives the same answer from its cached formatter on a second call', () => {
    expect(formatReactors(['Ada', 'Bo'], 2, { locale: 'fr', others })).toBe('Ada et Bo');
    expect(formatReactors(['Ada', 'Bo'], 2, { locale: 'fr', others })).toBe('Ada et Bo');
  });
});

describe('visibleReactors', () => {
  const ADA = 'aa'.repeat(32);
  const BO = 'BB'.repeat(32);
  const CY = 'cc'.repeat(32);
  const others = (n: number) => (n === 1 ? '1 other' : `${n} others`);

  it('drops ignored members, whatever the case of their key', () => {
    expect(visibleReactors([ADA, BO, CY], new Set([BO.toLowerCase()]))).toEqual([ADA, CY]);
  });

  it('keeps everyone when nobody is ignored', () => {
    expect(visibleReactors([ADA, BO], new Set())).toEqual([ADA, BO]);
  });

  it('leaves an ignored reactor counted but unnamed', () => {
    const names = visibleReactors([ADA, BO], new Set([BO.toLowerCase()])).map((k) =>
      k === ADA ? 'Ada' : 'Bo',
    );
    expect(formatReactors(names, 2, { locale: 'en', others })).toBe('Ada and 1 other');
    expect(formatReactors([], 2, { locale: 'en', others })).toBe('2 others');
  });
});

describe('mergeReactionTallies', () => {
  const A = 'a'.repeat(32);
  const B = 'b'.repeat(32);
  const row = (msgId: string, count: number, mine = REACTION_NONE): ChannelReactionInfo => ({
    msg_id: msgId,
    reactions: [{ reaction: REACTION_UP, count, members: ['pk'] }],
    mine,
  });

  it('returns the previous map itself when nothing changed', () => {
    const prev = { [A]: row(A, 1), [B]: row(B, 2) };
    expect(mergeReactionTallies(prev, [row(A, 1), row(B, 2)])).toBe(prev);
  });

  it('keeps unchanged entries by identity and replaces changed ones', () => {
    const prev = { [A]: row(A, 1), [B]: row(B, 2) };
    const next = mergeReactionTallies(prev, [row(A, 1), row(B, 3)]);
    expect(next).not.toBe(prev);
    expect(next[A]).toBe(prev[A]);
    expect(next[B].reactions[0].count).toBe(3);
  });

  it('notices our own reaction changing even when the counts do not', () => {
    const prev = { [A]: row(A, 1) };
    const next = mergeReactionTallies(prev, [row(A, 1, REACTION_UP)]);
    expect(next[A].mine).toBe(REACTION_UP);
  });

  it('drops lines that no longer have any reaction', () => {
    const prev = { [A]: row(A, 1), [B]: row(B, 1) };
    const next = mergeReactionTallies(prev, [row(A, 1)]);
    expect(Object.keys(next)).toEqual([A]);
    expect(next[A]).toBe(prev[A]);
  });
});

describe('coalesceRefresh', () => {
  function deferredRuns() {
    const pending: Array<() => void> = [];
    let runs = 0;
    const run = () =>
      new Promise<void>((resolve) => {
        runs++;
        pending.push(resolve);
      });
    const settle = async () => {
      pending.shift()?.();
      // Let the chained `.then`s start the next run.
      for (let i = 0; i < 5; i++) await Promise.resolve();
    };
    return { run, settle, runs: () => runs, waiting: () => pending.length };
  }

  it('runs straight away when idle', async () => {
    const d = deferredRuns();
    const refresh = coalesceRefresh(d.run);
    const done = refresh();
    expect(d.runs()).toBe(1);
    await d.settle();
    await done;
  });

  it('folds a burst during a run into one trailing run', async () => {
    const d = deferredRuns();
    const refresh = coalesceRefresh(d.run);
    const first = refresh();
    const later = [refresh(), refresh(), refresh()];
    expect(d.runs()).toBe(1);
    expect(later[0]).toBe(later[2]);
    await d.settle();
    await first;
    expect(d.runs()).toBe(2);
    await d.settle();
    await Promise.all(later);
    expect(d.runs()).toBe(2);
    expect(d.waiting()).toBe(0);
  });

  it('never has two runs in flight', async () => {
    const d = deferredRuns();
    const refresh = coalesceRefresh(d.run);
    void refresh();
    void refresh();
    await d.settle();
    // The trailing run is in flight; a new request queues behind it.
    void refresh();
    expect(d.waiting()).toBe(1);
    await d.settle();
    expect(d.runs()).toBe(3);
    await d.settle();
    expect(d.waiting()).toBe(0);
  });

  it('carries on after a run that fails', async () => {
    let calls = 0;
    const refresh = coalesceRefresh(async () => {
      calls++;
      if (calls === 1) throw new Error('boom');
    });
    const failed = refresh();
    const trailing = refresh();
    await expect(failed).rejects.toThrow('boom');
    await trailing;
    expect(calls).toBe(2);
  });
});

describe('gridMove', () => {
  const cols = 5;
  const total = 20;

  it('moves by one horizontally and wraps at the ends', () => {
    expect(gridMove(0, 'ArrowRight', cols, total)).toBe(1);
    expect(gridMove(19, 'ArrowRight', cols, total)).toBe(0);
    expect(gridMove(0, 'ArrowLeft', cols, total)).toBe(19);
  });

  it('moves by a row vertically and wraps within the column', () => {
    expect(gridMove(2, 'ArrowDown', cols, total)).toBe(7);
    expect(gridMove(17, 'ArrowDown', cols, total)).toBe(2);
    expect(gridMove(2, 'ArrowUp', cols, total)).toBe(17);
    expect(gridMove(7, 'ArrowUp', cols, total)).toBe(2);
  });

  it('jumps to the ends on Home and End', () => {
    expect(gridMove(9, 'Home', cols, total)).toBe(0);
    expect(gridMove(9, 'End', cols, total)).toBe(19);
  });

  it('never strands focus in a short last row', () => {
    // 7 cells: a full row of 5, then 2.
    expect(gridMove(3, 'ArrowDown', cols, 7)).toBe(6);
    expect(gridMove(6, 'ArrowDown', cols, 7)).toBe(1);
    expect(gridMove(1, 'ArrowUp', cols, 7)).toBe(6);
    expect(gridMove(3, 'ArrowUp', cols, 7)).toBe(6);
  });

  it('leaves other keys to the browser', () => {
    expect(gridMove(0, 'Enter', cols, total)).toBeNull();
    expect(gridMove(0, 'a', cols, total)).toBeNull();
    expect(gridMove(0, 'ArrowDown', cols, 0)).toBeNull();
  });
});

describe('resolvePickerPlacement', () => {
  const box = { width: 180, height: 150 };
  const view = { width: 800, height: 600 };
  const at = (left: number, top: number) => ({ left, top, right: left + 24, bottom: top + 24 });

  it('opens below and start-aligned when there is room', () => {
    expect(resolvePickerPlacement(at(100, 100), box, view)).toEqual({ left: 100, top: 128, above: false });
  });

  it('flips above near the bottom edge', () => {
    const placed = resolvePickerPlacement(at(100, 560), box, view);
    expect(placed.above).toBe(true);
    expect(placed.top).toBe(560 - 4 - 150);
  });

  it('end-aligns near the right edge', () => {
    const placed = resolvePickerPlacement(at(760, 100), box, view);
    expect(placed.left).toBe(784 - 180);
    expect(placed.left + box.width).toBeLessThanOrEqual(view.width - 8);
  });

  it('stays on screen in a window smaller than the picker', () => {
    const placed = resolvePickerPlacement(at(10, 10), box, { width: 120, height: 100 });
    expect(placed.left).toBe(8);
    expect(placed.top).toBe(8);
  });
});
