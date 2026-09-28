/**
 * The curated reactions a room offers, and the pure logic around drawing them.
 *
 * A reaction travels as a one-byte code, never as an emoji: the backend signs,
 * stores and counts codes (`REACTION_CURATED_MAX` in
 * `src-tauri/src/network/ember/channel.rs`) and this table is the only place a
 * code becomes a glyph. Codes are permanent once shipped — v1.6.x draws 1–3 and
 * counts everything else nowhere, so giving a number a different emoji would
 * show as the old mark on those builds. Append, never renumber.
 */
import * as m from '$lib/paraglide/messages';
import { getLocale } from '$lib/i18n';
import { plural } from '$lib/plural';
import {
  REACTION_DOWN,
  REACTION_HEART,
  REACTION_UP,
  type ChannelReactionInfo,
  type ChannelReactionTally,
} from '$lib/api/channels';

export interface CuratedReaction {
  code: number;
  emoji: string;
  /** Localized name, for aria-labels and tooltips. */
  label: () => string;
}

/** Every reaction this build can send and draw, in code order. */
export const CURATED_REACTIONS: readonly CuratedReaction[] = [
  { code: REACTION_UP, emoji: '\u{1F44D}', label: m.channels_reaction_up },
  { code: REACTION_DOWN, emoji: '\u{1F44E}', label: m.channels_reaction_down },
  { code: REACTION_HEART, emoji: '\u{2764}\u{FE0F}', label: m.channels_reaction_heart },
  { code: 4, emoji: '\u{1F602}', label: m.channels_reaction_laugh },
  { code: 5, emoji: '\u{1F62E}', label: m.channels_reaction_surprised },
  { code: 6, emoji: '\u{1F622}', label: m.channels_reaction_sad },
  { code: 7, emoji: '\u{1F621}', label: m.channels_reaction_angry },
  { code: 8, emoji: '\u{1F389}', label: m.channels_reaction_party },
  { code: 9, emoji: '\u{1F64F}', label: m.channels_reaction_pray },
  { code: 10, emoji: '\u{1F525}', label: m.channels_reaction_fire },
  { code: 11, emoji: '\u{1F440}', label: m.channels_reaction_eyes },
  { code: 12, emoji: '\u{2705}', label: m.channels_reaction_check },
  { code: 13, emoji: '\u{274C}', label: m.channels_reaction_cross },
  { code: 14, emoji: '\u{1F4AF}', label: m.channels_reaction_hundred },
  { code: 15, emoji: '\u{1F914}', label: m.channels_reaction_thinking },
  { code: 16, emoji: '\u{1F44F}', label: m.channels_reaction_clap },
  { code: 17, emoji: '\u{1F680}', label: m.channels_reaction_rocket },
  { code: 18, emoji: '\u{2B50}', label: m.channels_reaction_star },
  { code: 19, emoji: '\u{1F60A}', label: m.channels_reaction_smile },
  { code: 20, emoji: '\u{1F44B}', label: m.channels_reaction_wave },
];

/** Must equal the backend's `REACTION_CURATED_MAX`; a test pins the two. */
export const REACTION_CURATED_MAX = 20;

/** Offered on hover without opening the picker: the three rooms always had. */
export const QUICK_REACTIONS: readonly number[] = [REACTION_HEART, REACTION_UP, REACTION_DOWN];

/** Columns in the picker grid. Arrow keys move by this much vertically. */
export const REACTION_GRID_COLUMNS = 5;

const BY_CODE = new Map(CURATED_REACTIONS.map((r) => [r.code, r]));

export function curatedReaction(code: number): CuratedReaction | undefined {
  return BY_CODE.get(code);
}

export function isCuratedReaction(code: number): boolean {
  return BY_CODE.has(code);
}

/** Names listed before the rest are summed into "and N others". */
export const REACTORS_NAMED_MAX = 3;

/**
 * "Ada", "Ada and Bo", "Ada, Bo and Cy", "Ada, Bo, Cy and 3 others".
 *
 * `names` may be shorter than `total` — the backend sends only the first few
 * keys per chip — so the remainder is counted from `total`, not from `names`.
 * A single leftover is named when we have the name, since "and 1 other" is
 * longer than the name it hides.
 */
export function formatReactors(
  names: readonly string[],
  total: number,
  options: {
    max?: number;
    locale?: string;
    others?: (count: number) => string;
  } = {},
): string {
  const max = options.max ?? REACTORS_NAMED_MAX;
  const others =
    options.others ??
    ((count: number) =>
      plural(count, {
        one: m.channels_reactors_others_one,
        other: () => m.channels_reactors_others_other({ count }),
      }));
  const count = Math.max(total, names.length);
  const limit = count <= max + 1 ? max + 1 : max;
  const named = names.slice(0, limit);
  const rest = count - named.length;
  const parts = rest > 0 ? [...named, others(rest)] : named;
  if (parts.length === 0) return '';
  return listFormat(options.locale ?? getLocale()).format(parts);
}

/** One formatter per locale: every chip label on every row asks for one. */
const listFormats = new Map<string, Intl.ListFormat>();

function listFormat(locale: string): Intl.ListFormat {
  let format = listFormats.get(locale);
  if (!format) {
    format = new Intl.ListFormat(locale, { style: 'long', type: 'conjunction' });
    listFormats.set(locale, format);
  }
  return format;
}

/**
 * The reactor keys worth naming: everyone but members this device ignores.
 * Only the names go — the chip's count still includes them, so the label sums
 * them into "and N others" rather than pretending they did not react.
 */
export function visibleReactors(members: readonly string[], ignored: ReadonlySet<string>): string[] {
  if (ignored.size === 0) return [...members];
  return members.filter((key) => !ignored.has(key.toLowerCase()));
}

function sameTally(a: ChannelReactionTally, b: ChannelReactionTally): boolean {
  if (a.reaction !== b.reaction || a.count !== b.count) return false;
  if (a.members.length !== b.members.length) return false;
  return a.members.every((key, i) => key === b.members[i]);
}

function sameReactions(a: ChannelReactionInfo, b: ChannelReactionInfo): boolean {
  if (a.mine !== b.mine || a.reactions.length !== b.reactions.length) return false;
  return a.reactions.every((tally, i) => sameTally(tally, b.reactions[i]));
}

/**
 * A fresh read of a room's tallies, keyed by wire id, reusing every entry of
 * `prev` that did not change — and `prev` itself when nothing did. Each row
 * draws from its own entry, so an unchanged object is a row that has nothing
 * to redraw when one line elsewhere gains a reaction.
 */
export function mergeReactionTallies(
  prev: Readonly<Record<string, ChannelReactionInfo>>,
  rows: readonly ChannelReactionInfo[],
): Record<string, ChannelReactionInfo> {
  const next: Record<string, ChannelReactionInfo> = {};
  let changed = Object.keys(prev).length !== rows.length;
  for (const row of rows) {
    const old = prev[row.msg_id];
    if (old && sameReactions(old, row)) {
      next[row.msg_id] = old;
    } else {
      next[row.msg_id] = row;
      changed = true;
    }
  }
  return changed ? next : (prev as Record<string, ChannelReactionInfo>);
}

/**
 * `run`, at most one at a time: a request made while one is in flight is
 * folded with every other such request into a single run after it. A burst of
 * nudges then costs two reads, not one each, and the reads cannot overtake one
 * another. The promise settles once a run that began after the request is done.
 */
export function coalesceRefresh(run: () => Promise<void>): () => Promise<void> {
  let running: Promise<void> | null = null;
  let queued: Promise<void> | null = null;
  const launch = (): Promise<void> => {
    const current = (async () => {
      try {
        await run();
      } finally {
        running = null;
      }
    })();
    running = current;
    return current;
  };
  return () => {
    if (queued) return queued;
    if (!running) return launch();
    queued = running
      .catch(() => {})
      .then(() => {
        queued = null;
        return launch();
      });
    return queued;
  };
}

/**
 * Where an arrow key moves focus in a grid of `total` cells laid out
 * `columns` wide, or null for keys the grid does not handle. Wraps at every
 * edge so no key is ever a dead end; a column missing from a short last row
 * lands on the last cell instead.
 */
export function gridMove(index: number, key: string, columns: number, total: number): number | null {
  if (total <= 0) return null;
  const last = total - 1;
  switch (key) {
    case 'ArrowRight':
      return index >= last ? 0 : index + 1;
    case 'ArrowLeft':
      return index <= 0 ? last : index - 1;
    case 'ArrowDown': {
      const next = index + columns;
      if (next <= last) return next;
      const column = index % columns;
      // Past the bottom of a short last row still means "down": finish on the
      // last cell before wrapping to the top of the column.
      return index < last && Math.floor(index / columns) < Math.floor(last / columns)
        ? last
        : column;
    }
    case 'ArrowUp': {
      const next = index - columns;
      if (next >= 0) return next;
      const column = index % columns;
      const bottom = Math.floor(last / columns) * columns + column;
      return bottom <= last ? bottom : last;
    }
    case 'Home':
      return 0;
    case 'End':
      return last;
    default:
      return null;
  }
}

export interface AnchorRect {
  top: number;
  bottom: number;
  left: number;
  right: number;
}

export interface PickerPlacement {
  left: number;
  top: number;
  /** Opened above the trigger because there was no room below. */
  above: boolean;
}

/**
 * Where to put a `position: fixed` picker of size `box` next to its trigger.
 *
 * Below and start-aligned by default; flipped above when it would run off the
 * bottom and there is more room up there; end-aligned when it would run off
 * the right. Clamped to `margin` as a last resort, so a window smaller than
 * the picker still shows its top-left rather than nothing.
 */
export function resolvePickerPlacement(
  anchor: AnchorRect,
  box: { width: number; height: number },
  view: { width: number; height: number },
  gap = 4,
  margin = 8,
): PickerPlacement {
  let left = anchor.left;
  if (left + box.width > view.width - margin) left = anchor.right - box.width;
  left = Math.min(Math.max(margin, left), Math.max(margin, view.width - box.width - margin));

  const below = anchor.bottom + gap;
  const roomBelow = view.height - margin - below;
  const roomAbove = anchor.top - gap - margin;
  const above = box.height > roomBelow && roomAbove > roomBelow;
  let top = above ? anchor.top - gap - box.height : below;
  top = Math.min(Math.max(margin, top), Math.max(margin, view.height - box.height - margin));
  return { left, top, above };
}
