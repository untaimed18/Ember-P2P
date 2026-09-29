import { untrack } from 'svelte';
import { computeRowWindow } from '$lib/rowWindow';

export type TableWindowOptions = {
  /** Lists this long or shorter render whole, so short lists keep their row
   *  animations and nothing about them changes. */
  minRows: number;
  /** Until a row has been measured. */
  rowHeight: number;
  /** Matches one rendered data row inside `body`, not a spacer or empty row. */
  rowSelector: string;
};

/**
 * Renders only the rows of a long table near its viewport, with a spacer row
 * above and below standing in for the rest — the search results' windowing,
 * for any table whose rows are all one height. The sticky header, the column
 * layout and every cell stay as they were.
 *
 * Construct it while the component initialises: it sets up its own effects,
 * listening for scrolls and size changes on `scroller` once that is bound.
 * The rule for which rows to render is `computeRowWindow`, which is tested.
 */
export class TableWindow {
  scroller = $state<HTMLElement | undefined>(undefined);
  body = $state<HTMLTableSectionElement | undefined>(undefined);
  #start = $state(0);
  #end = $state(0);
  #rowHeight = $state(0);
  #raf: number | null = null;
  readonly #total: () => number;
  readonly #minRows: number;
  readonly #rowSelector: string;

  constructor(total: () => number, options: TableWindowOptions) {
    this.#total = total;
    this.#minRows = options.minRows;
    this.#rowSelector = options.rowSelector;
    this.#rowHeight = options.rowHeight;
    this.#end = options.minRows;

    // The list, the row height or the elements changed; scrolls and resizes
    // come through `schedule` instead.
    $effect(() => {
      void this.#total();
      void this.#rowHeight;
      void this.scroller;
      void this.body;
      untrack(() => this.#update());
    });

    // Through the frame scheduler: a new window changes the content height,
    // which can bring a scrollbar in or out and so resize the scroller again.
    $effect(() => {
      const el = this.scroller;
      if (!el) return;
      const onScroll = () => this.schedule();
      el.addEventListener('scroll', onScroll, { passive: true });
      const ro = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(onScroll);
      ro?.observe(el);
      return () => {
        el.removeEventListener('scroll', onScroll);
        ro?.disconnect();
      };
    });

    // Measured from a rendered row, so font size, locale and zoom cannot put
    // the spacers out of step with the rows.
    $effect(() => {
      void this.start;
      void this.end;
      untrack(() => {
        const row = this.body?.querySelector<HTMLElement>(this.#rowSelector);
        const measured = row?.getBoundingClientRect().height ?? 0;
        if (measured > 0 && Math.abs(measured - this.#rowHeight) >= 0.5) this.#rowHeight = measured;
      });
    });

    $effect(() => () => {
      if (this.#raf !== null && typeof cancelAnimationFrame === 'function') cancelAnimationFrame(this.#raf);
      this.#raf = null;
    });
  }

  /** Whether the list is long enough to be windowed. */
  get active(): boolean {
    return this.#total() > this.#minRows;
  }

  /** Index of the first rendered row. */
  get start(): number {
    return this.active ? Math.min(this.#start, this.#total()) : 0;
  }

  /** One past the last rendered row. */
  get end(): number {
    const total = this.#total();
    return this.active ? Math.min(Math.max(this.#end, this.start), total) : total;
  }

  get topPad(): number {
    return this.start * this.#rowHeight;
  }

  get bottomPad(): number {
    return Math.max(0, this.#total() - this.end) * this.#rowHeight;
  }

  /** The rows of `list` to render. */
  slice<T>(list: readonly T[]): T[] {
    return list.slice(this.start, this.end);
  }

  /** Recompute on the next frame; several calls in one frame measure once. */
  schedule(): void {
    if (this.#raf !== null) return;
    if (typeof requestAnimationFrame !== 'function') {
      this.#update();
      return;
    }
    this.#raf = requestAnimationFrame(() => {
      this.#raf = null;
      this.#update();
    });
  }

  #update(): void {
    const total = this.#total();
    if (total <= this.#minRows) return;
    const scroller = this.scroller;
    const body = this.body;
    if (!scroller || !body || !body.isConnected) {
      this.#start = 0;
      this.#end = this.#minRows;
      return;
    }
    const { start, end } = computeRowWindow({
      total,
      bodyTop: body.getBoundingClientRect().top - scroller.getBoundingClientRect().top,
      viewportHeight: scroller.clientHeight,
      rowHeight: this.#rowHeight,
    });
    this.#start = start;
    this.#end = end;
  }
}
