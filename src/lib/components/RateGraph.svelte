<script lang="ts">
  // Download and upload rate over time: the view eMule users open to see
  // whether the network is healthy, which a single "current rate" number
  // cannot answer. Drawn from the history the backend already keeps.
  import * as m from '$lib/paraglide/messages';
  import type { RateHistory } from '$lib/api/statistics';
  import { formatSpeed } from '$lib/utils';

  let { history }: { history: RateHistory | undefined } = $props();

  type Range = 'recent' | 'hour';
  let range = $state<Range>('recent');

  const WIDTH = 600;
  const HEIGHT = 140;

  const samples = $derived<[number, number][]>(
    range === 'recent' ? (history?.recent ?? []) : (history?.minutes ?? []),
  );
  /** Slots across the axis, so a short history sits at the right, as "now". */
  const slots = $derived(range === 'recent' ? 300 : 60);

  const peak = $derived(
    samples.reduce((max, [down, up]) => Math.max(max, down, up), 0),
  );
  /** At least 1 KiB/s, so an idle line sits on the floor instead of filling
   *  the chart with noise. */
  const scale = $derived(Math.max(peak, 1024));

  function points(which: 0 | 1): string {
    const offset = slots - samples.length;
    const step = WIDTH / Math.max(slots - 1, 1);
    return samples
      .map((sample, i) => {
        const x = (offset + i) * step;
        const y = HEIGHT - (sample[which] / scale) * HEIGHT;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  }

  const downLine = $derived(points(0));
  const upLine = $derived(points(1));
  const downArea = $derived.by(() => {
    if (samples.length === 0) return '';
    const step = WIDTH / Math.max(slots - 1, 1);
    const first = ((slots - samples.length) * step).toFixed(1);
    return `${first},${HEIGHT} ${downLine} ${WIDTH},${HEIGHT}`;
  });

  function average(which: 0 | 1): number {
    if (samples.length === 0) return 0;
    return samples.reduce((sum, sample) => sum + sample[which], 0) / samples.length;
  }

  const summary = $derived(
    m.stats_graph_aria({ down: formatSpeed(average(0)), up: formatSpeed(average(1)) }),
  );
</script>

<section class="rate-graph">
  <div class="card-head">
    <h3 class="card-title">{m.stats_graph_title()}</h3>
    <div class="range" role="group" aria-label={m.stats_graph_title()}>
      <button type="button" class:active={range === 'recent'} aria-pressed={range === 'recent'} onclick={() => (range = 'recent')}>
        {m.stats_graph_range_recent()}
      </button>
      <button type="button" class:active={range === 'hour'} aria-pressed={range === 'hour'} onclick={() => (range = 'hour')}>
        {m.stats_graph_range_hour()}
      </button>
    </div>
  </div>

  {#if samples.length < 2}
    <p class="empty">{range === 'hour' ? m.stats_graph_empty_hour() : m.stats_graph_empty()}</p>
  {:else}
    <div class="plot">
      <span class="peak">{formatSpeed(scale)}</span>
      <svg viewBox="0 0 {WIDTH} {HEIGHT}" preserveAspectRatio="none" role="img" aria-label={summary}>
        <line class="grid" x1="0" y1={HEIGHT / 2} x2={WIDTH} y2={HEIGHT / 2} />
        <polygon class="down-area" points={downArea} />
        <polyline class="down-line" points={downLine} />
        <polyline class="up-line" points={upLine} />
      </svg>
    </div>
    <div class="axis">
      <span>{range === 'recent' ? m.stats_graph_axis_recent() : m.stats_graph_axis_hour()}</span>
      <span class="legend">
        <span class="swatch down" aria-hidden="true"></span>{m.stats_download_rate()}
        <span class="swatch up" aria-hidden="true"></span>{m.stats_upload_rate()}
      </span>
      <span>{m.stats_graph_axis_now()}</span>
    </div>
  {/if}
</section>

<style>
  /* The Statistics page's card look; its own styles are scoped to the page. */
  .rate-graph {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 18px 20px;
    box-shadow: var(--shadow-sm);
  }

  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 12px;
  }

  .card-title {
    margin: 0;
    font-size: var(--font-size-md);
    font-weight: 600;
  }

  .range {
    display: inline-flex;
    gap: 4px;
  }

  .range button {
    padding: 3px 10px;
    font-size: var(--font-size-sm);
    font-weight: 500;
    border: 1px solid var(--border);
    border-radius: var(--radius-pill);
    background: transparent;
    color: var(--text-secondary);
  }

  .range button.active {
    background: var(--accent-dim);
    border-color: var(--accent);
    color: var(--text-primary);
  }

  .plot {
    position: relative;
    height: 140px;
  }

  .plot svg {
    width: 100%;
    height: 100%;
    display: block;
    overflow: visible;
  }

  .peak {
    position: absolute;
    top: 0;
    left: 0;
    font-size: var(--font-size-2xs);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .grid {
    stroke: var(--border);
    stroke-dasharray: 3 4;
    vector-effect: non-scaling-stroke;
  }

  .down-area {
    fill: color-mix(in srgb, var(--accent) 14%, transparent);
  }

  .down-line,
  .up-line {
    fill: none;
    stroke-width: 1.75;
    stroke-linejoin: round;
    vector-effect: non-scaling-stroke;
  }

  .down-line {
    stroke: var(--accent);
  }

  .up-line {
    stroke: var(--warning);
  }

  .axis {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    margin-top: 6px;
    font-size: var(--font-size-2xs);
    color: var(--text-muted);
  }

  .legend {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .swatch {
    width: 10px;
    height: 3px;
    border-radius: 2px;
    display: inline-block;
  }

  .swatch.down {
    background: var(--accent);
  }

  .swatch.up {
    background: var(--warning);
    margin-left: 8px;
  }

  .empty {
    margin: 0;
    padding: 28px 0;
    text-align: center;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }
</style>
