<script lang="ts">
  import { getStatistics, type TransferStats } from '$lib/api/statistics';
  import { getReputationStats, type ReputationStatsInfo } from '$lib/api/reputation';
  import { formatBytes, formatSpeed as formatRate, formatDurationSecs as formatDuration } from '$lib/utils';
  import { onMount } from 'svelte';
  import * as m from '$lib/paraglide/messages';

  let stats = $state<TransferStats | null>(null);
  let loading = $state(true);
  let error: string | null = $state(null);
  let refreshInterval: ReturnType<typeof setInterval> | null = null;
  let refreshBusy = false;
  let tickCounter = $state(0);
  let unmounted = false;

  // Reputation-tracker snapshot. Loaded alongside stats on the same
  // 2-second cadence. `null` before the first successful fetch so the
  // UI can render a "—" placeholder instead of zeros (zeros are
  // misleading when the backend is briefly unreachable).
  let repStats = $state<ReputationStatsInfo | null>(null);

  async function loadStats() {
    if (refreshBusy || unmounted) return;
    refreshBusy = true;
    try {
      // Fire both fetches concurrently — they hit different backend
      // paths (stats reads a cached snapshot; reputation reads the
      // in-memory tracker) so there's no reason to serialise. If
      // reputation fails we still surface transfer stats; the inverse
      // is protected by the existing error path.
      const [result, repResult] = await Promise.all([
        Promise.race([
          getStatistics(),
          new Promise<TransferStats>((_, reject) => setTimeout(() => reject(new Error('timeout')), 4000)),
        ]),
        getReputationStats().catch(() => null as ReputationStatsInfo | null),
      ]);
      if (unmounted) return;
      stats = result;
      if (repResult) repStats = repResult;
      error = null;
    } catch (e) {
      if (unmounted) return;
      error = e instanceof Error ? e.message : String(e);
    } finally {
      if (!unmounted) loading = false;
      refreshBusy = false;
    }
  }

  let tickInterval: ReturnType<typeof setInterval> | null = null;

  onMount(() => {
    loadStats();
    refreshInterval = setInterval(loadStats, 2000);
    tickInterval = setInterval(() => tickCounter++, 1000);
    return () => {
      unmounted = true;
      if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = null; }
      if (tickInterval) { clearInterval(tickInterval); tickInterval = null; }
    };
  });

  let sessionTime = $derived.by(() => {
    void tickCounter;
    if (!stats || !stats.session_start_time) return 0;
    return Math.floor(Date.now() / 1000 - stats.session_start_time);
  });

  let cumConnTime = $derived(
    stats ? stats.cum_conn_time + sessionTime : 0
  );

  // cum_ values are loaded from DB at startup and exclude the current session, so adding session_ is correct
  let totalDown = $derived(stats ? stats.cum_downloaded + stats.session_downloaded : 0);
  let totalUp = $derived(stats ? stats.cum_uploaded + stats.session_uploaded : 0);

  let ratio = $derived.by(() => {
    if (!totalDown) return null;
    return totalUp / totalDown;
  });

  let ratioLabel = $derived.by(() => {
    if (ratio === null) return '\u2014';
    if (ratio >= 100) return ratio.toFixed(0);
    if (ratio >= 10) return ratio.toFixed(1);
    return ratio.toFixed(2);
  });

  let totalOverhead = $derived(
    stats
      ? stats.overhead_server + stats.overhead_kad + stats.overhead_source_exchange + stats.overhead_file_request
      : 0
  );

  function overheadPct(part: number): number {
    if (!totalOverhead) return 0;
    return (part / totalOverhead) * 100;
  }

  // Render overhead rows in descending size so the biggest contributor
  // sits at the top. Zero-byte categories used to be filtered out
  // entirely, but that hid Source Exchange from anyone running on KAD/
  // Ember without an active eD2K server connection (the SX counter is
  // only fed by server-based source asking, not the actual peer-to-peer
  // traffic — see backend `OverheadCategory::SourceExchange` sites).
  // Showing all four categories at all times tells the user which
  // pathway is contributing to overhead and which is silent.
  type OverheadRow = { key: string; label: string; value: number; cls: string };
  let overheadRows = $derived.by<OverheadRow[]>(() => {
    if (!stats) return [];
    const rows: OverheadRow[] = [
      { key: 'server', label: m.stats_overhead_server(), value: stats.overhead_server, cls: 'oh-server' },
      { key: 'kad', label: m.stats_overhead_kad(), value: stats.overhead_kad, cls: 'oh-kad' },
      { key: 'srcex', label: m.stats_overhead_source_exchange(), value: stats.overhead_source_exchange, cls: 'oh-srcex' },
      { key: 'freq', label: m.stats_overhead_file_requests(), value: stats.overhead_file_request, cls: 'oh-freq' },
    ];
    return rows.sort((a, b) => b.value - a.value);
  });

  // Friendly "Apr 18, 2026" rendering for the cumulative-since label.
  // Returns an em-dash if we don't have a reset timestamp yet (fresh
  // install before the first session ends).
  function formatSinceDate(ts: number): string {
    if (!ts) return '\u2014';
    return new Date(ts * 1000).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  }

  function formatSessionTime(secs: number): string {
    if (secs <= 0) return '0s';
    const h = Math.floor(secs / 3600);
    const min = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    if (h > 0) return `${h}h ${String(min).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
    if (min > 0) return `${min}m ${String(s).padStart(2, '0')}s`;
    return `${s}s`;
  }
</script>

<div class="page-header">
  <h2>{m.stats_title()}</h2>
</div>

<div class="page-content">
  {#if loading}
    <div class="empty-state">
      <div class="spinner lg"></div>
      <p>{m.stats_loading()}</p>
    </div>
  {:else if error}
    <div class="empty-state">
      <p style="color: var(--danger)">{error}</p>
      <button onclick={loadStats}>{m.common_retry()}</button>
    </div>
  {:else if stats}

    <!-- Hero cards -->
    <div class="hero-row">
      <div class="hero-card">
        <div class="hero-icon down-icon" aria-hidden="true">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <line x1="10" y1="3" x2="10" y2="15"/>
            <polyline points="5,10 10,15 15,10"/>
          </svg>
        </div>
        <div class="hero-body">
          <span class="hero-value">{formatRate(stats.session_down_rate)}</span>
          <span class="hero-label">{m.stats_download_rate()}</span>
        </div>
      </div>
      <div class="hero-card">
        <div class="hero-icon up-icon" aria-hidden="true">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <line x1="10" y1="17" x2="10" y2="5"/>
            <polyline points="5,10 10,5 15,10"/>
          </svg>
        </div>
        <div class="hero-body">
          <span class="hero-value">{formatRate(stats.session_up_rate)}</span>
          <span class="hero-label">{m.stats_upload_rate()}</span>
        </div>
      </div>
      <div class="hero-card">
        <div class="hero-icon time-icon" aria-hidden="true">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="10" cy="11" r="6.5"/>
            <line x1="10" y1="11" x2="10" y2="7"/>
            <line x1="10" y1="11" x2="13" y2="11"/>
            <line x1="8" y1="2.5" x2="12" y2="2.5"/>
          </svg>
        </div>
        <div class="hero-body">
          <span class="hero-value">{formatSessionTime(sessionTime)}</span>
          <span class="hero-label">{m.stats_session_time()}</span>
        </div>
      </div>
      <div class="hero-card">
        <div class="hero-icon ratio-icon" aria-hidden="true">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <line x1="6" y1="3.5" x2="6" y2="15"/>
            <polyline points="3.5,6 6,3.5 8.5,6"/>
            <line x1="14" y1="16.5" x2="14" y2="5"/>
            <polyline points="11.5,14 14,16.5 16.5,14"/>
          </svg>
        </div>
        <div class="hero-body">
          <span class="hero-value" class:ratio-good={ratio !== null && ratio >= 1} class:ratio-low={ratio !== null && ratio < 1}>{ratioLabel}</span>
          <span class="hero-label">{m.stats_upload_ratio()}</span>
        </div>
      </div>
    </div>

    <!-- Transfer summary -->
    <div class="section-row">
      <section class="card transfer-card">
        <div class="card-head">
          <span class="section-icon" aria-hidden="true">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <line x1="8" y1="2.5" x2="8" y2="11"/>
              <polyline points="4.5,7.5 8,11 11.5,7.5"/>
              <line x1="3" y1="13.5" x2="13" y2="13.5"/>
            </svg>
          </span>
          <h3>{m.stats_session_downloads()}</h3>
        </div>
        <div class="transfer-grid">
          <div class="big-stat">
            <span class="big-value down-color">{formatBytes(stats.session_downloaded)}</span>
            <span class="big-sub">{m.stats_transferred()}</span>
          </div>
          <div class="big-stat">
            <span class="big-value">{stats.session_completed_down}</span>
            <span class="big-sub">{m.stats_completed()}</span>
          </div>
        </div>
      </section>

      <section class="card transfer-card">
        <div class="card-head">
          <span class="section-icon" aria-hidden="true">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <line x1="8" y1="13.5" x2="8" y2="5"/>
              <polyline points="4.5,8.5 8,5 11.5,8.5"/>
              <line x1="3" y1="2.5" x2="13" y2="2.5"/>
            </svg>
          </span>
          <h3>{m.stats_session_uploads()}</h3>
        </div>
        <div class="transfer-grid">
          <div class="big-stat">
            <span class="big-value up-color">{formatBytes(stats.session_uploaded)}</span>
            <span class="big-sub">{m.stats_transferred()}</span>
          </div>
          <div class="big-stat">
            <span class="big-value">{stats.session_completed_up}</span>
            <span class="big-sub">{m.stats_completed()}</span>
          </div>
        </div>
      </section>
    </div>

    <!-- Cumulative -->
    <section class="card">
      <div class="card-head">
        <span class="section-icon" aria-hidden="true">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3,3 13,3 8,8 13,13 3,13"/>
          </svg>
        </span>
        <h3>{m.stats_all_time_totals()}</h3>
        {#if stats.stat_last_reset}
          <span
            class="head-aside"
            title={m.stats_cumulative_started_on({ when: new Date(stats.stat_last_reset * 1000).toLocaleString() })}
          >{m.stats_since({ date: formatSinceDate(stats.stat_last_reset) })}</span>
        {/if}
      </div>
      <div class="cum-grid">
        <div class="cum-item">
          <span class="cum-label">{m.stats_total_downloaded()}</span>
          <span class="cum-value down-color">{formatBytes(totalDown)}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">{m.stats_total_uploaded()}</span>
          <span class="cum-value up-color">{formatBytes(totalUp)}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">{m.stats_total_connection_time()}</span>
          <span class="cum-value">{formatDuration(cumConnTime)}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">{m.stats_completed_downloads()}</span>
          <!-- cum_ excludes current session (DB snapshot at startup), so addition is intentional -->
          <span class="cum-value">{stats.cum_completed_down + stats.session_completed_down}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">{m.stats_completed_uploads()}</span>
          <span class="cum-value">{stats.cum_completed_up + stats.session_completed_up}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">{m.stats_upload_download_ratio()}</span>
          <span class="cum-value" class:ratio-good={ratio !== null && ratio >= 1} class:ratio-low={ratio !== null && ratio < 1}>{ratioLabel}</span>
        </div>
      </div>
    </section>

    <!-- Overhead -->
    <section class="card">
      <div class="card-head">
        <span class="section-icon" aria-hidden="true">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="9,1.5 4,9 8,9 7,14.5 12,7 8,7"/>
          </svg>
        </span>
        <h3>{m.stats_protocol_overhead()}</h3>
        <span class="head-aside">{m.stats_overhead_total({ bytes: formatBytes(totalOverhead) })}</span>
      </div>

      <div class="overhead-bars">
        {#each overheadRows as row (row.key)}
          <div class="oh-row">
            <span class="oh-label">{row.label}</span>
            <div class="oh-track">
              <div class="oh-fill {row.cls}" style="width: {overheadPct(row.value)}%"></div>
            </div>
            <span class="oh-value">{formatBytes(row.value)}</span>
          </div>
        {/each}
        {#if totalOverhead === 0}
          <p class="oh-empty">{m.stats_no_overhead()}</p>
        {/if}
      </div>

      <div class="overhead-session-row">
        <span class="oh-label">{m.stats_session_down_overhead()}</span>
        <span class="oh-value">{formatBytes(stats.session_down_overhead)}</span>
        <span class="oh-label">{m.stats_session_up_overhead()}</span>
        <span class="oh-value">{formatBytes(stats.session_up_overhead)}</span>
      </div>
    </section>

    <!--
      Peer reputation snapshot. Surfaces the in-memory
      `ReputationTracker` state: how many peers we have behavioural
      records for, and how many are currently banned. Banned count
      coloured to draw attention — a non-zero value means the tracker
      is actively filtering out misbehaving peers on this session.
      Rendered only when we've had at least one successful fetch
      (`repStats != null`) so a transient backend hiccup doesn't make
      the row flash zeros and scare the user.
    -->
    {#if repStats}
      <section class="card">
        <div class="card-head">
          <span class="section-icon" aria-hidden="true">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M8 1.5 L2 4 V8 Q2 12.5 8 14.5 Q14 12.5 14 8 V4 Z"/>
              <polyline points="5.5,8 7.5,10 10.5,6"/>
            </svg>
          </span>
          <h3>{m.stats_peer_reputation()}</h3>
          <span class="head-aside">{m.stats_session_tracker()}</span>
        </div>
        <div class="reputation-row">
          <div class="rep-stat">
            <span class="rep-label">{m.stats_tracked_peers()}</span>
            <span class="rep-value">{repStats.tracked_peers.toLocaleString()}</span>
          </div>
          <div class="rep-stat">
            <span class="rep-label">{m.stats_banned_peers()}</span>
            <span class="rep-value" class:rep-danger={repStats.banned_peers > 0}>
              {repStats.banned_peers.toLocaleString()}
            </span>
          </div>
        </div>
      </section>
    {/if}

  {/if}
</div>

<style>
  .page-content {
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  /* ---- Hero row ---- */
  .hero-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
  }
  @media (max-width: 900px) {
    .hero-row { grid-template-columns: repeat(2, 1fr); }
  }
  .hero-card {
    display: flex;
    align-items: center;
    gap: 14px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 16px 18px;
    box-shadow: var(--shadow-sm);
    transition: box-shadow var(--transition-normal);
  }
  .hero-card:hover { box-shadow: var(--shadow-md); }
  .hero-icon {
    width: 42px;
    height: 42px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .hero-icon :global(svg) {
    width: 22px;
    height: 22px;
  }
  .down-icon  { background: color-mix(in srgb, var(--accent)  14%, transparent); color: var(--accent); }
  .up-icon    { background: color-mix(in srgb, var(--success) 14%, transparent); color: var(--success); }
  .time-icon  { background: color-mix(in srgb, var(--warning) 14%, transparent); color: var(--warning); }
  .ratio-icon { background: rgba(156, 39, 176, 0.12); color: #9c27b0; }
  :global([data-theme="dark"]) .ratio-icon { background: rgba(186, 104, 200, 0.18); color: #c792d9; }
  .hero-body { display: flex; flex-direction: column; min-width: 0; }
  .hero-value {
    font-size: 1.25rem;
    font-weight: 700;
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  .hero-label {
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-top: 1px;
  }

  /* ---- Section cards ---- */
  .card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 18px 20px;
    box-shadow: var(--shadow-sm);
  }
  .card-head {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 14px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }
  .card-head h3 {
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0;
  }
  .section-icon {
    display: inline-flex;
    align-items: center;
    color: var(--text-secondary);
    opacity: 0.7;
  }
  .section-icon :global(svg) {
    width: 16px;
    height: 16px;
  }
  .head-aside {
    margin-left: auto;
    font-size: 0.8rem;
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  /* ---- Section row (side-by-side) ---- */
  .section-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }
  @media (max-width: 700px) {
    .section-row { grid-template-columns: 1fr; }
  }

  /* ---- Transfer cards ---- */
  .transfer-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }
  .big-stat { display: flex; flex-direction: column; align-items: center; }
  .big-value {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
  }
  .big-sub {
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-top: 2px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .down-color { color: var(--accent); }
  .up-color   { color: var(--success); }

  /* ---- Cumulative grid ---- */
  .cum-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 18px 24px;
  }
  @media (max-width: 800px) {
    .cum-grid { grid-template-columns: repeat(2, 1fr); }
  }
  .cum-item { display: flex; flex-direction: column; }
  .cum-label {
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-bottom: 4px;
  }
  .cum-value {
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
  }

  .ratio-good { color: var(--success); }
  .ratio-low  { color: var(--warning); }

  /* ---- Overhead bars ---- */
  .overhead-bars {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .oh-row {
    display: grid;
    grid-template-columns: 120px 1fr 90px;
    align-items: center;
    gap: 10px;
  }
  .oh-label {
    font-size: 0.82rem;
    color: var(--text-secondary);
    white-space: nowrap;
  }
  .oh-value {
    font-size: 0.82rem;
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
    text-align: right;
    font-weight: 500;
  }
  .oh-track {
    height: 8px;
    background: var(--bg-tertiary);
    border-radius: 4px;
    overflow: hidden;
  }
  .oh-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.4s ease;
    min-width: 2px;
  }
  .oh-server { background: var(--accent); }
  .oh-kad    { background: var(--success); }
  .oh-srcex  { background: var(--warning); }
  .oh-freq   { background: #9c27b0; }
  :global([data-theme="dark"]) .oh-freq { background: #ba68c8; }
  .oh-empty {
    text-align: center;
    color: var(--text-muted);
    font-size: 0.82rem;
    padding: 8px 0;
  }

  .overhead-session-row {
    display: grid;
    grid-template-columns: auto auto auto auto;
    gap: 8px 20px;
    margin-top: 14px;
    padding-top: 12px;
    border-top: 1px solid var(--border);
    justify-content: start;
  }

  /* Reputation row on the statistics page. Two stat pills side-by-side
     mirrors the "total / active" pattern the overhead session row uses,
     keeping visual rhythm consistent across the page. */
  .reputation-row {
    display: flex;
    gap: 32px;
    padding: 4px 0 2px;
  }
  .rep-stat {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .rep-label {
    font-size: 11px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .rep-value {
    font-size: 18px;
    font-weight: 600;
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
  }
  .rep-value.rep-danger {
    color: var(--danger);
  }
</style>
