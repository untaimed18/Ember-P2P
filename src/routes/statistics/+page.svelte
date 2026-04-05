<script lang="ts">
  import { getStatistics, type TransferStats } from '$lib/api/statistics';
  import { formatBytes, formatSpeed as formatRate, formatDurationSecs as formatDuration } from '$lib/utils';
  import { onMount } from 'svelte';

  let stats = $state<TransferStats | null>(null);
  let loading = $state(true);
  let error: string | null = $state(null);
  let refreshInterval: ReturnType<typeof setInterval> | null = null;
  let refreshBusy = false;
  let tickCounter = $state(0);

  async function loadStats() {
    if (refreshBusy) return;
    refreshBusy = true;
    try {
      const result: TransferStats = await Promise.race([
        getStatistics(),
        new Promise<TransferStats>((_, reject) => setTimeout(() => reject(new Error('timeout')), 4000)),
      ]);
      stats = result;
      error = null;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
      refreshBusy = false;
    }
  }

  let tickInterval: ReturnType<typeof setInterval> | null = null;

  onMount(() => {
    loadStats();
    refreshInterval = setInterval(loadStats, 2000);
    tickInterval = setInterval(() => tickCounter++, 1000);
    return () => {
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
    stats ? stats.cum_conn_time : 0
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

  function formatSessionTime(secs: number): string {
    if (secs <= 0) return '0s';
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
    if (m > 0) return `${m}m ${String(s).padStart(2, '0')}s`;
    return `${s}s`;
  }
</script>

<div class="page-header">
  <h2>Statistics</h2>
</div>

<div class="page-content">
  {#if loading}
    <div class="empty-state">
      <div class="spinner lg"></div>
      <p>Loading statistics...</p>
    </div>
  {:else if error}
    <div class="empty-state">
      <p style="color: var(--danger)">{error}</p>
      <button onclick={loadStats}>Retry</button>
    </div>
  {:else if stats}

    <!-- Hero cards -->
    <div class="hero-row">
      <div class="hero-card">
        <div class="hero-icon down-icon">&#x2193;</div>
        <div class="hero-body">
          <span class="hero-value">{formatRate(stats.session_down_rate)}</span>
          <span class="hero-label">Download Rate</span>
        </div>
      </div>
      <div class="hero-card">
        <div class="hero-icon up-icon">&#x2191;</div>
        <div class="hero-body">
          <span class="hero-value">{formatRate(stats.session_up_rate)}</span>
          <span class="hero-label">Upload Rate</span>
        </div>
      </div>
      <div class="hero-card">
        <div class="hero-icon time-icon">&#x23F1;</div>
        <div class="hero-body">
          <span class="hero-value">{formatSessionTime(sessionTime)}</span>
          <span class="hero-label">Session Time</span>
        </div>
      </div>
      <div class="hero-card">
        <div class="hero-icon ratio-icon">&#x21C5;</div>
        <div class="hero-body">
          <span class="hero-value" class:ratio-good={ratio !== null && ratio >= 1} class:ratio-low={ratio !== null && ratio < 1}>{ratioLabel}</span>
          <span class="hero-label">Upload Ratio</span>
        </div>
      </div>
    </div>

    <!-- Transfer summary -->
    <div class="section-row">
      <section class="card transfer-card">
        <div class="card-head">
          <span class="section-icon">&#x2913;</span>
          <h3>Session Downloads</h3>
        </div>
        <div class="transfer-grid">
          <div class="big-stat">
            <span class="big-value down-color">{formatBytes(stats.session_downloaded)}</span>
            <span class="big-sub">transferred</span>
          </div>
          <div class="big-stat">
            <span class="big-value">{stats.session_completed_down}</span>
            <span class="big-sub">completed</span>
          </div>
        </div>
      </section>

      <section class="card transfer-card">
        <div class="card-head">
          <span class="section-icon">&#x2912;</span>
          <h3>Session Uploads</h3>
        </div>
        <div class="transfer-grid">
          <div class="big-stat">
            <span class="big-value up-color">{formatBytes(stats.session_uploaded)}</span>
            <span class="big-sub">transferred</span>
          </div>
          <div class="big-stat">
            <span class="big-value">{stats.session_completed_up}</span>
            <span class="big-sub">completed</span>
          </div>
        </div>
      </section>
    </div>

    <!-- Cumulative -->
    <section class="card">
      <div class="card-head">
        <span class="section-icon">&#x03A3;</span>
        <h3>All-Time Totals</h3>
      </div>
      <div class="cum-grid">
        <div class="cum-item">
          <span class="cum-label">Total Downloaded</span>
          <span class="cum-value down-color">{formatBytes(totalDown)}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">Total Uploaded</span>
          <span class="cum-value up-color">{formatBytes(totalUp)}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">Total Connection Time</span>
          <span class="cum-value">{formatDuration(cumConnTime)}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">Completed Downloads</span>
          <!-- cum_ excludes current session (DB snapshot at startup), so addition is intentional -->
          <span class="cum-value">{stats.cum_completed_down + stats.session_completed_down}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">Completed Uploads</span>
          <span class="cum-value">{stats.cum_completed_up + stats.session_completed_up}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">Upload : Download Ratio</span>
          <span class="cum-value" class:ratio-good={ratio !== null && ratio >= 1} class:ratio-low={ratio !== null && ratio < 1}>{ratioLabel}</span>
        </div>
      </div>
    </section>

    <!-- Overhead -->
    <section class="card">
      <div class="card-head">
        <span class="section-icon">&#x26A1;</span>
        <h3>Protocol Overhead</h3>
        <span class="head-aside">{formatBytes(totalOverhead)} total</span>
      </div>

      <div class="overhead-bars">
        {#if stats.overhead_server > 0}
        <div class="oh-row">
          <span class="oh-label">Server</span>
          <div class="oh-track">
            <div class="oh-fill oh-server" style="width: {overheadPct(stats.overhead_server)}%"></div>
          </div>
          <span class="oh-value">{formatBytes(stats.overhead_server)}</span>
        </div>
        {/if}
        {#if stats.overhead_kad > 0}
        <div class="oh-row">
          <span class="oh-label">KAD</span>
          <div class="oh-track">
            <div class="oh-fill oh-kad" style="width: {overheadPct(stats.overhead_kad)}%"></div>
          </div>
          <span class="oh-value">{formatBytes(stats.overhead_kad)}</span>
        </div>
        {/if}
        {#if stats.overhead_source_exchange > 0}
        <div class="oh-row">
          <span class="oh-label">Source Exchange</span>
          <div class="oh-track">
            <div class="oh-fill oh-srcex" style="width: {overheadPct(stats.overhead_source_exchange)}%"></div>
          </div>
          <span class="oh-value">{formatBytes(stats.overhead_source_exchange)}</span>
        </div>
        {/if}
        {#if stats.overhead_file_request > 0}
        <div class="oh-row">
          <span class="oh-label">File Requests</span>
          <div class="oh-track">
            <div class="oh-fill oh-freq" style="width: {overheadPct(stats.overhead_file_request)}%"></div>
          </div>
          <span class="oh-value">{formatBytes(stats.overhead_file_request)}</span>
        </div>
        {/if}
        {#if totalOverhead === 0}
          <p class="oh-empty">No overhead recorded yet</p>
        {/if}
      </div>

      <div class="overhead-session-row">
        <span class="oh-label">Session Down Overhead</span>
        <span class="oh-value">{formatBytes(stats.session_down_overhead)}</span>
        <span class="oh-label">Session Up Overhead</span>
        <span class="oh-value">{formatBytes(stats.session_up_overhead)}</span>
      </div>
    </section>

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
    font-size: 22px;
    flex-shrink: 0;
  }
  .down-icon { background: rgba(26,115,232,0.12); color: var(--accent); }
  .up-icon   { background: rgba(52,168,83,0.12);  color: var(--success); }
  .time-icon { background: rgba(234,134,0,0.12);  color: var(--warning); }
  .ratio-icon{ background: rgba(156,39,176,0.12);  color: #9c27b0; }
  :global([data-theme="dark"]) .down-icon { background: rgba(79,195,247,0.15); color: var(--accent); }
  :global([data-theme="dark"]) .up-icon   { background: rgba(102,187,106,0.15); color: var(--success); }
  :global([data-theme="dark"]) .time-icon { background: rgba(255,167,38,0.15); color: var(--warning); }
  :global([data-theme="dark"]) .ratio-icon{ background: rgba(186,104,200,0.15); color: #ba68c8; }
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
    font-size: 1.1rem;
    opacity: 0.6;
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
</style>
