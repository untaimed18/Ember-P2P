<script lang="ts">
  import { getStatistics, type TransferStats } from '$lib/api/statistics';
  import { getReputationStats, type ReputationStatsInfo } from '$lib/api/reputation';
  import {
    formatBytes,
    formatCalendarDate,
    formatDateTime,
    formatNumber,
    formatSpeed as formatRate,
    formatDurationSecs as formatDuration,
    formatElapsed,
    withTimeout,
  } from '$lib/utils';
  import { onMount } from 'svelte';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';

  let stats = $state<TransferStats | null>(null);
  let loading = $state(true);
  let error: string | null = $state(null);
  let refreshInterval: ReturnType<typeof setInterval> | null = null;
  /** Sequence number of the call holding the in-flight gate, 0 when idle. A
   *  forced refresh takes the gate over, so the poll it overlapped must not
   *  release it when it lands first. */
  let busySeq = 0;
  let requestSeq = 0;
  /** Newest call whose results were applied. An older call landing later is
   *  discarded rather than rolling the dashboard back. */
  let appliedSeq = 0;
  let tickCounter = $state(0);
  let unmounted = false;
  // Monotonic session elapsed from the backend at last successful poll,
  // plus the local tick counter at that moment — interpolate between polls
  // without falling back to wall-clock math (H1).
  let elapsedAtFetch = 0;
  let tickAtFetch = 0;

  // Reputation-tracker snapshot. Loaded alongside stats on the same
  // 2-second cadence. `null` before the first successful fetch so the
  // UI can render a "—" placeholder instead of zeros (zeros are
  // misleading when the backend is briefly unreachable).
  let repStats = $state<ReputationStatsInfo | null>(null);
  // True after at least one reputation fetch failed while we still have
  // no snapshot — drives the unavailable hint under Peer Reputation.
  let repUnavailable = $state(false);

  async function loadStats(opts: { force?: boolean } = {}) {
    if (unmounted) return;
    // A user-initiated retry (the error screen button) bypasses the poll's
    // in-flight gate so it never silently no-ops while a 2s poll happens to be
    // mid-flight. Watchdog timers are local to each call so a forced retry
    // running concurrently with a poll can't clobber the other's timer id.
    if (busySeq !== 0 && !opts.force) return;
    const seq = ++requestSeq;
    busySeq = seq;
    try {
      // Fire both fetches concurrently — they hit different backend
      // paths (stats reads a cached snapshot; reputation reads the
      // in-memory tracker) so there's no reason to serialise. If
      // reputation fails we still surface transfer stats; the inverse
      // is protected by the existing error path.
      // allSettled so a stats timeout can't discard an already-resolved
      // reputation result (and vice versa) — they're independent fetches.
      const [statsResult, repResult] = await Promise.allSettled([
        withTimeout(getStatistics(), 'get_statistics', 4000),
        // Reputation rides the same watchdog as stats. Unlike
        // getStatistics() (a direct cached-snapshot read), this round-trips
        // through the network task's command channel, whose reply timeout
        // is 10s. Because both fetches share the in-flight gate, a
        // briefly-busy network loop would otherwise stall the entire
        // dashboard refresh for up to 10s even though the transfer stats
        // themselves resolved instantly. Bound it independently.
        withTimeout(getReputationStats(), 'get_reputation_stats', 4000),
      ]);
      if (unmounted || seq < appliedSeq) return;
      appliedSeq = seq;
      if (repResult.status === 'fulfilled') {
        repStats = repResult.value;
        repUnavailable = false;
      } else if (!repStats) {
        // First successful stats paint with a failed reputation fetch:
        // keep the section visible with an unavailable hint instead of
        // hiding Peer Reputation entirely for the session.
        repUnavailable = true;
      }
      if (statsResult.status === 'fulfilled') {
        stats = statsResult.value;
        elapsedAtFetch = statsResult.value.session_elapsed_secs ?? 0;
        tickAtFetch = tickCounter;
        error = null;
      } else if (!stats) {
        // Only surface a blocking error screen on the very first load.
        // Once we have data, a transient poll failure must not blank the
        // whole dashboard — keep showing the last-known stats.
        error = translateError(statsResult.reason, m.error_operation_failed());
      }
    } catch (e) {
      if (unmounted || seq < appliedSeq) return;
      if (!stats) error = translateError(e, m.error_operation_failed());
    } finally {
      if (!unmounted) loading = false;
      if (busySeq === seq) busySeq = 0;
    }
  }

  let tickInterval: ReturnType<typeof setInterval> | null = null;

  onMount(() => {
    loadStats();
    // Skip while hidden, matching the shared stats poll and the KAD page: two
    // IPC round-trips every 2s is pure waste behind a minimized window.
    refreshInterval = setInterval(() => {
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
      loadStats();
    }, 2000);
    tickInterval = setInterval(() => tickCounter++, 1000);
    return () => {
      unmounted = true;
      if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = null; }
      if (tickInterval) { clearInterval(tickInterval); tickInterval = null; }
    };
  });

  let sessionTime = $derived.by(() => {
    void tickCounter;
    if (!stats) return 0;
    return elapsedAtFetch + Math.max(0, tickCounter - tickAtFetch);
  });

  let cumConnTime = $derived(
    stats ? stats.cum_conn_time + sessionTime : 0
  );

  // cum_ values are loaded from DB at startup and exclude the current session, so adding session_ is correct
  let totalDown = $derived(stats ? stats.cum_downloaded + stats.session_downloaded : 0);
  let totalUp = $derived(stats ? stats.cum_uploaded + stats.session_uploaded : 0);

  // Hero ratio is session-scoped (matches neighbouring session rate/time cards).
  // All-time ratio lives in the cumulative section below.
  let sessionRatio = $derived.by(() => {
    if (!stats) return null;
    if (stats.session_downloaded > 0) return stats.session_uploaded / stats.session_downloaded;
    if (stats.session_uploaded > 0) return Number.POSITIVE_INFINITY;
    return null;
  });

  let allTimeRatio = $derived.by(() => {
    if (totalDown > 0) return totalUp / totalDown;
    if (totalUp > 0) return Number.POSITIVE_INFINITY;
    return null;
  });

  function formatRatio(ratio: number | null): string {
    if (ratio === null) return '\u2014';
    if (!Number.isFinite(ratio)) return '\u221E';
    if (ratio >= 100) return ratio.toFixed(0);
    if (ratio >= 10) return ratio.toFixed(1);
    return ratio.toFixed(2);
  }

  let sessionRatioLabel = $derived(formatRatio(sessionRatio));
  let allTimeRatioLabel = $derived(formatRatio(allTimeRatio));

  let totalOverhead = $derived(
    stats
      ? stats.overhead_server
        + stats.overhead_kad
        + stats.overhead_source_exchange
        + stats.overhead_file_request
        + (stats.overhead_epx ?? 0)
        + (stats.overhead_ember_dht ?? 0)
      : 0
  );

  function overheadPct(part: number): number {
    if (!totalOverhead) return 0;
    return (part / totalOverhead) * 100;
  }

  // Render overhead rows in descending size so the biggest contributor
  // sits at the top. Zero-byte categories stay visible so a KAD/Ember
  // session still shows which pathways are silent versus active.
  // `help` is a hover explanation per category. "Source Exchange", "EPX",
  // "File Requests" and "Ember DHT" are protocol vocabulary, and this section
  // was six bar charts of it with nothing saying what any of them are or why
  // a large number there is fine.
  type OverheadRow = { key: string; label: string; help: string; value: number; cls: string };
  let overheadRows = $derived.by<OverheadRow[]>(() => {
    if (!stats) return [];
    const rows: OverheadRow[] = [
      { key: 'server', label: m.stats_overhead_server(), help: m.stats_overhead_server_help(), value: stats.overhead_server, cls: 'oh-server' },
      { key: 'kad', label: m.stats_overhead_kad(), help: m.stats_overhead_kad_help(), value: stats.overhead_kad, cls: 'oh-kad' },
      { key: 'srcex', label: m.stats_overhead_source_exchange(), help: m.stats_overhead_source_exchange_help(), value: stats.overhead_source_exchange, cls: 'oh-srcex' },
      { key: 'freq', label: m.stats_overhead_file_requests(), help: m.stats_overhead_file_requests_help(), value: stats.overhead_file_request, cls: 'oh-freq' },
      { key: 'epx', label: m.stats_overhead_epx(), help: m.stats_overhead_epx_help(), value: stats.overhead_epx ?? 0, cls: 'oh-epx' },
      { key: 'emberdht', label: m.stats_overhead_ember_dht(), help: m.stats_overhead_ember_dht_help(), value: stats.overhead_ember_dht ?? 0, cls: 'oh-ember-dht' },
    ];
    return rows.sort((a, b) => b.value - a.value);
  });

  // Friendly "Apr 18, 2026" rendering for the cumulative-since label.
  // Returns an em-dash if we don't have a reset timestamp yet (fresh
  // install before the first session ends).
  function formatSinceDate(ts: number): string {
    return formatCalendarDate(ts, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  }

</script>

<div class="page-header">
  <h2>{m.stats_title()}</h2>
  <div class="header-actions">
    <button class="ghost" onclick={() => loadStats({ force: true })} disabled={loading}>{m.common_refresh()}</button>
  </div>
</div>

<div class="page-content">
  {#if loading}
    <div class="empty-state">
      <div class="spinner lg"></div>
      <p>{m.stats_loading()}</p>
    </div>
  {:else if error}
    <!-- `.empty-title` + `.empty-action`, like every other failed-load state.
         This was the one that reached for an inline `style="color: danger"`,
         which meant it alone ignored the theme's error treatment. -->
    <div class="empty-state">
      <p class="empty-title">{error}</p>
      <button class="empty-action" onclick={() => loadStats({ force: true })}>{m.common_retry()}</button>
    </div>
  {:else if stats}

    <!-- Hero cards -->
    <div class="hero-row">
      <div class="stat-card hero-card">
        <div class="hero-icon down-icon" aria-hidden="true">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <line x1="10" y1="3" x2="10" y2="15"/>
            <polyline points="5,10 10,15 15,10"/>
          </svg>
        </div>
        <div class="hero-body">
          <span class="value">{formatRate(stats.session_down_rate)}</span>
          <span class="label">{m.stats_download_rate()}</span>
        </div>
      </div>
      <div class="stat-card hero-card">
        <div class="hero-icon up-icon" aria-hidden="true">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <line x1="10" y1="17" x2="10" y2="5"/>
            <polyline points="5,10 10,5 15,10"/>
          </svg>
        </div>
        <div class="hero-body">
          <span class="value">{formatRate(stats.session_up_rate)}</span>
          <span class="label">{m.stats_upload_rate()}</span>
        </div>
      </div>
      <div class="stat-card hero-card">
        <div class="hero-icon time-icon" aria-hidden="true">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="10" cy="11" r="6.5"/>
            <line x1="10" y1="11" x2="10" y2="7"/>
            <line x1="10" y1="11" x2="13" y2="11"/>
            <line x1="8" y1="2.5" x2="12" y2="2.5"/>
          </svg>
        </div>
        <div class="hero-body">
          <span class="value">{formatElapsed(sessionTime)}</span>
          <span class="label">{m.stats_session_time()}</span>
        </div>
      </div>
      <div class="stat-card hero-card">
        <div class="hero-icon ratio-icon" aria-hidden="true">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <line x1="6" y1="3.5" x2="6" y2="15"/>
            <polyline points="3.5,6 6,3.5 8.5,6"/>
            <line x1="14" y1="16.5" x2="14" y2="5"/>
            <polyline points="11.5,14 14,16.5 16.5,14"/>
          </svg>
        </div>
        <div class="hero-body">
          <span class="value" class:ratio-good={sessionRatio !== null && sessionRatio >= 1} class:ratio-low={sessionRatio !== null && sessionRatio < 1}>{sessionRatioLabel}</span>
          <span class="label">{m.stats_session_upload_ratio()}</span>
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
            <span class="big-value">{formatNumber(stats.session_completed_down)}</span>
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
            <span class="big-value">{formatNumber(stats.session_completed_up)}</span>
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
            title={m.stats_cumulative_started_on({ when: formatDateTime(stats.stat_last_reset) })}
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
          <span class="cum-label">{m.stats_total_uptime()}</span>
          <span class="cum-value">{formatDuration(cumConnTime)}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">{m.stats_completed_downloads()}</span>
          <!-- cum_ excludes current session (DB snapshot at startup), so addition is intentional -->
          <span class="cum-value">{formatNumber(stats.cum_completed_down + stats.session_completed_down)}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">{m.stats_completed_uploads()}</span>
          <span class="cum-value">{formatNumber(stats.cum_completed_up + stats.session_completed_up)}</span>
        </div>
        <div class="cum-item">
          <span class="cum-label">{m.stats_upload_download_ratio()}</span>
          <span class="cum-value" class:ratio-good={allTimeRatio !== null && allTimeRatio >= 1} class:ratio-low={allTimeRatio !== null && allTimeRatio < 1}>{allTimeRatioLabel}</span>
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
        <span class="head-aside">{m.stats_overhead_session_aside()} · {m.stats_overhead_total({ bytes: formatBytes(totalOverhead) })}</span>
      </div>

      <div class="overhead-bars">
        {#each overheadRows as row (row.key)}
          <div class="oh-row">
            <span class="oh-label" title={row.help}>{row.label}</span>
            <div class="oh-track">
              <div
                class="oh-fill {row.cls}"
                class:oh-nonzero={row.value > 0}
                style="width: {overheadPct(row.value)}%"
              ></div>
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
      records for, how many are currently reputation-banned, and the
      total enforced IP-ban count (which also includes automatic IP
      bans — request flooding / corruption — that don't run through the
      per-user-hash tracker). Banned counts are coloured to draw
      attention — a non-zero value means we're actively filtering out
      misbehaving peers. Rendered only when we've had at least one
      successful fetch (`repStats != null`) so a transient backend
      hiccup doesn't make the row flash zeros and scare the user. When
      the fetch keeps failing, show an unavailable hint instead of
      hiding the section forever.
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
          <span class="head-aside">{m.stats_live_counters()}</span>
        </div>
        <div class="reputation-row">
          <div class="rep-stat">
            <span class="rep-label" title={m.stats_tracked_peers_hint()}>{m.stats_tracked_peers()}</span>
            <span class="rep-value">{formatNumber(repStats.tracked_peers)}</span>
          </div>
          <div class="rep-stat">
            <span class="rep-label" title={m.stats_banned_peers_hint()}>{m.stats_banned_peers()}</span>
            <span class="rep-value" class:rep-danger={repStats.banned_peers > 0}>
              {formatNumber(repStats.banned_peers)}
            </span>
          </div>
          <div class="rep-stat">
            <span class="rep-label" title={m.stats_banned_ips_hint()}>{m.stats_banned_ips()}</span>
            <span class="rep-value" class:rep-danger={repStats.banned_ips > 0}>
              {formatNumber(repStats.banned_ips)}
            </span>
          </div>
        </div>
      </section>
    {:else if stats && repUnavailable}
      <section class="card">
        <div class="card-head">
          <span class="section-icon" aria-hidden="true">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M8 1.5 L2 4 V8 Q2 12.5 8 14.5 Q14 12.5 14 8 V4 Z"/>
              <polyline points="5.5,8 7.5,10 10.5,6"/>
            </svg>
          </span>
          <h3>{m.stats_peer_reputation()}</h3>
          <span class="head-aside">{m.stats_live_counters()}</span>
        </div>
        <p class="rep-unavailable">{m.stats_reputation_unavailable()}</p>
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
  @media (max-width: 980px) {
    .hero-row { grid-template-columns: repeat(2, 1fr); }
  }
  /* The shared `.stat-card`, with an icon beside the number. */
  .hero-card {
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .hero-icon {
    width: 42px;
    height: 42px;
    border-radius: var(--radius-lg);
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
  .up-icon    { background: color-mix(in srgb, var(--warning) 14%, transparent); color: var(--warning); }
  .time-icon  { background: color-mix(in srgb, var(--success) 14%, transparent); color: var(--success); }
  .ratio-icon { background: color-mix(in srgb, var(--stat-ratio) 14%, transparent); color: var(--stat-ratio); }
  .hero-body { display: flex; flex-direction: column; min-width: 0; }
  .hero-card .value {
    margin-top: 0;
    white-space: nowrap;
  }
  .hero-card .label {
    margin-top: 2px;
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
    font-size: var(--font-size-base);
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
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  /* ---- Section row (side-by-side) ---- */
  .section-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }
  @media (max-width: 760px) {
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
    font-size: var(--font-size-2xl);
    font-weight: 700;
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
  }
  .big-sub {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    margin-top: 2px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .down-color { color: var(--accent); }
  .up-color   { color: var(--warning); }

  /* ---- Cumulative grid ---- */
  .cum-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 18px 24px;
  }
  @media (max-width: 760px) {
    .cum-grid { grid-template-columns: repeat(2, 1fr); }
  }
  .cum-item { display: flex; flex-direction: column; }
  .cum-label {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-bottom: 4px;
  }
  .cum-value {
    font-size: var(--font-size-lg);
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
    grid-template-columns: max-content minmax(0, 1fr) 90px;
    align-items: center;
    gap: 10px;
  }
  .oh-label {
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    white-space: nowrap;
  }
  .oh-value {
    font-size: var(--font-size-sm);
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
    text-align: right;
    font-weight: 500;
  }
  .oh-track {
    height: 8px;
    background: var(--bg-tertiary);
    border-radius: var(--radius-pill);
    overflow: hidden;
  }
  .oh-fill {
    height: 100%;
    border-radius: var(--radius-pill);
    transition: width 0.4s ease;
  }
  /* Visible sliver only when the category contributed — a blanket
     min-width made every zero row look slightly active. */
  .oh-fill.oh-nonzero {
    min-width: 2px;
  }
  .oh-server { background: var(--accent); }
  .oh-kad    { background: var(--success); }
  .oh-srcex  { background: var(--warning); }
  .oh-freq   { background: var(--stat-ratio); }
  .oh-epx    { background: var(--ember-color); }
  .oh-ember-dht { background: var(--ember-dht-color); }
  .oh-empty {
    text-align: center;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
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

  /* Reputation row on the statistics page. Stat pills side-by-side
     mirror the "total / active" pattern the overhead session row uses,
     keeping visual rhythm consistent across the page. Wraps so the
     third "Banned IPs" pill drops to a new line on narrow widths
     instead of overflowing the card. */
  .reputation-row {
    display: flex;
    flex-wrap: wrap;
    gap: 16px 32px;
    padding: 4px 0 2px;
  }
  .rep-stat {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .rep-label {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .rep-value {
    font-size: var(--font-size-xl);
    font-weight: 600;
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
  }
  .rep-value.rep-danger {
    color: var(--danger);
  }
  .rep-unavailable {
    margin: 0;
    padding: 4px 2px 2px;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
  }
</style>
