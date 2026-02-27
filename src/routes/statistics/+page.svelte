<script lang="ts">
  import { getStatistics, type TransferStats } from '$lib/api/statistics';
  import { onMount, onDestroy } from 'svelte';

  let stats: TransferStats | null = $state(null);
  let loading = $state(true);
  let error: string | null = $state(null);
  let refreshInterval: ReturnType<typeof setInterval> | null = null;

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
  }

  function formatRate(bytesPerSec: number): string {
    return `${formatBytes(bytesPerSec)}/s`;
  }

  function formatDuration(seconds: number): string {
    if (seconds <= 0) return '0s';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    const parts = [];
    if (d > 0) parts.push(`${d}d`);
    if (h > 0) parts.push(`${h}h`);
    if (m > 0) parts.push(`${m}m`);
    if (parts.length === 0 || s > 0) parts.push(`${s}s`);
    return parts.join(' ');
  }

  async function loadStats() {
    try {
      stats = await getStatistics();
      error = null;
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    loadStats();
    refreshInterval = setInterval(loadStats, 2000);
  });

  onDestroy(() => {
    if (refreshInterval) clearInterval(refreshInterval);
  });

  let sessionTime = $derived(
    stats ? Math.floor(Date.now() / 1000 - stats.session_start_time) : 0
  );

  let cumConnTime = $derived(
    stats ? stats.cum_conn_time + sessionTime : 0
  );
</script>

<div class="page-container">
  <div class="page-header">
    <h1>Statistics</h1>
    <p class="subtitle">Session and cumulative transfer statistics</p>
  </div>

  {#if loading}
    <div class="loading">Loading statistics...</div>
  {:else if error}
    <div class="error-msg">{error}</div>
  {:else if stats}
    <div class="stats-grid">
      <div class="stats-section">
        <h2>Session</h2>
        <div class="stat-row">
          <span class="label">Session Duration</span>
          <span class="value">{formatDuration(sessionTime)}</span>
        </div>
        <div class="stat-row">
          <span class="label">Downloaded</span>
          <span class="value">{formatBytes(stats.session_downloaded)}</span>
        </div>
        <div class="stat-row">
          <span class="label">Uploaded</span>
          <span class="value">{formatBytes(stats.session_uploaded)}</span>
        </div>
        <div class="stat-row">
          <span class="label">Download Rate</span>
          <span class="value">{formatRate(stats.session_down_rate)}</span>
        </div>
        <div class="stat-row">
          <span class="label">Upload Rate</span>
          <span class="value">{formatRate(stats.session_up_rate)}</span>
        </div>
        <div class="stat-row">
          <span class="label">Completed Downloads</span>
          <span class="value">{stats.session_completed_down}</span>
        </div>
        <div class="stat-row">
          <span class="label">Completed Uploads</span>
          <span class="value">{stats.session_completed_up}</span>
        </div>
      </div>

      <div class="stats-section">
        <h2>Cumulative</h2>
        <div class="stat-row">
          <span class="label">Total Connection Time</span>
          <span class="value">{formatDuration(Number(cumConnTime))}</span>
        </div>
        <div class="stat-row">
          <span class="label">Total Downloaded</span>
          <span class="value">{formatBytes(stats.cum_downloaded + stats.session_downloaded)}</span>
        </div>
        <div class="stat-row">
          <span class="label">Total Uploaded</span>
          <span class="value">{formatBytes(stats.cum_uploaded + stats.session_uploaded)}</span>
        </div>
        <div class="stat-row">
          <span class="label">Total Completed Downloads</span>
          <span class="value">{stats.cum_completed_down + stats.session_completed_down}</span>
        </div>
        <div class="stat-row">
          <span class="label">Total Completed Uploads</span>
          <span class="value">{stats.cum_completed_up + stats.session_completed_up}</span>
        </div>
      </div>

      <div class="stats-section">
        <h2>Overhead</h2>
        <div class="stat-row">
          <span class="label">Session Download Overhead</span>
          <span class="value">{formatBytes(stats.session_down_overhead)}</span>
        </div>
        <div class="stat-row">
          <span class="label">Session Upload Overhead</span>
          <span class="value">{formatBytes(stats.session_up_overhead)}</span>
        </div>
        <div class="stat-row">
          <span class="label">Server Overhead</span>
          <span class="value">{formatBytes(stats.overhead_server)}</span>
        </div>
        <div class="stat-row">
          <span class="label">KAD Overhead</span>
          <span class="value">{formatBytes(stats.overhead_kad)}</span>
        </div>
        <div class="stat-row">
          <span class="label">Source Exchange Overhead</span>
          <span class="value">{formatBytes(stats.overhead_source_exchange)}</span>
        </div>
        <div class="stat-row">
          <span class="label">File Request Overhead</span>
          <span class="value">{formatBytes(stats.overhead_file_request)}</span>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .page-container {
    padding: 1.5rem;
    max-width: 1200px;
    margin: 0 auto;
  }
  .page-header {
    margin-bottom: 1.5rem;
  }
  .page-header h1 {
    font-size: 1.5rem;
    font-weight: 600;
    color: var(--text-primary, #e0e0e0);
    margin: 0;
  }
  .subtitle {
    font-size: 0.85rem;
    color: var(--text-secondary, #888);
    margin: 0.25rem 0 0 0;
  }
  .loading, .error-msg {
    padding: 2rem;
    text-align: center;
    color: var(--text-secondary, #888);
  }
  .error-msg { color: #e74c3c; }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
    gap: 1.5rem;
  }
  .stats-section {
    background: var(--bg-secondary, #1e1e2e);
    border: 1px solid var(--border-color, #333);
    border-radius: 8px;
    padding: 1rem 1.25rem;
  }
  .stats-section h2 {
    font-size: 1rem;
    font-weight: 600;
    color: var(--text-primary, #e0e0e0);
    margin: 0 0 0.75rem 0;
    border-bottom: 1px solid var(--border-color, #333);
    padding-bottom: 0.5rem;
  }
  .stat-row {
    display: flex;
    justify-content: space-between;
    padding: 0.35rem 0;
    font-size: 0.85rem;
  }
  .label {
    color: var(--text-secondary, #888);
  }
  .value {
    color: var(--text-primary, #e0e0e0);
    font-weight: 500;
    font-variant-numeric: tabular-nums;
  }
</style>
