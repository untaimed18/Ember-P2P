<script lang="ts">
  import { networkStats } from '$lib/stores/network';
  import { formatBytes, formatSpeed, pluralize } from '$lib/utils';
</script>

<footer class="statusbar" role="contentinfo">
  <div class="status-left" role="status" aria-live="polite">
    <span class="status-indicator badge {$networkStats.status}">
      {#if $networkStats.status === 'connected'}<span aria-hidden="true">●</span>
      {:else if $networkStats.status === 'connecting'}<span aria-hidden="true">◌</span>
      {:else}<span aria-hidden="true">○</span>
      {/if}
      <span class="sr-only">Network status:</span>
      {$networkStats.status}
    </span>
    <span class="status-item">
      {pluralize($networkStats.connected_peers, 'contact')}
    </span>
  </div>

  <div class="status-right" aria-label="Transfer speeds">
    <span class="status-item upload">
      <span aria-hidden="true">↑</span>
      <span class="sr-only">Upload speed:</span>
      {formatSpeed($networkStats.upload_speed)}
    </span>
    <span class="status-item download">
      <span aria-hidden="true">↓</span>
      <span class="sr-only">Download speed:</span>
      {formatSpeed($networkStats.download_speed)}
    </span>
    <span class="status-item muted" aria-label="Total transferred: {formatBytes($networkStats.total_uploaded)} up, {formatBytes($networkStats.total_downloaded)} down">
      <span aria-hidden="true">↑</span> {formatBytes($networkStats.total_uploaded)} / <span aria-hidden="true">↓</span> {formatBytes($networkStats.total_downloaded)}
    </span>
  </div>
</footer>

<style>
  .statusbar {
    min-height: var(--statusbar-height);
    background: var(--bg-secondary);
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 16px;
    font-size: 12px;
    flex-shrink: 0;
  }

  .status-left, .status-right {
    display: flex;
    align-items: center;
    gap: 16px;
  }

  .status-item {
    color: var(--text-secondary);
  }

  .status-item.upload {
    color: var(--warning);
  }

  .status-item.download {
    color: var(--accent);
  }

  .status-item.muted {
    color: var(--text-muted);
  }
</style>
