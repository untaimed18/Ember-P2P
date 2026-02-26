<script lang="ts">
  import { networkStats } from '$lib/stores/network';
  import { formatBytes, formatSpeed } from '$lib/utils';
</script>

<footer class="statusbar">
  <div class="status-left">
    <span class="status-indicator badge {$networkStats.status}" aria-label="Network status: {$networkStats.status}">
      {$networkStats.status}
    </span>
    <span class="status-item">
      {$networkStats.connected_peers} peers
    </span>
  </div>

  <div class="status-right">
    <span class="status-item upload">
      ↑ {formatSpeed($networkStats.upload_speed)}
    </span>
    <span class="status-item download">
      ↓ {formatSpeed($networkStats.download_speed)}
    </span>
    <span class="status-item muted">
      ↑ {formatBytes($networkStats.total_uploaded)} / ↓ {formatBytes($networkStats.total_downloaded)}
    </span>
  </div>
</footer>

<style>
  .statusbar {
    height: var(--statusbar-height);
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
