<script lang="ts">
  import { networkStats } from '$lib/stores/network';

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
  }

  function formatSpeed(bytesPerSec: number): string {
    return `${formatBytes(bytesPerSec)}/s`;
  }
</script>

<footer class="statusbar">
  <div class="status-left">
    <span class="status-indicator badge {$networkStats.status}">
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
