<script lang="ts">
  import { networkStats, serverStatus } from '$lib/stores/network';
  import { formatBytes, formatSpeed } from '$lib/utils';

  function epxStatus(stats: typeof $networkStats): 'active' | 'idle' | 'inactive' {
    if (stats.status === 'disconnected') return 'inactive';
    return stats.ember_peers > 0 ? 'active' : 'idle';
  }

  function epxTitle(stats: typeof $networkStats): string {
    const status = epxStatus(stats);
    if (status === 'inactive') return 'EPX: Network offline';
    if (status === 'idle') return 'EPX: Waiting for Ember peers';
    const punch = `${stats.broker_punch_successes}/${stats.broker_punch_attempts} punch`;
    const relay = `${stats.broker_relay_successes}/${stats.broker_relay_attempts} relay`;
    return `EPX: ${stats.ember_peers} peer${stats.ember_peers === 1 ? '' : 's'}, ${stats.epx_sources_received} source${stats.epx_sources_received === 1 ? '' : 's'} received, ${punch}, ${relay}`;
  }
</script>

<footer class="statusbar">
  <div class="status-left" role="status" aria-live="polite">
    <span class="status-label" title="KAD Network: {$networkStats.status}">
      KAD
      <span class="dot {$networkStats.status}" aria-label="{$networkStats.status}"></span>
    </span>
    <span class="status-label" title="ED2K: {$serverStatus}">
      ED2K
      <span class="dot {$serverStatus}" aria-label="{$serverStatus}"></span>
    </span>
    <span class="status-label" title={epxTitle($networkStats)}>
      EPX
      <span class="dot {epxStatus($networkStats)}" aria-label={epxStatus($networkStats)}></span>
    </span>
  </div>

  <div class="status-right" aria-label="Transfer speeds">
    <!--
      D7: status bar rate is the total network rate (file payload + protocol
      overhead: server, KAD, source exchange, reasks). The Transfers page
      "DL" / "UL" chips show only the active transfer-payload rate. The
      numbers legitimately differ, so label the status bar "Network" in the
      tooltip to flag the distinction.
    -->
    <span class="status-item upload" title="Total network upload (includes protocol overhead)">
      <span aria-hidden="true">↑</span>
      <span class="sr-only">Upload speed:</span>
      {formatSpeed($networkStats.upload_speed)}
    </span>
    <span class="status-item download" title="Total network download (includes protocol overhead)">
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

  .status-label {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--text-secondary);
    cursor: default;
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
    flex-shrink: 0;
  }

  .dot.connected {
    background: #22c55e;
    box-shadow: 0 0 4px #22c55e80;
  }

  .dot.connecting {
    background: #eab308;
    box-shadow: 0 0 4px #eab30880;
  }

  .dot.disconnected, .dot.inactive {
    background: #ef4444;
    box-shadow: 0 0 4px #ef444480;
  }

  .dot.active {
    background: #22c55e;
    box-shadow: 0 0 4px #22c55e80;
  }

  .dot.idle {
    background: #eab308;
    box-shadow: 0 0 4px #eab30880;
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
