<script lang="ts">
  import { networkStats, serverStatus } from '$lib/stores/network';
  import { formatBytes, formatSpeed } from '$lib/utils';
  import * as m from '$lib/paraglide/messages';

  function epxStatus(stats: typeof $networkStats): 'active' | 'idle' | 'inactive' {
    if (stats.status === 'disconnected') return 'inactive';
    return stats.ember_peers > 0 ? 'active' : 'idle';
  }

  // Localized status string for the tri-state network/server dots.
  // Keep the mapping co-located with the status-bar specifically
  // (instead of pulling from `network_status_*`) because the
  // status-bar shows "Connected/Connecting/Disconnected" while
  // some pages use the Spanish equivalents in different
  // grammatical positions; the mapping is identical today but may
  // diverge for accessibility tweaks per surface.
  function statusLabel(s: string): string {
    switch (s) {
      case 'connected': return m.network_status_connected();
      case 'connecting': return m.network_status_connecting();
      case 'disconnected': return m.network_status_disconnected();
      default: return m.network_status_unknown();
    }
  }

  // Two-axis plural for the EPX tooltip. English/Spanish both
  // distinguish singular/plural; we render one of four templates
  // rather than concatenating fragments so translators control
  // word order (Spanish often inverts noun-adjective compared to
  // English, even in technical strings like "1 fuente recibida"
  // vs "{n} fuentes recibidas").
  function epxTitle(stats: typeof $networkStats): string {
    const status = epxStatus(stats);
    if (status === 'inactive') return m.statusbar_epx_title_offline();
    if (status === 'idle') return m.statusbar_epx_title_idle();
    const p = stats.ember_peers;
    const s = stats.epx_sources_received;
    if (p === 1 && s === 1) return m.statusbar_epx_title_active_one_one();
    if (p === 1) return m.statusbar_epx_title_active_one_other({ sources: s });
    if (s === 1) return m.statusbar_epx_title_active_other_one({ peers: p });
    return m.statusbar_epx_title_active_other_other({ peers: p, sources: s });
  }
</script>

<footer class="statusbar">
  <div class="status-left" role="status" aria-live="polite">
    <span class="status-label" title={m.statusbar_kad_title({ status: statusLabel($networkStats.status) })}>
      {m.statusbar_kad_label()}
      <span class="dot {$networkStats.status}" aria-label={statusLabel($networkStats.status)}></span>
    </span>
    <span class="status-label" title={m.statusbar_ed2k_title({ status: statusLabel($serverStatus) })}>
      {m.statusbar_ed2k_label()}
      <span class="dot {$serverStatus}" aria-label={statusLabel($serverStatus)}></span>
    </span>
    <span class="status-label" title={epxTitle($networkStats)}>
      {m.statusbar_epx_label()}
      <span class="dot {epxStatus($networkStats)}" aria-label={epxStatus($networkStats)}></span>
    </span>
  </div>

  <div class="status-right" aria-label={m.statusbar_speeds_aria()}>
    <!--
      D7: status bar rate is the total network rate (file payload + protocol
      overhead: server, KAD, source exchange, reasks). The Transfers page
      "DL" / "UL" chips show only the active transfer-payload rate. The
      numbers legitimately differ, so label the status bar "Network" in the
      tooltip to flag the distinction.
    -->
    <span class="status-item upload" title={m.statusbar_upload_title()}>
      <span aria-hidden="true">↑</span>
      <span class="sr-only">{m.statusbar_upload_sr()}</span>
      {formatSpeed($networkStats.upload_speed)}
    </span>
    <span class="status-item download" title={m.statusbar_download_title()}>
      <span aria-hidden="true">↓</span>
      <span class="sr-only">{m.statusbar_download_sr()}</span>
      {formatSpeed($networkStats.download_speed)}
    </span>
    <span class="status-item muted" aria-label={m.statusbar_total_transferred({ up: formatBytes($networkStats.total_uploaded), down: formatBytes($networkStats.total_downloaded) })}>
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
