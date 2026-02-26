<script lang="ts">
  import { networkStats, networkError } from '$lib/stores/network';
  import { transfers } from '$lib/stores/transfers';
  import { formatBytes, formatSpeed } from '$lib/utils';

  let activeDownloads = $derived(
    $transfers.filter((t) => t.direction === 'download' && t.status === 'active').length
  );
  let activeUploads = $derived(
    $transfers.filter((t) => t.direction === 'upload' && t.status === 'active').length
  );
  let completedCount = $derived(
    $transfers.filter((t) => t.status === 'completed').length
  );
</script>

<div class="page-header">
  <h2>Dashboard</h2>
</div>

<div class="page-content">
  <div class="dashboard">
    <div class="stats-grid">
      <div class="stat-card">
        <div class="label">Network Status</div>
        <div class="value">
          <span class="badge {$networkStats.status}">{$networkStats.status}</span>
        </div>
      </div>

      <div class="stat-card">
        <div class="label">Connected Peers</div>
        <div class="value">{$networkStats.connected_peers}</div>
      </div>

      <div class="stat-card">
        <div class="label">Upload Speed</div>
        <div class="value">{formatSpeed($networkStats.upload_speed)}</div>
        <div class="sub">Total: {formatBytes($networkStats.total_uploaded)}</div>
      </div>

      <div class="stat-card">
        <div class="label">Download Speed</div>
        <div class="value">{formatSpeed($networkStats.download_speed)}</div>
        <div class="sub">Total: {formatBytes($networkStats.total_downloaded)}</div>
      </div>

      <div class="stat-card">
        <div class="label">Active Downloads</div>
        <div class="value">{activeDownloads}</div>
      </div>

      <div class="stat-card">
        <div class="label">Active Uploads</div>
        <div class="value">{activeUploads}</div>
      </div>

      <div class="stat-card">
        <div class="label">Completed Transfers</div>
        <div class="value">{completedCount}</div>
      </div>

      <div class="stat-card">
        <div class="label">External IP</div>
        <div class="value">{$networkStats.external_ip || 'Detecting...'}</div>
      </div>

      <div class="stat-card">
        <div class="label">Firewall</div>
        <div class="value">
          <span class="badge {$networkStats.firewalled ? 'firewalled' : 'open'}">
            {$networkStats.firewalled ? 'Firewalled' : 'Open'}
          </span>
        </div>
      </div>

      <div class="stat-card">
        <div class="label">UPnP</div>
        <div class="value">
          <span class="badge {$networkStats.upnp_mapped ? 'open' : 'firewalled'}">
            {$networkStats.upnp_mapped ? 'Mapped' : 'Not Mapped'}
          </span>
        </div>
      </div>

      <div class="stat-card">
        <div class="label">Buddy</div>
        <div class="value">{$networkStats.buddy_status === 'none' ? 'None' : $networkStats.buddy_status.startsWith('connected') ? 'Connected' : $networkStats.buddy_status.startsWith('serving') ? 'Serving' : $networkStats.buddy_status}</div>
      </div>

      <div class="stat-card">
        <div class="label">DHT Stores</div>
        <div class="value">{$networkStats.stores_acknowledged}</div>
      </div>
    </div>

    {#if $networkError}
      <div class="network-alert">
        <span class="alert-icon">&#x26A0;</span>
        <span>{$networkError}</span>
        <button class="ghost" onclick={() => $networkError = null}>Dismiss</button>
      </div>
    {/if}

    {#if $transfers.filter((t) => t.status === 'active').length > 0}
      <div class="section">
        <h3>Active Transfers</h3>
        <table>
          <thead>
            <tr>
              <th>File</th>
              <th>Direction</th>
              <th>Progress</th>
              <th>Speed</th>
            </tr>
          </thead>
          <tbody>
            {#each $transfers.filter((t) => t.status === 'active') as t (t.id)}
              <tr>
                <td>{t.file_name}</td>
                <td><span class="badge {t.direction}">{t.direction}</span></td>
                <td>{t.progress.toFixed(1)}%</td>
                <td>{formatSpeed(t.speed)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
</div>

<style>
  .dashboard {
    padding: 20px;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }

  .section {
    margin-top: 24px;
  }

  .section h3 {
    font-size: 15px;
    font-weight: 600;
    color: var(--text-secondary);
    margin-bottom: 12px;
  }

  .network-alert {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    background: var(--bg-secondary);
    border: 1px solid var(--warning, #f0ad4e);
    border-radius: 6px;
    margin-bottom: 16px;
    font-size: 13px;
    color: var(--text-primary);
  }

  .alert-icon {
    font-size: 18px;
    color: var(--warning, #f0ad4e);
  }

  .network-alert button {
    margin-left: auto;
  }
</style>
