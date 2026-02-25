<script lang="ts">
  import ProgressBar from '$lib/components/ProgressBar.svelte';
  import { transfers, startTransferPoll } from '$lib/stores/transfers';
  import { pauseTransfer, resumeTransfer, cancelTransfer } from '$lib/api/transfers';
  import { onMount } from 'svelte';

  onMount(() => {
    const stop = startTransferPoll();
    return () => stop();
  });

  function formatSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
  }

  function formatSpeed(bytesPerSec: number): string {
    return `${formatSize(bytesPerSec)}/s`;
  }

  let activeTransfers = $derived(
    $transfers.filter((t) => t.status !== 'completed' && t.status !== 'failed')
  );
  let completedTransfers = $derived(
    $transfers.filter((t) => t.status === 'completed' || t.status === 'failed')
  );
</script>

<div class="page-header">
  <h2>Transfers</h2>
  <span class="count">{activeTransfers.length} active</span>
</div>

<div class="page-content">
  {#if $transfers.length === 0}
    <div class="empty-state">
      <div class="icon">⇅</div>
      <p>No transfers yet</p>
      <p class="sub">Start a download from the Search page</p>
    </div>
  {:else}
    {#if activeTransfers.length > 0}
      <div class="section-header">Active</div>
      <table>
        <thead>
          <tr>
            <th>File</th>
            <th>Direction</th>
            <th>Progress</th>
            <th>Speed</th>
            <th>Size</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each activeTransfers as t (t.id)}
            <tr>
              <td title={t.file_name}>{t.file_name}</td>
              <td><span class="badge {t.direction}">{t.direction}</span></td>
              <td class="progress-cell">
                {#if t.status === 'searching'}
                  <span class="searching-label">Searching for sources...</span>
                {:else}
                  <ProgressBar
                    value={t.progress}
                    color={t.status === 'paused' ? 'var(--warning)' : 'var(--accent)'}
                  />
                {/if}
              </td>
              <td>{t.status === 'active' ? formatSpeed(t.speed) : '—'}</td>
              <td>{formatSize(t.transferred)} / {formatSize(t.total_size)}</td>
              <td class="actions">
                {#if t.status === 'active'}
                  <button class="ghost" onclick={() => pauseTransfer(t.id)}>⏸</button>
                {:else if t.status === 'paused'}
                  <button class="ghost" onclick={() => resumeTransfer(t.id)}>▶</button>
                {/if}
                <button class="ghost danger" onclick={() => cancelTransfer(t.id)}>✕</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}

    {#if completedTransfers.length > 0}
      <div class="section-header">History</div>
      <table>
        <thead>
          <tr>
            <th>File</th>
            <th>Direction</th>
            <th>Status</th>
            <th>Size</th>
          </tr>
        </thead>
        <tbody>
          {#each completedTransfers as t (t.id)}
            <tr>
              <td>{t.file_name}</td>
              <td><span class="badge {t.direction}">{t.direction}</span></td>
              <td><span class="badge {t.status}">{t.status}</span></td>
              <td>{formatSize(t.total_size)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</div>

<style>
  .count {
    font-size: 13px;
    color: var(--text-muted);
  }

  .section-header {
    padding: 10px 20px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    background: var(--bg-primary);
    border-bottom: 1px solid var(--border);
  }

  .progress-cell {
    min-width: 150px;
  }

  .actions {
    display: flex;
    gap: 4px;
  }

  .sub {
    font-size: 13px;
    color: var(--text-muted);
  }

  .searching-label {
    font-size: 12px;
    color: var(--warning, #f0ad4e);
    font-style: italic;
    animation: pulse 1.5s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
</style>
