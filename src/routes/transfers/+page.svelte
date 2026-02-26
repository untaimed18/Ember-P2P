<script lang="ts">
  import ProgressBar from '$lib/components/ProgressBar.svelte';
  import { transfers, startTransferPoll } from '$lib/stores/transfers';
  import { pauseTransfer, resumeTransfer, cancelTransfer, clearCompleted } from '$lib/api/transfers';
  import { findSources } from '$lib/api/search';
  import { formatSize, formatSpeed } from '$lib/utils';
  import { onMount } from 'svelte';

  onMount(() => {
    const stop = startTransferPoll();
    return () => stop();
  });

  let transferError: string | null = $state(null);

  function toErrorMsg(e: unknown): string {
    return e instanceof Error ? e.message : typeof e === 'string' ? e : 'Operation failed';
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
  <div class="header-actions">
    <span class="count">{activeTransfers.length} active</span>
    {#if completedTransfers.length > 0}
      <button class="ghost" onclick={async () => { try { await clearCompleted(); } catch (e) { transferError = toErrorMsg(e); } }}>
        Clear Completed ({completedTransfers.length})
      </button>
    {/if}
  </div>
</div>

<div class="page-content">
  {#if transferError}
    <div class="error-banner">
      <span>{transferError}</span>
      <button class="ghost" onclick={() => transferError = null}>Dismiss</button>
    </div>
  {/if}
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
                  <button class="ghost" onclick={async () => { try { await pauseTransfer(t.id); } catch (e) { transferError = toErrorMsg(e); } }}>⏸</button>
                {:else if t.status === 'paused'}
                  <button class="ghost" onclick={async () => { try { await resumeTransfer(t.id); } catch (e) { transferError = toErrorMsg(e); } }}>▶</button>
                {/if}
                {#if t.direction === 'download' && (t.status === 'searching' || t.status === 'queued')}
                  <button class="ghost" onclick={async () => { try { await findSources(t.file_hash, t.total_size); } catch (e) { transferError = toErrorMsg(e); } }} title="Find more sources">🔍</button>
                {/if}
                <button class="ghost danger" onclick={async () => { try { await cancelTransfer(t.id); } catch (e) { transferError = toErrorMsg(e); } }}>✕</button>
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

  .error-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 20px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--danger, #e74c3c);
    color: var(--danger, #e74c3c);
    font-size: 13px;
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
