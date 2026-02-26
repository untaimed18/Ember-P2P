<script lang="ts">
  import ProgressBar from '$lib/components/ProgressBar.svelte';
  import { transfers, startTransferPoll } from '$lib/stores/transfers';
  import { pauseTransfer, resumeTransfer, cancelTransfer, removeTransfer, clearCompleted } from '$lib/api/transfers';
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

  let activeDownloads = $derived(
    $transfers.filter((t) => t.direction === 'download' && t.status !== 'completed' && t.status !== 'failed')
  );
  let completedDownloads = $derived(
    $transfers.filter((t) => t.direction === 'download' && (t.status === 'completed' || t.status === 'failed'))
  );
  let activeUploads = $derived(
    $transfers.filter((t) => t.direction === 'upload' && t.status !== 'completed' && t.status !== 'failed')
  );
  let completedUploads = $derived(
    $transfers.filter((t) => t.direction === 'upload' && (t.status === 'completed' || t.status === 'failed'))
  );
  let totalActive = $derived(activeDownloads.length + activeUploads.length);
  let hasCompleted = $derived(completedDownloads.length + completedUploads.length > 0);

  async function handlePause(id: string) {
    try { await pauseTransfer(id); } catch (e: unknown) { transferError = toErrorMsg(e); }
  }
  async function handleResume(id: string) {
    try { await resumeTransfer(id); } catch (e: unknown) { transferError = toErrorMsg(e); }
  }
  async function handleCancel(id: string) {
    try { await cancelTransfer(id); } catch (e: unknown) { transferError = toErrorMsg(e); }
  }
  async function handleRemove(id: string) {
    try { await removeTransfer(id); } catch (e: unknown) { transferError = toErrorMsg(e); }
  }
  async function handleFindSources(hash: string, size: number) {
    try { await findSources(hash, size); } catch (e: unknown) { transferError = toErrorMsg(e); }
  }
  async function handleClearCompleted() {
    try { await clearCompleted(); } catch (e: unknown) { transferError = toErrorMsg(e); }
  }
</script>

<div class="page-header">
  <h2>Transfers</h2>
  <div class="header-actions">
    <span class="count">{totalActive} active</span>
    {#if hasCompleted}
      <button class="ghost" onclick={handleClearCompleted}>
        Clear Completed
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
    <!-- Downloads Panel -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">⬇ Downloads</span>
        <span class="panel-count">{activeDownloads.length} active · {completedDownloads.length} completed</span>
      </div>

      {#if activeDownloads.length === 0 && completedDownloads.length === 0}
        <div class="panel-empty">No downloads</div>
      {:else}
        {#if activeDownloads.length > 0}
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Progress</th>
                <th>Speed</th>
                <th>Size</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each activeDownloads as t (t.id)}
                <tr>
                  <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                  <td class="progress-cell">
                    {#if t.status === 'searching'}
                      <span class="searching-label">Searching...</span>
                    {:else}
                      <ProgressBar
                        value={t.progress}
                        color={t.status === 'paused' ? 'var(--warning)' : 'var(--accent)'}
                      />
                    {/if}
                  </td>
                  <td>{t.status === 'active' ? formatSpeed(t.speed) : '—'}</td>
                  <td>{formatSize(t.transferred)} / {formatSize(t.total_size)}</td>
                  <td><span class="badge {t.status}">{t.status}</span></td>
                  <td class="actions">
                    {#if t.status === 'active'}
                      <button class="action-btn" onclick={() => handlePause(t.id)} title="Pause">⏸</button>
                    {:else if t.status === 'paused'}
                      <button class="action-btn" onclick={() => handleResume(t.id)} title="Resume">▶</button>
                    {/if}
                    {#if t.status === 'searching' || t.status === 'queued'}
                      <button class="action-btn" onclick={() => handleFindSources(t.file_hash, t.total_size)} title="Find more sources">🔍</button>
                    {/if}
                    {#if t.status !== 'active'}
                      <button class="action-btn danger" onclick={() => handleCancel(t.id)} title="Cancel and remove">✕</button>
                    {:else}
                      <button class="action-btn danger" onclick={() => handleCancel(t.id)} title="Cancel download">✕</button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}

        {#if completedDownloads.length > 0}
          <div class="section-divider">Completed</div>
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Status</th>
                <th>Size</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each completedDownloads as t (t.id)}
                <tr>
                  <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                  <td><span class="badge {t.status}">{t.status}</span></td>
                  <td>{formatSize(t.total_size)}</td>
                  <td class="actions">
                    <button class="action-btn danger" onclick={() => handleRemove(t.id)} title="Remove from list">✕</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      {/if}
    </div>

    <!-- Uploads Panel -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">⬆ Uploads</span>
        <span class="panel-count">{activeUploads.length} active · {completedUploads.length} completed</span>
      </div>

      {#if activeUploads.length === 0 && completedUploads.length === 0}
        <div class="panel-empty">No uploads</div>
      {:else}
        {#if activeUploads.length > 0}
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Progress</th>
                <th>Speed</th>
                <th>Size</th>
                <th>Peer</th>
              </tr>
            </thead>
            <tbody>
              {#each activeUploads as t (t.id)}
                <tr>
                  <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                  <td class="progress-cell">
                    <ProgressBar value={t.progress} color="var(--success, #2ecc71)" />
                  </td>
                  <td>{t.status === 'active' ? formatSpeed(t.speed) : '—'}</td>
                  <td>{formatSize(t.transferred)} / {formatSize(t.total_size)}</td>
                  <td class="peer-cell" title={t.peer_name || t.peer_id}>{t.peer_name || t.peer_id || '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}

        {#if completedUploads.length > 0}
          <div class="section-divider">Completed</div>
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Status</th>
                <th>Size</th>
                <th>Peer</th>
              </tr>
            </thead>
            <tbody>
              {#each completedUploads as t (t.id)}
                <tr>
                  <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                  <td><span class="badge {t.status}">{t.status}</span></td>
                  <td>{formatSize(t.total_size)}</td>
                  <td class="peer-cell" title={t.peer_name || t.peer_id}>{t.peer_name || t.peer_id || '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      {/if}
    </div>
  {/if}
</div>

<style>
  .count {
    font-size: 13px;
    color: var(--text-muted);
  }

  .panel {
    border: 1px solid var(--border);
    border-radius: 8px;
    margin: 12px 16px;
    overflow: hidden;
    background: var(--bg-secondary);
  }

  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 16px;
    background: var(--bg-primary);
    border-bottom: 1px solid var(--border);
  }

  .panel-title {
    font-weight: 600;
    font-size: 14px;
  }

  .panel-count {
    font-size: 12px;
    color: var(--text-muted);
  }

  .panel-empty {
    padding: 24px 16px;
    text-align: center;
    color: var(--text-muted);
    font-size: 13px;
  }

  .section-divider {
    padding: 6px 16px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    background: var(--bg-primary);
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }

  .progress-cell {
    min-width: 120px;
    width: 20%;
  }

  .name-cell {
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .peer-cell {
    max-width: 140px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .actions {
    display: flex;
    gap: 2px;
  }

  .action-btn {
    background: none;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 2px 8px;
    cursor: pointer;
    font-size: 13px;
    color: var(--text);
    transition: background 0.15s, border-color 0.15s;
  }

  .action-btn:hover {
    background: var(--bg-primary);
    border-color: var(--text-muted);
  }

  .action-btn.danger {
    color: var(--danger, #e74c3c);
  }

  .action-btn.danger:hover {
    background: color-mix(in srgb, var(--danger, #e74c3c) 10%, transparent);
    border-color: var(--danger, #e74c3c);
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
