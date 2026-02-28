<script lang="ts">
  import ProgressBar from '$lib/components/ProgressBar.svelte';
  import { transfers, startTransferPoll } from '$lib/stores/transfers';
  import {
    pauseTransfer, resumeTransfer, cancelTransfer, removeTransfer,
    clearCompleted, setTransferPriority, pauseAllTransfers, resumeAllTransfers,
    getTransferSources,
  } from '$lib/api/transfers';
  import { findSources } from '$lib/api/search';
  import { previewFile } from '$lib/api/preview';
  import { formatSize, formatSpeed, formatEta, formatDate } from '$lib/utils';
  import { onMount, onDestroy } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import type { UnlistenFn } from '@tauri-apps/api/event';
  import type { Transfer, SourceInfo } from '$lib/types';

  let sourceUnlisten: UnlistenFn | null = $state(null);

  onMount(() => {
    const stop = startTransferPoll();
    listen<{
      transfer_id: string; ip: string; port: number; status: string;
      queue_rank?: number; speed: number; transferred: number; client_software: string;
    }>('transfer-source-detail', (event) => {
      const d = event.payload;
      // Update queue rank on the main transfer row
      if (d.queue_rank) {
        transfers.update((list) =>
          list.map((t) => t.id === d.transfer_id ? { ...t, queue_rank: d.queue_rank } : t)
        );
      }
      if (d.transfer_id !== expandedTransferId) return;
      expandedSources = expandedSources.map((s) => {
        if (s.ip === d.ip && s.port === d.port) {
          return { ...s, status: d.status as SourceInfo['status'], queue_rank: d.queue_rank, speed: d.speed, transferred: d.transferred, client_software: d.client_software || s.client_software };
        }
        return s;
      });
      if (!expandedSources.some((s) => s.ip === d.ip && s.port === d.port)) {
        expandedSources = [...expandedSources, { ip: d.ip, port: d.port, status: d.status as SourceInfo['status'], queue_rank: d.queue_rank, speed: d.speed, transferred: d.transferred, client_software: d.client_software }];
      }
    }).then((u) => { sourceUnlisten = u; });
    return () => stop();
  });

  onDestroy(() => { sourceUnlisten?.(); });

  let transferError: string | null = $state(null);

  // --- Source detail panel (eMule-style) ---
  let expandedTransferId: string | null = $state(null);
  let expandedSources: SourceInfo[] = $state([]);
  let loadingSources = $state(false);

  async function toggleSourceDetail(t: Transfer) {
    if (expandedTransferId === t.id) {
      expandedTransferId = null;
      expandedSources = [];
      return;
    }
    expandedTransferId = t.id;
    loadingSources = true;
    try {
      expandedSources = await getTransferSources(t.id);
    } catch {
      expandedSources = [];
    }
    loadingSources = false;
  }

  function sourceStatusLabel(s: SourceInfo): string {
    switch (s.status) {
      case 'connecting': return 'Connecting';
      case 'queued': return s.queue_rank ? `QR: ${s.queue_rank}` : 'Queued';
      case 'transferring': return 'Transferring';
      case 'completed': return 'Done';
      case 'failed': return 'Failed';
      default: return s.status;
    }
  }

  function toErrorMsg(e: unknown): string {
    return e instanceof Error ? e.message : typeof e === 'string' ? e : 'Operation failed';
  }

  // --- Downloads ---
  let allDownloads = $derived($transfers.filter(t => t.direction === 'download'));
  let activeDownloads = $derived(allDownloads.filter(t => t.status !== 'completed' && t.status !== 'failed'));
  let completedDownloads = $derived(allDownloads.filter(t => t.status === 'completed' || t.status === 'failed'));
  let hasCompletedDl = $derived(completedDownloads.length > 0);

  // --- Uploads ---
  let allUploads = $derived($transfers.filter(t => t.direction === 'upload'));
  let activeUploads = $derived(allUploads.filter(t => t.status !== 'completed' && t.status !== 'failed'));
  let completedUploads = $derived(allUploads.filter(t => t.status === 'completed' || t.status === 'failed'));

  // --- Sorting ---
  type DlSortField = 'file_name' | 'total_size' | 'transferred' | 'speed' | 'progress' | 'sources' | 'priority' | 'status' | 'remaining' | 'started_at';
  type UlSortField = 'peer_name' | 'file_name' | 'speed' | 'transferred' | 'status';
  let dlSortField: DlSortField = $state('file_name');
  let dlSortAsc = $state(true);
  let ulSortField: UlSortField = $state('file_name');
  let ulSortAsc = $state(true);

  function toggleDlSort(field: DlSortField) {
    if (dlSortField === field) dlSortAsc = !dlSortAsc;
    else { dlSortField = field; dlSortAsc = true; }
  }
  function toggleUlSort(field: UlSortField) {
    if (ulSortField === field) ulSortAsc = !ulSortAsc;
    else { ulSortField = field; ulSortAsc = true; }
  }
  function sortArrow(current: string, field: string, asc: boolean): string {
    if (current !== field) return '';
    return asc ? ' \u25B2' : ' \u25BC';
  }

  const priorityOrder: Record<string, number> = { auto: 0, high: 1, normal: 2, low: 3 };
  const statusOrder: Record<string, number> = { active: 0, verifying: 1, searching: 2, queued: 3, paused: 4, failed: 5, completed: 6 };

  function etaSeconds(t: Transfer): number {
    if (t.speed <= 0 || t.transferred >= t.total_size) return Infinity;
    return (t.total_size - t.transferred) / t.speed;
  }

  let sortedActiveDownloads = $derived.by(() => {
    const sorted = [...activeDownloads];
    sorted.sort((a, b) => {
      let cmp = 0;
      switch (dlSortField) {
        case 'file_name': cmp = a.file_name.localeCompare(b.file_name); break;
        case 'total_size': cmp = a.total_size - b.total_size; break;
        case 'transferred': cmp = a.transferred - b.transferred; break;
        case 'speed': cmp = a.speed - b.speed; break;
        case 'progress': cmp = a.progress - b.progress; break;
        case 'sources': cmp = a.sources - b.sources; break;
        case 'priority': cmp = (priorityOrder[a.priority] ?? 2) - (priorityOrder[b.priority] ?? 2); break;
        case 'status': cmp = (statusOrder[a.status] ?? 9) - (statusOrder[b.status] ?? 9); break;
        case 'remaining': cmp = etaSeconds(a) - etaSeconds(b); break;
        case 'started_at': cmp = a.started_at - b.started_at; break;
      }
      return dlSortAsc ? cmp : -cmp;
    });
    return sorted;
  });

  let sortedActiveUploads = $derived.by(() => {
    const sorted = [...activeUploads];
    sorted.sort((a, b) => {
      let cmp = 0;
      switch (ulSortField) {
        case 'peer_name': cmp = (a.peer_name || a.peer_id).localeCompare(b.peer_name || b.peer_id); break;
        case 'file_name': cmp = a.file_name.localeCompare(b.file_name); break;
        case 'speed': cmp = a.speed - b.speed; break;
        case 'transferred': cmp = a.transferred - b.transferred; break;
        case 'status': cmp = (statusOrder[a.status] ?? 9) - (statusOrder[b.status] ?? 9); break;
      }
      return ulSortAsc ? cmp : -cmp;
    });
    return sorted;
  });

  // --- eMule-style status labels ---
  function dlStatusLabel(t: Transfer): string {
    switch (t.status) {
      case 'active': return 'Downloading';
      case 'searching': return t.sources > 0 ? `Searching (${t.sources} src)` : 'Searching';
      case 'queued': return t.queue_rank ? `Queued (QR: ${t.queue_rank})` : 'Waiting';
      case 'paused': return 'Paused';
      case 'verifying': return 'Verifying';
      case 'completed': return 'Complete';
      case 'failed': return 'Error';
      default: return t.status;
    }
  }
  function sourcesLabel(t: Transfer): string {
    if (!t.sources) return '\u2014';
    const active = t.active_sources || 0;
    const queued = t.queued_sources || 0;
    const current = active + queued;
    if (current > 0 && current !== t.sources) return `${current}/${t.sources}`;
    return `${t.sources}`;
  }

  function ulStatusLabel(t: Transfer): string {
    switch (t.status) {
      case 'active': return 'Transferring';
      case 'completed': return 'Complete';
      case 'failed': return 'Error';
      default: return t.status;
    }
  }

  // --- Context menu ---
  let ctxMenu: { x: number; y: number; transfer: Transfer; section: 'active' | 'completed' | 'upload' } | null = $state(null);
  let ctxPrioritySub = $state(false);

  function onCtx(e: MouseEvent, t: Transfer, section: 'active' | 'completed' | 'upload') {
    e.preventDefault();
    ctxPrioritySub = false;
    ctxMenu = { x: e.clientX, y: e.clientY, transfer: t, section };
  }
  function closeCtx() { ctxMenu = null; ctxPrioritySub = false; }

  function onDocClick() { closeCtx(); }

  async function ctxAction(action: string, extra?: string) {
    if (!ctxMenu) return;
    const t = ctxMenu.transfer;
    closeCtx();
    try {
      switch (action) {
        case 'pause': await pauseTransfer(t.id); break;
        case 'resume': await resumeTransfer(t.id); break;
        case 'cancel': await cancelTransfer(t.id); break;
        case 'remove': await removeTransfer(t.id); break;
        case 'priority': if (extra) await setTransferPriority(t.id, extra); break;
        case 'find_sources': await findSources(t.file_hash, t.total_size); break;
        case 'preview': await previewFile(t.id); break;
        case 'copy_link': {
          const link = `ed2k://|file|${encodeURIComponent(t.file_name)}|${t.total_size}|${t.file_hash}|/`;
          await navigator.clipboard.writeText(link);
          break;
        }
      }
    } catch (e: unknown) { transferError = toErrorMsg(e); }
  }

  // --- Bulk actions ---
  async function handlePauseAll() {
    try { await pauseAllTransfers(); } catch (e: unknown) { transferError = toErrorMsg(e); }
  }
  async function handleResumeAll() {
    try { await resumeAllTransfers(); } catch (e: unknown) { transferError = toErrorMsg(e); }
  }
  async function handleClearCompleted() {
    try { await clearCompleted(); } catch (e: unknown) { transferError = toErrorMsg(e); }
  }

  // --- Splitter ---
  let splitPercent = $state(60);
  let dragging = $state(false);
  let containerEl: HTMLDivElement | undefined = $state(undefined);

  onMount(() => {
    const saved = localStorage.getItem('transfers-split');
    if (saved) splitPercent = Math.max(20, Math.min(80, parseFloat(saved)));
  });

  let dragCleanup: (() => void) | null = $state(null);

  function onSplitterDown(e: MouseEvent) {
    e.preventDefault();
    dragging = true;
    const onMove = (ev: MouseEvent) => {
      if (!containerEl) return;
      const rect = containerEl.getBoundingClientRect();
      splitPercent = Math.max(20, Math.min(80, ((ev.clientY - rect.top) / rect.height) * 100));
    };
    const onUp = () => {
      dragging = false;
      localStorage.setItem('transfers-split', String(splitPercent));
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      dragCleanup = null;
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    dragCleanup = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }

  onDestroy(() => { dragCleanup?.(); });
</script>

<svelte:document onclick={onDocClick} />

<div class="page-header">
  <h2>Transfers</h2>
</div>

{#if transferError}
  <div class="error-banner">
    <span>{transferError}</span>
    <button class="ghost" onclick={() => transferError = null}>Dismiss</button>
  </div>
{/if}

<div class="transfers-split" bind:this={containerEl}>
  <!-- TOP PANE: Downloads -->
  <div class="pane downloads-pane" style="flex: 0 0 {splitPercent}%;">
    <div class="pane-toolbar">
      <span class="pane-title">{activeDownloads.length} downloading</span>
      <div class="toolbar-actions">
        <button class="tb-btn" onclick={handlePauseAll} title="Pause All">Pause All</button>
        <button class="tb-btn" onclick={handleResumeAll} title="Resume All">Resume All</button>
        {#if hasCompletedDl}
          <button class="tb-btn" onclick={handleClearCompleted} title="Clear Completed">Clear Completed</button>
        {/if}
      </div>
    </div>
    <div class="pane-content">
      <table class="transfer-table">
        <thead>
          <tr>
            <th class="col-name sortable" onclick={() => toggleDlSort('file_name')}>Filename{sortArrow(dlSortField, 'file_name', dlSortAsc)}</th>
            <th class="col-size sortable" onclick={() => toggleDlSort('total_size')}>Size{sortArrow(dlSortField, 'total_size', dlSortAsc)}</th>
            <th class="col-size sortable" onclick={() => toggleDlSort('transferred')}>Transferred{sortArrow(dlSortField, 'transferred', dlSortAsc)}</th>
            <th class="col-speed sortable" onclick={() => toggleDlSort('speed')}>Speed{sortArrow(dlSortField, 'speed', dlSortAsc)}</th>
            <th class="col-progress sortable" onclick={() => toggleDlSort('progress')}>Progress{sortArrow(dlSortField, 'progress', dlSortAsc)}</th>
            <th class="col-num sortable" onclick={() => toggleDlSort('sources')}>Sources{sortArrow(dlSortField, 'sources', dlSortAsc)}</th>
            <th class="col-prio sortable" onclick={() => toggleDlSort('priority')}>Priority{sortArrow(dlSortField, 'priority', dlSortAsc)}</th>
            <th class="col-status sortable" onclick={() => toggleDlSort('status')}>Status{sortArrow(dlSortField, 'status', dlSortAsc)}</th>
            <th class="col-eta sortable" onclick={() => toggleDlSort('remaining')}>Remaining{sortArrow(dlSortField, 'remaining', dlSortAsc)}</th>
            <th class="col-date sortable" onclick={() => toggleDlSort('started_at')}>Added On{sortArrow(dlSortField, 'started_at', dlSortAsc)}</th>
          </tr>
        </thead>
        <tbody>
          {#each sortedActiveDownloads as t (t.id)}
            <tr
              class="dl-row {t.status}"
              class:expanded={expandedTransferId === t.id}
              oncontextmenu={(e) => onCtx(e, t, 'active')}
              ondblclick={() => toggleSourceDetail(t)}
            >
              <td class="name-cell" title={t.file_name}>{t.file_name}</td>
              <td class="num-cell">{formatSize(t.total_size)}</td>
              <td class="num-cell">{formatSize(t.transferred)}</td>
              <td class="num-cell">{t.status === 'active' ? formatSpeed(t.speed) : '\u2014'}</td>
              <td class="progress-cell">
                {#if t.status === 'searching'}
                  <span class="searching-label">Searching...</span>
                {:else}
                  <ProgressBar
                    value={t.progress}
                    color={t.status === 'paused' ? 'var(--warning)' : t.status === 'verifying' ? 'var(--success, #2ecc71)' : 'var(--accent)'}
                  />
                {/if}
              </td>
              <td class="num-cell" title={t.sources ? `${t.active_sources || 0} active, ${t.queued_sources || 0} queued of ${t.sources} total` : ''}>{sourcesLabel(t)}</td>
              <td class="prio-cell">
                <span class="prio-badge prio-{t.priority}">{t.priority.charAt(0).toUpperCase() + t.priority.slice(1)}</span>
              </td>
              <td class="status-cell">
                <span class="status-label st-{t.status}">{dlStatusLabel(t)}</span>
              </td>
              <td class="num-cell">{t.status === 'active' ? formatEta(t.total_size, t.transferred, t.speed) : '\u2014'}</td>
              <td class="date-cell">{formatDate(t.started_at)}</td>
            </tr>
            {#if expandedTransferId === t.id}
              <tr class="source-detail-row">
                <td colspan="10">
                  <div class="source-panel">
                    <div class="source-panel-header">Sources for {t.file_name}</div>
                    {#if loadingSources}
                      <div class="source-loading">Loading sources...</div>
                    {:else if expandedSources.length === 0}
                      <div class="source-empty">No source details available yet</div>
                    {:else}
                      <table class="source-table">
                        <thead>
                          <tr>
                            <th>IP</th>
                            <th>Port</th>
                            <th>Status</th>
                            <th>Queue Rank</th>
                            <th>Speed</th>
                            <th>Transferred</th>
                            <th>Client</th>
                          </tr>
                        </thead>
                        <tbody>
                          {#each expandedSources as src}
                            <tr class="src-row src-{src.status}">
                              <td>{src.ip}</td>
                              <td>{src.port}</td>
                              <td>
                                <span class="src-status src-st-{src.status}">{sourceStatusLabel(src)}</span>
                              </td>
                              <td class="num-cell">{src.queue_rank ?? '\u2014'}</td>
                              <td class="num-cell">{src.status === 'transferring' ? formatSpeed(src.speed) : '\u2014'}</td>
                              <td class="num-cell">{src.transferred > 0 ? formatSize(src.transferred) : '\u2014'}</td>
                              <td>{src.client_software || '\u2014'}</td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    {/if}
                  </div>
                </td>
              </tr>
            {/if}
          {/each}
          {#if completedDownloads.length > 0}
            <tr class="section-divider-row"><td colspan="10">Completed / Failed ({completedDownloads.length})</td></tr>
            {#each completedDownloads as t (t.id)}
              <tr class="dl-row completed-row {t.status}" oncontextmenu={(e) => onCtx(e, t, 'completed')}>
                <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                <td class="num-cell">{formatSize(t.total_size)}</td>
                <td class="num-cell">{formatSize(t.transferred)}</td>
                <td class="num-cell">{'\u2014'}</td>
                <td class="progress-cell">
                  <ProgressBar
                    value={t.progress}
                    color={t.status === 'failed' ? 'var(--danger, #e74c3c)' : 'var(--success, #2ecc71)'}
                  />
                </td>
                <td class="num-cell">{'\u2014'}</td>
                <td class="prio-cell">{'\u2014'}</td>
                <td class="status-cell">
                  <span class="status-label st-{t.status}">{dlStatusLabel(t)}</span>
                  {#if t.status === 'failed' && t.failure_reason}
                    <span class="failure-hint" title={t.failure_reason}>{t.failure_reason}</span>
                  {/if}
                </td>
                <td class="num-cell">{'\u2014'}</td>
                <td class="date-cell">{formatDate(t.started_at)}</td>
              </tr>
            {/each}
          {/if}
          {#if allDownloads.length === 0}
            <tr><td colspan="10" class="empty-cell">No downloads. Start one from the Search page.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
  </div>

  <!-- SPLITTER -->
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="splitter-bar"
    class:dragging
    role="separator"
    aria-orientation="horizontal"
    onmousedown={onSplitterDown}
  ></div>

  <!-- BOTTOM PANE: Uploads -->
  <div class="pane uploads-pane" style="flex: 1;">
    <div class="pane-toolbar">
      <span class="pane-title">{activeUploads.length} uploading</span>
    </div>
    <div class="pane-content">
      <table class="transfer-table">
        <thead>
          <tr>
            <th class="col-client sortable" onclick={() => toggleUlSort('peer_name')}>Client{sortArrow(ulSortField, 'peer_name', ulSortAsc)}</th>
            <th class="col-name sortable" onclick={() => toggleUlSort('file_name')}>Filename{sortArrow(ulSortField, 'file_name', ulSortAsc)}</th>
            <th class="col-speed sortable" onclick={() => toggleUlSort('speed')}>Speed{sortArrow(ulSortField, 'speed', ulSortAsc)}</th>
            <th class="col-size sortable" onclick={() => toggleUlSort('transferred')}>Transferred{sortArrow(ulSortField, 'transferred', ulSortAsc)}</th>
            <th class="col-status sortable" onclick={() => toggleUlSort('status')}>Status{sortArrow(ulSortField, 'status', ulSortAsc)}</th>
          </tr>
        </thead>
        <tbody>
          {#each sortedActiveUploads as t (t.id)}
            <tr class="ul-row" oncontextmenu={(e) => onCtx(e, t, 'upload')}>
              <td class="client-cell" title={t.peer_name || t.peer_id}>{t.peer_name || t.peer_id || '\u2014'}</td>
              <td class="name-cell" title={t.file_name}>{t.file_name}</td>
              <td class="num-cell">{t.status === 'active' ? formatSpeed(t.speed) : '\u2014'}</td>
              <td class="num-cell">{formatSize(t.transferred)}</td>
              <td class="status-cell"><span class="status-label st-{t.status}">{ulStatusLabel(t)}</span></td>
            </tr>
          {/each}
          {#if completedUploads.length > 0}
            <tr class="section-divider-row"><td colspan="5">Completed ({completedUploads.length})</td></tr>
            {#each completedUploads as t (t.id)}
              <tr class="ul-row completed-row">
                <td class="client-cell" title={t.peer_name || t.peer_id}>{t.peer_name || t.peer_id || '\u2014'}</td>
                <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                <td class="num-cell">{'\u2014'}</td>
                <td class="num-cell">{formatSize(t.transferred)}</td>
                <td class="status-cell"><span class="status-label st-{t.status}">{ulStatusLabel(t)}</span></td>
              </tr>
            {/each}
          {/if}
          {#if allUploads.length === 0}
            <tr><td colspan="5" class="empty-cell">No uploads</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Context Menu -->
{#if ctxMenu}
  <div class="context-menu" style="left: {ctxMenu.x}px; top: {ctxMenu.y}px;">
    {#if ctxMenu.section === 'active'}
      {#if ctxMenu.transfer.status === 'active'}
        <button class="ctx-item" onclick={() => ctxAction('pause')}>Pause</button>
      {:else if ctxMenu.transfer.status === 'paused'}
        <button class="ctx-item" onclick={() => ctxAction('resume')}>Resume</button>
      {/if}
      <button class="ctx-item danger" onclick={() => ctxAction('cancel')}>Cancel</button>
      <div class="ctx-sep"></div>
      <div class="ctx-submenu-wrap">
        <button class="ctx-item has-sub" onclick={() => ctxPrioritySub = !ctxPrioritySub}>
          Priority \u25B6
        </button>
        {#if ctxPrioritySub}
          <div class="ctx-submenu">
            <button class="ctx-item" class:ctx-active={ctxMenu.transfer.priority === 'low'} onclick={() => ctxAction('priority', 'low')}>Low</button>
            <button class="ctx-item" class:ctx-active={ctxMenu.transfer.priority === 'normal'} onclick={() => ctxAction('priority', 'normal')}>Normal</button>
            <button class="ctx-item" class:ctx-active={ctxMenu.transfer.priority === 'high'} onclick={() => ctxAction('priority', 'high')}>High</button>
            <button class="ctx-item" class:ctx-active={ctxMenu.transfer.priority === 'auto'} onclick={() => ctxAction('priority', 'auto')}>Auto</button>
          </div>
        {/if}
      </div>
      <div class="ctx-sep"></div>
      <button class="ctx-item" onclick={() => ctxAction('copy_link')}>Copy ED2K Link</button>
      <button class="ctx-item" onclick={() => ctxAction('find_sources')}>Find More Sources</button>
      <button class="ctx-item" onclick={() => ctxAction('preview')}>Preview File</button>
    {:else if ctxMenu.section === 'completed'}
      <button class="ctx-item" onclick={() => ctxAction('copy_link')}>Copy ED2K Link</button>
      <button class="ctx-item danger" onclick={() => ctxAction('remove')}>Remove from List</button>
    {:else}
      <button class="ctx-item" onclick={() => ctxAction('copy_link')}>Copy ED2K Link</button>
    {/if}
  </div>
{/if}

<style>
  /* --- Layout --- */
  .transfers-split {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .pane {
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: hidden;
  }
  .pane-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 4px 12px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    gap: 8px;
  }
  .pane-title {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
  }
  .toolbar-actions {
    display: flex;
    gap: 4px;
  }
  .tb-btn {
    font-size: 11px;
    padding: 2px 8px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-primary);
    color: var(--text-primary);
    cursor: pointer;
    transition: background 0.15s;
  }
  .tb-btn:hover {
    background: var(--bg-hover);
  }
  .pane-content {
    flex: 1;
    overflow: auto;
    min-height: 0;
  }

  /* --- Splitter --- */
  .splitter-bar {
    flex-shrink: 0;
    height: 5px;
    background: var(--border);
    cursor: row-resize;
    transition: background 0.1s;
  }
  .splitter-bar:hover, .splitter-bar.dragging {
    background: var(--accent);
  }

  /* --- Tables --- */
  .transfer-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    table-layout: fixed;
  }
  .transfer-table th {
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--bg-secondary);
    padding: 5px 8px;
    font-size: 11px;
    font-weight: 600;
    text-align: left;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
    user-select: none;
  }
  .transfer-table th.sortable {
    cursor: pointer;
  }
  .transfer-table th.sortable:hover {
    color: var(--text-primary);
  }
  .transfer-table td {
    padding: 4px 8px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 40%, transparent);
  }
  .transfer-table tbody tr:hover {
    background: var(--bg-hover);
  }

  /* Column widths */
  .col-name { width: 22%; }
  .col-size { width: 8%; }
  .col-speed { width: 8%; }
  .col-progress { width: 12%; min-width: 100px; }
  .col-num { width: 6%; }
  .col-prio { width: 7%; }
  .col-status { width: 9%; }
  .col-eta { width: 8%; }
  .col-date { width: 10%; }
  .col-client { width: 18%; }

  .name-cell {
    font-weight: 500;
    color: var(--text-primary);
  }
  .num-cell {
    text-align: right;
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
  }
  .client-cell {
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .date-cell {
    color: var(--text-muted);
    font-size: 11px;
  }
  .progress-cell {
    padding: 4px 6px;
  }
  .empty-cell {
    text-align: center;
    padding: 30px 16px !important;
    color: var(--text-muted);
    font-size: 13px;
  }

  /* --- Status labels --- */
  .status-cell { display: flex; flex-direction: column; gap: 1px; }
  .status-label {
    font-size: 11px;
    font-weight: 600;
  }
  .st-active { color: var(--accent); }
  .st-verifying { color: var(--success, #2ecc71); }
  .st-searching { color: var(--warning); }
  .st-queued { color: var(--text-muted); }
  .st-paused { color: var(--warning); }
  .st-completed { color: var(--success, #2ecc71); }
  .st-failed { color: var(--danger, #e74c3c); }
  .failure-hint {
    font-size: 10px;
    color: var(--danger, #e74c3c);
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 120px;
  }

  /* --- Priority badges --- */
  .prio-cell { text-align: center; }
  .prio-badge {
    font-size: 11px;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 3px;
  }
  .prio-high { color: var(--danger, #e74c3c); }
  .prio-normal { color: var(--text-secondary); }
  .prio-low { color: var(--text-muted); }
  .prio-auto { color: var(--accent); }

  /* --- Section divider --- */
  .section-divider-row td {
    background: var(--bg-secondary);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    padding: 4px 8px !important;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }

  .completed-row { opacity: 0.7; }
  .searching-label {
    font-size: 11px;
    color: var(--warning);
    font-style: italic;
    animation: pulse 1.5s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  /* --- Error banner --- */
  .error-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 16px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--danger, #e74c3c);
    color: var(--danger, #e74c3c);
    font-size: 12px;
    flex-shrink: 0;
  }

  /* --- Context Menu --- */
  .context-menu {
    position: fixed;
    z-index: 1000;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.25);
    padding: 4px 0;
    min-width: 160px;
  }
  .ctx-item {
    display: block;
    width: 100%;
    text-align: left;
    padding: 6px 14px;
    font-size: 12px;
    background: none;
    border: none;
    color: var(--text-primary);
    cursor: pointer;
    white-space: nowrap;
  }
  .ctx-item:hover { background: var(--bg-hover); }
  .ctx-item.danger { color: var(--danger, #e74c3c); }
  .ctx-item.has-sub { display: flex; justify-content: space-between; }
  .ctx-active { font-weight: 700; }
  .ctx-sep {
    height: 1px;
    background: var(--border);
    margin: 3px 0;
  }
  .ctx-submenu-wrap { position: relative; }
  .ctx-submenu {
    position: absolute;
    left: 100%;
    top: -4px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.25);
    padding: 4px 0;
    min-width: 100px;
  }

  /* --- Source detail panel (eMule-style) --- */
  .dl-row.expanded {
    background: color-mix(in srgb, var(--accent) 8%, transparent);
  }
  .dl-row {
    cursor: default;
  }
  .source-detail-row td {
    padding: 0 !important;
    border-bottom: 2px solid var(--accent);
  }
  .source-panel {
    background: color-mix(in srgb, var(--bg-secondary) 80%, var(--bg-primary));
    padding: 6px 12px 8px;
  }
  .source-panel-header {
    font-size: 11px;
    font-weight: 600;
    color: var(--text-secondary);
    margin-bottom: 4px;
    padding-bottom: 3px;
    border-bottom: 1px solid var(--border);
  }
  .source-loading, .source-empty {
    font-size: 11px;
    color: var(--text-muted);
    padding: 8px 0;
    text-align: center;
    font-style: italic;
  }
  .source-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 11px;
    table-layout: auto;
  }
  .source-table th {
    background: color-mix(in srgb, var(--bg-secondary) 60%, transparent);
    padding: 3px 8px;
    font-size: 10px;
    font-weight: 600;
    text-align: left;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  .source-table td {
    padding: 3px 8px;
    white-space: nowrap;
    color: var(--text-secondary);
    border-bottom: 1px solid color-mix(in srgb, var(--border) 30%, transparent);
  }
  .source-table tbody tr:hover {
    background: color-mix(in srgb, var(--accent) 6%, transparent);
  }
  .src-status {
    font-weight: 600;
    font-size: 10px;
  }
  .src-st-connecting { color: var(--warning); }
  .src-st-queued { color: var(--text-muted); }
  .src-st-transferring { color: var(--accent); }
  .src-st-completed { color: var(--success, #2ecc71); }
  .src-st-failed { color: var(--danger, #e74c3c); }
</style>
