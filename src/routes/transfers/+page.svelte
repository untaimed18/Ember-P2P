<script lang="ts">
  import ProgressBar from '$lib/components/ProgressBar.svelte';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import { transfers, startTransferPoll } from '$lib/stores/transfers';
  import {
    pauseTransfer, stopTransfer, resumeTransfer, cancelTransfer, removeTransfer,
    clearCompleted, setTransferPriority, setPreviewPriority, pauseAllTransfers, resumeAllTransfers,
    getTransferSources, openFile, recoverArchive,
  } from '$lib/api/transfers';
  import { findSources } from '$lib/api/search';
  import { previewFile } from '$lib/api/preview';
  import { formatSize, formatSpeed, formatDate, formatDuration, formatRemaining } from '$lib/utils';
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
  let confirmCancel: { open: boolean; id: string; name: string } = $state({ open: false, id: '', name: '' });
  let confirmClearCompleted = $state(false);

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

  // --- Bottom pane view tabs (eMule style) ---
  type BottomView = 'uploading' | 'on_queue' | 'download_clients';
  let bottomView: BottomView = $state('uploading');

  // --- Sorting ---
  type DlSortField = 'file_name' | 'total_size' | 'transferred' | 'completed_size' | 'speed' | 'progress' | 'sources' | 'priority' | 'status' | 'remaining' | 'last_seen_complete' | 'last_received' | 'category' | 'started_at';
  type UlSortField = 'peer_name' | 'file_name' | 'speed' | 'transferred' | 'waited' | 'upload_time' | 'status';
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
  const statusOrder: Record<string, number> = { active: 0, verifying: 1, completing: 2, searching: 3, queued: 4, paused: 5, stopped: 6, hashing: 7, noneneeded: 8, insufficient: 9, failed: 10, completed: 11 };

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
        case 'completed_size': cmp = (a.completed_size || 0) - (b.completed_size || 0); break;
        case 'speed': cmp = a.speed - b.speed; break;
        case 'progress': cmp = a.progress - b.progress; break;
        case 'sources': cmp = a.sources - b.sources; break;
        case 'priority': cmp = (priorityOrder[a.priority] ?? 2) - (priorityOrder[b.priority] ?? 2); break;
        case 'status': cmp = (statusOrder[a.status] ?? 9) - (statusOrder[b.status] ?? 9); break;
        case 'remaining': cmp = etaSeconds(a) - etaSeconds(b); break;
        case 'last_seen_complete': cmp = (a.last_seen_complete ?? 0) - (b.last_seen_complete ?? 0); break;
        case 'last_received': cmp = (a.last_received ?? 0) - (b.last_received ?? 0); break;
        case 'category': cmp = (a.category || '').localeCompare(b.category || ''); break;
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
        case 'waited': cmp = (a.wait_time || 0) - (b.wait_time || 0); break;
        case 'upload_time': cmp = (a.upload_time || 0) - (b.upload_time || 0); break;
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
      case 'stopped': return 'Stopped';
      case 'verifying': return 'Verifying';
      case 'completing': return 'Completing';
      case 'completed': return 'Complete';
      case 'failed': return 'Error';
      case 'hashing': return 'Hashing';
      case 'insufficient': return 'Insufficient Disk';
      case 'noneneeded': return 'No Needed Parts';
      default: return t.status;
    }
  }

  function sourcesLabel(t: Transfer): string {
    if (!t.sources) return '\u2014';
    const active = t.active_sources || 0;
    const queued = t.queued_sources || 0;
    const current = active + queued;
    let label: string;
    if (active > 0 && current !== t.sources) {
      label = `${current}/${t.sources}`;
    } else {
      label = `${t.sources}`;
    }
    if (t.a4af_sources > 0) label += `+${t.a4af_sources}`;
    if (t.max_sources > 0) label += ` [${t.max_sources}]`;
    return label;
  }

  function ulStatusLabel(t: Transfer): string {
    switch (t.status) {
      case 'active': return 'Transferring';
      case 'completed': return 'Complete';
      case 'failed': return 'Error';
      default: return t.status;
    }
  }

  function canPause(t: Transfer): boolean {
    return t.status === 'active' || t.status === 'searching' || t.status === 'queued';
  }

  function canStop(t: Transfer): boolean {
    return t.status !== 'completed' && t.status !== 'failed' && t.status !== 'stopped';
  }

  function canResume(t: Transfer): boolean {
    return t.status === 'paused' || t.status === 'stopped' || t.status === 'insufficient';
  }

  const archiveExts = ['zip', 'cbz', 'jar', 'rar', 'cbr', 'ace'];
  function isArchive(t: Transfer): boolean {
    const ext = t.file_name.split('.').pop()?.toLowerCase() ?? '';
    return archiveExts.includes(ext);
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
        case 'stop': await stopTransfer(t.id); break;
        case 'resume': await resumeTransfer(t.id); break;
        case 'cancel': confirmCancel = { open: true, id: t.id, name: t.file_name }; return;
        case 'remove': await removeTransfer(t.id); transfers.update((list) => list.filter((x) => x.id !== t.id)); break;
        case 'open': await openFile(t.id); break;
        case 'priority': if (extra) await setTransferPriority(t.id, extra); break;
        case 'find_sources': await findSources(t.file_hash, t.total_size); break;
        case 'preview': await previewFile(t.id); break;
        case 'toggle_preview_prio': await setPreviewPriority(t.id, !t.preview_priority); break;
        case 'recover_archive': {
          const path = await recoverArchive(t.id);
          transferError = `Archive recovered: ${path}`;
          break;
        }
        case 'clear_completed': confirmClearCompleted = true; return;
        case 'copy_link': {
          const link = `ed2k://|file|${encodeURIComponent(t.file_name)}|${t.total_size}|${t.file_hash}|/`;
          await navigator.clipboard.writeText(link);
          break;
        }
        case 'paste_link': {
          const text = await navigator.clipboard.readText();
          if (text.startsWith('ed2k://')) {
            // Dispatch to the ed2k link handler (reuse search page logic)
            window.dispatchEvent(new CustomEvent('paste-ed2k-link', { detail: text }));
          }
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
    try { await clearCompleted(); transfers.update((list) => list.filter((x) => x.status !== 'completed' && x.status !== 'failed')); } catch (e: unknown) { transferError = toErrorMsg(e); }
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

  const DL_COL_COUNT = 14;
  const UL_COL_COUNT = 8;
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
      <table class="transfer-table dl-table">
        <thead>
          <tr>
            <th class="col-dl-name sortable" onclick={() => toggleDlSort('file_name')}>File Name{sortArrow(dlSortField, 'file_name', dlSortAsc)}</th>
            <th class="col-dl-size sortable" onclick={() => toggleDlSort('total_size')}>Size{sortArrow(dlSortField, 'total_size', dlSortAsc)}</th>
            <th class="col-dl-size sortable" onclick={() => toggleDlSort('transferred')}>Transferred{sortArrow(dlSortField, 'transferred', dlSortAsc)}</th>
            <th class="col-dl-size sortable" onclick={() => toggleDlSort('completed_size')}>Completed{sortArrow(dlSortField, 'completed_size', dlSortAsc)}</th>
            <th class="col-dl-speed sortable" onclick={() => toggleDlSort('speed')}>Speed{sortArrow(dlSortField, 'speed', dlSortAsc)}</th>
            <th class="col-dl-progress sortable" onclick={() => toggleDlSort('progress')}>Progress{sortArrow(dlSortField, 'progress', dlSortAsc)}</th>
            <th class="col-dl-sources sortable" onclick={() => toggleDlSort('sources')}>Sources{sortArrow(dlSortField, 'sources', dlSortAsc)}</th>
            <th class="col-dl-prio sortable" onclick={() => toggleDlSort('priority')}>Priority{sortArrow(dlSortField, 'priority', dlSortAsc)}</th>
            <th class="col-dl-status sortable" onclick={() => toggleDlSort('status')}>Status{sortArrow(dlSortField, 'status', dlSortAsc)}</th>
            <th class="col-dl-remain sortable" onclick={() => toggleDlSort('remaining')}>Remaining{sortArrow(dlSortField, 'remaining', dlSortAsc)}</th>
            <th class="col-dl-lastseen sortable" onclick={() => toggleDlSort('last_seen_complete')}>Last Seen Complete{sortArrow(dlSortField, 'last_seen_complete', dlSortAsc)}</th>
            <th class="col-dl-lastrx sortable" onclick={() => toggleDlSort('last_received')}>Last Reception{sortArrow(dlSortField, 'last_received', dlSortAsc)}</th>
            <th class="col-dl-cat sortable" onclick={() => toggleDlSort('category')}>Category{sortArrow(dlSortField, 'category', dlSortAsc)}</th>
            <th class="col-dl-date sortable" onclick={() => toggleDlSort('started_at')}>Added On{sortArrow(dlSortField, 'started_at', dlSortAsc)}</th>
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
              <td class="num-cell">{formatSize(t.completed_size || t.transferred)}</td>
              <td class="num-cell">{t.status === 'active' ? formatSpeed(t.speed) : '\u2014'}</td>
              <td class="progress-cell">
                {#if t.status === 'searching'}
                  <span class="searching-label">Searching...</span>
                {:else}
                  <ProgressBar
                    value={t.progress}
                    color={t.status === 'paused' || t.status === 'stopped' ? 'var(--warning)' : t.status === 'verifying' || t.status === 'completing' ? 'var(--success, #2ecc71)' : 'var(--accent)'}
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
              <td class="num-cell">{t.status === 'active' ? formatRemaining(t.total_size, t.transferred, t.speed) : '\u2014'}</td>
              <td class="date-cell">{t.last_seen_complete ? formatDate(t.last_seen_complete) : '\u2014'}</td>
              <td class="date-cell">{t.last_received ? formatDate(t.last_received) : '\u2014'}</td>
              <td class="cat-cell">{t.category || '\u2014'}</td>
              <td class="date-cell">{formatDate(t.started_at)}</td>
            </tr>
            {#if expandedTransferId === t.id}
              <tr class="source-detail-row">
                <td colspan={DL_COL_COUNT}>
                  <div class="source-panel">
                    <!-- File info header -->
                    <div class="sp-header">
                      <div class="sp-file-info">
                        <span class="sp-filename" title={t.file_name}>{t.file_name}</span>
                        <div class="sp-meta">
                          <span class="sp-meta-item">{formatSize(t.total_size)}</span>
                          <span class="sp-meta-sep">&middot;</span>
                          <span class="sp-meta-item">{t.progress.toFixed(1)}%</span>
                          <span class="sp-meta-sep">&middot;</span>
                          <span class="sp-meta-item st-{t.status}">{dlStatusLabel(t)}</span>
                          {#if t.sources > 0}
                            <span class="sp-meta-sep">&middot;</span>
                            <span class="sp-meta-item">{sourcesLabel(t)} sources</span>
                          {/if}
                        </div>
                        <div class="sp-hash" title={t.file_hash}>{t.file_hash}</div>
                      </div>
                      <div class="sp-actions">
                        <button class="sp-btn" onclick={() => findSources(t.file_hash, t.total_size).catch(() => {})}>Find Sources</button>
                        <button class="sp-btn" onclick={() => previewFile(t.id).catch(() => {})}>Preview</button>
                        <button class="sp-btn sp-close" onclick={() => { expandedTransferId = null; expandedSources = []; }} title="Close">&times;</button>
                      </div>
                    </div>

                    <!-- Source summary -->
                    {#if !loadingSources && expandedSources.length > 0}
                      {@const transferring = expandedSources.filter(s => s.status === 'transferring').length}
                      {@const queued = expandedSources.filter(s => s.status === 'queued').length}
                      {@const connecting = expandedSources.filter(s => s.status === 'connecting').length}
                      {@const totalXfer = expandedSources.reduce((acc, s) => acc + s.transferred, 0)}
                      <div class="sp-summary">
                        {#if transferring > 0}
                          <span class="sp-sum-chip active">{transferring} transferring</span>
                        {/if}
                        {#if queued > 0}
                          <span class="sp-sum-chip queued">{queued} queued</span>
                        {/if}
                        {#if connecting > 0}
                          <span class="sp-sum-chip connecting">{connecting} connecting</span>
                        {/if}
                        {#if totalXfer > 0}
                          <span class="sp-sum-chip total">{formatSize(totalXfer)} received</span>
                        {/if}
                      </div>
                    {/if}

                    <!-- Source list -->
                    {#if loadingSources}
                      <div class="sp-loading"><div class="spinner"></div> Loading source details...</div>
                    {:else if expandedSources.length === 0}
                      <div class="sp-empty">
                        <span>No source details available yet.</span>
                        <button class="sp-btn" onclick={() => findSources(t.file_hash, t.total_size).catch(() => {})}>Search for Sources</button>
                      </div>
                    {:else}
                      <div class="sp-source-list">
                        {#each expandedSources as src, idx}
                          <div class="sp-source sp-src-{src.status}">
                            <div class="sp-src-status-dot"></div>
                            <div class="sp-src-main">
                              <span class="sp-src-client">{src.client_software || 'Unknown'}</span>
                              <span class="sp-src-addr">{src.ip}:{src.port}</span>
                            </div>
                            <div class="sp-src-detail">
                              <span class="sp-src-stat src-st-{src.status}">{sourceStatusLabel(src)}</span>
                            </div>
                            <div class="sp-src-metrics">
                              {#if src.status === 'transferring' && src.speed > 0}
                                <span class="sp-src-speed">{formatSpeed(src.speed)}</span>
                              {/if}
                              {#if src.transferred > 0}
                                <span class="sp-src-xfer">{formatSize(src.transferred)}</span>
                              {/if}
                            </div>
                          </div>
                        {/each}
                      </div>
                    {/if}
                  </div>
                </td>
              </tr>
            {/if}
          {/each}
          {#if completedDownloads.length > 0}
            <tr class="section-divider-row"><td colspan={DL_COL_COUNT}>Completed / Failed ({completedDownloads.length})</td></tr>
            {#each completedDownloads as t (t.id)}
              <tr class="dl-row completed-row {t.status}" oncontextmenu={(e) => onCtx(e, t, 'completed')}>
                <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                <td class="num-cell">{formatSize(t.total_size)}</td>
                <td class="num-cell">{formatSize(t.transferred)}</td>
                <td class="num-cell">{formatSize(t.completed_size || t.transferred)}</td>
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
                <td class="date-cell">{t.last_seen_complete ? formatDate(t.last_seen_complete) : '\u2014'}</td>
                <td class="date-cell">{'\u2014'}</td>
                <td class="cat-cell">{t.category || '\u2014'}</td>
                <td class="date-cell">{formatDate(t.started_at)}</td>
              </tr>
            {/each}
          {/if}
          {#if allDownloads.length === 0}
            <tr><td colspan={DL_COL_COUNT} class="empty-cell">No downloads yet. <a href="/search">Start a search</a> to find files.</td></tr>
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

  <!-- BOTTOM PANE: Uploads / On Queue / Download Clients (eMule tabs) -->
  <div class="pane uploads-pane" style="flex: 1;">
    <div class="pane-toolbar">
      <div class="bottom-tabs">
        <button
          class="tab-btn"
          class:active={bottomView === 'uploading'}
          onclick={() => bottomView = 'uploading'}
        >Uploading ({activeUploads.length})</button>
        <button
          class="tab-btn"
          class:active={bottomView === 'on_queue'}
          onclick={() => bottomView = 'on_queue'}
        >On Queue</button>
        <button
          class="tab-btn"
          class:active={bottomView === 'download_clients'}
          onclick={() => bottomView = 'download_clients'}
        >Download Clients</button>
      </div>
    </div>
    <div class="pane-content">
      {#if bottomView === 'uploading'}
        <!-- UPLOADING VIEW -->
        <table class="transfer-table ul-table">
          <thead>
            <tr>
              <th class="col-ul-client sortable" onclick={() => toggleUlSort('peer_name')}>User Name{sortArrow(ulSortField, 'peer_name', ulSortAsc)}</th>
              <th class="col-ul-name sortable" onclick={() => toggleUlSort('file_name')}>File{sortArrow(ulSortField, 'file_name', ulSortAsc)}</th>
              <th class="col-ul-speed sortable" onclick={() => toggleUlSort('speed')}>Speed{sortArrow(ulSortField, 'speed', ulSortAsc)}</th>
              <th class="col-ul-size sortable" onclick={() => toggleUlSort('transferred')}>Transferred{sortArrow(ulSortField, 'transferred', ulSortAsc)}</th>
              <th class="col-ul-waited sortable" onclick={() => toggleUlSort('waited')}>Waited{sortArrow(ulSortField, 'waited', ulSortAsc)}</th>
              <th class="col-ul-uptime sortable" onclick={() => toggleUlSort('upload_time')}>Upload Time{sortArrow(ulSortField, 'upload_time', ulSortAsc)}</th>
              <th class="col-ul-status sortable" onclick={() => toggleUlSort('status')}>Status{sortArrow(ulSortField, 'status', ulSortAsc)}</th>
              <th class="col-ul-bar">Up Status</th>
            </tr>
          </thead>
          <tbody>
            {#each sortedActiveUploads as t (t.id)}
              <tr class="ul-row" oncontextmenu={(e) => onCtx(e, t, 'upload')}>
                <td class="client-cell" title={t.peer_name || t.peer_id}>{t.peer_name || t.peer_id || '\u2014'}</td>
                <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                <td class="num-cell">{t.status === 'active' ? formatSpeed(t.speed) : '\u2014'}</td>
                <td class="num-cell">{formatSize(t.transferred)}</td>
                <td class="num-cell">{formatDuration(t.wait_time)}</td>
                <td class="num-cell">{formatDuration(t.upload_time)}</td>
                <td class="status-cell"><span class="status-label st-{t.status}">{ulStatusLabel(t)}</span></td>
                <td class="bar-cell">
                  {#if t.progress > 0}
                    <ProgressBar value={t.progress} color="var(--accent)" />
                  {:else}
                    <span class="no-bar">—</span>
                  {/if}
                </td>
              </tr>
            {/each}
            {#if completedUploads.length > 0}
              <tr class="section-divider-row"><td colspan={UL_COL_COUNT}>Completed ({completedUploads.length})</td></tr>
              {#each completedUploads as t (t.id)}
                <tr class="ul-row completed-row">
                  <td class="client-cell" title={t.peer_name || t.peer_id}>{t.peer_name || t.peer_id || '\u2014'}</td>
                  <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                  <td class="num-cell">{'\u2014'}</td>
                  <td class="num-cell">{formatSize(t.transferred)}</td>
                  <td class="num-cell">{formatDuration(t.wait_time)}</td>
                  <td class="num-cell">{formatDuration(t.upload_time)}</td>
                  <td class="status-cell"><span class="status-label st-{t.status}">{ulStatusLabel(t)}</span></td>
                  <td class="bar-cell"><span class="no-bar">—</span></td>
                </tr>
              {/each}
            {/if}
            {#if allUploads.length === 0}
              <tr><td colspan={UL_COL_COUNT} class="empty-cell">No uploads</td></tr>
            {/if}
          </tbody>
        </table>
      {:else if bottomView === 'on_queue'}
        <!-- ON QUEUE VIEW (eMule upload queue) -->
        <table class="transfer-table queue-table">
          <thead>
            <tr>
              <th class="col-q-client">User Name</th>
              <th class="col-q-file">File</th>
              <th class="col-q-prio">File Priority</th>
              <th class="col-q-rating">Rating</th>
              <th class="col-q-score">Score</th>
              <th class="col-q-asked">Asked</th>
              <th class="col-q-lastseen">Last Seen</th>
              <th class="col-q-entered">Entered Queue</th>
              <th class="col-q-banned">Banned</th>
              <th class="col-q-bar">Up Status</th>
            </tr>
          </thead>
          <tbody>
            <tr><td colspan="10" class="empty-cell">Queue data will appear when clients are waiting for upload slots.</td></tr>
          </tbody>
        </table>
      {:else}
        <!-- DOWNLOAD CLIENTS VIEW (eMule source clients for downloads) -->
        <table class="transfer-table clients-table">
          <thead>
            <tr>
              <th class="col-c-client">User Name</th>
              <th class="col-c-soft">Client Software</th>
              <th class="col-c-file">File</th>
              <th class="col-c-speed">Download Speed</th>
              <th class="col-c-parts">Available Parts</th>
              <th class="col-c-down">Downloaded</th>
              <th class="col-c-up">Uploaded</th>
              <th class="col-c-src">Source Type</th>
            </tr>
          </thead>
          <tbody>
            {#if expandedSources.length > 0 && expandedTransferId}
              {#each expandedSources as src}
                <tr class="client-row">
                  <td class="client-cell">{src.client_software || src.ip}</td>
                  <td>{src.client_software || '\u2014'}</td>
                  <td class="name-cell">{allDownloads.find(d => d.id === expandedTransferId)?.file_name || '\u2014'}</td>
                  <td class="num-cell">{src.status === 'transferring' ? formatSpeed(src.speed) : '\u2014'}</td>
                  <td class="num-cell">—</td>
                  <td class="num-cell">{src.transferred > 0 ? formatSize(src.transferred) : '\u2014'}</td>
                  <td class="num-cell">—</td>
                  <td>eD2K</td>
                </tr>
              {/each}
            {:else}
              <tr><td colspan="8" class="empty-cell">Double-click a download to see its source clients here.</td></tr>
            {/if}
          </tbody>
        </table>
      {/if}
    </div>
  </div>
</div>

<!-- Context Menu -->
{#if ctxMenu}
  <div class="context-menu" style="left: {ctxMenu.x}px; top: {ctxMenu.y}px;">
    {#if ctxMenu.section === 'active'}
      <!-- eMule-style download context menu -->
      {#if canPause(ctxMenu.transfer)}
        <button class="ctx-item" onclick={() => ctxAction('pause')}>Pause</button>
      {/if}
      {#if canStop(ctxMenu.transfer)}
        <button class="ctx-item" onclick={() => ctxAction('stop')}>Stop</button>
      {/if}
      {#if canResume(ctxMenu.transfer)}
        <button class="ctx-item" onclick={() => ctxAction('resume')}>Resume</button>
      {/if}
      <button class="ctx-item danger" onclick={() => ctxAction('cancel')}>Cancel</button>
      <div class="ctx-sep"></div>
      <button class="ctx-item" onclick={() => ctxAction('preview')}>Preview</button>
      <button class="ctx-item" onclick={() => ctxAction('toggle_preview_prio')}>
        {ctxMenu.transfer.preview_priority ? '✓ ' : ''}Preview Priority
      </button>
      {#if isArchive(ctxMenu.transfer)}
        <button class="ctx-item" onclick={() => ctxAction('recover_archive')}>Recover Archive</button>
      {/if}
      <div class="ctx-sep"></div>
      <div class="ctx-submenu-wrap">
        <button class="ctx-item has-sub" onclick={() => ctxPrioritySub = !ctxPrioritySub}>
          Priority ▶
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
      <button class="ctx-item" onclick={() => ctxAction('copy_link')}>Copy eD2K Link</button>
      <button class="ctx-item" onclick={() => ctxAction('paste_link')}>Paste eD2K Link</button>
      <button class="ctx-item" onclick={() => ctxAction('find_sources')}>Find More Sources</button>
      <div class="ctx-sep"></div>
      <button class="ctx-item" onclick={() => ctxAction('clear_completed')}>Clear Completed</button>
    {:else if ctxMenu.section === 'completed'}
      {#if ctxMenu.transfer.status === 'completed'}
        <button class="ctx-item" onclick={() => ctxAction('open')}>Open File</button>
        <div class="ctx-sep"></div>
      {/if}
      <button class="ctx-item" onclick={() => ctxAction('copy_link')}>Copy eD2K Link</button>
      <div class="ctx-sep"></div>
      <button class="ctx-item danger" onclick={() => ctxAction('remove')}>Remove from List</button>
      <button class="ctx-item" onclick={() => ctxAction('clear_completed')}>Clear Completed</button>
    {:else}
      <!-- Upload context menu (eMule style) -->
      <button class="ctx-item" onclick={() => ctxAction('copy_link')}>Copy eD2K Link</button>
    {/if}
  </div>
{/if}

<ConfirmDialog
  bind:open={confirmCancel.open}
  title="Cancel Download"
  message="Cancel download of &quot;{confirmCancel.name}&quot;? The partial file will be deleted."
  confirmLabel="Cancel Download"
  danger={true}
  onconfirm={async () => { await cancelTransfer(confirmCancel.id); transfers.update((list) => list.filter((x) => x.id !== confirmCancel.id)); }}
/>

<ConfirmDialog
  bind:open={confirmClearCompleted}
  title="Clear Completed"
  message="Remove all completed and failed transfers from the list?"
  confirmLabel="Clear"
  onconfirm={async () => { await clearCompleted(); transfers.update((list) => list.filter((x) => x.status !== 'completed' && x.status !== 'failed')); }}
/>

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

  /* --- Bottom pane tabs (eMule style) --- */
  .bottom-tabs {
    display: flex;
    gap: 0;
  }
  .tab-btn {
    font-size: 11px;
    padding: 4px 12px;
    border: 1px solid var(--border);
    border-bottom: none;
    border-radius: 4px 4px 0 0;
    background: var(--bg-primary);
    color: var(--text-secondary);
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
    margin-right: -1px;
  }
  .tab-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .tab-btn.active {
    background: var(--bg-secondary);
    color: var(--text-primary);
    font-weight: 600;
    border-bottom: 1px solid var(--bg-secondary);
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

  /* --- Download column widths (14 columns matching eMule) --- */
  .col-dl-name { width: 17%; }
  .col-dl-size { width: 6%; }
  .col-dl-speed { width: 6%; }
  .col-dl-progress { width: 10%; min-width: 80px; }
  .col-dl-sources { width: 6%; }
  .col-dl-prio { width: 5%; }
  .col-dl-status { width: 8%; }
  .col-dl-remain { width: 9%; }
  .col-dl-lastseen { width: 8%; }
  .col-dl-lastrx { width: 7%; }
  .col-dl-cat { width: 5%; }
  .col-dl-date { width: 7%; }

  /* --- Upload column widths (8 columns matching eMule) --- */
  .col-ul-client { width: 16%; }
  .col-ul-name { width: 20%; }
  .col-ul-speed { width: 8%; }
  .col-ul-size { width: 10%; }
  .col-ul-waited { width: 8%; }
  .col-ul-uptime { width: 8%; }
  .col-ul-status { width: 10%; }
  .col-ul-bar { width: 20%; }

  /* --- Queue column widths (10 columns matching eMule) --- */
  .col-q-client { width: 14%; }
  .col-q-file { width: 18%; }
  .col-q-prio { width: 8%; }
  .col-q-rating { width: 6%; }
  .col-q-score { width: 6%; }
  .col-q-asked { width: 6%; }
  .col-q-lastseen { width: 10%; }
  .col-q-entered { width: 10%; }
  .col-q-banned { width: 6%; }
  .col-q-bar { width: 16%; }

  /* --- Download clients column widths (8 columns matching eMule) --- */
  .col-c-client { width: 14%; }
  .col-c-soft { width: 12%; }
  .col-c-file { width: 18%; }
  .col-c-speed { width: 10%; }
  .col-c-parts { width: 14%; }
  .col-c-down { width: 10%; }
  .col-c-up { width: 10%; }
  .col-c-src { width: 12%; }

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
  .cat-cell {
    color: var(--text-muted);
    font-size: 11px;
  }
  .progress-cell {
    padding: 4px 6px;
  }
  .bar-cell {
    padding: 4px 6px;
  }
  .no-bar {
    color: var(--text-muted);
    font-size: 11px;
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
  .st-completing { color: var(--success, #2ecc71); }
  .st-searching { color: var(--warning); }
  .st-queued { color: var(--text-muted); }
  .st-paused { color: var(--warning); }
  .st-stopped { color: var(--text-muted); }
  .st-completed { color: var(--success, #2ecc71); }
  .st-failed { color: var(--danger, #e74c3c); }
  .st-hashing { color: var(--text-secondary); }
  .st-insufficient { color: var(--danger, #e74c3c); }
  .st-noneneeded { color: var(--text-muted); }
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
    min-width: 180px;
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

  /* --- Source detail panel --- */
  .dl-row.expanded {
    background: color-mix(in srgb, var(--accent) 8%, transparent);
  }
  .dl-row {
    cursor: default;
  }
  .source-detail-row td {
    padding: 0 !important;
    border-bottom: none;
  }
  .source-panel {
    background: var(--bg-surface, var(--bg-primary));
    border-top: 2px solid var(--accent);
    border-bottom: 2px solid var(--accent);
    padding: 0;
  }

  .sp-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 14px 8px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
  }
  .sp-file-info {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
    flex: 1;
  }
  .sp-filename {
    font-weight: 600;
    font-size: 12px;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sp-meta {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 11px;
    flex-wrap: wrap;
  }
  .sp-meta-item {
    color: var(--text-secondary);
    font-weight: 500;
  }
  .sp-meta-sep {
    color: var(--text-muted);
    font-size: 9px;
  }
  .sp-hash {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    margin-top: 1px;
    cursor: text;
    user-select: all;
  }
  .sp-actions {
    display: flex;
    gap: 4px;
    flex-shrink: 0;
    align-items: flex-start;
  }
  .sp-btn {
    font-size: 11px;
    padding: 3px 10px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-primary);
    color: var(--text-primary);
    cursor: pointer;
    white-space: nowrap;
    transition: background 0.1s;
  }
  .sp-btn:hover { background: var(--bg-hover); }
  .sp-close {
    font-size: 16px;
    line-height: 1;
    padding: 2px 7px;
    font-weight: 400;
    color: var(--text-muted);
  }
  .sp-close:hover { color: var(--text-primary); }

  .sp-summary {
    display: flex;
    gap: 6px;
    padding: 6px 14px;
    flex-wrap: wrap;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 50%, transparent);
  }
  .sp-sum-chip {
    font-size: 10px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 10px;
    text-transform: uppercase;
    letter-spacing: 0.3px;
  }
  .sp-sum-chip.active {
    background: color-mix(in srgb, var(--accent) 15%, transparent);
    color: var(--accent);
  }
  .sp-sum-chip.queued {
    background: color-mix(in srgb, var(--text-muted) 15%, transparent);
    color: var(--text-secondary);
  }
  .sp-sum-chip.connecting {
    background: color-mix(in srgb, var(--warning) 15%, transparent);
    color: var(--warning);
  }
  .sp-sum-chip.total {
    background: color-mix(in srgb, var(--success) 15%, transparent);
    color: var(--success);
  }

  .sp-loading {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 16px;
    font-size: 11px;
    color: var(--text-muted);
  }
  .sp-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 20px 16px;
    font-size: 12px;
    color: var(--text-muted);
  }

  .sp-source-list {
    display: flex;
    flex-direction: column;
  }
  .sp-source {
    display: grid;
    grid-template-columns: 8px 1fr auto auto;
    gap: 10px;
    align-items: center;
    padding: 5px 14px;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 30%, transparent);
    transition: background 0.1s;
  }
  .sp-source:hover {
    background: color-mix(in srgb, var(--accent) 5%, transparent);
  }
  .sp-source:last-child {
    border-bottom: none;
  }

  .sp-src-status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--text-muted);
    flex-shrink: 0;
  }
  .sp-src-transferring .sp-src-status-dot { background: var(--accent); }
  .sp-src-queued .sp-src-status-dot { background: var(--text-muted); }
  .sp-src-connecting .sp-src-status-dot { background: var(--warning); }
  .sp-src-completed .sp-src-status-dot { background: var(--success); }
  .sp-src-failed .sp-src-status-dot { background: var(--danger); }

  .sp-src-main {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .sp-src-client {
    font-size: 12px;
    font-weight: 500;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sp-src-addr {
    font-size: 10px;
    font-family: var(--font-mono);
    color: var(--text-muted);
  }

  .sp-src-detail {
    text-align: right;
  }
  .sp-src-stat {
    font-size: 11px;
    font-weight: 600;
  }
  .src-st-connecting { color: var(--warning); }
  .src-st-queued { color: var(--text-muted); }
  .src-st-transferring { color: var(--accent); }
  .src-st-completed { color: var(--success, #2ecc71); }
  .src-st-failed { color: var(--danger, #e74c3c); }

  .sp-src-metrics {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 1px;
    min-width: 70px;
  }
  .sp-src-speed {
    font-size: 11px;
    font-weight: 600;
    color: var(--accent);
    font-variant-numeric: tabular-nums;
  }
  .sp-src-xfer {
    font-size: 10px;
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
  }
</style>
