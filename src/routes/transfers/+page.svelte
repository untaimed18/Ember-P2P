<script lang="ts">
  import ProgressBar from '$lib/components/ProgressBar.svelte';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import { transfers } from '$lib/stores/transfers';
  import { networkStats } from '$lib/stores/network';
  import {
    pauseTransfer, stopTransfer, resumeTransfer, cancelTransfer, removeTransfer,
    clearCompleted, setTransferPriority, setTransferCategory, setPreviewPriority, pauseAllTransfers, resumeAllTransfers,
    pauseTransfersBatch, resumeTransfersBatch, stopTransfersBatch, cancelTransfersBatch,
    getTransferSources, openFile, openTransferFileLocation, recoverArchive, startDownload,
    getUploadQueue, getKnownClients,
  } from '$lib/api/transfers';
  import { findSources, parseEd2kLink, formatEd2kLink } from '$lib/api/search';
  import { previewFile } from '$lib/api/preview';
  import { addFriend } from '$lib/api/friends';
  import { banPeer } from '$lib/api/kad';
  import { formatSize, formatSpeed, formatDate, formatDateWithYear, formatDuration, formatRemaining } from '$lib/utils';
  import { onMount, onDestroy } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import type { UnlistenFn } from '@tauri-apps/api/event';
  import type { Transfer, SourceInfo, UploadQueueClient, KnownClient } from '$lib/types';

  function countryFlagSrc(code: string | undefined): string | null {
    if (!code || code.length !== 2) return null;
    // L9: only a-z codes map to /flags/*.svg; anything else is bogus
    // (e.g. backend sending "??" or a numeric code). Guard upfront so we
    // don't emit a broken <img> that causes an on-screen alt-text flash.
    const lower = code.toLowerCase();
    if (!/^[a-z]{2}$/.test(lower)) return null;
    return `/flags/${lower}.svg`;
  }

  function netOriginSrc(origin: string | undefined): string | null {
    if (origin === 'kad') return '/net-kad.svg';
    if (origin === 'ed2k') return '/net-ed2k.svg';
    return null;
  }

  function netOriginLabel(origin: string | undefined): string {
    if (origin === 'kad') return 'KAD Network';
    if (origin === 'ed2k') return 'eD2K Server';
    return '';
  }

  let sourceUnlisten: UnlistenFn | null = null;
  let searchUnlisten: UnlistenFn | null = null;
  let showAdvancedDlCols = $state(true);

  type TableKey = 'downloads' | 'uploads' | 'queue' | 'known' | 'clients';
  type TransferColumn<TSort extends string = string> = {
    key: string;
    label: string;
    width: number;
    minWidth: number;
    className: string;
    sortField?: TSort;
  };

  const DOWNLOAD_COLUMNS: TransferColumn<DlSortField>[] = [
    { key: 'file_name', label: 'File Name', width: 260, minWidth: 140, className: 'col-dl-name', sortField: 'file_name' },
    { key: 'total_size', label: 'Size', width: 65, minWidth: 56, className: 'col-dl-size', sortField: 'total_size' },
    { key: 'transferred', label: 'Transferred', width: 65, minWidth: 56, className: 'col-dl-size', sortField: 'transferred' },
    { key: 'completed_size', label: 'Completed', width: 65, minWidth: 56, className: 'col-dl-size', sortField: 'completed_size' },
    { key: 'speed', label: 'Speed', width: 65, minWidth: 56, className: 'col-dl-speed', sortField: 'speed' },
    { key: 'progress', label: 'Progress', width: 170, minWidth: 96, className: 'col-dl-progress', sortField: 'progress' },
    { key: 'sources', label: 'Sources', width: 60, minWidth: 56, className: 'col-dl-sources', sortField: 'sources' },
    { key: 'priority', label: 'Priority', width: 60, minWidth: 60, className: 'col-dl-prio', sortField: 'priority' },
    { key: 'status', label: 'Status', width: 70, minWidth: 80, className: 'col-dl-status', sortField: 'status' },
    { key: 'remaining', label: 'Remaining', width: 110, minWidth: 88, className: 'col-dl-remain', sortField: 'remaining' },
    { key: 'last_seen_complete', label: 'Last Seen Complete', width: 150, minWidth: 110, className: 'col-dl-lastseen', sortField: 'last_seen_complete' },
    { key: 'last_received', label: 'Last Reception', width: 120, minWidth: 100, className: 'col-dl-lastrx', sortField: 'last_received' },
    { key: 'category', label: 'Category', width: 100, minWidth: 88, className: 'col-dl-cat', sortField: 'category' },
    { key: 'started_at', label: 'Added On', width: 120, minWidth: 96, className: 'col-dl-date', sortField: 'started_at' },
  ];
  const DOWNLOAD_COMPACT_COLUMN_KEYS = new Set([
    'file_name',
    'total_size',
    'transferred',
    'completed_size',
    'speed',
    'progress',
    'sources',
    'priority',
    'status',
    'remaining',
  ]);
  const DOWNLOAD_ADVANCED_COLUMN_KEYS = DOWNLOAD_COLUMNS
    .filter((column) => !DOWNLOAD_COMPACT_COLUMN_KEYS.has(column.key))
    .map((column) => column.key);
  const UPLOAD_COLUMNS: TransferColumn<UlSortField>[] = [
    { key: 'country', label: '', width: 48, minWidth: 40, className: 'col-ul-flag' },
    { key: 'peer_name', label: 'User Name', width: 150, minWidth: 120, className: 'col-ul-client', sortField: 'peer_name' },
    { key: 'file_name', label: 'File', width: 220, minWidth: 140, className: 'col-ul-name', sortField: 'file_name' },
    { key: 'client_software', label: 'Software', width: 100, minWidth: 80, className: 'col-ul-sw', sortField: 'client_software' },
    { key: 'speed', label: 'Speed', width: 70, minWidth: 56, className: 'col-ul-speed', sortField: 'speed' },
    { key: 'transferred', label: 'Transferred', width: 80, minWidth: 56, className: 'col-ul-size', sortField: 'transferred' },
    { key: 'total_size', label: 'Size', width: 70, minWidth: 56, className: 'col-ul-total' },
    { key: 'upload_time', label: 'Upload Time', width: 80, minWidth: 72, className: 'col-ul-uptime', sortField: 'upload_time' },
    { key: 'status', label: 'Status', width: 100, minWidth: 84, className: 'col-ul-status', sortField: 'status' },
    { key: 'up_status', label: 'Up Status', width: 170, minWidth: 120, className: 'col-ul-bar' },
  ];
  // QUEUE_COLUMNS schema is for `UploadQueueClient` rows (the real
  // upload-server queue snapshot), NOT the legacy `Transfer` rows it
  // used to render. Storage keys were bumped to `QueueListCtrlV2` so any
  // user with persisted column widths from the old "On Queue" placeholder
  // tab gets defaults instead of a stale layout that doesn't match the
  // new column set.
  const QUEUE_COLUMNS: TransferColumn[] = [
    { key: 'country', label: '', width: 48, minWidth: 40, className: 'col-q-flag' },
    { key: 'user_name', label: 'User Name', width: 150, minWidth: 120, className: 'col-q-client' },
    { key: 'file_name', label: 'File', width: 260, minWidth: 160, className: 'col-q-file' },
    { key: 'wait_time', label: 'Wait Time', width: 90, minWidth: 72, className: 'col-q-wait' },
    { key: 'queue_rank', label: 'Rank', width: 60, minWidth: 50, className: 'col-q-rank' },
    { key: 'credit_ratio', label: 'Score', width: 64, minWidth: 56, className: 'col-q-score' },
    { key: 'transfer_history', label: 'Up / Down', width: 130, minWidth: 110, className: 'col-q-hist' },
    { key: 'ident_state', label: 'Identification', width: 110, minWidth: 96, className: 'col-q-ident' },
  ];
  // KNOWN_COLUMNS schema mirrors `KnownClient`: lifetime SecIdent records
  // sourced from clients.met. Independent of which peers are connected,
  // so this view is the "credit ledger" view of the network. Every
  // non-flag column is sortable; the user's last-used sort is persisted
  // via `transfers-kn-sort-field` / `transfers-kn-sort-asc` (see the
  // `KnSortField` type and `toggleKnSort` below).
  const KNOWN_COLUMNS: TransferColumn<KnSortField>[] = [
    { key: 'country', label: '', width: 48, minWidth: 40, className: 'col-k-flag' },
    { key: 'user_hash', label: 'User Hash', width: 200, minWidth: 140, className: 'col-k-hash', sortField: 'user_hash' },
    { key: 'last_known_ip', label: 'Last IP', width: 130, minWidth: 110, className: 'col-k-ip', sortField: 'last_known_ip' },
    { key: 'uploaded', label: 'Uploaded To', width: 100, minWidth: 80, className: 'col-k-up', sortField: 'uploaded' },
    { key: 'downloaded', label: 'Downloaded From', width: 110, minWidth: 88, className: 'col-k-down', sortField: 'downloaded' },
    { key: 'credit_ratio', label: 'Score', width: 64, minWidth: 56, className: 'col-k-score', sortField: 'credit_ratio' },
    { key: 'ident_state', label: 'Identification', width: 110, minWidth: 96, className: 'col-k-ident', sortField: 'ident_state' },
    { key: 'last_seen', label: 'Last Seen', width: 140, minWidth: 110, className: 'col-k-seen', sortField: 'last_seen' },
  ];
  const CLIENT_COLUMNS: TransferColumn[] = [
    { key: 'peer_name', label: 'User Name', width: 150, minWidth: 120, className: 'col-c-client' },
    { key: 'country', label: '', width: 48, minWidth: 40, className: 'col-c-flag' },
    { key: 'client_software', label: 'Client Software', width: 100, minWidth: 96, className: 'col-c-soft' },
    { key: 'file_name', label: 'File', width: 260, minWidth: 160, className: 'col-c-file' },
    { key: 'speed', label: 'Download Speed', width: 65, minWidth: 65, className: 'col-c-speed' },
    { key: 'downloaded', label: 'Downloaded', width: 65, minWidth: 65, className: 'col-c-down' },
    { key: 'parts', label: 'Parts', width: 60, minWidth: 50, className: 'col-c-parts' },
    { key: 'status', label: 'Status', width: 100, minWidth: 88, className: 'col-c-status' },
  ];
  const TABLE_COLUMNS: Record<TableKey, TransferColumn[]> = {
    downloads: DOWNLOAD_COLUMNS,
    uploads: UPLOAD_COLUMNS,
    queue: QUEUE_COLUMNS,
    known: KNOWN_COLUMNS,
    clients: CLIENT_COLUMNS,
  };
  const COLUMN_STORAGE_KEYS: Record<TableKey, string> = {
    downloads: 'transfers-columns-DownloadListCtrl',
    uploads: 'transfers-columns-UploadListCtrl',
    queue: 'transfers-columns-QueueListCtrlV2',
    known: 'transfers-columns-KnownClientsCtrl',
    clients: 'transfers-columns-DownloadClientsCtrl',
  };
  const COLUMN_HIDDEN_STORAGE_KEYS: Record<TableKey, string> = {
    downloads: 'transfers-column-hidden-DownloadListCtrl',
    uploads: 'transfers-column-hidden-UploadListCtrl',
    queue: 'transfers-column-hidden-QueueListCtrlV2',
    known: 'transfers-column-hidden-KnownClientsCtrl',
    clients: 'transfers-column-hidden-DownloadClientsCtrl',
  };
  const COLUMN_ORDER_STORAGE_KEYS: Record<TableKey, string> = {
    downloads: 'transfers-column-order-DownloadListCtrl',
    uploads: 'transfers-column-order-UploadListCtrl',
    queue: 'transfers-column-order-QueueListCtrlV2',
    known: 'transfers-column-order-KnownClientsCtrl',
    clients: 'transfers-column-order-DownloadClientsCtrl',
  };

  function createDefaultWidths(columns: TransferColumn[]): Record<string, number> {
    return Object.fromEntries(columns.map((column) => [column.key, column.width]));
  }

  function createDefaultHidden(columns: TransferColumn[]): Record<string, boolean> {
    return Object.fromEntries(columns.map((column) => [column.key, false]));
  }

  function createDefaultOrder(columns: TransferColumn[]): string[] {
    return columns.map((column) => column.key);
  }

  let columnWidths = $state<Record<TableKey, Record<string, number>>>({
    downloads: createDefaultWidths(DOWNLOAD_COLUMNS),
    uploads: createDefaultWidths(UPLOAD_COLUMNS),
    queue: createDefaultWidths(QUEUE_COLUMNS),
    known: createDefaultWidths(KNOWN_COLUMNS),
    clients: createDefaultWidths(CLIENT_COLUMNS),
  });
  let hiddenColumns = $state<Record<TableKey, Record<string, boolean>>>({
    downloads: createDefaultHidden(DOWNLOAD_COLUMNS),
    uploads: createDefaultHidden(UPLOAD_COLUMNS),
    queue: createDefaultHidden(QUEUE_COLUMNS),
    known: createDefaultHidden(KNOWN_COLUMNS),
    clients: createDefaultHidden(CLIENT_COLUMNS),
  });
  let columnOrder = $state<Record<TableKey, string[]>>({
    downloads: createDefaultOrder(DOWNLOAD_COLUMNS),
    uploads: createDefaultOrder(UPLOAD_COLUMNS),
    queue: createDefaultOrder(QUEUE_COLUMNS),
    known: createDefaultOrder(KNOWN_COLUMNS),
    clients: createDefaultOrder(CLIENT_COLUMNS),
  });
  let downloadTableEl: HTMLTableElement | undefined = $state(undefined);
  let uploadTableEl: HTMLTableElement | undefined = $state(undefined);
  let queueTableEl: HTMLTableElement | undefined = $state(undefined);
  let knownTableEl: HTMLTableElement | undefined = $state(undefined);
  let clientsTableEl: HTMLTableElement | undefined = $state(undefined);
  let columnDragCleanup: (() => void) | null = $state(null);
  let activeColumnResize: { table: TableKey; columnKey: string } | null = $state(null);
  let activeColumnDrag: { table: TableKey; columnKey: string } | null = $state(null);
  let columnDropTarget: { table: TableKey; columnKey: string; position: 'before' | 'after' } | null = $state(null);
  let columnMenu: { x: number; y: number; table: TableKey } | null = $state(null);
  let suppressHeaderClickUntil = 0;

  let mounted = false;
  onMount(() => {
    mounted = true;
    const saved = localStorage.getItem('transfers-split');
    if (saved) { const v = parseFloat(saved); if (Number.isFinite(v)) splitPercent = Math.max(20, Math.min(80, v)); }
    const savedAdvancedCols = localStorage.getItem('transfers-advanced-cols');
    loadStoredColumnWidths();
    loadStoredColumnSetup(savedAdvancedCols === '0');
    syncAdvancedDlState();

    // One-shot fetch of the upload-queue and known-clients snapshots so
    // the bottom-tab labels show their counts immediately on page load,
    // not just after the user has clicked each tab. The per-tab
    // `$effect`s below still own the ongoing polling while a tab is
    // visible — this only primes the counts for tabs the user hasn't
    // opened yet. Without it, "Queued (N)" / "Known Clients (N)"
    // rendered as bare "Queued" / "Known Clients" until first click,
    // and the numbers vanished again every time the user navigated
    // away from /transfers and back.
    refreshUploadQueue();
    refreshKnownClients();
    listen<{
      transfer_id: string; ip: string; port: number; status: string;
      queue_rank?: number; speed: number; transferred: number; client_software: string; peer_name: string;
      available_parts?: number; total_parts?: number; country_code?: string;
    }>('transfer-source-detail', (event) => {
      const d = event.payload;
      if (d.transfer_id !== expandedTransferId) return;
      const idx = expandedSources.findIndex((s) => s.ip === d.ip && s.port === d.port);
      const status = d.status as SourceInfo['status'];
      // D28: if the backend now reports a terminal status for this source,
      // drop it from the visible list rather than accumulating dead rows
      // that stay until the user collapses and re-opens the drawer.
      const isDead = status === 'failed';
      if (idx >= 0) {
        if (isDead) {
          expandedSources = expandedSources.filter((_, i) => i !== idx);
        } else {
          const s = expandedSources[idx];
          const updated: SourceInfo = { ...s, status, queue_rank: d.queue_rank, speed: d.speed, transferred: d.transferred, client_software: d.client_software || s.client_software, peer_name: d.peer_name || s.peer_name, available_parts: d.available_parts ?? s.available_parts, total_parts: d.total_parts ?? s.total_parts, country_code: d.country_code ?? s.country_code };
          expandedSources[idx] = updated;
          expandedSources = expandedSources;
        }
      } else if (!isDead) {
        // L16: cap the expanded list so a transfer with hundreds of
        // sources doesn't grow the DOM indefinitely. Drop the oldest
        // idle entry first, falling back to head-trim.
        const MAX_EXPANDED = 200;
        if (expandedSources.length >= MAX_EXPANDED) {
          const victim = expandedSources.findIndex((s) => s.speed === 0 && s.status !== 'transferring');
          const next = [...expandedSources];
          if (victim >= 0) next.splice(victim, 1); else next.shift();
          expandedSources = next;
        }
        expandedSources = [...expandedSources, { ip: d.ip, port: d.port, status, queue_rank: d.queue_rank, speed: d.speed, transferred: d.transferred, client_software: d.client_software, peer_name: d.peer_name || '', available_parts: d.available_parts, total_parts: d.total_parts, country_code: d.country_code } as SourceInfo];
      }
    }).then((u) => { if (mounted) sourceUnlisten = u; else u(); }).catch(() => { /* backend may not be up yet; the store also listens for the same event */ });

    const searchUnsubs: (() => void)[] = [];
    listen<{ transfer_id: string; kind: string; count?: number }>('transfer:source-search', (event) => {
      const d = event.payload;
      let msg: string;
      switch (d.kind) {
        case 'server_query': msg = 'Queried server...'; break;
        case 'server_found': msg = `Server: ${d.count} source${d.count !== 1 ? 's' : ''} found`; break;
        case 'server_empty': msg = 'Server: 0 sources'; break;
        case 'udp_found': msg = `UDP: ${d.count} source${d.count !== 1 ? 's' : ''} found`; break;
        case 'udp_empty': msg = 'UDP: 0 sources'; break;
        case 'kad_search': msg = 'Searching KAD...'; break;
        case 'kad_found': msg = `KAD: ${d.count} source${d.count !== 1 ? 's' : ''} found`; break;
        case 'kad_indirect': msg = `KAD: ${d.count} indirect source${d.count !== 1 ? 's' : ''} (callback)`; break;
        case 'kad_empty': msg = 'KAD: 0 sources'; break;
        default: msg = d.kind; break;
      }
      searchStatus.set(d.transfer_id, msg);
      searchStatus = new Map(searchStatus);
    }).then((u) => { if (mounted) searchUnsubs.push(u); else u(); }).catch((e) => { console.error('Failed to subscribe to transfer:source-search:', e); });

    listen<{ transfer_id: string; source: string; kind: string }>('transfer:source-failed', (event) => {
      const d = event.payload;
      const label = d.kind === 'permanent' ? 'rejected' : d.kind === 'timeout' ? 'timed out' : 'failed';
      searchStatus.set(d.transfer_id, `${d.source} ${label}`);
      searchStatus = new Map(searchStatus);
    }).then((u) => { if (mounted) searchUnsubs.push(u); else u(); }).catch((e) => { console.error('Failed to subscribe to transfer:source-failed:', e); });

    searchUnlisten = () => { for (const u of searchUnsubs) u(); searchUnsubs.length = 0; };
  });

  onDestroy(() => { mounted = false; sourceUnlisten?.(); searchUnlisten?.(); infoTimers.forEach(clearTimeout); columnDragCleanup?.(); speedHistory.clear(); });

  let searchStatus: Map<string, string> = $state(new Map());
  let transferError: string | null = $state(null);
  let transferInfo: string | null = $state(null);
  let infoTimers: ReturnType<typeof setTimeout>[] = [];

  function showInfo(msg: string) {
    infoTimers.forEach(clearTimeout);
    infoTimers = [];
    transferInfo = msg;
    infoTimers.push(setTimeout(() => (transferInfo = null), 5000));
  }
  let confirmCancel: { open: boolean; id: string; name: string } = $state({ open: false, id: '', name: '' });
  let confirmClearCompleted = $state(false);
  // D27: confirmation + in-flight tracker for archive recovery, which
  // can take noticeable time for large partials and isn't reversible.
  let confirmRecover: { open: boolean; id: string; name: string } = $state({ open: false, id: '', name: '' });
  let recoveringIds: Set<string> = $state(new Set());
  // L14: persist the Completed-section collapsed state so it survives
  // navigation. Falls back to expanded on first load or invalid storage.
  const COMPLETED_COLLAPSED_KEY = 'transfers-completed-collapsed';
  function loadCompletedCollapsed(): boolean {
    try {
      return localStorage.getItem(COMPLETED_COLLAPSED_KEY) === '1';
    } catch { return false; }
  }
  let completedCollapsed = $state(loadCompletedCollapsed());
  $effect(() => {
    try { localStorage.setItem(COMPLETED_COLLAPSED_KEY, completedCollapsed ? '1' : '0'); } catch { /* ignore */ }
  });

  // --- Source detail panel (eMule-style) ---
  let expandedTransferId: string | null = $state(null);
  let expandedSources: SourceInfo[] = $state([]);
  let loadingSources = $state(false);
  let sourceLoadError: string | null = $state(null);
  let sourceDetailRequestId = $state(0);

  async function toggleSourceDetail(t: Transfer) {
    if (expandedTransferId === t.id) {
      expandedTransferId = null;
      expandedSources = [];
      sourceLoadError = null;
      sourceDetailRequestId += 1;
      return;
    }
    const requestId = ++sourceDetailRequestId;
    expandedTransferId = t.id;
    loadingSources = true;
    sourceLoadError = null;
    // Snapshot any push-arrived rows present at fetch start. Keep the
    // reference so we can tell, after the await resolves, whether
    // push events mutated `expandedSources` during the fetch. Svelte
    // 5 reassigns the bound `$state` array on every mutating update
    // from the `transfer-source-detail` handler, so identity
    // inequality is a reliable "pushed during await" signal.
    const preFetchSources = expandedSources;
    try {
      const sources = await getTransferSources(t.id);
      if (expandedTransferId !== t.id || requestId !== sourceDetailRequestId) return;
      if (expandedSources === preFetchSources) {
        // No push events hit during the fetch — safe to replace.
        expandedSources = sources;
      } else {
        // Push events landed while the snapshot was in flight.
        // Merging prevents the snapshot from clobbering live row
        // updates (e.g. a peer that transitioned to `transferring`
        // during the 50-200ms round-trip would otherwise snap back
        // to the snapshot's "connecting" status). Push events are
        // more current than the snapshot, so push rows win on
        // collision and any snapshot row the push hasn't touched
        // is appended.
        const liveByKey = new Map<string, SourceInfo>();
        for (const s of expandedSources) {
          liveByKey.set(`${s.ip}:${s.port}`, s);
        }
        const merged: SourceInfo[] = [...expandedSources];
        for (const s of sources) {
          const key = `${s.ip}:${s.port}`;
          if (!liveByKey.has(key)) merged.push(s);
        }
        expandedSources = merged;
      }
    } catch (e) {
      if (expandedTransferId === t.id && requestId === sourceDetailRequestId) {
        // Only wipe on error if no push events have populated the
        // list in the meantime; otherwise keep what we have.
        if (expandedSources === preFetchSources) {
          expandedSources = [];
        }
        sourceLoadError = 'Failed to load sources';
      }
    }
    if (expandedTransferId === t.id && requestId === sourceDetailRequestId) {
      loadingSources = false;
    }
  }

  function sourceStatusLabel(s: SourceInfo): string {
    switch (s.status) {
      case 'connecting': return 'Connecting';
      case 'queued': return s.queue_rank != null && s.queue_rank > 0 ? `QR: ${s.queue_rank}` : 'Queued';
      case 'queue_full': return 'Queue Full';
      case 'no_needed_parts': return 'No Needed Parts';
      case 'transferring': return 'Transferring';
      case 'completed': return 'Done';
      case 'failed': return 'Failed';
      default: return s.status;
    }
  }

  // Source-list ordering: transferring rises to the top (most useful
  // info: who's actively sending us bytes), queued comes next (the
  // ones we're waiting on, ordered by closest-to-top-of-queue), then
  // everything else (connecting / queue_full / no_needed_parts /
  // completed) in stable insertion order. Within the transferring
  // tier, sort by speed descending so the fastest sources are easy
  // to find. Within the queued tier, sort by queue_rank ascending
  // (smaller rank = closer to a slot).
  //
  // Returns a new sorted array; the caller's input is not mutated.
  function sortSourcesByPriority(sources: SourceInfo[]): SourceInfo[] {
    const tier = (s: SourceInfo): number => {
      if (s.status === 'transferring') return 0;
      if (s.status === 'queued') return 1;
      return 2;
    };
    return sources
      .map((s, i) => ({ s, i }))
      .sort((a, b) => {
        const ta = tier(a.s);
        const tb = tier(b.s);
        if (ta !== tb) return ta - tb;
        if (ta === 0) {
          // Transferring: faster on top.
          return (b.s.speed ?? 0) - (a.s.speed ?? 0);
        }
        if (ta === 1) {
          // Queued: smaller queue_rank on top. Treat null/0 (queue
          // position unknown) as worst so known ranks float up.
          const ar = a.s.queue_rank != null && a.s.queue_rank > 0
            ? a.s.queue_rank : Number.MAX_SAFE_INTEGER;
          const br = b.s.queue_rank != null && b.s.queue_rank > 0
            ? b.s.queue_rank : Number.MAX_SAFE_INTEGER;
          if (ar !== br) return ar - br;
        }
        // Stable within tier: preserve original insertion order.
        return a.i - b.i;
      })
      .map((x) => x.s);
  }

  function toErrorMsg(e: unknown): string {
    return e instanceof Error ? e.message : typeof e === 'string' ? e : 'Operation failed';
  }

  // --- Downloads ---
  // Single-pass partition: every progress flush replaces `$transfers` with a
  // new array (`transfers.ts` spreads on update for reactivity), so each
  // `$derived` filter above ran a full scan over the whole list. With N
  // transfers that was 4 scans per flush just for the download buckets (plus
  // 6 more for uploads); do one scan and drop them all into the right bins.
  let downloadPartition = $derived.by(() => {
    const all: Transfer[] = [];
    const active: Transfer[] = [];
    const completed: Transfer[] = [];
    let anyCompleted = false;
    for (const t of $transfers) {
      if (t.direction !== 'download') continue;
      all.push(t);
      if (t.status === 'completed' || t.status === 'failed') {
        completed.push(t);
        if (t.status === 'completed') anyCompleted = true;
      } else {
        active.push(t);
      }
    }
    return { all, active, completed, anyCompleted };
  });
  let allDownloads = $derived(downloadPartition.all);
  let activeDownloads = $derived(downloadPartition.active);
  let completedDownloads = $derived(downloadPartition.completed);
  let hasCompletedDl = $derived(downloadPartition.anyCompleted);
  // L14: persist the filter so switching tabs and returning doesn't
  // wipe a user's narrow-down.
  const FILTER_KEY = 'transfers-filter';
  function loadFilter(): string {
    try { return localStorage.getItem(FILTER_KEY) ?? ''; } catch { return ''; }
  }
  let transferFilter = $state(loadFilter());
  $effect(() => {
    try { localStorage.setItem(FILTER_KEY, transferFilter); } catch { /* ignore */ }
  });
  let selectedDownloadIds = $state<string[]>([]);
  let selectedDlIdSet = $derived(new Set(selectedDownloadIds));
  let lastClickedDlId = $state<string | null>(null);

  // --- Uploads ---
  function isUploadFinished(t: Transfer): boolean {
    return t.status === 'completed' || t.status === 'failed' || (t.status === 'active' && t.total_size > 0 && t.transferred >= t.total_size);
  }
  // Single-pass partition (same rationale as `downloadPartition` above).
  let uploadPartition = $derived.by(() => {
    const all: Transfer[] = [];
    const active: Transfer[] = [];
    const completed: Transfer[] = [];
    const failed: Transfer[] = [];
    const queued: Transfer[] = [];
    for (const t of $transfers) {
      if (t.direction !== 'upload') continue;
      all.push(t);
      if (t.status === 'queued') {
        queued.push(t);
      } else if (t.status === 'failed') {
        failed.push(t);
      } else if (isUploadFinished(t)) {
        // completed && failed already handled above
        completed.push(t);
      } else {
        active.push(t);
      }
    }
    return { all, active, completed, failed, queued };
  });
  let allUploads = $derived(uploadPartition.all);
  let activeUploads = $derived(uploadPartition.active);
  // `completedUploads`, `failedUploads`, `queuedUploads` were derivations
  // for the old upload-pane "Completed"/"Failed"/"On Queue" placeholder
  // sections. With the auto-remove change (terminal upload-direction
  // events drop the row from the store immediately) `completed`/`failed`
  // are always empty, and the real upload queue is now sourced from
  // `uploadQueueClients` via `getUploadQueue()` rather than from
  // `Transfer.status === 'queued'` rows. Kept the partition itself
  // because `uploadPartition.all` and `.active` are still used.

  // --- Bottom pane view tabs (eMule style) ---
  // Migrated from `'on_queue'` (which was always-empty placeholder data
  // derived from `Transfer.status === 'queued'`) to `'queued'` (real
  // upload-server queue snapshot via `getUploadQueue()`). `'known_clients'`
  // is new — surfaces the SecIdent credit ledger so users can see who
  // they've earned upload priority with on the wider eMule network.
  type BottomView = 'uploading' | 'queued' | 'known_clients' | 'download_clients';
  const BOTTOM_VIEW_KEY = 'transfers-bottom-view';
  function loadBottomView(): BottomView {
    try {
      const v = localStorage.getItem(BOTTOM_VIEW_KEY);
      if (v === 'uploading' || v === 'queued' || v === 'known_clients' || v === 'download_clients') return v;
      // Migrate the legacy 'on_queue' key (replaced by 'queued') so users
      // with a stored preference don't get bumped back to the default tab.
      if (v === 'on_queue') return 'queued';
    } catch { /* ignore */ }
    return 'uploading';
  }
  let bottomView: BottomView = $state(loadBottomView());
  $effect(() => {
    try { localStorage.setItem(BOTTOM_VIEW_KEY, bottomView); } catch { /* ignore */ }
  });

  // --- Upload queue + known clients data (polled while the matching
  //     tab is visible). The backend snapshot commands are cheap (single
  //     read lock + already-resolved data) but we still gate on tab
  //     visibility so background tabs don't keep the network task busy.
  let uploadQueueClients: UploadQueueClient[] = $state([]);
  let knownClients: KnownClient[] = $state([]);
  let uploadQueueLoaded = $state(false);
  let knownClientsLoaded = $state(false);
  let queuePollHandle: ReturnType<typeof setInterval> | null = null;
  let knownPollHandle: ReturnType<typeof setInterval> | null = null;
  const QUEUE_POLL_INTERVAL_MS = 3000;
  const KNOWN_POLL_INTERVAL_MS = 8000;

  async function refreshUploadQueue() {
    try {
      uploadQueueClients = await getUploadQueue();
      uploadQueueLoaded = true;
    } catch (e) {
      // Network task may be momentarily busy (try_send full). Leave the
      // last good snapshot in place rather than flashing the table empty.
      console.warn('Failed to refresh upload queue:', e);
    }
  }
  async function refreshKnownClients() {
    try {
      knownClients = await getKnownClients();
      knownClientsLoaded = true;
    } catch (e) {
      console.warn('Failed to refresh known clients:', e);
    }
  }

  $effect(() => {
    // Poll the upload queue only while its tab is visible. Refresh
    // immediately on activation so the table is populated before the
    // next interval tick fires.
    if (bottomView === 'queued') {
      refreshUploadQueue();
      if (queuePollHandle === null) {
        queuePollHandle = setInterval(refreshUploadQueue, QUEUE_POLL_INTERVAL_MS);
      }
    } else if (queuePollHandle !== null) {
      clearInterval(queuePollHandle);
      queuePollHandle = null;
    }
    return () => {
      if (queuePollHandle !== null) {
        clearInterval(queuePollHandle);
        queuePollHandle = null;
      }
    };
  });

  $effect(() => {
    // Same pattern as the queue poll; longer interval because credit
    // records change far less often than queue rank.
    if (bottomView === 'known_clients') {
      refreshKnownClients();
      if (knownPollHandle === null) {
        knownPollHandle = setInterval(refreshKnownClients, KNOWN_POLL_INTERVAL_MS);
      }
    } else if (knownPollHandle !== null) {
      clearInterval(knownPollHandle);
      knownPollHandle = null;
    }
    return () => {
      if (knownPollHandle !== null) {
        clearInterval(knownPollHandle);
        knownPollHandle = null;
      }
    };
  });

  // Sorted view of `knownClients` driven by the column-header click
  // state. Comparators are picked per-field so numeric columns sort
  // numerically (not lexicographically), date columns sort by the raw
  // unix epoch the backend supplies, and string columns are compared
  // case-insensitively. `null`/empty values are pushed to the end on
  // ascending sort and to the start on descending sort so the UI never
  // shows a block of "—" cells in the middle of the list.
  const KNOWN_IDENT_ORDER: Record<string, number> = {
    Verified: 0, Needed: 1, Unknown: 2, Failed: 3, BadGuy: 4,
  };
  let sortedKnownClients = $derived.by(() => {
    if (knownClients.length === 0) return knownClients;
    const sorted = [...knownClients];
    const dir = knSortAsc ? 1 : -1;
    const cmpStr = (a: string | null | undefined, b: string | null | undefined) => {
      const ax = (a ?? '').toLowerCase();
      const bx = (b ?? '').toLowerCase();
      if (ax === bx) return 0;
      // Empty values sort last regardless of direction.
      if (!ax) return 1;
      if (!bx) return -1;
      return ax < bx ? -1 : 1;
    };
    const cmpNum = (a: number, b: number) => a === b ? 0 : (a < b ? -1 : 1);
    sorted.sort((a, b) => {
      let raw: number;
      switch (knSortField) {
        case 'user_hash':
          raw = cmpStr(a.user_hash, b.user_hash);
          break;
        case 'last_known_ip':
          raw = cmpStr(a.last_known_ip, b.last_known_ip);
          break;
        case 'uploaded':
          raw = cmpNum(a.uploaded, b.uploaded);
          break;
        case 'downloaded':
          raw = cmpNum(a.downloaded, b.downloaded);
          break;
        case 'credit_ratio':
          raw = cmpNum(a.credit_ratio, b.credit_ratio);
          break;
        case 'ident_state':
          raw = cmpNum(
            KNOWN_IDENT_ORDER[a.ident_state] ?? 99,
            KNOWN_IDENT_ORDER[b.ident_state] ?? 99,
          );
          break;
        case 'last_seen':
          raw = cmpNum(a.last_seen, b.last_seen);
          break;
      }
      // Stable secondary sort by user_hash so equal primary keys produce
      // a deterministic order across re-renders / re-polls.
      if (raw === 0) return cmpStr(a.user_hash, b.user_hash);
      return raw * dir;
    });
    return sorted;
  });

  // --- Sorting ---
  type DlSortField = 'file_name' | 'total_size' | 'transferred' | 'completed_size' | 'speed' | 'progress' | 'sources' | 'priority' | 'status' | 'remaining' | 'last_seen_complete' | 'last_received' | 'category' | 'started_at';
  type UlSortField = 'peer_name' | 'file_name' | 'speed' | 'transferred' | 'waited' | 'upload_time' | 'status' | 'client_software';
  type KnSortField = 'user_hash' | 'last_known_ip' | 'uploaded' | 'downloaded' | 'credit_ratio' | 'ident_state' | 'last_seen';
  const DL_SORT_FIELDS: DlSortField[] = ['file_name', 'total_size', 'transferred', 'completed_size', 'speed', 'progress', 'sources', 'priority', 'status', 'remaining', 'last_seen_complete', 'last_received', 'category', 'started_at'];
  const UL_SORT_FIELDS: UlSortField[] = ['peer_name', 'file_name', 'speed', 'transferred', 'waited', 'upload_time', 'status', 'client_software'];
  const KN_SORT_FIELDS: KnSortField[] = ['user_hash', 'last_known_ip', 'uploaded', 'downloaded', 'credit_ratio', 'ident_state', 'last_seen'];
  function safeGetItem(key: string): string | null { try { return localStorage.getItem(key); } catch { return null; } }
  let dlSortField: DlSortField = $state(DL_SORT_FIELDS.includes(safeGetItem('transfers-dl-sort-field') as DlSortField) ? safeGetItem('transfers-dl-sort-field') as DlSortField : 'file_name');
  let dlSortAsc = $state(safeGetItem('transfers-dl-sort-asc') !== 'false');
  let ulSortField: UlSortField = $state(UL_SORT_FIELDS.includes(safeGetItem('transfers-ul-sort-field') as UlSortField) ? safeGetItem('transfers-ul-sort-field') as UlSortField : 'file_name');
  let ulSortAsc = $state(safeGetItem('transfers-ul-sort-asc') !== 'false');
  // Default Known Clients sort: most-recently-seen first. Matches the
  // backend snapshot's default ordering so the first paint is stable
  // even before the user picks a column. `dlSortAsc` semantics: true =
  // ascending in display order; for `last_seen` ascending means
  // oldest-first, so we invert the default to false (descending = newest
  // first) to match the backend.
  let knSortField: KnSortField = $state(KN_SORT_FIELDS.includes(safeGetItem('transfers-kn-sort-field') as KnSortField) ? safeGetItem('transfers-kn-sort-field') as KnSortField : 'last_seen');
  let knSortAsc = $state(safeGetItem('transfers-kn-sort-asc') === 'true');

  function toggleDlSort(field: DlSortField) {
    if (dlSortField === field) dlSortAsc = !dlSortAsc;
    else { dlSortField = field; dlSortAsc = true; }
    localStorage.setItem('transfers-dl-sort-field', dlSortField);
    localStorage.setItem('transfers-dl-sort-asc', String(dlSortAsc));
  }
  function toggleUlSort(field: UlSortField) {
    if (ulSortField === field) ulSortAsc = !ulSortAsc;
    else { ulSortField = field; ulSortAsc = true; }
    localStorage.setItem('transfers-ul-sort-field', ulSortField);
    localStorage.setItem('transfers-ul-sort-asc', String(ulSortAsc));
  }
  function toggleKnSort(field: KnSortField) {
    if (knSortField === field) {
      knSortAsc = !knSortAsc;
    } else {
      // First click on a new column picks the "natural" direction:
      // numeric/date columns default to descending (largest first),
      // string columns default to ascending (A-Z first). Matches the
      // sorting UX in eMule and most file managers.
      knSortField = field;
      knSortAsc = field === 'user_hash' || field === 'last_known_ip' || field === 'ident_state';
    }
    localStorage.setItem('transfers-kn-sort-field', knSortField);
    localStorage.setItem('transfers-kn-sort-asc', String(knSortAsc));
  }
  function sortArrow(current: string, field: string, asc: boolean): string {
    if (current !== field) return '';
    return asc ? ' \u25B2' : ' \u25BC';
  }

  const priorityOrder: Record<string, number> = { release: 0, auto: 1, high: 2, normal: 3, low: 4, verylow: 5 };
  const statusOrder: Record<string, number> = { active: 0, verifying: 1, completing: 2, searching: 3, queued: 4, paused: 5, stopped: 6, hashing: 7, noneneeded: 8, insufficient: 9, failed: 10, completed: 11 };

  // Client-side EWMA speed tracker: computes speed from transferred-byte
  // deltas so the display works even when the backend reports speed=0.
  const speedHistory: Map<string, { ewma: number; lastTransferred: number; lastTime: number }> = new Map();

  // Prune `speedHistory` entries for transfers that no longer exist in the
  // store. Without this the map grows unbounded for the life of the page
  // whenever the backend removes a transfer via an event path the UI's
  // local `speedHistory.delete(...)` callers don't cover (e.g. backend
  // finalise / retention policies, or peers dropping).
  $effect(() => {
    const liveIds = new Set($transfers.map((t) => t.id));
    if (speedHistory.size > liveIds.size) {
      for (const id of Array.from(speedHistory.keys())) {
        if (!liveIds.has(id)) speedHistory.delete(id);
      }
    }
  });
  const EWMA_ALPHA = 0.3;
  const SPEED_STALE_MS = 12_000;

  // D8: EWMA updates run in a single $effect keyed on `$transfers`, not
  // inside sort comparators / templates. Previously every call site
  // mutated speedHistory as a side effect of reading, which made sort
  // order sensitive to call order and complicated reasoning.
  $effect(() => {
    const list = $transfers;
    const now = Date.now();
    for (const t of list) {
      const entry = speedHistory.get(t.id);
      if (!entry) {
        speedHistory.set(t.id, { ewma: 0, lastTransferred: t.transferred, lastTime: now });
        continue;
      }
      const dt = (now - entry.lastTime) / 1000;
      if (dt < 0.5) continue;
      const bytesThisPeriod = t.transferred - entry.lastTransferred;
      if (bytesThisPeriod > 0) {
        const measuredSpeed = bytesThisPeriod / dt;
        entry.ewma = EWMA_ALPHA * measuredSpeed + (1 - EWMA_ALPHA) * entry.ewma;
        entry.lastTransferred = t.transferred;
        entry.lastTime = now;
      } else if (now - entry.lastTime > SPEED_STALE_MS) {
        entry.ewma = 0;
      }
    }
  });

  /** Read the latest EWMA for a transfer. Pure — does not mutate
   *  speedHistory; updates happen in the $effect above. Falls back to the
   *  backend-reported `t.speed` when no EWMA is recorded yet. */
  function liveSpeed(t: Transfer): number {
    const entry = speedHistory.get(t.id);
    if (!entry) return t.speed > 0 ? t.speed : 0;
    if (entry.ewma > 0) return entry.ewma;
    return t.speed > 0 ? t.speed : 0;
  }

  /** D23: pick the progress-bar fill colour for a download row. Respects
   *  both status (paused/stopped/verifying/completing/failed) and health
   *  (stalled / degraded) so an active row with bad health doesn't still
   *  render the healthy accent colour. */
  function downloadProgressColor(t: Transfer): string {
    if (t.status === 'failed') return 'var(--danger)';
    if (t.status === 'paused' || t.status === 'stopped') return 'var(--warning)';
    if (t.status === 'verifying' || t.status === 'completing' || t.status === 'completed') {
      return 'var(--success, #2ecc71)';
    }
    if (t.status === 'active') {
      if (t.health === 'stalled') return 'var(--danger)';
      if (t.health === 'degraded') return 'var(--warning)';
    }
    return 'var(--accent)';
  }

  function etaSeconds(t: Transfer): number {
    const completed = t.completed_size ?? t.transferred;
    if (completed >= t.total_size) return Infinity;
    const speed = liveSpeed(t);
    if (speed <= 0) return Infinity;
    return (t.total_size - completed) / speed;
  }

  /** Shared download-sort comparator. D25 applies the same order to the
   *  Completed section so the user's sort preference isn't silently
   *  ignored for finished rows. */
  function compareDownloads(a: Transfer, b: Transfer): number {
    let cmp = 0;
    switch (dlSortField) {
      case 'file_name': cmp = a.file_name.localeCompare(b.file_name); break;
      case 'total_size': cmp = a.total_size - b.total_size; break;
      case 'transferred': cmp = a.transferred - b.transferred; break;
      case 'completed_size': cmp = (a.completed_size || 0) - (b.completed_size || 0); break;
      case 'speed': {
        const la = liveSpeed(a), lb = liveSpeed(b);
        cmp = (la > 0 ? la : a.speed) - (lb > 0 ? lb : b.speed);
        break;
      }
      case 'progress': cmp = a.progress - b.progress; break;
      case 'sources': cmp = a.sources - b.sources; break;
      case 'priority': cmp = (priorityOrder[a.priority] ?? 2) - (priorityOrder[b.priority] ?? 2); break;
      case 'status': cmp = (statusOrder[a.status] ?? 9) - (statusOrder[b.status] ?? 9); break;
      case 'remaining': {
        const ea = etaSeconds(a), eb = etaSeconds(b);
        cmp = (isFinite(ea) ? ea : Number.MAX_SAFE_INTEGER) - (isFinite(eb) ? eb : Number.MAX_SAFE_INTEGER);
        break;
      }
      case 'last_seen_complete': cmp = (a.last_seen_complete ?? 0) - (b.last_seen_complete ?? 0); break;
      case 'last_received': cmp = (a.last_received ?? 0) - (b.last_received ?? 0); break;
      case 'category': cmp = (a.category || '').localeCompare(b.category || ''); break;
      case 'started_at': cmp = a.started_at - b.started_at; break;
    }
    return dlSortAsc ? cmp : -cmp;
  }

  let sortedActiveDownloads = $derived.by(() => {
    return [...activeDownloads].sort(compareDownloads);
  });
  let sortedCompletedDownloads = $derived.by(() => {
    return [...completedDownloads].sort(compareDownloads);
  });

  let filteredActiveDownloads = $derived.by(() => {
    const query = transferFilter.trim().toLowerCase();
    if (!query) return sortedActiveDownloads;
    return sortedActiveDownloads.filter((t) =>
      t.file_name.toLowerCase().includes(query)
      || t.file_hash.toLowerCase().includes(query)
      || (t.category || '').toLowerCase().includes(query)
      || dlStatusLabel(t).toLowerCase().includes(query)
      // D24: also match peer fields so the shared filter actually works
      // against visible peer-name cells.
      || (t.peer_name || '').toLowerCase().includes(query)
      || (t.peer_id || '').toLowerCase().includes(query)
    );
  });
  let filteredCompletedDownloads = $derived.by(() => {
    const query = transferFilter.trim().toLowerCase();
    if (!query) return sortedCompletedDownloads;
    return sortedCompletedDownloads.filter((t) =>
      t.file_name.toLowerCase().includes(query)
      || t.file_hash.toLowerCase().includes(query)
      || (t.category || '').toLowerCase().includes(query)
      || dlStatusLabel(t).toLowerCase().includes(query)
      || (t.peer_name || '').toLowerCase().includes(query)
      || (t.peer_id || '').toLowerCase().includes(query)
    );
  });
  let filteredActiveUploads = $derived.by(() => {
    const query = transferFilter.trim().toLowerCase();
    if (!query) return sortedActiveUploads;
    return sortedActiveUploads.filter((t) =>
      t.file_name.toLowerCase().includes(query)
      || (t.peer_name || '').toLowerCase().includes(query)
      || (t.peer_id || '').toLowerCase().includes(query)
      || (t.client_software || '').toLowerCase().includes(query)
      || ulStatusLabel(t).toLowerCase().includes(query)
    );
  });
  // Removed `filteredCompletedUploads`, `filteredFailedUploads`,
  // `filteredQueuedUploads` derivations — they fed UI sections that no
  // longer exist (terminal upload rows are dropped from the store, and
  // the queued tab now uses `uploadQueueClients` from a backend snapshot
  // rather than a `Transfer`-status filter).

  let visibleActiveDownloadIds = $derived.by(() => new Set(filteredActiveDownloads.map((t) => t.id)));

  let selectedTransfer = $derived.by(() => {
    if (selectedDownloadIds.length !== 1) return null;
    return allDownloads.find((t) => t.id === selectedDownloadIds[0]) ?? null;
  });

  let selectedDownloadCount = $derived(selectedDownloadIds.length);

  function resolveLastClickedDlIndex(): number {
    if (!lastClickedDlId) return -1;
    return filteredActiveDownloads.findIndex((t) => t.id === lastClickedDlId);
  }

  let preClickSelection: string[] | null = null;
  let lastRowClickTime = 0;

  function onDownloadRowClick(e: MouseEvent, t: Transfer) {
    const now = Date.now();
    if (now - lastRowClickTime > 400) {
      preClickSelection = [...selectedDownloadIds];
    }
    lastRowClickTime = now;

    const idx = filteredActiveDownloads.indexOf(t);
    const lastIdx = resolveLastClickedDlIndex();
    if (e.shiftKey && lastIdx >= 0) {
      e.preventDefault();
      const lo = Math.min(lastIdx, idx);
      const hi = Math.max(lastIdx, idx);
      const rangeIds = filteredActiveDownloads.slice(lo, hi + 1).map((x) => x.id);
      const merged = new Set([...selectedDownloadIds, ...rangeIds]);
      selectedDownloadIds = [...merged];
    } else if (e.ctrlKey || e.metaKey) {
      e.preventDefault();
      if (selectedDlIdSet.has(t.id)) {
        selectedDownloadIds = selectedDownloadIds.filter((id) => id !== t.id);
      } else {
        selectedDownloadIds = [...selectedDownloadIds, t.id];
      }
    } else {
      selectedDownloadIds = [t.id];
    }
    lastClickedDlId = t.id;
  }

  function toggleDlCheck(t: Transfer, shiftKey: boolean) {
    const idx = filteredActiveDownloads.indexOf(t);
    const lastIdx = resolveLastClickedDlIndex();
    if (shiftKey && lastIdx >= 0 && lastIdx !== idx) {
      const lo = Math.min(lastIdx, idx);
      const hi = Math.max(lastIdx, idx);
      const rangeIds = filteredActiveDownloads.slice(lo, hi + 1).map((x) => x.id);
      const merged = new Set([...selectedDownloadIds, ...rangeIds]);
      selectedDownloadIds = [...merged];
    } else {
      if (selectedDlIdSet.has(t.id)) {
        selectedDownloadIds = selectedDownloadIds.filter((id) => id !== t.id);
      } else {
        selectedDownloadIds = [...selectedDownloadIds, t.id];
      }
    }
    lastClickedDlId = t.id;
  }

  let allActiveDlChecked = $derived(
    filteredActiveDownloads.length > 0 &&
    filteredActiveDownloads.every((t) => selectedDlIdSet.has(t.id))
  );
  let someActiveDlChecked = $derived(
    filteredActiveDownloads.some((t) => selectedDlIdSet.has(t.id))
  );

  function toggleDlCheckAll() {
    if (allActiveDlChecked) {
      const visibleIds = new Set(filteredActiveDownloads.map((t) => t.id));
      selectedDownloadIds = selectedDownloadIds.filter((id) => !visibleIds.has(id));
    } else {
      const merged = new Set([...selectedDownloadIds, ...filteredActiveDownloads.map((t) => t.id)]);
      selectedDownloadIds = [...merged];
    }
  }

  function clearDlSelection() {
    selectedDownloadIds = [];
    lastClickedDlId = null;
  }

  function transfersForBatchAction(): Transfer[] {
    return selectedDownloadIds
      .map((id) => allDownloads.find((x) => x.id === id))
      .filter((x): x is Transfer => x !== undefined);
  }
  // Helper that prefers the EWMA-smoothed `liveSpeed` rate used for row
  // cells, falling back to the raw `t.speed` value from the backend. Sort
  // and totals need to agree with what the user sees in each row; using
  // `t.speed` alone diverges when the backend reports 0 but bytes are
  // still flowing (very common during brief scheduling gaps).
  function displaySpeed(t: Transfer): number {
    const live = liveSpeed(t);
    return live > 0 ? live : (t.speed > 0 ? t.speed : 0);
  }
  // Match eMule-style behavior: show rate when transfer data is actually flowing.
  let totalDownloadRate = $derived(activeDownloads.reduce((sum, t) => sum + displaySpeed(t), 0));
  let totalUploadRate = $derived(activeUploads.reduce((sum, t) => sum + displaySpeed(t), 0));
  let transferringDownloads = $derived(activeDownloads.filter((t) => displaySpeed(t) > 0).length);
  let totalKnownSources = $derived(activeDownloads.reduce((sum, t) => sum + (t.sources || 0), 0));
  let activeConnectedSources = $derived(activeDownloads.reduce((sum, t) => sum + (t.active_sources || 0) + (t.queued_sources || 0), 0));

  let sortedActiveUploads = $derived.by(() => {
    const sorted = [...activeUploads];
    sorted.sort((a, b) => {
      let cmp = 0;
      switch (ulSortField) {
        case 'peer_name': cmp = (a.peer_name || a.peer_id).localeCompare(b.peer_name || b.peer_id); break;
        case 'file_name': cmp = a.file_name.localeCompare(b.file_name); break;
        case 'speed': cmp = displaySpeed(a) - displaySpeed(b); break;
        case 'transferred': cmp = a.transferred - b.transferred; break;
        case 'waited': cmp = (a.wait_time || 0) - (b.wait_time || 0); break;
        case 'upload_time': cmp = (a.upload_time || 0) - (b.upload_time || 0); break;
        case 'status': cmp = (statusOrder[a.status] ?? 9) - (statusOrder[b.status] ?? 9); break;
        case 'client_software': cmp = (a.client_software || '').localeCompare(b.client_software || ''); break;
      }
      return ulSortAsc ? cmp : -cmp;
    });
    return sorted;
  });

  // --- eMule-style status labels ---
  function failureBadgeLabel(t: Transfer): string {
    if (t.failure_kind === 'download_timeout') return 'Timeout';
    if (t.failure_kind === 'permanent') return 'Permanent Error';
    if (t.failure_stage === 'queue_wait') return 'Queue Wait';
    if (t.failure_stage === 'tcp_connect') return 'Connect Error';
    if (t.failure_reason) return t.failure_reason;
    return 'Error';
  }

  function dlStatusLabel(t: Transfer): string {
    switch (t.status) {
      case 'active':
        if (t.health === 'stalled') return 'Stalled';
        if (t.health === 'degraded') return 'Downloading (Idle)';
        return 'Downloading';
      case 'searching': {
        if (t.health === 'degraded' && t.health_reason) return 'Searching (Delayed)';
        if (t.sources > 0) return `Searching (${t.sources} src)`;
        const connected = $networkStats.status === 'connected' || $networkStats.status === 'connecting';
        return connected ? 'Searching' : 'Waiting';
      }
      case 'queued':
        if (t.sources === 0) return 'Searching';
        if (t.queue_rank != null && t.queue_rank > 0) return `Queued (QR: ${t.queue_rank})`;
        return 'Queued';
      case 'paused': return 'Paused';
      case 'stopped': return 'Stopped';
      case 'verifying': return 'Verifying';
      case 'completing': return 'Completing';
      case 'completed': return 'Complete';
      case 'failed': return failureBadgeLabel(t);
      case 'hashing': return 'Hashing';
      case 'insufficient': return 'Insufficient Disk';
      case 'noneneeded': return 'No Needed Parts';
      default: return t.status;
    }
  }

  function sourcesLabel(t: Transfer): string {
    const active = t.active_sources || 0;
    const queued = t.queued_sources || 0;
    const current = active + queued;
    if (!t.sources) {
      // L11: if the backend reports 0 known sources but there's live
      // activity (active/queued > 0), show what's live rather than an
      // em-dash that disagrees with the tooltip.
      return current > 0 ? `${current}` : '\u2014';
    }
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
      case 'active':
        if (t.total_size > 0 && t.transferred >= t.total_size) return 'Complete';
        return 'Transferring';
      case 'completed': return 'Complete';
      case 'failed': {
        const reason = (t.failure_reason || '').toLowerCase();
        // Map common failure messages to short, human labels so the
        // Completed / Failed section doesn't just say "Error" for every row.
        if (reason.includes('timeout') || reason.includes('timed out')) return 'Timeout';
        if (reason.includes('refused')) return 'Refused';
        if (reason.includes('reset') || reason.includes('eof')) return 'Disconnected';
        if (reason.includes('cancel')) return 'Cancelled';
        if (reason.includes('hash') && reason.includes('mismatch')) return 'Bad data';
        return 'Error';
      }
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
  let ctxTransfer = $derived.by(() => {
    const menu = ctxMenu;
    if (!menu) return null;
    return $transfers.find(t => t.id === menu.transfer.id) ?? menu.transfer;
  });
  let ctxPrioritySub = $state(false);
  let ctxCategorySub = $state(false);
  const CATEGORY_OPTIONS = ['None', 'Audio', 'Video', 'Image', 'Archive', 'Document', 'Program'] as const;

  function onCtx(e: MouseEvent, t: Transfer, section: 'active' | 'completed' | 'upload') {
    e.preventDefault();
    closeColumnMenu();
    ctxPrioritySub = false;
    ctxCategorySub = false;
    const margin = 8;
    const x = Math.max(margin, Math.min(e.clientX, window.innerWidth - 220 - margin));
    const y = Math.max(margin, Math.min(e.clientY, window.innerHeight - 300 - margin));
    ctxMenu = { x, y, transfer: t, section };
  }
  function closeCtx() { ctxMenu = null; ctxPrioritySub = false; ctxCategorySub = false; }
  function closeColumnMenu() { columnMenu = null; }

  function onDocClick() {
    closeCtx();
    closeColumnMenu();
  }

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
        case 'remove': await removeTransfer(t.id); speedHistory.delete(t.id); transfers.update((list) => list.filter((x) => x.id !== t.id)); break;
        case 'open': await openFile(t.id); break;
        case 'open_location': await openTransferFileLocation(t.id); break;
        case 'priority': if (extra) await setTransferPriority(t.id, extra as 'verylow' | 'low' | 'normal' | 'high' | 'release' | 'auto'); break;
        case 'find_sources': await findSources(t.file_hash, t.total_size); break;
        case 'preview': await previewFile(t.id); break;
        case 'toggle_preview_prio': { const live = $transfers.find(x => x.id === t.id); await setPreviewPriority(t.id, !(live ?? t).preview_priority); break; }
        case 'recover_archive': {
          // D27: confirm before a potentially-long rebuild; actual recovery
          // fires from the dialog below. Shows a spinner overlay while the
          // Rust task runs so the UI doesn't look frozen.
          confirmRecover = { open: true, id: t.id, name: t.file_name };
          return;
        }
        case 'clear_completed': confirmClearCompleted = true; return;
        case 'copy_link': {
          const link = await formatEd2kLink(t.file_name, t.total_size, t.file_hash);
          await navigator.clipboard.writeText(link);
          break;
        }
        case 'paste_link': {
          const text = await navigator.clipboard.readText();
          const trimmed = text.trim();
          if (trimmed.length > MAX_PASTE_LEN) {
            transferError = `Clipboard text is too long (${trimmed.length} chars, max ${MAX_PASTE_LEN}) — eD2K links are typically under 1 KiB`;
            break;
          }
          if (trimmed.toLowerCase().startsWith('ed2k://')) {
            const info = await parseEd2kLink(trimmed);
            const res = await startDownload(info.hash, info.name, info.size, '', 0);
            showInfo(res.already_queued
              ? `Already in download list: ${info.name}`
              : `Queued from clipboard: ${info.name}`);
          } else {
            transferError = 'Clipboard does not contain an ed2k:// link';
          }
          break;
        }
        case 'set_category': if (extra !== undefined) await setTransferCategory(t.id, extra === 'None' ? '' : extra); break;
        case 'add_friend': {
          if (!t.user_hash) { transferError = 'No user hash available for this peer'; break; }
          await addFriend(t.user_hash, t.peer_name || undefined);
          showInfo(`Added ${t.peer_name || t.user_hash.slice(0, 8) + '\u2026'} as friend`);
          break;
        }
        case 'ban_user': {
          if (!t.user_hash) { transferError = 'No user hash available for this peer'; break; }
          await banPeer(t.user_hash);
          showInfo(`Banned ${t.peer_name || t.user_hash.slice(0, 8) + '\u2026'}`);
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

  // Header-level "Paste link" — same flow as the row context-menu's
  // `paste_link` action, hoisted to a visible button so users don't
  // have to right-click an existing transfer (which is the only place
  // the action is otherwise discoverable). Reads ed2k:// from the
  // clipboard and queues a download.
  //
  // Length cap is generous (real ed2k:// links are well under 1 KiB
  // even with an AICH root and source list) but bounded so a paste of
  // megabytes doesn't reach the parser at all. Backend validation is
  // still the real boundary; this is just defense-in-depth + UX.
  const MAX_PASTE_LEN = 4096;
  let pasteLinkBusy = $state(false);
  async function handlePasteLinkFromHeader() {
    if (pasteLinkBusy) return;
    pasteLinkBusy = true;
    try {
      const text = (await navigator.clipboard.readText()).trim();
      if (text.length > MAX_PASTE_LEN) {
        transferError = `Clipboard text is too long (${text.length} chars, max ${MAX_PASTE_LEN}) — eD2K links are typically under 1 KiB`;
        return;
      }
      if (!text.toLowerCase().startsWith('ed2k://')) {
        transferError = 'Clipboard does not contain an ed2k:// link';
        return;
      }
      const info = await parseEd2kLink(text);
      const res = await startDownload(info.hash, info.name, info.size, '', 0);
      showInfo(res.already_queued
        ? `Already in download list: ${info.name}`
        : `Queued from clipboard: ${info.name}`);
    } catch (e: unknown) {
      transferError = toErrorMsg(e);
    } finally {
      pasteLinkBusy = false;
    }
  }

  async function runSelectedAction(action: 'pause' | 'resume' | 'stop' | 'sources' | 'preview') {
    if (!selectedTransfer) return;
    try {
      if (action === 'pause' && canPause(selectedTransfer)) await pauseTransfer(selectedTransfer.id);
      if (action === 'resume' && canResume(selectedTransfer)) await resumeTransfer(selectedTransfer.id);
      if (action === 'stop' && canStop(selectedTransfer)) await stopTransfer(selectedTransfer.id);
      if (action === 'sources') await findSources(selectedTransfer.file_hash, selectedTransfer.total_size);
      if (action === 'preview') await previewFile(selectedTransfer.id);
    } catch (e: unknown) {
      transferError = toErrorMsg(e);
    }
  }

  /** D29: render "Paused 5 of 6 transfers (1 failed: foo.zip)" so the
   *  user knows which rows in a batch didn't get the action applied. */
  function summarizeBatchResult(label: string, total: number, failed: { id: string; name: string; error: string }[]) {
    if (failed.length === 0) {
      showInfo(`${label} ${total} transfer${total === 1 ? '' : 's'}`);
      return;
    }
    const firstName = failed[0].name || failed[0].id.slice(0, 8);
    const rest = failed.length - 1;
    const restSuffix = rest > 0 ? ` (+${rest} more)` : '';
    transferError = `${label} ${total - failed.length} of ${total} transfers — failed: ${firstName}${restSuffix}: ${failed[0].error}`;
  }

  /** Run a per-id action in a bounded-concurrency loop so one bad id
   *  doesn't block the rest of the batch. */
  async function runBatchPerId(
    ids: string[],
    fn: (id: string) => Promise<void>,
    label: string,
  ): Promise<void> {
    if (!ids.length) return;
    const failed: { id: string; name: string; error: string }[] = [];
    const byId = new Map($transfers.map((t) => [t.id, t.file_name] as const));
    for (const id of ids) {
      try {
        await fn(id);
      } catch (e: unknown) {
        failed.push({ id, name: byId.get(id) ?? '', error: toErrorMsg(e) });
      }
    }
    summarizeBatchResult(label, ids.length, failed);
  }

  async function handleBatchPauseDownloads() {
    const ids = transfersForBatchAction().filter((t) => canPause(t)).map((t) => t.id);
    await runBatchPerId(ids, (id) => pauseTransfer(id), 'Paused');
  }

  async function handleBatchResumeDownloads() {
    const ids = transfersForBatchAction().filter((t) => canResume(t)).map((t) => t.id);
    await runBatchPerId(ids, (id) => resumeTransfer(id), 'Resumed');
  }

  async function handleBatchStopDownloads() {
    const ids = transfersForBatchAction().filter((t) => canStop(t)).map((t) => t.id);
    await runBatchPerId(ids, (id) => stopTransfer(id), 'Stopped');
  }

  let confirmBatchCancel = $state({ open: false, ids: [] as string[], count: 0 });

  function handleBatchCancelDownloads() {
    const ids = transfersForBatchAction()
      .filter((t) => t.status !== 'completed' && t.status !== 'failed')
      .map((t) => t.id);
    if (!ids.length) return;
    confirmBatchCancel = { open: true, ids, count: ids.length };
  }

  // --- Splitter ---
  let splitPercent = $state(60);
  let dragging = $state(false);
  let containerEl: HTMLDivElement | undefined = $state(undefined);

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

  onDestroy(() => {
    dragCleanup?.();
    endColumnResize();
  });

  function onSplitterKeydown(e: KeyboardEvent) {
    let newVal = splitPercent;
    switch (e.key) {
      case 'ArrowUp': newVal = splitPercent - 5; break;
      case 'ArrowDown': newVal = splitPercent + 5; break;
      case 'Home': newVal = 20; break;
      case 'End': newVal = 80; break;
      default: return;
    }
    e.preventDefault();
    splitPercent = Math.max(20, Math.min(80, newVal));
    localStorage.setItem('transfers-split', String(splitPercent));
  }

  function toggleAdvancedDlCols() {
    applyDownloadColumnPreset(showAdvancedDlCols);
  }

  function ariaSortValue(currentField: string, field: string, asc: boolean): 'ascending' | 'descending' | 'none' {
    if (currentField !== field) return 'none';
    return asc ? 'ascending' : 'descending';
  }

  function sortOnKey(e: KeyboardEvent, fn: () => void) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fn(); }
  }

  function onDownloadHeaderClick(column: TransferColumn<DlSortField>) {
    if (Date.now() < suppressHeaderClickUntil) return;
    if (!column.sortField) return;
    toggleDlSort(column.sortField);
  }

  function onDownloadHeaderKeydown(event: KeyboardEvent, column: TransferColumn<DlSortField>) {
    const sortField = column.sortField;
    if (!sortField) return;
    sortOnKey(event, () => toggleDlSort(sortField));
  }

  function onUploadHeaderClick(column: TransferColumn<UlSortField>) {
    if (Date.now() < suppressHeaderClickUntil) return;
    if (!column.sortField) return;
    toggleUlSort(column.sortField);
  }

  function onUploadHeaderKeydown(event: KeyboardEvent, column: TransferColumn<UlSortField>) {
    const sortField = column.sortField;
    if (!sortField) return;
    sortOnKey(event, () => toggleUlSort(sortField));
  }

  function onKnownHeaderClick(column: TransferColumn<KnSortField>) {
    if (Date.now() < suppressHeaderClickUntil) return;
    if (!column.sortField) return;
    toggleKnSort(column.sortField);
  }

  function onKnownHeaderKeydown(event: KeyboardEvent, column: TransferColumn<KnSortField>) {
    const sortField = column.sortField;
    if (!sortField) return;
    sortOnKey(event, () => toggleKnSort(sortField));
  }

  function getFixedColumnKey(table: TableKey): string {
    return TABLE_COLUMNS[table][0].key;
  }

  function sanitizeColumnOrder(table: TableKey, rawOrder: unknown): string[] {
    const defaultOrder = createDefaultOrder(TABLE_COLUMNS[table]);
    if (!Array.isArray(rawOrder)) return defaultOrder;

    const seen = new Set<string>();
    const sanitized: string[] = [];
    for (const value of rawOrder) {
      if (typeof value !== 'string' || seen.has(value) || !defaultOrder.includes(value)) continue;
      seen.add(value);
      sanitized.push(value);
    }
    for (const key of defaultOrder) {
      if (!seen.has(key)) sanitized.push(key);
    }
    sanitized.splice(0, sanitized.length, getFixedColumnKey(table), ...sanitized.filter((key) => key !== getFixedColumnKey(table)));
    return sanitized;
  }

  function getOrderedColumnKeys(table: TableKey): string[] {
    return sanitizeColumnOrder(table, columnOrder[table]);
  }

  function getOrderedColumns(table: TableKey): TransferColumn[] {
    const definitions = TABLE_COLUMNS[table];
    return getOrderedColumnKeys(table)
      .map((key) => definitions.find((column) => column.key === key))
      .filter((column): column is TransferColumn => Boolean(column));
  }

  function isColumnHidden(table: TableKey, columnKey: string): boolean {
    if (columnKey === getFixedColumnKey(table)) return false;
    return Boolean(hiddenColumns[table][columnKey]);
  }

  function getVisibleColumns(table: TableKey): TransferColumn[] {
    return getOrderedColumns(table).filter((column) => !isColumnHidden(table, column.key));
  }

  let visibleDownloadColumns = $derived.by(() => getVisibleColumns('downloads') as TransferColumn<DlSortField>[]);
  let visibleUploadColumns = $derived.by(() => getVisibleColumns('uploads') as TransferColumn<UlSortField>[]);
  let visibleQueueColumns = $derived.by(() => getVisibleColumns('queue'));
  let visibleKnownColumns = $derived.by(() => getVisibleColumns('known') as TransferColumn<KnSortField>[]);
  let visibleClientColumns = $derived.by(() => getVisibleColumns('clients'));

  function getTableElement(table: TableKey): HTMLTableElement | undefined {
    switch (table) {
      case 'downloads': return downloadTableEl;
      case 'uploads': return uploadTableEl;
      case 'queue': return queueTableEl;
      case 'known': return knownTableEl;
      case 'clients': return clientsTableEl;
    }
  }

  function getColumnDefinition(table: TableKey, columnKey: string): TransferColumn | undefined {
    return TABLE_COLUMNS[table].find((column) => column.key === columnKey);
  }

  function getColumnWidth(table: TableKey, columnKey: string): number {
    return columnWidths[table][columnKey] ?? getColumnDefinition(table, columnKey)?.width ?? 80;
  }

  function getTableMinWidth(table: TableKey, columns: TransferColumn[]): number {
    return columns.reduce((sum, column) => sum + getColumnWidth(table, column.key), 0);
  }

  function clampColumnWidth(table: TableKey, columnKey: string, width: number): number {
    const column = getColumnDefinition(table, columnKey);
    if (!column) return Math.max(40, Math.round(width));
    return Math.max(column.minWidth, Math.round(width));
  }

  function setColumnWidth(table: TableKey, columnKey: string, width: number) {
    columnWidths[table][columnKey] = clampColumnWidth(table, columnKey, width);
  }

  function persistColumnWidths(table: TableKey) {
    localStorage.setItem(COLUMN_STORAGE_KEYS[table], JSON.stringify(columnWidths[table]));
  }

  function syncAdvancedDlState() {
    showAdvancedDlCols = DOWNLOAD_ADVANCED_COLUMN_KEYS.every((key) => !isColumnHidden('downloads', key));
    localStorage.setItem('transfers-advanced-cols', showAdvancedDlCols ? '1' : '0');
  }

  function loadStoredColumnWidths() {
    for (const table of Object.keys(TABLE_COLUMNS) as TableKey[]) {
      const saved = localStorage.getItem(COLUMN_STORAGE_KEYS[table]);
      if (!saved) continue;
      try {
        const parsed = JSON.parse(saved) as Record<string, unknown>;
        for (const column of TABLE_COLUMNS[table]) {
          const width = parsed[column.key];
          if (typeof width === 'number' && Number.isFinite(width)) {
            columnWidths[table][column.key] = clampColumnWidth(table, column.key, width);
          }
        }
      } catch {
        localStorage.removeItem(COLUMN_STORAGE_KEYS[table]);
      }
    }
  }

  function persistColumnSetup(table: TableKey) {
    localStorage.setItem(
      COLUMN_HIDDEN_STORAGE_KEYS[table],
      JSON.stringify(getOrderedColumns(table).filter((column) => isColumnHidden(table, column.key)).map((column) => column.key)),
    );
    localStorage.setItem(COLUMN_ORDER_STORAGE_KEYS[table], JSON.stringify(getOrderedColumnKeys(table)));
    if (table === 'downloads') syncAdvancedDlState();
  }

  function loadStoredColumnSetup(useLegacyCompactDownloads: boolean) {
    let hasDownloadHiddenState = false;

    for (const table of Object.keys(TABLE_COLUMNS) as TableKey[]) {
      const savedOrder = localStorage.getItem(COLUMN_ORDER_STORAGE_KEYS[table]);
      if (savedOrder) {
        try {
          columnOrder[table] = sanitizeColumnOrder(table, JSON.parse(savedOrder));
        } catch {
          localStorage.removeItem(COLUMN_ORDER_STORAGE_KEYS[table]);
        }
      }

      const savedHidden = localStorage.getItem(COLUMN_HIDDEN_STORAGE_KEYS[table]);
      if (savedHidden) {
        if (table === 'downloads') hasDownloadHiddenState = true;
        try {
          const parsed = JSON.parse(savedHidden);
          hiddenColumns[table] = createDefaultHidden(TABLE_COLUMNS[table]);
          if (Array.isArray(parsed)) {
            for (const value of parsed) {
              if (typeof value === 'string' && value !== getFixedColumnKey(table) && TABLE_COLUMNS[table].some((column) => column.key === value)) {
                hiddenColumns[table][value] = true;
              }
            }
          }
        } catch {
          localStorage.removeItem(COLUMN_HIDDEN_STORAGE_KEYS[table]);
        }
      }
    }

    if (useLegacyCompactDownloads && !hasDownloadHiddenState) {
      applyDownloadColumnPreset(true, false);
    }
  }

  function applyDownloadColumnPreset(compact: boolean, persist = true) {
    for (const key of DOWNLOAD_ADVANCED_COLUMN_KEYS) {
      hiddenColumns.downloads[key] = compact;
    }
    if (persist) persistColumnSetup('downloads');
    else syncAdvancedDlState();
  }

  function canToggleColumn(table: TableKey, columnKey: string): boolean {
    return columnKey !== getFixedColumnKey(table);
  }

  function toggleColumnVisibility(table: TableKey, columnKey: string) {
    if (!canToggleColumn(table, columnKey)) return;
    hiddenColumns[table][columnKey] = !isColumnHidden(table, columnKey);
    persistColumnSetup(table);
  }

  function resetColumnLayout(table: TableKey) {
    hiddenColumns[table] = createDefaultHidden(TABLE_COLUMNS[table]);
    columnOrder[table] = createDefaultOrder(TABLE_COLUMNS[table]);
    persistColumnSetup(table);
  }

  function getColumnMenuTitle(table: TableKey): string {
    switch (table) {
      case 'downloads': return 'Download Columns';
      case 'uploads': return 'Upload Columns';
      case 'queue': return 'Queued Columns';
      case 'known': return 'Known Clients Columns';
      case 'clients': return 'Client Columns';
    }
  }

  function getColumnMenuColumns(table: TableKey): TransferColumn[] {
    return getOrderedColumns(table).filter((column) => column.key !== getFixedColumnKey(table));
  }

  function openColumnMenu(event: MouseEvent, table: TableKey) {
    event.preventDefault();
    event.stopPropagation();
    closeCtx();
    const margin = 8;
    columnMenu = {
      table,
      x: Math.max(margin, Math.min(event.clientX, window.innerWidth - 240 - margin)),
      y: Math.max(margin, Math.min(event.clientY, window.innerHeight - 360 - margin)),
    };
  }

  function canDragColumn(table: TableKey, columnKey: string): boolean {
    return columnKey !== getFixedColumnKey(table) && !isColumnHidden(table, columnKey);
  }

  function moveColumn(table: TableKey, sourceKey: string, targetKey: string, position: 'before' | 'after') {
    if (sourceKey === targetKey) return;
    const nextOrder = [...getOrderedColumnKeys(table)];
    const sourceIndex = nextOrder.indexOf(sourceKey);
    const targetIndex = nextOrder.indexOf(targetKey);
    if (sourceIndex < 0 || targetIndex < 0) return;

    nextOrder.splice(sourceIndex, 1);
    let insertIndex = position === 'after' ? targetIndex + 1 : targetIndex;
    if (sourceIndex < insertIndex) insertIndex -= 1;
    insertIndex = Math.max(1, Math.min(insertIndex, nextOrder.length));
    nextOrder.splice(insertIndex, 0, sourceKey);
    nextOrder.splice(0, nextOrder.length, getFixedColumnKey(table), ...nextOrder.filter((key) => key !== getFixedColumnKey(table)));
    columnOrder[table] = nextOrder;
    persistColumnSetup(table);
  }

  function clearColumnDragState() {
    activeColumnDrag = null;
    columnDropTarget = null;
  }

  function updateColumnDropTarget(event: DragEvent, table: TableKey, columnKey: string) {
    if (!activeColumnDrag || activeColumnDrag.table !== table || activeColumnDrag.columnKey === columnKey) return;
    const headerCell = event.currentTarget;
    if (!(headerCell instanceof HTMLElement)) return;
    const rect = headerCell.getBoundingClientRect();
    const midpoint = rect.left + rect.width / 2;
    let position: 'before' | 'after' = event.clientX < midpoint ? 'before' : 'after';
    if (columnKey === getFixedColumnKey(table)) position = 'after';
    columnDropTarget = { table, columnKey, position };
  }

  function handleColumnDragStart(event: DragEvent, table: TableKey, columnKey: string) {
    if (!canDragColumn(table, columnKey)) {
      event.preventDefault();
      return;
    }
    closeColumnMenu();
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', columnKey);
    }
    activeColumnDrag = { table, columnKey };
    columnDropTarget = null;
  }

  function handleColumnDragOver(event: DragEvent, table: TableKey, columnKey: string) {
    if (!activeColumnDrag || activeColumnDrag.table !== table || activeColumnDrag.columnKey === columnKey) return;
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'move';
    updateColumnDropTarget(event, table, columnKey);
  }

  function handleColumnDrop(event: DragEvent, table: TableKey, columnKey: string) {
    if (!activeColumnDrag || activeColumnDrag.table !== table) return;
    event.preventDefault();
    updateColumnDropTarget(event, table, columnKey);
    const dropTarget = columnDropTarget;
    if (dropTarget && dropTarget.table === table) {
      moveColumn(table, activeColumnDrag.columnKey, dropTarget.columnKey, dropTarget.position);
      suppressHeaderClickUntil = Date.now() + 250;
    }
    clearColumnDragState();
  }

  function handleColumnDragEnd() {
    if (activeColumnDrag) suppressHeaderClickUntil = Date.now() + 250;
    clearColumnDragState();
  }

  function isDropBefore(table: TableKey, columnKey: string): boolean {
    return columnDropTarget?.table === table && columnDropTarget.columnKey === columnKey && columnDropTarget.position === 'before';
  }

  function isDropAfter(table: TableKey, columnKey: string): boolean {
    return columnDropTarget?.table === table && columnDropTarget.columnKey === columnKey && columnDropTarget.position === 'after';
  }

  function endColumnResize() {
    columnDragCleanup?.();
    columnDragCleanup = null;
    activeColumnResize = null;
  }

  function beginColumnResize(event: MouseEvent, table: TableKey, columnKey: string) {
    event.preventDefault();
    event.stopPropagation();
    endColumnResize();

    const startX = event.clientX;
    const startWidth = getColumnWidth(table, columnKey);
    const previousCursor = document.body.style.cursor;
    const previousUserSelect = document.body.style.userSelect;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    activeColumnResize = { table, columnKey };

    const onMove = (moveEvent: MouseEvent) => {
      setColumnWidth(table, columnKey, startWidth + (moveEvent.clientX - startX));
    };
    const onUp = () => {
      persistColumnWidths(table);
      document.body.style.cursor = previousCursor;
      document.body.style.userSelect = previousUserSelect;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      window.removeEventListener('blur', onUp);
      columnDragCleanup = null;
      activeColumnResize = null;
    };

    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    window.addEventListener('blur', onUp);
    columnDragCleanup = () => {
      document.body.style.cursor = previousCursor;
      document.body.style.userSelect = previousUserSelect;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      window.removeEventListener('blur', onUp);
    };
  }

  function getExtraLeadingColumns(table: TableKey): number {
    return table === 'downloads' ? 1 : 0;
  }

  function autoSizeColumn(event: MouseEvent, table: TableKey, columnKey: string) {
    event.preventDefault();
    event.stopPropagation();

    const tableEl = getTableElement(table);
    const visibleCols = getVisibleColumns(table);
    const columnIndex = visibleCols.findIndex((column) => column.key === columnKey);
    if (!tableEl || columnIndex < 0) return;

    const cellIndex = columnIndex + getExtraLeadingColumns(table);

    let bestWidth = getColumnDefinition(table, columnKey)?.minWidth ?? 40;
    const headerCell = tableEl.tHead?.rows.item(0)?.cells.item(cellIndex);
    if (headerCell instanceof HTMLElement) {
      bestWidth = Math.max(bestWidth, Math.ceil(headerCell.scrollWidth + 12));
    }

    for (const body of Array.from(tableEl.tBodies)) {
      for (const row of Array.from(body.rows)) {
        const cell = row.cells.item(cellIndex);
        if (!(cell instanceof HTMLElement) || cell.colSpan !== 1) continue;
        bestWidth = Math.max(bestWidth, Math.ceil(cell.scrollWidth + 12));
      }
    }

    setColumnWidth(table, columnKey, bestWidth);
    persistColumnWidths(table);
  }

  function swallowResizeClick(event: MouseEvent) {
    event.preventDefault();
    event.stopPropagation();
  }

  function isResizingColumn(table: TableKey, columnKey: string): boolean {
    return activeColumnResize?.table === table && activeColumnResize?.columnKey === columnKey;
  }

  function priorityTooltip(priority: string): string {
    switch (priority) {
      case 'high': return 'High: downloaded before normal and low priority files';
      case 'normal': return 'Normal: default download priority';
      case 'low': return 'Low: downloaded after high and normal priority files';
      case 'verylow': return 'Very Low: downloaded only when no higher priority files are waiting';
      case 'auto': return 'Auto: priority adjusted automatically based on file size and availability';
      case 'release': return 'Release: highest priority, downloaded before all other files';
      default: return priority;
    }
  }

  function dlStatusTooltip(t: Transfer): string {
    switch (t.status) {
      case 'active': {
        // D6: mirror dlStatusLabel's health-sensitive branches so the
        // tooltip never contradicts the label (e.g. label "Stalled" +
        // tooltip "Actively downloading").
        if (t.health === 'stalled') {
          return t.health_reason
            ? `Stalled — no data received recently. ${t.health_reason}`
            : 'Stalled — no data received recently';
        }
        if (t.health === 'degraded') {
          return t.health_reason
            ? `Downloading slowly or idle. ${t.health_reason}`
            : 'Downloading slowly or idle';
        }
        return t.health_reason
          ? `Actively downloading data from sources. ${t.health_reason}`
          : 'Actively downloading data from sources';
      }
      case 'searching': {
        const conn = $networkStats.status === 'connected' || $networkStats.status === 'connecting';
        const base = conn ? 'Searching for sources on the network' : 'Waiting to connect before searching';
        return t.health_reason ? `${base}. ${t.health_reason}` : base;
      }
      case 'queued':
        if (t.sources === 0) return 'No sources found yet, searching the network';
        return t.health_reason
          ? `Waiting in a remote client's upload queue. ${t.health_reason}`
          : 'Waiting in a remote client\'s upload queue';
      case 'paused': return 'Download paused by user';
      case 'stopped': return 'Download stopped by user';
      case 'verifying': return 'Verifying downloaded data integrity';
      case 'completing': return 'Moving completed file to destination';
      case 'completed': return 'Download finished successfully';
      case 'failed': return t.failure_reason ? `Download failed: ${t.failure_reason}` : 'Download failed';
      case 'hashing': return 'Computing file hash for verification';
      case 'insufficient': return 'Insufficient disk space to continue download';
      case 'noneneeded': return 'No sources have parts needed to complete the file';
      default: return t.status;
    }
  }

  function ulStatusTooltip(t: Transfer): string {
    switch (t.status) {
      case 'active':
        if (t.total_size > 0 && t.transferred >= t.total_size) return 'Upload to this client completed';
        return 'Actively uploading data to this client';
      case 'completed': return 'Upload to this client completed';
      case 'failed': {
        // Prefer the backend-supplied reason over a generic "failed" so the
        // user can understand why an upload dropped out (timeout, refused,
        // peer reset, hash mismatch, etc.).
        const reason = t.failure_reason?.trim();
        return reason ? `Upload failed: ${reason}` : 'Upload to this client failed';
      }
      default: return t.status;
    }
  }

  function sourcesTooltip(t: Transfer): string {
    if (!t.sources) return 'No sources found';
    const parts: string[] = [];
    parts.push(`${t.active_sources || 0} active`);
    parts.push(`${t.queued_sources || 0} queued`);
    parts.push(`${t.sources} total`);
    if (t.ember_sources > 0) parts.push(`${t.ember_sources} via Ember`);
    if (t.a4af_sources > 0) parts.push(`${t.a4af_sources} A4AF (asked for another file)`);
    if (t.max_sources > 0) parts.push(`max ${t.max_sources}`);
    return `Sources: ${parts.join(', ')}. Format: active/total+a4af [max]`;
  }

  let dlColCount = $derived(visibleDownloadColumns.length + 1);
  let ulColCount = $derived(visibleUploadColumns.length);
  let queueColCount = $derived(visibleQueueColumns.length);
  let knownColCount = $derived(visibleKnownColumns.length);
  let clientColCount = $derived(visibleClientColumns.length);

  $effect(() => {
    if (expandedTransferId && !visibleActiveDownloadIds.has(expandedTransferId)) {
      expandedTransferId = null;
      expandedSources = [];
      loadingSources = false;
      sourceDetailRequestId += 1;
    }
  });

  // When the currently-expanded transfer is paused or stopped, the
  // backend has torn down every peer connection for it — the
  // accumulated `expandedSources` list no longer reflects live state
  // (the rows that show Queued / Transferring would falsely imply
  // live peers on a paused download). Clear the panel so it matches
  // backend reality; on resume it will repopulate naturally from
  // the next `transfer-source-detail` push events.
  $effect(() => {
    if (!expandedTransferId) return;
    const t = activeDownloads.find((x) => x.id === expandedTransferId);
    if (!t) return;
    if (t.status === 'paused' || t.status === 'stopped') {
      expandedSources = [];
      // Invalidate any in-flight getTransferSources request so its
      // late-arriving response doesn't repopulate the list after
      // we've intentionally cleared it.
      sourceDetailRequestId += 1;
      loadingSources = false;
    }
  });

  $effect.pre(() => {
    const visible = visibleActiveDownloadIds;
    const next = selectedDownloadIds.filter((id) => visible.has(id));
    if (next.length !== selectedDownloadIds.length) {
      selectedDownloadIds = next;
    }
    // L12: keep the shift-range anchor in sync with selection pruning so
    // Shift+Click doesn't reach back to a row that's no longer visible.
    if (lastClickedDlId && !visible.has(lastClickedDlId)) {
      lastClickedDlId = null;
    }
  });
</script>

<svelte:document onclick={onDocClick} onkeydown={(e) => {
  if (e.key === 'Escape') {
    if (ctxMenu) { closeCtx(); e.preventDefault(); }
    else if (columnMenu) { closeColumnMenu(); e.preventDefault(); }
    return;
  }
  // D33: keyboard nav for download rows. Only hijack when focus is not
  // in a text input and no dialogs are open, so we don't disrupt the
  // filter box or confirm dialogs.
  const target = e.target as HTMLElement | null;
  const inEditable = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable);
  if (inEditable || ctxMenu || confirmCancel.open || confirmClearCompleted || confirmBatchCancel.open || confirmRecover.open) return;
  if (filteredActiveDownloads.length === 0) return;
  const currentId = selectedDownloadIds[selectedDownloadIds.length - 1];
  const idx = currentId ? filteredActiveDownloads.findIndex((t) => t.id === currentId) : -1;
  if (e.key === 'ArrowDown') {
    const next = filteredActiveDownloads[Math.min(filteredActiveDownloads.length - 1, idx + 1)];
    if (next) { selectedDownloadIds = [next.id]; lastClickedDlId = next.id; e.preventDefault(); }
  } else if (e.key === 'ArrowUp') {
    const next = filteredActiveDownloads[Math.max(0, idx < 0 ? 0 : idx - 1)];
    if (next) { selectedDownloadIds = [next.id]; lastClickedDlId = next.id; e.preventDefault(); }
  } else if ((e.key === 'Delete' || e.key === 'Backspace') && selectedDownloadIds.length > 0) {
    // Match the explicit UI control: prompt, don't just vaporize rows.
    const ids = [...selectedDownloadIds];
    confirmBatchCancel = { open: true, ids, count: ids.length };
    e.preventDefault();
  }
}} />

<div class="page-header">
  <h2>Transfers</h2>
  <div class="header-actions">
    <button
      class="ghost paste-link-btn"
      onclick={handlePasteLinkFromHeader}
      disabled={pasteLinkBusy}
      title="Read an ed2k:// link from the clipboard and start downloading"
    >
      <span class="paste-link-icon" aria-hidden="true">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <rect x="4" y="3" width="8" height="11" rx="1.5"/>
          <path d="M6 3v-.5a1 1 0 011-1h2a1 1 0 011 1V3"/>
          <line x1="6.5" y1="7.5" x2="9.5" y2="7.5"/>
          <line x1="6.5" y1="10" x2="9.5" y2="10"/>
        </svg>
      </span>
      {pasteLinkBusy ? 'Pasting…' : 'Paste eD2K Link'}
    </button>
  </div>
</div>

{#if transferError}
  <div class="error-banner">
    <span>{transferError}</span>
    <button class="ghost" onclick={() => transferError = null}>Dismiss</button>
  </div>
{/if}
{#if transferInfo}
  <div class="info-banner" role="status">
    <span>{transferInfo}</span>
    <button class="ghost" onclick={() => (transferInfo = null)}>Dismiss</button>
  </div>
{/if}

<div class="transfers-split" bind:this={containerEl}>
  <!-- TOP PANE: Downloads -->
  <div class="pane downloads-pane" style="flex: 0 0 {splitPercent}%;">
    <div class="transfer-overview-bar">
      <!--
        D7: these chips are payload-only rates summed over active transfers.
        The StatusBar shows the network rate (includes protocol overhead),
        which is expected to be higher. Tooltip clarifies the distinction.
      -->
      <span class="overview-chip" title="Active download payload rate (status bar shows total network rate)"><span class="overview-label">DL</span> {formatSpeed(totalDownloadRate)}</span>
      <span class="overview-chip" title="Active upload payload rate (status bar shows total network rate)"><span class="overview-label">UL</span> {formatSpeed(totalUploadRate)}</span>
      <span class="overview-chip"><span class="overview-label">Active</span> {transferringDownloads}</span>
      <span class="overview-chip"><span class="overview-label">Sources</span> {activeConnectedSources}/{totalKnownSources}</span>
      <label class="filter-wrap" aria-label="Filter transfers">
        <span class="filter-label">Filter</span>
        <input
          class="filter-input"
          type="text"
          placeholder="name, hash, category, peer..."
          bind:value={transferFilter}
        />
      </label>
    </div>
    <div class="pane-toolbar">
      <span class="pane-title">{filteredActiveDownloads.length}/{activeDownloads.length} downloading</span>
      <div class="toolbar-actions">
        <button class="tb-btn tb-toggle" onclick={toggleAdvancedDlCols} title="Toggle between full and compact columns">
          {showAdvancedDlCols ? 'Compact' : 'Full'}
        </button>
        <span class="toolbar-sep"></span>
        <button class="tb-btn" onclick={handlePauseAll} title="Pause All">Pause All</button>
        <button class="tb-btn" onclick={handleResumeAll} title="Resume All">Resume All</button>
        {#if hasCompletedDl}
          <button class="tb-btn" onclick={() => confirmClearCompleted = true} title="Clear Completed">Clear Completed</button>
        {/if}
      </div>
    </div>
    <div class="pane-content scroll-shadows">
      <table
        class="transfer-table dl-table"
        bind:this={downloadTableEl}
        style={`min-width: max(100%, ${getTableMinWidth('downloads', visibleDownloadColumns) + 32}px);`}
      >
        <colgroup>
          <col style="width: 32px;" />
          {#each visibleDownloadColumns as column (column.key)}
            <col style={`width: ${getColumnWidth('downloads', column.key)}px;`} />
          {/each}
        </colgroup>
        <thead oncontextmenu={(e) => openColumnMenu(e, 'downloads')}>
          <tr>
            <th class="col-dl-check">
              <input
                type="checkbox"
                checked={allActiveDlChecked}
                indeterminate={someActiveDlChecked && !allActiveDlChecked}
                onchange={toggleDlCheckAll}
                aria-label="Select all downloads"
                title="Select all downloads"
              />
            </th>
            {#each visibleDownloadColumns as column (column.key)}
              <th
                class={column.className}
                class:sortable={Boolean(column.sortField)}
                class:resizing={isResizingColumn('downloads', column.key)}
                class:drag-enabled={canDragColumn('downloads', column.key)}
                class:drop-before={isDropBefore('downloads', column.key)}
                class:drop-after={isDropAfter('downloads', column.key)}
                tabindex={column.sortField ? 0 : undefined}
                role="columnheader"
                draggable={canDragColumn('downloads', column.key)}
                aria-sort={column.sortField ? ariaSortValue(dlSortField, column.sortField, dlSortAsc) : undefined}
                onclick={() => onDownloadHeaderClick(column)}
                onkeydown={(e) => onDownloadHeaderKeydown(e, column)}
                ondragstart={(e) => handleColumnDragStart(e, 'downloads', column.key)}
                ondragover={(e) => handleColumnDragOver(e, 'downloads', column.key)}
                ondrop={(e) => handleColumnDrop(e, 'downloads', column.key)}
                ondragend={handleColumnDragEnd}
              >
                <span class="header-content">
                  {column.label}{column.sortField ? sortArrow(dlSortField, column.sortField, dlSortAsc) : ''}
                </span>
                <button
                  type="button"
                  class="col-resize-handle"
                  tabindex="-1"
                  aria-label={`Resize ${column.label} column`}
                  onmousedown={(e) => beginColumnResize(e, 'downloads', column.key)}
                  ondblclick={(e) => autoSizeColumn(e, 'downloads', column.key)}
                  onclick={swallowResizeClick}
                ></button>
              </th>
            {/each}
          </tr>
        </thead>
        <tbody>
          {#each filteredActiveDownloads as t (t.id)}
            <tr
              class="dl-row {t.status}"
              class:expanded={expandedTransferId === t.id}
              class:selected={selectedDlIdSet.has(t.id)}
              onclick={(e) => onDownloadRowClick(e, t)}
              oncontextmenu={(e) => onCtx(e, t, 'active')}
              ondblclick={() => { if (preClickSelection !== null) { selectedDownloadIds = preClickSelection; preClickSelection = null; } toggleSourceDetail(t); }}
            >
              <td class="col-dl-check">
                <input
                  type="checkbox"
                  checked={selectedDlIdSet.has(t.id)}
                  onclick={(e) => { e.stopPropagation(); toggleDlCheck(t, e.shiftKey); }}
                  aria-label="Select {t.file_name}"
                />
              </td>
              {#each visibleDownloadColumns as column (column.key)}
                {#if column.key === 'file_name'}
                  <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                {:else if column.key === 'total_size'}
                  <td class="num-cell">{formatSize(t.total_size)}</td>
                {:else if column.key === 'transferred'}
                  <td class="num-cell">{formatSize(t.transferred)}</td>
                {:else if column.key === 'completed_size'}
                  <td class="num-cell">{formatSize(t.completed_size || t.transferred)}</td>
                {:else if column.key === 'speed'}
                  {@const spd = liveSpeed(t)}
                  <td class="num-cell">{spd > 0 ? formatSpeed(spd) : '\u2014'}</td>
                {:else if column.key === 'progress'}
                  <td class="progress-cell">
                    {#if t.status === 'searching' && t.sources === 0 && t.progress === 0}
                      <span class="searching-label">
                        {dlStatusLabel(t)}...
                        {#if searchStatus.get(t.id)}
                          <span class="search-detail">{searchStatus.get(t.id)}</span>
                        {/if}
                      </span>
                    {:else}
                      <ProgressBar
                        value={t.progress}
                        color={downloadProgressColor(t)}
                      />
                    {/if}
                  </td>
                {:else if column.key === 'sources'}
                  <td class="num-cell" title={sourcesTooltip(t)}>{sourcesLabel(t)}</td>
                {:else if column.key === 'priority'}
                  <td class="prio-cell">
                    <span class="prio-badge prio-{t.priority}" title={priorityTooltip(t.priority)}>{t.priority.charAt(0).toUpperCase() + t.priority.slice(1)}</span>
                  </td>
                {:else if column.key === 'status'}
                  <td class="status-cell">
                    <span class="status-label st-{t.status}" title={dlStatusTooltip(t)}>{dlStatusLabel(t)}</span>
                  </td>
                {:else if column.key === 'remaining'}
                  {@const spd = liveSpeed(t)}
                  <!--
                    D22: use `completed_size` for byte accounting so the
                    rendered Remaining matches what etaSeconds() uses for
                    sort. `transferred` can include transient re-fetched
                    ranges that later get invalidated, which shifts sort
                    vs display apart.
                  -->
                  <td class="num-cell">{formatRemaining(t.total_size, t.completed_size ?? t.transferred, spd)}</td>
                {:else if column.key === 'last_seen_complete'}
                  <td class="date-cell">{t.last_seen_complete ? formatDate(t.last_seen_complete) : '\u2014'}</td>
                {:else if column.key === 'last_received'}
                  <td class="date-cell">{t.last_received ? formatDate(t.last_received) : '\u2014'}</td>
                {:else if column.key === 'category'}
                  <td class="cat-cell">{t.category || '\u2014'}</td>
                {:else if column.key === 'started_at'}
                  <td class="date-cell">{formatDate(t.started_at)}</td>
                {/if}
              {/each}
            </tr>
            {#if expandedTransferId === t.id}
              {#if loadingSources}
                <tr class="source-child-row">
                  <td class="source-child-cell" colspan={dlColCount}><span class="source-indent">Loading sources...</span></td>
                </tr>
              {:else if sourceLoadError}
                <tr class="source-child-row">
                  <td class="source-child-cell" colspan={dlColCount}>
                    <span class="source-indent">
                      {sourceLoadError}
                      <button class="source-inline-btn" onclick={() => toggleSourceDetail(t)}>Retry</button>
                    </span>
                  </td>
                </tr>
              {:else if expandedSources.length === 0}
                <tr class="source-child-row">
                  <td class="source-child-cell" colspan={dlColCount}>
                    <span class="source-indent">
                      {t.sources > 0 ? `Connecting to ${t.sources} source${t.sources !== 1 ? 's' : ''}...` : 'No source details yet.'}
                      <button class="source-inline-btn" onclick={() => findSources(t.file_hash, t.total_size).catch(() => {})}>Find Sources</button>
                    </span>
                  </td>
                </tr>
              {:else}
                {@const visibleSources = sortSourcesByPriority(expandedSources.filter(s => s.status !== 'failed'))}
                {@const failedCount = expandedSources.length - visibleSources.length}
                {@const xferCount = visibleSources.filter(s => s.status === 'transferring').length}
                {@const queuedCount = visibleSources.filter(s => s.status === 'queued').length}
                {@const connectCount = visibleSources.filter(s => s.status === 'connecting').length}
                {@const otherCount = visibleSources.length - xferCount - queuedCount - connectCount}
                <tr class="source-child-row source-summary-row">
                  <td class="source-child-cell" colspan={dlColCount}>
                    <span class="source-summary">
                      <strong>{visibleSources.length}</strong> source{visibleSources.length !== 1 ? 's' : ''}
                      {#if xferCount > 0}<span class="ss-chip ss-xfer">{xferCount} transferring</span>{/if}
                      {#if queuedCount > 0}<span class="ss-chip ss-queued">{queuedCount} queued</span>{/if}
                      {#if connectCount > 0}<span class="ss-chip ss-connect">{connectCount} connecting</span>{/if}
                      {#if otherCount > 0}<span class="ss-chip ss-other">{otherCount} other</span>{/if}
                      {#if failedCount > 0}<span class="ss-chip ss-failed">{failedCount} failed</span>{/if}
                    </span>
                  </td>
                </tr>
                {#each visibleSources as src (src.ip + ':' + src.port)}
                  <tr class="source-child-row src-{src.status}">
                    <td class="source-child-cell" colspan={dlColCount}>
                      <span class="source-fields">
                        <span class="source-status-dot src-dot-{src.status}" title={src.status}></span>
                        {#if netOriginSrc(src.source_origin)}<span class="source-net-origin" title={netOriginLabel(src.source_origin)}><img src={netOriginSrc(src.source_origin)} alt={src.source_origin ?? ''} class="net-origin-img" /></span>{/if}
                        <span class="source-flag" title={src.country_code ?? ''}>{#if countryFlagSrc(src.country_code)}<img src={countryFlagSrc(src.country_code)} alt={src.country_code ?? ''} class="flag-img" />{/if}</span>
                        <span class="source-client" title={src.peer_name || src.client_software || 'Unknown Client'}>{src.peer_name || src.client_software || 'Unknown Client'}</span>
                        <span class="source-sep"></span>
                        <span class="source-addr" title="{src.ip}:{src.port}">{src.ip}:{src.port}</span>
                        <span class="source-state src-st-{src.status}">{sourceStatusLabel(src)}</span>
                        {#if src.available_parts != null && src.total_parts != null && src.total_parts > 0}
                          <span class="source-tag" title="Parts available from this source">{src.available_parts}/{src.total_parts} parts</span>
                        {/if}
                        {#if src.speed > 0}
                          <span class="source-tag source-tag-accent">{formatSpeed(src.speed)}</span>
                        {/if}
                        {#if src.transferred > 0}
                          <span class="source-tag">{formatSize(src.transferred)}</span>
                        {/if}
                      </span>
                    </td>
                  </tr>
                {/each}
                {#if failedCount > 0}
                  <tr class="source-child-row src-failed-summary">
                    <td class="source-child-cell" colspan={dlColCount}>
                      <span class="source-indent source-failed-note">{failedCount} failed source{failedCount !== 1 ? 's' : ''} hidden</span>
                    </td>
                  </tr>
                {/if}
              {/if}
            {/if}
          {/each}
          {#if filteredCompletedDownloads.length > 0}
            <tr class="section-divider-row">
              <td colspan={dlColCount}>
                <button class="divider-toggle" onclick={() => completedCollapsed = !completedCollapsed}>
                  <span class="divider-chevron" class:collapsed={completedCollapsed}>{completedCollapsed ? '\u25B6' : '\u25BC'}</span>
                  COMPLETED / FAILED ({filteredCompletedDownloads.length})
                </button>
              </td>
            </tr>
            {#if !completedCollapsed}
            {#each filteredCompletedDownloads as t (t.id)}
              <tr class="dl-row completed-row {t.status}" oncontextmenu={(e) => onCtx(e, t, 'completed')}>
                <td class="col-dl-check"></td>
                {#each visibleDownloadColumns as column (column.key)}
                  {#if column.key === 'file_name'}
                    <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                  {:else if column.key === 'total_size'}
                    <td class="num-cell">{formatSize(t.total_size)}</td>
                  {:else if column.key === 'transferred'}
                    <td class="num-cell">{formatSize(t.transferred)}</td>
                  {:else if column.key === 'completed_size'}
                    <td class="num-cell">{formatSize(t.completed_size || t.transferred)}</td>
                  {:else if column.key === 'speed'}
                    <td class="num-cell">{'\u2014'}</td>
                  {:else if column.key === 'progress'}
                    <td class="progress-cell">
                      <ProgressBar
                        value={t.progress}
                        color={t.status === 'failed' ? 'var(--danger, #e74c3c)' : 'var(--success, #2ecc71)'}
                      />
                    </td>
                  {:else if column.key === 'sources'}
                    <td class="num-cell">{'\u2014'}</td>
                  {:else if column.key === 'priority'}
                    <td class="prio-cell">{'\u2014'}</td>
                  {:else if column.key === 'status'}
                    <td class="status-cell">
                      <span class="status-label st-{t.status}" title={dlStatusTooltip(t)} aria-label={`Status: ${dlStatusLabel(t)}. ${dlStatusTooltip(t)}`}>{dlStatusLabel(t)}</span>
                      <!--
                        L10: surface failure_kind / failure_stage in the
                        tooltip so the user can distinguish transient from
                        terminal failures without opening the context menu.
                      -->
                      {#if t.status === 'failed' && t.failure_reason}
                        <span class="failure-hint" title={[t.failure_reason, t.failure_stage, t.failure_kind].filter(Boolean).join(' — ')}>{t.failure_reason}</span>
                      {:else if t.health !== 'healthy' && t.health_reason}
                        <span class="failure-hint" title={t.health_reason}>{t.health_reason}</span>
                      {/if}
                    </td>
                  {:else if column.key === 'remaining'}
                    <td class="num-cell">{'\u2014'}</td>
                  {:else if column.key === 'last_seen_complete'}
                    <td class="date-cell">{t.last_seen_complete ? formatDate(t.last_seen_complete) : '\u2014'}</td>
                  {:else if column.key === 'last_received'}
                    <td class="date-cell">{'\u2014'}</td>
                  {:else if column.key === 'category'}
                    <td class="cat-cell">{t.category || '\u2014'}</td>
                  {:else if column.key === 'started_at'}
                    <td class="date-cell">{formatDate(t.started_at)}</td>
                  {/if}
                {/each}
              </tr>
            {/each}
            {/if}
          {/if}
          {#if allDownloads.length === 0}
            <tr><td colspan={dlColCount} class="empty-cell">No downloads yet. <a href="/search">Start a search</a> to find files.</td></tr>
          {:else if filteredActiveDownloads.length === 0 && filteredCompletedDownloads.length === 0}
            <tr><td colspan={dlColCount} class="empty-cell">No transfers match this filter.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
    {#if selectedDownloadCount > 1}
      <div class="selection-footer">
        <div class="selection-meta">
          <strong>{selectedDownloadCount} downloads selected</strong>
        </div>
        <div class="selection-actions">
          <button class="tb-btn" onclick={handleBatchPauseDownloads} title="Pause all selected downloads">Pause</button>
          <button class="tb-btn" onclick={handleBatchResumeDownloads} title="Resume all selected downloads">Resume</button>
          <button class="tb-btn" onclick={handleBatchStopDownloads} title="Stop all selected downloads">Stop</button>
          <button class="tb-btn danger-outline" onclick={handleBatchCancelDownloads} title="Cancel and remove all selected downloads">Cancel</button>
          <button class="tb-btn" onclick={clearDlSelection} title="Clear selection">Clear</button>
        </div>
      </div>
    {:else if selectedTransfer}
      <div class="selection-footer">
        <div class="selection-meta" title={selectedTransfer.file_name}>
          <strong>{selectedTransfer.file_name}</strong>
          <span>{formatSize(selectedTransfer.transferred)} / {formatSize(selectedTransfer.total_size)}</span>
          <span>{dlStatusLabel(selectedTransfer)}</span>
          <span>{sourcesLabel(selectedTransfer)} src{#if selectedTransfer.ember_sources > 0} ({selectedTransfer.ember_sources} EPX){/if}</span>
        </div>
        <div class="selection-actions">
          <button class="tb-btn" disabled={!canPause(selectedTransfer)} onclick={() => runSelectedAction('pause')}>Pause</button>
          <button class="tb-btn" disabled={!canResume(selectedTransfer)} onclick={() => runSelectedAction('resume')}>Resume</button>
          <button class="tb-btn" disabled={!canStop(selectedTransfer)} onclick={() => runSelectedAction('stop')}>Stop</button>
          <button class="tb-btn" onclick={() => runSelectedAction('sources')}>Find Sources</button>
          <button class="tb-btn" onclick={() => runSelectedAction('preview')}>Preview</button>
        </div>
      </div>
    {:else}
      <div class="selection-footer selection-footer-idle">
        <span class="selection-idle-hint">Click to select &middot; Shift+click for range &middot; Ctrl/Cmd+click to toggle &middot; Double-click for sources</span>
      </div>
    {/if}
  </div>

  <!-- SPLITTER -->
  <button
    type="button"
    class="splitter-bar"
    class:dragging
    onmousedown={onSplitterDown}
    onkeydown={onSplitterKeydown}
    aria-label="Resize transfer panes"
  ></button>

  <!-- BOTTOM PANE: Uploading / Queued / Known Clients / Download Clients
       (eMule-style tabs). Queued + Known Clients are backed by on-demand
       backend snapshots (`get_upload_queue`, `get_known_clients`) polled
       only while the matching tab is visible — see the `$effect`s above. -->
  <div class="pane uploads-pane" style="flex: 1;">
    <div class="pane-toolbar">
      <!--
        ARIA tablist semantics: each `<button>` is a `tab` inside a
        `tablist`, the active tab gets `aria-selected="true"` and a
        roving tabindex (only the selected tab is in the tab order;
        the others are reachable with Left/Right arrow). The pane body
        below is implicitly the tabpanel — wired via aria-controls
        pointing at its DOM id. Without these roles, screen readers
        announce four unrelated buttons rather than "tab 1 of 4".
      -->
      <div
        class="bottom-tabs"
        role="tablist"
        aria-label="Bottom pane view"
        tabindex="-1"
        onkeydown={(e) => {
          const order: typeof bottomView[] = ['uploading', 'queued', 'known_clients', 'download_clients'];
          const idx = order.indexOf(bottomView);
          if (idx < 0) return;
          if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
            e.preventDefault();
            bottomView = order[(idx + 1) % order.length];
          } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
            e.preventDefault();
            bottomView = order[(idx - 1 + order.length) % order.length];
          } else if (e.key === 'Home') {
            e.preventDefault();
            bottomView = order[0];
          } else if (e.key === 'End') {
            e.preventDefault();
            bottomView = order[order.length - 1];
          }
        }}
      >
        <button
          class="tab-btn"
          class:active={bottomView === 'uploading'}
          role="tab"
          aria-selected={bottomView === 'uploading'}
          aria-controls="bottom-pane-content"
          tabindex={bottomView === 'uploading' ? 0 : -1}
          onclick={() => bottomView = 'uploading'}
        >Uploading ({filteredActiveUploads.length})</button>
        <button
          class="tab-btn"
          class:active={bottomView === 'queued'}
          role="tab"
          aria-selected={bottomView === 'queued'}
          aria-controls="bottom-pane-content"
          tabindex={bottomView === 'queued' ? 0 : -1}
          onclick={() => bottomView = 'queued'}
          title="Peers waiting in our upload queue"
        >Queued{uploadQueueLoaded ? ` (${uploadQueueClients.length})` : ''}</button>
        <button
          class="tab-btn"
          class:active={bottomView === 'known_clients'}
          role="tab"
          aria-selected={bottomView === 'known_clients'}
          aria-controls="bottom-pane-content"
          tabindex={bottomView === 'known_clients' ? 0 : -1}
          onclick={() => bottomView = 'known_clients'}
          title="Every peer with a SecIdent credit record (lifetime)"
        >Known Clients{knownClientsLoaded ? ` (${knownClients.length})` : ''}</button>
        <button
          class="tab-btn"
          class:active={bottomView === 'download_clients'}
          role="tab"
          aria-selected={bottomView === 'download_clients'}
          aria-controls="bottom-pane-content"
          tabindex={bottomView === 'download_clients' ? 0 : -1}
          onclick={() => bottomView = 'download_clients'}
        >Download Clients</button>
      </div>
    </div>
    <div
      class="pane-content scroll-shadows"
      id="bottom-pane-content"
      role="tabpanel"
      aria-label={
        bottomView === 'uploading' ? 'Uploading'
        : bottomView === 'queued' ? 'Queued'
        : bottomView === 'known_clients' ? 'Known Clients'
        : 'Download Clients'
      }
    >
      {#if bottomView === 'uploading'}
        <!-- UPLOADING VIEW -->
        <table
          class="transfer-table ul-table"
          bind:this={uploadTableEl}
          style={`min-width: max(100%, ${getTableMinWidth('uploads', visibleUploadColumns)}px);`}
        >
          <colgroup>
            {#each visibleUploadColumns as column (column.key)}
              <col style={`width: ${getColumnWidth('uploads', column.key)}px;`} />
            {/each}
          </colgroup>
          <thead oncontextmenu={(e) => openColumnMenu(e, 'uploads')}>
            <tr>
              {#each visibleUploadColumns as column (column.key)}
                <th
                  class={column.className}
                  class:sortable={Boolean(column.sortField)}
                  class:resizing={isResizingColumn('uploads', column.key)}
                  class:drag-enabled={canDragColumn('uploads', column.key)}
                  class:drop-before={isDropBefore('uploads', column.key)}
                  class:drop-after={isDropAfter('uploads', column.key)}
                  tabindex={column.sortField ? 0 : undefined}
                  role="columnheader"
                  draggable={canDragColumn('uploads', column.key)}
                  aria-sort={column.sortField ? ariaSortValue(ulSortField, column.sortField, ulSortAsc) : undefined}
                  onclick={() => onUploadHeaderClick(column)}
                  onkeydown={(e) => onUploadHeaderKeydown(e, column)}
                  ondragstart={(e) => handleColumnDragStart(e, 'uploads', column.key)}
                  ondragover={(e) => handleColumnDragOver(e, 'uploads', column.key)}
                  ondrop={(e) => handleColumnDrop(e, 'uploads', column.key)}
                  ondragend={handleColumnDragEnd}
                >
                  <span class="header-content">
                    {column.label}{column.sortField ? sortArrow(ulSortField, column.sortField, ulSortAsc) : ''}
                  </span>
                  <button
                    type="button"
                    class="col-resize-handle"
                    tabindex="-1"
                    aria-label={`Resize ${column.label} column`}
                    onmousedown={(e) => beginColumnResize(e, 'uploads', column.key)}
                    ondblclick={(e) => autoSizeColumn(e, 'uploads', column.key)}
                    onclick={swallowResizeClick}
                  ></button>
                </th>
              {/each}
            </tr>
          </thead>
          <tbody>
            {#each filteredActiveUploads as t (t.id)}
              <tr class="ul-row" oncontextmenu={(e) => onCtx(e, t, 'upload')}>
                {#each visibleUploadColumns as column (column.key)}
                  {#if column.key === 'country'}
                    <td class="flag-cell" title={t.country_code ?? ''}>{#if countryFlagSrc(t.country_code)}<img src={countryFlagSrc(t.country_code)} alt={t.country_code ?? ''} class="flag-img" />{/if}</td>
                  {:else if column.key === 'peer_name'}
                    <td class="client-cell" title={t.peer_name || t.peer_id}>{t.peer_name || t.peer_id || '\u2014'}</td>
                  {:else if column.key === 'file_name'}
                    <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                  {:else if column.key === 'client_software'}
                    <td class="sw-cell" title={t.client_software || ''}>{t.client_software || '\u2014'}</td>
                  {:else if column.key === 'speed'}
                    {@const spd = liveSpeed(t)}
                    <td class="num-cell">{spd > 0 ? formatSpeed(spd) : '\u2014'}</td>
                  {:else if column.key === 'transferred'}
                    <td class="num-cell">{formatSize(t.transferred)}</td>
                  {:else if column.key === 'total_size'}
                    <td class="num-cell">{formatSize(t.total_size)}</td>
                  {:else if column.key === 'upload_time'}
                    <td class="num-cell">{formatDuration(t.upload_time)}</td>
                  {:else if column.key === 'status'}
                    <td class="status-cell"><span class="status-label st-{t.status}" title={ulStatusTooltip(t)}>{ulStatusLabel(t)}</span></td>
                  {:else if column.key === 'up_status'}
                    <td class="bar-cell">
                      {#if t.total_size > 0}
                        <!--
                          Feed the ProgressBar raw bytes rather than
                          `t.progress`. `t.progress` is recomputed from
                          `transferred / total_size` on every backend
                          `update_progress`, but in practice the
                          `transfer-progress` events for uploads arrive
                          much more often than any downstream effect
                          that re-derives progress, and we'd rather the
                          bar animate continuously as bytes flow than
                          freeze at 0% waiting for a progress sample
                          with a non-zero value. The old
                          `t.progress > 0` gate left the upload row
                          showing only a dash for the entire session
                          whenever the first few progress payloads
                          rounded to 0.0% (tiny `uploaded / total_size`
                          for the first block of a large file) — the
                          "uploads appear and freeze until they
                          complete" UX.
                        -->
                        <ProgressBar value={t.transferred} max={t.total_size} color="var(--accent)" />
                      {:else}
                        <span class="no-bar">—</span>
                      {/if}
                    </td>
                  {/if}
                {/each}
              </tr>
            {/each}
            <!--
              Completed and failed upload rows are dropped from the
              transfers store as soon as their `transfer-complete` /
              `transfer-failed` event arrives (see lib/stores/transfers.ts —
              upload-direction terminal events `filter` the row out
              instead of stamping it with a sticky status). This matches
              eMule's "session ends → row vanishes" behaviour: the
              cumulative byte counters live in the Statistics view, not
              as forever-pinned rows in the active uploads pane. The
              previous "Completed (N)" and "Failed (N)" section
              dividers were therefore guaranteed to render zero items
              once the auto-remove landed and have been removed.
            -->
            {#if activeUploads.length === 0}
              <tr><td colspan={ulColCount} class="empty-cell">No uploads</td></tr>
            {:else if filteredActiveUploads.length === 0}
              <tr><td colspan={ulColCount} class="empty-cell">No uploads match this filter</td></tr>
            {/if}
          </tbody>
        </table>
      {:else if bottomView === 'queued'}
        <!-- QUEUED VIEW: peers waiting in our upload queue. Polled from
             the upload-server snapshot via `getUploadQueue()`; rows are
             passive (no per-row context-menu actions yet — eMule's queue
             doesn't really have any either, since promotion happens by
             score). -->
        <table
          class="transfer-table queue-table"
          bind:this={queueTableEl}
          style={`min-width: max(100%, ${getTableMinWidth('queue', visibleQueueColumns)}px);`}
        >
          <colgroup>
            {#each visibleQueueColumns as column (column.key)}
              <col style={`width: ${getColumnWidth('queue', column.key)}px;`} />
            {/each}
          </colgroup>
          <thead oncontextmenu={(e) => openColumnMenu(e, 'queue')}>
            <tr>
              {#each visibleQueueColumns as column (column.key)}
                <th
                  class={column.className}
                  class:resizing={isResizingColumn('queue', column.key)}
                  class:drag-enabled={canDragColumn('queue', column.key)}
                  class:drop-before={isDropBefore('queue', column.key)}
                  class:drop-after={isDropAfter('queue', column.key)}
                  role="columnheader"
                  draggable={canDragColumn('queue', column.key)}
                  ondragstart={(e) => handleColumnDragStart(e, 'queue', column.key)}
                  ondragover={(e) => handleColumnDragOver(e, 'queue', column.key)}
                  ondrop={(e) => handleColumnDrop(e, 'queue', column.key)}
                  ondragend={handleColumnDragEnd}
                >
                  <span class="header-content">{column.label}</span>
                  <button
                    type="button"
                    class="col-resize-handle"
                    tabindex="-1"
                    aria-label={`Resize ${column.label} column`}
                    onmousedown={(e) => beginColumnResize(e, 'queue', column.key)}
                    ondblclick={(e) => autoSizeColumn(e, 'queue', column.key)}
                    onclick={swallowResizeClick}
                  ></button>
                </th>
              {/each}
            </tr>
          </thead>
          <tbody>
            {#each uploadQueueClients as q (q.user_hash + ':' + q.peer_ip + ':' + q.peer_port + ':' + q.file_hash)}
              <tr class="ul-row">
                {#each visibleQueueColumns as column (column.key)}
                  {#if column.key === 'country'}
                    <td class="flag-cell" title={q.country_code ?? ''}>{#if countryFlagSrc(q.country_code ?? undefined)}<img src={countryFlagSrc(q.country_code ?? undefined)} alt={q.country_code ?? ''} class="flag-img" />{/if}</td>
                  {:else if column.key === 'user_name'}
                    {@const label = q.user_hash ? q.user_hash.slice(0, 8) + '\u2026' : (q.peer_ip || '\u2014')}
                    <td class="client-cell" title={q.user_hash || q.peer_ip}>{q.is_friend ? '\u2605 ' : ''}{label}</td>
                  {:else if column.key === 'file_name'}
                    <td class="name-cell" title={q.file_name}>{q.file_name}</td>
                  {:else if column.key === 'wait_time'}
                    <td class="num-cell">{formatDuration(q.wait_seconds * 1000)}</td>
                  {:else if column.key === 'queue_rank'}
                    <td class="num-cell" title={q.queue_rank == null ? 'Disconnected — waiting for callback' : ''}>{q.queue_rank == null ? '?' : q.queue_rank}</td>
                  {:else if column.key === 'credit_ratio'}
                    <td class="num-cell" title={`Credit ratio (1.0 = no history, 10.0 = max)`}>{q.credit_ratio.toFixed(2)}</td>
                  {:else if column.key === 'transfer_history'}
                    <td class="num-cell" title={`We've uploaded ${formatSize(q.uploaded)} to and downloaded ${formatSize(q.downloaded)} from this peer`}>
                      {formatSize(q.uploaded)} / {formatSize(q.downloaded)}
                    </td>
                  {:else if column.key === 'ident_state'}
                    <td class="status-cell"><span class="status-label ident-{q.ident_state.toLowerCase()}">{q.ident_state}</span></td>
                  {/if}
                {/each}
              </tr>
            {/each}
            {#if uploadQueueClients.length === 0}
              <tr><td colspan={queueColCount} class="empty-cell">{uploadQueueLoaded ? 'No peers are waiting in the upload queue.' : 'Loading…'}</td></tr>
            {/if}
          </tbody>
        </table>
      {:else if bottomView === 'known_clients'}
        <!-- KNOWN CLIENTS VIEW: lifetime SecIdent credit ledger (every
             peer in clients.met). Independent of which peers are
             connected; this is the cumulative view that drives upload
             priority across sessions. Polled at a longer cadence than
             the queue tab because credit records change far less often. -->
        <table
          class="transfer-table clients-table"
          bind:this={knownTableEl}
          style={`min-width: max(100%, ${getTableMinWidth('known', visibleKnownColumns)}px);`}
        >
          <colgroup>
            {#each visibleKnownColumns as column (column.key)}
              <col style={`width: ${getColumnWidth('known', column.key)}px;`} />
            {/each}
          </colgroup>
          <thead oncontextmenu={(e) => openColumnMenu(e, 'known')}>
            <tr>
              {#each visibleKnownColumns as column (column.key)}
                <th
                  class={column.className}
                  class:sortable={Boolean(column.sortField)}
                  class:resizing={isResizingColumn('known', column.key)}
                  class:drag-enabled={canDragColumn('known', column.key)}
                  class:drop-before={isDropBefore('known', column.key)}
                  class:drop-after={isDropAfter('known', column.key)}
                  tabindex={column.sortField ? 0 : undefined}
                  role="columnheader"
                  draggable={canDragColumn('known', column.key)}
                  aria-sort={column.sortField ? ariaSortValue(knSortField, column.sortField, knSortAsc) : undefined}
                  onclick={() => onKnownHeaderClick(column)}
                  onkeydown={(e) => onKnownHeaderKeydown(e, column)}
                  ondragstart={(e) => handleColumnDragStart(e, 'known', column.key)}
                  ondragover={(e) => handleColumnDragOver(e, 'known', column.key)}
                  ondrop={(e) => handleColumnDrop(e, 'known', column.key)}
                  ondragend={handleColumnDragEnd}
                >
                  <span class="header-content">
                    {column.label}{column.sortField ? sortArrow(knSortField, column.sortField, knSortAsc) : ''}
                  </span>
                  <button
                    type="button"
                    class="col-resize-handle"
                    tabindex="-1"
                    aria-label={`Resize ${column.label} column`}
                    onmousedown={(e) => beginColumnResize(e, 'known', column.key)}
                    ondblclick={(e) => autoSizeColumn(e, 'known', column.key)}
                    onclick={swallowResizeClick}
                  ></button>
                </th>
              {/each}
            </tr>
          </thead>
          <tbody>
            {#each sortedKnownClients as kc (kc.user_hash)}
              <tr class="client-row">
                {#each visibleKnownColumns as column (column.key)}
                  {#if column.key === 'country'}
                    <td class="flag-cell" title={kc.country_code ?? ''}>{#if countryFlagSrc(kc.country_code ?? undefined)}<img src={countryFlagSrc(kc.country_code ?? undefined)} alt={kc.country_code ?? ''} class="flag-img" />{/if}</td>
                  {:else if column.key === 'user_hash'}
                    <td class="client-cell mono" title={kc.user_hash}>{kc.user_hash.slice(0, 16) + '\u2026'}</td>
                  {:else if column.key === 'last_known_ip'}
                    <td class="client-cell" title={kc.last_known_ip ?? 'Never identified'}>{kc.last_known_ip ?? '\u2014'}</td>
                  {:else if column.key === 'uploaded'}
                    <td class="num-cell" title={`Lifetime bytes we've uploaded to this peer`}>{kc.uploaded > 0 ? formatSize(kc.uploaded) : '\u2014'}</td>
                  {:else if column.key === 'downloaded'}
                    <td class="num-cell" title={`Lifetime bytes we've downloaded from this peer`}>{kc.downloaded > 0 ? formatSize(kc.downloaded) : '\u2014'}</td>
                  {:else if column.key === 'credit_ratio'}
                    <td class="num-cell" title={!kc.has_public_key ? 'No public key cached — credit floor at 1.0' : ''}>{kc.credit_ratio.toFixed(2)}</td>
                  {:else if column.key === 'ident_state'}
                    <td class="status-cell"><span class="status-label ident-{kc.ident_state.toLowerCase()}" title={!kc.has_public_key ? 'No public key cached' : ''}>{kc.ident_state}</span></td>
                  {:else if column.key === 'last_seen'}
                    <!-- Use `formatDateWithYear` (not the year-omitting
                         `formatDate`) because Known Clients rows can be
                         months or years old, and the previous label
                         hid exactly the information needed to spot a
                         stale row. The earlier `kc.last_seen * 1000`
                         double-multiply through `formatDate` landed
                         every row in year ~56,000 with the year hidden,
                         producing convincing-looking "current year"
                         labels for records that had genuinely been
                         pruned-eligible for ages. -->
                    <td class="date-cell">{kc.last_seen > 0 ? formatDateWithYear(kc.last_seen) : '\u2014'}</td>
                  {/if}
                {/each}
              </tr>
            {/each}
            {#if knownClients.length === 0}
              <tr><td colspan={knownColCount} class="empty-cell">{knownClientsLoaded ? 'No SecIdent credit records yet. Records appear after peers verify their identity with us.' : 'Loading…'}</td></tr>
            {/if}
          </tbody>
        </table>
      {:else}
        <!-- DOWNLOAD CLIENTS VIEW (eMule source clients for downloads) -->
        <table
          class="transfer-table clients-table"
          bind:this={clientsTableEl}
          style={`min-width: max(100%, ${getTableMinWidth('clients', visibleClientColumns)}px);`}
        >
          <colgroup>
            {#each visibleClientColumns as column (column.key)}
              <col style={`width: ${getColumnWidth('clients', column.key)}px;`} />
            {/each}
          </colgroup>
          <thead oncontextmenu={(e) => openColumnMenu(e, 'clients')}>
            <tr>
              {#each visibleClientColumns as column (column.key)}
                <th
                  class={column.className}
                  class:resizing={isResizingColumn('clients', column.key)}
                  class:drag-enabled={canDragColumn('clients', column.key)}
                  class:drop-before={isDropBefore('clients', column.key)}
                  class:drop-after={isDropAfter('clients', column.key)}
                  role="columnheader"
                  draggable={canDragColumn('clients', column.key)}
                  ondragstart={(e) => handleColumnDragStart(e, 'clients', column.key)}
                  ondragover={(e) => handleColumnDragOver(e, 'clients', column.key)}
                  ondrop={(e) => handleColumnDrop(e, 'clients', column.key)}
                  ondragend={handleColumnDragEnd}
                >
                  <span class="header-content">{column.label}</span>
                  <button
                    type="button"
                    class="col-resize-handle"
                    tabindex="-1"
                    aria-label={`Resize ${column.label} column`}
                    onmousedown={(e) => beginColumnResize(e, 'clients', column.key)}
                    ondblclick={(e) => autoSizeColumn(e, 'clients', column.key)}
                    onclick={swallowResizeClick}
                  ></button>
                </th>
              {/each}
            </tr>
          </thead>
          <tbody>
            {#if expandedSources.length > 0 && expandedTransferId}
              {@const clientSources = sortSourcesByPriority(expandedSources.filter(s => s.status !== 'failed'))}
              {#each clientSources as src (src.ip + ':' + src.port)}
                <tr class="client-row">
                  {#each visibleClientColumns as column (column.key)}
                    {#if column.key === 'peer_name'}
                      <td class="client-cell" title={src.peer_name || src.ip}>{src.peer_name || src.ip}</td>
                    {:else if column.key === 'country'}
                      <td class="flag-cell" title={src.country_code ?? ''}>{#if netOriginSrc(src.source_origin)}<img src={netOriginSrc(src.source_origin)} alt={src.source_origin ?? ''} class="net-origin-img" title={netOriginLabel(src.source_origin)} />{/if}{#if countryFlagSrc(src.country_code)}<img src={countryFlagSrc(src.country_code)} alt={src.country_code ?? ''} class="flag-img" />{/if}</td>
                    {:else if column.key === 'client_software'}
                      <td title={src.client_software}>{src.client_software || '\u2014'}</td>
                    {:else if column.key === 'file_name'}
                      <td class="name-cell">{allDownloads.find(d => d.id === expandedTransferId)?.file_name || '\u2014'}</td>
                    {:else if column.key === 'speed'}
                      <td class="num-cell">{src.status === 'transferring' ? formatSpeed(src.speed) : '\u2014'}</td>
                    {:else if column.key === 'downloaded'}
                      <td class="num-cell">{src.transferred > 0 ? formatSize(src.transferred) : '\u2014'}</td>
                    {:else if column.key === 'parts'}
                      <td class="num-cell">{src.available_parts != null && src.total_parts ? `${src.available_parts}/${src.total_parts}` : '\u2014'}</td>
                    {:else if column.key === 'status'}
                      <td class="src-st-{src.status}">{sourceStatusLabel(src)}</td>
                    {/if}
                  {/each}
                </tr>
              {/each}
              {#if clientSources.length === 0}
                <tr><td colspan={clientColCount} class="empty-cell">All sources failed. Double-click a download to refresh.</td></tr>
              {/if}
            {:else}
              <tr><td colspan={clientColCount} class="empty-cell">Double-click a download to see its source clients here.</td></tr>
            {/if}
          </tbody>
        </table>
      {/if}
    </div>
  </div>
</div>

{#if columnMenu}
  {@const menu = columnMenu}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div class="context-menu column-menu" style="left: {menu.x}px; top: {menu.y}px;" onclick={(e) => e.stopPropagation()}>
    <div class="column-menu-title">{getColumnMenuTitle(menu.table)}</div>
    {#each getColumnMenuColumns(menu.table) as column (column.key)}
      <button class="ctx-item" onclick={() => toggleColumnVisibility(menu.table, column.key)}>
        {isColumnHidden(menu.table, column.key) ? '☐' : '☑'} {column.label}
      </button>
    {/each}
    <div class="ctx-sep"></div>
    <button class="ctx-item" onclick={() => resetColumnLayout(menu.table)}>Reset Columns</button>
  </div>
{/if}

<!-- Context Menu -->
{#if ctxMenu && ctxTransfer}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div class="context-menu" style="left: {ctxMenu.x}px; top: {ctxMenu.y}px;" onclick={(e) => e.stopPropagation()}>
    {#if ctxMenu.section === 'active'}
      {#if canPause(ctxTransfer)}
        <button class="ctx-item" onclick={() => ctxAction('pause')}>Pause</button>
      {/if}
      {#if canStop(ctxTransfer)}
        <button class="ctx-item" onclick={() => ctxAction('stop')}>Stop</button>
      {/if}
      {#if canResume(ctxTransfer)}
        <button class="ctx-item" onclick={() => ctxAction('resume')}>Resume</button>
      {/if}
      <button class="ctx-item danger" onclick={() => ctxAction('cancel')}>Cancel</button>
      <div class="ctx-sep"></div>
      <button class="ctx-item" onclick={() => ctxAction('preview')}>Preview</button>
      <button class="ctx-item" onclick={() => ctxAction('toggle_preview_prio')}>
        {ctxTransfer.preview_priority ? '✓ ' : ''}Preview Priority
      </button>
      {#if isArchive(ctxTransfer)}
        <button class="ctx-item" disabled={recoveringIds.has(ctxTransfer.id)} onclick={() => ctxAction('recover_archive')}>
          {recoveringIds.has(ctxTransfer.id) ? 'Recovering…' : 'Recover Archive'}
        </button>
      {/if}
      <button class="ctx-item" onclick={() => ctxAction('open_location')}>Open File Location</button>
      <div class="ctx-sep"></div>
      <div class="ctx-submenu-wrap">
        <button class="ctx-item has-sub" onclick={() => ctxPrioritySub = !ctxPrioritySub}>
          Priority ▶
        </button>
        {#if ctxPrioritySub}
          <div class="ctx-submenu">
            <button class="ctx-item" class:ctx-active={ctxTransfer.priority === 'verylow'} onclick={() => ctxAction('priority', 'verylow')}>Very Low</button>
            <button class="ctx-item" class:ctx-active={ctxTransfer.priority === 'low'} onclick={() => ctxAction('priority', 'low')}>Low</button>
            <button class="ctx-item" class:ctx-active={ctxTransfer.priority === 'normal'} onclick={() => ctxAction('priority', 'normal')}>Normal</button>
            <button class="ctx-item" class:ctx-active={ctxTransfer.priority === 'high'} onclick={() => ctxAction('priority', 'high')}>High</button>
            <button class="ctx-item" class:ctx-active={ctxTransfer.priority === 'auto'} onclick={() => ctxAction('priority', 'auto')}>Auto</button>
            <button class="ctx-item" class:ctx-active={ctxTransfer.priority === 'release'} onclick={() => ctxAction('priority', 'release')}>Release</button>
          </div>
        {/if}
      </div>
      <div class="ctx-submenu-wrap">
        <button class="ctx-item has-sub" onclick={() => ctxCategorySub = !ctxCategorySub}>
          Category ▶
        </button>
        {#if ctxCategorySub}
          <div class="ctx-submenu">
            {#each CATEGORY_OPTIONS as cat}
              <button
                class="ctx-item"
                class:ctx-active={(cat === 'None' && !ctxTransfer.category) || ctxTransfer.category === cat}
                onclick={() => ctxAction('set_category', cat)}
              >{cat}</button>
            {/each}
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
      <!--
        D26: also offer Open File for failed downloads that have produced a
        partial file on disk. If the file is truly missing, the backend
        `open_file` command returns an error that surfaces via transferError.
      -->
      {#if ctxTransfer.status === 'completed' || ctxTransfer.status === 'failed'}
        <button class="ctx-item" onclick={() => ctxAction('open')}>Open File</button>
      {/if}
      <button class="ctx-item" onclick={() => ctxAction('open_location')}>Open File Location</button>
      <div class="ctx-sep"></div>
      <button class="ctx-item" onclick={() => ctxAction('copy_link')}>Copy eD2K Link</button>
      <div class="ctx-sep"></div>
      <button class="ctx-item danger" onclick={() => ctxAction('remove')}>Remove from List</button>
      <button class="ctx-item" onclick={() => ctxAction('clear_completed')}>Clear Completed</button>
    {:else}
      <!-- Upload context menu -->
      {#if ctxTransfer.user_hash && ctxTransfer.client_software?.startsWith('Ember')}
        <button class="ctx-item" onclick={() => ctxAction('add_friend')}>Add as Friend</button>
        <div class="ctx-sep"></div>
      {/if}
      <button class="ctx-item" onclick={() => ctxAction('copy_link')}>Copy eD2K Link</button>
      {#if ctxTransfer.user_hash}
        <div class="ctx-sep"></div>
        <button class="ctx-item danger" onclick={() => ctxAction('ban_user')}>Ban User</button>
      {/if}
    {/if}
  </div>
{/if}

<ConfirmDialog
  bind:open={confirmCancel.open}
  title="Cancel Download"
  message="Cancel download of &quot;{confirmCancel.name}&quot;? The partial file will be deleted."
  confirmLabel="Cancel Download"
  danger={true}
  onconfirm={async () => { try { await cancelTransfer(confirmCancel.id); speedHistory.delete(confirmCancel.id); transfers.update((list) => list.filter((x) => x.id !== confirmCancel.id)); } catch (e: unknown) { transferError = toErrorMsg(e); } }}
/>

<ConfirmDialog
  bind:open={confirmClearCompleted}
  title="Clear Completed"
  message="Remove all completed transfers from the list?"
  confirmLabel="Clear"
  onconfirm={async () => { try { await clearCompleted(); transfers.update((list) => { const remaining = list.filter((x) => !(x.direction === 'download' && x.status === 'completed')); const removedIds = new Set(list.filter((x) => x.direction === 'download' && x.status === 'completed').map((x) => x.id)); for (const id of removedIds) speedHistory.delete(id); return remaining; }); } catch (e: unknown) { transferError = toErrorMsg(e); } }}
/>

<!-- D27: recover-archive confirm + async feedback -->
<ConfirmDialog
  bind:open={confirmRecover.open}
  title="Recover Archive"
  message="Rebuild a salvage copy of &quot;{confirmRecover.name}&quot; from the downloaded parts? This can take a minute or two for large files. The original .part file is not modified."
  confirmLabel="Recover"
  onconfirm={async () => {
    const id = confirmRecover.id;
    const next = new Set(recoveringIds); next.add(id); recoveringIds = next;
    try {
      const path = await recoverArchive(id);
      showInfo(`Archive recovered: ${path}`);
    } catch (e: unknown) {
      transferError = toErrorMsg(e);
    } finally {
      const cleared = new Set(recoveringIds); cleared.delete(id); recoveringIds = cleared;
    }
  }}
/>

<ConfirmDialog
  bind:open={confirmBatchCancel.open}
  title="Cancel Downloads"
  message="Cancel {confirmBatchCancel.count} {confirmBatchCancel.count === 1 ? 'download' : 'downloads'} and delete partial data?"
  confirmLabel="Cancel Downloads"
  danger={true}
  onconfirm={async () => {
    const ids = confirmBatchCancel.ids; const idSet = new Set(ids);
    try {
      await cancelTransfersBatch(ids);
      for (const id of idSet) speedHistory.delete(id);
      transfers.update((list) => list.filter((x) => !idSet.has(x.id)));
      selectedDownloadIds = [];
      lastClickedDlId = null;
      // L13: move focus back to the page toolbar after destructive
      // actions so keyboard users don't land on a detached element.
      requestAnimationFrame(() => {
        (document.querySelector('.filter-input') as HTMLInputElement | null)?.focus();
      });
    } catch (e: unknown) { transferError = toErrorMsg(e); }
  }}
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
  .transfer-overview-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 3px 8px;
    border-bottom: 1px solid var(--border);
    background: color-mix(in srgb, var(--bg-secondary) 70%, var(--bg-primary));
    flex-wrap: wrap;
  }
  .overview-chip {
    font-size: 11px;
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
    border: 1px solid var(--border);
    padding: 1px 6px;
    background: var(--bg-primary);
  }
  .overview-label {
    font-weight: 600;
    color: var(--text-muted);
    margin-right: 2px;
  }
  .filter-wrap {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    color: var(--text-muted);
  }
  .filter-label {
    white-space: nowrap;
  }
  .filter-input {
    width: 220px;
    max-width: 45vw;
    padding: 2px 6px;
    border: 1px solid var(--border);
    border-radius: 0;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 11px;
  }
  .filter-input:focus {
    outline: 1px solid var(--accent);
    outline-offset: 0;
  }
  .pane-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 3px 8px;
    background: color-mix(in srgb, var(--bg-secondary) 90%, #c8c8c8 10%);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    gap: 6px;
  }
  .pane-title {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
  }
  .toolbar-actions {
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .toolbar-sep {
    width: 1px;
    height: 14px;
    background: var(--border);
    margin: 0 2px;
  }
  .tb-btn {
    font-size: 11px;
    padding: 1px 8px;
    border: 1px solid var(--border);
    border-radius: 0;
    background: var(--bg-primary);
    color: var(--text-primary);
    cursor: pointer;
    transition: background 0.15s;
    min-height: 20px;
  }
  .tb-btn:hover {
    background: var(--bg-hover);
  }
  .tb-btn:disabled {
    opacity: 0.5;
    cursor: default;
    background: var(--bg-primary);
  }
  .tb-btn.tb-toggle {
    color: var(--text-muted);
    border-style: dashed;
    font-size: 10px;
  }
  .tb-btn.tb-toggle:hover {
    color: var(--text-primary);
    border-style: solid;
  }
  .tb-btn.danger-outline {
    border-color: var(--danger, #e74c3c);
    color: var(--danger, #e74c3c);
  }
  .tb-btn.danger-outline:hover {
    background: color-mix(in srgb, var(--danger, #e74c3c) 12%, var(--bg-primary));
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
    position: relative;
    font-size: 11px;
    padding: 3px 10px;
    border: 1px solid var(--border);
    border-bottom: none;
    border-radius: 0;
    background: var(--bg-primary);
    color: var(--text-muted);
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
    font-weight: 500;
    border-bottom: 1px solid var(--bg-secondary);
  }
  .tab-btn.active::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: var(--accent);
  }

  /* --- Splitter --- */
  .splitter-bar {
    appearance: none;
    border: none;
    width: 100%;
    flex-shrink: 0;
    height: 4px;
    background: var(--border);
    cursor: row-resize;
    transition: background 0.1s;
  }
  .splitter-bar:hover, .splitter-bar.dragging {
    background: var(--accent);
  }
  .splitter-bar:focus-visible {
    background: var(--accent);
    outline: 2px solid var(--accent);
    outline-offset: -1px;
  }

  /* --- Tables --- */
  .transfer-table {
    width: max-content;
    min-width: 100%;
    border-collapse: collapse;
    font-size: 11px;
    table-layout: fixed;
  }
  .transfer-table th {
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--bg-secondary);
    padding: 3px 6px;
    font-size: 11px;
    font-weight: 500;
    text-align: left;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
    user-select: none;
    overflow: hidden;
    padding-right: 16px;
  }
  .transfer-table th.sortable {
    cursor: pointer;
  }
  .transfer-table th.sortable:hover {
    color: var(--text-primary);
  }
  .transfer-table th.drag-enabled {
    cursor: grab;
  }
  .transfer-table th.drag-enabled:active {
    cursor: grabbing;
  }
  .transfer-table th.resizing {
    color: var(--text-primary);
  }
  .transfer-table th.drop-before {
    box-shadow: inset 2px 0 0 var(--accent);
  }
  .transfer-table th.drop-after {
    box-shadow: inset -2px 0 0 var(--accent);
  }
  .header-content {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .col-resize-handle {
    position: absolute;
    top: 0;
    right: 0;
    width: 10px;
    height: 100%;
    border: none;
    padding: 0;
    margin: 0;
    background: transparent;
    cursor: col-resize;
  }
  .col-resize-handle::after {
    content: '';
    position: absolute;
    top: 2px;
    bottom: 2px;
    left: 50%;
    width: 1px;
    transform: translateX(-50%);
    background: transparent;
    transition: background 0.12s ease;
  }
  .transfer-table th:hover .col-resize-handle::after,
  .transfer-table th.resizing .col-resize-handle::after,
  .col-resize-handle:hover::after,
  .col-resize-handle:active::after {
    background: var(--accent);
  }
  .col-resize-handle:focus {
    outline: none;
  }
  .transfer-table td {
    padding: 2px 6px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 40%, transparent);
  }
  .transfer-table tbody tr:nth-child(even of :not(.source-child-row):not(.section-divider-row):not(.src-failed-summary)) {
    background: color-mix(in srgb, var(--bg-secondary) 40%, var(--bg-primary));
  }
  .transfer-table tbody tr:hover {
    background: var(--bg-hover);
  }
  .dl-row.selected {
    background: color-mix(in srgb, var(--accent) 14%, transparent);
  }

  .col-dl-check {
    width: 32px;
    text-align: center;
    padding-left: 4px !important;
    padding-right: 0 !important;
  }
  .col-dl-check input[type="checkbox"] {
    margin: 0;
    cursor: pointer;
  }

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
  .sw-cell {
    color: var(--text-muted);
    font-size: 11px;
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
  .selection-footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 3px 8px;
    border-top: 1px solid var(--border);
    background: color-mix(in srgb, var(--bg-secondary) 80%, var(--bg-primary));
  }
  .selection-meta {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    font-size: 11px;
    color: var(--text-secondary);
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }
  .selection-meta strong {
    color: var(--text-primary);
    font-weight: 600;
  }
  .selection-footer-idle {
    justify-content: center;
    padding: 2px 8px;
  }
  .selection-idle-hint {
    font-size: 10px;
    color: var(--text-muted);
  }
  .selection-actions {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
  }

  /* --- Status labels --- */
  .status-cell { display: flex; flex-direction: column; gap: 1px; }
  .status-label {
    font-size: 11px;
    font-weight: 500;
  }
  .status-label::before {
    content: '';
    display: inline-block;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    margin-right: 4px;
    background: currentColor;
    vertical-align: middle;
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
  /* SecIdent status badge colours used in Queued + Known Clients tabs.
     Verified is the only "good" state; Failed and BadGuy are red flags
     for credit accounting. Unknown is the default/no-handshake state. */
  .ident-verified { color: var(--success, #2ecc71); }
  .ident-failed { color: var(--danger, #e74c3c); }
  .ident-badguy { color: var(--danger, #e74c3c); }
  .ident-needed { color: var(--warning); }
  .ident-unknown { color: var(--text-muted); }
  /* Monospace cell — used for raw user-hash columns where alignment
     across rows matters more than narrow rendering. */
  .mono { font-family: var(--font-mono, ui-monospace, 'Cascadia Code', Consolas, monospace); font-size: 11px; }
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
    font-weight: 500;
    padding: 0;
    border-radius: 0;
  }
  .prio-release { color: #e09830; font-weight: 700; }
  .prio-high { color: var(--danger, #e74c3c); }
  .prio-normal { color: var(--text-secondary); }
  /* L8: distinguish prio-low from prio-verylow visually — prior rules
     only differed in opacity and were hard to tell apart at a glance. */
  .prio-low { color: var(--text-secondary); font-style: italic; }
  .prio-verylow { color: var(--text-muted); opacity: 0.55; font-style: italic; }
  .prio-auto { color: var(--accent); }

  /* --- Section divider --- */
  .section-divider-row td {
    background: var(--bg-secondary);
    font-size: 10px;
    font-weight: 600;
    color: var(--text-muted);
    padding: 2px 6px !important;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
    letter-spacing: 0.03em;
  }
  .divider-toggle {
    all: unset;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 10px;
    font-weight: 600;
    color: var(--text-muted);
    letter-spacing: 0.03em;
  }
  .divider-toggle:hover {
    color: var(--text-secondary);
  }
  .divider-chevron {
    font-size: 8px;
    transition: transform 0.15s;
  }

  .completed-row { opacity: 1; }
  .searching-label {
    font-size: 11px;
    color: var(--warning);
    font-style: italic;
    animation: pulse 1.5s ease-in-out infinite;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .search-detail {
    font-size: 10px;
    color: var(--text-muted);
    font-style: normal;
    animation: none;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
  @media (prefers-reduced-motion: reduce) {
    .searching-label {
      animation: none;
    }
  }

  /* --- Page header actions --- */
  .header-actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .paste-link-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    padding: 5px 12px;
  }
  .paste-link-icon {
    display: inline-flex;
    align-items: center;
    color: currentColor;
  }
  .paste-link-icon :global(svg) {
    width: 13px;
    height: 13px;
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

  .info-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 16px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--success, #2ecc71);
    color: var(--success, #2ecc71);
    font-size: 12px;
    flex-shrink: 0;
  }

  /* --- Context Menu --- */
  .context-menu {
    position: fixed;
    z-index: 1000;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 2px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.25);
    padding: 4px 0;
    min-width: 180px;
  }
  .column-menu {
    min-width: 220px;
  }
  .column-menu-title {
    padding: 4px 14px 6px;
    font-size: 11px;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .ctx-item {
    display: flex;
    width: 100%;
    text-align: left;
    padding: 4px 14px;
    font-size: 11px;
    background: none;
    border: none;
    color: var(--text-primary);
    cursor: pointer;
    white-space: nowrap;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
  }
  .ctx-item:hover { background: var(--bg-hover); }
  .ctx-item.danger { color: var(--danger, #e74c3c); }
  .ctx-item.has-sub { display: flex; justify-content: space-between; }
  .ctx-shortcut {
    font-size: 10px;
    color: var(--text-muted);
    margin-left: auto;
  }
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
    border-radius: 2px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.25);
    padding: 4px 0;
    min-width: 100px;
  }

  /* --- Expanded source rows (compact, eMule-like) --- */
  .dl-row.expanded {
    background: color-mix(in srgb, var(--accent) 7%, transparent);
  }
  .dl-row {
    cursor: default;
  }
  /* Suppress text selection on interactive transfer rows. Double-click
     toggles the source-detail panel, and single-click toggles selection
     — both gestures kept triggering native text-range highlighting on
     the file-name / peer-name cells, which flashed a jarring blue
     selection and prevented subsequent double-clicks in some browsers
     from registering cleanly. `user-select: none` on the rows (and on
     the source detail rows / upload / client rows that share the
     same double-click-to-expand UX) makes the rows behave like
     first-class controls. If a cell needs to be copyable (a future
     text-copy cell), override this locally with `user-select: text`. */
  .dl-row,
  .ul-row,
  .source-child-row,
  .client-row {
    user-select: none;
    -webkit-user-select: none;
  }
  .source-child-row td {
    padding: 3px 6px 3px 0 !important;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 35%, transparent);
    border-left: 2px solid var(--accent);
    background: color-mix(in srgb, var(--bg-secondary) 65%, var(--bg-primary));
  }
  .source-child-row:last-of-type td {
    border-bottom: 1px solid var(--border);
  }
  .source-child-cell {
    font-size: 11px;
    color: var(--text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .source-indent {
    padding-left: 20px;
  }
  .source-fields {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding-left: 20px;
  }
  .source-status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
    background: var(--text-muted);
  }
  .src-dot-connecting { background: var(--warning); box-shadow: 0 0 3px var(--warning); }
  .src-dot-queued { background: #e09830; box-shadow: 0 0 3px #e09830; }
  .src-dot-queue_full { background: var(--text-muted); }
  .src-dot-no_needed_parts { background: var(--text-muted); }
  .src-dot-transferring { background: var(--accent); box-shadow: 0 0 4px color-mix(in srgb, var(--accent) 60%, transparent); }
  .src-dot-completed { background: var(--success, #2ecc71); box-shadow: 0 0 3px color-mix(in srgb, var(--success) 50%, transparent); }
  .src-dot-failed { background: var(--danger, #e74c3c); }
  .source-flag {
    line-height: 1;
    width: 18px;
    text-align: center;
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  .flag-img {
    width: 16px;
    height: 16px;
    border-radius: 50%;
    object-fit: cover;
    vertical-align: middle;
  }
  .source-net-origin {
    line-height: 1;
    width: 18px;
    text-align: center;
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  .net-origin-img {
    width: 16px;
    height: 16px;
    border-radius: 50%;
    object-fit: cover;
    vertical-align: middle;
  }
  .source-client {
    color: var(--text-primary);
    font-weight: 600;
    font-size: 11px;
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .source-sep {
    width: 1px;
    height: 12px;
    background: var(--border);
    flex-shrink: 0;
  }
  .source-addr {
    color: var(--text-muted);
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: -0.2px;
  }
  .source-state {
    font-weight: 600;
    font-size: 10px;
    padding: 1px 7px;
    border-radius: 3px;
    line-height: 1.4;
  }
  .source-tag {
    font-size: 10px;
    color: var(--text-muted);
    background: color-mix(in srgb, var(--bg-hover) 60%, var(--bg-secondary));
    border: 1px solid color-mix(in srgb, var(--border) 50%, transparent);
    border-radius: 3px;
    padding: 1px 6px;
    font-variant-numeric: tabular-nums;
    line-height: 1.4;
  }
  .source-tag-accent {
    color: var(--accent);
    border-color: color-mix(in srgb, var(--accent) 30%, var(--border));
    background: color-mix(in srgb, var(--accent) 8%, transparent);
  }
  .source-inline-btn {
    margin-left: 8px;
    font-size: 11px;
    padding: 2px 8px;
    border: 1px solid var(--border);
    border-radius: 3px;
    background: var(--bg-primary);
    color: var(--text-primary);
    cursor: pointer;
  }
  .source-inline-btn:hover {
    background: var(--bg-hover);
  }
  .src-st-connecting {
    color: var(--warning);
    background: color-mix(in srgb, var(--warning) 10%, transparent);
  }
  .src-st-queued {
    color: #e09830;
    background: color-mix(in srgb, #e09830 12%, transparent);
  }
  .src-st-queue_full,
  .src-st-no_needed_parts {
    color: var(--text-muted);
    background: color-mix(in srgb, var(--text-muted) 8%, transparent);
  }
  .src-st-transferring {
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 12%, transparent);
  }
  .src-st-completed {
    color: var(--success, #2ecc71);
    background: color-mix(in srgb, var(--success, #2ecc71) 10%, transparent);
  }
  .src-st-failed {
    color: var(--danger, #e74c3c);
    background: color-mix(in srgb, var(--danger, #e74c3c) 10%, transparent);
  }
  .source-failed-note {
    font-style: italic;
    color: var(--text-muted);
    font-size: 10px;
  }
  .flag-cell {
    text-align: center;
    font-size: 13px;
    line-height: 1;
    padding: 2px 0 !important;
    white-space: nowrap;
  }
  .flag-cell .net-origin-img {
    margin-right: 2px;
  }
  .source-summary-row td {
    background: color-mix(in srgb, var(--bg-secondary) 85%, var(--bg-primary)) !important;
  }
  .source-summary {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding-left: 20px;
    font-size: 10px;
    color: var(--text-muted);
  }
  .source-summary strong {
    color: var(--text-secondary);
    font-weight: 700;
  }
  .ss-chip {
    font-size: 10px;
    padding: 0 5px;
    border-radius: 3px;
    font-variant-numeric: tabular-nums;
  }
  .ss-xfer { color: var(--accent); background: color-mix(in srgb, var(--accent) 10%, transparent); }
  .ss-queued { color: #e09830; background: color-mix(in srgb, #e09830 10%, transparent); }
  .ss-connect { color: var(--warning); background: color-mix(in srgb, var(--warning) 10%, transparent); }
  .ss-other { color: var(--text-muted); background: color-mix(in srgb, var(--text-muted) 8%, transparent); }
  .ss-failed { color: var(--danger, #e74c3c); background: color-mix(in srgb, var(--danger, #e74c3c) 8%, transparent); }
</style>
