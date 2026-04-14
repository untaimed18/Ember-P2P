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
  } from '$lib/api/transfers';
  import { findSources, parseEd2kLink, formatEd2kLink } from '$lib/api/search';
  import { previewFile } from '$lib/api/preview';
  import { addFriend } from '$lib/api/friends';
  import { banPeer } from '$lib/api/kad';
  import { formatSize, formatSpeed, formatDate, formatDuration, formatRemaining } from '$lib/utils';
  import { onMount, onDestroy } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import type { UnlistenFn } from '@tauri-apps/api/event';
  import type { Transfer, SourceInfo } from '$lib/types';

  function countryFlagSrc(code: string | undefined): string | null {
    if (!code || code.length !== 2) return null;
    return `/flags/${code.toLowerCase()}.svg`;
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

  type TableKey = 'downloads' | 'uploads' | 'queue' | 'clients';
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
  const QUEUE_COLUMNS: TransferColumn[] = [
    { key: 'peer_name', label: 'User Name', width: 150, minWidth: 120, className: 'col-q-client' },
    { key: 'file_name', label: 'File', width: 260, minWidth: 160, className: 'col-q-file' },
    { key: 'priority', label: 'File Priority', width: 60, minWidth: 60, className: 'col-q-prio' },
    { key: 'entered_queue', label: 'Entered Queue', width: 110, minWidth: 96, className: 'col-q-entered' },
    { key: 'up_status', label: 'Up Status', width: 170, minWidth: 120, className: 'col-q-bar' },
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
    clients: CLIENT_COLUMNS,
  };
  const COLUMN_STORAGE_KEYS: Record<TableKey, string> = {
    downloads: 'transfers-columns-DownloadListCtrl',
    uploads: 'transfers-columns-UploadListCtrl',
    queue: 'transfers-columns-QueueListCtrl',
    clients: 'transfers-columns-DownloadClientsCtrl',
  };
  const COLUMN_HIDDEN_STORAGE_KEYS: Record<TableKey, string> = {
    downloads: 'transfers-column-hidden-DownloadListCtrl',
    uploads: 'transfers-column-hidden-UploadListCtrl',
    queue: 'transfers-column-hidden-QueueListCtrl',
    clients: 'transfers-column-hidden-DownloadClientsCtrl',
  };
  const COLUMN_ORDER_STORAGE_KEYS: Record<TableKey, string> = {
    downloads: 'transfers-column-order-DownloadListCtrl',
    uploads: 'transfers-column-order-UploadListCtrl',
    queue: 'transfers-column-order-QueueListCtrl',
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
    clients: createDefaultWidths(CLIENT_COLUMNS),
  });
  let hiddenColumns = $state<Record<TableKey, Record<string, boolean>>>({
    downloads: createDefaultHidden(DOWNLOAD_COLUMNS),
    uploads: createDefaultHidden(UPLOAD_COLUMNS),
    queue: createDefaultHidden(QUEUE_COLUMNS),
    clients: createDefaultHidden(CLIENT_COLUMNS),
  });
  let columnOrder = $state<Record<TableKey, string[]>>({
    downloads: createDefaultOrder(DOWNLOAD_COLUMNS),
    uploads: createDefaultOrder(UPLOAD_COLUMNS),
    queue: createDefaultOrder(QUEUE_COLUMNS),
    clients: createDefaultOrder(CLIENT_COLUMNS),
  });
  let downloadTableEl: HTMLTableElement | undefined = $state(undefined);
  let uploadTableEl: HTMLTableElement | undefined = $state(undefined);
  let queueTableEl: HTMLTableElement | undefined = $state(undefined);
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
    listen<{
      transfer_id: string; ip: string; port: number; status: string;
      queue_rank?: number; speed: number; transferred: number; client_software: string; peer_name: string;
      available_parts?: number; total_parts?: number; country_code?: string;
    }>('transfer-source-detail', (event) => {
      const d = event.payload;
      if (d.transfer_id !== expandedTransferId) return;
      const idx = expandedSources.findIndex((s) => s.ip === d.ip && s.port === d.port);
      if (idx >= 0) {
        const s = expandedSources[idx];
        const updated: SourceInfo = { ...s, status: d.status as SourceInfo['status'], queue_rank: d.queue_rank, speed: d.speed, transferred: d.transferred, client_software: d.client_software || s.client_software, peer_name: d.peer_name || s.peer_name, available_parts: d.available_parts ?? s.available_parts, total_parts: d.total_parts ?? s.total_parts, country_code: d.country_code ?? s.country_code };
        expandedSources[idx] = updated;
        expandedSources = expandedSources;
      } else {
        expandedSources = [...expandedSources, { ip: d.ip, port: d.port, status: d.status as SourceInfo['status'], queue_rank: d.queue_rank, speed: d.speed, transferred: d.transferred, client_software: d.client_software, peer_name: d.peer_name || '', available_parts: d.available_parts, total_parts: d.total_parts, country_code: d.country_code } as SourceInfo];
      }
    }).then((u) => { if (mounted) sourceUnlisten = u; else u(); }).catch((e) => { console.error('Failed to subscribe to transfer-source-detail:', e); });

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
  let completedCollapsed = $state(false);

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
    try {
      const sources = await getTransferSources(t.id);
      if (expandedTransferId !== t.id || requestId !== sourceDetailRequestId) return;
      expandedSources = sources;
    } catch (e) {
      if (expandedTransferId === t.id && requestId === sourceDetailRequestId) {
        expandedSources = [];
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

  function toErrorMsg(e: unknown): string {
    return e instanceof Error ? e.message : typeof e === 'string' ? e : 'Operation failed';
  }

  // --- Downloads ---
  let allDownloads = $derived($transfers.filter(t => t.direction === 'download'));
  let activeDownloads = $derived(allDownloads.filter(t => t.status !== 'completed' && t.status !== 'failed'));
  let completedDownloads = $derived(allDownloads.filter(t => t.status === 'completed' || t.status === 'failed'));
  let hasCompletedDl = $derived(completedDownloads.some(t => t.status === 'completed'));
  let transferFilter = $state('');
  let selectedDownloadIds = $state<string[]>([]);
  let selectedDlIdSet = $derived(new Set(selectedDownloadIds));
  let lastClickedDlId = $state<string | null>(null);

  // --- Uploads ---
  let allUploads = $derived($transfers.filter(t => t.direction === 'upload'));
  let activeUploads = $derived(allUploads.filter(t => t.status !== 'completed' && t.status !== 'failed' && t.status !== 'queued'));
  let completedUploads = $derived(allUploads.filter(t => t.status === 'completed' || t.status === 'failed'));
  let queuedUploads = $derived(allUploads.filter(t => t.status === 'queued'));

  // --- Bottom pane view tabs (eMule style) ---
  type BottomView = 'uploading' | 'on_queue' | 'download_clients';
  let bottomView: BottomView = $state('uploading');

  // --- Sorting ---
  type DlSortField = 'file_name' | 'total_size' | 'transferred' | 'completed_size' | 'speed' | 'progress' | 'sources' | 'priority' | 'status' | 'remaining' | 'last_seen_complete' | 'last_received' | 'category' | 'started_at';
  type UlSortField = 'peer_name' | 'file_name' | 'speed' | 'transferred' | 'waited' | 'upload_time' | 'status' | 'client_software';
  const DL_SORT_FIELDS: DlSortField[] = ['file_name', 'total_size', 'transferred', 'completed_size', 'speed', 'progress', 'sources', 'priority', 'status', 'remaining', 'last_seen_complete', 'last_received', 'category', 'started_at'];
  const UL_SORT_FIELDS: UlSortField[] = ['peer_name', 'file_name', 'speed', 'transferred', 'waited', 'upload_time', 'status', 'client_software'];
  function safeGetItem(key: string): string | null { try { return localStorage.getItem(key); } catch { return null; } }
  let dlSortField: DlSortField = $state(DL_SORT_FIELDS.includes(safeGetItem('transfers-dl-sort-field') as DlSortField) ? safeGetItem('transfers-dl-sort-field') as DlSortField : 'file_name');
  let dlSortAsc = $state(safeGetItem('transfers-dl-sort-asc') !== 'false');
  let ulSortField: UlSortField = $state(UL_SORT_FIELDS.includes(safeGetItem('transfers-ul-sort-field') as UlSortField) ? safeGetItem('transfers-ul-sort-field') as UlSortField : 'file_name');
  let ulSortAsc = $state(safeGetItem('transfers-ul-sort-asc') !== 'false');

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
  function sortArrow(current: string, field: string, asc: boolean): string {
    if (current !== field) return '';
    return asc ? ' \u25B2' : ' \u25BC';
  }

  const priorityOrder: Record<string, number> = { release: 0, auto: 1, high: 2, normal: 3, low: 4, verylow: 5 };
  const statusOrder: Record<string, number> = { active: 0, verifying: 1, completing: 2, searching: 3, queued: 4, paused: 5, stopped: 6, hashing: 7, noneneeded: 8, insufficient: 9, failed: 10, completed: 11 };

  // EWMA speed smoothing for stable ETA estimates (eMule "advanced remaining time")
  const speedHistory: Map<string, { ewma: number; lastTransferred: number; lastTime: number }> = new Map();
  const EWMA_ALPHA = 0.3;

  function smoothedSpeed(t: Transfer): number {
    if (t.speed <= 0) return 0;
    const now = Date.now();
    let entry = speedHistory.get(t.id);
    if (!entry) {
      entry = { ewma: t.speed, lastTransferred: t.transferred, lastTime: now };
      speedHistory.set(t.id, entry);
      return t.speed;
    }
    const dt = (now - entry.lastTime) / 1000;
    if (dt < 1) return entry.ewma > 0 ? entry.ewma : t.speed;
    const bytesThisPeriod = t.transferred - entry.lastTransferred;
    const measuredSpeed = Math.max(0, bytesThisPeriod / dt);
    entry.ewma = EWMA_ALPHA * measuredSpeed + (1 - EWMA_ALPHA) * entry.ewma;
    entry.lastTransferred = t.transferred;
    entry.lastTime = now;
    return entry.ewma;
  }

  function etaSeconds(t: Transfer): number {
    const completed = t.completed_size ?? t.transferred;
    if (t.speed <= 0 || completed >= t.total_size) return Infinity;
    const speed = smoothedSpeed(t);
    if (speed <= 0) return Infinity;
    return (t.total_size - completed) / speed;
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
    });
    return sorted;
  });

  let filteredActiveDownloads = $derived.by(() => {
    const query = transferFilter.trim().toLowerCase();
    if (!query) return sortedActiveDownloads;
    return sortedActiveDownloads.filter((t) =>
      t.file_name.toLowerCase().includes(query)
      || t.file_hash.toLowerCase().includes(query)
      || (t.category || '').toLowerCase().includes(query)
      || dlStatusLabel(t).toLowerCase().includes(query)
    );
  });
  let filteredCompletedDownloads = $derived.by(() => {
    const query = transferFilter.trim().toLowerCase();
    if (!query) return completedDownloads;
    return completedDownloads.filter((t) =>
      t.file_name.toLowerCase().includes(query)
      || t.file_hash.toLowerCase().includes(query)
      || (t.category || '').toLowerCase().includes(query)
      || dlStatusLabel(t).toLowerCase().includes(query)
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
  let filteredCompletedUploads = $derived.by(() => {
    const query = transferFilter.trim().toLowerCase();
    if (!query) return completedUploads;
    return completedUploads.filter((t) =>
      t.file_name.toLowerCase().includes(query)
      || (t.peer_name || '').toLowerCase().includes(query)
      || (t.peer_id || '').toLowerCase().includes(query)
      || ulStatusLabel(t).toLowerCase().includes(query)
    );
  });
  let filteredQueuedUploads = $derived.by(() => {
    const query = transferFilter.trim().toLowerCase();
    if (!query) return queuedUploads;
    return queuedUploads.filter((t) =>
      t.file_name.toLowerCase().includes(query)
      || (t.peer_name || '').toLowerCase().includes(query)
      || (t.peer_id || '').toLowerCase().includes(query)
    );
  });

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
  // Match eMule-style behavior: show rate when transfer data is actually flowing.
  let totalDownloadRate = $derived(activeDownloads.reduce((sum, t) => sum + (t.speed > 0 ? t.speed : 0), 0));
  let totalUploadRate = $derived(activeUploads.reduce((sum, t) => sum + (t.speed > 0 ? t.speed : 0), 0));
  let transferringDownloads = $derived(activeDownloads.filter((t) => t.speed > 0).length);
  let totalKnownSources = $derived(activeDownloads.reduce((sum, t) => sum + (t.sources || 0), 0));
  let activeConnectedSources = $derived(activeDownloads.reduce((sum, t) => sum + (t.active_sources || 0) + (t.queued_sources || 0), 0));

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
        if (t.health === 'degraded') return t.queue_rank != null && t.queue_rank > 0 ? `Queued (QR: ${t.queue_rank})` : 'Queued';
        return t.queue_rank != null && t.queue_rank > 0 ? `Queued (QR: ${t.queue_rank})` : 'Waiting';
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
          const path = await recoverArchive(t.id);
          showInfo(`Archive recovered: ${path}`);
          break;
        }
        case 'clear_completed': confirmClearCompleted = true; return;
        case 'copy_link': {
          const link = await formatEd2kLink(t.file_name, t.total_size, t.file_hash);
          await navigator.clipboard.writeText(link);
          break;
        }
        case 'paste_link': {
          const text = await navigator.clipboard.readText();
          if (text.startsWith('ed2k://')) {
            const info = await parseEd2kLink(text);
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

  async function handleBatchPauseDownloads() {
    const ids = transfersForBatchAction().filter((t) => canPause(t)).map((t) => t.id);
    if (!ids.length) return;
    try {
      await pauseTransfersBatch(ids);
    } catch (e: unknown) {
      transferError = toErrorMsg(e);
    }
  }

  async function handleBatchResumeDownloads() {
    const ids = transfersForBatchAction().filter((t) => canResume(t)).map((t) => t.id);
    if (!ids.length) return;
    try {
      await resumeTransfersBatch(ids);
    } catch (e: unknown) {
      transferError = toErrorMsg(e);
    }
  }

  async function handleBatchStopDownloads() {
    const ids = transfersForBatchAction().filter((t) => canStop(t)).map((t) => t.id);
    if (!ids.length) return;
    try {
      await stopTransfersBatch(ids);
    } catch (e: unknown) {
      transferError = toErrorMsg(e);
    }
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
  let visibleClientColumns = $derived.by(() => getVisibleColumns('clients'));

  function getTableElement(table: TableKey): HTMLTableElement | undefined {
    switch (table) {
      case 'downloads': return downloadTableEl;
      case 'uploads': return uploadTableEl;
      case 'queue': return queueTableEl;
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
      case 'queue': return 'Queue Columns';
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
      case 'active':
        return t.health_reason
          ? `Actively downloading data from sources. ${t.health_reason}`
          : 'Actively downloading data from sources';
      case 'searching': {
        const conn = $networkStats.status === 'connected' || $networkStats.status === 'connecting';
        const base = conn ? 'Searching for sources on the network' : 'Waiting to connect before searching';
        return t.health_reason ? `${base}. ${t.health_reason}` : base;
      }
      case 'queued':
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
      case 'active': return 'Actively uploading data to this client';
      case 'completed': return 'Upload to this client completed';
      case 'failed': return 'Upload to this client failed';
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
  let clientColCount = $derived(visibleClientColumns.length);

  $effect(() => {
    if (expandedTransferId && !visibleActiveDownloadIds.has(expandedTransferId)) {
      expandedTransferId = null;
      expandedSources = [];
      loadingSources = false;
      sourceDetailRequestId += 1;
    }
  });

  $effect.pre(() => {
    const visible = visibleActiveDownloadIds;
    const next = selectedDownloadIds.filter((id) => visible.has(id));
    if (next.length !== selectedDownloadIds.length) {
      selectedDownloadIds = next;
    }
  });
</script>

<svelte:document onclick={onDocClick} onkeydown={(e) => {
  if (e.key === 'Escape') {
    if (ctxMenu) { closeCtx(); e.preventDefault(); }
    else if (columnMenu) { closeColumnMenu(); e.preventDefault(); }
  }
}} />

<div class="page-header">
  <h2>Transfers</h2>
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
      <span class="overview-chip"><span class="overview-label">DL</span> {formatSpeed(totalDownloadRate)}</span>
      <span class="overview-chip"><span class="overview-label">UL</span> {formatSpeed(totalUploadRate)}</span>
      <span class="overview-chip"><span class="overview-label">Active</span> {transferringDownloads}</span>
      <span class="overview-chip"><span class="overview-label">Sources</span> {activeConnectedSources}/{totalKnownSources}</span>
      <label class="filter-wrap" aria-label="Filter transfers">
        <span class="filter-label">Filter</span>
        <input
          class="filter-input"
          type="text"
          placeholder="name, hash, category..."
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
    <div class="pane-content">
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
                  <td class="num-cell">{t.speed > 0 ? formatSpeed(t.speed) : '\u2014'}</td>
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
                        color={t.status === 'paused' || t.status === 'stopped' ? 'var(--warning)' : t.status === 'verifying' || t.status === 'completing' ? 'var(--success, #2ecc71)' : 'var(--accent)'}
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
                  <td class="num-cell">{formatRemaining(t.total_size, t.transferred, t.speed > 0 ? smoothedSpeed(t) : 0)}</td>
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
                {@const visibleSources = expandedSources.filter(s => s.status !== 'failed')}
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
                      <span class="status-label st-{t.status}" title={dlStatusTooltip(t)}>{dlStatusLabel(t)}</span>
                      {#if t.status === 'failed' && t.failure_reason}
                        <span class="failure-hint" title={t.failure_reason}>{t.failure_reason}</span>
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

  <!-- BOTTOM PANE: Uploads / On Queue / Download Clients (eMule tabs) -->
  <div class="pane uploads-pane" style="flex: 1;">
    <div class="pane-toolbar">
      <div class="bottom-tabs">
        <button
          class="tab-btn"
          class:active={bottomView === 'uploading'}
          onclick={() => bottomView = 'uploading'}
        >Uploading ({filteredActiveUploads.length})</button>
        <button
          class="tab-btn"
          class:active={bottomView === 'on_queue'}
          onclick={() => bottomView = 'on_queue'}
        >On Queue ({filteredQueuedUploads.length})</button>
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
                    <td class="num-cell">{t.speed > 0 ? formatSpeed(t.speed) : '\u2014'}</td>
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
                      {#if t.progress > 0}
                        <ProgressBar value={t.progress} color="var(--accent)" />
                      {:else}
                        <span class="no-bar">—</span>
                      {/if}
                    </td>
                  {/if}
                {/each}
              </tr>
            {/each}
            {#if filteredCompletedUploads.length > 0}
              <tr class="section-divider-row"><td colspan={ulColCount}>Completed ({filteredCompletedUploads.length})</td></tr>
              {#each filteredCompletedUploads as t (t.id)}
                <tr class="ul-row completed-row">
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
                      <td class="num-cell">{'\u2014'}</td>
                    {:else if column.key === 'transferred'}
                      <td class="num-cell">{formatSize(t.transferred)}</td>
                    {:else if column.key === 'total_size'}
                      <td class="num-cell">{formatSize(t.total_size)}</td>
                    {:else if column.key === 'upload_time'}
                      <td class="num-cell">{formatDuration(t.upload_time)}</td>
                    {:else if column.key === 'status'}
                      <td class="status-cell"><span class="status-label st-{t.status}" title={ulStatusTooltip(t)}>{ulStatusLabel(t)}</span></td>
                    {:else if column.key === 'up_status'}
                      <td class="bar-cell"><span class="no-bar">—</span></td>
                    {/if}
                  {/each}
                </tr>
              {/each}
            {/if}
            {#if allUploads.length === 0}
              <tr><td colspan={ulColCount} class="empty-cell">No uploads</td></tr>
            {:else if filteredActiveUploads.length === 0 && filteredCompletedUploads.length === 0}
              <tr><td colspan={ulColCount} class="empty-cell">No uploads match this filter</td></tr>
            {/if}
          </tbody>
        </table>
      {:else if bottomView === 'on_queue'}
        <!-- ON QUEUE VIEW (eMule upload queue) -->
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
            {#each filteredQueuedUploads as t (t.id)}
              <tr class="ul-row" oncontextmenu={(e) => onCtx(e, t, 'upload')}>
                {#each visibleQueueColumns as column (column.key)}
                  {#if column.key === 'peer_name'}
                    <td class="client-cell" title={t.peer_name || t.peer_id}>{t.peer_name || t.peer_id || '\u2014'}</td>
                  {:else if column.key === 'file_name'}
                    <td class="name-cell" title={t.file_name}>{t.file_name}</td>
                  {:else if column.key === 'priority'}
                    <td class="prio-cell">
                      <span class="prio-badge prio-{t.priority}" title={priorityTooltip(t.priority)}>{t.priority.charAt(0).toUpperCase() + t.priority.slice(1)}</span>
                    </td>
                  {:else if column.key === 'entered_queue'}
                    <td class="date-cell">{formatDate(t.started_at)}</td>
                  {:else if column.key === 'up_status'}
                    <td class="bar-cell"><span class="no-bar">—</span></td>
                  {/if}
                {/each}
              </tr>
            {/each}
            {#if filteredQueuedUploads.length === 0}
              <tr><td colspan={queueColCount} class="empty-cell">No clients are waiting in the upload queue.</td></tr>
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
              {@const clientSources = expandedSources.filter(s => s.status !== 'failed')}
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
        <button class="ctx-item" onclick={() => ctxAction('recover_archive')}>Recover Archive</button>
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
      {#if ctxTransfer.status === 'completed'}
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

<ConfirmDialog
  bind:open={confirmBatchCancel.open}
  title="Cancel Downloads"
  message="Cancel {confirmBatchCancel.count} download(s) and delete partial data?"
  confirmLabel="Cancel Downloads"
  danger={true}
  onconfirm={async () => { const ids = confirmBatchCancel.ids; const idSet = new Set(ids); try { await cancelTransfersBatch(ids); for (const id of idSet) speedHistory.delete(id); transfers.update((list) => list.filter((x) => !idSet.has(x.id))); selectedDownloadIds = []; } catch (e: unknown) { transferError = toErrorMsg(e); } }}
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
  .prio-low { color: var(--text-muted); }
  .prio-verylow { color: var(--text-muted); opacity: 0.6; }
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
