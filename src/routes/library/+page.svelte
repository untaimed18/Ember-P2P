<script lang="ts">
  import {
    addSharedFolder,
    deleteSharedFile,
    removeSharedFolder,
    getSharedFiles,
    getSharedFolders,
    reloadSharedFiles,
    getScanStatus,
    stopHashing,
    resumeHashing,
    setFilePriority,
    unshareFile,
    shareFile,
    unshareFolder,
    openSharedFile as openSharedFileCommand,
    openSharedFolder as openSharedFolderCommand,
    batchSetPriority,
    batchShare,
    batchUnshare,
    republishFile,
    scanMissingFiles,
    removeMissingFiles,
    getFolderPriorities,
    setFolderPriority,
    getFileMediaMetadata,
  } from '$lib/api/sharing';
  import { getFileComments, setFileComment, type FileCommentInfo } from '$lib/api/comments';
  import { formatEd2kLink, buildEd2kLink } from '$lib/api/search';
  import { loadCollection, createCollection, downloadCollectionFiles, type Collection, type CollectionFile } from '$lib/api/collections';
  import { incomingCollection } from '$lib/stores/collection';
  import { toastSuccess, toastError, toastWarning } from '$lib/stores/toast';
  import { networkStats } from '$lib/stores/network';
  import { formatSize } from '$lib/utils';
  import type { FileInfo, MediaMetadata } from '$lib/types';
  import { onMount, tick } from 'svelte';
  import { fly } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';

  import { listen } from '@tauri-apps/api/event';
  import LibraryVirtualTable from '$lib/components/LibraryVirtualTable.svelte';
  import IconX from '$lib/components/IconX.svelte';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';

  let folders: string[] = $state([]);
  let folderPriorities: Record<string, string> = $state({});
  let files: FileInfo[] = $state([]);
  let scanning = $state(false);
  let error: string | null = $state(null);
  let selectedPath: string | null = $state(null);
  // Bound to the virtualized file table; used by arrow-key navigation
  // to scroll the new selection into view (the row may not exist in
  // the DOM yet because the table is virtualized).
  let libraryTableRef: { scrollRowIntoView: (i: number) => void } | undefined = $state(undefined);
  let filterFolder: string | null = $state(null);
  let hashProgress: { current: number; total: number; file_name: string } | null = $state(null);
  let stoppedByUser = $state(false);
  let fileByPath = $derived.by(() => {
    const map = new Map<string, FileInfo>();
    for (const f of files) map.set(f.path, f);
    return map;
  });
  let selectedFile = $derived(selectedPath ? (fileByPath.get(selectedPath) ?? null) : null);
  let selectedHash = $derived.by(() => selectedFile?.hash || null);
  let selectedMedia: MediaMetadata | null = $state(null);

  let hashedLibraryFiles = $derived.by(() => files.filter((f) => !!f.hash));

  // --- Collections ---
  let collectionsOpen = $state(false);
  let loadedCollection: Collection | null = $state(null);
  let collectionLoading = $state(false);
  let downloadingCollection = $state(false);
  let createCollectionOpen = $state(false);
  let newCollName = $state('');
  let newCollAuthor = $state('');
  let selectedFileHashes: Set<string> = $state(new Set());
  let creatingCollection = $state(false);
  let newCollFormat: 'binary' | 'text' = $state('binary');
  let copyingCollectionLinks = $state(false);

  async function handleOpenCollection() {
    try {
      const { open: openDialog } = await import('@tauri-apps/plugin-dialog');
      const selected = await openDialog({
        multiple: false,
        filters: [{ name: 'eMule Collection', extensions: ['emulecollection', 'txt'] }],
      });
      if (!selected) return;
      collectionLoading = true;
      collectionsOpen = true;
      loadedCollection = await loadCollection(selected as string);
      toastSuccess(m.library_collection_loaded({ name: loadedCollection.name, count: loadedCollection.files.length }));
    } catch (e: unknown) {
      toastError(toErr(e));
      loadedCollection = null;
    } finally {
      collectionLoading = false;
    }
  }

  async function handleDownloadAll() {
    if (!loadedCollection || downloadingCollection) return;
    downloadingCollection = true;
    try {
      const msg = await downloadCollectionFiles(loadedCollection.files);
      toastSuccess(msg || m.library_queued_files_download({ count: loadedCollection.files.length }));
    } catch (e: unknown) {
      toastError(toErr(e));
    } finally {
      downloadingCollection = false;
    }
  }

  async function handleCopyCollectionLinks() {
    if (!loadedCollection || copyingCollectionLinks) return;
    copyingCollectionLinks = true;
    try {
      const links = await Promise.all(
        loadedCollection.files.map((f) => formatEd2kLink(f.name, f.size, f.hash))
      );
      await navigator.clipboard.writeText(links.join('\n'));
      toastSuccess(links.length === 1 ? m.library_copied_link_one() : m.library_copied_links_other({ count: links.length }));
    } catch (e: unknown) {
      toastError(toErr(e));
    } finally {
      copyingCollectionLinks = false;
    }
  }

  const COLLECTION_PICKER_DISPLAY_LIMIT = 500;

  let collectionSearch = $state('');
  let collectionFilteredFiles = $derived.by(() => {
    const q = collectionSearch.trim().toLowerCase();
    if (!q) return hashedLibraryFiles;
    return hashedLibraryFiles.filter(f => f.name.toLowerCase().includes(q));
  });
  let displayedCollectionFiles = $derived.by(() =>
    collectionFilteredFiles.slice(0, COLLECTION_PICKER_DISPLAY_LIMIT)
  );

  function openCreateDialog(preselectHashes?: Iterable<string>) {
    newCollName = '';
    newCollAuthor = '';
    selectedFileHashes = new Set(preselectHashes ?? []);
    collectionSearch = '';
    newCollFormat = 'binary';
    createCollectionOpen = true;
  }

  function openCreateDialogFromSelection() {
    const hashes = getCheckedFiles()
      .map((f) => f.hash)
      .filter((h): h is string => !!h);
    if (hashes.length === 0) {
      toastWarning(m.library_select_hashed_file());
      return;
    }
    openCreateDialog(hashes);
  }

  function toggleFileSelection(hash: string) {
    const next = new Set(selectedFileHashes);
    if (next.has(hash)) next.delete(hash);
    else next.add(hash);
    selectedFileHashes = next;
  }

  function toggleAllFileSelection() {
    const visibleHashes = new Set(collectionFilteredFiles.map((f) => f.hash));
    const allVisible = visibleHashes.size > 0 && [...visibleHashes].every(h => selectedFileHashes.has(h));
    if (allVisible) {
      const next = new Set(selectedFileHashes);
      for (const h of visibleHashes) next.delete(h);
      selectedFileHashes = next;
    } else {
      selectedFileHashes = new Set([...selectedFileHashes, ...visibleHashes]);
    }
  }

  function sanitizeFilename(raw: string): string {
    // Strip characters forbidden by Windows/macOS/Linux plus path separators
    // and control chars. Collapse runs of whitespace and trim dots/spaces
    // from the ends so that e.g. "My:Mix/2025." -> "My_Mix_2025".
    const cleaned = raw
      // eslint-disable-next-line no-control-regex
      .replace(/[\\/:*?"<>|\x00-\x1f]/g, '_')
      .replace(/\s+/g, ' ')
      .replace(/^[.\s]+|[.\s]+$/g, '')
      .slice(0, 120);
    return cleaned.length > 0 ? cleaned : 'Collection';
  }

  async function handleCreateCollection() {
    if (!newCollName.trim() || selectedFileHashes.size === 0) return;
    try {
      const { save: saveDialog } = await import('@tauri-apps/plugin-dialog');
      const isBinary = newCollFormat === 'binary';
      const ext = isBinary ? 'emulecollection' : 'txt';
      const filterName = isBinary ? m.library_emule_collection() : m.library_ed2k_links_text();
      const safeName = sanitizeFilename(newCollName.trim());
      const outputPath = await saveDialog({
        defaultPath: `${safeName}.${ext}`,
        filters: [{ name: filterName, extensions: [ext] }],
      });
      if (!outputPath) return;
      creatingCollection = true;
      const collFiles: CollectionFile[] = hashedLibraryFiles
        .filter((f) => selectedFileHashes.has(f.hash))
        .map((f) => ({ name: f.name, size: f.size, hash: f.hash, aich_hash: f.aich_hash }));
      const msg = await createCollection(newCollName.trim(), newCollAuthor.trim(), collFiles, outputPath, isBinary);
      toastSuccess(msg || m.library_collection_created({ name: newCollName.trim(), count: collFiles.length }));
      createCollectionOpen = false;
    } catch (e: unknown) {
      toastError(toErr(e));
    } finally {
      creatingCollection = false;
    }
  }

  // --- Search / Type filter ---
  let searchQuery = $state('');
  // Debounced mirror of `searchQuery`. The heavy filter+sort pipeline keys
  // off this rather than the raw input so that typing into the search box
  // doesn't re-filter and re-sort the whole library (up to ~50k rows) on
  // every keystroke. Immediate UI affordances (clear button, Escape, the
  // "active filters" chip) still read `searchQuery` directly.
  let debouncedQuery = $state('');
  let searchDebounceTimer: ReturnType<typeof setTimeout> | null = null;
  $effect(() => {
    const q = searchQuery;
    if (searchDebounceTimer) {
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = null;
    }
    // Apply the first character of a new query (and restored filters on
    // mount, where debouncedQuery is still '') synchronously so results
    // appear instantly; debounce only the rapid follow-up keystrokes.
    // Also apply an empty query immediately: clearing the box (clear button,
    // Escape, clearLibraryFilters, reveal-file) must un-filter the table at
    // once so the table state matches the `hasActiveLibraryFilters` UI that
    // reads `searchQuery` directly — otherwise they disagree for ~150 ms.
    if (debouncedQuery === '' || q === '') {
      debouncedQuery = q;
      return;
    }
    searchDebounceTimer = setTimeout(() => {
      searchDebounceTimer = null;
      debouncedQuery = q;
    }, 150);
    return () => {
      if (searchDebounceTimer) {
        clearTimeout(searchDebounceTimer);
        searchDebounceTimer = null;
      }
    };
  });
  let searchInputEl: HTMLInputElement | undefined = $state(undefined);
  const typeFilterOptions = ['All', 'Audio', 'Video', 'Image', 'Archive', 'Document', 'CD/DVD'] as const;
  type TypeFilter = (typeof typeFilterOptions)[number];
  let typeFilter: TypeFilter = $state('All');
  let showDuplicatesOnly = $state(false);
  let showMissingOnly = $state(false);
  let missingPathSet: Set<string> = $state(new Set());
  let missingScanInFlight = false;
  // `scanMissingFiles` stats every shared file on disk, so it must not run on
  // every data refresh — and `refresh()` itself fires every 3s while hashing.
  // Throttle background scans to once per interval; user-initiated paths pass
  // `force` to bypass it (e.g. right after removing missing entries).
  let lastMissingScanAt = 0;
  const MISSING_SCAN_MIN_INTERVAL_MS = 30_000;
  // A persisted "missing only" filter is applied lazily: enabling it before
  // the first missing-file scan completes would filter against an empty set
  // and blank the whole library. Set from localStorage, consumed by the
  // first refreshMissingSet().
  let pendingRestoreMissingOnly = false;

  async function refreshMissingSet(force = false) {
    if (missingScanInFlight) return;
    if (!force && Date.now() - lastMissingScanAt < MISSING_SCAN_MIN_INTERVAL_MS) return;
    missingScanInFlight = true;
    lastMissingScanAt = Date.now();
    try {
      const list = await scanMissingFiles();
      if (!mounted) return;
      missingPathSet = new Set(list);
      // Apply a deferred persisted "missing only" filter now that we know
      // whether any files are actually missing — only enable it if so.
      if (pendingRestoreMissingOnly) {
        pendingRestoreMissingOnly = false;
        showMissingOnly = missingPathSet.size > 0;
      }
      if (showMissingOnly && missingPathSet.size === 0) {
        showMissingOnly = false;
      }
    } catch {
      // Non-fatal: leave previous set in place.
    } finally {
      missingScanInFlight = false;
    }
  }

  async function handleRemoveMissing() {
    if (missingPathSet.size === 0) return;
    try {
      const { confirm } = await import('@tauri-apps/plugin-dialog');
      const confirmed = await confirm(
        missingPathSet.size === 1 ? m.library_confirm_remove_missing_one() : m.library_confirm_remove_missing_other({ count: missingPathSet.size }),
        { title: m.library_remove_missing_title(), kind: 'warning' }
      );
      if (!confirmed) return;
      const removed = await removeMissingFiles([...missingPathSet]);
      toastSuccess(removed === 1 ? m.library_removed_missing_one() : m.library_removed_missing_other({ count: removed }));
      missingPathSet = new Set();
      showMissingOnly = false;
      await refresh();
    } catch (e: unknown) {
      toastError(toErr(e));
    }
  }

  let duplicateHashes = $derived.by(() => {
    const counts = new Map<string, number>();
    for (const f of files) {
      if (!f.hash) continue;
      counts.set(f.hash, (counts.get(f.hash) ?? 0) + 1);
    }
    const dupes = new Set<string>();
    for (const [h, n] of counts) {
      if (n > 1) dupes.add(h);
    }
    return dupes;
  });
  let duplicateFileCount = $derived.by(() => {
    if (duplicateHashes.size === 0) return 0;
    let n = 0;
    for (const f of files) if (f.hash && duplicateHashes.has(f.hash)) n++;
    return n;
  });

  function normalizePathForMatch(path: string): string {
    return path.replace(/\\/g, '/').replace(/\/+$/, '');
  }

  function isPathInFolder(filePath: string, folderPath: string): boolean {
    const normalizedFilePath = normalizePathForMatch(filePath);
    const normalizedFolderPath = normalizePathForMatch(folderPath);
    return normalizedFilePath === normalizedFolderPath
      || normalizedFilePath.startsWith(`${normalizedFolderPath}/`);
  }

  function folderDisplayName(path: string | null): string {
    if (!path) return m.library_all_folders();
    return path.split(/[\\/]/).filter(Boolean).pop() || path;
  }

  // --- Comments panel ---
  let commentInfo: FileCommentInfo | null = $state(null);
  let commentLoading = $state(false);
  let ourRating = $state(0);
  let ourComment = $state('');
  let commentSaveState = $state<'idle' | 'saving' | 'saved' | 'error'>('idle');
  let commentSaveMessage = $state('');
  let commentLastSavedAt = $state<number | null>(null);
  let commentSaveTimer: ReturnType<typeof setTimeout> | null = null;

  let mounted = false;
  let busy = false;
  let pendingRefresh = false;
  let refreshTimer: ReturnType<typeof setTimeout> | null = null;

  function debouncedRefresh() {
    if (refreshTimer) clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => { refreshTimer = null; refresh(); }, 300);
  }

  function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<T>((_, reject) => {
      timer = setTimeout(() => reject(new Error('timeout')), ms);
    });
    // Clear the watchdog once either side settles so the loser timer doesn't
    // linger (and can't reject after the real promise already resolved).
    return Promise.race([promise, timeout]).finally(() => {
      if (timer) clearTimeout(timer);
    });
  }

  async function refresh() {
    if (!mounted) return;
    if (busy) {
      pendingRefresh = true;
      return;
    }
    busy = true;
    pendingRefresh = false;
    try {
      const [newFolders, newFiles, isScanning, newPriorities] = await withTimeout(
        Promise.all([
          getSharedFolders(),
          getSharedFiles(),
          getScanStatus(),
          getFolderPriorities(),
        ]),
        5000,
      );
      if (!mounted) return;
      folders = newFolders;
      if (!stoppedByUser) scanning = isScanning;
      files = newFiles;
      folderPriorities = newPriorities;
    } catch (e) {
      if (mounted && e instanceof Error && e.message !== 'timeout')
        console.error('Failed to load shared files:', e);
    } finally {
      busy = false;
      if (pendingRefresh && mounted) {
        pendingRefresh = false;
        debouncedRefresh();
      }
    }
    if (mounted) void refreshMissingSet();
  }

  function toErr(e: unknown): string {
    return translateError(e, m.error_operation_failed());
  }

  async function openSharedFile(path: string) {
    try {
      await openSharedFileCommand(path);
    } catch (e: unknown) {
      error = toErr(e);
      toastError(error);
    }
  }

  async function openSharedFolder(path: string) {
    try {
      await openSharedFolderCommand(path);
    } catch (e: unknown) {
      error = toErr(e);
      toastError(error);
    }
  }

  async function copyToClipboard(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      toastSuccess(label);
    } catch {
      toastError(m.library_copy_failed());
    }
  }

  async function handleAddFolder() {
    error = null;
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({ directory: true, multiple: false });
      if (!mounted || !selected) return;
      stoppedByUser = false;
      scanning = true;
      await addSharedFolder(selected as string);
      if (mounted) await refresh();
    } catch (e: unknown) {
      if (mounted) error = toErr(e);
    }
  }

  async function handleSetFolderPriority(path: string, priority: string) {
    try {
      error = null;
      const count = await setFolderPriority(path, priority);
      if (!mounted) return;
      if (priority) {
        folderPriorities = { ...folderPriorities, [path]: priority };
        toastSuccess(m.library_folder_priority_set({ count: count.toLocaleString() }));
      } else {
        const next = { ...folderPriorities };
        delete next[path];
        folderPriorities = next;
        toastSuccess(m.library_folder_priority_cleared());
      }
      await refresh();
    } catch (e: unknown) {
      if (mounted) error = toErr(e);
    }
  }

  async function handleRemoveFolder(path: string) {
    const stats = folderStats.counts.get(path) ?? 0;
    try {
      const { confirm } = await import('@tauri-apps/plugin-dialog');
      const displayName = path.split(/[\\/]/).filter(Boolean).pop() || path;
      const body = stats > 0
        ? (stats === 1
            ? m.library_confirm_remove_folder_one({ name: displayName })
            : m.library_confirm_remove_folder_other({ name: displayName, count: stats.toLocaleString() }))
        : m.library_confirm_remove_folder_empty({ name: displayName });
      const confirmed = await confirm(body, { title: m.library_remove_folder_title(), kind: 'warning' });
      if (!confirmed || !mounted) return;
      error = null;
      await removeSharedFolder(path);
      if (!mounted) return;
      if (filterFolder === path) filterFolder = null;
      await refresh();
    } catch (e: unknown) {
      if (mounted) error = toErr(e);
    }
  }

  async function handleReload() {
    error = null;
    // An explicit reload is a fresh user-initiated rescan, so clear any
    // prior "stopped by user" state. Otherwise the progress listener and
    // the scan-status poll (both gated on !stoppedByUser) stay suppressed,
    // leaving the reload to run invisibly while the "hashing stopped"
    // banner lingers.
    stoppedByUser = false;
    scanning = true;
    try {
      await reloadSharedFiles();
    } catch (e: unknown) {
      // The success path clears `scanning` via the background hash-progress
      // "done" event, but on an invoke failure no such event fires — clear it
      // here so the scanning banner doesn't linger until the 3s status poll.
      if (mounted) {
        scanning = false;
        error = toErr(e);
      }
    }
  }

  let stopConfirmVisible = $state(false);

  function handleStopRequest() {
    stopConfirmVisible = true;
  }

  function handleStopCancel() {
    stopConfirmVisible = false;
  }

  async function handleStopConfirm() {
    stopConfirmVisible = false;
    scanning = false;
    hashProgress = null;
    stoppedByUser = true;
    try {
      await stopHashing();
      if (mounted) {
        stoppedByUser = false;
        await refresh();
      }
    } catch (e: unknown) {
      if (mounted) error = toErr(e);
    }
  }

  async function handleResume() {
    stoppedByUser = false;
    scanning = true;
    try {
      await resumeHashing();
      await refresh();
    } catch (e: unknown) {
      if (mounted) error = toErr(e);
    }
  }

  // --- Filtering ---
  // Combine all five predicates into a single pass. The previous chain
  // allocated a new intermediate array for each active filter (so up to 5
  // mid-sized copies on every keystroke-triggered re-derive with ~50k
  // files in the library). Collapsing to one `.filter` also lets the JIT
  // fuse the hot path and cuts one dependency read per skipped row.
  let filteredFiles = $derived.by(() => {
    const q = debouncedQuery.trim().toLowerCase();
    const hasFolder = !!filterFolder;
    const folder = filterFolder;
    const hasQuery = q.length > 0;
    const hasType = typeFilter !== 'All';
    const dupOnly = showDuplicatesOnly;
    const missOnly = showMissingOnly;
    if (!hasFolder && !hasQuery && !hasType && !dupOnly && !missOnly) return files;
    return files.filter((f) => {
      if (hasFolder && !isPathInFolder(f.path, folder!)) return false;
      if (hasQuery && !f.name.toLowerCase().includes(q)) return false;
      if (hasType && fileTypeKey(f.extension) !== typeFilter) return false;
      if (dupOnly && (!f.hash || !duplicateHashes.has(f.hash))) return false;
      if (missOnly && !missingPathSet.has(f.path)) return false;
      return true;
    });
  });

  let hasActiveLibraryFilters = $derived(!!filterFolder || !!searchQuery.trim() || typeFilter !== 'All' || showDuplicatesOnly || showMissingOnly);
  let libraryFileStats = $derived.by(() => {
    let shared = 0;
    let hashed = 0;
    for (const f of files) {
      if (f.shared) shared++;
      if (f.hash) hashed++;
    }
    return { shared, hashed };
  });
  let filteredSharedCount = $derived.by(() => {
    let n = 0;
    for (const f of filteredFiles) if (f.shared) n++;
    return n;
  });
  let allHashedFilesSelected = $derived.by(() => {
    const list = collectionFilteredFiles;
    if (list.length === 0) return false;
    return list.every(f => selectedFileHashes.has(f.hash));
  });

  function clearLibraryFilters() {
    filterFolder = null;
    searchQuery = '';
    typeFilter = 'All';
    showDuplicatesOnly = false;
    showMissingOnly = false;
  }

  // --- Multi-select ---
  let checkedPaths: Set<string> = $state(new Set());
  let lastClickedPath: string | null = $state(null);
  let checkedCount = $derived.by(() => {
    let n = 0;
    for (const f of sortedFiles) if (checkedPaths.has(f.path)) n++;
    return n;
  });
  // Selections persist across filter changes, but bulk actions only operate on
  // rows currently in `sortedFiles` (see getCheckedFiles). Count how many
  // checked files exist in the library yet are hidden by the active filter so
  // the bulk bar can warn rather than silently acting on a subset.
  let checkedHiddenCount = $derived.by(() => {
    if (!hasActiveLibraryFilters || checkedPaths.size === 0) return 0;
    const visible = new Set(sortedFiles.map((f) => f.path));
    let n = 0;
    for (const p of checkedPaths) {
      if (!visible.has(p) && fileByPath.has(p)) n++;
    }
    return n;
  });

  function toggleCheck(path: string, shiftKey: boolean) {
    if (shiftKey && lastClickedPath) {
      const list = sortedFiles;
      const startIdx = list.findIndex(f => f.path === lastClickedPath);
      const endIdx = list.findIndex(f => f.path === path);
      if (startIdx !== -1 && endIdx !== -1) {
        const lo = Math.min(startIdx, endIdx);
        const hi = Math.max(startIdx, endIdx);
        const next = new Set(checkedPaths);
        for (let i = lo; i <= hi; i++) next.add(list[i].path);
        checkedPaths = next;
        lastClickedPath = path;
        return;
      }
    }
    const next = new Set(checkedPaths);
    if (next.has(path)) next.delete(path);
    else next.add(path);
    checkedPaths = next;
    lastClickedPath = path;
  }

  function clearChecked() { checkedPaths = new Set(); lastClickedPath = null; }

  let allFilteredChecked = $derived.by(() => {
    if (sortedFiles.length === 0) return false;
    return sortedFiles.every(f => checkedPaths.has(f.path));
  });
  let someFilteredChecked = $derived.by(() => {
    return sortedFiles.some(f => checkedPaths.has(f.path));
  });

  function toggleCheckAll() {
    if (allFilteredChecked) {
      checkedPaths = new Set();
    } else {
      checkedPaths = new Set(sortedFiles.map(f => f.path));
    }
    lastClickedPath = null;
  }

  function getCheckedFiles(): FileInfo[] {
    return sortedFiles.filter(f => checkedPaths.has(f.path));
  }

  async function bulkSetPriority(priority: FileInfo['priority']) {
    const targets = getCheckedFiles().filter(f => !!f.hash);
    if (targets.length === 0) return;
    try {
      const count = await batchSetPriority(targets.map(f => f.path), priority);
      await refresh();
      toastSuccess(count === 1
        ? m.library_set_priority_one({ priority: priorityLabel(priority) })
        : m.library_set_priority_other({ priority: priorityLabel(priority), count }));
    } catch (e: unknown) { error = toErr(e); }
  }

  async function bulkShare() {
    const targets = getCheckedFiles().filter(f => !!f.hash && !f.shared);
    if (targets.length === 0) return;
    try {
      const count = await batchShare(targets.map(f => f.path));
      await refresh();
      toastSuccess(count === 1 ? m.library_shared_one() : m.library_shared_other({ count }));
    } catch (e: unknown) { error = toErr(e); }
  }

  async function bulkUnshare() {
    const targets = getCheckedFiles().filter(f => !!f.hash && f.shared);
    if (targets.length === 0) return;
    try {
      const count = await batchUnshare(targets.map(f => f.path));
      await refresh();
      toastSuccess(count === 1 ? m.library_unshared_one() : m.library_unshared_other({ count }));
    } catch (e: unknown) { error = toErr(e); }
  }

  async function bulkDelete() {
    const targets = getCheckedFiles();
    if (targets.length === 0) return;
    const totalBytes = targets.reduce((sum, f) => sum + f.size, 0);
    try {
      const { confirm } = await import('@tauri-apps/plugin-dialog');
      const confirmed = await confirm(
        targets.length === 1
          ? m.library_confirm_delete_one({ size: formatSize(totalBytes) })
          : m.library_confirm_delete_other({ count: targets.length.toLocaleString(), size: formatSize(totalBytes) }),
        { title: m.library_delete_files_title(), kind: 'warning' }
      );
      if (!confirmed) return;
      let deleted = 0;
      const failures: string[] = [];
      for (const f of targets) {
        try {
          await deleteSharedFile(f.path, f.hash || undefined);
          deleted++;
        } catch (e: unknown) {
          failures.push(`${f.name}: ${toErr(e)}`);
        }
      }
      if (selectedPath && targets.some((f) => f.path === selectedPath)) {
        selectedPath = null;
      }
      clearChecked();
      await refresh();
      if (deleted > 0) {
        const base = deleted === 1 ? m.library_deleted_one() : m.library_deleted_other({ count: deleted });
        toastSuccess(failures.length ? m.library_deleted_with_failures({ base, failed: failures.length }) : base);
      }
      if (failures.length > 0) {
        toastError(failures[0]);
      }
    } catch (e: unknown) { error = toErr(e); }
  }

  async function bulkCopyLinks() {
    const targets = getCheckedFiles().filter(f => !!f.hash);
    if (targets.length === 0) return;
    try {
      const links = await Promise.all(targets.map(f => formatEd2kLink(f.name, f.size, f.hash)));
      await navigator.clipboard.writeText(links.join('\n'));
      const unsharedCount = targets.filter(f => !f.shared).length;
      if (unsharedCount > 0) {
        toastWarning(m.library_copied_with_unshared({
          links: links.length,
          link_label: links.length === 1 ? m.library_link_singular() : m.library_link_plural(),
          unshared: unsharedCount,
          unshared_label: unsharedCount === 1 ? m.library_file_is_unshared() : m.library_files_are_unshared(),
        }));
      } else {
        toastSuccess(links.length === 1 ? m.library_copied_link_one() : m.library_copied_links_other({ count: links.length }));
      }
    } catch (e: unknown) { error = toErr(e); }
  }

  // --- Sorting ---
  type SortField = 'name' | 'size' | 'extension' | 'priority' | 'hash' | 'requests' | 'accepted' | 'bytes_transferred' | 'folder' | 'complete_sources' | 'modified_at';
  let sortField: SortField = $state('name');
  let sortAsc = $state(true);

  function toggleSort(field: SortField) {
    if (sortField === field) sortAsc = !sortAsc;
    else { sortField = field; sortAsc = true; }
  }
  function arrow(field: string): string {
    if (sortField !== field) return ' \u00A0';
    return sortAsc ? ' \u25B2' : ' \u25BC';
  }
  function ariaSort(field: string): 'ascending' | 'descending' | 'none' {
    if (sortField !== field) return 'none';
    return sortAsc ? 'ascending' : 'descending';
  }
  function sortOnKey(e: KeyboardEvent, field: SortField) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      toggleSort(field);
    }
  }

  const priorityOrder: Record<string, number> = { verylow: 0, low: 1, normal: 2, high: 3, release: 4, auto: 5 };

  // One reused collator instead of an implicit `String.prototype.localeCompare`
  // collator per comparison (which, on a 50k-row sort, is hundreds of
  // thousands of allocations). `numeric: true` also gives natural ordering so
  // "File2" sorts before "File10", and `sensitivity: 'base'` makes the sort
  // case/accent-insensitive the way users expect from a file manager.
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

  let sortedFiles = $derived.by(() => {
    const copy = [...filteredFiles];
    const dir = sortAsc ? 1 : -1;
    copy.sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'name': cmp = collator.compare(a.name, b.name); break;
        case 'size': cmp = a.size - b.size; break;
        case 'extension': cmp = collator.compare(a.extension, b.extension); break;
        case 'priority': cmp = (priorityOrder[a.priority] ?? 2) - (priorityOrder[b.priority] ?? 2); break;
        case 'hash': cmp = collator.compare(a.hash, b.hash); break;
        case 'requests': cmp = a.requests - b.requests; break;
        case 'accepted': cmp = a.accepted - b.accepted; break;
        case 'bytes_transferred': cmp = a.bytes_transferred - b.bytes_transferred; break;
        case 'folder': cmp = collator.compare(a.folder, b.folder); break;
        case 'complete_sources': cmp = a.complete_sources - b.complete_sources; break;
        case 'modified_at': cmp = (a.modified_at || 0) - (b.modified_at || 0); break;
      }
      // Stable, deterministic ordering for ties: fall back to the file name
      // (and then the full path, which is unique) so equal sizes/priorities/
      // dates don't render in arbitrary order. The tiebreakers always read
      // ascending regardless of the primary sort direction so names stay A→Z.
      if (cmp === 0) {
        if (sortField !== 'name') {
          const byName = collator.compare(a.name, b.name);
          if (byName !== 0) return byName;
        }
        return collator.compare(a.path, b.path);
      }
      return dir * cmp;
    });
    return copy;
  });

  // Per-folder count AND size. Superset of the old `folderCounts` map;
  // main's cherry-picked bulk-folder-delete handler reads `.counts` and
  // `.sizes`, and ember-V2's tree UI reads `.counts` via the same derived
  // store. Sort shared folders by depth (deepest first) so nested
  // shared folders attribute each file to the most specific ancestor.
  let folderStats = $derived.by(() => {
    const counts = new Map<string, number>();
    const sizes = new Map<string, number>();
    if (folders.length === 0) return { counts, sizes };

    const normalizedFolders = folders
      .map((folder) => ({ folder, norm: normalizePathForMatch(folder) }))
      .sort((a, b) => b.norm.length - a.norm.length);
    for (const { folder } of normalizedFolders) {
      counts.set(folder, 0);
      sizes.set(folder, 0);
    }
    for (const f of files) {
      const np = normalizePathForMatch(f.path);
      for (const { folder, norm } of normalizedFolders) {
        if (np === norm || np.startsWith(`${norm}/`)) {
          counts.set(folder, (counts.get(folder) ?? 0) + 1);
          sizes.set(folder, (sizes.get(folder) ?? 0) + f.size);
          break;
        }
      }
    }
    return { counts, sizes };
  });
  let activeFolderLabel = $derived(folderDisplayName(filterFolder));

  // --- Top Uploads (popularity panel) ---
  let topPanelOpen = $state(true);
  let topPanelMetric: 'bytes' | 'requests' = $state('bytes');
  let topPanelScope: 'session' | 'alltime' = $state('alltime');
  const TOP_PANEL_SIZE = 10;

  function topValueFor(f: FileInfo): number {
    if (topPanelScope === 'session') {
      return topPanelMetric === 'bytes' ? f.bytes_transferred : f.accepted;
    }
    return topPanelMetric === 'bytes' ? f.alltime_transferred : f.alltime_accepted;
  }

  let topFiles = $derived.by(() => {
    return [...files]
      .filter((f) => f.hash && topValueFor(f) > 0)
      .sort((a, b) => topValueFor(b) - topValueFor(a))
      .slice(0, TOP_PANEL_SIZE);
  });
  let topMaxValue = $derived(topFiles.length === 0 ? 0 : topValueFor(topFiles[0]));
  function selectAndRevealFile(path: string) {
    selectedPath = path;
    clearLibraryFilters();
  }

  // --- File type display ---
  const audioExts = new Set([
    'aac','ac3','aif','aifc','aiff','amr','ape','au','aud','audio','cda',
    'dmf','dsm','dts','far','flac','it','m1a','m2a','m4a','mdl','med',
    'mid','midi','mka','mod','mp1','mp2','mp3','mpa','mpc','mtm','ogg',
    'opus','psm','ptm','ra','rmi','s3m','snd','stm','umx','wav','wma','xm',
  ]);
  const videoExts = new Set([
    '3g2','3gp','3gp2','3gpp','amv','asf','avi','bik','divx','dvr-ms',
    'flc','fli','flic','flv','hdmov','ifo','m1v','m2t','m2ts','m2v',
    'm4b','m4v','mkv','mov','movie','mp1v','mp2v','mp4','mpe','mpeg',
    'mpg','mpv','mpv1','mpv2','ogm','pva','qt','ram','ratdvd','rm',
    'rmm','rmvb','rv','smil','smk','swf','tp','ts','vid','video','vob',
    'vp6','webm','wm','wmv','xvid',
  ]);
  const imageExts = new Set([
    'bmp','emf','gif','ico','jfif','jpe','jpeg','jpg','pct','pcx','pic',
    'pict','png','psd','psp','svg','tga','tif','tiff','webp','wmf','wmp','xif',
  ]);
  const archiveExts = new Set([
    '7z','ace','alz','arc','arj','bz2','cab','cbr','cbz','gz','hqx',
    'lha','lzh','msi','pak','par','par2','rar','sit','sitx','tar',
    'tbz2','tgz','xpi','xz','z','zip',
  ]);
  const docExts = new Set([
    'chm','css','diz','doc','docx','dot','djvu','epub','hlp','htm',
    'html','lit','mobi','azw','nfo','ods','odt','odp','pdf','pps',
    'ppt','pptx','ps','rtf','text','txt','wri','xls','xlsx','xml',
  ]);
  const isoExts = new Set([
    'bin','bwa','bwi','bws','bwt','ccd','cue','dmg','img','iso',
    'mdf','mds','nrg','sub','toast',
  ]);
  function fileType(ext: string): string {
    const lower = ext.toLowerCase();
    if (audioExts.has(lower)) return m.library_type_audio();
    if (videoExts.has(lower)) return m.library_type_video();
    if (imageExts.has(lower)) return m.library_type_image();
    if (archiveExts.has(lower)) return m.library_type_archive();
    if (docExts.has(lower)) return m.library_type_document();
    if (isoExts.has(lower)) return m.library_type_cd_dvd();
    return ext ? ext.toUpperCase() : '\u2014';
  }

  // Stable, locale-independent category key used by the type filter. The
  // `typeFilter` state holds the English option *values* ('Audio', 'Video',
  // ...), so the filter must compare against these keys rather than against
  // `fileType()`, whose return value is translated (e.g. 'Vídeo' in Spanish)
  // and would never match the stored value in non-English locales.
  function fileTypeKey(ext: string): TypeFilter | '' {
    const lower = ext.toLowerCase();
    if (audioExts.has(lower)) return 'Audio';
    if (videoExts.has(lower)) return 'Video';
    if (imageExts.has(lower)) return 'Image';
    if (archiveExts.has(lower)) return 'Archive';
    if (docExts.has(lower)) return 'Document';
    if (isoExts.has(lower)) return 'CD/DVD';
    return '';
  }

  function formatTransferred(session: number, alltime: number): string {
    if (session === 0 && alltime === 0) return '\u2014';
    const s = session > 0 ? formatSize(session) : '0';
    if (alltime > 0 && alltime !== session) return `${s} (${formatSize(alltime)})`;
    return s;
  }

  function priorityLabel(p: string): string {
    switch (p) {
      case 'verylow': return m.library_priority_verylow();
      case 'low': return m.library_priority_low();
      case 'normal': return m.library_priority_normal();
      case 'high': return m.library_priority_high();
      case 'release': return m.library_priority_release();
      case 'auto': return m.library_priority_auto();
      default: return p;
    }
  }

  // --- Comments ---
  // Selecting rows rapidly (e.g. arrow-keying through 50 files) would otherwise
  // fire a getFileComments RPC per row. Debounce so we only hit the backend
  // once the selection has settled for ~200ms.
  let commentFetchTimer: ReturnType<typeof setTimeout> | null = null;
  $effect(() => {
    const hash = selectedHash;
    commentSaveState = 'idle';
    commentSaveMessage = '';
    // Reset the bound editor fields IMMEDIATELY on selection change so the
    // textarea never shows — or, on Save/Ctrl+Enter, persists — the PREVIOUS
    // file's comment during the debounced fetch window below. Without this,
    // saving right after switching files wrote file A's text onto file B.
    // `commentLoading` gates handleSaveComment so this reset can't wipe the
    // new file's stored comment with an empty save before the fetch lands.
    ourComment = '';
    ourRating = 0;
    if (commentSaveTimer) {
      clearTimeout(commentSaveTimer);
      commentSaveTimer = null;
    }
    if (commentFetchTimer) {
      clearTimeout(commentFetchTimer);
      commentFetchTimer = null;
    }
    if (!hash) {
      commentInfo = null;
      commentLoading = false;
      commentLastSavedAt = null;
      return;
    }
    commentLoading = true;
    commentFetchTimer = setTimeout(() => {
      commentFetchTimer = null;
      if (selectedHash !== hash) return;
      getFileComments(hash).then((info) => {
        if (selectedHash !== hash) return;
        commentInfo = info;
        ourRating = info?.our_rating ?? 0;
        ourComment = info?.our_comment ?? '';
        commentLoading = false;
      }).catch(() => {
        if (selectedHash !== hash) return;
        commentInfo = null;
        commentLoading = false;
      });
    }, 200);
    return () => {
      if (commentFetchTimer) {
        clearTimeout(commentFetchTimer);
        commentFetchTimer = null;
      }
    };
  });

  // Lazily probe media metadata (duration/bitrate/codec/tags) for the selected
  // file. Keyed on path (not hash) so it works before hashing completes.
  let mediaFetchTimer: ReturnType<typeof setTimeout> | null = null;
  $effect(() => {
    const path = selectedPath;
    if (mediaFetchTimer) {
      clearTimeout(mediaFetchTimer);
      mediaFetchTimer = null;
    }
    selectedMedia = null;
    if (!path) return;
    mediaFetchTimer = setTimeout(() => {
      mediaFetchTimer = null;
      if (selectedPath !== path) return;
      getFileMediaMetadata(path).then((media) => {
        if (selectedPath !== path) return;
        selectedMedia = media;
      }).catch(() => {
        if (selectedPath !== path) return;
        selectedMedia = null;
      });
    }, 200);
    return () => {
      if (mediaFetchTimer) {
        clearTimeout(mediaFetchTimer);
        mediaFetchTimer = null;
      }
    };
  });

  function formatMediaLength(seconds: number): string {
    const s = Math.max(0, Math.floor(seconds));
    const h = Math.floor(s / 3600);
    const m2 = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return h > 0
      ? `${h}:${String(m2).padStart(2, '0')}:${String(sec).padStart(2, '0')}`
      : `${m2}:${String(sec).padStart(2, '0')}`;
  }

  async function handleSaveComment() {
    const hash = selectedHash;
    if (!hash) return;
    // The editor fields are reset on selection change and only repopulated
    // once the debounced fetch for THIS hash lands. Refuse to save until then,
    // otherwise we'd persist empty/stale fields over the file's real comment.
    if (commentLoading) return;
    commentSaveState = 'saving';
    commentSaveMessage = m.library_saving();
    try {
      await setFileComment(hash, ourRating, ourComment);
      const info = await getFileComments(hash);
      if (selectedHash !== hash) return;
      commentInfo = info;
      commentSaveState = 'saved';
      commentSaveMessage = m.library_saved();
      commentLastSavedAt = Date.now();
      if (commentSaveTimer) clearTimeout(commentSaveTimer);
      commentSaveTimer = setTimeout(() => {
        commentSaveState = 'idle';
        commentSaveMessage = '';
      }, 2500);
    } catch (e: unknown) {
      if (selectedHash !== hash) return;
      error = toErr(e);
      commentSaveState = 'error';
      commentSaveMessage = m.library_save_failed();
    }
  }

  // --- Context menu ---
  let ctxMenu: { x: number; y: number; file: FileInfo } | null = $state(null);
  let ctxPrioritySub = $state(false);
  let ctxCopySub = $state(false);
  let ctxMenuEl: HTMLDivElement | undefined = $state(undefined);
  let ctxSubmenuLeft = $state(false);
  let ctxSubmenuUp = $state(false);

  async function positionCtxMenu() {
    if (!ctxMenu) return;
    await tick();
    if (!ctxMenu || !ctxMenuEl) return;
    const margin = 8;
    // Use offsetWidth/offsetHeight (untransformed layout size) rather than
    // getBoundingClientRect(), whose width/height reflect the entrance scale
    // animation mid-flight and would clamp the menu a few px off near edges.
    const menuW = ctxMenuEl.offsetWidth;
    const menuH = ctxMenuEl.offsetHeight;
    const x = Math.min(ctxMenu.x, Math.max(margin, window.innerWidth - menuW - margin));
    const y = Math.min(ctxMenu.y, Math.max(margin, window.innerHeight - menuH - margin));
    ctxSubmenuLeft = x + menuW * 2 > window.innerWidth - margin;
    ctxSubmenuUp = y + 240 > window.innerHeight - margin;
    if (x !== ctxMenu.x || y !== ctxMenu.y) {
      ctxMenu = { ...ctxMenu, x, y };
    }
  }

  function onCtx(e: MouseEvent, f: FileInfo) {
    e.preventDefault();
    ctxPrioritySub = false;
    ctxCopySub = false;
    ctxMenu = { x: e.clientX, y: e.clientY, file: f };
    selectedPath = f.path;
    void positionCtxMenu();
  }
  function closeCtx() {
    ctxMenu = null;
    ctxPrioritySub = false;
    ctxCopySub = false;
    ctxSubmenuLeft = false;
    ctxSubmenuUp = false;
  }
  function onDocClick() { if (mounted) closeCtx(); }

  function isTypingTarget(el: EventTarget | null): boolean {
    if (!(el instanceof HTMLElement)) return false;
    if (el.isContentEditable) return true;
    const tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
  }

  async function deleteSelectedFile() {
    const f = selectedFile;
    if (!f) return;
    try {
      const { confirm } = await import('@tauri-apps/plugin-dialog');
      const confirmed = await confirm(
        m.library_confirm_delete_single({ name: f.name }),
        { title: m.library_delete_file_title(), kind: 'warning' }
      );
      if (!confirmed) return;
      await deleteSharedFile(f.path, f.hash || undefined);
      if (selectedPath === f.path) selectedPath = null;
      toastSuccess(m.library_deleted_named({ name: f.name }));
      await refresh();
    } catch (e: unknown) { error = toErr(e); }
  }

  async function copyLinkForSelection() {
    const targets = checkedCount > 0
      ? getCheckedFiles().filter(f => !!f.hash)
      : (selectedFile && selectedFile.hash ? [selectedFile] : []);
    if (targets.length === 0) return;
    try {
      const links = await Promise.all(targets.map(f => formatEd2kLink(f.name, f.size, f.hash)));
      await navigator.clipboard.writeText(links.join('\n'));
      const unsharedCount = targets.filter(f => !f.shared).length;
      if (unsharedCount > 0) {
        toastWarning(m.library_copied_with_unshared({
          links: links.length,
          link_label: links.length === 1 ? m.library_link_singular() : m.library_link_plural(),
          unshared: unsharedCount,
          unshared_label: unsharedCount === 1 ? m.library_file_is_unshared() : m.library_files_are_unshared(),
        }));
      } else {
        toastSuccess(links.length === 1 ? m.library_copied_link_one() : m.library_copied_links_other({ count: links.length }));
      }
    } catch (e: unknown) { error = toErr(e); }
  }

  function onPageKeyDown(e: KeyboardEvent) {
    if (!mounted) return;
    if (ctxMenu && e.key === 'Escape') { closeCtx(); e.preventDefault(); return; }

    const typing = isTypingTarget(e.target);

    // "/" focuses the search input when not already typing.
    if (!typing && e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault();
      searchInputEl?.focus();
      searchInputEl?.select();
      return;
    }

    // Escape clears the search if it's focused and has content; otherwise clears selection.
    if (e.key === 'Escape') {
      if (typing && e.target === searchInputEl && searchQuery) {
        searchQuery = '';
        e.preventDefault();
        return;
      }
      if (!typing && selectedPath) {
        selectedPath = null;
        e.preventDefault();
        return;
      }
    }

    if (typing) return;

    // Ignore shortcuts while a modal is open.
    if (createCollectionOpen) return;

    // Ctrl/Cmd+A selects all visible.
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && (e.key === 'a' || e.key === 'A')) {
      if (sortedFiles.length === 0) return;
      e.preventDefault();
      checkedPaths = new Set(sortedFiles.map(f => f.path));
      lastClickedPath = null;
      return;
    }

    // Ctrl/Cmd+D clears the check selection.
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && (e.key === 'd' || e.key === 'D')) {
      if (checkedPaths.size === 0) return;
      e.preventDefault();
      clearChecked();
      return;
    }

    // Ctrl/Cmd+C copies links for the current check selection or selected row.
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && (e.key === 'c' || e.key === 'C')) {
      const hasTargets = checkedCount > 0 || (selectedFile && !!selectedFile.hash);
      if (!hasTargets) return;
      e.preventDefault();
      void copyLinkForSelection();
      return;
    }

    // Enter on the selected row opens the file.
    if (e.key === 'Enter' && selectedFile) {
      e.preventDefault();
      void openSharedFile(selectedFile.path);
      return;
    }

    // Delete prefers the checkbox selection when one exists; otherwise it
    // falls back to the single row that was last clicked. This prevents a
    // surprising "deleted only one of my 200 selected files" scenario.
    if (e.key === 'Delete') {
      if (checkedCount > 0) {
        e.preventDefault();
        void bulkDelete();
        return;
      }
      if (selectedFile) {
        e.preventDefault();
        void deleteSelectedFile();
        return;
      }
    }

    // Space toggles the check on the selected row.
    if (e.key === ' ' && selectedFile) {
      e.preventDefault();
      toggleCheck(selectedFile.path, false);
      return;
    }

    // Arrow-key navigation: move `selectedPath` through `sortedFiles`
    // and ask the virtual table to scroll the new row into view (the
    // table is virtualized, so the row may not be in the DOM yet).
    // Home / End jump to the boundaries; Shift+Arrow extends the
    // checkbox selection along the way (useful for keyboard-driven
    // bulk actions). PageUp/PageDown move ten rows for big lists.
    if (sortedFiles.length > 0 && (
      e.key === 'ArrowDown' || e.key === 'ArrowUp' ||
      e.key === 'Home' || e.key === 'End' ||
      e.key === 'PageDown' || e.key === 'PageUp'
    )) {
      const currentIdx = selectedPath
        ? sortedFiles.findIndex(f => f.path === selectedPath)
        : -1;
      let nextIdx = currentIdx;
      if (e.key === 'ArrowDown') nextIdx = currentIdx < 0 ? 0 : Math.min(sortedFiles.length - 1, currentIdx + 1);
      else if (e.key === 'ArrowUp') nextIdx = currentIdx <= 0 ? 0 : currentIdx - 1;
      else if (e.key === 'Home') nextIdx = 0;
      else if (e.key === 'End') nextIdx = sortedFiles.length - 1;
      else if (e.key === 'PageDown') nextIdx = currentIdx < 0 ? 0 : Math.min(sortedFiles.length - 1, currentIdx + 10);
      else if (e.key === 'PageUp') nextIdx = currentIdx <= 0 ? 0 : Math.max(0, currentIdx - 10);
      if (nextIdx !== currentIdx && nextIdx >= 0) {
        e.preventDefault();
        const next = sortedFiles[nextIdx];
        selectedPath = next.path;
        if (e.shiftKey) {
          // Extending selection — toggle along the path the way the
          // mouse Shift+click code does, but row-by-row.
          toggleCheck(next.path, false);
        }
        libraryTableRef?.scrollRowIntoView(nextIdx);
      }
      return;
    }
  }

  async function ctxAction(action: string, extra?: string) {
    if (!ctxMenu) return;
    const f = ctxMenu.file;
    closeCtx();
    try {
      switch (action) {
        case 'open_file': await openSharedFile(f.path); break;
        case 'open_folder': await openSharedFolder(f.path); break;
        case 'delete': {
          const { confirm } = await import('@tauri-apps/plugin-dialog');
          const confirmed = await confirm(
            m.library_confirm_delete_single({ name: f.name }),
            { title: m.library_delete_file_title(), kind: 'warning' }
          );
          if (!confirmed) break;
          await deleteSharedFile(f.path, f.hash || undefined);
          if (selectedPath === f.path) selectedPath = null;
          toastSuccess(m.library_deleted_named({ name: f.name }));
          await refresh();
          break;
        }
        case 'priority': if (extra) { await setFilePriority(f.path, extra as 'verylow' | 'low' | 'normal' | 'high' | 'release' | 'auto'); await refresh(); } break;
        case 'copy_link': {
          let link: string;
          if (extra === 'aich') {
            link = await buildEd2kLink(f.name, f.size, f.hash, { aichHash: f.aich_hash || undefined });
          } else if (extra === 'sources') {
            link = await buildEd2kLink(f.name, f.size, f.hash, { withSources: true });
          } else {
            link = await formatEd2kLink(f.name, f.size, f.hash);
          }
          await navigator.clipboard.writeText(link);
          if (!f.shared) {
            toastWarning(m.library_copied_link_unshared_single());
          } else if (extra === 'aich') {
            toastSuccess(m.library_copied_ed2k_link_aich());
          } else if (extra === 'sources') {
            toastSuccess(m.library_copied_ed2k_link_sources());
          } else {
            toastSuccess(m.library_copied_ed2k_link());
          }
          break;
        }
        case 'unshare': await unshareFile(f.path, f.hash || undefined); await refresh(); break;
        case 'share': await shareFile(f.path); await refresh(); break;
        case 'republish': {
          if (!f.hash || !f.shared) break;
          await republishFile(f.hash);
          if ($networkStats.status === 'connected') {
            toastSuccess(m.library_queued_republish_kad());
          } else {
            toastWarning(m.library_kad_not_connected_republish());
          }
          break;
        }
      }
    } catch (e: unknown) { error = toErr(e); }
  }

  async function handleUnshareFolder(path: string) {
    try {
      const { confirm } = await import('@tauri-apps/plugin-dialog');
      const displayName = path.split(/[\\/]/).filter(Boolean).pop() || path;
      const sharedCount = files.filter((f) => f.shared && isPathInFolder(f.path, path)).length;
      if (sharedCount === 0) {
        toastWarning(m.library_no_shared_files_in({ name: displayName }));
        return;
      }
      const confirmed = await confirm(
        sharedCount === 1
          ? m.library_confirm_unshare_folder_one({ name: displayName })
          : m.library_confirm_unshare_folder_other({ count: sharedCount.toLocaleString(), name: displayName }),
        { title: m.library_unshare_folder_title(), kind: 'warning' }
      );
      if (!confirmed) return;
      await unshareFolder(path);
      await refresh();
    } catch (e: unknown) { error = toErr(e); }
  }

  function formatSavedTime(ts: number | null): string {
    if (!ts) return '';
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  // --- Persisted filters / sort ---
  const FILTERS_KEY = 'library-filters-v1';
  const VALID_TYPE_FILTERS = new Set(typeFilterOptions);
  const VALID_SORT_FIELDS: Set<SortField> = new Set([
    'name', 'size', 'extension', 'priority', 'hash', 'requests', 'accepted',
    'bytes_transferred', 'folder', 'complete_sources', 'modified_at',
  ]);
  let filtersRestored = $state(false);

  function loadPersistedFilters() {
    try {
      const raw = localStorage.getItem(FILTERS_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        if (typeof parsed.typeFilter === 'string' && VALID_TYPE_FILTERS.has(parsed.typeFilter as TypeFilter)) {
          typeFilter = parsed.typeFilter as TypeFilter;
        }
        if (typeof parsed.filterFolder === 'string' && parsed.filterFolder.length > 0) {
          filterFolder = parsed.filterFolder;
        } else if (parsed.filterFolder === null) {
          filterFolder = null;
        }
        if (typeof parsed.searchQuery === 'string' && parsed.searchQuery.length <= 500) {
          searchQuery = parsed.searchQuery;
        }
        if (typeof parsed.sortField === 'string' && VALID_SORT_FIELDS.has(parsed.sortField as SortField)) {
          sortField = parsed.sortField as SortField;
        }
        if (typeof parsed.sortAsc === 'boolean') {
          sortAsc = parsed.sortAsc;
        }
        if (typeof parsed.showDuplicatesOnly === 'boolean') {
          showDuplicatesOnly = parsed.showDuplicatesOnly;
        }
        // Restore "missing only" only if the user actually has missing
        // files; otherwise the toggle would re-enable a filter that
        // immediately matches zero rows. The clearing in the onMount
        // effect (~line 221) handles the case where missing files
        // disappear later in the session.
        if (parsed.showMissingOnly === true) {
          // Defer until the first missing-file scan (see
          // pendingRestoreMissingOnly) so we don't blank the library by
          // filtering against an empty missing set on load.
          pendingRestoreMissingOnly = true;
        }
        if (typeof parsed.topPanelOpen === 'boolean') {
          topPanelOpen = parsed.topPanelOpen;
        }
        if (parsed.topPanelMetric === 'bytes' || parsed.topPanelMetric === 'requests') {
          topPanelMetric = parsed.topPanelMetric;
        }
        if (parsed.topPanelScope === 'session' || parsed.topPanelScope === 'alltime') {
          topPanelScope = parsed.topPanelScope;
        }
      }
    } catch {
      try { localStorage.removeItem(FILTERS_KEY); } catch {}
    }
  }

  function persistFilters() {
    try {
      localStorage.setItem(FILTERS_KEY, JSON.stringify({
        typeFilter,
        filterFolder,
        searchQuery,
        sortField,
        sortAsc,
        showDuplicatesOnly,
        showMissingOnly,
        topPanelOpen,
        topPanelMetric,
        topPanelScope,
      }));
    } catch {}
  }

  $effect(() => {
    if (!filtersRestored) return;
    // Track dependencies explicitly so this effect re-runs when any filter/sort changes.
    void typeFilter; void filterFolder; void searchQuery; void sortField; void sortAsc; void showDuplicatesOnly; void showMissingOnly;
    void topPanelOpen; void topPanelMetric; void topPanelScope;
    persistFilters();
  });

  // If the persisted folder no longer exists after folders load, clear it silently.
  $effect(() => {
    if (!filtersRestored) return;
    if (filterFolder && folders.length > 0 && !folders.includes(filterFolder)) {
      filterFolder = null;
    }
  });

  // --- Sidebar resize ---
  let sidebarWidth = $state(200);
  let sidebarDragging = $state(false);
  let dragCleanup: (() => void) | null = null;

  function onSidebarDown(e: MouseEvent) {
    e.preventDefault();
    sidebarDragging = true;
    const container = (e.target as HTMLElement).closest('.shared-layout');
    const containerLeft = container ? container.getBoundingClientRect().left : 0;
    const onMove = (ev: MouseEvent) => {
      if (!mounted) return;
      sidebarWidth = Math.max(120, Math.min(400, ev.clientX - containerLeft));
    };
    const onUp = () => {
      if (mounted) sidebarDragging = false;
      // Remove listeners first so a localStorage failure (private mode /
      // quota) can't strand the drag handlers and leave the page stuck.
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      dragCleanup = null;
      try {
        localStorage.setItem('library-sidebar-w', String(sidebarWidth));
      } catch (e) {
        console.warn('library: failed to persist sidebar width', e);
      }
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    dragCleanup = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }

  let dndActive = $state(false);
  let dndHover = $state(false);

  async function handleOsFolderDrop(paths: string[]) {
    const uniquePaths = [...new Set(paths.filter((p) => typeof p === 'string' && p.length > 0))];
    if (uniquePaths.length === 0) return;

    // Backend `add_shared_folder` will reject non-directories and already-shared paths.
    // We let it arbitrate and surface per-path errors here.
    let added = 0;
    const failures: string[] = [];
    for (const path of uniquePaths) {
      try {
        await addSharedFolder(path);
        added++;
      } catch (e: unknown) {
        failures.push(`${path}: ${toErr(e)}`);
      }
    }
    if (added > 0) {
      stoppedByUser = false;
      scanning = true;
      const base = added === 1 ? m.library_added_folder_one() : m.library_added_folder_other({ count: added });
      toastSuccess(failures.length ? m.library_added_with_skipped({ base, skipped: failures.length }) : base);
      if (mounted) await refresh();
    } else if (failures.length > 0) {
      toastWarning(failures[0]);
    }
  }

  // A collection opened from the OS (double-clicked .emulecollection) is
  // parsed by the deep-link handler, which stashes it in `incomingCollection`
  // and routes us to this page. Consume it via an effect rather than only in
  // onMount: when we are ALREADY on /library, navigating to the current route
  // does not remount the component, so onMount would never fire again and the
  // collection would be dropped. The effect runs on mount and on every later
  // set, then clears the store so a future navigation doesn't re-open a stale
  // collection. Resetting the store re-runs the effect with `null`, which is a
  // no-op (no infinite loop).
  $effect(() => {
    const incoming = $incomingCollection;
    if (incoming) {
      loadedCollection = incoming;
      collectionsOpen = true;
      incomingCollection.set(null);
    }
  });

  onMount(() => {
    mounted = true;
    // localStorage can throw in private mode / quota-exceeded; wrap
    // the read so a storage failure doesn't abort onMount and leave
    // the library page without its event listeners attached.
    try {
      const saved = localStorage.getItem('library-sidebar-w');
      if (saved) {
        const val = parseInt(saved, 10);
        if (!isNaN(val)) sidebarWidth = Math.max(120, Math.min(400, val));
      }
    } catch (e) {
      console.warn('library: localStorage unavailable for sidebar width', e);
    }

    loadPersistedFilters();
    filtersRestored = true;

    refresh();

    // Poll every 3s: detect scan completion and refresh data while scanning.
    // The poll never INITIATES the scanning UI state -- only progress events do that.
    // This prevents the banner from reappearing after Stop or page re-navigation.
    const scanPoll = setInterval(async () => {
      if (!mounted || stoppedByUser) return;
      try {
        const isScanning = await getScanStatus();
        if (!mounted) return;
        if (scanning && !isScanning) {
          scanning = false;
          hashProgress = null;
          await refresh();
        } else if (scanning && isScanning) {
          await refresh();
        }
      } catch {}
    }, 3000);

    const unlisteners: Array<() => void> = [];
    let destroyed = false;

    // Sequential listen + rollback on partial failure. Earlier this
    // used `Promise.all([listen, listen])`, but if the second listen
    // rejected the first one's unlisten function was lost — leaving an
    // orphan subscription registered for the rest of the webview's
    // lifetime. Awaiting them one at a time means we always have a
    // handle to anything that successfully registered, and a thrown
    // error just unregisters whatever has already attached.
    (async () => {
      let u1: (() => void) | null = null;
      let u2: (() => void) | null = null;
      try {
        u1 = await listen<{ phase: string; count: number }>(
          'shared-files-changed', () => { if (mounted) debouncedRefresh(); }
        );
        if (destroyed) { u1(); return; }
        u2 = await listen<{ current: number; total: number; file_name: string; done?: boolean }>(
          'file-hash-progress', (event) => {
            if (!mounted || stoppedByUser) return;
            if (event.payload.done) {
              hashProgress = null;
              scanning = false;
              refresh();
            } else {
              hashProgress = {
                current: event.payload.current,
                total: event.payload.total,
                file_name: event.payload.file_name,
              };
              scanning = true;
            }
          }
        );
        if (destroyed) { u1(); u2(); return; }
        unlisteners.push(u1, u2);
      } catch (e) {
        console.warn('library: failed to register file-system event listeners', e);
        if (u1) u1();
        if (u2) u2();
      }
    })();

    (async () => {
      try {
        const { getCurrentWebview } = await import('@tauri-apps/api/webview');
        const u = await getCurrentWebview().onDragDropEvent((event) => {
          if (!mounted) return;
          const t = event.payload.type;
          // Only surface the overlay when the drag actually carries OS paths.
          // Tauri fires enter/over for in-app drags (e.g. column reorders, text
          // selections) too, which would otherwise flash the overlay.
          const paths = (event.payload as { paths?: string[] }).paths ?? [];
          const hasPaths = paths.length > 0;
          if (t === 'enter' || t === 'over') {
            if (!hasPaths) return;
            dndActive = true;
            dndHover = t === 'over';
          } else if (t === 'leave') {
            dndActive = false;
            dndHover = false;
          } else if (t === 'drop') {
            dndActive = false;
            dndHover = false;
            if (hasPaths) void handleOsFolderDrop(paths);
          }
        });
        if (destroyed) u(); else unlisteners.push(u);
      } catch (e) {
        console.warn('Drag-drop listener unavailable:', e);
      }
    })();

    return () => {
      mounted = false;
      destroyed = true;
      clearInterval(scanPoll);
      if (refreshTimer) { clearTimeout(refreshTimer); refreshTimer = null; }
      if (searchDebounceTimer) { clearTimeout(searchDebounceTimer); searchDebounceTimer = null; }
      if (commentSaveTimer) {
        clearTimeout(commentSaveTimer);
        commentSaveTimer = null;
      }
      if (commentFetchTimer) {
        clearTimeout(commentFetchTimer);
        commentFetchTimer = null;
      }
      dragCleanup?.();
      for (const u of unlisteners) u();
    };
  });
</script>

<svelte:document onclick={onDocClick} onkeydown={onPageKeyDown} />

<div class="page-header">
  <h2>{m.library_title()}</h2>
  <div class="header-actions">
    <button class="ghost" onclick={handleOpenCollection} disabled={collectionLoading}>
      {#if collectionLoading}
        <span class="spinner-inline" aria-hidden="true"></span> {m.library_opening()}
      {:else}
        {m.library_open_collection()}
      {/if}
    </button>
    <button class="ghost" onclick={() => openCreateDialog()}>{m.library_create_collection()}</button>
    <button onclick={handleReload}>{m.library_reload()}</button>
    <button onclick={handleAddFolder}>{m.library_add_folder()}</button>
  </div>
</div>

<div class="filter-bar">
  <div class="library-filter-row">
    <div class="filter-search-wrap">
      <span class="filter-search-icon">
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
          <circle cx="8.5" cy="8.5" r="5.5"/><line x1="12.5" y1="12.5" x2="17" y2="17"/>
        </svg>
      </span>
      <input
        type="text"
        class="filter-search"
        placeholder={m.library_search_placeholder()}
        bind:value={searchQuery}
        bind:this={searchInputEl}
      />
      {#if searchQuery}
        <button class="filter-clear-btn" onclick={() => (searchQuery = '')} title={m.search_bar_clear()}>✕</button>
      {/if}
    </div>
    <select class="filter-type" bind:value={typeFilter}>
      {#each typeFilterOptions as opt}
        <option value={opt}>{opt === 'All' ? m.library_all_types() : (
          opt === 'Audio' ? m.library_type_audio() :
          opt === 'Video' ? m.library_type_video() :
          opt === 'Image' ? m.library_type_image() :
          opt === 'Archive' ? m.library_type_archive() :
          opt === 'Document' ? m.library_type_document() :
          opt === 'CD/DVD' ? m.library_type_cd_dvd() : opt
        )}</option>
      {/each}
    </select>
    <button
      class="dupes-toggle"
      class:active={showDuplicatesOnly}
      disabled={duplicateHashes.size === 0}
      onclick={() => (showDuplicatesOnly = !showDuplicatesOnly)}
      title={duplicateHashes.size === 0 ? m.library_no_duplicates() : m.library_duplicates_tooltip({ files: duplicateFileCount, hashes: duplicateHashes.size })}
    >
      {m.library_duplicates()}{duplicateHashes.size > 0 ? ` (${duplicateFileCount})` : ''}
    </button>
    <button
      class="dupes-toggle missing-toggle"
      class:active={showMissingOnly}
      disabled={missingPathSet.size === 0}
      onclick={() => (showMissingOnly = !showMissingOnly)}
      title={missingPathSet.size === 0 ? m.library_no_missing() : m.library_missing_tooltip({ count: missingPathSet.size })}
    >
      {m.library_missing()}{missingPathSet.size > 0 ? ` (${missingPathSet.size})` : ''}
    </button>
    {#if showMissingOnly && missingPathSet.size > 0}
      <button
        class="dupes-toggle missing-remove-btn"
        onclick={handleRemoveMissing}
        title={m.library_remove_missing_tooltip()}
      >{m.library_remove_missing()}</button>
    {/if}
    {#if hasActiveLibraryFilters}
      <button class="ghost clear-library-filters" onclick={clearLibraryFilters}>{m.library_clear_filters()}</button>
    {/if}
    <span class="inline-stats">
      <span class="inline-stat">{m.library_stat_files({ count: files.length.toLocaleString() })}</span>
      <span class="inline-sep">&middot;</span>
      <span class="inline-stat">{m.library_stat_shared({ count: libraryFileStats.shared.toLocaleString() })}</span>
      <span class="inline-sep">&middot;</span>
      <span class="inline-stat">{m.library_stat_hashed({ count: libraryFileStats.hashed.toLocaleString() })}</span>
      <span class="inline-sep">&middot;</span>
      <span class="inline-stat">{m.library_stat_folders({ count: folders.length.toLocaleString() })}</span>
    </span>
  </div>
</div>

{#if loadedCollection || collectionLoading}
  <div class="collection-section">
    <div class="collection-toggle-bar">
      <button class="collection-toggle" onclick={() => collectionsOpen = !collectionsOpen}>
        <span class="toggle-arrow">{collectionsOpen ? '\u25BC' : '\u25B6'}</span>
        <span class="collection-title">
          {m.library_collection_label({ name: loadedCollection?.name ?? m.library_loading_ellipsis() })}
          {#if loadedCollection}
            <span class="collection-meta">
              {loadedCollection.files.length === 1
                ? m.library_collection_meta_one({ author: loadedCollection.author || m.common_unknown() })
                : m.library_collection_meta_other({ author: loadedCollection.author || m.common_unknown(), count: loadedCollection.files.length })}
            </span>
          {/if}
        </span>
      </button>
      {#if loadedCollection}
        <button class="coll-action-btn download-all-btn" onclick={handleDownloadAll} disabled={downloadingCollection}>
          {downloadingCollection ? m.library_queueing() : m.library_download_all()}
        </button>
        <button class="coll-action-btn ghost" onclick={handleCopyCollectionLinks} disabled={copyingCollectionLinks || loadedCollection.files.length === 0} title={m.library_copy_all_links_title()}>
          {copyingCollectionLinks ? m.library_copying() : m.library_copy_links()}
        </button>
        <button class="coll-action-btn ghost" onclick={() => { loadedCollection = null; collectionsOpen = false; }}>{m.common_close()}</button>
      {/if}
    </div>
    {#if collectionsOpen}
      <div class="collection-files">
        {#if collectionLoading}
          <div class="coll-loading"><span class="scan-spinner"></span> {m.library_loading_collection()}</div>
        {:else if loadedCollection}
          <table class="compact-table coll-table">
            <thead>
              <tr>
                <th>{m.library_col_filename()}</th>
                <th class="coll-col-size">{m.library_col_size()}</th>
                <th class="coll-col-hash">{m.library_col_hash()}</th>
              </tr>
            </thead>
            <tbody>
              {#each loadedCollection.files as cf (cf.hash)}
                <tr>
                  <td title={cf.name}>{cf.name}</td>
                  <td class="coll-col-size">{formatSize(cf.size)}</td>
                  <td class="coll-col-hash" title={cf.hash}>{cf.hash.substring(0, 16)}&hellip;</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    {/if}
  </div>
{/if}

{#if createCollectionOpen}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="modal-overlay" role="dialog" aria-modal="true" tabindex="-1" onkeydown={(e) => {
    if (e.key === 'Escape') { createCollectionOpen = false; return; }
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      if (!!newCollName.trim() && selectedFileHashes.size > 0 && !creatingCollection) {
        e.preventDefault();
        void handleCreateCollection();
      }
    }
  }}>
    <div class="modal-content create-coll-modal">
      <div class="modal-header">
        <span class="modal-title">{m.library_create_collection()}</span>
        <button class="ghost modal-close" onclick={() => createCollectionOpen = false} aria-label={m.common_close()}><IconX size={15} /></button>
      </div>
      <div class="modal-body">
        <div class="form-row">
          <label class="form-label" for="coll-name">{m.library_coll_name()}</label>
          <input
            id="coll-name"
            type="text"
            class="form-input"
            bind:value={newCollName}
            placeholder={m.library_coll_name_placeholder()}
            onkeydown={(e) => {
              if (e.key === 'Enter' && !!newCollName.trim() && selectedFileHashes.size > 0 && !creatingCollection) {
                e.preventDefault();
                void handleCreateCollection();
              }
            }}
          />
        </div>
        <div class="form-row">
          <label class="form-label" for="coll-author">{m.library_coll_author()}</label>
          <input id="coll-author" type="text" class="form-input" bind:value={newCollAuthor} placeholder={m.library_coll_optional()} />
        </div>
        <div class="form-row">
          <span class="form-label">{m.library_coll_format()}</span>
          <div class="format-toggle">
            <label class="format-option">
              <input type="radio" name="coll-format" value="binary" bind:group={newCollFormat} />
              <span class="format-label">
                <span class="format-name">{m.library_coll_format_binary_name()}</span>
                <span class="format-desc">{m.library_coll_format_binary_desc()}</span>
              </span>
            </label>
            <label class="format-option">
              <input type="radio" name="coll-format" value="text" bind:group={newCollFormat} />
              <span class="format-label">
                <span class="format-name">{m.library_coll_format_text_name()}</span>
                <span class="format-desc">{m.library_coll_format_text_desc()}</span>
              </span>
            </label>
          </div>
        </div>
        <div class="form-row">
          <span class="form-label">{m.library_coll_select_files({ selected: selectedFileHashes.size, total: hashedLibraryFiles.length })}</span>
          <button class="ghost select-all-btn" onclick={toggleAllFileSelection}>
            {allHashedFilesSelected ? m.common_deselect_all() : m.common_select_all()}
          </button>
        </div>
        <div class="coll-search-row">
          <input
            type="text"
            class="form-input coll-search-input"
            placeholder={m.library_coll_search_placeholder()}
            bind:value={collectionSearch}
          />
        </div>
        <div class="coll-file-picker">
          {#each displayedCollectionFiles as f (f.path)}
            <label class="coll-pick-row">
              <input type="checkbox" checked={selectedFileHashes.has(f.hash)} onchange={() => toggleFileSelection(f.hash)} />
              <span class="coll-pick-name" title={f.name}>{f.name}</span>
              <span class="coll-pick-size">{formatSize(f.size)}</span>
            </label>
          {/each}
          {#if collectionFilteredFiles.length > displayedCollectionFiles.length}
            <div class="coll-pick-empty">
              {m.library_status_showing({ shown: displayedCollectionFiles.length.toLocaleString(), total: collectionFilteredFiles.length.toLocaleString() })}
            </div>
          {/if}
          {#if collectionFilteredFiles.length === 0 && hashedLibraryFiles.length > 0}
            <div class="coll-pick-empty">{m.library_coll_no_matches({ query: collectionSearch })}</div>
          {:else if hashedLibraryFiles.length === 0}
            <div class="coll-pick-empty">{m.library_coll_no_hashed_files()}</div>
          {/if}
        </div>
      </div>
      <div class="modal-footer">
        <button class="ghost" onclick={() => createCollectionOpen = false}>{m.common_cancel()}</button>
        <button
          disabled={!newCollName.trim() || selectedFileHashes.size === 0 || creatingCollection}
          onclick={handleCreateCollection}
        >
          {creatingCollection ? m.library_creating() : m.common_create()}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if error}
  <div class="error-banner">
    <span>{error}</span>
    <button class="ghost" onclick={() => error = null}>{m.common_dismiss()}</button>
  </div>
{/if}

{#if dndActive}
  <div class="dnd-overlay" class:hover={dndHover} role="presentation">
    <div class="dnd-hint">
      <div class="dnd-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" width="42" height="42">
          <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
          <line x1="12" y1="11" x2="12" y2="17"/>
          <polyline points="9 14 12 11 15 14"/>
        </svg>
      </div>
      <div class="dnd-title">{m.library_dnd_title()}</div>
      <div class="dnd-sub">{m.library_dnd_sub()}</div>
    </div>
  </div>
{/if}

<div class="shared-layout" class:dragging={sidebarDragging}>
  <!-- Sidebar: folder filter tree -->
  <div class="sidebar" style="width: {sidebarWidth}px; min-width: {sidebarWidth}px;">
    <div class="sidebar-header">{m.library_shared_folders()}</div>
    <div class="folder-tree">
      <div
        class="tree-item"
        class:active={filterFolder === null}
        onclick={() => filterFolder = null}
        role="button"
        tabindex="0"
        onkeydown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            filterFolder = null;
          }
        }}
      >
        <span class="tree-main">
          <span class="tree-icon">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" width="14" height="14" aria-hidden="true">
              <rect x="5" y="5" width="8.5" height="8.5" rx="1.2"/>
              <path d="M3 11V3.5a1 1 0 0 1 1-1H10"/>
            </svg>
          </span>
          <span class="tree-folder-name">{m.library_all_files()}</span>
        </span>
        <div class="tree-meta">
          <span class="tree-count">{files.length.toLocaleString()}</span>
        </div>
      </div>
      {#each folders as folder (folder)}
        <div
          class="tree-item"
          class:active={filterFolder === folder}
          onclick={() => filterFolder = folder}
          role="button"
          tabindex="0"
          onkeydown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              filterFolder = folder;
            }
          }}
        >
          <span class="tree-main">
            <span class="tree-icon">
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" width="14" height="14" aria-hidden="true">
                <path d="M2 4.5a1 1 0 0 1 1-1h3l1.5 1.5H13a1 1 0 0 1 1 1V12a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1z"/>
              </svg>
            </span>
            <span class="tree-folder-name" title={folder}>
              {folder.split(/[\\/]/).filter(Boolean).pop() || folder}
            </span>
          </span>
          <div class="tree-meta">
            <span class="tree-count">{(folderStats.counts.get(folder) ?? 0).toLocaleString()} &middot; {formatSize(folderStats.sizes.get(folder) ?? 0)}</span>
            <select
              class="tree-prio"
              class:tree-prio-set={!!folderPriorities[folder]}
              title={m.library_folder_priority_title()}
              aria-label={m.library_folder_priority_title()}
              value={folderPriorities[folder] ?? ''}
              onclick={(e) => e.stopPropagation()}
              onchange={(e) => { e.stopPropagation(); handleSetFolderPriority(folder, (e.currentTarget as HTMLSelectElement).value); }}
            >
              <option value="">{m.library_folder_priority_default()}</option>
              <option value="verylow">{m.library_priority_verylow()}</option>
              <option value="low">{m.library_priority_low()}</option>
              <option value="normal">{m.library_priority_normal()}</option>
              <option value="high">{m.library_priority_high()}</option>
              <option value="release">{m.library_priority_release()}</option>
              <option value="auto">{m.library_priority_auto()}</option>
            </select>
            <span class="tree-actions">
              <button
                class="tree-btn tree-unshare"
                onclick={(e) => { e.stopPropagation(); handleUnshareFolder(folder); }}
                title={m.library_unshare_folder_title()}
              >&#x20E0;</button>
              <button
                class="tree-btn tree-remove"
                onclick={(e) => { e.stopPropagation(); handleRemoveFolder(folder); }}
                title={m.library_remove_folder_btn_title()}
              >&times;</button>
            </span>
          </div>
        </div>
      {/each}
    </div>

    <div class="sidebar-section top-section">
      <button
        type="button"
        class="sidebar-section-header"
        aria-expanded={topPanelOpen}
        onclick={() => (topPanelOpen = !topPanelOpen)}
      >
        <span class="section-arrow">{topPanelOpen ? '\u25BE' : '\u25B8'}</span>
        <span class="section-title">{m.library_top_uploads()}</span>
      </button>
      {#if topPanelOpen}
        <div class="top-metric-switch" role="tablist" aria-label={m.library_top_upload_scope()}>
          <button
            type="button"
            role="tab"
            aria-selected={topPanelScope === 'alltime'}
            class:active={topPanelScope === 'alltime'}
            onclick={() => (topPanelScope = 'alltime')}
            title={m.library_top_alltime_title()}
          >{m.library_top_alltime()}</button>
          <button
            type="button"
            role="tab"
            aria-selected={topPanelScope === 'session'}
            class:active={topPanelScope === 'session'}
            onclick={() => (topPanelScope = 'session')}
            title={m.library_top_session_title()}
          >{m.library_top_session()}</button>
        </div>
        <div class="top-metric-switch" role="tablist" aria-label={m.library_top_upload_metric()}>
          <button
            type="button"
            role="tab"
            aria-selected={topPanelMetric === 'bytes'}
            class:active={topPanelMetric === 'bytes'}
            onclick={() => (topPanelMetric = 'bytes')}
          >{m.library_top_by_bytes()}</button>
          <button
            type="button"
            role="tab"
            aria-selected={topPanelMetric === 'requests'}
            class:active={topPanelMetric === 'requests'}
            onclick={() => (topPanelMetric = 'requests')}
          >{m.library_top_by_uploads()}</button>
        </div>
        <div class="top-list">
          {#if topFiles.length === 0}
            <div class="top-empty">
              {topPanelScope === 'session'
                ? m.library_top_empty_session()
                : m.library_top_empty_alltime()}
            </div>
          {:else}
            {#each topFiles as tf, i (tf.path)}
              {@const val = topValueFor(tf)}
              {@const pct = topMaxValue > 0 ? Math.max(4, Math.round((val / topMaxValue) * 100)) : 0}
              <button
                type="button"
                class="top-row"
                class:selected={selectedPath === tf.path}
                onclick={() => selectAndRevealFile(tf.path)}
                title={tf.name}
              >
                <span class="top-rank">{i + 1}</span>
                <span class="top-body">
                  <span class="top-name">{tf.name}</span>
                  <span class="top-bar-wrap">
                    <span class="top-bar" style="width:{pct}%"></span>
                  </span>
                  <span class="top-value">
                    {topPanelMetric === 'bytes'
                      ? formatSize(val)
                      : (val === 1 ? m.library_uploads_one() : m.library_uploads_other({ count: val.toLocaleString() }))}
                  </span>
                </span>
              </button>
            {/each}
          {/if}
        </div>
      {/if}
    </div>
  </div>

  <!-- Sidebar resize handle -->
  <div
    class="sidebar-divider"
    onmousedown={onSidebarDown}
    onkeydown={(e) => {
      if (e.key === 'ArrowLeft') { e.preventDefault(); sidebarWidth = Math.max(120, sidebarWidth - 10); localStorage.setItem('library-sidebar-w', String(sidebarWidth)); }
      else if (e.key === 'ArrowRight') { e.preventDefault(); sidebarWidth = Math.min(400, sidebarWidth + 10); localStorage.setItem('library-sidebar-w', String(sidebarWidth)); }
    }}
    role="slider"
    tabindex="0"
    aria-orientation="vertical"
    aria-valuenow={sidebarWidth}
    aria-valuemin={120}
    aria-valuemax={400}
    aria-valuetext={`${sidebarWidth}px`}
    aria-label={m.library_resize_sidebar()}
  ></div>

  <!-- Main: file list -->
  <div class="file-list-area">
    {#if scanning || hashProgress}
      <div class="scan-banner">
        <span class="scan-spinner"></span>
        <span class="scan-text">
          {#if hashProgress}
            {m.library_hashing_file({ current: hashProgress.current, total: hashProgress.total, name: hashProgress.file_name })}
          {:else}
            {m.library_scanning_files()}
          {/if}
        </span>
        <button class="scan-btn stop-btn" onclick={handleStopRequest}>{m.common_stop()}</button>
      </div>
    {/if}
    {#if stopConfirmVisible}
      <div class="confirm-banner">
        <span class="confirm-text">{m.library_stop_confirm_text()}</span>
        <button class="scan-btn resume-btn" onclick={handleStopCancel}>{m.common_cancel()}</button>
        <button class="scan-btn stop-btn" onclick={handleStopConfirm}>{m.library_remove_folder()}</button>
      </div>
    {/if}
    {#if stoppedByUser && !scanning && !stopConfirmVisible}
      <div class="scan-banner resume-banner">
        <span class="scan-text">{m.library_hashing_stopped()}</span>
        <button class="scan-btn resume-btn" onclick={handleResume}>{m.library_resume_hashing()}</button>
      </div>
    {/if}
    {#if sortedFiles.length === 0 && !scanning && hasActiveLibraryFilters && files.length > 0}
      <div class="empty-state">
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="56" height="56" aria-hidden="true">
          <circle cx="11" cy="11" r="8"></circle>
          <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          <line x1="11" y1="8" x2="11" y2="14"></line>
          <line x1="8" y1="11" x2="14" y2="11"></line>
        </svg>
        <p>{m.library_empty_no_matches()}</p>
        <p class="sub"><button class="link-btn" onclick={clearLibraryFilters}>{m.library_clear_filters()}</button></p>
      </div>
    {:else if sortedFiles.length === 0 && !scanning}
      <div class="empty-state">
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="56" height="56" aria-hidden="true">
          <path d="M3 7v13a1 1 0 0 0 1 1h16a1 1 0 0 0 1-1V9a1 1 0 0 0-1-1h-9l-2-2H4a1 1 0 0 0-1 1z"></path>
          <line x1="12" y1="13" x2="12" y2="17"></line>
          <line x1="10" y1="15" x2="14" y2="15"></line>
        </svg>
        <p>{m.library_empty_no_shared()}</p>
        <p class="sub">{m.library_empty_no_shared_sub()}</p>
        <button class="empty-action" onclick={handleAddFolder}>{m.library_add_folder()}</button>
      </div>
    {:else if sortedFiles.length === 0 && scanning}
      <div class="empty-state">
        <div class="spinner lg"></div>
        <p>{m.library_waiting_scan()}</p>
      </div>
    {:else}
      <LibraryVirtualTable
        bind:this={libraryTableRef}
        {sortedFiles}
        {selectedPath}
        onSelectPath={(path) => { selectedPath = path; }}
        onOpenFile={openSharedFile}
        onRowContextMenu={onCtx}
        {fileType}
        {priorityLabel}
        {formatTransferred}
        {toggleSort}
        {sortOnKey}
        {arrow}
        {ariaSort}
        checkedPaths={checkedPaths}
        allChecked={allFilteredChecked}
        someChecked={someFilteredChecked}
        onToggleCheck={toggleCheck}
        onToggleCheckAll={toggleCheckAll}
        missingPaths={missingPathSet}
      />
    {/if}

    {#if checkedCount > 0}
      <div class="bulk-action-bar">
        <span class="bulk-count">{checkedCount === 1 ? m.library_bulk_count_one() : m.library_bulk_count_other({ count: checkedCount })}</span>
        {#if checkedHiddenCount > 0}
          <button
            type="button"
            class="bulk-hidden-note"
            onclick={clearLibraryFilters}
            title={m.library_bulk_hidden_title({ shown: checkedCount.toLocaleString() })}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="11" height="11" aria-hidden="true">
              <path d="M2 3h12l-4.5 5.5V13l-3 1.5V8.5z"/>
            </svg>
            {checkedHiddenCount === 1 ? m.library_bulk_hidden_one() : m.library_bulk_hidden_other({ count: checkedHiddenCount.toLocaleString() })}
          </button>
        {/if}
        <div class="bulk-prio-group">
          <span class="bulk-label">{m.library_bulk_priority_label()}</span>
          <div class="bulk-prio-seg">
            {#each ['verylow', 'low', 'normal', 'high', 'release', 'auto'] as p}
              <button class="bulk-prio-btn" onclick={() => bulkSetPriority(p as FileInfo['priority'])} title={m.library_set_priority_title({ priority: priorityLabel(p) })}>{priorityLabel(p)}</button>
            {/each}
          </div>
        </div>
        <span class="bulk-sep" aria-hidden="true"></span>
        <button class="tb-btn" onclick={bulkShare} title={m.library_bulk_share_title()}>{m.library_bulk_share()}</button>
        <button class="tb-btn" onclick={bulkUnshare} title={m.library_bulk_unshare_title()}>{m.library_bulk_unshare()}</button>
        <button class="tb-btn" onclick={bulkCopyLinks} title={m.library_bulk_copy_links_title()}>{m.library_copy_links()}</button>
        <button class="tb-btn" onclick={openCreateDialogFromSelection} title={m.library_bulk_new_collection_title()}>{m.library_bulk_new_collection()}</button>
        <span class="bulk-spacer"></span>
        <button class="tb-btn tb-danger" onclick={bulkDelete} title={m.library_bulk_delete_title()}>{m.common_delete()}</button>
        <button class="tb-btn" onclick={clearChecked} title={m.library_bulk_clear_title()}>{m.common_clear()}</button>
      </div>
    {/if}

    <div class="status-bar">
      {#if hasActiveLibraryFilters && filteredFiles.length !== files.length}
        <span>{m.library_status_showing({ shown: filteredFiles.length.toLocaleString(), total: files.length.toLocaleString() })}</span>
        <span class="status-sep">&middot;</span>
        <span>{m.library_status_shared_in_view({ count: filteredSharedCount.toLocaleString() })}</span>
        <span class="status-sep">&middot;</span>
      {/if}
      <span>{activeFolderLabel}</span>
      {#if selectedFile}
        <span class="status-sep">&middot;</span>
        <span class="status-selected" title={selectedFile.name}>{m.library_status_selected({ name: selectedFile.name })}</span>
      {/if}
    </div>
  </div>

  <!-- Side drawer for file details + comments -->
  {#if selectedFile}
    <div class="detail-drawer" transition:fly={{ x: 24, duration: prefersReducedMotion.current ? 0 : 200 }}>
      <div class="drawer-header">
        <span class="drawer-title" title={selectedFile.name}>{selectedFile.name}</span>
        <button class="ghost drawer-close" onclick={() => selectedPath = null} title={m.library_close_details()} aria-label={m.library_close_details()}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15" aria-hidden="true">
            <line x1="6" y1="6" x2="18" y2="18"/>
            <line x1="18" y1="6" x2="6" y2="18"/>
          </svg>
        </button>
      </div>
      <div class="drawer-body">
        <div class="details-meta-grid">
          <span class="meta-label">{m.library_meta_path()}</span>
          <span class="meta-value meta-path" title={selectedFile.path}>{selectedFile.path}</span>
          <span class="meta-label">{m.library_col_size()}</span>
          <span class="meta-value">{formatSize(selectedFile.size)}</span>
          {#if selectedFile.modified_at}
            <span class="meta-label">{m.library_col_modified()}</span>
            <span class="meta-value">{new Date(selectedFile.modified_at * 1000).toLocaleString()}</span>
          {/if}
          {#if selectedFile.hash}
            <span class="meta-label">{m.library_meta_hash()}</span>
            <span class="meta-value meta-hash">
              <code>{selectedFile.hash}</code>
              <button class="ghost copy-btn" onclick={() => { const f = selectedFile; if (f) copyToClipboard(f.hash, m.library_copied_hash()); }} title={m.library_meta_copy_hash()}>{m.common_copy()}</button>
            </span>
          {/if}
          {#if selectedFile.aich_hash}
            <span class="meta-label">{m.library_meta_aich()}</span>
            <span class="meta-value meta-hash">
              <code>{selectedFile.aich_hash}</code>
              <button class="ghost copy-btn" onclick={() => { const f = selectedFile; if (f) copyToClipboard(f.aich_hash, m.library_copied_aich()); }} title={m.library_meta_copy_aich()}>{m.common_copy()}</button>
            </span>
          {/if}
          <span class="meta-label">{m.library_col_priority()}</span>
          <span class="meta-value">
            <span class="prio-badge prio-{selectedFile.priority}">{priorityLabel(selectedFile.priority)}</span>
          </span>
          <span class="meta-label">{m.library_col_shared()}</span>
          <span class="meta-value">
            {selectedFile.shared ? m.common_yes() : m.common_no()}
            {#if selectedFile.hash}
              <span class="meta-badges">
                {#if selectedFile.shared && selectedFile.shared_kad}<span class="meta-badge" title={m.library_published_kad()}>KAD</span>{/if}
                {#if selectedFile.shared && selectedFile.shared_ed2k}<span class="meta-badge" title={m.library_published_ed2k()}>eD2K</span>{/if}
                {#if selectedFile.aich_hash}<span class="meta-badge meta-badge-aich" title={m.library_aich_available()}>AICH</span>{/if}
              </span>
            {/if}
          </span>
          <span class="meta-label">{m.library_col_requests()}</span>
          <span class="meta-value">{selectedFile.requests}{selectedFile.alltime_requests ? ` (${m.library_meta_alltime({ value: selectedFile.alltime_requests })})` : ''}</span>
          <span class="meta-label">{m.library_col_accepted()}</span>
          <span class="meta-value">{selectedFile.accepted}{selectedFile.alltime_accepted ? ` (${m.library_meta_alltime({ value: selectedFile.alltime_accepted })})` : ''}</span>
          <span class="meta-label">{m.library_col_transferred()}</span>
          <span class="meta-value">{formatSize(selectedFile.bytes_transferred)}{selectedFile.alltime_transferred ? ` (${m.library_meta_alltime({ value: formatSize(selectedFile.alltime_transferred) })})` : ''}</span>
          {#if selectedFile.complete_sources > 0}
            <span class="meta-label">{m.library_col_peers()}</span>
            <span class="meta-value" title={m.library_meta_peers_title()}>
              {m.library_meta_peers_count({ count: selectedFile.complete_sources.toLocaleString() })}
            </span>
          {/if}
        </div>

        {#if selectedMedia}
          <div class="drawer-section-divider"></div>
          <div class="details-meta-grid">
            {#if selectedMedia.title}
              <span class="meta-label">{m.library_meta_title()}</span>
              <span class="meta-value"><bdi>{selectedMedia.title}</bdi></span>
            {/if}
            {#if selectedMedia.artist}
              <span class="meta-label">{m.library_meta_artist()}</span>
              <span class="meta-value"><bdi>{selectedMedia.artist}</bdi></span>
            {/if}
            {#if selectedMedia.album}
              <span class="meta-label">{m.library_meta_album()}</span>
              <span class="meta-value"><bdi>{selectedMedia.album}</bdi></span>
            {/if}
            {#if selectedMedia.duration}
              <span class="meta-label">{m.library_meta_duration()}</span>
              <span class="meta-value">{formatMediaLength(selectedMedia.duration)}</span>
            {/if}
            {#if selectedMedia.bitrate}
              <span class="meta-label">{m.library_meta_bitrate()}</span>
              <span class="meta-value">{m.library_meta_bitrate_value({ kbps: selectedMedia.bitrate })}</span>
            {/if}
            {#if selectedMedia.codec}
              <span class="meta-label">{m.library_meta_codec()}</span>
              <span class="meta-value">{selectedMedia.codec}</span>
            {/if}
          </div>
        {/if}

        <div class="drawer-actions">
          <button class="drawer-action-btn" onclick={() => openSharedFile(selectedFile.path)} title={m.library_open_file_title()}>
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
              <path d="M2 2.5h4.5l1.5 2H14v9H2z"/>
              <path d="M6 8.5l2 2 2-2"/>
              <line x1="8" y1="5" x2="8" y2="10.5"/>
            </svg>
            {m.library_open_file()}
          </button>
          <button class="drawer-action-btn" onclick={() => openSharedFolder(selectedFile.path)} title={m.library_open_folder_title()}>
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
              <path d="M2 2.5h4.5l1.5 2H14v9H2z"/>
            </svg>
            {m.library_open_folder()}
          </button>
        </div>

        {#if selectedHash}
          <div class="drawer-section">
            <div class="drawer-section-header">
              <span class="drawer-section-title">{m.library_comments_rating()}</span>
              {#if commentLastSavedAt}
                <span class="comment-last-saved">{m.library_saved_at({ time: formatSavedTime(commentLastSavedAt) })}</span>
              {/if}
            </div>
            {#if commentLoading}
              <div class="comment-loading">{m.library_loading_comments()}</div>
            {:else}
              <div class="comment-our">
                <div class="comment-rating-row">
                  <span class="comment-label">{m.library_your_rating()}</span>
                  {#each [1,2,3,4,5] as star}
                    <button class="star-btn" onclick={() => ourRating = star} title={star === 1 ? m.library_star_one() : m.library_star_other({ count: star })}>
                      {star <= ourRating ? '\u2605' : '\u2606'}
                    </button>
                  {/each}
                  {#if ourRating > 0}
                    <button class="star-clear" onclick={() => ourRating = 0} title={m.library_clear_rating()}>&times;</button>
                  {/if}
                </div>
                <div class="comment-input-row">
                  <textarea
                    class="comment-input"
                    placeholder={m.library_add_comment_placeholder()}
                    bind:value={ourComment}
                    rows="2"
                    onkeydown={(e) => {
                      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                        e.preventDefault();
                        handleSaveComment();
                      }
                    }}
                  ></textarea>
                  <button class="comment-save" onclick={handleSaveComment} disabled={commentSaveState === 'saving'}>
                    {commentSaveState === 'saving' ? m.library_saving() : m.common_save()}
                  </button>
                </div>
                {#if commentSaveState !== 'idle'}
                  <div class="comment-save-state" class:error={commentSaveState === 'error'}>
                    {commentSaveMessage}
                  </div>
                {/if}
              </div>
              {#if commentInfo?.peer_comments?.length}
                <div class="comment-peers">
                  <div class="comment-label">{m.library_peer_comments()}</div>
                  {#each commentInfo.peer_comments as pc, i (i)}
                    <div class="comment-peer-item">
                      <span class="comment-peer-name"><bdi>{pc.user_name}</bdi></span>
                      <span class="comment-peer-stars">
                        {#each [1,2,3,4,5] as s}
                          <span class="star-display">{s <= pc.rating ? '\u2605' : '\u2606'}</span>
                        {/each}
                      </span>
                      {#if pc.comment}
                        <span class="comment-peer-text"><bdi>{pc.comment}</bdi></span>
                      {/if}
                    </div>
                  {/each}
                </div>
              {:else}
                <div class="comment-empty">{m.library_no_peer_comments()}</div>
              {/if}
            {/if}
          </div>
        {/if}
      </div>
    </div>
  {/if}
</div>

<!-- Context menu -->
{#if ctxMenu}
  {@const fileHashed = !!ctxMenu.file.hash}
  <div bind:this={ctxMenuEl} class="ctx-menu" style="left:{ctxMenu.x}px;top:{ctxMenu.y}px;" role="menu">
    <button class="ctx-item" role="menuitem" onclick={() => ctxAction('open_file')}>{m.library_open_file()}</button>
    <button class="ctx-item" role="menuitem" onclick={() => ctxAction('open_folder')}>{m.library_open_folder()}</button>
    <button class="ctx-item ctx-danger" role="menuitem" onclick={() => ctxAction('delete')}>{m.library_delete_file_title()}</button>
    <div class="ctx-sep"></div>
    {#if fileHashed}
      <div
        class="ctx-item ctx-sub-parent"
        role="menuitem"
        tabindex="0"
        onmouseenter={() => ctxPrioritySub = true}
        onmouseleave={() => ctxPrioritySub = false}
        onkeydown={(e) => { if (e.key === 'Enter' || e.key === 'ArrowRight') ctxPrioritySub = true; }}
      >
        {m.library_col_priority()} &raquo;
        {#if ctxPrioritySub}
          <div class="ctx-submenu" class:ctx-submenu-left={ctxSubmenuLeft} class:ctx-submenu-up={ctxSubmenuUp} role="menu">
            <button class="ctx-item" role="menuitem" class:ctx-checked={ctxMenu.file.priority === 'verylow'} onclick={() => ctxAction('priority', 'verylow')}>{m.library_priority_verylow()}</button>
            <button class="ctx-item" role="menuitem" class:ctx-checked={ctxMenu.file.priority === 'low'} onclick={() => ctxAction('priority', 'low')}>{m.library_priority_low()}</button>
            <button class="ctx-item" role="menuitem" class:ctx-checked={ctxMenu.file.priority === 'normal'} onclick={() => ctxAction('priority', 'normal')}>{m.library_priority_normal()}</button>
            <button class="ctx-item" role="menuitem" class:ctx-checked={ctxMenu.file.priority === 'high'} onclick={() => ctxAction('priority', 'high')}>{m.library_priority_high()}</button>
            <button class="ctx-item" role="menuitem" class:ctx-checked={ctxMenu.file.priority === 'release'} onclick={() => ctxAction('priority', 'release')}>{m.library_priority_release()}</button>
            <div class="ctx-sep"></div>
            <button class="ctx-item" role="menuitem" class:ctx-checked={ctxMenu.file.priority === 'auto'} onclick={() => ctxAction('priority', 'auto')}>{m.library_priority_auto()}</button>
          </div>
        {/if}
      </div>
      <div class="ctx-sep"></div>
      <div
        class="ctx-item ctx-sub-parent"
        role="menuitem"
        tabindex="0"
        onmouseenter={() => ctxCopySub = true}
        onmouseleave={() => ctxCopySub = false}
        onkeydown={(e) => { if (e.key === 'Enter' || e.key === 'ArrowRight') ctxCopySub = true; }}
      >
        {m.servers_copy_ed2k_link()} &raquo;
        {#if ctxCopySub}
          <div class="ctx-submenu" class:ctx-submenu-left={ctxSubmenuLeft} class:ctx-submenu-up={ctxSubmenuUp} role="menu">
            <button class="ctx-item" role="menuitem" onclick={() => ctxAction('copy_link')}>{m.library_copy_link_plain()}</button>
            {#if ctxMenu.file.aich_hash}
              <button class="ctx-item" role="menuitem" onclick={() => ctxAction('copy_link', 'aich')}>{m.library_copy_link_aich()}</button>
            {/if}
            <button class="ctx-item" role="menuitem" onclick={() => ctxAction('copy_link', 'sources')}>{m.library_copy_link_sources()}</button>
          </div>
        {/if}
      </div>
      <div class="ctx-sep"></div>
      {#if ctxMenu.file.shared}
        <button
          class="ctx-item"
          role="menuitem"
          onclick={() => ctxAction('republish')}
          title={$networkStats.status === 'connected'
            ? m.library_republish_title_online()
            : m.library_republish_title_offline()}
        >{m.library_republish_kad()}{$networkStats.status !== 'connected' ? m.library_republish_offline_suffix() : ''}</button>
        <button class="ctx-item" role="menuitem" onclick={() => ctxAction('unshare')}>{m.library_unshare_file()}</button>
      {:else}
        <button class="ctx-item" role="menuitem" onclick={() => ctxAction('share')}>{m.library_share_file()}</button>
      {/if}
    {:else}
      <button class="ctx-item ctx-disabled" role="menuitem" disabled>{m.library_hashing_in_progress()}</button>
    {/if}
  </div>
{/if}

<style>
  /* --- Drag & drop overlay --- */
  .dnd-overlay {
    position: fixed;
    inset: 0;
    z-index: 1000;
    pointer-events: none;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(10, 15, 25, 0.55);
    backdrop-filter: blur(2px);
    border: 3px dashed var(--accent, #4a90e2);
    transition: background 0.12s ease;
  }
  .dnd-overlay.hover { background: rgba(74, 144, 226, 0.22); }
  .dnd-hint {
    background: var(--bg-secondary, #1e2433);
    border: 1px solid var(--border, #333);
    border-radius: 10px;
    padding: 22px 28px;
    text-align: center;
    color: var(--text, #e0e0e0);
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.45);
    max-width: 360px;
  }
  .dnd-icon { color: var(--accent, #4a90e2); margin-bottom: 6px; }
  .dnd-title { font-size: 16px; font-weight: 600; margin-bottom: 4px; }
  .dnd-sub { font-size: 12px; color: var(--text-muted, #999); }

  /* --- Layout --- */
  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    gap: 10px;
    flex-wrap: wrap;
  }
  .page-header h2 { margin: 0; font-size: 16px; }
  .header-actions { display: flex; gap: 8px; flex-wrap: wrap; }

  .error-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 20px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--danger, #e74c3c);
    color: var(--danger, #e74c3c);
    font-size: 13px;
  }

  .scan-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    color: var(--accent, #3498db);
    font-size: 12px;
    flex-shrink: 0;
  }
  .scan-text { flex: 1; }
  .confirm-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--danger, #e74c3c);
    color: var(--danger, #e74c3c);
    font-size: 12px;
    flex-shrink: 0;
  }
  .confirm-text { flex: 1; }
  .resume-banner { color: var(--warning, #e0a030); }
  .scan-btn {
    padding: 2px 10px;
    font-size: 11px;
    border-radius: 3px;
    border: 1px solid var(--border);
    cursor: pointer;
    flex-shrink: 0;
  }
  .stop-btn { background: var(--danger, #e74c3c); color: #fff; border-color: var(--danger, #e74c3c); }
  .stop-btn:hover { opacity: 0.85; }
  .resume-btn { background: var(--accent, #3498db); color: #fff; border-color: var(--accent, #3498db); }
  .resume-btn:hover { opacity: 0.85; }

  .scan-spinner {
    width: 12px;
    height: 12px;
    border: 2px solid var(--border);
    border-top-color: var(--accent, #3498db);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .shared-layout {
    display: flex;
    flex: 1;
    overflow: hidden;
    min-height: 0;
  }
  .shared-layout.dragging { user-select: none; cursor: col-resize; }

  /* --- Sidebar --- */
  .sidebar {
    display: flex;
    flex-direction: column;
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
    overflow: hidden;
    box-shadow: var(--shadow-sm);
  }
  .sidebar-header {
    padding: 10px 12px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
  }
  .folder-tree { flex: 1 1 auto; overflow-y: auto; padding: 6px; min-height: 80px; }

  /* --- Top Uploads (popularity) panel --- */
  .sidebar-section {
    display: flex;
    flex-direction: column;
    border-top: 1px solid var(--border);
    background: var(--bg-secondary);
    flex-shrink: 0;
    max-height: 45%;
  }
  .sidebar-section-header {
    display: flex;
    align-items: center;
    gap: 6px;
    width: 100%;
    padding: 8px 10px;
    background: var(--bg-surface);
    border: none;
    border-bottom: 1px solid var(--border);
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    cursor: pointer;
    text-align: left;
  }
  .sidebar-section-header:hover { color: var(--text-primary); }
  .section-arrow { width: 10px; color: var(--text-muted); font-size: 10px; }
  .section-title { flex: 1; }
  .top-metric-switch {
    display: flex;
    gap: 4px;
    padding: 6px 6px 4px;
  }
  .top-metric-switch button {
    flex: 1;
    padding: 3px 6px;
    font-size: 11px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 3px;
    color: var(--text-muted);
    cursor: pointer;
    transition: background 0.12s, color 0.12s, border-color 0.12s;
  }
  .top-metric-switch button:hover { color: var(--text-primary); }
  .top-metric-switch button.active {
    background: color-mix(in srgb, var(--accent-dim) 55%, transparent);
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
    color: var(--text-primary);
    font-weight: 600;
  }
  .top-list {
    overflow-y: auto;
    padding: 4px 6px 8px;
    flex: 1;
    min-height: 0;
  }
  .top-empty {
    padding: 10px 8px;
    font-size: 11px;
    color: var(--text-muted);
    font-style: italic;
    line-height: 1.4;
  }
  .top-row {
    display: flex;
    width: 100%;
    align-items: center;
    gap: 6px;
    padding: 4px 6px;
    margin-bottom: 2px;
    background: transparent;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    color: var(--text-secondary);
    cursor: pointer;
    font: inherit;
    text-align: left;
    transition: background 0.12s, border-color 0.12s;
  }
  .top-row:hover {
    background: var(--bg-hover);
    border-color: var(--border);
  }
  .top-row.selected {
    background: color-mix(in srgb, var(--accent-dim) 55%, transparent);
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
    color: var(--text-primary);
  }
  .top-rank {
    flex-shrink: 0;
    width: 16px;
    text-align: right;
    font-size: 10px;
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }
  .top-body {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
    flex: 1;
  }
  .top-name {
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .top-bar-wrap {
    display: block;
    height: 3px;
    background: var(--bg-primary);
    border-radius: 2px;
    overflow: hidden;
  }
  .top-bar {
    display: block;
    height: 100%;
    background: linear-gradient(90deg, color-mix(in srgb, var(--accent) 70%, transparent), var(--accent));
    border-radius: 2px;
    transition: width 0.25s ease;
  }
  .top-value {
    font-size: 10px;
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }
  .tree-item {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 5px;
    padding: 6px 8px;
    margin-bottom: 4px;
    border: 1px solid var(--border);
    border-left: 3px solid transparent;
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    font-size: 12px;
    cursor: pointer;
    color: var(--text-secondary);
    transition: background 0.12s, border-color 0.12s, color 0.12s;
  }
  .tree-item:hover {
    background: var(--bg-hover);
    border-color: var(--border);
    border-left-color: color-mix(in srgb, var(--accent) 50%, transparent);
  }
  .tree-item.active {
    background: color-mix(in srgb, var(--accent-dim) 55%, transparent);
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
    border-left-color: var(--accent);
    color: var(--text-primary);
    font-weight: 600;
  }
  .tree-main {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    flex: 0 0 auto;
  }
  /* Second row: count/size badge, priority dropdown and action buttons stacked
     under the folder name so a long name gets the full width of the row. The
     left padding lines the meta row up with the folder name (icon chip 24px +
     8px gap). It wraps when the sidebar is narrow rather than squeezing the
     name. */
  .tree-meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    padding-left: 32px;
    min-width: 0;
  }
  /* Folder icon sits in a rounded tinted chip for a more deliberate, app-like
     look; the chip and glyph both intensify on the active row. */
  .tree-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border-radius: 6px;
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    color: var(--accent);
    flex-shrink: 0;
  }
  .tree-item.active .tree-icon {
    background: color-mix(in srgb, var(--accent) 22%, transparent);
    color: var(--accent);
  }
  .tree-folder-name {
    min-width: 0;
    overflow-wrap: anywhere;
    word-break: break-word;
    line-height: 1.3;
    font-size: 12.5px;
    font-weight: 500;
    color: var(--text-primary);
  }
  .tree-count {
    display: inline-flex;
    align-items: center;
    height: 22px;
    font-size: 11px;
    font-variant-numeric: tabular-nums;
    color: var(--text-accent);
    background: color-mix(in srgb, var(--accent-dim) 30%, transparent);
    border: 1px solid color-mix(in srgb, var(--accent) 25%, var(--border));
    border-radius: 999px;
    padding: 0 8px;
    flex-shrink: 0;
  }
  .tree-item.active .tree-count {
    color: var(--text-accent);
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
    background: color-mix(in srgb, var(--accent-dim) 45%, transparent);
  }
  .tree-actions {
    display: inline-flex;
    gap: 4px;
    flex-shrink: 0;
  }
  .tree-btn {
    width: 22px;
    height: 22px;
    border-radius: 5px;
    border: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-secondary);
    font-size: 12px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    line-height: 1;
    transition: background 0.12s, border-color 0.12s, color 0.12s;
  }
  /* Stop-sharing: warning (amber) tint; Remove: danger (red) tint. Subtle by
     default, fully saturated on hover so the destructive action reads clearly. */
  .tree-btn.tree-unshare {
    color: var(--warning);
    border-color: color-mix(in srgb, var(--warning) 35%, var(--border));
    background: color-mix(in srgb, var(--warning) 12%, transparent);
  }
  .tree-btn.tree-unshare:hover {
    color: #fff;
    border-color: var(--warning);
    background: var(--warning);
  }
  .tree-btn.tree-remove {
    font-size: 13px;
    color: var(--danger);
    border-color: color-mix(in srgb, var(--danger) 35%, var(--border));
    background: color-mix(in srgb, var(--danger) 12%, transparent);
  }
  .tree-btn.tree-remove:hover {
    color: #fff;
    border-color: var(--danger);
    background: var(--danger);
  }
  /* Per-folder default upload priority. Always visible; highlighted when a
     non-default priority is set. */
  .tree-prio {
    flex-shrink: 0;
    max-width: 96px;
    height: 22px;
    padding: 0 4px;
    font-size: 11px;
    border-radius: 5px;
    border: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-secondary);
    cursor: pointer;
  }
  .tree-prio.tree-prio-set {
    color: var(--text-accent);
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
    background: color-mix(in srgb, var(--accent-dim) 45%, transparent);
  }

  .sidebar-divider {
    width: 4px;
    cursor: col-resize;
    background: var(--border);
    flex-shrink: 0;
  }
  .sidebar-divider:hover { background: var(--accent, #3498db); }

  /* --- File list area --- */
  .file-list-area {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
  }

  /* --- Detail drawer (right side) --- */
  .detail-drawer {
    width: 420px;
    min-width: 360px;
    max-width: 520px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    border-left: 1px solid var(--border);
    background: var(--bg-secondary);
    overflow: hidden;
  }
  .drawer-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
    gap: 8px;
  }
  .drawer-title {
    font-weight: 700;
    font-size: 13px;
    color: var(--text-primary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }
  .drawer-close {
    width: 28px;
    height: 28px;
    padding: 0;
    cursor: pointer;
    border: 1px solid transparent;
    border-radius: 7px;
    background: transparent;
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: background 0.12s, border-color 0.12s, color 0.12s;
  }
  .drawer-close:hover {
    color: var(--danger);
    border-color: color-mix(in srgb, var(--danger) 35%, var(--border));
    background: color-mix(in srgb, var(--danger) 12%, transparent);
  }
  .drawer-close:active {
    background: color-mix(in srgb, var(--danger) 20%, transparent);
  }
  .drawer-body {
    flex: 1;
    overflow-y: auto;
    padding: 12px;
    font-size: 12px;
  }
  .drawer-section {
    margin-top: 16px;
    padding-top: 12px;
    border-top: 1px solid var(--border);
  }
  .drawer-section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 10px;
  }
  .drawer-section-title {
    font-weight: 700;
    font-size: 12px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.35px;
  }
  .empty-state {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    color: var(--text-muted);
    padding: 40px;
  }
  .empty-state .sub { font-size: 13px; margin-top: 4px; }
  .empty-action { margin-top: 12px; font-size: 12px; padding: 6px 18px; }

  .status-bar {
    padding: 6px 12px;
    font-size: 11px;
    color: var(--text-muted);
    border-top: 1px solid var(--border);
    background: var(--bg-secondary);
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .status-sep {
    opacity: 0.55;
  }
  .status-selected {
    color: var(--text-secondary);
    max-width: min(50vw, 420px);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* --- Context menu --- */
  .ctx-menu {
    position: fixed;
    z-index: 9999;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 0;
    min-width: 180px;
    box-shadow: 0 4px 16px rgba(0,0,0,.35);
    font-size: 12px;
    transform-origin: top left;
    animation: ctx-menu-pop 0.12s ease;
  }
  @keyframes ctx-menu-pop {
    from { opacity: 0; transform: scale(0.97); }
    to { opacity: 1; transform: scale(1); }
  }
  .ctx-item {
    display: block;
    width: 100%;
    text-align: left;
    padding: 5px 16px;
    cursor: pointer;
    white-space: nowrap;
    position: relative;
    border: none;
    border-radius: 0;
    background: none;
    color: inherit;
    font: inherit;
    font-size: 12px;
    line-height: inherit;
  }
  .ctx-item:hover { background: var(--accent, #3498db); color: #fff; }
  .ctx-item.ctx-danger { color: var(--danger, #e74c3c); }
  .ctx-item.ctx-danger:hover { background: var(--danger, #e74c3c); color: #fff; }
  .ctx-sep { height: 1px; margin: 4px 0; background: var(--border); }
  .ctx-checked::before { content: '\2713  '; }
  .ctx-sub-parent { padding-right: 24px; }
  .ctx-disabled { color: var(--text-muted); cursor: default; }
  .ctx-disabled:hover { background: none; color: var(--text-muted); }
  .ctx-submenu {
    position: absolute;
    left: 100%;
    top: 0;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 0;
    min-width: 140px;
    box-shadow: 0 4px 16px rgba(0,0,0,.35);
  }
  .ctx-submenu.ctx-submenu-left {
    left: auto;
    right: 100%;
  }
  .ctx-submenu.ctx-submenu-up {
    top: auto;
    bottom: 0;
  }

  /* --- Filter bar --- */
  .filter-bar {
    display: flex;
    flex-direction: column;
    gap: 0;
    padding: 6px 12px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .library-filter-row {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }

  .inline-stats {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin-left: auto;
    font-size: 11px;
    color: var(--text-muted);
    white-space: nowrap;
    flex-shrink: 0;
  }
  .inline-sep { opacity: 0.45; }
  .inline-stat { font-variant-numeric: tabular-nums; }

  .filter-search-wrap {
    flex: 1 1 340px;
    max-width: 520px;
    min-width: 220px;
    display: flex;
    align-items: center;
    gap: 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 0 8px;
    background: var(--bg-input);
  }

  .filter-search-wrap:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-dim);
  }

  .filter-search-icon {
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
  }

  .filter-search {
    flex: 1;
    min-width: 0;
    border: none;
    background: transparent;
    padding: 7px 0;
    font-size: 12px;
    color: inherit;
  }

  .filter-search:focus {
    outline: none;
  }

  .filter-clear-btn {
    border: none;
    background: transparent;
    color: var(--text-muted);
    width: 20px;
    height: 20px;
    border-radius: 50%;
    padding: 0;
    font-size: 11px;
    line-height: 1;
  }

  .filter-clear-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .filter-type {
    padding: 7px 10px;
    font-size: 12px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-primary, #1e1e1e);
    color: inherit;
    cursor: pointer;
  }

  .clear-library-filters {
    font-size: 12px;
    padding: 7px 12px;
  }
  .dupes-toggle {
    padding: 7px 10px;
    font-size: 12px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-primary, #1e1e1e);
    color: inherit;
    cursor: pointer;
    white-space: nowrap;
    transition: background 0.12s, border-color 0.12s, color 0.12s;
  }
  .dupes-toggle:hover:not(:disabled) {
    background: var(--bg-hover);
  }
  .dupes-toggle.active {
    background: color-mix(in srgb, var(--accent-dim) 55%, transparent);
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
    color: var(--text-primary);
    font-weight: 600;
  }
  .dupes-toggle:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .missing-toggle.active {
    background: color-mix(in srgb, var(--danger, #e74c3c) 20%, transparent);
    border-color: color-mix(in srgb, var(--danger, #e74c3c) 55%, var(--border));
    color: var(--danger, #e74c3c);
  }
  .missing-remove-btn {
    background: var(--danger, #e74c3c);
    color: #fff;
    border-color: var(--danger, #e74c3c);
  }
  .missing-remove-btn:hover:not(:disabled) { opacity: 0.85; background: var(--danger, #e74c3c); }

  /* --- Bulk action bar --- */
  .bulk-action-bar {
    border-top: 1px solid var(--border);
    background: color-mix(in srgb, var(--accent-dim) 22%, var(--bg-secondary));
    box-shadow: 0 -2px 6px -4px rgba(0, 0, 0, 0.25);
    padding: 8px 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    flex-shrink: 0;
    font-size: 12px;
  }
  .bulk-count {
    font-weight: 600;
    color: var(--accent);
    padding: 2px 8px;
    border-radius: 999px;
    background: color-mix(in srgb, var(--accent) 16%, transparent);
    white-space: nowrap;
  }
  /* Toolbar-style buttons: the library page has no base .tb-btn rule, so without
     this they fall back to the global accent-filled <button> style. Match the
     clean bordered look used by the other toolbars. */
  .bulk-action-bar .tb-btn {
    font-size: 12px;
    font-weight: 500;
    padding: 4px 11px;
    min-height: 26px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-secondary);
    color: var(--text-primary);
    cursor: pointer;
    white-space: nowrap;
    transition: background 0.13s ease, border-color 0.13s ease, color 0.13s ease;
  }
  .bulk-action-bar .tb-btn:hover:not(:disabled) {
    background: var(--bg-hover);
    border-color: var(--border-light);
  }
  .bulk-action-bar .tb-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .bulk-sep {
    width: 1px;
    align-self: stretch;
    margin: 2px 2px;
    background: var(--border);
  }
  .bulk-spacer {
    flex: 1 1 auto;
    min-width: 8px;
  }
  .bulk-hidden-note {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 11px;
    font-weight: 600;
    color: var(--warning, #e0a030);
    background: color-mix(in srgb, var(--warning, #e0a030) 14%, transparent);
    border: 1px solid color-mix(in srgb, var(--warning, #e0a030) 30%, transparent);
    border-radius: 999px;
    padding: 1px 8px;
    margin-right: 4px;
    cursor: pointer;
    white-space: nowrap;
    font-family: inherit;
    transition: background 0.12s ease, border-color 0.12s ease;
  }
  .bulk-hidden-note:hover {
    background: color-mix(in srgb, var(--warning, #e0a030) 24%, transparent);
    border-color: color-mix(in srgb, var(--warning, #e0a030) 55%, transparent);
  }
  .bulk-hidden-note:focus-visible {
    outline: 2px solid var(--warning, #e0a030);
    outline-offset: 1px;
  }
  .bulk-label {
    color: var(--text-muted);
    font-size: 11px;
    white-space: nowrap;
  }
  .bulk-prio-group {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  /* Segmented control for the six priority levels. */
  .bulk-prio-seg {
    display: inline-flex;
    align-items: stretch;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    overflow: hidden;
  }
  .bulk-prio-btn {
    font-size: 11px;
    font-weight: 500;
    padding: 3px 9px;
    min-height: 26px;
    border: none;
    border-left: 1px solid var(--border);
    border-radius: 0;
    background: var(--bg-secondary);
    color: var(--text-secondary);
    cursor: pointer;
    white-space: nowrap;
    transition: background 0.13s ease, color 0.13s ease;
  }
  .bulk-prio-btn:first-child { border-left: none; }
  .bulk-prio-btn:hover:not(:disabled) {
    background: var(--accent);
    color: #fff;
  }
  .spinner-inline {
    display: inline-block;
    width: 10px;
    height: 10px;
    border: 2px solid var(--text-muted);
    border-top-color: transparent;
    border-radius: 50%;
    animation: spinner-rotate 0.9s linear infinite;
    vertical-align: -1px;
    margin-right: 4px;
  }
  @keyframes spinner-rotate {
    to { transform: rotate(360deg); }
  }

  .tb-btn.tb-danger {
    border-color: rgba(231, 76, 60, 0.4);
    color: #e74c3c;
  }
  .tb-btn.tb-danger:hover:not(:disabled) {
    background: rgba(231, 76, 60, 0.12);
    border-color: #e74c3c;
  }

  /* --- Details meta grid --- */
  .details-meta-grid {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 3px 12px;
    align-items: baseline;
  }
  .meta-label {
    color: var(--text-muted);
    font-size: 11px;
    text-align: right;
    white-space: nowrap;
  }
  .meta-value {
    color: var(--text-primary);
    word-break: break-all;
    font-size: 12px;
  }
  .meta-path {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 100%;
  }
  .meta-hash {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-mono, monospace);
    font-size: 11px;
  }
  .drawer-actions {
    display: flex;
    gap: 6px;
    margin-top: 12px;
  }
  .drawer-action-btn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 5px 12px;
    font-size: 12px;
    font-weight: 500;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    color: var(--text-secondary);
    cursor: pointer;
    transition: background 0.12s, color 0.12s, border-color 0.12s;
  }
  .drawer-action-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
    border-color: var(--accent);
  }
  .drawer-action-btn svg {
    flex-shrink: 0;
  }
  .copy-btn {
    font-size: 10px;
    padding: 1px 5px;
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
    color: var(--text-muted);
    background: var(--bg-surface);
    flex-shrink: 0;
  }
  .copy-btn:hover { color: var(--accent); border-color: var(--accent); }
  .meta-badges { display: inline-flex; gap: 4px; margin-left: 4px; }
  .meta-badge {
    font-size: 10px;
    padding: 1px 4px;
    border-radius: 3px;
    background: var(--accent);
    color: #fff;
    font-weight: 600;
    letter-spacing: 0.3px;
  }
  .meta-badge.meta-badge-aich {
    background: #27ae60;
  }

  .drawer-section-divider {
    height: 1px;
    background: var(--border);
    margin: 10px 0;
  }

  /* Priority pill in the properties drawer — mirrors the table cell colors. */
  .prio-badge {
    display: inline-block;
    font-size: 11px;
    font-weight: 600;
    padding: 1px 7px;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--bg-surface);
  }
  .prio-badge.prio-verylow { color: #888; }
  .prio-badge.prio-low { color: #59b; }
  .prio-badge.prio-normal { color: var(--text-primary); }
  .prio-badge.prio-high { color: #e0a030; border-color: color-mix(in srgb, #e0a030 45%, var(--border)); }
  .prio-badge.prio-release { color: #e05050; border-color: color-mix(in srgb, #e05050 45%, var(--border)); }
  .prio-badge.prio-auto { color: #7cb342; }

  /* --- Comment panel --- */
  .comment-last-saved {
    font-size: 11px;
    color: var(--text-muted);
  }
  .comment-loading {
    color: var(--text-muted);
    font-style: italic;
    padding: 12px 2px;
  }
  .comment-our {
    margin-bottom: 10px;
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
  }
  .comment-rating-row {
    display: flex;
    align-items: center;
    gap: 3px;
    margin-bottom: 8px;
    flex-wrap: wrap;
  }
  .comment-label {
    font-size: 11px;
    color: var(--text-muted);
    margin-right: 4px;
    font-weight: 600;
  }
  .star-btn {
    background: none;
    border: none;
    cursor: pointer;
    font-size: 16px;
    color: #f1c40f;
    padding: 0 1px;
    line-height: 1;
  }
  .star-btn:hover { transform: scale(1.2); }
  .star-clear {
    background: none;
    border: none;
    cursor: pointer;
    font-size: 13px;
    color: var(--text-muted);
    margin-left: 4px;
    padding: 0 2px;
    line-height: 1;
  }
  .star-clear:hover { color: var(--danger, #e74c3c); }
  .comment-input-row {
    display: flex;
    align-items: flex-end;
    gap: 6px;
  }
  .comment-input {
    flex: 1;
    padding: 6px 8px;
    font-size: 12px;
    font-family: inherit;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-primary, #1e1e1e);
    color: inherit;
    outline: none;
    /* textarea-specific: vertical resize only with a sensible cap. */
    resize: vertical;
    min-height: 44px;
    max-height: 160px;
    line-height: 1.4;
  }
  .comment-input:focus { border-color: var(--accent, #3498db); }
  .comment-save {
    padding: 6px 12px;
    font-size: 11px;
    border: 1px solid var(--accent, #3498db);
    border-radius: 6px;
    background: var(--accent, #3498db);
    color: #fff;
    cursor: pointer;
    flex-shrink: 0;
    font-weight: 600;
  }
  .comment-save:hover { opacity: 0.85; }
  .comment-save-state {
    margin-top: 6px;
    font-size: 11px;
    color: var(--success);
    font-weight: 600;
  }
  .comment-save-state.error {
    color: var(--danger);
  }
  .comment-peers {
    margin-top: 4px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .comment-peer-item {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: color-mix(in srgb, var(--bg-secondary) 85%, var(--bg-primary));
    flex-wrap: wrap;
  }
  .comment-peer-name {
    font-weight: 600;
    color: var(--accent, #3498db);
    min-width: 60px;
  }
  .comment-peer-stars {
    color: #f1c40f;
    font-size: 13px;
    letter-spacing: 1px;
  }
  .star-display { pointer-events: none; }
  .comment-peer-text {
    color: var(--text-secondary);
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .comment-empty {
    color: var(--text-muted);
    font-style: italic;
    font-size: 11px;
    padding: 10px 2px;
  }

  /* --- Collections section --- */
  .collection-section {
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
    flex-shrink: 0;
  }
  .collection-toggle-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-right: 12px;
  }
  .collection-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    padding: 8px 16px;
    border: none;
    background: none;
    color: inherit;
    font: inherit;
    font-size: 13px;
    cursor: pointer;
    text-align: left;
  }
  .collection-toggle:hover { background: var(--bg-hover); }
  .toggle-arrow { font-size: 10px; color: var(--text-muted); flex-shrink: 0; }
  .collection-title { flex: 1; font-weight: 600; }
  .collection-meta { font-weight: 400; color: var(--text-muted); font-size: 12px; margin-left: 6px; }
  .coll-action-btn {
    padding: 3px 10px;
    font-size: 11px;
    border-radius: 3px;
    border: 1px solid var(--border);
    cursor: pointer;
    flex-shrink: 0;
  }
  .download-all-btn { background: var(--accent, #3498db); color: #fff; border-color: var(--accent, #3498db); }
  .download-all-btn:hover { opacity: 0.85; }
  .collection-files {
    max-height: 240px;
    overflow-y: auto;
    border-top: 1px solid var(--border);
  }
  .coll-loading {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 16px;
    color: var(--text-muted);
    font-size: 12px;
  }
  .coll-table { font-size: 12px; }
  .coll-table th {
    padding: 5px 10px;
    font-size: 11px;
    font-weight: 600;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    text-align: left;
    position: sticky;
    top: 0;
  }
  .coll-table td {
    padding: 4px 10px;
    border-bottom: 1px solid var(--border-light, rgba(255,255,255,0.04));
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .coll-col-size { width: 90px; text-align: right; }
  .coll-col-hash { width: 160px; font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); }

  /* --- Create Collection modal --- */
  .modal-overlay {
    position: fixed;
    inset: 0;
    z-index: 10000;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    animation: modal-fade-in 0.15s ease;
  }
  .modal-content {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow:
      inset 0 1px 0 0 rgba(255, 255, 255, 0.05),
      0 16px 48px rgba(0, 0, 0, 0.45);
    display: flex;
    flex-direction: column;
    max-height: 80vh;
    animation: modal-pop-in 0.2s ease;
  }
  @keyframes modal-fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  @keyframes modal-pop-in {
    from { opacity: 0; transform: scale(0.96); }
    to { opacity: 1; transform: scale(1); }
  }
  @media (prefers-reduced-motion: reduce) {
    .modal-overlay,
    .modal-content {
      animation: none;
    }
  }
  .create-coll-modal { width: 520px; }
  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
  }
  .modal-title { font-weight: 600; font-size: 14px; }
  .modal-close {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    padding: 0;
    cursor: pointer;
    border: 1px solid transparent;
    border-radius: 7px;
    background: none;
    color: var(--text-muted);
    transition: background 0.12s, border-color 0.12s, color 0.12s;
  }
  .modal-close:hover {
    color: var(--danger);
    border-color: color-mix(in srgb, var(--danger) 35%, var(--border));
    background: color-mix(in srgb, var(--danger) 12%, transparent);
  }
  .modal-body { padding: 16px; overflow-y: auto; flex: 1; }
  .modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 12px 16px;
    border-top: 1px solid var(--border);
  }
  .form-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 10px;
  }
  .form-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    width: 80px;
    flex-shrink: 0;
  }
  .form-input {
    flex: 1;
    padding: 5px 8px;
    font-size: 12px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-secondary);
    color: inherit;
    outline: none;
  }
  .form-input:focus { border-color: var(--accent, #3498db); }

  .format-toggle {
    display: flex;
    flex-direction: column;
    gap: 4px;
    flex: 1;
  }
  .format-option {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 6px 8px;
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
    transition: background 0.12s, border-color 0.12s;
  }
  .format-option:hover { background: var(--bg-hover); }
  .format-option input[type="radio"] { margin-top: 2px; flex-shrink: 0; cursor: pointer; }
  .format-option:has(input[type="radio"]:checked) {
    border-color: color-mix(in srgb, var(--accent) 55%, var(--border));
    background: color-mix(in srgb, var(--accent-dim) 30%, transparent);
  }
  .format-label {
    display: flex;
    flex-direction: column;
    gap: 2px;
    line-height: 1.3;
  }
  .format-name { font-size: 12px; font-weight: 600; color: var(--text-primary); }
  .format-desc { font-size: 11px; color: var(--text-muted); }

  .select-all-btn { font-size: 11px; margin-left: auto; padding: 2px 8px; }
  .coll-search-row {
    margin-bottom: 6px;
  }
  .coll-search-input {
    width: 100%;
    font-size: 12px;
  }
  .coll-file-picker {
    max-height: 260px;
    overflow-y: auto;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-secondary);
  }
  .coll-pick-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 10px;
    font-size: 12px;
    cursor: pointer;
    transition: background 0.1s;
  }
  .coll-pick-row:hover { background: var(--bg-hover); }
  .coll-pick-name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .coll-pick-size { color: var(--text-muted); flex-shrink: 0; font-size: 11px; }
  .coll-pick-empty {
    padding: 16px;
    text-align: center;
    color: var(--text-muted);
    font-size: 12px;
    font-style: italic;
  }

  @media (max-width: 640px) {
    .library-filter-row {
      align-items: stretch;
    }
    .filter-search-wrap,
    .filter-type {
      max-width: none;
      width: 100%;
    }
    .inline-stats { display: none; }
  }
</style>
