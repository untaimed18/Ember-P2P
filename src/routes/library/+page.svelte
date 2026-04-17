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
    openSharedFile,
    openSharedFolder,
  } from '$lib/api/sharing';
  import { getFileComments, setFileComment, type FileCommentInfo } from '$lib/api/comments';
  import { formatEd2kLink } from '$lib/api/search';
  import { loadCollection, createCollection, downloadCollectionFiles, type Collection, type CollectionFile } from '$lib/api/collections';
  import { toastSuccess, toastError, toastWarning } from '$lib/stores/toast';
  import { networkStats } from '$lib/stores/network';
  import { formatSize } from '$lib/utils';
  import type { FileInfo } from '$lib/types';
  import { onMount, tick } from 'svelte';

  import { listen } from '@tauri-apps/api/event';
  import LibraryVirtualTable from '$lib/components/LibraryVirtualTable.svelte';

  let folders: string[] = $state([]);
  let files: FileInfo[] = $state([]);
  let scanning = $state(false);
  let error: string | null = $state(null);
  let selectedPath: string | null = $state(null);
  let filterFolder: string | null = $state(null);
  let hashProgress: { current: number; total: number; file_name: string } | null = $state(null);
  let stoppedByUser = $state(false);
  let fileByPath = $derived.by(() => {
    const m = new Map<string, FileInfo>();
    for (const f of files) m.set(f.path, f);
    return m;
  });
  let selectedFile = $derived(selectedPath ? (fileByPath.get(selectedPath) ?? null) : null);
  let selectedHash = $derived.by(() => selectedFile?.hash || null);

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
      toastSuccess(`Loaded collection "${loadedCollection.name}" with ${loadedCollection.files.length} files`);
    } catch (e: unknown) {
      toastError(toErr(e));
      loadedCollection = null;
      collectionsOpen = false;
    } finally {
      collectionLoading = false;
    }
  }

  async function handleDownloadAll() {
    if (!loadedCollection || downloadingCollection) return;
    downloadingCollection = true;
    try {
      const msg = await downloadCollectionFiles(loadedCollection.files);
      toastSuccess(msg || `Queued ${loadedCollection.files.length} files for download`);
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
      toastSuccess(`Copied ${links.length} eD2K link${links.length !== 1 ? 's' : ''}`);
    } catch (e: unknown) {
      toastError(toErr(e));
    } finally {
      copyingCollectionLinks = false;
    }
  }

  let collectionSearch = $state('');
  let collectionFilteredFiles = $derived.by(() => {
    const q = collectionSearch.trim().toLowerCase();
    if (!q) return hashedLibraryFiles;
    return hashedLibraryFiles.filter(f => f.name.toLowerCase().includes(q));
  });

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
      toastWarning('Select at least one hashed file to build a collection.');
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
      const filterName = isBinary ? 'eMule Collection' : 'eD2K Links (Text)';
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
      toastSuccess(msg || `Created collection "${newCollName.trim()}" with ${collFiles.length} files`);
      createCollectionOpen = false;
    } catch (e: unknown) {
      toastError(toErr(e));
    } finally {
      creatingCollection = false;
    }
  }

  // --- Search / Type filter ---
  let searchQuery = $state('');
  let searchInputEl: HTMLInputElement | undefined = $state(undefined);
  const typeFilterOptions = ['All', 'Audio', 'Video', 'Image', 'Archive', 'Document', 'CD/DVD'] as const;
  type TypeFilter = (typeof typeFilterOptions)[number];
  let typeFilter: TypeFilter = $state('All');
  let showDuplicatesOnly = $state(false);
  let showMissingOnly = $state(false);
  let missingPathSet: Set<string> = $state(new Set());
  let missingScanInFlight = false;

  async function refreshMissingSet() {
    if (missingScanInFlight) return;
    missingScanInFlight = true;
    try {
      const list = await scanMissingFiles();
      if (!mounted) return;
      missingPathSet = new Set(list);
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
        `Remove ${missingPathSet.size} missing file${missingPathSet.size !== 1 ? 's' : ''} from your library?\n\nThis only affects Ember's index — no files on disk are touched.`,
        { title: 'Remove Missing Files', kind: 'warning' }
      );
      if (!confirmed) return;
      const removed = await removeMissingFiles([...missingPathSet]);
      toastSuccess(`Removed ${removed} missing file${removed !== 1 ? 's' : ''}`);
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
    if (!path) return 'All folders';
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
    return Promise.race([
      promise,
      new Promise<T>((_, reject) => setTimeout(() => reject(new Error('timeout')), ms)),
    ]);
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
      const [newFolders, newFiles, isScanning] = await withTimeout(
        Promise.all([
          getSharedFolders(),
          getSharedFiles(),
          getScanStatus(),
        ]),
        5000,
      );
      if (!mounted) return;
      folders = newFolders;
      if (!stoppedByUser) scanning = isScanning;
      files = newFiles;
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
    return e instanceof Error ? e.message : typeof e === 'string' ? e : 'Operation failed';
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

  async function handleRemoveFolder(path: string) {
    const stats = folderStats.counts.get(path) ?? 0;
    try {
      const { confirm } = await import('@tauri-apps/plugin-dialog');
      const displayName = path.split(/[\\/]/).filter(Boolean).pop() || path;
      const body = stats > 0
        ? `Remove "${displayName}" from your shared folders?\n\n${stats.toLocaleString()} file${stats !== 1 ? 's' : ''} will be removed from the index. No files on disk are touched.`
        : `Remove "${displayName}" from your shared folders?\n\nNo files on disk are touched.`;
      const confirmed = await confirm(body, { title: 'Remove Folder', kind: 'warning' });
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
    try {
      await reloadSharedFiles();
    } catch (e: unknown) {
      if (mounted) error = toErr(e);
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
      const incompleteFolders = await stopHashing();
      for (const folder of incompleteFolders) {
        try {
          await removeSharedFolder(folder);
          if (filterFolder === folder) filterFolder = null;
        } catch {}
      }
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
  let filteredFiles = $derived.by(() => {
    let result = files;
    if (filterFolder) result = result.filter(f => isPathInFolder(f.path, filterFolder!));
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      result = result.filter(f => f.name.toLowerCase().includes(q));
    }
    if (typeFilter !== 'All') {
      result = result.filter(f => fileType(f.extension) === typeFilter);
    }
    if (showDuplicatesOnly) {
      result = result.filter(f => !!f.hash && duplicateHashes.has(f.hash));
    }
    if (showMissingOnly) {
      result = result.filter(f => missingPathSet.has(f.path));
    }
    return result;
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
      await Promise.all(targets.map(f => setFilePriority(f.path, priority)));
      await refresh();
      toastSuccess(`Set priority to ${priorityLabel(priority)} for ${targets.length} file${targets.length !== 1 ? 's' : ''}`);
    } catch (e: unknown) { error = toErr(e); }
  }

  async function bulkShare() {
    const targets = getCheckedFiles().filter(f => !!f.hash && !f.shared);
    if (targets.length === 0) return;
    try {
      await Promise.all(targets.map(f => shareFile(f.path)));
      await refresh();
      toastSuccess(`Shared ${targets.length} file${targets.length !== 1 ? 's' : ''}`);
    } catch (e: unknown) { error = toErr(e); }
  }

  async function bulkUnshare() {
    const targets = getCheckedFiles().filter(f => !!f.hash && f.shared);
    if (targets.length === 0) return;
    try {
      await Promise.all(targets.map(f => unshareFile(f.path, f.hash || undefined)));
      await refresh();
      toastSuccess(`Unshared ${targets.length} file${targets.length !== 1 ? 's' : ''}`);
    } catch (e: unknown) { error = toErr(e); }
  }

  async function bulkDelete() {
    const targets = getCheckedFiles();
    if (targets.length === 0) return;
    const totalBytes = targets.reduce((sum, f) => sum + f.size, 0);
    try {
      const { confirm } = await import('@tauri-apps/plugin-dialog');
      const confirmed = await confirm(
        `Delete ${targets.length.toLocaleString()} file${targets.length !== 1 ? 's' : ''} (${formatSize(totalBytes)}) from disk?\n\nThis cannot be undone.`,
        { title: 'Delete Files', kind: 'warning' }
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
        toastSuccess(`Deleted ${deleted} file${deleted !== 1 ? 's' : ''}${failures.length ? ` (${failures.length} failed)` : ''}`);
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
        toastWarning(`Copied ${links.length} link${links.length !== 1 ? 's' : ''}, but ${unsharedCount} file${unsharedCount !== 1 ? 's are' : ' is'} not shared.`);
      } else {
        toastSuccess(`Copied ${links.length} eD2K link${links.length !== 1 ? 's' : ''}`);
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

  let sortedFiles = $derived.by(() => {
    const copy = [...filteredFiles];
    copy.sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'name': cmp = a.name.localeCompare(b.name); break;
        case 'size': cmp = a.size - b.size; break;
        case 'extension': cmp = a.extension.localeCompare(b.extension); break;
        case 'priority': cmp = (priorityOrder[a.priority] ?? 2) - (priorityOrder[b.priority] ?? 2); break;
        case 'hash': cmp = a.hash.localeCompare(b.hash); break;
        case 'requests': cmp = a.requests - b.requests; break;
        case 'accepted': cmp = a.accepted - b.accepted; break;
        case 'bytes_transferred': cmp = a.bytes_transferred - b.bytes_transferred; break;
        case 'folder': cmp = a.folder.localeCompare(b.folder); break;
        case 'complete_sources': cmp = a.complete_sources - b.complete_sources; break;
        case 'modified_at': cmp = (a.modified_at || 0) - (b.modified_at || 0); break;
      }
      return sortAsc ? cmp : -cmp;
    });
    return copy;
  });

  let folderCounts = $derived.by(() => {
    const counts = new Map<string, number>();
    const normalizedFolders = folders.map((folder) => ({
      folder,
      norm: normalizePathForMatch(folder),
    }));
    for (const { folder } of normalizedFolders) counts.set(folder, 0);
    for (const f of files) {
      const np = normalizePathForMatch(f.path);
      for (const { folder, norm } of normalizedFolders) {
        if (np === norm || np.startsWith(`${norm}/`)) {
          counts.set(folder, (counts.get(folder) ?? 0) + 1);
        }
      }
    }
    return counts;
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
    if (audioExts.has(lower)) return 'Audio';
    if (videoExts.has(lower)) return 'Video';
    if (imageExts.has(lower)) return 'Image';
    if (archiveExts.has(lower)) return 'Archive';
    if (docExts.has(lower)) return 'Document';
    if (isoExts.has(lower)) return 'CD/DVD';
    return ext ? ext.toUpperCase() : '\u2014';
  }

  function formatTransferred(session: number, alltime: number): string {
    if (session === 0 && alltime === 0) return '\u2014';
    const s = session > 0 ? formatSize(session) : '0';
    if (alltime > 0 && alltime !== session) return `${s} (${formatSize(alltime)})`;
    return s;
  }

  function priorityLabel(p: string): string {
    switch (p) {
      case 'verylow': return 'Very Low';
      case 'low': return 'Low';
      case 'normal': return 'Normal';
      case 'high': return 'High';
      case 'release': return 'Release';
      case 'auto': return 'Auto';
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
  });

  async function handleSaveComment() {
    const hash = selectedHash;
    if (!hash) return;
    commentSaveState = 'saving';
    commentSaveMessage = 'Saving...';
    try {
      await setFileComment(hash, ourRating, ourComment);
      const info = await getFileComments(hash);
      if (selectedHash !== hash) return;
      commentInfo = info;
      commentSaveState = 'saved';
      commentSaveMessage = 'Saved';
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
      commentSaveMessage = 'Save failed';
    }
  }

  // --- Context menu ---
  let ctxMenu: { x: number; y: number; file: FileInfo } | null = $state(null);
  let ctxPrioritySub = $state(false);
  let ctxMenuEl: HTMLDivElement | undefined = $state(undefined);
  let ctxSubmenuLeft = $state(false);
  let ctxSubmenuUp = $state(false);

  async function positionCtxMenu() {
    if (!ctxMenu) return;
    await tick();
    if (!ctxMenu || !ctxMenuEl) return;
    const margin = 8;
    const rect = ctxMenuEl.getBoundingClientRect();
    const x = Math.min(ctxMenu.x, Math.max(margin, window.innerWidth - rect.width - margin));
    const y = Math.min(ctxMenu.y, Math.max(margin, window.innerHeight - rect.height - margin));
    ctxSubmenuLeft = x + rect.width * 2 > window.innerWidth - margin;
    ctxSubmenuUp = y + 240 > window.innerHeight - margin;
    if (x !== ctxMenu.x || y !== ctxMenu.y) {
      ctxMenu = { ...ctxMenu, x, y };
    }
  }

  function onCtx(e: MouseEvent, f: FileInfo) {
    e.preventDefault();
    ctxPrioritySub = false;
    ctxMenu = { x: e.clientX, y: e.clientY, file: f };
    selectedPath = f.path;
    void positionCtxMenu();
  }
  function closeCtx() {
    ctxMenu = null;
    ctxPrioritySub = false;
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
        `Delete "${f.name}" from disk?\n\nThis cannot be undone.`,
        { title: 'Delete File', kind: 'warning' }
      );
      if (!confirmed) return;
      await deleteSharedFile(f.path, f.hash || undefined);
      if (selectedPath === f.path) selectedPath = null;
      toastSuccess(`Deleted "${f.name}"`);
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
        toastWarning(`Copied ${links.length} link${links.length !== 1 ? 's' : ''}, but ${unsharedCount} file${unsharedCount !== 1 ? 's are' : ' is'} not shared.`);
      } else {
        toastSuccess(`Copied ${links.length} eD2K link${links.length !== 1 ? 's' : ''}`);
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
            `Delete "${f.name}" from disk?\n\nThis cannot be undone.`,
            { title: 'Delete File', kind: 'warning' }
          );
          if (!confirmed) break;
          await deleteSharedFile(f.path, f.hash || undefined);
          if (selectedPath === f.path) selectedPath = null;
          toastSuccess(`Deleted "${f.name}"`);
          await refresh();
          break;
        }
        case 'priority': if (extra) { await setFilePriority(f.path, extra as 'verylow' | 'low' | 'normal' | 'high' | 'release' | 'auto'); await refresh(); } break;
        case 'copy_link': {
          const link = await formatEd2kLink(f.name, f.size, f.hash);
          await navigator.clipboard.writeText(link);
          if (!f.shared) {
            toastWarning('Copied link, but this file is not shared. Other peers won\'t find you as a source until you share it.');
          } else {
            toastSuccess('Copied eD2K link');
          }
          break;
        }
        case 'unshare': await unshareFile(f.path, f.hash || undefined); await refresh(); break;
        case 'share': await shareFile(f.path); await refresh(); break;
        case 'republish': {
          if (!f.hash || !f.shared) break;
          await republishFile(f.hash);
          if ($networkStats.status === 'connected') {
            toastSuccess('Queued republish to KAD');
          } else {
            toastWarning('KAD is not connected — file will be republished once the network comes online.');
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
        toastWarning(`No shared files in "${displayName}"`);
        return;
      }
      const confirmed = await confirm(
        `Unshare ${sharedCount.toLocaleString()} file${sharedCount !== 1 ? 's' : ''} in "${displayName}"?\n\nOther peers will no longer be able to download these files from you. The folder itself stays in your library.`,
        { title: 'Unshare Folder', kind: 'warning' }
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
        topPanelOpen,
        topPanelMetric,
        topPanelScope,
      }));
    } catch {}
  }

  $effect(() => {
    if (!filtersRestored) return;
    // Track dependencies explicitly so this effect re-runs when any filter/sort changes.
    void typeFilter; void filterFolder; void searchQuery; void sortField; void sortAsc; void showDuplicatesOnly;
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
      localStorage.setItem('library-sidebar-w', String(sidebarWidth));
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
      toastSuccess(
        `Added ${added} folder${added !== 1 ? 's' : ''}${failures.length ? ` (${failures.length} skipped)` : ''}`
      );
      if (mounted) await refresh();
    } else if (failures.length > 0) {
      toastWarning(failures[0]);
    }
  }

  onMount(() => {
    mounted = true;
    const saved = localStorage.getItem('library-sidebar-w');
    if (saved) {
      const val = parseInt(saved);
      if (!isNaN(val)) sidebarWidth = Math.max(120, Math.min(400, val));
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

    (async () => {
      const [u1, u2] = await Promise.all([
        listen<{ phase: string; count: number }>(
          'shared-files-changed', () => { if (mounted) debouncedRefresh(); }
        ),
        listen<{ current: number; total: number; file_name: string; done?: boolean }>(
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
        ),
      ]);
      if (destroyed) { u1(); u2(); } else { unlisteners.push(u1, u2); }
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
      if (refreshTimer) clearTimeout(refreshTimer);
      if (commentSaveTimer) {
        clearTimeout(commentSaveTimer);
        commentSaveTimer = null;
      }
      dragCleanup?.();
      for (const u of unlisteners) u();
    };
  });
</script>

<svelte:document onclick={onDocClick} onkeydown={onPageKeyDown} />

<div class="page-header">
  <h2>Library</h2>
  <div class="header-actions">
    <button class="ghost" onclick={handleOpenCollection} disabled={collectionLoading}>
      {#if collectionLoading}
        <span class="spinner-inline" aria-hidden="true"></span> Opening&hellip;
      {:else}
        Open Collection
      {/if}
    </button>
    <button class="ghost" onclick={() => openCreateDialog()}>Create Collection</button>
    <button onclick={handleReload}>Reload</button>
    <button onclick={handleAddFolder}>+ Add Folder</button>
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
        placeholder="Search files by name…  (press / to focus)"
        bind:value={searchQuery}
        bind:this={searchInputEl}
      />
      {#if searchQuery}
        <button class="filter-clear-btn" onclick={() => (searchQuery = '')} title="Clear search">✕</button>
      {/if}
    </div>
    <select class="filter-type" bind:value={typeFilter}>
      {#each typeFilterOptions as opt}
        <option value={opt}>{opt === 'All' ? 'All Types' : opt}</option>
      {/each}
    </select>
    <button
      class="dupes-toggle"
      class:active={showDuplicatesOnly}
      disabled={duplicateHashes.size === 0}
      onclick={() => (showDuplicatesOnly = !showDuplicatesOnly)}
      title={duplicateHashes.size === 0 ? 'No duplicates detected' : `Show only files whose hash matches another file (${duplicateFileCount} file${duplicateFileCount !== 1 ? 's' : ''} across ${duplicateHashes.size} hash${duplicateHashes.size !== 1 ? 'es' : ''})`}
    >
      {showDuplicatesOnly ? '\u2714' : ' '} Duplicates{duplicateHashes.size > 0 ? ` (${duplicateFileCount})` : ''}
    </button>
    <button
      class="dupes-toggle missing-toggle"
      class:active={showMissingOnly}
      disabled={missingPathSet.size === 0}
      onclick={() => (showMissingOnly = !showMissingOnly)}
      title={missingPathSet.size === 0 ? 'No indexed files are missing from disk' : `Show only files whose path no longer exists on disk (${missingPathSet.size})`}
    >
      {showMissingOnly ? '\u2714' : ' '} Missing{missingPathSet.size > 0 ? ` (${missingPathSet.size})` : ''}
    </button>
    {#if showMissingOnly && missingPathSet.size > 0}
      <button
        class="dupes-toggle missing-remove-btn"
        onclick={handleRemoveMissing}
        title="Remove all missing files from the shared index (does not touch disk)"
      >Remove Missing</button>
    {/if}
    {#if hasActiveLibraryFilters}
      <button class="ghost clear-library-filters" onclick={clearLibraryFilters}>Clear Filters</button>
    {/if}
    <span class="inline-stats">
      <span class="inline-stat">{files.length.toLocaleString()} files</span>
      <span class="inline-sep">&middot;</span>
      <span class="inline-stat">{libraryFileStats.shared.toLocaleString()} shared</span>
      <span class="inline-sep">&middot;</span>
      <span class="inline-stat">{libraryFileStats.hashed.toLocaleString()} hashed</span>
      <span class="inline-sep">&middot;</span>
      <span class="inline-stat">{folders.length.toLocaleString()} folders</span>
    </span>
  </div>
</div>

{#if loadedCollection || collectionLoading}
  <div class="collection-section">
    <div class="collection-toggle-bar">
      <button class="collection-toggle" onclick={() => collectionsOpen = !collectionsOpen}>
        <span class="toggle-arrow">{collectionsOpen ? '\u25BC' : '\u25B6'}</span>
        <span class="collection-title">
          Collection: {loadedCollection?.name ?? 'Loading\u2026'}
          {#if loadedCollection}
            <span class="collection-meta">
              by {loadedCollection.author || 'Unknown'} \u2014 {loadedCollection.files.length} file{loadedCollection.files.length !== 1 ? 's' : ''}
            </span>
          {/if}
        </span>
      </button>
      {#if loadedCollection}
        <button class="coll-action-btn download-all-btn" onclick={handleDownloadAll} disabled={downloadingCollection}>
          {downloadingCollection ? 'Queueing…' : 'Download All'}
        </button>
        <button class="coll-action-btn ghost" onclick={handleCopyCollectionLinks} disabled={copyingCollectionLinks || loadedCollection.files.length === 0} title="Copy all eD2K links to clipboard">
          {copyingCollectionLinks ? 'Copying…' : 'Copy Links'}
        </button>
        <button class="coll-action-btn ghost" onclick={() => { loadedCollection = null; collectionsOpen = false; }}>Close</button>
      {/if}
    </div>
    {#if collectionsOpen}
      <div class="collection-files">
        {#if collectionLoading}
          <div class="coll-loading"><span class="scan-spinner"></span> Loading collection&hellip;</div>
        {:else if loadedCollection}
          <table class="compact-table coll-table">
            <thead>
              <tr>
                <th>Filename</th>
                <th class="coll-col-size">Size</th>
                <th class="coll-col-hash">Hash</th>
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
        <span class="modal-title">Create Collection</span>
        <button class="ghost modal-close" onclick={() => createCollectionOpen = false}>&times;</button>
      </div>
      <div class="modal-body">
        <div class="form-row">
          <label class="form-label" for="coll-name">Name</label>
          <input
            id="coll-name"
            type="text"
            class="form-input"
            bind:value={newCollName}
            placeholder="My Collection"
            onkeydown={(e) => {
              if (e.key === 'Enter' && !!newCollName.trim() && selectedFileHashes.size > 0 && !creatingCollection) {
                e.preventDefault();
                void handleCreateCollection();
              }
            }}
          />
        </div>
        <div class="form-row">
          <label class="form-label" for="coll-author">Author</label>
          <input id="coll-author" type="text" class="form-input" bind:value={newCollAuthor} placeholder="Optional" />
        </div>
        <div class="form-row">
          <span class="form-label">Format</span>
          <div class="format-toggle">
            <label class="format-option">
              <input type="radio" name="coll-format" value="binary" bind:group={newCollFormat} />
              <span class="format-label">
                <span class="format-name">Binary (.emulecollection)</span>
                <span class="format-desc">Standard eMule collection — preserves author and name</span>
              </span>
            </label>
            <label class="format-option">
              <input type="radio" name="coll-format" value="text" bind:group={newCollFormat} />
              <span class="format-label">
                <span class="format-name">Text (.txt)</span>
                <span class="format-desc">Plain list of eD2K links — works with any client or paste target</span>
              </span>
            </label>
          </div>
        </div>
        <div class="form-row">
          <span class="form-label">Select Files ({selectedFileHashes.size} of {hashedLibraryFiles.length} selected)</span>
          <button class="ghost select-all-btn" onclick={toggleAllFileSelection}>
            {allHashedFilesSelected ? 'Deselect All' : 'Select All'}
          </button>
        </div>
        <div class="coll-search-row">
          <input
            type="text"
            class="form-input coll-search-input"
            placeholder="Search files…"
            bind:value={collectionSearch}
          />
        </div>
        <div class="coll-file-picker">
          {#each collectionFilteredFiles as f (f.path)}
            <label class="coll-pick-row">
              <input type="checkbox" checked={selectedFileHashes.has(f.hash)} onchange={() => toggleFileSelection(f.hash)} />
              <span class="coll-pick-name" title={f.name}>{f.name}</span>
              <span class="coll-pick-size">{formatSize(f.size)}</span>
            </label>
          {/each}
          {#if collectionFilteredFiles.length === 0 && hashedLibraryFiles.length > 0}
            <div class="coll-pick-empty">No files match "{collectionSearch}"</div>
          {:else if hashedLibraryFiles.length === 0}
            <div class="coll-pick-empty">No hashed files available. Add folders and wait for hashing to complete.</div>
          {/if}
        </div>
      </div>
      <div class="modal-footer">
        <button class="ghost" onclick={() => createCollectionOpen = false}>Cancel</button>
        <button
          disabled={!newCollName.trim() || selectedFileHashes.size === 0 || creatingCollection}
          onclick={handleCreateCollection}
        >
          {creatingCollection ? 'Creating\u2026' : 'Create'}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if error}
  <div class="error-banner">
    <span>{error}</span>
    <button class="ghost" onclick={() => error = null}>Dismiss</button>
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
      <div class="dnd-title">Drop folder to share</div>
      <div class="dnd-sub">Folders will be scanned and added to your library</div>
    </div>
  </div>
{/if}

<div class="shared-layout" class:dragging={sidebarDragging}>
  <!-- Sidebar: folder filter tree -->
  <div class="sidebar" style="width: {sidebarWidth}px; min-width: {sidebarWidth}px;">
    <div class="sidebar-header">Shared Folders</div>
    <div class="folder-tree">
      <div
        class="tree-item"
        class:active={filterFolder === null}
        onclick={() => filterFolder = null}
        role="button"
        tabindex="0"
        onkeydown={(e) => { if (e.key === 'Enter') filterFolder = null; }}
      >
        <span class="tree-main">
          <span class="tree-icon">◧</span>
          <span class="tree-folder-name">All Files</span>
        </span>
        <span class="tree-count">{files.length.toLocaleString()}</span>
      </div>
      {#each folders as folder (folder)}
        <div
          class="tree-item"
          class:active={filterFolder === folder}
          onclick={() => filterFolder = folder}
          role="button"
          tabindex="0"
          onkeydown={(e) => { if (e.key === 'Enter') filterFolder = folder; }}
        >
          <span class="tree-main">
            <span class="tree-icon">◨</span>
            <span class="tree-folder-name" title={folder}>
              {folder.split(/[\\/]/).filter(Boolean).pop() || folder}
            </span>
          </span>
          <span class="tree-count">{(folderCounts.get(folder) ?? 0).toLocaleString()}</span>
          <span class="tree-actions">
            <button
              class="tree-btn"
              onclick={(e) => { e.stopPropagation(); handleUnshareFolder(folder); }}
              title="Unshare all files in this folder"
            >&#x20E0;</button>
            <button
              class="tree-btn tree-remove"
              onclick={(e) => { e.stopPropagation(); handleRemoveFolder(folder); }}
              title="Remove folder"
            >&times;</button>
          </span>
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
        <span class="section-title">Top Uploads</span>
      </button>
      {#if topPanelOpen}
        <div class="top-metric-switch" role="tablist" aria-label="Top upload scope">
          <button
            type="button"
            role="tab"
            aria-selected={topPanelScope === 'alltime'}
            class:active={topPanelScope === 'alltime'}
            onclick={() => (topPanelScope = 'alltime')}
            title="Cumulative uploads across all sessions"
          >All time</button>
          <button
            type="button"
            role="tab"
            aria-selected={topPanelScope === 'session'}
            class:active={topPanelScope === 'session'}
            onclick={() => (topPanelScope = 'session')}
            title="Uploads since the app was last started"
          >Session</button>
        </div>
        <div class="top-metric-switch" role="tablist" aria-label="Top upload metric">
          <button
            type="button"
            role="tab"
            aria-selected={topPanelMetric === 'bytes'}
            class:active={topPanelMetric === 'bytes'}
            onclick={() => (topPanelMetric = 'bytes')}
          >By Bytes</button>
          <button
            type="button"
            role="tab"
            aria-selected={topPanelMetric === 'requests'}
            class:active={topPanelMetric === 'requests'}
            onclick={() => (topPanelMetric = 'requests')}
          >By Uploads</button>
        </div>
        <div class="top-list">
          {#if topFiles.length === 0}
            <div class="top-empty">
              {topPanelScope === 'session'
                ? 'No uploads yet this session. Activity resets each time Ember starts.'
                : "No upload activity yet. Files you've shared will appear here once peers start downloading."}
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
                      : `${val.toLocaleString()} upload${val !== 1 ? 's' : ''}`}
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
    aria-label="Resize sidebar"
  ></div>

  <!-- Main: file list -->
  <div class="file-list-area">
    {#if scanning || hashProgress}
      <div class="scan-banner">
        <span class="scan-spinner"></span>
        <span class="scan-text">
          {#if hashProgress}
            Hashing file {hashProgress.current} of {hashProgress.total}: {hashProgress.file_name}
          {:else}
            Scanning files&hellip;
          {/if}
        </span>
        <button class="scan-btn stop-btn" onclick={handleStopRequest}>Stop</button>
      </div>
    {/if}
    {#if stopConfirmVisible}
      <div class="confirm-banner">
        <span class="confirm-text">Stopping will remove incompletely scanned folders from the Library. Continue?</span>
        <button class="scan-btn resume-btn" onclick={handleStopCancel}>Cancel</button>
        <button class="scan-btn stop-btn" onclick={handleStopConfirm}>Remove Folder</button>
      </div>
    {/if}
    {#if stoppedByUser && !scanning && !stopConfirmVisible}
      <div class="scan-banner resume-banner">
        <span class="scan-text">Hashing was stopped.</span>
        <button class="scan-btn resume-btn" onclick={handleResume}>Resume Hashing</button>
      </div>
    {/if}
    {#if sortedFiles.length === 0 && !scanning && hasActiveLibraryFilters && files.length > 0}
      <div class="empty-state">
        <p>No files match your filters</p>
        <p class="sub"><button class="link-btn" onclick={clearLibraryFilters}>Clear Filters</button></p>
      </div>
    {:else if sortedFiles.length === 0 && !scanning}
      <div class="empty-state">
        <p>No shared files</p>
        <p class="sub">Add a folder to share files with the network</p>
        <button class="empty-action" onclick={handleAddFolder}>+ Add Folder</button>
      </div>
    {:else if sortedFiles.length === 0 && scanning}
      <div class="empty-state"><p>Waiting for scan results&hellip;</p></div>
    {:else}
      <LibraryVirtualTable
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
      />
    {/if}

    {#if checkedCount > 0}
      <div class="bulk-action-bar">
        <span class="bulk-count">{checkedCount} file{checkedCount !== 1 ? 's' : ''} selected</span>
        <div class="bulk-prio-group">
          <span class="bulk-label">Priority:</span>
          {#each ['verylow', 'low', 'normal', 'high', 'release', 'auto'] as p}
            <button class="tb-btn bulk-prio-btn" onclick={() => bulkSetPriority(p as FileInfo['priority'])} title="Set priority to {priorityLabel(p)}">{priorityLabel(p)}</button>
          {/each}
        </div>
        <button class="tb-btn" onclick={bulkShare} title="Share all selected files">Share</button>
        <button class="tb-btn" onclick={bulkUnshare} title="Unshare all selected files">Unshare</button>
        <button class="tb-btn" onclick={bulkCopyLinks} title="Copy eD2K links for selected files">Copy Links</button>
        <button class="tb-btn" onclick={openCreateDialogFromSelection} title="Create a collection from selected files">New Collection</button>
        <button class="tb-btn tb-danger" onclick={bulkDelete} title="Delete selected files from disk">Delete</button>
        <button class="tb-btn" onclick={clearChecked} title="Clear selection">Clear</button>
      </div>
    {/if}

    <div class="status-bar">
      {#if hasActiveLibraryFilters && filteredFiles.length !== files.length}
        <span>Showing {filteredFiles.length.toLocaleString()} of {files.length.toLocaleString()} files</span>
        <span class="status-sep">&middot;</span>
        <span>{filteredSharedCount.toLocaleString()} shared in view</span>
        <span class="status-sep">&middot;</span>
      {/if}
      <span>{activeFolderLabel}</span>
      {#if selectedFile}
        <span class="status-sep">&middot;</span>
        <span class="status-selected" title={selectedFile.name}>Selected: {selectedFile.name}</span>
      {/if}
    </div>
  </div>

  <!-- Side drawer for file details + comments -->
  {#if selectedFile}
    <div class="detail-drawer">
      <div class="drawer-header">
        <span class="drawer-title" title={selectedFile.name}>{selectedFile.name}</span>
        <button class="ghost drawer-close" onclick={() => selectedPath = null} title="Close details">&times;</button>
      </div>
      <div class="drawer-body">
        <div class="details-meta-grid">
          <span class="meta-label">Path</span>
          <span class="meta-value meta-path" title={selectedFile.path}>{selectedFile.path}</span>
          <span class="meta-label">Size</span>
          <span class="meta-value">{formatSize(selectedFile.size)}</span>
          {#if selectedFile.modified_at}
            <span class="meta-label">Modified</span>
            <span class="meta-value">{new Date(selectedFile.modified_at * 1000).toLocaleString()}</span>
          {/if}
          {#if selectedFile.hash}
            <span class="meta-label">Hash</span>
            <span class="meta-value meta-hash">
              <code>{selectedFile.hash}</code>
              <button class="ghost copy-btn" onclick={() => { const f = selectedFile; if (f) navigator.clipboard.writeText(f.hash).catch(() => {}); }} title="Copy hash">Copy</button>
            </span>
          {/if}
          {#if selectedFile.aich_hash}
            <span class="meta-label">AICH</span>
            <span class="meta-value meta-hash">
              <code>{selectedFile.aich_hash}</code>
              <button class="ghost copy-btn" onclick={() => { const f = selectedFile; if (f) navigator.clipboard.writeText(f.aich_hash).catch(() => {}); }} title="Copy AICH hash">Copy</button>
            </span>
          {/if}
          <span class="meta-label">Shared</span>
          <span class="meta-value">
            {selectedFile.shared ? 'Yes' : 'No'}
            {#if selectedFile.hash}
              <span class="meta-badges">
                {#if selectedFile.shared && selectedFile.shared_kad}<span class="meta-badge" title="Published to KAD network">KAD</span>{/if}
                {#if selectedFile.shared && selectedFile.shared_ed2k}<span class="meta-badge" title="Published to eD2K servers">eD2K</span>{/if}
                {#if selectedFile.aich_hash}<span class="meta-badge meta-badge-aich" title="AICH hash available — bad chunks can be identified without re-downloading the whole file">AICH</span>{/if}
              </span>
            {/if}
          </span>
          <span class="meta-label">Requests</span>
          <span class="meta-value">{selectedFile.requests}{selectedFile.alltime_requests ? ` (${selectedFile.alltime_requests} all-time)` : ''}</span>
          <span class="meta-label">Accepted</span>
          <span class="meta-value">{selectedFile.accepted}{selectedFile.alltime_accepted ? ` (${selectedFile.alltime_accepted} all-time)` : ''}</span>
          <span class="meta-label">Transferred</span>
          <span class="meta-value">{formatSize(selectedFile.bytes_transferred)}{selectedFile.alltime_transferred ? ` (${formatSize(selectedFile.alltime_transferred)} all-time)` : ''}</span>
          {#if selectedFile.complete_sources > 0}
            <span class="meta-label">Peers</span>
            <span class="meta-value" title="KAD peers that have acknowledged a source record or known complete copies">
              {selectedFile.complete_sources.toLocaleString()} with a copy
            </span>
          {/if}
        </div>

        {#if selectedHash}
          <div class="drawer-section">
            <div class="drawer-section-header">
              <span class="drawer-section-title">Comments &amp; Rating</span>
              {#if commentLastSavedAt}
                <span class="comment-last-saved">Saved {formatSavedTime(commentLastSavedAt)}</span>
              {/if}
            </div>
            {#if commentLoading}
              <div class="comment-loading">Loading comments&hellip;</div>
            {:else}
              <div class="comment-our">
                <div class="comment-rating-row">
                  <span class="comment-label">Your rating:</span>
                  {#each [1,2,3,4,5] as star}
                    <button class="star-btn" onclick={() => ourRating = star} title="{star} star{star > 1 ? 's' : ''}">
                      {star <= ourRating ? '\u2605' : '\u2606'}
                    </button>
                  {/each}
                  {#if ourRating > 0}
                    <button class="star-clear" onclick={() => ourRating = 0} title="Clear rating">&times;</button>
                  {/if}
                </div>
                <div class="comment-input-row">
                  <input
                    type="text"
                    class="comment-input"
                    placeholder="Add a comment…"
                    bind:value={ourComment}
                    onkeydown={(e) => { if (e.key === 'Enter') handleSaveComment(); }}
                  />
                  <button class="comment-save" onclick={handleSaveComment} disabled={commentSaveState === 'saving'}>
                    {commentSaveState === 'saving' ? 'Saving\u2026' : 'Save'}
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
                  <div class="comment-label">Peer comments:</div>
                  {#each commentInfo.peer_comments as pc, i (i)}
                    <div class="comment-peer-item">
                      <span class="comment-peer-name">{pc.user_name}</span>
                      <span class="comment-peer-stars">
                        {#each [1,2,3,4,5] as s}
                          <span class="star-display">{s <= pc.rating ? '\u2605' : '\u2606'}</span>
                        {/each}
                      </span>
                      {#if pc.comment}
                        <span class="comment-peer-text">{pc.comment}</span>
                      {/if}
                    </div>
                  {/each}
                </div>
              {:else}
                <div class="comment-empty">No peer comments yet.</div>
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
    <button class="ctx-item" role="menuitem" onclick={() => ctxAction('open_file')}>Open File</button>
    <button class="ctx-item" role="menuitem" onclick={() => ctxAction('open_folder')}>Open Folder</button>
    <button class="ctx-item ctx-danger" role="menuitem" onclick={() => ctxAction('delete')}>Delete File</button>
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
        Priority &raquo;
        {#if ctxPrioritySub}
          <div class="ctx-submenu" class:ctx-submenu-left={ctxSubmenuLeft} class:ctx-submenu-up={ctxSubmenuUp} role="menu">
            <button class="ctx-item" role="menuitem" class:ctx-checked={ctxMenu.file.priority === 'verylow'} onclick={() => ctxAction('priority', 'verylow')}>Very Low</button>
            <button class="ctx-item" role="menuitem" class:ctx-checked={ctxMenu.file.priority === 'low'} onclick={() => ctxAction('priority', 'low')}>Low</button>
            <button class="ctx-item" role="menuitem" class:ctx-checked={ctxMenu.file.priority === 'normal'} onclick={() => ctxAction('priority', 'normal')}>Normal</button>
            <button class="ctx-item" role="menuitem" class:ctx-checked={ctxMenu.file.priority === 'high'} onclick={() => ctxAction('priority', 'high')}>High</button>
            <button class="ctx-item" role="menuitem" class:ctx-checked={ctxMenu.file.priority === 'release'} onclick={() => ctxAction('priority', 'release')}>Release</button>
            <div class="ctx-sep"></div>
            <button class="ctx-item" role="menuitem" class:ctx-checked={ctxMenu.file.priority === 'auto'} onclick={() => ctxAction('priority', 'auto')}>Auto</button>
          </div>
        {/if}
      </div>
      <div class="ctx-sep"></div>
      <button class="ctx-item" role="menuitem" onclick={() => ctxAction('copy_link')}>Copy eD2K Link</button>
      <div class="ctx-sep"></div>
      {#if ctxMenu.file.shared}
        <button
          class="ctx-item"
          role="menuitem"
          onclick={() => ctxAction('republish')}
          title={$networkStats.status === 'connected'
            ? 'Reset publish timers so this file is re-published to the KAD network on the next cycle'
            : 'KAD is not connected — republish will be deferred until the network comes online'}
        >Republish to KAD{$networkStats.status !== 'connected' ? ' (offline)' : ''}</button>
        <button class="ctx-item" role="menuitem" onclick={() => ctxAction('unshare')}>Unshare File</button>
      {:else}
        <button class="ctx-item" role="menuitem" onclick={() => ctxAction('share')}>Share File</button>
      {/if}
    {:else}
      <button class="ctx-item ctx-disabled" role="menuitem" disabled>Hashing in progress&hellip;</button>
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
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 6px 8px;
    margin-bottom: 4px;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    font-size: 12px;
    cursor: pointer;
    color: var(--text-secondary);
    transition: background 0.12s, border-color 0.12s, color 0.12s;
  }
  .tree-item:hover {
    background: var(--bg-hover);
    border-color: var(--border);
  }
  .tree-item.active {
    background: color-mix(in srgb, var(--accent-dim) 55%, transparent);
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
    color: var(--text-primary);
    font-weight: 600;
  }
  .tree-main {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    min-width: 0;
    flex: 1;
  }
  .tree-icon {
    width: 16px;
    text-align: center;
    color: var(--text-muted);
    font-size: 11px;
    flex-shrink: 0;
  }
  .tree-item.active .tree-icon {
    color: var(--text-accent);
  }
  .tree-folder-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }
  .tree-count {
    font-size: 11px;
    color: var(--text-muted);
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 1px 7px;
    line-height: 1.4;
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
    opacity: 0;
    transition: opacity 0.12s;
    flex-shrink: 0;
  }
  .tree-item:hover .tree-actions,
  .tree-item.active .tree-actions {
    opacity: 1;
  }
  .tree-btn {
    width: 20px;
    height: 20px;
    border-radius: 4px;
    border: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-secondary);
    font-size: 12px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    line-height: 1;
  }
  .tree-btn.tree-remove { font-size: 13px; }
  .tree-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
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
    width: 320px;
    min-width: 260px;
    max-width: 420px;
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
    font-size: 16px;
    line-height: 1;
    width: 22px;
    height: 22px;
    padding: 0;
    cursor: pointer;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-surface);
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .drawer-close:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
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
    background: color-mix(in srgb, var(--accent-dim) 30%, var(--bg-secondary));
    padding: 6px 12px;
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
    margin-right: 4px;
  }
  .bulk-label {
    color: var(--text-muted);
    font-size: 11px;
  }
  .bulk-prio-group {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .bulk-prio-btn { font-size: 11px; padding: 2px 6px; }
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
    gap: 6px;
  }
  .comment-input {
    flex: 1;
    padding: 4px 8px;
    font-size: 12px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-primary, #1e1e1e);
    color: inherit;
    outline: none;
  }
  .comment-input:focus { border-color: var(--accent, #3498db); }
  .comment-save {
    padding: 4px 12px;
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
    font-size: 18px;
    line-height: 1;
    padding: 0 4px;
    cursor: pointer;
    border: none;
    background: none;
    color: var(--text-muted);
  }
  .modal-close:hover { color: var(--text-primary); }
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
