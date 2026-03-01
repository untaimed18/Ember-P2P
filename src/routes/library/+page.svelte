<script lang="ts">
  import {
    addSharedFolder,
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
  import { formatEd2kLink } from '$lib/api/search';
  import { formatSize } from '$lib/utils';
  import type { FileInfo } from '$lib/types';
  import { onMount } from 'svelte';

  import { listen } from '@tauri-apps/api/event';

  let folders: string[] = $state([]);
  let files: FileInfo[] = $state([]);
  let scanning = $state(false);
  let error: string | null = $state(null);
  let selectedHash: string | null = $state(null);
  let filterFolder: string | null = $state(null);
  let hashProgress: { current: number; total: number; file_name: string } | null = $state(null);
  let stoppedByUser = $state(false);

  let mounted = true;
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
    error = null;
    try {
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

  async function handleStopHashing() {
    scanning = false;
    hashProgress = null;
    stoppedByUser = true;
    try {
      await stopHashing();
    } catch (e: unknown) {
      if (mounted) error = toErr(e);
    }
  }

  async function handleResumeHashing() {
    try {
      stoppedByUser = false;
      await resumeHashing();
    } catch (e: unknown) {
      if (mounted) error = toErr(e);
    }
  }

  let hasUnhashedFiles = $derived(files.some(f => !f.hash));

  // --- Filtering ---
  let filteredFiles = $derived.by(() => {
    if (!filterFolder) return files;
    return files.filter(f => f.path.startsWith(filterFolder!));
  });

  // --- Sorting ---
  type SortField = 'name' | 'size' | 'extension' | 'priority' | 'hash' | 'requests' | 'accepted' | 'bytes_transferred' | 'folder' | 'complete_sources';
  let sortField: SortField = $state('name');
  let sortAsc = $state(true);

  function toggleSort(field: SortField) {
    if (sortField === field) sortAsc = !sortAsc;
    else { sortField = field; sortAsc = true; }
  }
  function arrow(field: string): string {
    if (sortField !== field) return '';
    return sortAsc ? ' \u25B2' : ' \u25BC';
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
      }
      return sortAsc ? cmp : -cmp;
    });
    return copy;
  });

  // --- File type display ---
  function fileType(ext: string): string {
    const lower = ext.toLowerCase();
    const audio = ['mp3', 'ogg', 'wav', 'wma', 'flac', 'aac', 'm4a', 'opus'];
    const video = ['avi', 'mkv', 'mp4', 'wmv', 'mov', 'mpg', 'mpeg', 'flv', 'webm'];
    const image = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg'];
    const archive = ['zip', 'rar', '7z', 'tar', 'gz'];
    const doc = ['doc', 'docx', 'pdf', 'txt', 'xls', 'xlsx', 'ppt', 'pptx'];
    const iso = ['iso', 'bin', 'img', 'nrg'];
    if (audio.includes(lower)) return 'Audio';
    if (video.includes(lower)) return 'Video';
    if (image.includes(lower)) return 'Image';
    if (archive.includes(lower)) return 'Archive';
    if (doc.includes(lower)) return 'Document';
    if (iso.includes(lower)) return 'CD/DVD';
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

  // --- Context menu ---
  let ctxMenu: { x: number; y: number; file: FileInfo } | null = $state(null);
  let ctxPrioritySub = $state(false);

  function onCtx(e: MouseEvent, f: FileInfo) {
    e.preventDefault();
    ctxPrioritySub = false;
    ctxMenu = { x: e.clientX, y: e.clientY, file: f };
    selectedHash = f.hash;
  }
  function closeCtx() { ctxMenu = null; ctxPrioritySub = false; }
  function onDocClick() { if (mounted) closeCtx(); }

  async function ctxAction(action: string, extra?: string) {
    if (!ctxMenu) return;
    const f = ctxMenu.file;
    closeCtx();
    try {
      switch (action) {
        case 'open_file': await openSharedFile(f.path); break;
        case 'open_folder': await openSharedFolder(f.path); break;
        case 'priority': if (extra) { await setFilePriority(f.hash, extra); await refresh(); } break;
        case 'copy_link': {
          const link = await formatEd2kLink(f.name, f.size, f.hash);
          await navigator.clipboard.writeText(link);
          break;
        }
        case 'unshare': await unshareFile(f.hash); await refresh(); break;
        case 'share': await shareFile(f.hash); await refresh(); break;
        case 'unshare_folder': if (f.folder) { await unshareFolder(f.folder); await refresh(); } break;
      }
    } catch (e: unknown) { error = toErr(e); }
  }

  async function handleUnshareFolder(path: string) {
    try {
      await unshareFolder(path);
      await refresh();
    } catch (e: unknown) { error = toErr(e); }
  }

  // --- Virtual scroll ---
  const ROW_HEIGHT = 28;
  const OVERSCAN = 10;
  let scrollContainer: HTMLDivElement | undefined = $state(undefined);
  let scrollTop = $state(0);
  let viewportHeight = $state(600);

  let virtualSlice = $derived.by(() => {
    const totalRows = sortedFiles.length;
    if (totalRows === 0) return { startIdx: 0, endIdx: 0, topPad: 0, bottomPad: 0, visible: [] as FileInfo[] };
    const firstVisible = Math.floor(scrollTop / ROW_HEIGHT);
    const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT);
    const startIdx = Math.max(0, firstVisible - OVERSCAN);
    const endIdx = Math.min(totalRows, firstVisible + visibleCount + OVERSCAN);
    return {
      startIdx,
      endIdx,
      topPad: startIdx * ROW_HEIGHT,
      bottomPad: (totalRows - endIdx) * ROW_HEIGHT,
      visible: sortedFiles.slice(startIdx, endIdx),
    };
  });

  function onTableScroll(e: Event) {
    const el = e.target as HTMLDivElement;
    scrollTop = el.scrollTop;
    viewportHeight = el.clientHeight;
  }

  // --- Sidebar resize ---
  let sidebarWidth = $state(200);
  let sidebarDragging = $state(false);
  let dragCleanup: (() => void) | null = null;

  function onSidebarDown(e: MouseEvent) {
    e.preventDefault();
    sidebarDragging = true;
    const onMove = (ev: MouseEvent) => {
      if (!mounted) return;
      sidebarWidth = Math.max(120, Math.min(400, ev.clientX));
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

  onMount(() => {
    mounted = true;
    const saved = localStorage.getItem('library-sidebar-w');
    if (saved) {
      const val = parseInt(saved);
      if (!isNaN(val)) sidebarWidth = Math.max(120, Math.min(400, val));
    }

    refresh();

    const resizeObs = new ResizeObserver((entries) => {
      for (const entry of entries) {
        viewportHeight = entry.contentRect.height;
      }
    });
    if (scrollContainer) resizeObs.observe(scrollContainer);
    const checkContainer = setInterval(() => {
      if (scrollContainer && !resizeObs.observe) return;
      if (scrollContainer) { resizeObs.observe(scrollContainer); clearInterval(checkContainer); }
    }, 100);

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

    (async () => {
      unlisteners.push(await listen<{ phase: string; count: number }>(
        'shared-files-changed', () => { if (mounted) debouncedRefresh(); }
      ));
      unlisteners.push(await listen<{ current: number; total: number; file_name: string; done?: boolean }>(
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
      ));
    })();

    return () => {
      mounted = false;
      clearInterval(scanPoll);
      clearInterval(checkContainer);
      resizeObs.disconnect();
      if (refreshTimer) clearTimeout(refreshTimer);
      dragCleanup?.();
      for (const u of unlisteners) u();
    };
  });
</script>

<svelte:document onclick={onDocClick} />

<div class="page-header">
  <h2>Library</h2>
  <div class="header-actions">
    <button onclick={handleReload}>Reload</button>
    <button onclick={handleAddFolder}>+ Add Folder</button>
  </div>
</div>

{#if error}
  <div class="error-banner">
    <span>{error}</span>
    <button class="ghost" onclick={() => error = null}>Dismiss</button>
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
        All Files ({files.length})
      </div>
      {#each folders as folder}
        <div
          class="tree-item"
          class:active={filterFolder === folder}
          onclick={() => filterFolder = folder}
          role="button"
          tabindex="0"
          onkeydown={(e) => { if (e.key === 'Enter') filterFolder = folder; }}
        >
          <span class="tree-folder-name" title={folder}>
            {folder.split(/[\\/]/).filter(Boolean).pop() || folder}
          </span>
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
  </div>

  <!-- Sidebar resize handle -->
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="sidebar-divider" onmousedown={onSidebarDown} role="separator"></div>

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
        <button class="scan-btn stop-btn" onclick={handleStopHashing}>Stop</button>
      </div>
    {:else if hasUnhashedFiles && !scanning}
      <div class="scan-banner resume-banner">
        <span class="scan-text">Hashing incomplete &mdash; some files are pending</span>
        <button class="scan-btn resume-btn" onclick={handleResumeHashing}>Resume</button>
      </div>
    {/if}
    {#if sortedFiles.length === 0 && !scanning}
      <div class="empty-state">
        <p>No shared files</p>
        <p class="sub">Click "Add Folder" to share files with the network</p>
      </div>
    {:else if sortedFiles.length === 0 && scanning}
      <div class="empty-state"><p>Waiting for scan results&hellip;</p></div>
    {:else}
      <div class="vtable-header">
        <table class="shared-table">
          <thead>
            <tr>
              <th class="col-name sortable" onclick={() => toggleSort('name')}>Filename{arrow('name')}</th>
              <th class="col-size sortable" onclick={() => toggleSort('size')}>Size{arrow('size')}</th>
              <th class="col-type sortable" onclick={() => toggleSort('extension')}>Type{arrow('extension')}</th>
              <th class="col-prio sortable" onclick={() => toggleSort('priority')}>Priority{arrow('priority')}</th>
              <th class="col-hash">File ID</th>
              <th class="col-num sortable" onclick={() => toggleSort('requests')}>Requests{arrow('requests')}</th>
              <th class="col-num sortable" onclick={() => toggleSort('accepted')}>Accepted{arrow('accepted')}</th>
              <th class="col-size sortable" onclick={() => toggleSort('bytes_transferred')}>Transferred{arrow('bytes_transferred')}</th>
              <th class="col-folder sortable" onclick={() => toggleSort('folder')}>Folder{arrow('folder')}</th>
              <th class="col-num sortable" onclick={() => toggleSort('complete_sources')}>Sources{arrow('complete_sources')}</th>
              <th class="col-shared">Shared</th>
            </tr>
          </thead>
        </table>
      </div>
      <div class="vtable-scroll" bind:this={scrollContainer} onscroll={onTableScroll}>
        <div style="height:{sortedFiles.length * ROW_HEIGHT}px; position:relative;">
          <table class="shared-table vtable-body" style="transform:translateY({virtualSlice.topPad}px);">
            <tbody>
              {#each virtualSlice.visible as file (file.hash || file.id)}
                <tr
                  class:selected={selectedHash === file.hash}
                  onclick={() => selectedHash = file.hash}
                  oncontextmenu={(e) => onCtx(e, file)}
                  style="height:{ROW_HEIGHT}px;"
                >
                  <td class="col-name" title={file.path}>{file.name}</td>
                  <td class="col-size">{formatSize(file.size)}</td>
                  <td class="col-type">{fileType(file.extension)}</td>
                  <td class="col-prio prio-{file.priority}">{priorityLabel(file.priority)}</td>
                  <td class="col-hash" title={file.hash || 'Hashing...'}>
                    {#if file.hash}
                      {file.hash.substring(0, 16)}&hellip;
                    {:else}
                      <span class="hashing-label">Hashing&hellip;</span>
                    {/if}
                  </td>
                  <td class="col-num">{file.requests}{file.alltime_requests ? ` (${file.alltime_requests})` : ''}</td>
                  <td class="col-num">{file.accepted}{file.alltime_accepted ? ` (${file.alltime_accepted})` : ''}</td>
                  <td class="col-size">{formatTransferred(file.bytes_transferred, file.alltime_transferred)}</td>
                  <td class="col-folder" title={file.folder}>{file.folder.split(/[\\/]/).filter(Boolean).pop() || file.folder}</td>
                  <td class="col-num">{file.complete_sources || '\u2014'}</td>
                  <td class="col-shared">
                    {#if !file.hash}
                      <span class="hashing-label">Pending</span>
                    {:else if file.shared}
                      <span class="shared-icon shared-yes" title="Shared">&#x2713;</span>
                      {#if file.shared_kad || file.shared_ed2k}
                        <span class="shared-badges">
                          {#if file.shared_kad}<span class="shared-badge kad">KAD</span>{/if}
                          {#if file.shared_ed2k}<span class="shared-badge ed2k">eD2K</span>{/if}
                        </span>
                      {/if}
                    {:else}
                      <span class="shared-icon shared-no" title="Not shared">&#x2715;</span>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    {/if}

    <div class="status-bar">
      <span>{filteredFiles.length} file{filteredFiles.length !== 1 ? 's' : ''} ({filteredFiles.filter(f => f.shared).length} shared)</span>
    </div>
  </div>
</div>

<!-- Context menu -->
{#if ctxMenu}
  {@const fileHashed = !!ctxMenu.file.hash}
  <div class="ctx-menu" style="left:{ctxMenu.x}px;top:{ctxMenu.y}px;" role="menu">
    <button class="ctx-item" role="menuitem" onclick={() => ctxAction('open_file')}>Open File</button>
    <button class="ctx-item" role="menuitem" onclick={() => ctxAction('open_folder')}>Open Folder</button>
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
          <div class="ctx-submenu" role="menu">
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
  /* --- Layout --- */
  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
  }
  .page-header h2 { margin: 0; font-size: 16px; }
  .header-actions { display: flex; gap: 8px; }

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
  }
  .sidebar-header {
    padding: 8px 12px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border);
  }
  .folder-tree { flex: 1; overflow-y: auto; padding: 4px 0; }
  .tree-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 5px 12px;
    font-size: 12px;
    cursor: pointer;
    color: var(--text-secondary);
    transition: background 0.1s;
  }
  .tree-item:hover { background: var(--bg-hover); }
  .tree-item.active { background: var(--accent, #3498db); color: #fff; }
  .tree-folder-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    flex: 1;
  }
  .tree-actions { display: flex; gap: 2px; flex-shrink: 0; }
  .tree-btn {
    background: none;
    border: none;
    color: inherit;
    font-size: 12px;
    cursor: pointer;
    padding: 0 2px;
    opacity: 0;
    transition: opacity 0.15s;
    line-height: 1;
  }
  .tree-btn.tree-remove { font-size: 14px; }
  .tree-item:hover .tree-btn { opacity: 0.7; }
  .tree-btn:hover { opacity: 1 !important; }

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
    overflow: hidden;
  }
  .vtable-header {
    flex-shrink: 0;
    overflow: hidden;
  }
  .vtable-header table { margin-bottom: 0; }
  .vtable-scroll {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
    min-height: 0;
  }
  .vtable-body { position: absolute; left: 0; right: 0; }
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

  .status-bar {
    padding: 4px 12px;
    font-size: 11px;
    color: var(--text-muted);
    border-top: 1px solid var(--border);
    background: var(--bg-secondary);
  }

  /* --- Table --- */
  .shared-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    table-layout: fixed;
  }
  .shared-table th {
    padding: 5px 8px;
    text-align: left;
    white-space: nowrap;
    font-weight: 600;
    font-size: 11px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    user-select: none;
    box-sizing: border-box;
  }
  .shared-table th.sortable { cursor: pointer; }
  .shared-table th.sortable:hover { color: var(--accent, #3498db); }

  .shared-table td {
    padding: 4px 8px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    border-bottom: 1px solid var(--border-light, rgba(255,255,255,0.04));
    box-sizing: border-box;
  }
  .shared-table tbody tr { cursor: default; box-sizing: border-box; }
  .shared-table tbody tr:hover { background: var(--bg-hover); }
  .shared-table tbody tr.selected { background: var(--accent, #3498db); color: #fff; }

  .col-name { width: 22%; }
  .col-size { width: 7%; text-align: right; }
  .col-type { width: 6%; }
  .col-prio { width: 7%; }
  .col-hash { width: 13%; font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); }
  .col-num { width: 6%; text-align: right; }
  .col-folder { width: 12%; color: var(--text-muted); }
  .col-shared { width: 9%; color: var(--text-secondary); white-space: nowrap; }
  .hashing-label {
    color: var(--warning, #e0a030);
    font-style: italic;
    font-size: 11px;
    animation: pulse 1.5s ease-in-out infinite;
  }
  .shared-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    font-size: 11px;
    font-weight: 700;
    vertical-align: middle;
  }
  .shared-yes { background: rgba(46, 204, 113, 0.2); color: #2ecc71; }
  .shared-no { background: rgba(200, 200, 200, 0.15); color: var(--text-muted); font-size: 9px; }
  .shared-badges { display: inline-flex; gap: 3px; margin-left: 4px; vertical-align: middle; }
  .shared-badge {
    font-size: 9px;
    font-weight: 600;
    padding: 0 4px;
    border-radius: 3px;
    line-height: 15px;
  }
  .shared-badge.kad { background: rgba(52, 152, 219, 0.15); color: #3498db; }
  .shared-badge.ed2k { background: rgba(155, 89, 182, 0.15); color: #9b59b6; }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  /* Priority colors */
  .prio-verylow { color: #888; }
  .prio-low { color: #59b; }
  .prio-normal { color: var(--text-primary); }
  .prio-high { color: #e0a030; }
  .prio-release { color: #e05050; font-weight: 600; }
  .prio-auto { color: #7cb342; }

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
</style>
