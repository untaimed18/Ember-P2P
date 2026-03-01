<script lang="ts">
  import {
    addSharedFolder,
    removeSharedFolder,
    getSharedFiles,
    getSharedFolders,
    reloadSharedFiles,
    getScanStatus,
    setFilePriority,
    unshareFile,
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

  let mounted = true;
  let busy = false;

  async function refresh() {
    if (busy || !mounted) return;
    busy = true;
    try {
      const [newFolders, newFiles, isScanning] = await Promise.all([
        getSharedFolders(),
        getSharedFiles(),
        getScanStatus(),
      ]);
      if (!mounted) return;
      folders = newFolders;
      scanning = isScanning;
      files = newFiles;
    } catch (e) {
      if (mounted && e instanceof Error)
        console.error('Failed to load shared files:', e);
    } finally {
      busy = false;
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
      await addSharedFolder(selected as string);
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
      }
    } catch (e: unknown) { error = toErr(e); }
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
    const pollInterval = setInterval(refresh, 5000);

    const unlisteners: Array<() => void> = [];
    let listenersReady = false;

    (async () => {
      unlisteners.push(await listen<{ phase: string; count: number }>(
        'shared-files-changed', () => { if (mounted) refresh(); }
      ));
      unlisteners.push(await listen<{ current: number; total: number; file_name: string; done?: boolean }>(
        'file-hash-progress', (event) => {
          if (!mounted) return;
          if (event.payload.done) {
            hashProgress = null;
            refresh();
          } else {
            hashProgress = {
              current: event.payload.current,
              total: event.payload.total,
              file_name: event.payload.file_name,
            };
          }
        }
      ));
      unlisteners.push(await listen<{ hash: string; file_name: string }>(
        'file-hashed', () => { if (mounted) refresh(); }
      ));
      listenersReady = true;
    })();

    return () => {
      mounted = false;
      clearInterval(pollInterval);
      dragCleanup?.();
      if (listenersReady) {
        for (const u of unlisteners) u();
      }
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
          <button
            class="tree-remove"
            onclick={(e) => { e.stopPropagation(); handleRemoveFolder(folder); }}
            title="Remove folder"
          >&times;</button>
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
        {#if hashProgress}
          Hashing file {hashProgress.current} of {hashProgress.total}: {hashProgress.file_name}
        {:else}
          Scanning files&hellip;
        {/if}
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
      <div class="table-scroll">
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
              <th class="col-num sortable" onclick={() => toggleSort('complete_sources')}>Complete Src.{arrow('complete_sources')}</th>
              <th class="col-shared">Shared</th>
            </tr>
          </thead>
          <tbody>
            {#each sortedFiles as file (file.hash || file.id)}
              <tr
                class:selected={selectedHash === file.hash}
                onclick={() => selectedHash = file.hash}
                oncontextmenu={(e) => onCtx(e, file)}
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
                  {:else if file.shared_kad}
                    eD2K | Kad
                  {:else}
                    eD2K
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}

    <div class="status-bar">
      <span>{filteredFiles.length} file{filteredFiles.length !== 1 ? 's' : ''} shared</span>
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
      <button class="ctx-item" role="menuitem" onclick={() => ctxAction('copy_link')}>Copy eD2k Link</button>
      <div class="ctx-sep"></div>
      <button class="ctx-item" role="menuitem" onclick={() => ctxAction('unshare')}>Unshare</button>
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
  .tree-remove {
    background: none;
    border: none;
    color: inherit;
    font-size: 14px;
    cursor: pointer;
    padding: 0 2px;
    opacity: 0;
    transition: opacity 0.15s;
  }
  .tree-item:hover .tree-remove { opacity: 0.7; }
  .tree-remove:hover { opacity: 1 !important; }

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
  .table-scroll { flex: 1; overflow: auto; }
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
  }
  .shared-table thead { position: sticky; top: 0; z-index: 2; }
  .shared-table th {
    padding: 5px 8px;
    text-align: left;
    white-space: nowrap;
    font-weight: 600;
    font-size: 11px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    user-select: none;
  }
  .shared-table th.sortable { cursor: pointer; }
  .shared-table th.sortable:hover { color: var(--accent, #3498db); }

  .shared-table td {
    padding: 4px 8px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    border-bottom: 1px solid var(--border-light, rgba(255,255,255,0.04));
  }
  .shared-table tbody tr { cursor: default; }
  .shared-table tbody tr:hover { background: var(--bg-hover); }
  .shared-table tbody tr.selected { background: var(--accent, #3498db); color: #fff; }

  .col-name { min-width: 200px; max-width: 350px; }
  .col-size { text-align: right; min-width: 80px; }
  .col-type { min-width: 60px; }
  .col-prio { min-width: 70px; }
  .col-hash { min-width: 140px; font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); }
  .col-num { text-align: right; min-width: 60px; }
  .col-folder { max-width: 200px; color: var(--text-muted); }
  .col-shared { min-width: 80px; color: var(--text-secondary); white-space: nowrap; }
  .hashing-label {
    color: var(--warning, #e0a030);
    font-style: italic;
    font-size: 11px;
    animation: pulse 1.5s ease-in-out infinite;
  }
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
