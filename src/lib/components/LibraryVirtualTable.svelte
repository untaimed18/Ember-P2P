<script lang="ts">
  import type { FileInfo } from '$lib/types';
  import { passiveScroll } from '$lib/actions/passiveScroll';
  import { formatSize } from '$lib/utils';
  import { onMount, untrack } from 'svelte';

  type SortField =
    | 'name'
    | 'size'
    | 'extension'
    | 'priority'
    | 'hash'
    | 'requests'
    | 'accepted'
    | 'bytes_transferred'
    | 'folder'
    | 'complete_sources'
    | 'modified_at';

  type LibraryColumn = {
    key: string;
    label: string;
    width: number;
    minWidth: number;
    sortField?: SortField;
  };

  const ALL_COLUMNS: LibraryColumn[] = [
    { key: 'name',        label: 'Filename',    width: 280, minWidth: 140, sortField: 'name' },
    { key: 'size',        label: 'Size',        width: 75,  minWidth: 56,  sortField: 'size' },
    { key: 'type',        label: 'Type',        width: 70,  minWidth: 56,  sortField: 'extension' },
    { key: 'priority',    label: 'Priority',    width: 72,  minWidth: 60,  sortField: 'priority' },
    { key: 'transferred', label: 'Transferred', width: 90,  minWidth: 60,  sortField: 'bytes_transferred' },
    { key: 'sources',     label: 'Peers',       width: 60,  minWidth: 50,  sortField: 'complete_sources' },
    { key: 'shared',      label: 'Shared',      width: 80,  minWidth: 60 },
    { key: 'hash',        label: 'File ID',     width: 120, minWidth: 80,  sortField: 'hash' },
    { key: 'requests',    label: 'Requests',    width: 70,  minWidth: 50,  sortField: 'requests' },
    { key: 'accepted',    label: 'Accepted',    width: 70,  minWidth: 50,  sortField: 'accepted' },
    { key: 'folder',      label: 'Folder',      width: 100, minWidth: 60,  sortField: 'folder' },
    { key: 'modified',    label: 'Modified',    width: 100, minWidth: 80,  sortField: 'modified_at' },
  ];

  const DEFAULT_HIDDEN = new Set(['hash', 'requests', 'accepted', 'folder']);
  const FIXED_KEY = 'name';
  const STORAGE_WIDTHS = 'library-col-widths';
  const STORAGE_HIDDEN = 'library-col-hidden';
  const STORAGE_ORDER = 'library-col-order';

  function formatDate(ts: number): string {
    if (!ts) return '\u2014';
    return new Date(ts * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  let {
    sortedFiles,
    selectedPath,
    onSelectPath,
    onOpenFile,
    onRowContextMenu,
    fileType,
    priorityLabel,
    formatTransferred,
    toggleSort,
    sortOnKey,
    arrow,
    ariaSort,
    checkedPaths = new Set<string>(),
    allChecked = false,
    someChecked = false,
    onToggleCheck,
    onToggleCheckAll,
  }: {
    sortedFiles: FileInfo[];
    selectedPath: string | null;
    onSelectPath: (path: string) => void;
    onOpenFile: (path: string) => void;
    onRowContextMenu: (e: MouseEvent, file: FileInfo) => void;
    fileType: (ext: string) => string;
    priorityLabel: (p: string) => string;
    formatTransferred: (session: number, alltime: number) => string;
    toggleSort: (field: SortField) => void;
    sortOnKey: (e: KeyboardEvent, field: SortField) => void;
    arrow: (field: string) => string;
    ariaSort: (field: string) => 'ascending' | 'descending' | 'none';
    checkedPaths?: Set<string>;
    allChecked?: boolean;
    someChecked?: boolean;
    onToggleCheck?: (path: string, shiftKey: boolean) => void;
    onToggleCheckAll?: () => void;
  } = $props();

  // --- Virtualization ---
  const ROW_HEIGHT = 28;
  const OVERSCAN = 10;

  let scrollContainer: HTMLDivElement | undefined = $state(undefined);
  let headerWrap: HTMLDivElement | undefined = $state(undefined);
  let scrollTop = $state(0);
  let viewportHeight = $state(600);
  let scrollbarWidth = $state(0);

  let scrollRaf = 0;
  let lastScrollEl: HTMLDivElement | null = null;

  function onTableScroll(e: Event) {
    lastScrollEl = e.target as HTMLDivElement;
    if (scrollRaf) return;
    scrollRaf = requestAnimationFrame(() => {
      scrollRaf = 0;
      if (lastScrollEl) {
        scrollTop = lastScrollEl.scrollTop;
        if (headerWrap) headerWrap.scrollLeft = lastScrollEl.scrollLeft;
      }
    });
  }

  let virtualSlice = $derived.by(() => {
    const totalRows = sortedFiles.length;
    if (totalRows === 0) return { startIdx: 0, endIdx: 0, topPad: 0, visible: [] as FileInfo[] };
    const firstVisible = Math.floor(scrollTop / ROW_HEIGHT);
    const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT);
    const startIdx = Math.max(0, firstVisible - OVERSCAN);
    const endIdx = Math.min(totalRows, firstVisible + visibleCount + OVERSCAN);
    return {
      startIdx,
      endIdx,
      topPad: startIdx * ROW_HEIGHT,
      visible: sortedFiles.slice(startIdx, endIdx),
    };
  });

  $effect(() => {
    const maxScroll = Math.max(0, sortedFiles.length * ROW_HEIGHT - viewportHeight);
    const current = untrack(() => scrollTop);
    if (current > maxScroll) {
      scrollTop = maxScroll;
      if (scrollContainer) scrollContainer.scrollTop = maxScroll;
    }
  });

  $effect(() => {
    const el = scrollContainer;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        viewportHeight = entry.contentRect.height;
        const t = entry.target as HTMLElement;
        scrollbarWidth = t.offsetWidth - t.clientWidth;
      }
    });
    ro.observe(el);
    viewportHeight = el.clientHeight;
    scrollbarWidth = el.offsetWidth - el.clientWidth;
    return () => ro.disconnect();
  });

  // --- Column state ---
  let colWidths = $state<Record<string, number>>(
    Object.fromEntries(ALL_COLUMNS.map(c => [c.key, c.width]))
  );
  let colHidden = $state<Record<string, boolean>>(
    Object.fromEntries(ALL_COLUMNS.map(c => [c.key, DEFAULT_HIDDEN.has(c.key)]))
  );
  let colOrder = $state<string[]>(ALL_COLUMNS.map(c => c.key));

  function safeGet(key: string): string | null {
    try { return localStorage.getItem(key); } catch { return null; }
  }

  function loadColumnState() {
    const savedWidths = safeGet(STORAGE_WIDTHS);
    if (savedWidths) {
      try {
        const parsed = JSON.parse(savedWidths) as Record<string, unknown>;
        for (const col of ALL_COLUMNS) {
          const w = parsed[col.key];
          if (typeof w === 'number' && Number.isFinite(w)) {
            colWidths[col.key] = Math.max(col.minWidth, Math.round(w));
          }
        }
      } catch { localStorage.removeItem(STORAGE_WIDTHS); }
    }

    const savedOrder = safeGet(STORAGE_ORDER);
    if (savedOrder) {
      try {
        const parsed = JSON.parse(savedOrder);
        if (Array.isArray(parsed)) colOrder = sanitizeOrder(parsed);
      } catch { localStorage.removeItem(STORAGE_ORDER); }
    }

    const savedHidden = safeGet(STORAGE_HIDDEN);
    if (savedHidden) {
      try {
        const parsed = JSON.parse(savedHidden);
        colHidden = Object.fromEntries(ALL_COLUMNS.map(c => [c.key, false]));
        if (Array.isArray(parsed)) {
          for (const k of parsed) {
            if (typeof k === 'string' && k !== FIXED_KEY && ALL_COLUMNS.some(c => c.key === k)) {
              colHidden[k] = true;
            }
          }
        }
      } catch { localStorage.removeItem(STORAGE_HIDDEN); }
    }
  }

  function sanitizeOrder(raw: unknown[]): string[] {
    const allKeys = ALL_COLUMNS.map(c => c.key);
    const seen = new Set<string>();
    const result: string[] = [];
    for (const v of raw) {
      if (typeof v === 'string' && !seen.has(v) && allKeys.includes(v)) {
        seen.add(v);
        result.push(v);
      }
    }
    for (const k of allKeys) {
      if (!seen.has(k)) result.push(k);
    }
    const fixedIdx = result.indexOf(FIXED_KEY);
    if (fixedIdx > 0) {
      result.splice(fixedIdx, 1);
      result.unshift(FIXED_KEY);
    }
    return result;
  }

  function persistWidths() { localStorage.setItem(STORAGE_WIDTHS, JSON.stringify(colWidths)); }
  function persistSetup() {
    localStorage.setItem(STORAGE_HIDDEN, JSON.stringify(
      orderedColumns.filter(c => colHidden[c.key]).map(c => c.key)
    ));
    localStorage.setItem(STORAGE_ORDER, JSON.stringify(colOrder));
  }

  let orderedColumns = $derived.by(() => {
    return colOrder
      .map(k => ALL_COLUMNS.find(c => c.key === k))
      .filter((c): c is LibraryColumn => !!c);
  });

  let visibleColumns = $derived.by(() => {
    return orderedColumns.filter(c => c.key === FIXED_KEY || !colHidden[c.key]);
  });

  function getColWidth(key: string): number {
    return colWidths[key] ?? ALL_COLUMNS.find(c => c.key === key)?.width ?? 80;
  }

  let tableMinWidth = $derived(
    visibleColumns.reduce((sum, c) => sum + getColWidth(c.key), 0) + (onToggleCheck ? 32 : 0)
  );

  // --- Column resize ---
  let activeResize: { key: string } | null = $state(null);
  let resizeCleanup: (() => void) | null = null;

  function endResize() {
    resizeCleanup?.();
    resizeCleanup = null;
    activeResize = null;
  }

  function beginResize(event: MouseEvent, key: string) {
    event.preventDefault();
    event.stopPropagation();
    endResize();
    const startX = event.clientX;
    const startW = getColWidth(key);
    const minW = ALL_COLUMNS.find(c => c.key === key)?.minWidth ?? 40;
    const prevCursor = document.body.style.cursor;
    const prevSelect = document.body.style.userSelect;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    activeResize = { key };

    const onMove = (e: MouseEvent) => {
      colWidths[key] = Math.max(minW, Math.round(startW + (e.clientX - startX)));
    };
    const onUp = () => {
      persistWidths();
      document.body.style.cursor = prevCursor;
      document.body.style.userSelect = prevSelect;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      window.removeEventListener('blur', onUp);
      resizeCleanup = null;
      activeResize = null;
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    window.addEventListener('blur', onUp);
    resizeCleanup = () => {
      document.body.style.cursor = prevCursor;
      document.body.style.userSelect = prevSelect;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      window.removeEventListener('blur', onUp);
    };
  }

  function swallowClick(e: MouseEvent) { e.preventDefault(); e.stopPropagation(); }

  // --- Column drag reorder ---
  let activeDrag: { key: string } | null = $state(null);
  let dropTarget: { key: string; position: 'before' | 'after' } | null = $state(null);
  let suppressClickUntil = 0;

  function canDrag(key: string): boolean {
    return key !== FIXED_KEY && !colHidden[key];
  }

  function onDragStart(e: DragEvent, key: string) {
    if (!canDrag(key)) { e.preventDefault(); return; }
    closeMenu();
    if (e.dataTransfer) {
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', key);
    }
    activeDrag = { key };
    dropTarget = null;
  }

  function onDragOver(e: DragEvent, key: string) {
    if (!activeDrag || activeDrag.key === key) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
    const el = e.currentTarget;
    if (!(el instanceof HTMLElement)) return;
    const rect = el.getBoundingClientRect();
    const mid = rect.left + rect.width / 2;
    let pos: 'before' | 'after' = e.clientX < mid ? 'before' : 'after';
    if (key === FIXED_KEY) pos = 'after';
    dropTarget = { key, position: pos };
  }

  function onDrop(e: DragEvent, key: string) {
    if (!activeDrag) return;
    e.preventDefault();
    onDragOver(e, key);
    if (dropTarget) {
      const src = activeDrag.key;
      const next = [...colOrder];
      const srcIdx = next.indexOf(src);
      let tgtIdx = next.indexOf(dropTarget.key);
      if (srcIdx >= 0 && tgtIdx >= 0) {
        next.splice(srcIdx, 1);
        let insert = dropTarget.position === 'after' ? tgtIdx + 1 : tgtIdx;
        if (srcIdx < insert) insert -= 1;
        insert = Math.max(1, Math.min(insert, next.length));
        next.splice(insert, 0, src);
        next.splice(0, next.length, FIXED_KEY, ...next.filter(k => k !== FIXED_KEY));
        colOrder = next;
        persistSetup();
      }
      suppressClickUntil = Date.now() + 250;
    }
    activeDrag = null;
    dropTarget = null;
  }

  function onDragEnd() {
    if (activeDrag) suppressClickUntil = Date.now() + 250;
    activeDrag = null;
    dropTarget = null;
  }

  function isDropBefore(key: string): boolean {
    return dropTarget?.key === key && dropTarget.position === 'before';
  }
  function isDropAfter(key: string): boolean {
    return dropTarget?.key === key && dropTarget.position === 'after';
  }

  // --- Column context menu ---
  let colMenu: { x: number; y: number } | null = $state(null);

  function openMenu(e: MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    const margin = 8;
    colMenu = {
      x: Math.max(margin, Math.min(e.clientX, window.innerWidth - 240 - margin)),
      y: Math.max(margin, Math.min(e.clientY, window.innerHeight - 360 - margin)),
    };
  }

  function closeMenu() { colMenu = null; }

  function toggleVisibility(key: string) {
    if (key === FIXED_KEY) return;
    colHidden[key] = !colHidden[key];
    persistSetup();
  }

  function resetLayout() {
    colHidden = Object.fromEntries(ALL_COLUMNS.map(c => [c.key, DEFAULT_HIDDEN.has(c.key)]));
    colOrder = ALL_COLUMNS.map(c => c.key);
    colWidths = Object.fromEntries(ALL_COLUMNS.map(c => [c.key, c.width]));
    persistSetup();
    persistWidths();
  }

  function onHeaderClick(col: LibraryColumn) {
    if (Date.now() < suppressClickUntil) return;
    if (col.sortField) toggleSort(col.sortField);
  }

  // --- Lifecycle ---
  onMount(() => {
    loadColumnState();
    return () => {
      if (scrollRaf) cancelAnimationFrame(scrollRaf);
      resizeCleanup?.();
    };
  });
</script>

<svelte:document onclick={() => closeMenu()} />

<div class="library-virtual-table-root">
<div class="vtable-header" bind:this={headerWrap} style="padding-right:{scrollbarWidth}px;">
  <table class="lib-table" style="min-width:{tableMinWidth}px;">
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <thead oncontextmenu={openMenu}>
      <tr>
        {#if onToggleCheck}
          <th class="col-check">
            <input
              type="checkbox"
              checked={allChecked}
              indeterminate={someChecked && !allChecked}
              onchange={() => onToggleCheckAll?.()}
              aria-label="Select all files"
              title="Select all files"
            />
          </th>
        {/if}
        {#each visibleColumns as col (col.key)}
          <th
            style="width:{getColWidth(col.key)}px;min-width:{col.minWidth}px;"
            class:sortable={!!col.sortField}
            class:resizing={activeResize?.key === col.key}
            class:drag-enabled={canDrag(col.key)}
            class:drop-before={isDropBefore(col.key)}
            class:drop-after={isDropAfter(col.key)}
            tabindex={col.sortField ? 0 : undefined}
            role="columnheader"
            draggable={canDrag(col.key)}
            aria-sort={col.sortField ? ariaSort(col.sortField) : undefined}
            onclick={() => onHeaderClick(col)}
            onkeydown={(e) => { if (col.sortField) sortOnKey(e, col.sortField); }}
            ondragstart={(e) => onDragStart(e, col.key)}
            ondragover={(e) => onDragOver(e, col.key)}
            ondrop={(e) => onDrop(e, col.key)}
            ondragend={onDragEnd}
          >
            <span class="header-content">
              {col.label}{col.sortField ? arrow(col.sortField) : ''}
            </span>
            <button
              type="button"
              class="col-resize-handle"
              tabindex="-1"
              aria-label="Resize {col.label} column"
              onmousedown={(e) => beginResize(e, col.key)}
              onclick={swallowClick}
            ></button>
          </th>
        {/each}
      </tr>
    </thead>
  </table>
</div>
<div class="vtable-scroll" bind:this={scrollContainer} use:passiveScroll={onTableScroll}>
  <div class="vtable-spacer" style="height:{sortedFiles.length * ROW_HEIGHT}px;">
    <table class="lib-table vtable-body" style="transform:translateY({virtualSlice.topPad}px);min-width:{tableMinWidth}px;">
      <colgroup>
        {#if onToggleCheck}<col style="width:32px;" />{/if}
        {#each visibleColumns as col (col.key)}
          <col style="width:{getColWidth(col.key)}px;" />
        {/each}
      </colgroup>
      <tbody>
        {#each virtualSlice.visible as file, i (file.path)}
          <tr
            class:row-alt={((virtualSlice.startIdx + i) & 1) === 1}
            class:selected={selectedPath === file.path}
            onclick={() => onSelectPath(file.path)}
            ondblclick={() => onOpenFile(file.path)}
            oncontextmenu={(e) => onRowContextMenu(e, file)}
            style="height:{ROW_HEIGHT}px;"
          >
            {#if onToggleCheck}
              <td class="col-check" onclick={(e) => e.stopPropagation()}>
                <input
                  type="checkbox"
                  checked={checkedPaths.has(file.path)}
                  onclick={(e) => { e.stopPropagation(); onToggleCheck(file.path, e.shiftKey); e.preventDefault(); }}
                  aria-label="Select {file.name}"
                />
              </td>
            {/if}
            {#each visibleColumns as col (col.key)}
              {#if col.key === 'name'}
                <td class="cell-name" title={file.path}>{file.name}</td>
              {:else if col.key === 'size'}
                <td class="cell-num">{formatSize(file.size)}</td>
              {:else if col.key === 'type'}
                <td class="cell-type">{fileType(file.extension)}</td>
              {:else if col.key === 'priority'}
                <td class="cell-prio prio-{file.priority}">{priorityLabel(file.priority)}</td>
              {:else if col.key === 'hash'}
                <td class="cell-hash" title={file.hash || 'Hashing...'}>
                  {#if file.hash}
                    {file.hash.substring(0, 16)}&hellip;
                  {:else}
                    <span class="hashing-label">Hashing&hellip;</span>
                  {/if}
                </td>
              {:else if col.key === 'requests'}
                <td class="cell-num">{file.requests}{file.alltime_requests ? ` (${file.alltime_requests})` : ''}</td>
              {:else if col.key === 'accepted'}
                <td class="cell-num">{file.accepted}{file.alltime_accepted ? ` (${file.alltime_accepted})` : ''}</td>
              {:else if col.key === 'transferred'}
                <td class="cell-num">{formatTransferred(file.bytes_transferred, file.alltime_transferred)}</td>
              {:else if col.key === 'folder'}
                <td class="cell-folder" title={file.folder}>{file.folder.split(/[\\/]/).filter(Boolean).pop() || file.folder}</td>
              {:else if col.key === 'modified'}
                <td class="cell-date" title={file.modified_at ? new Date(file.modified_at * 1000).toLocaleString() : ''}>{formatDate(file.modified_at)}</td>
              {:else if col.key === 'sources'}
                <td class="cell-num">{file.complete_sources || '\u2014'}</td>
              {:else if col.key === 'shared'}
                <td class="cell-shared">
                  {#if !file.hash}
                    <span class="hashing-label">Pending</span>
                  {:else if file.shared}
                    <span class="shared-icon shared-yes" title="Shared">&#x2713;</span>
                    {#if file.shared_kad || file.shared_ed2k || file.aich_hash}
                      <span class="shared-badges">
                        {#if file.shared_kad}<span class="shared-badge kad" title="Published to KAD network">KAD</span>{/if}
                        {#if file.shared_ed2k}<span class="shared-badge ed2k" title="Published to eD2K servers">eD2K</span>{/if}
                        {#if file.aich_hash}<span class="shared-badge aich" title="AICH hash available — bad chunks can be identified without re-downloading the whole file">AICH</span>{/if}
                      </span>
                    {/if}
                  {:else}
                    <span class="shared-icon shared-no" title="Not shared">&#x2715;</span>
                    {#if file.aich_hash}
                      <span class="shared-badges">
                        <span class="shared-badge aich" title="AICH hash available — bad chunks can be identified without re-downloading the whole file">AICH</span>
                      </span>
                    {/if}
                  {/if}
                </td>
              {/if}
            {/each}
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>
</div>

{#if colMenu}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div class="col-ctx-menu" style="left:{colMenu.x}px;top:{colMenu.y}px;" onclick={(e) => e.stopPropagation()}>
    <div class="col-ctx-title">Library Columns</div>
    {#each orderedColumns.filter(c => c.key !== FIXED_KEY) as col (col.key)}
      <button class="col-ctx-item" onclick={() => toggleVisibility(col.key)}>
        {colHidden[col.key] ? '\u2610' : '\u2611'} {col.label}
      </button>
    {/each}
    <div class="col-ctx-sep"></div>
    <button class="col-ctx-item" onclick={resetLayout}>Reset Columns</button>
  </div>
{/if}

<style>
  .library-virtual-table-root {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: hidden;
  }

  .vtable-header {
    flex-shrink: 0;
    overflow: hidden;
  }
  .vtable-header table {
    margin-bottom: 0;
  }
  .vtable-scroll {
    flex: 1;
    overflow-y: auto;
    overflow-x: auto;
    min-height: 0;
  }
  .vtable-spacer {
    position: relative;
    width: 100%;
  }
  .vtable-body {
    position: absolute;
    left: 0;
    right: 0;
    will-change: transform;
  }

  .lib-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    table-layout: fixed;
  }
  .lib-table th {
    position: relative;
    padding: 4px 6px;
    text-align: left;
    white-space: nowrap;
    font-weight: 600;
    font-size: 11px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
    user-select: none;
    box-sizing: border-box;
    color: var(--text-secondary);
    overflow: hidden;
  }
  .lib-table th.sortable {
    cursor: pointer;
  }
  .lib-table th.sortable:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }
  .lib-table th.sortable:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }
  .lib-table th.drag-enabled {
    cursor: grab;
  }
  .lib-table th.drag-enabled:active {
    cursor: grabbing;
  }
  .lib-table th.resizing {
    color: var(--text-primary);
  }
  .lib-table th.drop-before {
    box-shadow: inset 2px 0 0 var(--accent);
  }
  .lib-table th.drop-after {
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
    z-index: 1;
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
    transition: background 0.1s;
  }
  .lib-table th:hover .col-resize-handle::after,
  .lib-table th.resizing .col-resize-handle::after,
  .col-resize-handle:hover::after,
  .col-resize-handle:active::after {
    background: var(--accent);
  }
  .col-resize-handle:focus {
    outline: none;
  }

  .lib-table td {
    padding: 2px 6px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 40%, transparent);
    box-sizing: border-box;
  }
  .lib-table tbody tr {
    cursor: pointer;
    box-sizing: border-box;
    transition: background-color 0.12s ease;
  }
  .lib-table tbody tr.row-alt td {
    background: color-mix(in srgb, var(--bg-secondary) 90%, var(--bg-primary));
  }
  .lib-table tbody tr:hover td {
    background: var(--bg-hover);
  }
  .lib-table tbody tr.selected td {
    background: color-mix(in srgb, var(--accent-dim) 55%, transparent);
    color: var(--text-primary);
    border-bottom-color: color-mix(in srgb, var(--accent) 30%, var(--border));
  }

  .col-check {
    width: 32px;
    min-width: 32px;
    max-width: 32px;
    text-align: center;
    padding: 0 4px !important;
  }
  .col-check input[type="checkbox"] {
    cursor: pointer;
    margin: 0;
  }
  .cell-num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .cell-hash {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }
  .cell-folder {
    color: var(--text-muted);
  }
  .cell-date {
    color: var(--text-muted);
    font-size: 11px;
  }
  .cell-shared {
    text-align: center;
    white-space: nowrap;
  }

  .hashing-label {
    color: var(--warning, #e0a030);
    font-size: 11px;
    font-style: italic;
  }
  .shared-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 18px;
    border-radius: 10px;
    font-size: 10px;
    font-weight: 700;
    padding: 0 6px;
    vertical-align: middle;
  }
  .shared-yes {
    background: color-mix(in srgb, var(--success) 20%, transparent);
    color: var(--success);
  }
  .shared-no {
    background: color-mix(in srgb, var(--text-muted) 16%, transparent);
    color: var(--text-muted);
    font-size: 9px;
  }
  .shared-badges {
    display: inline-flex;
    gap: 3px;
    margin-left: 4px;
    vertical-align: middle;
  }
  .shared-badge {
    font-size: 9px;
    font-weight: 600;
    padding: 0 4px;
    border-radius: 999px;
    line-height: 15px;
  }
  .shared-badge.kad {
    background: rgba(52, 152, 219, 0.15);
    color: #3498db;
  }
  .shared-badge.ed2k {
    background: rgba(155, 89, 182, 0.15);
    color: #9b59b6;
  }
  .shared-badge.aich {
    background: rgba(39, 174, 96, 0.15);
    color: #27ae60;
  }

  .prio-verylow { color: #888; }
  .prio-low { color: #59b; }
  .prio-normal { color: var(--text-primary); }
  .prio-high { color: #e0a030; }
  .prio-release { color: #e05050; font-weight: 600; }
  .prio-auto { color: #7cb342; }

  /* --- Column context menu --- */
  .col-ctx-menu {
    position: fixed;
    z-index: 9999;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 0;
    min-width: 220px;
    box-shadow: 0 4px 16px rgba(0,0,0,.35);
    font-size: 12px;
  }
  .col-ctx-title {
    padding: 4px 14px 6px;
    font-size: 11px;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .col-ctx-item {
    display: block;
    width: 100%;
    text-align: left;
    padding: 5px 16px;
    cursor: pointer;
    white-space: nowrap;
    border: none;
    border-radius: 0;
    background: none;
    color: inherit;
    font: inherit;
    font-size: 12px;
  }
  .col-ctx-item:hover {
    background: var(--accent, #3498db);
    color: #fff;
  }
  .col-ctx-sep {
    height: 1px;
    margin: 4px 0;
    background: var(--border);
  }
</style>
