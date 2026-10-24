<script lang="ts">
  /*
   * Picks Library files for one of the user's feeds, laid out like Browse
   * Friend: type chips with counts, a filter, a sortable table with
   * checkboxes (Shift for a range) and a bulk Add. Only files shared with
   * everyone that have finished hashing can go in a feed (`set_feed_items`
   * refuses the rest), so only those are listed.
   */
  import { tick } from 'svelte';
  import { getSharedFilesIfChanged } from '$lib/api/sharing';
  import type { FileInfo } from '$lib/types';
  import {
    FILE_TYPE_FILTERS,
    extensionFromPath,
    fileTypeFilterLabel,
    fileTypeKey,
    type FileTypeFilter,
    type FileTypeKey,
  } from '$lib/fileTypes';
  import { compareFileNames, formatNumber, formatSize } from '$lib/utils';
  import { translateError } from '$lib/i18n';
  import { inertBackground, trapTabKey } from '$lib/a11y';
  import IconX from '$lib/components/IconX.svelte';
  import * as m from '$lib/paraglide/messages';

  interface Props {
    open: boolean;
    feedTitle: string;
    /** eD2K hashes (lowercase) already in the feed. */
    inFeed: ReadonlySet<string>;
    /** How many more files the feed can take. */
    room: number;
    onadd: (files: FileInfo[]) => void;
    onclose: () => void;
  }

  let { open = $bindable(), feedTitle, inFeed, room, onadd, onclose }: Props = $props();

  /** Rows drawn at once; the filter narrows a large library down. */
  const RENDER_LIMIT = 500;
  const instanceId = Math.random().toString(36).slice(2, 10);

  let library: FileInfo[] = $state([]);
  let loading = $state(false);
  let error: string | null = $state(null);
  let filterQuery = $state('');
  let typeFilter: FileTypeFilter = $state('All');
  type SortKey = 'name' | 'size';
  let sortKey: SortKey = $state('name');
  let sortAsc = $state(true);
  let hideAdded = $state(false);
  let selectedHashes: Set<string> = $state(new Set());
  let selectionAnchor: string | null = null;

  const VIEW_PREFS_KEY = 'feed-picker-view';
  try {
    const saved = JSON.parse(localStorage.getItem(VIEW_PREFS_KEY) ?? 'null');
    if (saved?.sortKey === 'name' || saved?.sortKey === 'size') sortKey = saved.sortKey;
    if (typeof saved?.sortAsc === 'boolean') sortAsc = saved.sortAsc;
    if (typeof saved?.hideAdded === 'boolean') hideAdded = saved.hideAdded;
  } catch {
    // Storage unavailable or the value corrupt: keep the defaults.
  }
  $effect(() => {
    const prefs = JSON.stringify({ sortKey, sortAsc, hideAdded });
    try {
      localStorage.setItem(VIEW_PREFS_KEY, prefs);
    } catch {
      // Not persisting a sort order is harmless.
    }
  });

  const keyOf = (f: FileInfo) => f.hash.toLowerCase();
  const isEligible = (f: FileInfo) => f.shared && !f.friends_only && f.ember_file_hash?.length === 64;
  const isAdded = (f: FileInfo) => inFeed.has(keyOf(f));

  // The Library has a row per path, so copies of one file share a hash; the
  // table keys on it, and Svelte throws on a repeated key.
  let eligible = $derived([...new Map(library.filter(isEligible).map((f) => [keyOf(f), f])).values()]);
  /** Files, not rows, that cannot go in: a file with an eligible copy is in
   *  the table, and an unhashed one counts once per path. */
  let notShown = $derived.by(() => {
    const listed = new Set(eligible.map(keyOf));
    return new Set(
      library.filter((f) => !isEligible(f) && !listed.has(keyOf(f))).map((f) => keyOf(f) || f.path),
    ).size;
  });
  let addedCount = $derived(eligible.filter(isAdded).length);
  let hidingAdded = $derived(hideAdded && addedCount > 0);

  let typeByHash = $derived(
    new Map<string, FileTypeKey | ''>(eligible.map((f) => [keyOf(f), fileTypeKey(extensionFromPath(f.name))])),
  );

  let textMatched = $derived.by(() => {
    const q = filterQuery.trim().toLowerCase();
    const base = hidingAdded ? eligible.filter((f) => !isAdded(f)) : eligible;
    if (!q) return base;
    return base.filter((f) => f.name.toLowerCase().includes(q) || keyOf(f).includes(q));
  });

  /** Counts of what the text filter leaves, so the chips show where the
   *  matches are. */
  let typeCounts = $derived.by(() => {
    const counts: Record<FileTypeFilter, number> = {
      All: textMatched.length, Audio: 0, Video: 0, Image: 0, Archive: 0, Document: 0, Program: 0, 'CD/DVD': 0, Collection: 0,
    };
    for (const f of textMatched) {
      const key = typeByHash.get(keyOf(f));
      if (key) counts[key]++;
    }
    return counts;
  });

  /** `list` in the table's order. */
  function sorted(list: FileInfo[]): FileInfo[] {
    list.sort(
      sortKey === 'size'
        ? (a, b) => a.size - b.size || compareFileNames(a.name, b.name)
        : (a, b) => compareFileNames(a.name, b.name),
    );
    if (!sortAsc) list.reverse();
    return list;
  }

  let filtered = $derived(
    sorted(typeFilter === 'All' ? [...textMatched] : textMatched.filter((f) => typeByHash.get(keyOf(f)) === typeFilter)),
  );
  let shown = $derived(filtered.slice(0, RENDER_LIMIT));
  let filteredSize = $derived(filtered.reduce((sum, f) => sum + f.size, 0));
  let isFiltered = $derived(Boolean(filterQuery.trim()) || typeFilter !== 'All' || hidingAdded);

  /** Selection survives switching type, so files can be picked across
   *  several; one that joined the feed meanwhile drops out. Kept in the
   *  table's order, which is the order they join the feed in. */
  let selected = $derived(sorted(eligible.filter((f) => selectedHashes.has(keyOf(f)) && !isAdded(f))));
  let selectedSize = $derived(selected.reduce((sum, f) => sum + f.size, 0));
  let selectableShown = $derived(shown.filter((f) => !isAdded(f)));
  let allShownSelected = $derived(selectableShown.length > 0 && selectableShown.every((f) => selectedHashes.has(keyOf(f))));
  let someShownSelected = $derived(selectableShown.some((f) => selectedHashes.has(keyOf(f))));
  let overRoom = $derived(selected.length > room);

  async function load() {
    loading = true;
    error = null;
    try {
      const snapshot = await getSharedFilesIfChanged(null);
      if (open) library = snapshot.files ?? [];
    } catch (e) {
      error = translateError(e, m.error_operation_failed());
    } finally {
      loading = false;
    }
    // The filter appears once the list has; focus moves to it from the
    // dialog, not from wherever the user has gone since.
    await tick();
    if (open && document.activeElement === modalEl) filterInputEl?.focus();
  }

  // Each opening starts fresh: the Library may have changed, and a choice
  // left from the last time would be added by mistake.
  $effect(() => {
    if (!open) return;
    filterQuery = '';
    typeFilter = 'All';
    selectedHashes = new Set();
    selectionAnchor = null;
    void load();
  });

  function onRowCheckboxClick(e: MouseEvent, file: FileInfo) {
    const next = new Set(selectedHashes);
    const key = keyOf(file);
    const select = !next.has(key);
    const from = e.shiftKey && selectionAnchor ? shown.findIndex((f) => keyOf(f) === selectionAnchor) : -1;
    const to = from === -1 ? -1 : shown.findIndex((f) => keyOf(f) === key);
    if (from !== -1 && to !== -1) {
      for (const f of shown.slice(Math.min(from, to), Math.max(from, to) + 1)) {
        if (isAdded(f)) continue;
        if (select) next.add(keyOf(f));
        else next.delete(keyOf(f));
      }
    } else if (select) {
      next.add(key);
    } else {
      next.delete(key);
    }
    selectionAnchor = key;
    selectedHashes = next;
  }

  function toggleSelectAllShown() {
    const next = new Set(selectedHashes);
    for (const f of selectableShown) {
      if (allShownSelected) next.delete(keyOf(f));
      else next.add(keyOf(f));
    }
    selectedHashes = next;
  }

  function setSort(key: SortKey) {
    if (sortKey === key) {
      sortAsc = !sortAsc;
    } else {
      sortKey = key;
      // Largest first is the useful default for size; A→Z for names.
      sortAsc = key === 'name';
    }
  }

  function ariaSort(key: SortKey): 'ascending' | 'descending' | 'none' {
    if (sortKey !== key) return 'none';
    return sortAsc ? 'ascending' : 'descending';
  }

  /** One file now, from its row; the dialog stays open for more. Its button
   *  goes (the row may too), so focus moves on to the next row's. */
  async function addOne(file: FileInfo, row: number) {
    if (room <= 0 || isAdded(file)) return;
    onadd([file]);
    const next = new Set(selectedHashes);
    next.delete(keyOf(file));
    selectedHashes = next;
    await tick();
    const following = Array.from(modalEl?.querySelectorAll<HTMLButtonElement>('.row-add-btn:not(:disabled)') ?? []).find(
      (button) => Number(button.dataset.row) >= row,
    );
    if (following) following.focus();
    else if (filterInputEl) filterInputEl.focus();
    else modalEl?.focus();
  }

  function addSelected() {
    if (selected.length === 0 || overRoom) return;
    onadd(selected);
    close();
  }

  function close() {
    open = false;
    onclose();
  }

  let modalEl: HTMLDivElement | undefined = $state(undefined);
  let dialogRootEl: HTMLDivElement | undefined = $state(undefined);
  let filterInputEl: HTMLInputElement | undefined = $state(undefined);
  let returnFocusEl: HTMLElement | null = null;

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      close();
      return;
    }
    trapTabKey(e, modalEl);
  }

  $effect(() => {
    if (open) {
      const active = typeof document !== 'undefined' ? document.activeElement : null;
      if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
      void tick().then(() => {
        if (filterInputEl) filterInputEl.focus();
        else modalEl?.focus();
      });
    }
    return () => {
      if (!open && returnFocusEl) {
        const el = returnFocusEl;
        returnFocusEl = null;
        requestAnimationFrame(() => {
          if (typeof document !== 'undefined' && document.contains(el)) el.focus();
        });
      }
    };
  });

  $effect(() => {
    if (!open || !dialogRootEl) return;
    return inertBackground(dialogRootEl);
  });
</script>

{#if open}
  <div bind:this={dialogRootEl}>
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="picker-overlay" onclick={close}></div>
    <!-- svelte-ignore a11y_interactive_supports_focus -->
    <div
      class="picker-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="feed-picker-title-{instanceId}"
      tabindex="-1"
      bind:this={modalEl}
      onkeydown={handleKeydown}
    >
      <div class="picker-header">
        <div class="picker-header-text">
          <h3 id="feed-picker-title-{instanceId}">{m.feeds_add_files()}</h3>
          <p class="picker-subtitle" title={feedTitle}><bdi dir="auto">{feedTitle}</bdi></p>
        </div>
        <div class="picker-header-actions">
          <button
            type="button"
            class="picker-icon-btn"
            class:spinning={loading}
            onclick={() => void load()}
            disabled={loading}
            aria-busy={loading}
            title={m.common_refresh()}
            aria-label={m.common_refresh()}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9"/><polyline points="13.5 2.5 13.5 5.5 10.5 5.5"/>
            </svg>
          </button>
          <button type="button" class="icon-close" onclick={close} title={m.common_close()} aria-label={m.common_close()}>
            <IconX size={16} />
          </button>
        </div>
      </div>

      <div class="picker-body">
        {#if loading && library.length === 0}
          <div class="picker-status">{m.feeds_picker_loading()}</div>
        {:else if error && library.length === 0}
          <div class="picker-error">
            <p>{error}</p>
            <button type="button" class="picker-secondary-btn" onclick={() => void load()}>{m.common_retry()}</button>
          </div>
        {:else if eligible.length === 0}
          <div class="picker-status">
            <p>{m.feeds_add_files_none()}</p>
            {#if notShown > 0}
              <p class="picker-status-sub">{m.feeds_picker_not_shown({ count: formatNumber(notShown) })}</p>
            {/if}
          </div>
        {:else}
          <div class="picker-toolbar">
            <div class="picker-categories" role="group" aria-label={m.library_type_filter_aria()}>
              {#each FILE_TYPE_FILTERS as opt (opt)}
                <button
                  type="button"
                  class="picker-chip"
                  class:active={typeFilter === opt}
                  aria-pressed={typeFilter === opt}
                  disabled={opt !== 'All' && opt !== typeFilter && typeCounts[opt] === 0}
                  onclick={() => (typeFilter = opt)}
                >
                  <span>{fileTypeFilterLabel(opt)}</span>
                  <span class="picker-chip-count">{formatNumber(typeCounts[opt])}</span>
                </button>
              {/each}
            </div>
            <div class="picker-filter-row">
              <div class="picker-filter">
                <span class="picker-filter-icon" aria-hidden="true">
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
                    <circle cx="7" cy="7" r="4.5"/><line x1="10.5" y1="10.5" x2="13.5" y2="13.5"/>
                  </svg>
                </span>
                <input
                  bind:this={filterInputEl}
                  class="picker-filter-input"
                  type="search"
                  bind:value={filterQuery}
                  placeholder={m.feeds_add_files_search()}
                  aria-label={m.feeds_add_files_search()}
                  onkeydown={(e) => {
                    // Clear first, close second.
                    if (e.key === 'Escape' && filterQuery) {
                      e.preventDefault();
                      e.stopPropagation();
                      filterQuery = '';
                    }
                  }}
                />
                {#if filterQuery.trim()}
                  <button
                    type="button"
                    class="picker-filter-clear"
                    onclick={() => {
                      filterQuery = '';
                      filterInputEl?.focus();
                    }}
                    title={m.common_clear()}
                    aria-label={m.common_clear()}
                  ><IconX size={14} /></button>
                {/if}
              </div>
              {#if addedCount > 0}
                <button
                  type="button"
                  class="picker-chip picker-toggle"
                  class:active={hideAdded}
                  aria-pressed={hideAdded}
                  onclick={() => (hideAdded = !hideAdded)}
                >
                  <span class="picker-toggle-box" aria-hidden="true">
                    {#if hideAdded}
                      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="3.5 8.5 6.5 11.5 12.5 5"/>
                      </svg>
                    {/if}
                  </span>
                  <span>{m.feeds_picker_hide_added()}</span>
                  <span class="picker-chip-count">{formatNumber(addedCount)}</span>
                </button>
              {/if}
            </div>
            <div class="picker-count-row">
              <div class="picker-count">
                {#if isFiltered}
                  {m.browse_count_filtered({ filtered: formatNumber(filtered.length), total: formatNumber(eligible.length) })}
                {:else}
                  {m.feeds_picker_count({ count: formatNumber(eligible.length) })}
                {/if}
                <span aria-hidden="true">·</span>
                {formatSize(filteredSize)}
              </div>
              {#if selected.length > 0}
                <div class="picker-selection">
                  <span class="picker-selection-summary">
                    {m.browse_selected_summary({ count: formatNumber(selected.length), size: formatSize(selectedSize) })}
                  </span>
                  <button type="button" class="picker-link-btn" onclick={() => (selectedHashes = new Set())}>{m.common_clear()}</button>
                  <button type="button" class="picker-add-btn" onclick={addSelected} disabled={overRoom}>
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" aria-hidden="true">
                      <line x1="8" y1="3" x2="8" y2="13"/><line x1="3" y1="8" x2="13" y2="8"/>
                    </svg>
                    <span>{m.feeds_picker_add_selected()}</span>
                  </button>
                </div>
              {/if}
            </div>
          </div>

          {#if room <= 0}
            <div class="picker-banner picker-banner-error" role="alert">{m.feeds_picker_full()}</div>
          {:else if overRoom}
            <div class="picker-banner picker-banner-error" role="alert">{m.feeds_picker_over_room({ room: formatNumber(room) })}</div>
          {/if}
          {#if error}
            <div class="picker-banner picker-banner-error" role="alert">{error}</div>
          {/if}
          {#if notShown > 0}
            <div class="picker-banner picker-banner-note" role="status">
              {m.feeds_picker_not_shown({ count: formatNumber(notShown) })}
            </div>
          {/if}
          {#if filtered.length > shown.length}
            <div class="picker-banner picker-banner-note" role="status">
              {m.feeds_picker_showing_first({ shown: formatNumber(shown.length), total: formatNumber(filtered.length) })}
            </div>
          {/if}

          {#if filtered.length === 0}
            <div class="picker-status picker-status-compact">{m.browse_no_match()}</div>
          {:else}
            <div class="picker-table-wrap">
              <table class="picker-table">
                <thead>
                  <tr>
                    <th class="col-select">
                      <input
                        type="checkbox"
                        checked={allShownSelected}
                        {@attach (el: HTMLInputElement) => {
                          el.indeterminate = someShownSelected && !allShownSelected;
                        }}
                        disabled={selectableShown.length === 0}
                        onchange={toggleSelectAllShown}
                        title={m.common_select_all()}
                        aria-label={m.common_select_all()}
                      />
                    </th>
                    <th class="col-name" aria-sort={ariaSort('name')}>
                      <button type="button" class="sort-btn" onclick={() => setSort('name')}>
                        {m.browse_col_name()}
                        {#if sortKey === 'name'}<span class="sort-arrow" aria-hidden="true">{sortAsc ? '▲' : '▼'}</span>{/if}
                      </button>
                    </th>
                    <th class="col-type">{m.library_type_filter_aria()}</th>
                    <th class="col-size" aria-sort={ariaSort('size')}>
                      <button type="button" class="sort-btn" onclick={() => setSort('size')}>
                        {m.browse_col_size()}
                        {#if sortKey === 'size'}<span class="sort-arrow" aria-hidden="true">{sortAsc ? '▲' : '▼'}</span>{/if}
                      </button>
                    </th>
                    <th class="col-action"><span class="sr-only">{m.feeds_add()}</span></th>
                  </tr>
                </thead>
                <tbody>
                  {#each shown as file, row (file.hash)}
                    {@const added = isAdded(file)}
                    {@const type = typeByHash.get(keyOf(file))}
                    <tr class:selected={!added && selectedHashes.has(keyOf(file))} class:added>
                      <td class="col-select">
                        <input
                          type="checkbox"
                          checked={added || selectedHashes.has(keyOf(file))}
                          disabled={added}
                          onmousedown={(e) => {
                            // Shift-click would otherwise select the text between rows.
                            if (e.shiftKey) e.preventDefault();
                          }}
                          onclick={(e) => onRowCheckboxClick(e, file)}
                          title={m.browse_range_hint()}
                          aria-label={m.browse_select_file({ name: file.name })}
                        />
                      </td>
                      <td class="col-name" title={file.name}>
                        <div class="name-cell">
                          <bdi dir="auto" class="name-text">{file.name}</bdi>
                          {#if added}
                            <span class="file-tag tag-added">{m.feeds_picker_in_feed()}</span>
                          {/if}
                        </div>
                      </td>
                      <td class="col-type">{type ? fileTypeFilterLabel(type) : '—'}</td>
                      <td class="col-size">{formatSize(file.size)}</td>
                      <td class="col-action">
                        {#if added}
                          <span class="add-done" aria-label={m.feeds_picker_in_feed()}>
                            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                              <polyline points="3 8 7 12 13 4"/>
                            </svg>
                          </span>
                        {:else}
                          <button
                            type="button"
                            class="row-add-btn"
                            data-row={row}
                            onclick={() => void addOne(file, row)}
                            disabled={room <= 0}
                            aria-label={m.feeds_add_named({ name: file.name })}
                          >
                            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" aria-hidden="true">
                              <line x1="8" y1="3" x2="8" y2="13"/><line x1="3" y1="8" x2="13" y2="8"/>
                            </svg>
                            <span>{m.feeds_add()}</span>
                          </button>
                        {/if}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        {/if}
      </div>

      <div class="picker-footer">
        <button type="button" class="picker-secondary-btn" onclick={close}>{m.common_close()}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .picker-overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    z-index: 10000;
    animation: picker-fade-in 0.15s ease;
  }

  .picker-modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 860px;
    max-width: 94vw;
    height: 80vh;
    max-height: 760px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    z-index: 10001;
    display: flex;
    flex-direction: column;
    box-shadow:
      inset 0 1px 0 var(--surface-highlight),
      var(--shadow-lg);
    animation: picker-pop-in 0.2s ease;
  }

  @keyframes picker-fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  @keyframes picker-pop-in {
    from { opacity: 0; transform: translate(-50%, -50%) scale(0.96); }
    to { opacity: 1; transform: translate(-50%, -50%) scale(1); }
  }
  @keyframes picker-spin {
    to { transform: rotate(360deg); }
  }

  @media (prefers-reduced-motion: reduce) {
    .picker-overlay,
    .picker-modal {
      animation: none;
    }
    .picker-icon-btn.spinning svg {
      animation: none;
    }
  }

  .picker-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .picker-header-text {
    min-width: 0;
  }

  .picker-header h3 {
    margin: 0;
    font-size: var(--font-size-lg);
    font-weight: 600;
    color: var(--text-primary);
  }

  .picker-subtitle {
    margin: 4px 0 0;
    font-size: var(--font-size-md);
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .picker-header-actions {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
  }

  .picker-icon-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    padding: 0;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text-secondary);
    cursor: pointer;
  }

  .picker-icon-btn svg {
    width: 15px;
    height: 15px;
  }

  .picker-icon-btn:hover:not(:disabled) {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .picker-icon-btn:disabled {
    opacity: 0.45;
    cursor: default;
  }

  .picker-icon-btn.spinning:disabled {
    opacity: 0.8;
  }

  .picker-icon-btn.spinning svg {
    animation: picker-spin 0.9s linear infinite;
  }

  .picker-body {
    flex: 1;
    min-height: 0;
    overflow: hidden;
    padding: 16px 20px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .picker-status,
  .picker-error {
    text-align: center;
    padding: 32px 16px;
    font-size: var(--font-size-md);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
  }

  .picker-status p,
  .picker-error p {
    margin: 0;
    max-width: 480px;
  }

  .picker-status { color: var(--text-muted); }
  .picker-error { color: var(--danger); }

  .picker-status-sub {
    font-size: var(--font-size-sm);
  }

  .picker-status-compact {
    padding: 24px 16px;
  }

  .picker-toolbar {
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex-shrink: 0;
  }

  .picker-categories {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  .picker-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-pill);
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font: inherit;
    font-size: var(--font-size-sm);
    font-weight: 500;
    cursor: pointer;
    transition: background var(--transition-fast), border-color var(--transition-fast), color var(--transition-fast);
  }

  .picker-chip:hover:not(:disabled):not(.active) {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .picker-chip.active {
    color: var(--accent);
    border-color: color-mix(in srgb, var(--accent) 55%, var(--border));
    background: color-mix(in srgb, var(--accent) 14%, transparent);
  }

  .picker-chip:disabled {
    opacity: 0.45;
    cursor: default;
  }

  .picker-chip-count {
    font-size: var(--font-size-xs);
    font-variant-numeric: tabular-nums;
    color: var(--text-muted);
  }

  .picker-chip.active .picker-chip-count {
    color: inherit;
  }

  .picker-filter-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .picker-filter {
    position: relative;
    display: flex;
    align-items: center;
    flex: 1;
    min-width: 0;
  }

  .picker-filter-icon {
    position: absolute;
    left: 10px;
    color: var(--text-muted);
    display: flex;
    pointer-events: none;
  }

  .picker-filter-icon svg {
    width: 14px;
    height: 14px;
  }

  .picker-filter-input {
    width: 100%;
    padding: 8px 32px;
    border: 1px solid var(--input-border);
    border-radius: var(--radius-pill);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: var(--font-size-md);
    font-family: inherit;
  }

  .picker-filter-input:focus {
    border-color: var(--accent);
    outline: none;
    box-shadow: 0 0 0 2px var(--accent-halo);
  }

  .picker-filter-clear {
    position: absolute;
    right: 6px;
    width: 22px;
    height: 22px;
    padding: 0;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text-secondary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    line-height: 1;
  }

  .picker-filter-clear:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .picker-toggle {
    flex-shrink: 0;
    white-space: nowrap;
    padding-top: 7px;
    padding-bottom: 7px;
  }

  .picker-toggle-box {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 14px;
    height: 14px;
    border: 1.5px solid currentColor;
    border-radius: 4px;
    opacity: 0.8;
  }

  .picker-toggle-box svg {
    width: 11px;
    height: 11px;
  }

  .picker-count-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px;
    min-height: 30px;
  }

  .picker-count {
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .picker-selection {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .picker-selection-summary {
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
  }

  .picker-link-btn {
    padding: 0;
    border: none;
    background: none;
    color: var(--text-muted);
    font: inherit;
    font-size: var(--font-size-sm);
    cursor: pointer;
    text-decoration: underline;
    text-underline-offset: 2px;
  }

  .picker-link-btn:hover {
    color: var(--text-primary);
  }

  .picker-secondary-btn {
    min-height: 30px;
    padding: 0 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-secondary);
    color: var(--text-primary);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font: inherit;
    font-size: var(--font-size-sm);
    font-weight: 500;
    transition: background var(--transition-fast), border-color var(--transition-fast);
  }

  .picker-secondary-btn:hover {
    background: var(--bg-hover);
  }

  .picker-add-btn,
  .row-add-btn {
    min-height: 30px;
    padding: 0 10px;
    border: 1px solid color-mix(in srgb, var(--accent) 35%, var(--border));
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    color: var(--accent);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    font-size: var(--font-size-sm);
    font-weight: 600;
    font-family: inherit;
    transition: background var(--transition-fast), border-color var(--transition-fast), color var(--transition-fast);
  }

  .picker-add-btn:hover:not(:disabled),
  .row-add-btn:hover:not(:disabled) {
    background: color-mix(in srgb, var(--accent) 22%, transparent);
    border-color: var(--accent);
  }

  .picker-add-btn:disabled,
  .row-add-btn:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .picker-add-btn svg,
  .row-add-btn svg {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
  }

  .picker-banner {
    font-size: var(--font-size-sm);
    padding: 8px 10px;
    border-radius: var(--radius-md);
    flex-shrink: 0;
  }

  .picker-banner-error {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 12%, transparent);
  }

  .picker-banner-note {
    color: var(--text-muted);
    background: color-mix(in srgb, var(--accent) 10%, transparent);
  }

  .picker-table-wrap {
    flex: 1;
    min-height: 0;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }

  .picker-table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--font-size-md);
  }

  .picker-table th {
    position: sticky;
    top: 0;
    z-index: 1;
    text-align: left;
    font-size: var(--font-size-xs);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    background: var(--bg-secondary);
  }

  .picker-table td {
    padding: 8px 10px;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 50%, transparent);
    color: var(--text-primary);
    vertical-align: middle;
  }

  .picker-table tbody tr:hover td {
    background: color-mix(in srgb, var(--bg-hover) 70%, transparent);
  }

  .picker-table tbody tr.selected td {
    background: var(--table-row-selected);
  }

  .picker-table tbody tr.added td {
    color: var(--text-muted);
  }

  .sort-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 0;
    border: none;
    background: none;
    color: inherit;
    font: inherit;
    letter-spacing: inherit;
    text-transform: inherit;
    cursor: pointer;
  }

  .sort-btn:hover {
    color: var(--text-primary);
  }

  .sort-arrow {
    font-size: 8px;
  }

  .picker-table .col-select {
    width: 32px;
    padding-right: 0;
    text-align: center;
  }

  .col-select input {
    margin: 0;
    cursor: pointer;
    accent-color: var(--accent);
  }

  .col-select input:disabled {
    cursor: default;
  }

  .col-name {
    max-width: 0;
    width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .name-cell {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .name-text {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .file-tag {
    flex-shrink: 0;
    padding: 1px 6px;
    border-radius: var(--radius-pill);
    font-size: var(--font-size-2xs);
    font-weight: 600;
    line-height: 16px;
  }

  .tag-added {
    color: var(--success);
    background: color-mix(in srgb, var(--success) 14%, transparent);
  }

  .col-type {
    width: 96px;
    white-space: nowrap;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }

  .col-size {
    width: 96px;
    white-space: nowrap;
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .col-action {
    width: 92px;
    text-align: right;
    white-space: nowrap;
  }

  .add-done {
    min-height: 30px;
    padding: 0 10px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: var(--success);
  }

  .add-done svg {
    width: 14px;
    height: 14px;
  }

  .picker-footer {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 12px 20px;
    border-top: 1px solid var(--border);
    flex-shrink: 0;
  }

  @media (max-width: 640px) {
    .col-type {
      display: none;
    }
  }
</style>
