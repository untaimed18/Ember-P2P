<script lang="ts">
  // The download history as Settings > Transfers counts it: every file
  // downloaded or cancelled that Search and friends' shared files mark, any
  // of which can be removed so it is no longer marked.
  import * as m from '$lib/paraglide/messages';
  import {
    getDownloadHistoryEntries,
    getDownloadHistoryStats,
    removeDownloadHistoryEntry,
    type DownloadHistoryEntry,
    type DownloadHistoryStatus,
  } from '$lib/api/search';
  import type { DownloadHistoryStats } from '$lib/types';
  import { translateError } from '$lib/i18n';
  import { toastsFor } from '$lib/stores/toast';
  import { formatDateWithYear, formatNumber, formatSize } from '$lib/utils';
  import IconX from './IconX.svelte';
  import { listen } from '@tauri-apps/api/event';
  import { onDestroy, tick, untrack } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground, trapTabKey } from '$lib/a11y';

  const { toastSuccess } = toastsFor('downloads');

  let { open = $bindable(false), onchange }: { open?: boolean; onchange?: () => void } = $props();

  const PAGE = 100;
  /** Typing waits this long before the list is asked again. */
  const QUERY_DELAY_MS = 200;

  const LISTS: {
    id: DownloadHistoryStatus;
    label: () => string;
    count: (s: DownloadHistoryStats) => number;
  }[] = [
    { id: 'all', label: m.settings_history_tab_all, count: (s) => s.total },
    { id: 'completed', label: m.search_history_downloaded, count: (s) => s.completed },
    { id: 'cancelled', label: m.search_history_cancelled, count: (s) => s.cancelled },
  ];

  let list = $state<DownloadHistoryStatus>('all');
  let query = $state('');
  let entries = $state<DownloadHistoryEntry[]>([]);
  let matched = $state(0);
  /** How far into the list the pages have read: the next page's offset. A
   *  row shown twice is dropped, so this can run ahead of `entries`. */
  let fetched = $state(0);
  let stats = $state<DownloadHistoryStats | null>(null);
  let loaded = $state(false);
  let loadingMore = $state(false);
  let loadError = $state<string | null>(null);
  /** Files whose removal is on its way. */
  let removing = $state<string[]>([]);
  let error = $state<string | null>(null);
  let loadSeq = 0;
  /** Files removed since the dialog opened. */
  let removals = 0;
  /** A list or search is on its way in, whose rows Show more would follow. */
  let readingFirstPage = false;
  let queryTimer: ReturnType<typeof setTimeout> | null = null;
  let unmounted = false;

  let panelEl: HTMLDivElement | undefined = $state();
  let overlayEl: HTMLDivElement | undefined = $state();
  let searchEl: HTMLInputElement | undefined = $state();
  let returnFocusEl: HTMLElement | null = null;

  let motion = $derived(prefersReducedMotion.current ? 0 : 1);

  /** The first page of the open list, or with `more` the next one. */
  async function load(more = false) {
    if (more && (loadingMore || readingFirstPage || queryTimer)) return;
    const seq = ++loadSeq;
    if (more) loadingMore = true;
    else readingFirstPage = true;
    try {
      let offset: number;
      let page: Awaited<ReturnType<typeof getDownloadHistoryEntries>>;
      let removalsBefore: number;
      // A page read before a file was removed would put its row back.
      do {
        removalsBefore = removals;
        offset = more ? fetched : 0;
        page = await getDownloadHistoryEntries(list, query, offset, PAGE);
        if (unmounted || seq !== loadSeq) return;
      } while (removals !== removalsBefore);
      const firstNew = more ? entries.length : 0;
      fetched = offset + page.entries.length;
      if (more) {
        // A download finishing between pages moves the list under them and
        // brings a row back that is already shown.
        const shown = new Set(entries.map((e) => e.file_hash));
        entries = [...entries, ...page.entries.filter((e) => !shown.has(e.file_hash))];
      } else {
        entries = page.entries;
      }
      matched = page.matched;
      loadError = null;
      void tick().then(() => keepFocusInDialog(removeButton(entries[firstNew]?.file_hash)));
    } catch (e: unknown) {
      if (unmounted || seq !== loadSeq) return;
      if (!more) entries = [];
      loadError = translateError(e, m.settings_history_data_load_failed());
    } finally {
      if (!unmounted && seq === loadSeq) {
        loaded = true;
        loadingMore = false;
        readingFirstPage = false;
      }
    }
  }

  async function loadStats() {
    try {
      const s = await getDownloadHistoryStats();
      if (!unmounted) stats = s;
    } catch {
      // The tabs go without their counts; the list says what failed.
    }
  }

  function selectList(id: DownloadHistoryStatus) {
    if (id === list) return;
    list = id;
    loaded = false;
    error = null;
    void load();
  }

  function onQueryInput() {
    if (queryTimer) clearTimeout(queryTimer);
    queryTimer = setTimeout(() => {
      queryTimer = null;
      void load();
    }, QUERY_DELAY_MS);
  }

  /** Left and Right move between the tabs, as in every tab list. */
  function onTabKeydown(e: KeyboardEvent, index: number) {
    let next: number;
    if (e.key === 'ArrowRight') next = (index + 1) % LISTS.length;
    else if (e.key === 'ArrowLeft') next = (index - 1 + LISTS.length) % LISTS.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = LISTS.length - 1;
    else return;
    e.preventDefault();
    selectList(LISTS[next].id);
    void tick().then(() => panelEl?.querySelector<HTMLButtonElement>(`[data-list="${LISTS[next].id}"]`)?.focus());
  }

  $effect(() => {
    if (!open) return;
    // What loading reads is not what opening depends on.
    untrack(() => {
      list = 'all';
      query = '';
      entries = [];
      fetched = 0;
      loaded = false;
      error = null;
      void load();
      void loadStats();
    });
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
    requestAnimationFrame(() => (searchEl ?? panelEl)?.focus());
    return () => {
      if (queryTimer) clearTimeout(queryTimer);
      queryTimer = null;
      const el = returnFocusEl;
      returnFocusEl = null;
      if (el) requestAnimationFrame(() => { if (document.contains(el)) el.focus(); });
    };
  });

  $effect(() => {
    if (!open || !overlayEl) return;
    return inertBackground(overlayEl);
  });

  // The history can change from elsewhere while this is open: Search's own
  // Remove, or on emberd another browser.
  $effect(() => {
    if (!open) return;
    let live = true;
    const unlisten: (() => void)[] = [];
    const keep = (u: () => void) => (live ? unlisten.push(u) : u());
    listen('download-history-cleared', () => {
      entries = [];
      fetched = 0;
      loaded = false;
      void load();
      void loadStats();
      onchange?.();
    }).then(keep).catch(() => {});
    listen<{ hash: string }>('download-history-removed', (event) => {
      if (!event.payload?.hash) return;
      dropEntry(event.payload.hash);
      void loadStats();
      onchange?.();
    }).then(keep).catch(() => {});
    return () => {
      live = false;
      for (const u of unlisten) u();
    };
  });

  onDestroy(() => {
    unmounted = true;
    if (queryTimer) clearTimeout(queryTimer);
  });

  /** The file as a toast or a screen reader names it: a file with no known
   *  name goes by the start of its hash, which tells one from another. */
  function fileName(entry: DownloadHistoryEntry): string {
    return entry.file_name || `${entry.file_hash.slice(0, 12)}…`;
  }

  function removeButton(hash: string | undefined): HTMLButtonElement | null {
    return hash
      ? (panelEl?.querySelector<HTMLButtonElement>(`.remove-btn[data-hash="${CSS.escape(hash)}"]`) ?? null)
      : null;
  }

  /** A button that goes away with what it did (Show more, Retry) takes focus
   *  out of the dialog, and Escape stops reaching it. Hand focus to `next`,
   *  or the search box. */
  function keepFocusInDialog(next?: HTMLElement | null) {
    if (!open || !panelEl) return;
    const active = document.activeElement;
    if (active instanceof HTMLElement && panelEl.contains(active)) return;
    (next ?? searchEl ?? panelEl).focus();
  }

  /** Take the row for `hash` off the list once, whichever of the call and its
   *  event arrives first. */
  function dropEntry(hash: string) {
    const lower = hash.toLowerCase();
    const before = entries.length;
    entries = entries.filter((e) => e.file_hash.toLowerCase() !== lower);
    const gone = before - entries.length;
    if (gone === 0) return;
    removals++;
    matched = Math.max(0, matched - gone);
    fetched = Math.max(0, fetched - gone);
  }

  async function remove(entry: DownloadHistoryEntry) {
    const hash = entry.file_hash;
    if (removing.includes(hash)) return;
    removing = [...removing, hash];
    error = null;
    const index = entries.findIndex((e) => e.file_hash === hash);
    try {
      await removeDownloadHistoryEntry(hash);
      if (unmounted) return;
      dropEntry(hash);
      const next = index < 0 ? undefined : (entries[index] ?? entries[index - 1]);
      toastSuccess(m.settings_history_data_removed({ name: fileName(entry) }));
      void loadStats();
      onchange?.();
      await tick();
      focusAfterRemoving(hash, next?.file_hash);
    } catch (e: unknown) {
      if (!unmounted) error = translateError(e, m.search_failed_remove_history());
    } finally {
      if (!unmounted) removing = removing.filter((h) => h !== hash);
    }
  }

  /** The button pressed leaves with its row, fading out first, which would
   *  drop focus out of the dialog. Hand it to the row that took that place. */
  function focusAfterRemoving(removedHash: string, nextHash: string | undefined) {
    const active = document.activeElement;
    const leaving = active instanceof HTMLElement && active.dataset.hash === removedHash;
    if (leaving) (removeButton(nextHash) ?? searchEl ?? panelEl)?.focus();
    else keepFocusInDialog(removeButton(nextHash));
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      open = false;
      return;
    }
    trapTabKey(e, panelEl);
  }

  /** Escape still closes the dialog when focus has fallen out of it, which
   *  the page behind, made inert, leaves only on the document body. */
  function onWindowKeydown(e: KeyboardEvent) {
    if (!open || e.key !== 'Escape' || e.defaultPrevented) return;
    if (e.target instanceof Node && overlayEl?.contains(e.target)) return;
    e.preventDefault();
    open = false;
  }
</script>

<svelte:window onkeydown={onWindowKeydown} />

{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div
    class="history-overlay"
    bind:this={overlayEl}
    onclick={() => (open = false)}
    onkeydown={onKeydown}
    transition:fade={{ duration: 150 * motion }}
  >
    <div
      class="history-panel"
      role="dialog"
      aria-modal="true"
      aria-labelledby="download-history-title"
      aria-describedby="download-history-hint"
      tabindex="-1"
      bind:this={panelEl}
      onclick={(e) => e.stopPropagation()}
      transition:scale={{ start: 0.96, opacity: 0, duration: 200 * motion }}
    >
      <header class="history-header">
        <div class="history-heading">
          <span class="history-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M3 12a9 9 0 1 0 3-6.7" />
              <path d="M3 4v4h4" />
              <path d="M12 7v5l3 2" />
            </svg>
          </span>
          <div>
            <h3 id="download-history-title">{m.settings_download_history()}</h3>
            <p id="download-history-hint" class="history-hint">{m.settings_download_history_hint()}</p>
          </div>
        </div>
        <button type="button" class="icon-close" title={m.common_close()} aria-label={m.common_close()} onclick={() => (open = false)}>
          <IconX size={16} />
        </button>
      </header>

      <div class="history-tabs" role="tablist" aria-label={m.settings_download_history()}>
        {#each LISTS as tab, index (tab.id)}
          <button
            type="button"
            role="tab"
            class="history-tab"
            id="download-history-tab-{tab.id}"
            data-list={tab.id}
            aria-selected={list === tab.id}
            aria-controls="download-history-panel"
            tabindex={list === tab.id ? 0 : -1}
            onclick={() => selectList(tab.id)}
            onkeydown={(e) => onTabKeydown(e, index)}
          >
            {tab.label()}
            {#if stats}
              <span class="history-count">{formatNumber(tab.count(stats))}</span>
            {/if}
          </button>
        {/each}
      </div>

      <div class="history-toolbar">
        <input
          bind:this={searchEl}
          type="search"
          class="history-search"
          bind:value={query}
          oninput={onQueryInput}
          placeholder={m.settings_history_data_search()}
          aria-label={m.settings_history_data_search()}
          aria-controls="download-history-panel"
        />
        {#if loaded && !loadError && matched > 0}
          <span class="history-showing" role="status">
            {m.settings_spam_data_showing({ shown: formatNumber(entries.length), count: formatNumber(matched) })}
          </span>
        {/if}
      </div>

      {#if error}
        <div class="history-message error" role="alert">{error}</div>
      {/if}

      <div class="history-body" id="download-history-panel" role="tabpanel" aria-labelledby="download-history-tab-{list}">
        {#if !loaded}
          <div class="history-placeholder">
            <span class="spinner"></span>
            <span>{m.common_loading()}</span>
          </div>
        {:else if loadError}
          <div class="history-placeholder" role="alert">
            <p class="history-load-error">{loadError}</p>
            <button type="button" class="secondary" onclick={() => void load()}>{m.common_retry()}</button>
          </div>
        {:else if entries.length === 0}
          <div class="history-placeholder">
            <p class="history-empty">{query.trim() ? m.settings_spam_data_no_match() : m.settings_spam_data_empty()}</p>
          </div>
        {:else}
          <ul class="history-list">
            {#each entries as entry (entry.file_hash)}
              <li class="history-row" out:fade={{ duration: 150 * motion }}>
                <div class="who">
                  <bdi dir="auto" class="name" class:unnamed={!entry.file_name} title={entry.file_name || undefined}>
                    {entry.file_name || m.settings_spam_data_name_unknown()}
                  </bdi>
                  <span class="detail">
                    <span class="tag" class:cancelled={entry.status === 'cancelled'}>
                      {entry.status === 'cancelled' ? m.search_history_cancelled() : m.search_history_downloaded()}
                    </span>
                    <span class="when">{formatDateWithYear(entry.timestamp)}</span>
                    {#if entry.file_size > 0}
                      <span class="size">{formatSize(entry.file_size)}</span>
                    {/if}
                    <span class="hash" title={entry.file_hash}>{entry.file_hash}</span>
                  </span>
                </div>
                <button
                  type="button"
                  class="secondary remove-btn"
                  data-hash={entry.file_hash}
                  onclick={() => void remove(entry)}
                  aria-disabled={removing.includes(entry.file_hash)}
                  aria-label={m.settings_history_data_remove_aria({ name: fileName(entry) })}
                >
                  {#if removing.includes(entry.file_hash)}
                    <span class="spinner xs current" aria-hidden="true"></span>
                  {/if}
                  {m.common_remove()}
                </button>
              </li>
            {/each}
          </ul>
          {#if fetched < matched}
            <div class="history-more">
              <button type="button" class="secondary" onclick={() => void load(true)} aria-disabled={loadingMore} aria-busy={loadingMore}>
                {#if loadingMore}
                  <span class="spinner xs current" aria-hidden="true"></span>
                {/if}
                {m.settings_spam_data_show_more()}
              </button>
            </div>
          {/if}
        {/if}
      </div>

      <footer class="history-footer">
        <button type="button" class="secondary" onclick={() => (open = false)}>{m.common_close()}</button>
      </footer>
    </div>
  </div>
{/if}

<style>
  .history-overlay {
    position: fixed;
    inset: 0;
    z-index: 10000;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--overlay-bg);
  }

  .history-panel {
    display: flex;
    flex-direction: column;
    width: min(760px, calc(100vw - 40px));
    height: min(78vh, 680px);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow:
      inset 0 1px 0 var(--surface-highlight),
      var(--shadow-lg);
    overflow: hidden;
  }

  .history-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    padding: 18px 20px 14px;
  }
  .history-heading {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    min-width: 0;
  }
  .history-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 34px;
    height: 34px;
    border-radius: var(--radius-md);
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 12%, transparent);
  }
  .history-header h3 {
    margin: 0;
    font-size: var(--font-size-lg);
    font-weight: 600;
  }
  .history-hint {
    margin: 4px 0 0;
    max-width: 60ch;
    font-size: var(--font-size-sm);
    line-height: 1.45;
    color: var(--text-muted);
  }

  .history-tabs {
    display: flex;
    gap: 2px;
    padding: 0 16px;
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
  }
  .history-tab {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 10px;
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0;
    background: none;
    color: var(--text-secondary);
    font-size: var(--font-size-sm);
    font-weight: 500;
    white-space: nowrap;
    cursor: pointer;
  }
  .history-tab:hover {
    color: var(--text-primary);
  }
  .history-tab[aria-selected='true'] {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }
  .history-tab:focus-visible {
    outline: none;
    box-shadow: inset 0 0 0 2px var(--accent-halo);
  }
  .history-count {
    min-width: 20px;
    padding: 0 6px;
    border-radius: var(--radius-pill);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-size: var(--font-size-2xs);
    font-weight: 600;
    line-height: 18px;
    text-align: center;
    font-variant-numeric: tabular-nums;
  }
  .history-tab[aria-selected='true'] .history-count {
    background: color-mix(in srgb, var(--accent) 16%, transparent);
    color: var(--accent);
  }

  .history-toolbar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 20px 0;
  }
  .history-search {
    flex: 1;
    min-width: 0;
    max-width: 24rem;
  }
  .history-showing {
    margin-left: auto;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .history-message {
    margin: 10px 20px 0;
    padding: 8px 12px;
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
  }
  .history-message.error {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 9%, var(--bg-secondary));
  }

  .history-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 12px 20px 14px;
  }
  .history-placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    min-height: 200px;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }
  .history-empty,
  .history-load-error {
    margin: 0;
    max-width: 56ch;
    text-align: center;
  }
  .history-load-error {
    color: var(--danger);
  }

  .history-list {
    display: flex;
    flex-direction: column;
    margin: 0;
    padding: 0;
    list-style: none;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    overflow: hidden;
  }
  .history-row {
    display: flex;
    align-items: center;
    gap: 12px;
    min-height: 40px;
    padding: 8px 12px;
    background: var(--bg-secondary);
  }
  .history-row + .history-row {
    border-top: 1px solid color-mix(in srgb, var(--border) 70%, transparent);
  }
  .history-row:hover {
    background: var(--bg-hover);
  }

  .who {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .name,
  .hash {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .name {
    font-size: var(--font-size-sm);
    font-weight: 500;
    color: var(--text-primary);
  }
  .name.unnamed {
    font-style: italic;
    color: var(--text-secondary);
  }
  .hash {
    min-width: 0;
    font-family: var(--font-mono);
  }
  .detail {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    font-size: var(--font-size-2xs);
    color: var(--text-muted);
  }
  .when,
  .size {
    flex-shrink: 0;
    font-variant-numeric: tabular-nums;
  }
  .tag {
    flex-shrink: 0;
    padding: 0 6px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--success) 14%, transparent);
    color: var(--success);
    font-weight: 600;
    line-height: 16px;
  }
  .tag.cancelled {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
  }

  .remove-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
    padding: 4px 12px;
    font-size: var(--font-size-sm);
  }
  /* Busy, not disabled: a disabled button drops focus out of the dialog. */
  .remove-btn[aria-disabled='true'],
  .history-more button[aria-disabled='true'] {
    cursor: wait;
    opacity: 0.65;
  }

  .history-more {
    display: flex;
    justify-content: center;
    padding-top: 12px;
  }
  .history-more button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .history-footer {
    display: flex;
    justify-content: flex-end;
    padding: 12px 20px;
    border-top: 1px solid var(--border);
  }
</style>
