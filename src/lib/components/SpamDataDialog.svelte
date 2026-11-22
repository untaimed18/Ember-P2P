<script lang="ts">
  // What the spam filter has learned, list by list, as Settings > Search
  // counts it: the files marked spam, each of which can be unmarked, the
  // files it trusts, each of which can be forgotten, and the names and
  // addresses it learned from the marks.
  import * as m from '$lib/paraglide/messages';
  import {
    forgetNotSpam,
    getLearnedSpam,
    getSpamStats,
    unmarkSpam,
    type LearnedSpamEntry,
    type LearnedSpamList,
  } from '$lib/api/search';
  import type { SpamStats } from '$lib/types';
  import { notifySpamVerdictRemoved } from '$lib/stores/search';
  import { translateError } from '$lib/i18n';
  import { toastsFor } from '$lib/stores/toast';
  import { formatNumber, formatSize } from '$lib/utils';
  import IconX from './IconX.svelte';
  import { onDestroy, tick, untrack } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground, trapTabKey } from '$lib/a11y';

  const { toastSuccess } = toastsFor('search');

  let { open = $bindable(false), onchange }: { open?: boolean; onchange?: () => void } = $props();

  const PAGE = 100;
  /** Typing waits this long before the list is asked again. */
  const QUERY_DELAY_MS = 200;

  const LISTS: {
    id: LearnedSpamList;
    label: () => string;
    hint: () => string;
    count: (s: SpamStats) => number;
  }[] = [
    { id: 'spam', label: m.settings_spam_stat_hashes, hint: m.settings_spam_data_spam_hint, count: (s) => s.spam_hashes },
    { id: 'not_spam', label: m.settings_spam_stat_not_spam_hashes, hint: m.settings_spam_data_not_spam_hint, count: (s) => s.not_spam_hashes },
    { id: 'names', label: m.settings_spam_stat_names, hint: m.settings_spam_data_names_hint, count: (s) => s.spam_filenames },
    { id: 'source_ips', label: m.settings_spam_stat_source_ips, hint: m.settings_spam_data_ips_hint, count: (s) => s.spam_source_ips },
  ];

  let list = $state<LearnedSpamList>('spam');
  let query = $state('');
  let entries = $state<LearnedSpamEntry[]>([]);
  let matched = $state(0);
  /** How far into the list the pages have read: the next page's offset. A
   *  row shown twice is dropped, so this can run ahead of `entries`. */
  let fetched = $state(0);
  let stats = $state<SpamStats | null>(null);
  let loaded = $state(false);
  let loadingMore = $state(false);
  let loadError = $state<string | null>(null);
  /** Files whose Unmark or Forget is on its way. */
  let removing = $state<string[]>([]);
  let error = $state<string | null>(null);
  let loadSeq = 0;
  /** Files taken off a list since the dialog opened. */
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
  let current = $derived(LISTS.find((l) => l.id === list) ?? LISTS[0]);
  let isFiles = $derived(list === 'spam' || list === 'not_spam');

  /** The first page of the open list, or with `more` the next one. */
  async function load(more = false) {
    if (more && (loadingMore || readingFirstPage || queryTimer)) return;
    const seq = ++loadSeq;
    if (more) loadingMore = true;
    else readingFirstPage = true;
    try {
      let offset: number;
      let page: Awaited<ReturnType<typeof getLearnedSpam>>;
      let removalsBefore: number;
      // A page read before a file was taken off would put its row back.
      do {
        removalsBefore = removals;
        offset = more ? fetched : 0;
        page = await getLearnedSpam(list, query, offset, PAGE);
        if (unmounted || seq !== loadSeq) return;
      } while (removals !== removalsBefore);
      const firstNew = more ? entries.length : 0;
      fetched = offset + page.entries.length;
      if (more) {
        // A download finishing between pages moves the list under them and
        // brings a row back that is already shown.
        const shown = new Set(entries.map(entryKey));
        entries = [...entries, ...page.entries.filter((e) => !shown.has(entryKey(e)))];
      } else {
        entries = page.entries;
      }
      matched = page.matched;
      loadError = null;
      void tick().then(() => keepFocusInDialog(removeButton(entries[firstNew]?.hash)));
    } catch (e: unknown) {
      if (unmounted || seq !== loadSeq) return;
      if (!more) entries = [];
      loadError = translateError(e, m.settings_spam_data_load_failed());
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
      const s = await getSpamStats();
      if (!unmounted) stats = s;
    } catch {
      // The tabs go without their counts; the list says what failed.
    }
  }

  function selectList(id: LearnedSpamList) {
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
      list = 'spam';
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

  onDestroy(() => {
    unmounted = true;
    if (queryTimer) clearTimeout(queryTimer);
  });

  function entryKey(entry: LearnedSpamEntry): string {
    return entry.hash ?? entry.text;
  }

  /** The file as a toast or a screen reader names it: a file with no known
   *  name goes by the start of its hash, which tells one from another. */
  function fileName(entry: LearnedSpamEntry): string {
    return entry.text || (entry.hash ? `${entry.hash.slice(0, 12)}…` : m.settings_spam_data_name_unknown());
  }

  function removeButton(hash: string | null | undefined): HTMLButtonElement | null {
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

  /** Take a file off its list: unmark a spam file, or stop trusting a file
   *  marked not spam or downloaded. */
  async function remove(entry: LearnedSpamEntry) {
    const hash = entry.hash;
    if (!hash || removing.includes(hash)) return;
    const spam = list === 'spam';
    removing = [...removing, hash];
    error = null;
    try {
      await (spam ? unmarkSpam(hash) : forgetNotSpam(hash));
      if (unmounted) return;
      removals++;
      const index = entries.findIndex((e) => e.hash === hash);
      entries = entries.filter((e) => e.hash !== hash);
      matched = Math.max(0, matched - 1);
      fetched = Math.max(0, fetched - 1);
      const next = index < 0 ? undefined : (entries[index] ?? entries[index - 1]);
      const name = fileName(entry);
      toastSuccess(spam ? m.settings_spam_data_unmarked({ name }) : m.settings_spam_data_forgotten({ name }));
      notifySpamVerdictRemoved(hash);
      void loadStats();
      onchange?.();
      await tick();
      focusAfterRemoving(hash, next?.hash);
    } catch (e: unknown) {
      if (!unmounted) error = translateError(e, m.error_operation_failed());
    } finally {
      if (!unmounted) removing = removing.filter((h) => h !== hash);
    }
  }

  /** The button pressed leaves with its row, fading out first, which would
   *  drop focus out of the dialog. Hand it to the row that took that place. */
  function focusAfterRemoving(removedHash: string, nextHash: string | null | undefined) {
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
    class="spam-overlay"
    bind:this={overlayEl}
    onclick={() => (open = false)}
    onkeydown={onKeydown}
    transition:fade={{ duration: 150 * motion }}
  >
    <div
      class="spam-panel"
      role="dialog"
      aria-modal="true"
      aria-labelledby="spam-data-title"
      aria-describedby="spam-data-hint"
      tabindex="-1"
      bind:this={panelEl}
      onclick={(e) => e.stopPropagation()}
      transition:scale={{ start: 0.96, opacity: 0, duration: 200 * motion }}
    >
      <header class="spam-header">
        <div class="spam-heading">
          <span class="spam-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M3 5h18l-7 8v5l-4 2v-7z" />
            </svg>
          </span>
          <div>
            <h3 id="spam-data-title">{m.settings_spam_db_label()}</h3>
            <p id="spam-data-hint" class="spam-hint">{m.settings_spam_db_hint()}</p>
          </div>
        </div>
        <button type="button" class="icon-close" title={m.common_close()} aria-label={m.common_close()} onclick={() => (open = false)}>
          <IconX size={16} />
        </button>
      </header>

      <div class="spam-tabs" role="tablist" aria-label={m.settings_spam_db_label()}>
        {#each LISTS as tab, index (tab.id)}
          <button
            type="button"
            role="tab"
            class="spam-tab"
            id="spam-data-tab-{tab.id}"
            data-list={tab.id}
            aria-selected={list === tab.id}
            aria-controls="spam-data-panel"
            tabindex={list === tab.id ? 0 : -1}
            onclick={() => selectList(tab.id)}
            onkeydown={(e) => onTabKeydown(e, index)}
          >
            {tab.label()}
            {#if stats}
              <span class="spam-count">{formatNumber(tab.count(stats))}</span>
            {/if}
          </button>
        {/each}
      </div>

      <div class="spam-toolbar">
        <input
          bind:this={searchEl}
          type="search"
          class="spam-search"
          bind:value={query}
          oninput={onQueryInput}
          placeholder={m.settings_spam_data_search()}
          aria-label={m.settings_spam_data_search()}
          aria-controls="spam-data-panel"
        />
        {#if loaded && !loadError && matched > 0}
          <span class="spam-showing" role="status">
            {m.settings_spam_data_showing({ shown: formatNumber(entries.length), count: formatNumber(matched) })}
          </span>
        {/if}
      </div>

      {#if error}
        <div class="spam-message error" role="alert">{error}</div>
      {/if}

      <div class="spam-body" id="spam-data-panel" role="tabpanel" aria-labelledby="spam-data-tab-{list}">
        <p class="spam-list-hint">{current.hint()}</p>
        {#if !loaded}
          <div class="spam-placeholder">
            <span class="spinner"></span>
            <span>{m.common_loading()}</span>
          </div>
        {:else if loadError}
          <div class="spam-placeholder" role="alert">
            <p class="spam-load-error">{loadError}</p>
            <button type="button" class="secondary" onclick={() => void load()}>{m.common_retry()}</button>
          </div>
        {:else if entries.length === 0}
          <div class="spam-placeholder">
            <p class="spam-empty">{query.trim() ? m.settings_spam_data_no_match() : m.settings_spam_data_empty()}</p>
          </div>
        {:else}
          <ul class="spam-list">
            {#each entries as entry (entryKey(entry))}
              <li class="spam-row" out:fade={{ duration: 150 * motion }}>
                {#if isFiles}
                  <div class="who">
                    <bdi dir="auto" class="name" class:unnamed={!entry.text} title={entry.text || undefined}>{entry.text || m.settings_spam_data_name_unknown()}</bdi>
                    <span class="detail">
                      {#if list === 'not_spam'}
                        <span class="tag" class:downloaded={entry.downloaded}>
                          {entry.downloaded ? m.settings_spam_data_downloaded() : m.settings_spam_data_marked()}
                        </span>
                      {/if}
                      {#if entry.size !== null}
                        <span class="size">{formatSize(entry.size)}</span>
                      {/if}
                      <span class="hash" title={entry.hash ?? ''}>{entry.hash}</span>
                    </span>
                  </div>
                  {#if entry.hash}
                    <button
                      type="button"
                      class="secondary remove-btn"
                      data-hash={entry.hash}
                      onclick={() => void remove(entry)}
                      aria-disabled={removing.includes(entry.hash)}
                      aria-label={list === 'spam'
                        ? m.settings_spam_data_unmark_aria({ name: fileName(entry) })
                        : m.settings_spam_data_forget_aria({ name: fileName(entry) })}
                    >
                      {#if removing.includes(entry.hash)}
                        <span class="spinner xs current" aria-hidden="true"></span>
                      {/if}
                      {list === 'spam' ? m.settings_spam_data_unmark() : m.settings_spam_data_forget()}
                    </button>
                  {/if}
                {:else}
                  <bdi dir="auto" class="text" class:mono={list === 'source_ips'} title={entry.text}>{entry.text}</bdi>
                {/if}
              </li>
            {/each}
          </ul>
          {#if fetched < matched}
            <div class="spam-more">
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

      <footer class="spam-footer">
        <button type="button" class="secondary" onclick={() => (open = false)}>{m.common_close()}</button>
      </footer>
    </div>
  </div>
{/if}

<style>
  .spam-overlay {
    position: fixed;
    inset: 0;
    z-index: 10000;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--overlay-bg);
  }

  .spam-panel {
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

  .spam-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    padding: 18px 20px 14px;
  }
  .spam-heading {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    min-width: 0;
  }
  .spam-icon {
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
  .spam-header h3 {
    margin: 0;
    font-size: var(--font-size-lg);
    font-weight: 600;
  }
  .spam-hint {
    margin: 4px 0 0;
    max-width: 60ch;
    font-size: var(--font-size-sm);
    line-height: 1.45;
    color: var(--text-muted);
  }

  .spam-tabs {
    display: flex;
    gap: 2px;
    padding: 0 16px;
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
  }
  .spam-tab {
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
  .spam-tab:hover {
    color: var(--text-primary);
  }
  .spam-tab[aria-selected='true'] {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }
  .spam-tab:focus-visible {
    outline: none;
    box-shadow: inset 0 0 0 2px var(--accent-halo);
  }
  .spam-count {
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
  .spam-tab[aria-selected='true'] .spam-count {
    background: color-mix(in srgb, var(--accent) 16%, transparent);
    color: var(--accent);
  }

  .spam-toolbar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 20px 0;
  }
  .spam-search {
    flex: 1;
    min-width: 0;
    max-width: 24rem;
  }
  .spam-showing {
    margin-left: auto;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .spam-message {
    margin: 10px 20px 0;
    padding: 8px 12px;
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
  }
  .spam-message.error {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 9%, var(--bg-secondary));
  }

  .spam-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 10px 20px 14px;
  }
  .spam-list-hint {
    margin: 0 0 10px;
    font-size: var(--font-size-xs);
    line-height: 1.5;
    color: var(--text-muted);
  }
  .spam-placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    min-height: 200px;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }
  .spam-empty,
  .spam-load-error {
    margin: 0;
    max-width: 56ch;
    text-align: center;
  }
  .spam-load-error {
    color: var(--danger);
  }

  .spam-list {
    display: flex;
    flex-direction: column;
    margin: 0;
    padding: 0;
    list-style: none;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    overflow: hidden;
  }
  .spam-row {
    display: flex;
    align-items: center;
    gap: 12px;
    min-height: 40px;
    padding: 8px 12px;
    background: var(--bg-secondary);
  }
  .spam-row + .spam-row {
    border-top: 1px solid color-mix(in srgb, var(--border) 70%, transparent);
  }
  .spam-row:hover {
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
  .text,
  .hash {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .name,
  .text {
    font-size: var(--font-size-sm);
    color: var(--text-primary);
  }
  .name {
    font-weight: 500;
  }
  .name.unnamed {
    font-style: italic;
    color: var(--text-secondary);
  }
  .text {
    flex: 1;
    min-width: 0;
  }
  .mono,
  .hash {
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
  .size {
    flex-shrink: 0;
    font-variant-numeric: tabular-nums;
  }
  .hash {
    min-width: 0;
  }
  .tag {
    flex-shrink: 0;
    padding: 0 6px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    color: var(--accent);
    font-weight: 600;
    line-height: 16px;
  }
  .tag.downloaded {
    background: color-mix(in srgb, var(--success) 14%, transparent);
    color: var(--success);
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
  .spam-more button[aria-disabled='true'] {
    cursor: wait;
    opacity: 0.65;
  }

  .spam-more {
    display: flex;
    justify-content: center;
    padding-top: 12px;
  }
  .spam-more button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .spam-footer {
    display: flex;
    justify-content: flex-end;
    padding: 12px 20px;
    border-top: 1px solid var(--border);
  }
</style>
