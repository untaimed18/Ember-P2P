<script lang="ts">
  // Another member's room library: their folders for this room, a search
  // across them, and Download, which fetches a file as a room transfer.
  import * as m from '$lib/paraglide/messages';
  import {
    browseRoomLibrary,
    fetchRoomLibraryFile,
    type RoomLibraryEntry,
    type RoomLibraryPage,
  } from '$lib/api/roomLibrary';
  import { translateError } from '$lib/i18n';
  import { channelTransfers } from '$lib/stores/channels';
  import { toastsFor } from '$lib/stores/toast';
  import { formatDateWithYear, formatNumber, formatSize } from '$lib/utils';
  import IconX from './IconX.svelte';
  import { onDestroy, tick, untrack } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground, trapTabKey } from '$lib/a11y';

  const { toastSuccess } = toastsFor('channels');

  let {
    open = $bindable(false),
    channelId,
    memberPubkey,
    memberName,
  }: {
    open?: boolean;
    channelId: string;
    memberPubkey: string;
    memberName: string;
  } = $props();

  /** Rows read per Show more. Each page the member sends holds a dozen or
   *  so, so this is several asks in a row. */
  const BATCH = 150;
  /** Typing waits this long before the library is searched. */
  const QUERY_DELAY_MS = 350;

  type Crumb = { id: string | null; name: string };

  let trail = $state<Crumb[]>([]);
  let query = $state('');
  let entries = $state<RoomLibraryEntry[]>([]);
  let total = $state(0);
  /** The next page's offset. */
  let fetched = $state(0);
  let loaded = $state(false);
  let loading = $state(false);
  let closed = $state(false);
  let missing = $state(false);
  let loadError = $state<string | null>(null);
  let error = $state<string | null>(null);
  /** Files whose fetch is being asked for; those on their way, by the room
   *  transfer each arrives as; and those that arrived. */
  let asking = $state<string[]>([]);
  let requested = $state<Record<string, string>>({});
  let arrived = $state<string[]>([]);
  /** Where a fetch ends without the file, which can then be asked for again. */
  const ENDED_WITHOUT_FILE = new Set([
    'unavailable',
    'cancelled',
    'not_allowed',
    'declined',
    'stalled',
    'expired',
    'failed',
    'source_gone',
    'busy',
    'too_large',
  ]);
  let loadSeq = 0;
  let queryTimer: ReturnType<typeof setTimeout> | null = null;
  let unmounted = false;

  let panelEl: HTMLDivElement | undefined = $state();
  let overlayEl: HTMLDivElement | undefined = $state();
  let searchEl: HTMLInputElement | undefined = $state();
  let returnFocusEl: HTMLElement | null = null;
  let motion = $derived(prefersReducedMotion.current ? 0 : 1);

  let folder = $derived(trail.length > 0 ? trail[trail.length - 1].id : null);
  let searching = $derived(query.trim().length > 0);

  /** Read pages until `BATCH` more rows are in or the list ends. Starting
   *  over when `more` is false. */
  async function load(more = false) {
    if (more && loading) return;
    const seq = ++loadSeq;
    const at = { folder, query: query.trim() };
    loading = true;
    if (!more) {
      entries = [];
      fetched = 0;
      total = 0;
      loaded = false;
      closed = false;
      missing = false;
      loadError = null;
    }
    try {
      const goal = fetched + BATCH;
      let page: RoomLibraryPage;
      do {
        page = await browseRoomLibrary(channelId, memberPubkey, at.folder, at.query, fetched);
        if (unmounted || seq !== loadSeq) return;
        if (page.closed || page.missing) {
          closed = page.closed;
          missing = page.missing;
          entries = [];
          total = 0;
          break;
        }
        total = page.total;
        const seen = new Set(entries.map((e) => e.id));
        entries = [...entries, ...page.entries.filter((e) => !seen.has(e.id))];
        fetched += page.entries.length;
      } while (page.entries.length > 0 && fetched < total && fetched < goal);
      loadError = null;
    } catch (e: unknown) {
      if (unmounted || seq !== loadSeq) return;
      if (!more) entries = [];
      loadError = translateError(e, m.channels_library_load_failed());
    } finally {
      if (!unmounted && seq === loadSeq) {
        loaded = true;
        loading = false;
      }
    }
  }

  function enter(entry: RoomLibraryEntry) {
    if (!entry.is_folder) return;
    if (queryTimer) clearTimeout(queryTimer);
    queryTimer = null;
    query = '';
    trail = [...trail, { id: entry.id, name: entry.name }];
    void load();
    void tick().then(() => searchEl?.focus());
  }

  function goTo(index: number) {
    if (queryTimer) clearTimeout(queryTimer);
    queryTimer = null;
    query = '';
    trail = index < 0 ? [] : trail.slice(0, index + 1);
    void load();
  }

  function onQueryInput() {
    if (queryTimer) clearTimeout(queryTimer);
    queryTimer = setTimeout(() => {
      queryTimer = null;
      void load();
    }, QUERY_DELAY_MS);
  }

  function unavailable(entry: RoomLibraryEntry): boolean {
    return asking.includes(entry.id) || entry.id in requested || arrived.includes(entry.id);
  }

  // A fetch is followed through its room transfer: one that arrives stays
  // marked, one that ends without the file can be asked for again.
  $effect(() => {
    const rows = $channelTransfers;
    untrack(() => {
      let next: Record<string, string> | null = null;
      for (const [entryId, xferId] of Object.entries(requested)) {
        const status = rows[xferId]?.status;
        if (status === 'complete') {
          if (!arrived.includes(entryId)) arrived = [...arrived, entryId];
        } else if (!status || !ENDED_WITHOUT_FILE.has(status)) {
          continue;
        }
        next ??= { ...requested };
        delete next[entryId];
      }
      if (next) requested = next;
    });
  });

  async function download(entry: RoomLibraryEntry) {
    if (entry.is_folder || unavailable(entry)) return;
    asking = [...asking, entry.id];
    error = null;
    try {
      const xferId = await fetchRoomLibraryFile(channelId, memberPubkey, entry);
      if (unmounted) return;
      requested = { ...requested, [entry.id]: xferId };
      toastSuccess(m.channels_library_download_queued({ name: entry.name }));
    } catch (e: unknown) {
      if (!unmounted) error = translateError(e, m.browse_download_failed());
    } finally {
      if (!unmounted) asking = asking.filter((id) => id !== entry.id);
    }
  }

  $effect(() => {
    if (!open) return;
    untrack(() => {
      trail = [];
      query = '';
      asking = [];
      requested = {};
      arrived = [];
      error = null;
      void load();
    });
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
    requestAnimationFrame(() => (searchEl ?? panelEl)?.focus());
    return () => {
      loadSeq++;
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

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      open = false;
      return;
    }
    trapTabKey(e, panelEl);
  }

  function onWindowKeydown(e: KeyboardEvent) {
    if (!open || e.key !== 'Escape' || e.defaultPrevented) return;
    if (e.target instanceof Node && overlayEl?.contains(e.target)) return;
    e.preventDefault();
    open = false;
  }

  function onRowKeydown(e: KeyboardEvent, entry: RoomLibraryEntry) {
    if (e.target !== e.currentTarget || !entry.is_folder) return;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      enter(entry);
    }
  }
</script>

<svelte:window onkeydown={onWindowKeydown} />

{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div
    class="shelf-overlay"
    bind:this={overlayEl}
    onclick={() => (open = false)}
    onkeydown={onKeydown}
    transition:fade={{ duration: 150 * motion }}
  >
    <div
      class="shelf-panel"
      role="dialog"
      aria-modal="true"
      aria-labelledby="room-library-browse-title"
      aria-describedby="room-library-browse-hint"
      tabindex="-1"
      bind:this={panelEl}
      onclick={(e) => e.stopPropagation()}
      transition:scale={{ start: 0.96, opacity: 0, duration: 200 * motion }}
    >
      <header class="shelf-header">
        <div class="shelf-heading">
          <span class="shelf-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M4 4.5h4v15H4zM10 4.5h4v15h-4z" />
              <path d="m16 5.2 3.8-1 3.4 14.4-3.8 1z" />
            </svg>
          </span>
          <div>
            <h3 id="room-library-browse-title"><bdi dir="auto">{m.channels_library_browse_title({ name: memberName })}</bdi></h3>
            <p id="room-library-browse-hint" class="shelf-hint">{m.channels_library_browse_hint()}</p>
          </div>
        </div>
        <button type="button" class="icon-close" title={m.common_close()} aria-label={m.common_close()} onclick={() => (open = false)}>
          <IconX size={16} />
        </button>
      </header>

      <div class="shelf-toolbar">
        <nav class="crumbs" aria-label={m.channels_library_where()}>
          <button type="button" class="crumb" aria-current={trail.length === 0 && !searching ? 'location' : undefined} onclick={() => goTo(-1)}>
            {m.channels_library_top()}
          </button>
          {#each trail as crumb, index (crumb.id)}
            <span class="crumb-sep" aria-hidden="true">/</span>
            <button
              type="button"
              class="crumb"
              aria-current={index === trail.length - 1 && !searching ? 'location' : undefined}
              onclick={() => goTo(index)}
            >
              <bdi dir="auto">{crumb.name}</bdi>
            </button>
          {/each}
        </nav>
        <input
          bind:this={searchEl}
          type="search"
          class="shelf-search"
          bind:value={query}
          oninput={onQueryInput}
          maxlength="64"
          placeholder={m.channels_library_search()}
          aria-label={m.channels_library_search()}
        />
      </div>

      {#if error}
        <div class="shelf-message error" role="alert">{error}</div>
      {/if}

      <div class="shelf-body" aria-busy={loading}>
        {#if !loaded}
          <div class="shelf-placeholder">
            <span class="spinner"></span>
            <span>{m.common_loading()}</span>
          </div>
        {:else if loadError}
          <div class="shelf-placeholder" role="alert">
            <p class="shelf-load-error">{loadError}</p>
            <button type="button" class="secondary" onclick={() => void load()}>{m.common_retry()}</button>
          </div>
        {:else if closed}
          <div class="shelf-placeholder"><p class="shelf-empty">{m.channels_library_closed()}</p></div>
        {:else if missing}
          <div class="shelf-placeholder">
            <p class="shelf-empty">{m.channels_library_missing()}</p>
            <button type="button" class="secondary" onclick={() => goTo(-1)}>{m.channels_library_top()}</button>
          </div>
        {:else if entries.length === 0}
          <div class="shelf-placeholder">
            <p class="shelf-empty">{searching ? m.channels_library_no_match() : m.channels_library_empty()}</p>
          </div>
        {:else}
          <ul class="shelf-list">
            {#each entries as entry (entry.id)}
              <li class="shelf-row" class:folder={entry.is_folder}>
                {#if entry.is_folder}
                  <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
                  <div
                    class="who open-folder"
                    role="button"
                    tabindex="0"
                    onclick={() => enter(entry)}
                    onkeydown={(e) => onRowKeydown(e, entry)}
                  >
                    <span class="name"><span class="kind" aria-hidden="true">▸</span> <bdi dir="auto">{entry.name}</bdi></span>
                    <span class="detail">{m.channels_library_items({ count: formatNumber(entry.items) })}</span>
                  </div>
                {:else}
                  <div class="who">
                    <bdi dir="auto" class="name" title={entry.name}>{entry.name}</bdi>
                    <span class="detail">
                      <span class="size">{formatSize(entry.size)}</span>
                      {#if entry.modified > 0}
                        <span class="when">{formatDateWithYear(entry.modified)}</span>
                      {/if}
                      {#if entry.folder}
                        <bdi dir="auto" class="in-folder">{m.channels_library_in_folder({ folder: entry.folder })}</bdi>
                      {/if}
                      {#if entry.risky}
                        <span class="risky" title={m.common_risky_file()}>{m.channels_library_risky()}</span>
                      {/if}
                    </span>
                  </div>
                  <button
                    type="button"
                    class="secondary row-btn"
                    onclick={() => void download(entry)}
                    aria-disabled={unavailable(entry)}
                    aria-label={m.channels_library_download_aria({ name: entry.name })}
                  >
                    {#if asking.includes(entry.id)}
                      <span class="spinner xs current" aria-hidden="true"></span>
                    {/if}
                    {arrived.includes(entry.id)
                      ? m.search_history_downloaded()
                      : entry.id in requested
                        ? m.channels_library_requested()
                        : m.browse_download()}
                  </button>
                {/if}
              </li>
            {/each}
          </ul>
          {#if fetched < total}
            <div class="shelf-more">
              <button type="button" class="secondary" onclick={() => void load(true)} aria-disabled={loading} aria-busy={loading}>
                {#if loading}
                  <span class="spinner xs current" aria-hidden="true"></span>
                {/if}
                {m.settings_spam_data_show_more()}
              </button>
            </div>
          {/if}
        {/if}
      </div>

      <footer class="shelf-footer">
        {#if loaded && !loadError && !closed && !missing && total > 0}
          <span class="shelf-showing" role="status">
            {m.settings_spam_data_showing({ shown: formatNumber(entries.length), count: formatNumber(total) })}
          </span>
        {/if}
        <button type="button" class="secondary" onclick={() => (open = false)}>{m.common_close()}</button>
      </footer>
    </div>
  </div>
{/if}

<style>
  .shelf-overlay {
    position: fixed;
    inset: 0;
    z-index: 10000;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--overlay-bg);
  }

  .shelf-panel {
    display: flex;
    flex-direction: column;
    width: min(760px, calc(100vw - 40px));
    height: min(80vh, 700px);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow:
      inset 0 1px 0 var(--surface-highlight),
      var(--shadow-lg);
    overflow: hidden;
  }

  .shelf-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    padding: 18px 20px 14px;
  }
  .shelf-heading {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    min-width: 0;
  }
  .shelf-icon {
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
  .shelf-header h3 {
    margin: 0;
    font-size: var(--font-size-lg);
    font-weight: 600;
  }
  .shelf-hint {
    margin: 4px 0 0;
    max-width: 62ch;
    font-size: var(--font-size-sm);
    line-height: 1.45;
    color: var(--text-muted);
  }

  .shelf-toolbar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 0 20px 12px;
    border-bottom: 1px solid var(--border);
  }
  .crumbs {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 2px;
    flex: 1;
    min-width: 0;
  }
  .crumb {
    max-width: 14rem;
    padding: 2px 6px;
    border: none;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text-secondary);
    font-size: var(--font-size-sm);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    cursor: pointer;
  }
  .crumb:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }
  .crumb[aria-current='location'] {
    color: var(--text-primary);
    font-weight: 600;
  }
  .crumb-sep {
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }
  .shelf-search {
    flex: 0 1 16rem;
    min-width: 0;
  }

  .shelf-message {
    margin: 10px 20px 0;
    padding: 8px 12px;
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
  }
  .shelf-message.error {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 9%, var(--bg-secondary));
  }

  .shelf-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 12px 20px 14px;
  }
  .shelf-placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    min-height: 200px;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }
  .shelf-empty,
  .shelf-load-error {
    margin: 0;
    max-width: 56ch;
    text-align: center;
  }
  .shelf-load-error {
    color: var(--danger);
  }

  .shelf-list {
    display: flex;
    flex-direction: column;
    margin: 0;
    padding: 0;
    list-style: none;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    overflow: hidden;
  }
  .shelf-row {
    display: flex;
    align-items: center;
    gap: 12px;
    min-height: 40px;
    padding: 8px 12px;
    background: var(--bg-secondary);
  }
  .shelf-row + .shelf-row {
    border-top: 1px solid color-mix(in srgb, var(--border) 70%, transparent);
  }
  .shelf-row:hover {
    background: var(--bg-hover);
  }
  .who {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .open-folder {
    cursor: pointer;
    border-radius: var(--radius-sm);
  }
  .open-folder:focus-visible {
    outline: none;
    box-shadow: 0 0 0 2px var(--accent-halo);
  }
  .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: var(--font-size-sm);
    font-weight: 500;
    color: var(--text-primary);
  }
  .kind {
    color: var(--accent);
  }
  .detail {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    font-size: var(--font-size-2xs);
    color: var(--text-muted);
  }
  .size,
  .when {
    flex-shrink: 0;
    font-variant-numeric: tabular-nums;
  }
  .in-folder {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .risky {
    flex-shrink: 0;
    color: var(--danger);
    font-weight: 600;
  }

  .row-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
    padding: 4px 12px;
    font-size: var(--font-size-sm);
  }
  /* Busy, not disabled: a disabled button drops focus out of the dialog. */
  .row-btn[aria-disabled='true'],
  .shelf-more button[aria-disabled='true'] {
    cursor: default;
    opacity: 0.65;
  }

  .shelf-more {
    display: flex;
    justify-content: center;
    padding-top: 12px;
  }
  .shelf-more button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .shelf-footer {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 12px;
    padding: 12px 20px;
    border-top: 1px solid var(--border);
  }
  .shelf-showing {
    margin-right: auto;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }
</style>
