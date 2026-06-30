<script lang="ts">
  import * as m from '$lib/paraglide/messages';

  let {
    value = $bindable(''),
    placeholder = m.search_bar_placeholder(),
    onsubmit,
    recentKey,
    recentMax = 10,
    maxLength = 256,
    historyEnabled = true,
  }: {
    value?: string;
    placeholder?: string;
    onsubmit?: (query: string) => void;
    /**
     * When set, the component persists recent submitted queries under this
     * localStorage key and exposes them as a dropdown when the input is
     * focused with an empty value. Leave undefined on search bars where
     * history should not be tracked (e.g. filter inputs).
     */
    recentKey?: string;
    /** Maximum number of recent queries to keep. */
    recentMax?: number;
    /** Maximum accepted query length (characters); guards backend/UI from
     *  pathologically long pasted/automated input. */
    maxLength?: number;
    /**
     * Gate for persisting `recentKey` history (driven by the "Save search
     * history" setting). When false the component neither loads nor saves
     * recent queries and purges any already-stored history. Defaults to true
     * so callers that don't opt out keep the prior save-by-default behavior.
     */
    historyEnabled?: boolean;
  } = $props();

  let recent: string[] = $state([]);
  let showRecent = $state(false);
  let activeIndex = $state(-1);
  let wrapEl: HTMLDivElement | undefined = $state(undefined);
  let inputEl: HTMLInputElement | undefined = $state(undefined);

  function loadRecent() {
    if (!recentKey) return;
    try {
      const raw = localStorage.getItem(recentKey);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        recent = parsed
          .filter((s): s is string => typeof s === 'string')
          .slice(0, recentMax);
      }
    } catch {
      try { localStorage.removeItem(recentKey); } catch { /* ignore */ }
    }
  }

  function saveRecent() {
    if (!recentKey || !historyEnabled) return;
    try { localStorage.setItem(recentKey, JSON.stringify(recent)); } catch { /* quota — non-fatal */ }
  }

  function addRecent(q: string) {
    const trimmed = q.trim();
    if (!trimmed || !recentKey || !historyEnabled) return;
    // De-dupe case-insensitively but keep the most recent casing.
    const lower = trimmed.toLowerCase();
    const filtered = recent.filter((r) => r.toLowerCase() !== lower);
    recent = [trimmed, ...filtered].slice(0, recentMax);
    saveRecent();
  }

  function removeRecent(q: string) {
    const removedIdx = recent.findIndex((r) => r === q);
    recent = recent.filter((r) => r !== q);
    // Keep the keyboard highlight pointing at the same logical row. Without
    // this, removing an item at/above `activeIndex` leaves the highlight on
    // the wrong entry (or past the end of the now-shorter list).
    if (removedIdx !== -1 && activeIndex >= 0) {
      if (removedIdx < activeIndex) activeIndex -= 1;
      else if (removedIdx === activeIndex) activeIndex = -1;
      if (activeIndex >= recent.length) activeIndex = recent.length - 1;
    }
    saveRecent();
  }

  function clearRecent() {
    recent = [];
    saveRecent();
  }

  function submit(q: string) {
    if (!onsubmit) return;
    addRecent(q);
    onsubmit(q);
    showRecent = false;
    activeIndex = -1;
  }

  function pickRecent(q: string) {
    value = q;
    submit(q);
  }

  function handleKeydown(e: KeyboardEvent) {
    if (showRecent && recent.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        activeIndex = (activeIndex + 1) % recent.length;
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        activeIndex = activeIndex <= 0 ? recent.length - 1 : activeIndex - 1;
        return;
      }
      if (e.key === 'Escape') {
        showRecent = false;
        activeIndex = -1;
        return;
      }
      if (e.key === 'Enter' && activeIndex >= 0 && activeIndex < recent.length) {
        e.preventDefault();
        pickRecent(recent[activeIndex]);
        return;
      }
    }
    if (e.key === 'Enter') {
      submit(value);
    }
  }

  function handleFocus() {
    if (recentKey && historyEnabled && recent.length > 0) {
      showRecent = true;
    }
  }

  function handleBlur(e: FocusEvent) {
    // Hide only when focus moves entirely outside the wrapper — letting the
    // user click a dropdown item without the list vanishing first.
    const next = e.relatedTarget as Node | null;
    if (next && wrapEl && wrapEl.contains(next)) return;
    showRecent = false;
    activeIndex = -1;
  }

  $effect(() => {
    if (!recentKey) return;
    if (historyEnabled) {
      loadRecent();
    } else {
      // History disabled (via the "Save search history" setting): drop the
      // in-memory list, close the dropdown, and purge the persisted entries so
      // turning the setting off actually erases past queries rather than just
      // hiding them. Re-enabling later starts fresh.
      recent = [];
      showRecent = false;
      activeIndex = -1;
      try { localStorage.removeItem(recentKey); } catch { /* ignore */ }
    }
  });
</script>

<div class="search-bar-wrap" bind:this={wrapEl}>
  <div class="search-bar">
    <span class="search-icon" aria-hidden="true">
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
        <circle cx="8.5" cy="8.5" r="5.5"/><line x1="12.5" y1="12.5" x2="17" y2="17"/>
      </svg>
    </span>
    {#if recentKey}
      <!--
        When `recentKey` is set the input acts as a combobox over a listbox
        of recent queries. Without the combobox role, aria-expanded/controls
        aren't valid on a plain textbox (svelte-check a11y warning).
      -->
      <input
        bind:this={inputEl}
        type="text"
        bind:value
        {placeholder}
        maxlength={maxLength}
        onkeydown={handleKeydown}
        onfocus={handleFocus}
        onblur={handleBlur}
        aria-label={m.search_bar_aria()}
        role="combobox"
        aria-autocomplete="list"
        aria-expanded={showRecent}
        aria-controls="search-recent-list"
        autocomplete="off"
      />
    {:else}
      <input
        bind:this={inputEl}
        type="text"
        bind:value
        {placeholder}
        maxlength={maxLength}
        onkeydown={handleKeydown}
        onfocus={handleFocus}
        onblur={handleBlur}
        aria-label={m.search_bar_aria()}
        autocomplete="off"
      />
    {/if}
    {#if value}
      <button class="clear-btn" onclick={() => (value = '')} aria-label={m.search_bar_clear()}>
        <svg viewBox="0 0 14 14" width="11" height="11" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
          <line x1="3.5" y1="3.5" x2="10.5" y2="10.5"/>
          <line x1="10.5" y1="3.5" x2="3.5" y2="10.5"/>
        </svg>
      </button>
    {/if}
  </div>

  {#if recentKey && showRecent && recent.length > 0}
    <div id="search-recent-list" class="recent-dropdown" role="listbox" aria-label={m.search_bar_recent_searches()}>
      <div class="recent-header">
        <span>{m.search_bar_recent_searches()}</span>
        <button type="button" class="recent-clear" onclick={clearRecent}>{m.search_bar_clear_all()}</button>
      </div>
      {#each recent as q, i (q)}
        <div
          class="recent-item"
          class:active={i === activeIndex}
          role="option"
          aria-selected={i === activeIndex}
        >
          <button
            type="button"
            class="recent-pick"
            onmousedown={(e) => { e.preventDefault(); pickRecent(q); }}
            onmouseenter={() => (activeIndex = i)}
          >
            <svg class="recent-icon" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <circle cx="8" cy="8" r="6.25"/>
              <path d="M8 4.5V8l2.25 1.5"/>
            </svg>
            <span class="recent-text">{q}</span>
          </button>
          <button
            type="button"
            class="recent-remove"
            aria-label={m.search_bar_remove_recent({ query: q })}
            onmousedown={(e) => { e.preventDefault(); removeRecent(q); }}
          >
            <svg viewBox="0 0 14 14" width="10" height="10" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
              <line x1="3.5" y1="3.5" x2="10.5" y2="10.5"/>
              <line x1="10.5" y1="3.5" x2="3.5" y2="10.5"/>
            </svg>
          </button>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .search-bar-wrap {
    position: relative;
    flex: 1 1 420px;
    min-width: 260px;
  }

  .search-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    min-height: 42px;
    padding: 0 12px;
    border: 1px solid color-mix(in srgb, var(--border) 84%, transparent);
    border-radius: 999px;
    background: linear-gradient(
      to bottom,
      color-mix(in srgb, var(--bg-input) 95%, #fff 5%),
      var(--bg-input)
    );
    box-shadow: var(--shadow-sm);
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }

  .search-bar:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent-dim) 45%, transparent), var(--shadow-md);
  }

  .search-icon {
    width: 22px;
    height: 22px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: color-mix(in srgb, var(--accent-dim) 35%, transparent);
    color: var(--text-accent);
    font-size: 13px;
    font-weight: 700;
    flex-shrink: 0;
  }

  input {
    flex: 1;
    border: none;
    background: none;
    padding: 10px 0;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-primary);
    min-width: 0;
  }

  input:focus {
    border: none;
    outline: none;
  }

  input::placeholder {
    color: color-mix(in srgb, var(--text-muted) 85%, transparent);
    font-weight: 400;
  }

  .clear-btn {
    width: 24px;
    height: 24px;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    cursor: pointer;
  }

  .clear-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .recent-dropdown {
    position: absolute;
    top: calc(100% + 6px);
    left: 0;
    right: 0;
    z-index: 50;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-md);
    overflow: hidden;
    max-height: 280px;
    overflow-y: auto;
  }

  .recent-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 12px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    background: color-mix(in srgb, var(--bg-secondary) 55%, transparent);
    border-bottom: 1px solid var(--border);
  }

  .recent-clear {
    background: none;
    border: none;
    color: var(--text-muted);
    font-size: 11px;
    text-transform: none;
    letter-spacing: normal;
    cursor: pointer;
    padding: 2px 6px;
    border-radius: var(--radius-sm);
  }

  .recent-clear:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .recent-item {
    display: flex;
    align-items: stretch;
    min-height: 32px;
  }

  .recent-item.active,
  .recent-item:hover {
    background: var(--bg-hover);
  }

  .recent-pick {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: 13px;
    text-align: left;
    cursor: pointer;
  }

  .recent-pick:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }

  .recent-icon {
    color: var(--text-muted);
    flex-shrink: 0;
  }

  .recent-text {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .recent-remove {
    width: 28px;
    padding: 0;
    border: none;
    background: transparent;
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    opacity: 0.6;
    flex-shrink: 0;
  }

  .recent-item:hover .recent-remove,
  .recent-item.active .recent-remove {
    opacity: 1;
  }

  .recent-remove:hover {
    color: var(--danger, #e74c3c);
    background: var(--bg-hover);
  }
</style>
