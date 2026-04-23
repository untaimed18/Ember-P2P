<script lang="ts">
  import {
    getIpFilterStats,
    addIpFilterRange,
    removeIpFilterRange,
    setIpFilterEnabled,
    setBlockPrivateIps,
    downloadAndLoadIpfilter,
    updateIpfilterFromUrl,
    importIpfilterFile,
    type IpFilterStats,
    type IpFilterEntry,
  } from '$lib/api/security';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import { passiveScroll } from '$lib/actions/passiveScroll';
  import { onMount, untrack } from 'svelte';

  let stats: IpFilterStats | null = $state(null);
  let loading = $state(true);
  let error: string | null = $state(null);
  let successMsg: string | null = $state(null);

  let downloading = $state(false);
  let importing = $state(false);
  // Custom-URL ipfilter state. Separate from `downloading` so the
  // "Download default" and "Fetch from URL" buttons can surface
  // independent spinners, and the inline URL input stays visible
  // while the fetch is in flight.
  let customUrl = $state('');
  let urlFetching = $state(false);
  let showUrlForm = $state(false);

  let showAddForm = $state(false);
  let newStartIp = $state('');
  let newEndIp = $state('');
  let newDescription = $state('');

  let confirmRemoveOpen = $state(false);
  let pendingRemoveEntry: IpFilterEntry | null = $state(null);

  let searchQuery = $state('');
  let sortBy: 'range' | 'hits' | 'description' = $state('hits');
  let sortAsc = $state(false);

  // IP filter lists can easily contain tens of thousands of ranges
  // (the default nipfilter.dat is ~60k rows). Virtualized scrolling
  // replaces the old 50-per-page pagination so users can scroll the
  // whole list without repeatedly clicking "Next". Fixed row height
  // keeps the math simple and is already what the table CSS enforces.
  const IP_ROW_HEIGHT = 28;
  const IP_OVERSCAN = 15;
  let ipScrollContainer: HTMLDivElement | undefined = $state();
  let ipScrollTop = $state(0);
  let ipViewportHeight = $state(400);

  let filteredEntries = $derived.by(() => {
    if (!stats) return [];
    let entries = [...stats.entries];
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      entries = entries.filter(
        (e) =>
          e.start_ip.includes(q) ||
          e.end_ip.includes(q) ||
          e.description.toLowerCase().includes(q)
      );
    }
    entries.sort((a, b) => {
      let cmp = 0;
      if (sortBy === 'hits') cmp = a.hits - b.hits;
      else if (sortBy === 'description') cmp = a.description.localeCompare(b.description);
      else {
        const pa = a.start_ip.split('.').map(Number);
        const pb = b.start_ip.split('.').map(Number);
        if (pa.length === 4 && pb.length === 4) {
          cmp = (pa[0] - pb[0]) || (pa[1] - pb[1]) || (pa[2] - pb[2]) || (pa[3] - pb[3]);
        } else {
          cmp = a.start_ip.localeCompare(b.start_ip);
        }
      }
      return sortAsc ? cmp : -cmp;
    });
    return entries;
  });

  let virtualIps = $derived.by(() => {
    const total = filteredEntries.length;
    if (total === 0) return { visible: [], startIdx: 0, topPad: 0, bottomPad: 0 };
    const firstVisible = Math.floor(ipScrollTop / IP_ROW_HEIGHT);
    const visibleCount = Math.ceil(ipViewportHeight / IP_ROW_HEIGHT);
    const startIdx = Math.max(0, firstVisible - IP_OVERSCAN);
    const endIdx = Math.min(total, firstVisible + visibleCount + IP_OVERSCAN);
    return {
      visible: filteredEntries.slice(startIdx, endIdx),
      startIdx,
      topPad: startIdx * IP_ROW_HEIGHT,
      bottomPad: (total - endIdx) * IP_ROW_HEIGHT,
    };
  });

  $effect(() => {
    if (!ipScrollContainer) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        ipViewportHeight = entry.contentRect.height;
      }
    });
    ro.observe(ipScrollContainer);
    ipViewportHeight = ipScrollContainer.clientHeight;
    return () => ro.disconnect();
  });

  // Reset scroll to top when the filter/sort reshapes the list so the
  // user isn't looking at arbitrary rows from the previous ordering.
  $effect(() => {
    void searchQuery; void sortBy; void sortAsc;
    untrack(() => {
      if (ipScrollContainer) ipScrollContainer.scrollTop = 0;
      ipScrollTop = 0;
    });
  });

  let unmounted = false;

  onMount(() => {
    loadStats();
    return () => { unmounted = true; clearTimeout(flashTimer); };
  });

  async function loadStats() {
    if (unmounted) return;
    loading = true;
    error = null;
    try {
      const result = await getIpFilterStats();
      if (unmounted) return;
      stats = result;
    } catch (e: unknown) {
      if (unmounted) return;
      error = toErrorMsg(e);
    } finally {
      if (!unmounted) loading = false;
    }
  }

  function toErrorMsg(e: unknown): string {
    return e instanceof Error ? e.message : typeof e === 'string' ? e : 'Operation failed';
  }

  let flashTimer: ReturnType<typeof setTimeout> | undefined;
  function flash(msg: string) {
    clearTimeout(flashTimer);
    successMsg = msg;
    flashTimer = setTimeout(() => (successMsg = null), 4000);
  }

  async function handleToggleEnabled() {
    if (!stats) return;
    const prev = stats.enabled;
    stats.enabled = !prev;
    try {
      await setIpFilterEnabled(stats.enabled);
    } catch (e: unknown) {
      stats.enabled = prev;
      error = toErrorMsg(e);
    }
  }

  async function handleTogglePrivate() {
    if (!stats) return;
    const prev = stats.block_private;
    stats.block_private = !prev;
    try {
      await setBlockPrivateIps(stats.block_private);
    } catch (e: unknown) {
      stats.block_private = prev;
      error = toErrorMsg(e);
    }
  }

  async function handleDownload() {
    downloading = true;
    error = null;
    try {
      const msg = await downloadAndLoadIpfilter();
      flash(msg);
      await loadStats();
    } catch (e: unknown) {
      error = toErrorMsg(e);
    } finally {
      downloading = false;
    }
  }

  async function handleImport() {
    importing = true;
    error = null;
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({
        multiple: false,
        filters: [{ name: 'IP Filter', extensions: ['dat', 'txt'] }],
      });
      if (selected) {
        const msg = await importIpfilterFile(selected as string);
        flash(msg);
        await loadStats();
      }
    } catch (e: unknown) {
      error = toErrorMsg(e);
    } finally {
      importing = false;
    }
  }

  /** Fetch an ipfilter from a user-supplied URL. Validation (scheme,
   *  host, private-IP filtering) happens backend-side in
   *  `update_ipfilter_from_url`; we only do a cheap front-end sanity
   *  pass here (non-empty + https://) so the most common mistake
   *  surfaces instantly instead of round-tripping. */
  async function handleUrlFetch() {
    const trimmed = customUrl.trim();
    if (!trimmed) {
      error = 'Enter a URL';
      return;
    }
    if (!trimmed.toLowerCase().startsWith('https://')) {
      error = 'URL must start with https://';
      return;
    }
    urlFetching = true;
    error = null;
    try {
      const msg = await updateIpfilterFromUrl(trimmed);
      flash(msg);
      await loadStats();
      // Collapse the form on success — saves a click and signals
      // completion. The URL is preserved so users who want to refetch
      // the same list (e.g. after an upstream update) can reopen and
      // re-submit without retyping.
      showUrlForm = false;
    } catch (e: unknown) {
      error = toErrorMsg(e);
    } finally {
      urlFetching = false;
    }
  }

  function isValidIpv4(ip: string): boolean {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(p => { const n = Number(p); return Number.isInteger(n) && n >= 0 && n <= 255 && p === String(n); });
  }

  async function handleAddRange() {
    const startIp = newStartIp.trim();
    const endIp = newEndIp.trim();
    const desc = newDescription.trim();
    if (!startIp || !endIp) {
      error = 'Both start and end IP are required';
      return;
    }
    if (!isValidIpv4(startIp) || !isValidIpv4(endIp)) {
      error = 'Invalid IP address format. Use dotted decimal (e.g. 192.168.1.0)';
      return;
    }
    error = null;
    try {
      await addIpFilterRange(startIp, endIp, desc);
      flash(`Added range ${startIp} \u2014 ${endIp}`);
      newStartIp = '';
      newEndIp = '';
      newDescription = '';
      showAddForm = false;
      await loadStats();
    } catch (e: unknown) {
      error = toErrorMsg(e);
    }
  }

  function handleRemoveRange(entry: IpFilterEntry) {
    pendingRemoveEntry = entry;
    confirmRemoveOpen = true;
  }

  async function confirmRemoveRange() {
    if (!pendingRemoveEntry) return;
    const entry = pendingRemoveEntry;
    pendingRemoveEntry = null;
    error = null;
    try {
      await removeIpFilterRange(entry.start_ip, entry.end_ip);
      flash(`Removed range ${entry.start_ip} \u2014 ${entry.end_ip}`);
      await loadStats();
    } catch (e: unknown) {
      error = toErrorMsg(e);
    }
  }

  function toggleSort(col: 'range' | 'hits' | 'description') {
    if (sortBy === col) {
      sortAsc = !sortAsc;
    } else {
      sortBy = col;
      sortAsc = col === 'range' || col === 'description';
    }
    if (ipScrollContainer) ipScrollContainer.scrollTop = 0;
    ipScrollTop = 0;
  }

  function sortArrow(col: string): string {
    if (sortBy !== col) return ' \u00A0';
    return sortAsc ? ' \u25B2' : ' \u25BC';
  }

  function ariaSort(col: string): 'ascending' | 'descending' | 'none' {
    if (sortBy !== col) return 'none';
    return sortAsc ? 'ascending' : 'descending';
  }
</script>

<div class="page-header">
  <h2>Security</h2>
  <div class="header-actions">
    <button onclick={handleDownload} disabled={downloading}>
      {downloading ? 'Downloading\u2026' : 'Download IP Filter'}
    </button>
    <button class="ghost" onclick={handleImport} disabled={importing}>
      {importing ? 'Importing\u2026' : 'Import File'}
    </button>
    <!--
      Toggle the custom-URL form. Kept as a collapsible row so the
      default/import actions stay visible without a second click, and
      power-users who do want a custom source get a clearly-scoped
      input instead of a modal.
    -->
    <button
      class="ghost"
      onclick={() => { showUrlForm = !showUrlForm; if (!showUrlForm) error = null; }}
      aria-expanded={showUrlForm}
      aria-controls="ipfilter-url-form"
    >
      {showUrlForm ? 'Cancel URL' : 'From URL\u2026'}
    </button>
    <button class="ghost" onclick={loadStats}>Refresh</button>
  </div>
</div>

{#if showUrlForm}
  <div id="ipfilter-url-form" class="ipfilter-url-form" role="group" aria-label="Fetch ipfilter from URL">
    <label for="ipfilter-url-input" class="sr-only">IP filter URL</label>
    <input
      id="ipfilter-url-input"
      type="url"
      placeholder="https://example.com/ipfilter.zip"
      bind:value={customUrl}
      disabled={urlFetching}
      onkeydown={(e) => { if (e.key === 'Enter' && !urlFetching) handleUrlFetch(); }}
    />
    <button onclick={handleUrlFetch} disabled={urlFetching || !customUrl.trim()}>
      {urlFetching ? 'Fetching\u2026' : 'Fetch'}
    </button>
  </div>
{/if}

<div class="page-content">
  {#if error}
    <div class="banner error-banner">
      <span>{error}</span>
      <button class="ghost" onclick={() => (error = null)}>Dismiss</button>
    </div>
  {/if}
  {#if successMsg}
    <div class="banner success-banner">
      <span>{successMsg}</span>
    </div>
  {/if}

  {#if loading && !stats}
    <div class="empty-state"><p>Loading IP filter data&hellip;</p></div>
  {:else if stats}
    <!-- Controls bar: toggles + stats inline -->
    <div class="controls-bar">
      <div class="controls-left">
        <label class="toggle-switch" title="Enable or disable the IP filter">
          <input type="checkbox" checked={stats.enabled} onchange={handleToggleEnabled} />
          <span class="switch-track"></span>
          <span class="switch-label">IP Filter</span>
        </label>
        <label class="toggle-switch" title="Block private and reserved IP ranges (10.x, 172.16.x, 192.168.x, etc.)">
          <input type="checkbox" checked={stats.block_private} onchange={handleTogglePrivate} />
          <span class="switch-track"></span>
          <span class="switch-label">Block Private IPs</span>
        </label>
        <button class="ghost add-range-btn" onclick={() => (showAddForm = !showAddForm)}>
          {showAddForm ? 'Cancel' : '+ Add Range'}
        </button>
      </div>
      <div class="controls-right">
        <span class="inline-stat">{stats.range_count.toLocaleString()} ranges</span>
        <span class="inline-sep">&middot;</span>
        <span class="inline-stat hits-stat">{stats.total_hits.toLocaleString()} hits</span>
      </div>
    </div>

    {#if showAddForm}
      <div class="add-form">
        <div class="add-form-inner">
          <label class="add-field">
            <span class="add-field-label">Start IP</span>
            <input bind:value={newStartIp} placeholder="e.g. 1.0.0.0" class="ip-input" aria-label="Start IP" />
          </label>
          <span class="range-sep" aria-hidden="true">&mdash;</span>
          <label class="add-field">
            <span class="add-field-label">End IP</span>
            <input bind:value={newEndIp} placeholder="e.g. 1.0.0.255" class="ip-input" aria-label="End IP" />
          </label>
          <label class="add-field add-field-grow">
            <span class="add-field-label">Description (optional)</span>
            <input bind:value={newDescription} placeholder="Why is this range blocked?" class="desc-input" aria-label="Description" />
          </label>
          <button class="add-form-submit" onclick={handleAddRange}>Add</button>
        </div>
      </div>
    {/if}

    <!-- Search toolbar -->
    <div class="table-toolbar">
      <div class="search-wrap">
        <span class="search-icon">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
            <circle cx="8.5" cy="8.5" r="5.5"/><line x1="12.5" y1="12.5" x2="17" y2="17"/>
          </svg>
        </span>
        <input
          type="text"
          class="search-input"
          bind:value={searchQuery}
          placeholder="Search IP ranges or descriptions&hellip;"
        />
        {#if searchQuery}
          <button class="search-clear" onclick={() => { searchQuery = ''; }} title="Clear search" aria-label="Clear search">&times;</button>
        {/if}
      </div>
      <span class="result-count">
        {filteredEntries.length.toLocaleString()} range{filteredEntries.length !== 1 ? 's' : ''}
      </span>
    </div>

    {#if filteredEntries.length === 0 && !searchQuery.trim()}
      <div class="empty-state">
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="56" height="56" aria-hidden="true">
          <path d="M12 2l7 4v6c0 4.4-3 8.5-7 10-4-1.5-7-5.6-7-10V6l7-4z"></path>
        </svg>
        <p>No IP ranges loaded</p>
        <p class="sub">Download or import an ipfilter.dat to get started</p>
      </div>
    {:else if filteredEntries.length === 0}
      <div class="empty-state">
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="56" height="56" aria-hidden="true">
          <circle cx="11" cy="11" r="8"></circle>
          <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
        </svg>
        <p>No matching ranges</p>
        <p class="sub">Try a different search term</p>
      </div>
    {:else}
      <div
        class="table-area"
        bind:this={ipScrollContainer}
        use:passiveScroll={(e) => { ipScrollTop = (e.target as HTMLDivElement).scrollTop; }}
      >
        <table class="ip-table">
          <thead>
            <tr>
              <th
                class="sortable col-range"
                role="columnheader"
                aria-sort={ariaSort('range')}
                onclick={() => toggleSort('range')}
              >
                <span class="th-content">IP Range{sortArrow('range')}</span>
              </th>
              <th
                class="sortable col-desc"
                role="columnheader"
                aria-sort={ariaSort('description')}
                onclick={() => toggleSort('description')}
              >
                <span class="th-content">Description{sortArrow('description')}</span>
              </th>
              <th
                class="sortable col-hits"
                role="columnheader"
                aria-sort={ariaSort('hits')}
                onclick={() => toggleSort('hits')}
              >
                <span class="th-content">Hits{sortArrow('hits')}</span>
              </th>
              <th class="col-actions"></th>
            </tr>
          </thead>
          <tbody>
            {#if virtualIps.topPad > 0}
              <tr class="spacer-row" style="height: {virtualIps.topPad}px;"><td colspan="4"></td></tr>
            {/if}
            {#each virtualIps.visible as entry, i (`${entry.start_ip}-${entry.end_ip}`)}
              <tr class:row-alt={((virtualIps.startIdx + i) & 1) === 1}>
                <td class="ip-cell">
                  <span class="ip-range">{entry.start_ip}</span>
                  <span class="range-arrow">&rarr;</span>
                  <span class="ip-range">{entry.end_ip}</span>
                </td>
                <td class="desc-cell" title={entry.description}>{entry.description || '\u2014'}</td>
                <td class="hits-cell">
                  {#if entry.hits === 0}
                    <span class="no-hits">0</span>
                  {:else if entry.hits >= 100}
                    <!-- Reserve the "danger" red for ranges that are
                         actually doing meaningful blocking; otherwise
                         every populated table reads as alarming. -->
                    <span class="hit-count hit-count-high">{entry.hits.toLocaleString()}</span>
                  {:else}
                    <span class="hit-count">{entry.hits.toLocaleString()}</span>
                  {/if}
                </td>
                <td class="actions-cell">
                  <button
                    class="ghost danger btn-remove"
                    onclick={() => handleRemoveRange(entry)}
                    title="Remove this range"
                    aria-label={`Remove range ${entry.start_ip} to ${entry.end_ip}`}
                  >&times;</button>
                </td>
              </tr>
            {/each}
            {#if virtualIps.bottomPad > 0}
              <tr class="spacer-row" style="height: {virtualIps.bottomPad}px;"><td colspan="4"></td></tr>
            {/if}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
</div>

<ConfirmDialog
  bind:open={confirmRemoveOpen}
  title="Remove IP Range"
  message={pendingRemoveEntry ? `Remove the blocked range ${pendingRemoveEntry.start_ip} \u2192 ${pendingRemoveEntry.end_ip}?` : 'Remove this IP range?'}
  confirmLabel="Remove"
  danger={true}
  onconfirm={confirmRemoveRange}
  oncancel={() => { pendingRemoveEntry = null; }}
/>

<style>
  .header-actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  /* Visually-hidden label for the URL input; the placeholder
     doubles as the visible cue while the label keeps the
     accessibility tree honest for screen readers. */
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

  /* Collapsible "Fetch from URL" row. Sits directly under the
     page header when expanded so it's clearly scoped to the
     ipfilter actions above and doesn't disrupt the main content
     layout. */
  .ipfilter-url-form {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 16px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
  }
  .ipfilter-url-form input[type='url'] {
    flex: 1;
    min-width: 0;
    padding: 6px 10px;
    border-radius: var(--radius-sm, 4px);
    border: 1px solid var(--border);
    background: var(--bg-primary);
    color: var(--text-primary);
    font-family: inherit;
    font-size: 12px;
  }
  .ipfilter-url-form input[type='url']:focus {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }
  .ipfilter-url-form button {
    flex-shrink: 0;
  }

  /* --- Banners --- */
  .banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 16px;
    font-size: 12px;
  }
  .error-banner {
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--danger);
    color: var(--danger);
  }
  .success-banner {
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--success);
    color: var(--success);
  }

  /* --- Controls bar (combines toggles + inline stats) --- */
  .controls-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 16px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }
  .controls-left {
    display: flex;
    align-items: center;
    gap: 18px;
    flex-wrap: wrap;
  }
  .controls-right {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    color: var(--text-muted);
    white-space: nowrap;
  }
  .inline-stat { font-variant-numeric: tabular-nums; }
  .inline-sep { opacity: 0.45; }
  .hits-stat { color: var(--danger); font-weight: 600; }

  /* --- Toggle switch --- */
  .toggle-switch {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    user-select: none;
    font-size: 12px;
  }
  .toggle-switch input {
    position: absolute;
    opacity: 0;
    width: 0;
    height: 0;
    pointer-events: none;
  }
  .switch-track {
    position: relative;
    width: 32px;
    height: 18px;
    border-radius: 9px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    transition: background 0.2s, border-color 0.2s;
    flex-shrink: 0;
  }
  .switch-track::after {
    content: '';
    position: absolute;
    top: 2px;
    left: 2px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: var(--text-muted);
    transition: transform 0.2s, background 0.2s;
  }
  .toggle-switch input:checked + .switch-track {
    background: var(--accent);
    border-color: var(--accent);
  }
  .toggle-switch input:checked + .switch-track::after {
    transform: translateX(14px);
    background: #fff;
  }
  .toggle-switch:hover .switch-track {
    border-color: var(--accent);
  }
  .switch-label {
    color: var(--text-primary);
    font-weight: 500;
  }

  .add-range-btn {
    font-size: 12px;
    padding: 4px 10px;
  }

  /* --- Add range form --- */
  .add-form {
    padding: 10px 16px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
  }
  .add-form-inner {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .add-field {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .add-field-grow {
    flex: 1;
    min-width: 140px;
  }
  .add-field-label {
    font-size: 10px;
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.4px;
  }
  .ip-input {
    width: 156px;
    font-family: var(--font-mono);
    font-size: 12px;
  }
  .desc-input {
    width: 100%;
    font-size: 12px;
  }
  .range-sep {
    color: var(--text-muted);
    font-size: 14px;
    flex-shrink: 0;
    align-self: end;
    padding-bottom: 6px;
  }
  .add-form-submit {
    align-self: end;
  }

  /* --- Search toolbar --- */
  .table-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 16px;
    gap: 12px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
  }
  .search-wrap {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    max-width: 400px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md, 6px);
    padding: 0 8px;
    background: var(--bg-input, var(--bg-primary));
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  .search-wrap:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-dim);
  }
  .search-icon {
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
    flex-shrink: 0;
  }
  .search-input {
    flex: 1;
    min-width: 0;
    border: none;
    background: transparent;
    padding: 6px 0;
    font-size: 12px;
    color: inherit;
    outline: none;
  }
  .search-clear {
    border: none;
    background: transparent;
    color: var(--text-muted);
    width: 20px;
    height: 20px;
    border-radius: 50%;
    padding: 0;
    font-size: 14px;
    line-height: 1;
    cursor: pointer;
    flex-shrink: 0;
  }
  .search-clear:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }
  .result-count {
    font-size: 11px;
    color: var(--text-muted);
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }

  /* --- Table --- */
  .table-area {
    flex: 1;
    overflow: auto;
    min-height: 0;
  }
  .ip-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    table-layout: fixed;
  }
  .ip-table thead {
    position: sticky;
    top: 0;
    z-index: 1;
  }
  .ip-table th {
    padding: 4px 8px;
    text-align: left;
    white-space: nowrap;
    font-weight: 600;
    font-size: 11px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
    user-select: none;
    color: var(--text-secondary);
  }
  .ip-table th.sortable {
    cursor: pointer;
  }
  .ip-table th.sortable:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }
  .th-content {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .col-range { width: 36%; }
  .col-desc { width: auto; }
  .col-hits { width: 80px; text-align: right; }
  .col-actions { width: 44px; text-align: center; }

  .ip-table td {
    padding: 3px 8px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 40%, transparent);
    height: 28px;
    box-sizing: border-box;
  }
  .ip-table tbody tr {
    transition: background-color 0.1s;
  }
  .ip-table tbody tr.row-alt td {
    background: color-mix(in srgb, var(--bg-secondary) 90%, var(--bg-primary));
  }
  .ip-table tbody tr:hover td {
    background: var(--bg-hover);
  }
  /* Virtual spacer rows take space but don't render any content; skip
     the hover highlight so they don't flash on scroll-momentum
     pointer crossings. */
  .ip-table tbody tr.spacer-row {
    background: transparent;
  }
  .ip-table tbody tr.spacer-row td {
    border: none;
    padding: 0;
    background: transparent;
  }
  .ip-table tbody tr.spacer-row:hover td {
    background: transparent;
  }

  .ip-cell {
    font-family: var(--font-mono);
    font-size: 12px;
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }
  .ip-range {
    color: var(--text-primary);
  }
  .range-arrow {
    color: var(--text-muted);
    margin: 0 4px;
    font-size: 10px;
  }
  .desc-cell {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-secondary);
  }
  .hits-cell {
    text-align: right;
    font-family: var(--font-mono);
    font-size: 12px;
    font-variant-numeric: tabular-nums;
  }
  .hit-count {
    color: var(--text-primary);
    font-weight: 600;
  }
  .hit-count-high {
    color: var(--danger);
  }
  .no-hits {
    color: var(--text-muted);
  }
  .actions-cell {
    text-align: center;
  }
  /* Remove button stays visible (no opacity-0 default) so touch and
     keyboard users can reach it without first hovering the row. Faded
     baseline keeps it from competing with the IP/description text. */
  .btn-remove {
    padding: 2px 6px;
    font-size: 14px;
    line-height: 1;
    opacity: 0.5;
    transition: opacity 0.15s;
  }
  .ip-table tbody tr:hover .btn-remove,
  .ip-table tbody tr:focus-within .btn-remove,
  .btn-remove:focus-visible {
    opacity: 1;
  }

  /* --- Empty state --- */
  .sub {
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 2px;
  }
</style>
