<script lang="ts">
  import {
    getIpFilterStats,
    addIpFilterRange,
    removeIpFilterRange,
    setIpFilterEnabled,
    setBlockPrivateIps,
    downloadAndLoadIpfilter,
    updateIpfilterFromUrl,
    pickAndImportIpfilterFile,
    type IpFilterStats,
    type IpFilterEntry,
    type IpFilterApplyResult,
  } from '$lib/api/security';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
  import { passiveScroll } from '$lib/actions/passiveScroll';
  import { onMount, untrack } from 'svelte';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';
  import { getSettings } from '$lib/api/settings';
  import { setAppSettings } from '$lib/stores/settings';
  import IconX from '$lib/components/IconX.svelte';

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

  function ipFilterApplyMessage(result: IpFilterApplyResult): string {
    switch (result.outcome) {
      case 'applied':
        return m.security_ipfilter_applied({ entries: result.entryCount });
      case 'failed':
        return m.security_ipfilter_live_reload_failed({ entries: result.entryCount });
      default:
        return m.security_ipfilter_live_reload_deferred({ entries: result.entryCount });
    }
  }

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
    // Parse a dotted-quad IPv4 into a 32-bit unsigned key suitable
    // for ordering. Any non-numeric octet falls back to the lexical
    // path below, which guarantees a total order even on garbage
    // input (otherwise `NaN - NaN === NaN` propagates and
    // `Array.sort` produces an unstable, undefined permutation).
    const ipKey = (s: string): number | null => {
      const parts = s.split('.');
      if (parts.length !== 4) return null;
      let acc = 0;
      for (const part of parts) {
        const n = Number(part);
        if (!Number.isFinite(n) || n < 0 || n > 255) return null;
        acc = acc * 256 + n;
      }
      return acc;
    };
    entries.sort((a, b) => {
      let cmp = 0;
      if (sortBy === 'hits') cmp = a.hits - b.hits;
      else if (sortBy === 'description') cmp = a.description.localeCompare(b.description);
      else {
        const ka = ipKey(a.start_ip);
        const kb = ipKey(b.start_ip);
        if (ka !== null && kb !== null) {
          cmp = ka - kb;
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
    void (async () => {
      await loadStats();
      // Startup deferred ipfilter load may still be in flight — re-poll
      // briefly while enabled && !ranges_ready so we don't stick on empty.
      for (const delay of [500, 1000, 2000, 3000]) {
        if (unmounted) return;
        if (!stats?.enabled || stats.ranges_ready) return;
        await new Promise((r) => setTimeout(r, delay));
        if (unmounted) return;
        await loadStats();
      }
    })();
    return () => { unmounted = true; clearTimeout(flashTimer); };
  });

  let loadStatsSeq = 0;
  // Number of optimistic enable/block-private toggles whose backend write is
  // still in flight. While > 0, a refresh that raced the toggle could carry a
  // pre-toggle snapshot of the switch fields and silently revert the UI, so we
  // preserve the optimistic switch state and let the toggle's own post-write
  // reload reconcile the authoritative value.
  let togglesInFlight = 0;
  async function loadStats() {
    if (unmounted) return;
    // Only the latest invocation commits, so overlapping refreshes (mount plus
    // the several post-action reloads) can't clobber newer stats out of order.
    const seq = ++loadStatsSeq;
    loading = true;
    error = null;

    // The network task only starts serving commands after its full startup,
    // which runs UPnP gateway discovery (bounded to ~5s) concurrently with the
    // ipfilter load and then more init before the command loop begins. Opening
    // this page in that window — most notably the relaunch that finishes the
    // setup wizard — makes the first `get_ip_filter_stats` race startup and
    // time out. A one-shot load would then leave the page empty for the whole
    // session even though the filter is loaded in the backend, until the user
    // restarts the app. Retry with bounded backoff while we still have no
    // stats, so the list appears as soon as the network is ready (mirrors the
    // layout's getSettings startup-retry policy). Refreshes after stats exist
    // surface a single error immediately — the network is already up by then.
    const retryDelaysMs = stats ? [] : [300, 600, 1000, 1500, 2500];
    let lastErr: unknown = null;
    for (let attempt = 0; ; attempt++) {
      try {
        const result = await getIpFilterStats();
        if (unmounted || seq !== loadStatsSeq) return;
        if (togglesInFlight > 0 && stats) {
          stats = { ...result, enabled: stats.enabled, block_private: stats.block_private };
        } else {
          stats = result;
        }
        error = null;
        loading = false;
        return;
      } catch (e: unknown) {
        if (unmounted || seq !== loadStatsSeq) return;
        lastErr = e;
        if (attempt >= retryDelaysMs.length) break;
        await new Promise((r) => setTimeout(r, retryDelaysMs[attempt]));
        if (unmounted || seq !== loadStatsSeq) return;
      }
    }
    error = toErrorMsg(lastErr);
    loading = false;
  }

  function toErrorMsg(e: unknown): string {
    return translateError(e, m.error_operation_failed());
  }

  let flashTimer: ReturnType<typeof setTimeout> | undefined;
  function flash(msg: string) {
    error = null;
    clearTimeout(flashTimer);
    successMsg = msg;
    flashTimer = setTimeout(() => (successMsg = null), 4000);
  }

  async function syncIpFilterSettingsCache() {
    try {
      // Backend already persisted the toggled value; do not patch a
      // possibly-stale getSettings snapshot (rapid on/off races).
      const current = await getSettings();
      setAppSettings(current);
    } catch {
      // Settings page will reload from disk on next visit.
    }
  }

  async function persistIpFilterEnabled(next: boolean) {
    if (!stats) return;
    const prev = !next;
    togglesInFlight++;
    try {
      await setIpFilterEnabled(next);
      await syncIpFilterSettingsCache();
      // Enable may lazily load ipfilter.dat — refresh so range_count /
      // ranges_ready / entries match the live filter (SEC-01).
      await loadStats();
      // While deferred/lazy load is still in flight, keep polling briefly
      // so the empty list does not stick (SEC-02).
      if (next) {
        for (const delay of [400, 800, 1600]) {
          if (unmounted) return;
          if (stats?.ranges_ready && (stats.range_count > 0 || !stats.enabled)) break;
          if (stats && !stats.enabled) break;
          await new Promise((r) => setTimeout(r, delay));
          if (unmounted) return;
          await loadStats();
          if (stats?.ranges_ready) break;
        }
      }
    } catch (e: unknown) {
      stats.enabled = prev;
      error = toErrorMsg(e);
    } finally {
      togglesInFlight--;
    }
  }

  async function persistBlockPrivate(next: boolean) {
    if (!stats) return;
    const prev = !next;
    togglesInFlight++;
    try {
      await setBlockPrivateIps(next);
      await syncIpFilterSettingsCache();
    } catch (e: unknown) {
      stats.block_private = prev;
      error = toErrorMsg(e);
    } finally {
      togglesInFlight--;
    }
  }

  async function handleDownload() {
    downloading = true;
    error = null;
    try {
      const result = await downloadAndLoadIpfilter();
      if (unmounted) return;
      flash(ipFilterApplyMessage(result));
      await syncIpFilterSettingsCache();
      await loadStats();
    } catch (e: unknown) {
      if (unmounted) return;
      error = toErrorMsg(e);
    } finally {
      if (!unmounted) downloading = false;
    }
  }

  async function handleImport() {
    importing = true;
    error = null;
    try {
      // The picker runs in the Rust core rather than here, so the chosen path
      // never travels over IPC — selecting a file in the OS dialog is what
      // authorizes the read. `null` means the user dismissed it.
      const result = await pickAndImportIpfilterFile();
      if (unmounted) return;
      if (result) {
        flash(ipFilterApplyMessage(result));
        await syncIpFilterSettingsCache();
        await loadStats();
      }
    } catch (e: unknown) {
      if (unmounted) return;
      error = toErrorMsg(e);
    } finally {
      if (!unmounted) importing = false;
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
      error = m.security_enter_url();
      return;
    }
    if (!trimmed.toLowerCase().startsWith('https://')) {
      error = m.security_url_must_be_https();
      return;
    }
    urlFetching = true;
    error = null;
    try {
      const result = await updateIpfilterFromUrl(trimmed);
      if (unmounted) return;
      flash(ipFilterApplyMessage(result));
      await syncIpFilterSettingsCache();
      await loadStats();
      // Collapse the form on success — saves a click and signals
      // completion. The URL is preserved so users who want to refetch
      // the same list (e.g. after an upstream update) can reopen and
      // re-submit without retyping.
      showUrlForm = false;
    } catch (e: unknown) {
      if (unmounted) return;
      error = toErrorMsg(e);
    } finally {
      if (!unmounted) urlFetching = false;
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
      error = m.security_both_ips_required();
      return;
    }
    if (!isValidIpv4(startIp) || !isValidIpv4(endIp)) {
      error = m.security_invalid_ip_format();
      return;
    }
    error = null;
    try {
      await addIpFilterRange(startIp, endIp, desc);
      if (unmounted) return;
      flash(m.security_added_range({ start: startIp, end: endIp }));
      newStartIp = '';
      newEndIp = '';
      newDescription = '';
      showAddForm = false;
      await loadStats();
    } catch (e: unknown) {
      if (unmounted) return;
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
      if (unmounted) return;
      flash(m.security_removed_range({ start: entry.start_ip, end: entry.end_ip }));
    } catch (e: unknown) {
      if (unmounted) return;
      error = toErrorMsg(e);
    } finally {
      if (!unmounted) await loadStats();
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

  function sortOnKey(event: KeyboardEvent, action: () => void) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      action();
    }
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
  <h2>{m.security_title()}</h2>
  <div class="header-actions">
    <button onclick={handleDownload} disabled={downloading}>
      {downloading ? m.security_downloading() : m.security_download_ipfilter()}
    </button>
    <button class="ghost" onclick={handleImport} disabled={importing}>
      {importing ? m.security_importing() : m.security_import_file()}
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
      {showUrlForm ? m.security_cancel_url() : m.security_from_url()}
    </button>
    <button class="ghost" onclick={loadStats}>{m.common_refresh()}</button>
  </div>
</div>

{#if showUrlForm}
  <div id="ipfilter-url-form" class="ipfilter-url-form" role="group" aria-label={m.security_fetch_url_aria()}>
    <label for="ipfilter-url-input" class="sr-only">{m.security_url_label()}</label>
    <input
      id="ipfilter-url-input"
      type="url"
      placeholder="https://example.com/ipfilter.zip"
      bind:value={customUrl}
      disabled={urlFetching}
      onkeydown={(e) => { if (e.key === 'Enter' && !urlFetching) handleUrlFetch(); }}
    />
    <button onclick={handleUrlFetch} disabled={urlFetching || !customUrl.trim()}>
      {urlFetching ? m.security_fetching() : m.security_fetch()}
    </button>
  </div>
{/if}

<div class="security-content">
  {#if error}
    <div class="banner error-banner" role="alert">
      <span>{error}</span>
      <button class="ghost" onclick={() => (error = null)}>{m.common_dismiss()}</button>
    </div>
  {:else if successMsg}
    <div class="banner success-banner" role="status">
      <span>{successMsg}</span>
    </div>
  {/if}

  {#if loading && !stats}
    <div class="empty-state">
      <div class="spinner lg"></div>
      <p>{m.security_loading()}</p>
    </div>
  {:else if stats}
    <!-- Controls bar: toggles + stats inline -->
    <div class="controls-bar">
      <div class="controls-left">
        <ToggleSwitch
          bind:checked={stats.enabled}
          label={m.security_ipfilter_label()}
          onchange={(v) => { void persistIpFilterEnabled(v); }}
        />
        <ToggleSwitch
          bind:checked={stats.block_private}
          label={m.security_block_private_label()}
          onchange={(v) => { void persistBlockPrivate(v); }}
        />
        <button class="ghost add-range-btn" onclick={() => (showAddForm = !showAddForm)}>
          {showAddForm ? m.common_cancel() : m.security_add_range()}
        </button>
      </div>
      <div class="controls-right">
        <span class="inline-stat">{m.security_ranges_count({ count: stats.range_count.toLocaleString() })}</span>
        <span class="inline-sep">&middot;</span>
        <span class="inline-stat hits-stat">{m.security_hits_count({ count: stats.total_hits.toLocaleString() })}</span>
      </div>
    </div>

    {#if stats.enabled && !stats.ranges_ready}
      <div class="banner error-banner" role="alert">
        <span>{m.security_filter_fail_closed_banner()}</span>
      </div>
    {/if}

    {#if showAddForm}
      <div class="add-form">
        <div class="add-form-inner">
          <label class="add-field">
            <span class="add-field-label">{m.security_start_ip()}</span>
            <input bind:value={newStartIp} placeholder={m.security_start_ip_placeholder()} class="ip-input" aria-label={m.security_start_ip()} />
          </label>
          <span class="range-sep" aria-hidden="true">&mdash;</span>
          <label class="add-field">
            <span class="add-field-label">{m.security_end_ip()}</span>
            <input bind:value={newEndIp} placeholder={m.security_end_ip_placeholder()} class="ip-input" aria-label={m.security_end_ip()} />
          </label>
          <label class="add-field add-field-grow">
            <span class="add-field-label">{m.security_description_optional()}</span>
            <input bind:value={newDescription} placeholder={m.security_description_placeholder()} class="desc-input" aria-label={m.security_description_optional()} />
          </label>
          <button class="add-form-submit" onclick={handleAddRange}>{m.common_add()}</button>
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
          placeholder={m.security_search_placeholder()}
          aria-label={m.security_search_placeholder()}
        />
        {#if searchQuery}
          <button type="button" class="search-clear" onclick={() => { searchQuery = ''; }} title={m.security_clear_search()} aria-label={m.security_clear_search()}><IconX size={12} /></button>
        {/if}
      </div>
      <span class="result-count">
        {filteredEntries.length === 1
          ? m.security_range_count_one()
          : m.security_range_count_other({ count: filteredEntries.length.toLocaleString() })}
      </span>
    </div>

    {#if filteredEntries.length === 0 && !searchQuery.trim()}
      <div class="empty-state">
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="56" height="56" aria-hidden="true">
          <path d="M12 2l7 4v6c0 4.4-3 8.5-7 10-4-1.5-7-5.6-7-10V6l7-4z"></path>
        </svg>
        <p>{m.security_empty_no_ranges()}</p>
        <p class="sub">{m.security_empty_no_ranges_sub()}</p>
      </div>
    {:else if filteredEntries.length === 0}
      <div class="empty-state">
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="56" height="56" aria-hidden="true">
          <circle cx="11" cy="11" r="8"></circle>
          <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
        </svg>
        <p>{m.security_empty_no_matches()}</p>
        <p class="sub">{m.security_empty_no_matches_sub()}</p>
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
                tabindex="0"
                role="columnheader"
                aria-sort={ariaSort('range')}
                onclick={() => toggleSort('range')}
                onkeydown={(e) => sortOnKey(e, () => toggleSort('range'))}
              >
                <span class="th-content">{m.security_col_ip_range()}{sortArrow('range')}</span>
              </th>
              <th
                class="sortable col-desc"
                tabindex="0"
                role="columnheader"
                aria-sort={ariaSort('description')}
                onclick={() => toggleSort('description')}
                onkeydown={(e) => sortOnKey(e, () => toggleSort('description'))}
              >
                <span class="th-content">{m.security_col_description()}{sortArrow('description')}</span>
              </th>
              <th
                class="sortable col-hits"
                tabindex="0"
                role="columnheader"
                aria-sort={ariaSort('hits')}
                onclick={() => toggleSort('hits')}
                onkeydown={(e) => sortOnKey(e, () => toggleSort('hits'))}
              >
                <span class="th-content">{m.security_col_hits()}{sortArrow('hits')}</span>
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
                <td class="desc-cell" title={entry.description}>
                  <bdi dir="auto">{entry.description || '\u2014'}</bdi>
                </td>
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
                    type="button"
                    class="btn-remove"
                    onclick={() => handleRemoveRange(entry)}
                    title={m.security_remove_range_title()}
                    aria-label={m.security_remove_range_aria({ start: entry.start_ip, end: entry.end_ip })}
                  ><IconX size={13} /></button>
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
  title={m.security_confirm_remove_title()}
  message={pendingRemoveEntry
    ? m.security_confirm_remove_message({ start: pendingRemoveEntry.start_ip, end: pendingRemoveEntry.end_ip })
    : m.security_confirm_remove_message_generic()}
  confirmLabel={m.common_remove()}
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
    padding: 10px 16px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
  }
  .ipfilter-url-form input[type='url'] {
    flex: 1;
    min-width: 0;
    padding: 6px 10px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--bg-primary);
    color: var(--text-primary);
    font-family: inherit;
    font-size: 12px;
  }
  .ipfilter-url-form input[type='url']:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-halo);
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

  .add-range-btn {
    font-size: 12px;
    padding: 4px 10px;
  }

  /* --- Add range form --- */
  .add-form {
    padding: 12px 16px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
  }
  .add-form-inner {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }
  .add-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
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
    padding: 8px 16px;
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
    border-radius: var(--radius-pill);
    padding: 0 8px;
    background: var(--bg-input, var(--bg-primary));
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  .search-wrap:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-halo);
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
    box-shadow: none;
  }
  .search-clear {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: none;
    background: transparent;
    color: var(--text-secondary);
    width: 20px;
    height: 20px;
    border-radius: 50%;
    padding: 0;
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

  /*
   * Page root: own flex-column container that replaces the global
   * .page-content so the inner .table-area can virtualize against a
   * bounded viewport. With the global .page-content (which has
   * `overflow: auto; flex: 1`) the table area would grow to the
   * height of its contents — 60,000+ rows × 28px = 1.6M pixels of
   * single-row spacer — and the browser would stall trying to lay
   * that out. Here the page is overflow: hidden and the only scroll
   * container is the table body.
   */
  .security-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    min-height: 0;
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
  .ip-table th.sortable:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
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
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    padding: 0;
    border: 1px solid color-mix(in srgb, var(--danger) 38%, var(--border));
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--danger) 12%, transparent);
    color: var(--danger);
    cursor: pointer;
    line-height: 1;
    opacity: 0.7;
    transition: opacity 0.15s, background 0.12s, border-color 0.12s, color 0.12s;
  }
  .btn-remove:hover {
    color: #ffffff;
    border-color: var(--danger);
    background: var(--danger);
    opacity: 1;
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
