<script lang="ts">
  import {
    getIpFilterStats,
    addIpFilterRange,
    removeIpFilterRange,
    setIpFilterEnabled,
    setBlockPrivateIps,
    downloadAndLoadIpfilter,
    importIpfilterFile,
    type IpFilterStats,
    type IpFilterEntry,
  } from '$lib/api/security';
  import { onMount } from 'svelte';

  let stats: IpFilterStats | null = $state(null);
  let loading = $state(true);
  let error: string | null = $state(null);
  let successMsg: string | null = $state(null);

  let downloading = $state(false);
  let importing = $state(false);

  let showAddForm = $state(false);
  let newStartIp = $state('');
  let newEndIp = $state('');
  let newDescription = $state('');

  let searchQuery = $state('');
  let sortBy: 'range' | 'hits' | 'description' = $state('hits');
  let sortAsc = $state(false);

  let currentPage = $state(0);
  const pageSize = 50;

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
      else cmp = a.start_ip.localeCompare(b.start_ip);
      return sortAsc ? cmp : -cmp;
    });
    return entries;
  });

  let totalPages = $derived(Math.max(1, Math.ceil(filteredEntries.length / pageSize)));
  let pagedEntries = $derived(filteredEntries.slice(currentPage * pageSize, (currentPage + 1) * pageSize));

  onMount(() => {
    loadStats();
  });

  async function loadStats() {
    loading = true;
    error = null;
    try {
      stats = await getIpFilterStats();
    } catch (e: unknown) {
      error = toErrorMsg(e);
    } finally {
      loading = false;
    }
  }

  function toErrorMsg(e: unknown): string {
    return e instanceof Error ? e.message : typeof e === 'string' ? e : 'Operation failed';
  }

  function flash(msg: string) {
    successMsg = msg;
    setTimeout(() => (successMsg = null), 4000);
  }

  async function handleToggleEnabled() {
    if (!stats) return;
    try {
      await setIpFilterEnabled(!stats.enabled);
      stats.enabled = !stats.enabled;
    } catch (e: unknown) {
      error = toErrorMsg(e);
    }
  }

  async function handleTogglePrivate() {
    if (!stats) return;
    try {
      await setBlockPrivateIps(!stats.block_private);
      stats.block_private = !stats.block_private;
    } catch (e: unknown) {
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

  function isValidIpv4(ip: string): boolean {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(p => { const n = Number(p); return Number.isInteger(n) && n >= 0 && n <= 255 && p === String(n); });
  }

  async function handleAddRange() {
    if (!newStartIp || !newEndIp) {
      error = 'Both start and end IP are required';
      return;
    }
    if (!isValidIpv4(newStartIp.trim()) || !isValidIpv4(newEndIp.trim())) {
      error = 'Invalid IP address format. Use dotted decimal (e.g. 192.168.1.0)';
      return;
    }
    error = null;
    try {
      await addIpFilterRange(newStartIp, newEndIp, newDescription);
      flash(`Added range ${newStartIp} — ${newEndIp}`);
      newStartIp = '';
      newEndIp = '';
      newDescription = '';
      showAddForm = false;
      await loadStats();
    } catch (e: unknown) {
      error = toErrorMsg(e);
    }
  }

  async function handleRemoveRange(entry: IpFilterEntry) {
    error = null;
    try {
      await removeIpFilterRange(entry.start_ip, entry.end_ip);
      flash(`Removed range ${entry.start_ip} — ${entry.end_ip}`);
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
    currentPage = 0;
  }

  function sortIndicator(col: string) {
    if (sortBy !== col) return '';
    return sortAsc ? ' ▲' : ' ▼';
  }
</script>

<div class="page-header">
  <h2>Security</h2>
  <div class="header-actions">
    <button onclick={handleDownload} disabled={downloading}>
      {downloading ? 'Downloading...' : 'Download IP Filter'}
    </button>
    <button class="ghost" onclick={handleImport} disabled={importing}>
      {importing ? 'Importing...' : 'Import File'}
    </button>
    <button class="ghost" onclick={loadStats}>Refresh</button>
  </div>
</div>

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
    <div class="empty-state"><p>Loading IP filter data...</p></div>
  {:else if stats}
    <!-- Stats overview -->
    <div class="stats-row">
      <div class="stat-card">
        <div class="label">Status</div>
        <div class="value">
          <span class="badge" class:active={stats.enabled} class:disconnected={!stats.enabled}>
            {stats.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
      </div>
      <div class="stat-card">
        <div class="label">Blocked Ranges</div>
        <div class="value">{stats.range_count.toLocaleString()}</div>
      </div>
      <div class="stat-card">
        <div class="label">Total Hits</div>
        <div class="value">{stats.total_hits.toLocaleString()}</div>
      </div>
      <div class="stat-card">
        <div class="label">Block Private IPs</div>
        <div class="value">
          <span class="badge" class:active={stats.block_private} class:disconnected={!stats.block_private}>
            {stats.block_private ? 'Yes' : 'No'}
          </span>
        </div>
      </div>
    </div>

    <!-- Toggles -->
    <div class="controls-row">
      <label class="toggle-label">
        <input type="checkbox" checked={stats.enabled} onchange={handleToggleEnabled} />
        <span>IP Filter Enabled</span>
      </label>
      <label class="toggle-label">
        <input type="checkbox" checked={stats.block_private} onchange={handleTogglePrivate} />
        <span>Block Private/Reserved IPs</span>
      </label>
      <button class="ghost" onclick={() => (showAddForm = !showAddForm)}>
        {showAddForm ? 'Cancel' : '+ Add Range'}
      </button>
    </div>

    <!-- Add range form -->
    {#if showAddForm}
      <div class="add-form">
        <input bind:value={newStartIp} placeholder="Start IP (e.g. 1.0.0.0)" />
        <span class="range-sep">—</span>
        <input bind:value={newEndIp} placeholder="End IP (e.g. 1.0.0.255)" />
        <input bind:value={newDescription} placeholder="Description (optional)" class="desc-input" />
        <button onclick={handleAddRange}>Add</button>
      </div>
    {/if}

    <!-- Search & table -->
    <div class="table-toolbar">
      <input
        class="search-input"
        bind:value={searchQuery}
        placeholder="Search IP ranges or descriptions..."
        oninput={() => (currentPage = 0)}
      />
      <span class="result-count">
        {filteredEntries.length.toLocaleString()} range{filteredEntries.length !== 1 ? 's' : ''}
      </span>
    </div>

    {#if filteredEntries.length === 0}
      <div class="empty-state">
        <div class="icon">🛡</div>
        <p>No IP ranges loaded</p>
        <p class="sub">Download or import an ipfilter.dat to get started</p>
      </div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th class="sortable" onclick={() => toggleSort('range')}>IP Range{sortIndicator('range')}</th>
              <th class="sortable" onclick={() => toggleSort('description')}>Description{sortIndicator('description')}</th>
              <th class="sortable" onclick={() => toggleSort('hits')}>Hits{sortIndicator('hits')}</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each pagedEntries as entry (`${entry.start_ip}-${entry.end_ip}`)}
              <tr>
                <td class="ip-cell">
                  <span class="ip-range">{entry.start_ip}</span>
                  <span class="range-arrow">→</span>
                  <span class="ip-range">{entry.end_ip}</span>
                </td>
                <td class="desc-cell" title={entry.description}>{entry.description || '—'}</td>
                <td class="hits-cell">
                  {#if entry.hits > 0}
                    <span class="hit-count">{entry.hits.toLocaleString()}</span>
                  {:else}
                    <span class="no-hits">0</span>
                  {/if}
                </td>
                <td>
                  <button class="ghost danger btn-sm" onclick={() => handleRemoveRange(entry)} title="Remove this range">✕</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      {#if totalPages > 1}
        <div class="pagination">
          <button class="ghost" disabled={currentPage === 0} onclick={() => (currentPage = 0)}>First</button>
          <button class="ghost" disabled={currentPage === 0} onclick={() => currentPage--}>Prev</button>
          <span class="page-info">Page {currentPage + 1} of {totalPages}</span>
          <button class="ghost" disabled={currentPage >= totalPages - 1} onclick={() => currentPage++}>Next</button>
          <button class="ghost" disabled={currentPage >= totalPages - 1} onclick={() => (currentPage = totalPages - 1)}>Last</button>
        </div>
      {/if}
    {/if}
  {/if}
</div>

<style>
  .header-actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 20px;
    font-size: 13px;
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

  .stats-row {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 12px;
    padding: 16px 20px;
  }

  .controls-row {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 0 20px 12px;
    flex-wrap: wrap;
  }

  .toggle-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: var(--text-primary);
    cursor: pointer;
    user-select: none;
  }

  .toggle-label input[type='checkbox'] {
    width: 16px;
    height: 16px;
    accent-color: var(--accent);
    cursor: pointer;
  }

  .add-form {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 20px;
    background: var(--bg-surface);
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }

  .add-form input {
    width: 160px;
  }

  .add-form .desc-input {
    width: 220px;
  }

  .range-sep {
    color: var(--text-muted);
    font-size: 16px;
  }

  .table-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 20px;
    gap: 12px;
    border-bottom: 1px solid var(--border);
  }

  .search-input {
    flex: 1;
    max-width: 400px;
  }

  .result-count {
    font-size: 12px;
    color: var(--text-muted);
    white-space: nowrap;
  }

  .table-wrap {
    overflow: auto;
  }

  .ip-cell {
    font-family: var(--font-mono);
    font-size: 12px;
    white-space: nowrap;
  }

  .ip-range {
    color: var(--text-primary);
  }

  .range-arrow {
    color: var(--text-muted);
    margin: 0 4px;
  }

  .desc-cell {
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-secondary);
  }

  .hits-cell {
    text-align: right;
    font-family: var(--font-mono);
    font-size: 12px;
  }

  .hit-count {
    color: var(--danger);
    font-weight: 600;
  }

  .no-hits {
    color: var(--text-muted);
  }

  .btn-sm {
    padding: 2px 8px;
    font-size: 12px;
  }

  .pagination {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 10px 20px;
    border-top: 1px solid var(--border);
  }

  .page-info {
    font-size: 12px;
    color: var(--text-muted);
    min-width: 100px;
    text-align: center;
  }

  .sub {
    font-size: 13px;
    color: var(--text-muted);
  }
</style>
