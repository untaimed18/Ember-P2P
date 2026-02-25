<script lang="ts">
  import SearchBar from '$lib/components/SearchBar.svelte';
  import { searchFiles } from '$lib/api/search';
  import { startDownload } from '$lib/api/transfers';
  import { searchResults, searchQuery, isSearching } from '$lib/stores/search';
  import type { SearchResult } from '$lib/types';

  const FILE_TYPES = [
    { value: '', label: 'Any' },
    { value: 'Audio', label: 'Audio' },
    { value: 'Video', label: 'Video' },
    { value: 'Image', label: 'Image' },
    { value: 'Pro', label: 'Program' },
    { value: 'Doc', label: 'Document' },
    { value: 'Arc', label: 'Archive' },
    { value: 'Iso', label: 'CD-Image' },
  ];

  const SIZE_UNITS = [
    { value: 1, label: 'B' },
    { value: 1024, label: 'KB' },
    { value: 1024 * 1024, label: 'MB' },
    { value: 1024 * 1024 * 1024, label: 'GB' },
  ];

  let filterType = $state('');
  let filterMinSize = $state('');
  let filterMinUnit = $state(1024 * 1024);
  let filterMaxSize = $state('');
  let filterMaxUnit = $state(1024 * 1024 * 1024);
  let filterExtension = $state('');
  let filterMinSources = $state('');

  type SortField = 'name' | 'size' | 'type' | 'sources';
  type SortDir = 'asc' | 'desc';
  let sortField: SortField = $state('sources');
  let sortDir: SortDir = $state('desc');

  function toggleSort(field: SortField) {
    if (sortField === field) {
      sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      sortField = field;
      sortDir = field === 'name' || field === 'type' ? 'asc' : 'desc';
    }
  }

  function sortIndicator(field: SortField): string {
    if (sortField !== field) return '';
    return sortDir === 'asc' ? ' \u25B2' : ' \u25BC';
  }

  let filteredResults: SearchResult[] = $derived.by(() => {
    let results = [...$searchResults];

    if (filterType) {
      results = results.filter(r => r.file_type === filterType);
    }

    if (filterExtension.trim()) {
      const ext = filterExtension.trim().toLowerCase().replace(/^\./, '');
      results = results.filter(r => r.file.extension.toLowerCase() === ext);
    }

    if (filterMinSize !== '') {
      const minBytes = parseFloat(filterMinSize) * filterMinUnit;
      if (!isNaN(minBytes) && minBytes > 0) {
        results = results.filter(r => r.file.size >= minBytes);
      }
    }

    if (filterMaxSize !== '') {
      const maxBytes = parseFloat(filterMaxSize) * filterMaxUnit;
      if (!isNaN(maxBytes) && maxBytes > 0) {
        results = results.filter(r => r.file.size <= maxBytes);
      }
    }

    if (filterMinSources !== '') {
      const minSrc = parseInt(filterMinSources, 10);
      if (!isNaN(minSrc) && minSrc > 0) {
        results = results.filter(r => r.availability >= minSrc);
      }
    }

    results.sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'name':
          cmp = a.file.name.localeCompare(b.file.name);
          break;
        case 'size':
          cmp = a.file.size - b.file.size;
          break;
        case 'type':
          cmp = (a.file_type || a.file.extension).localeCompare(b.file_type || b.file.extension);
          break;
        case 'sources':
          cmp = a.availability - b.availability;
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return results;
  });

  async function handleSearch(query: string) {
    if (!query.trim()) return;
    $searchQuery = query;
    $isSearching = true;
    $searchResults = [];
    try {
      const results = await searchFiles(query);
      $searchResults = results;
    } catch (e) {
      console.error('Search failed:', e);
    } finally {
      $isSearching = false;
    }
  }

  let downloadErrors: Record<string, string> = $state({});
  let downloadStarted: Record<string, boolean> = $state({});

  async function download(result: SearchResult) {
    const key = result.file.hash;
    downloadErrors[key] = '';
    downloadStarted[key] = false;
    try {
      const addr = result.source_addresses?.[0] || result.peer_id;
      const parts = addr.split(':');
      const peerIp = parts[0] || '';
      const peerPort = parseInt(parts[1] || '4662', 10);
      await startDownload(
        result.file.hash,
        result.file.name,
        result.file.size,
        peerIp,
        peerPort
      );
      downloadStarted[key] = true;
      setTimeout(() => (downloadStarted[key] = false), 3000);
    } catch (e: any) {
      console.error('Download failed:', e);
      downloadErrors[key] = typeof e === 'string' ? e : e?.message || 'Download failed';
    }
  }

  function formatSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
  }

  function clearFilters() {
    filterType = '';
    filterMinSize = '';
    filterMaxSize = '';
    filterExtension = '';
    filterMinSources = '';
  }

  let hasActiveFilters = $derived(
    filterType !== '' ||
    filterMinSize !== '' ||
    filterMaxSize !== '' ||
    filterExtension !== '' ||
    filterMinSources !== ''
  );
</script>

<div class="page-header">
  <h2>Search</h2>
</div>

<div class="search-area">
  <SearchBar
    bind:value={$searchQuery}
    placeholder="Search files across the network..."
    onsubmit={handleSearch}
  />
  <button onclick={() => handleSearch($searchQuery)} disabled={$isSearching}>
    {$isSearching ? 'Searching...' : 'Search'}
  </button>
</div>

<div class="filter-bar">
  <div class="filter-group">
    <label for="filter-type">Type</label>
    <select id="filter-type" bind:value={filterType}>
      {#each FILE_TYPES as ft}
        <option value={ft.value}>{ft.label}</option>
      {/each}
    </select>
  </div>

  <div class="filter-group">
    <label for="filter-min-size">Min Size</label>
    <div class="size-input">
      <input
        id="filter-min-size"
        type="number"
        min="0"
        step="any"
        placeholder="—"
        bind:value={filterMinSize}
      />
      <select bind:value={filterMinUnit}>
        {#each SIZE_UNITS as u}
          <option value={u.value}>{u.label}</option>
        {/each}
      </select>
    </div>
  </div>

  <div class="filter-group">
    <label for="filter-max-size">Max Size</label>
    <div class="size-input">
      <input
        id="filter-max-size"
        type="number"
        min="0"
        step="any"
        placeholder="—"
        bind:value={filterMaxSize}
      />
      <select bind:value={filterMaxUnit}>
        {#each SIZE_UNITS as u}
          <option value={u.value}>{u.label}</option>
        {/each}
      </select>
    </div>
  </div>

  <div class="filter-group">
    <label for="filter-ext">Extension</label>
    <input
      id="filter-ext"
      type="text"
      placeholder="e.g. mp3"
      bind:value={filterExtension}
      class="ext-input"
    />
  </div>

  <div class="filter-group">
    <label for="filter-sources">Min Sources</label>
    <input
      id="filter-sources"
      type="number"
      min="1"
      step="1"
      placeholder="—"
      bind:value={filterMinSources}
      class="sources-input"
    />
  </div>

  {#if hasActiveFilters}
    <button class="ghost clear-filters" onclick={clearFilters}>Clear Filters</button>
  {/if}
</div>

<div class="page-content">
  {#if $searchResults.length === 0 && !$isSearching}
    <div class="empty-state">
      <div class="icon">&#x2315;</div>
      <p>Search for files across the P2P network</p>
      <p class="hint">Enter a query and press Enter or click Search</p>
    </div>
  {:else if $isSearching}
    <div class="empty-state">
      <p>Searching the network...</p>
    </div>
  {:else}
    <div class="results-info">
      {#if hasActiveFilters}
        Showing {filteredResults.length} of {$searchResults.length} results
      {:else}
        {$searchResults.length} results
      {/if}
    </div>
    <table>
      <thead>
        <tr>
          <th class="sortable col-name" onclick={() => toggleSort('name')}>
            Name{sortIndicator('name')}
          </th>
          <th class="sortable col-size" onclick={() => toggleSort('size')}>
            Size{sortIndicator('size')}
          </th>
          <th class="sortable col-type" onclick={() => toggleSort('type')}>
            Type{sortIndicator('type')}
          </th>
          <th class="sortable col-sources" onclick={() => toggleSort('sources')}>
            Sources{sortIndicator('sources')}
          </th>
          <th class="col-actions">Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each filteredResults as result (result.file.hash)}
          <tr>
            <td class="col-name" title={result.file.name}>{result.file.name}</td>
            <td class="col-size">{formatSize(result.file.size)}</td>
            <td class="col-type">{result.file_type || result.file.extension || '\u2014'}</td>
            <td class="col-sources">
              <span class="source-count" class:high-sources={result.availability >= 10}>
                {result.availability}
              </span>
            </td>
            <td class="col-actions">
              <button onclick={() => download(result)}>Download</button>
              {#if downloadStarted[result.file.hash]}
                <span class="success-msg">Queued</span>
              {/if}
              {#if downloadErrors[result.file.hash]}
                <span class="error-msg">{downloadErrors[result.file.hash]}</span>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if filteredResults.length === 0 && $searchResults.length > 0}
      <div class="empty-state">
        <p>No results match the current filters</p>
        <button class="ghost" onclick={clearFilters}>Clear Filters</button>
      </div>
    {/if}
  {/if}
</div>

<style>
  .search-area {
    display: flex;
    gap: 12px;
    padding: 16px 20px 12px;
    align-items: stretch;
  }

  .search-area :global(.search-bar) {
    flex: 1;
  }

  .filter-bar {
    display: flex;
    gap: 16px;
    padding: 0 20px 12px;
    align-items: flex-end;
    flex-wrap: wrap;
    border-bottom: 1px solid var(--border);
  }

  .filter-group {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .filter-group label {
    font-size: 11px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.4px;
  }

  .filter-group select,
  .filter-group input {
    font-size: 13px;
    padding: 5px 8px;
    min-width: 0;
  }

  .filter-group select {
    min-width: 100px;
  }

  .size-input {
    display: flex;
    gap: 4px;
  }

  .size-input input {
    width: 72px;
  }

  .size-input select {
    min-width: 56px;
  }

  .ext-input {
    width: 80px;
  }

  .sources-input {
    width: 64px;
  }

  .clear-filters {
    font-size: 12px;
    padding: 5px 10px;
    align-self: flex-end;
    margin-bottom: 1px;
  }

  .results-info {
    padding: 8px 20px;
    font-size: 12px;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
  }

  .col-name {
    width: 45%;
    max-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .col-size {
    width: 12%;
    text-align: right;
  }

  .col-type {
    width: 12%;
  }

  .col-sources {
    width: 10%;
    text-align: center;
  }

  .col-actions {
    width: 21%;
  }

  th.sortable {
    cursor: pointer;
    user-select: none;
  }

  th.sortable:hover {
    color: var(--text-primary);
  }

  .source-count {
    display: inline-block;
    min-width: 24px;
    text-align: center;
    padding: 1px 6px;
    border-radius: 10px;
    font-size: 12px;
    font-weight: 600;
    background: var(--bg-hover);
  }

  .source-count.high-sources {
    background: var(--accent-dim);
    color: var(--text-accent);
  }

  .hint {
    font-size: 13px;
    color: var(--text-muted);
  }

  .error-msg {
    color: var(--danger);
    font-size: 11px;
    margin-left: 8px;
  }

  .success-msg {
    color: var(--success, #2ecc71);
    font-size: 11px;
    margin-left: 8px;
  }
</style>
