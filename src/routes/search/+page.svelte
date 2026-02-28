<script lang="ts">
  import SearchBar from '$lib/components/SearchBar.svelte';
  import { searchFiles, parseEd2kLink, findNotes, publishNote, type SearchMethod } from '$lib/api/search';
  import { startDownload } from '$lib/api/transfers';
  import { searchResults, searchQuery, isSearching, searchProgress, newSearchNonce } from '$lib/stores/search';
  import type { SearchResult } from '$lib/types';

  let searchMethod: SearchMethod = $state('global');

  let ed2kInput = $state('');
  let ed2kError = $state('');
  let ed2kSuccess = $state('');
  let searchError: string | null = $state(null);

  let selectedResult: SearchResult | null = $state(null);
  let notes: SearchResult[] = $state([]);
  let loadingNotes = $state(false);
  let noteRating = $state(0);
  let noteComment = $state('');
  let publishSuccess = $state(false);

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

  let searchTimeout: ReturnType<typeof setTimeout> | null = null;

  async function handleSearch(query: string) {
    if (!query.trim()) return;
    $searchQuery = query;
    $isSearching = true;
    $searchResults = [];
    searchError = null;
    newSearchNonce();
    if (searchTimeout) clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      if ($isSearching) {
        $isSearching = false;
        $searchProgress = null;
      }
    }, 90_000);
    try {
      const results = await searchFiles(query, searchMethod);
      if (results && results.length > 0) {
        $searchResults = results;
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Search failed';
      searchError = msg;
      console.error('Search failed:', e);
      $isSearching = false;
      $searchProgress = null;
      if (searchTimeout) { clearTimeout(searchTimeout); searchTimeout = null; }
    }
  }

  async function showFileDetails(result: SearchResult) {
    selectedResult = result;
    loadingNotes = true;
    notes = [];
    try {
      notes = await findNotes(result.file.hash, result.file.size);
    } catch (e: unknown) {
      console.error('Failed to load notes:', e);
    } finally {
      loadingNotes = false;
    }
  }

  async function handlePublishNote() {
    if (!selectedResult) return;
    publishSuccess = false;
    try {
      await publishNote(selectedResult.file.hash, noteRating, noteComment);
      publishSuccess = true;
      noteComment = '';
      noteRating = 0;
      setTimeout(() => publishSuccess = false, 3000);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Publish failed';
      searchError = msg;
    }
  }

  let downloadErrors: Record<string, string> = $state({});
  let downloadStarted: Record<string, boolean> = $state({});

  async function download(result: SearchResult) {
    const key = result.file.hash;
    downloadErrors[key] = '';
    downloadStarted[key] = false;
    try {
      let peerIp = '';
      let peerPort = 0;
      const addr = result.source_addresses?.[0];
      if (addr && addr.includes(':')) {
        const parts = addr.split(':');
        peerIp = parts[0] || '';
        peerPort = parseInt(parts[1] || '0', 10);
      }
      await startDownload(
        result.file.hash,
        result.file.name,
        result.file.size,
        peerIp,
        peerPort
      );
      downloadStarted[key] = true;
      setTimeout(() => (downloadStarted[key] = false), 3000);
    } catch (e: unknown) {
      console.error('Download failed:', e);
      downloadErrors[key] = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Download failed';
    }
  }

  import { formatSize } from '$lib/utils';

  async function handleEd2kLink() {
    const link = ed2kInput.trim();
    if (!link) return;
    ed2kError = '';
    ed2kSuccess = '';
    try {
      const info = await parseEd2kLink(link);
      await startDownload(info.hash, info.name, info.size, '', 0);
      ed2kSuccess = `Queued: ${info.name}`;
      ed2kInput = '';
      setTimeout(() => (ed2kSuccess = ''), 5000);
    } catch (e: unknown) {
      ed2kError = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Invalid ed2k link';
      setTimeout(() => (ed2kError = ''), 5000);
    }
  }

  function clearFilters() {
    filterType = '';
    filterMinSize = '';
    filterMaxSize = '';
    filterExtension = '';
    filterMinSources = '';
  }

  function clearResults() {
    $searchResults = [];
    searchError = null;
    selectedResult = null;
    notes = [];
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
  <div class="method-selector">
    <button
      class="method-btn"
      class:active={searchMethod === 'global'}
      onclick={() => searchMethod = 'global'}
      title="Search all sources (Server + KAD)"
    >Global</button>
    <button
      class="method-btn"
      class:active={searchMethod === 'server'}
      onclick={() => searchMethod = 'server'}
      title="Search connected ed2k servers only"
    >Server</button>
    <button
      class="method-btn"
      class:active={searchMethod === 'kad'}
      onclick={() => searchMethod = 'kad'}
      title="Search KAD network only"
    >KAD</button>
  </div>
  <button onclick={() => handleSearch($searchQuery)} disabled={$isSearching}>
    {$isSearching ? 'Searching...' : 'Search'}
  </button>
</div>

<div class="ed2k-bar">
  <input
    type="text"
    placeholder="Paste ed2k://|file|... link to download"
    bind:value={ed2kInput}
    onkeydown={(e) => { if (e.key === 'Enter') handleEd2kLink(); }}
    aria-label="ed2k link input"
  />
  <button onclick={handleEd2kLink} disabled={!ed2kInput.trim()}>Add Link</button>
  {#if ed2kSuccess}
    <span class="ed2k-success">{ed2kSuccess}</span>
  {/if}
  {#if ed2kError}
    <span class="ed2k-error">{ed2kError}</span>
  {/if}
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
  {#if searchError}
    <div class="search-error-banner">
      <span>Search failed: {searchError}</span>
      <button class="ghost" onclick={() => searchError = null}>Dismiss</button>
    </div>
  {/if}
  {#if $searchResults.length === 0 && !$isSearching}
    <div class="empty-state">
      <div class="icon">&#x2315;</div>
      <p>Search for files across the P2P network</p>
      <p class="hint">Enter a query and press Enter or click Search</p>
    </div>
  {:else if $isSearching}
    <div class="empty-state">
      <p>Searching the network...</p>
      {#if $searchProgress}
        <p class="search-detail">
          Contacted {$searchProgress.nodes_contacted} nodes
          {#if $searchProgress.results_so_far > 0}
            &middot; {$searchProgress.results_so_far} results found
          {/if}
          &middot; {$searchProgress.phase}
        </p>
      {/if}
    </div>
  {:else}
    <div class="results-info">
      <span>
        {#if hasActiveFilters}
          Showing {filteredResults.length} of {$searchResults.length} results
        {:else}
          {$searchResults.length} results
        {/if}
      </span>
      <button class="ghost clear-results-btn" onclick={clearResults}>Clear Results</button>
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
            <td class="col-name" title={result.file.name}>
              <button class="ghost link-btn" onclick={() => showFileDetails(result)}>{result.file.name}</button>
            </td>
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
    {#if selectedResult}
      <div class="file-details-panel">
        <div class="panel-header">
          <h3>File Details</h3>
          <button class="ghost" onclick={() => selectedResult = null}>✕</button>
        </div>
        <div class="panel-body">
          <div class="detail-row"><strong>Name:</strong> {selectedResult.file.name}</div>
          <div class="detail-row"><strong>Size:</strong> {formatSize(selectedResult.file.size)}</div>
          <div class="detail-row"><strong>Hash:</strong> <code>{selectedResult.file.hash}</code></div>
          <div class="detail-row"><strong>Sources:</strong> {selectedResult.availability}</div>
          
          <h4>Notes & Comments</h4>
          {#if loadingNotes}
            <p class="hint">Loading notes...</p>
          {:else if notes.length === 0}
            <p class="hint">No notes found for this file</p>
          {:else}
            <div class="notes-list">
              {#each notes as note}
                <div class="note-item">
                  <span class="note-peer">{note.peer_name || 'Anonymous'}</span>
                  {#if note.rating}
                    <span class="note-rating">{'★'.repeat(note.rating)}{'☆'.repeat(5 - note.rating)}</span>
                  {/if}
                  {#if note.comment}
                    <span class="note-comment">{note.comment}</span>
                  {/if}
                </div>
              {/each}
            </div>
          {/if}
          
          <div class="publish-note">
            <h4>Add Note</h4>
            <div class="note-form">
              <label for="note-rating">Rating (0-5)</label>
              <input id="note-rating" type="number" min="0" max="5" bind:value={noteRating} />
              <label for="note-comment">Comment</label>
              <input id="note-comment" type="text" bind:value={noteComment} placeholder="Optional comment..." />
              <button onclick={handlePublishNote}>Publish Note</button>
              {#if publishSuccess}
                <span class="success-msg">Published!</span>
              {/if}
            </div>
          </div>
        </div>
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

  .method-selector {
    display: flex;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    overflow: hidden;
    flex-shrink: 0;
  }

  .method-btn {
    padding: 6px 14px;
    font-size: 12px;
    font-weight: 600;
    border: none;
    border-radius: 0;
    background: var(--bg-surface);
    color: var(--text-secondary);
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
    border-right: 1px solid var(--border);
  }

  .method-btn:last-child {
    border-right: none;
  }

  .method-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .method-btn.active {
    background: var(--accent);
    color: #fff;
  }

  [data-theme="dark"] .method-btn.active {
    background: var(--accent-dim);
    color: var(--text-primary);
  }

  .ed2k-bar {
    display: flex;
    gap: 8px;
    padding: 0 20px 12px;
    align-items: center;
  }

  .ed2k-bar input {
    flex: 1;
    font-family: var(--font-mono);
    font-size: 12px;
    padding: 5px 8px;
  }

  .ed2k-success {
    color: var(--success, #2ecc71);
    font-size: 12px;
    white-space: nowrap;
  }

  .ed2k-error {
    color: var(--danger, #e74c3c);
    font-size: 12px;
    white-space: nowrap;
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
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .clear-results-btn {
    font-size: 11px;
    padding: 2px 10px;
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

  .hint, .search-detail {
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

  .search-error-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 20px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--danger, #e74c3c);
    color: var(--danger, #e74c3c);
    font-size: 13px;
  }

  .file-details-panel {
    border-top: 2px solid var(--border);
    background: var(--bg-secondary);
    max-height: 300px;
    overflow-y: auto;
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 20px;
    border-bottom: 1px solid var(--border);
  }

  .panel-header h3 {
    margin: 0;
    font-size: 14px;
  }

  .panel-body {
    padding: 12px 20px;
  }

  .detail-row {
    font-size: 13px;
    margin-bottom: 6px;
  }

  .detail-row code {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-muted);
  }

  .notes-list {
    margin: 8px 0;
  }

  .note-item {
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }

  .publish-note {
    margin-top: 12px;
  }

  .publish-note h4 {
    font-size: 13px;
    margin-bottom: 8px;
  }

  .note-form {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }

  .note-form label {
    font-size: 12px;
    color: var(--text-muted);
  }

  .note-form input[type="number"] {
    width: 60px;
  }

  .note-form input[type="text"] {
    flex: 1;
    min-width: 200px;
  }

  .link-btn {
    text-align: left;
    font-size: inherit;
    color: inherit;
    padding: 0;
    text-decoration: none;
  }

  .link-btn:hover {
    color: var(--accent);
    text-decoration: underline;
  }
</style>
