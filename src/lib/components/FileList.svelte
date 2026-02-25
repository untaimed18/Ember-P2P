<script lang="ts">
  import type { FileInfo } from '$lib/types';

  let {
    files = [],
    onselect,
  }: {
    files: FileInfo[];
    onselect?: (file: FileInfo) => void;
  } = $props();

  let sortKey: keyof FileInfo = $state('name');
  let sortAsc = $state(true);

  let sorted = $derived.by(() => {
    const copy = [...files];
    copy.sort((a, b) => {
      const aVal = a[sortKey];
      const bVal = b[sortKey];
      if (typeof aVal === 'string' && typeof bVal === 'string') {
        return sortAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
      }
      return sortAsc ? Number(aVal) - Number(bVal) : Number(bVal) - Number(aVal);
    });
    return copy;
  });

  function toggleSort(key: keyof FileInfo) {
    if (sortKey === key) {
      sortAsc = !sortAsc;
    } else {
      sortKey = key;
      sortAsc = true;
    }
  }

  function formatSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
  }

  function sortIndicator(key: keyof FileInfo): string {
    if (sortKey !== key) return '';
    return sortAsc ? ' ▲' : ' ▼';
  }
</script>

{#if files.length === 0}
  <div class="empty-state">
    <div class="icon">📂</div>
    <p>No files to display</p>
  </div>
{:else}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th class="sortable" onclick={() => toggleSort('name')}>
            Name{sortIndicator('name')}
          </th>
          <th class="sortable" onclick={() => toggleSort('extension')}>
            Type{sortIndicator('extension')}
          </th>
          <th class="sortable" onclick={() => toggleSort('size')}>
            Size{sortIndicator('size')}
          </th>
          <th>Hash</th>
        </tr>
      </thead>
      <tbody>
        {#each sorted as file (file.id)}
          <tr onclick={() => onselect?.(file)} class="clickable">
            <td title={file.path}>{file.name}</td>
            <td>{file.extension || '—'}</td>
            <td>{formatSize(file.size)}</td>
            <td class="hash">{file.hash.slice(0, 16)}…</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  .table-wrap {
    overflow: auto;
    max-height: 100%;
  }

  .clickable {
    cursor: pointer;
  }

  .hash {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-muted);
  }
</style>
