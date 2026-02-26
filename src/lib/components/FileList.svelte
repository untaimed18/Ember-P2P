<script lang="ts">
  import type { FileInfo } from '$lib/types';
  import { formatEd2kLink } from '$lib/api/search';

  let {
    files = [],
    onselect,
    showCopyLink = false,
  }: {
    files: FileInfo[];
    onselect?: (file: FileInfo) => void;
    showCopyLink?: boolean;
  } = $props();

  let copiedId: string | null = $state(null);

  async function copyLink(file: FileInfo) {
    try {
      const link = await formatEd2kLink(file.name, file.size, file.hash);
      await navigator.clipboard.writeText(link);
      copiedId = file.id;
      setTimeout(() => { copiedId = null; }, 2000);
    } catch (e) {
      console.error('Failed to copy link:', e);
    }
  }

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

  import { formatSize } from '$lib/utils';

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
          {#if showCopyLink}
            <th>Link</th>
          {/if}
        </tr>
      </thead>
      <tbody>
        {#each sorted as file (file.id)}
          <tr onclick={() => onselect?.(file)} class:clickable={!!onselect}>
            <td title={file.path}>{file.name}</td>
            <td>{file.extension || '—'}</td>
            <td>{formatSize(file.size)}</td>
            <td class="hash">{file.hash.slice(0, 16)}…</td>
            {#if showCopyLink}
              <td>
                <button class="ghost copy-btn" onclick={(e: MouseEvent) => { e.stopPropagation(); copyLink(file); }}>
                  {copiedId === file.id ? 'Copied!' : 'Copy ed2k Link'}
                </button>
              </td>
            {/if}
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

  .copy-btn {
    font-size: 11px;
    padding: 2px 8px;
    white-space: nowrap;
  }
</style>
