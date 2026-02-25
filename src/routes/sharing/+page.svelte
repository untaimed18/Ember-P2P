<script lang="ts">
  import FileList from '$lib/components/FileList.svelte';
  import {
    addSharedFolder,
    removeSharedFolder,
    getSharedFiles,
    getSharedFolders,
  } from '$lib/api/sharing';
  import type { FileInfo } from '$lib/types';
  import { onMount } from 'svelte';

  let folders: string[] = $state([]);
  let files: FileInfo[] = $state([]);
  let loading = $state(false);

  onMount(async () => {
    await refresh();
  });

  async function refresh() {
    loading = true;
    try {
      [folders, files] = await Promise.all([getSharedFolders(), getSharedFiles()]);
    } catch (e) {
      console.error('Failed to load shared files:', e);
    } finally {
      loading = false;
    }
  }

  async function handleAddFolder() {
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({ directory: true, multiple: false });
      if (selected) {
        loading = true;
        await addSharedFolder(selected as string);
        await refresh();
      }
    } catch (e) {
      console.error('Failed to add folder:', e);
    }
  }

  async function handleRemoveFolder(path: string) {
    try {
      loading = true;
      await removeSharedFolder(path);
      await refresh();
    } catch (e) {
      console.error('Failed to remove folder:', e);
    }
  }
</script>

<div class="page-header">
  <h2>Sharing</h2>
  <button onclick={handleAddFolder}>+ Add Folder</button>
</div>

<div class="page-content">
  {#if folders.length > 0}
    <div class="folders-section">
      <div class="section-title">Shared Folders</div>
      <div class="folder-list">
        {#each folders as folder}
          <div class="folder-item">
            <span class="folder-icon">📁</span>
            <span class="folder-path" title={folder}>{folder}</span>
            <button class="ghost danger" onclick={() => handleRemoveFolder(folder)}>Remove</button>
          </div>
        {/each}
      </div>
    </div>
  {/if}

  {#if loading}
    <div class="empty-state">
      <p>Scanning files...</p>
    </div>
  {:else if files.length === 0}
    <div class="empty-state">
      <div class="icon">⊕</div>
      <p>No files shared yet</p>
      <p class="sub">Click "Add Folder" to share files with the network</p>
    </div>
  {:else}
    <div class="files-section">
      <div class="section-title">{files.length} files shared</div>
      <FileList {files} />
    </div>
  {/if}
</div>

<style>
  .folders-section, .files-section {
    border-bottom: 1px solid var(--border);
  }

  .section-title {
    padding: 10px 20px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    background: var(--bg-primary);
    border-bottom: 1px solid var(--border);
  }

  .folder-list {
    padding: 8px 0;
  }

  .folder-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 20px;
    transition: background 0.1s;
  }

  .folder-item:hover {
    background: var(--bg-hover);
  }

  .folder-icon {
    font-size: 18px;
  }

  .folder-path {
    flex: 1;
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .sub {
    font-size: 13px;
    color: var(--text-muted);
  }
</style>
