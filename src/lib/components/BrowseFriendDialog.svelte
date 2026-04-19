<script lang="ts">
  import { onDestroy } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { browseFriend, type BrowseFileEntry } from '$lib/api/friends';
  import { startDownload } from '$lib/api/transfers';

  interface Props {
    open: boolean;
    friendHash: string;
    friendName: string;
    friendLastIp: string;
    friendLastPort: number;
    onclose: () => void;
  }

  let { open = $bindable(), friendHash, friendName, friendLastIp, friendLastPort, onclose }: Props = $props();

  let files: BrowseFileEntry[] = $state([]);
  let loading = $state(false);
  let error: string | null = $state(null);
  let unlisten: UnlistenFn | null = null;
  let listenerGen = 0;
  let browseTimeout: ReturnType<typeof setTimeout> | undefined;

  $effect(() => {
    if (open && friendHash) {
      // Capture the generation BEFORE awaiting so we can detect a
      // close/re-open race: if the user closes the dialog (or
      // switches friend) while `setupListener` is still awaiting,
      // the cleanup destructor bumps `listenerGen` and we abort
      // before issuing a stale `requestBrowse()`. Without this, a
      // closed dialog could still fire IPC and corrupt the next
      // session's state.
      const gen = ++listenerGen;
      (async () => {
        const ok = await setupListener(gen);
        if (!ok || gen !== listenerGen || !open) return;
        await requestBrowse();
      })();
    }
    return () => {
      listenerGen++;
      clearTimeout(browseTimeout);
      if (unlisten) { unlisten(); unlisten = null; }
      if (unlistenError) { unlistenError(); unlistenError = null; }
    };
  });

  let unlistenError: UnlistenFn | null = null;

  /// Returns true on success, false if either listener registration
  /// failed (caller should NOT proceed to requestBrowse — without
  /// the listeners we'd never see results / errors and the user
  /// would just stare at a spinner). The previous implementation
  /// `return`ed on failure but the caller still called
  /// `requestBrowse()` afterward — which then ran `error = null`
  /// and wiped the actionable error message before the user saw it.
  async function setupListener(gen: number): Promise<boolean> {
    if (unlisten) { unlisten(); unlisten = null; }
    if (unlistenError) { unlistenError(); unlistenError = null; }
    let fn: UnlistenFn;
    try {
      fn = await listen<{ user_hash: string; files: BrowseFileEntry[] }>('ember:browse-result', (event) => {
        if (event.payload.user_hash === friendHash) {
          clearTimeout(browseTimeout);
          // Defensive: treat missing/invalid `files` as empty rather than
          // crashing the dialog if the backend ever emits a malformed payload.
          files = Array.isArray(event.payload.files) ? event.payload.files : [];
          loading = false;
        }
      });
    } catch (e) {
      console.warn('BrowseFriendDialog: failed to register browse-result listener', e);
      error = 'Could not listen for browse results. Try re-opening the dialog.';
      loading = false;
      return false;
    }
    if (gen !== listenerGen) { fn(); return false; }
    unlisten = fn;

    let errFn: UnlistenFn;
    try {
      errFn = await listen<{ user_hash: string; reason: string }>('ember:browse-error', (event) => {
        if (event.payload.user_hash === friendHash && loading) {
          clearTimeout(browseTimeout);
          error = event.payload.reason || 'Browse failed — friend went offline.';
          loading = false;
        }
      });
    } catch (e) {
      console.warn('BrowseFriendDialog: failed to register browse-error listener', e);
      // result-listener succeeded but error-listener failed: still
      // usable for the happy path, but we won't surface backend
      // browse failures. Set a soft warning rather than block.
      error = 'Browse error notifications unavailable; results may still arrive.';
      // Returning true: the result listener is live and the caller
      // can still request browse. We just won't see backend errors
      // until the next dialog open.
      return true;
    }
    if (gen !== listenerGen) { errFn(); return false; }
    unlistenError = errFn;
    return true;
  }

  async function requestBrowse() {
    loading = true;
    error = null;
    downloadError = null;
    downloadedHashes = new Set();
    files = [];
    clearTimeout(browseTimeout);
    try {
      await browseFriend(friendHash);
      browseTimeout = setTimeout(() => {
        if (loading) {
          loading = false;
          error = 'Browse request timed out. The friend may be offline.';
        }
      }, 30_000);
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Failed to browse';
      loading = false;
    }
  }

  function formatSize(bytes: number): string {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  }

  let downloadError: string | null = $state(null);
  let downloadedHashes: Set<string> = $state(new Set());

  async function downloadFile(file: BrowseFileEntry) {
    if (downloadedHashes.has(file.hash)) return;
    downloadError = null;
    try {
      await startDownload(file.hash, file.name, file.size, friendLastIp, friendLastPort);
      downloadedHashes.add(file.hash);
      downloadedHashes = new Set(downloadedHashes);
    } catch (e: unknown) {
      downloadError = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Download failed';
    }
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') onclose();
  }

  onDestroy(() => {
    clearTimeout(browseTimeout);
    if (unlisten) { unlisten(); unlisten = null; }
    if (unlistenError) { unlistenError(); unlistenError = null; }
  });
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="browse-overlay" onclick={onclose}></div>
  <!-- svelte-ignore a11y_interactive_supports_focus -->
  <div class="browse-modal" role="dialog" onkeydown={handleKeydown}>
    <div class="browse-header">
      <h3>Browsing {friendName || friendHash.slice(0, 8) + '\u2026'}</h3>
      <button class="browse-close" onclick={onclose} title="Close">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <line x1="4" y1="4" x2="12" y2="12"/><line x1="12" y1="4" x2="4" y2="12"/>
        </svg>
      </button>
    </div>

    <div class="browse-body">
      {#if loading}
        <div class="browse-status">Requesting file list...</div>
      {:else if error}
        <div class="browse-error">{error}</div>
      {:else if files.length === 0}
        <div class="browse-status">No shared files found.</div>
      {:else}
        {#if downloadError}
          <div class="browse-error" style="margin-bottom: 8px">{downloadError}</div>
        {/if}
        <div class="browse-count">{files.length} file{files.length !== 1 ? 's' : ''} shared</div>
        <div class="browse-table-wrap">
          <table class="browse-table">
            <thead>
              <tr>
                <th class="col-name">Name</th>
                <th class="col-size">Size</th>
                <th class="col-action"></th>
              </tr>
            </thead>
            <tbody>
              {#each files as file (file.hash)}
                <tr>
                  <td class="col-name" title={file.name}>{file.name}</td>
                  <td class="col-size">{formatSize(file.size)}</td>
                  <td class="col-action">
                    {#if downloadedHashes.has(file.hash)}
                      <span class="dl-done" title="Queued">
                        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                          <polyline points="3 8 7 12 13 4"/>
                        </svg>
                      </span>
                    {:else}
                      <button class="dl-btn" onclick={() => downloadFile(file)} title="Download">
                        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                          <path d="M8 2v9M4 8l4 4 4-4"/><line x1="3" y1="14" x2="13" y2="14"/>
                        </svg>
                      </button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .browse-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.4);
    z-index: 999;
  }

  .browse-modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 640px;
    max-width: 90vw;
    max-height: 80vh;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    z-index: 1000;
    display: flex;
    flex-direction: column;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
  }

  .browse-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .browse-header h3 {
    margin: 0;
    font-size: 15px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .browse-close {
    width: 28px;
    height: 28px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .browse-close:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .browse-close svg {
    width: 14px;
    height: 14px;
  }

  .browse-body {
    flex: 1;
    overflow-y: auto;
    padding: 16px 20px;
  }

  .browse-status,
  .browse-error {
    text-align: center;
    padding: 32px 16px;
    font-size: 13px;
  }

  .browse-status { color: var(--text-muted); }
  .browse-error { color: var(--danger); }

  .browse-count {
    font-size: 12px;
    color: var(--text-muted);
    margin-bottom: 10px;
  }

  .browse-table-wrap {
    overflow-x: auto;
  }

  .browse-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  .browse-table th {
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
  }

  .browse-table td {
    padding: 8px 8px;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 50%, transparent);
    color: var(--text-primary);
  }

  .col-name {
    max-width: 350px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .col-size {
    width: 90px;
    white-space: nowrap;
    color: var(--text-muted);
  }

  .col-action {
    width: 40px;
    text-align: center;
  }

  .dl-btn {
    width: 28px;
    height: 28px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .dl-btn:hover {
    background: var(--accent-dim);
    color: var(--accent);
  }

  .dl-btn svg {
    width: 14px;
    height: 14px;
  }

  .dl-done {
    width: 28px;
    height: 28px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: var(--success);
  }

  .dl-done svg {
    width: 14px;
    height: 14px;
  }
</style>
