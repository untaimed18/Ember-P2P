<script lang="ts">
  import { onDestroy } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import {
    browseFriend,
    cancelBrowseFriend,
    type BrowseFileEntry,
  } from '$lib/api/friends';
  import { startDownload } from '$lib/api/transfers';
  import { formatSize } from '$lib/utils';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';
  import { inertBackground, trapTabKey } from '$lib/a11y';

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
  let filterQuery = $state('');
  let loading = $state(false);
  let error: string | null = $state(null);
  let unlisten: UnlistenFn | null = null;
  let listenerGen = 0;
  let browseTimeout: ReturnType<typeof setTimeout> | undefined;
  const MAX_BROWSE_FILES = 1_000;
  const instanceId = Math.random().toString(36).slice(2, 10);
  // M4: per-request gen used to disambiguate result/error events
  // from successive browses. Without it, a late error from request
  // N is dropped by the `loading` guard if request N+1 already
  // finished; with it, only events whose payload carries the gen
  // we're currently tracking land in the UI, so a real failure
  // never gets silently swallowed.
  let currentBrowseGen = 0;
  // Generation the listeners currently accept. requestBrowse assigns this
  // to myGen so a late result from a prior open can't land after reopen.
  let expectedBrowseGen = 0;
  let expectedRequestId = '';

  let filteredFiles = $derived.by(() => {
    const q = filterQuery.trim().toLowerCase();
    if (!q) return files;
    return files.filter((file) => {
      const name = file.name.toLowerCase();
      const hash = file.hash.toLowerCase();
      return name.includes(q) || hash.includes(q);
    });
  });

  let hasUsableFriendAddress = $derived(
    Boolean(
      friendLastIp?.trim() &&
        friendLastIp.trim() !== '0.0.0.0' &&
        friendLastPort > 0,
    ),
  );

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
      const hash = friendHash;
      // Clear previous session synchronously so reopen never paints
      // the prior friend's file list (or allows downloads from it)
      // while listeners are still being registered.
      loading = true;
      error = null;
      downloadError = null;
      downloadNote = null;
      listenerWarning = null;
      files = [];
      filterQuery = '';
      downloadedHashes = new Set();
      downloadingHashes = new Set();
      (async () => {
        const ok = await setupListener(gen, hash);
        if (!ok || gen !== listenerGen || !open) return;
        await requestBrowse(hash);
      })();
    }
    return () => {
      if (expectedRequestId && friendHash) {
        void cancelBrowseFriend(friendHash, expectedRequestId).catch((e) =>
          console.error('Failed to cancel friend browse:', e),
        );
      }
      listenerGen++;
      currentBrowseGen = 0;
      expectedBrowseGen = 0;
      expectedRequestId = '';
      loading = false;
      files = [];
      filterQuery = '';
      error = null;
      downloadError = null;
      downloadNote = null;
      listenerWarning = null;
      downloadedHashes = new Set();
      downloadingHashes = new Set();
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
  async function setupListener(gen: number, hash: string): Promise<boolean> {
    if (unlisten) { unlisten(); unlisten = null; }
    if (unlistenError) { unlistenError(); unlistenError = null; }
    let fn: UnlistenFn;
    try {
      fn = await listen<{ user_hash: string; request_id: string; files: BrowseFileEntry[] }>('ember:browse-result', (event) => {
        if (event.payload.user_hash !== hash) return;
        // Only accept results for the in-flight browse generation.
        // `currentBrowseGen === 0` means dismissed; mismatch vs
        // `expectedBrowseGen` means a stale result from a prior open.
        if (
          currentBrowseGen === 0 ||
          currentBrowseGen !== expectedBrowseGen ||
          event.payload.request_id !== expectedRequestId
        ) return;
        clearTimeout(browseTimeout);
        // Defensive: treat missing/invalid `files` as empty rather than
        // crashing the dialog if the backend ever emits a malformed payload.
        // De-duplicate by hash before rendering: the sharer's index is keyed
        // by path, so two copies of one file under a shared folder arrive as
        // two entries with the same hash — and the table keys on hash, which
        // Svelte 5 turns into a thrown error on collision.
        files = Array.isArray(event.payload.files)
          ? [...new Map(event.payload.files.map((f) => [f.hash, f])).values()].slice(
              0,
              MAX_BROWSE_FILES,
            )
          : [];
        loading = false;
        // Successful result terminates this browse generation; a
        // later error for the same friend is most likely from a
        // separate (subsequent) request and shouldn't replace the
        // result we just rendered.
        currentBrowseGen = 0;
        requestAnimationFrame(() => filterInputEl?.focus());
      });
    } catch (e) {
      console.warn('BrowseFriendDialog: failed to register browse-result listener', e);
      error = m.browse_listener_failed();
      loading = false;
      return false;
    }
    if (gen !== listenerGen) { fn(); return false; }
    unlisten = fn;

    let errFn: UnlistenFn;
    try {
      errFn = await listen<{ user_hash: string; request_id: string; reason: string }>('ember:browse-error', (event) => {
        if (event.payload.user_hash !== hash) return;
        // M4: key on browse generation so a late error after a
        // successful result (gen cleared) is discarded, and a stale
        // error from a prior open can't land after reopen.
        if (
          currentBrowseGen === 0 ||
          currentBrowseGen !== expectedBrowseGen ||
          event.payload.request_id !== expectedRequestId
        ) return;
        clearTimeout(browseTimeout);
        // Run the backend reason through `translateError` so a coded error is
        // localized; a plain string falls through unchanged, and an empty
        // reason uses the friendly offline fallback.
        error = event.payload.reason
          ? translateError(event.payload.reason, m.browse_failed_offline())
          : m.browse_failed_offline();
        loading = false;
        currentBrowseGen = 0;
      });
    } catch (e) {
      console.warn('BrowseFriendDialog: failed to register browse-error listener', e);
      // Soft warning only — result listener is still live. Kept separate
      // from `error` so requestBrowse() does not wipe it immediately.
      listenerWarning = m.browse_error_notifications_unavailable();
      // Returning true: the result listener is live and the caller
      // can still request browse. We just won't see backend errors
      // until the next dialog open.
      return true;
    }
    if (gen !== listenerGen) { errFn(); return false; }
    unlistenError = errFn;
    return true;
  }

  async function requestBrowse(hash: string) {
    loading = true;
    error = null;
    downloadError = null;
    downloadNote = null;
    downloadedHashes = new Set();
    downloadingHashes = new Set();
    filterQuery = '';
    files = [];
    clearTimeout(browseTimeout);
    // Open a fresh browse generation so the listeners above will
    // accept events for THIS request even if a result and a late
    // error race each other on the wire.
    currentBrowseGen++;
    const myGen = currentBrowseGen;
    expectedBrowseGen = myGen;
    expectedRequestId = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${instanceId}-${Date.now()}-${myGen}`;
    const myRequestId = expectedRequestId;
    try {
      await browseFriend(hash, myRequestId);
      browseTimeout = setTimeout(() => {
        if (currentBrowseGen === myGen && expectedRequestId === myRequestId && loading) {
          loading = false;
          error = m.browse_request_timed_out();
          void cancelBrowseFriend(hash, myRequestId).catch((e) =>
            console.error('Failed to cancel friend browse:', e),
          );
          currentBrowseGen = 0;
        }
      }, 30_000);
    } catch (e: unknown) {
      error = translateError(e, m.browse_failed_to_browse());
      loading = false;
      if (currentBrowseGen === myGen) currentBrowseGen = 0;
    }
  }

  let downloadError: string | null = $state(null);
  let downloadNote: string | null = $state(null);
  let listenerWarning: string | null = $state(null);
  let downloadedHashes: Set<string> = $state(new Set());
  // Tracks hashes with a `startDownload` call currently in flight. The
  // `downloadedHashes` guard alone only prevents a re-click AFTER the first
  // call resolves — a fast double-click on the download button fires both
  // clicks before either `await` settles, so both would call `startDownload`
  // for the same file without this.
  let downloadingHashes: Set<string> = $state(new Set());

  async function downloadFile(file: BrowseFileEntry) {
    if (downloadedHashes.has(file.hash) || downloadingHashes.has(file.hash)) return;
    downloadError = null;
    downloadingHashes = new Set(downloadingHashes).add(file.hash);
    const peerIp = hasUsableFriendAddress ? friendLastIp.trim() : '';
    const peerPort = hasUsableFriendAddress ? friendLastPort : 0;
    try {
      await startDownload(
        file.hash,
        file.name,
        file.size,
        peerIp,
        peerPort,
        undefined,
        file.ember_file_hash,
        file.aich_hash,
        friendHash,
      );
      downloadedHashes = new Set(downloadedHashes).add(file.hash);
      if (!hasUsableFriendAddress) {
        downloadNote = m.browse_download_discovery_note();
      }
    } catch (e: unknown) {
      downloadError = translateError(e, m.browse_download_failed());
    } finally {
      const next = new Set(downloadingHashes);
      next.delete(file.hash);
      downloadingHashes = next;
    }
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      onclose();
      return;
    }
    trapTabKey(e, modalEl);
  }

  let modalEl: HTMLDivElement | undefined = $state(undefined);
  let dialogRootEl: HTMLDivElement | undefined = $state(undefined);
  let filterInputEl: HTMLInputElement | undefined = $state(undefined);
  let returnFocusEl: HTMLElement | null = null;

  $effect(() => {
    if (open) {
      const active = typeof document !== 'undefined' ? document.activeElement : null;
      if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
      requestAnimationFrame(() => {
        modalEl?.querySelector<HTMLButtonElement>('button:not([disabled])')?.focus();
      });
    }
    return () => {
      if (!open && returnFocusEl) {
        const el = returnFocusEl;
        returnFocusEl = null;
        requestAnimationFrame(() => {
          if (typeof document !== 'undefined' && document.contains(el)) el.focus();
        });
      }
    };
  });

  $effect(() => {
    if (!open || !dialogRootEl) return;
    return inertBackground(dialogRootEl);
  });

  onDestroy(() => {
    clearTimeout(browseTimeout);
    if (unlisten) { unlisten(); unlisten = null; }
    if (unlistenError) { unlistenError(); unlistenError = null; }
  });
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
{#if open}
  <div bind:this={dialogRootEl}>
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="browse-overlay" onclick={onclose}></div>
    <!-- svelte-ignore a11y_interactive_supports_focus -->
    <div
      class="browse-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="browse-title-{instanceId}"
      tabindex="-1"
      bind:this={modalEl}
      onkeydown={handleKeydown}
    >
      <div class="browse-header">
        <div class="browse-header-text">
          <h3 id="browse-title-{instanceId}">{m.browse_title_prefix()}</h3>
          <p class="browse-subtitle">
            <bdi dir="auto">{friendName || friendHash.slice(0, 8) + '\u2026'}</bdi>
          </p>
        </div>
        <button class="browse-close" onclick={onclose} title={m.common_close()} aria-label={m.common_close()}>
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <line x1="4" y1="4" x2="12" y2="12"/><line x1="12" y1="4" x2="4" y2="12"/>
          </svg>
        </button>
      </div>

      <div class="browse-body">
        {#if loading}
          <div class="browse-status">{m.browse_requesting()}</div>
        {:else if error}
          <div class="browse-error">{error}</div>
        {:else if files.length === 0}
          <div class="browse-status">{m.browse_no_files()}</div>
        {:else}
          <div class="browse-toolbar">
            <div class="browse-filter">
              <span class="browse-filter-icon" aria-hidden="true">
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
                  <circle cx="7" cy="7" r="4.5"/><line x1="10.5" y1="10.5" x2="13.5" y2="13.5"/>
                </svg>
              </span>
              <input
                bind:this={filterInputEl}
                class="browse-filter-input"
                type="search"
                bind:value={filterQuery}
                placeholder={m.browse_filter_placeholder()}
                aria-label={m.browse_filter_placeholder()}
              />
              {#if filterQuery.trim()}
                <button
                  type="button"
                  class="browse-filter-clear"
                  onclick={() => {
                    filterQuery = '';
                    filterInputEl?.focus();
                  }}
                  title={m.common_clear()}
                  aria-label={m.common_clear()}
                >×</button>
              {/if}
            </div>
            <div class="browse-count">
              {#if filterQuery.trim()}
                {m.browse_count_filtered({ filtered: filteredFiles.length, total: files.length })}
              {:else if files.length === 1}
                {m.browse_count_one()}
              {:else}
                {m.browse_count_other({ count: files.length })}
              {/if}
            </div>
          </div>

          {#if listenerWarning}
            <div class="browse-banner browse-banner-note" role="status">{listenerWarning}</div>
          {/if}
          {#if downloadError}
            <div class="browse-banner browse-banner-error" role="alert">{downloadError}</div>
          {/if}
          {#if downloadNote}
            <div class="browse-banner browse-banner-note" role="status">{downloadNote}</div>
          {/if}

          {#if filteredFiles.length === 0}
            <div class="browse-status browse-status-compact">{m.browse_no_match()}</div>
          {:else}
            <div class="browse-table-wrap">
              <table class="browse-table">
                <thead>
                  <tr>
                    <th class="col-name">{m.browse_col_name()}</th>
                    <th class="col-size">{m.browse_col_size()}</th>
                    <th class="col-action">{m.browse_col_action()}</th>
                  </tr>
                </thead>
                <tbody>
                  {#each filteredFiles as file (file.hash)}
                    <tr>
                      <!--
                        M14: file names come from the remote peer and
                        can contain RTL/LTR override characters that
                        reorder neighbouring elements ("Trojan Source"
                        style spoof). `<bdi>` isolates each name's
                        bidi influence to the cell, so a malicious
                        name can't reverse the size column or action
                        button next to it. The text itself is still
                        rendered exactly as written.
                      -->
                      <td class="col-name" title={file.name}><bdi dir="auto">{file.name}</bdi></td>
                      <td class="col-size">{formatSize(file.size)}</td>
                      <td class="col-action">
                        {#if downloadedHashes.has(file.hash)}
                          <span class="dl-done" title={m.browse_queued()} aria-label={m.browse_queued()}>
                            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                              <polyline points="3 8 7 12 13 4"/>
                            </svg>
                            <span>{m.browse_queued()}</span>
                          </span>
                        {:else}
                          <button
                            type="button"
                            class="dl-btn"
                            onclick={() => downloadFile(file)}
                            disabled={downloadingHashes.has(file.hash)}
                            title={m.browse_download()}
                            aria-label={m.browse_download()}
                          >
                            {#if downloadingHashes.has(file.hash)}
                              <span class="dl-spinner" aria-hidden="true"></span>
                              <span>{m.browse_downloading()}</span>
                            {:else}
                              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                <path d="M8 2v9M4 8l4 4 4-4"/><line x1="3" y1="14" x2="13" y2="14"/>
                              </svg>
                              <span>{m.browse_download()}</span>
                            {/if}
                          </button>
                        {/if}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  .browse-overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    z-index: 999;
    animation: browse-fade-in 0.15s ease;
  }

  :global([data-theme='dark']) .browse-overlay {
    backdrop-filter: blur(6px) saturate(1.15);
    -webkit-backdrop-filter: blur(6px) saturate(1.15);
  }

  .browse-modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 760px;
    max-width: 94vw;
    max-height: 80vh;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    z-index: 1000;
    display: flex;
    flex-direction: column;
    box-shadow:
      inset 0 1px 0 var(--surface-highlight),
      var(--shadow-lg);
    animation: browse-pop-in 0.2s ease;
  }

  /* Keyframe keeps the translate centering while scaling/fading in. */
  @keyframes browse-fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  @keyframes browse-pop-in {
    from { opacity: 0; transform: translate(-50%, -50%) scale(0.96); }
    to { opacity: 1; transform: translate(-50%, -50%) scale(1); }
  }

  .browse-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .browse-header-text {
    min-width: 0;
  }

  .browse-header h3 {
    margin: 0;
    font-size: 15px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .browse-subtitle {
    margin: 4px 0 0;
    font-size: 13px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
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
    flex-shrink: 0;
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
    min-height: 0;
    overflow: hidden;
    padding: 16px 20px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .browse-status,
  .browse-error {
    text-align: center;
    padding: 32px 16px;
    font-size: 13px;
  }

  .browse-status-compact {
    padding: 24px 16px;
  }

  .browse-status { color: var(--text-muted); }
  .browse-error { color: var(--danger); }

  .browse-toolbar {
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex-shrink: 0;
  }

  .browse-filter {
    position: relative;
    display: flex;
    align-items: center;
  }

  .browse-filter-icon {
    position: absolute;
    left: 10px;
    color: var(--text-muted);
    display: flex;
    pointer-events: none;
  }

  .browse-filter-icon svg {
    width: 14px;
    height: 14px;
  }

  .browse-filter-input {
    width: 100%;
    padding: 8px 32px 8px 32px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 13px;
    font-family: inherit;
  }

  .browse-filter-input:focus {
    border-color: var(--accent);
    outline: none;
  }

  .browse-filter-clear {
    position: absolute;
    right: 6px;
    width: 22px;
    height: 22px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    line-height: 1;
  }

  .browse-filter-clear:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .browse-count {
    font-size: 12px;
    color: var(--text-muted);
  }

  .browse-banner {
    font-size: 12px;
    padding: 8px 10px;
    border-radius: var(--radius-md);
    flex-shrink: 0;
  }

  .browse-banner-error {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 12%, transparent);
  }

  .browse-banner-note {
    color: var(--text-muted);
    background: color-mix(in srgb, var(--accent) 10%, transparent);
  }

  .browse-table-wrap {
    flex: 1;
    min-height: 0;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }

  .browse-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  .browse-table th {
    position: sticky;
    top: 0;
    z-index: 1;
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    background: var(--bg-primary);
  }

  .browse-table td {
    padding: 8px 10px;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 50%, transparent);
    color: var(--text-primary);
    vertical-align: middle;
  }

  .browse-table tbody tr:hover td {
    background: color-mix(in srgb, var(--bg-hover) 70%, transparent);
  }

  .col-name {
    max-width: 0;
    width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .col-size {
    width: 96px;
    white-space: nowrap;
    color: var(--text-muted);
  }

  .col-action {
    width: 132px;
    text-align: right;
    white-space: nowrap;
  }

  .dl-btn {
    min-height: 30px;
    padding: 0 10px;
    border: 1px solid color-mix(in srgb, var(--accent) 35%, var(--border));
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    color: var(--accent);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    font-size: 12px;
    font-weight: 600;
    font-family: inherit;
    transition: background var(--transition-fast), border-color var(--transition-fast), color var(--transition-fast);
  }

  .dl-btn:hover:not(:disabled) {
    background: color-mix(in srgb, var(--accent) 22%, transparent);
    border-color: var(--accent);
  }

  .dl-btn:disabled {
    opacity: 0.7;
    cursor: default;
  }

  .dl-btn svg {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
  }

  .dl-spinner {
    width: 12px;
    height: 12px;
    border: 2px solid color-mix(in srgb, var(--accent) 30%, transparent);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: browse-spin 0.7s linear infinite;
    flex-shrink: 0;
  }

  @keyframes browse-spin {
    to { transform: rotate(360deg); }
  }

  .dl-done {
    min-height: 30px;
    padding: 0 10px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    color: var(--success);
    font-size: 12px;
    font-weight: 600;
  }

  .dl-done svg {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
  }
</style>
