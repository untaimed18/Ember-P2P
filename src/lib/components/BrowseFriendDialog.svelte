<script lang="ts">
  import { onDestroy } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { browseFriend, type BrowseFileEntry } from '$lib/api/friends';
  import { startDownload } from '$lib/api/transfers';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';

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
  // M4: per-request gen used to disambiguate result/error events
  // from successive browses. Without it, a late error from request
  // N is dropped by the `loading` guard if request N+1 already
  // finished; with it, only events whose payload carries the gen
  // we're currently tracking land in the UI, so a real failure
  // never gets silently swallowed.
  let currentBrowseGen = 0;

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
        if (event.payload.user_hash !== friendHash) return;
        // Only accept results while a browse is in flight. If
        // `currentBrowseGen` is 0 the event belongs to a previous
        // browse the user already dismissed; ignoring it stops a
        // stale result from overwriting the dialog after the user
        // navigated past it.
        if (currentBrowseGen === 0) return;
        clearTimeout(browseTimeout);
        // Defensive: treat missing/invalid `files` as empty rather than
        // crashing the dialog if the backend ever emits a malformed payload.
        files = Array.isArray(event.payload.files) ? event.payload.files : [];
        loading = false;
        // Successful result terminates this browse generation; a
        // later error for the same friend is most likely from a
        // separate (subsequent) request and shouldn't replace the
        // result we just rendered.
        currentBrowseGen = 0;
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
      errFn = await listen<{ user_hash: string; reason: string }>('ember:browse-error', (event) => {
        if (event.payload.user_hash !== friendHash) return;
        // M4: previously this guard required `loading`, which meant
        // an error that arrived shortly after a result was silently
        // dropped — including the common case where the backend
        // emits a partial result then a transport failure for the
        // same browse. We now key on `currentBrowseGen`: as long as
        // this dialog still has an open browse generation, surface
        // the error. After a successful result clears the gen, late
        // errors for that browse are discarded as expected.
        if (currentBrowseGen === 0) return;
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
      // result-listener succeeded but error-listener failed: still
      // usable for the happy path, but we won't surface backend
      // browse failures. Set a soft warning rather than block.
      error = m.browse_error_notifications_unavailable();
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
    // Open a fresh browse generation so the listeners above will
    // accept events for THIS request even if a result and a late
    // error race each other on the wire.
    currentBrowseGen++;
    const myGen = currentBrowseGen;
    try {
      await browseFriend(friendHash);
      browseTimeout = setTimeout(() => {
        if (currentBrowseGen === myGen && loading) {
          loading = false;
          error = m.browse_request_timed_out();
          currentBrowseGen = 0;
        }
      }, 30_000);
    } catch (e: unknown) {
      error = translateError(e, m.browse_failed_to_browse());
      loading = false;
      if (currentBrowseGen === myGen) currentBrowseGen = 0;
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
      downloadError = translateError(e, m.browse_download_failed());
    }
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') onclose();
  }

  // The keydown handler lives on the modal, but the modal isn't focused
  // when it opens — so Escape did nothing until the user tabbed/clicked
  // into the dialog. Focus it on open so Escape works immediately (other
  // dialogs in this app do the same).
  let modalEl: HTMLDivElement | undefined = $state(undefined);
  $effect(() => {
    if (open && modalEl) modalEl.focus();
  });

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
  <div class="browse-modal" role="dialog" tabindex="-1" bind:this={modalEl} onkeydown={handleKeydown}>
    <div class="browse-header">
      <h3>{m.browse_title_prefix()} <bdi>{friendName || friendHash.slice(0, 8) + '\u2026'}</bdi></h3>
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
        {#if downloadError}
          <div class="browse-error" style="margin-bottom: 8px">{downloadError}</div>
        {/if}
        <div class="browse-count">
          {files.length === 1 ? m.browse_count_one() : m.browse_count_other({ count: files.length })}
        </div>
        <div class="browse-table-wrap">
          <table class="browse-table">
            <thead>
              <tr>
                <th class="col-name">{m.browse_col_name()}</th>
                <th class="col-size">{m.browse_col_size()}</th>
                <th class="col-action"></th>
              </tr>
            </thead>
            <tbody>
              {#each files as file (file.hash)}
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
                  <td class="col-name" title={file.name}><bdi>{file.name}</bdi></td>
                  <td class="col-size">{formatSize(file.size)}</td>
                  <td class="col-action">
                    {#if downloadedHashes.has(file.hash)}
                      <span class="dl-done" title={m.browse_queued()} aria-label={m.browse_queued()}>
                        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                          <polyline points="3 8 7 12 13 4"/>
                        </svg>
                      </span>
                    {:else}
                      <button class="dl-btn" onclick={() => downloadFile(file)} title={m.browse_download()} aria-label={m.browse_download()}>
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
    animation: browse-fade-in 0.15s ease;
  }

  :global([data-theme='dark']) .browse-overlay {
    background: rgba(8, 10, 13, 0.45);
    backdrop-filter: blur(6px) saturate(1.15);
    -webkit-backdrop-filter: blur(6px) saturate(1.15);
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
