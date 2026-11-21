<script lang="ts">
  // The user's own room library for one private room: whether it is open to
  // the room, the folders it holds, and what is in them.
  import * as m from '$lib/paraglide/messages';
  import {
    addRoomLibraryFolder,
    getRoomLibrary,
    removeRoomLibraryFolder,
    setRoomLibraryOpen,
    type RoomLibraryInfo,
  } from '$lib/api/roomLibrary';
  import { isServer } from '$lib/runtime';
  import { translateError } from '$lib/i18n';
  import { formatNumber, formatSize } from '$lib/utils';
  import ToggleSwitch from './ToggleSwitch.svelte';
  import IconX from './IconX.svelte';
  import { onDestroy, untrack } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground, trapTabKey } from '$lib/a11y';

  let {
    open = $bindable(false),
    channelId,
    onchange,
  }: {
    open?: boolean;
    channelId: string;
    /** The library was opened or closed. */
    onchange?: (info: RoomLibraryInfo) => void;
  } = $props();

  let info = $state<RoomLibraryInfo | null>(null);
  let libraryOpen = $state(false);
  let loadError = $state<string | null>(null);
  let error = $state<string | null>(null);
  let saving = $state(false);
  let adding = $state(false);
  let removing = $state<string[]>([]);
  let serverPath = $state('');
  let loadSeq = 0;
  let unmounted = false;

  let panelEl: HTMLDivElement | undefined = $state();
  let overlayEl: HTMLDivElement | undefined = $state();
  let returnFocusEl: HTMLElement | null = null;
  let motion = $derived(prefersReducedMotion.current ? 0 : 1);

  function take(next: RoomLibraryInfo) {
    info = next;
    libraryOpen = next.open;
  }

  async function load() {
    const seq = ++loadSeq;
    const id = channelId;
    try {
      const next = await getRoomLibrary(id);
      if (unmounted || seq !== loadSeq || id !== channelId) return;
      take(next);
      loadError = null;
    } catch (e: unknown) {
      if (unmounted || seq !== loadSeq) return;
      loadError = translateError(e, m.channels_library_load_own_failed());
    }
  }

  $effect(() => {
    if (!open) return;
    untrack(() => {
      info = null;
      loadError = null;
      error = null;
      serverPath = '';
      void load();
    });
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
    requestAnimationFrame(() => panelEl?.focus());
    return () => {
      const el = returnFocusEl;
      returnFocusEl = null;
      if (el) requestAnimationFrame(() => { if (document.contains(el)) el.focus(); });
    };
  });

  $effect(() => {
    if (!open || !overlayEl) return;
    return inertBackground(overlayEl);
  });

  onDestroy(() => {
    unmounted = true;
  });

  async function setOpen(next: boolean) {
    if (saving) return;
    saving = true;
    error = null;
    try {
      const updated = await setRoomLibraryOpen(channelId, next);
      if (unmounted) return;
      take(updated);
      onchange?.(updated);
    } catch (e: unknown) {
      if (unmounted) return;
      libraryOpen = !next;
      error = translateError(e, m.error_operation_failed());
    } finally {
      if (!unmounted) saving = false;
    }
  }

  async function addFolder() {
    if (adding) return;
    if (isServer && !serverPath.trim()) return;
    adding = true;
    error = null;
    try {
      const updated = await addRoomLibraryFolder(channelId, serverPath.trim());
      if (unmounted || !updated) return;
      take(updated);
      serverPath = '';
    } catch (e: unknown) {
      if (!unmounted) error = translateError(e, m.error_operation_failed());
    } finally {
      if (!unmounted) adding = false;
    }
  }

  async function removeFolder(path: string) {
    if (removing.includes(path)) return;
    removing = [...removing, path];
    error = null;
    try {
      const updated = await removeRoomLibraryFolder(channelId, path);
      if (!unmounted) take(updated);
    } catch (e: unknown) {
      if (!unmounted) error = translateError(e, m.error_operation_failed());
    } finally {
      if (!unmounted) removing = removing.filter((p) => p !== path);
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      open = false;
      return;
    }
    trapTabKey(e, panelEl);
  }

  function onWindowKeydown(e: KeyboardEvent) {
    if (!open || e.key !== 'Escape' || e.defaultPrevented) return;
    if (e.target instanceof Node && overlayEl?.contains(e.target)) return;
    e.preventDefault();
    open = false;
  }
</script>

<svelte:window onkeydown={onWindowKeydown} />

{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div
    class="library-overlay"
    bind:this={overlayEl}
    onclick={() => (open = false)}
    onkeydown={onKeydown}
    transition:fade={{ duration: 150 * motion }}
  >
    <div
      class="library-panel"
      role="dialog"
      aria-modal="true"
      aria-labelledby="room-library-title"
      aria-describedby="room-library-hint"
      tabindex="-1"
      bind:this={panelEl}
      onclick={(e) => e.stopPropagation()}
      transition:scale={{ start: 0.96, opacity: 0, duration: 200 * motion }}
    >
      <header class="library-header">
        <div class="library-heading">
          <span class="library-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M4 4.5h4v15H4zM10 4.5h4v15h-4z" />
              <path d="m16 5.2 3.8-1 3.4 14.4-3.8 1z" />
            </svg>
          </span>
          <div>
            <h3 id="room-library-title">{m.channels_library_title()}</h3>
            <p id="room-library-hint" class="library-hint">{m.channels_library_hint()}</p>
          </div>
        </div>
        <button type="button" class="icon-close" title={m.common_close()} aria-label={m.common_close()} onclick={() => (open = false)}>
          <IconX size={16} />
        </button>
      </header>

      <div class="library-body">
        {#if loadError}
          <div class="library-placeholder" role="alert">
            <p class="library-load-error">{loadError}</p>
            <button type="button" class="secondary" onclick={() => void load()}>{m.common_retry()}</button>
          </div>
        {:else if !info}
          <div class="library-placeholder">
            <span class="spinner"></span>
            <span>{m.common_loading()}</span>
          </div>
        {:else}
          <div class="library-switch">
            <ToggleSwitch
              bind:checked={libraryOpen}
              label={m.channels_library_open_label()}
              disabled={saving}
              onchange={(v) => void setOpen(v)}
            />
            <p class="library-state" role="status">
              {libraryOpen ? m.channels_library_open_note() : m.channels_library_closed_note()}
            </p>
          </div>

          {#if error}
            <div class="library-message error" role="alert">{error}</div>
          {/if}

          <section class="library-folders" aria-labelledby="room-library-folders">
            <h4 id="room-library-folders">{m.channels_library_folders()}</h4>
            {#if info.folders.length === 0}
              <p class="library-empty">{m.channels_library_no_folders()}</p>
            {:else}
              <ul class="folder-list">
                {#each info.folders as folder (folder)}
                  <li class="folder-row">
                    <bdi dir="auto" class="folder-path" title={folder}>{folder}</bdi>
                    <button
                      type="button"
                      class="secondary row-btn"
                      onclick={() => void removeFolder(folder)}
                      aria-disabled={removing.includes(folder)}
                      aria-label={m.channels_library_remove_aria({ path: folder })}
                    >
                      {#if removing.includes(folder)}
                        <span class="spinner xs current" aria-hidden="true"></span>
                      {/if}
                      {m.common_remove()}
                    </button>
                  </li>
                {/each}
              </ul>
            {/if}
            {#if isServer}
              <form class="server-add" onsubmit={(e) => { e.preventDefault(); void addFolder(); }}>
                <input
                  type="text"
                  bind:value={serverPath}
                  placeholder={m.channels_library_server_path()}
                  aria-label={m.channels_library_server_path()}
                  spellcheck="false"
                  autocomplete="off"
                />
                <button type="submit" class="secondary row-btn" aria-disabled={adding || !serverPath.trim()}>
                  {#if adding}
                    <span class="spinner xs current" aria-hidden="true"></span>
                  {/if}
                  {m.channels_library_add()}
                </button>
              </form>
            {:else}
              <button type="button" class="secondary add-btn" onclick={() => void addFolder()} aria-disabled={adding}>
                {#if adding}
                  <span class="spinner xs current" aria-hidden="true"></span>
                {/if}
                {m.channels_library_add_folder()}
              </button>
            {/if}
          </section>

          {#if info.folders.length > 0}
            <section class="library-stats" aria-label={m.channels_library_contents()}>
              <p>
                {m.channels_library_stats({ files: formatNumber(info.stats.files), size: formatSize(info.stats.bytes) })}
              </p>
              {#if info.stats.too_large > 0}
                <p class="note">{m.channels_library_too_large({ count: formatNumber(info.stats.too_large) })}</p>
              {/if}
              {#if info.stats.truncated}
                <p class="note">{m.channels_library_truncated()}</p>
              {/if}
              {#each info.stats.unreadable as folder (folder)}
                <p class="note warn"><bdi dir="auto">{m.channels_library_unreadable({ path: folder })}</bdi></p>
              {/each}
            </section>
          {/if}
        {/if}
      </div>

      <footer class="library-footer">
        <button type="button" class="secondary" onclick={() => (open = false)}>{m.common_close()}</button>
      </footer>
    </div>
  </div>
{/if}

<style>
  .library-overlay {
    position: fixed;
    inset: 0;
    z-index: 10000;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--overlay-bg);
  }

  .library-panel {
    display: flex;
    flex-direction: column;
    width: min(620px, calc(100vw - 40px));
    max-height: min(84vh, 720px);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow:
      inset 0 1px 0 var(--surface-highlight),
      var(--shadow-lg);
    overflow: hidden;
  }

  .library-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    padding: 18px 20px 14px;
    border-bottom: 1px solid var(--border);
  }
  .library-heading {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    min-width: 0;
  }
  .library-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 34px;
    height: 34px;
    border-radius: var(--radius-md);
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 12%, transparent);
  }
  .library-header h3 {
    margin: 0;
    font-size: var(--font-size-lg);
    font-weight: 600;
  }
  .library-hint {
    margin: 4px 0 0;
    max-width: 60ch;
    font-size: var(--font-size-sm);
    line-height: 1.45;
    color: var(--text-muted);
  }

  .library-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding: 16px 20px;
  }
  .library-placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    min-height: 160px;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }
  .library-load-error {
    margin: 0;
    color: var(--danger);
    text-align: center;
  }

  .library-switch {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .library-state {
    margin: 0;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
  }

  .library-message {
    padding: 8px 12px;
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
  }
  .library-message.error {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 9%, var(--bg-secondary));
  }

  .library-folders {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .library-folders h4 {
    margin: 0;
    font-size: var(--font-size-sm);
    font-weight: 600;
    color: var(--text-secondary);
  }
  .library-empty {
    margin: 0;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
  }
  .folder-list {
    display: flex;
    flex-direction: column;
    margin: 0;
    padding: 0;
    list-style: none;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    overflow: hidden;
  }
  .folder-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 12px;
  }
  .folder-row + .folder-row {
    border-top: 1px solid color-mix(in srgb, var(--border) 70%, transparent);
  }
  .folder-path {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: var(--font-size-sm);
  }
  .server-add {
    display: flex;
    gap: 8px;
  }
  .server-add input {
    flex: 1;
    min-width: 0;
  }
  .add-btn {
    align-self: flex-start;
  }
  .row-btn,
  .add-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
    padding: 4px 12px;
    font-size: var(--font-size-sm);
  }
  /* Busy, not disabled: a disabled button drops focus out of the dialog. */
  .row-btn[aria-disabled='true'],
  .add-btn[aria-disabled='true'] {
    cursor: wait;
    opacity: 0.65;
  }

  .library-stats {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
  }
  .library-stats p {
    margin: 0;
  }
  .library-stats .note {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
  }
  .library-stats .note.warn {
    color: var(--warning, var(--danger));
  }

  .library-footer {
    display: flex;
    justify-content: flex-end;
    padding: 12px 20px;
    border-top: 1px solid var(--border);
  }
</style>
