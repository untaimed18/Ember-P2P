<script lang="ts">
  // The peers the user banned from Transfers, each with an Unban button.
  // Loads on mount so the page can show how many there are before it opens.
  import * as m from '$lib/paraglide/messages';
  import { getBannedPeers, unbanPeer, type BannedPeer } from '$lib/api/kad';
  import { translateError } from '$lib/i18n';
  import { formatNumber } from '$lib/utils';
  import IconX from './IconX.svelte';
  import { onMount } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import { flip } from 'svelte/animate';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground, trapTabKey } from '$lib/a11y';

  let { open = $bindable(false), count = $bindable(0) }: { open?: boolean; count?: number } = $props();

  let peers = $state<BannedPeer[]>([]);
  let loaded = $state(false);
  let unbanning = $state<string[]>([]);
  let error = $state<string | null>(null);
  let status = $state<string | null>(null);
  let loadSeq = 0;
  let unmounted = false;

  let panelEl: HTMLDivElement | undefined = $state();
  let overlayEl: HTMLDivElement | undefined = $state();
  let returnFocusEl: HTMLElement | null = null;

  let motion = $derived(prefersReducedMotion.current ? 0 : 1);

  async function load(opts?: { quiet?: boolean }) {
    const seq = ++loadSeq;
    try {
      const list = await getBannedPeers();
      if (unmounted || seq !== loadSeq) return;
      peers = list;
      count = list.length;
      loaded = true;
    } catch (e: unknown) {
      if (unmounted || seq !== loadSeq) return;
      loaded = true;
      if (!opts?.quiet) error = translateError(e, m.error_operation_failed());
    }
  }

  onMount(() => {
    void load({ quiet: true });
    return () => { unmounted = true; };
  });

  $effect(() => {
    if (!open) return;
    error = null;
    status = null;
    void load();
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
    requestAnimationFrame(() => {
      (panelEl?.querySelector<HTMLButtonElement>('.icon-close') ?? panelEl)?.focus();
    });
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

  function displayName(peer: BannedPeer): string {
    return peer.name || m.common_unknown();
  }

  function initial(peer: BannedPeer): string {
    return peer.name ? [...peer.name.trim()][0]?.toUpperCase() ?? '?' : '?';
  }

  /** The address a ban was last recorded at, without the placeholder port 0
   *  an IP-only capture is stored with. */
  function lastAddress(peer: BannedPeer): string {
    const addr = peer.addresses[peer.addresses.length - 1];
    if (!addr) return '\u2014';
    return addr.endsWith(':0') ? addr.slice(0, -2) : addr;
  }

  async function unban(peer: BannedPeer) {
    if (unbanning.includes(peer.user_hash)) return;
    unbanning = [...unbanning, peer.user_hash];
    error = null;
    status = null;
    try {
      await unbanPeer(peer.user_hash);
      if (unmounted) return;
      peers = peers.filter((p) => p.user_hash !== peer.user_hash);
      count = peers.length;
      status = m.security_unbanned_user({ name: displayName(peer) });
    } catch (e: unknown) {
      if (unmounted) return;
      error = translateError(e, m.error_operation_failed());
    } finally {
      if (!unmounted) {
        unbanning = unbanning.filter((h) => h !== peer.user_hash);
        void load({ quiet: true });
      }
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
</script>

{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div
    class="banned-overlay"
    bind:this={overlayEl}
    onclick={() => (open = false)}
    onkeydown={onKeydown}
    transition:fade={{ duration: 150 * motion }}
  >
    <div
      class="banned-panel"
      role="dialog"
      aria-modal="true"
      aria-labelledby="banned-users-title"
      aria-describedby="banned-users-hint"
      tabindex="-1"
      bind:this={panelEl}
      onclick={(e) => e.stopPropagation()}
      transition:scale={{ start: 0.96, opacity: 0, duration: 200 * motion }}
    >
      <header class="banned-header">
        <div class="banned-heading">
          <span class="banned-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 2l7 4v6c0 4.4-3 8.5-7 10-4-1.5-7-5.6-7-10V6l7-4z" />
              <line x1="8.5" y1="8.5" x2="15.5" y2="15.5" />
            </svg>
          </span>
          <div>
            <h3 id="banned-users-title">
              {m.security_banned_users()}
              {#if peers.length > 0}
                <span class="banned-count">{formatNumber(peers.length)}</span>
              {/if}
            </h3>
            <p id="banned-users-hint" class="banned-hint">{m.security_banned_users_hint()}</p>
          </div>
        </div>
        <button type="button" class="icon-close" title={m.common_close()} aria-label={m.common_close()} onclick={() => (open = false)}>
          <IconX size={16} />
        </button>
      </header>

      {#if error}
        <div class="banned-message error" role="alert">{error}</div>
      {:else if status}
        <div class="banned-message ok" role="status">{status}</div>
      {/if}

      <div class="banned-body">
        {#if !loaded}
          <div class="banned-placeholder">
            <span class="spinner"></span>
            <span>{m.common_loading()}</span>
          </div>
        {:else if peers.length === 0}
          <div class="banned-placeholder">
            <span class="banned-empty-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" width="40" height="40" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 2l7 4v6c0 4.4-3 8.5-7 10-4-1.5-7-5.6-7-10V6l7-4z" />
                <polyline points="8.5 12 11 14.5 15.5 9.5" />
              </svg>
            </span>
            <p class="banned-empty-title">{m.security_banned_users_empty()}</p>
          </div>
        {:else}
          <div class="banned-cols" aria-hidden="true">
            <span class="col-user">{m.security_banned_col_user()}</span>
            <span>{m.security_banned_col_client()}</span>
            <span>{m.security_banned_col_address()}</span>
            <span></span>
          </div>
          <ul class="banned-list">
            {#each peers as peer (peer.user_hash)}
              <li
                class="banned-row"
                animate:flip={{ duration: 200 * motion }}
                out:fade={{ duration: 150 * motion }}
              >
                <span class="avatar" class:unknown={!peer.name} aria-hidden="true">{initial(peer)}</span>
                <div class="who">
                  <bdi dir="auto" class="name" class:unnamed={!peer.name}>{displayName(peer)}</bdi>
                  <span class="hash" title={peer.user_hash}>{peer.user_hash}</span>
                </div>
                <bdi dir="auto" class="client">{peer.client_software || '\u2014'}</bdi>
                <span class="addr" title={peer.addresses.map((a) => (a.endsWith(':0') ? a.slice(0, -2) : a)).join('\n')}>
                  {lastAddress(peer)}
                </span>
                <button
                  type="button"
                  class="secondary unban-btn"
                  onclick={() => void unban(peer)}
                  disabled={unbanning.includes(peer.user_hash)}
                  aria-label={m.security_unban_aria({ name: displayName(peer) })}
                >
                  {#if unbanning.includes(peer.user_hash)}
                    <span class="spinner xs current" aria-hidden="true"></span>
                  {/if}
                  {m.security_unban()}
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </div>

      <footer class="banned-footer">
        <button type="button" class="secondary" onclick={() => (open = false)}>{m.common_close()}</button>
      </footer>
    </div>
  </div>
{/if}

<style>
  .banned-overlay {
    position: fixed;
    inset: 0;
    z-index: 10000;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--overlay-bg);
  }

  .banned-panel {
    display: flex;
    flex-direction: column;
    width: min(760px, calc(100vw - 40px));
    max-height: min(78vh, 680px);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow:
      inset 0 1px 0 var(--surface-highlight),
      var(--shadow-lg);
    overflow: hidden;
  }

  .banned-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    padding: 18px 20px 14px;
    border-bottom: 1px solid var(--border);
  }
  .banned-heading {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    min-width: 0;
  }
  .banned-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 34px;
    height: 34px;
    border-radius: var(--radius-md);
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 12%, transparent);
  }
  .banned-header h3 {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
    font-size: var(--font-size-lg);
    font-weight: 600;
  }
  .banned-count {
    min-width: 20px;
    padding: 0 7px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--danger) 16%, transparent);
    color: var(--danger);
    font-size: var(--font-size-xs);
    font-weight: 600;
    line-height: 20px;
    text-align: center;
    font-variant-numeric: tabular-nums;
  }
  .banned-hint {
    margin: 4px 0 0;
    max-width: 56ch;
    font-size: var(--font-size-sm);
    line-height: 1.45;
    color: var(--text-muted);
  }

  .banned-message {
    padding: 8px 20px;
    font-size: var(--font-size-sm);
    border-bottom: 1px solid var(--border);
  }
  .banned-message.error {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 9%, var(--bg-secondary));
  }
  .banned-message.ok {
    color: var(--badge-success-text);
    background: color-mix(in srgb, var(--success) 9%, var(--bg-secondary));
  }

  .banned-body {
    flex: 1;
    min-height: 180px;
    overflow-y: auto;
    padding: 8px 12px 12px;
  }

  .banned-placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    min-height: 200px;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }
  .banned-empty-icon {
    color: var(--success);
    opacity: 0.8;
  }
  .banned-empty-title {
    margin: 0;
    font-size: var(--font-size-md);
    color: var(--text-secondary);
  }

  /* Header and rows share one grid so the columns line up. */
  .banned-cols,
  .banned-row {
    display: grid;
    grid-template-columns: 34px minmax(0, 1.7fr) minmax(0, 1fr) minmax(0, 0.9fr) auto;
    align-items: center;
    column-gap: 12px;
  }
  .banned-cols {
    position: sticky;
    top: -8px;
    z-index: 1;
    padding: 8px 10px 6px;
    background: var(--bg-secondary);
    font-size: var(--font-size-2xs);
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    color: var(--text-muted);
  }
  .banned-cols .col-user {
    grid-column: 1 / 3;
  }

  .banned-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .banned-row {
    padding: 9px 10px;
    border: 1px solid color-mix(in srgb, var(--border) 70%, transparent);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
    transition: border-color var(--transition-normal), background var(--transition-normal);
  }
  .banned-row:hover {
    border-color: var(--border-light);
    background: var(--bg-hover);
  }

  .avatar {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 34px;
    height: 34px;
    border-radius: 50%;
    background: color-mix(in srgb, var(--danger) 14%, var(--bg-secondary));
    color: var(--danger);
    font-weight: 600;
    font-size: var(--font-size-md);
  }
  .avatar.unknown {
    background: var(--bg-tertiary);
    color: var(--text-muted);
  }

  .who {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .name,
  .hash,
  .client,
  .addr {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .name {
    font-weight: 600;
    color: var(--text-primary);
  }
  .name.unnamed {
    font-weight: 500;
    font-style: italic;
    color: var(--text-secondary);
  }
  .hash {
    font-family: var(--font-mono);
    font-size: var(--font-size-2xs);
    color: var(--text-muted);
  }
  .client {
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
  }
  .addr {
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
    font-variant-numeric: tabular-nums;
    color: var(--text-secondary);
  }

  .unban-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 14px;
    font-size: var(--font-size-sm);
  }

  .banned-footer {
    display: flex;
    justify-content: flex-end;
    padding: 12px 20px;
    border-top: 1px solid var(--border);
  }

  @media (max-width: 620px) {
    .banned-cols {
      display: none;
    }
    .banned-row {
      grid-template-columns: 34px minmax(0, 1fr) auto;
      row-gap: 4px;
    }
    .client,
    .addr {
      grid-column: 2;
    }
    .unban-btn {
      grid-column: 3;
      grid-row: 1 / 4;
    }
  }
</style>
