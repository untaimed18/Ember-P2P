<script lang="ts">
  /*
   * Share the official Ember website. Copy stays in-app; social targets
   * open an allowlisted intent URL in the default browser (the site
   * itself is hardcoded in the backend, same as About → Website).
   */
  import * as m from '$lib/paraglide/messages';
  import {
    getEmberWebsiteUrl,
    openEmberShare,
    type EmberShareTarget,
  } from '$lib/api/settings';
  import { translateError } from '$lib/i18n';
  import { copyToClipboard } from '$lib/utils';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground, trapTabKey } from '$lib/a11y';

  let { open = $bindable(false) }: { open?: boolean } = $props();

  let panelEl: HTMLDivElement | undefined = $state(undefined);
  let overlayEl: HTMLDivElement | undefined = $state(undefined);
  let returnFocusEl: HTMLElement | null = null;
  const instanceId = Math.random().toString(36).slice(2, 10);

  let websiteUrl = $state('');
  let loadError = $state('');
  let actionError = $state('');
  let copied = $state(false);
  let sharing = $state<EmberShareTarget | null>(null);
  let copyTimer: ReturnType<typeof setTimeout> | null = null;
  // Bumped on close so an in-flight copy/share/load cannot write into the
  // next dialog session (or clear `sharing` for a newer click).
  let actionSeq = 0;

  type ShareTarget = {
    id: EmberShareTarget;
    label: () => string;
  };

  const targets: ShareTarget[] = [
    { id: 'x', label: () => m.share_ember_x() },
    { id: 'facebook', label: () => m.share_ember_facebook() },
    { id: 'reddit', label: () => m.share_ember_reddit() },
    { id: 'bluesky', label: () => m.share_ember_bluesky() },
    { id: 'linkedin', label: () => m.share_ember_linkedin() },
    { id: 'telegram', label: () => m.share_ember_telegram() },
    { id: 'whatsapp', label: () => m.share_ember_whatsapp() },
    { id: 'email', label: () => m.share_ember_email() },
  ];

  function close() {
    open = false;
    actionSeq += 1;
    actionError = '';
    loadError = '';
    copied = false;
    sharing = null;
    if (copyTimer) {
      clearTimeout(copyTimer);
      copyTimer = null;
    }
  }

  async function loadUrl() {
    const seq = actionSeq;
    loadError = '';
    try {
      const url = await getEmberWebsiteUrl();
      if (seq !== actionSeq) return;
      websiteUrl = url;
    } catch (e) {
      if (seq !== actionSeq) return;
      websiteUrl = '';
      loadError = translateError(e);
    }
  }

  async function copyLink() {
    actionError = '';
    if (!websiteUrl) {
      await loadUrl();
    }
    if (!websiteUrl || !open) return;
    const seq = actionSeq;
    if (await copyToClipboard(websiteUrl)) {
      if (seq !== actionSeq || !open) return;
      copied = true;
      if (copyTimer) clearTimeout(copyTimer);
      copyTimer = setTimeout(() => {
        if (seq !== actionSeq) return;
        copied = false;
        copyTimer = null;
      }, 1600);
    } else if (seq === actionSeq && open) {
      actionError = m.share_ember_copy_failed();
    }
  }

  async function share(target: EmberShareTarget) {
    actionError = '';
    sharing = target;
    const seq = actionSeq;
    try {
      await openEmberShare(target, m.share_ember_text());
    } catch (e) {
      if (seq !== actionSeq || !open) return;
      actionError = translateError(e);
    } finally {
      if (seq === actionSeq) sharing = null;
    }
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      close();
      return;
    }
    trapTabKey(e, panelEl);
  }

  function handleOverlayClick(e: MouseEvent) {
    if (e.target === e.currentTarget) close();
  }

  $effect(() => {
    if (!open) return;
    const active = typeof document !== 'undefined' ? document.activeElement : null;
    if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
    let cancelled = false;
    // Focus Close immediately — same as About. Waiting on IPC left keyboard
    // focus on the inert sidebar trigger until the URL came back. loadUrl runs
    // from rAF so its `$state` writes cannot re-run this effect and yank focus.
    requestAnimationFrame(() => {
      if (cancelled) return;
      panelEl?.querySelector<HTMLButtonElement>('.share-close')?.focus();
      void loadUrl();
    });
    return () => {
      cancelled = true;
      if (copyTimer) {
        clearTimeout(copyTimer);
        copyTimer = null;
      }
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
    if (!open || !overlayEl) return;
    return inertBackground(overlayEl);
  });
</script>

{#if open}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="share-overlay"
    bind:this={overlayEl}
    role="dialog"
    aria-modal="true"
    aria-labelledby="share-title-{instanceId}"
    aria-describedby="share-desc-{instanceId}"
    tabindex="-1"
    onkeydown={handleKeydown}
    onclick={handleOverlayClick}
    transition:fade={{ duration: prefersReducedMotion.current ? 0 : 150 }}
  >
    <div
      class="share-panel"
      bind:this={panelEl}
      transition:scale={{ start: 0.96, opacity: 0, duration: prefersReducedMotion.current ? 0 : 200 }}
    >
      <div class="share-brand">
        <div class="share-mark" aria-hidden="true">
          <img src="/icon.png" alt="" width="48" height="48" />
        </div>
        <div>
          <h2 id="share-title-{instanceId}">{m.share_ember_title()}</h2>
          <p id="share-desc-{instanceId}" class="share-lede">{m.share_ember_lede()}</p>
        </div>
      </div>

      <div class="share-link-row">
        <code class="share-url" title={websiteUrl || undefined}>{websiteUrl || '—'}</code>
        <button
          type="button"
          class="share-copy"
          class:copied
          onclick={() => void copyLink()}
          disabled={!websiteUrl}
          aria-live="polite"
        >
          <span class="share-copy-icon" aria-hidden="true">
            {#if copied}
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 10.5l3.2 3.2L15 6.5"/></svg>
            {:else}
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="7" width="9" height="10" rx="1.5"/><path d="M13 7V5.5A1.5 1.5 0 0011.5 4h-7A1.5 1.5 0 003 5.5v10A1.5 1.5 0 004.5 17H7"/></svg>
            {/if}
          </span>
          {copied ? m.share_ember_copied() : m.share_ember_copy()}
        </button>
      </div>

      <p class="share-on">{m.share_ember_on()}</p>
      <div class="share-grid">
        {#each targets as t (t.id)}
          <button
            type="button"
            class="share-target"
            class:busy={sharing === t.id}
            onclick={() => void share(t.id)}
            disabled={sharing !== null}
            title={t.label()}
          >
            <span class="share-icon" aria-hidden="true">
              {#if t.id === 'x'}
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
              {:else if t.id === 'facebook'}
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M22 12.06C22 6.5 17.52 2 12 2S2 6.5 2 12.06c0 5.02 3.66 9.18 8.44 9.94v-7.03H8.08v-2.91h2.36V9.84c0-2.34 1.4-3.63 3.52-3.63.7 0 1.64.12 2.06.18v2.27h-1.16c-1.14 0-1.5.71-1.5 1.44v1.74h2.56l-.41 2.91h-2.15V22c4.78-.76 8.44-4.92 8.44-9.94z"/></svg>
              {:else if t.id === 'reddit'}
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="12" cy="14.2" r="6"/>
                  <circle cx="9.6" cy="13.6" r="1" fill="currentColor" stroke="none"/>
                  <circle cx="14.4" cy="13.6" r="1" fill="currentColor" stroke="none"/>
                  <path d="M9.7 16.2c.7 1 1.6 1.5 2.3 1.5s1.6-.5 2.3-1.5"/>
                  <path d="M12 8.2V5.4h3.2"/>
                  <circle cx="16.4" cy="5.2" r="1.15" fill="currentColor" stroke="none"/>
                  <circle cx="6.6" cy="10.2" r="1.15"/>
                  <circle cx="17.4" cy="10.2" r="1.15"/>
                </svg>
              {:else if t.id === 'bluesky'}
                <svg viewBox="0 0 320 286" fill="currentColor"><path d="M69.364 19.146c36.687 27.806 76.147 84.186 90.636 114.439 14.489-30.253 53.948-86.633 90.636-114.439C277.107-.887 320-16.44 320 32.976c0 9.865-5.603 82.875-8.889 94.729-11.423 41.208-53.045 51.719-90.071 45.357 64.738 11.312 81.194 47.703 45.687 84.315-80.348 69.188-106.912-25.697-115.128-58.54-.24-.973-.435-1.904-.608-2.778-.173.874-.368 1.805-.608 2.778-8.216 32.843-34.78 127.728-115.128 58.54-35.507-36.612-19.051-73.003 45.687-84.315-37.026 6.362-78.648-4.149-90.071-45.357C5.603 115.851 0 42.84 0 32.976 0-16.44 42.893-.887 69.364 19.146Z"/></svg>
              {:else if t.id === 'linkedin'}
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M20.45 20.45h-3.56v-5.57c0-1.33-.03-3.04-1.85-3.04-1.85 0-2.14 1.45-2.14 2.94v5.67H9.35V9h3.41v1.56h.05c.48-.9 1.64-1.85 3.37-1.85 3.6 0 4.27 2.37 4.27 5.46v6.28zM5.34 7.43a2.06 2.06 0 1 1 0-4.13 2.06 2.06 0 0 1 0 4.13zM7.12 20.45H3.56V9h3.56v11.45zM22.23 0H1.77C.79 0 0 .77 0 1.73v20.54C0 23.23.79 24 1.77 24h20.45C23.2 24 24 23.23 24 22.27V1.73C24 .77 23.2 0 22.23 0z"/></svg>
              {:else if t.id === 'telegram'}
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.94 0A12 12 0 1 0 24 12 12 12 0 0 0 11.94 0zm5.03 7.22c.1 0 .32.02.46.14.14.1.18.25.17.33.02.09.04.3.02.47-.18 1.9-.96 6.5-1.36 8.63-.17.9-.5 1.2-.82 1.23-.7.06-1.23-.46-1.9-.9-1.06-.69-1.65-1.12-2.68-1.8-1.18-.78-.42-1.21.26-1.91.18-.18 3.25-2.98 3.31-3.23.01-.03.01-.15-.06-.21s-.17-.04-.25-.02c-.1.02-1.79 1.14-5.06 3.34-.48.33-.91.49-1.3.48-.43-.01-1.25-.24-1.87-.44-.75-.24-1.35-.37-1.3-.79.03-.22.33-.44.9-.66 3.5-1.53 5.83-2.53 7-3.02 3.33-1.38 4.02-1.62 4.48-1.63z"/></svg>
              {:else if t.id === 'whatsapp'}
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M17.47 14.38c-.3-.15-1.76-.87-2.03-.97-.27-.1-.47-.15-.67.15-.2.3-.77.97-.94 1.17-.17.2-.35.22-.64.07-.3-.15-1.26-.46-2.4-1.48-.89-.79-1.48-1.76-1.65-2.06-.17-.3-.02-.46.13-.61.13-.13.3-.35.45-.52.14-.17.2-.3.3-.5.1-.2.05-.37-.02-.52-.08-.15-.67-1.61-.92-2.21-.24-.58-.49-.5-.67-.51h-.57c-.2 0-.52.07-.79.37-.27.3-1.04 1.02-1.04 2.48s1.06 2.88 1.21 3.07c.15.2 2.1 3.2 5.08 4.49.71.31 1.26.49 1.69.63.71.22 1.36.19 1.87.12.57-.08 1.76-.72 2.01-1.41.25-.7.25-1.29.17-1.41-.07-.13-.27-.2-.57-.35zM12.05 21.78h-.01a9.87 9.87 0 0 1-5.03-1.38l-.36-.21-3.74.98 1-3.65-.24-.37a9.86 9.86 0 0 1-1.51-5.26C2.16 5.34 6.6.9 12.05.9a9.82 9.82 0 0 1 6.99 2.9 9.83 9.83 0 0 1 2.89 6.99c0 5.45-4.44 9.88-9.88 9.88zm8.41-18.3A11.82 11.82 0 0 0 12.05 0C5.5 0 .16 5.34.16 11.89c0 2.1.55 4.14 1.59 5.95L0 24l6.3-1.65a11.88 11.88 0 0 0 5.69 1.45h.01c6.55 0 11.89-5.34 11.89-11.89a11.82 11.82 0 0 0-3.48-8.41z"/></svg>
              {:else}
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></svg>
              {/if}
            </span>
            <span>{t.label()}</span>
          </button>
        {/each}
      </div>

      {#if loadError}
        <p class="share-error" role="alert">{loadError}</p>
      {/if}
      {#if actionError}
        <p class="share-error" role="alert">{actionError}</p>
      {/if}

      <div class="share-actions">
        <button type="button" class="share-close" onclick={close}>{m.common_close()}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .share-overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10000;
  }

  .share-panel {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 22px 24px 20px;
    width: min(420px, calc(100vw - 32px));
    max-height: calc(100vh - 32px);
    overflow-y: auto;
    box-shadow:
      inset 0 1px 0 var(--surface-highlight),
      var(--shadow-lg);
  }

  .share-brand {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    margin-bottom: 16px;
  }

  .share-mark {
    width: 48px;
    height: 48px;
    border-radius: var(--radius-md);
    overflow: hidden;
    flex-shrink: 0;
  }

  .share-mark img {
    width: 100%;
    height: 100%;
    display: block;
  }

  .share-brand h2 {
    font-size: 16px;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0 0 4px;
    line-height: 1.2;
  }

  .share-lede {
    margin: 0;
    font-size: 13px;
    line-height: 1.45;
    color: var(--text-secondary);
  }

  .share-link-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 16px;
    min-width: 0;
  }

  .share-url {
    flex: 1;
    min-width: 0;
    font-family: var(--font-mono, ui-monospace, monospace);
    font-size: 12px;
    color: var(--text-secondary);
    background: var(--bg-tertiary, var(--bg-primary));
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 8px 10px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    user-select: all;
  }

  .share-copy {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 12px;
    font-size: 13px;
    font-weight: 600;
    font-family: inherit;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    background: transparent;
    color: var(--text-primary);
    cursor: pointer;
    white-space: nowrap;
    transition: background-color var(--transition-normal), border-color var(--transition-normal), color var(--transition-normal), filter var(--transition-normal);
  }

  .share-copy:hover:not(:disabled) {
    background: var(--bg-hover);
  }

  .share-copy.copied {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--on-accent);
  }

  .share-copy:disabled {
    opacity: 0.55;
    cursor: default;
  }

  .share-copy-icon {
    width: 16px;
    height: 16px;
    display: flex;
  }

  .share-copy-icon svg {
    width: 16px;
    height: 16px;
  }

  .share-copy:focus-visible,
  .share-target:focus-visible,
  .share-close:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .share-on {
    margin: 0 0 8px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--text-muted);
  }

  .share-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }

  .share-target {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--text-primary);
    font-size: 13px;
    font-family: inherit;
    text-align: left;
    cursor: pointer;
    transition: background-color var(--transition-normal), border-color var(--transition-normal), color var(--transition-normal);
  }

  .share-target:hover:not(:disabled) {
    background: var(--bg-hover);
    border-color: var(--accent);
    color: var(--text-primary);
  }

  .share-target:disabled {
    opacity: 0.55;
    cursor: default;
  }

  .share-target.busy {
    opacity: 0.8;
  }

  .share-icon {
    width: 20px;
    height: 20px;
    flex-shrink: 0;
    color: var(--text-secondary);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .share-icon svg {
    width: 18px;
    height: 18px;
  }

  .share-target:hover:not(:disabled) .share-icon {
    color: var(--accent);
  }

  .share-error {
    color: var(--danger);
    font-size: 12px;
    margin: 12px 0 0;
  }

  .share-actions {
    display: flex;
    justify-content: flex-end;
    margin-top: 16px;
  }

  .share-close {
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
    font-family: inherit;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    background: var(--accent);
    color: var(--on-accent);
    cursor: pointer;
    transition: opacity var(--transition-normal), filter var(--transition-normal);
  }

  .share-close:hover {
    filter: brightness(1.06);
  }
</style>
