<script lang="ts">
  import * as m from '$lib/paraglide/messages';
  import BuyCoffeeButton from './BuyCoffeeButton.svelte';
  import EmberLinks from './EmberLinks.svelte';
  const appVersion = import.meta.env.VITE_APP_VERSION;
  const license = import.meta.env.VITE_APP_LICENSE;
  // Description used to come from the package.json `description`
  // field (available as VITE_APP_DESCRIPTION). We now route it
  // through the message catalog so translators can rephrase the
  // tagline in their own language without rebuilding the package
  // metadata. The package field stays as the source of truth for
  // npm/Tauri metadata where the app name appears outside the UI.

  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground, trapTabKey } from '$lib/a11y';

  let { open = $bindable(false) }: { open?: boolean } = $props();

  let panelEl: HTMLDivElement | undefined = $state(undefined);
  let overlayEl: HTMLDivElement | undefined = $state(undefined);
  // Element focused before the dialog opened, restored on close.
  let returnFocusEl: HTMLElement | null = null;
  const instanceId = Math.random().toString(36).slice(2, 10);

  function close() {
    open = false;
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
    if (open) {
      const active = typeof document !== 'undefined' ? document.activeElement : null;
      if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
      requestAnimationFrame(() => {
        const closeBtn = panelEl?.querySelector<HTMLButtonElement>('button.about-close');
        (closeBtn ?? panelEl?.querySelector<HTMLButtonElement>('button'))?.focus();
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

  // Keep background content out of the AT/Tab order while the dialog is open.
  $effect(() => {
    if (!open || !overlayEl) return;
    return inertBackground(overlayEl);
  });
</script>

{#if open}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="about-overlay"
    bind:this={overlayEl}
    role="dialog"
    aria-modal="true"
    aria-labelledby="about-title-{instanceId}"
    aria-describedby="about-desc-{instanceId}"
    tabindex="-1"
    onkeydown={handleKeydown}
    onclick={handleOverlayClick}
    transition:fade={{ duration: prefersReducedMotion.current ? 0 : 150 }}
  >
    <div
      class="about-panel"
      bind:this={panelEl}
      transition:scale={{ start: 0.96, opacity: 0, duration: prefersReducedMotion.current ? 0 : 200 }}
    >
      <div class="about-hero">
        <div class="about-brand">
          <div class="about-mark" aria-hidden="true">
            <img src="/icon.png" alt="" width="52" height="52" />
          </div>
          <div class="about-wordmark">
            <h2 id="about-title-{instanceId}">EMBER</h2>
            <p class="about-tagline">{m.app_tagline()}</p>
            <p class="about-version">{m.about_dialog_version({ version: appVersion })}</p>
          </div>
        </div>
        <p id="about-desc-{instanceId}" class="about-description">{m.about_dialog_description()}</p>
      </div>

      <section class="about-section" aria-labelledby="about-links-{instanceId}">
        <h3 id="about-links-{instanceId}" class="about-section-title">{m.about_dialog_links_title()}</h3>
        <EmberLinks />
      </section>

      <div class="about-support">
        <p class="about-support-text">{m.support_body()}</p>
        <BuyCoffeeButton size="sm" />
      </div>

      <div class="about-footer">
        <p class="about-license">{m.about_dialog_license({ license })}</p>
        <button type="button" class="primary about-close" onclick={close}>{m.common_close()}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .about-overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10000;
  }

  .about-panel {
    width: min(420px, calc(100vw - 48px));
    max-height: calc(100vh - 48px);
    overflow-y: auto;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 0 0 18px;
    box-shadow:
      inset 0 1px 0 var(--surface-highlight),
      var(--shadow-lg);
  }

  /* The same warm wash as the Settings → About card, so the two read as one
     place. */
  .about-hero {
    padding: 22px 24px 16px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(
      160deg,
      color-mix(in srgb, var(--accent) 12%, transparent) 0%,
      transparent 70%
    );
  }

  .about-brand {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .about-mark {
    width: 52px;
    height: 52px;
    border-radius: var(--radius-md);
    overflow: hidden;
    flex-shrink: 0;
    box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--border) 70%, transparent);
  }

  .about-mark img {
    width: 100%;
    height: 100%;
    display: block;
  }

  .about-wordmark {
    min-width: 0;
  }

  .about-wordmark h2 {
    font-size: var(--font-size-2xl);
    font-weight: 700;
    letter-spacing: 1.5px;
    color: var(--accent);
    line-height: 1;
    margin: 0 0 4px;
  }

  .about-tagline {
    font-size: var(--font-size-2xs);
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.9px;
    margin: 0 0 8px;
    line-height: 1.2;
  }

  .about-version {
    display: inline-block;
    margin: 0;
    padding: 2px 8px;
    font-size: var(--font-size-xs);
    font-weight: 600;
    color: var(--badge-accent-text);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    border: 1px solid color-mix(in srgb, var(--accent) 22%, transparent);
    border-radius: var(--radius-pill);
    line-height: 1.4;
  }

  .about-description {
    color: var(--text-secondary);
    font-size: var(--font-size-md);
    line-height: 1.5;
    margin: 14px 0 0;
  }

  .about-section {
    padding: 16px 24px 0;
  }

  .about-section-title {
    margin: 0 0 8px;
    font-size: var(--font-size-xs);
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-secondary);
  }

  .about-support {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 14px 24px 0;
    padding: 10px 12px;
    border: 1px solid color-mix(in srgb, #ffdd00 35%, var(--border));
    border-radius: var(--radius-md);
    background: linear-gradient(
      120deg,
      color-mix(in srgb, #ffdd00 14%, transparent) 0%,
      color-mix(in srgb, #ffdd00 3%, transparent) 75%
    );
  }

  .about-support-text {
    flex: 1;
    margin: 0;
    color: var(--text-secondary);
    font-size: var(--font-size-sm);
    line-height: 1.45;
  }

  .about-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 16px 24px 0;
  }

  .about-license {
    margin: 0;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }

  @media (max-width: 480px) {
    .about-support {
      flex-direction: column;
      align-items: flex-start;
    }
  }
</style>
