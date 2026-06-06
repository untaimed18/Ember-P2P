<script lang="ts">
  import * as m from '$lib/paraglide/messages';
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

  let { open = $bindable(false) }: { open?: boolean } = $props();

  let panelEl: HTMLDivElement | undefined = $state(undefined);
  const instanceId = Math.random().toString(36).slice(2, 10);

  function close() {
    open = false;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') close();
    if (e.key === 'Tab' && panelEl) {
      const focusable = panelEl.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  function handleOverlayClick(e: MouseEvent) {
    if (e.target === e.currentTarget) close();
  }

  $effect(() => {
    if (open) {
      requestAnimationFrame(() => {
        panelEl?.querySelector<HTMLButtonElement>('button')?.focus();
      });
    }
  });
</script>

{#if open}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="about-overlay"
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
      <div class="about-brand">
        <div class="about-mark" aria-hidden="true">
          <img src="/icon.png" alt="" width="48" height="48" />
        </div>
        <div class="about-wordmark">
          <h2 id="about-title-{instanceId}">EMBER</h2>
          <p class="about-tagline">{m.app_tagline()}</p>
        </div>
      </div>

      <p id="about-desc-{instanceId}" class="about-version">{m.about_dialog_version({ version: appVersion })}</p>
      <p class="about-description">{m.about_dialog_description()}</p>
      <p class="about-license">{m.about_dialog_license({ license })}</p>

      <div class="about-actions">
        <button type="button" class="about-close" onclick={close}>{m.common_close()}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .about-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.45);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10000;
  }

  .about-panel {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 22px 24px 20px;
    min-width: 300px;
    max-width: 380px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.24);
  }

  .about-brand {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 14px;
  }

  .about-mark {
    width: 48px;
    height: 48px;
    border-radius: 10px;
    overflow: hidden;
    flex-shrink: 0;
  }

  .about-mark img {
    width: 100%;
    height: 100%;
    display: block;
  }

  .about-wordmark h2 {
    font-size: 20px;
    font-weight: 800;
    letter-spacing: 3px;
    color: var(--accent);
    line-height: 1;
    margin: 0 0 4px;
  }

  .about-tagline {
    font-size: 10px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin: 0;
    line-height: 1;
  }

  .about-version {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0 0 10px;
  }

  .about-description {
    color: var(--text-secondary);
    font-size: 13px;
    line-height: 1.5;
    margin: 0 0 12px;
  }

  .about-license {
    color: var(--text-muted);
    font-size: 12px;
    margin: 0 0 18px;
  }

  .about-actions {
    display: flex;
    justify-content: flex-end;
  }

  .about-close {
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    background: var(--accent);
    color: #fff;
    cursor: pointer;
    transition: opacity var(--transition-normal), filter var(--transition-normal);
  }

  .about-close:hover {
    filter: brightness(1.06);
  }

  .about-close:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
</style>
