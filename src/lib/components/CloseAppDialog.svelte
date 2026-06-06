<script lang="ts">
  // Three-button close confirmation dialog. Surfaces when the saved
  // `close_to_tray_behavior` is `"ask"` and the user clicks the title-bar X
  // (or the backend re-emits `close-requested` for any other reason).
  //
  // Mirrors the visual language of `ConfirmDialog.svelte` so the prompt
  // feels native — same dark overlay, same focus trap, same Escape-to-cancel.
  // ConfirmDialog only exposes Confirm / Cancel, so this is a sibling
  // component rather than a reuse.
  import * as m from '$lib/paraglide/messages';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';

  let {
    open = $bindable(false),
    onhide,
    onexit,
    oncancel,
  }: {
    open?: boolean;
    onhide?: (remember: boolean) => void;
    onexit?: (remember: boolean) => void;
    oncancel?: () => void;
  } = $props();

  let dialogEl: HTMLDivElement | undefined = $state(undefined);
  let trayBtn: HTMLButtonElement | undefined = $state(undefined);
  let remember = $state(false);
  const instanceId = Math.random().toString(36).slice(2, 10);

  function handleHide() {
    onhide?.(remember);
    open = false;
  }

  function handleExit() {
    onexit?.(remember);
    open = false;
  }

  function handleCancel() {
    oncancel?.();
    open = false;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') handleCancel();
    if (e.key === 'Tab' && dialogEl) {
      const focusable = dialogEl.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])',
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
    if (e.target === e.currentTarget) handleCancel();
  }

  $effect(() => {
    if (open) {
      // Reset the checkbox each time the dialog is reopened so a stale
      // tick from the previous session doesn't silently flip the saved
      // preference on the next close.
      remember = false;
      requestAnimationFrame(() => {
        trayBtn?.focus();
      });
    }
  });

  // Make the rest of the page inert while the dialog is up, matching the
  // behaviour of `ConfirmDialog`.
  $effect(() => {
    if (!open || typeof document === 'undefined') return;
    const body = document.body;
    const previous: { el: Element; had: boolean }[] = [];
    for (const child of Array.from(body.children)) {
      if (child.querySelector('.close-overlay')) continue;
      previous.push({ el: child, had: child.hasAttribute('inert') });
      child.setAttribute('inert', '');
    }
    return () => {
      for (const { el, had } of previous) {
        if (!had) el.removeAttribute('inert');
      }
    };
  });
</script>

{#if open}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="close-overlay"
    role="dialog"
    aria-modal="true"
    aria-labelledby="close-title-{instanceId}"
    aria-describedby="close-message-{instanceId}"
    tabindex="-1"
    onkeydown={handleKeydown}
    onclick={handleOverlayClick}
    transition:fade={{ duration: prefersReducedMotion.current ? 0 : 150 }}
  >
    <div
      class="close-dialog"
      bind:this={dialogEl}
      transition:scale={{ start: 0.96, opacity: 0, duration: prefersReducedMotion.current ? 0 : 200 }}
    >
      <h3 id="close-title-{instanceId}">{m.close_dialog_title()}</h3>
      <p id="close-message-{instanceId}">
        {m.close_dialog_message()}
      </p>
      <label class="remember-row">
        <input type="checkbox" bind:checked={remember} />
        <span>{m.close_dialog_remember()}</span>
      </label>
      <div class="dialog-actions">
        <button class="ghost" onclick={handleCancel}>{m.common_cancel()}</button>
        <button class="exit-btn" onclick={handleExit}>{m.close_dialog_exit()}</button>
        <button bind:this={trayBtn} class="primary" onclick={handleHide}>
          {m.close_dialog_minimize()}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .close-overlay {
    position: fixed;
    inset: 0;
    z-index: 10000;
    display: grid;
    place-items: center;
    background: rgba(0, 0, 0, 0.5);
    padding: 20px;
  }

  /* Frosted backdrop in dark mode, matching ConfirmDialog/AboutDialog. */
  :global([data-theme='dark']) .close-overlay {
    background: rgba(8, 10, 13, 0.45);
    backdrop-filter: blur(6px) saturate(1.15);
    -webkit-backdrop-filter: blur(6px) saturate(1.15);
  }

  .close-dialog {
    width: min(440px, 100%);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-lg);
    padding: 22px 24px 18px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .close-dialog h3 {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .close-dialog p {
    margin: 0;
    color: var(--text-secondary);
    font-size: 13px;
    line-height: 1.5;
  }

  .remember-row {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
  }

  .remember-row input[type='checkbox'] {
    width: 14px;
    height: 14px;
    accent-color: var(--accent);
    cursor: pointer;
  }

  .dialog-actions {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
    flex-wrap: wrap;
    margin-top: 4px;
  }

  .dialog-actions button {
    padding: 7px 14px;
    font-size: 13px;
    font-weight: 600;
    border-radius: var(--radius-md);
    cursor: pointer;
  }

  .dialog-actions .ghost {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
  }

  .dialog-actions .ghost:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .dialog-actions .exit-btn {
    background: transparent;
    color: var(--text-primary);
    border: 1px solid var(--border);
  }

  .dialog-actions .exit-btn:hover {
    background: var(--bg-hover);
    border-color: color-mix(in srgb, var(--danger) 50%, var(--border));
    color: var(--danger);
  }

  .dialog-actions .primary {
    background: var(--accent);
    color: #fff;
    border: 1px solid var(--accent);
  }

  .dialog-actions .primary:hover {
    opacity: 0.9;
  }
</style>
