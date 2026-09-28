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
  import { inertBackground, trapTabKey } from '$lib/a11y';

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
  let overlayEl: HTMLDivElement | undefined = $state(undefined);
  let trayBtn: HTMLButtonElement | undefined = $state(undefined);
  let remember = $state(false);
  // Element focused before the dialog opened, restored on close.
  let returnFocusEl: HTMLElement | null = null;
  const instanceId = Math.random().toString(36).slice(2, 10);
  // Guards Hide/Exit/Cancel against a second click landing during the
  // ~150-200ms outro transition, while the buttons are still mounted and
  // clickable (see `actionTaken` reset below). Without this, a fast
  // double-click could fire both `onhide` and `onexit` for the same close
  // request.
  let actionTaken = $state(false);

  function handleHide() {
    if (actionTaken) return;
    actionTaken = true;
    onhide?.(remember);
    open = false;
  }

  function handleExit() {
    if (actionTaken) return;
    actionTaken = true;
    onexit?.(remember);
    open = false;
  }

  function handleCancel() {
    if (actionTaken) return;
    actionTaken = true;
    oncancel?.();
    open = false;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      handleCancel();
      return;
    }
    trapTabKey(e, dialogEl);
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
      actionTaken = false;
      const active = typeof document !== 'undefined' ? document.activeElement : null;
      if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
      requestAnimationFrame(() => {
        trayBtn?.focus();
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

  // Make the rest of the page inert while the dialog is up, matching the
  // behaviour of `ConfirmDialog`. SvelteKit mounts the whole app under a
  // single `display: contents` wrapper `<div>` (see `src/app.html`), so
  // `document.body.children` is just that one element — the previous
  // implementation's `child.querySelector('.close-overlay')` skip-check
  // always matched *that* wrapper (since the overlay renders inside it)
  // and inerted nothing, leaving the sidebar/page reachable by Tab/click
  // behind this dialog. `inertBackground` walks up from the overlay through
  // its real ancestor chain and inerts siblings at each level instead.
  $effect(() => {
    if (!open || !overlayEl) return;
    return inertBackground(overlayEl);
  });
</script>

{#if open}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="close-overlay"
    bind:this={overlayEl}
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
        <button class="ghost" onclick={handleCancel} disabled={actionTaken}>{m.common_cancel()}</button>
        <button class="secondary exit-btn" onclick={handleExit} disabled={actionTaken}>{m.close_dialog_exit()}</button>
        <button bind:this={trayBtn} class="primary" onclick={handleHide} disabled={actionTaken}>
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
    /* Above the splash (100000): a close request during a slow or wedged
       startup must still be answerable, otherwise the app can't be quit. */
    z-index: 100001;
    display: grid;
    place-items: center;
    background: var(--overlay-bg);
    padding: 20px;
  }
  .close-dialog {
    width: min(440px, 100%);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow:
      inset 0 1px 0 var(--surface-highlight),
      var(--shadow-lg);
    padding: 22px 24px 18px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .close-dialog h3 {
    margin: 0;
    font-size: var(--font-size-lg);
    font-weight: 600;
    color: var(--text-primary);
  }

  .close-dialog p {
    margin: 0;
    color: var(--text-secondary);
    font-size: var(--font-size-md);
    line-height: 1.5;
  }

  .remember-row {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
  }

  .dialog-actions {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
    flex-wrap: wrap;
    margin-top: 4px;
  }

  /* Leaving is the one choice here that loses something, so it warns on
     hover without shouting at rest. */
  .dialog-actions .exit-btn:hover:not(:disabled) {
    border-color: color-mix(in srgb, var(--danger) 50%, var(--border));
    color: var(--danger);
  }
</style>
