<script lang="ts">
  import * as m from '$lib/paraglide/messages';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground } from '$lib/a11y';
  // Defaults route through the translated catalog so callers that
  // omit `title`/`confirmLabel`/`cancelLabel` get a localized
  // dialog. Svelte 5 evaluates destructuring defaults at instance
  // mount time, so `m.*()` runs against the current locale on
  // every show — perfectly fine, because dialogs are short-lived.
  let {
    open = $bindable(false),
    title = m.confirm_default_title(),
    message = m.confirm_default_message(),
    confirmLabel = m.confirm_default_button(),
    cancelLabel = m.common_cancel(),
    danger = false,
    // When true, render as a single-button informational alert: the Cancel
    // button is hidden and the confirm button acts as a plain "dismiss". The
    // overlay/Escape still close it. Defaults false so existing confirm dialogs
    // are unchanged.
    alert = false,
    onconfirm,
    oncancel,
  }: {
    open?: boolean;
    title?: string;
    message?: string;
    confirmLabel?: string;
    cancelLabel?: string;
    danger?: boolean;
    alert?: boolean;
    onconfirm?: () => void;
    oncancel?: () => void;
  } = $props();

  let confirmBtn: HTMLButtonElement | undefined = $state(undefined);
  let dialogEl: HTMLDivElement | undefined = $state(undefined);
  let overlayEl: HTMLDivElement | undefined = $state(undefined);
  // Element focused before the dialog opened, restored on close so keyboard
  // users land back where they were (mirrors ChatDock's return-focus pattern).
  let returnFocusEl: HTMLElement | null = null;
  const instanceId = Math.random().toString(36).slice(2, 10);

  function handleConfirm() {
    // Run the callback first so it sees the dialog still mounted and any
    // parent-owned state remains valid. Flipping `open` before the callback
    // can let the parent teardown (remove bindings, unmount the dialog)
    // race against the callback's state reads.
    onconfirm?.();
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
    if (e.target === e.currentTarget) handleCancel();
  }

  $effect(() => {
    if (open) {
      const active = typeof document !== 'undefined' ? document.activeElement : null;
      if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
      requestAnimationFrame(() => {
        confirmBtn?.focus();
      });
    }
    return () => {
      // On close (open → false), return focus to the opener. Guard on !open so
      // an unmount-while-open doesn't try to refocus a tearing-down element.
      if (!open && returnFocusEl) {
        const el = returnFocusEl;
        returnFocusEl = null;
        requestAnimationFrame(() => {
          if (typeof document !== 'undefined' && document.contains(el)) el.focus();
        });
      }
    };
  });

  // D32: make background content inert while the dialog is open so
  // screen readers and keyboard users can't reach behind the modal.
  // The dialog is usually mounted *inside* the page tree (within
  // `.app-shell`), so `inertBackground` walks up from the overlay and
  // inerts every sibling subtree along the way. Restores on close.
  $effect(() => {
    if (!open || !overlayEl) return;
    return inertBackground(overlayEl);
  });
</script>

{#if open}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="confirm-overlay"
    bind:this={overlayEl}
    role="dialog"
    aria-modal="true"
    aria-labelledby="confirm-title-{instanceId}"
    aria-describedby="confirm-message-{instanceId}"
    tabindex="-1"
    onkeydown={handleKeydown}
    onclick={handleOverlayClick}
    transition:fade={{ duration: prefersReducedMotion.current ? 0 : 150 }}
  >
    <div
      class="confirm-dialog"
      bind:this={dialogEl}
      transition:scale={{ start: 0.96, opacity: 0, duration: prefersReducedMotion.current ? 0 : 200 }}
    >
      <h3 id="confirm-title-{instanceId}">{title}</h3>
      <p id="confirm-message-{instanceId}">{message}</p>
      <div class="dialog-actions">
        {#if !alert}
          <button class="ghost" onclick={handleCancel}>{cancelLabel}</button>
        {/if}
        <button bind:this={confirmBtn} class={danger ? 'danger' : ''} onclick={handleConfirm}>{confirmLabel}</button>
      </div>
    </div>
  </div>
{/if}
