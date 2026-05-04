<script lang="ts">
  import * as m from '$lib/paraglide/messages';
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
    onconfirm,
    oncancel,
  }: {
    open?: boolean;
    title?: string;
    message?: string;
    confirmLabel?: string;
    cancelLabel?: string;
    danger?: boolean;
    onconfirm?: () => void;
    oncancel?: () => void;
  } = $props();

  let confirmBtn: HTMLButtonElement | undefined = $state(undefined);
  let dialogEl: HTMLDivElement | undefined = $state(undefined);
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
      requestAnimationFrame(() => {
        confirmBtn?.focus();
      });
    }
  });

  // D32: make background content inert while the dialog is open so
  // screen readers and keyboard users can't reach behind the modal.
  // Uses the `inert` attribute on the page's top-level children other
  // than the overlay itself. Restores on close.
  $effect(() => {
    if (!open || typeof document === 'undefined') return;
    const body = document.body;
    const previous: { el: Element; had: boolean }[] = [];
    for (const child of Array.from(body.children)) {
      // Svelte mounts overlays as siblings; skip the active overlay itself
      // (identified by our role attribute being set somewhere inside it).
      if (child.querySelector('.confirm-overlay')) continue;
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
    class="confirm-overlay"
    role="dialog"
    aria-modal="true"
    aria-labelledby="confirm-title-{instanceId}"
    aria-describedby="confirm-message-{instanceId}"
    tabindex="-1"
    onkeydown={handleKeydown}
    onclick={handleOverlayClick}
  >
    <div class="confirm-dialog" bind:this={dialogEl}>
      <h3 id="confirm-title-{instanceId}">{title}</h3>
      <p id="confirm-message-{instanceId}">{message}</p>
      <div class="dialog-actions">
        <button class="ghost" onclick={handleCancel}>{cancelLabel}</button>
        <button bind:this={confirmBtn} class={danger ? 'danger' : ''} onclick={handleConfirm}>{confirmLabel}</button>
      </div>
    </div>
  </div>
{/if}
