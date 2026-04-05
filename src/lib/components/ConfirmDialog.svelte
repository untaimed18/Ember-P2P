<script lang="ts">
  let {
    open = $bindable(false),
    title = 'Confirm',
    message = 'Are you sure?',
    confirmLabel = 'Confirm',
    cancelLabel = 'Cancel',
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
    open = false;
    onconfirm?.();
  }

  function handleCancel() {
    open = false;
    oncancel?.();
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
