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
  }

  function handleOverlayClick(e: MouseEvent) {
    if (e.target === e.currentTarget) handleCancel();
  }
</script>

{#if open}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="confirm-overlay"
    role="dialog"
    aria-modal="true"
    aria-labelledby="confirm-title"
    onkeydown={handleKeydown}
    onclick={handleOverlayClick}
  >
    <div class="confirm-dialog">
      <h3 id="confirm-title">{title}</h3>
      <p>{message}</p>
      <div class="dialog-actions">
        <button class="ghost" onclick={handleCancel}>{cancelLabel}</button>
        <button class={danger ? 'danger' : ''} onclick={handleConfirm}>{confirmLabel}</button>
      </div>
    </div>
  </div>
{/if}
