<script lang="ts">
  import { toasts, removeToast } from '$lib/stores/toast';
</script>

{#if $toasts.length > 0}
  <div class="toast-container" role="log" aria-live="polite" aria-label="Notifications">
    {#each $toasts as toast (toast.id)}
      <div class="toast toast-{toast.type}" role="alert">
        <span class="toast-icon">
          {#if toast.type === 'success'}&#10003;{:else if toast.type === 'error'}&#10007;{:else if toast.type === 'warning'}&#9888;{:else}&#8505;{/if}
        </span>
        <span class="toast-msg">{toast.message}</span>
        <button class="toast-close" onclick={() => removeToast(toast.id)} aria-label="Dismiss">&times;</button>
      </div>
    {/each}
  </div>
{/if}

<style>
  .toast-container {
    position: fixed;
    top: 12px;
    right: 12px;
    z-index: 9999;
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-width: 400px;
    pointer-events: none;
  }
  .toast {
    pointer-events: auto;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    border-radius: var(--radius-md, 8px);
    font-size: 13px;
    color: #fff;
    box-shadow: var(--shadow-md, 0 4px 12px rgba(0,0,0,0.15));
    animation: toast-in 0.25s ease-out;
  }
  @keyframes toast-in {
    from { opacity: 0; transform: translateX(20px); }
    to { opacity: 1; transform: translateX(0); }
  }
  .toast-success { background: var(--success, #22c55e); }
  .toast-error { background: var(--danger, #ef4444); }
  .toast-warning { background: var(--warning, #f59e0b); color: #1a1a1a; }
  .toast-info { background: var(--accent, #3b82f6); }
  .toast-icon { font-size: 15px; flex-shrink: 0; }
  .toast-msg { flex: 1; line-height: 1.35; }
  .toast-close {
    background: none; border: none; color: inherit; cursor: pointer;
    font-size: 16px; padding: 0 2px; opacity: 0.7; flex-shrink: 0;
  }
  .toast-close:hover { opacity: 1; }
</style>
