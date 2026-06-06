<script lang="ts">
  import { toasts, removeToast } from '$lib/stores/toast';
  import * as m from '$lib/paraglide/messages';
  import { fly } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';

  const flyParams = () => ({ x: prefersReducedMotion.current ? 0 : 24, duration: prefersReducedMotion.current ? 0 : 200 });
</script>

{#if $toasts.length > 0}
  <div class="toast-container" role="log" aria-live="polite" aria-label={m.toast_default_title()}>
    {#each $toasts as toast (toast.id)}
      <div class="toast toast-{toast.type}" role="alert" transition:fly={flyParams()}>
        <span class="toast-icon" aria-hidden="true">
          {#if toast.type === 'success'}
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" width="16" height="16">
              <polyline points="5 12.5 10 17.5 19 7" />
            </svg>
          {:else if toast.type === 'error'}
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" width="16" height="16">
              <line x1="6" y1="6" x2="18" y2="18" />
              <line x1="18" y1="6" x2="6" y2="18" />
            </svg>
          {:else if toast.type === 'warning'}
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16">
              <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12" y2="17" />
            </svg>
          {:else}
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16">
              <circle cx="12" cy="12" r="9" />
              <line x1="12" y1="11" x2="12" y2="16" />
              <line x1="12" y1="8" x2="12" y2="8" />
            </svg>
          {/if}
        </span>
        <span class="toast-msg">{toast.message}</span>
        <button class="toast-close" onclick={() => removeToast(toast.id)} aria-label={m.common_dismiss()}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13" aria-hidden="true">
            <line x1="6" y1="6" x2="18" y2="18" />
            <line x1="18" y1="6" x2="6" y2="18" />
          </svg>
        </button>
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
    gap: 10px;
    padding: 10px 12px 10px 14px;
    border-radius: var(--radius-md, 8px);
    font-size: 13px;
    color: #fff;
    box-shadow: var(--shadow-md, 0 4px 12px rgba(0, 0, 0, 0.15));
  }
  .toast-success { background: var(--success, #22c55e); }
  .toast-error { background: var(--danger, #ef4444); }
  .toast-warning { background: var(--warning, #f59e0b); color: #1a1a1a; }
  .toast-info { background: var(--accent, #3b82f6); }
  .toast-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .toast-msg { flex: 1; line-height: 1.35; }
  .toast-close {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    background: none;
    border: none;
    border-radius: 5px;
    color: inherit;
    cursor: pointer;
    padding: 0;
    opacity: 0.75;
    flex-shrink: 0;
    transition: opacity 0.12s, background 0.12s;
  }
  .toast-close:hover {
    opacity: 1;
    background: rgba(255, 255, 255, 0.18);
  }
  .toast-warning .toast-close:hover {
    background: rgba(0, 0, 0, 0.1);
  }
</style>
