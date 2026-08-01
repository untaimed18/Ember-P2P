<script lang="ts">
  import { toasts, removeToast } from '$lib/stores/toast';
  import * as m from '$lib/paraglide/messages';
  import { fly } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';

  const flyParams = () => ({ x: prefersReducedMotion.current ? 0 : 24, duration: prefersReducedMotion.current ? 0 : 200 });
</script>

{#if $toasts.length > 0}
  <!-- No live region on the container: each toast is its own `role="alert"`,
       and nesting an assertive region inside a polite one makes the
       announcement behavior ambiguous across screen readers. -->
  <div class="toast-container" data-a11y-no-inert>
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
    /* Above the modal overlay tier (10000). A toast raised while a dialog is
       open is usually reporting that dialog's action failing, so it must not
       render behind the scrim. */
    z-index: 10001;
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
    color: var(--on-accent);
    box-shadow: var(--shadow-md);
  }
  .toast-success { background: var(--success); color: var(--on-success); }
  .toast-error { background: var(--danger); color: var(--on-danger); }
  .toast-warning { background: var(--warning); color: var(--on-warning); }
  .toast-info { background: var(--accent); color: var(--on-accent); }
  .toast-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  /* Backend error strings carry hashes and full Windows paths; without
     min-width:0 a flex item won't shrink below its min-content width. */
  .toast-msg { flex: 1; min-width: 0; line-height: 1.35; overflow-wrap: anywhere; }
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
    background: color-mix(in srgb, currentColor 18%, transparent);
  }
</style>
