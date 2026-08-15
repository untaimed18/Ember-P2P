<script lang="ts">
  import { toasts, removeToast } from '$lib/stores/toast';
  import * as m from '$lib/paraglide/messages';
  import { fly } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { chatDockOpen } from '$lib/stores/chatTabs';
  import IconX from './IconX.svelte';

  const flyParams = () => ({ x: prefersReducedMotion.current ? 0 : 24, duration: prefersReducedMotion.current ? 0 : 200 });
</script>

{#if $toasts.length > 0}
  <!-- No live region on the container: each toast is its own `role="alert"`,
       and nesting an assertive region inside a polite one makes the
       announcement behavior ambiguous across screen readers. -->
  <div class="toast-container" class:dock-open={$chatDockOpen} data-a11y-no-inert>
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
          <IconX size={13} />
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
    /* Hard stop against a burst (or a few very long backend error strings)
       growing the stack past the bottom of the window, where the oldest
       toasts would be unreachable. The container is `pointer-events: none`
       so it never blocks the app behind it; the toasts opt back in, which is
       also what lets a wheel over one scroll this list. */
    max-height: calc(100dvh - 24px);
    overflow-y: auto;
    /* Not `visible`: alongside `overflow-y: auto` that computes to `auto` too,
       and the enter/exit `fly` translates 24px on x — enough to flash a
       horizontal scrollbar on every toast. */
    overflow-x: clip;
    overscroll-behavior: contain;
    pointer-events: none;
  }
  .toast-container.dock-open {
    right: calc(min(420px, 40vw) + 12px);
  }
  .toast {
    pointer-events: auto;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px 10px 14px;
    border-radius: var(--radius-md);
    font-size: 13px;
    color: var(--text-primary);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    box-shadow: var(--shadow-md);
  }
  .toast-success {
    background: color-mix(in srgb, var(--success) 14%, var(--bg-secondary));
    border-color: color-mix(in srgb, var(--success) 32%, transparent);
  }
  .toast-error {
    background: color-mix(in srgb, var(--danger) 14%, var(--bg-secondary));
    border-color: color-mix(in srgb, var(--danger) 32%, transparent);
  }
  .toast-warning {
    background: color-mix(in srgb, var(--warning) 14%, var(--bg-secondary));
    border-color: color-mix(in srgb, var(--warning) 32%, transparent);
  }
  .toast-info {
    background: color-mix(in srgb, var(--accent) 12%, var(--bg-secondary));
    border-color: color-mix(in srgb, var(--accent) 30%, transparent);
  }
  .toast-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .toast-success .toast-icon { color: var(--badge-success-text); }
  .toast-error .toast-icon { color: var(--badge-danger-text); }
  .toast-warning .toast-icon { color: var(--badge-warning-text); }
  .toast-info .toast-icon { color: var(--badge-accent-text); }
  :global([data-theme="dark"]) .toast-success {
    background: color-mix(in srgb, var(--success) 18%, var(--bg-secondary));
    border-color: color-mix(in srgb, var(--success) 36%, transparent);
  }
  :global([data-theme="dark"]) .toast-error {
    background: color-mix(in srgb, var(--danger) 18%, var(--bg-secondary));
    border-color: color-mix(in srgb, var(--danger) 36%, transparent);
  }
  :global([data-theme="dark"]) .toast-warning {
    background: color-mix(in srgb, var(--warning) 18%, var(--bg-secondary));
    border-color: color-mix(in srgb, var(--warning) 36%, transparent);
  }
  :global([data-theme="dark"]) .toast-info {
    background: color-mix(in srgb, var(--accent) 16%, var(--bg-secondary));
    border-color: color-mix(in srgb, var(--accent) 34%, transparent);
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
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    cursor: pointer;
    padding: 0;
    opacity: 0.85;
    flex-shrink: 0;
    transition: opacity 0.12s, background 0.12s, color 0.12s;
  }
  .toast-close:hover {
    opacity: 1;
    color: var(--text-primary);
    background: color-mix(in srgb, var(--text-primary) 10%, transparent);
  }
</style>
