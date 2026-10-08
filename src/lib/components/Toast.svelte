<script lang="ts">
  import { toasts, removeToast, pauseToastDismiss, resumeToastDismiss } from '$lib/stores/toast';
  import * as m from '$lib/paraglide/messages';
  import { cubicIn, cubicInOut, cubicOut } from 'svelte/easing';
  import { prefersReducedMotion } from 'svelte/motion';
  import { chatDockOpen } from '$lib/stores/chatTabs';
  import IconX from './IconX.svelte';
  import { isChatWindow } from '$lib/windowRole';
  import { shortcutModAria } from '$lib/platform';

  /** The chat window is all dock, so there is no dock beside it to clear. */
  const besideDock = !isChatWindow();

  /** Slides in from the window edge, settling as it lands. */
  function toastIn(_node: Element) {
    if (prefersReducedMotion.current) {
      return { duration: 140, css: (t: number) => `opacity: ${t}` };
    }
    return {
      duration: 340,
      css: (t: number) => {
        const e = cubicOut(t);
        return `opacity: ${Math.min(1, t * 1.6)}; transform: translateX(${(1 - e) * 36}px) scale(${0.96 + 0.04 * e})`;
      },
    };
  }

  /** Slides back out, then gives up its height so the toasts after it glide
   *  into place instead of jumping once it is gone. */
  function toastOut(node: Element) {
    const style = getComputedStyle(node);
    const height = (node as HTMLElement).offsetHeight;
    const margin = parseFloat(style.marginBottom) || 0;
    const padTop = parseFloat(style.paddingTop) || 0;
    const padBottom = parseFloat(style.paddingBottom) || 0;
    if (prefersReducedMotion.current) {
      return { duration: 140, css: (t: number) => `opacity: ${t}` };
    }
    const SLIDE = 0.55;
    return {
      duration: 380,
      css: (t: number) => {
        const p = 1 - t;
        const slide = cubicIn(Math.min(1, p / SLIDE));
        const keep = 1 - cubicInOut(Math.max(0, (p - SLIDE) / (1 - SLIDE)));
        return `opacity: ${1 - slide}; transform: translateX(${slide * 32}px); height: ${height * keep}px; padding-top: ${padTop * keep}px; padding-bottom: ${padBottom * keep}px; border-block-width: ${keep}px; margin-bottom: ${margin * keep}px; overflow: hidden`;
      },
    };
  }

  let container = $state<HTMLDivElement>();
  /** The Undo Ctrl+Z takes: the newest. */
  const latestUndoId = $derived($toasts.findLast((t) => t.action?.undo)?.id);

  /** Chromium fires no `focusout` for a focused button removed with its
   *  toast, so the countdowns of the toasts left would stay held. */
  function afterRemoving(fn: () => void) {
    fn();
    queueMicrotask(() => {
      if (!container) return;
      if (!container.contains(document.activeElement) && !container.matches(':hover')) resumeToastDismiss();
    });
  }
</script>

<!-- Always mounted, empty or not: a transition plays only when its own block
     comes or goes, so a container created with the first toast and removed
     with the last showed a lone toast, the most common kind, popping in and
     vanishing with no animation at all. -->
<!-- No live region on the container: each toast is its own `role="alert"`,
     and nesting an assertive region inside a polite one makes the
     announcement behavior ambiguous across screen readers. -->
<!-- Hovering or tabbing in holds every countdown; `focusin`/`focusout` cover
     the keyboard path to the close buttons, which a pointer-only pause would
     leave racing the timer. -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<!-- The pointer handlers are a timing hint, not an affordance: there is
     nothing here to activate, so a role would advertise an interaction that
     does not exist. The container is deliberately role-less (see above), and
     the keyboard equivalent is `focusin`/`focusout` rather than a click. -->
<div
  bind:this={container}
  class="toast-container"
  class:dock-open={besideDock && $chatDockOpen}
  data-a11y-no-inert
  onmouseenter={pauseToastDismiss}
  onmouseleave={resumeToastDismiss}
  onfocusin={pauseToastDismiss}
  onfocusout={resumeToastDismiss}
>
  {#each $toasts as toast (toast.id)}
    <!--
      Severity picks the role. `role="alert"` is assertive: it interrupts
      whatever the screen reader is saying mid-sentence, which is right for
      a failed download and wrong for "Copied to clipboard" — and every
      toast used to be assertive, so a burst of successes talked over the
      page the user was actually reading. Warnings and errors keep it;
      success and info become polite `status`.
    -->
    <div
      class="toast toast-{toast.type}"
      role={toast.type === 'error' || toast.type === 'warning' ? 'alert' : 'status'}
      in:toastIn
      out:toastOut
    >
      <span class="toast-icon" aria-hidden="true">
        {#if toast.type === 'success'}
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
            <polyline points="5 12.5 10 17.5 19 7" />
          </svg>
        {:else if toast.type === 'error'}
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" width="12" height="12">
            <line x1="6" y1="6" x2="18" y2="18" />
            <line x1="18" y1="6" x2="6" y2="18" />
          </svg>
        {:else if toast.type === 'warning'}
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" width="13" height="13">
            <line x1="12" y1="5" x2="12" y2="13.5" />
            <line x1="12" y1="19" x2="12" y2="19" />
          </svg>
        {:else}
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" width="13" height="13">
            <line x1="12" y1="5" x2="12" y2="5" />
            <line x1="12" y1="10.5" x2="12" y2="19" />
          </svg>
        {/if}
      </span>
      <span class="toast-msg" id="toast-msg-{toast.id}">{toast.message}</span>
      {#if toast.action}
        {@const action = toast.action}
        <button
          type="button"
          class="toast-action"
          aria-describedby="toast-msg-{toast.id}"
          aria-keyshortcuts={toast.id === latestUndoId ? `${shortcutModAria()}+Z` : undefined}
          onclick={() => afterRemoving(() => action.run())}
        >{action.label}</button>
      {/if}
      <button type="button" class="toast-close" onclick={() => afterRemoving(() => removeToast(toast.id))} title={m.common_dismiss()} aria-label={m.common_dismiss()}>
        <IconX size={13} />
      </button>
    </div>
  {/each}
</div>

<style>
  .toast-container {
    position: fixed;
    /* The padding is room for the toasts' shadows, which the scroll box
       below would otherwise cut off; the edges are where the toasts sit. */
    top: 4px;
    right: 0;
    padding: 8px 12px 20px 24px;
    /* Above the modal overlay tier (10000). A toast raised while a dialog is
       open is usually reporting that dialog's action failing, so it must not
       render behind the scrim. */
    z-index: 10001;
    display: flex;
    flex-direction: column;
    width: min(392px, 100vw);
    /* Hard stop against a burst (or a few very long backend error strings)
       growing the stack past the bottom of the window, where the oldest
       toasts would be unreachable. The container is `pointer-events: none`
       so it never blocks the app behind it; the toasts opt back in, which is
       also what lets a wheel over one scroll this list. */
    max-height: calc(100dvh - 4px);
    overflow-y: auto;
    /* Not `visible`: alongside `overflow-y: auto` that computes to `auto` too,
       and the slide in and out on x is enough to flash a horizontal
       scrollbar on every toast. */
    overflow-x: clip;
    overscroll-behavior: contain;
    pointer-events: none;
  }
  .toast-container.dock-open {
    right: min(420px, 40vw);
  }

  /* One card for every kind, so a toast reads as a toast whatever it says:
     the kind is carried by `--tone` alone, on the edge, the icon and the
     action. A tinted fill made each kind a different card, and the faint
     info tint was easy to miss over a busy table. */
  .toast {
    --tone: var(--accent);
    --tone-text: var(--badge-accent-text);
    --on-tone: var(--on-accent);
    position: relative;
    pointer-events: auto;
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
    padding: 11px 8px 11px 16px;
    border-radius: var(--radius-md);
    font-size: var(--font-size-md);
    color: var(--text-primary);
    background: var(--ctx-surface);
    border: 1px solid var(--ctx-border);
    box-shadow: var(--ctx-shadow);
    overflow: hidden;
  }
  .toast-success {
    --tone: var(--success);
    --tone-text: var(--badge-success-text);
    --on-tone: var(--on-success);
  }
  .toast-error {
    --tone: var(--danger);
    --tone-text: var(--badge-danger-text);
    --on-tone: var(--on-danger);
  }
  .toast-warning {
    --tone: var(--warning);
    --tone-text: var(--badge-warning-text);
    --on-tone: var(--on-warning);
  }
  .toast::before {
    content: '';
    position: absolute;
    inset-block: 0;
    inset-inline-start: 0;
    width: 4px;
    background: var(--tone);
  }
  .toast-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: var(--tone);
    color: var(--on-tone);
  }
  /* Backend error strings carry hashes and full Windows paths; without
     min-width:0 a flex item won't shrink below its min-content width. */
  .toast-msg { flex: 1; min-width: 0; line-height: 1.4; overflow-wrap: anywhere; }
  .toast-action {
    flex-shrink: 0;
    padding: 4px 11px;
    border: 1px solid color-mix(in srgb, var(--tone) 45%, transparent);
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--tone) 12%, transparent);
    color: var(--tone-text);
    font-size: var(--font-size-sm);
    font-weight: 600;
    cursor: pointer;
    transition: background var(--transition-fast), border-color var(--transition-fast);
  }
  .toast-action:hover {
    background: color-mix(in srgb, var(--tone) 22%, transparent);
    border-color: color-mix(in srgb, var(--tone) 65%, transparent);
  }
  .toast-close {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    background: none;
    border: none;
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    cursor: pointer;
    padding: 0;
    flex-shrink: 0;
    transition: background var(--transition-fast), color var(--transition-fast);
  }
  .toast-close:hover {
    color: var(--text-primary);
    background: color-mix(in srgb, var(--text-primary) 10%, transparent);
  }
</style>
