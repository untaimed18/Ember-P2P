<script lang="ts">
  import type { Snippet } from 'svelte';
  import * as m from '$lib/paraglide/messages';

  /**
   * Shows a translated fallback with Retry in place of children that threw
   * while rendering or in an effect, instead of leaving the region blank.
   * Event handlers and async callbacks are not covered by `<svelte:boundary>`;
   * those still reach the window's unhandled-rejection handler.
   */
  let {
    children,
    title,
    body,
    variant = 'page',
    onclose,
    active = true,
  }: {
    children: Snippet;
    title: string;
    body?: string;
    /** `page` fills the route area, `panel` floats where the chat dock sits,
     *  `window` fills the popped-out chat window. */
    variant?: 'page' | 'panel' | 'window';
    /** Adds a Close button that runs this and hides the fallback. */
    onclose?: () => void;
    /**
     * After Close, the boundary stays failed and hidden until this is true,
     * then resets. Resetting straight away would remount children that throw
     * even while idle — the dock's effects run when it is closed — and bring
     * the fallback straight back.
     */
    active?: boolean;
  } = $props();

  let dismissed = $state(false);
  let resetFailed: (() => void) | null = null;

  $effect(() => {
    if (active && dismissed) {
      dismissed = false;
      const reset = resetFailed;
      resetFailed = null;
      reset?.();
    }
  });

  function describe(error: unknown): string {
    return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  }
</script>

<svelte:boundary
  onerror={(error, reset) => {
    console.error('Render failed:', error);
    resetFailed = reset;
  }}
>
  {@render children()}

  {#snippet failed(error, reset)}
    {#if !dismissed}
      <div
        class="empty-state render-error"
        class:page={variant === 'page'}
        class:panel={variant === 'panel'}
        class:window={variant === 'window'}
        role="alert"
      >
        <p class="empty-title">{title}</p>
        {#if body}<p class="empty-sub">{body}</p>{/if}
        <details class="render-error-details">
          <summary>{m.layout_render_error_details()}</summary>
          <pre>{describe(error)}</pre>
        </details>
        <div class="empty-actions">
          <button class="empty-action" onclick={reset}>{m.common_retry()}</button>
          {#if onclose}
            <button
              class="empty-action ghost"
              onclick={() => {
                onclose();
                dismissed = true;
              }}
            >
              {m.common_close()}
            </button>
          {/if}
        </div>
      </div>
    {/if}
  {/snippet}
</svelte:boundary>

<style>
  .render-error.page {
    flex: 1;
  }

  .render-error.panel {
    position: fixed;
    right: 16px;
    bottom: calc(var(--statusbar-height) + 16px);
    z-index: 1000;
    width: min(340px, calc(100vw - 32px));
    padding: 20px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-secondary);
    box-shadow: var(--shadow-md);
  }

  .render-error.window {
    position: fixed;
    inset: 0;
    background: var(--bg-primary);
  }

  .render-error-details {
    max-width: min(560px, 100%);
    font-size: var(--font-size-sm);
    text-align: start;
  }

  .render-error-details summary {
    cursor: pointer;
    text-align: center;
  }

  .render-error-details pre {
    max-height: 160px;
    margin: 8px 0 0;
    overflow: auto;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    user-select: text;
  }
</style>
