<script lang="ts">
  // Paste eD2K links into a box and download them, the way eMule's
  // "Paste eD2K links" does. The clipboard-only paste used to be the only
  // route: nothing to see or edit before a batch was queued, and nothing at
  // all when the links were in a page the clipboard could not reach.
  import * as m from '$lib/paraglide/messages';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground, trapTabKey } from '$lib/a11y';
  import { parseEd2kLinks, type Ed2kLinkBatch } from '$lib/api/search';
  import { formatNumber, readFromClipboard } from '$lib/utils';
  import { plural } from '$lib/plural';

  let {
    open = $bindable(false),
    busy = false,
    maxLength,
    onsubmit,
  }: {
    open?: boolean;
    busy?: boolean;
    maxLength: number;
    onsubmit: (text: string) => void | Promise<void>;
  } = $props();

  const instanceId = Math.random().toString(36).slice(2, 10);
  const encoder = new TextEncoder();
  /** The backend caps the paste in UTF-8 bytes, which non-Latin names exceed long before characters. */
  const overLimit = (value: string) => value.length > maxLength || encoder.encode(value).length > maxLength;
  let text = $state('');
  let batch = $state<Ed2kLinkBatch | null>(null);
  let dialogEl: HTMLDivElement | undefined = $state(undefined);
  let overlayEl: HTMLDivElement | undefined = $state(undefined);
  let textareaEl: HTMLTextAreaElement | undefined = $state(undefined);
  let returnFocusEl: HTMLElement | null = null;

  // Opening fills the box from the clipboard when it holds links, so the
  // common case is one click more than the old paste, with a look first.
  $effect(() => {
    if (!open) return;
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
    text = '';
    batch = null;
    let cancelled = false;
    void readFromClipboard().then((clip) => {
      if (cancelled || !clip || !/ed2k:\/\//i.test(clip) || overLimit(clip)) return;
      if (text === '') text = clip.trim();
    });
    requestAnimationFrame(() => textareaEl?.focus());
    return () => {
      cancelled = true;
      const el = returnFocusEl;
      returnFocusEl = null;
      if (el) requestAnimationFrame(() => document.contains(el) && el.focus());
    };
  });

  $effect(() => {
    if (!open || !overlayEl) return;
    return inertBackground(overlayEl);
  });

  // Parsed as the user types, so the button says how many will be queued.
  $effect(() => {
    const value = text.trim();
    if (!open || value === '' || overLimit(value)) {
      batch = null;
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void parseEd2kLinks(value)
        .then((result) => {
          if (!cancelled) batch = result;
        })
        .catch(() => {
          if (!cancelled) batch = null;
        });
    }, 200);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  });

  const tooLong = $derived(overLimit(text.trim()));
  const count = $derived(batch?.links.length ?? 0);
  const ignored = $derived((batch?.invalid ?? 0) + (batch?.skipped ?? 0));

  function close() {
    open = false;
  }

  async function submit() {
    const value = text.trim();
    if (busy || value === '' || tooLong) return;
    // Parsed afresh: the count above trails typing and the clipboard fill.
    const parsed = await parseEd2kLinks(value).catch(() => null);
    if (!parsed || parsed.links.length === 0 || !open || text.trim() !== value) return;
    open = false;
    await onsubmit(value);
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      close();
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      e.stopPropagation();
      void submit();
      return;
    }
    trapTabKey(e, dialogEl);
  }
</script>

{#if open}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="confirm-overlay"
    bind:this={overlayEl}
    role="dialog"
    aria-modal="true"
    aria-labelledby="add-links-title-{instanceId}"
    aria-describedby="add-links-hint-{instanceId}"
    tabindex="-1"
    onkeydown={onKeydown}
    onclick={(e) => e.target === e.currentTarget && close()}
    transition:fade={{ duration: prefersReducedMotion.current ? 0 : 150 }}
  >
    <div
      class="confirm-dialog add-links-dialog"
      bind:this={dialogEl}
      transition:scale={{ start: 0.96, opacity: 0, duration: prefersReducedMotion.current ? 0 : 200 }}
    >
      <h3 id="add-links-title-{instanceId}">{m.transfers_add_links_title()}</h3>
      <p id="add-links-hint-{instanceId}">{m.transfers_add_links_hint()}</p>
      <textarea
        bind:this={textareaEl}
        bind:value={text}
        class="add-links-input"
        rows="8"
        spellcheck="false"
        autocomplete="off"
        placeholder="ed2k://|file|…|/"
        aria-label={m.transfers_add_links_title()}
      ></textarea>
      <div class="add-links-status" aria-live="polite">
        {#if tooLong}
          <span class="warn">{m.transfers_clipboard_too_long({ length: text.trim().length, max: maxLength })}</span>
        {:else if batch}
          {plural(count, {
            one: m.transfers_add_links_found_one,
            other: () => m.transfers_add_links_found_other({ count: formatNumber(count) }),
          })}{#if ignored > 0}
            {' '}{m.transfers_add_links_ignored({ count: formatNumber(ignored) })}{/if}
        {/if}
      </div>
      <div class="dialog-actions">
        <button type="button" class="ghost" onclick={close}>{m.common_cancel()}</button>
        <button type="button" onclick={() => void submit()} disabled={busy || count === 0 || tooLong}>
          {m.transfers_add_links_submit()}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .add-links-dialog {
    width: min(560px, calc(100vw - 48px));
    max-width: none;
  }

  .add-links-input {
    width: 100%;
    min-height: 140px;
    resize: vertical;
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
    line-height: 1.45;
    white-space: pre;
    overflow-wrap: normal;
  }

  .add-links-status {
    min-height: 1.4em;
    margin: 8px 0 16px;
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
  }

  .add-links-status .warn {
    color: var(--warning);
  }
</style>
