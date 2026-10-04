<script lang="ts">
  // The user's own download categories: made here, or from a download's
  // Category menu, where the new one is also assigned to the downloads picked.
  import * as m from '$lib/paraglide/messages';
  import { tick } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground, trapTabKey } from '$lib/a11y';
  import { formatNumber } from '$lib/utils';
  import { translateError } from '$lib/i18n';
  import { plural } from '$lib/plural';
  import IconX from '$lib/components/IconX.svelte';

  /** The backend's limits, so what the box accepts is what is kept. */
  const CATEGORY_MAX_CHARS = 40;
  const MAX_CATEGORIES = 32;

  let {
    open = $bindable(false),
    categories,
    counts,
    assignCount = 0,
    isTaken,
    onadd,
    onremove,
  }: {
    open?: boolean;
    categories: string[];
    /** Downloads in each category, by category value. */
    counts: Record<string, number>;
    /** Above zero, the dialog makes one category for that many downloads. */
    assignCount?: number;
    isTaken: (name: string) => boolean;
    onadd: (name: string) => Promise<void>;
    onremove: (name: string) => Promise<void>;
  } = $props();

  const instanceId = Math.random().toString(36).slice(2, 10);
  let name = $state('');
  let error = $state<string | null>(null);
  let busy = $state(false);
  let dialogEl: HTMLDivElement | undefined = $state(undefined);
  let overlayEl: HTMLDivElement | undefined = $state(undefined);
  let inputEl: HTMLInputElement | undefined = $state(undefined);
  let returnFocusEl: HTMLElement | null = null;

  const creating = $derived(assignCount > 0);
  const cleaned = $derived(name.replace(/\s+/g, ' ').trim());
  const full = $derived(categories.length >= MAX_CATEGORIES);

  $effect(() => {
    if (!open) return;
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
    name = '';
    error = null;
    busy = false;
    requestAnimationFrame(() => inputEl?.focus());
    return () => {
      const el = returnFocusEl;
      returnFocusEl = null;
      if (el) requestAnimationFrame(() => document.contains(el) && el.focus());
    };
  });

  $effect(() => {
    if (!open || !overlayEl) return;
    return inertBackground(overlayEl);
  });

  function close() {
    if (busy) return;
    open = false;
  }

  async function add() {
    if (busy || !cleaned) return;
    if (full) {
      error = m.transfers_categories_limit({ max: MAX_CATEGORIES });
      return;
    }
    if (isTaken(cleaned)) {
      error = m.transfers_categories_exists();
      return;
    }
    busy = true;
    error = null;
    try {
      await onadd(cleaned);
      name = '';
      if (creating) {
        busy = false;
        open = false;
        return;
      }
    } catch (e: unknown) {
      error = translateError(e, m.transfers_operation_failed());
    }
    busy = false;
    // Once the controls `busy` disabled are enabled again: a disabled one
    // cannot take focus, which then went to the page, out of Escape's reach.
    await tick();
    inputEl?.focus();
  }

  async function remove(category: string) {
    if (busy) return;
    const index = categories.indexOf(category);
    busy = true;
    error = null;
    try {
      await onremove(category);
    } catch (e: unknown) {
      error = translateError(e, m.transfers_operation_failed());
    }
    busy = false;
    await tick();
    // The row now in its place, or the one above when it was the last, or the
    // name box once none are left; its own button again if the remove failed.
    const buttons = dialogEl?.querySelectorAll<HTMLButtonElement>('.categories-remove') ?? [];
    (buttons[Math.min(index, buttons.length - 1)] ?? inputEl)?.focus();
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      close();
      return;
    }
    trapTabKey(e, dialogEl);
  }

  function countLabel(count: number): string {
    return plural(count, {
      one: m.transfers_categories_count_one,
      other: () => m.transfers_categories_count_other({ count: formatNumber(count) }),
    });
  }
</script>

{#if open}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="confirm-overlay"
    bind:this={overlayEl}
    role="dialog"
    aria-modal="true"
    aria-labelledby="categories-title-{instanceId}"
    aria-describedby="categories-hint-{instanceId}"
    tabindex="-1"
    onkeydown={onKeydown}
    onclick={(e) => e.target === e.currentTarget && close()}
    transition:fade={{ duration: prefersReducedMotion.current ? 0 : 150 }}
  >
    <div
      class="confirm-dialog categories-dialog"
      bind:this={dialogEl}
      transition:scale={{ start: 0.96, opacity: 0, duration: prefersReducedMotion.current ? 0 : 200 }}
    >
      <h3 id="categories-title-{instanceId}">
        {creating ? m.transfers_categories_new_title() : m.transfers_categories_title()}
      </h3>
      <p id="categories-hint-{instanceId}">
        {#if creating}
          {plural(assignCount, {
            one: m.transfers_categories_new_hint_one,
            other: () => m.transfers_categories_new_hint_other({ count: formatNumber(assignCount) }),
          })}
        {:else}
          {m.transfers_categories_hint()}
        {/if}
      </p>

      {#if !creating}
        {#if categories.length === 0}
          <p class="categories-empty">{m.transfers_categories_none_yet()}</p>
        {:else}
          <ul class="categories-list">
            {#each categories as category (category)}
              <li>
                <span class="categories-name">{category}</span>
                <span class="categories-count">{countLabel(counts[category] ?? 0)}</span>
                <button
                  type="button"
                  class="ghost categories-remove"
                  disabled={busy}
                  aria-label={m.transfers_categories_remove_aria({ name: category })}
                  title={m.transfers_categories_remove_aria({ name: category })}
                  onclick={() => void remove(category)}
                ><IconX size={13} /></button>
              </li>
            {/each}
          </ul>
        {/if}
      {/if}

      <form class="categories-add" onsubmit={(e) => { e.preventDefault(); void add(); }}>
        <input
          bind:this={inputEl}
          bind:value={name}
          type="text"
          maxlength={CATEGORY_MAX_CHARS}
          autocomplete="off"
          spellcheck="false"
          placeholder={m.transfers_categories_name_label()}
          aria-label={m.transfers_categories_name_label()}
          disabled={busy}
          oninput={() => (error = null)}
        />
        {#if !creating}
          <button type="submit" disabled={busy || !cleaned}>{m.transfers_categories_add()}</button>
        {/if}
      </form>
      <div class="categories-error" aria-live="polite">
        {#if error}<span>{error}</span>{/if}
      </div>

      <div class="dialog-actions">
        {#if creating}
          <button type="button" class="ghost" disabled={busy} onclick={close}>{m.common_cancel()}</button>
          <button type="button" disabled={busy || !cleaned} onclick={() => void add()}>{m.transfers_categories_create()}</button>
        {:else}
          <button type="button" disabled={busy} onclick={close}>{m.common_close()}</button>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  .categories-dialog {
    width: min(440px, calc(100vw - 48px));
    max-width: none;
  }

  .categories-empty {
    margin: 0 0 12px;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }

  .categories-list {
    list-style: none;
    margin: 0 0 12px;
    padding: 0;
    max-height: 240px;
    overflow-y: auto;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }

  .categories-list li {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 6px 6px 6px 12px;
  }

  .categories-list li + li {
    border-top: 1px solid var(--border);
  }

  .categories-name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .categories-count {
    color: var(--text-muted);
    font-size: var(--font-size-sm);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }

  .categories-remove {
    padding: 4px;
    line-height: 0;
  }

  .categories-add {
    display: flex;
    gap: 8px;
  }

  .categories-add input {
    flex: 1;
    min-width: 0;
  }

  .categories-error {
    min-height: 1.4em;
    margin: 6px 0 12px;
    font-size: var(--font-size-sm);
    color: var(--danger);
  }
</style>
