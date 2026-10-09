<script lang="ts">
  // The user's own download categories: made here, or from a download's
  // Category menu, where the new one is also assigned to the downloads picked.
  // Each category, the built-in ones included, can have a folder inside
  // Downloads that its downloads land in when they finish.
  import * as m from '$lib/paraglide/messages';
  import { tick } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground, trapTabKey } from '$lib/a11y';
  import { formatNumber } from '$lib/utils';
  import { translateError } from '$lib/i18n';
  import { plural } from '$lib/plural';
  import { normalizeCategoryFolder } from '$lib/categoryFolders';
  import IconX from '$lib/components/IconX.svelte';

  /** The backend's limits, so what the box accepts is what is kept. */
  const CATEGORY_MAX_CHARS = 40;
  const MAX_CATEGORIES = 32;
  /** Three levels of 64 characters and their separators; the backend cuts
   *  what is longer, and the preview shows where. */
  const FOLDER_INPUT_MAX = 200;

  let {
    open = $bindable(false),
    categories,
    builtins = [],
    labelFor = (category: string) => category,
    folders = {},
    counts,
    assignCount = 0,
    isTaken,
    onadd,
    onremove,
    onfolder,
  }: {
    open?: boolean;
    categories: string[];
    /** The built-in category values, which can have a folder too. */
    builtins?: readonly string[];
    /** A category's name as shown; built-in values are translated. */
    labelFor?: (category: string) => string;
    /** Each category's folder inside Downloads, as saved. */
    folders?: Record<string, string>;
    /** Downloads in each category, by category value. */
    counts: Record<string, number>;
    /** Above zero, the dialog makes one category for that many downloads. */
    assignCount?: number;
    isTaken: (name: string) => boolean;
    /** `ownFolder`: also give it a folder named after it. */
    onadd: (name: string, ownFolder: boolean) => Promise<void>;
    onremove: (name: string) => Promise<void>;
    /** Set a category's folder; `null` finishes its downloads in Downloads itself. */
    onfolder: (category: string, folder: string | null) => Promise<void>;
  } = $props();

  const instanceId = Math.random().toString(36).slice(2, 10);
  let name = $state('');
  let ownFolder = $state(true);
  let error = $state<string | null>(null);
  let busy = $state(false);
  /** Folder edits not saved yet, by category. */
  let drafts = $state<Record<string, string>>({});
  let dialogEl: HTMLDivElement | undefined = $state(undefined);
  let overlayEl: HTMLDivElement | undefined = $state(undefined);
  let inputEl: HTMLInputElement | undefined = $state(undefined);
  let returnFocusEl: HTMLElement | null = null;
  // Folder saves run one at a time, in the order they were asked for, so a
  // blur and the Enter before it cannot race to the backend.
  let folderSaves: Promise<void> = Promise.resolve();

  const creating = $derived(assignCount > 0);
  const cleaned = $derived(name.replace(/\s+/g, ' ').trim());
  const full = $derived(categories.length >= MAX_CATEGORIES);
  const newFolder = $derived(cleaned ? normalizeCategoryFolder(cleaned) : null);

  $effect(() => {
    if (!open) return;
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
    name = '';
    ownFolder = true;
    error = null;
    busy = false;
    drafts = {};
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

  async function close() {
    if (busy) return;
    // A folder typed and not yet confirmed is kept, as leaving the field
    // would have kept it. One that could not be saved keeps the dialog open,
    // or its error would close with it.
    for (const category of Object.keys(drafts)) void saveFolder(category);
    await folderSaves;
    if (Object.keys(drafts).length > 0 && error) return;
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
      await onadd(cleaned, ownFolder && newFolder !== null);
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
      delete drafts[category];
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

  /** Save a category's folder edit, if it changes what is saved. */
  function saveFolder(category: string): Promise<void> {
    folderSaves = folderSaves.then(async () => {
      const draft = drafts[category];
      if (draft === undefined) return;
      const next = normalizeCategoryFolder(draft);
      if (next === (folders[category] ?? null)) {
        delete drafts[category];
        return;
      }
      error = null;
      try {
        await onfolder(category, next);
        // Only if it was not edited again while this saved.
        if (drafts[category] === draft) delete drafts[category];
      } catch (e: unknown) {
        error = translateError(e, m.transfers_operation_failed());
      }
    });
    return folderSaves;
  }

  function onFolderKeydown(e: KeyboardEvent, category: string) {
    if (e.key === 'Enter') {
      e.preventDefault();
      void saveFolder(category);
    } else if (e.key === 'Escape' && drafts[category] !== undefined) {
      // Escape undoes the edit first, and closes the dialog only after.
      e.preventDefault();
      e.stopPropagation();
      delete drafts[category];
    }
  }

  function folderPreview(draft: string): string {
    const folder = normalizeCategoryFolder(draft);
    return folder === null
      ? m.transfers_categories_folder_preview_none()
      : m.transfers_categories_folder_preview({ folder: `Downloads/${folder}` });
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      void close();
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

{#snippet folderField(category: string, key: string)}
  {@const fieldId = `categories-folder-${instanceId}-${key}`}
  {@const draft = drafts[category]}
  <div class="categories-folder">
    <label class="categories-folder-prefix" for={fieldId}>Downloads/</label>
    <input
      id={fieldId}
      type="text"
      maxlength={FOLDER_INPUT_MAX}
      autocomplete="off"
      spellcheck="false"
      value={draft ?? folders[category] ?? ''}
      placeholder={m.transfers_categories_folder_placeholder()}
      aria-label={m.transfers_categories_folder_aria({ name: labelFor(category) })}
      oninput={(e) => {
        drafts[category] = e.currentTarget.value;
        error = null;
      }}
      onkeydown={(e) => onFolderKeydown(e, category)}
      onblur={() => void saveFolder(category)}
    />
  </div>
  {#if draft !== undefined}
    <p class="categories-folder-preview" aria-live="polite">{folderPreview(draft)}</p>
  {/if}
{/snippet}

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
    onclick={(e) => e.target === e.currentTarget && void close()}
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
          {m.transfers_categories_folder_hint()}
        {/if}
      </p>

      {#if !creating}
        <div class="categories-scroll">
          <h4 class="categories-section">{m.transfers_categories_yours_title()}</h4>
          {#if categories.length === 0}
            <p class="categories-empty">{m.transfers_categories_none_yet()}</p>
          {:else}
            <ul class="categories-list">
              {#each categories as category, index (category)}
                <li>
                  <div class="categories-row">
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
                  </div>
                  {@render folderField(category, `user-${index}`)}
                </li>
              {/each}
            </ul>
          {/if}

          {#if builtins.length > 0}
            <h4 class="categories-section">{m.transfers_categories_builtin_title()}</h4>
            <ul class="categories-list">
              {#each builtins as category, index (category)}
                <li>
                  <div class="categories-row">
                    <span class="categories-name">{labelFor(category)}</span>
                    <span class="categories-count">{countLabel(counts[category] ?? 0)}</span>
                  </div>
                  {@render folderField(category, `builtin-${index}`)}
                </li>
              {/each}
            </ul>
          {/if}
        </div>
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
      <label class="categories-own-folder">
        <input type="checkbox" bind:checked={ownFolder} disabled={busy || (cleaned !== '' && newFolder === null)} />
        <span>
          {newFolder
            ? m.transfers_categories_own_folder({ folder: `Downloads/${newFolder}` })
            : m.transfers_categories_own_folder_generic()}
        </span>
      </label>
      <div class="categories-error" aria-live="polite">
        {#if error}<span>{error}</span>{/if}
      </div>

      <div class="dialog-actions">
        {#if creating}
          <button type="button" class="ghost" disabled={busy} onclick={() => void close()}>{m.common_cancel()}</button>
          <button type="button" disabled={busy || !cleaned} onclick={() => void add()}>{m.transfers_categories_create()}</button>
        {:else}
          <button type="button" disabled={busy} onclick={() => void close()}>{m.common_close()}</button>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  .categories-dialog {
    width: min(500px, calc(100vw - 48px));
    max-width: none;
  }

  .categories-scroll {
    max-height: min(50vh, 380px);
    overflow-y: auto;
    margin: 0 0 12px;
    padding-right: 2px;
  }

  .categories-section {
    margin: 0 0 6px;
    font-size: var(--font-size-sm);
    font-weight: 600;
    color: var(--text-muted);
  }

  .categories-section:not(:first-child) {
    margin-top: 12px;
  }

  .categories-empty {
    margin: 0 0 12px;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }

  .categories-list {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }

  .categories-list li {
    padding: 6px 6px 8px 12px;
  }

  .categories-list li + li {
    border-top: 1px solid var(--border);
  }

  .categories-row {
    display: flex;
    align-items: center;
    gap: 10px;
    min-height: 26px;
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

  .categories-folder {
    display: flex;
    align-items: center;
    gap: 4px;
    margin-top: 4px;
  }

  .categories-folder-prefix {
    color: var(--text-muted);
    font-size: var(--font-size-sm);
    white-space: nowrap;
  }

  .categories-folder input {
    flex: 1;
    min-width: 0;
    font-size: var(--font-size-sm);
  }

  .categories-folder-preview {
    margin: 4px 0 0;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
    overflow-wrap: anywhere;
  }

  .categories-add {
    display: flex;
    gap: 8px;
  }

  .categories-add input {
    flex: 1;
    min-width: 0;
  }

  .categories-own-folder {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    margin-top: 8px;
    font-size: var(--font-size-sm);
    overflow-wrap: anywhere;
  }

  .categories-error {
    min-height: 1.4em;
    margin: 6px 0 12px;
    font-size: var(--font-size-sm);
    color: var(--danger);
  }
</style>
