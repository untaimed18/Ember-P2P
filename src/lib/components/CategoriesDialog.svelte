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
  import { FILE_TYPE_FILTERS, type FileTypeKey } from '$lib/fileTypes';
  import IconX from '$lib/components/IconX.svelte';
  import FileTypeIcon from '$lib/components/FileTypeIcon.svelte';

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
  /** Categories whose folder was just saved, for the brief confirmation. */
  let saved = $state<Record<string, number>>({});
  const SAVED_FLASH_MS = 1800;
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
    saved = {};
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
    const buttons = dialogEl?.querySelectorAll<HTMLButtonElement>('.cat-remove') ?? [];
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
        const stamp = Date.now();
        saved[category] = stamp;
        setTimeout(() => {
          if (saved[category] === stamp) delete saved[category];
        }, SAVED_FLASH_MS);
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

  const FILE_TYPE_KEYS = new Set<string>(FILE_TYPE_FILTERS.filter((f) => f !== 'All'));
  function builtinKind(category: string): FileTypeKey | '' {
    return FILE_TYPE_KEYS.has(category) ? (category as FileTypeKey) : '';
  }

  function countLabel(count: number): string {
    return plural(count, {
      one: m.transfers_categories_count_one,
      other: () => m.transfers_categories_count_other({ count: formatNumber(count) }),
    });
  }
</script>

{#snippet tagGlyph(size: number)}
  <svg viewBox="0 0 20 20" width={size} height={size} fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M10.6 2.5H16a1.5 1.5 0 0 1 1.5 1.5v5.4a1.5 1.5 0 0 1-.44 1.06l-6.6 6.6a1.5 1.5 0 0 1-2.12 0l-5.4-5.4a1.5 1.5 0 0 1 0-2.12l6.6-6.6a1.5 1.5 0 0 1 1.06-.44z"/>
    <circle cx="13.6" cy="6.4" r="1.2"/>
  </svg>
{/snippet}

{#snippet folderField(category: string, key: string)}
  {@const fieldId = `categories-folder-${instanceId}-${key}`}
  {@const draft = drafts[category]}
  {@const hasFolder = (draft ?? folders[category] ?? '').trim() !== ''}
  <div class="cat-folder" class:has-folder={hasFolder}>
    <svg class="cat-folder-icon" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" aria-hidden="true">
      <path d="M1.75 4.25a1 1 0 0 1 1-1h3.1l1.4 1.5h5.999a1 1 0 0 1 1 1v6.5a1 1 0 0 1-1 1H2.75a1 1 0 0 1-1-1z"/>
    </svg>
    <label class="cat-folder-prefix" for={fieldId}>Downloads/</label>
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
    {#if saved[category] && draft === undefined}
      <span class="cat-saved" transition:fade={{ duration: prefersReducedMotion.current ? 0 : 150 }}>
        <svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m3.5 8.5 3 3 6-7"/></svg>
        {m.transfers_categories_folder_saved()}
      </span>
    {/if}
  </div>
  {#if draft !== undefined}
    <p class="cat-folder-preview" aria-live="polite">{folderPreview(draft)}</p>
  {/if}
{/snippet}

{#snippet row(category: string, key: string, builtin: boolean)}
  <li class="cat-row">
    <div class="cat-row-head">
      {#if builtin}
        <FileTypeIcon kind={builtinKind(category)} size={30} />
      {:else}
        <span class="cat-tile" aria-hidden="true">{@render tagGlyph(16)}</span>
      {/if}
      <div class="cat-row-title">
        <span class="cat-name">{labelFor(category)}</span>
        <span class="cat-count">{countLabel(counts[category] ?? 0)}</span>
      </div>
      {#if !builtin}
        <button
          type="button"
          class="icon-close cat-remove"
          disabled={busy}
          aria-label={m.transfers_categories_remove_aria({ name: category })}
          title={m.transfers_categories_remove_aria({ name: category })}
          onclick={() => void remove(category)}
        ><IconX size={14} /></button>
      {/if}
    </div>
    {@render folderField(category, key)}
  </li>
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
      class="confirm-dialog cat-dialog"
      class:creating
      bind:this={dialogEl}
      transition:scale={{ start: 0.96, opacity: 0, duration: prefersReducedMotion.current ? 0 : 200 }}
    >
      <header class="cat-header">
        <span class="cat-header-tile" aria-hidden="true">{@render tagGlyph(20)}</span>
        <div class="cat-header-text">
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
              {m.transfers_categories_subtitle()}
            {/if}
          </p>
        </div>
        <button
          type="button"
          class="icon-close"
          disabled={busy}
          aria-label={m.common_close()}
          onclick={() => void close()}
        ><IconX size={15} /></button>
      </header>

      <div class="cat-body">
        <form class="cat-create" onsubmit={(e) => { e.preventDefault(); void add(); }}>
          {#if !creating}
            <span class="cat-create-label">{m.transfers_categories_new_title()}</span>
          {/if}
          <div class="cat-create-row">
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
              <button type="submit" class="primary" disabled={busy || !cleaned}>{m.transfers_categories_add()}</button>
            {/if}
          </div>
          <label class="cat-own-folder">
            <input type="checkbox" bind:checked={ownFolder} disabled={busy || (cleaned !== '' && newFolder === null)} />
            <span>
              {newFolder
                ? m.transfers_categories_own_folder({ folder: `Downloads/${newFolder}` })
                : m.transfers_categories_own_folder_generic()}
            </span>
          </label>
        </form>

        {#if !creating}
          <section class="cat-section" aria-labelledby="categories-yours-{instanceId}">
            <div class="cat-section-head">
              <h4 id="categories-yours-{instanceId}">{m.transfers_categories_yours_title()}</h4>
              <span class="cat-section-count">{categories.length}/{MAX_CATEGORIES}</span>
            </div>
            <p class="cat-section-note">{m.transfers_categories_hint()}</p>
            {#if categories.length === 0}
              <p class="cat-empty">{m.transfers_categories_none_yet()}</p>
            {:else}
              <ul class="cat-list">
                {#each categories as category, index (category)}
                  {@render row(category, `user-${index}`, false)}
                {/each}
              </ul>
            {/if}
          </section>

          {#if builtins.length > 0}
            <section class="cat-section" aria-labelledby="categories-builtin-{instanceId}">
              <div class="cat-section-head">
                <h4 id="categories-builtin-{instanceId}">{m.transfers_categories_builtin_title()}</h4>
              </div>
              <ul class="cat-list">
                {#each builtins as category, index (category)}
                  {@render row(category, `builtin-${index}`, true)}
                {/each}
              </ul>
            </section>
          {/if}

          <p class="cat-footnote">
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" aria-hidden="true">
              <circle cx="8" cy="8" r="6.25"/>
              <path d="M8 7.25v4M8 4.9v.1"/>
            </svg>
            <span>{m.transfers_categories_folder_hint()}</span>
          </p>
        {/if}
      </div>

      <footer class="cat-footer">
        <div class="cat-error" aria-live="polite">
          {#if error}<span>{error}</span>{/if}
        </div>
        <div class="dialog-actions">
          {#if creating}
            <button type="button" class="ghost" disabled={busy} onclick={() => void close()}>{m.common_cancel()}</button>
            <button type="button" class="primary" disabled={busy || !cleaned} onclick={() => void add()}>{m.transfers_categories_create()}</button>
          {:else}
            <button type="button" disabled={busy} onclick={() => void close()}>{m.common_close()}</button>
          {/if}
        </div>
      </footer>
    </div>
  </div>
{/if}

<style>
  /* Header, scrolling body and footer, so the list can grow while the title
     and the Close button stay in reach. */
  .cat-dialog {
    display: flex;
    flex-direction: column;
    width: min(580px, calc(100vw - 48px));
    max-width: none;
    max-height: min(720px, calc(100vh - 48px));
    padding: 0;
  }
  .cat-dialog.creating {
    width: min(460px, calc(100vw - 48px));
  }

  .cat-header {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 18px 18px 14px 20px;
    border-bottom: 1px solid var(--border);
  }
  .cat-header-tile {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 38px;
    height: 38px;
    border-radius: var(--radius-md);
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
  }
  .cat-header-text {
    flex: 1;
    min-width: 0;
  }
  .cat-header-text h3 {
    margin: 0 0 3px;
  }
  .cat-header-text p {
    margin: 0;
    color: var(--text-secondary);
    font-size: var(--font-size-md);
    line-height: 1.45;
  }

  .cat-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 16px 20px 18px;
    scrollbar-width: thin;
  }

  .cat-create {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
  }
  .cat-dialog.creating .cat-create {
    padding: 0;
    border: none;
    background: none;
  }
  .cat-create-label {
    font-size: var(--font-size-sm);
    font-weight: 600;
    color: var(--text-secondary);
  }
  .cat-create-row {
    display: flex;
    gap: 8px;
  }
  .cat-create-row input {
    flex: 1;
    min-width: 0;
  }
  .cat-own-folder {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    overflow-wrap: anywhere;
    cursor: pointer;
  }
  .cat-own-folder input {
    margin-top: 1px;
  }

  .cat-section {
    margin-top: 20px;
  }
  .cat-section-head {
    display: flex;
    align-items: baseline;
    gap: 8px;
    margin-bottom: 6px;
  }
  .cat-section-head h4 {
    margin: 0;
    font-size: var(--font-size-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-muted);
  }
  .cat-section-count {
    font-size: var(--font-size-xs);
    font-variant-numeric: tabular-nums;
    color: var(--text-muted);
  }
  .cat-section-note {
    margin: 0 0 10px;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    line-height: 1.45;
  }
  .cat-empty {
    margin: 0;
    padding: 14px;
    border: 1px dashed var(--border);
    border-radius: var(--radius-md);
    text-align: center;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
  }

  .cat-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .cat-row {
    padding: 10px 10px 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-primary);
    transition: border-color var(--transition-normal);
  }
  .cat-row:focus-within {
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
  }
  .cat-row-head {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .cat-tile {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    border-radius: min(var(--radius-md), 8px);
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 15%, transparent);
  }
  .cat-row-title {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .cat-name {
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .cat-count {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  /* One field that reads as a path: the fixed `Downloads/` and what is typed
     after it, inside the same border. Indented under the name, past the tile. */
  .cat-folder {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 8px 0 0 40px;
    padding: 0 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    color: var(--text-muted);
    transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
  }
  .cat-folder:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-halo);
  }
  .cat-folder.has-folder .cat-folder-icon {
    color: var(--accent);
  }
  .cat-folder-icon {
    flex: none;
  }
  .cat-folder-prefix {
    flex: none;
    font-size: var(--font-size-sm);
    white-space: nowrap;
    cursor: text;
  }
  .cat-folder input {
    flex: 1;
    min-width: 0;
    padding: 6px 0;
    border: none;
    background: transparent;
    box-shadow: none;
    outline: none;
    font-size: var(--font-size-sm);
    color: var(--text-primary);
  }
  .cat-saved {
    flex: none;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: var(--font-size-xs);
    font-weight: 500;
    color: var(--success);
  }
  .cat-folder-preview {
    margin: 5px 0 0 40px;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    overflow-wrap: anywhere;
  }

  .cat-remove {
    width: 26px;
    height: 26px;
  }

  .cat-footnote {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    margin: 18px 0 0;
    font-size: var(--font-size-sm);
    line-height: 1.45;
    color: var(--text-muted);
  }
  .cat-footnote svg {
    flex: none;
    margin-top: 2px;
  }

  .cat-footer {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 18px 14px 20px;
    border-top: 1px solid var(--border);
  }
  .cat-error {
    flex: 1;
    min-width: 0;
    font-size: var(--font-size-sm);
    color: var(--danger);
  }
</style>
