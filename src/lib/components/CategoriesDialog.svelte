<script lang="ts">
  // The user's own download categories: made here, or from a download's
  // Category menu, where the new one is also assigned to the downloads picked.
  // Each category, the built-in ones included, can have a folder inside
  // Downloads that its downloads land in when they finish.
  //
  // Managing them is a list beside the one being edited, as a settings window
  // is: every category's folder can be read down the list, and the pane has
  // room to say what a change will do before it is made.
  import * as m from '$lib/paraglide/messages';
  import { tick, untrack } from 'svelte';
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
  /** Below this many categories the whole list fits, and a search box would
   *  only be in the way. */
  const SEARCH_FROM = 9;

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
  /** The category whose remove button was pressed and is waiting on a second
   *  click. Removing one takes its downloads out of it, so it asks first. */
  let confirmingRemove = $state<string | null>(null);
  /** The category the pane shows; `null` is the new-category form. */
  let selected = $state<string | null>(null);
  let query = $state('');
  const SAVED_FLASH_MS = 1800;
  let dialogEl: HTMLDivElement | undefined = $state(undefined);
  let overlayEl: HTMLDivElement | undefined = $state(undefined);
  let inputEl: HTMLInputElement | undefined = $state(undefined);
  let listEl: HTMLDivElement | undefined = $state(undefined);
  let returnFocusEl: HTMLElement | null = null;
  // Folder saves run one at a time, in the order they were asked for, so a
  // blur and the Enter before it cannot race to the backend.
  let folderSaves: Promise<void> = Promise.resolve();

  const creating = $derived(assignCount > 0);
  const cleaned = $derived(name.replace(/\s+/g, ' ').trim());
  const full = $derived(categories.length >= MAX_CATEGORIES);
  const newFolder = $derived(cleaned ? normalizeCategoryFolder(cleaned) : null);
  /** The selection while it still exists; a category removed from elsewhere
   *  falls back to the new-category form. */
  const current = $derived(
    selected !== null && (categories.includes(selected) || builtins.includes(selected)) ? selected : null,
  );
  const showSearch = $derived(categories.length + builtins.length >= SEARCH_FROM);
  const folded = $derived(showSearch ? query.trim().toLocaleLowerCase() : '');
  function matches(category: string): boolean {
    if (!folded) return true;
    return labelFor(category).toLocaleLowerCase().includes(folded)
      || (folders[category] ?? '').toLocaleLowerCase().includes(folded);
  }
  const shownCategories = $derived(categories.filter(matches));
  const shownBuiltins = $derived(builtins.filter(matches));
  /** The list entry Tab lands on: the selection when it is listed, otherwise
   *  the first. The rest are reached with the arrow keys. */
  const tabStop = $derived.by(() => {
    const shown = [...shownCategories, ...shownBuiltins];
    return current !== null && shown.includes(current) ? current : (shown[0] ?? null);
  });

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
    confirmingRemove = null;
    query = '';
    // Read once: the list changing while the dialog is open must not reset it.
    const first = untrack(() => (assignCount > 0 ? null : (categories[0] ?? null)));
    selected = first;
    requestAnimationFrame(() => {
      if (first === null) inputEl?.focus();
      else listButton(first)?.focus();
    });
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

  function listButton(category: string): HTMLButtonElement | undefined {
    const buttons = listEl?.querySelectorAll<HTMLButtonElement>('.cat-item') ?? [];
    return [...buttons].find((button) => button.dataset.category === category);
  }

  function select(category: string) {
    if (selected === category) return;
    selected = category;
    confirmingRemove = null;
  }

  async function openNew() {
    selected = null;
    confirmingRemove = null;
    await tick();
    inputEl?.focus();
  }

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
      error = m.transfers_categories_limit({ max: formatNumber(MAX_CATEGORIES) });
      return;
    }
    if (isTaken(cleaned)) {
      error = m.transfers_categories_exists();
      return;
    }
    busy = true;
    error = null;
    const before = [...categories];
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
    // Show the one just made, so its folder can be checked or changed; also
    // when the error is that its folder could not be saved.
    const added = creating ? undefined : categories.find((category) => !before.includes(category));
    if (added !== undefined) {
      name = '';
      query = '';
      selected = added;
      await tick();
      listButton(added)?.focus();
      return;
    }
    inputEl?.focus();
  }

  async function askRemove(category: string) {
    confirmingRemove = category;
    await tick();
    dialogEl?.querySelector<HTMLButtonElement>('.cat-confirm-cancel')?.focus();
  }

  async function cancelRemove() {
    confirmingRemove = null;
    await tick();
    dialogEl?.querySelector<HTMLButtonElement>('.cat-remove')?.focus();
  }

  async function remove(category: string) {
    if (busy) return;
    confirmingRemove = null;
    const index = categories.indexOf(category);
    busy = true;
    error = null;
    let removed = false;
    try {
      await onremove(category);
      delete drafts[category];
      removed = true;
    } catch (e: unknown) {
      error = translateError(e, m.transfers_operation_failed());
    }
    busy = false;
    await tick();
    if (!removed) {
      dialogEl?.querySelector<HTMLButtonElement>('.cat-remove')?.focus();
      return;
    }
    // The category now in its place, or the one above when it was the last,
    // or the new-category form once none are left.
    const next = categories[Math.min(index, categories.length - 1)] ?? null;
    selected = next;
    await tick();
    if (next === null) inputEl?.focus();
    else listButton(next)?.focus();
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

  async function clearFolder(category: string, field: HTMLInputElement | null) {
    drafts[category] = '';
    await saveFolder(category);
    field?.focus();
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

  function onSearchKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && query) {
      // Clears the search first, and closes the dialog only after.
      e.preventDefault();
      e.stopPropagation();
      query = '';
    } else if (e.key === 'ArrowDown') {
      const first = listEl?.querySelector<HTMLButtonElement>('.cat-item');
      if (!first) return;
      e.preventDefault();
      first.focus();
      const category = first.dataset.category;
      if (category !== undefined) select(category);
    }
  }

  /** Up and Down walk the list and show each category as they land on it. */
  function onListKeydown(e: KeyboardEvent) {
    const items = [...(listEl?.querySelectorAll<HTMLButtonElement>('.cat-item') ?? [])];
    const at = items.indexOf(e.currentTarget as HTMLButtonElement);
    if (at < 0) return;
    const to =
      e.key === 'ArrowDown' ? at + 1
      : e.key === 'ArrowUp' ? at - 1
      : e.key === 'Home' ? 0
      : e.key === 'End' ? items.length - 1
      : null;
    if (to === null) return;
    e.preventDefault();
    const item = items[Math.max(0, Math.min(to, items.length - 1))];
    item.focus();
    const category = item.dataset.category;
    if (category !== undefined) select(category);
  }

  function folderPath(folder: string | null | undefined): string {
    return folder ? `Downloads/${folder}` : 'Downloads';
  }

  function folderPreview(draft: string): string {
    const folder = normalizeCategoryFolder(draft);
    return folder === null
      ? m.transfers_categories_folder_preview_none()
      : m.transfers_categories_folder_preview({ folder: folderPath(folder) });
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      // Backs out of a remove first, as it does a folder edit.
      if (confirmingRemove !== null) void cancelRemove();
      else void close();
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

{#snippet plusGlyph(size: number)}
  <svg viewBox="0 0 16 16" width={size} height={size} fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true">
    <path d="M8 3.25v9.5M3.25 8h9.5"/>
  </svg>
{/snippet}

{#snippet folderGlyph(size: number)}
  <svg viewBox="0 0 16 16" width={size} height={size} fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" aria-hidden="true">
    <path d="M1.75 4.25a1 1 0 0 1 1-1h3.1l1.4 1.5h5.999a1 1 0 0 1 1 1v6.5a1 1 0 0 1-1 1H2.75a1 1 0 0 1-1-1z"/>
  </svg>
{/snippet}

{#snippet categoryIcon(category: string, builtin: boolean, size: number)}
  {#if builtin}
    <FileTypeIcon kind={builtinKind(category)} {size} />
  {:else}
    <span class="cat-tile" style:width="{size}px" style:height="{size}px" aria-hidden="true">
      {@render tagGlyph(Math.round(size * 0.52))}
    </span>
  {/if}
{/snippet}

{#snippet item(category: string, builtin: boolean)}
  {@const count = counts[category] ?? 0}
  <li>
    <button
      type="button"
      class="cat-item"
      class:active={current === category}
      data-category={category}
      aria-current={current === category ? 'true' : undefined}
      tabindex={tabStop === category ? 0 : -1}
      onclick={() => select(category)}
      onkeydown={onListKeydown}
    >
      {@render categoryIcon(category, builtin, 28)}
      <span class="cat-item-text">
        <span class="cat-item-name">{labelFor(category)}</span>
        <span class="cat-item-folder" class:has-folder={!!folders[category]}>
          {@render folderGlyph(11)}
          <bdi dir="auto">{folderPath(folders[category])}</bdi>
        </span>
      </span>
      {#if count > 0}
        <span class="cat-item-count" aria-hidden="true">{formatNumber(count)}</span>
        <span class="sr-only">{countLabel(count)}</span>
      {/if}
    </button>
  </li>
{/snippet}

{#snippet folderField(category: string, fieldId: string)}
  {@const draft = drafts[category]}
  {@const value = draft ?? folders[category] ?? ''}
  {@const hasFolder = value.trim() !== ''}
  <div class="cat-folder" class:has-folder={hasFolder}>
    <span class="cat-folder-icon">{@render folderGlyph(15)}</span>
    <label class="cat-folder-prefix" for={fieldId}>Downloads/</label>
    <input
      id={fieldId}
      type="text"
      maxlength={FOLDER_INPUT_MAX}
      autocomplete="off"
      spellcheck="false"
      {value}
      placeholder={m.transfers_categories_folder_placeholder()}
      aria-label={m.transfers_categories_folder_aria({ name: labelFor(category) })}
      aria-describedby="categories-preview-{instanceId}"
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
    {#if hasFolder}
      <button
        type="button"
        class="cat-folder-clear"
        disabled={busy}
        aria-label={m.transfers_categories_folder_clear()}
        title={m.transfers_categories_folder_clear()}
        onclick={(e) => {
          const field = e.currentTarget.parentElement?.querySelector('input') ?? null;
          void clearFolder(category, field);
        }}
      ><IconX size={12} /></button>
    {/if}
  </div>
  <p class="cat-folder-preview" id="categories-preview-{instanceId}" aria-live="polite">
    {folderPreview(value)}
  </p>
{/snippet}

{#snippet createForm()}
  <form class="cat-create" onsubmit={(e) => { e.preventDefault(); void add(); }}>
    {#if !creating}
      <div class="cat-pane-head">
        <span class="cat-tile cat-tile-new" aria-hidden="true">{@render plusGlyph(22)}</span>
        <div class="cat-pane-title">
          <h4>{m.transfers_categories_new_title()}</h4>
          <p>{m.transfers_categories_hint()}</p>
        </div>
      </div>
    {/if}
    <div class="cat-field">
      <label class="cat-field-label" for="categories-name-{instanceId}">{m.transfers_categories_name_label()}</label>
      <div class="cat-create-row">
        <input
          id="categories-name-{instanceId}"
          bind:this={inputEl}
          bind:value={name}
          type="text"
          maxlength={CATEGORY_MAX_CHARS}
          autocomplete="off"
          spellcheck="false"
          disabled={busy || (!creating && full)}
          oninput={() => (error = null)}
        />
        {#if !creating}
          <button type="submit" class="primary" disabled={busy || !cleaned || full}>
            {@render plusGlyph(14)}
            {m.transfers_categories_add()}
          </button>
        {/if}
      </div>
    </div>
    <label class="cat-own-folder">
      <input type="checkbox" bind:checked={ownFolder} disabled={busy || (cleaned !== '' && newFolder === null)} />
      <span>
        {newFolder
          ? m.transfers_categories_own_folder({ folder: `Downloads/${newFolder}` })
          : m.transfers_categories_own_folder_generic()}
      </span>
    </label>
    {#if !creating && full}
      <p class="cat-limit">{m.transfers_categories_limit({ max: formatNumber(MAX_CATEGORIES) })}</p>
    {/if}
  </form>
{/snippet}

{#snippet details(category: string, builtin: boolean)}
  {@const count = counts[category] ?? 0}
  <div class="cat-pane-head">
    {@render categoryIcon(category, builtin, 44)}
    <div class="cat-pane-title">
      <h4 id="categories-detail-{instanceId}">{labelFor(category)}</h4>
      <p>
        <span class="cat-kind" class:builtin>
          {builtin ? m.transfers_categories_kind_builtin() : m.transfers_categories_kind_yours()}
        </span>
        <span>{countLabel(count)}</span>
      </p>
    </div>
  </div>

  <div class="cat-field">
    <span class="cat-field-label">{m.transfers_categories_folder_label()}</span>
    {@render folderField(category, `categories-folder-${instanceId}`)}
  </div>

  <p class="cat-footnote">
    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" aria-hidden="true">
      <circle cx="8" cy="8" r="6.25"/>
      <path d="M8 7.25v4M8 4.9v.1"/>
    </svg>
    <span>{m.transfers_categories_folder_hint()}</span>
  </p>

  {#if !builtin}
    <div class="cat-danger" class:confirming={confirmingRemove === category}>
      {#if confirmingRemove === category}
        <div class="cat-confirm" role="group" aria-label={m.transfers_categories_remove_confirm({ name: category })}>
          <p>
            <strong>{m.transfers_categories_remove_confirm({ name: category })}</strong>
            {#if count > 0}
              {plural(count, {
                one: m.transfers_categories_remove_confirm_moves_one,
                other: () => m.transfers_categories_remove_confirm_moves_other({ count: formatNumber(count) }),
              })}
            {/if}
          </p>
          <div class="cat-confirm-actions">
            <button type="button" class="ghost cat-confirm-cancel" disabled={busy} onclick={() => void cancelRemove()}>{m.common_cancel()}</button>
            <button type="button" class="danger" disabled={busy} onclick={() => void remove(category)}>{m.common_remove()}</button>
          </div>
        </div>
      {:else}
        <p class="cat-danger-text">{m.transfers_categories_remove_note()}</p>
        <button
          type="button"
          class="secondary cat-remove"
          disabled={busy}
          onclick={() => void askRemove(category)}
        >{m.transfers_categories_remove()}</button>
      {/if}
    </div>
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

      {#if creating}
        <div class="cat-body">
          {@render createForm()}
        </div>
      {:else}
        <div class="cat-main">
          <aside class="cat-side">
            <div class="cat-side-top">
              <button
                type="button"
                class="cat-new"
                class:active={current === null}
                aria-current={current === null ? 'true' : undefined}
                disabled={busy}
                onclick={() => void openNew()}
              >
                <span class="cat-new-icon">{@render plusGlyph(14)}</span>
                {m.transfers_categories_new_title()}
              </button>
              {#if showSearch}
                <label class="cat-search">
                  <svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
                    <circle cx="7" cy="7" r="4.5"/>
                    <line x1="10.5" y1="10.5" x2="14" y2="14"/>
                  </svg>
                  <input
                    type="text"
                    bind:value={query}
                    autocomplete="off"
                    spellcheck="false"
                    placeholder={m.transfers_categories_search_placeholder()}
                    aria-label={m.transfers_categories_search_placeholder()}
                    onkeydown={onSearchKeydown}
                  />
                  {#if query}
                    <button
                      type="button"
                      class="cat-search-clear"
                      aria-label={m.transfers_known_clear_filter()}
                      onclick={() => (query = '')}
                    ><IconX size={12} /></button>
                  {/if}
                </label>
              {/if}
            </div>

            <div class="cat-list-scroll" bind:this={listEl}>
              <div class="cat-group-head">
                <h4 id="categories-yours-{instanceId}">{m.transfers_categories_yours_title()}</h4>
                <span class="cat-group-count">{formatNumber(categories.length)}/{formatNumber(MAX_CATEGORIES)}</span>
              </div>
              {#if categories.length === 0}
                <p class="cat-side-empty">{m.transfers_categories_none_yet()}</p>
              {:else if shownCategories.length > 0}
                <ul class="cat-items" aria-labelledby="categories-yours-{instanceId}">
                  {#each shownCategories as category (category)}
                    {@render item(category, false)}
                  {/each}
                </ul>
              {/if}

              {#if shownBuiltins.length > 0}
                <div class="cat-group-head">
                  <h4 id="categories-builtin-{instanceId}">{m.transfers_categories_builtin_title()}</h4>
                </div>
                <ul class="cat-items" aria-labelledby="categories-builtin-{instanceId}">
                  {#each shownBuiltins as category (category)}
                    {@render item(category, true)}
                  {/each}
                </ul>
              {/if}

              {#if folded && shownCategories.length === 0 && shownBuiltins.length === 0}
                <p class="cat-side-empty" aria-live="polite">{m.transfers_categories_search_none()}</p>
              {/if}
            </div>
          </aside>

          <section
            class="cat-pane"
            aria-labelledby={current === null ? undefined : `categories-detail-${instanceId}`}
          >
            {#key current}
              <div class="cat-pane-inner" in:fade={{ duration: prefersReducedMotion.current ? 0 : 120 }}>
                {#if current === null}
                  {@render createForm()}
                {:else}
                  {@render details(current, builtins.includes(current))}
                {/if}
              </div>
            {/key}
          </section>
        </div>
      {/if}

      <footer class="cat-footer">
        <div class="cat-error" aria-live="polite">
          {#if error}<span>{error}</span>{/if}
        </div>
        <div class="dialog-actions">
          {#if creating}
            <button type="button" class="ghost" disabled={busy} onclick={() => void close()}>{m.common_cancel()}</button>
            <button type="button" class="primary" disabled={busy || !cleaned} onclick={() => void add()}>{m.transfers_categories_create()}</button>
          {:else}
            <button type="button" class="primary" disabled={busy} onclick={() => void close()}>{m.transfers_categories_done()}</button>
          {/if}
        </div>
      </footer>
    </div>
  </div>
{/if}

<style>
  /* A fixed-size window, so moving down the list never makes it jump. The
     list and the pane scroll on their own; the header and footer stay put. */
  .cat-dialog {
    display: flex;
    flex-direction: column;
    width: min(920px, calc(100vw - 48px));
    height: min(660px, calc(100vh - 48px));
    max-width: none;
    padding: 0;
  }
  .cat-dialog.creating {
    width: min(480px, calc(100vw - 48px));
    height: auto;
    max-height: calc(100vh - 48px);
  }

  .cat-header {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    padding: 20px 20px 16px 24px;
    border-bottom: 1px solid var(--border);
  }
  .cat-header-tile {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 42px;
    height: 42px;
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
    font-size: var(--font-size-xl);
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
    padding: 18px 24px 20px;
  }

  /* --- The list beside the pane --- */
  .cat-main {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: 300px minmax(0, 1fr);
  }
  .cat-side {
    display: flex;
    flex-direction: column;
    min-height: 0;
    border-right: 1px solid var(--border);
    background: var(--bg-surface);
  }
  .cat-side-top {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 14px 14px 10px;
  }
  .cat-new {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 8px 10px;
    border: 1px dashed color-mix(in srgb, var(--accent) 45%, var(--border));
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--text-accent);
    font-weight: 600;
    text-align: left;
    transition: background var(--transition-fast), border-color var(--transition-fast);
  }
  .cat-new:hover:not(:disabled) {
    background: color-mix(in srgb, var(--accent) 8%, transparent);
    border-color: var(--accent);
  }
  .cat-new.active {
    border-style: solid;
    border-color: var(--accent);
    background: var(--accent-fill);
  }
  .cat-new-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: min(var(--radius-md), 8px);
    background: color-mix(in srgb, var(--accent) 15%, transparent);
  }

  .cat-search {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 0 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    color: var(--text-muted);
    transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
  }
  .cat-search:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-halo);
  }
  .cat-search input {
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
  .cat-search-clear,
  .cat-folder-clear {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 20px;
    height: 20px;
    padding: 0;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
  }
  .cat-search-clear:hover,
  .cat-folder-clear:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .cat-list-scroll {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 0 8px 12px;
    scrollbar-width: thin;
  }
  .cat-group-head {
    display: flex;
    align-items: baseline;
    gap: 8px;
    padding: 12px 8px 6px;
  }
  .cat-group-head h4 {
    margin: 0;
    font-size: var(--font-size-xs);
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-muted);
  }
  .cat-group-count {
    margin-left: auto;
    font-size: var(--font-size-xs);
    font-variant-numeric: tabular-nums;
    color: var(--text-muted);
  }
  .cat-side-empty {
    margin: 2px 6px 4px;
    padding: 12px;
    border: 1px dashed var(--border);
    border-radius: var(--radius-md);
    text-align: center;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    line-height: 1.45;
  }
  .cat-items {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .cat-item {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 7px 8px;
    border: 1px solid transparent;
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--text-primary);
    font-weight: 400;
    text-align: left;
    transition: background var(--transition-fast), border-color var(--transition-fast);
  }
  .cat-item:hover {
    background: var(--bg-hover);
  }
  .cat-item.active {
    background: var(--accent-fill);
    border-color: color-mix(in srgb, var(--accent) 40%, transparent);
  }
  .cat-item-text {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .cat-item-name {
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .cat-item-folder {
    display: flex;
    align-items: center;
    gap: 4px;
    min-width: 0;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
  }
  .cat-item-folder bdi {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .cat-item-folder.has-folder {
    color: var(--text-secondary);
  }
  .cat-item-folder.has-folder :global(svg) {
    color: var(--accent);
  }
  .cat-item-folder :global(svg) {
    flex: none;
  }
  .cat-item-count {
    flex: none;
    min-width: 22px;
    padding: 1px 7px;
    border-radius: var(--radius-pill);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-size: var(--font-size-xs);
    font-weight: 600;
    font-variant-numeric: tabular-nums;
    text-align: center;
  }
  .cat-item.active .cat-item-count {
    background: color-mix(in srgb, var(--accent) 22%, transparent);
    color: var(--text-accent);
  }

  /* --- The pane --- */
  .cat-pane {
    min-width: 0;
    min-height: 0;
    overflow-y: auto;
    scrollbar-width: thin;
  }
  .cat-pane-inner {
    display: flex;
    flex-direction: column;
    gap: 22px;
    max-width: 560px;
    padding: 24px 28px 28px;
  }
  .cat-pane-head {
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .cat-pane-title {
    flex: 1;
    min-width: 0;
  }
  .cat-pane-title h4 {
    margin: 0 0 4px;
    font-size: var(--font-size-lg);
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .cat-pane-title p {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    margin: 0;
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    line-height: 1.45;
  }
  .cat-kind {
    padding: 1px 8px;
    border-radius: var(--radius-pill);
    background: var(--accent-fill);
    color: var(--text-accent);
    font-size: var(--font-size-xs);
    font-weight: 600;
  }
  .cat-kind.builtin {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
  }
  .cat-tile {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: min(var(--radius-md), 10px);
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 15%, transparent);
  }
  .cat-tile-new {
    width: 44px;
    height: 44px;
  }

  .cat-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .cat-field-label {
    font-size: var(--font-size-sm);
    font-weight: 600;
    color: var(--text-secondary);
  }

  .cat-create {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .cat-dialog.creating .cat-create {
    gap: 12px;
  }
  .cat-create-row {
    display: flex;
    gap: 8px;
  }
  .cat-create-row input {
    flex: 1;
    min-width: 0;
  }
  .cat-create-row button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .cat-own-folder {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: var(--font-size-md);
    color: var(--text-secondary);
    overflow-wrap: anywhere;
    cursor: pointer;
  }
  .cat-own-folder input {
    margin-top: 2px;
  }
  .cat-limit {
    margin: 0;
    font-size: var(--font-size-sm);
    color: var(--warning);
  }

  /* One field that reads as a path: the fixed `Downloads/` and what is typed
     after it, inside the same border. */
  .cat-folder {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 0 6px 0 10px;
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
  .cat-folder-icon {
    flex: none;
    display: inline-flex;
  }
  .cat-folder.has-folder .cat-folder-icon {
    color: var(--accent);
  }
  .cat-folder-prefix {
    flex: none;
    font-size: var(--font-size-md);
    white-space: nowrap;
    cursor: text;
  }
  .cat-folder input {
    flex: 1;
    min-width: 0;
    padding: 8px 0;
    border: none;
    background: transparent;
    box-shadow: none;
    outline: none;
    font-size: var(--font-size-md);
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
    margin: 0;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    overflow-wrap: anywhere;
  }

  .cat-footnote {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    margin: 0;
    padding: 12px 14px;
    border-radius: var(--radius-md);
    background: var(--bg-surface);
    font-size: var(--font-size-sm);
    line-height: 1.5;
    color: var(--text-secondary);
  }
  .cat-footnote svg {
    flex: none;
    margin-top: 2px;
    color: var(--text-muted);
  }

  .cat-danger {
    display: flex;
    align-items: center;
    gap: 12px;
    padding-top: 18px;
    border-top: 1px solid var(--border);
  }
  .cat-danger-text {
    flex: 1;
    min-width: 0;
    margin: 0;
    font-size: var(--font-size-sm);
    line-height: 1.45;
    color: var(--text-muted);
  }
  .cat-remove {
    flex: none;
    color: var(--danger);
  }
  .cat-remove:hover:not(:disabled) {
    color: var(--danger);
    border-color: color-mix(in srgb, var(--danger) 45%, var(--border));
    background: color-mix(in srgb, var(--danger) 10%, transparent);
  }
  .cat-confirm {
    flex: 1;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 12px;
    padding: 10px 12px;
    border: 1px solid color-mix(in srgb, var(--danger) 40%, var(--border));
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--danger) 8%, transparent);
  }
  .cat-confirm p {
    flex: 1;
    min-width: 12em;
    margin: 0;
    font-size: var(--font-size-sm);
    line-height: 1.45;
    color: var(--text-secondary);
  }
  .cat-confirm strong {
    color: var(--text-primary);
  }
  .cat-confirm-actions {
    display: flex;
    gap: 6px;
  }

  .cat-footer {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 20px 14px 24px;
    border-top: 1px solid var(--border);
  }
  .cat-error {
    flex: 1;
    min-width: 0;
    font-size: var(--font-size-sm);
    color: var(--danger);
  }

  /* Narrow windows: the list goes above the pane rather than beside it. */
  @media (max-width: 700px) {
    .cat-main {
      grid-template-columns: minmax(0, 1fr);
      grid-template-rows: minmax(0, 2fr) minmax(0, 3fr);
    }
    .cat-side {
      border-right: none;
      border-bottom: 1px solid var(--border);
    }
    .cat-pane-inner {
      padding: 18px 18px 22px;
    }
  }
</style>
