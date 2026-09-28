<script lang="ts">
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { untrack } from 'svelte';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';
  import { plural } from '$lib/plural';
  import { inertBackground, trapTabKey } from '$lib/a11y';
  import IconX from '$lib/components/IconX.svelte';
  import { formatBytes, formatNumber } from '$lib/utils';
  import {
    addSharedFolder,
    closeShareBrowser,
    listShareBrowserChildren,
    measureShareBrowserEntries,
    navigateShareBrowser,
    openShareBrowser,
    shareBrowserSelection,
    type ShareBrowserEntry,
    type ShareBrowserKind,
    type ShareBrowserMeasure,
    type ShareBrowserView,
    type SharedFolderPick,
  } from '$lib/api/sharing';

  let {
    open = $bindable(false),
    onshared,
    onerror,
  }: {
    open?: boolean;
    onshared?: (result: SharedFolderPick) => void;
    onerror?: (error: unknown) => void;
  } = $props();

  const IS_WINDOWS =
    typeof navigator !== 'undefined' &&
    (/Win/i.test(navigator.platform) || /Windows/i.test(navigator.userAgent));

  let overlayEl: HTMLDivElement | undefined = $state(undefined);
  let dialogEl: HTMLDivElement | undefined = $state(undefined);
  let pathInputEl: HTMLInputElement | undefined = $state(undefined);
  let listEl: HTMLDivElement | undefined = $state(undefined);
  let treeRowEls: Record<number, HTMLDivElement | undefined> = {};
  let returnFocusEl: HTMLElement | null = null;

  let sessionId: number | null = $state(null);
  let currentEntry = $state<ShareBrowserEntry | null>(null);
  let children: ShareBrowserEntry[] = $state([]);
  let pathDraft = $state('');
  let loading = $state(false);
  let sharing = $state(false);
  let error: string | null = $state(null);
  let selectedPaths = $state(new Set<string>());
  let idByPath = $state(new Map<string, number>());
  let expanded = $state(new Set<number>());
  let loadedKids = $state(new Map<number, ShareBrowserEntry[]>());
  let history: number[] = $state([]);
  let truncated = $state(false);
  let loadGen = 0;
  let sessionGen = 0;
  let rootEntry: ShareBrowserEntry | null = $state(null);

  $effect(() => {
    if (!open || !overlayEl) return;
    return inertBackground(overlayEl);
  });

  $effect(() => {
    if (!open) return;
    const active = typeof document !== 'undefined' ? document.activeElement : null;
    if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
    const gen = ++sessionGen;
    untrack(() => { void startSession(gen); });
    return () => {
      sessionGen += 1;
      const id = sessionId;
      sessionId = null;
      if (id != null) void closeShareBrowser(id).catch(() => {});
      if (returnFocusEl && typeof returnFocusEl.focus === 'function') {
        try { returnFocusEl.focus(); } catch { /* unmounted */ }
      }
    };
  });

  async function startSession(gen: number) {
    // Retires any listing still in flight from a previous open: its ids belong
    // to a session the backend has already dropped, so letting it land would
    // paint folders that error the moment they are clicked.
    loadGen += 1;
    loading = true;
    error = null;
    selectedPaths = new Set();
    measureCache = new Map();
    measured = null;
    idByPath = new Map();
    entryByPath = new Map();
    history = [];
    expanded = new Set();
    loadedKids = new Map();
    currentEntry = null;
    rootEntry = null;
    children = [];
    truncated = false;
    pathDraft = '';
    try {
      const view = await openShareBrowser();
      if (gen !== sessionGen) {
        void closeShareBrowser(view.session_id).catch(() => {});
        return;
      }
      sessionId = view.session_id;
      applyView(view, { recordHistory: false });
      expanded = new Set([view.current.id]);
      // This PC repeats the same places in both panes, and it cannot be
      // shared. Land in Documents (then Downloads) so the list is files.
      const start = view.children.find((entry) => entry.kind === 'documents')
        ?? view.children.find((entry) => entry.kind === 'downloads');
      if (start && gen === sessionGen) {
        await showEntry(start.id, { recordHistory: true });
      }
      requestAnimationFrame(() => pathInputEl?.focus());
    } catch (e: unknown) {
      if (gen === sessionGen) error = translateError(e);
    } finally {
      if (gen === sessionGen) loading = false;
    }
  }

  function applyView(view: ShareBrowserView, opts?: { recordHistory?: boolean }) {
    const movedFolder = currentEntry?.id !== view.current.id;
    if (opts?.recordHistory !== false && currentEntry && movedFolder) {
      history = [...history, currentEntry.id];
    }
    if (movedFolder) includeSubfolders = true;
    // A new folder starts at its first item. Keeping the old offset would
    // drop the user into the middle of a list they have not seen.
    if (movedFolder && listEl) listEl.scrollTop = 0;
    if (view.current.kind === 'this_pc') rootEntry = view.current;
    currentEntry = view.current;
    children = view.children;
    truncated = view.truncated;
    pathDraft = view.current.path;
    loadedKids = new Map(loadedKids).set(view.current.id, view.children);
    rememberEntries([view.current, ...view.children]);
  }

  // Back, Up, and the address bar can all land on a folder scrolled out of
  // the tree. Bring it into view without moving the pane otherwise.
  $effect(() => {
    const id = currentEntry?.id;
    if (id == null) return;
    const row = treeRowEls[id];
    row?.scrollIntoView({ block: 'nearest' });
  });

  function rememberEntries(entries: ShareBrowserEntry[]) {
    const next = new Map(idByPath);
    const known = new Map(entryByPath);
    for (const entry of entries) {
      if (entry.path) {
        next.set(entry.path, entry.id);
        known.set(entry.path, entry);
      }
    }
    idByPath = next;
    entryByPath = known;
  }

  async function showEntry(id: number, opts?: { recordHistory?: boolean }) {
    if (sessionId == null || sharing) return;
    const gen = ++loadGen;
    loading = true;
    error = null;
    try {
      const view = await listShareBrowserChildren(sessionId, id);
      if (gen !== loadGen) return;
      applyView(view, opts);
      const next = new Set(expanded);
      next.add(id);
      expanded = next;
    } catch (e: unknown) {
      if (gen === loadGen) error = translateError(e);
    } finally {
      if (gen === loadGen) loading = false;
    }
  }

  async function goPath(path: string) {
    if (sessionId == null || sharing) return;
    const gen = ++loadGen;
    loading = true;
    error = null;
    try {
      const view = await navigateShareBrowser(sessionId, path);
      if (gen !== loadGen) return;
      applyView(view);
      const next = new Set(expanded);
      next.add(view.current.id);
      if (view.current.parent_id != null) next.add(view.current.parent_id);
      expanded = next;
    } catch (e: unknown) {
      if (gen === loadGen) error = translateError(e);
    } finally {
      if (gen === loadGen) loading = false;
    }
  }

  function closeDialog() {
    open = false;
  }

  function toggleExpand(entry: ShareBrowserEntry, e: Event) {
    e.stopPropagation();
    if (expanded.has(entry.id)) {
      const next = new Set(expanded);
      next.delete(entry.id);
      expanded = next;
      return;
    }
    if (!loadedKids.has(entry.id)) {
      void showEntry(entry.id, { recordHistory: false });
      return;
    }
    const next = new Set(expanded);
    next.add(entry.id);
    expanded = next;
  }

  function entryLabel(entry: ShareBrowserEntry): string {
    switch (entry.kind) {
      case 'this_pc':
        return IS_WINDOWS ? m.library_explorer_this_pc() : m.library_explorer_computer();
      case 'home': return m.library_explorer_home();
      case 'desktop': return m.library_explorer_desktop();
      case 'documents': return m.library_explorer_documents();
      case 'downloads': return m.library_explorer_downloads();
      case 'music': return m.library_explorer_music();
      case 'pictures': return m.library_explorer_pictures();
      case 'videos': return m.library_explorer_videos();
      case 'drive':
        if (entry.letter) return m.library_explorer_drive({ letter: entry.letter });
        return entry.name;
      default:
        return entry.name;
    }
  }

  function canCheck(entry: ShareBrowserEntry): boolean {
    return entry.share_status === 'shareable' || entry.share_status === 'partial';
  }

  /** Offered to peers: a share itself, or a folder inside one shared whole,
   *  which Ember shares along with it. */
  function isShared(entry: ShareBrowserEntry): boolean {
    return entry.share_status === 'already' || entry.share_status === 'inherited';
  }

  function toggleSelect(entry: ShareBrowserEntry, e?: Event) {
    e?.stopPropagation();
    if (!canCheck(entry) || !entry.path) return;
    const next = new Set(selectedPaths);
    if (next.has(entry.path)) next.delete(entry.path);
    else next.add(entry.path);
    selectedPaths = next;
  }

  let entryByPath = $state(new Map<string, ShareBrowserEntry>());
  let selectedCount = $derived(selectedPaths.size);
  let selectedEntries = $derived(
    [...selectedPaths].map((path) => entryByPath.get(path)).filter((entry): entry is ShareBrowserEntry => entry != null),
  );
  let selectedFileCount = $derived(selectedEntries.filter((entry) => entry.kind === 'file').length);
  let selectedFolderCount = $derived(selectedEntries.length - selectedFileCount);
  let currentShareable = $derived(currentEntry?.share_status === 'shareable');
  let currentPartial = $derived(currentEntry?.share_status === 'partial');

  /**
   * Sharing the open folder takes its subfolders too, as every Ember share
   * does. Unticked, it shares the files directly in it instead, through the
   * folder's allowlist the way a selection of files is shared, which is the
   * nearest thing to eMule's one-folder share. Offered only when the whole
   * listing is loaded, since the files have to be named one by one.
   */
  let includeSubfolders = $state(true);
  let currentSubfolders = $derived(children.filter((entry) => entry.kind !== 'file').length);
  let currentOwnFiles = $derived(children.filter((entry) => entry.kind === 'file' && canCheck(entry)));
  /** `MAX_SHARE_SELECTION` in `share_browser.rs`: one selection names at most this many. */
  const MAX_SHARE_SELECTION = 500;
  let offerSubfolderChoice = $derived(
    selectedCount === 0
      && currentShareable
      && currentSubfolders > 0
      && currentOwnFiles.length <= MAX_SHARE_SELECTION
      && !truncated
      && !loading,
  );
  let ownFilesOnly = $derived(offerSubfolderChoice && !includeSubfolders);

  let shareIds = $derived.by(() => {
    if (selectedCount > 0) {
      return [...selectedPaths].map((path) => idByPath.get(path)).filter((id): id is number => id != null);
    }
    if (ownFilesOnly) return currentOwnFiles.map((entry) => entry.id);
    return currentEntry && (currentShareable || currentPartial) ? [currentEntry.id] : [];
  });
  let shareDisabled = $derived(sharing || loading || shareIds.length === 0);
  let shareLabel = $derived.by(() => {
    if (sharing) return m.library_explorer_sharing();
    if (ownFilesOnly) {
      return plural(currentOwnFiles.length, {
        one: m.library_explorer_share_file_one,
        other: () => m.library_explorer_share_file_other({ count: currentOwnFiles.length }),
      });
    }
    if (selectedCount === 0) {
      if (currentPartial) return m.library_explorer_share_rest();
      if (currentShareable) return m.library_explorer_share_folder();
      return m.library_explorer_share();
    }
    if (selectedFileCount > 0 && selectedFolderCount === 0) {
      return plural(selectedFileCount, {
        one: m.library_explorer_share_file_one,
        other: () => m.library_explorer_share_file_other({ count: selectedFileCount }),
      });
    }
    if (selectedFileCount === 0 && selectedFolderCount === 1 && selectedEntries[0]?.share_status === 'partial') {
      return m.library_explorer_share_rest();
    }
    if (selectedFileCount === 0 && selectedFolderCount === 1) return m.library_explorer_share_folder();
    return m.library_explorer_share_other({ count: selectedCount });
  });
  let shareOutcome = $derived.by(() => {
    if (ownFilesOnly) {
      return currentOwnFiles.length === 0
        ? m.library_explorer_outcome_no_own_files()
        : m.library_explorer_outcome_own_files({ count: currentOwnFiles.length });
    }
    if (selectedCount === 0) {
      if (currentPartial) return m.library_explorer_outcome_rest();
      if (currentShareable) return m.library_explorer_outcome_folder();
      if (currentEntry?.share_status === 'inherited') return m.library_explorer_outcome_inherited();
      return m.library_explorer_choose();
    }
    if (selectedFileCount > 0 && selectedFolderCount === 0) return m.library_explorer_outcome_files();
    if (selectedFileCount === 0 && selectedEntries.every((entry) => entry.share_status === 'partial')) {
      return m.library_explorer_outcome_rest();
    }
    if (selectedFileCount === 0) return m.library_explorer_outcome_folder();
    return m.library_explorer_outcome_mixed();
  });

  /**
   * What the Share button is about to offer. Files carry their size from the
   * listing; folders are counted by the backend, by the rules the scan will
   * use, so the total is known before anything is shared. A count that runs
   * out of time is shown as a lower bound rather than held back.
   */
  type ShareSummary = {
    files: number;
    bytes: number;
    /** `exact`: the total. `counting`: folders are still being walked.
     *  `lower_bound`: the walk stopped early. `uncounted`: it failed, so
     *  `folders` are named without their contents. */
    state: 'exact' | 'counting' | 'lower_bound' | 'uncounted';
    folders: number;
    /** The folders are inside the open folder rather than picked one by one. */
    subfolders: boolean;
  };

  const totalBytes = (files: ShareBrowserEntry[]) => files.reduce((sum, f) => sum + (f.size ?? 0), 0);

  /** Folders whose contents the summary needs counted. Sharing the open folder
   *  counts it whole, which covers its own files and any the listing cut off. */
  let measureIds = $derived.by((): number[] => {
    if (shareIds.length === 0) return [];
    if (selectedCount > 0) {
      return selectedEntries
        .filter((entry) => entry.kind !== 'file')
        .map((entry) => idByPath.get(entry.path))
        .filter((id): id is number => id != null);
    }
    if (ownFilesOnly || !currentEntry) return [];
    return [currentEntry.id];
  });
  let measureKey = $derived(`${sessionId}:${[...measureIds].sort((a, b) => a - b).join(',')}`);

  type Measured = ShareBrowserMeasure & { failed: boolean };
  /** Per session: going back to a folder, or re-ticking the same selection,
   *  answers at once instead of walking the tree again. */
  let measureCache = new Map<string, Measured>();
  let measured = $state<{ key: string; result: Measured } | null>(null);

  $effect(() => {
    // Keyed on the string alone. `measureIds` is a fresh array whenever the
    // listing grows, which browsing with folders ticked does on every step,
    // and restarting the walk each time would keep a big one from finishing.
    const key = measureKey;
    const ids = untrack(() => measureIds);
    const id = sessionId;
    if (id == null || ids.length === 0) return;
    const cached = measureCache.get(key);
    if (cached) {
      measured = { key, result: cached };
      return;
    }
    let stale = false;
    // Ticking several boxes in a row should start one walk, not one per box.
    const timer = setTimeout(() => {
      measureShareBrowserEntries(id, ids)
        .then((result) => ({ ...result, failed: false }))
        .catch(() => ({ files: 0, bytes: 0, complete: false, failed: true }))
        .then((result) => {
          if (stale) return;
          // An early stop is worth another try next time; a finished count is not.
          if (result.complete) measureCache.set(key, result);
          measured = { key, result };
        });
    }, 200);
    return () => {
      stale = true;
      clearTimeout(timer);
    };
  });

  let measurement = $derived(measured?.key === measureKey ? measured.result : null);

  let shareSummary = $derived.by((): ShareSummary | null => {
    if (shareIds.length === 0) return null;
    const wholeFolder = selectedCount === 0 && !ownFilesOnly;
    const listed = selectedCount > 0
      ? selectedEntries.filter((entry) => entry.kind === 'file')
      : ownFilesOnly ? currentOwnFiles : [];
    const known = { files: listed.length, bytes: totalBytes(listed) };
    if (measureIds.length === 0) {
      return { ...known, state: 'exact', folders: 0, subfolders: false };
    }
    if (!measurement) {
      return { ...known, state: 'counting', folders: measureIds.length, subfolders: false };
    }
    if (measurement.failed) {
      // What the listing alone can say: the open folder's own files, and how
      // many folders are left for the scan to count.
      return wholeFolder
        ? {
            files: currentOwnFiles.length,
            bytes: totalBytes(currentOwnFiles),
            state: 'uncounted',
            folders: currentSubfolders,
            subfolders: true,
          }
        : { ...known, state: 'uncounted', folders: measureIds.length, subfolders: false };
    }
    return {
      files: known.files + measurement.files,
      bytes: known.bytes + measurement.bytes,
      state: measurement.complete ? 'exact' : 'lower_bound',
      folders: 0,
      subfolders: false,
    };
  });

  let summaryFiles = $derived.by(() => {
    const count = shareSummary?.files ?? 0;
    if (shareSummary?.state === 'lower_bound') {
      return m.library_explorer_summary_files_at_least({ count: formatNumber(count) });
    }
    return plural(count, {
      one: m.library_explorer_summary_files_one,
      other: () => m.library_explorer_summary_files_other({ count: formatNumber(count) }),
    });
  });
  let summarySize = $derived(
    shareSummary
      ? `${formatBytes(shareSummary.bytes)}${shareSummary.state === 'lower_bound' ? '+' : ''}`
      : '',
  );
  let summaryFolders = $derived.by(() => {
    if (!shareSummary) return '';
    const { folders: count, subfolders } = shareSummary;
    if (subfolders) {
      return plural(count, {
        one: m.library_explorer_summary_subfolders_one,
        other: () => m.library_explorer_summary_subfolders_other({ count: formatNumber(count) }),
      });
    }
    return plural(count, {
      one: m.library_explorer_summary_folders_one,
      other: () => m.library_explorer_summary_folders_other({ count: formatNumber(count) }),
    });
  });
  let summaryHint = $derived.by(() => {
    switch (shareSummary?.state) {
      case 'lower_bound': return m.library_explorer_summary_incomplete();
      case 'uncounted': return shareSummary.folders > 0 ? m.library_explorer_summary_pending() : null;
      default: return null;
    }
  });

  type TreeRow = { entry: ShareBrowserEntry; depth: number; isExpanded: boolean; canExpand: boolean };

  let treeRows = $derived.by(() => {
    const rows: TreeRow[] = [];
    if (!rootEntry) return rows;
    const walk = (entry: ShareBrowserEntry, depth: number) => {
      if (entry.kind === 'file') return;
      const kids = loadedKids.get(entry.id);
      const folderKids = kids?.filter((kid) => kid.kind !== 'file');
      const isExpanded = expanded.has(entry.id);
      const canExpand = kids === undefined || (folderKids?.length ?? 0) > 0 || entry.kind === 'this_pc';
      rows.push({ entry, depth, isExpanded, canExpand });
      if (isExpanded && folderKids) {
        for (const kid of folderKids) walk(kid, depth + 1);
      }
    };
    walk(rootEntry, 0);
    return rows;
  });

  async function shareSelected() {
    if (sessionId == null || shareIds.length === 0 || sharing) return;
    sharing = true;
    error = null;
    try {
      const result = await shareBrowserSelection(sessionId, shareIds);
      onshared?.(result);
      open = false;
    } catch (e: unknown) {
      error = translateError(e);
    } finally {
      sharing = false;
    }
  }

  async function useSystemDialog() {
    const id = sessionId;
    open = false;
    if (id != null) void closeShareBrowser(id).catch(() => {});
    try {
      const result = await addSharedFolder();
      onshared?.(result);
    } catch (e: unknown) {
      onerror?.(e);
    }
  }

  function goUp() {
    if (!currentEntry?.parent_id || loading || sharing) return;
    void showEntry(currentEntry.parent_id);
  }

  function goBack() {
    if (history.length === 0 || loading || sharing) return;
    const next = [...history];
    const id = next.pop()!;
    history = next;
    void showEntry(id, { recordHistory: false });
  }

  function onDialogKey(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      // Mid-share the dialog is already unclosable by click or button; letting
      // Escape through would unmount it while the selection is still being
      // added and leave the Library with no report of what happened.
      if (!sharing) closeDialog();
      return;
    }
    if (e.key === 'Backspace' && e.target instanceof HTMLInputElement) return;
    if (e.key === 'Backspace' || ((e.altKey || e.metaKey) && e.key === 'ArrowUp')) {
      e.preventDefault();
      goUp();
      return;
    }
    if ((e.altKey || e.metaKey) && e.key === 'ArrowLeft') {
      e.preventDefault();
      goBack();
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      void shareSelected();
      return;
    }
    trapTabKey(e, dialogEl);
  }

  function statusLabel(entry: ShareBrowserEntry): string | null {
    switch (entry.share_status) {
      case 'already': return m.library_explorer_already();
      case 'partial': {
        const count = entry.shared_count ?? 0;
        if (count === 0) return m.library_explorer_partial_none();
        return plural(count, {
          one: m.library_explorer_partial_one,
          other: () => m.library_explorer_partial_other({ count }),
        });
      }
      case 'inherited': return m.library_explorer_inherited();
      case 'overlap': return m.library_explorer_overlap();
      case 'contains_shared': return m.library_explorer_contains_shared();
      case 'blocked':
        // Drives are listed to be opened, never shared — every one of them
        // carrying a warning badge would be noise. Their checkbox is already
        // disabled, which is the whole message.
        return entry.kind === 'drive' || entry.kind === 'this_pc'
          ? null
          : m.library_explorer_blocked();
      default: return null;
    }
  }

  function folderGlyph(kind: ShareBrowserKind) {
    return kind === 'drive' || kind === 'this_pc' ? 'drive' : 'folder';
  }
</script>

{#if open}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="modal-overlay"
    bind:this={overlayEl}
    role="dialog"
    aria-modal="true"
    aria-labelledby="share-explorer-title"
    tabindex="-1"
    onclick={(e) => { if (e.target === e.currentTarget && !sharing) closeDialog(); }}
    onkeydown={onDialogKey}
    transition:fade={{ duration: prefersReducedMotion.current ? 0 : 150 }}
  >
    <div
      class="modal-content explorer"
      bind:this={dialogEl}
      transition:scale={{ start: 0.96, opacity: 0, duration: prefersReducedMotion.current ? 0 : 200 }}
    >
      <div class="modal-header">
        <span id="share-explorer-title" class="modal-title">{m.library_add_folder_title()}</span>
        <button type="button" class="icon-close" onclick={closeDialog} aria-label={m.common_close()} disabled={sharing}>
          <IconX size={15} />
        </button>
      </div>

      <div class="toolbar">
        <button type="button" class="tool-btn" onclick={goBack} disabled={history.length === 0 || loading || sharing} title={m.library_explorer_back()} aria-label={m.library_explorer_back()}>
          <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M10 3 L5 8 L10 13" />
          </svg>
        </button>
        <button type="button" class="tool-btn" onclick={goUp} disabled={!currentEntry?.parent_id || loading || sharing} title={m.library_explorer_up()} aria-label={m.library_explorer_up()}>
          <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M8 12 V4" /><path d="M4 8 L8 4 L12 8" />
          </svg>
        </button>
        <form class="path-form" onsubmit={(e) => { e.preventDefault(); void goPath(pathDraft); }}>
          <input
            bind:this={pathInputEl}
            class="path-input"
            type="text"
            bind:value={pathDraft}
            aria-label={m.library_explorer_path_aria()}
            placeholder={IS_WINDOWS ? m.library_explorer_this_pc() : m.library_explorer_computer()}
            disabled={sharing}
          />
        </form>
      </div>

      {#if error}
        <div class="error" role="alert">{error}</div>
      {/if}

      <div class="panes">
        <div class="tree" role="tree" aria-label={m.library_explorer_tree_aria()}>
          {#each treeRows as row (row.entry.id)}
            <div
              class="tree-row"
              bind:this={treeRowEls[row.entry.id]}
              class:active={currentEntry?.id === row.entry.id}
              class:shared={isShared(row.entry)}
              style="padding-left: {8 + row.depth * 14}px"
              role="treeitem"
              aria-level={row.depth + 1}
              aria-expanded={row.canExpand ? row.isExpanded : undefined}
              aria-selected={currentEntry?.id === row.entry.id}
              tabindex="0"
              onclick={() => void showEntry(row.entry.id, { recordHistory: true })}
              onkeydown={(e) => {
                // Leave the chevron button's own Enter/Space activation alone.
                if (e.target !== e.currentTarget) return;
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  void showEntry(row.entry.id);
                } else if (e.key === 'ArrowRight' && row.canExpand && !row.isExpanded) {
                  e.preventDefault();
                  toggleExpand(row.entry, e);
                } else if (e.key === 'ArrowLeft' && row.isExpanded) {
                  e.preventDefault();
                  toggleExpand(row.entry, e);
                }
              }}
            >
              {#if row.canExpand}
                <button
                  type="button"
                  class="chevron"
                  class:open={row.isExpanded}
                  onclick={(e) => toggleExpand(row.entry, e)}
                  aria-label={row.isExpanded ? m.library_folder_collapse() : m.library_folder_expand()}
                >
                  <svg viewBox="0 0 12 12" width="10" height="10" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M4 2.5 L8.5 6 L4 9.5" />
                  </svg>
                </button>
              {:else}
                <span class="chevron-spacer"></span>
              {/if}
              <span class="glyph" data-kind={folderGlyph(row.entry.kind)} aria-hidden="true">
                {#if row.entry.kind === 'drive' || row.entry.kind === 'this_pc'}
                  <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="2" y="4" width="12" height="8" rx="1.2"/><path d="M5 10h2"/></svg>
                {:else}
                  <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M2 4.5a1 1 0 0 1 1-1h3l1.5 1.5H13a1 1 0 0 1 1 1V12a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1z"/></svg>
                {/if}
              </span>
              <span class="tree-name">{entryLabel(row.entry)}</span>
            </div>
          {/each}
        </div>

        <div class="list" bind:this={listEl} role="group" aria-label={m.library_explorer_list_aria()} aria-busy={loading}>
          {#if loading && children.length === 0}
            <div class="empty">{m.library_loading_ellipsis()}</div>
          {:else if children.length === 0}
            <div class="empty">{m.library_explorer_empty()}</div>
          {:else}
            <div class="list-head">
              <span></span>
              <span>{m.browse_col_name()}</span>
              <span class="list-size">{m.library_col_size()}</span>
            </div>
            {#each children as entry (entry.id)}
              {@const badge = statusLabel(entry)}
              <div class="list-row" class:shared={isShared(entry)} class:file={entry.kind === 'file'}>
                <input
                  type="checkbox"
                  checked={selectedPaths.has(entry.path) || isShared(entry)}
                  disabled={!canCheck(entry) || sharing}
                  onchange={() => toggleSelect(entry)}
                  aria-label={entryLabel(entry)}
                />
                <button
                  type="button"
                  class="list-open"
                  onclick={() => {
                    if (entry.kind === 'file') toggleSelect(entry);
                    else void showEntry(entry.id);
                  }}
                  title={entry.path}
                >
                  <span class="glyph" aria-hidden="true">
                    {#if entry.kind === 'file'}
                      <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"><path d="M4 2.5h5l3 3V13a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1z"/><path d="M9 2.5V6h3"/></svg>
                    {:else}
                      <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M2 4.5a1 1 0 0 1 1-1h3l1.5 1.5H13a1 1 0 0 1 1 1V12a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1z"/></svg>
                    {/if}
                  </span>
                  <span class="list-name">{entryLabel(entry)}</span>
                </button>
                {#if badge}
                  <span
                    class="badge"
                    class:already={isShared(entry)}
                    class:partial={entry.share_status === 'partial'}
                    class:warn={entry.share_status === 'overlap'
                      || entry.share_status === 'contains_shared'
                      || entry.share_status === 'blocked'}
                  >{badge}</span>
                {:else if entry.kind === 'file' && entry.size != null}
                  <span class="list-size">{formatBytes(entry.size)}</span>
                {:else}
                  <span class="list-size"></span>
                {/if}
              </div>
            {/each}
            {#if truncated}
              <div class="empty">{m.library_explorer_truncated({ count: formatNumber(children.length) })}</div>
            {/if}
          {/if}
        </div>
      </div>

      <div class="modal-footer">
        {#if offerSubfolderChoice}
          <label class="subfolder-choice">
            <input type="checkbox" bind:checked={includeSubfolders} disabled={sharing} />
            <span>{m.library_explorer_include_subfolders({ count: currentSubfolders })}</span>
          </label>
        {/if}
        <!-- Always rendered, so the buttons below keep their place when the
             selection empties and the summary has nothing to say. -->
        <div class="share-summary" aria-live="polite">
          {#if shareSummary}
            {@const counting = shareSummary.state === 'counting'}
            {#if !counting || shareSummary.files > 0}
              <span class="summary-item">
                <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" aria-hidden="true"><path d="M4 2.5h5l3 3V13a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1z"/><path d="M9 2.5V6h3"/></svg>
                {summaryFiles}
              </span>
            {/if}
            {#if shareSummary.files > 0}
              <span class="summary-sep" aria-hidden="true">·</span>
              <span class="summary-item summary-size">{summarySize}</span>
            {/if}
            {#if counting}
              <span class="summary-counting">
                <span class="spinner xs current" aria-hidden="true"></span>
                {m.library_explorer_summary_counting()}
              </span>
            {:else if shareSummary.folders > 0}
              {#if shareSummary.files > 0}
                <span class="summary-sep" aria-hidden="true">·</span>
              {/if}
              <span class="summary-item">
                <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true"><path d="M2 4.5a1 1 0 0 1 1-1h3l1.5 1.5H13a1 1 0 0 1 1 1V12a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1z"/></svg>
                {summaryFolders}
              </span>
            {/if}
            {#if summaryHint}
              <span class="summary-hint">{summaryHint}</span>
            {/if}
          {/if}
        </div>
        <p class="selection-meta">{shareOutcome}</p>
        <div class="footer-actions">
          <button type="button" class="ghost footer-fallback" onclick={useSystemDialog} disabled={sharing}>{m.library_explorer_system_dialog()}</button>
          <button type="button" class="ghost" onclick={closeDialog} disabled={sharing}>{m.common_cancel()}</button>
          <button type="button" onclick={() => void shareSelected()} disabled={shareDisabled}>
            {shareLabel}
          </button>
        </div>
      </div>
    </div>
  </div>
{/if}

<style>
  .modal-overlay {
    position: fixed;
    inset: 0;
    z-index: 10000;
    background: var(--overlay-bg);
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .modal-content {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: inset 0 1px 0 var(--surface-highlight), var(--shadow-lg);
    display: flex;
    flex-direction: column;
    max-height: 85vh;
  }
  /* Fixed, not content-sized. Every folder holds a different number of items,
     and letting the dialog grow to fit meant the toolbar, the row under the
     pointer, and the Share button all moved on each navigation. */
  .explorer {
    width: min(920px, calc(100vw - 2rem));
    height: min(660px, calc(100vh - 3rem));
  }
  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
  }
  .modal-title { font-weight: 600; font-size: var(--font-size-lg); }
  .toolbar {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 10px 12px;
    padding: 4px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  /* Name the element so this beats the global button rule. That rule's
     padding is wider than these squares, which was clipping both arrows. */
  button.tool-btn {
    width: 28px;
    height: 28px;
    padding: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-primary);
    cursor: pointer;
    transform: none;
    opacity: 1;
  }
  button.tool-btn svg {
    width: 14px;
    height: 14px;
    min-width: 14px;
    min-height: 14px;
    flex-shrink: 0;
    display: block;
    stroke: currentColor;
  }
  button.tool-btn:disabled {
    color: var(--text-muted);
    background: transparent;
    opacity: 1;
    cursor: default;
  }
  button.tool-btn:not(:disabled):hover,
  button.tool-btn:not(:disabled):active:not(:disabled) {
    color: var(--text-primary);
    background: var(--bg-hover);
    transform: none;
  }
  .path-form { flex: 1; min-width: 0; }
  .path-input {
    width: 100%;
    height: 28px;
    padding: 0 8px;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-primary);
    font: inherit;
    font-size: var(--font-size-md);
  }
  .path-input:focus {
    outline: none;
    background: var(--bg-secondary);
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-halo);
  }
  .error {
    margin: 0 12px 10px;
    padding: 6px 8px;
    font-size: var(--font-size-sm);
    color: var(--badge-danger-text);
    background: color-mix(in srgb, var(--danger) 10%, var(--bg-secondary));
    border: 1px solid color-mix(in srgb, var(--danger) 35%, var(--border));
    border-radius: var(--radius-sm);
  }
  .panes {
    display: grid;
    grid-template-columns: minmax(180px, 34%) 1fr;
    gap: 0;
    min-height: 0;
    flex: 1;
    margin: 0 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    overflow: hidden;
  }
  .tree, .list {
    overflow: auto;
    min-height: 0;
  }
  .tree {
    border-right: 1px solid var(--border);
    background: var(--bg-surface);
    padding: 4px;
    border-radius: var(--radius-md) 0 0 var(--radius-md);
  }
  .tree-row, .list-row {
    display: flex;
    align-items: center;
    gap: 6px;
    min-height: 32px;
    padding: 2px 8px;
    font-size: var(--font-size-md);
    color: var(--text-secondary);
    cursor: pointer;
    border-radius: var(--radius-sm);
  }
  .tree-row:hover, .list-row:hover { background: var(--bg-hover); color: var(--text-primary); }
  .tree-row.active {
    background: color-mix(in srgb, var(--accent) 14%, var(--bg-secondary));
    color: var(--text-primary);
    font-weight: 600;
  }
  .tree-row.shared .tree-name, .list-row.shared .list-name { color: var(--accent); }
  .list-row.file .glyph { color: var(--text-muted); }
  .chevron, .chevron-spacer {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: none;
    background: none;
    color: inherit;
    padding: 0;
    cursor: pointer;
  }
  .chevron.open { transform: rotate(90deg); }
  .glyph {
    display: inline-flex;
    color: var(--accent);
    flex-shrink: 0;
  }
  .tree-name, .list-name {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .list-head, .list-row {
    display: grid;
    grid-template-columns: 22px minmax(0, 1fr) max-content;
    column-gap: 8px;
  }
  .list-head {
    position: sticky;
    top: 0;
    z-index: 1;
    min-height: 32px;
    padding: 6px 10px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    border-radius: 0;
    color: var(--text-muted);
    font-size: var(--font-size-xs);
    font-weight: 600;
    letter-spacing: 0.02em;
  }
  .list-row { padding: 2px 8px; cursor: default; }
  .list-row input {
    margin: 0;
    width: 14px;
    height: 14px;
    accent-color: var(--accent);
    justify-self: center;
  }
  .list-size {
    justify-self: end;
    font-size: var(--font-size-xs);
    font-variant-numeric: tabular-nums;
    color: var(--text-muted);
    white-space: nowrap;
  }
  .list-row .badge { margin-left: 0; justify-self: end; }
  /* Opens the folder. A real button so Tab and Enter work without a roving
     tabindex, and so the checkbox beside it stays independently reachable. */
  .list-open {
    display: flex;
    align-items: center;
    gap: 6px;
    flex: 1;
    min-width: 0;
    padding: 2px 4px;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: transparent;
    color: inherit;
    font: inherit;
    text-align: left;
    cursor: pointer;
  }
  .list-open:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .badge {
    margin-left: auto;
    font-size: var(--font-size-2xs);
    font-weight: 600;
    padding: 1px 6px;
    border-radius: var(--radius-pill);
    border: 1px solid var(--border);
    color: var(--text-muted);
    flex-shrink: 0;
  }
  .badge.already {
    color: var(--badge-accent-text);
    border-color: color-mix(in srgb, var(--accent) 40%, var(--border));
    background: color-mix(in srgb, var(--accent) 10%, transparent);
  }
  .badge.partial {
    color: var(--text-secondary);
    border-color: var(--border-light);
    background: var(--bg-surface);
  }
  .badge.warn {
    color: var(--badge-warning-text);
    border-color: color-mix(in srgb, var(--warning) 40%, var(--border));
    background: color-mix(in srgb, var(--warning) 10%, transparent);
  }
  .empty {
    padding: 24px 12px;
    text-align: center;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }
  .modal-footer {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 10px;
    padding: 12px 16px 14px;
  }
  .footer-actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .footer-fallback { margin-right: auto; }
  /* Two lines' worth whatever the message says, so the buttons below it do
     not move when the selection changes. */
  .selection-meta {
    margin: 0;
    min-height: 2.8em;
    font-size: var(--font-size-sm);
    line-height: 1.4;
    color: var(--text-secondary);
  }
  .share-summary {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    column-gap: 8px;
    row-gap: 2px;
    min-height: 20px;
    font-size: var(--font-size-md);
    font-weight: 600;
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
  }
  .summary-item {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
  }
  .summary-item svg {
    color: var(--accent);
    flex-shrink: 0;
  }
  .summary-size { color: var(--text-secondary); }
  .summary-sep { color: var(--text-muted); }
  .summary-counting {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--font-size-sm);
    font-weight: 400;
    color: var(--text-muted);
  }
  .summary-hint {
    margin-left: 4px;
    font-size: var(--font-size-sm);
    font-weight: 400;
    color: var(--text-muted);
  }
  .subfolder-choice {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--font-size-md);
    color: var(--text-primary);
    cursor: pointer;
  }
</style>
