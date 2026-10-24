<script lang="ts">
  /*
   * Feeds: follow a publisher's signed list of files and see what is new, or
   * publish lists of your own. See `commands/feeds.rs`.
   */
  import { onMount, untrack } from 'svelte';
  import { page } from '$app/state';
  import { beforeNavigate, goto } from '$app/navigation';
  import { navigatingForDeepLink } from '$lib/deepLinkNavigation';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import {
    createFeed,
    deleteFeed,
    downloadFeedItems,
    FEEDS_CHANGED_EVENT,
    followFeed,
    getFeedItems,
    listMyFeeds,
    markFeedRead,
    publishFeed,
    refreshFeed,
    setFeedAutoDownload,
    setFeedDetails,
    setFeedItems,
    unfollowFeed,
    type FeedItem,
    type FollowedFeed,
    type FollowedItem,
    type OwnFeed,
  } from '$lib/api/feeds';
  import type { FileInfo } from '$lib/types';
  import FeedFilePicker from '$lib/components/FeedFilePicker.svelte';
  import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
  import IconX from '$lib/components/IconX.svelte';
  import { followedFeeds, refreshFollowedFeeds } from '$lib/stores/feeds';
  import { appSettings } from '$lib/stores/settings';
  import { toastError, toastSuccess } from '$lib/stores/toast';
  import { translateError } from '$lib/i18n';
  import { formatBytes, formatNumber, formatRelativeTime } from '$lib/utils';
  import { extensionFromPath, fileTypeFilterLabel, fileTypeKey, type FileTypeKey } from '$lib/fileTypes';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import * as m from '$lib/paraglide/messages';

  /** The backend's limits, in UTF-8 bytes (`network/ember/feed.rs`). */
  const TITLE_MAX = 64;
  const DESCRIPTION_MAX = 256;
  const NOTE_MAX = 256;
  const FEED_ITEMS_MAX = 2000;
  /** Past this many feeds the list gets a search box. */
  const LIST_SEARCH_FROM = 6;

  type Tab = 'following' | 'mine';
  let tab = $state<Tab>('following');
  let emberOff = $derived($appSettings?.ember_native_enabled === false);
  /** The inline card for following a link or starting a feed. */
  let compose = $state<'follow' | 'create' | null>(null);
  let listQuery = $state('');
  /** Seconds, refreshed each minute so "2 minutes ago" keeps up. */
  let now = $state(Math.floor(Date.now() / 1000));

  function setTab(next: Tab) {
    if (tab === next) return;
    tab = next;
    compose = null;
    listQuery = '';
  }

  function toggleCompose(kind: 'follow' | 'create') {
    compose = compose === kind ? null : kind;
  }

  /** `text` cut to `max` UTF-8 bytes at a character boundary. */
  function fitBytes(text: string, max: number): string {
    const encoder = new TextEncoder();
    if (encoder.encode(text).length <= max) return text;
    let out = '';
    let used = 0;
    for (const ch of text) {
      const size = encoder.encode(ch).length;
      if (used + size > max) break;
      out += ch;
      used += size;
    }
    return out;
  }

  function emberFocused(): boolean {
    return typeof document !== 'undefined' && document.visibilityState === 'visible' && document.hasFocus();
  }

  /** Mid-composition in an input method: clipping now would break it. */
  function composing(e: Event): boolean {
    return (e as InputEvent).isComposing === true;
  }

  /** A steady colour per feed, from its key, so a feed is told apart at a
   *  glance in the list and its header. */
  function hueOf(hex: string): number {
    return (parseInt(hex.slice(0, 4), 16) || 0) % 360;
  }

  function typeOf(name: string): FileTypeKey | '' {
    return fileTypeKey(extensionFromPath(name));
  }

  function ago(ts: number): string {
    return formatRelativeTime(ts, now);
  }

  // ── Following ────────────────────────────────────────────────────────
  let followLink = $state('');
  let following = $state(false);
  let selectedKey = $state<string | null>(null);
  let items = $state<FollowedItem[]>([]);
  let itemsLoading = $state(false);
  let unfollowOpen = $state(false);
  let refreshing = $state(false);
  let downloading = $state(false);
  let autoEnabled = $state(false);
  let autoItemMib = $state(0);
  let autoDayMib = $state(0);
  let autoCategory = $state('');
  let autoOpen = $state(false);
  let autoSaving = $state(false);
  let itemFilter = $state<'all' | 'new'>('all');
  let itemQuery = $state('');

  const keyOf = (f: { publisher: string; salt: string }) => `${f.publisher}/${f.salt}`;
  let selected = $derived($followedFeeds.find((f) => keyOf(f) === selectedKey) ?? null);
  let newItems = $derived(items.filter((i) => i.is_new && !i.removed && !i.downloaded));
  let listedItems = $derived(items.filter((i) => !i.removed));
  let listedSize = $derived(listedItems.reduce((sum, i) => sum + i.size, 0));
  let shownItems = $derived.by(() => {
    const q = itemQuery.trim().toLowerCase();
    return items.filter(
      (i) =>
        (itemFilter === 'all' || (i.is_new && !i.removed)) &&
        (!q || i.name.toLowerCase().includes(q) || i.note.toLowerCase().includes(q)),
    );
  });
  let followedShown = $derived.by(() => {
    const q = listQuery.trim().toLowerCase();
    return q ? $followedFeeds.filter((f) => feedLabel(f).toLowerCase().includes(q)) : $followedFeeds;
  });
  /** What a cap field holds, as saved: an emptied or negative one is 0. */
  const mib = (value: number | null) => Math.max(0, Math.floor(value || 0));
  let autoChanged = $derived(
    !!selected &&
      (mib(autoItemMib) !== selected.auto_max_item_mib ||
        mib(autoDayMib) !== selected.auto_max_day_mib ||
        autoCategory !== selected.auto_category),
  );
  /** New and still listed, downloaded or not: what the New filter shows. */
  let newShownCount = $derived(items.filter((i) => i.is_new && !i.removed).length);

  function feedLabel(f: FollowedFeed): string {
    return f.title.trim() || m.feeds_untitled();
  }

  /** The line under a followed feed's name in the list. */
  function followedSub(f: FollowedFeed): string {
    if (f.state === 'waiting') return m.feeds_state_waiting_short();
    if (f.state === 'fetching') return m.feeds_state_fetching_short();
    if (f.state === 'broken') return m.feeds_state_broken_short();
    return m.feeds_items_count({ count: f.item_count });
  }

  async function follow(link = followLink) {
    const text = link.trim();
    if (!text || following) return;
    following = true;
    try {
      const feed = await followFeed(text);
      followLink = '';
      compose = null;
      await refreshFollowedFeeds();
      selectedKey = keyOf(feed);
      toastSuccess(m.feeds_followed_toast());
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      following = false;
    }
  }

  // A link opened from outside, already confirmed: followed once, then
  // dropped from the address so Back does not follow it again.
  $effect(() => {
    const linked = page.url.searchParams.get('follow');
    if (!linked) return;
    untrack(() => {
      setTab('following');
      void follow(linked);
      const next = new URL(page.url);
      next.searchParams.delete('follow');
      void goto(`${next.pathname}${next.search}${next.hash}`, { replaceState: true, keepFocus: true, noScroll: true }).catch(
        () => {},
      );
    });
  });

  // Something is always open while there is something to open.
  $effect(() => {
    const feeds = $followedFeeds;
    if (feeds.length === 0) return;
    untrack(() => {
      if (!feeds.some((f) => keyOf(f) === selectedKey)) selectedKey = keyOf(feeds[0]);
    });
  });

  let itemsSeq = 0;
  let itemsFor = '';
  async function loadItems(feed: FollowedFeed | null) {
    const seq = ++itemsSeq;
    if (!feed || itemsFor !== keyOf(feed)) {
      // Another feed's files must not show under this one while it loads.
      items = [];
      itemFilter = 'all';
      itemQuery = '';
    }
    if (!feed) {
      itemsFor = '';
      return;
    }
    itemsLoading = true;
    try {
      const rows = await getFeedItems(feed.publisher, feed.salt);
      if (seq !== itemsSeq) return;
      // What was new stays shown as new while the feed stays open, though
      // opening it marks it read.
      const wasNew = new Set(itemsFor === keyOf(feed) ? items.filter((i) => i.is_new).map((i) => i.ed2k) : []);
      items = rows.map((r) => (wasNew.has(r.ed2k) ? { ...r, is_new: true } : r));
      itemsFor = keyOf(feed);
      await markShownRead();
    } catch (e) {
      if (seq === itemsSeq) toastError(translateError(e, m.error_operation_failed()));
    } finally {
      if (seq === itemsSeq) itemsLoading = false;
    }
  }

  /** The feed whose files are on screen is read once seen: not while Ember
   *  is hidden or behind another window, nor from the My feeds tab. */
  async function markShownRead() {
    const feed = selected;
    if (!feed || itemsFor !== keyOf(feed) || tab !== 'following' || feed.unread === 0 || !emberFocused()) return;
    try {
      await markFeedRead(feed.publisher, feed.salt);
      await refreshFollowedFeeds();
    } catch (e) {
      console.warn('feeds: could not mark read', e);
    }
  }

  // The settings shown are the selected feed's, taken when the selection
  // changes, not on every refresh (which would undo an edit in progress).
  let shownSettingsFor: string | null = null;
  $effect(() => {
    const feed = selected;
    if (!feed) {
      shownSettingsFor = null;
      return;
    }
    const key = `${keyOf(feed)}@${feed.followed_at}`;
    if (shownSettingsFor !== key) {
      shownSettingsFor = key;
      autoEnabled = feed.auto_download;
      autoItemMib = feed.auto_max_item_mib;
      autoDayMib = feed.auto_max_day_mib;
      autoCategory = feed.auto_category;
      autoOpen = false;
    }
  });

  // Back on the Following tab, the feed on screen is seen.
  $effect(() => {
    if (tab === 'following') untrack(() => void markShownRead());
  });

  let loadedFor = '';
  $effect(() => {
    const feed = selected;
    const key = feed ? `${keyOf(feed)}@${feed.list_sequence}` : '';
    if (key !== loadedFor) {
      loadedFor = key;
      void untrack(() => loadItems(feed));
    }
  });

  async function saveAuto(): Promise<boolean> {
    const feed = selected;
    if (!feed || autoSaving) return false;
    autoSaving = true;
    try {
      autoItemMib = mib(autoItemMib);
      autoDayMib = mib(autoDayMib);
      await setFeedAutoDownload(feed.publisher, feed.salt, autoEnabled, autoItemMib, autoDayMib, autoCategory);
      await refreshFollowedFeeds();
      return true;
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
      return false;
    } finally {
      autoSaving = false;
    }
  }

  /** The switch saves at once; turning it on opens the limits that go with it. */
  async function toggleAuto(on: boolean) {
    autoEnabled = on;
    if (!(await saveAuto())) {
      autoEnabled = !on;
      return;
    }
    if (on) autoOpen = true;
  }

  async function saveAutoLimits() {
    if (await saveAuto()) toastSuccess(m.feeds_auto_saved());
  }

  async function download(ed2ks: string[]) {
    const feed = selected;
    if (!feed || ed2ks.length === 0 || downloading) return;
    downloading = true;
    try {
      const started = await downloadFeedItems(feed.publisher, feed.salt, ed2ks);
      toastSuccess(m.feeds_downloads_started({ count: started }));
      // Not if the user has opened another feed meanwhile.
      if (selectedKey === keyOf(feed)) await loadItems(feed);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      downloading = false;
    }
  }

  async function refreshSelected() {
    const feed = selected;
    if (!feed || refreshing) return;
    refreshing = true;
    try {
      await refreshFeed(feed.publisher, feed.salt);
      await refreshFollowedFeeds();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      refreshing = false;
    }
  }

  async function doUnfollow() {
    const feed = selected;
    if (!feed) return;
    try {
      await unfollowFeed(feed.publisher, feed.salt);
      selectedKey = null;
      await refreshFollowedFeeds();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      toastSuccess(m.feeds_link_copied());
    } catch {
      toastError(m.error_operation_failed());
    }
  }

  function stateText(f: FollowedFeed): string | null {
    if (f.state === 'waiting') return m.feeds_state_waiting();
    if (f.state === 'fetching') return m.feeds_state_fetching();
    if (f.state === 'broken') return m.feeds_state_broken();
    return null;
  }

  // ── My feeds ─────────────────────────────────────────────────────────
  let mine = $state<OwnFeed[]>([]);
  let mineLoaded = $state(false);
  let newTitle = $state('');
  let newDescription = $state('');
  let creating = $state(false);
  let mineSelected = $state<string | null>(null);
  let editTitle = $state('');
  let editDescription = $state('');
  let editItems = $state<FeedItem[]>([]);
  let dirty = $state(false);
  let saving = $state(false);
  let publishing = $state(false);
  let deleteOpen = $state(false);
  let pickerOpen = $state(false);
  /** What to do once the user agrees to drop unsaved edits. */
  let discardThen = $state<(() => void) | null>(null);
  let leaving = false;

  let busy = $derived(saving || publishing || creating);
  let mineFeed = $derived(mine.find((f) => f.salt === mineSelected) ?? null);
  let inFeed = $derived(new Set(editItems.map((i) => i.ed2k.toLowerCase())));
  let editSize = $derived(editItems.reduce((sum, i) => sum + i.size, 0));
  /** Published, and nothing saved or typed since: nothing to publish. */
  let upToDate = $derived(!!mineFeed && mineFeed.published_at > 0 && !mineFeed.changed && !dirty);
  let mineShown = $derived.by(() => {
    const q = listQuery.trim().toLowerCase();
    return q ? mine.filter((f) => f.title.toLowerCase().includes(q)) : mine;
  });

  async function loadMine() {
    try {
      mine = await listMyFeeds();
      mineLoaded = true;
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  // As on Following: the first feed opens when none is.
  $effect(() => {
    const feeds = mine;
    if (feeds.length === 0) return;
    untrack(() => {
      if (!feeds.some((f) => f.salt === mineSelected) && !dirty) selectMine(feeds[0]);
    });
  });

  /** Run `then` now, or after the user agrees to lose unsaved edits. */
  function unlessDirty(then: () => void) {
    if (dirty) discardThen = then;
    else then();
  }

  function selectMine(feed: OwnFeed) {
    mineSelected = feed.salt;
    editTitle = feed.title;
    editDescription = feed.description;
    editItems = feed.items.map((i) => ({ ...i }));
    dirty = false;
  }

  async function create() {
    if (creating || !newTitle.trim()) return;
    creating = true;
    try {
      const feed = await createFeed(newTitle, newDescription);
      newTitle = '';
      newDescription = '';
      compose = null;
      await loadMine();
      selectMine(feed);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      creating = false;
    }
  }

  function addFiles(files: FileInfo[]) {
    const fresh = files
      .filter((f) => !inFeed.has(f.hash.toLowerCase()))
      .slice(0, Math.max(0, FEED_ITEMS_MAX - editItems.length));
    if (fresh.length === 0) return;
    editItems = [
      ...editItems,
      ...fresh.map((f) => ({ ed2k: f.hash, name: f.name, size: f.size, aich: f.aich_hash, blake3: f.ember_file_hash, note: '' })),
    ];
    dirty = true;
  }

  function move(index: number, step: -1 | 1) {
    const to = index + step;
    if (to < 0 || to >= editItems.length) return;
    const next = editItems.slice();
    [next[index], next[to]] = [next[to], next[index]];
    editItems = next;
    dirty = true;
  }

  function removeItem(index: number) {
    editItems = editItems.filter((_, i) => i !== index);
    dirty = true;
  }

  interface Draft {
    salt: string;
    title: string;
    description: string;
    items: { ed2k: string; note: string }[];
  }

  /** The editor as it stands, taken once so a click elsewhere mid-save
   *  cannot change which feed is saved or published. */
  function draft(): Draft | null {
    if (!mineFeed) return null;
    return {
      salt: mineFeed.salt,
      title: editTitle,
      description: editDescription,
      items: editItems.map((i) => ({ ed2k: i.ed2k, note: i.note })),
    };
  }

  async function saveDraft(d: Draft): Promise<boolean> {
    try {
      await setFeedDetails(d.salt, d.title, d.description);
      await setFeedItems(d.salt, d.items);
      if (mineSelected === d.salt) dirty = false;
      await loadMine();
      return true;
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
      return false;
    }
  }

  async function save() {
    const d = draft();
    if (!d || busy) return;
    saving = true;
    try {
      await saveDraft(d);
    } finally {
      saving = false;
    }
  }

  async function publish() {
    const d = draft();
    if (!d || busy) return;
    publishing = true;
    try {
      if (dirty && !(await saveDraft(d))) return;
      await publishFeed(d.salt);
      await loadMine();
      const feed = mine.find((f) => f.salt === d.salt);
      if (feed && mineSelected === d.salt) selectMine(feed);
      toastSuccess(m.feeds_published_toast());
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      publishing = false;
    }
  }

  async function doDelete() {
    const feed = mineFeed;
    if (!feed) return;
    try {
      await deleteFeed(feed.salt);
      if (mineSelected === feed.salt) {
        mineSelected = null;
        dirty = false;
      }
      await loadMine();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  beforeNavigate((nav) => {
    if (leaving || !dirty || nav.willUnload) return;
    const to = nav.to?.url;
    if (!to || to.pathname === nav.from?.url.pathname) return;
    nav.cancel();
    // A deep link waits for Review instead; Discard would run it a second time.
    if (navigatingForDeepLink()) return;
    const delta = nav.type === 'popstate' ? nav.delta : undefined;
    if (delta) {
      // Back or Forward: moved through history again, not pushed onto it.
      discardThen = () => {
        leaving = true;
        history.go(delta);
        setTimeout(() => (leaving = false), 1000);
      };
      return;
    }
    discardThen = () => {
      leaving = true;
      void goto(to.href).finally(() => (leaving = false));
    };
  });

  onMount(() => {
    void refreshFollowedFeeds();
    void loadMine();
    let unlisten: UnlistenFn | null = null;
    let alive = true;
    void listen(FEEDS_CHANGED_EVENT, () => void loadMine()).then((fn) => {
      if (alive) unlisten = fn;
      else fn();
    });
    // Seen once the user comes back to Ember.
    const onFocus = () => void markShownRead();
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onFocus);
    const clock = setInterval(() => (now = Math.floor(Date.now() / 1000)), 60_000);
    return () => {
      alive = false;
      unlisten?.();
      clearInterval(clock);
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onFocus);
    };
  });
</script>

{#snippet feedGlyph()}
  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
    <path d="M3 3a10 10 0 0 1 10 10"/><path d="M3 7a6 6 0 0 1 6 6"/><circle cx="3.5" cy="12.5" r="1.2" fill="currentColor" stroke="none"/>
  </svg>
{/snippet}

{#snippet fileIcon(type: FileTypeKey | '')}
  <span class="file-icon" data-type={type || 'Other'} aria-hidden="true">
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round">
      <path d="M4 1.75h5.25L12.5 5v9.25H4z"/><path d="M9 1.75V5.25h3.5"/>
    </svg>
  </span>
{/snippet}

{#snippet searchBox(value: string, set: (v: string) => void, label: string)}
  <div class="search-wrap">
    <span class="search-icon" aria-hidden="true">
      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" width="13" height="13">
        <circle cx="7" cy="7" r="4.5"/><line x1="10.5" y1="10.5" x2="13.5" y2="13.5"/>
      </svg>
    </span>
    <input
      type="search"
      class="search-input"
      {value}
      oninput={(e) => set(e.currentTarget.value)}
      onkeydown={(e) => {
        if (e.key === 'Escape' && value) {
          e.preventDefault();
          set('');
        }
      }}
      placeholder={label}
      aria-label={label}
    />
    {#if value}
      <button type="button" class="search-clear" onclick={() => set('')} title={m.common_clear()} aria-label={m.common_clear()}>
        <IconX size={12} />
      </button>
    {/if}
  </div>
{/snippet}

<div class="page-header">
  <div class="header-title">
    <h2>
      {m.nav_feeds()}
      <span class="beta-badge">{m.common_beta()}</span>
    </h2>
  </div>
  <div class="header-actions">
    <div class="segmented" role="group" aria-label={m.nav_feeds()}>
      <button type="button" aria-pressed={tab === 'following'} class:active={tab === 'following'} onclick={() => setTab('following')}>
        {m.feeds_tab_following()}
        {#if $followedFeeds.length > 0}<span class="seg-count">{formatNumber($followedFeeds.length)}</span>{/if}
      </button>
      <button type="button" aria-pressed={tab === 'mine'} class:active={tab === 'mine'} onclick={() => setTab('mine')}>
        {m.feeds_tab_mine()}
        {#if mine.length > 0}<span class="seg-count">{formatNumber(mine.length)}</span>{/if}
      </button>
    </div>
    {#if tab === 'following'}
      <button type="button" class="primary" aria-expanded={compose === 'follow'} onclick={() => toggleCompose('follow')}>
        {compose === 'follow' ? m.common_cancel() : m.feeds_follow_a_feed()}
      </button>
    {:else}
      <button type="button" class="primary" aria-expanded={compose === 'create'} disabled={busy} onclick={() => toggleCompose('create')}>
        {compose === 'create' ? m.common_cancel() : m.feeds_new_feed()}
      </button>
    {/if}
  </div>
</div>

{#if emberOff}
  <div class="warning-banner" role="status">
    <span><strong>{m.channels_disabled_title()}</strong> · {m.feeds_disabled_body()}</span>
  </div>
{/if}

<div class="page-content feeds-page">
  {#if compose === 'follow' && tab === 'following'}
    <form class="compose-card" onsubmit={(e) => { e.preventDefault(); void follow(); }}>
      <div class="compose-row">
        <div class="compose-input-wrap">
          <span class="compose-input-icon" aria-hidden="true">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M6.5 9.5a3 3 0 0 0 4.2 0l2.1-2.1a3 3 0 0 0-4.2-4.2l-.7.7"/><path d="M9.5 6.5a3 3 0 0 0-4.2 0L3.2 8.6a3 3 0 0 0 4.2 4.2l.7-.7"/>
            </svg>
          </span>
          <input
            type="text"
            class="compose-input"
            bind:value={followLink}
            placeholder={m.feeds_follow_placeholder()}
            aria-label={m.feeds_follow_placeholder()}
            spellcheck="false"
            autocomplete="off"
            onkeydown={(e) => {
              if (e.key === 'Escape') {
                e.preventDefault();
                compose = null;
              }
            }}
            {@attach (el: HTMLInputElement) => el.focus()}
          />
        </div>
        <button type="submit" class="primary" disabled={following || !followLink.trim()}>{m.feeds_follow()}</button>
      </div>
      <p class="compose-hint">{m.feeds_follow_privacy()}</p>
    </form>
  {:else if compose === 'create' && tab === 'mine'}
    <form class="compose-card" onsubmit={(e) => { e.preventDefault(); unlessDirty(() => void create()); }}>
      <div class="compose-row">
        <input
          type="text"
          class="compose-input plain"
          bind:value={newTitle}
          oninput={(e) => {
            if (!composing(e)) newTitle = fitBytes(newTitle, TITLE_MAX);
          }}
          oncompositionend={() => (newTitle = fitBytes(newTitle, TITLE_MAX))}
          onkeydown={(e) => {
            if (e.key === 'Escape') {
              e.preventDefault();
              compose = null;
            }
          }}
          placeholder={m.feeds_title_placeholder()}
          aria-label={m.feeds_title_placeholder()}
          {@attach (el: HTMLInputElement) => el.focus()}
        />
        <input
          type="text"
          class="compose-input plain grow"
          bind:value={newDescription}
          oninput={(e) => {
            if (!composing(e)) newDescription = fitBytes(newDescription, DESCRIPTION_MAX);
          }}
          oncompositionend={() => (newDescription = fitBytes(newDescription, DESCRIPTION_MAX))}
          placeholder={m.feeds_description_placeholder()}
          aria-label={m.feeds_description_placeholder()}
        />
        <button type="submit" class="primary" disabled={creating || !newTitle.trim()}>{m.feeds_create()}</button>
      </div>
      <p class="compose-hint">{m.feeds_publish_public_hint()}</p>
    </form>
  {/if}

  {#if tab === 'following'}
    {#if $followedFeeds.length === 0}
      <div class="empty-card">
        <div class="empty-state">
          <span class="empty-glyph">{@render feedGlyph()}</span>
          <p class="empty-title">{m.feeds_none_followed()}</p>
          <p class="empty-sub">{m.feeds_empty_following_body()}</p>
          {#if compose !== 'follow'}
            <div class="empty-actions">
              <button type="button" class="primary empty-action" onclick={() => (compose = 'follow')}>{m.feeds_follow_a_feed()}</button>
            </div>
          {/if}
        </div>
      </div>
    {:else}
      <div class="workspace">
        <aside class="list-pane" aria-label={m.feeds_tab_following()}>
          {#if $followedFeeds.length >= LIST_SEARCH_FROM}
            {@render searchBox(listQuery, (v) => (listQuery = v), m.feeds_search_feeds())}
          {/if}
          <div class="list-scroll">
            {#each followedShown as feed (keyOf(feed))}
              {@const active = keyOf(feed) === selectedKey}
              <button
                type="button"
                class="feed-row"
                class:active
                class:has-unread={feed.unread > 0}
                aria-current={active ? 'true' : undefined}
                onclick={() => (selectedKey = keyOf(feed))}
              >
                <span class="feed-avatar" style:--feed-hue={hueOf(feed.publisher)}>{@render feedGlyph()}</span>
                <span class="feed-row-text">
                  <span class="feed-row-title"><bdi dir="auto">{feedLabel(feed)}</bdi></span>
                  <span class="feed-row-sub" class:warn={feed.state === 'broken'}>{followedSub(feed)}</span>
                </span>
                {#if feed.unread > 0}
                  <span class="count-pill" aria-hidden="true">{feed.unread > 99 ? '99+' : feed.unread}</span>
                  <span class="sr-only">{m.feeds_unread_title({ count: feed.unread })}</span>
                {/if}
              </button>
            {:else}
              <p class="list-empty">{m.feeds_no_matches()}</p>
            {/each}
          </div>
        </aside>

        <section class="detail-pane">
          {#if selected}
            <header class="detail-head">
              <span class="feed-avatar lg" style:--feed-hue={hueOf(selected.publisher)}>{@render feedGlyph()}</span>
              <div class="detail-title">
                <h3><bdi dir="auto">{feedLabel(selected)}</bdi></h3>
                <p class="detail-meta">
                  <span>{m.feeds_items_count({ count: listedItems.length })}</span>
                  {#if listedSize > 0}<span aria-hidden="true">·</span><span>{formatBytes(listedSize)}</span>{/if}
                  {#if selected.checked_at > 0}
                    <span aria-hidden="true">·</span><span>{m.feeds_checked_at({ when: ago(selected.checked_at) })}</span>
                  {/if}
                </p>
              </div>
              <div class="detail-actions">
                <button
                  type="button"
                  class="icon-btn"
                  class:spinning={refreshing}
                  disabled={refreshing || emberOff}
                  title={m.feeds_refresh()}
                  aria-label={m.feeds_refresh()}
                  onclick={() => void refreshSelected()}
                >
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9"/><polyline points="13.5 2.5 13.5 5.5 10.5 5.5"/>
                  </svg>
                </button>
                <button type="button" class="icon-btn" title={m.feeds_copy_link()} aria-label={m.feeds_copy_link()} onclick={() => void copy(selected!.link)}>
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M6.5 9.5a3 3 0 0 0 4.2 0l2.1-2.1a3 3 0 0 0-4.2-4.2l-.7.7"/><path d="M9.5 6.5a3 3 0 0 0-4.2 0L3.2 8.6a3 3 0 0 0 4.2 4.2l.7-.7"/>
                  </svg>
                </button>
                <button type="button" class="pill-btn danger-hover" onclick={() => (unfollowOpen = true)}>{m.feeds_unfollow()}</button>
              </div>
            </header>
            {#if selected.description}
              <p class="detail-description"><bdi dir="auto">{selected.description}</bdi></p>
            {/if}

            {#if stateText(selected)}
              <div class="state-strip" class:tone-warning={selected.state === 'broken'} role="status">
                {#if selected.state === 'broken'}
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M8 2.5 14 13H2z"/><line x1="8" y1="6.5" x2="8" y2="9.5"/><line x1="8" y1="11.5" x2="8" y2="11.6"/>
                  </svg>
                {:else}
                  <span class="spinner xs" aria-hidden="true"></span>
                {/if}
                <span>{stateText(selected)}</span>
              </div>
            {/if}

            <div class="auto-card" class:on={selected.auto_download}>
              <div class="auto-head">
                <span class="auto-icon" aria-hidden="true">
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M8 2v8M4.5 6.5 8 10l3.5-3.5"/><path d="M2.5 11.5v1.75h11V11.5"/>
                  </svg>
                </span>
                <button type="button" class="auto-title" aria-expanded={autoOpen} onclick={() => (autoOpen = !autoOpen)}>
                  <span class="auto-name">{m.feeds_auto_title()}</span>
                  <span class="auto-state">{selected.auto_download ? m.feeds_auto_on() : m.feeds_auto_off()}</span>
                  <svg class="chevron" class:open={autoOpen} viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <polyline points="4 6 8 10 12 6"/>
                  </svg>
                </button>
                <ToggleSwitch
                  checked={autoEnabled}
                  disabled={autoSaving}
                  ariaLabel={m.feeds_auto_enable()}
                  onchange={(on) => void toggleAuto(on)}
                />
              </div>
              {#if autoOpen}
                <div class="auto-body">
                  <div class="auto-grid">
                    <label class="field">
                      <span class="field-label">{m.feeds_auto_max_item()}</span>
                      <input type="number" min="0" bind:value={autoItemMib} />
                    </label>
                    <label class="field">
                      <span class="field-label">{m.feeds_auto_max_day()}</span>
                      <input type="number" min="0" bind:value={autoDayMib} />
                    </label>
                    <label class="field">
                      <span class="field-label">{m.feeds_auto_category()}</span>
                      <input type="text" bind:value={autoCategory} maxlength="256" />
                    </label>
                  </div>
                  <div class="auto-foot">
                    <p class="hint">{m.feeds_auto_hint()}</p>
                    <button type="button" class="secondary" disabled={!autoChanged || autoSaving} onclick={() => void saveAutoLimits()}>
                      {m.feeds_save()}
                    </button>
                  </div>
                </div>
              {/if}
            </div>

            <div class="files-toolbar">
              <h4 class="section-label">{m.feeds_files_heading()}</h4>
              <div class="segmented small" role="group" aria-label={m.feeds_files_heading()}>
                <button type="button" aria-pressed={itemFilter === 'all'} class:active={itemFilter === 'all'} onclick={() => (itemFilter = 'all')}>
                  {m.feeds_filter_all()}
                </button>
                <button type="button" aria-pressed={itemFilter === 'new'} class:active={itemFilter === 'new'} onclick={() => (itemFilter = 'new')}>
                  {m.feeds_filter_new_only()}
                  {#if newShownCount > 0}<span class="seg-count">{formatNumber(newShownCount)}</span>{/if}
                </button>
              </div>
              {#if items.length > LIST_SEARCH_FROM}
                <div class="files-search">
                  {@render searchBox(itemQuery, (v) => (itemQuery = v), m.browse_filter_placeholder())}
                </div>
              {/if}
              <span class="toolbar-spacer"></span>
              {#if newItems.length > 0}
                <button type="button" class="primary sm-btn" disabled={downloading} onclick={() => void download(newItems.map((i) => i.ed2k))}>
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M8 2v9M4 8l4 4 4-4"/><line x1="3" y1="14" x2="13" y2="14"/>
                  </svg>
                  {m.feeds_download_all_new({ count: newItems.length })}
                </button>
              {/if}
            </div>

            <div class="file-list">
              {#if itemsLoading && items.length === 0}
                <div class="file-list-empty"><span class="spinner xs" aria-hidden="true"></span></div>
              {:else if items.length === 0}
                <div class="file-list-empty">{m.feeds_no_items()}</div>
              {:else if shownItems.length === 0}
                <div class="file-list-empty">{itemFilter === 'new' && !itemQuery.trim() ? m.feeds_no_new() : m.browse_no_match()}</div>
              {/if}
              {#each shownItems as item (item.ed2k)}
                {@const type = typeOf(item.name)}
                <div class="file-row" class:removed={item.removed} class:is-new={item.is_new && !item.removed}>
                  {@render fileIcon(type)}
                  <div class="file-main">
                    <span class="file-name">
                      <bdi dir="auto">{item.name}</bdi>
                      {#if item.is_new && !item.removed}<span class="badge sm tone-accent">{m.feeds_badge_new()}</span>{/if}
                      {#if item.removed}<span class="badge sm tone-muted">{m.feeds_badge_removed()}</span>{/if}
                    </span>
                    <span class="file-meta">
                      <span>{formatBytes(item.size)}</span>
                      {#if type}<span aria-hidden="true">·</span><span>{fileTypeFilterLabel(type)}</span>{/if}
                      {#if item.first_seen > 0}<span aria-hidden="true">·</span><span>{m.feeds_item_added_at({ when: ago(item.first_seen) })}</span>{/if}
                    </span>
                    {#if item.note}
                      <span class="file-note"><bdi dir="auto">{item.note}</bdi></span>
                    {/if}
                  </div>
                  {#if item.downloaded}
                    <span class="row-done" title={m.feeds_badge_downloaded()}>
                      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <polyline points="3 8 7 12 13 4"/>
                      </svg>
                      <span>{m.feeds_badge_downloaded()}</span>
                    </span>
                  {:else}
                    <button
                      type="button"
                      class="row-btn"
                      disabled={downloading}
                      aria-label={m.feeds_download_named({ name: item.name })}
                      onclick={() => void download([item.ed2k])}
                    >
                      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M8 2v9M4 8l4 4 4-4"/><line x1="3" y1="14" x2="13" y2="14"/>
                      </svg>
                      <span>{m.feeds_download()}</span>
                    </button>
                  {/if}
                </div>
              {/each}
            </div>
          {:else}
            <div class="empty-state compact"><p class="empty-sub">{m.feeds_pick_one()}</p></div>
          {/if}
        </section>
      </div>
    {/if}
  {:else if mineLoaded && mine.length === 0}
    <div class="empty-card">
      <div class="empty-state">
        <span class="empty-glyph">{@render feedGlyph()}</span>
        <p class="empty-title">{m.feeds_none_mine()}</p>
        <p class="empty-sub">{m.feeds_empty_mine_body()}</p>
        {#if compose !== 'create'}
          <div class="empty-actions">
            <button type="button" class="primary empty-action" onclick={() => (compose = 'create')}>{m.feeds_new_feed()}</button>
          </div>
        {/if}
      </div>
    </div>
  {:else if mine.length > 0}
    <div class="workspace">
      <aside class="list-pane" aria-label={m.feeds_tab_mine()}>
        {#if mine.length >= LIST_SEARCH_FROM}
          {@render searchBox(listQuery, (v) => (listQuery = v), m.feeds_search_feeds())}
        {/if}
        <div class="list-scroll">
          {#each mineShown as feed (feed.salt)}
            {@const active = feed.salt === mineSelected}
            <button
              type="button"
              class="feed-row"
              class:active
              aria-current={active ? 'true' : undefined}
              disabled={busy}
              onclick={() => !active && unlessDirty(() => selectMine(feed))}
            >
              <span class="feed-avatar" style:--feed-hue={hueOf(feed.salt)}>{@render feedGlyph()}</span>
              <span class="feed-row-text">
                <span class="feed-row-title"><bdi dir="auto">{feed.title}</bdi></span>
                <span class="feed-row-sub">
                  {feed.published_at > 0 ? m.feeds_published_short({ when: ago(feed.published_at) }) : m.feeds_badge_draft()}
                </span>
              </span>
              {#if feed.published_at === 0}
                <span class="badge sm tone-muted">{m.feeds_badge_draft()}</span>
              {:else if feed.changed || (active && dirty)}
                <span class="badge sm tone-warning">{m.feeds_badge_unpublished()}</span>
              {/if}
            </button>
          {:else}
            <p class="list-empty">{m.feeds_no_matches()}</p>
          {/each}
        </div>
      </aside>

      <section class="detail-pane">
        {#if mineFeed}
          <header class="detail-head">
            <span class="feed-avatar lg" style:--feed-hue={hueOf(mineFeed.salt)}>{@render feedGlyph()}</span>
            <div class="detail-title">
              <input
                type="text"
                class="title-input"
                bind:value={editTitle}
                disabled={busy}
                oninput={(e) => {
                  if (!composing(e)) editTitle = fitBytes(editTitle, TITLE_MAX);
                  dirty = true;
                }}
                oncompositionend={() => (editTitle = fitBytes(editTitle, TITLE_MAX))}
                placeholder={m.feeds_title_placeholder()}
                aria-label={m.feeds_title_placeholder()}
              />
              <p class="detail-meta">
                {#if mineFeed.published_at > 0}
                  <span class="status-dot published" aria-hidden="true"></span>
                  <span>{m.feeds_published_short({ when: ago(mineFeed.published_at) })}</span>
                {:else}
                  <span class="status-dot" aria-hidden="true"></span>
                  <span>{m.feeds_badge_draft()}</span>
                {/if}
                <span aria-hidden="true">·</span>
                <span>{m.feeds_items_count({ count: editItems.length })}</span>
                {#if editSize > 0}<span aria-hidden="true">·</span><span>{formatBytes(editSize)}</span>{/if}
                {#if dirty}<span aria-hidden="true">·</span><span class="unsaved">{m.feeds_unsaved()}</span>{/if}
              </p>
            </div>
            <div class="detail-actions">
              {#if mineFeed.published_at > 0}
                <button type="button" class="icon-btn" title={m.feeds_copy_link()} aria-label={m.feeds_copy_link()} onclick={() => void copy(mineFeed!.link)}>
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M6.5 9.5a3 3 0 0 0 4.2 0l2.1-2.1a3 3 0 0 0-4.2-4.2l-.7.7"/><path d="M9.5 6.5a3 3 0 0 0-4.2 0L3.2 8.6a3 3 0 0 0 4.2 4.2l.7-.7"/>
                  </svg>
                </button>
              {/if}
              <button type="button" class="icon-btn danger-hover" disabled={busy} title={m.feeds_delete()} aria-label={m.feeds_delete()} onclick={() => (deleteOpen = true)}>
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M2.5 4.5h11"/><path d="M6 4.5V3h4v1.5"/><path d="M4 4.5l.7 9h6.6l.7-9"/>
                </svg>
              </button>
            </div>
          </header>
          <textarea
            class="desc-input"
            rows="2"
            bind:value={editDescription}
            disabled={busy}
            oninput={(e) => {
              if (!composing(e)) editDescription = fitBytes(editDescription, DESCRIPTION_MAX);
              dirty = true;
            }}
            oncompositionend={() => (editDescription = fitBytes(editDescription, DESCRIPTION_MAX))}
            placeholder={m.feeds_description_placeholder()}
            aria-label={m.feeds_description_placeholder()}
          ></textarea>

          {#if mineFeed.published_at === 0}
            <div class="state-strip" role="status">
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true">
                <circle cx="8" cy="8" r="6"/><line x1="8" y1="7" x2="8" y2="11"/><line x1="8" y1="5" x2="8" y2="5.1"/>
              </svg>
              <span>{m.feeds_not_published()}</span>
            </div>
          {:else if mineFeed.changed || dirty}
            <div class="state-strip tone-warning" role="status">
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true">
                <circle cx="8" cy="8" r="6"/><line x1="8" y1="7" x2="8" y2="11"/><line x1="8" y1="5" x2="8" y2="5.1"/>
              </svg>
              <span>{m.feeds_unpublished_changes()}</span>
            </div>
          {/if}

          <div class="files-toolbar">
            <h4 class="section-label">{m.feeds_files_heading()}</h4>
            <span class="toolbar-spacer"></span>
            <button type="button" class="secondary sm-btn" disabled={busy} onclick={() => (pickerOpen = true)}>
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" aria-hidden="true">
                <line x1="8" y1="3" x2="8" y2="13"/><line x1="3" y1="8" x2="13" y2="8"/>
              </svg>
              {m.feeds_add_files()}
            </button>
          </div>

          <div class="file-list">
            {#if editItems.length === 0}
              <div class="file-list-empty">
                <p>{m.feeds_no_items()}</p>
                <button type="button" class="primary sm-btn" disabled={busy} onclick={() => (pickerOpen = true)}>{m.feeds_add_files()}</button>
              </div>
            {/if}
            {#each editItems as item, i (item.ed2k)}
              {@const type = typeOf(item.name)}
              <div class="file-row">
                <span class="file-index" aria-hidden="true">{i + 1}</span>
                {@render fileIcon(type)}
                <div class="file-main">
                  <span class="file-name"><bdi dir="auto">{item.name}</bdi></span>
                  <span class="file-meta">
                    <span>{formatBytes(item.size)}</span>
                    {#if type}<span aria-hidden="true">·</span><span>{fileTypeFilterLabel(type)}</span>{/if}
                  </span>
                  <input
                    type="text"
                    class="note-input"
                    bind:value={item.note}
                    disabled={busy}
                    placeholder={m.feeds_note_placeholder()}
                    aria-label={m.feeds_note_placeholder()}
                    oninput={(e) => {
                      if (!composing(e)) item.note = fitBytes(item.note, NOTE_MAX);
                      dirty = true;
                    }}
                    oncompositionend={() => (item.note = fitBytes(item.note, NOTE_MAX))}
                  />
                </div>
                <div class="row-tools">
                  <button type="button" class="icon-btn sm" disabled={busy || i === 0} aria-label={m.feeds_move_up()} title={m.feeds_move_up()} onclick={() => move(i, -1)}>
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="4 10 8 6 12 10"/></svg>
                  </button>
                  <button type="button" class="icon-btn sm" disabled={busy || i === editItems.length - 1} aria-label={m.feeds_move_down()} title={m.feeds_move_down()} onclick={() => move(i, 1)}>
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="4 6 8 10 12 6"/></svg>
                  </button>
                  <button type="button" class="icon-btn sm danger-hover" disabled={busy} aria-label={m.feeds_remove_named({ name: item.name })} title={m.feeds_remove()} onclick={() => removeItem(i)}>
                    <IconX size={13} />
                  </button>
                </div>
              </div>
            {/each}
          </div>

          <footer class="editor-foot">
            <p class="hint">{m.feeds_publish_public_hint()}</p>
            <div class="editor-foot-actions">
              <button type="button" class="secondary" disabled={!dirty || busy} onclick={() => void save()}>{m.feeds_save()}</button>
              <!-- Published and unchanged: publishing again would only bump the
                   sequence, and the daily republish keeps the head alive. -->
              <button
                type="button"
                class="primary"
                disabled={busy || emberOff || upToDate}
                title={upToDate ? m.feeds_publish_up_to_date_title() : undefined}
                onclick={() => void publish()}
              >
                {#if publishing}
                  <span class="spinner xs" aria-hidden="true"></span>
                {:else if upToDate}
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <polyline points="3 8 7 12 13 4"/>
                  </svg>
                {/if}
                {upToDate ? m.feeds_publish_up_to_date() : mineFeed.published_at > 0 ? m.feeds_publish_changes() : m.feeds_publish()}
              </button>
            </div>
          </footer>

          <FeedFilePicker
            bind:open={pickerOpen}
            feedTitle={editTitle || mineFeed.title}
            {inFeed}
            room={FEED_ITEMS_MAX - editItems.length}
            onadd={addFiles}
            onclose={() => {}}
          />
        {:else}
          <div class="empty-state compact"><p class="empty-sub">{m.feeds_pick_one_mine()}</p></div>
        {/if}
      </section>
    </div>
  {/if}
</div>

<ConfirmDialog
  bind:open={unfollowOpen}
  title={m.feeds_unfollow_confirm()}
  message={m.feeds_unfollow_confirm_body()}
  confirmLabel={m.feeds_unfollow()}
  danger
  onconfirm={() => void doUnfollow()}
/>

<ConfirmDialog
  bind:open={deleteOpen}
  title={m.feeds_delete_confirm()}
  message={m.feeds_delete_confirm_body()}
  confirmLabel={m.feeds_delete()}
  danger
  onconfirm={() => void doDelete()}
/>

<ConfirmDialog
  open={discardThen !== null}
  title={m.feeds_discard_title()}
  message={m.feeds_discard_body()}
  confirmLabel={m.feeds_discard_confirm()}
  danger
  onconfirm={() => {
    // `dirty` is cleared by what replaces the editor, if anything does.
    const then = discardThen;
    discardThen = null;
    then?.();
  }}
  oncancel={() => (discardThen = null)}
  ondismiss={() => (discardThen = null)}
/>

<style>
  .page-header {
    flex-wrap: wrap;
    gap: 10px;
  }

  .header-title {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
  }

  .header-title h2 {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  /* ── Segmented switch (tabs, file filter) ─────────────────────────── */
  .segmented {
    display: inline-flex;
    padding: 2px;
    gap: 2px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-tertiary);
  }

  .segmented button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    border: 0;
    border-radius: calc(var(--radius-md) - 2px);
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--font-size-sm);
    font-weight: 500;
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast), box-shadow var(--transition-fast);
  }

  .segmented button:hover:not(.active) {
    color: var(--text-primary);
  }

  .segmented button.active {
    background: var(--bg-secondary);
    color: var(--text-primary);
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.18), inset 0 1px 0 var(--surface-highlight);
  }

  .segmented.small button {
    padding: 3px 10px;
    font-size: var(--font-size-xs);
  }

  .seg-count {
    font-size: var(--font-size-xs);
    font-variant-numeric: tabular-nums;
    color: var(--text-muted);
  }

  .segmented button.active .seg-count {
    color: var(--text-accent);
  }

  /* ── Page body ────────────────────────────────────────────────────── */
  .feeds-page {
    flex: 1;
    min-height: 0;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    padding: var(--workspace-padding) 16px 16px;
    gap: 10px;
    --scroll-cover: var(--bg-primary);
    /* The window's minimum width is 900px, so the layout answers to the
       room the sidebar leaves, not to the window. */
    container-type: inline-size;
  }

  .compose-card {
    flex-shrink: 0;
    padding: 12px 14px;
    background: var(--bg-secondary);
    border: 1px solid color-mix(in srgb, var(--accent) 35%, var(--border));
    border-radius: var(--radius-lg);
    box-shadow: inset 0 1px 0 var(--surface-highlight);
    animation: feeds-drop-in 0.18s ease;
  }

  .compose-row {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }

  .compose-input-wrap {
    position: relative;
    flex: 1;
    min-width: 240px;
    display: flex;
    align-items: center;
  }

  .compose-input-icon {
    position: absolute;
    left: 11px;
    display: flex;
    color: var(--text-muted);
    pointer-events: none;
  }

  .compose-input-icon svg {
    width: 14px;
    height: 14px;
  }

  .compose-input {
    width: 100%;
    padding: 8px 12px 8px 32px;
    border-radius: var(--radius-md);
    font-size: var(--font-size-md);
  }

  .compose-input.plain {
    width: auto;
    min-width: 200px;
    padding-left: 12px;
  }

  .compose-input.grow {
    flex: 1;
  }

  .compose-input:focus,
  .title-input:focus,
  .desc-input:focus,
  .note-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-halo);
  }

  .compose-hint {
    margin: 8px 0 0;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    line-height: 1.5;
  }

  @keyframes feeds-drop-in {
    from { opacity: 0; transform: translateY(-4px); }
    to { opacity: 1; transform: none; }
  }

  .empty-card {
    flex: 1;
    min-height: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
  }

  .empty-card .empty-state {
    max-width: 440px;
  }

  .empty-glyph {
    display: grid;
    place-items: center;
    width: 56px;
    height: 56px;
    border-radius: 16px;
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--accent) 28%, transparent);
    margin-bottom: 4px;
  }

  .empty-glyph :global(svg) {
    width: 26px;
    height: 26px;
  }

  /* ── Workspace: list beside detail ────────────────────────────────── */
  .workspace {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: 300px minmax(0, 1fr);
    gap: 10px;
  }

  .list-pane,
  .detail-pane {
    min-height: 0;
    min-width: 0;
    display: flex;
    flex-direction: column;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: inset 0 1px 0 var(--surface-highlight);
  }

  .list-pane {
    padding: 8px;
  }

  .list-scroll {
    flex: 1;
    min-height: 0;
    overflow: auto;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .list-empty {
    margin: 0;
    padding: 16px 10px;
    text-align: center;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
  }

  .search-wrap {
    position: relative;
    display: flex;
    align-items: center;
    margin: 2px 2px 8px;
  }

  .search-icon {
    position: absolute;
    left: 10px;
    display: flex;
    color: var(--text-muted);
    pointer-events: none;
  }

  .search-input {
    width: 100%;
    padding: 5px 26px 5px 30px;
    border-radius: var(--radius-pill);
    font-size: var(--font-size-sm);
  }

  .search-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-halo);
  }

  .search-clear {
    position: absolute;
    right: 4px;
    width: 20px;
    height: 20px;
    padding: 0;
    display: grid;
    place-items: center;
    border: 0;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text-muted);
    cursor: pointer;
  }

  .search-clear:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .feed-row {
    position: relative;
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 7px 8px;
    border: 0;
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--text-primary);
    text-align: start;
    cursor: pointer;
    transition: background-color var(--transition-fast) ease;
  }

  .feed-row:hover:not(:disabled) {
    background: var(--bg-hover);
  }

  .feed-row:disabled {
    background: transparent;
    color: inherit;
    cursor: wait;
    opacity: 0.75;
  }

  .feed-row.active {
    background: color-mix(in srgb, var(--accent) 12%, var(--bg-hover));
  }

  .feed-row.active::before {
    content: '';
    position: absolute;
    inset-block: 9px;
    inset-inline-start: 0;
    width: 2px;
    border-radius: var(--radius-pill);
    background: var(--accent);
  }

  .feed-avatar {
    --feed-hue: 210;
    flex-shrink: 0;
    display: grid;
    place-items: center;
    width: var(--avatar-size);
    height: var(--avatar-size);
    border-radius: 9px;
    color: #fff;
    background: linear-gradient(
      145deg,
      hsl(var(--feed-hue) 62% 56%),
      hsl(calc(var(--feed-hue) + 28) 58% 42%)
    );
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.22);
  }

  .feed-avatar :global(svg) {
    width: 15px;
    height: 15px;
  }

  .feed-avatar.lg {
    width: 44px;
    height: 44px;
    border-radius: 12px;
  }

  .feed-avatar.lg :global(svg) {
    width: 20px;
    height: 20px;
  }

  .feed-row-text {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .feed-row-title {
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .feed-row.active .feed-row-title {
    color: var(--text-accent);
  }

  .feed-row.has-unread .feed-row-title {
    font-weight: 700;
  }

  .feed-row-sub {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .feed-row-sub.warn {
    color: var(--badge-warning-text);
  }

  /* ── Detail ───────────────────────────────────────────────────────── */
  /* Scrolls as a whole only when a short window cannot fit the header,
     cards and a usable file list; otherwise the file list scrolls alone. */
  .detail-pane {
    overflow: auto;
  }

  .detail-head {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 16px 18px 12px;
  }

  .detail-title {
    flex: 1;
    min-width: 0;
  }

  .detail-title h3 {
    margin: 0;
    font-size: var(--font-size-lg);
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .detail-meta {
    margin: 3px 0 0;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .detail-meta .unsaved {
    color: var(--badge-warning-text);
    font-weight: 600;
  }

  .status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--text-muted);
  }

  .status-dot.published {
    background: var(--success);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--success) 20%, transparent);
  }

  .detail-actions {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
  }

  .detail-description {
    margin: 0 18px 12px;
    color: var(--text-secondary);
    line-height: 1.5;
  }

  .icon-btn {
    display: inline-grid;
    place-items: center;
    width: 30px;
    height: 30px;
    padding: 0;
    border: 1px solid transparent;
    border-radius: var(--radius-md);
    background: none;
    color: var(--text-secondary);
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
  }

  .icon-btn svg {
    width: 15px;
    height: 15px;
  }

  .icon-btn.sm {
    width: 26px;
    height: 26px;
  }

  .icon-btn.sm svg {
    width: 13px;
    height: 13px;
  }

  .icon-btn:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .icon-btn:disabled {
    background: none;
    opacity: 0.4;
    cursor: default;
  }

  .icon-btn.spinning svg {
    animation: feeds-spin 0.9s linear infinite;
  }

  .pill-btn {
    min-height: 30px;
    padding: 0 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--font-size-sm);
    font-weight: 500;
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
  }

  .pill-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .danger-hover:hover:not(:disabled) {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 12%, transparent);
    border-color: color-mix(in srgb, var(--danger) 35%, transparent);
  }

  @keyframes feeds-spin {
    to { transform: rotate(360deg); }
  }

  .state-strip {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0 18px 12px;
    padding: 8px 12px;
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
    color: var(--badge-accent-text);
    background: color-mix(in srgb, var(--accent) 10%, transparent);
    border: 1px solid color-mix(in srgb, var(--accent) 22%, transparent);
  }

  .state-strip.tone-warning {
    color: var(--badge-warning-text);
    background: color-mix(in srgb, var(--warning) 10%, transparent);
    border-color: color-mix(in srgb, var(--warning) 26%, transparent);
  }

  .state-strip svg {
    flex-shrink: 0;
    width: 15px;
    height: 15px;
  }

  /* ── Auto-download card ───────────────────────────────────────────── */
  .auto-card {
    margin: 0 18px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-primary);
    transition: border-color var(--transition-fast);
  }

  .auto-card.on {
    border-color: color-mix(in srgb, var(--accent) 38%, var(--border));
  }

  .auto-head {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px 8px 12px;
  }

  .auto-icon {
    display: grid;
    place-items: center;
    width: 26px;
    height: 26px;
    border-radius: 8px;
    color: var(--text-secondary);
    background: var(--bg-tertiary);
  }

  .auto-card.on .auto-icon {
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
  }

  .auto-icon svg {
    width: 14px;
    height: 14px;
  }

  .auto-title {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 0;
    border: 0;
    background: none;
    color: var(--text-primary);
    font-size: var(--font-size-md);
    text-align: start;
    cursor: pointer;
  }

  .auto-title:hover {
    background: none;
  }

  .auto-name {
    font-weight: 600;
  }

  .auto-state {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
  }

  .auto-card.on .auto-state {
    color: var(--text-accent);
    font-weight: 600;
  }

  .chevron {
    width: 14px;
    height: 14px;
    color: var(--text-muted);
    transition: transform var(--transition-fast);
  }

  .chevron.open {
    transform: rotate(180deg);
  }

  .auto-body {
    padding: 4px 12px 12px;
    border-top: 1px solid color-mix(in srgb, var(--border) 60%, transparent);
  }

  .auto-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 10px;
    margin-top: 10px;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }

  .field-label {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
  }

  .field input {
    width: 100%;
  }

  .auto-foot {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 12px;
    margin-top: 10px;
  }

  .hint {
    margin: 0;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    line-height: 1.5;
  }

  /* ── Files ────────────────────────────────────────────────────────── */
  .files-toolbar {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    padding: 6px 18px 8px;
    border-top: 1px solid color-mix(in srgb, var(--border) 60%, transparent);
  }

  .section-label {
    margin: 0 4px 0 0;
    font-size: var(--font-size-xs);
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--text-muted);
  }

  .files-search {
    width: 220px;
  }

  .files-search .search-wrap {
    margin: 0;
  }

  .toolbar-spacer {
    flex: 1;
  }

  .sm-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-height: 28px;
    padding: 0 12px;
    font-size: var(--font-size-sm);
    font-weight: 600;
  }

  .sm-btn svg {
    width: 13px;
    height: 13px;
  }

  .file-list {
    flex: 1 1 auto;
    min-height: 160px;
    overflow: auto;
    padding: 0 10px 10px;
  }

  .file-list-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
    padding: 36px 16px;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
    text-align: center;
  }

  .file-list-empty p {
    margin: 0;
  }

  .file-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 9px 8px;
    border-radius: var(--radius-md);
    transition: background-color var(--transition-fast);
  }

  .file-row + .file-row {
    box-shadow: inset 0 1px 0 color-mix(in srgb, var(--border) 45%, transparent);
  }

  .file-row:hover {
    background: color-mix(in srgb, var(--bg-hover) 70%, transparent);
  }

  .file-row.is-new {
    background: color-mix(in srgb, var(--accent) 6%, transparent);
  }

  .file-row.removed .file-main,
  .file-row.removed .file-icon {
    opacity: 0.55;
  }

  .file-index {
    width: 22px;
    flex-shrink: 0;
    text-align: end;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .file-icon {
    --type-color: var(--text-muted);
    flex-shrink: 0;
    display: grid;
    place-items: center;
    width: 32px;
    height: 32px;
    border-radius: 8px;
    color: var(--type-color);
    background: color-mix(in srgb, var(--type-color) 14%, transparent);
  }

  .file-icon svg {
    width: 16px;
    height: 16px;
  }

  .file-icon[data-type='Audio'] { --type-color: #a77bf3; }
  .file-icon[data-type='Video'] { --type-color: #f0727a; }
  .file-icon[data-type='Image'] { --type-color: #4fbf8a; }
  .file-icon[data-type='Archive'] { --type-color: #e0a54a; }
  .file-icon[data-type='Document'] { --type-color: #5b9cf0; }
  .file-icon[data-type='Program'] { --type-color: #9aa3ad; }
  .file-icon[data-type='CD/DVD'] { --type-color: #3fb8c4; }
  .file-icon[data-type='Collection'] { --type-color: var(--accent); }

  .file-main {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .file-name {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
    font-weight: 500;
  }

  .file-name bdi {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .file-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .file-note {
    margin-top: 2px;
    padding-inline-start: 8px;
    border-inline-start: 2px solid color-mix(in srgb, var(--accent) 40%, var(--border));
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    line-height: 1.45;
  }

  .note-input {
    margin-top: 4px;
    max-width: 520px;
    padding: 4px 8px;
    font-size: var(--font-size-sm);
    border-color: transparent;
    background: color-mix(in srgb, var(--bg-input) 60%, transparent);
  }

  .note-input:hover:not(:disabled) {
    border-color: var(--input-border);
  }

  .row-btn {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-height: 30px;
    padding: 0 12px;
    border: 1px solid color-mix(in srgb, var(--accent) 35%, var(--border));
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    color: var(--accent);
    font-size: var(--font-size-sm);
    font-weight: 600;
    cursor: pointer;
    transition: background var(--transition-fast), border-color var(--transition-fast);
  }

  .row-btn:hover:not(:disabled) {
    background: color-mix(in srgb, var(--accent) 22%, transparent);
    border-color: var(--accent);
  }

  .row-btn svg {
    width: 13px;
    height: 13px;
  }

  .row-done {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-height: 30px;
    padding: 0 10px;
    color: var(--success);
    font-size: var(--font-size-sm);
    font-weight: 600;
  }

  .row-done svg {
    width: 13px;
    height: 13px;
  }

  .row-tools {
    flex-shrink: 0;
    display: flex;
    gap: 2px;
    opacity: 0.55;
    transition: opacity var(--transition-fast);
  }

  .file-row:hover .row-tools,
  .row-tools:focus-within {
    opacity: 1;
  }

  /* ── Editor footer ────────────────────────────────────────────────── */
  .title-input {
    width: 100%;
    padding: 3px 8px;
    margin-inline-start: -8px;
    border-color: transparent;
    background: transparent;
    font-size: var(--font-size-lg);
    font-weight: 600;
  }

  .title-input:hover:not(:disabled) {
    border-color: var(--input-border);
  }

  .desc-input {
    margin: 0 18px 12px;
    resize: none;
    line-height: 1.5;
    color: var(--text-secondary);
  }

  .editor-foot {
    position: sticky;
    bottom: 0;
    z-index: 1;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 10px 18px;
    border-top: 1px solid var(--border);
    background: color-mix(in srgb, var(--bg-tertiary) 50%, var(--bg-secondary));
    border-radius: 0 0 var(--radius-lg) var(--radius-lg);
  }

  .editor-foot-actions {
    display: flex;
    gap: 8px;
    flex-shrink: 0;
  }

  .editor-foot-actions .primary {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .editor-foot-actions .primary svg {
    width: 13px;
    height: 13px;
  }

  @media (prefers-reduced-motion: reduce) {
    .compose-card { animation: none; }
    .icon-btn.spinning svg { animation: none; }
  }

  @container (max-width: 860px) {
    .workspace {
      grid-template-columns: 230px minmax(0, 1fr);
    }

    .files-search {
      width: 160px;
    }

    .editor-foot .hint {
      display: none;
    }
  }

  @container (max-width: 600px) {
    .workspace {
      grid-template-columns: 1fr;
      grid-template-rows: minmax(120px, 32%) minmax(0, 1fr);
    }

    .files-search {
      width: 100%;
    }
  }
</style>
