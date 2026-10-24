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
  import { getSharedFilesIfChanged } from '$lib/api/sharing';
  import type { FileInfo } from '$lib/types';
  import { followedFeeds, refreshFollowedFeeds } from '$lib/stores/feeds';
  import { appSettings } from '$lib/stores/settings';
  import { toastError, toastSuccess } from '$lib/stores/toast';
  import { translateError } from '$lib/i18n';
  import { formatBytes, formatRelativeTime } from '$lib/utils';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import * as m from '$lib/paraglide/messages';

  /** The backend's limits, in UTF-8 bytes (`network/ember/feed.rs`). */
  const TITLE_MAX = 64;
  const DESCRIPTION_MAX = 256;
  const NOTE_MAX = 256;

  type Tab = 'following' | 'mine';
  let tab = $state<Tab>('following');
  let emberOff = $derived($appSettings?.ember_native_enabled === false);

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

  const keyOf = (f: { publisher: string; salt: string }) => `${f.publisher}/${f.salt}`;
  let selected = $derived($followedFeeds.find((f) => keyOf(f) === selectedKey) ?? null);
  let newItems = $derived(items.filter((i) => i.is_new && !i.removed && !i.downloaded));

  function feedLabel(f: FollowedFeed): string {
    return f.title.trim() || m.feeds_untitled();
  }

  async function follow(link = followLink) {
    const text = link.trim();
    if (!text || following) return;
    following = true;
    try {
      const feed = await followFeed(text);
      followLink = '';
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
      tab = 'following';
      void follow(linked);
      const next = new URL(page.url);
      next.searchParams.delete('follow');
      void goto(`${next.pathname}${next.search}${next.hash}`, { replaceState: true, keepFocus: true, noScroll: true }).catch(
        () => {},
      );
    });
  });

  let itemsSeq = 0;
  let itemsFor = '';
  async function loadItems(feed: FollowedFeed | null) {
    const seq = ++itemsSeq;
    if (!feed || itemsFor !== keyOf(feed)) {
      // Another feed's files must not show under this one while it loads.
      items = [];
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

  async function saveAuto() {
    if (!selected) return;
    try {
      await setFeedAutoDownload(
        selected.publisher,
        selected.salt,
        autoEnabled,
        Math.max(0, Math.floor(autoItemMib || 0)),
        Math.max(0, Math.floor(autoDayMib || 0)),
        autoCategory,
      );
      await refreshFollowedFeeds();
      toastSuccess(m.feeds_auto_saved());
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
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
  let library = $state<FileInfo[]>([]);
  let pickerQuery = $state('');
  /** What to do once the user agrees to drop unsaved edits. */
  let discardThen = $state<(() => void) | null>(null);
  let leaving = false;

  let busy = $derived(saving || publishing || creating);
  let mineFeed = $derived(mine.find((f) => f.salt === mineSelected) ?? null);
  let pickable = $derived(
    library
      .filter((f) => f.shared && !f.friends_only && f.ember_file_hash?.length === 64)
      .filter((f) => !editItems.some((i) => i.ed2k === f.hash))
      .filter((f) => !pickerQuery.trim() || f.name.toLowerCase().includes(pickerQuery.trim().toLowerCase()))
      .slice(0, 50),
  );

  async function loadMine() {
    try {
      mine = await listMyFeeds();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  async function loadLibrary() {
    try {
      library = (await getSharedFilesIfChanged(null)).files ?? [];
    } catch (e) {
      console.warn('feeds: could not read the library', e);
    }
  }

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
      await loadMine();
      selectMine(feed);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      creating = false;
    }
  }

  function addFile(file: FileInfo) {
    editItems = [
      ...editItems,
      { ed2k: file.hash, name: file.name, size: file.size, aich: file.aich_hash, blake3: file.ember_file_hash, note: '' },
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
    void loadLibrary();
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
    return () => {
      alive = false;
      unlisten?.();
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onFocus);
    };
  });
</script>

<div class="page-header">
  <h2>
    {m.nav_feeds()}
    <span class="beta-badge">{m.common_beta()}</span>
  </h2>
  <div class="feeds-tabs" role="group" aria-label={m.nav_feeds()}>
    <button type="button" aria-pressed={tab === 'following'} class:active={tab === 'following'} onclick={() => (tab = 'following')}>
      {m.feeds_tab_following()}
    </button>
    <button type="button" aria-pressed={tab === 'mine'} class:active={tab === 'mine'} onclick={() => (tab = 'mine')}>
      {m.feeds_tab_mine()}
    </button>
  </div>
</div>

{#if emberOff}
  <div class="feeds-banner" role="status">
    <strong>{m.channels_disabled_title()}</strong>
    {m.feeds_disabled_body()}
  </div>
{/if}

{#if tab === 'following'}
  <section class="feeds-follow">
    <form class="feeds-follow-form" onsubmit={(e) => { e.preventDefault(); void follow(); }}>
      <input
        type="text"
        bind:value={followLink}
        placeholder={m.feeds_follow_placeholder()}
        aria-label={m.feeds_follow_placeholder()}
        spellcheck="false"
        autocomplete="off"
      />
      <button type="submit" class="primary" disabled={following || !followLink.trim()}>{m.feeds_follow()}</button>
    </form>
    <p class="hint">{m.feeds_follow_privacy()}</p>
  </section>

  <div class="feeds-layout">
    <ul class="feeds-list" aria-label={m.feeds_tab_following()}>
      {#if $followedFeeds.length === 0}
        <li class="feeds-empty">{m.feeds_none_followed()}</li>
      {/if}
      {#each $followedFeeds as feed (keyOf(feed))}
        <li>
          <button
            type="button"
            class="feeds-list-row"
            class:current={keyOf(feed) === selectedKey}
            aria-current={keyOf(feed) === selectedKey ? 'true' : undefined}
            onclick={() => (selectedKey = keyOf(feed))}
          >
            <span class="feeds-list-title"><bdi dir="auto">{feedLabel(feed)}</bdi></span>
            {#if feed.unread > 0}
              <span class="count-pill" aria-hidden="true">{feed.unread}</span>
              <span class="sr-only">{m.feeds_unread_title({ count: feed.unread })}</span>
            {/if}
          </button>
        </li>
      {/each}
    </ul>

    <div class="feeds-detail">
      {#if selected}
        <header class="feeds-detail-head">
          <h3><bdi dir="auto">{feedLabel(selected)}</bdi></h3>
          {#if selected.description}
            <p class="feeds-description"><bdi dir="auto">{selected.description}</bdi></p>
          {/if}
          <div class="feeds-actions">
            <button type="button" class="ghost" onclick={() => void copy(selected!.link)}>{m.feeds_copy_link()}</button>
            <button type="button" class="ghost" disabled={refreshing || emberOff} onclick={() => void refreshSelected()}>
              {m.feeds_refresh()}
            </button>
            <button type="button" class="ghost" onclick={() => (unfollowOpen = true)}>{m.feeds_unfollow()}</button>
          </div>
          {#if stateText(selected)}
            <p class="feeds-state" role="status">{stateText(selected)}</p>
          {/if}
        </header>

        <details class="feeds-auto">
          <summary>{m.feeds_auto_title()}</summary>
          <label class="feeds-auto-row">
            <input type="checkbox" bind:checked={autoEnabled} />
            {m.feeds_auto_enable()}
          </label>
          <label class="feeds-auto-row">
            {m.feeds_auto_max_item()}
            <input type="number" min="0" bind:value={autoItemMib} />
          </label>
          <label class="feeds-auto-row">
            {m.feeds_auto_max_day()}
            <input type="number" min="0" bind:value={autoDayMib} />
          </label>
          <label class="feeds-auto-row">
            {m.feeds_auto_category()}
            <input type="text" bind:value={autoCategory} maxlength="256" />
          </label>
          <p class="hint">{m.feeds_auto_hint()}</p>
          <button type="button" class="primary" onclick={() => void saveAuto()}>{m.feeds_save()}</button>
        </details>

        <div class="feeds-items-head">
          <span>{m.feeds_items_count({ count: items.filter((i) => !i.removed).length })}</span>
          {#if newItems.length > 0}
            <button type="button" class="primary" disabled={downloading} onclick={() => void download(newItems.map((i) => i.ed2k))}>
              {m.feeds_download_all_new({ count: newItems.length })}
            </button>
          {/if}
        </div>
        {#if itemsLoading && items.length === 0}
          <p class="feeds-empty">{m.chat_loading_messages()}</p>
        {:else if items.length === 0}
          <p class="feeds-empty">{m.feeds_no_items()}</p>
        {/if}
        <ul class="feeds-items">
          {#each items as item (item.ed2k)}
            <li class="feeds-item" class:removed={item.removed}>
              <div class="feeds-item-main">
                <span class="feeds-item-name"><bdi dir="auto">{item.name}</bdi></span>
                <span class="feeds-item-meta">
                  {formatBytes(item.size)}
                  {#if item.is_new}<span class="badge">{m.feeds_badge_new()}</span>{/if}
                  {#if item.removed}<span class="badge">{m.feeds_badge_removed()}</span>{/if}
                  {#if item.downloaded}<span class="badge">{m.feeds_badge_downloaded()}</span>{/if}
                </span>
                {#if item.note}
                  <span class="feeds-item-note"><bdi dir="auto">{item.note}</bdi></span>
                {/if}
              </div>
              <button
                type="button"
                class="ghost"
                disabled={downloading}
                aria-label={m.feeds_download_named({ name: item.name })}
                onclick={() => void download([item.ed2k])}
              >
                {m.feeds_download()}
              </button>
            </li>
          {/each}
        </ul>
      {:else}
        <p class="feeds-empty">{m.feeds_pick_one()}</p>
      {/if}
    </div>
  </div>
{:else}
  <section class="feeds-create">
    <form onsubmit={(e) => { e.preventDefault(); unlessDirty(() => void create()); }}>
      <input
        type="text"
        bind:value={newTitle}
        oninput={(e) => {
          if (!composing(e)) newTitle = fitBytes(newTitle, TITLE_MAX);
        }}
        oncompositionend={() => (newTitle = fitBytes(newTitle, TITLE_MAX))}
        placeholder={m.feeds_title_placeholder()}
        aria-label={m.feeds_title_placeholder()}
      />
      <input
        type="text"
        bind:value={newDescription}
        oninput={(e) => {
          if (!composing(e)) newDescription = fitBytes(newDescription, DESCRIPTION_MAX);
        }}
        oncompositionend={() => (newDescription = fitBytes(newDescription, DESCRIPTION_MAX))}
        placeholder={m.feeds_description_placeholder()}
        aria-label={m.feeds_description_placeholder()}
      />
      <button type="submit" class="primary" disabled={creating || !newTitle.trim()}>{m.feeds_create()}</button>
    </form>
    <p class="hint">{m.feeds_publish_public_hint()}</p>
  </section>

  <div class="feeds-layout">
    <ul class="feeds-list" aria-label={m.feeds_tab_mine()}>
      {#if mine.length === 0}
        <li class="feeds-empty">{m.feeds_none_mine()}</li>
      {/if}
      {#each mine as feed (feed.salt)}
        <li>
          <button
            type="button"
            class="feeds-list-row"
            class:current={feed.salt === mineSelected}
            aria-current={feed.salt === mineSelected ? 'true' : undefined}
            disabled={busy}
            onclick={() => feed.salt !== mineSelected && unlessDirty(() => selectMine(feed))}
          >
            <span class="feeds-list-title"><bdi dir="auto">{feed.title}</bdi></span>
            {#if feed.published_at === 0}
              <span class="badge">{m.feeds_badge_draft()}</span>
            {:else if feed.changed}
              <span class="badge">{m.feeds_badge_unpublished()}</span>
            {/if}
          </button>
        </li>
      {/each}
    </ul>

    <div class="feeds-detail">
      {#if mineFeed}
        <div class="feeds-edit">
          <input
            type="text"
            bind:value={editTitle}
            disabled={busy}
            oninput={(e) => {
              if (!composing(e)) editTitle = fitBytes(editTitle, TITLE_MAX);
              dirty = true;
            }}
            oncompositionend={() => (editTitle = fitBytes(editTitle, TITLE_MAX))}
            aria-label={m.feeds_title_placeholder()}
          />
          <input
            type="text"
            bind:value={editDescription}
            disabled={busy}
            oninput={(e) => {
              if (!composing(e)) editDescription = fitBytes(editDescription, DESCRIPTION_MAX);
              dirty = true;
            }}
            oncompositionend={() => (editDescription = fitBytes(editDescription, DESCRIPTION_MAX))}
            aria-label={m.feeds_description_placeholder()}
          />
          <div class="feeds-actions">
            <button type="button" class="ghost" disabled={!dirty || busy} onclick={() => void save()}>{m.feeds_save()}</button>
            <button type="button" class="primary" disabled={busy || emberOff} onclick={() => void publish()}>
              {m.feeds_publish()}
            </button>
            {#if mineFeed.published_at > 0}
              <button type="button" class="ghost" onclick={() => void copy(mineFeed!.link)}>{m.feeds_copy_link()}</button>
            {/if}
            <button type="button" class="ghost" disabled={busy} onclick={() => (deleteOpen = true)}>{m.feeds_delete()}</button>
          </div>
          <p class="hint">
            {mineFeed.published_at > 0
              ? m.feeds_published_at({ when: formatRelativeTime(mineFeed.published_at, Math.floor(Date.now() / 1000)), count: mineFeed.item_count })
              : m.feeds_not_published()}
          </p>
          {#if mineFeed.published_at > 0 && (mineFeed.changed || dirty)}
            <p class="hint">{m.feeds_unpublished_changes()}</p>
          {/if}
        </div>

        <ul class="feeds-items">
          {#each editItems as item, i (item.ed2k)}
            <li class="feeds-item">
              <div class="feeds-item-main">
                <span class="feeds-item-name"><bdi dir="auto">{item.name}</bdi></span>
                <span class="feeds-item-meta">{formatBytes(item.size)}</span>
                <input
                  type="text"
                  class="feeds-note"
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
              <div class="feeds-item-tools">
                <button type="button" class="ghost" disabled={busy || i === 0} aria-label={m.feeds_move_up()} title={m.feeds_move_up()} onclick={() => move(i, -1)}>↑</button>
                <button type="button" class="ghost" disabled={busy || i === editItems.length - 1} aria-label={m.feeds_move_down()} title={m.feeds_move_down()} onclick={() => move(i, 1)}>↓</button>
                <button type="button" class="ghost" disabled={busy} aria-label={m.feeds_remove_named({ name: item.name })} onclick={() => removeItem(i)}>
                  {m.feeds_remove()}
                </button>
              </div>
            </li>
          {/each}
        </ul>

        <details class="feeds-picker">
          <summary>{m.feeds_add_files()}</summary>
          <input type="search" bind:value={pickerQuery} placeholder={m.feeds_add_files_search()} aria-label={m.feeds_add_files_search()} />
          <ul class="feeds-items">
            {#each pickable as file (file.hash)}
              <li class="feeds-item">
                <div class="feeds-item-main">
                  <span class="feeds-item-name"><bdi dir="auto">{file.name}</bdi></span>
                  <span class="feeds-item-meta">{formatBytes(file.size)}</span>
                </div>
                <button type="button" class="ghost" disabled={busy} aria-label={m.feeds_add_named({ name: file.name })} onclick={() => addFile(file)}>
                  {m.feeds_add()}
                </button>
              </li>
            {/each}
            {#if pickable.length === 0}
              <li class="feeds-empty">{m.feeds_add_files_none()}</li>
            {/if}
          </ul>
        </details>
      {:else}
        <p class="feeds-empty">{m.feeds_pick_one_mine()}</p>
      {/if}
    </div>
  </div>
{/if}

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
  .feeds-tabs {
    display: flex;
    gap: 4px;
  }

  .feeds-tabs button {
    padding: 4px 12px;
    border-radius: var(--radius-pill);
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-secondary);
  }

  .feeds-tabs button.active {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--on-accent);
  }

  .feeds-banner {
    margin: 12px 16px 0;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-secondary);
    color: var(--text-secondary);
  }

  .feeds-follow,
  .feeds-create {
    padding: 12px 16px 0;
  }

  .feeds-follow-form,
  .feeds-create form {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }

  .feeds-follow-form input,
  .feeds-create input {
    flex: 1;
    min-width: 200px;
  }

  .hint {
    color: var(--text-muted);
    font-size: var(--font-size-xs);
    margin: 6px 0 0;
  }

  .feeds-layout {
    display: grid;
    grid-template-columns: minmax(180px, 260px) 1fr;
    gap: 16px;
    padding: 12px 16px 16px;
    min-height: 0;
  }

  .feeds-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .feeds-list-row {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 8px 10px;
    border-radius: var(--radius-md);
    background: transparent;
    border: 1px solid transparent;
    text-align: start;
    color: var(--text-primary);
  }

  .feeds-list-row:hover {
    background: var(--bg-hover);
  }

  .feeds-list-row.current {
    background: var(--bg-tertiary);
    border-color: var(--border);
  }

  .feeds-list-title {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .feeds-detail {
    min-width: 0;
  }

  .feeds-detail-head h3 {
    margin: 0 0 4px;
  }

  .feeds-description {
    margin: 0 0 8px;
    color: var(--text-secondary);
  }

  .feeds-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin: 6px 0;
  }

  .feeds-state {
    color: var(--text-secondary);
    font-size: var(--font-size-sm);
  }

  .feeds-auto,
  .feeds-picker {
    margin: 10px 0;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }

  .feeds-auto-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 6px 0;
  }

  .feeds-auto-row input[type='number'] {
    width: 8em;
  }

  .feeds-items-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 10px 0 6px;
    color: var(--text-secondary);
  }

  .feeds-items {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .feeds-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 6px 10px;
    border-radius: var(--radius-md);
    background: var(--bg-secondary);
  }

  .feeds-item.removed {
    opacity: 0.6;
  }

  .feeds-item-main {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
    flex: 1;
  }

  .feeds-item-name {
    overflow-wrap: anywhere;
  }

  .feeds-item-meta {
    display: flex;
    gap: 6px;
    align-items: center;
    color: var(--text-muted);
    font-size: var(--font-size-xs);
  }

  .feeds-item-note {
    color: var(--text-secondary);
    font-size: var(--font-size-sm);
  }

  .feeds-item-tools {
    display: flex;
    gap: 4px;
  }

  .feeds-note {
    margin-top: 4px;
  }

  .feeds-edit input {
    display: block;
    width: 100%;
    margin-bottom: 6px;
  }

  .feeds-empty {
    color: var(--text-muted);
    font-size: var(--font-size-sm);
    padding: 8px 4px;
  }

  @media (max-width: 760px) {
    .feeds-layout {
      grid-template-columns: 1fr;
    }
  }
</style>
