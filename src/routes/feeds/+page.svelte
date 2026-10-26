<script lang="ts">
  /*
   * Feeds: follow a publisher's signed list of files and see what is new, or
   * publish lists of your own. See `commands/feeds.rs`.
   */
  import { onMount, tick, untrack } from 'svelte';
  import { page } from '$app/state';
  import { beforeNavigate, goto } from '$app/navigation';
  import { navigatingForDeepLink } from '$lib/deepLinkNavigation';
  import { ctxMenuPosition } from '$lib/actions/ctxMenu';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import {
    cachedDiscoveredFeeds,
    cancelFeedDownload,
    clearHiddenDiscoveredFeeds,
    createFeed,
    deleteFeed,
    downloadFeedItems,
    FEEDS_CHANGED_EVENT,
    FEEDS_FOUND_EVENT,
    followFeed,
    getFeedItems,
    hiddenDiscoveredFeedCount,
    listMyFeeds,
    markFeedRead,
    openFeedFolder,
    openFeedItem,
    publishFeed,
    refreshFeed,
    setDiscoveredFeedHidden,
    setFeedAutoDownload,
    setFeedDetails,
    setFeedItems,
    setFeedListed,
    showFeedItem,
    unfollowFeed,
    type DiscoveredFeed,
    type FeedItem,
    type FeedsChangedEvent,
    type FeedsFoundEvent,
    type FollowedFeed,
    type FollowedItem,
    type LookupOutcome,
    type OwnFeed,
  } from '$lib/api/feeds';
  import {
    AUTO_MIB_MAX,
    capMib,
    concernsFollowed,
    draftOf,
    keepUnchanged,
    onDisk,
    pickFollowed,
    runEach,
    sameDraft,
    withLiveProgress,
    type FeedDraft,
    type LiveProgress,
  } from '$lib/feedsPage';
  import type { FileInfo } from '$lib/types';
  import FeedFilePicker from '$lib/components/FeedFilePicker.svelte';
  import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
  import IconX from '$lib/components/IconX.svelte';
  import {
    discoverWalkRunning,
    feedsPageMemory,
    followedFeeds,
    followedFeedsFailed,
    followedFeedsLoaded,
    lastDiscoverWalkAt,
    refreshFollowedFeeds,
    startDiscoverWalk,
  } from '$lib/stores/feeds';
  import { noteUiActivity } from '$lib/uiStall';
  import { appSettings } from '$lib/stores/settings';
  import { addActionToast, toastError, toastSuccess, toastWarning } from '$lib/stores/toast';
  import { menuKeydown } from '$lib/a11y';
  import { codedErrorOf, transferFailureReasonText, translateError } from '$lib/i18n';
  import { plural } from '$lib/plural';
  import { copyToClipboard, formatBytes, formatDurationSecs, formatNumber, formatRelativeTime, formatSpeed } from '$lib/utils';
  import { pauseTransfer, resumeTransfer } from '$lib/api/transfers';
  import { extensionFromPath, fileTypeFilterLabel, fileTypeKey, type FileTypeKey } from '$lib/fileTypes';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import * as m from '$lib/paraglide/messages';

  /** The backend's limits, in UTF-8 bytes (`network/ember/feed.rs`). */
  const TITLE_MAX = 64;
  const DESCRIPTION_MAX = 256;
  const NOTE_MAX = 256;
  const FEED_ITEMS_MAX = 2000;
  /** Feeds one identity keeps (`FEEDS_PER_IDENTITY`). */
  const FEEDS_MAX = 8;
  /** Past this many feeds the list gets a search box. */
  const LIST_SEARCH_FROM = 6;

  type Tab = 'following' | 'discover' | 'mine';
  /** The tab left open on the last visit; Discover's walk starts on mount. */
  let tab = $state<Tab>(feedsPageMemory.tab);
  let emberOff = $derived($appSettings?.ember_native_enabled === false);
  /** The inline card for following a link or starting a feed. */
  let compose = $state<'follow' | 'create' | null>(null);
  let listQuery = $state('');
  /** Seconds, refreshed each minute so "2 minutes ago" keeps up. */
  let now = $state(Math.floor(Date.now() / 1000));

  function setTab(next: Tab) {
    if (tab === next) return;
    tab = next;
    feedsPageMemory.tab = next;
    compose = null;
    listQuery = '';
    menu = null;
    if (next === 'discover') void openDiscover();
  }

  function toggleCompose(kind: 'follow' | 'create') {
    compose = compose === kind ? null : kind;
  }

  /** The header button that opens the inline card, for focus to go back to
   *  once the card closes: its input had it, and goes with it. */
  let composeTrigger = $state<HTMLButtonElement | null>(null);

  async function closeCompose() {
    compose = null;
    await tick();
    composeTrigger?.focus();
  }

  /** Focus the list's open row: where a card that just added a feed, or
   *  the Unfollow button that just removed one, leaves the user. */
  async function focusActiveRow() {
    await tick();
    document.querySelector<HTMLElement>('.feed-row.active')?.focus();
  }

  /** Escape anywhere in the card closes it; not while an IME is composing,
   *  whose Escape cancels the composition. */
  function composeKeydown(e: KeyboardEvent) {
    if (e.key !== 'Escape' || e.isComposing) return;
    e.preventDefault();
    void closeCompose();
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
  function hueOf(key: string): number {
    let hash = 0;
    for (let i = 0; i < key.length; i++) hash = (hash * 31 + key.charCodeAt(i)) >>> 0;
    return hash % 360;
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
  /** The feed Unfollow asks about, named as it was asked: the dialog's
   *  title must not turn into the next feed's while it closes. */
  let unfollowTitle = $state('');
  let markingAll = $state(false);
  let anyUnread = $derived($followedFeeds.some((f) => f.unread > 0));
  /** Feeds a Check now or a Download is running for, by key: another feed
   *  opened meanwhile has its own buttons. */
  let refreshingFor = $state<ReadonlySet<string>>(new Set());
  let downloadingFor = $state<ReadonlySet<string>>(new Set());
  let refreshing = $derived(selectedKey !== null && refreshingFor.has(selectedKey));
  let downloading = $derived(selectedKey !== null && downloadingFor.has(selectedKey));
  let autoEnabled = $state(false);
  let autoItemMib = $state(0);
  let autoDayMib = $state(0);
  let autoOpen = $state(false);
  let autoSaving = $state(false);
  let itemFilter = $state<'all' | 'new'>('all');
  let itemQuery = $state('');

  const keyOf = (f: { publisher: string; salt: string }) => `${f.publisher}/${f.salt}`;
  let selected = $derived($followedFeeds.find((f) => keyOf(f) === selectedKey) ?? null);
  let itemsFailed = $state(false);
  /** Whether a file can be downloaded now: not on its way, nor here. */
  const canDownload = (i: FollowedItem) =>
    !i.removed &&
    (i.status === 'none' ||
      i.status === 'missing' ||
      i.status === 'cancelled' ||
      i.status === 'elsewhere' ||
      i.status === 'failed');
  /** What the Download all buttons take: not a file had and deleted since,
   *  one cancelled, or one another feed already has, which its own Download
   *  brings here. */
  const bulkTakes = (i: FollowedItem) =>
    canDownload(i) && i.status !== 'missing' && i.status !== 'cancelled' && i.status !== 'elsewhere';
  let newItems = $derived(items.filter((i) => i.is_new && bulkTakes(i)));
  /** Every file that can be downloaded, for a feed just followed, whose first
   *  list brings nothing marked new. */
  let downloadableItems = $derived(items.filter(bulkTakes));
  let downloadableSize = $derived(downloadableItems.reduce((sum, i) => sum + i.size, 0));
  let newSize = $derived(newItems.reduce((sum, i) => sum + i.size, 0));
  let listedItems = $derived(items.filter((i) => !i.removed));
  let listedSize = $derived(listedItems.reduce((sum, i) => sum + i.size, 0));
  /** Files on their way, so the list keeps up with them. */
  let itemsInFlight = $derived(items.some((i) => i.status === 'queued' || i.status === 'downloading'));
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
  let autoChanged = $derived(
    !!selected &&
      (capMib(autoItemMib) !== selected.auto_max_item_mib ||
        capMib(autoDayMib) !== selected.auto_max_day_mib),
  );
  /** New and still listed, downloaded or not: what the New filter shows. */
  let newShownCount = $derived(items.filter((i) => i.is_new && !i.removed).length);

  function feedLabel(f: FollowedFeed): string {
    return f.title.trim() || m.feeds_untitled();
  }

  /** A publisher's key, short, as Discover shows it: enough to tell two
   *  publishers of one name apart. */
  const shortKey = (publisher: string) => publisher.slice(0, 8);

  /** No list held yet: its head never found, or found and its list not in. */
  const noList = (f: FollowedFeed) => f.list_sequence === 0;
  /** The list its newest head names is owed, and its last fetch gave up:
   *  nothing runs until `retry_at`, or Retry. */
  const resting = (f: FollowedFeed) =>
    f.activity.fetching === null && f.sequence > 0 && f.list_sequence !== f.sequence && f.activity.retry_at > now;

  /** How long lookups that reached the network may miss a feed whose list
   *  is held before it is said to be gone: its head lives a day after the
   *  publisher's last republish. */
  const NOT_SEEN_SECS = 2 * 24 * 3600;
  /** Lookups that reached the network have not found it for a long while:
   *  its publisher may have stopped publishing it. Not while we were the
   *  ones offline, which `checked_at` (an answered lookup) rules out. */
  const notSeen = (f: FollowedFeed) =>
    !emberOff && !noList(f) && f.seen_at > 0 && f.checked_at - f.seen_at >= NOT_SEEN_SECS;

  /** The line under a followed feed's name in the list. */
  function followedSub(f: FollowedFeed): string {
    if (f.deleted) return m.feeds_state_deleted_short();
    if (f.activity.too_large) return m.feeds_state_too_large_short();
    if (f.state === 'broken') return m.feeds_state_broken_short();
    if (notSeen(f)) return m.feeds_state_not_seen_short({ when: ago(f.seen_at) });
    if (f.activity.fetching) return m.feeds_state_fetching_short();
    if (resting(f)) return m.feeds_state_list_waiting_short();
    if (f.state === 'fetching' || (noList(f) && f.sequence > 0)) return m.feeds_state_fetching_short();
    if (noList(f)) {
      return f.activity.unreachable ? m.feeds_state_unreachable_short() : m.feeds_state_waiting_short();
    }
    return m.feeds_items_count({ count: formatNumber(f.item_count) });
  }

  /** A feed link's own part: the same in an `ember-feed:` link and the
   *  website's address. */
  const linkBody = (link: string) => link.trim().toLowerCase().replace(/\/+$/, '').split(/[:/]/).pop() ?? '';

  /** The link named one of the user's own feeds: open it there, rather than
   *  only saying it cannot be followed. */
  async function openOwnFeed(link: string) {
    setTab('mine');
    const feeds = mineLoaded ? mine : ((await loadMine()) ?? []);
    const own = feeds.find((f) => linkBody(f.link) === linkBody(link));
    if (own && mineSelected !== own.salt) unlessDirty(() => selectMine(own));
    toastSuccess(m.feeds_own_opened());
  }

  /** Links opened from outside while another follow was running, in the
   *  order they came. */
  let queuedLinks: string[] = [];

  async function follow(link = followLink) {
    const text = link.trim();
    if (!text || following) return;
    following = true;
    try {
      const feed = await followFeed(text);
      followLink = '';
      compose = null;
      await refreshFollowedFeeds();
      selectFollowed(keyOf(feed));
      toastSuccess(feed.already_following ? m.feeds_already_following() : m.feeds_followed_toast());
      await focusActiveRow();
    } catch (e) {
      if (codedErrorOf(e)?.code === 'feeds_own') {
        followLink = '';
        compose = null;
        await openOwnFeed(text);
      } else {
        toastError(translateError(e, m.error_operation_failed()));
      }
    } finally {
      following = false;
      const next = queuedLinks.shift();
      if (next) void follow(next);
    }
  }

  // A link opened from outside, already confirmed: followed once, then
  // dropped from the address so Back does not follow it again.
  $effect(() => {
    const linked = page.url.searchParams.get('follow');
    if (!linked) return;
    untrack(() => {
      setTab('following');
      if (!following) void follow(linked);
      else if (!queuedLinks.includes(linked)) queuedLinks.push(linked);
      const next = new URL(page.url);
      next.searchParams.delete('follow');
      void goto(`${next.pathname}${next.search}${next.hash}`, { replaceState: true, keepFocus: true, noScroll: true }).catch(
        () => {},
      );
    });
  });

  /** The followed feed last opened, so coming back opens it again. */
  const SELECTED_KEY = 'ember.feeds.followedSelected';

  /** The followed feed the user opened, or did something in, themselves:
   *  only it is marked read once seen. One opened for them, on arriving or
   *  in an unfollowed one's place, keeps its new files new until then. */
  let openedKey = $state<string | null>(null);

  function rememberFollowed(key: string) {
    try {
      localStorage.setItem(SELECTED_KEY, key);
    } catch {
      // Storage unavailable: the choice lasts the visit.
    }
  }

  /** The user opens a followed feed: read once its files are on screen. */
  function selectFollowed(key: string) {
    selectedKey = key;
    openedKey = key;
    rememberFollowed(key);
    void markShownRead();
  }

  /** The user clicked, pressed a key or scrolled in the open feed: one
   *  opened for them is theirs from now on. */
  function claimOpen() {
    if (selectedKey === null || openedKey === selectedKey) return;
    openedKey = selectedKey;
    void markShownRead();
  }

  // Something is always open while there is something to open: the feed last
  // opened, else the first with something new, else the first. It is not the
  // user's pick, so it is not marked read for them (see `openedKey`).
  $effect(() => {
    const feeds = $followedFeeds;
    if (feeds.length === 0) return;
    untrack(() => {
      if (feeds.some((f) => keyOf(f) === selectedKey)) return;
      let remembered: string | null = null;
      try {
        remembered = localStorage.getItem(SELECTED_KEY);
      } catch {
        remembered = null;
      }
      const pick = pickFollowed(feeds, remembered);
      if (pick) selectedKey = keyOf(pick);
    });
  });

  let itemsSeq = 0;
  /** The feed whose files `items` holds; empty while none's are in. */
  let itemsFor = $state('');
  /** The open feed's size: its listed files', once they are in; until then,
   *  what its newest head gave, 0 when that is not known. */
  let selectedSize = $derived(selected && itemsFor !== keyOf(selected) ? selected.total_size : listedSize);
  /** The open feed's downloads, whose transfer events it shows. */
  let itemTransferIds = $derived(new Set(items.flatMap((i) => (i.transfer ? [i.transfer.id] : []))));
  /** How often the open feed's rows take in their downloads' progress. */
  const LIVE_PROGRESS_MS = 500;
  /** How long after a download of the open feed ends, or the feed changes,
   *  its files are read again, so several together are read once. */
  const SETTLED_RELOAD_MS = 300;

  /** `quiet` for the refresh that keeps a list's progress current: no
   *  spinner, no toast. */
  async function loadItems(feed: FollowedFeed | null, quiet = false) {
    const seq = ++itemsSeq;
    if (!feed || itemsFor !== keyOf(feed)) {
      // Another feed's files must not show under this one while it loads.
      items = [];
      itemsFor = '';
      itemFilter = 'all';
      itemQuery = '';
    }
    if (!feed) return;
    if (!quiet) itemsLoading = true;
    try {
      const rows = await getFeedItems(feed.publisher, feed.salt);
      if (seq !== itemsSeq) return;
      noteUiActivity(`feed items ${rows.length}${quiet ? ' (refresh)' : ''}`);
      // What was new stays shown as new while the feed stays open, though
      // opening it marks it read.
      const wasNew = new Set(itemsFor === keyOf(feed) ? items.filter((i) => i.is_new).map((i) => i.ed2k) : []);
      const next = keepUnchanged(
        items,
        rows.map((r) => (wasNew.has(r.ed2k) ? { ...r, is_new: true } : r)),
      );
      if (next !== items) items = next;
      itemsFor = keyOf(feed);
      itemsFailed = false;
      await markShownRead();
    } catch (e) {
      if (seq !== itemsSeq) return;
      if (!quiet) {
        itemsFailed = true;
        toastError(translateError(e, m.error_operation_failed()));
      }
    } finally {
      if (seq === itemsSeq) itemsLoading = false;
    }
  }

  /** The feed whose files are on screen is read once seen: not while Ember
   *  is hidden or behind another window, nor from the My feeds tab, nor
   *  before the user has opened it or done something in it. */
  async function markShownRead() {
    const feed = selected;
    if (
      !feed ||
      openedKey !== keyOf(feed) ||
      itemsFor !== keyOf(feed) ||
      tab !== 'following' ||
      feed.unread === 0 ||
      !emberFocused()
    ) {
      return;
    }
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
      autoOpen = false;
    }
  });

  // Back on the Following tab, the feed on screen is seen, if the user opened it.
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
      autoItemMib = capMib(autoItemMib);
      autoDayMib = capMib(autoDayMib);
      const saved = await setFeedAutoDownload(feed.publisher, feed.salt, autoEnabled, autoItemMib, autoDayMib);
      await refreshFollowedFeeds();
      // The fields show what was saved, which the backend may have clipped.
      if (selectedKey === keyOf(feed)) {
        autoItemMib = saved.auto_max_item_mib;
        autoDayMib = saved.auto_max_day_mib;
      }
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
    const key = selectedKey;
    autoEnabled = on;
    if (!(await saveAuto())) {
      // Not another feed's switch, if the user moved on meanwhile.
      if (selectedKey === key) autoEnabled = !on;
      return;
    }
    if (on && selectedKey === key) autoOpen = true;
  }

  async function saveAutoLimits() {
    if (await saveAuto()) toastSuccess(m.feeds_auto_saved());
  }

  /** A cap in MiB as people read sizes; 0 is no limit. */
  function mibText(mib: number): string {
    const capped = capMib(mib);
    return capped === 0 ? m.feeds_auto_no_limit() : formatBytes(capped * 1024 * 1024);
  }

  /** The limits in force, said under the switch while it is on. */
  function autoSummary(itemMib: number, dayMib: number): string {
    return m.feeds_auto_summary({ item: mibText(itemMib), day: mibText(dayMib) });
  }

  /** Why auto-download has left a file for the user to start. */
  function heldText(held: NonNullable<FollowedItem['held']>): string {
    if (held === 'risky') return m.feeds_held_risky();
    if (held === 'too_large') return m.feeds_held_too_large();
    if (held === 'disk') return m.feeds_held_disk();
    return m.feeds_held_day_limit();
  }

  /** Downloads waiting on the user's word, because some can run code: all
   *  of them, and those that cannot; `from`, the row whose Download asked. */
  let riskyAsk = $state<{ ed2ks: string[]; safe: string[]; names: string[]; from?: string } | null>(null);

  function riskyText(names: string[]): string {
    return plural(names.length, {
      one: () => m.feeds_risky_confirm_body_one({ name: names[0] }),
      other: () => m.feeds_risky_confirm_body_other({ count: formatNumber(names.length), name: names[0] }),
    });
  }

  /** Download, after asking when any of them can run code. `from`: the row
   *  whose own Download this is. */
  function askDownload(ed2ks: string[], from?: string) {
    const wanted = new Set(ed2ks);
    const chosen = items.filter((i) => wanted.has(i.ed2k));
    const risky = chosen.filter((i) => i.risky);
    if (risky.length > 0) {
      riskyAsk = { ed2ks, safe: chosen.filter((i) => !i.risky).map((i) => i.ed2k), names: risky.map((i) => i.name), from };
    } else {
      void download(ed2ks, from);
    }
  }

  /** The open feed's file list. */
  let followList = $state<HTMLElement | null>(null);

  /** Focus has fallen to the page: what had it is gone or was disabled. */
  const focusLost = () => !document.activeElement || document.activeElement === document.body;

  /** Once a row's Download has run, focus goes back to it; where the row
   *  shows its download instead, to the nearest row's Download after it,
   *  else before it, else the list. Not if the user has moved on. */
  async function focusDownloadNear(ed2k: string) {
    await tick();
    if (!followList || !focusLost()) return;
    const rows = [...followList.querySelectorAll<HTMLElement>('[data-row]')];
    const at = rows.findIndex((r) => r.dataset.row === ed2k);
    const button = (r: HTMLElement) => r.querySelector<HTMLElement>('[data-download]:not(:disabled)');
    const near =
      (at >= 0 ? button(rows[at]) : null) ??
      rows.slice(at + 1).map(button).find(Boolean) ??
      rows.slice(0, Math.max(0, at)).reverse().map(button).find(Boolean);
    (near ?? followList).focus();
  }

  async function openFolder() {
    const feed = selected;
    if (!feed) return;
    try {
      await openFeedFolder(feed.publisher, feed.salt);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  /** `text`, naming the feed it is about when another one is open now. */
  function aboutFeed(feed: FollowedFeed, text: string): string {
    return selectedKey === keyOf(feed) ? text : m.feeds_toast_in_feed({ feed: feedLabel(feed), text });
  }

  async function download(ed2ks: string[], from?: string) {
    const feed = selected;
    if (!feed || ed2ks.length === 0) return;
    const key = keyOf(feed);
    if (downloadingFor.has(key)) return;
    downloadingFor = new Set([...downloadingFor, key]);
    try {
      const started = await downloadFeedItems(feed.publisher, feed.salt, ed2ks);
      toastSuccess(
        aboutFeed(
          feed,
          plural(started, {
            one: () => m.feeds_download_started_one(),
            other: () => m.feeds_downloads_started({ count: formatNumber(started) }),
          }),
        ),
      );
      // Not if the user has opened another feed meanwhile.
      if (selectedKey === key) await loadItems(feed, true);
    } catch (e) {
      toastError(aboutFeed(feed, translateError(e, m.error_operation_failed())));
    } finally {
      downloadingFor = new Set([...downloadingFor].filter((other) => other !== key));
      if (from && selectedKey === key) void focusDownloadNear(from);
    }
  }

  /** Downloads whose pause, resume or cancel is on its way. */
  let controlling = $state<ReadonlySet<string>>(new Set());
  /** The download waiting on the user's word before it is cancelled. */
  let cancelAsk = $state<FollowedItem | null>(null);

  /** Pause, resume or cancel an item's download, then show what it does now. */
  async function controlItem(item: FollowedItem, run: (transferId: string) => Promise<void>) {
    const feed = selected;
    const id = item.transfer?.id;
    if (!feed || !id || controlling.has(id)) return;
    controlling = new Set([...controlling, id]);
    try {
      await run(id);
      if (selectedKey === keyOf(feed)) await loadItems(feed, true);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      controlling = new Set([...controlling].filter((other) => other !== id));
    }
  }

  /** Where an item's download is getting it from, and how fast. */
  function transferText(item: FollowedItem): string {
    const t = item.transfer;
    if (!t) return '';
    const parts: string[] = [m.feeds_item_done_of({ done: formatBytes(t.done), size: formatBytes(item.size) })];
    if (item.status === 'downloading' && t.speed > 0) {
      parts.push(formatSpeed(t.speed));
      const left = Math.max(0, item.size - t.done);
      if (left > 0) parts.push(m.feeds_item_time_left({ time: formatDurationSecs(Math.ceil(left / t.speed)) }));
    }
    if (item.status !== 'paused') {
      if (t.from_publisher) {
        parts.push(m.feeds_item_from_publisher());
      } else if (t.sources > 0) {
        const active = formatNumber(t.active_sources);
        parts.push(
          plural(t.sources, {
            one: () => m.feeds_item_sources_one({ active }),
            other: () => m.feeds_item_sources({ active, total: formatNumber(t.sources) }),
          }),
        );
      }
    }
    return parts.join(' · ');
  }

  async function refreshSelected() {
    const feed = selected;
    if (!feed) return;
    const key = keyOf(feed);
    if (refreshingFor.has(key)) return;
    refreshingFor = new Set([...refreshingFor, key]);
    try {
      const outcome = await refreshFeed(feed.publisher, feed.salt);
      await refreshFollowedFeeds();
      const said = outcomeText(outcome, feed);
      if (said) {
        (outcome === 'unreachable' || outcome === 'too_large' ? toastWarning : toastSuccess)(aboutFeed(feed, said));
      }
    } catch (e) {
      toastError(aboutFeed(feed, translateError(e, m.error_operation_failed())));
    } finally {
      refreshingFor = new Set([...refreshingFor].filter((other) => other !== key));
    }
  }

  /** What "Check now" found, said in a toast. */
  function outcomeText(outcome: LookupOutcome, feed: FollowedFeed): string | null {
    switch (outcome) {
      case 'updated':
        return m.feeds_check_updated();
      case 'unchanged':
        return noList(feed) ? m.feeds_check_fetching_list() : m.feeds_check_unchanged();
      case 'not_found':
        return m.feeds_check_not_found();
      case 'unreachable':
        return m.feeds_check_unreachable();
      case 'too_large':
        return m.feeds_state_too_large();
      case 'busy':
        return m.feeds_state_waiting_short();
      default:
        return null;
    }
  }

  function askUnfollow() {
    if (!selected) return;
    unfollowTitle = feedLabel(selected);
    unfollowOpen = true;
  }

  async function doUnfollow() {
    const feed = selected;
    if (!feed) return;
    const key = keyOf(feed);
    try {
      await unfollowFeed(feed.publisher, feed.salt);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
      return;
    }
    // Gone at once, so a reload that fails cannot leave it listed and opened
    // again. Its neighbour in the list opens in its place.
    const list = $followedFeeds;
    const at = list.findIndex((f) => keyOf(f) === key);
    const next = list[at + 1] ?? list[at - 1] ?? null;
    followedFeeds.update((feeds) => feeds.filter((f) => keyOf(f) !== key));
    selectedKey = next ? keyOf(next) : null;
    if (next) rememberFollowed(keyOf(next));
    toastSuccess(m.feeds_unfollowed_toast({ feed: feedLabel(feed) }));
    // The Unfollow button went with the feed: focus goes to the one opened,
    // or to Follow a feed when none is left.
    if (next) {
      await focusActiveRow();
    } else {
      await tick();
      composeTrigger?.focus();
    }
    void refreshFollowedFeeds();
  }

  /** How many feeds Mark all as read marks at once. */
  const MARK_ALL_AT_ONCE = 4;

  /** Every followed feed with something new is marked read; one that fails
   *  stays as it was, and the first failure is said. */
  async function markAllRead() {
    if (markingAll) return;
    markingAll = true;
    try {
      const unread = $followedFeeds.filter((f) => f.unread > 0);
      const failed = await runEach(unread, MARK_ALL_AT_ONCE, (f) => markFeedRead(f.publisher, f.salt));
      await refreshFollowedFeeds();
      if (failed.length > 0) toastError(translateError(failed[0], m.error_operation_failed()));
    } finally {
      markingAll = false;
      // The button goes once nothing is unread, and focus with it.
      await tick();
      if (focusLost()) composeTrigger?.focus();
    }
  }

  /** Open a downloaded file, or show it in its folder. One gone from disk
   *  since is read again, for its row to say so. */
  async function openItem(item: FollowedItem, run: typeof openFeedItem) {
    const feed = selected;
    if (!feed) return;
    try {
      await run(feed.publisher, feed.salt, item.ed2k);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
      if (codedErrorOf(e)?.code === 'feeds_item_not_on_disk' && selectedKey === keyOf(feed)) void loadItems(feed, true);
    }
  }

  async function copy(text: string) {
    if (await copyToClipboard(text)) {
      toastSuccess(m.feeds_link_copied());
    } else {
      toastError(m.error_operation_failed());
    }
  }

  /** The strip above a followed feed's files, saying what it waits on,
   *  whether that is a fault (`warn`), and whether Retry would do anything. */
  function stateText(f: FollowedFeed): StripState | null {
    // Nothing more will come of a deleted feed: its own notice says so.
    if (f.deleted) return null;
    const strip = feedState(f);
    // Nothing runs while the network is off: no spinner promising otherwise.
    if (strip?.busy && emberOff) return { text: m.feeds_state_paused_off(), warn: true, busy: false, retry: false };
    return strip;
  }

  /** `spoken`, when set, is what a screen reader is told instead of `text`:
   *  the strip is a live region, and a count or a time in it would have the
   *  whole sentence read out again each time it moves. */
  type StripState = { text: string; spoken?: string; warn: boolean; busy: boolean; retry: boolean };

  function feedState(f: FollowedFeed): StripState | null {
    const fetch = f.activity.fetching;
    if (f.activity.too_large) return { text: m.feeds_state_too_large(), warn: true, busy: false, retry: false };
    if (f.state === 'broken') return { text: m.feeds_state_broken(), warn: true, busy: false, retry: true };
    if (fetch) {
      // The source count changes as the poll runs: a screen reader is told
      // the fetch, not each count.
      return fetch.sources > 0
        ? {
            text: m.feeds_state_fetching_from({ count: formatNumber(fetch.sources) }),
            spoken: m.feeds_state_fetching(),
            warn: false,
            busy: true,
            retry: false,
          }
        : { text: m.feeds_state_fetching_finding(), warn: false, busy: true, retry: false };
    }
    if (resting(f)) {
      const minutes = Math.max(1, Math.ceil((f.activity.retry_at - now) / 60));
      return {
        text: m.feeds_state_list_waiting({ minutes: formatNumber(minutes) }),
        spoken: m.feeds_state_list_waiting_spoken(),
        warn: true,
        busy: false,
        retry: true,
      };
    }
    if (f.state === 'fetching' || (f.sequence > 0 && noList(f))) {
      return { text: m.feeds_state_fetching(), warn: false, busy: true, retry: false };
    }
    if (notSeen(f)) {
      return {
        text: m.feeds_state_not_seen({ when: ago(f.seen_at) }),
        spoken: m.feeds_state_not_seen_spoken(),
        warn: true,
        busy: false,
        retry: true,
      };
    }
    if (noList(f)) {
      if (f.activity.unreachable) return { text: m.feeds_state_unreachable(), warn: true, busy: false, retry: true };
      const checked = f.checked_at > 0 ? ` ${m.feeds_checked_at({ when: ago(f.checked_at) })}.` : '';
      return {
        text: `${m.feeds_state_waiting()}${checked}`,
        spoken: m.feeds_state_waiting(),
        warn: false,
        busy: true,
        retry: false,
      };
    }
    return null;
  }

  // ── Discover ─────────────────────────────────────────────────────────
  /** Cards shown at first, and added by each Show more. */
  const DISCOVER_PAGE = 60;
  /** Opening the tab again walks the index again after this long. */
  const DISCOVER_STALE_MS = 10 * 60_000;
  let discovered = $state<DiscoveredFeed[]>([]);
  /** The cache or a walk has answered. */
  let discoverLoaded = $state(false);
  let discovering = $state(false);
  let discoverQuery = $state('');
  let discoverFilter = $state<'all' | 'active'>('all');
  let discoverLimit = $state(DISCOVER_PAGE);
  let hiddenCount = $state(0);
  /** The card menu open, with where its button is: the app's own
   *  `ctx-menu`, fixed to the window, so neither the next card nor the
   *  scrolling grid can cover or clip it. */
  let menu = $state<{ feed: DiscoveredFeed; x: number; y: number } | null>(null);
  let menuFor = $derived(menu ? keyOf(menu.feed) : null);

  /** The button that opened the card menu, to give focus back to. */
  let menuTrigger: HTMLElement | null = null;

  function toggleMenu(feed: DiscoveredFeed, button: HTMLElement) {
    if (menuFor === keyOf(feed)) {
      closeCardMenu(true);
      return;
    }
    const rect = button.getBoundingClientRect();
    menuTrigger = button;
    menu = { feed, x: rect.left, y: rect.bottom + 4 };
  }

  function closeCardMenu(refocus: boolean) {
    menu = null;
    if (refocus) menuTrigger?.focus();
    menuTrigger = null;
  }

  /** Keys in the card menu: arrows move, Escape and Tab close it. */
  function cardMenuKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      closeCardMenu(true);
      return;
    }
    if (e.key === 'Tab') {
      closeCardMenu(true);
      return;
    }
    menuKeydown(e, e.currentTarget as HTMLElement);
  }

  type DiscoverSort = 'active' | 'newest' | 'files' | 'name';
  let discoverSort = $state<DiscoverSort>('active');
  /** Feeds being followed from Discover. */
  let followingFromDiscover = $state<Set<string>>(new Set());
  /** The walk whose shards are taken; any other's are stale. */
  let discoverWalk = '';
  let discoverOpened = false;

  /** Show only this publisher's feeds. */
  let discoverPublisher = $state<string | null>(null);
  let discoverMatches = $derived.by(() => {
    const q = discoverQuery.trim().toLowerCase();
    const matched = discovered.filter(
      (f) =>
        (discoverFilter === 'all' || f.active) &&
        (!discoverPublisher || f.publisher === discoverPublisher) &&
        (!q ||
          f.title.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q) ||
          f.publisher.startsWith(q)),
    );
    // While a walk fills in, cards stay where they are and new ones go at
    // the end: a card moving under the pointer is followed by mistake.
    return discovering ? matched : sortDiscovered(matched, discoverSort);
  });

  /** A sort picked during a walk orders the cards found so far at once;
   *  those still to come go at the end, as before. */
  function pickSort(by: DiscoverSort) {
    discoverSort = by;
    if (discovering) discovered = sortDiscovered(discovered, by);
  }

  let discoverShown = $derived(discoverMatches.slice(0, discoverLimit));
  let activeDiscovered = $derived(discovered.filter((f) => f.active).length);
  let followedKeys = $derived(new Set($followedFeeds.map(keyOf)));

  // A new search or filter starts from the first page again.
  $effect(() => {
    void discoverQuery;
    void discoverFilter;
    void discoverPublisher;
    untrack(() => (discoverLimit = DISCOVER_PAGE));
  });

  /** By the chosen order; by default running publishers first, then the
   *  most lately published. */
  function sortDiscovered(feeds: DiscoveredFeed[], by: DiscoverSort = 'active'): DiscoveredFeed[] {
    const newest = (a: DiscoveredFeed, b: DiscoveredFeed) => b.sequence - a.sequence;
    const compare: Record<DiscoverSort, (a: DiscoveredFeed, b: DiscoveredFeed) => number> = {
      active: (a, b) => Number(b.active) - Number(a.active) || newest(a, b),
      newest,
      files: (a, b) => b.item_count - a.item_count || newest(a, b),
      name: (a, b) => a.title.localeCompare(b.title) || newest(a, b),
    };
    return feeds.slice().sort(compare[by]);
  }

  /** Feeds, as `publisher/salt`, and publishers, as `publisher/`, hidden
   *  since the last walk began, which may still bring them in. */
  let hiddenMeanwhile = new Set<string>();
  const hiddenNow = (f: DiscoveredFeed) => hiddenMeanwhile.has(keyOf(f)) || hiddenMeanwhile.has(`${f.publisher}/`);

  /** Take a shard's feeds in place: one known is updated where it is, a new
   *  one goes at the end (see `discoverMatches`). */
  function takeFound(feeds: DiscoveredFeed[], gone: FeedsFoundEvent['gone']) {
    const byKey = new Map(discovered.map((f) => [keyOf(f), f]));
    for (const g of gone) {
      const held = byKey.get(keyOf(g));
      if (held && held.listed_at <= g.listed_at) byKey.delete(keyOf(g));
    }
    for (const f of feeds) {
      const held = byKey.get(keyOf(f));
      if (!hiddenNow(f) && (!held || held.listed_at <= f.listed_at)) byKey.set(keyOf(f), f);
    }
    discovered = [...byKey.values()];
  }

  async function refreshHiddenCount() {
    try {
      hiddenCount = await hiddenDiscoveredFeedCount();
    } catch (e) {
      console.warn('feeds: could not count hidden feeds', e);
    }
  }

  async function openDiscover() {
    if (!discoverOpened) {
      discoverOpened = true;
      try {
        const cached = await cachedDiscoveredFeeds();
        // A walk's shards may have landed first; they are newer.
        if (discovered.length === 0) discovered = sortDiscovered(cached);
      } catch (e) {
        console.warn('feeds: could not read the Discover cache', e);
      }
      discoverLoaded = true;
      void refreshHiddenCount();
    }
    if (discoverWalkRunning() || Date.now() - lastDiscoverWalkAt() >= DISCOVER_STALE_MS) void walkDiscover();
  }

  /** Walk the index, or take in the walk running since an earlier visit. */
  async function walkDiscover() {
    if (discovering || emberOff) return;
    const { walk, result } = startDiscoverWalk();
    discoverWalk = walk;
    discovering = true;
    try {
      const feeds = await result;
      if (discoverWalk === walk) discovered = sortDiscovered(feeds.filter((f) => !hiddenNow(f)));
    } catch (e) {
      if (discoverWalk === walk) toastError(translateError(e, m.error_operation_failed()));
    } finally {
      if (discoverWalk === walk) {
        discovering = false;
        discoverLoaded = true;
        // The walk read them hidden as it ended.
        hiddenMeanwhile = new Set();
      }
    }
  }

  async function followDiscovered(feed: DiscoveredFeed) {
    const key = keyOf(feed);
    if (followingFromDiscover.has(key)) return;
    followingFromDiscover = new Set([...followingFromDiscover, key]);
    try {
      await followFeed(feed.link);
      await refreshFollowedFeeds();
      toastSuccess(m.feeds_followed_toast());
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      const next = new Set(followingFromDiscover);
      next.delete(key);
      followingFromDiscover = next;
      // Follow, disabled while it ran, has become Open, or is Follow again.
      await tick();
      if (focusLost()) cardAction(key)?.focus();
    }
  }

  /** The Discover grid, for focus to fall back on once a card is gone. */
  let discoverScroll = $state<HTMLElement | null>(null);

  const cardAction = (key: string) =>
    discoverScroll?.querySelector<HTMLElement>(`[data-card="${CSS.escape(key)}"] [data-card-action]`);

  function openFollowed(feed: DiscoveredFeed) {
    selectFollowed(keyOf(feed));
    setTab('following');
  }

  /** One of the user's own listed feeds, opened in the editor. */
  function editOwn(feed: DiscoveredFeed) {
    setTab('mine');
    const own = mine.find((f) => f.salt === feed.salt);
    if (own && mineSelected !== own.salt) unlessDirty(() => selectMine(own));
  }

  /** Once the cards of `hidden` are gone, focus the menu button of the
   *  nearest card left of those that were `shown`: after it, else before
   *  it, else the grid, or the empty Discover's own buttons. */
  async function focusCardNear(shown: string[], hidden: string) {
    await tick();
    if (!focusLost()) return;
    const left = new Set(discoverShown.map(keyOf));
    const at = shown.indexOf(hidden);
    const near =
      shown.slice(at + 1).find((k) => left.has(k)) ?? shown.slice(0, Math.max(0, at)).reverse().find((k) => left.has(k));
    const button = near
      ? discoverScroll?.querySelector<HTMLElement>(`[data-card="${CSS.escape(near)}"] .card-menu-btn`)
      : null;
    (button ?? (discoverScroll?.isConnected ? discoverScroll : document.querySelector<HTMLElement>('.empty-card button')))?.focus();
  }

  async function hideDiscovered(feed: DiscoveredFeed, wholePublisher: boolean) {
    const trigger = menuTrigger;
    const shown = discoverShown.map(keyOf);
    closeCardMenu(false);
    const salt = wholePublisher ? null : feed.salt;
    const matches = (f: DiscoveredFeed) => (wholePublisher ? f.publisher === feed.publisher : keyOf(f) === keyOf(feed));
    try {
      await setDiscoveredFeedHidden(feed.publisher, salt, true);
      const tag = wholePublisher ? `${feed.publisher}/` : keyOf(feed);
      if (discovering) hiddenMeanwhile.add(tag);
      if (wholePublisher && discoverPublisher === feed.publisher) discoverPublisher = null;
      const removed = discovered.filter(matches);
      discovered = discovered.filter((f) => !matches(f));
      void focusCardNear(shown, keyOf(feed));
      hiddenCount += 1;
      addActionToast(
        'success',
        m.feeds_discover_hidden_toast(),
        {
          label: m.common_undo(),
          undo: true,
          run: () => {
            void (async () => {
              try {
                await setDiscoveredFeedHidden(feed.publisher, salt, false);
                hiddenMeanwhile.delete(tag);
                hiddenCount = Math.max(0, hiddenCount - 1);
                const back = new Set(discovered.map(keyOf));
                discovered = [...discovered, ...removed.filter((f) => !back.has(keyOf(f)))];
              } catch (e) {
                toastError(translateError(e, m.error_operation_failed()));
              }
            })();
          },
        },
        () => {},
      );
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
      // The card stays, and so does the button its menu came from.
      if (focusLost()) trigger?.focus();
    }
  }

  let showHiddenAsk = $state(false);

  /** Not during a walk, whose result leaves out what it read hidden. */
  async function showHidden() {
    if (discovering) return;
    try {
      await clearHiddenDiscoveredFeeds();
      hiddenCount = 0;
      discovered = sortDiscovered(await cachedDiscoveredFeeds());
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  /** The line saying when a listed feed's publisher was last running. */
  function seenText(feed: DiscoveredFeed): string {
    return feed.active ? m.feeds_discover_active() : m.feeds_discover_seen({ when: ago(feed.listed_at) });
  }

  // ── My feeds ─────────────────────────────────────────────────────────
  let mine = $state<OwnFeed[]>([]);
  let mineLoaded = $state(false);
  let mineFailed = $state(false);
  let newTitle = $state('');
  let newDescription = $state('');
  /** Whether a new feed is listed in Discover; link only unless chosen. */
  let newListed = $state(false);
  let creating = $state(false);
  let listing = $state(false);
  let mineSelected = $state<string | null>(null);
  let editTitle = $state('');
  let editDescription = $state('');
  let editItems = $state<FeedItem[]>([]);
  /** The open feed as last loaded or saved, to tell real edits from undone ones. */
  let savedDraft = $state.raw<FeedDraft>({ title: '', description: '', items: [] });
  let saving = $state(false);
  let publishing = $state(false);
  let deleteOpen = $state(false);
  /** The feed Delete asks about, as `unfollowTitle` is. */
  let deleteTitle = $state('');
  let pickerOpen = $state(false);
  /** What to do once the user agrees to drop unsaved edits. */
  let discardThen = $state<(() => void) | null>(null);
  let leaving = false;

  let busy = $derived(saving || publishing || creating);
  let mineFeed = $derived(mine.find((f) => f.salt === mineSelected) ?? null);
  let dirty = $derived(
    !!mineFeed && !sameDraft({ title: editTitle, description: editDescription, items: editItems }, savedDraft),
  );
  let inFeed = $derived(new Set(editItems.map((i) => i.ed2k.toLowerCase())));
  let editSize = $derived(editItems.reduce((sum, i) => sum + i.size, 0));
  /** Published, and nothing saved or typed since: nothing to publish. */
  let upToDate = $derived(!!mineFeed && mineFeed.published_at > 0 && !mineFeed.changed && !dirty);
  let mineShown = $derived.by(() => {
    const q = listQuery.trim().toLowerCase();
    return q ? mine.filter((f) => f.title.toLowerCase().includes(q)) : mine;
  });

  function followersText({ count, at_least }: { count: number; at_least: boolean }): string {
    if (at_least) return m.feeds_followers({ count: `${formatNumber(count)}+` });
    return plural(count, {
      one: () => m.feeds_followers_one(),
      other: () => m.feeds_followers({ count: formatNumber(count) }),
    });
  }

  /** Followers who downloaded the file from this identity. */
  function downloadsOf(feed: OwnFeed, ed2k: string): number {
    return feed.downloads[ed2k.toLowerCase()] ?? 0;
  }

  function downloadsText(count: number): string {
    return plural(count, {
      one: () => m.feeds_item_downloads_one(),
      other: () => m.feeds_item_downloads({ count: formatNumber(count) }),
    });
  }

  let mineSeq = 0;
  let mineShownSeq = 0;
  /** The user's feeds, shown unless a later load has answered first.
   *  Returns what was read either way, or null if it could not be. `quiet`
   *  for a reload the user did not ask for: no toast. */
  async function loadMine(quiet = false): Promise<OwnFeed[] | null> {
    const seq = ++mineSeq;
    try {
      const feeds = await listMyFeeds();
      if (seq > mineShownSeq) {
        mineShownSeq = seq;
        mine = feeds;
        mineLoaded = true;
        mineFailed = false;
      }
      return feeds;
    } catch (e) {
      if (seq === mineSeq) {
        mineFailed = true;
        if (!quiet) toastError(translateError(e, m.error_operation_failed()));
      }
      return null;
    }
  }

  // As on Following: the feed open on the last visit opens again, else the
  // first, when none is.
  $effect(() => {
    const feeds = mine;
    if (feeds.length === 0) return;
    untrack(() => {
      if (feeds.some((f) => f.salt === mineSelected) || dirty) return;
      selectMine(feeds.find((f) => f.salt === feedsPageMemory.own) ?? feeds[0]);
    });
  });

  /** Run `then` now, or after the user agrees to lose unsaved edits. */
  function unlessDirty(then: () => void) {
    if (dirty) discardThen = then;
    else then();
  }

  function selectMine(feed: OwnFeed) {
    mineSelected = feed.salt;
    feedsPageMemory.own = feed.salt;
    editTitle = feed.title;
    editDescription = feed.description;
    editItems = feed.items.map((i) => ({ ...i }));
    savedDraft = draftOf(feed);
  }

  async function create() {
    if (creating || !newTitle.trim()) return;
    creating = true;
    try {
      const feed = await createFeed(newTitle, newDescription, newListed);
      newTitle = '';
      newDescription = '';
      newListed = false;
      compose = null;
      await loadMine();
      selectMine(feed);
      await focusActiveRow();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      creating = false;
    }
  }

  function addFiles(files: FileInfo[]) {
    const taken = new Set(inFeed);
    const fresh = files
      .filter((f) => {
        const key = f.hash.toLowerCase();
        if (taken.has(key)) return false;
        taken.add(key);
        return true;
      })
      .slice(0, Math.max(0, FEED_ITEMS_MAX - editItems.length));
    if (fresh.length === 0) return;
    editItems = [
      ...editItems,
      ...fresh.map((f) => ({ ed2k: f.hash, name: f.name, size: f.size, aich: f.aich_hash, blake3: f.ember_file_hash, note: '' })),
    ];
  }

  /** The editor's file list. */
  let editList = $state<HTMLElement | null>(null);

  /** The editor's row `index`'s `tool` button, if it can be pressed. */
  const editTool = (index: number, tool: 'up' | 'down' | 'remove') =>
    editList?.querySelector<HTMLElement>(`[data-row="${index}"] [data-tool="${tool}"]:not(:disabled)`);

  async function move(index: number, step: -1 | 1) {
    const to = index + step;
    if (to < 0 || to >= editItems.length) return;
    const next = editItems.slice();
    [next[index], next[to]] = [next[to], next[index]];
    editItems = next;
    // Focus stays with the file moved; at the top or the bottom, the arrow
    // pressed is disabled, and the other one takes it.
    await tick();
    const [same, other] = step < 0 ? (['up', 'down'] as const) : (['down', 'up'] as const);
    (editTool(to, same) ?? editTool(to, other))?.focus();
  }

  async function removeItem(index: number) {
    editItems = editItems.filter((_, i) => i !== index);
    // The button pressed went with its row: the next row's takes focus,
    // else the one before's, else the list's Add files.
    await tick();
    const near = editTool(index, 'remove') ?? editTool(index - 1, 'remove');
    (near ?? editList?.querySelector<HTMLElement>('.file-list-empty button:not(:disabled)') ?? editList)?.focus();
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

  /** Files the feed no longer holds because they stopped being shared with everyone. */
  function droppedText(names: string[]): string {
    return plural(names.length, {
      one: () => m.feeds_items_dropped_one({ name: names[0] }),
      other: () => m.feeds_items_dropped_other({ count: formatNumber(names.length), name: names[0] }),
    });
  }

  async function saveDraft(d: Draft): Promise<boolean> {
    try {
      const details = await setFeedDetails(d.salt, d.title, d.description);
      const { items, dropped } = await setFeedItems(d.salt, d.items);
      // What was kept, which leaves out anything dropped and is cleaned as
      // the backend saves it: as reloaded, or as the save answered when the
      // reload fails.
      const saved = (await loadMine())?.find((f) => f.salt === d.salt) ?? { ...details, items };
      if (mineSelected === d.salt) {
        // Edits made while the save ran stay in the editor, unsaved.
        if (sameDraft({ title: editTitle, description: editDescription, items: editItems }, d)) {
          editTitle = saved.title;
          editDescription = saved.description;
          editItems = saved.items.map((i) => ({ ...i }));
        }
        savedDraft = draftOf(saved);
      }
      if (dropped.length > 0) toastWarning(droppedText(dropped));
      return true;
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
      return false;
    }
  }

  async function save() {
    const d = draft();
    if (!d || busy || !d.title.trim()) return;
    saving = true;
    try {
      await saveDraft(d);
    } finally {
      saving = false;
    }
  }

  async function publish() {
    const d = draft();
    if (!d || busy || !d.title.trim()) return;
    publishing = true;
    try {
      if (dirty && !(await saveDraft(d))) return;
      const published = await publishFeed(d.salt);
      const feed = (await loadMine())?.find((f) => f.salt === d.salt);
      if (feed && mineSelected === d.salt) selectMine(feed);
      addActionToast(
        'success',
        m.feeds_published_toast(),
        { label: m.feeds_copy_link(), run: () => void copy(published.link) },
        () => {},
      );
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      publishing = false;
    }
  }

  /** What the listing switch shows: the open feed's, or the user's choice
   *  while it saves. */
  let listedSwitch = $state(false);
  $effect(() => {
    listedSwitch = mineFeed?.listed ?? false;
  });

  /** Listing goes out at once, apart from the editor's Save and Publish. */
  async function toggleListed(on: boolean) {
    const feed = mineFeed;
    if (!feed || listing) return;
    listedSwitch = on;
    listing = true;
    try {
      const saved = await setFeedListed(feed.salt, on);
      mine = mine.map((f) => (f.salt === saved.salt ? { ...f, listed: saved.listed } : f));
      if (saved.published_at > 0) toastSuccess(on ? m.feeds_listed_on_toast() : m.feeds_listed_off_toast());
    } catch (e) {
      if (mineSelected === feed.salt) listedSwitch = !on;
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      listing = false;
    }
  }

  function askDelete() {
    if (!mineFeed) return;
    deleteTitle = mineFeed.title.trim() || m.feeds_untitled();
    deleteOpen = true;
  }

  async function doDelete() {
    const feed = mineFeed;
    if (!feed) return;
    try {
      await deleteFeed(feed.salt);
      if (mineSelected === feed.salt) mineSelected = null;
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
    // Back on Discover, as `setTab` would have opened it.
    if (tab === 'discover') void openDiscover();
    let unlisten: UnlistenFn | null = null;
    let alive = true;
    let settledTimer: ReturnType<typeof setTimeout> | null = null;
    const reloadItemsSoon = () => {
      if (settledTimer) return;
      settledTimer = setTimeout(() => {
        settledTimer = null;
        const feed = selected;
        if (feed && itemsFor === keyOf(feed)) void loadItems(feed, true);
      }, SETTLED_RELOAD_MS);
    };
    void listen<FeedsChangedEvent>(FEEDS_CHANGED_EVENT, (event) => {
      // One of ours names only its salt; a followed one, its publisher too.
      if (!event.payload?.publisher) void loadMine(true);
      // Files can change without a new list, as when one is downloaded
      // automatically.
      const feed = selected;
      if (feed && itemsFor === keyOf(feed) && concernsFollowed(event.payload, feed)) reloadItemsSoon();
    }).then((fn) => {
      if (alive) unlisten = fn;
      else fn();
    });
    let unlistenFound: UnlistenFn | null = null;
    void listen<FeedsFoundEvent>(FEEDS_FOUND_EVENT, (event) => {
      if (discovering && event.payload.walk === discoverWalk) takeFound(event.payload.feeds, event.payload.gone);
    }).then((fn) => {
      if (alive) unlistenFound = fn;
      else fn();
    });
    // The open feed's downloads move as their bytes arrive, between polls,
    // and show done or failed as soon as they are.
    const live = new Map<string, LiveProgress>();
    let liveTimer: ReturnType<typeof setTimeout> | null = null;
    const takeLive = () => {
      liveTimer = null;
      const next = withLiveProgress(items, live);
      live.clear();
      if (next !== items) items = next;
    };
    const unlistenTransfers: UnlistenFn[] = [];
    const listenTransfers = <T,>(event: string, handler: (payload: T) => void) =>
      void listen<T>(event, (e) => handler(e.payload)).then((fn) => {
        if (alive) unlistenTransfers.push(fn);
        else fn();
      });
    listenTransfers<{ id: string; direction?: string; completed_size?: number; downloaded: number; speed: number }>(
      'transfer-progress',
      (p) => {
        if (!p || p.direction === 'upload' || tab !== 'following' || !itemTransferIds.has(p.id)) return;
        live.set(p.id, { done: p.completed_size ?? p.downloaded, speed: p.speed });
        liveTimer ??= setTimeout(takeLive, LIVE_PROGRESS_MS);
      },
    );
    for (const event of ['transfer-complete', 'transfer-failed']) {
      listenTransfers<{ id: string }>(event, (p) => {
        if (p && tab === 'following' && itemTransferIds.has(p.id)) reloadItemsSoon();
      });
    }
    // Seen once the user comes back to Ember.
    const onFocus = () => void markShownRead();
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onFocus);
    // A card's menu closes on a click anywhere else, Escape, or the window
    // changing size, which would leave it beside a card that moved.
    const closeMenu = (e: Event) => {
      if (menu === null) return;
      if (
        e.type === 'resize' ||
        (e instanceof KeyboardEvent
          ? e.key === 'Escape'
          : !(e.target as Element | null)?.closest?.('.feed-card-menu, .card-menu-btn'))
      ) {
        menu = null;
      }
    };
    window.addEventListener('pointerdown', closeMenu);
    window.addEventListener('keydown', closeMenu);
    window.addEventListener('resize', closeMenu);
    const clock = setInterval(() => (now = Math.floor(Date.now() / 1000)), 60_000);
    // While the open feed waits on something, or its files are on their
    // way, keep what it shows current: nothing announces a fetch's progress
    // or a download's percentage.
    let polls = 0;
    const poll = setInterval(() => {
      const feed = selected;
      if (tab !== 'following' || !feed || document.visibilityState !== 'visible') return;
      polls++;
      // Files only queued, waiting on sources for hours perhaps, and a fetch
      // resting after giving up are looked at less often.
      const moving = items.some((i) => i.status === 'downloading');
      if (itemsInFlight && itemsFor === keyOf(feed) && (moving || polls % 4 === 0)) void loadItems(feed, true);
      const waiting = noList(feed) || feed.activity.fetching !== null || feed.state === 'fetching';
      if (waiting && polls % (resting(feed) ? 15 : 3) === 0) void refreshFollowedFeeds();
    }, 4_000);
    return () => {
      alive = false;
      unlisten?.();
      unlistenFound?.();
      for (const fn of unlistenTransfers) fn();
      if (liveTimer) clearTimeout(liveTimer);
      if (settledTimer) clearTimeout(settledTimer);
      clearInterval(clock);
      clearInterval(poll);
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onFocus);
      window.removeEventListener('pointerdown', closeMenu);
      window.removeEventListener('keydown', closeMenu);
      window.removeEventListener('resize', closeMenu);
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
      <button type="button" aria-pressed={tab === 'discover'} class:active={tab === 'discover'} onclick={() => setTab('discover')}>
        {m.feeds_tab_discover()}
      </button>
      <button type="button" aria-pressed={tab === 'mine'} class:active={tab === 'mine'} onclick={() => setTab('mine')}>
        {m.feeds_tab_mine()}
        {#if mine.length > 0}<span class="seg-count">{formatNumber(mine.length)}</span>{/if}
      </button>
    </div>
    {#if tab === 'following'}
      {#if anyUnread || markingAll}
        <button type="button" class="secondary refresh-btn" disabled={markingAll} onclick={() => void markAllRead()}>
          {#if markingAll}
            <span class="spinner xs" aria-hidden="true"></span>
          {:else}
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <polyline points="3 8 7 12 13 4"/>
            </svg>
          {/if}
          {m.feeds_mark_all_read()}
        </button>
      {/if}
      <button
        type="button"
        class="primary"
        aria-expanded={compose === 'follow'}
        bind:this={composeTrigger}
        onclick={() => toggleCompose('follow')}
      >
        {compose === 'follow' ? m.common_cancel() : m.feeds_follow_a_feed()}
      </button>
    {:else if tab === 'discover'}
      <button type="button" class="secondary refresh-btn" disabled={discovering || emberOff} onclick={() => void walkDiscover()}>
        {#if discovering}
          <span class="spinner xs" aria-hidden="true"></span>
          {m.feeds_discover_searching()}
        {:else}
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9"/><polyline points="13.5 2.5 13.5 5.5 10.5 5.5"/>
          </svg>
          {m.feeds_discover_refresh()}
        {/if}
      </button>
    {:else}
      {#if mineLoaded}
        <span class="feed-quota" title={m.feeds_quota_title({ max: formatNumber(FEEDS_MAX) })}>
          {m.feeds_quota({ count: formatNumber(mine.length), max: formatNumber(FEEDS_MAX) })}
        </span>
      {/if}
      <button
        type="button"
        class="primary"
        aria-expanded={compose === 'create'}
        disabled={busy || (compose !== 'create' && mine.length >= FEEDS_MAX)}
        title={compose !== 'create' && mine.length >= FEEDS_MAX ? m.feeds_quota_full({ max: formatNumber(FEEDS_MAX) }) : undefined}
        bind:this={composeTrigger}
        onclick={() => toggleCompose('create')}
      >
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
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions (Escape from any of its fields) -->
    <form class="compose-card" onsubmit={(e) => { e.preventDefault(); void follow(); }} onkeydown={composeKeydown}>
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
            {@attach (el: HTMLInputElement) => el.focus()}
          />
        </div>
        <button type="submit" class="primary" disabled={following || !followLink.trim()}>{m.feeds_follow()}</button>
      </div>
      <p class="compose-hint">{m.feeds_follow_privacy()}</p>
    </form>
  {:else if compose === 'create' && tab === 'mine'}
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions (Escape from any of its fields) -->
    <form class="compose-card" onsubmit={(e) => { e.preventDefault(); unlessDirty(() => void create()); }} onkeydown={composeKeydown}>
      <div class="compose-row">
        <input
          type="text"
          class="compose-input plain"
          bind:value={newTitle}
          oninput={(e) => {
            if (!composing(e)) newTitle = fitBytes(newTitle, TITLE_MAX);
          }}
          oncompositionend={() => (newTitle = fitBytes(newTitle, TITLE_MAX))}
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
      <fieldset class="visibility">
        <legend class="visibility-legend">{m.feeds_visibility_label()}</legend>
        <label class="visibility-option" class:chosen={!newListed}>
          <input type="radio" name="feed-visibility" checked={!newListed} onchange={() => (newListed = false)} />
          <span class="visibility-text">
            <span class="visibility-name">{m.feeds_visibility_link()}</span>
            <span class="visibility-hint">{m.feeds_visibility_link_hint()}</span>
          </span>
        </label>
        <label class="visibility-option" class:chosen={newListed}>
          <input type="radio" name="feed-visibility" checked={newListed} onchange={() => (newListed = true)} />
          <span class="visibility-text">
            <span class="visibility-name">{m.feeds_visibility_public()}</span>
            <span class="visibility-hint">{m.feeds_visibility_public_hint()}</span>
          </span>
        </label>
      </fieldset>
      <p class="compose-hint">{m.feeds_publish_public_hint()}</p>
    </form>
  {/if}

  {#if tab === 'following'}
    {#if $followedFeeds.length === 0 && $followedFeedsFailed}
      <div class="empty-card">
        <div class="empty-state">
          <p class="empty-title">{m.feeds_load_failed()}</p>
          <div class="empty-actions">
            <button type="button" class="primary empty-action" onclick={() => void refreshFollowedFeeds()}>{m.common_retry()}</button>
          </div>
        </div>
      </div>
    {:else if $followedFeeds.length === 0 && !$followedFeedsLoaded}
      <div class="empty-card"><span class="spinner xs" aria-hidden="true"></span><span class="sr-only">{m.common_loading()}</span></div>
    {:else if $followedFeeds.length === 0}
      <div class="empty-card">
        <div class="empty-state">
          <span class="empty-glyph">{@render feedGlyph()}</span>
          <p class="empty-title">{m.feeds_none_followed()}</p>
          <p class="empty-sub">{m.feeds_empty_following_body()}</p>
          {#if compose !== 'follow'}
            <div class="empty-actions">
              <button type="button" class="primary empty-action" onclick={() => (compose = 'follow')}>{m.feeds_follow_a_feed()}</button>
              <button type="button" class="secondary empty-action" onclick={() => setTab('discover')}>{m.feeds_browse_discover()}</button>
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
                class:deleted={feed.deleted}
                aria-current={active ? 'true' : undefined}
                title={feed.deleted ? `${feedLabel(feed)}: ${m.feeds_deleted_notice()}` : feedLabel(feed)}
                onclick={() => selectFollowed(keyOf(feed))}
              >
                <span class="feed-avatar" style:--feed-hue={hueOf(feed.publisher + feed.salt)}>{@render feedGlyph()}</span>
                <span class="feed-row-text">
                  <span class="feed-row-title">
                    <bdi dir="auto">{feedLabel(feed)}</bdi>
                    {#if !feed.title.trim()}<span class="row-key">{shortKey(feed.publisher)}</span>{/if}
                  </span>
                  <span
                    class="feed-row-sub"
                    class:warn={!feed.deleted && (feed.state === 'broken' || feed.activity.too_large || notSeen(feed))}
                  >{followedSub(feed)}</span>
                </span>
                {#if feed.unread > 0}
                  <span class="count-pill" aria-hidden="true">{feed.unread > 99 ? '99+' : feed.unread}</span>
                  <span class="sr-only">{m.feeds_unread_title({ count: formatNumber(feed.unread) })}</span>
                {/if}
              </button>
            {:else}
              <p class="list-empty">{m.feeds_no_matches()}</p>
            {/each}
          </div>
        </aside>

        <!-- svelte-ignore a11y_no_static_element_interactions (noticing the user act in the open feed; the controls are its own) -->
        <section class="detail-pane" onpointerdown={claimOpen} onkeydown={claimOpen} onwheel={claimOpen}>
          {#if selected}
            <header class="detail-head">
              <span class="feed-avatar lg" style:--feed-hue={hueOf(selected.publisher + selected.salt)}>{@render feedGlyph()}</span>
              <div class="detail-title">
                <h3 title={feedLabel(selected)}><bdi dir="auto">{feedLabel(selected)}</bdi></h3>
                <p class="detail-meta">
                  <span title={m.feeds_discover_publisher({ id: selected.publisher })}>{m.feeds_discover_publisher({ id: shortKey(selected.publisher) })}</span>
                  <span aria-hidden="true">·</span>
                  <!-- The count its head gave, until its files are in. -->
                  <span>{m.feeds_items_count({ count: formatNumber(itemsFor === keyOf(selected) ? listedItems.length : selected.item_count) })}</span>
                  {#if selectedSize > 0}<span aria-hidden="true">·</span><span>{formatBytes(selectedSize)}</span>{/if}
                  {#if selected.sequence > 0}
                    <span aria-hidden="true">·</span><span>{m.feeds_discover_updated({ when: ago(Math.floor(selected.sequence / 1000)) })}</span>
                  {/if}
                  {#if selected.checked_at > 0}
                    <span aria-hidden="true">·</span><span>{m.feeds_checked_at({ when: ago(selected.checked_at) })}</span>
                  {/if}
                </p>
              </div>
              <div class="detail-actions">
                {#if !selected.deleted}
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
                {/if}
                <button type="button" class="icon-btn" title={m.feeds_open_folder()} aria-label={m.feeds_open_folder()} onclick={() => void openFolder()}>
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" aria-hidden="true">
                    <path d="M2 4.5V12.5h12V6H7.5L6 4.5z"/>
                  </svg>
                </button>
                <button type="button" class="icon-btn" title={m.feeds_copy_link()} aria-label={m.feeds_copy_link()} onclick={() => void copy(selected!.link)}>
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M6.5 9.5a3 3 0 0 0 4.2 0l2.1-2.1a3 3 0 0 0-4.2-4.2l-.7.7"/><path d="M9.5 6.5a3 3 0 0 0-4.2 0L3.2 8.6a3 3 0 0 0 4.2 4.2l.7-.7"/>
                  </svg>
                </button>
                <button type="button" class="pill-btn danger-hover" onclick={askUnfollow}>{m.feeds_unfollow()}</button>
              </div>
            </header>
            {#if selected.description}
              <p class="detail-description"><bdi dir="auto">{selected.description}</bdi></p>
            {/if}
            <p class="private-note">
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <rect x="3.5" y="7" width="9" height="6.5" rx="1"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>
              </svg>
              <span>{m.feeds_private_note()}</span>
            </p>

            {#if selected.deleted}
              <div class="state-strip tone-warning" role="status">
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M8 2.5 14 13H2z"/><line x1="8" y1="6.5" x2="8" y2="9.5"/><line x1="8" y1="11.5" x2="8" y2="11.6"/>
                </svg>
                <span class="state-text">{m.feeds_deleted_notice()}</span>
                <button type="button" class="pill-btn strip-btn" onclick={askUnfollow}>{m.feeds_unfollow()}</button>
              </div>
            {/if}

            {@const strip = stateText(selected)}
            {#if strip}
              <div class="state-strip" class:tone-warning={strip.warn} role="status">
                {#if strip.busy}
                  <span class="spinner xs" aria-hidden="true"></span>
                {:else}
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M8 2.5 14 13H2z"/><line x1="8" y1="6.5" x2="8" y2="9.5"/><line x1="8" y1="11.5" x2="8" y2="11.6"/>
                  </svg>
                {/if}
                {#if strip.spoken}
                  <span class="state-text" aria-hidden="true">{strip.text}</span>
                  <span class="sr-only">{strip.spoken}</span>
                {:else}
                  <span class="state-text">{strip.text}</span>
                {/if}
                {#if strip.retry}
                  <button type="button" class="pill-btn strip-btn" disabled={refreshing || emberOff} onclick={() => void refreshSelected()}>
                    {m.common_retry()}
                  </button>
                {/if}
              </div>
            {/if}

            <!-- Nothing new comes of a deleted feed, so nothing downloads by itself. -->
            {#if !selected.deleted}
              <div class="auto-card" class:on={selected.auto_download}>
                <div class="auto-head">
                  <span class="auto-icon" aria-hidden="true">
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                      <path d="M8 2v8M4.5 6.5 8 10l3.5-3.5"/><path d="M2.5 11.5v1.75h11V11.5"/>
                    </svg>
                  </span>
                  <button type="button" class="auto-title" aria-expanded={autoOpen} onclick={() => (autoOpen = !autoOpen)}>
                    <span class="auto-text">
                      <span class="auto-line">
                        <span class="auto-name">{m.feeds_auto_title()}</span>
                        <span class="auto-state">{selected.auto_download ? m.feeds_auto_on() : m.feeds_auto_off()}</span>
                      </span>
                      <span class="auto-desc">{m.feeds_auto_desc()}</span>
                      {#if selected.auto_download}
                        <span class="auto-summary">{autoSummary(selected.auto_max_item_mib, selected.auto_max_day_mib)}</span>
                      {/if}
                    </span>
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
                        <input type="number" min="0" max={AUTO_MIB_MAX} bind:value={autoItemMib} onchange={() => (autoItemMib = capMib(autoItemMib))} />
                        <span class="field-hint">{mibText(autoItemMib)}</span>
                      </label>
                      <label class="field">
                        <span class="field-label">{m.feeds_auto_max_day()}</span>
                        <input type="number" min="0" max={AUTO_MIB_MAX} bind:value={autoDayMib} onchange={() => (autoDayMib = capMib(autoDayMib))} />
                        <span class="field-hint">{mibText(autoDayMib)}</span>
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
            {/if}

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
                <button type="button" class="primary sm-btn" disabled={downloading} onclick={() => askDownload(newItems.map((i) => i.ed2k))}>
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M8 2v9M4 8l4 4 4-4"/><line x1="3" y1="14" x2="13" y2="14"/>
                  </svg>
                  {m.feeds_download_all_new_size({ count: formatNumber(newItems.length), size: formatBytes(newSize) })}
                </button>
              {:else if downloadableItems.length > 1}
                <button type="button" class="secondary sm-btn" disabled={downloading} onclick={() => askDownload(downloadableItems.map((i) => i.ed2k))}>
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M8 2v9M4 8l4 4 4-4"/><line x1="3" y1="14" x2="13" y2="14"/>
                  </svg>
                  {m.feeds_download_all_size({ count: formatNumber(downloadableItems.length), size: formatBytes(downloadableSize) })}
                </button>
              {/if}
            </div>

            <div class="file-list" tabindex="-1" bind:this={followList}>
              {#if itemsLoading && items.length === 0}
                <div class="file-list-empty"><span class="spinner xs" aria-hidden="true"></span><span class="sr-only">{m.common_loading()}</span></div>
              {:else if itemsFailed && items.length === 0}
                <div class="file-list-empty">
                  <p>{m.feeds_items_load_failed()}</p>
                  <button type="button" class="secondary sm-btn" onclick={() => void loadItems(selected)}>{m.common_retry()}</button>
                </div>
              {:else if items.length === 0}
                <div class="file-list-empty">{m.feeds_no_items()}</div>
              {:else if shownItems.length === 0}
                <div class="file-list-empty">{itemFilter === 'new' && !itemQuery.trim() ? m.feeds_no_new() : m.browse_no_match()}</div>
              {/if}
              {#each shownItems as item (item.ed2k)}
                {@const type = typeOf(item.name)}
                <div class="file-row" class:removed={item.removed} class:is-new={item.is_new && !item.removed} data-row={item.ed2k}>
                  {@render fileIcon(type)}
                  <div class="file-main">
                    <span class="file-name" title={item.name}>
                      <bdi dir="auto">{item.name}</bdi>
                      {#if item.is_new && !item.removed}<span class="badge sm tone-accent">{m.feeds_badge_new()}</span>{/if}
                      {#if item.removed}<span class="badge sm tone-muted">{m.feeds_badge_removed()}</span>{/if}
                      {#if item.risky}<span class="badge sm tone-warning" title={m.common_risky_file()}>{m.feeds_badge_risky()}</span>{/if}
                    </span>
                    <span class="file-meta">
                      <span>{formatBytes(item.size)}</span>
                      {#if type}<span aria-hidden="true">·</span><span>{fileTypeFilterLabel(type)}</span>{/if}
                      {#if item.first_seen > 0}<span aria-hidden="true">·</span><span>{m.feeds_item_added_at({ when: ago(item.first_seen) })}</span>{/if}
                      {#if item.held}<span aria-hidden="true">·</span><span class="held">{heldText(item.held)}</span>{/if}
                      {#if item.status === 'missing'}<span aria-hidden="true">·</span><span>{m.feeds_item_missing()}</span>{/if}
                      {#if item.status === 'cancelled'}<span aria-hidden="true">·</span><span>{m.feeds_item_cancelled()}</span>{/if}
                      {#if item.status === 'elsewhere'}
                        <span aria-hidden="true">·</span>
                        <span>{m.feeds_item_elsewhere({ feed: item.elsewhere?.trim() || m.feeds_untitled() })}</span>
                      {/if}
                      {#if item.status === 'failed' && item.transfer && (item.transfer.failure_reason || item.transfer.failure_code)}
                        <span aria-hidden="true">·</span>
                        <span class="failed">{transferFailureReasonText(item.transfer.failure_reason, item.transfer.failure_code)}</span>
                      {/if}
                    </span>
                    {#if item.note}
                      <span class="file-note"><bdi dir="auto">{item.note}</bdi></span>
                    {/if}
                    {#if item.status === 'downloading' || item.status === 'queued' || item.status === 'paused'}
                      <span class="row-progress" aria-hidden="true"><span style:width={`${Math.min(100, Math.max(0, item.progress))}%`}></span></span>
                      {#if item.transfer}
                        <span class="file-meta transfer-meta">{transferText(item)}</span>
                      {/if}
                    {/if}
                  </div>
                  {#if onDisk(item.status)}
                    <div class="row-controls">
                      <span class="row-done" title={item.status === 'done' ? m.feeds_badge_downloaded() : m.feeds_item_in_library()}>
                        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                          <polyline points="3 8 7 12 13 4"/>
                        </svg>
                        <span>{item.status === 'done' ? m.feeds_badge_downloaded() : m.feeds_item_in_library()}</span>
                      </span>
                      <button
                        type="button"
                        class="icon-btn"
                        title={m.feeds_item_open()}
                        aria-label={m.feeds_item_open_named({ name: item.name })}
                        onclick={() => void openItem(item, openFeedItem)}
                      >
                        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                          <path d="M9.5 2.5h4v4"/><path d="M13.5 2.5 7.5 8.5"/><path d="M12 9.5v4H2.5V4h4"/>
                        </svg>
                      </button>
                      <button
                        type="button"
                        class="icon-btn"
                        title={m.feeds_item_show()}
                        aria-label={m.feeds_item_show_named({ name: item.name })}
                        onclick={() => void openItem(item, showFeedItem)}
                      >
                        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" aria-hidden="true">
                          <path d="M2 4.5V12.5h12V6H7.5L6 4.5z"/>
                        </svg>
                      </button>
                    </div>
                  {:else if item.status === 'downloading' || item.status === 'queued' || item.status === 'paused'}
                    {@const stateText =
                      item.status === 'downloading'
                        ? m.feeds_item_downloading({ percent: formatNumber(Math.floor(item.progress)) })
                        : item.status === 'queued'
                          ? m.feeds_item_queued()
                          : m.feeds_item_paused()}
                    {#if item.transfer?.other_feed}
                      <span class="row-state muted" title={m.feeds_item_other_feed()}>{stateText}</span>
                    {:else if !item.transfer || item.transfer.in_transfers}
                      <a
                        class="row-state"
                        href="/transfers"
                        title={m.feeds_show_in_transfers()}
                        aria-label={m.feeds_item_in_transfers_named({ name: item.name, state: stateText })}
                      >{stateText}</a>
                    {:else}
                      {@const busy = controlling.has(item.transfer.id)}
                      <div class="row-controls">
                        <span class="row-state">{stateText}</span>
                        {#if item.status === 'paused'}
                          <button
                            type="button"
                            class="icon-btn"
                            disabled={busy}
                            title={m.feeds_item_resume()}
                            aria-label={m.feeds_item_resume_named({ name: item.name })}
                            onclick={() => void controlItem(item, resumeTransfer)}
                          >
                            <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M5 3.5v9l7-4.5z"/></svg>
                          </button>
                        {:else}
                          <button
                            type="button"
                            class="icon-btn"
                            disabled={busy}
                            title={m.feeds_item_pause()}
                            aria-label={m.feeds_item_pause_named({ name: item.name })}
                            onclick={() => void controlItem(item, pauseTransfer)}
                          >
                            <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><rect x="4" y="3.5" width="2.6" height="9" rx="0.6"/><rect x="9.4" y="3.5" width="2.6" height="9" rx="0.6"/></svg>
                          </button>
                        {/if}
                        <button
                          type="button"
                          class="icon-btn danger"
                          disabled={busy}
                          title={m.feeds_item_cancel()}
                          aria-label={m.feeds_item_cancel_named({ name: item.name })}
                          onclick={() => (cancelAsk = item)}
                        >
                          <IconX />
                        </button>
                      </div>
                    {/if}
                  {:else if canDownload(item)}
                    {@const discardable =
                      item.status === 'failed' && !!item.transfer && !item.transfer.in_transfers && !item.transfer.other_feed}
                    <div class="row-controls">
                      <button
                        type="button"
                        class="row-btn"
                        class:retry={item.status === 'failed'}
                        disabled={downloading}
                        aria-label={item.status === 'failed'
                          ? m.feeds_item_retry_named({ name: item.name })
                          : m.feeds_download_named({ name: item.name })}
                        data-download
                        onclick={() => askDownload([item.ed2k], item.ed2k)}
                      >
                        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                          <path d="M8 2v9M4 8l4 4 4-4"/><line x1="3" y1="14" x2="13" y2="14"/>
                        </svg>
                        <span>{item.status === 'failed' ? m.feeds_item_failed_retry() : m.feeds_download()}</span>
                      </button>
                      {#if discardable && item.transfer}
                        <button
                          type="button"
                          class="icon-btn danger"
                          disabled={controlling.has(item.transfer.id)}
                          title={m.feeds_item_discard()}
                          aria-label={m.feeds_item_discard_named({ name: item.name })}
                          onclick={() => (cancelAsk = item)}
                        >
                          <IconX />
                        </button>
                      {/if}
                    </div>
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
  {:else if tab === 'discover'}
    {#if !discoverLoaded}
      <div class="empty-card"><span class="spinner xs" aria-hidden="true"></span><span class="sr-only">{m.common_loading()}</span></div>
    {:else if discovered.length === 0}
      <div class="empty-card">
        <div class="empty-state">
          <span class="empty-glyph">{@render feedGlyph()}</span>
          <p class="empty-title">{discovering ? m.feeds_discover_searching() : m.feeds_discover_empty_title()}</p>
          <p class="empty-sub">{m.feeds_discover_empty_body()}</p>
          {#if hiddenCount > 0 && !discovering}
            <div class="empty-actions">
              <button type="button" class="secondary empty-action" onclick={() => (showHiddenAsk = true)}>
                {m.feeds_discover_show_hidden({ count: formatNumber(hiddenCount) })}
              </button>
            </div>
          {/if}
        </div>
      </div>
    {:else}
      <div class="discover-pane">
        <div class="discover-toolbar">
          <div class="discover-search">
            {@render searchBox(discoverQuery, (v) => (discoverQuery = v), m.feeds_discover_search())}
          </div>
          <div class="segmented small" role="group" aria-label={m.feeds_tab_discover()}>
            <button type="button" aria-pressed={discoverFilter === 'all'} class:active={discoverFilter === 'all'} onclick={() => (discoverFilter = 'all')}>
              {m.feeds_filter_all()}
              <span class="seg-count">{formatNumber(discovered.length)}</span>
            </button>
            <button type="button" aria-pressed={discoverFilter === 'active'} class:active={discoverFilter === 'active'} onclick={() => (discoverFilter = 'active')}>
              {m.feeds_discover_filter_active()}
              <span class="seg-count">{formatNumber(activeDiscovered)}</span>
            </button>
          </div>
          {#if discoverPublisher}
            <span class="filter-chip">
              <span title={discoverPublisher}>{m.feeds_discover_publisher_filter({ id: shortKey(discoverPublisher) })}</span>
              <button type="button" title={m.common_clear()} aria-label={m.common_clear()} onclick={() => (discoverPublisher = null)}>
                <IconX size={11} />
              </button>
            </span>
          {/if}
          <span class="toolbar-spacer"></span>
          {#if hiddenCount > 0}
            <button type="button" class="link-btn" disabled={discovering} onclick={() => (showHiddenAsk = true)}>
              {m.feeds_discover_show_hidden({ count: formatNumber(hiddenCount) })}
            </button>
          {/if}
          <label class="sort-select">
            <span class="sr-only">{m.feeds_discover_sort()}</span>
            <select
              value={discoverSort}
              aria-label={m.feeds_discover_sort()}
              onchange={(e) => pickSort(e.currentTarget.value as DiscoverSort)}
            >
              <option value="active">{m.feeds_discover_sort_active()}</option>
              <option value="newest">{m.feeds_discover_sort_newest()}</option>
              <option value="files">{m.feeds_discover_sort_files()}</option>
              <option value="name">{m.feeds_discover_sort_name()}</option>
            </select>
          </label>
        </div>
        <p class="discover-hint">{m.feeds_discover_hint()}</p>

        <div class="discover-scroll" tabindex="-1" bind:this={discoverScroll} onscroll={() => menu && closeCardMenu(false)}>
          {#if discoverMatches.length === 0}
            <p class="list-empty">{m.feeds_no_matches()}</p>
          {/if}
          <div class="discover-grid">
            {#each discoverShown as feed (keyOf(feed))}
              {@const key = keyOf(feed)}
              {@const isFollowed = followedKeys.has(key)}
              <article class="discover-card" class:menu-open={menuFor === key} data-card={key}>
                <header class="discover-card-head">
                  <span class="feed-avatar" style:--feed-hue={hueOf(feed.publisher + feed.salt)}>{@render feedGlyph()}</span>
                  <div class="discover-card-title">
                    <h3 title={feed.title}><bdi dir="auto">{feed.title.trim() || m.feeds_untitled()}</bdi></h3>
                    <p class="discover-seen">
                      <span class="seen-state" class:active={feed.active} title={feed.active ? m.feeds_discover_active_title() : undefined}>
                        <span class="status-dot" class:published={feed.active} aria-hidden="true"></span>
                        {seenText(feed)}
                      </span>
                      <span class="seen-sep" aria-hidden="true">·</span>
                      <button
                        type="button"
                        class="publisher-key"
                        title={m.feeds_discover_publisher({ id: feed.publisher })}
                        aria-label={`${m.feeds_discover_publisher({ id: shortKey(feed.publisher) })}: ${m.feeds_discover_by_publisher()}`}
                        onclick={() => (discoverPublisher = feed.publisher)}
                      >{shortKey(feed.publisher)}</button>
                    </p>
                  </div>
                  <button
                    type="button"
                    class="icon-btn sm card-menu-btn"
                    aria-haspopup="menu"
                    aria-expanded={menuFor === key}
                    title={m.feeds_discover_more()}
                    aria-label={m.feeds_discover_more()}
                    onclick={(e) => toggleMenu(feed, e.currentTarget)}
                  >
                    <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
                      <circle cx="3.5" cy="8" r="1.3"/><circle cx="8" cy="8" r="1.3"/><circle cx="12.5" cy="8" r="1.3"/>
                    </svg>
                  </button>
                </header>
                {#if feed.description}
                  <p class="discover-description" title={feed.description}><bdi dir="auto">{feed.description}</bdi></p>
                {/if}
                <footer class="discover-card-foot">
                  <span class="discover-meta">
                    <span>{m.feeds_items_count({ count: formatNumber(feed.item_count) })}</span>
                    {#if feed.total_size > 0}<span aria-hidden="true">·</span><span>{formatBytes(feed.total_size)}</span>{/if}
                    {#if feed.sequence > 0}
                      <span aria-hidden="true">·</span>
                      <span>{m.feeds_discover_updated({ when: ago(Math.floor(feed.sequence / 1000)) })}</span>
                    {/if}
                  </span>
                  {#if feed.own}
                    <span class="own-actions">
                      <span class="badge sm tone-muted">{m.feeds_badge_yours()}</span>
                      <button type="button" class="secondary sm-btn" onclick={() => editOwn(feed)}>{m.feeds_discover_edit()}</button>
                    </span>
                  {:else if isFollowed}
                    <button type="button" class="secondary sm-btn" data-card-action onclick={() => openFollowed(feed)}>{m.feeds_discover_open()}</button>
                  {:else}
                    <button
                      type="button"
                      class="primary sm-btn"
                      disabled={emberOff || followingFromDiscover.has(key)}
                      data-card-action
                      onclick={() => void followDiscovered(feed)}
                    >
                      {m.feeds_follow()}
                    </button>
                  {/if}
                </footer>
              </article>
            {/each}
          </div>
          <!-- Keyed so another card's menu is a new one, given focus too. -->
          {#key menuFor}
          {#if menu}
            {@const feed = menu.feed}
            <div
              class="ctx-menu feed-card-menu"
              role="menu"
              tabindex="-1"
              aria-label={m.feeds_discover_more()}
              use:ctxMenuPosition={{ x: menu.x, y: menu.y }}
              onkeydown={cardMenuKeydown}
              {@attach (el: HTMLElement) => el.querySelector<HTMLElement>('[role="menuitem"]')?.focus()}
            >
              <button type="button" class="ctx-item" role="menuitem" onclick={() => { closeCardMenu(true); void copy(feed.link); }}>
                {m.feeds_copy_link()}
              </button>
              {#if discoverPublisher !== feed.publisher}
                <button type="button" class="ctx-item" role="menuitem" onclick={() => { closeCardMenu(true); discoverPublisher = feed.publisher; }}>
                  {m.feeds_discover_by_publisher()}
                </button>
              {/if}
              {#if !feed.own}
                <div class="ctx-sep" role="separator"></div>
                <button type="button" class="ctx-item" role="menuitem" onclick={() => void hideDiscovered(feed, false)}>
                  {m.feeds_discover_hide()}
                </button>
                <button type="button" class="ctx-item ctx-danger" role="menuitem" onclick={() => void hideDiscovered(feed, true)}>
                  {m.feeds_discover_hide_publisher()}
                </button>
              {/if}
            </div>
          {/if}
          {/key}
          {#if discoverMatches.length > discoverShown.length}
            <div class="discover-more">
              <button type="button" class="secondary" onclick={() => (discoverLimit += DISCOVER_PAGE)}>
                {m.feeds_discover_show_more({ count: formatNumber(discoverMatches.length - discoverShown.length) })}
              </button>
            </div>
          {/if}
        </div>
      </div>
    {/if}
  {:else if !mineLoaded}
    <div class="empty-card">
      {#if mineFailed}
        <div class="empty-state">
          <p class="empty-title">{m.feeds_load_failed()}</p>
          <div class="empty-actions">
            <button type="button" class="primary empty-action" onclick={() => void loadMine()}>{m.common_retry()}</button>
          </div>
        </div>
      {:else}
        <span class="spinner xs" aria-hidden="true"></span>
        <span class="sr-only">{m.common_loading()}</span>
      {/if}
    </div>
  {:else if mine.length === 0}
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
              <span class="feed-avatar" style:--feed-hue={hueOf(feed.publisher + feed.salt)}>{@render feedGlyph()}</span>
              <span class="feed-row-text">
                <span class="feed-row-title"><bdi dir="auto">{feed.title}</bdi></span>
                <span class="feed-row-sub">
                  {feed.published_at > 0
                    ? m.feeds_published_short({ when: ago(feed.published_at) })
                    : m.feeds_items_count({ count: formatNumber(feed.items.length) })}
                  {#if feed.published_at > 0 && (feed.followers || !emberOff)}
                    <span aria-hidden="true"> · </span>{feed.followers ? followersText(feed.followers) : m.feeds_followers_counting()}
                  {/if}
                  {#if feed.listed && feed.published_at > 0}<span aria-hidden="true"> · </span>{m.feeds_badge_listed()}{/if}
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
            <span class="feed-avatar lg" style:--feed-hue={hueOf(mineFeed.publisher + mineFeed.salt)}>{@render feedGlyph()}</span>
            <div class="detail-title">
              <input
                type="text"
                class="title-input"
                bind:value={editTitle}
                disabled={busy}
                oninput={(e) => {
                  if (!composing(e)) editTitle = fitBytes(editTitle, TITLE_MAX);
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
                <span>{m.feeds_items_count({ count: formatNumber(editItems.length) })}</span>
                {#if editSize > 0}<span aria-hidden="true">·</span><span>{formatBytes(editSize)}</span>{/if}
                {#if mineFeed.published_at > 0 && mineFeed.followers}
                  <span aria-hidden="true">·</span>
                  <span class="has-hint" title={m.feeds_followers_hint({ when: ago(mineFeed.followers.checked_at) })}>
                    {followersText(mineFeed.followers)}
                  </span>
                {:else if mineFeed.published_at > 0 && !emberOff}
                  <!-- Not counted yet: nothing is counted while the network is off. -->
                  <span aria-hidden="true">·</span>
                  <span>{m.feeds_followers_counting()}</span>
                {/if}
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
              <button type="button" class="icon-btn danger-hover" disabled={busy} title={m.feeds_delete()} aria-label={m.feeds_delete()} onclick={askDelete}>
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
            }}
            oncompositionend={() => (editDescription = fitBytes(editDescription, DESCRIPTION_MAX))}
            placeholder={m.feeds_description_placeholder()}
            aria-label={m.feeds_description_placeholder()}
          ></textarea>

          <div class="share-row">
            <span class="share-label">{m.feeds_share_label()}</span>
            {#if mineFeed.published_at > 0}
              <input
                type="text"
                class="share-link"
                readonly
                value={mineFeed.link}
                aria-label={m.feeds_share_label()}
                onfocus={(e) => e.currentTarget.select()}
              />
              <button type="button" class="secondary sm-btn" onclick={() => void copy(mineFeed!.link)}>{m.feeds_copy_link()}</button>
            {:else}
              <span class="share-pending">{m.feeds_share_after_publish()}</span>
            {/if}
          </div>

          <div class="listed-row" class:on={mineFeed.listed}>
            <span class="auto-icon" aria-hidden="true">
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="8" cy="8" r="6"/><path d="M2 8h12"/><path d="M8 2a9 9 0 0 1 0 12a9 9 0 0 1 0-12"/>
              </svg>
            </span>
            <span class="listed-text">
              <span class="auto-name">{m.feeds_listed_toggle()}</span>
              <span class="hint">
                {#if !mineFeed.listed}
                  {m.feeds_visibility_link_hint()}
                {:else if mineFeed.published_at === 0}
                  {m.feeds_listed_hint_unpublished()}
                {:else}
                  {m.feeds_visibility_public_hint()}
                {/if}
              </span>
            </span>
            <ToggleSwitch
              checked={listedSwitch}
              disabled={listing || busy || (emberOff && mineFeed.published_at > 0)}
              ariaLabel={m.feeds_listed_toggle()}
              onchange={(on) => void toggleListed(on)}
            />
          </div>

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

          <div class="file-list" tabindex="-1" bind:this={editList}>
            {#if editItems.length === 0}
              <div class="file-list-empty">
                <p>{m.feeds_no_items()}</p>
                <button type="button" class="primary sm-btn" disabled={busy} onclick={() => (pickerOpen = true)}>{m.feeds_add_files()}</button>
              </div>
            {/if}
            {#each editItems as item, i (item.ed2k)}
              {@const type = typeOf(item.name)}
              {@const downloads = downloadsOf(mineFeed, item.ed2k)}
              <div class="file-row" data-row={i}>
                <span class="file-index" aria-hidden="true">{i + 1}</span>
                {@render fileIcon(type)}
                <div class="file-main">
                  <span class="file-name"><bdi dir="auto">{item.name}</bdi></span>
                  <span class="file-meta">
                    <span>{formatBytes(item.size)}</span>
                    {#if type}<span aria-hidden="true">·</span><span>{fileTypeFilterLabel(type)}</span>{/if}
                    {#if downloads > 0}
                      <span aria-hidden="true">·</span>
                      <span class="has-hint" title={m.feeds_item_downloads_hint()}>{downloadsText(downloads)}</span>
                    {/if}
                  </span>
                  <input
                    type="text"
                    class="note-input"
                    bind:value={item.note}
                    disabled={busy}
                    placeholder={m.feeds_note_placeholder()}
                    aria-label={m.feeds_note_named({ name: item.name })}
                    oninput={(e) => {
                      if (!composing(e)) item.note = fitBytes(item.note, NOTE_MAX);
                    }}
                    oncompositionend={() => (item.note = fitBytes(item.note, NOTE_MAX))}
                  />
                </div>
                <div class="row-tools">
                  <button
                    type="button"
                    class="icon-btn sm"
                    disabled={busy || i === 0}
                    aria-label={m.feeds_move_up_named({ name: item.name })}
                    title={m.feeds_move_up()}
                    data-tool="up"
                    onclick={() => void move(i, -1)}
                  >
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="4 10 8 6 12 10"/></svg>
                  </button>
                  <button
                    type="button"
                    class="icon-btn sm"
                    disabled={busy || i === editItems.length - 1}
                    aria-label={m.feeds_move_down_named({ name: item.name })}
                    title={m.feeds_move_down()}
                    data-tool="down"
                    onclick={() => void move(i, 1)}
                  >
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="4 6 8 10 12 6"/></svg>
                  </button>
                  <button
                    type="button"
                    class="icon-btn sm danger-hover"
                    disabled={busy}
                    aria-label={m.feeds_remove_named({ name: item.name })}
                    title={m.feeds_remove()}
                    data-tool="remove"
                    onclick={() => void removeItem(i)}
                  >
                    <IconX size={13} />
                  </button>
                </div>
              </div>
            {/each}
          </div>

          <footer class="editor-foot">
            <p class="hint" class:up-to-date={upToDate} id="feeds-publish-hint">
              {upToDate ? m.feeds_publish_up_to_date_title() : m.feeds_publish_public_hint()}
            </p>
            <div class="editor-foot-actions">
              <button type="button" class="secondary" disabled={!dirty || busy || !editTitle.trim()} onclick={() => void save()}>{m.feeds_save()}</button>
              <!-- Published and unchanged: publishing again would only bump the
                   sequence, and the hourly republish keeps the head alive. -->
              <button
                type="button"
                class="primary"
                disabled={busy || emberOff || upToDate || !editTitle.trim()}
                aria-describedby={upToDate ? 'feeds-publish-hint' : undefined}
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
  title={m.feeds_unfollow_confirm_named({ title: unfollowTitle })}
  message={m.feeds_unfollow_confirm_body()}
  confirmLabel={m.feeds_unfollow()}
  danger
  onconfirm={() => void doUnfollow()}
/>

<ConfirmDialog
  bind:open={showHiddenAsk}
  title={m.feeds_discover_show_hidden_title()}
  message={m.feeds_discover_show_hidden_body()}
  confirmLabel={m.feeds_discover_show_hidden_confirm()}
  onconfirm={() => void showHidden()}
/>

<ConfirmDialog
  open={riskyAsk !== null}
  title={m.feeds_risky_confirm_title()}
  message={riskyAsk ? riskyText(riskyAsk.names) : ''}
  confirmLabel={m.feeds_risky_confirm()}
  danger
  onconfirm={() => {
    const ask = riskyAsk;
    riskyAsk = null;
    if (ask) void download(ask.ed2ks, ask.from);
  }}
  altLabel={riskyAsk && riskyAsk.safe.length > 0 ? m.feeds_risky_skip({ count: formatNumber(riskyAsk.safe.length) }) : undefined}
  onalt={() => {
    const ask = riskyAsk;
    riskyAsk = null;
    if (ask) void download(ask.safe, ask.from);
  }}
  oncancel={() => (riskyAsk = null)}
  ondismiss={() => (riskyAsk = null)}
/>

<ConfirmDialog
  open={cancelAsk !== null}
  title={cancelAsk?.status === 'failed' ? m.feeds_item_discard_title() : m.feeds_item_cancel_title()}
  message={cancelAsk
    ? cancelAsk.status === 'failed'
      ? m.feeds_item_discard_body({ name: cancelAsk.name })
      : m.feeds_item_cancel_body({ name: cancelAsk.name })
    : ''}
  confirmLabel={cancelAsk?.status === 'failed' ? m.feeds_item_discard() : m.feeds_item_cancel()}
  danger
  onconfirm={() => {
    const item = cancelAsk;
    const feed = selected;
    cancelAsk = null;
    if (item && feed) void controlItem(item, () => cancelFeedDownload(feed.publisher, feed.salt, item.ed2k));
  }}
  oncancel={() => (cancelAsk = null)}
/>

<ConfirmDialog
  bind:open={deleteOpen}
  title={m.feeds_delete_confirm_named({ title: deleteTitle })}
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
  cancelLabel={m.feeds_discard_keep()}
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

  /* Kept for what was downloaded, but nothing more comes of it. */
  .feed-row.deleted .feed-avatar {
    filter: grayscale(1);
    opacity: 0.6;
  }

  .feed-row.deleted:not(.active) .feed-row-title {
    color: var(--text-secondary);
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
    overflow-wrap: anywhere;
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
    padding: 10px 10px 10px 12px;
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

  .auto-text {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .auto-line {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .auto-desc {
    font-size: var(--font-size-xs);
    font-weight: 400;
    color: var(--text-muted);
    line-height: 1.45;
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

  /* Two lines of room, text at the bottom, so the inputs of labels that wrap
     differently still line up. */
  .field-label {
    display: flex;
    align-items: flex-end;
    min-height: calc(2 * 1.35em);
    font-size: var(--font-size-xs);
    line-height: 1.35;
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

  .has-hint {
    cursor: help;
    text-decoration: underline dotted;
    text-decoration-color: color-mix(in srgb, currentColor 45%, transparent);
    text-underline-offset: 2px;
  }

  .file-note {
    margin-top: 2px;
    padding-inline-start: 8px;
    border-inline-start: 2px solid color-mix(in srgb, var(--accent) 40%, var(--border));
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    line-height: 1.45;
    overflow-wrap: anywhere;
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

  /* ── Visibility (new feed, editor) ────────────────────────────────── */
  .visibility {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 8px;
    margin: 10px 0 0;
    padding: 0;
    border: 0;
  }

  .visibility-legend {
    margin-bottom: 6px;
    padding: 0;
    font-size: var(--font-size-xs);
    font-weight: 600;
    color: var(--text-secondary);
  }

  .visibility-option {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-primary);
    cursor: pointer;
    transition: border-color var(--transition-fast), background var(--transition-fast);
  }

  .visibility-option.chosen {
    border-color: color-mix(in srgb, var(--accent) 50%, var(--border));
    background: color-mix(in srgb, var(--accent) 7%, var(--bg-primary));
  }

  .visibility-option input {
    margin-top: 2px;
    accent-color: var(--accent);
  }

  .visibility-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .visibility-name {
    font-size: var(--font-size-sm);
    font-weight: 600;
  }

  .visibility-hint {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    line-height: 1.45;
  }

  .share-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0 18px 10px;
    min-width: 0;
  }

  .share-label {
    flex-shrink: 0;
    font-size: var(--font-size-xs);
    font-weight: 600;
    color: var(--text-secondary);
  }

  .share-link {
    flex: 1;
    min-width: 0;
    padding: 5px 8px;
    font-size: var(--font-size-xs);
    font-family: var(--font-mono, monospace);
    color: var(--text-secondary);
  }

  .share-pending {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
  }

  .feed-quota {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .row-key {
    margin-inline-start: 6px;
    font-size: var(--font-size-xs);
    font-weight: 400;
    color: var(--text-muted);
  }

  .state-text {
    flex: 1;
    min-width: 0;
  }

  .strip-btn {
    min-height: 24px;
    padding: 0 10px;
    flex-shrink: 0;
  }

  .auto-summary {
    font-size: var(--font-size-xs);
    color: var(--text-accent);
  }

  .field-hint {
    font-size: var(--font-size-2xs, 11px);
    color: var(--text-muted);
  }

  .file-meta .held {
    color: var(--badge-warning-text);
  }

  .file-meta .failed {
    color: var(--danger);
  }

  .row-state.muted {
    color: var(--text-muted);
  }

  .row-progress {
    display: block;
    height: 3px;
    margin-top: 6px;
    max-width: 320px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--text-muted) 20%, transparent);
    overflow: hidden;
  }

  .row-progress > span {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 0.4s ease;
  }

  .row-state {
    flex-shrink: 0;
    min-height: 30px;
    display: inline-flex;
    align-items: center;
    padding: 0 10px;
    font-size: var(--font-size-sm);
    font-weight: 600;
    color: var(--text-accent);
    font-variant-numeric: tabular-nums;
    text-decoration: none;
  }

  a.row-state:hover {
    text-decoration: underline;
  }

  .row-controls {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    gap: 2px;
  }

  .row-controls .row-state,
  .row-controls .row-done {
    padding-inline-end: 4px;
  }

  .row-controls .row-btn + .icon-btn {
    margin-inline-start: 4px;
  }

  .icon-btn.danger:hover:not(:disabled) {
    color: var(--danger);
  }

  .transfer-meta {
    margin-top: 4px;
  }

  .row-btn.retry {
    color: var(--badge-warning-text);
    border-color: color-mix(in srgb, var(--warning) 40%, var(--border));
    background: color-mix(in srgb, var(--warning) 10%, transparent);
  }

  .sort-select select {
    min-height: 28px;
    padding: 2px 8px;
    font-size: var(--font-size-xs);
  }

  .own-actions {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .listed-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 0 18px 12px;
    padding: 8px 10px 8px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-primary);
    transition: border-color var(--transition-fast);
  }

  .listed-row.on {
    border-color: color-mix(in srgb, var(--accent) 38%, var(--border));
  }

  .listed-row.on .auto-icon {
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
  }

  .listed-text {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  /* ── Discover ─────────────────────────────────────────────────────── */
  .refresh-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .refresh-btn svg {
    width: 13px;
    height: 13px;
  }

  .discover-pane {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: inset 0 1px 0 var(--surface-highlight);
  }

  .discover-toolbar {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    padding: 10px 14px 0;
  }

  .discover-search {
    width: 280px;
  }

  .discover-search .search-wrap {
    margin: 0;
  }

  .link-btn {
    padding: 2px 4px;
    border: 0;
    background: none;
    color: var(--text-accent);
    font-size: var(--font-size-sm);
    cursor: pointer;
  }

  .link-btn:hover:not(:disabled) {
    background: none;
    text-decoration: underline;
  }

  .link-btn:disabled {
    background: none;
    color: var(--text-muted);
    cursor: default;
  }

  .discover-hint {
    margin: 8px 14px 0;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    line-height: 1.5;
  }

  .discover-scroll {
    flex: 1;
    min-height: 0;
    overflow: auto;
    padding: 10px 14px 14px;
  }

  .discover-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 10px;
  }

  .discover-card {
    display: flex;
    flex-direction: column;
    gap: 10px;
    min-width: 0;
    min-height: 148px;
    padding: 14px 14px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-primary);
    transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
  }

  .discover-card:hover,
  .discover-card.menu-open {
    border-color: color-mix(in srgb, var(--accent) 35%, var(--border));
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.06);
  }

  .discover-card-head {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    min-width: 0;
  }

  .discover-card-title {
    flex: 1;
    min-width: 0;
  }

  .discover-card-title h3 {
    margin: 1px 0 0;
    font-size: var(--font-size-md);
    font-weight: 600;
    line-height: 1.3;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .discover-seen {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
    margin: 3px 0 0;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    white-space: nowrap;
  }

  .seen-state {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    min-width: 0;
    /* Room for the status dot's ring, which `overflow` would clip. */
    padding-inline-start: 3px;
    margin-inline-start: -3px;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .seen-state.active {
    color: var(--success);
  }

  .seen-state .status-dot {
    flex-shrink: 0;
  }

  .seen-sep {
    flex-shrink: 0;
  }

  .card-menu-btn {
    flex-shrink: 0;
    margin: -4px -6px 0 0;
  }

  .feed-card-menu {
    min-width: 230px;
  }

  .discover-description {
    margin: 0;
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    line-height: 1.45;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    overflow-wrap: anywhere;
  }

  .discover-card-foot {
    margin-top: auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding-top: 10px;
    border-top: 1px solid color-mix(in srgb, var(--border) 60%, transparent);
  }

  .discover-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 6px;
    min-width: 0;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .discover-more {
    display: flex;
    justify-content: center;
    padding-top: 12px;
  }

  /* A short key, not a heading: it reads as part of the status line. */
  .publisher-key {
    flex-shrink: 0;
    min-height: 0;
    padding: 0 4px;
    border: 0;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text-muted);
    font: inherit;
    font-weight: 400;
    font-variant-numeric: tabular-nums;
    letter-spacing: 0.02em;
    cursor: pointer;
  }

  .publisher-key:hover {
    background: var(--bg-hover);
    color: var(--text-accent);
  }

  .filter-chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 4px 2px 10px;
    border: 1px solid color-mix(in srgb, var(--accent) 40%, var(--border));
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--accent) 10%, transparent);
    color: var(--text-accent);
    font-size: var(--font-size-xs);
  }

  .filter-chip button {
    display: grid;
    place-items: center;
    width: 18px;
    height: 18px;
    padding: 0;
    border: 0;
    border-radius: 50%;
    background: none;
    color: inherit;
    cursor: pointer;
  }

  .filter-chip button:hover {
    background: color-mix(in srgb, var(--accent) 20%, transparent);
  }

  .private-note {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 0 18px 12px;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    line-height: 1.45;
  }

  .private-note svg {
    flex-shrink: 0;
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

    /* The public notice stays: it is what is said before a first publish. */
    .editor-foot {
      flex-wrap: wrap;
    }
  }

  @container (max-width: 600px) {
    .workspace {
      grid-template-columns: 1fr;
      grid-template-rows: minmax(120px, 32%) minmax(0, 1fr);
    }

    .files-search,
    .discover-search {
      width: 100%;
    }
  }
</style>
