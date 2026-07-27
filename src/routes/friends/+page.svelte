<script lang="ts">
  import { getFriends, addFriend, removeFriend, blockFriend, unblockFriend, getBlockedFriends, updateFriendNickname, getMyEmberHash, acceptFriendRequest, rejectFriendRequest, retryFriendSearch, type FriendInfo, type FriendRequestInfo, type BlockedInfo } from '$lib/api/friends';
  import { getNetworkStats, kadRecheckFirewall } from '$lib/api/kad';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import BrowseFriendDialog from '$lib/components/BrowseFriendDialog.svelte';
  import { openChat as openChatTab, removeChatForFriend, renameTab as renameChatTab } from '$lib/stores/chatTabs';
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import { fade, fly } from 'svelte/transition';
  import { flip } from 'svelte/animate';
  import { toastWarning } from '$lib/stores/toast';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';
  import {
    onlineFriends as onlineFriendsStore,
    unreadCounts as unreadCountsStore,
    friendRequests as friendRequestsStore,
    searchingFriends as searchingFriendsStore,
    clearFriendSearch,
    isDiscoverable as isDiscoverableStore,
    discoverabilityFailed as discoverabilityFailedStore,
    clearUnread,
    beginFriendRequestMutation,
    endFriendRequestMutation,
    fileOffers as fileOffersStore,
    clearFileOffer,
  } from '$lib/stores/friends';
  import { appSettings } from '$lib/stores/settings';
  import { networkStats } from '$lib/stores/network';

  let friends: FriendInfo[] = $state([]);
  let browseDisabled = $derived($appSettings?.friend_browse_disabled === true);
  let loading = $state(true);
  let error: string | null = $state(null);
  let successMsg: string | null = $state(null);

  let myHash = $state('');
  let myHashCopied = $state(false);
  let myHashCopyTimer: ReturnType<typeof setTimeout> | undefined;

  let showAddForm = $state(false);
  let newHash = $state('');
  let newNickname = $state('');
  let addError: string | null = $state(null);

  let confirmRemoveOpen = $state(false);
  let pendingRemove: FriendInfo | null = $state(null);

  let confirmBlockOpen = $state(false);
  /** Either a friend or a stranger from the approval queue — blocking works
   *  the same for both, so only the name and hash are carried. */
  let pendingBlock: { user_hash: string; nickname: string } | null = $state(null);
  let blocked: BlockedInfo[] = $state([]);
  let blockedOpen = $state(false);

  let editingHash: string | null = $state(null);
  let editNickname = $state('');

  let searchQuery = $state('');
  let copiedHash: string | null = $state(null);
  let copyTimer: ReturnType<typeof setTimeout> | undefined;

  let onlineFriends: Set<string> = $derived($onlineFriendsStore);
  let unreadCounts: Map<string, number> = $derived($unreadCountsStore);

  let friendRequests: FriendRequestInfo[] = $derived($friendRequestsStore);
  let pendingOffers = $derived($fileOffersStore);
  /** Offer currently being accepted, so its buttons can be disabled. */
  let acceptingOffer: string | null = $state(null);

  function offerKey(userHash: string, fileHash: string): string {
    return `${userHash}:${fileHash}`;
  }

  function friendLabel(userHash: string): string {
    const f = friends.find(x => x.user_hash === userHash);
    return f?.nickname || userHash.slice(0, 8) + '\u2026';
  }

  function formatOfferSize(bytes: number): string {
    if (!bytes) return '';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit++;
    }
    return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
  }

  /**
   * Accept an offer by starting an ordinary download, seeded with the offering
   * friend as a source. Nothing about the push path bypasses the normal
   * transfer pipeline.
   */
  async function acceptOffer(offer: { user_hash: string; file_hash: string; file_name: string; file_size: number }) {
    const key = offerKey(offer.user_hash, offer.file_hash);
    if (acceptingOffer) return;
    acceptingOffer = key;
    try {
      const { startDownload } = await import('$lib/api/transfers');
      // Seed the friend's last-known address when we have one; the backend
      // falls back to rendezvous lookup and normal source discovery otherwise.
      const f = friends.find(x => x.user_hash === offer.user_hash);
      const ip = f?.last_ip?.trim() ?? '';
      const port = f?.last_port ?? 0;
      await startDownload(
        offer.file_hash,
        offer.file_name,
        offer.file_size,
        ip && port > 0 ? ip : '',
        ip && port > 0 ? port : 0,
        undefined,
        undefined,
        offer.user_hash,
      );
      clearFileOffer(offer.user_hash, offer.file_hash);
      flash(m.friends_offer_accepted({ name: offer.file_name }));
    } catch (e: unknown) {
      error = toErr(e);
    } finally {
      acceptingOffer = null;
    }
  }
  let failedSearchToastsShown = new Set<string>();
  const FRIEND_HASH_RE = /^[0-9a-f]{32}$/i;

  function validFriendHash(raw: unknown): string | null {
    return typeof raw === 'string' && FRIEND_HASH_RE.test(raw) ? raw.toLowerCase() : null;
  }

  // Whenever a friend comes online, reset our "we already toasted for this
  // hash" memo so the next offline search failure can re-toast. Reactively
  // driven from the onlineFriends store (no separate Tauri listener needed).
  $effect(() => {
    for (const hash of onlineFriends) failedSearchToastsShown.delete(hash);
  });
  let searchingFriends: Set<string> = $derived($searchingFriendsStore);
  let reconnectingFriends = $state(new Set<string>());
  let isFirewalled = $state(false);
  // A symmetric NAT re-maps per destination, so hole punching cannot get
  // through and a firewalled friend genuinely cannot be reached without port
  // forwarding. Every other NAT class can be punched, so the advice differs.
  //
  // Read from the shared store rather than a local snapshot: the STUN NAT probe
  // resolves well after this page mounts and emits no event of its own, so a
  // one-shot fetch would leave a symmetric user reading the softer advice
  // indefinitely. The store is polled app-wide from `+layout.svelte`.
  let isSymmetricNat = $derived($networkStats.nat_type === 'Symmetric');
  let recheckingFirewall = $state(false);
  let recheckError: string | null = $state(null);

  let browseOpen = $state(false);
  let browseFriendHash = $state('');
  let browseFriendName = $state('');
  let browseFriendIp = $state('');
  let browseFriendPort = $state(0);

  let isDiscoverable = $derived($isDiscoverableStore);
  let registrationFailed = $derived($discoverabilityFailedStore);
  let processingRequests: Set<string> = $state(new Set());
  let adding = $state(false);

  // Module-scoped lifecycle flag used by async loaders below so they don't
  // patch state after navigation.
  let destroyed = false;

  function autoFocus(node: HTMLElement) {
    node.focus();
  }

  let flashTimer: ReturnType<typeof setTimeout> | undefined;

  let filtered = $derived.by(() => {
    let list = friends;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (f) => f.user_hash.toLowerCase().includes(q) || f.nickname.toLowerCase().includes(q),
      );
    }
    return list.slice().sort((a, b) => {
      const aOn = onlineFriends.has(a.user_hash) ? 0 : 1;
      const bOn = onlineFriends.has(b.user_hash) ? 0 : 1;
      if (aOn !== bOn) return aOn - bOn;
      const aName = (a.nickname || a.user_hash).toLowerCase();
      const bName = (b.nickname || b.user_hash).toLowerCase();
      return aName.localeCompare(bName);
    });
  });

  let onlineFiltered = $derived(filtered.filter(f => onlineFriends.has(f.user_hash)));
  let offlineFiltered = $derived(filtered.filter(f => !onlineFriends.has(f.user_hash)));
  // Count only friends that are online — `onlineFriends` (the raw store set)
  // can momentarily hold a hash that isn't in the current friend list, which
  // would inflate the header count.
  let onlineFriendCount = $derived(friends.filter(f => onlineFriends.has(f.user_hash)).length);

  function openChat(f: FriendInfo) {
    // Delegate to the global multi-conversation dock. It opens the
    // dock if not already visible, adds (or focuses) a tab for this
    // friend, and lets the user keep chatting while navigating to
    // other pages. `clearUnread` is also called inside
    // `ChatConversation` on mount, but firing it here too keeps the
    // friend-card badge from briefly flashing the stale count
    // between click and tab-mount.
    openChatTab(f.user_hash, f.nickname || f.user_hash.slice(0, 8) + '\u2026');
    clearUnread(f.user_hash);
  }

  function openBrowse(f: FriendInfo) {
    if (browseDisabled) return;
    browseFriendHash = f.user_hash;
    browseFriendName = f.nickname || f.user_hash.slice(0, 8) + '\u2026';
    browseFriendIp = f.last_ip || '';
    browseFriendPort = f.last_port || 0;
    browseOpen = true;
  }

  function closeBrowse() {
    browseOpen = false;
  }

  function formatLastSeen(ts: number): string {
    if (!ts) return '';
    const now = Date.now() / 1000;
    const diff = now - ts;
    if (diff < 60) return m.friends_just_now();
    if (diff < 3600) return m.friends_minutes_ago({ minutes: Math.floor(diff / 60) });
    if (diff < 86400) return m.friends_hours_ago({ hours: Math.floor(diff / 3600) });
    return new Date(ts * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  function friendPresence(f: FriendInfo): 'online' | 'offline' {
    return onlineFriends.has(f.user_hash) ? 'online' : 'offline';
  }

  async function reloadFriendRequests() {
    try {
      const { getFriendRequests } = await import('$lib/api/friends');
      const reqs = await getFriendRequests();
      friendRequestsStore.set(reqs);
    } catch (e) {
      // Non-fatal: the optimistic update already adjusted the list. Log so a
      // persistent reconciliation failure is visible in devtools.
      console.warn('reloadFriendRequests failed:', e);
    }
  }

  async function handleAcceptRequest(req: FriendRequestInfo) {
    if (processingRequests.has(req.sender_hash)) return;
    processingRequests.add(req.sender_hash);
    processingRequests = new Set(processingRequests);
    beginFriendRequestMutation();
    try {
      await acceptFriendRequest(req.sender_hash);
      // Optimistically drop the accepted row so it disappears immediately even
      // if the follow-up reconciliation fetch fails.
      friendRequestsStore.update(reqs => reqs.filter(r => r.sender_hash !== req.sender_hash));
      flash(m.friends_accepted_request({ name: req.sender_nickname || req.sender_hash.slice(0, 8) + '\u2026' }));
      await reloadFriendRequests();
      await loadFriends();
    } catch (e: unknown) {
      error = toErr(e);
      // Accept can fail because the request no longer exists (withdrawn, or
      // handled in another window). Resync so a stale row doesn't linger.
      await reloadFriendRequests();
    } finally {
      endFriendRequestMutation();
      processingRequests.delete(req.sender_hash);
      processingRequests = new Set(processingRequests);
    }
  }

  async function handleRetrySearch(f: FriendInfo) {
    // Re-trigger a rendezvous/DHT search for an offline friend. The backend
    // emits `ember:friend-searching` (which drives the row's "Searching…"
    // state) and then a terminal online/failed event, so no extra local
    // spinner state is needed here.
    if (searchingFriends.has(f.user_hash) || reconnectingFriends.has(f.user_hash)) return;
    reconnectingFriends = new Set(reconnectingFriends).add(f.user_hash);
    try {
      await retryFriendSearch(f.user_hash);
    } catch (e: unknown) {
      error = toErr(e);
    } finally {
      const next = new Set(reconnectingFriends);
      next.delete(f.user_hash);
      reconnectingFriends = next;
    }
  }

  async function handleRejectRequest(req: FriendRequestInfo) {
    if (processingRequests.has(req.sender_hash)) return;
    processingRequests.add(req.sender_hash);
    processingRequests = new Set(processingRequests);
    beginFriendRequestMutation();
    try {
      await rejectFriendRequest(req.sender_hash);
      friendRequestsStore.update(reqs => reqs.filter(r => r.sender_hash !== req.sender_hash));
    } catch (e: unknown) {
      error = toErr(e);
    } finally {
      endFriendRequestMutation();
      processingRequests.delete(req.sender_hash);
      processingRequests = new Set(processingRequests);
    }
  }

  /**
   * Backstop for the case where no attempt ever reports back at all.
   *
   * A registration that genuinely fails emits `ember:friend-discoverable`
   * with a reason, and that path shows the warning immediately — this timer
   * is not how a real fault is meant to surface. What it covers is silence:
   * an attempt that hangs, or one that never starts because the external IP
   * has yet to be confirmed. It therefore sits past the backend's 60-second
   * registration watchdog on purpose, so the UI never reports a fault while
   * an attempt is still legitimately running. Erring the other way would put
   * a warning on screen during ordinary startups, and one that cries wolf
   * costs us the times it is right.
   */
  const DISCOVERABILITY_GRACE_MS = 90_000;
  let undiscoverable = $state(false);
  /** Deliberately not `$state`. The effect below re-runs on every network
   *  stats poll, so a reactive handle would restart the countdown each time
   *  and the grace period would never elapse. */
  let discoverabilityTimer: ReturnType<typeof setTimeout> | undefined;

  $effect(() => {
    const stalled = $networkStats.status === 'connected' && !isDiscoverable;
    if (!stalled) {
      clearTimeout(discoverabilityTimer);
      discoverabilityTimer = undefined;
      undiscoverable = false;
      return;
    }
    // An attempt that came back failed needs no waiting out — the grace
    // period exists to tell "still trying" apart from "cannot", and the
    // backend has just answered that question.
    if (registrationFailed) {
      clearTimeout(discoverabilityTimer);
      discoverabilityTimer = undefined;
      undiscoverable = true;
      return;
    }
    // Left assigned after it fires, so the poll-driven re-runs above see an
    // armed timer and do not queue another one behind it.
    discoverabilityTimer ??= setTimeout(() => {
      undiscoverable = true;
    }, DISCOVERABILITY_GRACE_MS);
  });

  let recheckTimer: ReturnType<typeof setTimeout> | undefined;

  async function handleRecheckFirewall() {
    recheckingFirewall = true;
    recheckError = null;
    try {
      await kadRecheckFirewall();
    } catch (e) {
      if (destroyed) return;
      recheckError = translateError(e, m.error_operation_failed());
    }
    if (destroyed) return;
    clearTimeout(recheckTimer);
    recheckTimer = setTimeout(() => { recheckingFirewall = false; }, 5000);
  }

  onMount(() => {
    destroyed = false;
    loadFriends();
    loadBlocked();
    loadMyHash();
    getNetworkStats()
      .then(s => { if (!destroyed) isFirewalled = s.firewalled; })
      .catch((e) => { console.warn('friends: initial getNetworkStats failed:', e); });

    const unlistenFns: (() => void)[] = [];

    // Page-local listeners for side effects not already covered by the shared
    // friends store (which already handles online/offline state updates).
    // We intentionally do NOT register another listener for 'ember:friend-online'
    // — we rely on the `onlineFriendsStore` subscription above to drive
    // `onlineFriends`, and the effect below takes care of the toast-clear
    // side effect. This avoids double event handling when the page is open.
    listen<{ user_hash: string }>('ember:friend-confirmed', () => {
      if (destroyed) return;
      loadFriends();
    }).then(fn => { if (destroyed) fn(); else unlistenFns.push(fn); })
      .catch((e) => console.error('friends: failed to register ember:friend-confirmed listener', e));

    listen<{ firewalled: boolean }>('firewall-status', (event) => {
      if (destroyed) return;
      if (typeof event.payload?.firewalled !== 'boolean') return;
      isFirewalled = event.payload.firewalled;
      if (!event.payload.firewalled) recheckingFirewall = false;
    }).then(fn => { if (destroyed) fn(); else unlistenFns.push(fn); })
      .catch((e) => console.error('friends: failed to register firewall-status listener', e));

    listen<{ user_hash: string; reason?: string }>('ember:friend-search-failed', (event) => {
      if (destroyed) return;
      const hash = validFriendHash(event.payload?.user_hash);
      if (!hash) return;
      const reason = typeof event.payload?.reason === 'string' ? event.payload.reason : 'error';
      const f = friends.find(fr => fr.user_hash === hash);
      const name = f ? (f.nickname || hash.slice(0, 8) + '\u2026') : hash.slice(0, 8) + '\u2026';
      // Reconnect sweeps run on their own, so "offline / unreachable / not
      // found" outcomes are not events the user asked about — the friend card
      // already shows presence. Only surface outcomes they can act on.
      let msg: string | null;
      switch (reason) {
        case 'firewalled':
          msg = m.friends_search_firewalled({ name });
          break;
        case 'secure_v2_required':
          msg = m.error_secure_friend_v2_required();
          break;
        default:
          msg = null;
      }
      if (!msg) return;
      // Dedupe after picking the message so a silent sweep result can't
      // suppress the actionable toast that follows it.
      if (failedSearchToastsShown.has(hash)) return;
      failedSearchToastsShown.add(hash);
      toastWarning(msg);
    }).then(fn => { if (destroyed) fn(); else unlistenFns.push(fn); })
      .catch((e) => console.error('friends: failed to register ember:friend-search-failed listener', e));

    window.addEventListener('pointerdown', onCardMenuPointerDown, true);
    window.addEventListener('keydown', onCardMenuKeydown, true);

    return () => {
      destroyed = true;
      clearTimeout(flashTimer);
      clearTimeout(copyTimer);
      clearTimeout(myHashCopyTimer);
      clearTimeout(recheckTimer);
      clearTimeout(discoverabilityTimer);
      window.removeEventListener('pointerdown', onCardMenuPointerDown, true);
      window.removeEventListener('keydown', onCardMenuKeydown, true);
      unlistenFns.forEach(fn => fn());
    };
  });

  async function loadMyHash() {
    try {
      const h = await getMyEmberHash();
      if (destroyed) return;
      myHash = h;
    } catch {
      if (destroyed) return;
      myHash = '';
    }
  }

  function flash(msg: string) {
    error = null;
    clearTimeout(flashTimer);
    successMsg = msg;
    flashTimer = setTimeout(() => (successMsg = null), 4000);
  }

  function toErr(e: unknown): string {
    return translateError(e, m.error_operation_failed());
  }

  let loadFriendsSeq = 0;
  async function loadFriends() {
    if (destroyed) return;
    // Guard against overlapping loads (mount + 'ember:friend-confirmed' event,
    // or rapid events) resolving out of order and clobbering newer data with a
    // stale snapshot. Only the most recent invocation commits its result.
    const seq = ++loadFriendsSeq;
    loading = true;
    error = null;
    try {
      const list = await getFriends();
      if (destroyed || seq !== loadFriendsSeq) return;
      friends = list;
    } catch (e: unknown) {
      if (destroyed || seq !== loadFriendsSeq) return;
      error = toErr(e);
    } finally {
      if (!destroyed && seq === loadFriendsSeq) loading = false;
    }
  }

  async function loadBlocked() {
    if (destroyed) return;
    try {
      const list = await getBlockedFriends();
      if (!destroyed) blocked = list;
    } catch (e: unknown) {
      // A failed block list must not take the page down with it — the
      // friends list above is the primary content and loads independently.
      console.warn('friends: failed to load blocked identities:', e);
    }
  }

  function confirmBlock(user_hash: string, nickname: string) {
    pendingBlock = { user_hash, nickname };
    confirmBlockOpen = true;
  }

  async function handleBlock() {
    if (!pendingBlock) return;
    const target = pendingBlock;
    confirmBlockOpen = false;
    pendingBlock = null;
    // Holds the accept/reject buttons on any matching request card while this
    // runs, so the two cannot be dispatched against the same identity at once.
    processingRequests.add(target.user_hash);
    processingRequests = new Set(processingRequests);
    let reportedOk = false;
    try {
      await blockFriend(target.user_hash);
      reportedOk = true;
      flash(m.friends_blocked({ name: target.nickname || target.user_hash.slice(0, 8) + '\u2026' }));
    } catch (e: unknown) {
      error = toErr(e);
    } finally {
      await Promise.all([loadFriends(), loadBlocked()]);
      // Decide from the reloaded list rather than from whether the call
      // threw. The row is committed before the live teardown is
      // acknowledged, so a rejection can still mean "blocked, but the
      // network task did not confirm" — and skipping the cleanup then would
      // leave an open chat tab and an online marker for someone who is in
      // fact blocked. A failure earlier than the write leaves no row, and
      // this correctly does nothing.
      if (reportedOk || blocked.some(b => b.user_hash === target.user_hash)) {
        // Blocking subsumes removal, so the same cleanup applies: online
        // marker, unread badge, in-flight search, chat tab, pending request.
        onlineFriendsStore.update(s => { const next = new Set(s); next.delete(target.user_hash); return next; });
        clearUnread(target.user_hash);
        clearFriendSearch(target.user_hash);
        removeChatForFriend(target.user_hash);
        friendRequestsStore.update(reqs => reqs.filter(r => r.sender_hash !== target.user_hash));
      }
      processingRequests.delete(target.user_hash);
      processingRequests = new Set(processingRequests);
    }
  }

  async function handleUnblock(b: BlockedInfo) {
    try {
      await unblockFriend(b.user_hash);
      flash(m.friends_unblocked({ name: b.nickname || b.user_hash.slice(0, 8) + '\u2026' }));
      await loadBlocked();
    } catch (e: unknown) {
      error = toErr(e);
    }
  }

  function friendHashFromCode(value: string): string | null {
    const trimmed = value.trim();
    if (/^[0-9a-fA-F]{32}$/.test(trimmed)) return trimmed.toLowerCase();
    const match = /^ember2:([0-9a-fA-F]{32}):([0-9a-fA-F]{64})$/i.exec(trimmed);
    return match?.[1]?.toLowerCase() ?? null;
  }

  function isValidHash(h: string): boolean {
    return friendHashFromCode(h) !== null;
  }

  async function handleAdd() {
    if (adding) return;
    addError = null;
    const hash = newHash.trim();
    const nick = newNickname.trim();
    if (!hash) { addError = m.friends_validation_hash_required(); return; }
    if (!isValidHash(hash)) { addError = m.friends_validation_hash_format(); return; }
    const canonicalHash = friendHashFromCode(hash);
    if (myHash && canonicalHash === friendHashFromCode(myHash)) {
      addError = m.friends_validation_self_add();
      return;
    }
    if (friends.some((f) => f.user_hash.toLowerCase() === canonicalHash)) {
      addError = m.friends_validation_already_friend();
      return;
    }
    adding = true;
    try {
      await addFriend(hash, nick || undefined);
      flash(m.friends_added({ name: nick || hash.slice(0, 8) + '\u2026' }));
      newHash = '';
      newNickname = '';
      showAddForm = false;
      await loadFriends();
    } catch (e: unknown) {
      addError = toErr(e);
    } finally {
      adding = false;
    }
  }

  function confirmRemoveFriend(f: FriendInfo) {
    pendingRemove = f;
    confirmRemoveOpen = true;
  }

  async function handleRemove() {
    if (!pendingRemove) return;
    const f = pendingRemove;
    confirmRemoveOpen = false;
    pendingRemove = null;
    try {
      await removeFriend(f.user_hash);
      onlineFriendsStore.update(s => { const next = new Set(s); next.delete(f.user_hash); return next; });
      clearUnread(f.user_hash);
      // Drop any in-flight "searching" spinner/timer for the removed friend so
      // it doesn't keep spinning against a row that's about to disappear.
      clearFriendSearch(f.user_hash);
      // Close any open chat tab for the removed friend; leaving it
      // open would show a session for someone who is no longer in
      // the user's friend list and silently fail to send.
      removeChatForFriend(f.user_hash);
      flash(m.friends_removed({ name: f.nickname || f.user_hash.slice(0, 8) + '\u2026' }));
      await loadFriends();
    } catch (e: unknown) {
      error = toErr(e);
    }
  }

  function startEdit(f: FriendInfo) {
    editingHash = f.user_hash;
    editNickname = f.nickname;
  }

  let saveEditPending = false;
  async function saveEdit() {
    if (!editingHash || saveEditPending) return;
    saveEditPending = true;
    const hash = editingHash;
    const nick = editNickname.trim();
    try {
      await updateFriendNickname(hash, nick);
      const idx = friends.findIndex((f) => f.user_hash === hash);
      if (idx !== -1) friends[idx] = { ...friends[idx], nickname: nick };
      // Push the rename through to any open chat tab so the strip
      // and the conversation header don't keep the old nickname.
      renameChatTab(hash, nick || hash.slice(0, 8) + '\u2026');
      editingHash = null;
    } catch (e: unknown) {
      error = toErr(e);
    } finally {
      saveEditPending = false;
    }
  }

  function cancelEdit() {
    editingHash = null;
  }

  function editKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') saveEdit();
    else if (e.key === 'Escape') cancelEdit();
  }

  function addFormKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') handleAdd();
    else if (e.key === 'Escape') { showAddForm = false; addError = null; }
  }

  function formatDate(ts: number): string {
    if (!ts) return '';
    return new Date(ts * 1000).toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
    });
  }

  // The per-card overflow menu is a native `<details>`, matching the toolbar
  // menu on the Transfers page. `<details>` only closes on its own summary, so
  // selecting an item, clicking elsewhere, or pressing Escape closes it here.
  function closeCardMenu(from: HTMLElement) {
    (from.closest('details') as HTMLDetailsElement | null)?.removeAttribute('open');
  }

  function closeCardMenus(keepContaining?: Element | null) {
    for (const el of document.querySelectorAll<HTMLDetailsElement>('.card-more[open]')) {
      if (keepContaining && el.contains(keepContaining)) continue;
      el.open = false;
    }
  }

  function onCardMenuPointerDown(e: PointerEvent) {
    const target = e.target instanceof Element ? e.target : null;
    closeCardMenus(target);
  }

  function onCardMenuKeydown(e: KeyboardEvent) {
    if (e.key !== 'Escape') return;
    // Only swallow Escape when a menu is actually open, so dialogs and the
    // nickname editor keep their own Escape handling.
    if (!document.querySelector('.card-more[open]')) return;
    closeCardMenus();
    e.stopPropagation();
  }

  async function copyHash(hash: string) {
    try {
      await navigator.clipboard.writeText(hash);
      clearTimeout(copyTimer);
      copiedHash = hash;
      copyTimer = setTimeout(() => (copiedHash = null), 1500);
    } catch {
      // Clipboard API may be blocked
    }
  }

  async function copyMyHash() {
    try {
      await navigator.clipboard.writeText(myHash);
      clearTimeout(myHashCopyTimer);
      myHashCopied = true;
      myHashCopyTimer = setTimeout(() => (myHashCopied = false), 1500);
    } catch {
      // Clipboard API may be blocked
    }
  }

</script>

<ConfirmDialog
  bind:open={confirmRemoveOpen}
  title={m.friends_confirm_remove_title()}
  message={m.friends_confirm_remove_message({ name: pendingRemove ? (pendingRemove.nickname || pendingRemove.user_hash.slice(0, 8) + '\u2026') : '' })}
  confirmLabel={m.common_remove()}
  danger={true}
  onconfirm={handleRemove}
/>

<ConfirmDialog
  bind:open={confirmBlockOpen}
  title={m.friends_confirm_block_title()}
  message={m.friends_confirm_block_message({ name: pendingBlock ? (pendingBlock.nickname || pendingBlock.user_hash.slice(0, 8) + '\u2026') : '' })}
  confirmLabel={m.friends_block()}
  danger={true}
  onconfirm={handleBlock}
/>

<BrowseFriendDialog
  bind:open={browseOpen}
  friendHash={browseFriendHash}
  friendName={browseFriendName}
  friendLastIp={browseFriendIp}
  friendLastPort={browseFriendPort}
  onclose={closeBrowse}
/>

<div class="page-header">
  <h2>{m.nav_friends()}</h2>
  <div class="header-actions">
    <button class="ghost" onclick={loadFriends}>{m.common_refresh()}</button>
  </div>
</div>

<div class="page-content friends-content">
  <div class="alerts-stack">
    {#if error}
      <div class="banner error-banner" role="alert">
        <span>{error}</span>
        <button class="ghost" onclick={() => (error = null)}>{m.common_dismiss()}</button>
      </div>
    {:else if successMsg}
      <div class="banner success-banner" role="status">
        <span>{successMsg}</span>
      </div>
    {/if}

    {#if isFirewalled}
      <div class="banner firewall-banner" role="status">
        <div class="firewall-banner-content">
          <svg class="firewall-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10 1l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V4z"/>
            <line x1="10" y1="7" x2="10" y2="11"/>
            <circle cx="10" cy="14" r="0.5" fill="currentColor" stroke="none"/>
          </svg>
          <div class="firewall-text">
            <strong>{m.friends_firewall_title()}</strong>
            {isSymmetricNat ? m.friends_firewall_body_symmetric() : m.friends_firewall_body()}
          </div>
        </div>
        <button class="firewall-recheck" onclick={handleRecheckFirewall} disabled={recheckingFirewall}>
          {recheckingFirewall ? m.friends_firewall_checking() : m.friends_firewall_recheck()}
        </button>
        {#if recheckError}
          <span class="firewall-recheck-error" role="status">{m.friends_firewall_recheck_failed({ error: recheckError })}</span>
        {/if}
      </div>
    {/if}

    <!-- Only when not firewalled, which is the case that had no signal at
         all. A firewalled user already has the banner above telling them
         their reachability is limited, and stacking a second one would bury
         the advice that is actually actionable. No retry control: the network
         task is already retrying every ten seconds, so a button would do
         nothing the app is not doing anyway. -->
    {#if !isFirewalled && undiscoverable}
      <div class="banner undiscoverable-banner" role="status">
        <div class="firewall-banner-content">
          <svg class="undiscoverable-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="10" cy="10" r="7.5"/>
            <line x1="5" y1="5" x2="15" y2="15"/>
          </svg>
          <div class="firewall-text">
            <strong>{m.friends_undiscoverable_title()}</strong>
            {m.friends_undiscoverable_body()}
          </div>
        </div>
      </div>
    {/if}
  </div>

  <!-- Your Friend ID + network status -->
  {#if myHash}
    <div class="my-id-card">
      <div class="my-id-left">
        <div class="my-id-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="5" width="18" height="14" rx="2"/>
            <circle cx="9" cy="12" r="2.5"/>
            <path d="M15 10h3M15 14h2"/>
          </svg>
        </div>
        <div class="my-id-info">
          <span class="my-id-label">{m.friends_your_id_label()}</span>
          <span class="my-id-hash">{myHash}</span>
          <span class="my-id-hint">{m.friends_id_share_hint()}</span>
          {#if isFirewalled}
            <span class="my-id-status firewalled">{m.friends_status_firewalled_short()}</span>
          {:else if isDiscoverable}
            <span class="my-id-status discoverable">{m.friends_status_discoverable()}</span>
          {:else if undiscoverable}
            <span class="my-id-status undiscoverable">{m.friends_status_undiscoverable()}</span>
          {/if}
        </div>
      </div>
      <button class="my-id-copy" class:copied={myHashCopied} onclick={copyMyHash}>
        {#if myHashCopied}
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 8 7 12 13 4"/>
          </svg>
          {m.common_copied()}
        {:else}
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="5" y="5" width="9" height="9" rx="1.5"/>
            <path d="M3 11V3a1.5 1.5 0 011.5-1.5H11"/>
          </svg>
          {m.common_copy()}
        {/if}
      </button>
    </div>
  {/if}

  <!-- How Friends work -->
  <div class="how-panel" role="region" aria-label={m.friends_how_title()}>
    <div class="how-title">{m.friends_how_title()}</div>
    <ul class="how-list">
      <li>{m.friends_how_share()}</li>
      <li>{m.friends_how_mutual()}</li>
      <li>{m.friends_how_priority()}</li>
      <li>{m.friends_how_encrypted()}</li>
    </ul>
  </div>

  <!-- Pending friend requests -->
  {#if pendingOffers.length > 0}
    <div class="requests-section">
      <div class="requests-header">
        <span class="requests-title">{m.friends_offers_title()}</span>
        <span class="requests-badge">{pendingOffers.length}</span>
      </div>
      <div class="requests-list">
        {#each pendingOffers as offer (offerKey(offer.user_hash, offer.file_hash))}
          <div
            class="request-card"
            in:fly={{ y: 6, duration: 200 }}
            out:fade={{ duration: 150 }}
            animate:flip={{ duration: 200 }}
          >
            <div class="request-avatar">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 16V4" />
                <path d="M7 9l5-5 5 5" />
                <path d="M4 17v2a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-2" />
              </svg>
            </div>
            <div class="request-info">
              <span class="request-name"><bdi>{offer.file_name}</bdi></span>
              <span class="request-hash">
                {m.friends_offer_from({ name: friendLabel(offer.user_hash) })}
                {#if offer.file_size}&nbsp;&middot;&nbsp;{formatOfferSize(offer.file_size)}{/if}
              </span>
            </div>
            <div class="request-actions">
              <button
                class="req-accept"
                disabled={acceptingOffer !== null}
                onclick={() => acceptOffer(offer)}
              >{m.friends_offer_download()}</button>
              <button
                class="req-reject"
                disabled={acceptingOffer !== null}
                onclick={() => clearFileOffer(offer.user_hash, offer.file_hash)}
              >{m.common_dismiss()}</button>
            </div>
          </div>
        {/each}
      </div>
    </div>
  {/if}

  {#if friendRequests.length > 0}
    <div class="requests-section">
      <div class="requests-header">
        <span class="requests-title">{m.friends_requests_title()}</span>
        <span class="requests-badge">{friendRequests.length}</span>
      </div>
      <div class="requests-list">
        {#each friendRequests as req (req.sender_hash)}
          <div
            class="request-card"
            in:fly={{ y: 6, duration: 200 }}
            out:fade={{ duration: 150 }}
            animate:flip={{ duration: 200 }}
          >
            <div class="request-avatar">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="8" r="4"/>
                <path d="M4 21c0-4.418 3.582-8 8-8s8 3.582 8 8"/>
              </svg>
            </div>
            <div class="request-info">
              <span class="request-name">
                <!--
                  M14: nickname is peer-controlled. Wrap in `<bdi>`
                  so RTL/LTR override characters embedded in a
                  malicious nickname can't reorder the surrounding
                  layout (e.g. flipping "Verified"/"Unverified"
                  next to a different name). Default Svelte
                  escaping prevents XSS; this closes the
                  bidi-spoofing presentation gap.
                -->
                <bdi dir="auto">{req.sender_nickname || m.friends_unknown_sender()}</bdi>
                {#if req.verified}
                  <!-- "Verified" badge: see commit history for the
                       cryptographic semantics. -->
                  <span class="request-badge request-badge-verified" title={m.friends_request_verified_title()}>{m.friends_request_verified()}</span>
                {:else}
                  <!-- Unverified: peer didn't complete identity
                       verification on this session. -->
                  <span class="request-badge request-badge-unverified" title={m.friends_request_unverified_title()}>{m.friends_request_unverified()}</span>
                {/if}
              </span>
              <span class="request-hash" title={req.sender_hash}>{req.sender_hash.slice(0, 8)}&hellip;{req.sender_hash.slice(-6)}</span>
            </div>
            <div class="request-actions">
              <button class="request-accept" onclick={() => handleAcceptRequest(req)} disabled={processingRequests.has(req.sender_hash)}>{m.friends_accept()}</button>
              <button class="request-reject" onclick={() => handleRejectRequest(req)} disabled={processingRequests.has(req.sender_hash)}>{m.friends_reject()}</button>
              <!-- Rejecting only clears the row; the same stranger can ask
                   again immediately. Blocking from here is the way to make
                   a persistent requester stop. -->
              <button class="request-block" onclick={() => confirmBlock(req.sender_hash, req.sender_nickname)} disabled={processingRequests.has(req.sender_hash)}>{m.friends_block()}</button>
            </div>
          </div>
        {/each}
      </div>
    </div>
  {/if}

  <!-- Controls bar -->
  <div class="controls-bar">
    <div class="controls-left">
      <button
        class="add-btn"
        class:primary={!showAddForm}
        class:danger={showAddForm}
        onclick={() => { showAddForm = !showAddForm; addError = null; }}
      >
        {showAddForm ? m.common_cancel() : m.friends_add_friend()}
      </button>
    </div>
    <div class="controls-right">
      {#if friends.length > 0}
        <div class="search-wrap">
          <span class="search-icon">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
              <circle cx="8.5" cy="8.5" r="5.5"/><line x1="12.5" y1="12.5" x2="17" y2="17"/>
            </svg>
          </span>
          <input
            type="text"
            class="search-input"
            bind:value={searchQuery}
            placeholder={m.common_search() + '…'}
            aria-label={m.common_search()}
          />
          {#if searchQuery}
            <button class="search-clear" onclick={() => { searchQuery = ''; }} title={m.friends_clear_search()} aria-label={m.friends_clear_search()}>&times;</button>
          {/if}
        </div>
      {/if}
      <span class="inline-stat">
        {friends.length === 1
          ? m.friends_online_count_one({ online: onlineFriendCount })
          : m.friends_online_count_other({ online: onlineFriendCount, total: friends.length })}
      </span>
    </div>
  </div>

  {#if showAddForm}
    <div class="add-form">
      <div class="add-form-inner">
        <input
          type="text"
          bind:value={newHash}
          placeholder={m.friends_hash_placeholder()}
          maxlength="128"
          spellcheck="false"
          autocomplete="off"
          class="hash-input"
          onkeydown={addFormKeydown}
          aria-label={m.friends_hash_placeholder()}
        />
        <input
          type="text"
          bind:value={newNickname}
          placeholder={m.friends_nickname_placeholder()}
          maxlength="64"
          class="nick-input"
          onkeydown={addFormKeydown}
          aria-label={m.friends_nickname_placeholder()}
        />
        <button onclick={handleAdd} disabled={!newHash.trim() || adding}>{adding ? m.friends_adding() : m.common_add()}</button>
      </div>
      {#if addError}
        <div class="field-error">{addError}</div>
      {/if}
    </div>
  {/if}

  {#if searchQuery.trim() && friends.length > 0}
    <div class="result-count-row">
      <span class="result-count">
        {filtered.length === 1
          ? m.friends_match_count_one()
          : m.friends_match_count_other({ count: filtered.length })}
      </span>
    </div>
  {/if}

  {#if loading && friends.length === 0}
    <div class="empty-state">
      <div class="spinner lg"></div>
      <p>{m.friends_loading()}</p>
    </div>
  {:else if friends.length === 0}
    <div class="empty-state">
      <div class="empty-icon">
        <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="18" cy="16" r="6"/>
          <path d="M6 38c0-6.627 5.373-12 12-12h0c6.627 0 12 5.373 12 12"/>
          <circle cx="36" cy="16" r="5"/>
          <path d="M42 38c0-5.523-4.477-10-10-10-1.5 0-2.93.33-4.21.92"/>
          <line x1="36" y1="28" x2="36" y2="34"/>
          <line x1="33" y1="31" x2="39" y2="31"/>
        </svg>
      </div>
      <p class="empty-title">{m.friends_empty_title()}</p>
      <p class="empty-sub">{m.friends_empty_sub()}</p>
      <button class="empty-action" onclick={() => { showAddForm = true; addError = null; }}>{m.friends_add_friend()}</button>
    </div>
  {:else if filtered.length === 0}
    <div class="empty-state">
      <p class="empty-title">{m.friends_no_matches()}</p>
      <p class="empty-sub">{m.friends_no_matches_sub()}</p>
    </div>
  {:else}
    <!--
      Compact friend row. Presence is stated once (the avatar dot) because the
      section headers above already group online vs offline, and unread is
      stated once as a dot on Chat with the count in the status line. Reference
      data (Friend ID, last address, added date) and the secondary actions live
      in the overflow menu so the resting card is name + status + Chat.
    -->
    {#snippet friendCard(f: FriendInfo, isOnline: boolean)}
      {@const presence = friendPresence(f)}
      {@const unread = unreadCounts.get(f.user_hash) ?? 0}
      {@const searching = searchingFriends.has(f.user_hash) || reconnectingFriends.has(f.user_hash)}
      {@const truncatedId = `${f.user_hash.slice(0, 8)}\u2026${f.user_hash.slice(-6)}`}
      {@const lastAddr = f.last_ip && f.last_port > 0 ? `${f.last_ip}:${f.last_port}` : (f.last_ip || '')}
      {@const shortName = f.nickname || f.user_hash.slice(0, 8)}
      <div class="friend-card" class:editing={editingHash === f.user_hash}>
        <div class="card-avatar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="8" r="4"/>
            <path d="M4 21c0-4.418 3.582-8 8-8s8 3.582 8 8"/>
          </svg>
          <span class="status-dot" class:dot-online={presence === 'online'} class:dot-offline={presence === 'offline'}></span>
        </div>

        <div class="card-identity">
          {#if editingHash === f.user_hash}
            <input
              type="text"
              class="edit-input"
              bind:value={editNickname}
              onkeydown={editKeydown}
              onblur={saveEdit}
              maxlength="64"
              placeholder={m.friends_nickname_edit_placeholder()}
              use:autoFocus
              aria-label={m.friends_nickname_edit_placeholder()}
            />
          {:else}
            <div class="card-name-row">
              <button class="nick-btn" onclick={() => startEdit(f)} title={m.friends_edit_nickname_title()}>
                <!-- `<bdi>` isolates the peer-supplied nickname from
                     the surrounding UI direction. -->
                {#if f.nickname}<bdi dir="auto">{f.nickname}</bdi>{:else}{m.friends_no_nickname()}{/if}
              </button>
              {#if f.mutual && isOnline}
                <!-- Icon only: the encryption guarantee is identical for every
                     mutual online friend, so spelling it out on each card was
                     pure repetition. Wording stays in the tooltip. -->
                <span class="lock-glyph" title={m.friends_encrypted_chat_title()} aria-label={m.friends_encrypted_chat()}>
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <rect x="3.5" y="7" width="9" height="6.5" rx="1.5"/>
                    <path d="M5.5 7V5.5a2.5 2.5 0 0 1 5 0V7"/>
                  </svg>
                </span>
              {/if}
            </div>
          {/if}
          <!-- Exactly one status line, highest-priority state wins. -->
          <span class="card-substatus">
            {#if searching}
              <span class="status-searching">{m.friends_status_searching()}</span>
            {:else if !f.mutual}
              <span class="status-pending">{m.friends_status_waiting_accept()}</span>
            {:else if unread > 0}
              <span class="status-unread">
                {unread === 1 ? m.friends_unread_one() : m.friends_unread_other({ count: unread })}
              </span>
            {:else if presence === 'online'}
              <span class="status-online">{m.friends_status_online()}</span>
            {:else if f.last_seen}
              {m.friends_status_last_seen({ when: formatLastSeen(f.last_seen) })}
            {:else}
              {m.friends_status_added({ when: formatDate(f.added_at) })}
            {/if}
          </span>
        </div>

        <div class="card-controls">
          <button
            class="chat-btn"
            class:has-unread={unread > 0}
            onclick={() => openChat(f)}
            disabled={!f.mutual}
            title={f.mutual ? (isOnline ? m.friends_encrypted_chat_title() : m.friends_action_chat()) : m.friends_action_waiting_accept()}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M2 3h12v8H5l-3 3z"/>
            </svg>
            <span class="chat-btn-label">{m.friends_action_chat()}</span>
            {#if unread > 0}<span class="unread-dot" aria-hidden="true"></span>{/if}
          </button>

          <details class="card-more">
            <summary class="card-more-btn" title={m.common_more()} aria-haspopup="menu" aria-label={m.common_more()}>
              <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
                <circle cx="3.5" cy="8" r="1.4"/>
                <circle cx="8" cy="8" r="1.4"/>
                <circle cx="12.5" cy="8" r="1.4"/>
              </svg>
            </summary>
            <div class="card-more-menu" role="menu">
              <button
                type="button"
                role="menuitem"
                onclick={(e) => { closeCardMenu(e.currentTarget); openBrowse(f); }}
                disabled={!f.mutual || !isOnline || browseDisabled}
                title={browseDisabled
                  ? m.settings_friend_browse_disabled()
                  : !f.mutual
                  ? m.friends_action_waiting_accept()
                  : isOnline
                    ? m.friends_action_browse_files()
                    : m.friends_action_browse_offline()}
              >{m.friends_action_browse_files()}</button>
              {#if f.mutual && !isOnline}
                <button
                  type="button"
                  role="menuitem"
                  onclick={(e) => { closeCardMenu(e.currentTarget); handleRetrySearch(f); }}
                  disabled={searching}
                  title={m.friends_action_reconnect_title()}
                >{searching ? m.friends_status_searching() : m.friends_action_reconnect()}</button>
              {/if}
              <!-- The ID lives on the action that uses it, so the reference
                   value is one hover away without sitting on every card.
                   Deliberately does NOT close the menu: the label flips to
                   "Copied!" for 1.5s, which the user could not see otherwise. -->
              <button
                type="button"
                role="menuitem"
                class="menu-item-stacked"
                onclick={() => copyHash(f.user_hash)}
                title={f.user_hash}
                aria-label={copiedHash === f.user_hash
                  ? m.friends_copied_id_aria()
                  : m.friends_copy_id_aria({ name: shortName })}
              >
                <span>{copiedHash === f.user_hash ? m.friends_copied_title() : m.friends_copy_id_title()}</span>
                <span class="menu-item-sub">{truncatedId}</span>
              </button>
              <div class="card-more-facts">
                {#if lastAddr}
                  <span class="card-more-fact">{m.friends_last_address({ addr: lastAddr })}</span>
                {/if}
                <span class="card-more-fact">{m.friends_status_added({ when: formatDate(f.added_at) })}</span>
              </div>
              <button
                type="button"
                role="menuitem"
                class="menu-item-danger"
                onclick={(e) => { closeCardMenu(e.currentTarget); confirmRemoveFriend(f); }}
                aria-label={m.friends_remove_aria({ name: shortName })}
              >{m.friends_remove_title()}</button>
              <button
                type="button"
                role="menuitem"
                class="menu-item-danger"
                onclick={(e) => { closeCardMenu(e.currentTarget); confirmBlock(f.user_hash, f.nickname); }}
                aria-label={m.friends_block_aria({ name: shortName })}
              >{m.friends_block()}</button>
            </div>
          </details>
        </div>
      </div>
    {/snippet}

    {#if onlineFiltered.length > 0}
      <div class="section-divider">
        <span class="section-dot online-dot-label"></span>
        <span class="section-label">{m.friends_section_online({ count: onlineFiltered.length })}</span>
      </div>
      <div class="cards-grid">
        {#each onlineFiltered as f (f.user_hash)}
          {@render friendCard(f, true)}
        {/each}
      </div>
    {/if}

    {#if offlineFiltered.length > 0}
      <div class="section-divider" class:mt-section={onlineFiltered.length > 0}>
        <span class="section-dot offline-dot-label"></span>
        <span class="section-label">{m.friends_section_offline({ count: offlineFiltered.length })}</span>
      </div>
      <div class="cards-grid">
        {#each offlineFiltered as f (f.user_hash)}
          {@render friendCard(f, false)}
        {/each}
      </div>
    {/if}
  {/if}

  <!-- Collapsed by default and hidden entirely when empty: a block list is
       something the user consults deliberately, not standing content. -->
  {#if blocked.length > 0}
    <div class="blocked-section">
      <button
        type="button"
        class="blocked-toggle"
        aria-expanded={blockedOpen}
        onclick={() => (blockedOpen = !blockedOpen)}
      >
        <span class="blocked-chevron" class:open={blockedOpen} aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M9 18l6-6-6-6"/>
          </svg>
        </span>
        <span class="blocked-title">{m.friends_blocked_title()}</span>
        <span class="blocked-badge">{blocked.length}</span>
      </button>
      {#if blockedOpen}
        <div class="blocked-list">
          {#each blocked as b (b.user_hash)}
            <div class="blocked-row">
              <div class="blocked-info">
                <!-- Peer-controlled name: same bidi neutralisation as the
                     friend and request cards. -->
                <bdi dir="auto" class="blocked-name">{b.nickname || m.friends_unknown_sender()}</bdi>
                <span class="blocked-hash" title={b.user_hash}>{b.user_hash.slice(0, 8)}&hellip;{b.user_hash.slice(-6)}</span>
              </div>
              <button class="ghost" onclick={() => handleUnblock(b)} aria-label={m.friends_unblock_aria({ name: b.nickname || b.user_hash.slice(0, 8) + '\u2026' })}>{m.friends_unblock()}</button>
            </div>
          {/each}
        </div>
        <p class="blocked-hint">{m.friends_blocked_hint()}</p>
      {/if}
    </div>
  {/if}
</div>

<style>
  .friends-content {
    padding: 20px;
  }

  /* --- Banners --- */
  .alerts-stack {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 12px;
  }

  .alerts-stack:empty {
    display: none;
  }

  .banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 16px;
    border-radius: var(--radius-md);
    margin-bottom: 0;
    font-size: 12px;
  }

  .error-banner {
    background: var(--bg-secondary);
    border: 1px solid var(--danger);
    color: var(--danger);
  }

  .success-banner {
    background: var(--bg-secondary);
    border: 1px solid var(--success);
    color: var(--success);
  }

  /* --- Your Friend ID card --- */
  .my-id-card {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 14px 18px;
    background: var(--bg-surface);
    border: 1px solid var(--accent-dim);
    border-radius: var(--radius-lg);
    margin-bottom: 12px;
  }

  .my-id-left {
    display: flex;
    align-items: center;
    gap: 14px;
    min-width: 0;
  }

  .my-id-icon {
    width: 38px;
    height: 38px;
    flex-shrink: 0;
    border-radius: var(--radius-md);
    background: var(--accent-dim);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--accent);
  }

  .my-id-icon svg {
    width: 20px;
    height: 20px;
  }

  .my-id-info {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .my-id-label {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
  }

  .my-id-hash {
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--text-primary);
    letter-spacing: 0.4px;
    user-select: all;
    word-break: break-all;
  }

  .my-id-hint {
    font-size: 12px;
    color: var(--text-secondary);
    margin-top: 2px;
  }

  .my-id-status {
    display: inline-flex;
    align-items: center;
    width: fit-content;
    margin-top: 4px;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
  }

  .my-id-status.discoverable {
    background: color-mix(in srgb, var(--success) 16%, transparent);
    color: var(--success);
  }

  .my-id-status.firewalled {
    background: color-mix(in srgb, var(--warning) 16%, transparent);
    color: color-mix(in srgb, var(--warning) 85%, var(--text-primary));
  }

  .my-id-status.undiscoverable {
    background: color-mix(in srgb, var(--danger) 14%, transparent);
    color: color-mix(in srgb, var(--danger) 85%, var(--text-primary));
  }

  .my-id-copy {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px;
    border: 1px solid var(--accent);
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--accent);
    font-size: 12px;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    white-space: nowrap;
    flex-shrink: 0;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .my-id-copy:hover {
    background: var(--accent);
    color: var(--on-accent);
  }

  .my-id-copy.copied {
    border-color: var(--success);
    color: var(--success);
  }

  .my-id-copy.copied:hover {
    background: transparent;
    color: var(--success);
  }

  .my-id-copy svg {
    width: 13px;
    height: 13px;
  }

  /* --- How Friends work --- */
  .how-panel {
    padding: 12px 16px;
    margin-bottom: 12px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
  }

  .how-title {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 6px;
  }

  .how-list {
    margin: 0;
    padding-left: 18px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 12px;
    line-height: 1.45;
    color: var(--text-secondary);
  }

  .how-list li::marker {
    color: var(--accent);
  }

  /* --- Controls bar --- */
  .controls-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 16px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    margin-bottom: 12px;
    gap: 12px;
  }

  .controls-left {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-shrink: 0;
  }

  .controls-right {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .add-btn {
    font-weight: 600;
    font-size: 12px;
  }

  .add-btn.primary {
    padding: 6px 14px;
    border: 1px solid var(--accent);
    border-radius: var(--radius-md);
    background: var(--accent);
    color: var(--on-accent);
    cursor: pointer;
    font-family: inherit;
  }

  .add-btn.primary:hover {
    background: var(--accent-hover);
    border-color: var(--accent-hover);
  }

  .inline-stat {
    font-size: 12px;
    color: var(--text-muted);
    font-weight: 500;
    white-space: nowrap;
    flex-shrink: 0;
  }

  /* --- Add form --- */
  .add-form {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 12px 16px;
    margin-bottom: 12px;
  }

  .add-form-inner {
    display: flex;
    gap: 10px;
    align-items: center;
    flex-wrap: wrap;
  }

  .add-form-inner input {
    padding: 7px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 13px;
    font-family: inherit;
  }

  .add-form-inner input:focus {
    border-color: var(--accent);
    outline: none;
  }

  .hash-input {
    flex: 2;
    min-width: 200px;
    font-family: var(--font-mono);
    letter-spacing: 0.3px;
  }

  .nick-input {
    flex: 1;
    min-width: 140px;
  }

  .field-error {
    font-size: 12px;
    color: var(--danger);
    margin-top: 8px;
    padding-left: 2px;
  }

  /* --- Search in controls bar --- */
  .search-wrap {
    position: relative;
    width: 200px;
  }

  .search-icon {
    position: absolute;
    left: 10px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-muted);
    pointer-events: none;
    display: flex;
  }

  .search-input {
    width: 100%;
    padding: 5px 26px 5px 30px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 12px;
    font-family: inherit;
  }

  .search-input:focus {
    border-color: var(--accent);
    outline: none;
  }

  .search-clear {
    position: absolute;
    right: 4px;
    top: 50%;
    transform: translateY(-50%);
    width: 20px;
    height: 20px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 15px;
    line-height: 1;
    padding: 0;
  }

  .search-clear:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .result-count-row {
    margin-bottom: 8px;
  }

  .result-count {
    font-size: 12px;
    color: var(--text-muted);
  }

  /* --- Card grid --- */
  .cards-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 10px;
  }

  /* Single row: avatar · identity · controls. No `overflow: hidden` — the
     overflow menu is absolutely positioned and must escape the card. */
  .friend-card {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 9px 10px;
    transition: border-color var(--transition-normal), box-shadow var(--transition-normal);
  }

  .friend-card:hover {
    border-color: var(--border-light);
    box-shadow: var(--shadow-sm);
  }

  .friend-card.editing {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-dim);
  }

  .card-avatar {
    width: 34px;
    height: 34px;
    flex-shrink: 0;
    border-radius: 50%;
    background: var(--accent-dim);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--accent);
  }

  .card-avatar svg {
    width: 18px;
    height: 18px;
  }

  .card-identity {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .card-name-row {
    display: flex;
    align-items: center;
    gap: 5px;
    min-width: 0;
  }

  .lock-glyph {
    display: inline-flex;
    color: var(--accent);
    flex-shrink: 0;
  }

  .lock-glyph svg {
    width: 11px;
    height: 11px;
  }

  .card-substatus {
    font-size: 11px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .status-online {
    color: var(--success);
    font-weight: 600;
  }

  .status-unread {
    color: var(--accent);
    font-weight: 600;
  }

  .nick-btn {
    border: none;
    background: none;
    color: var(--text-primary);
    font-weight: 600;
    font-size: 14px;
    font-family: inherit;
    padding: 2px 4px;
    margin: -2px -4px;
    border-radius: var(--radius-sm);
    cursor: pointer;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    display: block;
    text-align: left;
    transition: color var(--transition-fast);
  }

  .nick-btn:hover {
    color: var(--accent);
    background: var(--bg-hover);
  }

  .edit-input {
    width: 100%;
    padding: 4px 8px;
    border: 1px solid var(--accent);
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 14px;
    font-family: inherit;
    font-weight: 600;
  }

  .edit-input:focus {
    outline: none;
    box-shadow: 0 0 0 2px var(--accent-dim);
  }

  @keyframes badge-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  /* --- Card controls: one primary action plus an overflow menu --- */
  .card-controls {
    display: flex;
    align-items: center;
    gap: 2px;
    flex-shrink: 0;
  }

  .chat-btn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 5px 10px;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    color: var(--accent);
    font-size: 11px;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .chat-btn:hover:not(:disabled) {
    background: color-mix(in srgb, var(--accent) 20%, transparent);
  }

  .chat-btn:disabled {
    background: transparent;
    color: var(--text-muted);
    opacity: 0.5;
    cursor: not-allowed;
  }

  .chat-btn svg {
    width: 13px;
    height: 13px;
    flex-shrink: 0;
  }

  /* Unread is a presence cue here; the count is in the status line. */
  .unread-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent);
    flex-shrink: 0;
  }

  .card-more {
    position: relative;
  }

  .card-more > summary {
    list-style: none;
    width: 26px;
    height: 26px;
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .card-more > summary::-webkit-details-marker {
    display: none;
  }

  .card-more > summary:hover,
  .card-more[open] > summary {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .card-more > summary svg {
    width: 14px;
    height: 14px;
  }

  .card-more-menu {
    position: absolute;
    right: 0;
    top: calc(100% + 4px);
    z-index: 20;
    min-width: 190px;
    padding: 4px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    box-shadow: var(--shadow-md);
    display: flex;
    flex-direction: column;
  }

  .card-more-menu button {
    text-align: left;
    font-size: 12px;
    font-family: inherit;
    padding: 6px 10px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-primary);
    cursor: pointer;
  }

  .card-more-menu button:hover:not(:disabled) {
    background: var(--bg-hover);
  }

  .card-more-menu button:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .menu-item-stacked {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .menu-item-sub {
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.2px;
    color: var(--text-muted);
  }

  .menu-item-danger:hover:not(:disabled) {
    color: var(--danger);
  }

  /* Reference facts, not actions — separated so they don't read as
     clickable rows in the menu. */
  .card-more-facts {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin: 4px 0;
    padding: 6px 10px;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }

  .card-more-fact {
    font-size: 10px;
    color: var(--text-muted);
  }

  /* --- Empty state --- */
  .empty-state {
    text-align: center;
    padding: 56px 24px;
    color: var(--text-muted);
  }

  .empty-icon {
    width: 64px;
    height: 64px;
    margin: 0 auto 16px;
    border-radius: 50%;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-muted);
  }

  .empty-icon svg {
    width: 32px;
    height: 32px;
  }

  .empty-title {
    font-size: 15px;
    font-weight: 600;
    color: var(--text-secondary);
    margin: 0 0 6px;
  }

  .empty-sub {
    font-size: 12px;
    color: var(--text-muted);
    max-width: 360px;
    margin: 0 auto;
    line-height: 1.5;
  }

  .empty-action {
    margin-top: 16px;
    font-size: 12px;
    padding: 7px 20px;
  }

  /* --- Online status --- */
  .card-avatar {
    position: relative;
  }


  .status-dot {
    position: absolute;
    bottom: -1px;
    right: -1px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    border: 2px solid var(--bg-surface);
  }

  .dot-online {
    background: var(--success);
  }

  .dot-offline {
    background: var(--text-muted);
  }


  /* --- Section dividers --- */
  .section-divider {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 4px;
    margin-bottom: 8px;
  }

  .section-divider.mt-section {
    margin-top: 18px;
  }

  .section-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .online-dot-label {
    background: var(--success);
  }

  .offline-dot-label {
    background: var(--text-muted);
  }

  .section-label {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
  }

  .status-searching {
    color: var(--warning);
    font-weight: 500;
    animation: badge-pulse 2s ease-in-out infinite;
  }

  /* Idle "we added them, they haven't accepted yet" state. Static
     (no pulse animation) to distinguish from the active-search
     spinner above and to avoid implying the app is doing work
     when it isn't. Same warning hue as `.status-searching` so the
     two pre-mutual states still read as a single "not yet
     friends" group. */
  .status-pending {
    color: var(--text-muted);
    font-weight: 500;
  }

  @media (prefers-reduced-motion: reduce) {
    .status-searching {
      animation: none;
    }
  }

  /* --- Friend requests section --- */
  .requests-section {
    background: var(--bg-surface);
    border: 1px solid var(--accent-dim);
    border-radius: var(--radius-lg);
    margin-bottom: 12px;
    overflow: hidden;
  }

  .requests-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
  }

  .requests-title {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
  }

  .requests-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 18px;
    border-radius: 9px;
    background: var(--accent);
    color: var(--on-accent);
    font-size: 10px;
    font-weight: 700;
    padding: 0 5px;
    line-height: 1;
  }

  .requests-list {
    display: flex;
    flex-direction: column;
  }

  .request-card {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 16px;
  }

  .request-card + .request-card {
    border-top: 1px solid color-mix(in srgb, var(--border) 50%, transparent);
  }

  .request-avatar {
    width: 32px;
    height: 32px;
    flex-shrink: 0;
    border-radius: 50%;
    background: var(--accent-dim);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--accent);
  }

  .request-avatar svg {
    width: 16px;
    height: 16px;
  }

  .request-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .request-name {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .request-hash {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-muted);
    letter-spacing: 0.3px;
  }

  /* Verification badges on incoming friend requests. "Verified"
     means the peer advertised an Ed25519 pubkey whose BLAKE3 prefix
     matches their claimed ember_hash (offline identity binding).
     "Unverified" means no pubkey was advertised or the binding
     check failed; users should only accept from people they
     recognise until the full challenge-response runs on accept. */
  .request-badge {
    display: inline-flex;
    align-items: center;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    padding: 1px 6px;
    border-radius: 4px;
    flex-shrink: 0;
  }
  .request-badge-verified {
    background: color-mix(in srgb, var(--success) 18%, transparent);
    color: var(--success);
    border: 1px solid color-mix(in srgb, var(--success) 40%, transparent);
  }
  .request-badge-unverified {
    background: color-mix(in srgb, var(--warning) 14%, transparent);
    color: var(--warning);
    border: 1px solid color-mix(in srgb, var(--warning) 35%, transparent);
  }

  .request-actions {
    display: flex;
    gap: 6px;
    flex-shrink: 0;
  }

  .request-accept {
    padding: 5px 14px;
    border: none;
    border-radius: var(--radius-md);
    background: var(--accent);
    color: var(--on-accent);
    font-size: 11px;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    transition: opacity var(--transition-fast);
  }

  .request-accept:hover {
    opacity: 0.85;
  }

  .request-reject {
    padding: 5px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    transition: color var(--transition-fast), border-color var(--transition-fast);
  }

  .request-reject:hover {
    color: var(--danger);
    border-color: var(--danger);
  }

  .request-block {
    padding: 5px 14px;
    border: 1px solid transparent;
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    transition: color var(--transition-fast), border-color var(--transition-fast);
  }

  .request-block:hover {
    color: var(--danger);
    border-color: var(--danger);
  }

  .request-block:disabled,
  .request-reject:disabled {
    opacity: 0.5;
    cursor: default;
  }

  /* --- Blocked identities --- */
  .blocked-section {
    margin-top: 20px;
    border-top: 1px solid var(--border);
    padding-top: 12px;
  }

  .blocked-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 6px 2px;
    border: none;
    background: transparent;
    color: var(--text-muted);
    font-size: 12px;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    text-align: left;
  }

  .blocked-toggle:hover {
    color: var(--text-secondary);
  }

  .blocked-chevron {
    display: inline-flex;
    width: 14px;
    height: 14px;
    transition: transform var(--transition-fast);
  }

  .blocked-chevron.open {
    transform: rotate(90deg);
  }

  .blocked-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 18px;
    border-radius: 9px;
    background: var(--bg-elevated);
    color: var(--text-muted);
    font-size: 10px;
    font-weight: 700;
    padding: 0 5px;
    line-height: 1;
  }

  .blocked-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-top: 8px;
  }

  .blocked-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
  }

  .blocked-info {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .blocked-name {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .blocked-hash {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-muted);
  }

  .blocked-hint {
    margin: 8px 2px 0;
    font-size: 11px;
    color: var(--text-muted);
  }

  /* --- Firewall warning banner --- */
  .firewall-banner {
    background: color-mix(in srgb, var(--warning) 8%, var(--bg-surface));
    border: 1px solid color-mix(in srgb, var(--warning) 40%, var(--border));
    color: var(--text-secondary);
    padding: 12px 16px;
    border-radius: var(--radius-lg);
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    flex-wrap: wrap;
  }

  /* Shares the firewall banner's shape but reads as a fault rather than a
     limitation: being unreachable by friends is a broken state, not a
     degraded one. */
  .undiscoverable-banner {
    background: color-mix(in srgb, var(--danger) 7%, var(--bg-surface));
    border: 1px solid color-mix(in srgb, var(--danger) 35%, var(--border));
    color: var(--text-secondary);
    padding: 12px 16px;
    border-radius: var(--radius-lg);
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
  }

  .undiscoverable-banner .firewall-text strong {
    color: var(--danger);
  }

  .undiscoverable-icon {
    width: 20px;
    height: 20px;
    flex-shrink: 0;
    color: var(--danger);
    margin-top: 1px;
  }

  .firewall-banner-content {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    min-width: 0;
  }

  .firewall-icon {
    width: 20px;
    height: 20px;
    flex-shrink: 0;
    color: var(--warning);
    margin-top: 1px;
  }

  .firewall-text {
    font-size: 12px;
    line-height: 1.5;
  }

  .firewall-text strong {
    color: var(--warning);
  }

  .firewall-recheck {
    padding: 5px 14px;
    border: 1px solid color-mix(in srgb, var(--warning) 50%, var(--border));
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--warning);
    font-size: 11px;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    white-space: nowrap;
    flex-shrink: 0;
    transition: background var(--transition-fast), opacity var(--transition-fast);
  }

  .firewall-recheck-error {
    margin-left: 10px;
    font-size: 11px;
    color: var(--danger);
    align-self: center;
    flex-basis: 100%;
  }

  .firewall-recheck:hover:not(:disabled) {
    background: color-mix(in srgb, var(--warning) 15%, transparent);
  }

  .firewall-recheck:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }



</style>
