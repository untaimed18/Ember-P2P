<script lang="ts">
  import { getFriends, addFriend, removeFriend, updateFriendNickname, getMyEmberHash, acceptFriendRequest, rejectFriendRequest, retryFriendSearch, type FriendInfo, type FriendRequestInfo } from '$lib/api/friends';
  import { getNetworkStats, kadRecheckFirewall } from '$lib/api/kad';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import BrowseFriendDialog from '$lib/components/BrowseFriendDialog.svelte';
  import { openChat as openChatTab, removeChatForFriend, renameTab as renameChatTab } from '$lib/stores/chatTabs';
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
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
    clearUnread,
  } from '$lib/stores/friends';

  let friends: FriendInfo[] = $state([]);
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

  let editingHash: string | null = $state(null);
  let editNickname = $state('');

  let searchQuery = $state('');
  let copiedHash: string | null = $state(null);
  let copyTimer: ReturnType<typeof setTimeout> | undefined;

  let onlineFriends: Set<string> = $derived($onlineFriendsStore);
  let unreadCounts: Map<string, number> = $derived($unreadCountsStore);

  let friendRequests: FriendRequestInfo[] = $derived($friendRequestsStore);
  let failedSearchToastsShown = new Set<string>();

  // Whenever a friend comes online, reset our "we already toasted for this
  // hash" memo so the next offline search failure can re-toast. Reactively
  // driven from the onlineFriends store (no separate Tauri listener needed).
  $effect(() => {
    for (const hash of onlineFriends) failedSearchToastsShown.delete(hash);
  });
  let searchingFriends: Set<string> = $derived($searchingFriendsStore);
  let isFirewalled = $state(false);
  let recheckingFirewall = $state(false);
  let recheckError: string | null = $state(null);

  let browseOpen = $state(false);
  let browseFriendHash = $state('');
  let browseFriendName = $state('');
  let browseFriendIp = $state('');
  let browseFriendPort = $state(0);

  let isDiscoverable = $derived($isDiscoverableStore);
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
      processingRequests.delete(req.sender_hash);
      processingRequests = new Set(processingRequests);
    }
  }

  async function handleRetrySearch(f: FriendInfo) {
    // Re-trigger a rendezvous/DHT search for an offline friend. The backend
    // emits `ember:friend-searching` (which drives the row's "Searching…"
    // state) and then a terminal online/failed event, so no extra local
    // spinner state is needed here.
    if (searchingFriends.has(f.user_hash)) return;
    try {
      await retryFriendSearch(f.user_hash);
    } catch (e: unknown) {
      error = toErr(e);
    }
  }

  async function handleRejectRequest(req: FriendRequestInfo) {
    if (processingRequests.has(req.sender_hash)) return;
    processingRequests.add(req.sender_hash);
    processingRequests = new Set(processingRequests);
    try {
      await rejectFriendRequest(req.sender_hash);
      friendRequestsStore.update(reqs => reqs.filter(r => r.sender_hash !== req.sender_hash));
    } catch (e: unknown) {
      error = toErr(e);
    } finally {
      processingRequests.delete(req.sender_hash);
      processingRequests = new Set(processingRequests);
    }
  }

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
      isFirewalled = event.payload.firewalled;
      if (!event.payload.firewalled) recheckingFirewall = false;
    }).then(fn => { if (destroyed) fn(); else unlistenFns.push(fn); })
      .catch((e) => console.error('friends: failed to register firewall-status listener', e));

    listen<{ user_hash: string; reason?: string }>('ember:friend-search-failed', (event) => {
      if (destroyed) return;
      const hash = event.payload.user_hash;
      const reason = event.payload.reason || 'error';
      if (failedSearchToastsShown.has(hash)) return;
      failedSearchToastsShown.add(hash);
      const f = friends.find(fr => fr.user_hash === hash);
      const name = f ? (f.nickname || hash.slice(0, 8) + '\u2026') : hash.slice(0, 8) + '\u2026';
      let msg: string;
      switch (reason) {
        case 'firewalled':
          msg = m.friends_search_firewalled({ name });
          break;
        case 'not_found':
          msg = m.friends_search_not_found({ name });
          break;
        case 'timeout':
          msg = m.friends_search_timeout({ name });
          break;
        case 'refused':
          msg = m.friends_search_refused({ name });
          break;
        default:
          msg = m.friends_search_generic({ name });
      }
      toastWarning(msg);
    }).then(fn => { if (destroyed) fn(); else unlistenFns.push(fn); })
      .catch((e) => console.error('friends: failed to register ember:friend-search-failed listener', e));

    return () => {
      destroyed = true;
      clearTimeout(flashTimer);
      clearTimeout(copyTimer);
      clearTimeout(myHashCopyTimer);
      clearTimeout(recheckTimer);
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

  function isValidHash(h: string): boolean {
    return /^[0-9a-fA-F]{32}$/.test(h);
  }

  async function handleAdd() {
    if (adding) return;
    addError = null;
    const hash = newHash.trim();
    const nick = newNickname.trim();
    if (!hash) { addError = m.friends_validation_hash_required(); return; }
    if (!isValidHash(hash)) { addError = m.friends_validation_hash_format(); return; }
    if (myHash && hash.toLowerCase() === myHash.toLowerCase()) {
      addError = m.friends_validation_self_add();
      return;
    }
    if (friends.some((f) => f.user_hash.toLowerCase() === hash.toLowerCase())) {
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
  {#if error}
    <div class="banner error-banner">
      <span>{error}</span>
      <button class="ghost" onclick={() => (error = null)}>{m.common_dismiss()}</button>
    </div>
  {/if}
  {#if successMsg}
    <div class="banner success-banner">
      <span>{successMsg}</span>
    </div>
  {/if}

  <!-- Your Friend ID -->
  {#if myHash}
    <div class="my-id-card">
      <div class="my-id-left">
        <div class="my-id-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="5" width="18" height="14" rx="2"/>
            <circle cx="9" cy="12" r="2.5"/>
            <path d="M15 10h3M15 14h2"/>
          </svg>
        </div>
        <div class="my-id-info">
          <span class="my-id-label">{m.friends_your_id_label()}</span>
          <span class="my-id-hash">{myHash}</span>
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

  <!-- Discoverable status -->
  {#if isDiscoverable && !isFirewalled}
    <div class="banner discoverable-banner">
      <div class="discoverable-content">
        <svg class="discoverable-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="10" cy="10" r="3"/>
          <path d="M5.64 5.64a7 7 0 000 8.72"/>
          <path d="M14.36 5.64a7 7 0 010 8.72"/>
          <path d="M3.05 3.05a11 11 0 000 13.9"/>
          <path d="M16.95 3.05a11 11 0 010 13.9"/>
        </svg>
        <span>
          {m.friends_discoverable_prefix()}
          <strong>{m.friends_discoverable_emphasis()}</strong>
          {m.friends_discoverable_suffix()}
        </span>
      </div>
    </div>
  {/if}

  <!-- Firewall warning -->
  {#if isFirewalled}
    <div class="banner firewall-banner">
      <div class="firewall-banner-content">
        <svg class="firewall-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10 1l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V4z"/>
          <line x1="10" y1="7" x2="10" y2="11"/>
          <circle cx="10" cy="14" r="0.5" fill="currentColor" stroke="none"/>
        </svg>
        <div class="firewall-text">
          <strong>{m.friends_firewall_title()}</strong>
          {m.friends_firewall_body()}
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

  <!-- Pending friend requests -->
  {#if friendRequests.length > 0}
    <div class="requests-section">
      <div class="requests-header">
        <span class="requests-title">{m.friends_requests_title()}</span>
        <span class="requests-badge">{friendRequests.length}</span>
      </div>
      <div class="requests-list">
        {#each friendRequests as req (req.sender_hash)}
          <div class="request-card">
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
                <bdi>{req.sender_nickname || m.friends_unknown_sender()}</bdi>
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
        class="ghost add-btn"
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
          maxlength="32"
          spellcheck="false"
          class="hash-input"
          onkeydown={addFormKeydown}
        />
        <input
          type="text"
          bind:value={newNickname}
          placeholder={m.friends_nickname_placeholder()}
          maxlength="64"
          class="nick-input"
          onkeydown={addFormKeydown}
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
    {#snippet friendCard(f: FriendInfo, isOnline: boolean)}
      {@const presence = friendPresence(f)}
      <div class="friend-card" class:editing={editingHash === f.user_hash} class:online={isOnline} class:has-unread-card={!!unreadCounts.get(f.user_hash)}>
        <div class="card-header-row">
          <div class="card-avatar" class:avatar-online={presence === 'online'} class:avatar-offline={presence === 'offline'}>
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
              />
            {:else}
              <button class="nick-btn" onclick={() => startEdit(f)} title={m.friends_edit_nickname_title()}>
                <!-- `<bdi>` isolates the peer-supplied nickname from
                     the surrounding UI direction. -->
                {#if f.nickname}<bdi>{f.nickname}</bdi>{:else}{m.friends_no_nickname()}{/if}
              </button>
            {/if}
            <span class="card-status-label">
              {#if searchingFriends.has(f.user_hash)}
                <span class="status-searching">{m.friends_status_searching()}</span>
              {:else if !f.mutual}
                <span class="status-pending">{m.friends_status_waiting_accept()}</span>
              {:else if presence === 'online'}
                <span class="status-online">{m.friends_status_online()}</span>
              {:else if f.last_seen}
                {m.friends_status_last_seen({ when: formatLastSeen(f.last_seen) })}
              {:else}
                {m.friends_status_added({ when: formatDate(f.added_at) })}
              {/if}
            </span>
            {#if unreadCounts.get(f.user_hash)}
              <span class="card-unread-preview">
                {(unreadCounts.get(f.user_hash) ?? 0) === 1
                  ? m.friends_unread_one()
                  : m.friends_unread_other({ count: unreadCounts.get(f.user_hash) ?? 0 })}
              </span>
            {/if}
          </div>
          <button
            class="icon-btn copy-hash-btn"
            onclick={() => copyHash(f.user_hash)}
            title={copiedHash === f.user_hash ? m.friends_copied_title() : m.friends_copy_id_title()}
            aria-label={copiedHash === f.user_hash ? m.friends_copied_id_aria() : m.friends_copy_id_aria({ name: f.nickname || f.user_hash.slice(0, 8) })}
          >
            {#if copiedHash === f.user_hash}
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="3 8 7 12 13 4"/>
              </svg>
            {:else}
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <rect x="5" y="5" width="9" height="9" rx="1.5"/>
                <path d="M3 11V3a1.5 1.5 0 011.5-1.5H11"/>
              </svg>
            {/if}
          </button>
          <button
            class="icon-btn danger remove-btn"
            onclick={() => confirmRemoveFriend(f)}
            title={m.friends_remove_title()}
            aria-label={m.friends_remove_aria({ name: f.nickname || f.user_hash.slice(0, 8) })}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <line x1="4" y1="4" x2="12" y2="12"/>
              <line x1="12" y1="4" x2="4" y2="12"/>
            </svg>
          </button>
        </div>

        <div class="card-actions-bar">
          <button
            class="action-btn chat-action"
            class:has-unread={unreadCounts.get(f.user_hash)}
            onclick={() => openChat(f)}
            disabled={!f.mutual}
            title={f.mutual ? m.friends_action_chat() : m.friends_action_waiting_accept()}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M2 3h12v8H5l-3 3z"/>
            </svg>
            {m.friends_action_chat()}
            {#if unreadCounts.get(f.user_hash)}
              <span class="unread-badge">{unreadCounts.get(f.user_hash)}</span>
            {/if}
          </button>
          <button
            class="action-btn browse-action"
            onclick={() => openBrowse(f)}
            disabled={!f.mutual || !isOnline}
            title={!f.mutual
              ? m.friends_action_waiting_accept()
              : isOnline
                ? m.friends_action_browse_files()
                : m.friends_action_browse_offline()}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M2 4h5l2 2h5v7H2z"/>
            </svg>
            {m.friends_action_browse()}
          </button>
          {#if f.mutual && !isOnline}
            <button
              class="action-btn reconnect-action"
              onclick={() => handleRetrySearch(f)}
              disabled={searchingFriends.has(f.user_hash)}
              title={m.friends_action_reconnect_title()}
            >
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9"/>
                <polyline points="13.5 2 13.5 5 10.5 5"/>
              </svg>
              {searchingFriends.has(f.user_hash) ? m.friends_status_searching() : m.friends_action_reconnect()}
            </button>
          {/if}
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
</div>

<style>
  .friends-content {
    padding: 20px;
  }

  /* --- Banners --- */
  .banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 16px;
    border-radius: var(--radius-md);
    margin-bottom: 12px;
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
    color: white;
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

  .friend-card {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 0;
    overflow: hidden;
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

  .card-header-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 14px 10px;
  }

  .card-avatar {
    width: 40px;
    height: 40px;
    flex-shrink: 0;
    border-radius: 50%;
    background: var(--accent-dim);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--accent);
  }

  .card-avatar svg {
    width: 20px;
    height: 20px;
  }

  .card-identity {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .card-status-label {
    font-size: 11px;
    color: var(--text-muted);
  }

  .status-online {
    color: var(--success);
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

  /* Same touch/keyboard reasoning as `.copy-hash-btn` above. */
  .remove-btn {
    opacity: 0.55;
    transition: opacity var(--transition-fast), background var(--transition-fast), color var(--transition-fast);
  }

  .friend-card:hover .remove-btn,
  .friend-card:focus-within .remove-btn,
  .remove-btn:focus-visible {
    opacity: 1;
  }


  @keyframes badge-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  .card-actions-bar {
    display: flex;
    border-top: 1px solid var(--border);
  }

  .action-btn {
    flex: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 9px 8px;
    border: none;
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    position: relative;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .action-btn + .action-btn {
    border-left: 1px solid var(--border);
  }

  .action-btn:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .action-btn:disabled {
    opacity: 0.35;
    cursor: not-allowed;
  }

  .action-btn svg {
    width: 13px;
    height: 13px;
    flex-shrink: 0;
  }

  .action-btn.has-unread {
    color: var(--accent);
  }

  .icon-btn {
    width: 28px;
    height: 28px;
    padding: 0;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .icon-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .icon-btn.danger:hover {
    color: var(--danger);
  }

  .icon-btn svg {
    width: 14px;
    height: 14px;
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

  .avatar-online {
    border: 2px solid var(--success);
  }

  /* Offline avatars use a muted neutral border instead of red.
     Reserving --danger for actual errors stops "offline" from reading
     as "broken" and keeps the page calm when most friends are offline. */
  .avatar-offline {
    border: 2px solid var(--border-light);
    opacity: 0.85;
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

  .friend-card.online {
    border-left: 3px solid var(--success);
  }

  .friend-card.has-unread-card {
    border-left: 3px solid var(--accent);
    background: color-mix(in srgb, var(--accent) 4%, var(--bg-surface));
  }

  .friend-card.online.has-unread-card {
    border-left: 3px solid var(--accent);
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

  /* --- Card-level unread preview --- */
  .card-unread-preview {
    font-size: 11px;
    color: var(--accent);
    font-weight: 500;
    margin-top: 1px;
  }

  .status-searching {
    color: var(--warning, #eab308);
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

  /* --- Copy hash button in header ---
     Always present (not opacity 0) so touch users and keyboard
     navigation can reach it without first triggering hover. Faded by
     default to avoid competing with primary content; resolves to full
     opacity on hover OR focus-within so keyboard tabbing reveals it. */
  .copy-hash-btn {
    opacity: 0.55;
    transition: opacity var(--transition-fast), background var(--transition-fast), color var(--transition-fast);
  }

  .friend-card:hover .copy-hash-btn,
  .friend-card:focus-within .copy-hash-btn,
  .copy-hash-btn:focus-visible {
    opacity: 1;
  }

  .unread-badge {
    min-width: 14px;
    height: 14px;
    border-radius: 7px;
    background: var(--danger);
    color: white;
    font-size: 9px;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0 3px;
    line-height: 1;
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
    color: white;
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
    background: color-mix(in srgb, var(--success, #2ecc71) 18%, transparent);
    color: var(--success, #2ecc71);
    border: 1px solid color-mix(in srgb, var(--success, #2ecc71) 40%, transparent);
  }
  .request-badge-unverified {
    background: color-mix(in srgb, var(--warning, #e0a23b) 14%, transparent);
    color: var(--warning, #e0a23b);
    border: 1px solid color-mix(in srgb, var(--warning, #e0a23b) 35%, transparent);
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
    color: white;
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

  /* --- Discoverable banner --- */
  .discoverable-banner {
    background: color-mix(in srgb, var(--success) 8%, var(--bg-surface));
    border: 1px solid color-mix(in srgb, var(--success) 40%, var(--border));
    color: var(--text-secondary);
    padding: 10px 16px;
    border-radius: var(--radius-lg);
    margin-bottom: 12px;
  }

  .discoverable-content {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 12px;
    line-height: 1.5;
  }

  .discoverable-content strong {
    color: var(--success);
  }

  .discoverable-icon {
    width: 18px;
    height: 18px;
    flex-shrink: 0;
    color: var(--success);
  }

  /* --- Firewall warning banner --- */
  .firewall-banner {
    background: color-mix(in srgb, var(--warning, #eab308) 8%, var(--bg-surface));
    border: 1px solid color-mix(in srgb, var(--warning, #eab308) 40%, var(--border));
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
    color: var(--warning, #eab308);
    margin-top: 1px;
  }

  .firewall-text {
    font-size: 12px;
    line-height: 1.5;
  }

  .firewall-text strong {
    color: var(--warning, #eab308);
  }

  .firewall-recheck {
    padding: 5px 14px;
    border: 1px solid color-mix(in srgb, var(--warning, #eab308) 50%, var(--border));
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--warning, #eab308);
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
    color: var(--danger, #ef4444);
    align-self: center;
    flex-basis: 100%;
  }

  .firewall-recheck:hover:not(:disabled) {
    background: color-mix(in srgb, var(--warning, #eab308) 15%, transparent);
  }

  .firewall-recheck:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }



</style>
