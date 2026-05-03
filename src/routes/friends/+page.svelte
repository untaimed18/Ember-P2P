<script lang="ts">
  import { getFriends, addFriend, removeFriend, updateFriendNickname, getMyEmberHash, acceptFriendRequest, rejectFriendRequest, type FriendInfo, type FriendRequestInfo } from '$lib/api/friends';
  import { getNetworkStats, kadRecheckFirewall } from '$lib/api/kad';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import ChatSidebar from '$lib/components/ChatSidebar.svelte';
  import BrowseFriendDialog from '$lib/components/BrowseFriendDialog.svelte';
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import { toastWarning } from '$lib/stores/toast';
  import {
    onlineFriends as onlineFriendsStore,
    unreadCounts as unreadCountsStore,
    friendRequests as friendRequestsStore,
    searchingFriends as searchingFriendsStore,
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

  let onlineFriends: Set<string> = $state(new Set());
  let unreadCounts: Map<string, number> = $state(new Map());

  let friendRequests: FriendRequestInfo[] = $state([]);
  let failedSearchToastsShown = new Set<string>();

  // Whenever a friend comes online, reset our "we already toasted for this
  // hash" memo so the next offline search failure can re-toast. Reactively
  // driven from the onlineFriends store (no separate Tauri listener needed).
  $effect(() => {
    for (const hash of onlineFriends) failedSearchToastsShown.delete(hash);
  });
  let searchingFriends: Set<string> = $state(new Set());
  let isFirewalled = $state(false);
  let recheckingFirewall = $state(false);
  let recheckError: string | null = $state(null);

  let chatOpen = $state(false);
  let chatFriendHash = $state('');
  let chatFriendName = $state('');

  let browseOpen = $state(false);
  let browseFriendHash = $state('');
  let browseFriendName = $state('');
  let browseFriendIp = $state('');
  let browseFriendPort = $state(0);

  let isDiscoverable = $state(false);
  let processingRequests: Set<string> = $state(new Set());
  let adding = $state(false);

  // Module-scoped lifecycle flag used by async loaders below so they don't
  // patch state after navigation.
  let destroyed = false;

  // Sync global friend stores into local reactive state so the template
  // picks up events even if they arrived before this page mounted.
  onMount(() => {
    const unsubs = [
      onlineFriendsStore.subscribe(v => { onlineFriends = v; }),
      unreadCountsStore.subscribe(v => { unreadCounts = v; }),
      friendRequestsStore.subscribe(v => { friendRequests = v; }),
      searchingFriendsStore.subscribe(v => { searchingFriends = v; }),
      isDiscoverableStore.subscribe(v => { isDiscoverable = v; }),
    ];
    return () => unsubs.forEach(u => u());
  });

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

  function openChat(f: FriendInfo) {
    chatFriendHash = f.user_hash;
    chatFriendName = f.nickname || f.user_hash.slice(0, 8) + '\u2026';
    chatOpen = true;
    clearUnread(f.user_hash);
  }

  function closeChat() {
    chatOpen = false;
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
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
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
    } catch (_) { /* best-effort */ }
  }

  async function handleAcceptRequest(req: FriendRequestInfo) {
    if (processingRequests.has(req.sender_hash)) return;
    processingRequests.add(req.sender_hash);
    processingRequests = new Set(processingRequests);
    try {
      await acceptFriendRequest(req.sender_hash);
      flash(`Accepted friend request from ${req.sender_nickname || req.sender_hash.slice(0, 8) + '\u2026'}`);
      await reloadFriendRequests();
      await loadFriends();
    } catch (e: unknown) {
      error = toErr(e);
    } finally {
      processingRequests.delete(req.sender_hash);
      processingRequests = new Set(processingRequests);
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
      recheckError = e instanceof Error ? e.message : String(e);
    }
    clearTimeout(recheckTimer);
    recheckTimer = setTimeout(() => { recheckingFirewall = false; }, 5000);
  }

  onMount(() => {
    destroyed = false;
    loadFriends();
    loadMyHash();
    getNetworkStats()
      .then(s => { if (!destroyed) isFirewalled = s.firewalled; })
      .catch(() => {});

    const unlistenFns: (() => void)[] = [];

    // Page-local listeners for side effects not already covered by the shared
    // friends store (which already handles online/offline state updates).
    // We intentionally do NOT register another listener for 'ember:friend-online'
    // — we rely on the `onlineFriendsStore` subscription above to drive
    // `onlineFriends`, and the effect below takes care of the toast-clear
    // side effect. This avoids double event handling when the page is open.
    listen<{ user_hash: string }>('ember:friend-confirmed', () => {
      loadFriends();
    }).then(fn => { if (destroyed) fn(); else unlistenFns.push(fn); });

    listen<{ firewalled: boolean }>('firewall-status', (event) => {
      isFirewalled = event.payload.firewalled;
      if (!event.payload.firewalled) recheckingFirewall = false;
    }).then(fn => { if (destroyed) fn(); else unlistenFns.push(fn); });

    listen<{ user_hash: string; reason?: string }>('ember:friend-search-failed', (event) => {
      const hash = event.payload.user_hash;
      const reason = event.payload.reason || 'error';
      if (failedSearchToastsShown.has(hash)) return;
      failedSearchToastsShown.add(hash);
      const f = friends.find(fr => fr.user_hash === hash);
      const name = f ? (f.nickname || hash.slice(0, 8) + '\u2026') : hash.slice(0, 8) + '\u2026';
      let msg: string;
      switch (reason) {
        case 'firewalled':
          msg = `${name} is behind a firewall. They may need to enable port forwarding, or wait for them to find you.`;
          break;
        case 'not_found':
          msg = `${name} could not be found on the network. Make sure they're online with Ember.`;
          break;
        case 'timeout':
          msg = `${name} appears to be offline or unreachable.`;
          break;
        case 'refused':
          msg = `${name} went offline.`;
          break;
        default:
          msg = `Could not reach ${name}.`;
      }
      toastWarning(msg);
    }).then(fn => { if (destroyed) fn(); else unlistenFns.push(fn); });

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
    return e instanceof Error ? e.message : typeof e === 'string' ? e : 'Operation failed';
  }

  async function loadFriends() {
    if (destroyed) return;
    loading = true;
    error = null;
    try {
      const list = await getFriends();
      if (destroyed) return;
      friends = list;
    } catch (e: unknown) {
      if (destroyed) return;
      error = toErr(e);
    } finally {
      if (!destroyed) loading = false;
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
    if (!hash) { addError = 'User hash is required'; return; }
    if (!isValidHash(hash)) { addError = 'Must be exactly 32 hex characters'; return; }
    if (myHash && hash.toLowerCase() === myHash.toLowerCase()) {
      addError = 'You cannot add yourself as a friend';
      return;
    }
    if (friends.some((f) => f.user_hash.toLowerCase() === hash.toLowerCase())) {
      addError = 'This user is already in your friend list';
      return;
    }
    adding = true;
    try {
      await addFriend(hash, nick || undefined);
      flash(`Added friend ${nick || hash.slice(0, 8) + '\u2026'}`);
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
      onlineFriendsStore.update(s => { s.delete(f.user_hash); return new Set(s); });
      flash(`Removed ${f.nickname || f.user_hash.slice(0, 8) + '\u2026'}`);
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
  title="Remove Friend"
  message={`Remove ${pendingRemove ? (pendingRemove.nickname || pendingRemove.user_hash.slice(0, 8) + '\u2026') : ''} from your friend list? They will lose upload priority.`}
  confirmLabel="Remove"
  danger={true}
  onconfirm={handleRemove}
/>

<ChatSidebar
  bind:open={chatOpen}
  friendHash={chatFriendHash}
  friendName={chatFriendName}
  onclose={closeChat}
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
  <h2>Friends</h2>
  <div class="header-actions">
    <button class="ghost" onclick={loadFriends}>Refresh</button>
  </div>
</div>

<div class="page-content friends-content">
  {#if error}
    <div class="banner error-banner">
      <span>{error}</span>
      <button class="ghost" onclick={() => (error = null)}>Dismiss</button>
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
          <span class="my-id-label">Your Friend ID</span>
          <span class="my-id-hash">{myHash}</span>
        </div>
      </div>
      <button class="my-id-copy" class:copied={myHashCopied} onclick={copyMyHash}>
        {#if myHashCopied}
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 8 7 12 13 4"/>
          </svg>
          Copied
        {:else}
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="5" y="5" width="9" height="9" rx="1.5"/>
            <path d="M3 11V3a1.5 1.5 0 011.5-1.5H11"/>
          </svg>
          Copy
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
        <span>Your Friend ID is <strong>discoverable</strong> &mdash; friends can find you on the network.</span>
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
          <strong>You are behind a firewall (LowID).</strong>
          Friends can find you but won't be able to connect directly. Enable port forwarding or UPnP in your router to fix this.
        </div>
      </div>
      <button class="firewall-recheck" onclick={handleRecheckFirewall} disabled={recheckingFirewall}>
        {recheckingFirewall ? 'Checking\u2026' : 'Recheck'}
      </button>
      {#if recheckError}
        <span class="firewall-recheck-error" role="status">Recheck failed: {recheckError}</span>
      {/if}
    </div>
  {/if}

  <!-- Pending friend requests -->
  {#if friendRequests.length > 0}
    <div class="requests-section">
      <div class="requests-header">
        <span class="requests-title">Friend Requests</span>
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
                <bdi>{req.sender_nickname || '(unknown)'}</bdi>
                {#if req.verified}
                  <!-- "Verified" badge: the peer's identity was
                       cryptographically confirmed on the session
                       this request rode in on. On friend-connect
                       dial sessions that's full proof of possession
                       (perform_ember_auth signed-nonce round-trip);
                       on regular upload/download sessions it's the
                       offline BLAKE3 binding check (peer's pubkey
                       matches their advertised hash). Either way,
                       the peer is being internally consistent
                       about which Ed25519 key backs their Ember
                       identity — a hash-only spoofer fails this. -->
                  <span class="request-badge request-badge-verified" title="Peer's Ember identity is cryptographically consistent on the session this request arrived on.">Verified</span>
                {:else}
                  <!-- Unverified: peer didn't advertise an Ed25519
                       pubkey, the binding check failed, or
                       (single-source transfer.rs path) the
                       handshake doesn't yet parse OP_EMBER_HELLO.
                       Still surfaces for user approval — only
                       accept from someone you actually know. -->
                  <span class="request-badge request-badge-unverified" title="Peer did not complete identity verification on this session. Only accept if you know who this is.">Unverified</span>
                {/if}
              </span>
              <span class="request-hash" title={req.sender_hash}>{req.sender_hash.slice(0, 8)}&hellip;{req.sender_hash.slice(-6)}</span>
            </div>
            <div class="request-actions">
              <button class="request-accept" onclick={() => handleAcceptRequest(req)} disabled={processingRequests.has(req.sender_hash)}>Accept</button>
              <button class="request-reject" onclick={() => handleRejectRequest(req)} disabled={processingRequests.has(req.sender_hash)}>Reject</button>
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
        {showAddForm ? 'Cancel' : '+ Add Friend'}
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
            placeholder="Search&hellip;"
          />
          {#if searchQuery}
            <button class="search-clear" onclick={() => { searchQuery = ''; }} title="Clear search" aria-label="Clear search">&times;</button>
          {/if}
        </div>
      {/if}
      <span class="inline-stat">{onlineFriends.size} online / {friends.length} friend{friends.length !== 1 ? 's' : ''}</span>
    </div>
  </div>

  {#if showAddForm}
    <div class="add-form">
      <div class="add-form-inner">
        <input
          type="text"
          bind:value={newHash}
          placeholder="Friend ID (32 hex characters)"
          maxlength="32"
          spellcheck="false"
          class="hash-input"
          onkeydown={addFormKeydown}
        />
        <input
          type="text"
          bind:value={newNickname}
          placeholder="Nickname (optional)"
          maxlength="64"
          class="nick-input"
          onkeydown={addFormKeydown}
        />
        <button onclick={handleAdd} disabled={!newHash.trim() || adding}>{adding ? 'Adding\u2026' : 'Add'}</button>
      </div>
      {#if addError}
        <div class="field-error">{addError}</div>
      {/if}
    </div>
  {/if}

  {#if searchQuery.trim() && friends.length > 0}
    <div class="result-count-row">
      <span class="result-count">
        {filtered.length} match{filtered.length !== 1 ? 'es' : ''}
      </span>
    </div>
  {/if}

  {#if loading && friends.length === 0}
    <div class="empty-state">
      <p>Loading friends&hellip;</p>
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
      <p class="empty-title">No friends yet</p>
      <p class="empty-sub">Share your Friend ID above so others can add you. Friends get priority upload slots &mdash; they jump to the front of your queue.</p>
      <button class="empty-action" onclick={() => { showAddForm = true; addError = null; }}>+ Add Friend</button>
    </div>
  {:else if filtered.length === 0}
    <div class="empty-state">
      <p class="empty-title">No matches</p>
      <p class="empty-sub">Try a different search term</p>
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
                placeholder="Enter nickname"
                use:autoFocus
              />
            {:else}
              <button class="nick-btn" onclick={() => startEdit(f)} title="Click to edit nickname">
                <!-- `<bdi>` isolates the peer-supplied nickname from
                     the surrounding UI text direction so an embedded
                     RTL/LTR override character can't reorder
                     neighbouring elements (Trojan-Source-style
                     spoofing). Falls back to a non-peer string when
                     the nickname is empty. -->
                {#if f.nickname}<bdi>{f.nickname}</bdi>{:else}(no nickname){/if}
              </button>
            {/if}
            <span class="card-status-label">
              {#if searchingFriends.has(f.user_hash)}
                <!-- Active rendezvous lookup / dial in flight for
                     this friend. Distinct from the "Waiting for
                     accept" idle state below — the spinner only
                     animates while there's real network work
                     happening, which keeps the UI honest about
                     whether the app is doing something on the
                     friend's behalf. -->
                <span class="status-searching">Searching&hellip;</span>
              {:else if !f.mutual}
                <!-- We've added this peer but they haven't accepted
                     our friend request yet (or we haven't seen the
                     reciprocal request to accept on our side). No
                     active search is running, so don't show the
                     spinner — show a static label that reflects the
                     idle "waiting on user action" state. -->
                <span class="status-pending">Waiting for accept</span>
              {:else if presence === 'online'}
                <span class="status-online">Online</span>
              {:else if f.last_seen}
                Last seen {formatLastSeen(f.last_seen)}
              {:else}
                Added {formatDate(f.added_at)}
              {/if}
            </span>
            {#if unreadCounts.get(f.user_hash)}
              <span class="card-unread-preview">{unreadCounts.get(f.user_hash)} unread message{(unreadCounts.get(f.user_hash) ?? 0) > 1 ? 's' : ''}</span>
            {/if}
          </div>
          <button
            class="icon-btn copy-hash-btn"
            onclick={() => copyHash(f.user_hash)}
            title={copiedHash === f.user_hash ? 'Copied!' : 'Copy Friend ID'}
            aria-label={copiedHash === f.user_hash ? 'Copied Friend ID' : `Copy Friend ID for ${f.nickname || f.user_hash.slice(0, 8)}`}
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
            title="Remove friend"
            aria-label={`Remove friend ${f.nickname || f.user_hash.slice(0, 8)}`}
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
            title={f.mutual ? 'Chat' : 'Waiting for friend to accept'}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M2 3h12v8H5l-3 3z"/>
            </svg>
            Chat
            {#if unreadCounts.get(f.user_hash)}
              <span class="unread-badge">{unreadCounts.get(f.user_hash)}</span>
            {/if}
          </button>
          <button
            class="action-btn browse-action"
            onclick={() => openBrowse(f)}
            disabled={!f.mutual || !isOnline}
            title={!f.mutual ? 'Waiting for friend to accept' : isOnline ? 'Browse files' : 'Browse (offline)'}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M2 4h5l2 2h5v7H2z"/>
            </svg>
            Browse
          </button>
        </div>
      </div>
    {/snippet}

    {#if onlineFiltered.length > 0}
      <div class="section-divider">
        <span class="section-dot online-dot-label"></span>
        <span class="section-label">Online &mdash; {onlineFiltered.length}</span>
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
        <span class="section-label">Offline &mdash; {offlineFiltered.length}</span>
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
