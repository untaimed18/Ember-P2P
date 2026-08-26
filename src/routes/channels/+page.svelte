<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { MQ_MAX_LG } from '$lib/layoutBreakpoints';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import ChatConversation from '$lib/components/ChatConversation.svelte';
  import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
  import IconX from '$lib/components/IconX.svelte';
  import { appSettings, loadAppSettings } from '$lib/stores/settings';
  import { copyToClipboard, formatRelativeTime } from '$lib/utils';
  import { toast, toastError, toastSuccess } from '$lib/stores/toast';
  import { translateError } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';
  import {
    addChannelModerator,
    banChannelMember,
    cachedChannels,
    cancelChannelTransfer,
    channelMemberFriendCode,
    createChannel,
    deleteOwnedChannel,
    enterChannel,
    gatherChannels,
    getChannelInvite,
    joinChannel,
    leaveChannel,
    listChannelMembers,
    listChannelTransfers,
    offerChannelTransfer,
    removeChannelModerator,
    respondChannelTransfer,
    claimChannelOwnership,
    claimChannelUsername,
    searchChannelMessages,
    setChannelSuccessorNominee,
    transferChannelOwnership,
    unbanChannelMember,
    updateChannelModeration,
    type ChannelInfo,
    type ChannelMemberInfo,
    type ChannelMessageInfo,
    type ChannelTransferInfo,
    type GatheredChannelInfo,
  } from '$lib/api/channels';
  import { addFriend } from '$lib/api/friends';
  import {
    activeChannelId,
    channels as channelsStore,
    clearChannelUnread,
    ignoredMembers,
    mutedChannels,
    refreshChannels,
    replaceChannel,
    restoreActiveChannelOnEnter,
    stashActiveChannelOnLeave,
    toggleChannelMute,
    toggleMemberIgnore,
  } from '$lib/stores/channels';

  let channelList = $derived($channelsStore.filter((c) => !c.deleted));
  let selectedId = $derived($activeChannelId);
  let members: ChannelMemberInfo[] = $state([]);
  let loading = $state(true);
  let discovering = $state(false);
  let discovered: GatheredChannelInfo[] = $state([]);
  let createName = $state('');
  let createPrivate = $state(false);
  let joinUri = $state('');
  let error: string | null = $state(null);
  let leaveOpen = $state(false);
  let deleteOpen = $state(false);
  let leaveTargetId = $state<string | null>(null);
  let usernameDraft = $state('');
  let claimingUsername = $state(false);
  let editTopic = $state('');
  let editWelcome = $state('');
  let editingModeration = $state(false);
  let savingModeration = $state(false);
  let moderatingMember = $state<string | null>(null);
  let claiming = $state(false);
  /** Matches the backend default; the backend clamps to 7–365 either way. */
  const DEFAULT_CLAIM_DAYS = 14;
  const CLAIM_WINDOWS = [7, 14, 30, 90, 180, 365];
  let transferTarget = $state<ChannelMemberInfo | null>(null);
  let transferOpen = $state(false);
  let composeMode = $state<'create' | 'join' | null>(null);
  let membersOpen = $state(true);
  let roomInfoOpen = $state(false);
  let listQuery = $state('');
  /** Separate in-flight flags per operation. One shared "form busy" gate meant
   *  creating a room, pasting an invite, and joining from Discover all blocked
   *  each other despite touching nothing in common. */
  let creating = $state(false);
  let joiningForm = $state(false);
  let joiningIds = $state<string[]>([]);
  /** Which member a handoff offer went to this session, per room. `ChannelInfo`
   *  carries no pending-handoff field, and the backend refuses only a switch to
   *  a different member — re-offering to the same one is the retry path for a
   *  dropped gossip offer, so keep that action reachable. */
  let transferSent = $state<Record<string, string>>({});
  /** A `?join=` invite is waiting on the user, so the list must not open a
   *  room over the top of it. Separate from `joinUri` so dismissing the form
   *  doesn't have to discard what they typed. */
  let deepLinkJoin = $state(false);
  /** In-room history search. Local only, so it finds what this device kept. */
  let searchOpen = $state(false);
  let searchQuery = $state('');
  let searchHits: ChannelMessageInfo[] = $state([]);
  let searching = $state(false);
  let searchRan = $state(false);
  /** Guards against a superseded query's reply landing last and showing hits
   *  for text the box no longer contains. */
  let searchGen = 0;
  /**
   * Ember Transfers this session, keyed by transfer id.
   *
   * Not persisted, because the backend does not persist them either: a
   * transfer belongs to the session that started it. Terminal rows are kept
   * briefly so "complete" or "declined" is actually seen before it vanishes.
   */
  let transfers = $state<Record<string, ChannelTransferInfo>>({});
  /** Members we have a send action in flight for, so the menu item can't be
   *  double-fired while the file is being hashed. */
  let sendingTo = $state<string[]>([]);
  let addingFriend = $state<string[]>([]);

  let emberOff = $derived($appSettings?.ember_native_enabled === false);
  let selected = $derived(
    channelList.find((c) => c.channel_id === selectedId && c.in_room) ?? null,
  );
  let needsUsername = $derived(!($appSettings?.channel_username ?? '').trim());
  let canModerate = $derived(!!selected && (selected.is_owner || selected.you_are_moderator));
  /**
   * The one gate that has to serialise. Every owner moderation command —
   * topic/welcome, ban, unban, promote, demote — is a read-modify-write of the
   * whole signed snapshot on the backend (`load_banned_pubkeys` then
   * `commit_channel_moderation`). Two in flight would build from the same base
   * and the later would silently discard the earlier's change, so they share a
   * gate rather than getting one each.
   */
  let moderationBusy = $derived(savingModeration || moderatingMember !== null);
  let transferPendingTo = $derived(
    selected && !selected.successor_id ? transferSent[selected.channel_id] ?? null : null,
  );
  /**
   * Memoised primitives for `ChatConversation`. Passing `selected.name` and
   * friends inline made its props depend on `selected`'s object *identity*, and
   * every write to the channels store allocates fresh row objects — so the
   * effect in that component which calls `clearChannelUnread` re-triggered
   * itself, wiping the composer on each pass. A `$derived` only propagates when
   * the value really differs, which keeps that boundary stable no matter how
   * often the store churns.
   */
  /**
   * "Owner is away, X can take over" — but only worth saying once the owner has
   * actually gone quiet. `presenceNow` ticks, so the countdown moves on its own.
   */
  let nomineeNotice = $derived.by(() => {
    if (!selected?.successor_nominee || selected.claim_after_days <= 0) return '';
    const who = memberNames[selected.successor_nominee] || shortId(selected.successor_nominee);
    if (selected.can_claim) return m.channels_owner_inactive_now({ name: who });
    if (selected.moderation_updated_at <= 0) return '';
    const elapsedDays = (presenceNow / 1000 - selected.moderation_updated_at) / 86400;
    const left = Math.ceil(selected.claim_after_days - elapsedDays);
    // Only worth mentioning once the owner has actually started to go quiet.
    if (left <= 0 || elapsedDays < selected.claim_after_days / 2) return '';
    return m.channels_owner_inactive({ name: who, days: left });
  });
  let selectedMuted = $derived(!!selected && $mutedChannels.includes(selected.channel_id));
  let selectedChannelId = $derived(selected?.channel_id ?? '');
  let selectedName = $derived(selected?.name ?? '');
  let selectedBanned = $derived(selected?.you_are_banned ?? false);
  let selectedKeyBehind = $derived(selected?.key_behind ?? false);
  let memberNames = $derived(
    Object.fromEntries(
      members.map((mem) => [
        mem.member_pubkey,
        mem.is_self ? m.channels_you() : mem.nickname,
      ]),
    ),
  );
  let directoryList = $derived.by(() => {
    const hidden = new Set(
      $channelsStore.filter((c) => c.deleted).map((c) => c.channel_id),
    );
    const byId = new Map<string, ChannelInfo>();
    for (const ch of channelList) {
      byId.set(ch.channel_id, ch);
    }
    for (const item of discovered) {
      if (hidden.has(item.channel_id) || byId.has(item.channel_id)) continue;
      byId.set(item.channel_id, {
        channel_id: item.channel_id,
        pubkey: item.pubkey,
        name: item.name,
        visibility: 'public',
        is_owner: false,
        topic: '',
        welcome: '',
        joined_at: 0,
        last_active: 0,
        member_count: 0,
        unread: 0,
        you_are_banned: false,
        you_are_moderator: false,
        successor_id: '',
        predecessor_id: '',
        successor_nominee: '',
        claim_after_days: 0,
        moderation_updated_at: 0,
        can_claim: false,
        key_behind: false,
        owner_pubkey: '',
        in_room: item.joined,
        deleted: false,
      });
    }
    return [...byId.values()];
  });
  let leaveTargetName = $derived(
    directoryList.find((c) => c.channel_id === leaveTargetId)?.name
      ?? channelList.find((c) => c.channel_id === leaveTargetId)?.name
      ?? '',
  );
  let visibleChannels = $derived.by(() => {
    const q = listQuery.trim().toLowerCase();
    const list = directoryList;
    if (!q) return list;
    return list.filter(
      (ch) =>
        ch.name.toLowerCase().includes(q) ||
        ch.topic.toLowerCase().includes(q),
    );
  });
  let sortedMembers = $derived(
    members.slice().sort((a, b) => {
      if (a.is_self !== b.is_self) return a.is_self ? -1 : 1;
      if (a.banned !== b.banned) return a.banned ? 1 : -1;
      if (a.moderator !== b.moderator) return a.moderator ? -1 : 1;
      const an = (a.nickname || a.member_pubkey).toLowerCase();
      const bn = (b.nickname || b.member_pubkey).toLowerCase();
      return an.localeCompare(bn);
    }),
  );

  function autoFocus(node: HTMLElement) {
    node.focus();
  }

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

  function onPageKeydown(e: KeyboardEvent) {
    if (e.key !== 'Escape') return;
    if (document.querySelector('.card-more[open]')) {
      closeCardMenus();
      e.preventDefault();
      e.stopPropagation();
      return;
    }
    if (roomInfoOpen) {
      roomInfoOpen = false;
      e.preventDefault();
      return;
    }
    if (composeMode) {
      composeMode = null;
      deepLinkJoin = false;
      error = null;
      e.preventDefault();
      return;
    }
    if (membersOpen && typeof window !== 'undefined' && window.matchMedia(MQ_MAX_LG).matches) {
      membersOpen = false;
      e.preventDefault();
    }
  }

  /**
   * Whether a member has been heard from recently enough to call them present.
   *
   * `last_seen` advances on their presence record (republished every
   * `PRESENCE_REPUBLISH_SECS`, ten minutes) and on any message of theirs we
   * ingest. Two intervals of slack means one missed republish does not blink
   * somebody offline; the DHT drops the record entirely at 45 minutes, so
   * anything beyond that would be claiming more than we know.
   */
  const PRESENCE_FRESH_SECS = 20 * 60;

  /** Ticks the clock the presence check reads. Freshness is measured against
   *  wall-clock, which no amount of roster reactivity refreshes on its own, so
   *  without this a member keeps whatever dot they had when the list was last
   *  fetched — potentially long past the window. */
  let presenceNow = $state(Math.floor(Date.now() / 1000));

  function isPresent(mem: ChannelMemberInfo, nowSecs: number): boolean {
    if (mem.last_seen <= 0) return false;
    return nowSecs - mem.last_seen <= PRESENCE_FRESH_SECS;
  }

  function channelHue(id: string): number {
    let h = 0;
    for (let i = 0; i < Math.min(id.length, 8); i++) {
      h = (h * 33 + id.charCodeAt(i)) % 360;
    }
    return h;
  }

  function toggleCompose(mode: 'create' | 'join') {
    composeMode = composeMode === mode ? null : mode;
    if (composeMode !== 'join') deepLinkJoin = false;
    error = null;
  }

  onMount(() => {
    restoreActiveChannelOnEnter();
    if (typeof window !== 'undefined' && window.matchMedia(MQ_MAX_LG).matches) {
      membersOpen = false;
    }
    loadChannels();
    void refreshDirectory(false);
    const gatherTimer = setInterval(() => {
      void refreshDirectory(false);
    }, 60_000);
    let cancelled = false;
    let unlistenMembers: UnlistenFn | undefined;
    listen<{ channel_id: string }>('ember:channel-members', (event) => {
      const id = event.payload.channel_id;
      refreshChannels().catch(() => {});
      if (id === selectedId) void refreshMembers(id);
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenMembers = fn;
    });
    let unlistenModeration: UnlistenFn | undefined;
    listen<{ channel_id: string }>('ember:channel-moderation', (event) => {
      const id = event.payload.channel_id;
      refreshChannels()
        .then(() => {
          const ch = $channelsStore.find((c) => c.channel_id === selectedId);
          if (ch && !editingModeration) {
            editTopic = ch.topic;
            editWelcome = ch.welcome;
          }
        })
        .catch(() => {});
      if (id === selectedId) void refreshMembers(id);
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenModeration = fn;
    });
    let unlistenHandoff: UnlistenFn | undefined;
    listen<{ channel_id: string; successor_id?: string }>('ember:channel-handoff', (event) => {
      // Only the room that actually moved: wiping the map cleared the pending
      // banner for every other room too.
      const moved = event.payload?.channel_id;
      if (moved) {
        transferSent = Object.fromEntries(
          Object.entries(transferSent).filter(([key]) => key !== moved),
        );
      }
      refreshChannels()
        .then(() => {
          if (selectedId) void refreshMembers(selectedId);
        })
        .catch(() => {});
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenHandoff = fn;
    });
    // One index shard answered. Sixteen of these arrive per browse, in whatever
    // order the DHT returns them, so the list grows as the walk proceeds instead
    // of appearing all at once when the slowest shard gives up. Ignored unless a
    // browse is actually running, so a dismissed list stays dismissed.
    let unlistenFound: UnlistenFn | undefined;
    listen<GatheredChannelInfo[]>('ember:channels-found', (event) => {
      const batch = event.payload ?? [];
      if (batch.length === 0) return;
      const byId = new Map(discovered.map((item) => [item.channel_id, item]));
      for (const item of batch) byId.set(item.channel_id, item);
      discovered = [...byId.values()];
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenFound = fn;
    });
    // Ember Transfer. `xfer-offer` is an offer waiting on the user;
    // `xfer-update` carries every state change including progress.
    let unlistenXferOffer: UnlistenFn | undefined;
    listen<{
      xfer_id: string;
      channel_id: string;
      peer_pubkey: string;
      name: string;
      size: number;
    }>('ember:xfer-offer', (event) => {
      const p = event.payload;
      transfers = {
        ...transfers,
        [p.xfer_id]: {
          xfer_id: p.xfer_id,
          channel_id: p.channel_id,
          peer_pubkey: p.peer_pubkey,
          direction: 'receive',
          name: p.name,
          size: p.size,
          transferred: 0,
          status: 'awaiting',
        },
      };
      // The panel only draws the open room's transfers, so an offer made
      // while the user is reading somewhere else would sit unseen until it
      // expired. Say which room it is in instead.
      if (p.channel_id !== selectedId) {
        const room = channelList.find((c) => c.channel_id === p.channel_id);
        toast(
          room
            ? m.channels_xfer_offer_elsewhere({ room: room.name })
            : m.channels_xfer_offer_elsewhere_unknown(),
        );
      }
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenXferOffer = fn;
    });
    let unlistenXferUpdate: UnlistenFn | undefined;
    // Keyed by transfer, so a row that reports two terminal states in a row
    // replaces its own timer instead of stacking a second one.
    const xferClearTimers = new Map<string, ReturnType<typeof setTimeout>>();
    listen<ChannelTransferInfo>('ember:xfer-update', (event) => {
      const t = event.payload;
      transfers = { ...transfers, [t.xfer_id]: t };
      // A finished row is worth seeing, not worth keeping. Clearing it after a
      // few seconds saves the user dismissing every transfer by hand.
      if (TERMINAL_XFER.includes(t.status)) {
        const existing = xferClearTimers.get(t.xfer_id);
        if (existing) clearTimeout(existing);
        xferClearTimers.set(
          t.xfer_id,
          setTimeout(() => {
            xferClearTimers.delete(t.xfer_id);
            const { [t.xfer_id]: _done, ...rest } = transfers;
            transfers = rest;
          }, 8000),
        );
      }
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenXferUpdate = fn;
    });
    // Anything already in flight when this page mounted. Merged rather than
    // assigned, and with live rows winning: the listeners above are already
    // running, so an offer arriving while this call is in flight would
    // otherwise be wiped by a snapshot taken before it existed.
    listChannelTransfers()
      .then((list) => {
        if (cancelled) return;
        transfers = { ...Object.fromEntries(list.map((t) => [t.xfer_id, t])), ...transfers };
      })
      .catch((e) => {
        console.warn('Channels: could not list transfers already in flight', e);
      });
    document.addEventListener('pointerdown', onCardMenuPointerDown);
    document.addEventListener('keydown', onPageKeydown);
    // Half the presence-republish interval, so a member crossing the freshness
    // line is reflected within a minute or so without polling the backend.
    const presenceTimer = setInterval(() => {
      presenceNow = Math.floor(Date.now() / 1000);
    }, 30_000);
    return () => {
      cancelled = true;
      clearInterval(presenceTimer);
      clearInterval(gatherTimer);
      for (const timer of xferClearTimers.values()) clearTimeout(timer);
      xferClearTimers.clear();
      unlistenMembers?.();
      unlistenModeration?.();
      unlistenHandoff?.();
      unlistenFound?.();
      unlistenXferOffer?.();
      unlistenXferUpdate?.();
      document.removeEventListener('pointerdown', onCardMenuPointerDown);
      document.removeEventListener('keydown', onPageKeydown);
      stashActiveChannelOnLeave();
    };
  });

  $effect(() => {
    if (emberOff) {
      goto('/ember').catch(() => {});
    }
  });

  $effect(() => {
    const joinParam = $page.url.searchParams.get('join');
    if (!joinParam) return;
    joinUri = joinParam;
    composeMode = 'join';
    deepLinkJoin = true;
    error = null;
    untrack(() => {
      const next = new URL($page.url);
      next.searchParams.delete('join');
      void goto(`${next.pathname}${next.search}${next.hash}`, {
        replaceState: true,
        keepFocus: true,
        noScroll: true,
      }).catch(() => {});
    });
  });

  async function loadChannels() {
    loading = true;
    error = null;
    try {
      await refreshChannels();
      const current = selectedId;
      if (current && !$channelsStore.some((c) => c.channel_id === current && c.in_room)) {
        activeChannelId.set(null);
        members = [];
      } else if (current) {
        // `activeChannelId` is a module-level store, but the roster and the
        // moderation drafts are component state and the layout keys this page
        // on the pathname — so navigating away and back keeps the selection
        // while resetting everything around it. Re-seed both: otherwise the
        // members pane sits on its loading text forever, and the owner's topic
        // and welcome come up blank, which saving from there would persist.
        const ch = $channelsStore.find((c) => c.channel_id === current);
        if (!editingModeration) {
          editTopic = ch?.topic ?? '';
          editWelcome = ch?.welcome ?? '';
        }
        if (members.length === 0) await refreshMembers(current, true);
      } else if ($channelsStore.some((c) => c.in_room && !c.deleted) && !deepLinkJoin) {
        const newest = $channelsStore
          .filter((c) => c.in_room && !c.deleted)
          .slice()
          .sort((a, b) => b.last_active - a.last_active)[0];
        if (newest) await selectChannel(newest.channel_id);
      }
    } catch (e) {
      error = translateError(e, m.error_operation_failed());
    } finally {
      loading = false;
    }
  }

  /** Apply only while `id` is still the open room, so a slow reply from a
   *  previous selection cannot replace the current roster. */
  async function refreshMembers(id: string, notify = false) {
    try {
      const mems = await listChannelMembers(id);
      if (id === selectedId) members = mems;
    } catch (e) {
      if (notify && id === selectedId) {
        toastError(translateError(e, m.error_operation_failed()));
      }
    }
  }

  async function selectChannel(id: string) {
    const ch = $channelsStore.find((c) => c.channel_id === id);
    if (!ch?.in_room) return;
    activeChannelId.set(id);
    members = [];
    editTopic = ch.topic ?? '';
    editWelcome = ch.welcome ?? '';
    editingModeration = false;
    roomInfoOpen = false;
    resetSearch();
    // Ahead of the fetch: a roster that fails to load must not leave an unread
    // badge on the room the user is now reading.
    clearChannelUnread(id);
    await refreshMembers(id, true);
  }

  function resetSearch() {
    searchGen++;
    searchOpen = false;
    searchQuery = '';
    searchHits = [];
    searchRan = false;
    searching = false;
  }

  async function runSearch() {
    const id = selectedId;
    const query = searchQuery.trim();
    if (!id || !query) {
      searchHits = [];
      searchRan = false;
      return;
    }
    const gen = ++searchGen;
    searching = true;
    try {
      const hits = await searchChannelMessages(id, query);
      // Apply only if this is still the newest query for the still-open room:
      // a slower earlier search must not overwrite a later one's hits.
      if (gen === searchGen && id === selectedId) {
        searchHits = hits;
        searchRan = true;
      }
    } catch (e) {
      if (gen === searchGen && id === selectedId) {
        toastError(translateError(e, m.error_operation_failed()));
      }
    } finally {
      if (gen === searchGen) searching = false;
    }
  }

  function clearSelection() {
    activeChannelId.set(null);
    members = [];
    roomInfoOpen = false;
  }

  async function handleCreate() {
    if (creating) return;
    if (needsUsername) {
      composeMode = 'create';
      return;
    }
    error = null;
    creating = true;
    try {
      const invite = await createChannel(createName.trim(), createPrivate);
      createName = '';
      createPrivate = false;
      composeMode = null;
      deepLinkJoin = false;
      // The clipboard write needs nothing from the list refresh, so overlap
      // them. `refreshChannels` rather than `loadChannels`: we select the new
      // room explicitly below, so the latter's roster fetch for whatever was
      // previously open would be thrown away.
      const [copied] = await Promise.all([
        copyToClipboard(invite.uri),
        refreshChannels(),
      ]);
      await selectChannel(invite.channel_id);
      if (copied) {
        toastSuccess(m.channels_invite_copied());
      } else {
        toastError(m.kad_clipboard_unavailable());
      }
    } catch (e) {
      error = translateError(e, m.error_operation_failed());
    } finally {
      creating = false;
    }
  }

  /** `discoveredId` marks a join started from the Discover list. Those must not
   *  touch the invite box or close a form the user is still filling in, and
   *  each row gets its own in-flight slot so several can run at once. */
  async function handleJoin(uri = joinUri, discoveredId?: string) {
    if (needsUsername) {
      composeMode = composeMode ?? 'join';
      return;
    }
    if (discoveredId) {
      if (joiningIds.includes(discoveredId)) return;
      joiningIds = [...joiningIds, discoveredId];
    } else {
      if (joiningForm) return;
      joiningForm = true;
    }
    error = null;
    try {
      const joined = await joinChannel(uri.trim());
      if (!discoveredId) {
        joinUri = '';
        composeMode = null;
        deepLinkJoin = false;
      }
      discovered = discovered.map((item) =>
        item.channel_id === joined.channel_id ? { ...item, joined: joined.in_room } : item,
      );
      await refreshChannels();
      await selectChannel(joined.channel_id);
    } catch (e) {
      error = translateError(e, m.error_operation_failed());
    } finally {
      if (discoveredId) {
        joiningIds = joiningIds.filter((channelId) => channelId !== discoveredId);
      } else {
        joiningForm = false;
      }
    }
  }

  async function handleLeave() {
    const id = leaveTargetId;
    if (!id) return;
    try {
      await leaveChannel(id);
      if (selectedId === id) {
        activeChannelId.set(null);
        members = [];
        resetSearch();
      }
      transferSent = Object.fromEntries(
        Object.entries(transferSent).filter(([key]) => key !== id),
      );
      discovered = discovered.map((item) =>
        item.channel_id === id ? { ...item, joined: false } : item,
      );
      await refreshChannels();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      leaveTargetId = null;
    }
  }

  async function handleCopyInvite() {
    if (!selectedId) return;
    try {
      const invite = await getChannelInvite(selectedId);
      if (await copyToClipboard(invite.uri)) {
        toastSuccess(m.channels_invite_copied());
      } else {
        toastError(m.kad_clipboard_unavailable());
      }
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  async function refreshDirectory(notifyEmpty: boolean) {
    discovering = true;
    try {
      if (discovered.length === 0) {
        try {
          discovered = await cachedChannels();
        } catch {
          // A cold cache is the normal first run, not a failure to report.
        }
      }
      const found = await gatherChannels();
      discovered = found;
      await refreshChannels();
      if (notifyEmpty && found.length === 0) {
        toastSuccess(m.channels_none_found());
      }
    } catch (e) {
      if (notifyEmpty) toastError(translateError(e, m.error_operation_failed()));
    } finally {
      discovering = false;
    }
  }

  async function handleDiscover() {
    await refreshDirectory(true);
  }

  async function joinCard(ch: ChannelInfo) {
    if (needsUsername) {
      composeMode = 'join';
      return;
    }
    if (joiningIds.includes(ch.channel_id)) return;
    joiningIds = [...joiningIds, ch.channel_id];
    error = null;
    try {
      const local = $channelsStore.find(
        (row) => row.channel_id === ch.channel_id && !row.deleted,
      );
      const joined = local
        ? await enterChannel(ch.channel_id)
        : await joinChannel(
            `ember-channel:${ch.channel_id}?pk=${ch.pubkey}&name=${encodeURIComponent(ch.name)}`,
          );
      discovered = discovered.map((item) =>
        item.channel_id === joined.channel_id ? { ...item, joined: joined.in_room } : item,
      );
      await refreshChannels();
      await selectChannel(joined.channel_id);
    } catch (e) {
      error = translateError(e, m.error_operation_failed());
    } finally {
      joiningIds = joiningIds.filter((id) => id !== ch.channel_id);
    }
  }

  function requestLeave(channelId: string) {
    leaveTargetId = channelId;
    leaveOpen = true;
  }

  async function handleDeleteOwned() {
    const id = selectedId;
    if (!id) return;
    try {
      await deleteOwnedChannel(id);
      activeChannelId.set(null);
      members = [];
      discovered = discovered.filter((item) => item.channel_id !== id);
      resetSearch();
      await refreshChannels();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  async function handleClaimUsername() {
    if (claimingUsername) return;
    claimingUsername = true;
    error = null;
    try {
      await claimChannelUsername(usernameDraft.trim());
      usernameDraft = '';
      await loadAppSettings();
    } catch (e) {
      error = translateError(e, m.error_operation_failed());
    } finally {
      claimingUsername = false;
    }
  }

  async function handleSaveModeration() {
    const id = selectedId;
    if (!id || moderationBusy) return;
    savingModeration = true;
    try {
      const updated = await updateChannelModeration(id, editTopic, editWelcome);
      replaceChannel(updated);
      editingModeration = false;
      toastSuccess(m.channels_moderation_saved());
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      savingModeration = false;
    }
  }

  async function handleBan(memberPubkey: string) {
    const id = selectedId;
    if (!id || moderationBusy) return;
    moderatingMember = memberPubkey;
    const rotates = !!selected?.is_owner && selected.visibility === 'private';
    try {
      await banChannelMember(id, memberPubkey);
      await refreshMembers(id, true);
      // Worth saying out loud: the removal also killed every invite link the
      // owner has ever handed out for this room.
      if (rotates) toastSuccess(m.channels_rotated_notice());
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      moderatingMember = null;
    }
  }

  async function handleUnban(memberPubkey: string) {
    const id = selectedId;
    if (!id || moderationBusy) return;
    moderatingMember = memberPubkey;
    try {
      await unbanChannelMember(id, memberPubkey);
      await refreshMembers(id, true);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      moderatingMember = null;
    }
  }

  async function handleAddModerator(memberPubkey: string) {
    const id = selectedId;
    if (!id || moderationBusy) return;
    moderatingMember = memberPubkey;
    try {
      await addChannelModerator(id, memberPubkey);
      await refreshMembers(id, true);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      moderatingMember = null;
    }
  }

  async function handleRemoveModerator(memberPubkey: string) {
    const id = selectedId;
    if (!id || moderationBusy) return;
    moderatingMember = memberPubkey;
    try {
      await removeChannelModerator(id, memberPubkey);
      await refreshMembers(id, true);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      moderatingMember = null;
    }
  }

  function requestTransfer(member: ChannelMemberInfo) {
    transferTarget = member;
    transferOpen = true;
  }

  async function handleTransfer() {
    const id = selectedId;
    const target = transferTarget;
    if (!id || !target) return;
    try {
      await transferChannelOwnership(id, target.member_pubkey);
      transferSent = { ...transferSent, [id]: target.member_pubkey };
      toastSuccess(m.channels_transfer_started());
      await refreshChannels();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      transferTarget = null;
    }
  }

  async function handleNominee(memberPubkey: string, days = DEFAULT_CLAIM_DAYS) {
    const id = selectedId;
    if (!id) return;
    savingModeration = true;
    try {
      await setChannelSuccessorNominee(id, memberPubkey || null, memberPubkey ? days : null);
      toastSuccess(m.channels_succession_saved());
      await refreshChannels();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      savingModeration = false;
    }
  }

  async function handleClaim() {
    const id = selectedId;
    if (!id || claiming) return;
    claiming = true;
    try {
      const successor = await claimChannelOwnership(id);
      toastSuccess(m.channels_claimed());
      await refreshChannels();
      await selectChannel(successor.channel_id);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      claiming = false;
    }
  }

  async function openSuccessor() {
    const id = selected?.successor_id;
    if (!id) return;
    await refreshChannels().catch(() => {});
    if ($channelsStore.some((c) => c.channel_id === id)) {
      await selectChannel(id);
    } else {
      toastError(m.error_channels_not_found());
    }
  }

  function shortId(id: string): string {
    return id.slice(0, 8) + '\u2026';
  }

  /** Anyone other than yourself has a menu now: ignoring is available to every
   *  member, where the moderation items below are not. */
  function memberHasMenu(mem: ChannelMemberInfo): boolean {
    return !!selected && !mem.is_self;
  }

  function isChannelOwner(mem: ChannelMemberInfo): boolean {
    if (!selected) return false;
    if (mem.is_self && selected.is_owner) return true;
    const owner = selected.owner_pubkey;
    return !!owner && mem.member_pubkey.toLowerCase() === owner.toLowerCase();
  }

  /** Right-click opens the same menu the button does, rather than a second one
   *  that would have to be kept in step with it. */
  function openMemberMenu(e: MouseEvent) {
    const row = e.currentTarget as HTMLElement;
    const menu = row.querySelector('details.card-more') as HTMLDetailsElement | null;
    if (!menu) return;
    e.preventDefault();
    closeCardMenus(menu);
    menu.open = true;
  }

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  async function handleAddFriend(mem: ChannelMemberInfo) {
    const pk = mem.member_pubkey;
    if (addingFriend.includes(pk)) return;
    addingFriend = [...addingFriend, pk];
    try {
      const code = await channelMemberFriendCode(pk);
      await addFriend(code, mem.nickname || undefined);
      toastSuccess(m.channels_friend_added({ name: mem.nickname || shortId(pk) }));
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      addingFriend = addingFriend.filter((k) => k !== pk);
    }
  }

  async function handleCopyMemberId(mem: ChannelMemberInfo) {
    if (await copyToClipboard(mem.member_pubkey)) {
      toastSuccess(m.channels_member_id_copied());
    } else {
      toastError(m.kad_clipboard_unavailable());
    }
  }

  async function handleSendFile(mem: ChannelMemberInfo) {
    const id = selectedId;
    const pk = mem.member_pubkey;
    if (!id || sendingTo.includes(pk)) return;
    // Claimed before the picker opens, not after. Hashing a large file takes a
    // moment, and the menu item is only disabled once this is set — so a
    // second click while the dialog was up used to start a second offer.
    sendingTo = [...sendingTo, pk];
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const picked = await open({ multiple: false, title: m.channels_send_file() });
      if (!picked || Array.isArray(picked)) return;
      await offerChannelTransfer(id, pk, picked);
      toastSuccess(m.channels_xfer_offer_sent({ name: mem.nickname || shortId(pk) }));
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      sendingTo = sendingTo.filter((k) => k !== pk);
    }
  }

  /** Transfers with an answer in flight. Without this a second click sends a
   *  second reply, and the backend answers the first one and rejects the
   *  second with "no longer waiting" — an error for doing nothing wrong. */
  let respondingTo = $state<string[]>([]);

  async function handleRespondTransfer(xferId: string, accept: boolean) {
    if (respondingTo.includes(xferId)) return;
    respondingTo = [...respondingTo, xferId];
    try {
      await respondChannelTransfer(xferId, accept);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      respondingTo = respondingTo.filter((id) => id !== xferId);
    }
  }

  async function handleCancelTransfer(xferId: string) {
    if (respondingTo.includes(xferId)) return;
    respondingTo = [...respondingTo, xferId];
    try {
      await cancelChannelTransfer(xferId);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      respondingTo = respondingTo.filter((id) => id !== xferId);
    }
  }

  /** Transfers belonging to the room on screen. A transfer is between two
   *  people in one room, so showing another room's would be noise. */
  /** Offers waiting on an answer come first — they are the only rows that
   *  need the user to do something, and they expire. Everything else keeps a
   *  stable order so a progress bar does not jump around as it fills. */
  let roomTransfers = $derived(
    Object.values(transfers)
      .filter((t) => t.channel_id === selectedChannelId)
      .sort((a, b) => {
        const waiting = (t: ChannelTransferInfo) => (t.status === 'awaiting' ? 0 : 1);
        return waiting(a) - waiting(b) || a.xfer_id.localeCompare(b.xfer_id);
      }),
  );
  const TERMINAL_XFER: string[] = [
    'complete',
    'declined',
    'cancelled',
    'stalled',
    'expired',
    'failed',
    'busy',
    'too_large',
    'not_allowed',
    'source_gone',
  ];

  function transferLabel(t: ChannelTransferInfo): string {
    const who = memberNames[t.peer_pubkey] || shortId(t.peer_pubkey);
    switch (t.status) {
      case 'awaiting':
        return m.channels_xfer_awaiting({ name: who });
      case 'offered':
        return m.channels_xfer_offered({ name: who });
      case 'accepted':
      case 'active':
        return t.direction === 'send'
          ? m.channels_xfer_sending({ name: who })
          : m.channels_xfer_receiving({ name: who });
      case 'complete':
        return t.direction === 'send'
          ? m.channels_xfer_sent({ name: who })
          : m.channels_xfer_received({ name: who });
      case 'declined':
        return m.channels_xfer_declined({ name: who });
      case 'busy':
        return m.channels_xfer_peer_busy({ name: who });
      case 'too_large':
        return m.channels_xfer_peer_too_large({ name: who });
      case 'not_allowed':
        return m.channels_xfer_peer_refuses({ name: who });
      case 'expired':
        return m.channels_xfer_expired();
      case 'stalled':
        return m.channels_xfer_stalled();
      case 'source_gone':
        return m.channels_xfer_source_gone();
      case 'cancelled':
        return m.channels_xfer_cancelled();
      default:
        return m.channels_xfer_failed();
    }
  }
</script>

<div class="page-header">
  <div class="header-title">
    <h2>{m.nav_channels()}</h2>
    {#if channelList.length > 0 || directoryList.length > 0}
      <span class="header-count">
        {directoryList.length === 1
          ? m.channels_count_one()
          : m.channels_count_other({ count: directoryList.length })}
      </span>
    {/if}
  </div>
  <div class="header-actions">
    <button class="ghost" onclick={handleDiscover} disabled={discovering || emberOff}>
      {discovering ? m.channels_discovering() : m.channels_discover()}
    </button>
    <button
      class="ghost"
      class:active-toggle={composeMode === 'join'}
      onclick={() => toggleCompose('join')}
      disabled={emberOff}
    >
      {composeMode === 'join' ? m.common_cancel() : m.channels_join()}
    </button>
    <button
      class="add-btn primary"
      class:danger={composeMode === 'create'}
      onclick={() => toggleCompose('create')}
      disabled={emberOff}
    >
      {composeMode === 'create' ? m.common_cancel() : m.channels_create()}
    </button>
  </div>
</div>

<div class="page-content channels-page">
  <details class="how-panel">
    <summary class="how-title">{m.channels_how_title()}</summary>
    <p class="how-lede">{m.channels_page_subtitle()}</p>
    <p class="how-limits">{m.channels_limits_note()}</p>
  </details>

  {#if error}
    <div class="banner error-banner" role="alert">
      <span>{error}</span>
      <button class="ghost" onclick={() => (error = null)}>{m.common_dismiss()}</button>
    </div>
  {/if}

  {#if emberOff}
    <div class="banner" role="status">
      <strong>{m.channels_disabled_title()}</strong>
      {m.channels_disabled_body()}
    </div>
  {:else}
    {#if needsUsername}
      <form
        class="add-form"
        onsubmit={(e) => {
          e.preventDefault();
          handleClaimUsername();
        }}
      >
        <p class="form-title">{m.channels_username_title()}</p>
        <p class="form-hint">{m.channels_username_hint()}</p>
        <div class="add-form-inner">
          <input
            bind:value={usernameDraft}
            placeholder={m.channels_username_placeholder()}
            maxlength="32"
            aria-label={m.channels_username_placeholder()}
            use:autoFocus
          />
          <button type="submit" disabled={usernameDraft.trim().length < 2 || claimingUsername}>
            {m.channels_username_save()}
          </button>
        </div>
      </form>
    {:else if composeMode === 'create'}
      <form
        class="add-form"
        onsubmit={(e) => {
          e.preventDefault();
          handleCreate();
        }}
      >
        <p class="form-title">{m.channels_create_title()}</p>
        <div class="add-form-inner">
          <input
            bind:value={createName}
            placeholder={m.channels_name_placeholder()}
            maxlength="64"
            aria-label={m.channels_name_placeholder()}
            use:autoFocus
          />
          <ToggleSwitch bind:checked={createPrivate} label={m.channels_private_label()} />
          <button type="submit" disabled={!createName.trim() || creating}>{m.channels_create()}</button>
        </div>
      </form>
    {:else if composeMode === 'join'}
      <form
        class="add-form"
        onsubmit={(e) => {
          e.preventDefault();
          handleJoin();
        }}
      >
        <p class="form-title">{m.channels_join_title()}</p>
        <div class="add-form-inner">
          <input
            class="join-input"
            bind:value={joinUri}
            placeholder={m.channels_join_placeholder()}
            aria-label={m.channels_join_title()}
            spellcheck="false"
            autocomplete="off"
            use:autoFocus
          />
          <button type="submit" disabled={!joinUri.trim() || joiningForm}>{m.channels_join()}</button>
        </div>
      </form>
    {/if}

    {#if loading && directoryList.length === 0}
      <div class="empty-state">
        <div class="spinner lg"></div>
        <p>{m.common_loading()}</p>
      </div>
    {:else if directoryList.length === 0}
      <div class="empty-state">
        <div class="empty-icon">
          <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M8 14h32v22H8z"/>
            <path d="M8 14l16 10 16-10"/>
            <circle cx="36" cy="12" r="4"/>
          </svg>
        </div>
        <p class="empty-title">{m.channels_empty_title()}</p>
        <p class="empty-sub">{m.channels_empty()}</p>
        <div class="empty-actions">
          <button
            class="empty-action"
            onclick={() => {
              composeMode = 'create';
              error = null;
            }}
          >{m.channels_create()}</button>
          <button
            class="ghost"
            onclick={() => {
              composeMode = 'join';
              error = null;
            }}
          >{m.channels_join_title()}</button>
        </div>
      </div>
    {:else}
      <div class="workspace" class:members-open={membersOpen && !!selected}>
        <aside class="list-pane" class:hidden-when-chat={!!selected}>
          {#if directoryList.length > 5}
            <div class="search-wrap">
              <span class="search-icon">
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
                  <circle cx="8.5" cy="8.5" r="5.5"/><line x1="12.5" y1="12.5" x2="17" y2="17"/>
                </svg>
              </span>
              <input
                type="text"
                class="search-input"
                bind:value={listQuery}
                placeholder={m.common_search() + '…'}
                aria-label={m.common_search()}
                onkeydown={(e) => {
                  if (e.key !== 'Escape' || !listQuery) return;
                  e.preventDefault();
                  e.stopPropagation();
                  listQuery = '';
                }}
              />
              {#if listQuery}
                <button type="button" class="search-clear" onclick={() => (listQuery = '')} title={m.common_close()} aria-label={m.common_close()}><IconX size={12} /></button>
              {/if}
            </div>
          {/if}
          <div class="list-scroll">
            {#if visibleChannels.length === 0}
              <p class="muted list-empty">{m.channels_no_matches()}</p>
            {:else}
              {#each visibleChannels as ch (ch.channel_id)}
                <div
                  class="chan-row"
                  class:active={ch.in_room && ch.channel_id === selectedId}
                >
                  <button
                    type="button"
                    class="chan-row-main"
                    aria-current={ch.in_room && ch.channel_id === selectedId ? 'true' : undefined}
                    onclick={() => selectChannel(ch.channel_id)}
                  >
                    <div
                      class="chan-avatar"
                      class:private={ch.visibility === 'private'}
                      style="--chan-hue: {channelHue(ch.channel_id)}"
                      aria-hidden="true"
                    >
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M4 7h16M4 12h10M4 17h16"/>
                      </svg>
                      {#if ch.visibility === 'private'}
                        <span class="lock-dot">
                          <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="2.5" y="5.5" width="7" height="5" rx="1"/>
                            <path d="M4 5.5V4a2 2 0 014 0v1.5"/>
                          </svg>
                        </span>
                      {/if}
                    </div>
                    <span class="chan-identity">
                      <span class="chan-name"><bdi dir="auto">{ch.name}</bdi></span>
                      <span class="chan-sub">
                        {#if ch.successor_id}
                          {m.channels_transferred_badge()}
                        {:else if ch.topic}
                          <bdi dir="auto">{ch.topic}</bdi>
                        {:else}
                          {ch.visibility === 'private' ? m.channels_private_badge() : m.channels_public_badge()}
                        {/if}
                      </span>
                    </span>
                    {#if ch.in_room && ch.member_count > 0 && ch.unread === 0}
                      <span class="chan-count" title={m.channels_members()}>{ch.member_count}</span>
                    {/if}
                    {#if ch.in_room && ch.unread > 0}
                      <span class="unread" class:silenced={$mutedChannels.includes(ch.channel_id)}>{ch.unread}</span>
                    {/if}
                  </button>
                  {#if ch.in_room}
                    <button
                      type="button"
                      class="ghost chan-door"
                      disabled={joiningIds.includes(ch.channel_id)}
                      onclick={() => requestLeave(ch.channel_id)}
                    >{m.channels_leave()}</button>
                  {:else}
                    <button
                      type="button"
                      class="req-accept chan-door"
                      disabled={joiningIds.includes(ch.channel_id) || needsUsername}
                      onclick={() => joinCard(ch)}
                    >{m.channels_join()}</button>
                  {/if}
                </div>
              {/each}
            {/if}
          </div>
        </aside>

        <section class="conversation-pane" class:hidden-when-list={!selected}>
          {#if !selected}
            <div class="empty-state compact">
              <div class="empty-icon">
                <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M8 14h32v22H8z"/>
                  <path d="M8 14l16 10 16-10"/>
                </svg>
              </div>
              <p class="empty-title">{m.channels_select_title()}</p>
              <p class="empty-sub">{m.channels_no_selection()}</p>
            </div>
          {:else}
            <header class="conv-header">
              <button class="back-btn" onclick={clearSelection} aria-label={m.common_back()}>
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M10 3L5 8l5 5"/>
                </svg>
              </button>
              <div
                class="chan-avatar sm"
                class:private={selected.visibility === 'private'}
                style="--chan-hue: {channelHue(selected.channel_id)}"
                aria-hidden="true"
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M4 7h16M4 12h10M4 17h16"/>
                </svg>
              </div>
              <div class="conv-heading">
                <h3><bdi dir="auto">{selected.name}</bdi></h3>
                {#if selected.topic.trim()}
                  <p class="topic"><bdi dir="auto">{selected.topic}</bdi></p>
                {:else}
                  <p class="topic">{selected.visibility === 'private' ? m.channels_private_badge() : m.channels_public_badge()}</p>
                {/if}
              </div>
              <div class="conv-actions">
                <span class="enc-lock" title={m.chat_encrypted_title()} aria-label={m.chat_encrypted_aria()}>
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <rect x="3.5" y="7" width="9" height="6.5" rx="1.5"/>
                    <path d="M5.5 7V5.5a2.5 2.5 0 0 1 5 0V7"/>
                  </svg>
                </span>
                {#if selected.is_owner}
                  <button
                    class="icon-btn"
                    class:on={roomInfoOpen}
                    onclick={() => (roomInfoOpen = !roomInfoOpen)}
                    title={m.channels_edit_moderation()}
                    aria-pressed={roomInfoOpen}
                    aria-label={m.channels_edit_moderation()}
                  >
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                      <circle cx="8" cy="8" r="2.2"/>
                      <path d="M8 2.5v1.5M8 12v1.5M2.5 8h1.5M12 8h1.5M4.1 4.1l1.1 1.1M10.8 10.8l1.1 1.1M4.1 11.9l1.1-1.1M10.8 5.2l1.1-1.1"/>
                    </svg>
                  </button>
                {/if}
                <button
                  class="icon-btn"
                  class:on={membersOpen}
                  onclick={() => (membersOpen = !membersOpen)}
                  title={membersOpen ? m.channels_hide_members() : m.channels_show_members()}
                  aria-pressed={membersOpen}
                  aria-label={membersOpen ? m.channels_hide_members() : m.channels_show_members()}
                >
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="6" cy="6" r="2.2"/>
                    <path d="M2 13c0-2.2 1.8-4 4-4s4 1.8 4 4"/>
                    <circle cx="11.5" cy="6.5" r="1.7"/>
                    <path d="M11.2 13c.9-.7 1.5-1.8 1.5-3"/>
                  </svg>
                </button>
                <button
                  class="icon-btn"
                  class:on={searchOpen}
                  onclick={() => {
                    searchOpen = !searchOpen;
                    if (!searchOpen) resetSearch();
                  }}
                  title={m.channels_search_room()}
                  aria-pressed={searchOpen}
                  aria-label={m.channels_search_room()}
                >
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="8.5" cy="8.5" r="5.5"/><line x1="12.5" y1="12.5" x2="17" y2="17"/>
                  </svg>
                </button>
                <button
                  class="icon-btn"
                  class:on={selectedMuted}
                  onclick={() => toggleChannelMute(selectedChannelId)}
                  title={selectedMuted ? m.channels_unmute() : m.channels_mute()}
                  aria-pressed={selectedMuted}
                  aria-label={selectedMuted ? m.channels_unmute() : m.channels_mute()}
                >
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M6.2 12.2a1.9 1.9 0 003.6 0"/>
                    <path d="M3.6 12.2h8.8l-1.1-1.6V7.4a3.3 3.3 0 00-6.6 0v3.2z"/>
                    {#if selectedMuted}
                      <path d="M2.6 2.6l10.8 10.8"/>
                    {/if}
                  </svg>
                </button>
                <button class="ghost" onclick={handleCopyInvite}>{m.channels_invite()}</button>
                <button class="ghost danger" onclick={() => requestLeave(selected.channel_id)}>{m.channels_leave()}</button>
                {#if selected.is_owner}
                  <button class="ghost danger" onclick={() => (deleteOpen = true)}>{m.channels_delete()}</button>
                {/if}
              </div>
            </header>
            {#if selected.welcome.trim()}
              <div class="welcome-banner" role="note">
                <p><bdi dir="auto">{selected.welcome}</bdi></p>
              </div>
            {/if}
            {#if selected.successor_id}
              <div class="successor-banner" role="status">
                <span>{m.channels_successor_banner()}</span>
                <button class="ghost" onclick={openSuccessor}>{m.channels_open_successor()}</button>
              </div>
            {:else if transferPendingTo}
              <div class="successor-banner" role="status">
                <span>{m.channels_transfer_started()}</span>
              </div>
            {/if}
            {#if selected.key_behind}
              <div class="key-behind-banner" role="status">
                <strong>{m.channels_key_behind()}</strong>
                <span>{m.channels_key_behind_body()}</span>
              </div>
            {/if}
            {#if !selected.is_owner && !selected.successor_id && nomineeNotice}
              <div class="successor-banner" role="status">
                <span>{nomineeNotice}</span>
                {#if selected.can_claim}
                  <button class="ghost" disabled={claiming} onclick={handleClaim}>
                    {claiming ? m.common_loading() : m.channels_claim_ownership()}
                  </button>
                {/if}
              </div>
            {/if}
            {#if selected.is_owner && roomInfoOpen}
              <form
                class="moderation-form"
                onsubmit={(e) => {
                  e.preventDefault();
                  handleSaveModeration();
                }}
              >
                <p class="mod-label">{m.channels_edit_moderation()}</p>
                <input
                  bind:value={editTopic}
                  maxlength="64"
                  placeholder={m.channels_topic_placeholder()}
                  aria-label={m.channels_topic_placeholder()}
                  oninput={() => (editingModeration = true)}
                />
                <textarea
                  bind:value={editWelcome}
                  maxlength="512"
                  rows="2"
                  placeholder={m.channels_welcome_placeholder()}
                  aria-label={m.channels_welcome_placeholder()}
                  oninput={() => (editingModeration = true)}
                ></textarea>
                <button type="submit" disabled={moderationBusy}>{m.channels_save_moderation()}</button>
              </form>
              <div class="succession-form">
                <p class="mod-label" id="succession-label">{m.channels_succession()}</p>
                <select
                  aria-labelledby="succession-label"
                  disabled={moderationBusy}
                  value={selected.successor_nominee}
                  onchange={(e) => handleNominee(e.currentTarget.value)}
                >
                  <option value="">{m.channels_succession_none()}</option>
                  {#each sortedMembers as mem (mem.member_pubkey)}
                    {#if !mem.is_self && !mem.banned}
                      <option value={mem.member_pubkey}>
                        {mem.nickname || shortId(mem.member_pubkey)}
                      </option>
                    {/if}
                  {/each}
                </select>
                {#if selected.successor_nominee}
                  <select
                    aria-label={m.channels_succession()}
                    disabled={moderationBusy}
                    value={String(selected.claim_after_days)}
                    onchange={(e) =>
                      handleNominee(selected.successor_nominee, Number(e.currentTarget.value))}
                  >
                    {#each CLAIM_WINDOWS as days (days)}
                      <option value={String(days)}>{m.channels_succession_days({ days })}</option>
                    {/each}
                  </select>
                {/if}
              </div>
            {/if}
            {#if roomTransfers.length > 0}
              <!-- Polite, not assertive: an arriving offer is worth announcing
                   but must not cut across whatever is being read. -->
              <div class="xfer-panel" aria-live="polite">
                {#each roomTransfers as t (t.xfer_id)}
                  {@const pct = t.size > 0 ? Math.min(100, Math.round((t.transferred / t.size) * 100)) : 0}
                  {@const busy = respondingTo.includes(t.xfer_id)}
                  <div class="xfer-row" class:awaiting={t.status === 'awaiting'}>
                    <div class="xfer-text">
                      <span class="xfer-name"><bdi dir="auto">{t.name}</bdi></span>
                      <span class="xfer-meta">
                        {formatBytes(t.size)} &middot; {transferLabel(t)}
                      </span>
                      {#if t.status === 'active' || t.status === 'accepted'}
                        <div
                          class="xfer-progress"
                          role="progressbar"
                          aria-label={t.name}
                          aria-valuemin="0"
                          aria-valuemax={t.size}
                          aria-valuenow={Math.min(t.transferred, t.size)}
                          aria-valuetext="{pct}%"
                        >
                          <div class="xfer-progress-fill" style="width: {pct}%"></div>
                        </div>
                      {/if}
                    </div>
                    <div class="xfer-actions">
                      {#if t.status === 'awaiting'}
                        <button
                          type="button"
                          disabled={busy}
                          onclick={() => handleRespondTransfer(t.xfer_id, true)}
                        >
                          {m.channels_xfer_accept()}
                        </button>
                        <button
                          type="button"
                          class="ghost"
                          disabled={busy}
                          onclick={() => handleRespondTransfer(t.xfer_id, false)}
                        >
                          {m.channels_xfer_decline()}
                        </button>
                      {:else if t.status === 'offered' || t.status === 'accepted' || t.status === 'active'}
                        <button
                          type="button"
                          class="ghost danger"
                          disabled={busy}
                          onclick={() => handleCancelTransfer(t.xfer_id)}
                        >
                          {m.common_cancel()}
                        </button>
                      {/if}
                    </div>
                  </div>
                {/each}
              </div>
            {/if}
            {#if searchOpen}
              <form
                class="room-search"
                onsubmit={(e) => {
                  e.preventDefault();
                  runSearch();
                }}
              >
                <input
                  bind:value={searchQuery}
                  placeholder={m.channels_search_placeholder()}
                  aria-label={m.channels_search_room()}
                  use:autoFocus
                  onkeydown={(e) => {
                    if (e.key !== 'Escape') return;
                    e.preventDefault();
                    e.stopPropagation();
                    resetSearch();
                  }}
                />
                <button type="submit" disabled={!searchQuery.trim() || searching}>
                  {searching ? m.common_loading() : m.common_search()}
                </button>
              </form>
              {#if searchRan}
                <div class="search-results">
                  {#if searchHits.length === 0}
                    <p class="muted list-empty">{m.channels_search_none()}</p>
                  {:else}
                    {#each searchHits as hit (hit.id)}
                      <div class="search-hit">
                        <span class="search-hit-who">
                          <bdi dir="auto">{memberNames[hit.sender_pubkey] || shortId(hit.sender_pubkey)}</bdi>
                        </span>
                        <span class="search-hit-text"><bdi dir="auto">{hit.message}</bdi></span>
                        <span class="search-hit-when">{formatRelativeTime(hit.timestamp, presenceNow)}</span>
                      </div>
                    {/each}
                  {/if}
                </div>
              {/if}
            {/if}
            <div class="transcript">
              <ChatConversation
                friendHash=""
                friendName={selectedName}
                channelId={selectedChannelId}
                hideHeader
                youAreBanned={selectedBanned}
                youAreKeyBehind={selectedKeyBehind}
                memberNames={memberNames}
                ignoredSenders={$ignoredMembers}
                mentionName={$appSettings?.channel_username || $appSettings?.nickname || ''}
              />
            </div>
          {/if}
        </section>

        {#if selected && membersOpen}
          <button
            class="members-backdrop"
            type="button"
            onclick={() => (membersOpen = false)}
            aria-label={m.channels_hide_members()}
          ></button>
          <aside class="members-pane">
            <div class="members-header">
              <span class="members-label">{m.channels_members()}</span>
              <span class="members-count">{members.length || selected.member_count}</span>
              <button
                class="icon-btn members-close"
                onclick={() => (membersOpen = false)}
                aria-label={m.channels_hide_members()}
              >
                <IconX size={14} />
              </button>
            </div>
            {#if members.length === 0}
              <p class="muted list-empty">{m.common_loading()}</p>
            {:else}
              <ul class="member-list">
                {#each sortedMembers as mem (mem.member_pubkey)}
                  {@const present = mem.is_self || isPresent(mem, presenceNow)}
                  <li
                    class:banned={mem.banned}
                    oncontextmenu={memberHasMenu(mem) ? openMemberMenu : undefined}
                  >
                    <div class="member-avatar" class:present>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <circle cx="12" cy="8" r="4"/>
                        <path d="M4 21c0-4.418 3.582-8 8-8s8 3.582 8 8"/>
                      </svg>
                      {#if present}
                        <span class="present-dot" role="img" title={m.channels_member_online()} aria-label={m.channels_member_online()}></span>
                      {/if}
                    </div>
                    <div class="member-identity">
                      <span class="member-name">
                        <bdi dir="auto">{mem.is_self ? m.channels_you() : mem.nickname || shortId(mem.member_pubkey)}</bdi>
                      </span>
                      <span class="member-badges">
                        {#if isChannelOwner(mem)}
                          <span class="badge owner">{m.channels_owner()}</span>
                        {:else if mem.moderator}
                          <span class="badge">{m.channels_moderator_badge()}</span>
                        {/if}
                        {#if mem.banned}
                          <span class="badge banned">{m.channels_banned_badge()}</span>
                        {/if}
                        {#if $ignoredMembers.includes(mem.member_pubkey.toLowerCase())}
                          <span class="badge">{m.channels_ignored_badge()}</span>
                        {/if}
                        {#if !present && mem.last_seen > 0}
                          <span class="member-seen">
                            {m.channels_member_last_seen({
                              when: formatRelativeTime(mem.last_seen, presenceNow),
                            })}
                          </span>
                        {/if}
                      </span>
                    </div>
                    {#if memberHasMenu(mem)}
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
                            disabled={sendingTo.includes(mem.member_pubkey) || mem.banned}
                            onclick={(e) => { closeCardMenu(e.currentTarget); handleSendFile(mem); }}
                          >{m.channels_send_file()}</button>
                          <button
                            type="button"
                            role="menuitem"
                            disabled={addingFriend.includes(mem.member_pubkey)}
                            onclick={(e) => { closeCardMenu(e.currentTarget); handleAddFriend(mem); }}
                          >{m.channels_add_friend()}</button>
                          <button
                            type="button"
                            role="menuitem"
                            onclick={(e) => { closeCardMenu(e.currentTarget); handleCopyMemberId(mem); }}
                          >{m.channels_copy_member_id()}</button>
                          <button
                            type="button"
                            role="menuitem"
                            onclick={(e) => { closeCardMenu(e.currentTarget); toggleMemberIgnore(mem.member_pubkey); }}
                          >{$ignoredMembers.includes(mem.member_pubkey.toLowerCase())
                            ? m.channels_unignore()
                            : m.channels_ignore()}</button>
                          {#if canModerate}
                            {#if mem.banned}
                              <button
                                type="button"
                                role="menuitem"
                                disabled={moderationBusy}
                                onclick={(e) => { closeCardMenu(e.currentTarget); handleUnban(mem.member_pubkey); }}
                              >{m.channels_unban()}</button>
                            {:else if !isChannelOwner(mem)}
                              <button
                                type="button"
                                role="menuitem"
                                class="menu-item-danger"
                                disabled={moderationBusy}
                                onclick={(e) => { closeCardMenu(e.currentTarget); handleBan(mem.member_pubkey); }}
                              >{m.channels_ban()}</button>
                            {/if}
                          {/if}
                          {#if selected.is_owner && !mem.banned && !selected.successor_id}
                            {#if mem.moderator}
                              <button
                                type="button"
                                role="menuitem"
                                disabled={moderationBusy}
                                onclick={(e) => { closeCardMenu(e.currentTarget); handleRemoveModerator(mem.member_pubkey); }}
                              >{m.channels_remove_moderator()}</button>
                            {:else}
                              <button
                                type="button"
                                role="menuitem"
                                disabled={moderationBusy}
                                onclick={(e) => { closeCardMenu(e.currentTarget); handleAddModerator(mem.member_pubkey); }}
                              >{m.channels_add_moderator()}</button>
                            {/if}
                            {#if !transferPendingTo || transferPendingTo === mem.member_pubkey}
                              <button
                                type="button"
                                role="menuitem"
                                class="menu-item-danger"
                                disabled={moderationBusy}
                                onclick={(e) => { closeCardMenu(e.currentTarget); requestTransfer(mem); }}
                              >{m.channels_transfer_ownership()}</button>
                            {/if}
                          {/if}
                        </div>
                      </details>
                    {/if}
                  </li>
                {/each}
              </ul>
            {/if}
          </aside>
        {/if}
      </div>
    {/if}
  {/if}
</div>

<ConfirmDialog
  bind:open={leaveOpen}
  title={m.channels_leave_confirm()}
  message={m.channels_leave_confirm_body({ name: leaveTargetName })}
  confirmLabel={m.channels_leave()}
  danger
  onconfirm={handleLeave}
/>

<ConfirmDialog
  bind:open={transferOpen}
  title={m.channels_transfer_confirm()}
  message={m.channels_transfer_confirm_body({
    name: transferTarget?.nickname || shortId(transferTarget?.member_pubkey ?? ''),
  })}
  confirmLabel={m.channels_transfer_ownership()}
  danger
  onconfirm={handleTransfer}
/>

<ConfirmDialog
  bind:open={deleteOpen}
  title={m.channels_delete_confirm()}
  message={m.channels_delete_confirm_body({ name: selected?.name ?? '' })}
  confirmLabel={m.channels_delete()}
  danger
  onconfirm={handleDeleteOwned}
/>

<style>
  .page-header {
    flex-wrap: wrap;
    gap: 10px;
  }

  .header-title {
    display: flex;
    align-items: baseline;
    gap: 10px;
    min-width: 0;
  }

  .header-count {
    font-size: 12px;
    font-weight: 500;
    color: var(--text-muted);
    white-space: nowrap;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    justify-content: flex-end;
  }

  .header-actions .ghost.active-toggle {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .add-btn.primary {
    padding: 6px 14px;
    border: 1px solid var(--accent);
    border-radius: var(--radius-md);
    background: var(--accent);
    color: var(--on-accent);
    cursor: pointer;
    font-family: inherit;
    font-weight: 600;
    font-size: 12px;
  }

  .add-btn.primary:hover:not(:disabled) {
    background: var(--accent-hover);
    border-color: var(--accent-hover);
  }

  .add-btn.primary.danger {
    background: transparent;
    color: var(--danger);
    border-color: color-mix(in srgb, var(--danger) 45%, var(--border));
  }

  .add-btn.primary.danger:hover:not(:disabled) {
    background: color-mix(in srgb, var(--danger) 12%, transparent);
    color: var(--danger);
    border-color: var(--danger);
  }

  .channels-page {
    flex: 1;
    min-height: 0;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    padding: 12px 16px 16px;
    gap: 10px;
    --scroll-cover: var(--bg-primary);
  }

  .how-panel {
    flex-shrink: 0;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 0 16px;
  }

  .how-title {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-primary);
    cursor: pointer;
    padding: 10px 0;
    list-style: none;
  }

  .how-title::-webkit-details-marker { display: none; }

  .how-title::after {
    content: '';
    width: 6px;
    height: 6px;
    border-right: 1.5px solid var(--text-muted);
    border-bottom: 1.5px solid var(--text-muted);
    transform: rotate(-45deg);
    transition: transform var(--transition-fast);
    flex-shrink: 0;
  }

  details[open] > .how-title::after {
    transform: rotate(45deg);
  }

  .how-lede,
  .how-limits {
    margin: 0 0 10px;
    font-size: 12px;
    line-height: 1.5;
    color: var(--text-muted);
    max-width: 52rem;
  }

  .how-lede { color: var(--text-secondary); }

  .banner {
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 12px;
    border-radius: var(--radius-md);
    background: var(--bg-surface);
    border: 1px solid var(--border);
  }

  .error-banner {
    border-color: color-mix(in srgb, var(--danger) 45%, var(--border));
    color: var(--badge-danger-text);
    background: color-mix(in srgb, var(--danger) 9%, var(--bg-secondary));
  }

  .add-form {
    flex-shrink: 0;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 14px 16px;
  }

  .form-title {
    margin: 0 0 10px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    color: var(--text-secondary);
  }

  .add-form-inner {
    display: flex;
    gap: 10px;
    align-items: center;
    flex-wrap: wrap;
  }

  .add-form-inner input,
  .moderation-form input,
  .moderation-form textarea {
    flex: 1;
    min-width: 180px;
  }

  .join-input {
    font-family: var(--font-mono);
    letter-spacing: 0.2px;
  }

  .requests-section {
    flex-shrink: 0;
    background: var(--bg-surface);
    border: 1px solid var(--accent-dim);
    border-radius: var(--radius-lg);
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
    border-radius: var(--radius-pill);
    background: var(--accent);
    color: var(--on-accent);
    font-size: 10px;
    font-weight: 700;
    padding: 0 5px;
  }

  .requests-dismiss { margin-left: auto; }

  .request-card {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 16px;
  }

  .request-card + .request-card {
    border-top: 1px solid color-mix(in srgb, var(--border) 50%, transparent);
  }

  .request-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .request-name {
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .request-hash {
    font-size: 11px;
    color: var(--text-muted);
  }

  .req-accept {
    font-size: 12px;
    font-weight: 600;
  }

  .workspace {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: minmax(220px, 280px) minmax(0, 1fr);
    gap: 10px;
    position: relative;
  }

  .workspace.members-open {
    grid-template-columns: minmax(200px, 260px) minmax(0, 1fr) minmax(200px, 240px);
  }

  .list-pane,
  .conversation-pane,
  .members-pane {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    min-height: 0;
    min-width: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .list-pane { padding: 8px; }

  .search-wrap {
    position: relative;
    margin: 2px 4px 8px;
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
    border-radius: var(--radius-pill);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 12px;
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
    color: var(--text-secondary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0;
  }

  .search-clear:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .list-scroll {
    flex: 1;
    min-height: 0;
    overflow: auto;
  }

  .list-empty { padding: 16px 10px; text-align: center; font-size: 12px; }

  .form-hint {
    margin: 0 0 10px;
    font-size: 13px;
    color: var(--text-secondary);
  }

  .chan-row {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    text-align: left;
    padding: 4px 6px 4px 4px;
    border: 0;
    background: transparent;
    color: inherit;
    border-radius: var(--radius-md);
  }

  .chan-row-main {
    display: flex;
    align-items: center;
    gap: 10px;
    flex: 1;
    min-width: 0;
    text-align: left;
    padding: 6px 4px;
    border: 0;
    background: transparent;
    color: inherit;
    cursor: pointer;
  }

  .chan-door {
    flex-shrink: 0;
    font-size: 12px;
  }

  .chan-row:hover { background: var(--bg-hover); }

  .chan-row.active {
    background: color-mix(in srgb, var(--accent) 12%, var(--bg-hover));
  }

  .chan-avatar {
    width: 34px;
    height: 34px;
    flex-shrink: 0;
    border-radius: 50%;
    background: hsl(var(--chan-hue, 210) 38% 42%);
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
  }

  .chan-avatar svg { width: 16px; height: 16px; }
  .chan-avatar.sm { width: 28px; height: 28px; }
  .chan-avatar.sm svg { width: 13px; height: 13px; }
  .chan-avatar.private {
    box-shadow: inset 0 0 0 1px color-mix(in srgb, #000 20%, transparent);
  }

  .lock-dot {
    position: absolute;
    bottom: -1px;
    right: -1px;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: var(--bg-secondary);
    color: var(--text-secondary);
    display: grid;
    place-items: center;
    box-shadow: 0 0 0 1px var(--border);
  }

  .lock-dot svg { width: 8px; height: 8px; }

  .chan-identity {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .chan-name {
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .chan-sub {
    font-size: 11px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .unread {
    min-width: 18px;
    height: 18px;
    border-radius: 9px;
    background: var(--accent);
    color: var(--on-accent);
    font-size: 11px;
    font-weight: 700;
    display: grid;
    place-items: center;
    padding: 0 5px;
    flex-shrink: 0;
  }

  .chan-count {
    font-size: 11px;
    color: var(--text-muted);
    flex-shrink: 0;
    font-variant-numeric: tabular-nums;
  }

  /* A silenced room still counts its unread, it just stops shouting about it. */
  .unread.silenced {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
  }

  .conversation-pane { background: var(--bg-primary); }

  .conv-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .conv-heading { flex: 1; min-width: 0; }
  .conv-heading h3 {
    margin: 0;
    font-size: 14px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .topic {
    margin: 2px 0 0;
    font-size: 12px;
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .conv-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
    flex-wrap: wrap;
    margin-left: auto;
  }

  .enc-lock {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 26px;
    height: 26px;
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    color: var(--accent);
    flex-shrink: 0;
  }

  .enc-lock svg { width: 12px; height: 12px; }

  .back-btn { display: none; }

  .icon-btn {
    width: 30px;
    height: 30px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0;
  }

  .icon-btn:hover,
  .icon-btn.on {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .icon-btn svg { width: 16px; height: 16px; }

  .successor-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 8px 14px;
    border-bottom: 1px solid color-mix(in srgb, var(--warning) 40%, var(--border));
    background: color-mix(in srgb, var(--warning) 12%, transparent);
    font-size: 13px;
    color: var(--badge-warning-text);
    flex-shrink: 0;
  }

  .key-behind-banner {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px 14px;
    border-bottom: 1px solid color-mix(in srgb, var(--danger) 40%, var(--border));
    background: color-mix(in srgb, var(--danger) 10%, transparent);
    font-size: 12px;
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .key-behind-banner strong {
    font-size: 13px;
    color: var(--text-primary);
  }

  .xfer-panel {
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
  }

  .xfer-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 14px;
  }

  .xfer-row + .xfer-row {
    border-top: 1px solid var(--border);
  }

  /* An offer waiting on the user is the only row that needs to be noticed;
     the rest are progress the user already knows about. */
  .xfer-row.awaiting {
    background: color-mix(in srgb, var(--accent) 10%, transparent);
  }

  .xfer-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
    flex: 1;
  }

  .xfer-name {
    font-size: 13px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .xfer-meta {
    font-size: 11px;
    color: var(--text-muted);
  }

  .xfer-progress {
    height: 3px;
    margin-top: 4px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--text-muted) 30%, transparent);
    overflow: hidden;
  }

  .xfer-progress-fill {
    height: 100%;
    background: var(--accent);
    transition: width var(--transition-fast) linear;
  }

  .xfer-actions {
    display: flex;
    gap: 6px;
    flex-shrink: 0;
  }

  .succession-form {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 0 14px 10px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
  }

  .welcome-banner {
    padding: 8px 14px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
    font-size: 12px;
    color: var(--text-secondary);
    line-height: 1.45;
    flex-shrink: 0;
    max-height: 4.8em;
    overflow: auto;
  }

  .welcome-banner p { margin: 0; }

  .moderation-form {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
    flex-shrink: 0;
  }

  .mod-label { margin: 0; font-size: 12px; color: var(--text-secondary); }

  .room-search {
    display: flex;
    gap: 8px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
    flex-shrink: 0;
  }

  .room-search input { flex: 1; min-width: 0; }

  /* Capped rather than flexible: the transcript below stays the main event, and
     a long hit list scrolls within its own band. */
  .search-results {
    flex-shrink: 0;
    max-height: 33%;
    overflow: auto;
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
  }

  .search-hit {
    display: flex;
    align-items: baseline;
    gap: 8px;
    padding: 7px 14px;
    font-size: 12px;
  }

  .search-hit + .search-hit {
    border-top: 1px solid color-mix(in srgb, var(--border) 50%, transparent);
  }

  .search-hit-who {
    font-weight: 600;
    color: var(--text-secondary);
    flex-shrink: 0;
    max-width: 30%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .search-hit-text {
    flex: 1;
    min-width: 0;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .search-hit-when {
    color: var(--text-muted);
    flex-shrink: 0;
    font-size: 11px;
  }

  .transcript {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
  }

  .members-backdrop {
    display: none;
  }

  .members-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .members-label {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
  }

  .members-count {
    font-size: 11px;
    color: var(--text-muted);
  }

  .members-close { margin-left: auto; }

  .member-list {
    list-style: none;
    margin: 0;
    padding: 6px;
    overflow: auto;
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .member-list li {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 8px;
    border-radius: var(--radius-md);
  }

  .member-list li.banned { opacity: 0.65; }

  .member-avatar {
    width: 28px;
    height: 28px;
    flex-shrink: 0;
    border-radius: 50%;
    background: var(--accent-dim);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .member-avatar svg { width: 14px; height: 14px; }

  .member-avatar {
    position: relative;
  }

  .member-avatar.present {
    color: var(--success);
    background: color-mix(in srgb, var(--success) 16%, transparent);
  }

  .present-dot {
    position: absolute;
    right: -1px;
    bottom: -1px;
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--success);
    box-shadow: 0 0 0 2px var(--bg-secondary);
  }

  .member-seen {
    font-size: 10px;
    color: var(--text-muted);
    white-space: nowrap;
  }

  .member-identity {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .member-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 13px;
  }

  .member-badges { display: flex; flex-wrap: wrap; gap: 4px; }

  .badge {
    font-size: 10px;
    font-weight: 600;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-pill);
    padding: 0 6px;
    line-height: 16px;
    text-transform: none;
    letter-spacing: 0;
    background: transparent;
  }

  .badge.owner {
    color: var(--badge-accent-text);
    border-color: color-mix(in srgb, var(--accent) 40%, var(--border));
  }

  .badge.banned {
    color: var(--badge-danger-text);
    border-color: color-mix(in srgb, var(--danger) 45%, var(--border));
  }

  .card-more { position: relative; flex-shrink: 0; }

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
  }

  .card-more > summary::-webkit-details-marker { display: none; }

  .card-more > summary:hover,
  .card-more[open] > summary {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .card-more-menu {
    position: absolute;
    right: 0;
    top: calc(100% + 4px);
    z-index: 20;
    min-width: 180px;
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

  .card-more-menu button:hover:not(:disabled) { background: var(--bg-hover); }
  .card-more-menu button:disabled { opacity: 0.4; cursor: not-allowed; }
  .menu-item-danger:hover:not(:disabled) { color: var(--danger); }

  .empty-state {
    text-align: center;
    padding: 56px 24px;
    color: var(--text-muted);
    margin: auto;
  }

  .empty-state.compact { padding: 40px 24px; }

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

  .empty-icon svg { width: 32px; height: 32px; }

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

  .empty-actions {
    display: flex;
    gap: 8px;
    justify-content: center;
    margin-top: 16px;
    flex-wrap: wrap;
  }

  .empty-action {
    font-size: 12px;
    padding: 7px 20px;
  }

  .muted { color: var(--text-secondary); }
  .danger { color: var(--danger); }

  @media (max-width: 1200px) {
    .workspace.members-open {
      grid-template-columns: minmax(200px, 240px) minmax(0, 1fr);
    }

    .members-backdrop {
      display: block;
      position: absolute;
      inset: 0;
      z-index: 4;
      border: 0;
      padding: 0;
      background: color-mix(in srgb, #000 28%, transparent);
      cursor: pointer;
    }

    .members-pane {
      position: absolute;
      top: 0;
      right: 0;
      bottom: 0;
      width: min(280px, 90%);
      z-index: 5;
      box-shadow: var(--shadow-panel-left);
    }
  }

  @media (max-width: 980px) {
    .workspace,
    .workspace.members-open {
      grid-template-columns: 1fr;
    }

    .back-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 30px;
      height: 30px;
      border: none;
      border-radius: var(--radius-sm);
      background: transparent;
      color: var(--text-primary);
      cursor: pointer;
      padding: 0;
      flex-shrink: 0;
    }

    .back-btn:hover { background: var(--bg-hover); }
    .back-btn svg { width: 16px; height: 16px; }

    .list-pane.hidden-when-chat { display: none; }
    .conversation-pane.hidden-when-list { display: none; }

    .conv-actions .ghost { padding: 5px 8px; font-size: 12px; }
  }

  @media (max-width: 760px) {
    .channels-page { padding: 8px 10px 12px; }
  }
</style>
