<script lang="ts">
  import { onDestroy, tick, untrack } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { getChatMessages, sendChatMessage, markMessagesRead, isChatLocked, type ChatMessage } from '$lib/api/friends';
  import {
    deleteChannelMessage,
    getChannelMessages,
    markChannelMessagesRead,
    sendChannelMessage,
    type ChannelMessageInfo,
  } from '$lib/api/channels';
  import { activeChatHash, clearUnread, onlineFriends } from '$lib/stores/friends';
  import { clearChannelUnread } from '$lib/stores/channels';
  import {
    editChannelMessage,
    getChannelReactions,
    setChannelMessageReaction,
    REACTION_NONE,
    REACTION_UP,
    REACTION_DOWN,
    REACTION_HEART,
    type ChannelReactionInfo,
  } from '$lib/api/channels';
  import { appSettings } from '$lib/stores/settings';
  import { getDraft, setDraft, clearDraft } from '$lib/stores/chatTabs';
  import * as m from '$lib/paraglide/messages';
  import { codedErrorOf, translateError } from '$lib/i18n';
  import {
    insertMention,
    isAppVisible,
    linkifyMessage,
    mentionTokenAt,
    shortPubkey,
  } from '$lib/utils';
  import { openExternalUrl } from '$lib/api/settings';
  import { toast } from '$lib/stores/toast';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import IconX from '$lib/components/IconX.svelte';
  import { passiveScroll } from '$lib/actions/passiveScroll';

  // The backend rejects chat messages whose UTF-8 encoding exceeds this many
  // bytes (`peers.rs`); the textarea `maxlength` only bounds characters, so we
  // mirror the byte check here to give a clear error instead of a generic
  // "send failed" on multi-byte/emoji-heavy text.
  const MAX_MESSAGE_BYTES = 4096;
  // Upper bound on messages held in memory at once. "Load older" stops past
  // this so a very long history can't grow the array (and the rendered DOM)
  // without bound; the rest stays in the DB and on disk.
  const MAX_LOADED_MESSAGES = 2000;

  interface Props {
    friendHash: string;
    friendName: string;
    channelId?: string;
    hideHeader?: boolean;
    youAreBanned?: boolean;
    /** Private room whose content key has rotated past what this device holds. */
    youAreKeyBehind?: boolean;
    /** The room's wait between messages, or 0 when it is off or this member is
     *  exempt. Drives the composer countdown; the backend enforces it. */
    slowModeSecs?: number;
    memberNames?: Record<string, string>;
    /** Senders hidden on this device. Presentational only — their messages are
     *  still received and stored, they just aren't drawn. */
    ignoredSenders?: string[];
    /** Own display name, so a message naming us can be picked out. Empty
     *  disables the check rather than matching everything. */
    mentionName?: string;
    /** Raw handles the composer can complete after `@`. Distinct from
     *  `memberNames`, which carries display labels — "You", or a
     *  disambiguated "Ada (a1b2c3)" — that would be wrong to type into a
     *  message. */
    mentionCandidates?: string[];
    /** Stored message to scroll to and mark. A fresh object each time, so
     *  asking twice for the same message still moves the transcript. */
    focusRequest?: { id: number } | null;
    /** The message could not be reached — too far back, or no longer stored. */
    onfocusmissing?: () => void;
  }

  type ConvMessage = ChatMessage & {
    sender_pubkey?: string;
    /** Channels only: when the author last revised this line, 0 if never. */
    edited_at?: number;
    /** Channels only: the wire id other members address this line by. */
    msg_id?: string;
  };

  /**
   * Mirrors `CHANNEL_EDIT_WINDOW_SECS` in the backend, which is the only place
   * that decides anything. Duplicated here purely so the Edit affordance is not
   * offered for a line the backend would refuse.
   */
  const EDIT_WINDOW_SECS = 15 * 60;
  /**
   * Coarse clock driving the Edit affordance's expiry. Ticks once a minute rather
   * than being read inline, because reading `Date.now()` inside the render would
   * never re-evaluate and the button would linger past the window until something
   * else invalidated the view.
   */
  let editClockNow = $state(Date.now());

  let {
    friendHash,
    friendName,
    channelId = '',
    hideHeader = false,
    youAreBanned = false,
    youAreKeyBehind = false,
    slowModeSecs = 0,
    memberNames = {},
    ignoredSenders = [],
    mentionName = '',
    mentionCandidates = [],
    focusRequest = null,
    onfocusmissing,
  }: Props = $props();

  let isChannel = $derived(channelId.length > 0);
  let conversationKey = $derived(isChannel ? `ch:${channelId}` : friendHash);

  // Live verification/online indicator. After the H1 fix the
  // `ember:friend-online` event is only emitted after the peer's
  // Ed25519 proof-of-possession succeeded, so membership in
  // `onlineFriends` is a reliable "the live session with this peer
  // is PoP-verified RIGHT NOW" signal. When the friend is offline we
  // surface a warning that the message will be queued and may reach
  // a peer that hasn't been re-authenticated since this session
  // opened.
  let isOnline = $derived(
    !isChannel && friendHash ? $onlineFriends.has(friendHash.toLowerCase()) : false,
  );

  // The user can disable chat entirely in Settings; when off, the backend
  // drops inbound and refuses outbound chat, so reflect that in the UI rather
  // than letting the user type into a textarea whose sends will be rejected.
  let chatDisabled = $derived(!isChannel && $appSettings?.friend_chat_disabled === true);
  let chatLocked = $state(false);

  $effect(() => {
    let cancelled = false;
    untrack(() => {
      isChatLocked()
        .then((locked) => {
          if (!cancelled) chatLocked = locked;
        })
        .catch(() => {
          if (!cancelled) chatLocked = false;
        });
    });
    return () => {
      cancelled = true;
    };
  });

  /**
   * Hard cap on in-memory chat messages per conversation. Old messages beyond
   * this are trimmed from the front of the array; they remain in the database
   * and can be re-fetched with "Load older". Without the cap a long-running
   * session (or a friend spamming the channel) causes unbounded memory growth.
   *
   * Tied to `MAX_LOADED_MESSAGES` on purpose. When this was smaller (500) than
   * the "Load older" bound (2000), the first live message that arrived after
   * the user paged in older history sliced the array back down to the live cap
   * and silently discarded the 1000+ messages they had just loaded and
   * scrolled to. Keeping the two caps equal means a live message only trims
   * once the array actually exceeds the same bound "Load older" enforces.
   */
  const MAX_LIVE_MESSAGES = MAX_LOADED_MESSAGES;

  let messages: ConvMessage[] = $state([]);
  let inputText = $state('');
  let loading = $state(false);
  let sending = $state(false);
  let sendError: string | null = $state(null);
  let loadError: string | null = $state(null);
  // Non-blocking notice shown above the (successfully loaded) message list when
  // the live `ember:chat-message` listener couldn't be registered, so the user
  // knows new messages won't stream in until they retry.
  let liveError = $state(false);
  let messagesEnd: HTMLDivElement | undefined = $state();
  let messagesContainerEl: HTMLDivElement | undefined = $state();
  let chatInputEl: HTMLTextAreaElement | undefined = $state();
  let unlisten: UnlistenFn | null = null;
  let unlistenDelivery: UnlistenFn | null = null;
  let removingMessage = $state<number | null>(null);
  let loadGen = 0;
  let msgIdCounter = 0;
  // Delivery events can beat the IPC response that appends an optimistic
  // queued bubble. Keep their durable row IDs briefly so that response can
  // reconcile the bubble instead of leaving it permanently queued.
  const earlyDeliveredIds = new Set<number>();

  const PAGE_SIZE = 100;
  let loadingOlder = $state(false);
  let hasMoreHistory = $state(false);
  let olderError = $state(false);
  // Pagination cursor: the smallest (oldest) DB row id we've loaded. Tracked
  // separately from `messages` because live messages use negative ids and the
  // MAX_LIVE_MESSAGES trim drops oldest-first — in a busy session that can
  // evict every positive (DB) id from the array. Deriving the cursor from the
  // array (the old `messages.find(m => m.id > 0)`) then returned undefined and
  // wrongly hid "load older" even though the DB still had history.
  let oldestDbId: number | null = null;
  /**
   * Row the "new messages" divider sits above, or null when the reader was
   * already caught up.
   *
   * Decided once from the first snapshot of a conversation and then frozen:
   * `markAsRead` clears the flag in the database within moments of the load, so
   * a value recomputed after that would find nothing and the divider would
   * vanish while the reader was still looking at it. `markerResolved` is what
   * keeps a retry, or a later page of history, from asking the question again.
   */
  let unreadMarkerId = $state<number | null>(null);
  let markerResolved = false;

  function fromChannelRow(row: ChannelMessageInfo): ConvMessage {
    return {
      id: row.id,
      direction: row.direction === 'sent' ? 'sent' : 'received',
      message: row.message,
      timestamp: row.timestamp,
      read: row.read,
      delivery: 'delivered',
      sender_pubkey: row.sender_pubkey,
      edited_at: row.edited_at,
      msg_id: row.msg_id,
    };
  }

  /** Reaction tallies for this room, keyed by wire message id. */
  let reactions = $state<Record<string, ChannelReactionInfo>>({});
  /** Which message is open in the inline editor, and the text being typed. */
  let editingId = $state<number | null>(null);
  let editDraft = $state('');
  let editBusy = $state(false);
  let editError = $state<string | null>(null);
  let reactionBusy = $state<number | null>(null);
  /** Brief feedback on only the chip the user just changed. */
  let reactionPulse = $state<{
    msgId: string;
    kind: number;
    action: 'add' | 'remove';
  } | null>(null);
  let reactionPulseTimer: ReturnType<typeof setTimeout> | null = null;
  let editInputEl: HTMLTextAreaElement | undefined = $state();

  async function refreshReactions() {
    const channel = channelId;
    if (!channel) return;
    try {
      const rows = await getChannelReactions(channel);
      if (channel !== channelId) return;
      reactions = Object.fromEntries(rows.map((row) => [row.msg_id, row]));
    } catch (e) {
      // A tally that fails to load leaves the bubbles bare rather than the room
      // unreadable, so this is not worth an error banner.
      console.warn('ChatConversation: failed to load reactions', e);
    }
  }

  /**
   * Whether this line is still ours to revise.
   *
   * The same window the backend enforces, checked here only so the affordance is
   * not offered for something that would be refused. A line with no wire id (a
   * copy carried across a room handoff) is not addressable by other members at
   * all, so it cannot be edited either.
   */
  function canEdit(msg: ConvMessage): boolean {
    if (!isChannel || msg.direction !== 'sent' || msg.id <= 0) return false;
    if (!msg.msg_id || msg.msg_id.length !== 32) return false;
    return editClockNow / 1000 - msg.timestamp <= EDIT_WINDOW_SECS;
  }

  function startEdit(msg: ConvMessage) {
    editingId = msg.id;
    editDraft = msg.message;
    editError = null;
  }

  function cancelEdit() {
    editingId = null;
    editDraft = '';
    editError = null;
  }

  async function commitEdit(msg: ConvMessage) {
    const channel = channelId;
    const text = editDraft.trim();
    if (!channel || editBusy) return;
    if (!text || text === msg.message) {
      cancelEdit();
      return;
    }
    editBusy = true;
    editError = null;
    try {
      const updated = await editChannelMessage(channel, msg.id, text);
      if (channel === channelId) {
        messages = messages.map((m) =>
          m.id === msg.id
            ? { ...m, message: updated.message, edited_at: updated.edited_at }
            : m,
        );
        cancelEdit();
      }
    } catch (e: unknown) {
      if (channel === channelId) editError = translateError(e, m.channels_edit_failed());
    } finally {
      editBusy = false;
    }
  }

  function onEditKeydown(e: KeyboardEvent, msg: ConvMessage) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      cancelEdit();
      return;
    }
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void commitEdit(msg);
    }
  }

  /** Toggle our reaction: pressing the one we already hold withdraws it. */
  async function toggleReaction(msg: ConvMessage, reaction: number) {
    const channel = channelId;
    if (!channel || !msg.msg_id || reactionBusy !== null) return;
    if (msg.direction === 'sent') return;
    const current = reactions[msg.msg_id]?.mine ?? REACTION_NONE;
    const next = current === reaction ? REACTION_NONE : reaction;
    reactionBusy = msg.id;
    reactionPulse = {
      msgId: msg.msg_id,
      kind: reaction,
      action: next === REACTION_NONE ? 'remove' : 'add',
    };
    if (reactionPulseTimer) clearTimeout(reactionPulseTimer);
    reactionPulseTimer = setTimeout(() => {
      reactionPulse = null;
      reactionPulseTimer = null;
    }, 560);
    try {
      await setChannelMessageReaction(channel, msg.id, next);
      if (channel === channelId) await refreshReactions();
    } catch (e: unknown) {
      if (channel === channelId) sendError = translateError(e, m.error_operation_failed());
    } finally {
      reactionBusy = null;
    }
  }

  function senderLabel(pubkey?: string): string {
    if (!pubkey) return '';
    return memberNames[pubkey] || shortPubkey(pubkey);
  }

  $effect(() => {
    if (!chatInputEl || youAreBanned || youAreKeyBehind) return;
    const raf = requestAnimationFrame(() => chatInputEl?.focus());
    return () => cancelAnimationFrame(raf);
  });

  // Select the text once, when the editor opens on a new message.
  //
  // Keyed on `editingId` alone and reading nothing else: focusing from anything
  // that re-runs as the user types would put the caret back and re-select after
  // every keystroke, which is what an inline attachment on the textarea did.
  $effect(() => {
    if (editingId === null) return;
    const el = editInputEl;
    if (!el) return;
    untrack(() => {
      el.focus();
      el.select();
    });
  });

  // Retires the Edit affordance as the window closes. A minute's granularity on a
  // fifteen-minute window is close enough, and the backend refuses anything this
  // clock lets through late.
  $effect(() => {
    const timer = setInterval(() => (editClockNow = Date.now()), 60_000);
    return () => clearInterval(timer);
  });

  // Edits and reactions from other members. Both arrive as a nudge rather than a
  // payload to patch in: the edit event carries the new text (it is one line), but
  // reactions are a tally the backend already counted, so re-reading is both
  // simpler and correct when several land at once.
  $effect(() => {
    if (!isChannel) return;
    const room = channelId;
    let disposed = false;
    const unlisteners: UnlistenFn[] = [];
    (async () => {
      try {
        const offEdit = await listen<{
          channel_id: string;
          id: number;
          msg_id: string;
          message: string;
          edited_at: number;
        }>('ember:channel-message-edited', (event) => {
          if (event.payload.channel_id !== room) return;
          messages = messages.map((msg) =>
            msg.msg_id === event.payload.msg_id || msg.id === event.payload.id
              ? { ...msg, message: event.payload.message, edited_at: event.payload.edited_at }
              : msg,
          );
          // A line we were editing has been revised under us — most likely from
          // this account on another device. Drop the stale draft rather than let
          // it overwrite the newer text.
          if (editingId !== null && editingId === event.payload.id) cancelEdit();
        });
        if (disposed) offEdit();
        else unlisteners.push(offEdit);

        const offReactions = await listen<{ channel_id: string }>(
          'ember:channel-reactions',
          (event) => {
            if (event.payload.channel_id !== room) return;
            void refreshReactions();
          },
        );
        if (disposed) offReactions();
        else unlisteners.push(offReactions);
      } catch (e) {
        console.warn('ChatConversation: failed to register edit/reaction listeners', e);
      }
    })();
    return () => {
      disposed = true;
      for (const off of unlisteners) off();
    };
  });

  // Whenever the active conversation changes (mounted with new
  // friendHash/channelId, or parent reuses this component for a different
  // tab), tear down the previous listener + state and re-fetch.
  $effect(() => {
    // Capture keys into locals so the cleanup closure below can save the
    // draft against the conversation we're LEAVING. Reading the props
    // directly inside cleanup would resolve to the new tab's id because
    // Svelte runs cleanup AFTER the rune has settled to its new value.
    const key = conversationKey;
    const channel = channelId;
    const friend = friendHash;
    if (key) {
      sendError = null;
      sending = false;
      inputText = getDraft(key);
      if (channel) {
        clearChannelUnread(channel);
      } else {
        activeChatHash.set(friend);
        clearUnread(friend);
      }
      const gen = ++loadGen;
      if (unlisten) { unlisten(); unlisten = null; }
      if (unlistenDelivery) { unlistenDelivery(); unlistenDelivery = null; }
      messages = [];
      earlyDeliveredIds.clear();
      loadError = null;
      liveError = false;
      loading = true;
      loadingOlder = false;
      hasMoreHistory = false;
      oldestDbId = null;
      unreadMarkerId = null;
      markerResolved = false;
      // Scroll position belongs to the conversation being left, not the one
      // being opened: `loadMessages` lands this one on its own unread marker
      // or at the bottom.
      scrolledAway = false;
      missedWhileAway = false;
      // Reactions and any half-finished edit belong to the room being left.
      reactions = {};
      cancelEdit();
      if (channel) void refreshReactions();
      (async () => {
        try {
          const listenerOk = await setupListener(gen, friend, channel);
          if (gen !== loadGen) return;
          await loadMessages(gen, friend, channel);
          if (gen === loadGen) liveError = !listenerOk;
        } finally {
          if (gen === loadGen) loading = false;
        }
        // After the load, not alongside it. Both are IPC round trips, so
        // running them together raced: clearing `read` in the database first
        // meant the snapshot came back with nothing unread and the divider had
        // nothing to sit above. The badge is still cleared synchronously above,
        // so this ordering costs the user nothing.
        if (gen === loadGen) void markAsRead();
      })();
    }
    return () => {
      loadGen++;
      if (unlisten) { unlisten(); unlisten = null; }
      if (unlistenDelivery) { unlistenDelivery(); unlistenDelivery = null; }
      if (key) setDraft(key, inputText);
      if (!channel) activeChatHash.set(null);
    };
  });

  async function setupListener(gen: number, hash: string, channel: string): Promise<boolean> {
    if (gen !== loadGen) return false;
    if (unlisten) { unlisten(); unlisten = null; }
    if (unlistenDelivery) { unlistenDelivery(); unlistenDelivery = null; }
    if (channel) {
      let fn: UnlistenFn;
      try {
        fn = await listen<{
          id: number;
          channel_id: string;
          sender_pubkey: string;
          direction: string;
          message: string;
          timestamp: number;
          msg_id?: string;
        }>('ember:channel-message', (event) => {
          if (gen !== loadGen) return;
          if (event.payload.channel_id !== channel) return;
          if (messages.some((mm) => mm.id === event.payload.id)) return;
          const wasPinned = isPinnedToBottom();
          const next: ConvMessage[] = [...messages, {
            id: event.payload.id,
            direction: event.payload.direction === 'sent' ? 'sent' : 'received',
            message: event.payload.message,
            timestamp: event.payload.timestamp,
            read: true,
            delivery: 'delivered',
            sender_pubkey: event.payload.sender_pubkey,
            edited_at: 0,
            msg_id: event.payload.msg_id,
          }];
          messages = next.length > MAX_LIVE_MESSAGES
            ? next.slice(next.length - MAX_LIVE_MESSAGES)
            : next;
          if (event.payload.direction === 'sent' || wasPinned) {
            scrollToBottom();
          }
          noteMissedMessage(wasPinned, event.payload.direction);
          if (event.payload.direction === 'received' && isAppVisible()) {
            markAsRead();
          }
        });
      } catch (e) {
        console.warn('ChatConversation: failed to register channel listener', e);
        return false;
      }
      if (gen !== loadGen) { fn(); return false; }
      unlisten = fn;
      return true;
    }
    let fn: UnlistenFn;
    try {
      fn = await listen<{ user_hash: string; message: string; direction: string; timestamp: number }>('ember:chat-message', (event) => {
        if (gen !== loadGen) return;
        if ((event.payload.user_hash || '').toLowerCase() !== (hash || '').toLowerCase()) return;
          // Dedup duplicate backend emits: inbound chat can be delivered on
          // both the download and upload event loops for the same logical
          // message. Compare the content tuple against the recent tail (a
          // small window avoids wrongly collapsing two genuinely-identical
          // messages sent seconds apart).
          // Inbound only. Two upload-listener routes can surface the same peer
          // message, which is what this guard is for — but the outbound echo has
          // a single emit site, so deduping it can only ever collapse two
          // genuinely distinct messages that share a whole-second timestamp.
          // `handleSend` deliberately renders nothing for a delivered message
          // and relies on this echo, so a collapsed one is lost until reload.
          const sig = `${event.payload.timestamp}|${event.payload.direction}|${event.payload.message}`;
          const isDuplicate =
            event.payload.direction === 'received' &&
            messages
              .slice(-5)
              .some((mm) => `${mm.timestamp}|${mm.direction}|${mm.message}` === sig);
          if (isDuplicate) return;
          const wasPinned = isPinnedToBottom();
          const next = [...messages, {
            id: --msgIdCounter,
            direction: event.payload.direction as 'sent' | 'received',
            message: event.payload.message,
            timestamp: event.payload.timestamp,
            read: true,
            delivery: 'delivered' as const,
          }];
          messages = next.length > MAX_LIVE_MESSAGES
            ? next.slice(next.length - MAX_LIVE_MESSAGES)
            : next;
          if (event.payload.direction === 'sent' || wasPinned) {
            scrollToBottom();
          }
          noteMissedMessage(wasPinned, event.payload.direction);
          // Only acknowledge what the user can actually see. A mounted
          // conversation in a minimized window would otherwise mark the
          // message read and suppress its badge, losing it entirely.
          if (event.payload.direction === 'received' && isAppVisible()) {
            markAsRead();
          }
      });
    } catch (e) {
      console.warn('ChatConversation: failed to register chat listener', e);
      return false;
    }
    if (gen !== loadGen) { fn(); return false; }
    unlisten = fn;

    // Delivery notices carry the durable outbox row ID. Buffer an early notice
    // until its optimistic queued bubble has been appended.
    try {
      const deliveryFn = await listen<{ user_hash: string; id: number; delivery: string }>(
        'ember:chat-delivery',
        (event) => {
          if (gen !== loadGen) return;
          if ((event.payload.user_hash || '').toLowerCase() !== (hash || '').toLowerCase()) return;
          // `failed` arrives when the backend's age sweep abandons a queued
          // message; without it the bubble reads "queued" for the whole
          // session even though the row on disk has already given up.
          const delivery = event.payload.delivery;
          if (delivery !== 'delivered' && delivery !== 'failed') return;
          const at = messages.findIndex((mm) => mm.id === event.payload.id);
          if (at === -1) {
            // The early-arrival buffer is a delivered-only reconciliation; an
            // abandoned row is already `failed` in the DB, so a later load
            // renders it correctly without help.
            if (delivery === 'delivered') earlyDeliveredIds.add(event.payload.id);
            return;
          }
          const next = [...messages];
          next[at] = { ...next[at], delivery };
          messages = next;
        },
      );
      if (gen !== loadGen) { deliveryFn(); return true; }
      unlistenDelivery = deliveryFn;
    } catch (e) {
      // Non-fatal: bubbles stay marked queued until the pane is reopened.
      console.warn('ChatConversation: failed to register delivery listener', e);
    }
    return true;
  }

  async function loadMessages(gen: number, hash: string, channel: string) {
    loading = true;
    loadError = null;
    try {
      const rows: ConvMessage[] = channel
        ? (await getChannelMessages(channel, PAGE_SIZE)).map(fromChannelRow)
        : await getChatMessages(hash, PAGE_SIZE);
      if (gen !== loadGen) return;
      hasMoreHistory = rows.length >= PAGE_SIZE;
      const snapshot = rows.reverse();
      // snapshot is ascending (oldest first); record the oldest loaded id.
      if (snapshot.length > 0) oldestDbId = snapshot[0].id;
      if (messages.length === 0) {
        messages = snapshot;
      } else {
        // Durable queued bubbles use their database row IDs. Prefer that
        // identity over a content/timestamp signature so a retry snapshot can
        // replace a stale queued bubble with the row's current delivery state.
        const snapshotById = new Map(snapshot.map((row) => [row.id, row]));
        const existingPositiveIds = new Set(
          messages.filter((message) => message.id > 0).map((message) => message.id),
        );
        const reconciledLive = messages.map(
          (message) => (message.id > 0 ? snapshotById.get(message.id) ?? message : message),
        );
        const liveSig = new Set(
          reconciledLive
            .filter((message) => message.id < 0)
            .map((message) => `${message.timestamp}|${message.direction}|${message.message}`),
        );
        const filteredSnapshot = snapshot.filter(
          (message) =>
            !existingPositiveIds.has(message.id)
            && !liveSig.has(`${message.timestamp}|${message.direction}|${message.message}`),
        );
        messages = [...filteredSnapshot, ...reconciledLive];
      }
      const earlyDeliveredInSnapshot = new Set(
        snapshot
          .filter((row) => earlyDeliveredIds.has(row.id))
          .map((row) => row.id),
      );
      if (earlyDeliveredInSnapshot.size > 0) {
        messages = messages.map((message) =>
          earlyDeliveredInSnapshot.has(message.id) && message.delivery === 'queued'
            ? { ...message, delivery: 'delivered' as const }
            : message,
        );
        for (const id of earlyDeliveredInSnapshot) earlyDeliveredIds.delete(id);
      }
      // Where the reader left off, taken from this first snapshot and then left
      // alone. `markAsRead` runs moments later and clears the flag in the
      // database, so anything recomputed after that would find nothing — the
      // marker has to be a decision made once, not a derived value.
      if (unreadMarkerId === null && !markerResolved) {
        markerResolved = true;
        // Skipping ignored senders, because the divider is drawn from the same
        // list the transcript renders. Landing it on a line that is filtered out
        // meant no divider at all, and `scrollToUnreadMarker` fell back to the
        // bottom — so a reader whose first unread line came from someone they
        // ignore lost the marker entirely.
        const firstUnread = messages.find(
          (message) =>
            message.direction === 'received' &&
            !message.read &&
            (!message.sender_pubkey ||
              !ignoredSenders.includes(message.sender_pubkey.toLowerCase())),
        );
        unreadMarkerId = firstUnread?.id ?? null;
      }
      if (unreadMarkerId !== null) scrollToUnreadMarker();
      else scrollToBottom();
    } catch (e: unknown) {
      if (gen !== loadGen) return;
      if (messages.length === 0) {
        loadError = translateError(e, m.chat_failed_to_load());
      }
    } finally {
      if (gen === loadGen) loading = false;
    }
  }

  async function loadOlderMessages() {
    if (loadingOlder || !hasMoreHistory || !conversationKey) return;
    const hash = friendHash;
    const channel = channelId;
    // Bound in-memory history. The rest stays in the DB; stopping here keeps
    // both the array and the rendered DOM from growing without limit on a very
    // long conversation.
    if (messages.length >= MAX_LOADED_MESSAGES) {
      hasMoreHistory = false;
      return;
    }
    loadingOlder = true;
    olderError = false;
    const gen = loadGen;
    try {
      const cursor = oldestDbId;
      if (cursor === null) {
        hasMoreHistory = false;
        return;
      }
      const rows: ConvMessage[] = channel
        ? (await getChannelMessages(channel, PAGE_SIZE, cursor)).map(fromChannelRow)
        : await getChatMessages(hash, PAGE_SIZE, cursor);
      if (gen !== loadGen) return;
      if (rows.length === 0) {
        hasMoreHistory = false;
        return;
      }
      const olderPage = rows.reverse();
      // Advance the cursor to the new oldest loaded id (ascending order).
      if (olderPage.length > 0) oldestDbId = olderPage[0].id;
      const el = messagesContainerEl;
      const prevScrollHeight = el?.scrollHeight ?? 0;
      const prevScrollTop = el?.scrollTop ?? 0;
      messages = [...olderPage, ...messages];
      // More history exists only if this page was full AND we're still under
      // the in-memory cap; otherwise hide the button.
      hasMoreHistory = rows.length >= PAGE_SIZE && messages.length < MAX_LOADED_MESSAGES;
      requestAnimationFrame(() => {
        if (!messagesContainerEl) return;
        const delta = messagesContainerEl.scrollHeight - prevScrollHeight;
        messagesContainerEl.scrollTop = prevScrollTop + delta;
      });
    } catch (e) {
      if (gen !== loadGen) return;
      // Surface the failure so the user knows the button did nothing and can
      // retry, instead of it silently re-enabling.
      console.warn('loadOlderMessages failed:', e);
      olderError = true;
    } finally {
      if (gen === loadGen) loadingOlder = false;
    }
  }

  async function retryLoad() {
    if (!conversationKey) return;
    const hash = friendHash;
    const channel = channelId;
    const gen = ++loadGen;
    if (unlisten) { unlisten(); unlisten = null; }
    if (unlistenDelivery) { unlistenDelivery(); unlistenDelivery = null; }
    liveError = false;
    const listenerOk = await setupListener(gen, hash, channel);
    if (gen !== loadGen) return;
    await loadMessages(gen, hash, channel);
    if (gen === loadGen) liveError = !listenerOk;
  }

  async function markAsRead() {
    const channel = channelId;
    const h = friendHash;
    if (channel) {
      try {
        await markChannelMessagesRead(channel);
        clearChannelUnread(channel);
      } catch (e) {
        console.warn('markChannelMessagesRead failed:', e);
      }
      return;
    }
    if (!h) return;
    try {
      await markMessagesRead(h);
      clearUnread(h);
    } catch (e) {
      console.warn('markMessagesRead failed:', e);
    }
  }

  // Messages that arrived while the window was hidden were deliberately left
  // unread; clear them once the user actually comes back to the conversation.
  $effect(() => {
    if (typeof document === 'undefined') return;
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') void markAsRead();
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  });

  function scrollToBottom() {
    requestAnimationFrame(() => {
      messagesEnd?.scrollIntoView({ behavior: 'smooth' });
    });
  }

  /**
   * Land on the first message the reader has not seen rather than at the
   * bottom.
   *
   * Re-entering a busy room used to drop them at the newest line with nothing
   * saying where they had got to, so catching up meant scrolling up and
   * guessing. Falls back to the bottom if the marker row is not on screen —
   * which it will not be if the divider sits above what the first page loaded.
   */
  function scrollToUnreadMarker() {
    requestAnimationFrame(() => {
      const el = messagesContainerEl?.querySelector<HTMLElement>('.conv-unread-divider');
      if (el) el.scrollIntoView({ block: 'center' });
      else messagesEnd?.scrollIntoView();
    });
  }

  function isPinnedToBottom(): boolean {
    const el = messagesContainerEl;
    if (!el) return true;
    return el.scrollHeight - (el.scrollTop + el.clientHeight) < 80;
  }

  /**
   * Whether the reader has scrolled away from the newest message, and whether
   * anything arrived while they were up there.
   *
   * Auto-scroll is deliberately suppressed when unpinned — yanking the view
   * down mid-sentence is worse than missing a line — but that left no way back
   * and no sign that a line had been missed at all. `missedWhileAway` only
   * tracks messages from someone else: our own send always scrolls, so it can
   * never be the thing left unseen.
   */
  let scrolledAway = $state(false);
  let missedWhileAway = $state(false);

  function onMessagesScroll() {
    const pinned = isPinnedToBottom();
    scrolledAway = !pinned;
    if (pinned) missedWhileAway = false;
  }

  function jumpToLatest() {
    missedWhileAway = false;
    scrolledAway = false;
    scrollToBottom();
  }

  /** Note an incoming message the reader is not positioned to see. */
  function noteMissedMessage(wasPinned: boolean, direction: string) {
    if (!wasPinned && direction === 'received') missedWhileAway = true;
  }

  /** The message a search hit pointed at, marked briefly so the eye can find
   *  it after the jump. */
  let focusedId = $state<number | null>(null);
  let focusing = false;
  /** A hit picked while an earlier jump is still paging. Held rather than
   *  dropped, and run after: two jumps interleaved would each see the other's
   *  `loadOlderMessages` as "no progress" and wrongly report the message gone. */
  let queuedFocus: number | null = null;
  let focusTimer: ReturnType<typeof setTimeout> | null = null;
  const FOCUS_MARK_MS = 2600;

  /**
   * Bring a stored message into view, paging history back until it is loaded.
   *
   * History only pages backwards, so the way to reach an old message is to walk
   * the same cursor "Load older" uses until it comes into range. That keeps the
   * transcript one continuous run rather than stranding the user in a window
   * with no path back to the live tail. Local SQLite, so the round trips are
   * cheap; the in-memory cap still bounds how far back it can go.
   */
  async function focusMessage(id: number) {
    if (id <= 0) return;
    if (focusing) {
      queuedFocus = id;
      return;
    }
    const gen = loadGen;
    focusing = true;
    try {
      while (!messages.some((message) => message.id === id)) {
        const before = oldestDbId;
        // Already paged past it: the row is not in this conversation's stored
        // history any more (removed locally, or trimmed by the live cap).
        if (before === null || before <= id) break;
        if (!hasMoreHistory || messages.length >= MAX_LOADED_MESSAGES) break;
        await loadOlderMessages();
        if (gen !== loadGen) return;
        // No progress means the page came back empty or the cap kicked in;
        // without this the loop would spin on an unreachable id.
        if (oldestDbId === before) break;
      }
      // Loaded is not the same as drawn: an ignored sender's message stays in
      // `messages` but never reaches the DOM, and scrolling to it would do
      // nothing at all. Report it rather than appear to ignore the click.
      if (!visibleMessages.some((message) => message.id === id)) {
        onfocusmissing?.();
        return;
      }
      focusedId = id;
      await tick();
      // After the render, and after the scroll anchoring `loadOlderMessages`
      // queues for itself — otherwise that restore lands on top of this jump.
      requestAnimationFrame(() => {
        messagesContainerEl
          ?.querySelector(`[data-msg-id="${id}"]`)
          ?.scrollIntoView({ block: 'center', behavior: 'smooth' });
      });
      if (focusTimer) clearTimeout(focusTimer);
      focusTimer = setTimeout(() => {
        focusedId = null;
        focusTimer = null;
      }, FOCUS_MARK_MS);
    } finally {
      focusing = false;
      const next = queuedFocus;
      queuedFocus = null;
      if (next !== null && next !== id) void focusMessage(next);
    }
  }

  $effect(() => {
    const request = focusRequest;
    if (!request) return;
    // Untracked: the jump reads and writes the message array it would
    // otherwise re-subscribe to, and would re-fire on its own output.
    untrack(() => {
      void focusMessage(request.id);
    });
  });


  /**
   * Hand `text` to the friend transport and reconcile the optimistic bubble.
   *
   * Split out of [`handleSend`] so a resend takes exactly the path a first
   * attempt does. Throws on transport failure; the caller owns the error copy,
   * because the composer and a failed bubble report it in different places.
   */
  async function deliverToFriend(h: string, text: string) {
    const result = await sendChatMessage(h, text);
    // A queued send is not echoed back as an `ember:chat-message`, since
    // nothing reached the peer. Append it here so the user sees what they
    // typed, marked as waiting, instead of an apparently-vanished message.
    if (result.delivery === 'queued' && h === friendHash) {
      const durableId = result.id ?? --msgIdCounter;
      const alreadyDelivered = result.id !== null && earlyDeliveredIds.delete(result.id);
      const existing = messages.findIndex((message) => message.id === durableId);
      if (existing === -1) {
        messages = [...messages, {
          id: durableId,
          direction: 'sent' as const,
          message: text,
          timestamp: Math.floor(Date.now() / 1000),
          read: true,
          delivery: alreadyDelivered ? 'delivered' as const : 'queued' as const,
        }];
      } else if (alreadyDelivered && messages[existing].delivery === 'queued') {
        const next = [...messages];
        next[existing] = { ...next[existing], delivery: 'delivered' };
        messages = next;
      }
      scrollToBottom();
    }
  }

  /** Which failed message is being resent, so its button can show progress and
   *  a double-click cannot send twice. */
  let resendingId = $state<number | null>(null);

  /**
   * Send a message the delivery queue gave up on again.
   *
   * The failed bubble is dropped rather than revived, because each attempt is a
   * new row in the backend and reviving would leave the same text on screen
   * twice. Restored in place if the resend itself fails, so the only copy of
   * what the user wrote is never the thing we throw away.
   */
  async function resendMessage(msg: ConvMessage) {
    const h = friendHash;
    if (!h || sending || resendingId !== null) return;
    if (chatDisabled || chatLocked) return;
    const at = messages.findIndex((message) => message.id === msg.id);
    if (at === -1) return;
    const restore = messages[at];
    resendingId = msg.id;
    sendError = null;
    messages = messages.filter((message) => message.id !== msg.id);
    try {
      await deliverToFriend(h, restore.message);
    } catch (e: unknown) {
      if (h === friendHash) {
        const next = [...messages];
        next.splice(Math.min(at, next.length), 0, restore);
        messages = next;
        sendError = translateError(e, m.chat_failed_to_send());
      }
    } finally {
      resendingId = null;
    }
  }

  async function handleSend() {
    const text = inputText.trim();
    if (!text || sending || youAreBanned || youAreKeyBehind || chatDisabled || chatLocked) return;
    if (slowModeLeft > 0) return;
    // Guard on UTF-8 byte length to match the backend's limit. `maxlength`
    // only caps characters, so a message of multi-byte glyphs (emoji, CJK)
    // can be under 4096 chars yet over 4096 bytes and be rejected server-side
    // with a generic error.
    if (new TextEncoder().encode(text).length > MAX_MESSAGE_BYTES) {
      sendError = m.chat_message_too_long({ max: MAX_MESSAGE_BYTES });
      return;
    }
    const channel = channelId;
    const h = friendHash;
    const key = conversationKey;
    sending = true;
    sendError = null;
    try {
      if (channel) {
        const sent = await sendChannelMessage(channel, text);
        if (channel === channelId) {
          if (!messages.some((message) => message.id === sent.id)) {
            messages = [...messages, fromChannelRow(sent)];
          }
          inputText = '';
          scrollToBottom();
        }
        if (slowModeSecs > 0) {
          nextSendAt = Date.now() + slowModeSecs * 1000;
          slowModeNow = Date.now();
        }
        clearDraft(key);
        return;
      }
      await deliverToFriend(h, text);
      // Only clear the live editor if we're still viewing this friend — on a
      // tab switch the main $effect already stashed/restored drafts, so
      // touching inputText here would wipe the NEW conversation's draft.
      if (h === friendHash) inputText = '';
      // Drop the (now-sent) draft for the friend we actually sent to. The
      // main $effect's cleanup may have re-stashed it during a tab switch, so
      // clear it explicitly; `clearDraft` is a no-op when there's no entry.
      clearDraft(h);
    } catch (e: unknown) {
      if (channel) {
        // The backend carries the seconds still owed in the error's context, so
        // a refusal starts the same countdown a successful send would — which
        // covers the cases this side cannot predict, like another device of
        // ours having posted, or a clock that disagrees.
        const coded = codedErrorOf(e);
        if (coded?.code === 'channels_slow_mode') {
          const remaining = Number(coded.context);
          if (Number.isFinite(remaining) && remaining > 0) {
            nextSendAt = Date.now() + remaining * 1000;
            slowModeNow = Date.now();
          }
        }
        if (channel === channelId) sendError = translateError(e, m.chat_failed_to_send());
      } else if (h === friendHash) {
        sendError = translateError(e, m.chat_failed_to_send());
      }
    } finally {
      // `sending` is the editor's state, not tied to a friend — always release
      // it so the (possibly newly-active) conversation's input is usable.
      sending = false;
    }
  }

  /** Forget one message on this device only. The protocol has no redaction, so
   *  every other member keeps their copy — the label says so rather than
   *  implying a delete that cannot happen. */
  async function handleRemoveMessage(id: number) {
    const channel = channelId;
    if (!channel || id <= 0 || removingMessage !== null) return;
    removingMessage = id;
    try {
      await deleteChannelMessage(channel, id);
      if (channel === channelId) {
        messages = messages.filter((msg) => msg.id !== id);
      }
    } catch (e: unknown) {
      if (channel === channelId) {
        sendError = translateError(e, m.error_operation_failed());
      }
    } finally {
      removingMessage = null;
    }
  }

  /**
   * Completing `@` in the composer.
   *
   * A channel handle is 2–12 ASCII alphanumerics — no spaces, no punctuation
   * (`sanitize_channel_username`) — so the token under the caret is
   * unambiguous and the inserted text needs no quoting. `@` has to be at a
   * word boundary, or an email address would open the list on every keystroke.
   *
   * Nothing here changes what a mention *means*: highlighting already matches
   * a bare handle at a word boundary, and `@` is one, so `@Ada` lights up for
   * Ada with no protocol change. This is only about being able to write it
   * without knowing how somebody spells their name.
   */
  const MENTION_SUGGESTION_MAX = 6;

  let mentionStart = $state(-1);
  let mentionQuery = $state('');
  let mentionIndex = $state(0);
  let mentionDismissed = $state(false);

  let mentionMatches = $derived.by(() => {
    if (mentionStart < 0 || mentionDismissed) return [];
    const query = mentionQuery.toLowerCase();
    return mentionCandidates
      .filter((name) => name.toLowerCase().startsWith(query))
      .slice(0, MENTION_SUGGESTION_MAX);
  });
  let mentionOpen = $derived(mentionMatches.length > 0);

  /** Re-read the token under the caret. Cheap enough to run on every keystroke
   *  and caret move, which is what keeps the list honest after an arrow key or
   *  a click into the middle of the text. */
  function refreshMentionToken() {
    if (!isChannel || !chatInputEl || mentionCandidates.length === 0) {
      mentionStart = -1;
      return;
    }
    const caret = chatInputEl.selectionStart ?? 0;
    // Only when there is no selection: with a range selected there is no one
    // place an insertion would belong.
    if ((chatInputEl.selectionEnd ?? caret) !== caret) {
      mentionStart = -1;
      return;
    }
    const token = mentionTokenAt(inputText, caret);
    if (!token) {
      mentionStart = -1;
      mentionQuery = '';
      mentionDismissed = false;
      return;
    }
    const start = token.start;
    if (start !== mentionStart) {
      // A different `@` than the one we were completing, so a previous Escape
      // does not carry over to it.
      mentionDismissed = false;
      mentionIndex = 0;
    }
    mentionStart = start;
    mentionQuery = token.query;
    if (mentionIndex >= MENTION_SUGGESTION_MAX) mentionIndex = 0;
  }

  function applyMention(name: string) {
    if (!chatInputEl || mentionStart < 0) return;
    const caret = chatInputEl.selectionStart ?? inputText.length;
    const next = insertMention(inputText, mentionStart, caret, name);
    inputText = next.text;
    const nextCaret = next.caret;
    mentionStart = -1;
    mentionQuery = '';
    mentionIndex = 0;
    // After the value has been written back to the element, or the caret jumps
    // to the end.
    tick().then(() => {
      chatInputEl?.focus();
      chatInputEl?.setSelectionRange(nextCaret, nextCaret);
    });
  }

  function handleKeydown(e: KeyboardEvent) {
    // Ahead of Enter-to-send: while the list is open, Enter picks a name.
    if (mentionOpen) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        mentionIndex = (mentionIndex + 1) % mentionMatches.length;
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        mentionIndex = (mentionIndex - 1 + mentionMatches.length) % mentionMatches.length;
        return;
      }
      if (e.key === 'Enter' || e.key === 'Tab') {
        e.preventDefault();
        applyMention(mentionMatches[Math.min(mentionIndex, mentionMatches.length - 1)]);
        return;
      }
      if (e.key === 'Escape') {
        // Only the list, not the page. Without stopping it here the room's own
        // Escape handler would close the members pane underneath.
        e.preventDefault();
        e.stopPropagation();
        mentionDismissed = true;
        return;
      }
    }
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  function startOfDay(ts: number): number {
    const d = new Date(ts * 1000);
    d.setHours(0, 0, 0, 0);
    return d.getTime();
  }

  /** `Today`, `Yesterday`, or a written date for anything older. */
  function dayLabel(ts: number): string {
    const today = startOfDay(Math.floor(Date.now() / 1000));
    const day = startOfDay(ts);
    if (day === today) return m.chat_day_today();
    // Step back a calendar day instead of subtracting 24h: on the day after a
    // DST change consecutive local midnights are 23 or 25 hours apart.
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    if (day === yesterday.getTime()) return m.chat_day_yesterday();
    const d = new Date(ts * 1000);
    const sameYear = d.getFullYear() === new Date().getFullYear();
    return d.toLocaleDateString(undefined, {
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      ...(sameYear ? {} : { year: 'numeric' }),
    });
  }

  function sameChannelAuthor(a: ConvMessage, b: ConvMessage): boolean {
    if (a.direction !== b.direction) return false;
    if (!isChannel) return true;
    return (a.sender_pubkey ?? '') === (b.sender_pubkey ?? '');
  }

  /**
   * Messages annotated for display: where a new day starts, and where a run of
   * consecutive messages from the same author begins and ends.
   *
   * Runs are what make a conversation readable — one block per turn instead of
   * a uniform ladder of identically-spaced bubbles, each repeating a timestamp
   * that almost always matches the one above it.
   */
  /** Drawn messages. Hiding an ignored sender here rather than at ingest keeps
   *  the decision reversible: un-ignoring brings their history straight back. */
  let visibleMessages = $derived(
    ignoredSenders.length === 0
      ? messages
      : messages.filter(
          (msg) => !msg.sender_pubkey || !ignoredSenders.includes(msg.sender_pubkey.toLowerCase()),
        ),
  );

  /**
   * Whole-word, case-insensitive match on our own display name. Word bounds
   * stop a short nickname lighting up every message that merely contains it.
   *
   * Compiled once per name rather than once per bubble. It used to be built
   * inside a function the template called for every rendered row, so a room
   * scrolled back to the 2000-message cap recompiled the same pattern two
   * thousand times on every reactive update.
   */
  let mentionPattern = $derived.by(() => {
    const name = mentionName.trim();
    if (!name || !isChannel) return null;
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    try {
      return new RegExp(`(^|[^\\p{L}\\p{N}])${escaped}([^\\p{L}\\p{N}]|$)`, 'iu');
    } catch {
      return null;
    }
  });

  let rows = $derived.by(() => {
    const messages = visibleMessages;
    // Day boundaries once per message, rather than recomputed for every
    // neighbour comparison. `null` means the row carries no usable date — a
    // zero timestamp is "unknown", and must not produce a 1970 separator.
    const days = messages.map((msg) => (msg.timestamp > 0 ? startOfDay(msg.timestamp) : null));
    return messages.map((msg, i) => {
      const day = days[i];
      const hasNext = i + 1 < messages.length;
      const newDay = day !== null && (i === 0 || days[i - 1] !== day);
      const sameAuthorAsPrev = i > 0 && sameChannelAuthor(messages[i - 1], msg);
      const sameAuthorAsNext = hasNext && sameChannelAuthor(messages[i + 1], msg);
      // An undated row neither opens nor closes a day, so it stays with its run.
      const sameDayAsNext =
        hasNext && (day === null || days[i + 1] === null || days[i + 1] === day);
      return {
        msg,
        daySeparator: newDay ? dayLabel(msg.timestamp) : null,
        startsRun: newDay || !sameAuthorAsPrev,
        endsRun: !sameAuthorAsNext || !sameDayAsNext,
        // Both computed once per message here rather than per render in the
        // template, which is where they used to be.
        mentionsMe: msg.direction === 'received' && (mentionPattern?.test(msg.message) ?? false),
        segments: linkifyMessage(msg.message),
      };
    });
  });

  /**
   * A link the user has clicked but not yet confirmed.
   *
   * Confirmed rather than opened straight away because in a room the author of
   * a link is whoever is in the room. The backend refuses anything but plain
   * `http`/`https` without credentials or bidi overrides, so this is not the
   * security boundary — it is so leaving the app for somewhere a stranger
   * chose is always a decision the user made on purpose.
   */
  /**
   * When this member may next post, in epoch ms, or 0 when they may now.
   *
   * Slow mode used to surface only as an error toast *after* a send was
   * refused, which reads as the app dropping the message. The wait is knowable
   * ahead of time, so the composer says so and the send button holds still
   * until it passes. The backend is still the thing that enforces it — this is
   * only the part that tells the user.
   */
  let nextSendAt = $state(0);
  let slowModeNow = $state(Date.now());

  $effect(() => {
    if (nextSendAt <= 0) return;
    // Only ticks while there is something to count down, so an idle room does
    // no per-second work.
    const timer = setInterval(() => {
      slowModeNow = Date.now();
      if (slowModeNow >= nextSendAt) nextSendAt = 0;
    }, 250);
    return () => clearInterval(timer);
  });

  /** Whole seconds left, rounded up so it never reads 0 while still waiting. */
  let slowModeLeft = $derived(
    nextSendAt > slowModeNow ? Math.ceil((nextSendAt - slowModeNow) / 1000) : 0,
  );

  /** The room changed, so a wait owed to the previous one does not follow. */
  $effect(() => {
    conversationKey;
    untrack(() => {
      nextSendAt = 0;
    });
  });

  let pendingLink = $state('');
  let linkConfirmOpen = $state(false);

  function askOpenLink(href: string) {
    pendingLink = href;
    linkConfirmOpen = true;
  }

  async function openPendingLink() {
    const url = pendingLink;
    pendingLink = '';
    if (!url) return;
    try {
      await openExternalUrl(url);
    } catch (e) {
      toast(translateError(e));
    }
  }

  function formatTime(ts: number): string {
    if (!ts) return '';
    const d = new Date(ts * 1000);
    const now = new Date();
    const sameDay = d.toDateString() === now.toDateString();
    if (sameDay) {
      return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    }
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' +
      d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }

  onDestroy(() => {
    if (unlisten) { unlisten(); unlisten = null; }
    if (unlistenDelivery) { unlistenDelivery(); unlistenDelivery = null; }
    if (focusTimer) { clearTimeout(focusTimer); focusTimer = null; }
    if (reactionPulseTimer) { clearTimeout(reactionPulseTimer); reactionPulseTimer = null; }
  });
</script>

{#snippet messageTimestamp(msg: ConvMessage, pending: boolean, failed: boolean)}
  <div class="bubble-time">
    {formatTime(msg.timestamp)}
    {#if (msg.edited_at ?? 0) > 0}
      <span class="bubble-edited" title={m.channels_edited_at({ time: formatTime(msg.edited_at ?? 0) })}>
        {m.channels_edited()}
      </span>
    {/if}
    {#if pending}
      <span class="bubble-delivery" title={m.chat_delivery_queued_title()}>{m.chat_delivery_queued()}</span>
    {:else if failed}
      <span class="bubble-delivery failed" title={m.chat_delivery_failed_title()}>{m.chat_delivery_failed()}</span>
      {#if !isChannel}
        <button
          class="bubble-resend"
          type="button"
          disabled={resendingId !== null || sending || chatDisabled || chatLocked}
          onclick={() => resendMessage(msg)}
          title={m.chat_resend()}
          aria-label={m.chat_resend()}
        >
          {resendingId === msg.id ? m.chat_loading_short() : m.chat_resend()}
        </button>
      {/if}
    {/if}
  </div>
{/snippet}

<div class="conversation" class:channel={isChannel}>
  {#if !hideHeader}
  <div class="conv-header">
    <div class="conv-header-info">
      <div class="conv-avatar" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.418 3.582-8 8-8s8 3.582 8 8"/>
        </svg>
      </div>
      <span class="conv-name" title={friendName || friendHash}>
        <span class="sr-only">{m.chat_friend_with_prefix()} </span><bdi dir="auto">{friendName || friendHash.slice(0, 8) + '\u2026'}</bdi>
      </span>
      {#if isOnline}
        <span class="conv-status online" title={m.chat_online_title()} aria-label={m.chat_online_aria()}>
          <svg viewBox="0 0 16 16" fill="currentColor" stroke="none" aria-hidden="true">
            <circle cx="8" cy="8" r="4"/>
          </svg>
          <span>{m.chat_online_label()}</span>
        </span>
      {:else}
        <span class="conv-status offline" title={m.chat_offline_title()} aria-label={m.chat_offline_aria()}>
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="8" cy="8" r="6"/>
            <path d="M8 5v3M8 11v.01"/>
          </svg>
          <span>{m.chat_offline_label()}</span>
        </span>
      {/if}
      <!--
        Icon only. Its label read "Encrypted in transit + locally", which in a
        ~420px dock consumed more width than the friend's name and squeezed it
        to an ellipsis on every conversation. A padlock is understood without
        being spelled out, and the full explanation is still one hover away in
        the tooltip and unchanged for screen readers.
      -->
      <span class="conv-status encrypted icon-only" title={m.chat_encrypted_title()} aria-label={m.chat_encrypted_aria()}>
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <rect x="3.5" y="7" width="9" height="6.5" rx="1.5"/>
          <path d="M5.5 7V5.5a2.5 2.5 0 0 1 5 0V7"/>
        </svg>
      </span>
    </div>
  </div>
  {/if}

  <div class="conv-messages" bind:this={messagesContainerEl} use:passiveScroll={onMessagesScroll}>
    {#if liveError && !loading && !loadError}
      <div class="conv-live-error" role="status">
        <span>{m.chat_live_unavailable()}</span>
        <button class="conv-load-retry" onclick={retryLoad} type="button">{m.common_retry()}</button>
      </div>
    {/if}
    {#if loading}
      <div class="conv-loading">{m.chat_loading_messages()}</div>
    {:else if loadError}
      <div class="conv-load-error" role="alert">
        <span>{m.chat_load_error({ error: loadError })}</span>
        <button class="conv-load-retry" onclick={retryLoad} type="button">{m.common_retry()}</button>
      </div>
    {:else if messages.length === 0}
      <div class="conv-empty">{chatLocked ? m.friends_chat_locked_title() : chatDisabled ? m.chat_empty_disabled() : isChannel ? m.channels_empty_chat() : m.chat_say_hello()}</div>
    {:else}
      {#if hasMoreHistory}
        <div class="conv-load-older">
          <button
            class="conv-load-older-btn"
            type="button"
            onclick={loadOlderMessages}
            disabled={loadingOlder}
            aria-label={m.chat_load_older()}
          >
            {loadingOlder ? m.chat_loading_short() : (olderError ? m.common_retry() : m.chat_load_older())}
          </button>
          {#if olderError}
            <span class="conv-load-older-error" role="alert">{m.chat_load_older_failed()}</span>
          {/if}
        </div>
      {/if}
      {#each rows as row (row.msg.id)}
        {#if row.daySeparator}
          <div class="conv-day">{row.daySeparator}</div>
        {/if}
        {#if row.msg.id === unreadMarkerId}
          <div class="conv-unread-divider" role="separator" aria-label={m.chat_unread_divider()}>
            <span>{m.chat_unread_divider()}</span>
          </div>
        {/if}
        {@const pending = row.msg.direction === 'sent' && row.msg.delivery === 'queued'}
        {@const failed = row.msg.direction === 'sent' && row.msg.delivery === 'failed'}
        <div
          class="conv-msg"
          class:sent={row.msg.direction === 'sent'}
          class:received={row.msg.direction === 'received'}
          class:starts-run={row.startsRun}
        >
        {#if isChannel}
          <div class="bubble-who">
            <bdi dir="auto">{senderLabel(row.msg.sender_pubkey)}</bdi>
          </div>
        {/if}
        <div
          class="conv-bubble"
          data-msg-id={row.msg.id}
          class:sent={row.msg.direction === 'sent'}
          class:received={row.msg.direction === 'received'}
          class:starts-run={row.startsRun}
          class:ends-run={row.endsRun}
          class:focused={row.msg.id === focusedId}
          class:mentions-me={row.mentionsMe}
        >
          <!--
            `<bdi>` isolates the message body from the surrounding UI's
            text direction so a peer-supplied RTL/LTR override character
            can't reorder neighbouring elements (a known "Trojan Source"-
            style spoofing class). The text is still rendered exactly as
            written; only its bidi influence is scoped to this element.
          -->
          <!--
            Segments, never markup: each run is a text node, so nothing a
            member types can become HTML. A link is a `<button>` rather than an
            `<a href>` so the webview itself has no navigable target — the only
            way out is the confirmed, scheme-checked backend opener.
          -->
          {#if editingId === row.msg.id}
            <!-- Edited in place rather than in the composer at the bottom: that
                 one owns per-conversation drafts, the slow-mode countdown and
                 mention autocomplete, all of which would fight an edit. -->
            <div class="bubble-edit">
              <textarea
                class="bubble-edit-input"
                bind:value={editDraft}
                onkeydown={(e) => onEditKeydown(e, row.msg)}
                maxlength="4096"
                rows="2"
                disabled={editBusy}
                aria-label={m.channels_edit_message()}
                bind:this={editInputEl}
              ></textarea>
              {#if editError}
                <span class="bubble-edit-error" role="alert">{editError}</span>
              {/if}
              <div class="bubble-edit-actions">
                <span class="bubble-edit-hint">{m.channels_edit_hint()}</span>
                <button type="button" class="bubble-edit-cancel" onclick={cancelEdit} disabled={editBusy}>
                  {m.common_cancel()}
                </button>
                <button
                  type="button"
                  class="bubble-edit-save"
                  onclick={() => commitEdit(row.msg)}
                  disabled={editBusy || !editDraft.trim()}
                >
                  {editBusy ? m.chat_loading_short() : m.common_save()}
                </button>
              </div>
            </div>
          {:else}
          <div class="bubble-text"><bdi dir="auto">{#each row.segments as seg, i (i)}{#if seg.href}<button
                  type="button"
                  class="bubble-link"
                  title={seg.href}
                  onclick={() => askOpenLink(seg.href!)}
                >{seg.text}</button>{:else}{seg.text}{/if}{/each}</bdi></div>
          {/if}
          {#if !isChannel && (row.endsRun || pending || failed || (row.msg.edited_at ?? 0) > 0)}
            {@render messageTimestamp(row.msg, pending, failed)}
          {/if}
          <!-- Channels only, and only for rows the DB can actually address:
               live bubbles carry negative synthetic ids. -->
          {#if isChannel && row.msg.id > 0}
            <div class="bubble-tools">
              {#if canEdit(row.msg) && editingId !== row.msg.id}
                <button
                  class="bubble-edit-btn"
                  onclick={() => startEdit(row.msg)}
                  title={m.channels_edit_message()}
                  aria-label={m.channels_edit_message()}
                >
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="11" height="11" aria-hidden="true">
                    <path d="M11.5 2.5l2 2L6 12l-3 1 1-3z"/>
                  </svg>
                </button>
              {/if}
              <button
                class="bubble-remove"
                disabled={removingMessage === row.msg.id}
                onclick={() => handleRemoveMessage(row.msg.id)}
                title={m.channels_remove_local()}
                aria-label={m.channels_remove_local()}
              >
                <IconX size={11} />
              </button>
            </div>
          {/if}
          {#if isChannel}
            <div class="bubble-meta">
              {#if row.msg.msg_id?.length === 32}
                {@const tally = reactions[row.msg.msg_id]}
                {@const mine = tally?.mine ?? REACTION_NONE}
                {@const hasAny = (tally?.up ?? 0) + (tally?.down ?? 0) + (tally?.heart ?? 0) > 0}
                {@const ownMessage = row.msg.direction === 'sent'}
                {#if !ownMessage || hasAny}
                <div class="bubble-reactions" class:has-any={hasAny} class:readonly={ownMessage}>
                  {#if !ownMessage || (tally?.heart ?? 0) > 0}
                  <button
                    type="button"
                    class="reaction-btn heart"
                    class:active={mine === REACTION_HEART}
                    class:pulse-add={!ownMessage && reactionPulse?.msgId === row.msg.msg_id && reactionPulse?.kind === REACTION_HEART && reactionPulse?.action === 'add'}
                    class:pulse-remove={!ownMessage && reactionPulse?.msgId === row.msg.msg_id && reactionPulse?.kind === REACTION_HEART && reactionPulse?.action === 'remove'}
                    disabled={ownMessage || reactionBusy !== null}
                    onclick={() => { if (!ownMessage) void toggleReaction(row.msg, REACTION_HEART); }}
                    title={m.channels_reaction_heart()}
                    aria-label={m.channels_reaction_heart()}
                    aria-pressed={mine === REACTION_HEART}
                    tabindex={ownMessage ? -1 : undefined}
                  >
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="14" height="14" aria-hidden="true">
                      <path d="M8 13.4S2.6 10.1 2.6 6.7A3.05 3.05 0 0 1 8 4.05a3.05 3.05 0 0 1 5.4 2.65C13.4 10.1 8 13.4 8 13.4z"/>
                    </svg>
                    {#if (tally?.heart ?? 0) > 0}<span class="reaction-count">{tally?.heart}</span>{/if}
                  </button>
                  {/if}
                  {#if !ownMessage || (tally?.up ?? 0) > 0}
                  <button
                    type="button"
                    class="reaction-btn"
                    class:active={mine === REACTION_UP}
                    class:pulse-add={!ownMessage && reactionPulse?.msgId === row.msg.msg_id && reactionPulse?.kind === REACTION_UP && reactionPulse?.action === 'add'}
                    class:pulse-remove={!ownMessage && reactionPulse?.msgId === row.msg.msg_id && reactionPulse?.kind === REACTION_UP && reactionPulse?.action === 'remove'}
                    disabled={ownMessage || reactionBusy !== null}
                    onclick={() => { if (!ownMessage) void toggleReaction(row.msg, REACTION_UP); }}
                    title={m.channels_reaction_up()}
                    aria-label={m.channels_reaction_up()}
                    aria-pressed={mine === REACTION_UP}
                    tabindex={ownMessage ? -1 : undefined}
                  >
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="14" height="14" aria-hidden="true">
                      <path d="M5 14V7l3.2-4.5a1.4 1.4 0 0 1 2.4 1.3L9.7 6.5H13a1.3 1.3 0 0 1 1.2 1.7l-1.3 4.6a1.7 1.7 0 0 1-1.6 1.2H5zM2.6 14h2.4V7H2.6z"/>
                    </svg>
                    {#if (tally?.up ?? 0) > 0}<span class="reaction-count">{tally?.up}</span>{/if}
                  </button>
                  {/if}
                  {#if !ownMessage || (tally?.down ?? 0) > 0}
                  <button
                    type="button"
                    class="reaction-btn"
                    class:active={mine === REACTION_DOWN}
                    class:pulse-add={!ownMessage && reactionPulse?.msgId === row.msg.msg_id && reactionPulse?.kind === REACTION_DOWN && reactionPulse?.action === 'add'}
                    class:pulse-remove={!ownMessage && reactionPulse?.msgId === row.msg.msg_id && reactionPulse?.kind === REACTION_DOWN && reactionPulse?.action === 'remove'}
                    disabled={ownMessage || reactionBusy !== null}
                    onclick={() => { if (!ownMessage) void toggleReaction(row.msg, REACTION_DOWN); }}
                    title={m.channels_reaction_down()}
                    aria-label={m.channels_reaction_down()}
                    aria-pressed={mine === REACTION_DOWN}
                    tabindex={ownMessage ? -1 : undefined}
                  >
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="14" height="14" aria-hidden="true">
                      <path d="M11 2v7l-3.2 4.5a1.4 1.4 0 0 1-2.4-1.3l.9-2.7H3a1.3 1.3 0 0 1-1.2-1.7l1.3-4.6A1.7 1.7 0 0 1 4.7 2H11zm2.4 0h-2.4v7h2.4z"/>
                    </svg>
                    {#if (tally?.down ?? 0) > 0}<span class="reaction-count">{tally?.down}</span>{/if}
                  </button>
                  {/if}
                </div>
                {/if}
              {/if}
              {@render messageTimestamp(row.msg, pending, failed)}
            </div>
          {/if}
        </div>
        </div>
      {/each}
    {/if}
    <div bind:this={messagesEnd}></div>
  </div>

  {#if scrolledAway && messages.length > 0 && !loading}
    <button
      class="conv-jump"
      class:has-unseen={missedWhileAway}
      type="button"
      onclick={jumpToLatest}
      title={missedWhileAway ? m.chat_new_messages_below() : m.chat_jump_to_latest()}
      aria-label={missedWhileAway ? m.chat_new_messages_below() : m.chat_jump_to_latest()}
    >
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
        <path d="M8 3v9M4.5 8.5 8 12l3.5-3.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <span>{missedWhileAway ? m.chat_new_messages_below() : m.chat_jump_to_latest()}</span>
    </button>
  {/if}

  {#if sendError}
    <div class="conv-error">{sendError}</div>
  {/if}

  {#if youAreBanned}
    <div class="conv-disabled" role="status">{m.channels_you_are_banned()}</div>
  {:else if youAreKeyBehind}
    <div class="conv-disabled" role="status">{m.channels_key_behind()}</div>
  {:else if chatLocked}
    <div class="conv-disabled" role="status">{m.chat_locked_notice()}</div>
  {:else if chatDisabled}
    <div class="conv-disabled" role="status">{m.chat_disabled_notice()}</div>
  {:else}
    <div class="conv-input-area">
      {#if mentionOpen}
        <!-- A listbox the textarea owns rather than a focusable menu: focus has
             to stay in the composer so typing keeps narrowing the list. -->
        <ul class="mention-list" role="listbox" aria-label={m.chat_mention_list_label()}>
          {#each mentionMatches as name, i (name)}
            <li>
              <button
                type="button"
                class="mention-option"
                class:active={i === Math.min(mentionIndex, mentionMatches.length - 1)}
                role="option"
                aria-selected={i === Math.min(mentionIndex, mentionMatches.length - 1)}
                onmousedown={(e) => {
                  // Before blur, or the textarea loses the caret we insert at.
                  e.preventDefault();
                  applyMention(name);
                }}
              >
                <bdi dir="auto">{name}</bdi>
              </button>
            </li>
          {/each}
        </ul>
      {/if}
      <textarea
        class="conv-input"
        bind:value={inputText}
        bind:this={chatInputEl}
        onkeydown={handleKeydown}
        oninput={refreshMentionToken}
        onclick={refreshMentionToken}
        onkeyup={refreshMentionToken}
        onblur={() => (mentionStart = -1)}
        placeholder={isChannel ? m.channels_send_placeholder() : m.chat_input_placeholder()}
        maxlength="4096"
        rows="2"
        disabled={sending}
      ></textarea>
      {#if slowModeLeft > 0}
        <!-- Polite: it changes every second, and a live region that asserted
             would talk over everything else in the room. -->
        <span class="conv-slow-mode" role="status" aria-live="polite">
          {m.chat_slow_mode_wait({ seconds: slowModeLeft })}
        </span>
      {/if}
      <button type="button" class="conv-send" onclick={handleSend} disabled={!inputText.trim() || sending || slowModeLeft > 0} title={slowModeLeft > 0 ? m.chat_slow_mode_wait({ seconds: slowModeLeft }) : m.chat_send_title_short()} aria-label={m.chat_send_aria()}>
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3 10l14-7-7 14-2-5z"/><line x1="10" y1="17" x2="17" y2="3"/>
        </svg>
      </button>
    </div>
  {/if}
</div>

<!-- `isolateMessage` so a link cannot reorder the dialog's own text around it. -->
<ConfirmDialog
  bind:open={linkConfirmOpen}
  title={m.chat_link_open_title()}
  message={pendingLink}
  isolateMessage
  confirmLabel={m.chat_link_open_confirm()}
  onconfirm={openPendingLink}
  oncancel={() => (pendingLink = '')}
  ondismiss={() => (pendingLink = '')}
/>

<style>
  .conversation {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
    background: var(--bg-primary);
    /* Anchors `.conv-jump`, which floats over the transcript rather than
       occupying a row in the column — a control that pushed the composer down
       every time the reader scrolled up would move the target they are aiming
       for. */
    position: relative;
  }

  /* Nested well: a step darker than the page canvas so white received
     bubbles and the compose field have something to sit on. */
  .conversation.channel {
    background: var(--bg-tertiary);
    --reaction-gold: #ffd34a;
    --reaction-heart: #ff4f5c;
  }

  :global([data-theme="dark"]) .conversation.channel {
    background: var(--bg-secondary);
  }

  .conv-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
    flex-shrink: 0;
  }

  .conv-header-info {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
  }

  .conv-avatar {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    background: var(--accent-dim);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--accent);
    flex-shrink: 0;
  }

  .conv-avatar svg {
    width: 14px;
    height: 14px;
  }

  .conv-name {
    font-weight: 600;
    font-size: 13px;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .conv-status {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: var(--radius-pill);
    font-size: 11px;
    font-weight: 600;
    line-height: 1;
    flex-shrink: 0;
  }

  .conv-status svg {
    width: 11px;
    height: 11px;
  }

  .conv-status.icon-only {
    padding: 4px;
    gap: 0;
  }

  .conv-status.icon-only svg {
    width: 12px;
    height: 12px;
  }

  .conv-status.online {
    background: color-mix(in srgb, var(--success) 16%, transparent);
    color: var(--success);
  }

  .conv-status.offline {
    background: var(--bg-tertiary);
    color: var(--text-muted);
  }

  .conv-status.encrypted {
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    color: var(--accent);
  }

  .conv-messages {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .conversation.channel .conv-messages {
    /* Six pixels keeps separate messages readable; `.starts-run` adds another
       six where the speaker changes, preserving visible conversation groups. */
    gap: 6px;
  }

  .conv-loading,
  .conv-empty {
    text-align: center;
    color: var(--text-muted);
    padding: 24px;
    font-size: 13px;
  }

  .conv-load-error {
    display: flex;
    flex-direction: column;
    gap: 8px;
    align-items: center;
    padding: 16px;
    color: var(--danger);
    font-size: 13px;
    text-align: center;
  }

  /* Non-blocking inline notice (live listener unavailable) — sits above the
     loaded history rather than replacing it like .conv-load-error. */
  .conv-live-error {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 8px;
    padding: 6px 10px;
    border: 1px solid color-mix(in srgb, var(--warning) 35%, var(--border));
    background: color-mix(in srgb, var(--warning) 12%, transparent);
    border-radius: var(--radius-sm);
    color: color-mix(in srgb, var(--warning) 80%, var(--text-primary));
    font-size: 12px;
  }

  .conv-load-retry {
    padding: 6px 14px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-primary);
    font-size: 12px;
    cursor: pointer;
    flex-shrink: 0;
  }

  .conv-load-retry:hover {
    background: var(--bg-hover);
  }

  .conv-load-older {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    margin-bottom: 8px;
  }

  .conv-load-older-error {
    font-size: 11px;
    color: var(--danger);
  }

  .conv-load-older-btn {
    padding: 6px 12px;
    border-radius: var(--radius-pill);
    border: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-secondary);
    font-size: 12px;
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .conv-load-older-btn:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .conv-load-older-btn:disabled {
    opacity: 0.5;
    cursor: default;
  }

  /* Day markers break the list into the units people actually recall
     conversations in, and give a long history somewhere for the eye to rest. */
  .conv-day {
    align-self: center;
    margin: 10px 0 4px;
    padding: 3px 10px;
    border-radius: var(--radius-pill);
    background: var(--bg-tertiary);
    color: var(--text-muted);
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.4px;
    text-transform: uppercase;
    flex-shrink: 0;
  }

  .conv-day:first-child {
    margin-top: 0;
  }

  .conversation.channel .conv-day {
    background: var(--bg-surface);
    border: 1px solid color-mix(in srgb, var(--border) 80%, transparent);
  }

  /* A full-width rule rather than a centred pill like `.conv-day`: it marks a
     boundary in the conversation, so it should read as a line across it. */
  .conv-unread-divider {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 10px 0 2px;
    color: var(--accent);
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.4px;
    text-transform: uppercase;
    flex-shrink: 0;
  }

  .conv-unread-divider::before,
  .conv-unread-divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: color-mix(in srgb, var(--accent) 45%, transparent);
  }

  .conv-bubble {
    max-width: 80%;
    padding: 8px 12px;
    border-radius: var(--radius-lg);
    font-size: 13px;
    line-height: 1.4;
    word-wrap: break-word;
    overflow-wrap: anywhere;
    /* Anchors the hover-revealed remove control. */
    position: relative;
  }

  /* A column so the sender name can sit above the bubble instead of inside
     it, and so sent/received alignment applies to the name + bubble as one. */
  .conv-msg {
    display: flex;
    flex-direction: column;
    max-width: 80%;
    min-width: 0;
  }

  .conv-msg.sent { align-self: flex-end; align-items: flex-end; }
  .conv-msg.received { align-self: flex-start; align-items: flex-start; }

  .conv-msg .conv-bubble {
    max-width: 100%;
  }

  .conversation.channel .conv-msg {
    position: relative;
    max-width: min(720px, 72%);
    min-width: min(156px, 72%);
  }

  .conversation.channel .conv-bubble {
    width: 100%;
    padding: 24px 12px 8px;
    line-height: 1.4;
    border-radius: 8px;
    box-shadow: none;
  }

  .conversation.channel .conv-msg.received .conv-bubble,
  .conversation.channel .conv-msg.sent .conv-bubble {
    border-top-left-radius: 8px;
  }

  /* Consecutive messages from one author read as a single block: the gap only
     opens where the speaker changes, and the corners facing a neighbour in the
     same run flatten so the bubbles visibly belong together. */
  /* A message naming you is the one thing in a busy room you cannot afford to
     scroll past, so it gets an edge marker rather than a colour change that
     would fight the sent/received distinction. */
  /* Revealed on hover of its own bubble: a per-message control that is always
     visible turns a transcript into a wall of buttons. Hidden with `opacity`
     rather than `display` so it stays in the tab order — `display: none` would
     put it out of reach of the keyboard entirely — and it reveals itself on
     focus so a keyboard user can see what they have landed on. */
  .bubble-remove {
    position: absolute;
    top: 2px;
    inset-inline-end: 2px;
    width: 18px;
    height: 18px;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: var(--bg-secondary);
    color: var(--text-muted);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    box-shadow: var(--shadow-sm);
    opacity: 0;
    transition: opacity var(--transition-fast);
  }

  .conv-bubble:hover .bubble-remove,
  .bubble-remove:focus-visible { opacity: 1; }
  .bubble-remove:hover { color: var(--danger); }
  .bubble-remove:disabled { opacity: 0.4; cursor: not-allowed; }

  .conv-bubble.mentions-me {
    border-inline-start: 2px solid var(--accent);
    padding-inline-start: 8px;
    background: color-mix(in srgb, var(--accent) 8%, transparent);
  }

  .conversation.channel .conv-bubble.mentions-me {
    background: color-mix(in srgb, var(--accent) 12%, var(--bg-secondary));
    padding-inline-start: 10px;
  }

  :global([data-theme="dark"]) .conversation.channel .conv-bubble.mentions-me {
    background: color-mix(in srgb, var(--accent) 16%, var(--bg-tertiary));
  }

  .conv-msg.starts-run:not(:first-child) {
    margin-top: 8px;
  }

  .conversation.channel .conv-msg.starts-run:not(:first-child) {
    margin-top: 6px;
  }

  .conv-bubble.sent {
    background: var(--accent);
    color: var(--on-accent);
  }

  .conv-bubble.sent:not(.starts-run) {
    border-top-right-radius: 6px;
  }

  .conv-bubble.sent:not(.ends-run) {
    border-bottom-right-radius: 6px;
  }

  .conv-bubble.sent.ends-run {
    border-bottom-right-radius: 4px;
  }

  .conv-bubble.received {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }

  .conversation.channel .conv-bubble.sent {
    background:
      linear-gradient(
        165deg,
        color-mix(in srgb, #fff 14%, var(--accent)) 0%,
        var(--accent) 46%
      );
    box-shadow: 0 1px 3px color-mix(in srgb, var(--accent) 28%, transparent);
  }

  .conversation.channel .conv-bubble.received {
    background: color-mix(in srgb, var(--bg-secondary) 88%, var(--bg-surface));
    border: 1px solid color-mix(in srgb, var(--border) 82%, transparent);
  }

  :global([data-theme="dark"]) .conversation.channel .conv-bubble.received {
    background: var(--bg-tertiary);
  }

  .conversation.channel .conv-bubble.sent:not(.starts-run) {
    border-top-right-radius: 4px;
  }

  .conversation.channel .conv-bubble.sent:not(.ends-run) {
    border-bottom-right-radius: 4px;
  }

  .conversation.channel .conv-bubble.sent.ends-run {
    border-bottom-right-radius: 8px;
  }

  .conversation.channel .conv-bubble.received:not(.starts-run) {
    border-top-left-radius: 8px;
  }

  .conversation.channel .conv-bubble.received:not(.ends-run) {
    border-bottom-left-radius: 4px;
  }

  .conversation.channel .conv-bubble.received.ends-run {
    border-bottom-left-radius: 8px;
  }

  .conv-bubble.received:not(.starts-run) {
    border-top-left-radius: 6px;
  }

  .conv-bubble.received:not(.ends-run) {
    border-bottom-left-radius: 6px;
  }

  .conv-bubble.received.ends-run {
    border-bottom-left-radius: 4px;
  }

  /* Marks the message a search hit jumped to. A ring rather than a background
     swap, so it reads the same on a sent bubble as on a received one. */
  .conv-bubble.focused {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .bubble-text {
    white-space: pre-wrap;
  }

  /* A button that has to sit inside wrapping text, so every bit of button
     chrome is stripped and the line-box geometry left to the paragraph. */
  .bubble-link {
    all: unset;
    display: inline;
    cursor: pointer;
    text-decoration: underline;
    text-underline-offset: 2px;
    word-break: break-all;
  }

  .bubble-link:hover,
  .bubble-link:focus-visible {
    text-decoration-thickness: 2px;
  }

  .bubble-link:focus-visible {
    outline: 2px solid currentColor;
    outline-offset: 1px;
    border-radius: 2px;
  }

  /* Received bubbles are on the surface colour, so the accent reads as a link.
     Sent bubbles are already accent-filled, where it would not. */
  .conv-bubble.received .bubble-link {
    color: var(--accent);
  }

  .bubble-who {
    font-size: 11px;
    font-weight: 600;
    opacity: 0.75;
    margin-bottom: 2px;
  }

  .conversation.channel .bubble-who {
    opacity: 1;
    position: absolute;
    z-index: 1;
    top: 0;
    inset-inline-start: 0;
    display: inline-flex;
    max-width: calc(100% - 16px);
    margin: 0;
    padding: 3px 9px 3px 8px;
    border-radius: 8px 6px 8px 0;
    background: color-mix(in srgb, var(--accent) 12%, var(--bg-secondary));
    border: 1px solid color-mix(in srgb, var(--accent) 22%, var(--border));
    color: var(--text-accent);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.2px;
    line-height: 1.2;
  }

  .conversation.channel .conv-msg.received .bubble-who {
    top: -1px;
    inset-inline-start: -1px;
  }

  .conversation.channel .conv-msg.sent .bubble-who {
    background: var(--on-accent);
    border-color: color-mix(in srgb, var(--on-accent) 55%, var(--accent));
    color: var(--accent);
    box-shadow:
      -1px -1px 0 var(--on-accent),
      0 1px 2px color-mix(in srgb, #000 12%, transparent);
  }

  .conversation.channel .bubble-who bdi {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .bubble-time {
    font-size: 10px;
    color: var(--text-muted);
    padding: 0 2px;
    line-height: 1.2;
    flex-shrink: 0;
  }

  .conversation.channel .conv-bubble.sent .bubble-time,
  .conversation.channel .conv-bubble.sent .bubble-edited {
    color: color-mix(in srgb, var(--on-accent) 88%, transparent);
  }

  .bubble-meta {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: flex-start;
    gap: 14px;
    margin-top: 10px;
    min-height: 16px;
    position: relative;
  }

  /* Internal footer: reactions stay by the near edge and time sits opposite. */
  .conversation.channel .bubble-time {
    margin-inline-start: auto;
  }

  /* Sits inside the timestamp line so a queued message reads as "sent at X,
     not yet delivered" rather than as a separate error state. */
  .bubble-delivery {
    margin-left: 6px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
  }

  .bubble-delivery.failed {
    color: var(--danger);
    opacity: 1;
  }

  /* Edit and remove share one hover-revealed cluster so they cannot overlap each
     other, and so a bubble has one control affordance rather than two competing
     ones. Same opacity-not-display reveal as `.bubble-remove` had alone: the
     buttons stay in the tab order, and reveal on focus so a keyboard user can see
     where they have landed. */
  .bubble-tools {
    position: absolute;
    top: 2px;
    inset-inline-end: 2px;
    display: flex;
    align-items: center;
    gap: 2px;
    opacity: 0;
    transition: opacity var(--transition-fast);
  }

  /* Channel rooms park the cluster on the top edge, half outside the fill,
     so it doesn't eat into a compact bubble. Hover still works: the buttons
     are descendants of the bubble even when they paint outside it. */
  .conversation.channel .bubble-tools {
    top: -8px;
    inset-inline-end: 2px;
    transform: none;
    z-index: 3;
    gap: 3px;
  }

  .conversation.channel .bubble-remove {
    position: static;
  }

  .conversation.channel .bubble-edit-btn,
  .conversation.channel .bubble-remove {
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--bg-primary);
    color: var(--text-muted);
    box-shadow: none;
    border: 1px solid var(--border);
  }

  /* Match the Channels beta badge: rose identifies this secondary action
     without giving a local-only delete the weight of a danger-red button. */
  .conversation.channel .bubble-remove {
    color: var(--ember-color);
    background: color-mix(in srgb, var(--ember-color) 14%, var(--bg-primary));
    border-color: color-mix(in srgb, var(--ember-color) 28%, var(--border));
  }

  .conversation.channel .bubble-remove:hover {
    color: var(--ember-color);
    background: color-mix(in srgb, var(--ember-color) 22%, var(--bg-primary));
    border-color: color-mix(in srgb, var(--ember-color) 45%, var(--border));
  }

  .conversation.channel .bubble-edit-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .conv-bubble:hover .bubble-tools,
  .bubble-tools:focus-within {
    opacity: 1;
  }

  .bubble-edit-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 17px;
    height: 17px;
    padding: 0;
    border: none;
    border-radius: 4px;
    background: transparent;
    color: inherit;
    cursor: pointer;
  }

  .bubble-edit-btn:hover {
    background: rgb(0 0 0 / 18%);
  }

  /* An edit marker belongs with the timestamp, not the text: it is metadata about
     when the line was last touched, which is exactly what the rest of that row
     already says. */
  .bubble-edited {
    margin-inline-start: 6px;
    font-style: italic;
    opacity: 0.85;
  }

  .bubble-edit {
    display: flex;
    flex-direction: column;
    gap: 5px;
    min-width: 220px;
  }

  .bubble-edit-input {
    width: 100%;
    padding: 5px 7px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-primary);
    color: var(--text-primary);
    font: inherit;
    resize: vertical;
  }

  .bubble-edit-error {
    color: var(--danger);
    font-size: 11px;
  }

  .bubble-edit-actions {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .bubble-edit-hint {
    flex: 1 1 auto;
    font-size: 10px;
    opacity: 0.7;
  }

  .bubble-edit-cancel,
  .bubble-edit-save {
    padding: 2px 8px;
    border: 1px solid var(--border);
    border-radius: 5px;
    background: var(--bg-surface);
    color: var(--text-primary);
    font-size: 11px;
    cursor: pointer;
  }

  .bubble-edit-save {
    border-color: var(--accent);
    background: var(--accent);
    color: var(--on-accent);
  }

  .bubble-edit-cancel:disabled,
  .bubble-edit-save:disabled {
    opacity: 0.6;
    cursor: default;
  }

  /* Hidden until hover while nobody has reacted, so an untouched transcript stays
     clean; once a count exists it is content and stays put. */
  .bubble-reactions {
    display: flex;
    align-items: center;
    gap: 3px;
    margin-top: 3px;
    opacity: 0;
    transition: opacity var(--transition-fast);
  }

  /* Reactions live in the internal footer. Keeping them in flow guarantees
     clear space from both the message and the timestamp. */
  .conversation.channel .bubble-reactions {
    margin: 0;
    flex-shrink: 0;
    pointer-events: none;
  }

  /* Hover-only controls do not make every untouched bubble taller. They use
     the footer's reserved near edge; a real tally returns to normal flow. */
  .conversation.channel .bubble-reactions:not(.has-any) {
    position: absolute;
    inset-inline-start: 0;
    top: 50%;
    transform: translateY(-50%);
  }

  .conversation.channel .conv-bubble.sent .bubble-reactions:not(.has-any) {
    inset-inline-start: auto;
    inset-inline-end: 0;
  }

  .conversation.channel .bubble-reactions.has-any {
    position: static;
    transform: none;
    pointer-events: auto;
  }

  .bubble-reactions.has-any,
  .conv-msg:hover .bubble-reactions,
  .bubble-reactions:focus-within {
    opacity: 1;
  }

  .conversation.channel .bubble-reactions.has-any,
  .conversation.channel .conv-msg:hover .bubble-reactions,
  .conversation.channel .bubble-reactions:focus-within {
    pointer-events: auto;
  }

  /* A pointer that cannot hover has no way to reveal any of these, so on a touch
     screen the edit, remove and reaction controls were unreachable outright.
     After all three base rules, since none of this adds specificity. */
  @media (hover: none) {
    .bubble-remove,
    .bubble-tools,
    .bubble-reactions {
      opacity: 1;
      pointer-events: auto;
    }
  }

  .reaction-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    min-width: 26px;
    height: 24px;
    padding: 2px 5px;
    border: 1px solid transparent;
    border-radius: 999px;
    background: transparent;
    color: var(--reaction-gold);
    font-size: 11px;
    font-variant-numeric: tabular-nums;
    cursor: pointer;
    transition:
      background var(--transition-fast) ease,
      color var(--transition-fast) ease,
      border-color var(--transition-fast) ease,
      transform 0.16s ease;
  }

  .conversation.channel .reaction-btn {
    background:
      linear-gradient(180deg, color-mix(in srgb, #fff 22%, transparent), transparent 58%);
    color: var(--reaction-gold);
    border-color: color-mix(in srgb, var(--reaction-gold) 20%, transparent);
    box-shadow: inset 0 1px 0 color-mix(in srgb, #fff 28%, transparent);
  }

  .conversation.channel .reaction-btn svg {
    fill: var(--reaction-gold);
    stroke: color-mix(in srgb, var(--reaction-gold) 62%, #8a5600);
    filter:
      drop-shadow(0 0.5px 0 color-mix(in srgb, #fff 78%, transparent))
      drop-shadow(0 1px 1.1px color-mix(in srgb, #000 26%, transparent));
  }

  .reaction-btn:hover:not(:disabled) {
    transform: translateY(-1px);
  }

  .conversation.channel .reaction-btn:hover:not(:disabled) {
    color: var(--reaction-gold);
    background:
      linear-gradient(180deg, color-mix(in srgb, #fff 42%, transparent), transparent 48%),
      color-mix(in srgb, var(--reaction-gold) 20%, transparent);
    border-color: color-mix(in srgb, var(--reaction-gold) 48%, transparent);
    box-shadow:
      inset 0 1px 0 color-mix(in srgb, #fff 55%, transparent),
      0 1px 3px color-mix(in srgb, var(--reaction-gold) 28%, transparent);
  }

  .reaction-btn:active:not(:disabled) {
    transform: scale(0.94);
  }

  .reaction-btn:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .reaction-btn.active {
    border-color: var(--accent);
    background: color-mix(in srgb, var(--accent) 22%, transparent);
  }

  .conversation.channel .reaction-btn.active {
    color: var(--reaction-gold);
    background:
      linear-gradient(180deg, color-mix(in srgb, #fff 36%, transparent), transparent 46%),
      color-mix(in srgb, var(--reaction-gold) 24%, transparent);
    border-color: color-mix(in srgb, var(--reaction-gold) 55%, transparent);
    box-shadow:
      inset 0 1px 0 color-mix(in srgb, #fff 50%, transparent),
      0 1px 4px color-mix(in srgb, var(--reaction-gold) 32%, transparent);
  }

  .conversation.channel .reaction-btn.heart {
    color: var(--reaction-heart);
    border-color: color-mix(in srgb, var(--reaction-heart) 20%, transparent);
  }

  .conversation.channel .reaction-btn.heart svg {
    fill: var(--reaction-heart);
    stroke: color-mix(in srgb, var(--reaction-heart) 68%, #7a121c);
  }

  .conversation.channel .reaction-btn.heart:hover:not(:disabled) {
    color: var(--reaction-heart);
    background:
      linear-gradient(180deg, color-mix(in srgb, #fff 42%, transparent), transparent 48%),
      color-mix(in srgb, var(--reaction-heart) 20%, transparent);
    border-color: color-mix(in srgb, var(--reaction-heart) 48%, transparent);
    box-shadow:
      inset 0 1px 0 color-mix(in srgb, #fff 55%, transparent),
      0 1px 3px color-mix(in srgb, var(--reaction-heart) 28%, transparent);
  }

  .conversation.channel .reaction-btn.heart.active {
    color: var(--reaction-heart);
    background:
      linear-gradient(180deg, color-mix(in srgb, #fff 36%, transparent), transparent 46%),
      color-mix(in srgb, var(--reaction-heart) 24%, transparent);
    border-color: color-mix(in srgb, var(--reaction-heart) 55%, transparent);
    box-shadow:
      inset 0 1px 0 color-mix(in srgb, #fff 50%, transparent),
      0 1px 4px color-mix(in srgb, var(--reaction-heart) 32%, transparent);
  }

  .conversation.channel .reaction-btn.heart .reaction-count {
    color: color-mix(in srgb, var(--reaction-heart) 65%, var(--text-primary));
  }

  .conversation.channel .reaction-btn.pulse-add {
    animation: reaction-pop 0.36s ease;
  }

  .conversation.channel .reaction-btn.pulse-remove {
    animation: reaction-release 0.32s ease;
  }

  .conversation.channel .reaction-btn.heart.pulse-add {
    animation: reaction-heartbeat 0.52s ease;
  }

  .conversation.channel .reaction-btn.heart.pulse-remove {
    animation: reaction-heartbeat-out 0.4s ease;
  }

  @keyframes reaction-pop {
    0% { transform: scale(1); }
    35% { transform: scale(1.16); }
    100% { transform: scale(1); }
  }

  @keyframes reaction-release {
    0% { transform: scale(1); opacity: 1; }
    45% { transform: scale(0.84); opacity: 0.48; }
    100% { transform: scale(1); opacity: 1; }
  }

  @keyframes reaction-heartbeat {
    0% { transform: scale(1); }
    18% { transform: scale(1.28); }
    34% { transform: scale(1.04); }
    52% { transform: scale(1.2); }
    100% { transform: scale(1); }
  }

  @keyframes reaction-heartbeat-out {
    0% { transform: scale(1); opacity: 1; }
    28% { transform: scale(1.12); opacity: 0.85; }
    100% { transform: scale(1); opacity: 1; }
  }

  .reaction-btn:disabled {
    cursor: default;
  }

  .conversation.channel .bubble-reactions.readonly .reaction-btn {
    pointer-events: none;
  }

  .reaction-count {
    font-weight: 600;
    color: color-mix(in srgb, var(--reaction-gold) 65%, var(--text-primary));
  }

  /* Resend sits inside the timestamp line of its own bubble, so it reads as
     part of the failure notice rather than a general-purpose action. Always
     visible (unlike `.bubble-remove`, which is hover-revealed): a message that
     did not arrive is exactly the case where the remedy should not be hidden. */
  .bubble-resend {
    margin-inline-start: 6px;
    padding: 0 5px;
    border: 1px solid color-mix(in srgb, var(--danger) 45%, transparent);
    border-radius: 4px;
    background: transparent;
    color: var(--danger);
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    cursor: pointer;
  }

  .bubble-resend:hover:not(:disabled) {
    background: color-mix(in srgb, var(--danger) 16%, transparent);
  }

  .bubble-resend:disabled {
    opacity: 0.6;
    cursor: default;
  }

  /* Floats just above the composer. `has-unseen` is the accent case: the
     difference between "you scrolled up" and "you scrolled up and missed
     something" is the whole reason this exists, so it is carried by colour and
     not only by the label. */
  .conv-jump {
    position: absolute;
    inset-inline-end: 18px;
    bottom: 76px;
    z-index: 4;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 5px 10px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--bg-surface);
    color: var(--text-secondary);
    font-size: 11px;
    font-weight: 600;
    box-shadow: 0 4px 12px rgb(0 0 0 / 22%);
    cursor: pointer;
  }

  .conv-jump:hover {
    color: var(--text-primary);
    border-color: var(--text-muted);
  }

  .conv-jump.has-unseen {
    border-color: var(--accent);
    background: var(--accent);
    color: var(--on-accent);
  }

  .conv-error {
    padding: 8px 14px;
    background: color-mix(in srgb, var(--danger) 14%, transparent);
    color: var(--danger);
    font-size: 12px;
    text-align: center;
  }

  .conv-disabled {
    padding: 12px 14px;
    border-top: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-muted);
    font-size: 12.5px;
    text-align: center;
    flex-shrink: 0;
  }

  .conv-input-area {
    display: flex;
    gap: 8px;
    padding: 10px 14px 14px;
    border-top: 1px solid var(--border);
    background: var(--bg-surface);
    flex-shrink: 0;
    /* Anchors the suggestion list, which sits above the composer rather than
       below it: there is nothing below but the window edge. */
    position: relative;
  }

  .conversation.channel .conv-input-area,
  .conversation.channel .conv-disabled {
    background: var(--bg-tertiary);
  }

  :global([data-theme="dark"]) .conversation.channel .conv-input-area,
  :global([data-theme="dark"]) .conversation.channel .conv-disabled {
    background: var(--bg-secondary);
  }

  .conversation.channel .conv-input-area {
    box-shadow: var(--shadow-up-sm);
  }

  .mention-list {
    position: absolute;
    bottom: calc(100% - 4px);
    inset-inline-start: 14px;
    z-index: 5;
    min-width: 160px;
    max-width: 260px;
    margin: 0;
    padding: 4px;
    list-style: none;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-surface);
  }

  .conversation.channel .mention-list {
    background: var(--bg-secondary);
    box-shadow: var(--shadow-md);
  }

  .mention-option {
    display: block;
    width: 100%;
    padding: 5px 8px;
    border: none;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text-primary);
    font: inherit;
    font-size: 12px;
    text-align: start;
    cursor: pointer;
  }

  .mention-option:hover,
  .mention-option.active {
    background: var(--accent);
    color: var(--on-accent);
  }

  /* Aligned to the bottom of the row so it sits level with the send button
     rather than floating against the top of a two-row textarea. */
  .conv-slow-mode {
    align-self: flex-end;
    padding-bottom: 10px;
    font-size: 11px;
    font-variant-numeric: tabular-nums;
    color: var(--text-secondary);
    white-space: nowrap;
  }

  .conv-input {
    flex: 1;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 13px;
    font-family: inherit;
    resize: none;
    outline: none;
    line-height: 1.4;
    min-height: 40px;
    max-height: 120px;
  }

  .conversation.channel .conv-input {
    background: var(--bg-input);
    box-shadow: var(--shadow-sm);
  }

  .conv-input:focus {
    border-color: var(--accent);
  }

  .conv-input:disabled {
    opacity: 0.6;
  }

  .conv-send {
    width: 40px;
    height: 40px;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: var(--accent);
    color: var(--on-accent);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    line-height: 1;
    transition: background var(--transition-fast), opacity var(--transition-fast);
  }

  .conv-send:hover:not(:disabled) {
    background: var(--accent-hover, var(--accent));
  }

  .conv-send:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .conv-send svg {
    width: 18px;
    height: 18px;
  }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }
</style>
