<script lang="ts">
  import { onDestroy, tick, untrack } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import {
    discardFailedChatMessage,
    getChatMessages,
    sendChatMessage,
    sendChatTyping,
    markMessagesRead,
    isChatLocked,
    listChatAttachments,
    mergeChatAttachment,
    parseChatAttachment,
    pickAndSendChatAttachment,
    type ChatAttachment,
    type ChatMessage,
  } from '$lib/api/friends';
  import ChatAttachmentBubble from '$lib/components/ChatAttachmentBubble.svelte';
  import { placeAttachments } from '$lib/chatAttachmentPlacement';
  import {
    deleteChannelMessage,
    getChannelDraft,
    getChannelMessages,
    getChannelPins,
    markChannelMessagesRead,
    sendChannelMessage,
    sendChannelTyping,
    setChannelDraft,
    setChannelMessagePinned,
    CHANNEL_PIN_MAX,
    REPLY_REFERENCE_BYTES,
    type ChannelInfo,
    type ChannelMessageInfo,
    type ChannelPinInfo,
    type ChannelReplyParent,
  } from '$lib/api/channels';
  import {
    clampPinIndex,
    nextPinIndex,
    pinAction,
    pinIndexAfterChange,
    resolvePins,
  } from '$lib/channelPins';
  import {
    cachedReplyExcerpt,
    getPendingReply,
    resolveReplyQuote,
    setPendingReply,
    type PendingReply,
  } from '$lib/channelReply';
  import { activeChatHash, clearUnread, onlineFriends } from '$lib/stores/friends';
  import { clearChannelUnread, noteChannelOnScreen } from '$lib/stores/channels';
  import {
    editChannelMessage,
    getChannelReactions,
    setChannelMessageReaction,
    REACTION_NONE,
    REACTION_UP,
    REACTION_DOWN,
    REACTION_HEART,
    type ChannelReactionInfo,
    type ChannelReactionTally,
  } from '$lib/api/channels';
  import {
    CURATED_REACTIONS,
    QUICK_REACTIONS,
    REACTION_GRID_COLUMNS,
    coalesceRefresh,
    curatedReaction,
    formatReactors,
    gridMove,
    mergeReactionTallies,
    resolvePickerPlacement,
    visibleReactors,
  } from '$lib/channelReactions';
  import {
    dropTypist,
    nextTypistExpiry,
    noteTypist,
    outgoingTypingAction,
    pruneTypists,
    shouldAnnounceTyping,
    typingLineSegments,
    visibleTypists,
    type Typists,
  } from '$lib/channelTyping';
  import { portal } from '$lib/actions/portal';
  import { rovingToolbar } from '$lib/actions/rovingToolbar';
  import { appSettings } from '$lib/stores/settings';
  import { getDraft, setDraft, clearDraft, registerDraftFlusher } from '$lib/stores/chatTabs';
  import { firstRowBelow, recalledScroll, rememberScroll, type ScrollSpot } from '$lib/chatScrollMemory';
  import { insertAtSelection } from '$lib/emojiPicker';
  import EmojiPicker from '$lib/components/EmojiPicker.svelte';
  import * as m from '$lib/paraglide/messages';
  import { codedErrorOf, translateError } from '$lib/i18n';
  import {
    copyToClipboard,
    formatCalendarDate,
    formatClockTime,
    formatDateTime,
    insertMention,
    isAppVisible,
    mentionTokenAt,
    shortPubkey,
  } from '$lib/utils';
  import { formatMessage, type FormatBlock, type InlineNode } from '$lib/messageFormat';
  import { prefersReducedMotion } from 'svelte/motion';
  import { openExternalUrl } from '$lib/api/settings';
  import { toast, toastError, toastSuccess } from '$lib/stores/toast';
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
    youAreBanned?: boolean;
    /** Private room whose content key has rotated past what this device holds. */
    youAreKeyBehind?: boolean;
    /** The room's wait between messages, or 0 when it is off or this member is
     *  exempt. Drives the composer countdown; the backend enforces it. */
    slowModeSecs?: number;
    /** An announcement-only room this member may not post in: the composer
     *  becomes a note and Reply is withdrawn. False for the owner and
     *  moderators. Reactions stay open. */
    announceOnly?: boolean;
    /** Wire ids of the room's pinned messages, oldest pin first. */
    pinnedMsgIds?: string[];
    /** This device owns the room, so Pin and Unpin are offered. */
    canPin?: boolean;
    /** A command returned the room's new state — a pin or unpin. */
    onchannelupdate?: (info: ChannelInfo) => void;
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
    /** Channels only: wire id of the line this one replies to. */
    reply_to?: string | null;
    /** Channels only: the parent was written by us. */
    reply_to_me?: boolean;
    /** Channels only: the parent as the backend last read it. */
    reply_parent?: ChannelReplyParent | null;
    /** Channels only: the parent was removed from this device. */
    reply_parent_deleted?: boolean;
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
    youAreBanned = false,
    youAreKeyBehind = false,
    slowModeSecs = 0,
    announceOnly = false,
    pinnedMsgIds = [],
    canPin = false,
    onchannelupdate,
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
  let showReadReceipts = $derived(
    !isChannel && $appSettings?.friend_chat_read_receipts !== false,
  );
  let chatLocked = $state(false);

  $effect(() => {
    let cancelled = false;
    untrack(() => {
      isChatLocked()
        .then((locked) => {
          if (!cancelled) chatLocked = locked;
        })
        .catch((e) => {
          // Fail closed. This asks the backend whether chat history is sealed
          // because its key could not be recovered; treating an unanswered
          // question as "not sealed" unlocked the composer in exactly the
          // situation where every send fails, and suppressed the warning that
          // explains why.
          console.error('Chat: could not determine chat-lock state', e);
          if (!cancelled) chatLocked = true;
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
  // One read-receipt eye on the newest opened outbound line, not a mark on
  // every earlier bubble the watermark covers.
  let lastSeenSentId = $derived(
    messages.reduce((best, message) => {
      if (message.direction === 'sent' && message.seen && message.id > best) return message.id;
      return best;
    }, 0),
  );
  // One "Sent" on the newest delivered outbound line. Queued/failed keep
  // their own per-bubble captions so a later send does not hide them.
  let lastDeliveredSentId = $derived(
    messages.reduce((best, message) => {
      if (message.direction === 'sent' && message.delivery === 'delivered' && message.id > best) {
        return message.id;
      }
      return best;
    }, 0),
  );
  let inputText = $state('');
  let loading = $state(false);
  let sending = $state(false);
  /** Which send owns `sending`. A send that outlives a conversation switch
   *  must not unlock the composer of a send started in the next one. */
  let sendSeq = 0;
  let sendError: string | null = $state(null);
  let loadError: string | null = $state(null);
  // Non-blocking notice shown above the (successfully loaded) message list when
  // the live `ember:chat-message` listener couldn't be registered, so the user
  // knows new messages won't stream in until they retry.
  let liveError = $state(false);
  let messagesEnd: HTMLDivElement | undefined = $state();
  let messagesContainerEl: HTMLDivElement | undefined = $state();
  let chatInputEl: HTMLTextAreaElement | undefined = $state();

  /**
   * Grow the composer with its draft up to the CSS max-height, past which it
   * scrolls. Keyed on `inputText` rather than the input event, so a restored
   * draft, a sent message and an inserted mention resize it too. The composer
   * takes its height from the transcript, which would otherwise slide the
   * newest lines under it.
   */
  $effect(() => {
    void inputText;
    const el = chatInputEl;
    if (!el) return;
    const before = el.offsetHeight;
    const pinned = untrack(() => isPinnedToBottom());
    el.style.height = 'auto';
    // Border-box sizing: scrollHeight leaves out the border the height includes.
    el.style.height = `${el.scrollHeight + el.offsetHeight - el.clientHeight}px`;
    const box = untrack(() => messagesContainerEl);
    if (pinned && box && el.offsetHeight !== before) box.scrollTop = box.scrollHeight;
  });

  let unlisten: UnlistenFn | null = null;
  let unlistenDelivery: UnlistenFn | null = null;
  let unlistenTyping: UnlistenFn | null = null;
  let unlistenRead: UnlistenFn | null = null;
  let unlistenAttach: UnlistenFn | null = null;

  /**
   * Files sent in this conversation, in either direction.
   *
   * Kept beside `messages` rather than inside it: an attachment is not a chat
   * line on the wire or on disk (friend chat bodies are plain text), and folding
   * it into the message model would put a second kind of row through every
   * path that assumes a message — dedup, delivery, read receipts, search. They
   * are merged into the transcript only where it is drawn, by time.
   */
  let attachments: ChatAttachment[] = $state([]);
  /** Friends a file is being picked and hashed for, which takes a while for a
   *  large one. Per friend: the hash outlives a switch to another chat. */
  let attachingFor: string[] = $state([]);
  let attaching = $derived(friendHash !== '' && attachingFor.includes(friendHash));
  let friendTyping = $state(false);
  let typingHoldTimer: ReturnType<typeof setTimeout> | null = null;
  let lastTypingSentOn = false;
  let lastTypingSentAt = 0;
  const TYPING_REFRESH_MS = 2000;
  const TYPING_HOLD_MS = 5000;
  /** Rooms only: who is composing here, and when each indicator lapses. */
  let roomTypists: Typists = $state(new Map());
  let roomTypistsNow = $state(Date.now());
  let roomTypistsTimer: ReturnType<typeof setTimeout> | null = null;
  /** Rooms only: the last signal this device sent, and to which room — the
   *  stop on the way out has to reach the room being left, not the next one. */
  let roomTypingSentOn = false;
  let roomTypingSentAt = 0;
  let roomTypingChannel = '';
  let removingMessage = $state<number | null>(null);
  /** Undo for this component's "room is on screen" claim. */
  let releaseChannelOnScreen: (() => void) | null = null;
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
  /**
   * Holds the transcript's live region quiet while a page of history lands, so
   * a screen reader announces arriving lines rather than reading out every row
   * a load or "Load older" inserted. Released a frame after the load settles:
   * the rows and the end of the load reach the DOM in the same flush, and a
   * log that goes idle in that mutation announces all of them.
   */
  let transcriptBusy = $state(false);
  $effect(() => {
    if (loading || loadingOlder) {
      transcriptBusy = true;
      return;
    }
    const frame = requestAnimationFrame(() => {
      transcriptBusy = false;
    });
    return () => cancelAnimationFrame(frame);
  });
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
  /** Extra history pages fetched on open to find where a long unread run
   *  starts. Past this the divider sits on the oldest loaded line. */
  const UNREAD_SEEK_PAGES = 4;
  /** The divider has been on screen since this conversation opened. */
  let unreadDividerSeen = $state(false);
  /** The divider is drawn and sits above the viewport, unseen. */
  let unreadDividerAbove = $state(false);

  function fromChannelRow(row: ChannelMessageInfo): ConvMessage {
    return {
      id: row.id,
      direction: row.direction === 'sent' ? 'sent' : 'received',
      message: row.message,
      timestamp: row.timestamp,
      read: row.read,
      // The backend's verdict, not an assumption. A room line is queued until
      // the flood finds somebody and failed once the retry gives up, and
      // reporting all three as delivered is what let a line nobody received
      // sit in the sender's transcript looking sent.
      delivery: row.delivery ?? 'delivered',
      seen: false,
      sender_pubkey: row.sender_pubkey,
      edited_at: row.edited_at,
      msg_id: row.msg_id,
      reply_to: row.reply_to ?? null,
      reply_to_me: row.reply_to_me === true,
      reply_parent: row.reply_parent ?? null,
      reply_parent_deleted: row.reply_parent_deleted === true,
    };
  }

  /** Reaction tallies for this room, keyed by wire message id. Raw, and
   *  replaced through `mergeReactionTallies`: each row reads its own entry, and
   *  an entry that keeps its identity is a row with nothing to redraw. */
  let reactions = $state.raw<Record<string, ChannelReactionInfo>>({});
  /** Bumped on every read and on leaving the room, so a response that comes
   *  back after either is dropped rather than drawn over the newer state. */
  let reactionSeq = 0;
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
  /** The "more reactions" grid, open for one line at a time. */
  let picker = $state<{ msg: ConvMessage & { msg_id: string }; trigger: HTMLElement } | null>(null);
  let pickerEl: HTMLElement | undefined = $state();
  let pickerIndex = $state(0);
  /** Null until measured, so the first frame is not drawn in the wrong place. */
  let pickerPos = $state<{ left: number; top: number } | null>(null);
  let editInputEl: HTMLTextAreaElement | undefined = $state();

  /** The line the composer is answering, or null. Rooms only, and kept per room
   *  alongside the draft (see `getPendingReply`). */
  let replyTarget = $state<PendingReply | null>(null);
  /** Wire ids removed from this device since the room opened. A reply's quote
   *  snapshot predates the removal, so this is what turns it into "deleted". */
  let removedMsgIds = $state<ReadonlySet<string>>(new Set());
  let ignoredSet = $derived(new Set(ignoredSenders.map((key) => key.toLowerCase())));

  function isIgnoredSender(pubkey: string | undefined): boolean {
    return !!pubkey && ignoredSet.has(pubkey.toLowerCase());
  }

  /** Loaded lines by wire id, for quotes and the reply bar. Ignored senders'
   *  lines stay in: a quote of one is drawn as hidden rather than falling back
   *  to the backend's snapshot, which would name them. */
  let messagesByMsgId = $derived(
    new Map(
      messages
        .filter((msg): msg is ConvMessage & { msg_id: string } => !!msg.msg_id)
        .map((msg) => [msg.msg_id, msg]),
    ),
  );
  /** Pages a quote click may walk back for its parent before giving up. */
  const REPLY_SEEK_PAGES = 10;

  /** Whether a line can be answered: rooms only, and only a line with a wire id
   *  every member shares — a handoff copy's synthetic id means nothing to them. */
  function canReply(msg: ConvMessage): boolean {
    return (
      isChannel &&
      msg.id > 0 &&
      msg.msg_id?.length === 32 &&
      !youAreBanned &&
      !youAreKeyBehind &&
      !announceOnly &&
      !chatLocked
    );
  }

  /** The backend's read of each pinned line, which the bar resolves against
   *  what is loaded. Re-read whenever the pin list itself changes. */
  let pinLookups = $state<ChannelPinInfo[]>([]);
  /** Which pin the bar shows, counted from the newest. */
  let pinIndex = $state(0);
  let pinBusy = $state(false);
  /** The pin list as a value. The page hands over a fresh array on every room
   *  list refresh, and anything keyed on the array itself re-fetched the pins
   *  and sent the bar back to the first one each time. */
  let pinIdsKey = $derived(isChannel ? pinnedMsgIds.join(',') : '');
  let stablePinnedIds = $derived(pinIdsKey ? pinIdsKey.split(',') : []);
  let pinEntries = $derived(
    isChannel ? resolvePins(stablePinnedIds, pinLookups, messagesByMsgId, removedMsgIds) : [],
  );
  let shownPinIndex = $derived(clampPinIndex(pinIndex, pinEntries.length));
  /** What the bar last showed, to tell a new pin from one taken away. */
  let lastPins: { channel: string; ids: string[] } = { channel: '', ids: [] };

  $effect(() => {
    const ids = stablePinnedIds;
    const channel = channelId;
    untrack(() => {
      const prev = lastPins.channel === channel ? lastPins.ids : [];
      pinIndex = pinIndexAfterChange(prev, ids, pinIndex);
      lastPins = { channel, ids };
    });
    if (!isChannel || ids.length === 0) {
      pinLookups = [];
      return;
    }
    let cancelled = false;
    untrack(() => {
      getChannelPins(channel)
        .then((rows) => {
          if (!cancelled) pinLookups = rows;
        })
        .catch((e) => {
          // The bar then shows each pin as not available yet, which is true
          // enough and keeps the room readable.
          console.warn('ChatConversation: failed to load pinned messages', e);
        });
    });
    return () => {
      cancelled = true;
    };
  });

  function jumpToPin(id: number) {
    void focusMessage(id, {
      maxPages: REPLY_SEEK_PAGES,
      onMissing: () => toast(m.channels_pinned_unavailable()),
    });
  }

  async function setPinned(msgId: string, pinned: boolean) {
    const channel = channelId;
    if (!channel || pinBusy) return;
    pinBusy = true;
    try {
      const info = await setChannelMessagePinned(channel, msgId, pinned);
      if (channel === channelId) onchannelupdate?.(info);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      pinBusy = false;
    }
  }

  function startReply(msg: ConvMessage) {
    const channel = channelId;
    if (!channel || !msg.msg_id || !canReply(msg)) return;
    if (editingId !== null) {
      // An edit with changes is not thrown away for a reply: the reader goes
      // back to it, and can reply once it is saved or cancelled.
      const editing = messages.find((line) => line.id === editingId);
      if (editing && editDraft.trim() !== editing.message) {
        editInputEl?.focus();
        return;
      }
      cancelEdit();
    }
    const target: PendingReply = {
      id: msg.id,
      msgId: msg.msg_id,
      senderPubkey: msg.sender_pubkey ?? '',
      text: msg.message,
    };
    replyTarget = target;
    setPendingReply(channel, target);
    void tick().then(() => focusComposer());
  }

  function cancelReply() {
    replyTarget = null;
    if (channelId) setPendingReply(channelId, null);
  }

  /** One read in flight and at most one waiting: every member's reaction lands
   *  as its own event, and a busy line would otherwise fire a full re-read for
   *  each, answered in whatever order the backend gets to them. */
  const refreshReactions = coalesceRefresh(async () => {
    const channel = channelId;
    if (!channel) return;
    const seq = ++reactionSeq;
    try {
      const rows = await getChannelReactions(channel);
      if (seq !== reactionSeq || channel !== channelId) return;
      reactions = mergeReactionTallies(reactions, rows);
    } catch (e) {
      // A tally that fails to load leaves the bubbles bare rather than the room
      // unreadable, so this is not worth an error banner.
      console.warn('ChatConversation: failed to load reactions', e);
    }
  });

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
    // What the backend refuses an edit for, as it refuses a send.
    if (youAreBanned || youAreKeyBehind || chatLocked) return false;
    if (!msg.msg_id || msg.msg_id.length !== 32) return false;
    return editClockNow / 1000 - msg.timestamp <= EDIT_WINDOW_SECS;
  }

  /** The edit was opened with ↑ from the composer, so closing it goes back
   *  there: the reader was typing, not reading back. */
  let editFromComposer = false;

  function startEdit(msg: ConvMessage, fromComposer = false) {
    editingId = msg.id;
    editDraft = msg.message;
    editError = null;
    editFromComposer = fromComposer;
  }

  function cancelEdit() {
    editingId = null;
    editDraft = '';
    editError = null;
  }

  /**
   * After the reader closes the editor: back to the line's Edit button, or the
   * composer once the edit window has taken the button away. The textarea that
   * held focus is gone, and focus would otherwise fall to `<body>`. Left alone
   * when the reader has already moved on to something else.
   */
  function restoreFocusAfterEdit(id: number) {
    const toComposer = editFromComposer;
    editFromComposer = false;
    void tick().then(() => {
      const active = document.activeElement;
      if (active && active !== document.body) return;
      if (toComposer) {
        // The newest line is the one that was edited, so the bottom is
        // where the reader was and still is.
        jumpToLatest();
        focusComposer();
        return;
      }
      const edit = messagesContainerEl?.querySelector<HTMLElement>(
        `[data-msg-id="${id}"] .bubble-edit-btn`,
      );
      if (edit) edit.focus();
      else focusComposer();
    });
  }

  function closeEditor(id: number) {
    cancelEdit();
    restoreFocusAfterEdit(id);
  }

  async function commitEdit(msg: ConvMessage) {
    const channel = channelId;
    const text = editDraft.trim();
    if (!channel || editBusy) return;
    if (!text || text === msg.message) {
      closeEditor(msg.id);
      return;
    }
    // Same UTF-8 byte guard `handleSend` applies, for the same reason: the
    // textarea's `maxlength` counts characters and the backend counts bytes, so
    // an emoji-heavy revision passed here and came back as a generic failure with
    // nothing to tell the user which limit they had hit.
    // A revised reply keeps its signed reference, which counts against the cap.
    const maxBytes = MAX_MESSAGE_BYTES - (msg.reply_to ? REPLY_REFERENCE_BYTES : 0);
    if (new TextEncoder().encode(text).length > maxBytes) {
      editError = m.chat_message_too_long({ max: maxBytes });
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
        closeEditor(msg.id);
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
      closeEditor(msg.id);
      return;
    }
    if (e.key === 'Enter' && !e.shiftKey && !isComposing(e)) {
      e.preventDefault();
      void commitEdit(msg);
    }
  }

  /** An IME is mid-composition: its Enter commits the candidate, and treating
   *  it as "send" would post half a word. 229 covers WebKit, which reports the
   *  keydown that ends a composition with `isComposing` already false. */
  function isComposing(e: KeyboardEvent): boolean {
    return e.isComposing || e.keyCode === 229;
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
      // A toast, not the composer's banner: that one is about the line being
      // written and stays until the next send.
      if (channel === channelId) toastError(translateError(e, m.error_operation_failed()));
    } finally {
      reactionBusy = null;
    }
  }

  interface ReactionChip {
    code: number;
    count: number;
    members: string[];
  }

  /**
   * The chips under one line. On someone else's line the quick three are always
   * there to press (zero counts included, shown on hover until anyone reacts),
   * followed by whatever else has been picked; on our own line, which we cannot
   * react to, only reactions somebody holds.
   */
  function reactionChips(tally: ChannelReactionInfo | undefined, ownMessage: boolean): ReactionChip[] {
    const held = new Map<number, ChannelReactionTally>(
      (tally?.reactions ?? []).map((t) => [t.reaction, t]),
    );
    const chip = (code: number): ReactionChip => ({
      code,
      count: held.get(code)?.count ?? 0,
      members: held.get(code)?.members ?? [],
    });
    const quick = QUICK_REACTIONS.map(chip);
    const rest = (tally?.reactions ?? [])
      .filter((t) => !QUICK_REACTIONS.includes(t.reaction) && curatedReaction(t.reaction))
      .map((t) => chip(t.reaction));
    const all = [...quick, ...rest];
    return ownMessage ? all.filter((c) => c.count > 0) : all;
  }

  /** "Heart: Ada, Bo and 3 others", or just "Heart" while nobody holds it.
   *  Ignored members are counted among the others, never named. */
  function reactionChipLabel(chip: ReactionChip): string {
    const name = curatedReaction(chip.code)?.label() ?? '';
    if (chip.count === 0) return name;
    const names = formatReactors(
      visibleReactors(chip.members, ignoredSet).map((key) => senderLabel(key)),
      chip.count,
    );
    return m.channels_reaction_by({ reaction: name, names });
  }

  function openPicker(msg: ConvMessage, trigger: HTMLElement) {
    if (!msg.msg_id || msg.direction === 'sent' || reactionBusy !== null) return;
    if (picker?.msg.msg_id === msg.msg_id) {
      closePicker(true);
      return;
    }
    const mine = reactions[msg.msg_id]?.mine ?? REACTION_NONE;
    const at = CURATED_REACTIONS.findIndex((r) => r.code === mine);
    pickerIndex = at >= 0 ? at : 0;
    pickerPos = null;
    picker = { msg: { ...msg, msg_id: msg.msg_id }, trigger };
  }

  function closePicker(restoreFocus: boolean) {
    const trigger = picker?.trigger;
    picker = null;
    pickerPos = null;
    if (restoreFocus && trigger?.isConnected) trigger.focus();
  }

  function choosePickedReaction(code: number) {
    const msg = picker?.msg;
    closePicker(true);
    if (msg) void toggleReaction(msg, code);
  }

  function placePicker() {
    if (!picker || !pickerEl) return;
    if (!picker.trigger.isConnected) {
      closePicker(false);
      return;
    }
    const { left, top } = resolvePickerPlacement(
      picker.trigger.getBoundingClientRect(),
      { width: pickerEl.offsetWidth, height: pickerEl.offsetHeight },
      { width: window.innerWidth, height: window.innerHeight },
    );
    pickerPos = { left, top };
  }

  function focusPickerItem(index: number) {
    pickerIndex = index;
    pickerEl?.querySelectorAll<HTMLButtonElement>('.reaction-picker-item')[index]?.focus();
  }

  /** Attached natively by the picker's effect; see there for why. */
  function onPickerKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      // The picker, and nothing behind it: the room page and the dock both
      // answer Escape further up, and one press should close one thing.
      e.preventDefault();
      e.stopPropagation();
      closePicker(true);
      return;
    }
    if (e.key === 'Tab') {
      // The grid sits at the end of <body>, so Tab would leave for nowhere
      // useful. Hand focus back to the line it was opened from instead.
      e.preventDefault();
      e.stopPropagation();
      closePicker(true);
      return;
    }
    const next = gridMove(pickerIndex, e.key, REACTION_GRID_COLUMNS, CURATED_REACTIONS.length);
    if (next !== null) {
      e.preventDefault();
      e.stopPropagation();
      focusPickerItem(next);
    }
  }

  // Placed once it has a size, then kept beside its trigger while the
  // transcript scrolls or the window resizes. Outside presses close it, and so
  // does focus leaving it by keyboard.
  $effect(() => {
    if (!picker || !pickerEl) return;
    const panel = pickerEl;
    placePicker();
    const index = untrack(() => pickerIndex);
    void tick().then(() => focusPickerItem(index));
    const trigger = picker.trigger;
    // Native, on the panel itself, not `onkeydown` in the markup. The panel is
    // portalled out of the component tree, so Svelte's delegated handler would
    // run from its listener on `document` — the same node the room page
    // listens on for Escape, where `stopPropagation` can no longer keep the
    // page's handler from closing its panes too. Stopped here, the event never
    // reaches `document` at all.
    const onKeyDown = (e: KeyboardEvent) => onPickerKeydown(e);
    const onFocusOut = (e: FocusEvent) => {
      const next = e.relatedTarget as Node | null;
      // Null is focus going nowhere in particular — a press on bare page,
      // which the pointer handler below already deals with, or the window
      // losing focus, which is no reason to close.
      if (!picker || !next) return;
      if (panel.contains(next) || trigger.contains(next)) return;
      closePicker(false);
    };
    panel.addEventListener('keydown', onKeyDown);
    panel.addEventListener('focusout', onFocusOut);
    const onPointerDown = (e: PointerEvent) => {
      const target = e.target as Node | null;
      if (!picker || !target) return;
      if (pickerEl?.contains(target) || picker.trigger.contains(target)) return;
      closePicker(false);
      // A press on something focusable keeps the focus it just took; a press
      // on bare transcript would otherwise leave focus on <body>.
      setTimeout(() => {
        const active = document.activeElement;
        if ((!active || active === document.body) && trigger.isConnected) trigger.focus();
      }, 0);
    };
    const onReflow = () => placePicker();
    document.addEventListener('pointerdown', onPointerDown, true);
    window.addEventListener('resize', onReflow);
    window.addEventListener('scroll', onReflow, true);
    return () => {
      panel.removeEventListener('keydown', onKeyDown);
      panel.removeEventListener('focusout', onFocusOut);
      document.removeEventListener('pointerdown', onPointerDown, true);
      window.removeEventListener('resize', onReflow);
      window.removeEventListener('scroll', onReflow, true);
    };
  });

  function senderLabel(pubkey?: string): string {
    if (!pubkey) return '';
    return memberNames[pubkey] || shortPubkey(pubkey);
  }

  $effect(() => {
    if (!chatInputEl || youAreBanned || youAreKeyBehind) return;
    // Not out from under an open dialog, which keeps focus inside itself.
    const raf = requestAnimationFrame(() => {
      if (document.querySelector('[aria-modal="true"]')) return;
      chatInputEl?.focus();
    });
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
          const edited = event.payload.msg_id;
          messages = messages.map((msg) => {
            if (msg.msg_id === edited || msg.id === event.payload.id) {
              return { ...msg, message: event.payload.message, edited_at: event.payload.edited_at };
            }
            // A reply whose parent is paged out quotes the backend's snapshot,
            // which would otherwise keep the words the parent no longer says.
            if (edited && msg.reply_to === edited && msg.reply_parent) {
              return { ...msg, reply_parent: { ...msg.reply_parent, excerpt: event.payload.message } };
            }
            return msg;
          });
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
      sendSeq++;
      sending = false;
      inputText = getDraft(key);
      if (channel) {
        loadRoomDraft(channel);
      } else {
        roomDraftSeq++;
        roomDraftReady = null;
      }
      // Channel unread is cleared only after `markAsRead` succeeds. Clearing
      // the badge here raced a `refreshChannels` that still saw unread rows
      // and put the count back — or hid a room that was never actually marked.
      if (channel) {
        // Say which room is on screen, so a line arriving in it does not raise
        // a badge or a toast for something the reader is looking at. The page
        // and the dock can both be showing it, which is why this counts rather
        // than sets.
        releaseChannelOnScreen?.();
        releaseChannelOnScreen = noteChannelOnScreen(channel);
      } else {
        activeChatHash.set(friend);
      }
      const gen = ++loadGen;
      if (unlisten) { unlisten(); unlisten = null; }
      if (unlistenDelivery) { unlistenDelivery(); unlistenDelivery = null; }
      if (unlistenTyping) { unlistenTyping(); unlistenTyping = null; }
      if (unlistenRead) { unlistenRead(); unlistenRead = null; }
      if (unlistenAttach) { unlistenAttach(); unlistenAttach = null; }
      messages = [];
      attachments = [];
      earlyDeliveredIds.clear();
      loadError = null;
      liveError = false;
      loading = true;
      loadingOlder = false;
      hasMoreHistory = false;
      olderError = false;
      oldestDbId = null;
      unreadMarkerId = null;
      markerResolved = false;
      unreadDividerSeen = false;
      unreadDividerAbove = false;
      // Scroll position belongs to the conversation being left, not the one
      // being opened: `loadMessages` lands this one where the reader last
      // left it, or else on its own unread marker or at the bottom.
      scrolledAway = false;
      missedWhileAway = false;
      scrollSpotReady = false;
      if (scrollSpotFrame) {
        cancelAnimationFrame(scrollSpotFrame);
        scrollSpotFrame = 0;
      }
      // A jump asked for in the room being left means nothing in this one.
      queuedFocus = null;
      focusedId = null;
      if (focusTimer) {
        clearTimeout(focusTimer);
        focusTimer = null;
      }
      // Reactions and any half-finished edit belong to the room being left.
      reactionSeq++;
      reactions = {};
      picker = null;
      pickerPos = null;
      emojiOpen = false;
      cancelEdit();
      // A pending reply is per room, like the draft restored above.
      replyTarget = channel ? getPendingReply(channel) : null;
      removedMsgIds = new Set();
      if (channel) void refreshReactions();
      (async () => {
        try {
          const listenerOk = await setupListener(gen, friend, channel);
          if (gen !== loadGen) return;
          await loadMessages(gen, friend, channel);
          if (gen === loadGen) liveError = !listenerOk;
          // Friends only: rooms have their own transfer system.
          if (!channel && gen === loadGen) await setupAttachments(gen, friend);
        } finally {
          if (gen === loadGen) loading = false;
        }
        // After the load, not alongside it. Both are IPC round trips, so
        // running them together raced: clearing `read` in the database first
        // meant the snapshot came back with nothing unread and the divider had
        // nothing to sit above. The badge waits for this to succeed.
        if (gen === loadGen) void markAsRead();
      })();
    }
    return () => {
      loadGen++;
      if (unlisten) { unlisten(); unlisten = null; }
      if (unlistenDelivery) { unlistenDelivery(); unlistenDelivery = null; }
      if (unlistenTyping) { unlistenTyping(); unlistenTyping = null; }
      if (unlistenRead) { unlistenRead(); unlistenRead = null; }
      if (unlistenAttach) { unlistenAttach(); unlistenAttach = null; }
      if (key) setDraft(key, inputText);
      flushRoomDraft();
      releaseChannelOnScreen?.();
      releaseChannelOnScreen = null;
      if (!channel) {
        if (lastTypingSentOn) {
          lastTypingSentOn = false;
          void sendChatTyping(friend, false).catch(() => {});
        }
        activeChatHash.set(null);
      } else {
        stopRoomTyping();
      }
      friendTyping = false;
      if (typingHoldTimer) {
        clearTimeout(typingHoldTimer);
        typingHoldTimer = null;
      }
      clearRoomTypists();
    };
  });

  // Saved on request as well as on the way out: popping the chat into its own
  // window, or docking it back, hands the drafts over while this is mounted.
  $effect(() => {
    const key = conversationKey;
    if (!key) return;
    return registerDraftFlusher(() => {
      setDraft(key, inputText);
      flushRoomDraft();
    });
  });

  // A room's draft also outlives a restart, sealed with the chat key on disk.
  // Friend drafts stay in memory only (see `chatTabs`).
  const ROOM_DRAFT_SAVE_MS = 600;
  /** The room whose stored draft has been read. Until then the composer is not
   *  written back, or the empty box of a room just opened would erase the copy
   *  on disk before it had loaded. */
  let roomDraftReady = $state<string | null>(null);
  let roomDraftSeq = 0;
  let roomDraftSaved = '';
  let roomDraftPending: { channel: string; text: string } | null = null;
  let roomDraftTimer: ReturnType<typeof setTimeout> | null = null;

  function flushRoomDraft() {
    if (roomDraftTimer) {
      clearTimeout(roomDraftTimer);
      roomDraftTimer = null;
    }
    const pending = roomDraftPending;
    roomDraftPending = null;
    if (pending) void setChannelDraft(pending.channel, pending.text).catch(() => {});
  }

  /** Drop a room's stored draft now, and any write of it still waiting, so a
   *  line just sent cannot come back as a draft after a restart. */
  function discardRoomDraft(channel: string) {
    if (roomDraftPending?.channel === channel) {
      roomDraftPending = null;
      if (roomDraftTimer) {
        clearTimeout(roomDraftTimer);
        roomDraftTimer = null;
      }
    }
    if (roomDraftReady === channel) roomDraftSaved = '';
    void setChannelDraft(channel, '').catch(() => {});
  }

  function loadRoomDraft(channel: string) {
    const seq = ++roomDraftSeq;
    roomDraftReady = null;
    void getChannelDraft(channel)
      .catch(() => '')
      .then((stored) => {
        if (seq !== roomDraftSeq || channelId !== channel) return;
        // Text already in the box is newer: typed since opening, or kept in
        // memory from earlier this session.
        if (!inputText && stored) inputText = stored;
        roomDraftSaved = stored;
        roomDraftReady = channel;
      });
  }

  $effect(() => {
    const channel = channelId;
    const text = inputText;
    if (!channel || roomDraftReady !== channel || text === roomDraftSaved) return;
    roomDraftSaved = text;
    roomDraftPending = { channel, text };
    if (roomDraftTimer) clearTimeout(roomDraftTimer);
    roomDraftTimer = setTimeout(flushRoomDraft, ROOM_DRAFT_SAVE_MS);
  });

  async function setupListener(gen: number, hash: string, channel: string): Promise<boolean> {
    if (gen !== loadGen) return false;
    if (unlisten) { unlisten(); unlisten = null; }
    if (unlistenDelivery) { unlistenDelivery(); unlistenDelivery = null; }
    if (unlistenTyping) { unlistenTyping(); unlistenTyping = null; }
    if (unlistenRead) { unlistenRead(); unlistenRead = null; }
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
          // Set when the line first reached us as a revision, which is how
          // catch-up serves one that was edited before we ever saw it.
          edited_at?: number;
          reply_to?: string | null;
          reply_to_me?: boolean;
          reply_parent?: ChannelReplyParent | null;
          reply_parent_deleted?: boolean;
        }>('ember:channel-message', (event) => {
          if (gen !== loadGen) return;
          if (event.payload.channel_id !== channel) return;
          if (messages.some((mm) => mm.id === event.payload.id)) return;
          // The line they were composing has landed, so they are not typing it
          // any more — whether or not a stop ever reaches us.
          if (event.payload.direction === 'received') {
            roomTypists = dropTypist(roomTypists, event.payload.sender_pubkey);
          }
          const wasPinned = isPinnedToBottom();
          const next: ConvMessage[] = [...messages, {
            id: event.payload.id,
            direction: event.payload.direction === 'sent' ? 'sent' : 'received',
            message: event.payload.message,
            timestamp: event.payload.timestamp,
            read: true,
            delivery: 'delivered',
            seen: false,
            sender_pubkey: event.payload.sender_pubkey,
            edited_at: event.payload.edited_at ?? 0,
            msg_id: event.payload.msg_id,
            reply_to: event.payload.reply_to ?? null,
            reply_to_me: event.payload.reply_to_me === true,
            reply_parent: event.payload.reply_parent ?? null,
            reply_parent_deleted: event.payload.reply_parent_deleted === true,
          }];
          commitLiveMessages(next, event.payload.direction === 'sent' || wasPinned);
          noteMissedMessage(wasPinned, event.payload.direction);
          // Not while the open is still seeking back for the first unread line:
          // clearing `read` now would stop that seek short and misplace the
          // divider. The read after the load covers this line too.
          if (event.payload.direction === 'received' && isAppVisible() && markerResolved) {
            markAsRead();
          }
        });
      } catch (e) {
        console.warn('ChatConversation: failed to register channel listener', e);
        return false;
      }
      if (gen !== loadGen) { fn(); return false; }
      unlisten = fn;
      // Its own registration, after the message listener is already stored:
      // sharing the `try` above meant a failure here returned without ever
      // unlistening the one that had already succeeded. Non-fatal for the same
      // reason the friend pane's delivery listener is — bubbles keep the state
      // they loaded with until the pane is reopened.
      try {
        const deliveryFn = await listen<{
          channel_id: string;
          id: number;
          delivery: string;
        }>('ember:channel-delivery', (event) => {
          if (gen !== loadGen) return;
          if (event.payload.channel_id !== channel) return;
          const delivery = event.payload.delivery;
          if (delivery !== 'delivered' && delivery !== 'queued' && delivery !== 'failed') return;
          messages = messages.map((message) =>
            message.id === event.payload.id ? { ...message, delivery } : message,
          );
        });
        if (gen !== loadGen) deliveryFn();
        else unlistenDelivery = deliveryFn;
      } catch (e) {
        console.warn('ChatConversation: failed to register channel delivery listener', e);
      }
      // Per open room rather than in a store: an indicator means nothing for a
      // room nobody is looking at, and the backend has already checked the
      // signature, the roster, the ban list and the clock.
      try {
        const typingFn = await listen<{
          channel_id: string;
          member_pubkey: string;
          typing: boolean;
        }>('ember:channel-typing', (event) => {
          if (gen !== loadGen) return;
          if (event.payload.channel_id !== channel) return;
          const now = Date.now();
          roomTypists = event.payload.typing
            ? noteTypist(roomTypists, event.payload.member_pubkey, now)
            : dropTypist(roomTypists, event.payload.member_pubkey);
          roomTypistsNow = now;
          scheduleRoomTypistsExpiry();
        });
        if (gen !== loadGen) typingFn();
        else unlistenTyping = typingFn;
      } catch (e) {
        console.warn('ChatConversation: failed to register channel typing listener', e);
      }
      return true;
    }
    let fn: UnlistenFn;
    try {
      fn = await listen<{ user_hash: string; id?: number; message: string; direction: string; timestamp: number }>('ember:chat-message', (event) => {
        if (gen !== loadGen) return;
        if ((event.payload.user_hash || '').toLowerCase() !== (hash || '').toLowerCase()) return;
        // Narrow the direction rather than asserting it (as `stores/friends.ts`
        // does): an unrecognised value would otherwise be cast straight into a
        // bubble while skipping the dedup and unread paths, both of which
        // branch on it being exactly 'sent' or 'received'.
        const direction: 'sent' | 'received' | null =
          event.payload.direction === 'sent'
            ? 'sent'
            : event.payload.direction === 'received'
              ? 'received'
              : null;
        if (direction === null) return;
          // Dedup duplicate backend emits: inbound chat can be delivered on
          // both the download and upload event loops for the same logical
          // message.
          //
          // By durable row id when there is one, because it names the row: a
          // re-emit is caught exactly and two distinct messages never collide.
          // That holds for the outbound echo too — a snapshot taken after the
          // row was marked delivered already holds it. The content tuple below
          // cannot manage that — its timestamp is whole seconds, so a friend
          // sending the same word twice inside one second produced one
          // signature and the second bubble was dropped for good. `handleSend`
          // renders nothing for a delivered message and relies on this echo, so
          // there was nothing to reveal it short of a reload. The tuple stays
          // as the fallback for an inbound emit that carries no id; the
          // outbound echo has a single emit site, so a tuple match there could
          // only ever collapse two real messages.
          const durableId = event.payload.id;
          const hasDurableId = typeof durableId === 'number' && durableId > 0;
          if (hasDurableId) {
            const at = messages.findIndex((mm) => mm.id === durableId);
            if (at !== -1) {
              if (messages[at].delivery === 'queued') {
                const next = [...messages];
                next[at] = { ...next[at], delivery: 'delivered' };
                messages = next;
              }
              return;
            }
          } else if (direction === 'received') {
            const sig = `${event.payload.timestamp}|${direction}|${event.payload.message}`;
            if (
              messages
                .slice(-5)
                .some((mm) => `${mm.timestamp}|${mm.direction}|${mm.message}` === sig)
            ) {
              return;
            }
          }
          if (direction === 'received') setFriendTyping(false);
          const wasPinned = isPinnedToBottom();
          const next = [...messages, {
            id: hasDurableId ? durableId : --msgIdCounter,
            direction,
            message: event.payload.message,
            timestamp: event.payload.timestamp,
            read: true,
            delivery: 'delivered' as const,
            seen: false,
          }];
          commitLiveMessages(next, direction === 'sent' || wasPinned);
          noteMissedMessage(wasPinned, direction);
          // Only acknowledge what the user can actually see. A mounted
          // conversation in a minimized window would otherwise mark the
          // message read and suppress its badge, losing it entirely. Held
          // until the unread divider is placed, as in the room listener.
          if (direction === 'received' && isAppVisible() && markerResolved) {
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

    try {
      const typingFn = await listen<{ user_hash: string; typing: boolean }>(
        'ember:chat-typing',
        (event) => {
          if (gen !== loadGen) return;
          if ((event.payload.user_hash || '').toLowerCase() !== (hash || '').toLowerCase()) return;
          setFriendTyping(event.payload.typing);
        },
      );
      if (gen !== loadGen) { typingFn(); return true; }
      unlistenTyping = typingFn;
    } catch (e) {
      console.warn('ChatConversation: failed to register typing listener', e);
    }

    try {
      const readFn = await listen<{ user_hash: string; until_id: number }>(
        'ember:chat-read',
        (event) => {
          if (gen !== loadGen) return;
          if ((event.payload.user_hash || '').toLowerCase() !== (hash || '').toLowerCase()) return;
          const until = event.payload.until_id;
          if (typeof until !== 'number' || until <= 0) return;
          messages = messages.map((message) =>
            message.direction === 'sent'
            && message.id > 0
            && message.id <= until
            && message.delivery === 'delivered'
              ? { ...message, seen: true }
              : message,
          );
        },
      );
      if (gen !== loadGen) { readFn(); return true; }
      unlistenRead = readFn;
    } catch (e) {
      console.warn('ChatConversation: failed to register read-receipt listener', e);
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
        // A first page that is unread all the way to its oldest line does not
        // say where the reader left off — the boundary is further back. Page
        // back for it now rather than when the divider is wanted: `markAsRead`
        // runs as soon as this returns and clears the flags that would tell.
        // Bounded, because a room left for a month can hold thousands of
        // unread lines, and every page is DOM the transcript has to carry.
        for (let page = 0; page < UNREAD_SEEK_PAGES && hasMoreHistory; page++) {
          const oldest = messages[0];
          if (!oldest || oldest.direction !== 'received' || oldest.read) break;
          const before = oldestDbId;
          await loadOlderMessages();
          if (gen !== loadGen) return;
          if (oldestDbId === before) break;
        }
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
      const spot = conversationKey ? recalledScroll(conversationKey) : undefined;
      if (spot && (await restoreScrollSpot(gen, spot))) {
        // Back where the reader was, which is above anything new: the lines
        // that arrived since are all further down.
        if (unreadMarkerId !== null) missedWhileAway = true;
      } else {
        if (gen !== loadGen) return;
        if (unreadMarkerId !== null) scrollToUnreadMarker();
        else scrollToBottom(true);
      }
      // A frame after the landing's own, so its scroll is not taken for the
      // reader's.
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          if (gen === loadGen) scrollSpotReady = true;
        });
      });
    } catch (e: unknown) {
      if (gen !== loadGen) return;
      if (messages.length === 0) {
        const detail = translateError(e, '');
        loadError = detail ? m.chat_load_error({ error: detail }) : m.chat_failed_to_load();
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
    if (unlistenTyping) { unlistenTyping(); unlistenTyping = null; }
    if (unlistenRead) { unlistenRead(); unlistenRead = null; }
    if (unlistenAttach) { unlistenAttach(); unlistenAttach = null; }
    liveError = false;
    olderError = false;
    const listenerOk = await setupListener(gen, hash, channel);
    if (gen !== loadGen) return;
    await loadMessages(gen, hash, channel);
    if (gen === loadGen) liveError = !listenerOk;
    // The bumped generation silenced the old attachment listener along with
    // the rest, so it has to be registered again too.
    if (!channel && gen === loadGen) await setupAttachments(gen, hash);
    // Live lines held back while the first load had not placed the divider.
    if (gen === loadGen) void markAsRead();
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

  function setFriendTyping(on: boolean) {
    friendTyping = on;
    if (typingHoldTimer) {
      clearTimeout(typingHoldTimer);
      typingHoldTimer = null;
    }
    if (on) {
      typingHoldTimer = setTimeout(() => {
        friendTyping = false;
        typingHoldTimer = null;
      }, TYPING_HOLD_MS);
    }
  }

  function sendOutgoingTyping(on: boolean) {
    if (isChannel || !friendHash || chatDisabled || chatLocked) return;
    lastTypingSentOn = on;
    lastTypingSentAt = Date.now();
    void sendChatTyping(friendHash, on).catch(() => {});
  }

  /** Whether this device may tell the room it is composing. Slow mode counts:
   *  "typing" from someone who cannot send yet promises a line that is not
   *  coming. Visibility counts too, because the chat can be popped out into a
   *  window of its own that is minimised while its text stays put. So does an
   *  announcement-only room this member may not post in (`announceOnly` is
   *  already false for the owner and moderators). */
  function roomTypingAllowed(): boolean {
    return (
      isChannel &&
      !youAreBanned &&
      !youAreKeyBehind &&
      !chatLocked &&
      !announceOnly &&
      slowModeLeft === 0 &&
      isAppVisible()
    );
  }

  function sendRoomTyping(channel: string, on: boolean) {
    roomTypingSentOn = on;
    roomTypingSentAt = Date.now();
    roomTypingChannel = channel;
    void sendChannelTyping(channel, on).catch(() => {});
  }

  function notifyRoomTyping(text: string) {
    const action = outgoingTypingAction({
      hasText: text.trim().length > 0,
      allowed: roomTypingAllowed(),
      lastSentOn: roomTypingSentOn && roomTypingChannel === channelId,
      lastSentAt: roomTypingSentAt,
      now: Date.now(),
    });
    if (action) sendRoomTyping(channelId, action === 'start');
  }

  function stopRoomTyping() {
    if (roomTypingSentOn && roomTypingChannel) sendRoomTyping(roomTypingChannel, false);
  }

  function clearRoomTypists() {
    roomTypists = new Map();
    if (roomTypistsTimer) {
      clearTimeout(roomTypistsTimer);
      roomTypistsTimer = null;
    }
  }

  /** One timer for the soonest lapse, re-armed after each, so an idle room
   *  holds no interval at all. */
  function scheduleRoomTypistsExpiry() {
    if (roomTypistsTimer) {
      clearTimeout(roomTypistsTimer);
      roomTypistsTimer = null;
    }
    const soonest = nextTypistExpiry(roomTypists);
    if (soonest === null) return;
    roomTypistsTimer = setTimeout(() => {
      roomTypistsTimer = null;
      roomTypistsNow = Date.now();
      roomTypists = pruneTypists(roomTypists, roomTypistsNow);
      scheduleRoomTypistsExpiry();
    }, Math.max(0, soonest - Date.now()) + 50);
  }

  let roomTypingSegments = $derived(
    isChannel
      ? typingLineSegments(
          visibleTypists(roomTypists, roomTypistsNow, ignoredSenders).map((pk) => senderLabel(pk)),
          {
            one: (name) => m.channels_typing_one({ name }),
            two: (first, second) => m.channels_typing_two({ first, second }),
            several: () => m.channels_typing_several(),
          },
        )
      : [],
  );

  /** What the room's typing live region says. Separate from the visible line,
   *  which follows every typist; this only speaks when the room goes from
   *  nobody typing to somebody, and not more than once per gap. */
  let roomTypingAnnouncement = $state('');
  let roomTypingActive = $derived(roomTypingSegments.length > 0 && !loading && !loadError);
  let friendTypingShown = $derived(!isChannel && friendTyping && !loading && !loadError);
  /** Only a friend's typing starting is announced; one person, so no gap
   *  throttling is needed the way a busy room needs it. */
  let friendTypingAnnouncement = $derived(
    friendTypingShown ? m.chat_typing({ name: friendName || friendHash.slice(0, 8) }) : '',
  );
  let typingPillShown = $derived(isChannel ? roomTypingActive : friendTypingShown);
  let roomTypingWasActive = false;
  let roomTypingAnnouncedAt = -Infinity;

  $effect(() => {
    const active = roomTypingActive;
    untrack(() => {
      const now = Date.now();
      if (
        shouldAnnounceTyping({
          active,
          wasActive: roomTypingWasActive,
          lastAnnouncedAt: roomTypingAnnouncedAt,
          now,
        })
      ) {
        roomTypingAnnouncedAt = now;
        roomTypingAnnouncement = roomTypingSegments.map((segment) => segment.text).join('');
      } else if (!active) {
        // Emptied, so the next announcement is a change the reader hears.
        roomTypingAnnouncement = '';
      }
      roomTypingWasActive = active;
    });
  });

  function notifyOutgoingTyping(text = inputText) {
    if (isChannel) {
      notifyRoomTyping(text);
      return;
    }
    // The backend drops this when there is no live session. Gating on the
    // UI online set used to swallow composing entirely: that store can lag
    // the session (or miss a friend-online event), while chat still delivers.
    if (chatDisabled || chatLocked) return;
    const on = text.trim().length > 0;
    if (!on) {
      if (lastTypingSentOn) sendOutgoingTyping(false);
      return;
    }
    const now = Date.now();
    if (!lastTypingSentOn || now - lastTypingSentAt >= TYPING_REFRESH_MS) {
      sendOutgoingTyping(true);
    }
  }

  function stopOutgoingTyping() {
    if (isChannel) {
      stopRoomTyping();
      return;
    }
    if (lastTypingSentOn) sendOutgoingTyping(false);
  }

  $effect(() => {
    if (isOnline) return;
    // A typing packet is itself proof they are composing. Do not subscribe
    // to the hold timer here: writing it from `setFriendTyping` would
    // re-run this effect and immediately clear the indicator whenever the
    // UI still thought they were offline.
    untrack(() => {
      friendTyping = false;
      if (typingHoldTimer) {
        clearTimeout(typingHoldTimer);
        typingHoldTimer = null;
      }
    });
  });

  // Messages that arrived while the window was hidden were deliberately left
  // unread; clear them once the user actually comes back to the conversation.
  $effect(() => {
    if (typeof document === 'undefined') return;
    const onVisibilityChange = () => {
      // Mid-open is left to the read that follows the load, for the reason the
      // live listeners give.
      if (document.visibilityState === 'visible') {
        if (markerResolved) void markAsRead();
      } else {
        stopOutgoingTyping();
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  });

  function scrollToBottom(instant = false) {
    requestAnimationFrame(() => {
      messagesEnd?.scrollIntoView({ behavior: instant || prefersReducedMotion.current ? 'auto' : 'smooth' });
    });
  }

  /**
   * Land on the first message the reader has not seen rather than at the
   * bottom.
   *
   * Re-entering a busy room used to drop them at the newest line with nothing
   * saying where they had got to, so catching up meant scrolling up and
   * guessing. Falls back to the bottom if the marker row is not drawn — its
   * sender is ignored, say.
   */
  function scrollToUnreadMarker() {
    requestAnimationFrame(() => {
      const el = messagesContainerEl?.querySelector<HTMLElement>('.conv-unread-divider');
      if (el) el.scrollIntoView({ block: 'center' });
      else messagesEnd?.scrollIntoView();
      checkUnreadDivider();
    });
  }

  /**
   * Keep the "Jump to first unread" pill honest.
   *
   * Opening a conversation lands on the divider, so this is for the reader who
   * ends up below it without having seen it: a search hit or mention jump that
   * lands further down, or "Jump to latest" pressed straight away. Once the
   * divider has been on screen the pill is gone for good — it is a way back to
   * something missed, not a permanent control. Being *above* the divider (the
   * reader scrolled back past it) hides it too, since the way on is down.
   */
  function checkUnreadDivider() {
    if (unreadMarkerId === null || unreadDividerSeen) {
      unreadDividerAbove = false;
      return;
    }
    const box = messagesContainerEl;
    // Zero height means the pane is hidden (a collapsed dock), where every rect
    // reads as zero and "above the viewport" would be a guess.
    if (!box || box.clientHeight === 0) return;
    const divider = box.querySelector<HTMLElement>('.conv-unread-divider');
    if (!divider) {
      unreadDividerAbove = false;
      return;
    }
    const view = box.getBoundingClientRect();
    const at = divider.getBoundingClientRect();
    if (at.bottom <= view.top) {
      unreadDividerAbove = true;
    } else {
      if (at.top < view.bottom) unreadDividerSeen = true;
      unreadDividerAbove = false;
    }
  }

  function jumpToFirstUnread() {
    const divider = messagesContainerEl?.querySelector<HTMLElement>('.conv-unread-divider');
    if (!divider) {
      unreadDividerAbove = false;
      return;
    }
    divider.scrollIntoView({
      block: 'center',
      behavior: prefersReducedMotion.current ? 'auto' : 'smooth',
    });
  }

  function isPinnedToBottom(): boolean {
    const el = messagesContainerEl;
    if (!el) return true;
    return el.scrollHeight - (el.scrollTop + el.clientHeight) < 80;
  }

  function commitLiveMessages(next: ConvMessage[], pinToBottom: boolean): void {
    const trimmed = next.length > MAX_LIVE_MESSAGES;
    const el = messagesContainerEl;
    const prevScrollHeight = trimmed && !pinToBottom ? (el?.scrollHeight ?? 0) : 0;
    const prevScrollTop = trimmed && !pinToBottom ? (el?.scrollTop ?? 0) : 0;
    messages = trimmed ? next.slice(next.length - MAX_LIVE_MESSAGES) : next;
    if (trimmed) {
      // The cursor named a row that has just been dropped; paging on from it
      // would leave a gap between it and what is still loaded. Kept as it was
      // when the trim evicted every stored row.
      let oldestKept: number | null = null;
      for (const message of messages) {
        if (message.id > 0 && (oldestKept === null || message.id < oldestKept)) oldestKept = message.id;
      }
      if (oldestKept !== null) oldestDbId = oldestKept;
    }
    if (pinToBottom) {
      scrollToBottom();
    } else if (trimmed) {
      requestAnimationFrame(() => {
        if (!messagesContainerEl) return;
        messagesContainerEl.scrollTop =
          prevScrollTop + (messagesContainerEl.scrollHeight - prevScrollHeight);
      });
    }
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
    checkUnreadDivider();
    if (scrollSpotReady && !scrollSpotFrame) {
      scrollSpotFrame = requestAnimationFrame(() => {
        scrollSpotFrame = 0;
        if (scrollSpotReady) captureScrollSpot();
      });
    }
  }

  /** Off while a conversation is being opened and placed, when the scroll
   *  events are the empty transcript and the landing, not the reader. */
  let scrollSpotReady = false;
  let scrollSpotFrame = 0;
  /** Pages walked back to reach a remembered spot before giving up on it. */
  const SCROLL_RESTORE_PAGES = 10;

  function captureScrollSpot() {
    const key = conversationKey;
    const box = messagesContainerEl;
    // Zero height is a hidden pane, where every rect reads as zero.
    if (!key || !box || box.clientHeight === 0) return;
    if (isPinnedToBottom()) {
      rememberScroll(key, null);
      return;
    }
    const top = box.getBoundingClientRect().top;
    const rows = box.querySelectorAll<HTMLElement>('[data-msg-id]');
    const first = firstRowBelow((i) => rows[i].getBoundingClientRect().bottom, rows.length, top);
    // A line still being sent has no row id to come back to; the next one does.
    for (let i = first; i < rows.length; i++) {
      const id = Number(rows[i].dataset.msgId);
      if (id > 0) {
        rememberScroll(key, { id, offset: rows[i].getBoundingClientRect().top - top });
        return;
      }
    }
  }

  /** Page back to a remembered message and put it where it was. False when it
   *  cannot be reached or is not drawn, and the usual landing should run. */
  async function restoreScrollSpot(gen: number, spot: ScrollSpot): Promise<boolean> {
    for (
      let page = 0;
      page < SCROLL_RESTORE_PAGES && !messages.some((message) => message.id === spot.id);
      page++
    ) {
      const before = oldestDbId;
      if (before === null || before <= spot.id || !hasMoreHistory) break;
      await loadOlderMessages();
      if (gen !== loadGen) return false;
      if (oldestDbId === before) break;
    }
    if (!visibleMessages.some((message) => message.id === spot.id)) return false;
    await tick();
    if (gen !== loadGen) return false;
    // After the anchoring `loadOlderMessages` queues for itself, or it would
    // land on top of this.
    requestAnimationFrame(() => {
      const box = messagesContainerEl;
      const row = box?.querySelector<HTMLElement>(`[data-msg-id="${spot.id}"]`);
      if (gen !== loadGen || !box || !row || box.clientHeight === 0) return;
      box.scrollTop += row.getBoundingClientRect().top - box.getBoundingClientRect().top - spot.offset;
      scrolledAway = !isPinnedToBottom();
      checkUnreadDivider();
    });
    return true;
  }

  /** Unread lines below the reader that they have not reached yet: coming back
   *  to a remembered spot, or a jump that landed above the divider. */
  let unreadAhead = $derived(unreadMarkerId !== null && !unreadDividerSeen && !unreadDividerAbove);

  function jumpToLatest() {
    // To the first of them rather than past them. Once the divider has been on
    // screen the next press goes the rest of the way.
    const box = messagesContainerEl;
    const divider = unreadAhead ? box?.querySelector<HTMLElement>('.conv-unread-divider') : null;
    if (box && divider && divider.getBoundingClientRect().top >= box.getBoundingClientRect().bottom) {
      divider.scrollIntoView({
        block: 'start',
        behavior: prefersReducedMotion.current ? 'auto' : 'smooth',
      });
      return;
    }
    missedWhileAway = false;
    scrolledAway = false;
    scrollToBottom();
  }

  /** Note an incoming message the reader is not positioned to see. */
  function noteMissedMessage(wasPinned: boolean, direction: string) {
    if (!wasPinned && direction === 'received') missedWhileAway = true;
  }

  /** Merge one attachment into the list, by id. Returns whether it was new. */
  function upsertAttachment(next: ChatAttachment): boolean {
    const at = attachments.findIndex((a) => a.xfer_id === next.xfer_id);
    if (at === -1) {
      attachments = [...attachments, next];
      return true;
    }
    const prev = attachments[at];
    const merged = mergeChatAttachment(prev, next);
    if (merged === prev) return false;
    const copy = [...attachments];
    copy[at] = merged;
    attachments = copy;
    return false;
  }

  /**
   * Load this conversation's files and follow their progress.
   *
   * Listener first, then the list, so an update that lands between the two is
   * not lost; the list is merged rather than assigned for the same reason.
   */
  async function setupAttachments(gen: number, hash: string) {
    const friend = (hash || '').toLowerCase();
    try {
      const fn = await listen('ember:attach-update', (event) => {
        if (gen !== loadGen) return;
        const next = parseChatAttachment(event.payload);
        if (!next || next.user_hash !== friend) return;
        const wasPinned = isPinnedToBottom();
        const isNew = upsertAttachment(next);
        if (isNew) {
          if (wasPinned || next.direction === 'sent') scrollToBottom();
          else noteMissedMessage(false, next.direction);
        }
      });
      if (gen !== loadGen) {
        fn();
        return;
      }
      unlistenAttach = fn;
    } catch (e) {
      console.warn('ChatConversation: failed to register attachment listener', e);
    }
    try {
      const listed = await listChatAttachments(friend);
      if (gen !== loadGen) return;
      const wasPinned = isPinnedToBottom();
      for (const a of listed) upsertAttachment(a);
      if (wasPinned) scrollToBottom();
    } catch (e) {
      // Non-fatal: the conversation still works, it just opens without its
      // earlier files until it is reopened.
      console.warn('ChatConversation: failed to load attachments', e);
    }
  }

  async function sendAttachment() {
    if (attaching || isChannel || !friendHash) return;
    const friend = friendHash;
    attachingFor = [...attachingFor, friend];
    try {
      const sentOne = await pickAndSendChatAttachment(friend);
      // Another chat may be open by now. Its card loads with that friend's
      // attachment list when their chat is next opened.
      if (sentOne && friendHash === friend) {
        upsertAttachment(sentOne);
        scrollToBottom();
      }
    } catch (e) {
      toastError(translateError(e));
    } finally {
      attachingFor = attachingFor.filter((hash) => hash !== friend);
      if (friendHash === friend) chatInputEl?.focus();
    }
  }

  /** The message a search hit pointed at, marked briefly so the eye can find
   *  it after the jump. */
  let focusedId = $state<number | null>(null);
  let focusing = false;
  /** A hit picked while an earlier jump is still paging. Held rather than
   *  dropped, and run after: two jumps interleaved would each see the other's
   *  `loadOlderMessages` as "no progress" and wrongly report the message gone.
   *  Carries the conversation it was asked in, since ids are per conversation. */
  let queuedFocus: { id: number; opts: FocusOptions; gen: number } | null = null;
  let focusTimer: ReturnType<typeof setTimeout> | null = null;
  const FOCUS_MARK_MS = 2600;

  interface FocusOptions {
    /** Older pages this jump may load before calling the message unreachable.
     *  Unset means as far as the in-memory cap allows. */
    maxPages?: number;
    /** Instead of `onfocusmissing`, whose wording is the search's. */
    onMissing?: () => void;
  }

  /**
   * Bring a stored message into view, paging history back until it is loaded.
   *
   * History only pages backwards, so the way to reach an old message is to walk
   * the same cursor "Load older" uses until it comes into range. That keeps the
   * transcript one continuous run rather than stranding the user in a window
   * with no path back to the live tail. Local SQLite, so the round trips are
   * cheap; the in-memory cap still bounds how far back it can go.
   */
  async function focusMessage(id: number, opts: FocusOptions = {}) {
    if (id <= 0) return;
    if (focusing) {
      queuedFocus = { id, opts, gen: loadGen };
      return;
    }
    const gen = loadGen;
    focusing = true;
    const missing = opts.onMissing ?? onfocusmissing;
    let pagesLoaded = 0;
    try {
      while (!messages.some((message) => message.id === id)) {
        const before = oldestDbId;
        if (opts.maxPages !== undefined && pagesLoaded >= opts.maxPages) break;
        // Already paged past it: the row is not in this conversation's stored
        // history any more (removed locally, or trimmed by the live cap).
        if (before === null || before <= id) break;
        if (!hasMoreHistory || messages.length >= MAX_LOADED_MESSAGES) break;
        // A page already in flight makes `loadOlderMessages` a no-op, so calling
        // it would leave `oldestDbId` unmoved and the check below would read that
        // as "no more history" — reporting the message missing when it was about
        // to arrive. Wait for the page that is already running instead.
        //
        // Bounded, because this is the one loop here whose exit depends on a flag
        // some other call has to clear. The conversation-switch effect resets
        // `loadingOlder`, so it cannot currently be stranded — but a jump that
        // gives up after a couple of seconds is a wrong answer, and one that spins
        // is a wedged tab.
        for (let waited = 0; loadingOlder && waited < 40; waited++) {
          await new Promise((resolve) => setTimeout(resolve, 50));
          if (gen !== loadGen) return;
        }
        if (messages.some((message) => message.id === id)) break;
        if (loadingOlder) break;
        if (oldestDbId !== before) continue;
        await loadOlderMessages();
        pagesLoaded++;
        if (gen !== loadGen) return;
        // No progress means the page came back empty or the cap kicked in;
        // without this the loop would spin on an unreachable id.
        if (oldestDbId === before) break;
      }
      if (gen !== loadGen) return;
      // Loaded is not the same as drawn: an ignored sender's message stays in
      // `messages` but never reaches the DOM, and scrolling to it would do
      // nothing at all. Report it rather than appear to ignore the click.
      if (!visibleMessages.some((message) => message.id === id)) {
        missing?.();
        return;
      }
      focusedId = id;
      await tick();
      if (gen !== loadGen) return;
      // After the render, and after the scroll anchoring `loadOlderMessages`
      // queues for itself — otherwise that restore lands on top of this jump.
      requestAnimationFrame(() => {
        messagesContainerEl
          ?.querySelector(`[data-msg-id="${id}"]`)
          ?.scrollIntoView({
            block: 'center',
            behavior: prefersReducedMotion.current ? 'auto' : 'smooth',
          });
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
      if (next !== null && next.gen === loadGen && next.id !== id) {
        void focusMessage(next.id, next.opts);
      }
    }
  }

  /** Follow a reply's quote to the line it answers. */
  function jumpToReplyParent(id: number) {
    void focusMessage(id, {
      maxPages: REPLY_SEEK_PAGES,
      onMissing: () => toast(m.channels_reply_unavailable()),
    });
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
          seen: false,
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
   * How long a room line may sit unconfirmed before the bubble says so.
   *
   * A send is written queued and the flood usually settles it within a tick,
   * so captioning that moment would put "Sending…" under every message the
   * user writes and make the normal case look like a fault. Past this, the
   * line really is waiting on somebody to carry it, which is worth saying.
   * The failed caption is not delayed — that one is already the slow path.
   */
  const CHANNEL_PENDING_GRACE_MS = 2000;
  let pendingClockNow = $state(Date.now());

  $effect(() => {
    if (!isChannel) return;
    // Only ticks while something is actually unconfirmed, so a settled room
    // costs nothing.
    if (!messages.some((msg) => msg.direction === 'sent' && msg.delivery === 'queued')) return;
    const timer = setInterval(() => {
      pendingClockNow = Date.now();
    }, 500);
    return () => clearInterval(timer);
  });

  /** Whether an unconfirmed line has waited long enough to be worth reporting. */
  function sendLooksStuck(msg: ConvMessage): boolean {
    if (msg.delivery !== 'queued' || msg.direction !== 'sent') return false;
    if (msg.timestamp <= 0) return true;
    return pendingClockNow - msg.timestamp * 1000 >= CHANNEL_PENDING_GRACE_MS;
  }

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
      // After the send, as on the room path: a delete that failed first
      // would lose the text outright if the resend failed too.
      if (msg.id > 0) {
        await discardFailedChatMessage(h, msg.id).catch((e) =>
          console.warn('ChatConversation: could not drop the abandoned message', e),
        );
      }
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

  /**
   * Send a room line the flood never placed again.
   *
   * Safe to mint a fresh `msg_id` — which `sendChannelMessage` does — only
   * because "failed" here means no rung took it: no neighbour, no overlay hop,
   * no relay. Nobody holds the original, so there is no copy for a new id to
   * duplicate. The local row goes first for the same reason the friend path
   * drops its bubble: each attempt is a new row, and keeping both would show
   * the same sentence twice.
   */
  async function resendChannelMessage(msg: ConvMessage) {
    const channel = channelId;
    if (!channel || sending || resendingId !== null) return;
    if (youAreBanned || youAreKeyBehind) return;
    const at = messages.findIndex((message) => message.id === msg.id);
    if (at === -1) return;
    const restore = messages[at];
    resendingId = msg.id;
    sendError = null;
    messages = messages.filter((message) => message.id !== msg.id);
    try {
      // Send before dropping the old row, not after. The other order lost the
      // user's text outright when the retry also failed: the bubble was put
      // back on screen against a row already deleted, so reloading the
      // transcript dropped it. A delete that fails after a successful send
      // leaves a visible duplicate instead, which is recoverable.
      const sent = await sendChannelMessage(channel, restore.message, restore.reply_to);
      await deleteChannelMessage(channel, msg.id).catch((e) =>
        console.warn('ChatConversation: could not drop the abandoned room line', e),
      );
      if (channel === channelId) {
        commitLiveMessages([...messages, fromChannelRow(sent)], true);
      }
    } catch (e: unknown) {
      if (channel === channelId) {
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
    const channel = channelId;
    const reply = channel ? replyTarget : null;
    // Guard on UTF-8 byte length to match the backend's limit. `maxlength`
    // only caps characters, so a message of multi-byte glyphs (emoji, CJK)
    // can be under 4096 chars yet over 4096 bytes and be rejected server-side
    // with a generic error. A reply's signed reference rides in the same 4096.
    const maxBytes = MAX_MESSAGE_BYTES - (reply ? REPLY_REFERENCE_BYTES : 0);
    if (new TextEncoder().encode(text).length > maxBytes) {
      sendError = m.chat_message_too_long({ max: maxBytes });
      return;
    }
    const waitSecs = slowModeSecs;
    const h = friendHash;
    const key = conversationKey;
    const seq = ++sendSeq;
    sending = true;
    sendError = null;
    if (channel) {
      // The line landing takes the indicator down on every receiver, so a stop
      // here would only spend a datagram per member. The next keystroke starts
      // a fresh one.
      roomTypingSentOn = false;
    } else {
      stopOutgoingTyping();
    }
    try {
      if (channel) {
        const sent = await sendChannelMessage(channel, text, reply?.msgId);
        // Only the reply this send carried: one chosen while it was in flight
        // is a new intention, not this message's.
        if (reply && getPendingReply(channel)?.msgId === reply.msgId) setPendingReply(channel, null);
        if (channel === channelId) {
          if (!messages.some((message) => message.id === sent.id)) {
            messages = [...messages, fromChannelRow(sent)];
          }
          if (reply && replyTarget?.msgId === reply.msgId) replyTarget = null;
          inputText = '';
          scrollToBottom();
          if (waitSecs > 0) {
            nextSendAt = Date.now() + waitSecs * 1000;
            slowModeNow = Date.now();
          }
        }
        clearDraft(key);
        discardRoomDraft(channel);
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
      const failed = translateError(e, m.chat_failed_to_send());
      if (channel) {
        // The backend carries the seconds still owed in the error's context, so
        // a refusal starts the same countdown a successful send would — which
        // covers the cases this side cannot predict, like another device of
        // ours having posted, or a clock that disagrees.
        const coded = codedErrorOf(e);
        if (coded?.code === 'channels_slow_mode') {
          const remaining = Number(coded.context);
          if (Number.isFinite(remaining) && remaining > 0 && channel === channelId) {
            nextSendAt = Date.now() + remaining * 1000;
            slowModeNow = Date.now();
          }
        }
        // The parent is no longer here to answer. Drop the reply so the text,
        // still in the composer, can go as a plain line on the next press.
        if (coded?.code === 'channels_reply_target_invalid' && reply) {
          setPendingReply(channel, null);
          if (channel === channelId && replyTarget?.msgId === reply.msgId) replyTarget = null;
        }
        if (channel === channelId) sendError = failed;
        else toastError(failed);
      } else if (h === friendHash) {
        sendError = failed;
      } else {
        toastError(failed);
      }
    } finally {
      // A switch already released the composer for the next conversation, and
      // a send started there owns it now.
      if (seq === sendSeq) sending = false;
      // A disabled/readonly composer (and a clicked Send button) drop the
      // caret; put it back so the next message can be typed without a click.
      const stillHere = channel ? channel === channelId : h === friendHash;
      if (stillHere) {
        void tick().then(() => focusComposer());
      }
    }
  }

  function focusComposer() {
    if (youAreBanned || youAreKeyBehind || chatDisabled || chatLocked) return;
    const el = chatInputEl;
    if (!el || el.disabled) return;
    el.focus();
  }

  /** The raw text, markers and all: formatting is only how it is drawn, and
   *  pasting it into another Ember (or anything Markdown-aware) keeps it. */
  async function copyMessageText(msg: ConvMessage) {
    if (await copyToClipboard(msg.message)) toastSuccess(m.chat_copied_text());
    else toastError(m.chat_copy_failed());
  }

  /** Which code block just reported "Copied", as `msgId:blockIndex`. */
  let copiedCodeKey = $state<string | null>(null);
  let copiedCodeTimer: ReturnType<typeof setTimeout> | null = null;

  async function copyCodeBlock(key: string, text: string) {
    if (!(await copyToClipboard(text))) {
      toastError(m.chat_copy_failed());
      return;
    }
    copiedCodeKey = key;
    if (copiedCodeTimer) clearTimeout(copiedCodeTimer);
    copiedCodeTimer = setTimeout(() => {
      copiedCodeKey = null;
      copiedCodeTimer = null;
    }, 1500);
  }

  /** Composer formatting cheat-sheet. The dock and the rooms page can both
   *  mount a conversation, so its id has to be per instance. */
  let formatHelpOpen = $state(false);
  const formatSheetId = $props.id();
  let emojiOpen = $state(false);
  const emojiPickerId = `${formatSheetId}-emoji`;
  const COMPOSER_MAX_CHARS = 4096;

  /** Put a picked emoji where the caret was. The textarea keeps its selection
   *  while the picker has focus, so that is still the place the user meant. */
  function insertEmoji(emoji: string) {
    emojiOpen = false;
    const el = chatInputEl;
    const at = insertAtSelection(
      inputText,
      el?.selectionStart ?? inputText.length,
      el?.selectionEnd ?? inputText.length,
      emoji,
      COMPOSER_MAX_CHARS,
    );
    if (at) {
      inputText = at.text;
      notifyOutgoingTyping(at.text);
    }
    tick().then(() => {
      chatInputEl?.focus();
      if (at) chatInputEl?.setSelectionRange(at.caret, at.caret);
    });
  }
  /** Describes the composer while it is replying, so a screen reader hears who
   *  the line will answer on focus. */
  const replyBarId = `${formatSheetId}-reply`;

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
        const removed = messages.find((msg) => msg.id === id)?.msg_id;
        messages = messages.filter((msg) => msg.id !== id);
        if (removed) {
          removedMsgIds = new Set([...removedMsgIds, removed]);
          if (replyTarget?.msgId === removed) cancelReply();
        }
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
    // Every key belongs to the IME while it is composing, arrows and Enter
    // included: they move between and commit its candidates.
    if (isComposing(e)) return;
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
    if (e.key === 'Escape' && replyTarget) {
      // The reply, and nothing behind it: the room page closes panes on
      // Escape from `document` without checking `defaultPrevented`, so only
      // stopping the event here keeps one press from doing both.
      e.preventDefault();
      e.stopPropagation();
      cancelReply();
      return;
    }
    if (
      e.key === 'ArrowUp' &&
      !e.shiftKey && !e.altKey && !e.ctrlKey && !e.metaKey &&
      inputText === '' &&
      editingId === null
    ) {
      // Only the newest line we sent, even while it is still on its way: an
      // older one is never what the key means, and `canEdit` refuses the rest.
      const lastOwn = messages.findLast((line) => line.direction === 'sent');
      if (lastOwn && canEdit(lastOwn)) {
        e.preventDefault();
        startEdit(lastOwn, true);
      }
      return;
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
    return formatCalendarDate(ts, {
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

  /**
   * The parts of a row that depend only on the message itself, cached across
   * rebuilds of {@link rows}.
   *
   * `rows` recomputes whenever `visibleMessages` changes, which is every
   * arriving line, every edit, and every ignore toggle. Moving link
   * segmentation and the mention test off the template and into that derived
   * stopped them running once per *render*, but they still ran once per
   * *message* on each rebuild: at the 2000-message cap, one incoming line
   * meant two thousand `formatMessage` passes and two thousand regex tests to
   * produce output identical to the previous frame for all but one row. That,
   * not the number of mounted bubbles, is what a busy room actually costs.
   *
   * Keyed by id and validated against the text and edit stamp, so a revised
   * line — or an optimistic bubble being replaced by its durable row — still
   * re-derives. Rebuilt into a fresh map each pass so ids that have scrolled
   * out of the window do not accumulate.
   */
  type CachedRow = {
    text: string;
    edited: number;
    day: number | null;
    mentionsMe: boolean;
    blocks: FormatBlock[];
  };
  let rowCache = new Map<number, CachedRow>();
  /** The pattern the cache was built against. A rename changes who is
   *  mentioned, so every cached verdict is stale. */
  let rowCachePattern: RegExp | null = null;

  let rows = $derived.by(() => {
    const messages = visibleMessages;
    const pattern = mentionPattern;
    if (pattern !== rowCachePattern) {
      rowCache.clear();
      rowCachePattern = pattern;
    }
    const prev = rowCache;
    const next = new Map<number, CachedRow>();
    const derivedRows = messages.map((msg) => {
      const edited = msg.edited_at ?? 0;
      const hit = prev.get(msg.id);
      const row =
        hit && hit.text === msg.message && hit.edited === edited
          ? hit
          : {
              text: msg.message,
              edited,
              // `null` means the row carries no usable date — a zero timestamp
              // is "unknown", and must not produce a 1970 separator.
              day: msg.timestamp > 0 ? startOfDay(msg.timestamp) : null,
              // Tested against the raw text, so a name inside `**…**` or next
              // to a code span still counts; formatting is display-only.
              mentionsMe: msg.direction === 'received' && (pattern?.test(msg.message) ?? false),
              blocks: formatMessage(msg.message),
            };
      next.set(msg.id, row);
      return row;
    });
    rowCache = next;
    // Run and day boundaries stay outside the cache: they depend on a
    // message's neighbours, so inserting a line can change the row above it.
    // Both are plain comparisons rather than regex work.
    //
    // A day only ever opens forwards. Room catch-up appends lines in arrival
    // order, not time order, so an older line landing after today's would
    // otherwise close today and open it again under a second "Today". It sits
    // in the day already open instead.
    let latestDay: number | null = null;
    const opensDay = derivedRows.map(({ day }) => {
      if (day === null || (latestDay !== null && day <= latestDay)) return false;
      latestDay = day;
      return true;
    });
    return messages.map((msg, i) => {
      const { day, mentionsMe, blocks } = derivedRows[i];
      const hasNext = i + 1 < messages.length;
      const newDay = opensDay[i];
      const sameAuthorAsPrev = i > 0 && sameChannelAuthor(messages[i - 1], msg);
      const sameAuthorAsNext = hasNext && sameChannelAuthor(messages[i + 1], msg);
      // An undated row neither opens nor closes a day, so it stays with its run.
      const sameDayAsNext = hasNext && (day === null || !opensDay[i + 1]);
      // Someone answering one of our lines is addressed to us the way a
      // mention is, so it is marked the same way. The backend's verdict covers
      // a parent paged out of view; a loaded one is checked directly.
      const repliesToMe =
        msg.direction === 'received' &&
        !!msg.reply_to &&
        (msg.reply_to_me === true || messagesByMsgId.get(msg.reply_to)?.direction === 'sent');
      return {
        msg,
        daySeparator: newDay ? dayLabel(msg.timestamp) : null,
        startsRun: newDay || !sameAuthorAsPrev,
        endsRun: !sameAuthorAsNext || !sameDayAsNext,
        mentionsMe: mentionsMe || repliesToMe,
        blocks,
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

  // Take our indicator down the moment we stop being able to send the line it
  // promises, rather than leave it up until it lapses on everyone's screen.
  $effect(() => {
    if (!isChannel) return;
    if (youAreBanned || youAreKeyBehind || chatLocked || announceOnly || slowModeLeft > 0) {
      untrack(() => stopRoomTyping());
    }
  });

  /** The room changed, so a wait owed to the previous one does not follow. */
  $effect(() => {
    conversationKey;
    untrack(() => {
      nextSendAt = 0;
    });
  });

  /**
   * Hand a link in a message to the backend, which decides whether it may be
   * opened and asks the user itself.
   *
   * No prompt here. `open_external_url` shows a native confirmation naming the
   * host before anything reaches the browser, and that is the one that counts:
   * a renderer under someone else's control simply would not run a prompt of
   * its own. Asking twice for the same decision trained people to click
   * through the dialog that actually protects them.
   *
   * Declining the native dialog resolves as success — nothing happened, which
   * is what the user asked for — so there is no toast for a cancelled open.
   */
  async function askOpenLink(href: string) {
    try {
      await openExternalUrl(href);
    } catch (e) {
      toast(translateError(e));
    }
  }

  function formatClock(ts: number): string {
    if (!ts) return '';
    return formatClockTime(ts, { hour: 'numeric', minute: '2-digit' });
  }

  /** With the date for anything not from today. Message rows use
   *  `formatClock` instead: every dated row sits under its day separator.
   *  Attachments are placed between messages rather than dated, so they
   *  can land under the previous day's separator and keep the date. */
  function formatTime(ts: number): string {
    if (!ts) return '';
    const d = new Date(ts * 1000);
    const now = new Date();
    const sameDay = d.toDateString() === now.toDateString();
    const clock = formatClock(ts);
    if (sameDay) return clock;
    return `${formatCalendarDate(ts, { month: 'short', day: 'numeric' })} ${clock}`;
  }

  /** Where each file sits among the messages. See `chatAttachmentPlacement`. */
  let attachmentPlacement = $derived(
    placeAttachments(
      rows.map((r) => ({ id: r.msg.id, timestamp: r.msg.timestamp })),
      isChannel ? [] : attachments,
      hasMoreHistory,
    ),
  );

  onDestroy(() => {
    if (unlisten) { unlisten(); unlisten = null; }
    if (unlistenDelivery) { unlistenDelivery(); unlistenDelivery = null; }
    if (unlistenTyping) { unlistenTyping(); unlistenTyping = null; }
    if (unlistenRead) { unlistenRead(); unlistenRead = null; }
    if (unlistenAttach) { unlistenAttach(); unlistenAttach = null; }
    if (typingHoldTimer) { clearTimeout(typingHoldTimer); typingHoldTimer = null; }
    if (lastTypingSentOn && friendHash) {
      void sendChatTyping(friendHash, false).catch(() => {});
    }
    stopRoomTyping();
    if (roomTypistsTimer) { clearTimeout(roomTypistsTimer); roomTypistsTimer = null; }
    if (focusTimer) { clearTimeout(focusTimer); focusTimer = null; }
    if (reactionPulseTimer) { clearTimeout(reactionPulseTimer); reactionPulseTimer = null; }
    if (copiedCodeTimer) { clearTimeout(copiedCodeTimer); copiedCodeTimer = null; }
  });

  let showUnreadJump = $derived(
    unreadMarkerId !== null && !unreadDividerSeen && unreadDividerAbove && !loading,
  );
</script>

{#snippet attachmentRow(a: ChatAttachment)}
  <div
    class="conv-msg conv-attach-row starts-run"
    class:sent={a.direction === 'sent'}
    class:received={a.direction === 'received'}
  >
    <ChatAttachmentBubble
      attachment={a}
      friendName={friendName || friendHash.slice(0, 8)}
      time={formatTime(a.created_at)}
    />
  </div>
{/snippet}

{#snippet messageTimestamp(msg: ConvMessage)}
  <div class="bubble-time">
    <time
      datetime={msg.timestamp ? new Date(msg.timestamp * 1000).toISOString() : undefined}
      title={msg.timestamp ? formatDateTime(msg.timestamp, { dateStyle: 'full', timeStyle: 'medium' }) : undefined}
    >{formatClock(msg.timestamp)}</time>
    {#if (msg.edited_at ?? 0) > 0}
      <span class="bubble-edited" title={m.channels_edited_at({ time: formatTime(msg.edited_at ?? 0) })}>
        {m.channels_edited()}
      </span>
    {/if}
  </div>
{/snippet}

<!-- The quick three keep the drawn icons rooms have always had; the rest of
     the curated set is the emoji itself. -->
{#snippet reactionGlyph(code: number)}
  {#if code === REACTION_HEART}
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="14" height="14" aria-hidden="true">
      <path d="M8 13.4S2.6 10.1 2.6 6.7A3.05 3.05 0 0 1 8 4.05a3.05 3.05 0 0 1 5.4 2.65C13.4 10.1 8 13.4 8 13.4z"/>
    </svg>
  {:else if code === REACTION_UP}
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="14" height="14" aria-hidden="true">
      <path d="M5 14V7l3.2-4.5a1.4 1.4 0 0 1 2.4 1.3L9.7 6.5H13a1.3 1.3 0 0 1 1.2 1.7l-1.3 4.6a1.7 1.7 0 0 1-1.6 1.2H5zM2.6 14h2.4V7H2.6z"/>
    </svg>
  {:else if code === REACTION_DOWN}
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="14" height="14" aria-hidden="true">
      <path d="M11 2v7l-3.2 4.5a1.4 1.4 0 0 1-2.4-1.3l.9-2.7H3a1.3 1.3 0 0 1-1.2-1.7l1.3-4.6A1.7 1.7 0 0 1 4.7 2H11zm2.4 0h-2.4v7h2.4z"/>
    </svg>
  {:else}
    <span class="reaction-emoji" aria-hidden="true">{curatedReaction(code)?.emoji ?? ''}</span>
  {/if}
{/snippet}

<!-- Opened from a line's "more reactions" button. The host stays where Svelte
     put it; only the panel moves to <body>, out of the transcript's clipping
     and any transform on the dock around it. -->
{#if picker}
  <div class="reaction-picker-host">
    <div
      class="reaction-picker"
      class:placed={pickerPos !== null}
      role="menu"
      tabindex="-1"
      aria-label={m.channels_reaction_picker()}
      style:left={pickerPos ? `${pickerPos.left}px` : undefined}
      style:top={pickerPos ? `${pickerPos.top}px` : undefined}
      bind:this={pickerEl}
      use:portal
    >
      {#each CURATED_REACTIONS as reaction, i (reaction.code)}
        {@const held = (reactions[picker.msg.msg_id]?.mine ?? REACTION_NONE) === reaction.code}
        <button
          type="button"
          class="reaction-picker-item"
          class:active={held}
          role="menuitemradio"
          aria-checked={held}
          tabindex={i === pickerIndex ? 0 : -1}
          title={reaction.label()}
          aria-label={reaction.label()}
          onfocus={() => (pickerIndex = i)}
          onclick={() => choosePickedReaction(reaction.code)}
        >{reaction.emoji}</button>
      {/each}
    </div>
  </div>
{/if}

<!-- Written without whitespace between tags: the bubble is `pre-wrap`, so any
     newline or indent here would be drawn inside the message. -->
{#snippet inlineNodes(nodes: InlineNode[])}{#each nodes as node, i (i)}{#if node.type === 'text'}{node.text}{:else if node.type === 'link'}<button
      type="button"
      class="bubble-link"
      title={node.href}
      onclick={() => void askOpenLink(node.href)}
    >{node.text}</button>{:else if node.type === 'code'}<code class="fmt-code">{node.text}</code>{:else if node.type === 'bold'}<strong>{@render inlineNodes(node.children)}</strong>{:else if node.type === 'italic'}<em>{@render inlineNodes(node.children)}</em>{:else}<s>{@render inlineNodes(node.children)}</s>{/if}{/each}{/snippet}

<div class="conversation" class:channel={isChannel}>
  {#if isChannel && pinEntries.length > 0}
    {@const pin = pinEntries[shownPinIndex]}
    <!-- Its own row above the transcript rather than floating over it, so the
         first lines are never hidden under it. One pin at a time: the bar is a
         pointer to the message, not a second transcript. -->
    <div class="conv-pin-bar" role="region" aria-label={m.channels_pinned_label()}>
      <svg class="conv-pin-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="12" height="12" aria-hidden="true">
        <path d="M6 2.5h4M7 2.5v4L4.5 9h7L9 6.5v-4M8 9v4.5"/>
      </svg>
      {#if pin.kind === 'message' && isIgnoredSender(pin.senderPubkey)}
        <!-- Still counted, so "1 of 3" stays true, but neither named nor
             quoted, and nothing to jump to: the line itself is not drawn. -->
        <span class="conv-pin-target unavailable">{m.channels_message_hidden_member()}</span>
      {:else if pin.kind === 'message'}
        {@const who = senderLabel(pin.senderPubkey)}
        {@const excerpt = cachedReplyExcerpt(pin.text)}
        <button
          type="button"
          class="conv-pin-target"
          onclick={() => jumpToPin(pin.id)}
          title={m.channels_pinned_jump()}
          aria-label={m.channels_pinned_aria({ name: who, text: excerpt })}
        >
          <bdi dir="auto" class="conv-reply-who">{who}</bdi><span class="conv-reply-sep" aria-hidden="true">:</span>
          <bdi dir="auto" class="conv-reply-excerpt">{excerpt}</bdi>
        </button>
      {:else}
        <span class="conv-pin-target unavailable">{m.channels_pinned_unavailable()}</span>
      {/if}
      {#if pinEntries.length > 1}
        <button
          type="button"
          class="conv-pin-cycle"
          onclick={() => (pinIndex = nextPinIndex(shownPinIndex, pinEntries.length))}
          title={m.channels_pinned_next()}
          aria-label={m.channels_pinned_next_count({ index: shownPinIndex + 1, total: pinEntries.length })}
        >
          {m.channels_pinned_count({ index: shownPinIndex + 1, total: pinEntries.length })}
        </button>
      {/if}
      {#if canPin}
        <button
          type="button"
          class="conv-reply-cancel"
          disabled={pinBusy}
          onclick={() => void setPinned(pin.msgId, false)}
          title={m.channels_unpin_message()}
          aria-label={m.channels_unpin_message()}
        >
          <IconX size={11} />
        </button>
      {/if}
    </div>
  {/if}

  <!-- Anchors the unread pill to the transcript's top edge, which moves with
       whether the header is shown. -->
  <div class="conv-transcript">
  <div class="conv-messages" role="log" aria-label={m.chat_messages_label()} aria-busy={transcriptBusy} bind:this={messagesContainerEl} use:passiveScroll={onMessagesScroll}>
    {#if liveError && !loading && !loadError}
      <div class="conv-live-error" role="status">
        <span>{m.chat_live_unavailable()}</span>
        <button class="conv-load-retry" onclick={retryLoad} type="button">{m.common_retry()}</button>
      </div>
    {/if}
    {#if loading}
      <div class="conv-loading" role="status">
        <span class="spinner sm" aria-hidden="true"></span>
        <span>{m.chat_loading_messages()}</span>
      </div>
    {:else if loadError}
      <div class="conv-load-error" role="alert">
        <span>{loadError}</span>
        <button class="conv-load-retry" onclick={retryLoad} type="button">{m.common_retry()}</button>
      </div>
    {:else if messages.length === 0 && attachmentPlacement.count === 0}
      <div class="empty-state compact">
        {#if chatLocked}
          <p class="empty-title">{m.friends_chat_locked_title()}</p>
        {:else if chatDisabled}
          <p class="empty-title">{m.chat_empty_disabled()}</p>
        {:else if isChannel}
          <p class="empty-title">
            {youAreBanned || youAreKeyBehind || announceOnly
              ? m.channels_empty_chat_readonly()
              : m.channels_empty_chat()}
          </p>
          <p class="empty-sub">{m.channels_empty_chat_hint()}</p>
        {:else}
          <p class="empty-title">{m.chat_say_hello()}</p>
        {/if}
      </div>
    {:else}
      {#if hasMoreHistory}
        <div class="conv-load-older">
          <button
            class="conv-load-older-btn"
            type="button"
            onclick={loadOlderMessages}
            disabled={loadingOlder}
          >
            {loadingOlder ? m.chat_loading_short() : (olderError ? m.common_retry() : m.chat_load_older())}
          </button>
          {#if olderError}
            <span class="conv-load-older-error" role="alert">{m.chat_load_older_failed()}</span>
          {/if}
        </div>
      {/if}
      {#each rows as row (row.msg.id)}
        {#each attachmentPlacement.before.get(row.msg.id) ?? [] as a (a.xfer_id)}
          {@render attachmentRow(a)}
        {/each}
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
        {@const slowSend = sendLooksStuck(row.msg)}
        {@const showSeen = row.msg.direction === 'sent' && row.msg.seen && showReadReceipts && row.msg.id === lastSeenSentId}
        {@const showSent = row.msg.direction === 'sent' && row.msg.delivery === 'delivered' && row.msg.id === lastDeliveredSentId && !showSeen}
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
            A node tree, never markup: `formatMessage` only decides which of a
            few fixed elements each run of text sits in, and every run is a
            text node, so nothing a member types can become HTML. A link is a
            `<button>` rather than an `<a href>` so the webview itself has no
            navigable target — the only way out is the confirmed,
            scheme-checked backend opener. A code block is a block of its own,
            so it takes `dir="auto"` itself rather than sitting in the `<bdi>`.
          -->
          {#if isChannel && row.msg.reply_to}
            {@const quote = resolveReplyQuote(row.msg, messagesByMsgId, removedMsgIds)}
            {#if quote?.kind === 'parent' && isIgnoredSender(quote.senderPubkey)}
              <!-- Not a button: the parent is not drawn, so there is nowhere
                   to jump, and its author is not named. -->
              <div class="bubble-quote unavailable">{m.channels_message_hidden_member()}</div>
            {:else if quote?.kind === 'parent'}
              {@const who = senderLabel(quote.senderPubkey)}
              {@const excerpt = cachedReplyExcerpt(quote.text)}
              <!-- Plain text nodes only, like the bubble body: the excerpt has
                   its formatting markers removed rather than rendered. -->
              <button
                type="button"
                class="bubble-quote"
                onclick={() => jumpToReplyParent(quote.id)}
                title={m.channels_reply_jump()}
                aria-label={m.channels_reply_quote_aria({ name: who, text: excerpt })}
              >
                <bdi dir="auto" class="bubble-quote-who">{who}</bdi>
                <bdi dir="auto" class="bubble-quote-text">{excerpt}</bdi>
              </button>
            {:else if quote}
              <div class="bubble-quote unavailable">
                {quote.kind === 'deleted' ? m.channels_reply_deleted() : m.channels_reply_unavailable()}
              </div>
            {/if}
          {/if}
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
                <button type="button" class="bubble-edit-cancel" onclick={() => closeEditor(row.msg.id)} disabled={editBusy}>
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
          <div class="bubble-text">{#each row.blocks as block, bi (bi)}{#if block.type === 'text'}<bdi dir="auto">{@render inlineNodes(block.children)}</bdi>{:else}{@const codeKey = `${row.msg.id}:${bi}`}<div class="fmt-codeblock"><!-- Focusable so a long line can be scrolled sideways from the keyboard: a scroll container is the one non-widget that needs a tab stop. --><!-- svelte-ignore a11y_no_noninteractive_tabindex --><pre dir="auto" tabindex="0" role="group" aria-label={m.chat_code_block_label()}><code>{block.text}</code></pre><button
                  type="button"
                  class="fmt-codeblock-copy"
                  onclick={() => void copyCodeBlock(codeKey, block.text)}
                  title={m.chat_copy_code()}
                  aria-label={copiedCodeKey === codeKey ? m.common_copied() : m.chat_copy_code()}
                >{copiedCodeKey === codeKey ? m.common_copied() : m.common_copy()}</button></div>{/if}{/each}</div>
          {/if}
          {#if !isChannel && (row.endsRun || pending || failed || (row.msg.edited_at ?? 0) > 0)}
            {@render messageTimestamp(row.msg)}
          {/if}
          <!-- Copy is offered on every line. Edit and remove are channels
               only, and only for rows the DB can actually address: live
               bubbles carry negative synthetic ids. -->
          {#if editingId !== row.msg.id || (isChannel && row.msg.id > 0)}
            <!-- One tab stop per line, arrows along it: five stops a message
                 made the transcript a slog to tab through. -->
            <div class="bubble-tools" role="toolbar" aria-label={m.chat_message_actions()} use:rovingToolbar>
              {#if editingId !== row.msg.id}
                <button
                  type="button"
                  class="bubble-copy-btn"
                  onclick={() => void copyMessageText(row.msg)}
                  title={m.chat_copy_text()}
                  aria-label={m.chat_copy_text()}
                >
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="11" height="11" aria-hidden="true">
                    <rect x="5.5" y="5.5" width="8" height="8" rx="1.5"/>
                    <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5"/>
                  </svg>
                </button>
              {/if}
              {#if editingId !== row.msg.id && canReply(row.msg)}
                <button
                  type="button"
                  class="bubble-reply-btn"
                  onclick={() => startReply(row.msg)}
                  title={m.channels_reply()}
                  aria-label={m.channels_reply()}
                >
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="11" height="11" aria-hidden="true">
                    <path d="M6.5 4 2.5 8l4 4"/>
                    <path d="M2.5 8h7a4 4 0 0 1 4 4v1"/>
                  </svg>
                </button>
              {/if}
              {#if isChannel && canPin && row.msg.id > 0 && row.msg.msg_id?.length === 32 && editingId !== row.msg.id}
                {@const action = pinAction(row.msg.msg_id, stablePinnedIds, CHANNEL_PIN_MAX)}
                {@const pinLabel =
                  action === 'unpin'
                    ? m.channels_unpin_message()
                    : action === 'full'
                      ? m.channels_pin_full({ max: CHANNEL_PIN_MAX })
                      : m.channels_pin_message()}
                <!-- At the cap it stays visible and says why, rather than
                     vanishing or quietly replacing the oldest pin. Not
                     `disabled`, so the tooltip still shows on hover. -->
                <button
                  type="button"
                  class="bubble-pin-btn"
                  class:active={action === 'unpin'}
                  class:unavailable={action === 'full'}
                  aria-disabled={action === 'full' || pinBusy}
                  aria-pressed={action === 'unpin'}
                  onclick={() => {
                    if (action === 'full') toast(pinLabel);
                    else if (row.msg.msg_id) void setPinned(row.msg.msg_id, action === 'pin');
                  }}
                  title={pinLabel}
                  aria-label={pinLabel}
                >
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="11" height="11" aria-hidden="true">
                    <path d="M6 2.5h4M7 2.5v4L4.5 9h7L9 6.5v-4M8 9v4.5"/>
                  </svg>
                </button>
              {/if}
              {#if isChannel && row.msg.id > 0 && canEdit(row.msg) && editingId !== row.msg.id}
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
              {#if isChannel && row.msg.id > 0}
                <button
                  class="bubble-remove"
                  disabled={removingMessage === row.msg.id}
                  onclick={() => handleRemoveMessage(row.msg.id)}
                  title={m.channels_remove_local()}
                  aria-label={m.channels_remove_local()}
                >
                  <IconX size={11} />
                </button>
              {/if}
            </div>
          {/if}
          {#if isChannel}
            <div class="bubble-meta">
              {#if row.msg.msg_id?.length === 32}
                {@const tally = reactions[row.msg.msg_id]}
                {@const mine = tally?.mine ?? REACTION_NONE}
                {@const hasAny = (tally?.reactions.length ?? 0) > 0}
                {@const ownMessage = row.msg.direction === 'sent'}
                {@const pickerHere = picker?.msg.msg_id === row.msg.msg_id}
                {#if !ownMessage || hasAny}
                <div class="bubble-reactions" class:has-any={hasAny} class:readonly={ownMessage} class:picker-open={pickerHere}>
                  {#each reactionChips(tally, ownMessage) as chip (chip.code)}
                    {@const label = reactionChipLabel(chip)}
                    {#if ownMessage}
                      <!-- Nothing to press on our own line, but who reacted is
                           still worth a hover, so a label rather than a dead
                           button that swallows the tooltip. -->
                      <span
                        class="reaction-btn static"
                        class:heart={chip.code === REACTION_HEART}
                        class:emoji={!QUICK_REACTIONS.includes(chip.code)}
                        role="img"
                        title={label}
                        aria-label={label}
                      >
                        {@render reactionGlyph(chip.code)}
                        <span class="reaction-count" aria-hidden="true">{chip.count}</span>
                      </span>
                    {:else}
                      <!-- `aria-disabled`, not `disabled`, while a reaction is
                           in flight: disabling the chip just pressed would
                           drop its focus to <body>. `toggleReaction` refuses. -->
                      <button
                        type="button"
                        class="reaction-btn"
                        class:heart={chip.code === REACTION_HEART}
                        class:emoji={!QUICK_REACTIONS.includes(chip.code)}
                        class:active={mine === chip.code}
                        class:pulse-add={reactionPulse?.msgId === row.msg.msg_id && reactionPulse?.kind === chip.code && reactionPulse?.action === 'add'}
                        class:pulse-remove={reactionPulse?.msgId === row.msg.msg_id && reactionPulse?.kind === chip.code && reactionPulse?.action === 'remove'}
                        aria-disabled={reactionBusy !== null}
                        onclick={() => void toggleReaction(row.msg, chip.code)}
                        title={label}
                        aria-label={label}
                        aria-pressed={mine === chip.code}
                      >
                        {@render reactionGlyph(chip.code)}
                        {#if chip.count > 0}<span class="reaction-count" aria-hidden="true">{chip.count}</span>{/if}
                      </button>
                    {/if}
                  {/each}
                  {#if !ownMessage}
                    <button
                      type="button"
                      class="reaction-btn reaction-more"
                      class:active={pickerHere}
                      aria-disabled={reactionBusy !== null}
                      onclick={(e) => openPicker(row.msg, e.currentTarget)}
                      title={m.channels_reaction_more()}
                      aria-label={m.channels_reaction_more()}
                      aria-haspopup="menu"
                      aria-expanded={pickerHere}
                    >
                      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="14" height="14" aria-hidden="true">
                        <path d="M13.2 8.6A5.5 5.5 0 1 1 7.4 2.5"/>
                        <path d="M5.4 9.6a3 3 0 0 0 5 0"/>
                        <path d="M5.9 6.4h.01M9.6 6.4h.01"/>
                        <path d="M12.5 1.5v4M10.5 3.5h4"/>
                      </svg>
                    </button>
                  {/if}
                </div>
                {/if}
              {/if}
              {@render messageTimestamp(row.msg)}
            </div>
          {/if}
        </div>
        <!-- Room lines carry the first two states only: nobody in a room sends
             a read receipt, and "Sent" on every bubble in a busy transcript is
             noise the friend pane can afford and this one cannot. -->
        {#if isChannel && (slowSend || failed)}
          <div class="bubble-status">
            {#if slowSend}
              <span title={m.channels_delivery_sending_title()}>{m.chat_delivery_queued()}</span>
            {:else}
              <span class="failed" title={m.channels_delivery_failed_title()}>{m.chat_delivery_failed()}</span>
              <button
                class="bubble-resend"
                type="button"
                disabled={resendingId !== null || sending || youAreBanned || youAreKeyBehind}
                onclick={() => resendChannelMessage(row.msg)}
                title={m.chat_resend()}
                aria-label={m.chat_resend()}
              >
                {resendingId === row.msg.id ? m.chat_loading_short() : m.chat_resend()}
              </button>
            {/if}
          </div>
        {:else if !isChannel && (pending || failed || showSeen || showSent)}
          <div class="bubble-status">
            {#if pending}
              <span title={m.chat_delivery_queued_title()}>{m.chat_delivery_queued()}</span>
            {:else if failed}
              <span class="failed" title={m.chat_delivery_failed_title()}>{m.chat_delivery_failed()}</span>
              <button
                class="bubble-resend"
                type="button"
                disabled={resendingId !== null || sending || chatDisabled || chatLocked}
                onclick={() => resendMessage(row.msg)}
                title={m.chat_resend()}
                aria-label={m.chat_resend()}
              >
                {resendingId === row.msg.id ? m.chat_loading_short() : m.chat_resend()}
              </button>
            {:else if showSeen}
              <span class="bubble-seen" title={m.chat_seen_title()} aria-label={m.chat_seen()} role="img">
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="12" height="12" aria-hidden="true">
                  <path d="M1.5 8s2.6-4.5 6.5-4.5S14.5 8 14.5 8s-2.6 4.5-6.5 4.5S1.5 8 1.5 8z"/>
                  <circle class="bubble-seen-pupil" cx="8" cy="8" r="1.85"/>
                </svg>
              </span>
            {:else}
              <span title={m.chat_delivery_sent_title()}>{m.chat_delivery_sent()}</span>
            {/if}
          </div>
        {/if}
        </div>
      {/each}
      {#each attachmentPlacement.after as a (a.xfer_id)}
        {@render attachmentRow(a)}
      {/each}
    {/if}
    <div bind:this={messagesEnd}></div>
  </div>
  {#if showUnreadJump}
    <button
      class="conv-jump conv-jump-unread has-unseen"
      type="button"
      onclick={jumpToFirstUnread}
      title={m.chat_jump_to_unread()}
      aria-label={m.chat_jump_to_unread()}
    >
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
        <path d="M8 13V4M4.5 7.5 8 4l3.5 3.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <span>{m.chat_jump_to_unread()}</span>
    </button>
  {/if}
  <!-- Inside the transcript's box rather than measured up from the bottom of
       the pane, so the reply bar, an error line or a taller composer below
       cannot end up under it. -->
  {#if scrolledAway && messages.length > 0 && !loading}
    <button
      class="conv-jump"
      class:has-unseen={missedWhileAway || unreadAhead}
      class:above-typing={typingPillShown}
      type="button"
      onclick={jumpToLatest}
      title={missedWhileAway || unreadAhead ? m.chat_new_messages_below() : m.chat_jump_to_latest()}
      aria-label={missedWhileAway || unreadAhead ? m.chat_new_messages_below() : m.chat_jump_to_latest()}
    >
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
        <path d="M8 3v9M4.5 8.5 8 12l3.5-3.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <span>{missedWhileAway || unreadAhead ? m.chat_new_messages_below() : m.chat_jump_to_latest()}</span>
    </button>
  {/if}
  </div>

  <!-- Floats over the space reserved at the foot of the transcript, like the
       jump control: a row that came and went with every typist would shove
       the conversation up and down under the reader. The live region is its
       own element and stays mounted, so what it says is decided by the
       announcement rather than by every change to the visible line. -->
  <div class="conv-typing-anchor">
    <span class="sr-only" role="status" aria-live="polite">{isChannel ? roomTypingAnnouncement : friendTypingAnnouncement}</span>
    {#if typingPillShown}
      <div class="conv-typing conv-typing-pill">
        <span class="conv-typing-text">
          {#if isChannel}
            {#each roomTypingSegments as segment, i (i)}
              {#if segment.kind === 'name'}<bdi dir="auto">{segment.text}</bdi>{:else}{segment.text}{/if}
            {/each}
          {:else}
            {m.chat_typing({ name: friendName || friendHash.slice(0, 8) })}
          {/if}
        </span>
        <span class="conv-typing-dots" aria-hidden="true"><span></span><span></span><span></span></span>
      </div>
    {/if}
  </div>

  {#if sendError}
    <div class="conv-error" role="alert">{sendError}</div>
  {/if}

  {#if youAreBanned}
    <div class="conv-disabled" role="status">{m.channels_you_are_banned()}</div>
  {:else if youAreKeyBehind}
    <div class="conv-disabled" role="status">{m.channels_key_behind()}</div>
  {:else if chatLocked}
    <div class="conv-disabled" role="status">{m.chat_locked_notice()}</div>
  {:else if isChannel && announceOnly}
    <div class="conv-disabled" role="status">{m.channels_announce_only_notice()}</div>
  {:else if chatDisabled}
    <div class="conv-disabled" role="status">{m.chat_disabled_notice()}</div>
  {:else}
    {#if isChannel && replyTarget}
      {@const target = replyTarget}
      {@const current = messagesByMsgId.get(target.msgId)}
      {@const targetHidden = isIgnoredSender(current?.sender_pubkey ?? target.senderPubkey)}
      <div class="conv-reply-bar">
        <svg class="conv-reply-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" width="12" height="12" aria-hidden="true">
          <path d="M6.5 4 2.5 8l4 4"/>
          <path d="M2.5 8h7a4 4 0 0 1 4 4v1"/>
        </svg>
        <button
          type="button"
          class="conv-reply-target"
          id={replyBarId}
          onclick={() => jumpToReplyParent(target.id)}
          title={m.channels_reply_jump()}
        >
          <span class="conv-reply-label">{m.channels_replying_to()}</span>
          {#if targetHidden}
            <span class="conv-reply-excerpt">{m.channels_message_hidden_member()}</span>
          {:else}
            <bdi dir="auto" class="conv-reply-who">{senderLabel(current?.sender_pubkey ?? target.senderPubkey)}</bdi><span class="conv-reply-sep" aria-hidden="true">:</span>
            <bdi dir="auto" class="conv-reply-excerpt">{cachedReplyExcerpt(current?.message ?? target.text)}</bdi>
          {/if}
        </button>
        <button
          type="button"
          class="conv-reply-cancel"
          onclick={() => {
            cancelReply();
            focusComposer();
          }}
          onkeydown={(e) => {
            if (e.key !== 'Escape') return;
            // Only the reply, not the room's own Escape handling.
            e.preventDefault();
            e.stopPropagation();
            cancelReply();
            focusComposer();
          }}
          title={m.channels_reply_cancel()}
          aria-label={m.channels_reply_cancel()}
        >
          <IconX size={11} />
        </button>
      </div>
    {/if}
    <div class="conv-input-area">
      <!-- Focus never leaves the textarea, so the highlighted suggestion is
           spoken from here rather than by moving focus onto it. Always in the
           DOM: a live region inserted with its text is not announced. -->
      <span class="sr-only" aria-live="polite">{mentionOpen ? mentionMatches[Math.min(mentionIndex, mentionMatches.length - 1)] : ''}</span>
      {#if mentionOpen}
        <!-- A listbox the textarea owns rather than a focusable menu: focus has
             to stay in the composer so typing keeps narrowing the list. -->
        <ul class="mention-list" role="listbox" aria-label={m.chat_mention_list_label()}>
          {#each mentionMatches as name, i (name)}
            <li role="none">
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
      {#if !isChannel}
        <!-- Disabled rather than hidden while the friend is offline: the bytes
             move over a live connection between the two of you, and a button
             that vanished would give no hint why. -->
        <button
          type="button"
          class="conv-attach"
          class:busy={attaching}
          onclick={sendAttachment}
          disabled={attaching || !isOnline}
          title={attaching
            ? m.chat_attach_preparing()
            : isOnline
              ? m.chat_attach_button()
              : m.chat_attach_offline({ name: friendName || friendHash.slice(0, 8) })}
          aria-label={m.chat_attach_button()}
          aria-busy={attaching}
        >
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M15.5 9.5 10 15a3.5 3.5 0 0 1-5-5l6-6a2.3 2.3 0 0 1 3.3 3.3l-6 6a1.2 1.2 0 0 1-1.7-1.7L12 6"/>
          </svg>
        </button>
      {/if}
      <textarea
        class="conv-input"
        bind:value={inputText}
        bind:this={chatInputEl}
        onkeydown={handleKeydown}
        oninput={(e) => {
          refreshMentionToken();
          notifyOutgoingTyping(e.currentTarget.value);
        }}
        onclick={refreshMentionToken}
        onkeyup={refreshMentionToken}
        onblur={() => (mentionStart = -1)}
        placeholder={isChannel ? m.channels_send_placeholder() : m.chat_input_placeholder()}
        aria-label={m.chat_input_label()}
        aria-describedby={isChannel && replyTarget ? replyBarId : undefined}
        maxlength={COMPOSER_MAX_CHARS}
        rows="2"
        readonly={sending}
      ></textarea>
      {#if slowModeLeft > 0}
        <!-- Polite: it changes every second, and a live region that asserted
             would talk over everything else in the room. -->
        <span class="conv-slow-mode" role="status" aria-live="polite">
          {m.chat_slow_mode_wait({ seconds: slowModeLeft })}
        </span>
      {/if}
      <div
        class="conv-emoji"
        onfocusout={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node | null)) emojiOpen = false;
        }}
      >
        <button
          type="button"
          class="conv-format-toggle conv-emoji-toggle"
          class:open={emojiOpen}
          onclick={() => (emojiOpen = !emojiOpen)}
          disabled={sending}
          title={m.chat_emoji_button()}
          aria-label={m.chat_emoji_button()}
          aria-expanded={emojiOpen}
          aria-controls={emojiPickerId}
        >
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="10" cy="10" r="7"/>
            <path d="M7 11.8a3.6 3.6 0 0 0 6 0"/>
            <line x1="7.6" y1="8" x2="7.6" y2="8.1"/>
            <line x1="12.4" y1="8" x2="12.4" y2="8.1"/>
          </svg>
        </button>
        {#if emojiOpen}
          <EmojiPicker
            id={emojiPickerId}
            onpick={insertEmoji}
            onclose={() => {
              emojiOpen = false;
              chatInputEl?.focus();
            }}
          />
        {/if}
      </div>
      <!-- A cheat-sheet rather than toolbar buttons: the markers are typed, and
           a row of B/I/S controls would crowd a composer the dock already
           keeps narrow. Closes on focus leaving it, so it never lingers. -->
      <div
        class="conv-format-help"
        onfocusout={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node | null)) formatHelpOpen = false;
        }}
      >
        <button
          type="button"
          class="conv-format-toggle"
          class:open={formatHelpOpen}
          onclick={() => (formatHelpOpen = !formatHelpOpen)}
          onkeydown={(e) => {
            if (e.key === 'Escape' && formatHelpOpen) {
              // Only the sheet, not the room's own Escape handling.
              e.preventDefault();
              e.stopPropagation();
              formatHelpOpen = false;
            }
          }}
          title={m.chat_format_help()}
          aria-label={m.chat_format_help()}
          aria-expanded={formatHelpOpen}
          aria-controls={formatSheetId}
        >Aa</button>
        {#if formatHelpOpen}
          <div class="conv-format-sheet" id={formatSheetId} role="note" aria-label={m.chat_format_help()}>
            <div class="conv-format-row"><code>**{m.chat_format_bold()}**</code><strong>{m.chat_format_bold()}</strong></div>
            <div class="conv-format-row"><code>*{m.chat_format_italic()}*</code><em>{m.chat_format_italic()}</em></div>
            <div class="conv-format-row"><code>~~{m.chat_format_strike()}~~</code><s>{m.chat_format_strike()}</s></div>
            <div class="conv-format-row"><code>`{m.chat_format_code()}`</code><code class="fmt-code">{m.chat_format_code()}</code></div>
            <p class="conv-format-note">{m.chat_format_code_block()}</p>
          </div>
        {/if}
      </div>
      <button
        type="button"
        class="conv-send"
        onclick={handleSend}
        onmousedown={(e) => {
          // Keep the caret in the composer; a click would otherwise move
          // focus to this button (and then lose it when the button disables).
          e.preventDefault();
        }}
        disabled={!inputText.trim() || sending || slowModeLeft > 0}
        title={slowModeLeft > 0 ? m.chat_slow_mode_wait({ seconds: slowModeLeft }) : m.chat_send_title_short()}
        aria-label={m.chat_send_aria()}
      >
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M3 10l14-7-7 14-2-5z"/><line x1="10" y1="17" x2="17" y2="3"/>
        </svg>
      </button>
    </div>
  {/if}
</div>

<style>
  .conversation {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
    background: var(--bg-primary);
    position: relative;
  }

  /* Nested well: a step darker than the page canvas so white received
     bubbles and the compose field have something to sit on. */
  .conversation.channel {
    background: var(--bg-tertiary);
  }

  :global([data-theme="dark"]) .conversation.channel {
    background: var(--bg-secondary);
  }

  /* Anchors both `.conv-jump` pills, which float over the transcript rather
     than occupying a row in the column — a control that pushed the composer
     down every time the reader scrolled up would move the target they are
     aiming for. */
  .conv-transcript {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    position: relative;
  }

  /* The extra room at the foot is where the typing pill floats, so it never
     covers the newest line and the transcript never moves to make way. */
  .conv-messages {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 16px 16px 30px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .conversation.channel .conv-messages {
    /* Six pixels keeps separate messages readable; `.starts-run` adds another
       six where the speaker changes, preserving visible conversation groups. */
    gap: 6px;
  }

  .conv-loading {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 24px;
    color: var(--text-muted);
    font-size: var(--font-size-md);
  }

  .conv-load-error {
    display: flex;
    flex-direction: column;
    gap: 8px;
    align-items: center;
    padding: 16px;
    color: var(--danger);
    font-size: var(--font-size-md);
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
    font-size: var(--font-size-sm);
  }

  .conv-load-retry {
    padding: 6px 14px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-primary);
    font-size: var(--font-size-sm);
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
    font-size: var(--font-size-xs);
    color: var(--danger);
  }

  .conv-load-older-btn {
    padding: 6px 12px;
    border-radius: var(--radius-pill);
    border: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-secondary);
    font-size: var(--font-size-sm);
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
    font-size: var(--font-size-xs);
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
    font-size: var(--font-size-xs);
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

  /* One bubble shape for friends and rooms: the corner, the tighter corner
     where a message meets its neighbour in the same run, and the tail at the
     end of a run. */
  .conversation {
    --bubble-radius: var(--radius-lg);
    --bubble-run-radius: 6px;
    --bubble-tail-radius: 4px;
  }

  .conv-bubble {
    max-width: 80%;
    padding: 8px 12px;
    border-radius: var(--bubble-radius);
    font-size: var(--font-size-md);
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
    box-shadow: none;
  }

  /* The sender's name chip sits in this corner, so it stays tight. */
  .conversation.channel .conv-msg.received .conv-bubble,
  .conversation.channel .conv-msg.sent .conv-bubble {
    border-top-left-radius: var(--radius-md);
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
    border-top-right-radius: var(--bubble-run-radius);
  }

  .conv-bubble.sent:not(.ends-run) {
    border-bottom-right-radius: var(--bubble-run-radius);
  }

  .conv-bubble.sent.ends-run {
    border-bottom-right-radius: var(--bubble-tail-radius);
  }

  .conv-bubble.received {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }

  /* A room's transcript is a well a step darker than the page, where the
     tertiary fill would disappear, so a received line lifts off it instead. */
  .conversation.channel .conv-bubble.received {
    background: color-mix(in srgb, var(--bg-secondary) 88%, var(--bg-surface));
    border: 1px solid color-mix(in srgb, var(--border) 82%, transparent);
  }

  :global([data-theme="dark"]) .conversation.channel .conv-bubble.received {
    background: var(--bg-tertiary);
  }

  .conv-bubble.received:not(.starts-run) {
    border-top-left-radius: var(--bubble-run-radius);
  }

  .conv-bubble.received:not(.ends-run) {
    border-bottom-left-radius: var(--bubble-run-radius);
  }

  .conv-bubble.received.ends-run {
    border-bottom-left-radius: var(--bubble-tail-radius);
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

  /* Tinted from `currentColor` so the same rule reads on an accent-filled sent
     bubble and a surface-coloured received one. */
  .fmt-code {
    padding: 0 3px;
    border-radius: 3px;
    background: color-mix(in srgb, currentColor 12%, transparent);
    font-family: var(--font-mono);
    font-size: 0.92em;
    overflow-wrap: anywhere;
  }

  .fmt-codeblock {
    position: relative;
    margin: 4px 0;
    min-width: 0;
    max-width: 100%;
  }

  /* `pre`, not `pre-wrap`: code keeps its line structure and scrolls sideways
     instead of wrapping into something that no longer reads as code. */
  .fmt-codeblock pre {
    margin: 0;
    padding: 6px 8px;
    padding-inline-end: 48px;
    border-radius: 5px;
    background: color-mix(in srgb, currentColor 10%, transparent);
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
    line-height: 1.45;
    white-space: pre;
    overflow-wrap: normal;
    overflow-x: auto;
    tab-size: 4;
  }

  .fmt-codeblock pre:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }

  .fmt-codeblock-copy {
    position: absolute;
    top: 4px;
    inset-inline-end: 4px;
    padding: 1px 6px;
    border: 1px solid color-mix(in srgb, currentColor 25%, transparent);
    border-radius: 4px;
    background: color-mix(in srgb, currentColor 8%, transparent);
    color: inherit;
    font-size: var(--font-size-2xs);
    font-weight: 600;
    cursor: pointer;
    opacity: 0.8;
  }

  .fmt-codeblock-copy:hover,
  .fmt-codeblock-copy:focus-visible {
    opacity: 1;
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
    font-size: var(--font-size-xs);
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
    font-size: var(--font-size-xs);
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
    font-size: var(--font-size-2xs);
    color: var(--text-muted);
    padding: 0 2px;
    line-height: 1.2;
    flex-shrink: 0;
  }

  /* Sent bubbles are filled with `--accent`; muted gray on that fill is
     unreadable. Use the same on-accent ink as the message body (white in
     light theme, dark in dark theme). */
  .conv-bubble.sent .bubble-time,
  .conv-bubble.sent .bubble-edited {
    color: var(--on-accent);
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

  /* Delivery captions (queued / sent / seen) share one slot under the
     trailing corner of a friend bubble, on the transcript surface. */
  .bubble-status {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin-top: 2px;
    font-size: var(--font-size-2xs);
    font-weight: 600;
    line-height: 1.2;
    color: var(--text-muted);
  }

  .bubble-status .failed {
    color: var(--danger);
  }

  .bubble-seen {
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .bubble-seen svg {
    display: block;
  }

  .bubble-seen-pupil {
    fill: var(--text-primary);
    stroke: none;
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
    background: color-mix(in srgb, currentColor 16%, transparent);
  }

  /* Friend bubbles have no header strip to park the cluster in, so it rides
     the top edge the way a room's does rather than covering the text. */
  .conversation:not(.channel) .bubble-tools {
    top: -8px;
    z-index: 3;
  }

  /* Styled like a room's edit control in both panes: it floats over the
     bubble's edge, so it needs its own fill to read on either bubble colour. */
  .bubble-copy-btn,
  .bubble-reply-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: 50%;
    background: var(--bg-primary);
    color: var(--text-muted);
    cursor: pointer;
  }

  .bubble-copy-btn:hover,
  .bubble-reply-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  /* The line a reply answers, above its text. Tinted from `currentColor` like
     inline code, so one rule reads on an accent-filled sent bubble and a
     surface-coloured received one; the edge bar is what says "quote". */
  .bubble-quote {
    display: flex;
    align-items: baseline;
    gap: 6px;
    width: 100%;
    min-width: 0;
    box-sizing: border-box;
    margin: 0 0 6px;
    padding: 3px 8px;
    border: none;
    border-inline-start: 2px solid color-mix(in srgb, currentColor 55%, transparent);
    border-radius: 4px;
    background: color-mix(in srgb, currentColor 9%, transparent);
    color: inherit;
    font: inherit;
    font-size: var(--font-size-sm);
    line-height: 1.35;
    text-align: start;
    white-space: nowrap;
    overflow: hidden;
  }

  button.bubble-quote {
    cursor: pointer;
  }

  button.bubble-quote:hover {
    background: color-mix(in srgb, currentColor 15%, transparent);
  }

  button.bubble-quote:focus-visible {
    outline: 2px solid currentColor;
    outline-offset: 1px;
  }

  .bubble-quote-who {
    flex-shrink: 0;
    max-width: 45%;
    overflow: hidden;
    text-overflow: ellipsis;
    font-weight: 600;
  }

  .bubble-quote-text {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    opacity: 0.85;
  }

  .bubble-quote.unavailable {
    font-style: italic;
    opacity: 0.75;
  }

  /* "Replying to …" sits on the composer's own surface, directly above it, so
     it reads as part of what is about to be sent. */
  .conv-reply-bar {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px 0;
    border-top: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-secondary);
    font-size: var(--font-size-sm);
    flex-shrink: 0;
    min-width: 0;
  }

  .conversation.channel .conv-reply-bar {
    background: var(--bg-tertiary);
  }

  :global([data-theme="dark"]) .conversation.channel .conv-reply-bar {
    background: var(--bg-secondary);
  }

  /* The composer's top border would draw a line between the bar and the box
     it belongs to. */
  .conv-reply-bar + .conv-input-area {
    border-top: none;
    padding-top: 6px;
  }

  .conv-reply-icon {
    flex-shrink: 0;
    color: var(--accent);
  }

  .conv-reply-target {
    display: flex;
    align-items: baseline;
    gap: 4px;
    flex: 1;
    min-width: 0;
    padding: 2px 0;
    border: none;
    background: none;
    color: inherit;
    font: inherit;
    text-align: start;
    white-space: nowrap;
    overflow: hidden;
    cursor: pointer;
  }

  .conv-reply-target:hover .conv-reply-excerpt {
    color: var(--text-primary);
  }

  .conv-reply-target:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
    border-radius: 3px;
  }

  .conv-reply-label {
    flex-shrink: 0;
  }

  .conv-reply-who {
    flex-shrink: 0;
    max-width: 40%;
    overflow: hidden;
    text-overflow: ellipsis;
    font-weight: 600;
    color: var(--text-primary);
  }

  .conv-reply-sep {
    flex-shrink: 0;
    margin-inline-start: -4px;
  }

  .conv-reply-excerpt {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .conv-reply-cancel {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 20px;
    height: 20px;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
  }

  .conv-reply-cancel:hover,
  .conv-reply-cancel:focus-visible {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  /* The room's pins, one line above the transcript. Quiet on purpose: it is
     read once and then only when wanted, and must not compete with the
     messages under it. */
  .conv-pin-bar {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 5px 14px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-secondary);
    font-size: var(--font-size-sm);
    flex-shrink: 0;
    min-width: 0;
  }

  .conversation.channel .conv-pin-bar {
    background: var(--bg-tertiary);
  }

  :global([data-theme="dark"]) .conversation.channel .conv-pin-bar {
    background: var(--bg-secondary);
  }

  .conv-pin-icon {
    flex-shrink: 0;
    color: var(--accent);
  }

  .conv-pin-target {
    display: flex;
    align-items: baseline;
    gap: 4px;
    flex: 1;
    min-width: 0;
    padding: 2px 0;
    border: none;
    background: none;
    color: inherit;
    font: inherit;
    text-align: start;
    white-space: nowrap;
    overflow: hidden;
  }

  button.conv-pin-target {
    cursor: pointer;
  }

  button.conv-pin-target:hover .conv-reply-excerpt {
    color: var(--text-primary);
  }

  button.conv-pin-target:focus-visible,
  .conv-pin-cycle:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
    border-radius: 3px;
  }

  .conv-pin-target.unavailable {
    font-style: italic;
    opacity: 0.8;
  }

  .conv-pin-cycle {
    flex-shrink: 0;
    padding: 1px 6px;
    border: 1px solid var(--border);
    border-radius: var(--radius-pill);
    background: transparent;
    color: var(--text-muted);
    font: inherit;
    font-size: var(--font-size-xs);
    font-variant-numeric: tabular-nums;
    cursor: pointer;
  }

  .conv-pin-cycle:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .bubble-pin-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: 50%;
    background: var(--bg-primary);
    color: var(--text-muted);
    cursor: pointer;
  }

  .bubble-pin-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .bubble-pin-btn.active {
    color: var(--accent);
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
  }

  .bubble-pin-btn.unavailable {
    opacity: 0.5;
    cursor: default;
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
    border-radius: var(--radius-sm);
    background: var(--bg-primary);
    color: var(--text-primary);
    font: inherit;
    resize: vertical;
  }

  .bubble-edit-error {
    color: var(--danger);
    font-size: var(--font-size-xs);
  }

  .bubble-edit-actions {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .bubble-edit-hint {
    flex: 1 1 auto;
    font-size: var(--font-size-2xs);
    opacity: 0.7;
  }

  .bubble-edit-cancel,
  .bubble-edit-save {
    padding: 2px 8px;
    border: 1px solid var(--border);
    border-radius: 5px;
    background: var(--bg-surface);
    color: var(--text-primary);
    font-size: var(--font-size-xs);
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
  .bubble-reactions:focus-within,
  .bubble-reactions.picker-open {
    opacity: 1;
  }

  .conversation.channel .bubble-reactions.has-any,
  .conversation.channel .conv-msg:hover .bubble-reactions,
  .conversation.channel .bubble-reactions:focus-within,
  .conversation.channel .bubble-reactions.picker-open {
    pointer-events: auto;
  }

  /* Once a tally makes the row permanent, the picker trigger is still a hover
     control: it holds its place so revealing it does not shift the chips. */
  .bubble-reactions.has-any .reaction-more {
    opacity: 0;
    transition: opacity var(--transition-fast);
  }

  .conv-msg:hover .bubble-reactions .reaction-more,
  .bubble-reactions:focus-within .reaction-more,
  .bubble-reactions.picker-open .reaction-more {
    opacity: 1;
  }

  /* A pointer that cannot hover has no way to reveal any of these, so on a touch
     screen the edit, remove and reaction controls were unreachable outright.
     After all three base rules, since none of this adds specificity. */
  @media (hover: none) {
    .bubble-remove,
    .bubble-tools,
    .bubble-reactions,
    .bubble-reactions.has-any .reaction-more {
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
    border-radius: var(--radius-pill);
    background: transparent;
    color: var(--reaction-gold);
    font-size: var(--font-size-xs);
    font-variant-numeric: tabular-nums;
    cursor: pointer;
    transition:
      background var(--transition-fast) ease,
      color var(--transition-fast) ease,
      border-color var(--transition-fast) ease,
      transform var(--transition-normal) ease;
  }

  .conversation.channel .reaction-btn {
    background:
      linear-gradient(180deg, color-mix(in srgb, var(--reaction-gloss) 22%, transparent), transparent 58%);
    color: var(--reaction-gold);
    border-color: color-mix(in srgb, var(--reaction-gold) 20%, transparent);
    box-shadow: inset 0 1px 0 color-mix(in srgb, var(--reaction-gloss) 28%, transparent);
  }

  .conversation.channel .reaction-btn svg {
    fill: var(--reaction-gold);
    stroke: color-mix(in srgb, var(--reaction-gold) 62%, #8a5600);
    filter:
      drop-shadow(0 0.5px 0 color-mix(in srgb, var(--reaction-gloss) 78%, transparent))
      drop-shadow(0 1px 1.1px color-mix(in srgb, #000 26%, transparent));
  }

  .reaction-btn:hover:not([aria-disabled='true']):not(.static) {
    transform: translateY(-1px);
  }

  .conversation.channel .reaction-btn:hover:not([aria-disabled='true']):not(.static) {
    color: var(--reaction-gold);
    background:
      linear-gradient(180deg, color-mix(in srgb, var(--reaction-gloss) 42%, transparent), transparent 48%),
      color-mix(in srgb, var(--reaction-gold) 20%, transparent);
    border-color: color-mix(in srgb, var(--reaction-gold) 48%, transparent);
    box-shadow:
      inset 0 1px 0 color-mix(in srgb, var(--reaction-gloss) 55%, transparent),
      0 1px 3px color-mix(in srgb, var(--reaction-gold) 28%, transparent);
  }

  .reaction-btn:active:not([aria-disabled='true']) {
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
      linear-gradient(180deg, color-mix(in srgb, var(--reaction-gloss) 36%, transparent), transparent 46%),
      color-mix(in srgb, var(--reaction-gold) 24%, transparent);
    border-color: color-mix(in srgb, var(--reaction-gold) 55%, transparent);
    box-shadow:
      inset 0 1px 0 color-mix(in srgb, var(--reaction-gloss) 50%, transparent),
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

  .conversation.channel .reaction-btn.heart:hover:not([aria-disabled='true']):not(.static) {
    color: var(--reaction-heart);
    background:
      linear-gradient(180deg, color-mix(in srgb, var(--reaction-gloss) 42%, transparent), transparent 48%),
      color-mix(in srgb, var(--reaction-heart) 20%, transparent);
    border-color: color-mix(in srgb, var(--reaction-heart) 48%, transparent);
    box-shadow:
      inset 0 1px 0 color-mix(in srgb, var(--reaction-gloss) 55%, transparent),
      0 1px 3px color-mix(in srgb, var(--reaction-heart) 28%, transparent);
  }

  .conversation.channel .reaction-btn.heart.active {
    color: var(--reaction-heart);
    background:
      linear-gradient(180deg, color-mix(in srgb, var(--reaction-gloss) 36%, transparent), transparent 46%),
      color-mix(in srgb, var(--reaction-heart) 24%, transparent);
    border-color: color-mix(in srgb, var(--reaction-heart) 55%, transparent);
    box-shadow:
      inset 0 1px 0 color-mix(in srgb, var(--reaction-gloss) 50%, transparent),
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

  .reaction-btn[aria-disabled='true'],
  .reaction-btn.static {
    cursor: default;
  }

  .reaction-count {
    font-weight: 600;
    color: color-mix(in srgb, var(--reaction-gold) 65%, var(--text-primary));
  }

  /* Emoji chips carry their own colour, so the gold wash stays on the frame and
     the count; the glyph is sized to sit level with the drawn icons. */
  .reaction-emoji {
    font-size: var(--font-size-md);
    line-height: 1;
  }

  .conversation.channel .reaction-btn.emoji .reaction-count {
    color: var(--text-primary);
  }

  /* The trigger is an outline icon: the gold fill the reaction icons take would
     turn it into a solid blob. */
  .conversation.channel .reaction-btn.reaction-more {
    color: var(--text-secondary);
    border-color: color-mix(in srgb, var(--text-secondary) 22%, transparent);
  }

  .conversation.channel .reaction-btn.reaction-more svg {
    fill: none;
    stroke: currentColor;
    filter: none;
  }

  .conversation.channel .reaction-btn.reaction-more:hover:not([aria-disabled='true']),
  .conversation.channel .reaction-btn.reaction-more.active {
    color: var(--text-primary);
  }

  .reaction-picker-host {
    display: contents;
  }

  /* Lives at the end of <body> (see the `portal` action), so nothing here may
     depend on `.conversation` around it — only the theme's root variables. */
  .reaction-picker {
    position: fixed;
    left: 0;
    top: 0;
    z-index: 9999;
    display: grid;
    grid-template-columns: repeat(5, 32px);
    gap: 2px;
    padding: 6px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-secondary);
    box-shadow: var(--shadow-lg);
    visibility: hidden;
  }

  .reaction-picker.placed {
    visibility: visible;
    animation: reaction-picker-in 0.12s ease-out;
  }

  @keyframes reaction-picker-in {
    from { opacity: 0; transform: scale(0.96); }
    to { opacity: 1; transform: scale(1); }
  }

  .reaction-picker-item {
    display: grid;
    place-items: center;
    width: 32px;
    height: 32px;
    padding: 0;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: transparent;
    font-size: var(--font-size-xl);
    line-height: 1;
    cursor: pointer;
    transition: background var(--transition-fast) ease, transform var(--transition-fast) ease;
  }

  .reaction-picker-item:hover {
    background: var(--bg-hover);
    transform: scale(1.12);
  }

  .reaction-picker-item:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -1px;
    background: var(--bg-hover);
  }

  .reaction-picker-item.active {
    border-color: color-mix(in srgb, var(--accent) 55%, transparent);
    background: color-mix(in srgb, var(--accent) 18%, transparent);
  }

  /* app.css already shortens every animation under reduced motion; these are
     removed outright, since a scale that still fires for 0.01ms is a flicker. */
  @media (prefers-reduced-motion: reduce) {
    .reaction-picker.placed,
    .conversation.channel .reaction-btn.pulse-add,
    .conversation.channel .reaction-btn.pulse-remove,
    .conversation.channel .reaction-btn.heart.pulse-add,
    .conversation.channel .reaction-btn.heart.pulse-remove {
      animation: none;
    }

    .reaction-btn:hover:not([aria-disabled='true']):not(.static),
    .reaction-picker-item:hover {
      transform: none;
    }
  }

  /* Resend sits beside the failure caption under its own bubble, so it
     reads as part of the failure notice rather than a general-purpose
     action. Always visible (unlike `.bubble-remove`, which is hover-revealed):
     a message that did not arrive is exactly the case where the remedy
     should not be hidden. */
  .bubble-resend {
    padding: 0 5px;
    border: 1px solid color-mix(in srgb, var(--danger) 45%, transparent);
    border-radius: 4px;
    background: transparent;
    color: var(--danger);
    font-size: var(--font-size-2xs);
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

  /* Floats at the foot of the transcript, just above whatever sits below it.
     `has-unseen` is the accent case: the difference between "you scrolled up"
     and "you scrolled up and missed something" is the whole reason this
     exists, so it is carried by colour and not only by the label. */
  .conv-jump {
    position: absolute;
    inset-inline-end: 18px;
    bottom: 12px;
    z-index: 4;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 5px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-pill);
    background: var(--bg-surface);
    color: var(--text-secondary);
    font-size: var(--font-size-xs);
    font-weight: 600;
    box-shadow: var(--shadow-md);
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

  /* Clear of the typing pill, which hangs over the same strip on a narrow
     dock. */
  .conv-jump.above-typing {
    bottom: 34px;
  }

  /* The way back up sits at the top edge, centred, so it cannot be mistaken
     for the jump-to-latest pill in the bottom corner. */
  .conv-jump-unread {
    top: 8px;
    bottom: auto;
    inset-inline-end: auto;
    left: 50%;
    transform: translateX(-50%);
    white-space: nowrap;
  }

  .conv-error {
    padding: 8px 14px;
    background: color-mix(in srgb, var(--danger) 14%, transparent);
    color: var(--danger);
    font-size: var(--font-size-sm);
    text-align: center;
  }

  .conv-disabled {
    padding: 12px 14px;
    border-top: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-muted);
    font-size: var(--font-size-md);
    text-align: center;
    flex-shrink: 0;
  }

  .conv-typing {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 2px;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
    flex-shrink: 0;
  }

  .conv-typing-dots {
    display: inline-flex;
    gap: 3px;
    align-items: center;
  }

  .conv-typing-dots span {
    width: 4px;
    height: 4px;
    border-radius: 50%;
    background: currentColor;
    animation: conv-typing-bounce 1.2s infinite ease-in-out;
  }

  .conv-typing-dots span:nth-child(2) { animation-delay: 0.15s; }
  .conv-typing-dots span:nth-child(3) { animation-delay: 0.3s; }

  @keyframes conv-typing-bounce {
    0%, 80%, 100% { opacity: 0.35; transform: translateY(0); }
    40% { opacity: 1; transform: translateY(-2px); }
  }

  @media (prefers-reduced-motion: reduce) {
    .conv-typing-dots span {
      animation: none;
      opacity: 0.6;
    }
  }

  /* Zero height in the column; its content hangs above it, in the space the
     transcript keeps free at its foot. */
  .conv-typing-anchor {
    position: relative;
    height: 0;
    flex-shrink: 0;
  }

  .conv-typing-pill {
    position: absolute;
    inset-inline-start: 14px;
    bottom: 4px;
    z-index: 3;
    max-width: 60%;
    padding: 2px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-pill);
    background: var(--bg-surface);
    pointer-events: none;
  }

  .conv-typing-text {
    min-width: 0;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
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
    font-size: var(--font-size-sm);
    text-align: start;
    cursor: pointer;
  }

  .mention-option:hover,
  .mention-option.active {
    background: var(--accent);
    color: var(--on-accent);
  }

  /* Static, so the sheet anchors to the composer row (the same box the mention
     list uses) rather than to this small button. */
  .conv-format-help,
  .conv-emoji {
    display: flex;
    align-self: center;
  }

  .conv-emoji-toggle {
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .conv-emoji-toggle:disabled {
    background: transparent;
    color: var(--text-muted);
    opacity: 0.45;
    cursor: default;
  }

  .conv-emoji-toggle svg {
    width: 18px;
    height: 18px;
  }

  .conv-format-toggle {
    width: 26px;
    height: 26px;
    padding: 0;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    font-size: var(--font-size-xs);
    font-weight: 700;
    cursor: pointer;
  }

  .conv-format-toggle:hover,
  .conv-format-toggle.open {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .conv-format-sheet {
    position: absolute;
    bottom: calc(100% - 4px);
    inset-inline-end: 14px;
    z-index: 5;
    display: flex;
    flex-direction: column;
    gap: 3px;
    max-width: 260px;
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-surface);
    box-shadow: var(--shadow-md);
    color: var(--text-primary);
    font-size: var(--font-size-sm);
  }

  .conv-format-row {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 14px;
  }

  .conv-format-row > code:first-child {
    font-family: var(--font-mono);
    font-size: var(--font-size-xs);
    color: var(--text-secondary);
  }

  .conv-format-note {
    margin: 3px 0 0;
    color: var(--text-secondary);
    font-size: var(--font-size-xs);
  }

  /* Aligned to the bottom of the row so it sits level with the send button
     rather than floating against the top of a two-row textarea. */
  .conv-slow-mode {
    align-self: flex-end;
    padding-bottom: 10px;
    font-size: var(--font-size-xs);
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
    font-size: var(--font-size-md);
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
    box-shadow: 0 0 0 2px var(--accent-halo);
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
    background: var(--accent-hover);
  }

  .conv-send:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .conv-send:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .conv-send svg {
    width: 18px;
    height: 18px;
  }

  /* Quiet beside the send button: it is the second thing you reach for. */
  .conv-attach {
    width: 36px;
    height: 36px;
    padding: 0;
    align-self: center;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--text-secondary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .conv-attach:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .conv-attach:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .conv-attach:disabled {
    opacity: 0.45;
    cursor: default;
  }

  .conv-attach.busy {
    opacity: 1;
    color: var(--accent);
    animation: conv-attach-pulse 1.2s ease-in-out infinite;
  }

  @keyframes conv-attach-pulse {
    50% {
      opacity: 0.45;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .conv-attach.busy {
      animation: none;
    }
  }

  .conv-attach svg {
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
