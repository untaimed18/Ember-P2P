<script lang="ts">
  import { onDestroy } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { getChatMessages, sendChatMessage, markMessagesRead, type ChatMessage } from '$lib/api/friends';
  import {
    deleteChannelMessage,
    getChannelMessages,
    markChannelMessagesRead,
    offerChannelFile,
    requestChannelFile,
    saveChannelFile,
    sendChannelMessage,
    type ChannelMessageInfo,
  } from '$lib/api/channels';
  import { activeChatHash, clearUnread, onlineFriends } from '$lib/stores/friends';
  import { clearChannelUnread } from '$lib/stores/channels';
  import { appSettings } from '$lib/stores/settings';
  import { getDraft, setDraft, clearDraft } from '$lib/stores/chatTabs';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';
  import { isAppVisible } from '$lib/utils';
  import IconX from '$lib/components/IconX.svelte';

  // The backend rejects chat messages whose UTF-8 encoding exceeds this many
  // bytes (`peers.rs`); the textarea `maxlength` only bounds characters, so we
  // mirror the byte check here to give a clear error instead of a generic
  // "send failed" on multi-byte/emoji-heavy text.
  const MAX_MESSAGE_BYTES = 4096;
  // Upper bound on messages held in memory at once. "Load older" stops past
  // this so a very long history can't grow the array (and the rendered DOM)
  // without bound; the rest stays in the DB and on disk.
  const MAX_LOADED_MESSAGES = 2000;
  const CHANNEL_FILE_PREFIX = 'EMBERFILE:';
  const CHANNEL_FILE_MAX_BYTES = 256 * 1024;

  interface Props {
    friendHash: string;
    friendName: string;
    channelId?: string;
    hideHeader?: boolean;
    youAreBanned?: boolean;
    memberNames?: Record<string, string>;
    /** Senders hidden on this device. Presentational only — their messages are
     *  still received and stored, they just aren't drawn. */
    ignoredSenders?: string[];
    /** Own display name, so a message naming us can be picked out. Empty
     *  disables the check rather than matching everything. */
    mentionName?: string;
  }

  type ConvMessage = ChatMessage & { sender_pubkey?: string };

  let {
    friendHash,
    friendName,
    channelId = '',
    hideHeader = false,
    youAreBanned = false,
    memberNames = {},
    ignoredSenders = [],
    mentionName = '',
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
  let isOnline = $derived(!isChannel && friendHash ? $onlineFriends.has(friendHash) : false);

  // The user can disable chat entirely in Settings; when off, the backend
  // drops inbound and refuses outbound chat, so reflect that in the UI rather
  // than letting the user type into a textarea whose sends will be rejected.
  let chatDisabled = $derived(!isChannel && $appSettings?.friend_chat_disabled === true);

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
  let unlistenFile: UnlistenFn | null = null;
  let unlistenFileProgress: UnlistenFn | null = null;
  let attaching = $state(false);
  let fileBusy = $state<string | null>(null);
  let readyFiles: Record<string, boolean> = $state({});
  let pendingFiles: Record<string, boolean> = $state({});
  /** Reassembly progress per digest, driven by `ember:channel-file-progress`. */
  let fileProgress: Record<string, { received: number; size: number }> = $state({});
  let removingMessage = $state<number | null>(null);
  let awaitingSave: { digest: string; name: string } | null = null;
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

  function fromChannelRow(row: ChannelMessageInfo): ConvMessage {
    return {
      id: row.id,
      direction: row.direction === 'sent' ? 'sent' : 'received',
      message: row.message,
      timestamp: row.timestamp,
      read: row.read,
      delivery: 'delivered',
      sender_pubkey: row.sender_pubkey,
    };
  }

  /** Both channel-file listeners share one lifecycle, so they are torn down
   *  together rather than leaving five call sites to remember the second. */
  function teardownChannelFileListeners() {
    if (unlistenFile) { unlistenFile(); unlistenFile = null; }
    if (unlistenFileProgress) { unlistenFileProgress(); unlistenFileProgress = null; }
  }

  function senderLabel(pubkey?: string): string {
    if (!pubkey) return '';
    const name = memberNames[pubkey];
    if (name) return name;
    return pubkey.slice(0, 8) + '\u2026';
  }

  function parseChannelFile(text: string): { digest: string; size: number; name: string } | null {
    if (!text.startsWith(CHANNEL_FILE_PREFIX)) return null;
    const rest = text.slice(CHANNEL_FILE_PREFIX.length);
    if (rest.length < 66) return null;
    const digest = rest.slice(0, 64).toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(digest) || rest[64] !== ':') return null;
    const sizeEnd = rest.indexOf(':', 65);
    if (sizeEnd < 0) return null;
    const size = Number(rest.slice(65, sizeEnd));
    const name = rest.slice(sizeEnd + 1);
    if (!name || !Number.isInteger(size) || size < 1 || size > CHANNEL_FILE_MAX_BYTES) return null;
    return { digest, size, name };
  }

  function formatFileSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    return `${Math.round(bytes / 1024)} KB`;
  }

  $effect(() => {
    if (!chatInputEl || youAreBanned) return;
    const raf = requestAnimationFrame(() => chatInputEl?.focus());
    return () => cancelAnimationFrame(raf);
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
      teardownChannelFileListeners();
      messages = [];
      earlyDeliveredIds.clear();
      readyFiles = {};
      pendingFiles = {};
      fileProgress = {};
      awaitingSave = null;
      attaching = false;
      fileBusy = null;
      loadError = null;
      liveError = false;
      loading = true;
      loadingOlder = false;
      hasMoreHistory = false;
      oldestDbId = null;
      (async () => {
        try {
          const listenerOk = await setupListener(gen, friend, channel);
          if (gen !== loadGen) return;
          await loadMessages(gen, friend, channel);
          if (gen === loadGen) liveError = !listenerOk;
        } finally {
          if (gen === loadGen) loading = false;
        }
      })();
      markAsRead();
    }
    return () => {
      loadGen++;
      if (unlisten) { unlisten(); unlisten = null; }
      if (unlistenDelivery) { unlistenDelivery(); unlistenDelivery = null; }
      teardownChannelFileListeners();
      if (key) setDraft(key, inputText);
      if (!channel) activeChatHash.set(null);
    };
  });

  async function setupListener(gen: number, hash: string, channel: string): Promise<boolean> {
    if (gen !== loadGen) return false;
    if (unlisten) { unlisten(); unlisten = null; }
    if (unlistenDelivery) { unlistenDelivery(); unlistenDelivery = null; }
    teardownChannelFileListeners();
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
          }];
          messages = next.length > MAX_LIVE_MESSAGES
            ? next.slice(next.length - MAX_LIVE_MESSAGES)
            : next;
          if (event.payload.direction === 'sent' || wasPinned) {
            scrollToBottom();
          }
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
      try {
        const fileFn = await listen<{
          channel_id: string;
          digest: string;
          file_name?: string;
        }>('ember:channel-file', (event) => {
          if (gen !== loadGen) return;
          if (event.payload.channel_id !== channel) return;
          const digest = event.payload.digest?.toLowerCase();
          if (!digest) return;
          readyFiles = { ...readyFiles, [digest]: true };
          pendingFiles = { ...pendingFiles, [digest]: false };
          const { [digest]: _done, ...restProgress } = fileProgress;
          fileProgress = restProgress;
          const waiting = awaitingSave;
          if (waiting && waiting.digest === digest) {
            awaitingSave = null;
            sendError = null;
            void pickAndSaveChannelFile(digest, waiting.name);
          }
        });
        if (gen !== loadGen) {
          fileFn();
          return false;
        }
        unlistenFile = fileFn;
      } catch (e) {
        console.warn('ChatConversation: failed to register channel file listener', e);
      }
      try {
        const progressFn = await listen<{
          channel_id: string;
          digest: string;
          received: number;
          size: number;
        }>('ember:channel-file-progress', (event) => {
          if (gen !== loadGen) return;
          if (event.payload.channel_id !== channel) return;
          const digest = event.payload.digest?.toLowerCase();
          if (!digest || !event.payload.size) return;
          fileProgress = {
            ...fileProgress,
            [digest]: { received: event.payload.received, size: event.payload.size },
          };
        });
        if (gen !== loadGen) {
          progressFn();
          return true;
        }
        unlistenFileProgress = progressFn;
      } catch (e) {
        // Non-fatal: the attachment still completes, just without a bar.
        console.warn('ChatConversation: failed to register file progress listener', e);
      }
      return true;
    }
    let fn: UnlistenFn;
    try {
      fn = await listen<{ user_hash: string; message: string; direction: string; timestamp: number }>('ember:chat-message', (event) => {
        if (gen !== loadGen) return;
        if (event.payload.user_hash === hash) {
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
          // Only acknowledge what the user can actually see. A mounted
          // conversation in a minimized window would otherwise mark the
          // message read and suppress its badge, losing it entirely.
          if (event.payload.direction === 'received' && isAppVisible()) {
            markAsRead();
          }
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
          if (event.payload.user_hash !== hash) return;
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
      scrollToBottom();
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
    teardownChannelFileListeners();
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

  function isPinnedToBottom(): boolean {
    const el = messagesContainerEl;
    if (!el) return true;
    return el.scrollHeight - (el.scrollTop + el.clientHeight) < 80;
  }

  async function pickAndSaveChannelFile(digest: string, name: string) {
    const { save } = await import('@tauri-apps/plugin-dialog');
    const dest = await save({ defaultPath: name });
    if (!dest) return;
    await saveChannelFile(channelId, digest, dest);
    readyFiles = { ...readyFiles, [digest]: true };
    pendingFiles = { ...pendingFiles, [digest]: false };
  }

  async function handleAttach() {
    if (!isChannel || sending || attaching || youAreBanned) return;
    const { open } = await import('@tauri-apps/plugin-dialog');
    const selected = await open({ multiple: false, title: m.channels_attach() });
    if (!selected || Array.isArray(selected)) return;
    attaching = true;
    sendError = null;
    try {
      const sent = await offerChannelFile(channelId, selected);
      if (!messages.some((message) => message.id === sent.id)) {
        messages = [...messages, fromChannelRow(sent)];
      }
      const parsed = parseChannelFile(sent.message);
      if (parsed) {
        readyFiles = { ...readyFiles, [parsed.digest]: true };
      }
      scrollToBottom();
    } catch (e: unknown) {
      const raw = e instanceof Error ? e.message : typeof e === 'string' ? e : '';
      sendError = raw.includes('channels_file_too_large')
        ? m.channels_attach_too_large()
        : translateError(e, m.error_operation_failed());
    } finally {
      attaching = false;
    }
  }

  async function handleFileDownload(digest: string, name: string) {
    if (!channelId || fileBusy) return;
    fileBusy = digest;
    sendError = null;
    try {
      await pickAndSaveChannelFile(digest, name);
    } catch (e: unknown) {
      try {
        await requestChannelFile(channelId, digest);
        pendingFiles = { ...pendingFiles, [digest]: true };
        awaitingSave = { digest, name };
        sendError = m.channels_file_pending();
      } catch (requestErr: unknown) {
        sendError = translateError(requestErr, translateError(e, m.error_operation_failed()));
      }
    } finally {
      fileBusy = null;
    }
  }

  async function handleSend() {
    const text = inputText.trim();
    if (!text || sending || youAreBanned) return;
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
        clearDraft(key);
        return;
      }
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

  function handleKeydown(e: KeyboardEvent) {
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

  /** Whole-word, case-insensitive match on our own display name. Word bounds
   *  stop a short nickname lighting up every message that merely contains it. */
  function mentionsMe(text: string): boolean {
    const name = mentionName.trim();
    if (!name || !isChannel) return false;
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    try {
      return new RegExp(`(^|[^\\p{L}\\p{N}])${escaped}([^\\p{L}\\p{N}]|$)`, 'iu').test(text);
    } catch {
      return text.toLowerCase().includes(name.toLowerCase());
    }
  }

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
      };
    });
  });

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
    teardownChannelFileListeners();
  });
</script>

<div class="conversation">
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

  <div class="conv-messages" bind:this={messagesContainerEl}>
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
      <div class="conv-empty">{chatDisabled ? m.chat_empty_disabled() : m.chat_say_hello()}</div>
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
        {@const pending = row.msg.direction === 'sent' && row.msg.delivery === 'queued'}
        {@const failed = row.msg.direction === 'sent' && row.msg.delivery === 'failed'}
        {@const file = isChannel ? parseChannelFile(row.msg.message) : null}
        <div
          class="conv-bubble"
          class:sent={row.msg.direction === 'sent'}
          class:received={row.msg.direction === 'received'}
          class:starts-run={row.startsRun}
          class:ends-run={row.endsRun}
          class:mentions-me={row.msg.direction === 'received' && !file && mentionsMe(row.msg.message)}
        >
          <!--
            `<bdi>` isolates the message body from the surrounding UI's
            text direction so a peer-supplied RTL/LTR override character
            can't reorder neighbouring elements (a known "Trojan Source"-
            style spoofing class). The text is still rendered exactly as
            written; only its bidi influence is scoped to this element.
          -->
          {#if isChannel && row.startsRun && row.msg.direction === 'received'}
            <div class="bubble-who">{senderLabel(row.msg.sender_pubkey)}</div>
          {/if}
          {#if file}
            <div class="bubble-file">
              <div class="file-name">{file.name}</div>
              <div class="file-meta">{formatFileSize(file.size)}</div>
              {#if pendingFiles[file.digest] && !readyFiles[file.digest]}
                {@const prog = fileProgress[file.digest]}
                {#if prog && prog.size > 0}
                  <div
                    class="file-progress"
                    role="progressbar"
                    aria-valuemin="0"
                    aria-valuemax={prog.size}
                    aria-valuenow={Math.min(prog.received, prog.size)}
                  >
                    <div class="file-progress-fill" style="width: {Math.min(100, Math.round((prog.received / prog.size) * 100))}%"></div>
                  </div>
                  <span class="file-status">
                    {m.channels_file_receiving({
                      percent: Math.min(100, Math.round((prog.received / prog.size) * 100)),
                    })}
                  </span>
                {:else}
                  <span class="file-status">{m.channels_file_pending()}</span>
                {/if}
              {:else}
                <button
                  class="file-action"
                  disabled={fileBusy === file.digest}
                  onclick={() => handleFileDownload(file.digest, file.name)}
                >
                  {readyFiles[file.digest] ? m.channels_file_save() : m.channels_file_download()}
                </button>
              {/if}
            </div>
          {:else}
            <div class="bubble-text"><bdi dir="auto">{row.msg.message}</bdi></div>
          {/if}
          <!--
            Once per run, not once per message: within a burst the timestamps
            repeat the same minute and add nothing. Delivery state is per
            message though, so a queued or failed one always shows its own.
          -->
          {#if row.endsRun || pending || failed}
            <div class="bubble-time">
              {formatTime(row.msg.timestamp)}
              {#if pending}
                <span class="bubble-delivery" title={m.chat_delivery_queued_title()}>{m.chat_delivery_queued()}</span>
              {:else if failed}
                <span class="bubble-delivery failed" title={m.chat_delivery_failed_title()}>{m.chat_delivery_failed()}</span>
              {/if}
            </div>
          {/if}
          <!-- Channels only, and only for rows the DB can actually address:
               live bubbles carry negative synthetic ids. -->
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
      {/each}
    {/if}
    <div bind:this={messagesEnd}></div>
  </div>

  {#if sendError}
    <div class="conv-error">{sendError}</div>
  {/if}

  {#if youAreBanned}
    <div class="conv-disabled" role="status">{m.channels_you_are_banned()}</div>
  {:else if chatDisabled}
    <div class="conv-disabled" role="status">{m.chat_disabled_notice()}</div>
  {:else}
    <div class="conv-input-area">
      {#if isChannel}
        <button
          class="conv-attach"
          onclick={handleAttach}
          disabled={sending || attaching}
          title={m.channels_attach()}
          aria-label={m.channels_attach()}
        >
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M7.5 9.5l5-5a2.5 2.5 0 013.5 3.5l-6.5 6.5a4 4 0 01-5.5-5.5L11 2.5"/>
          </svg>
        </button>
      {/if}
      <textarea
        class="conv-input"
        bind:value={inputText}
        bind:this={chatInputEl}
        onkeydown={handleKeydown}
        placeholder={isChannel ? m.channels_send_placeholder() : m.chat_input_placeholder()}
        maxlength="4096"
        rows="2"
        disabled={sending}
      ></textarea>
      <button type="button" class="conv-send" onclick={handleSend} disabled={!inputText.trim() || sending} title={m.chat_send_title_short()} aria-label={m.chat_send_aria()}>
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
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
    /* Tight by default; `.starts-run` reopens the gap where the speaker
       changes, so spacing carries meaning instead of being uniform. */
    gap: 2px;
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

  /* Consecutive messages from one author read as a single block: the gap only
     opens where the speaker changes, and the corners facing a neighbour in the
     same run flatten so the bubbles visibly belong together. */
  /* A message naming you is the one thing in a busy room you cannot afford to
     scroll past, so it gets an edge marker rather than a colour change that
     would fight the sent/received distinction. */
  .file-progress {
    height: 3px;
    margin: 6px 0 4px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--text-muted) 30%, transparent);
    overflow: hidden;
  }

  .file-progress-fill {
    height: 100%;
    background: var(--accent);
    transition: width var(--transition-fast) linear;
  }

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

  .conv-bubble.starts-run:not(:first-child) {
    margin-top: 8px;
  }

  .conv-bubble.sent {
    align-self: flex-end;
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
    align-self: flex-start;
    background: var(--bg-tertiary);
    color: var(--text-primary);
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

  .bubble-text {
    white-space: pre-wrap;
  }

  .bubble-who {
    font-size: 11px;
    font-weight: 600;
    opacity: 0.75;
    margin-bottom: 2px;
  }

  .bubble-time {
    font-size: 10px;
    opacity: 0.65;
    margin-top: 4px;
    text-align: right;
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

  .conv-attach {
    width: 40px;
    height: 40px;
    border: 1px solid var(--border);
    border-radius: 50%;
    background: var(--bg-primary);
    color: var(--text-secondary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .conv-attach:hover:not(:disabled) {
    color: var(--text-primary);
    border-color: var(--accent);
  }

  .conv-attach:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .conv-attach svg {
    width: 18px;
    height: 18px;
  }

  .bubble-file {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 140px;
  }

  .file-name {
    font-weight: 600;
    word-break: break-all;
  }

  .file-meta, .file-status {
    font-size: 11px;
    opacity: 0.75;
  }

  .file-action {
    align-self: flex-start;
    margin-top: 4px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-surface);
    color: inherit;
    cursor: pointer;
    font-size: 12px;
  }

  .file-action:disabled {
    opacity: 0.5;
    cursor: default;
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
