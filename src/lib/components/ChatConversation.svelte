<script lang="ts">
  import { onDestroy } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { getChatMessages, sendChatMessage, markMessagesRead, type ChatMessage } from '$lib/api/friends';
  import { activeChatHash, clearUnread, onlineFriends } from '$lib/stores/friends';
  import { getDraft, setDraft, clearDraft } from '$lib/stores/chatTabs';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';

  interface Props {
    friendHash: string;
    friendName: string;
  }

  let { friendHash, friendName }: Props = $props();

  // Live verification/online indicator. After the H1 fix the
  // `ember:friend-online` event is only emitted after the peer's
  // Ed25519 proof-of-possession succeeded, so membership in
  // `onlineFriends` is a reliable "the live session with this peer
  // is PoP-verified RIGHT NOW" signal. When the friend is offline we
  // surface a warning that the message will be queued and may reach
  // a peer that hasn't been re-authenticated since this session
  // opened.
  let isOnline = $derived(friendHash ? $onlineFriends.has(friendHash) : false);

  /**
   * Hard cap on in-memory chat messages per conversation. Old messages beyond
   * this are trimmed from the front of the array; they remain in the database
   * and can be re-fetched with "Load older". Without the cap a long-running
   * session (or a friend spamming the channel) causes unbounded memory growth.
   */
  const MAX_LIVE_MESSAGES = 500;

  let messages: ChatMessage[] = $state([]);
  let inputText = $state('');
  let loading = $state(false);
  let sending = $state(false);
  let sendError: string | null = $state(null);
  let loadError: string | null = $state(null);
  let messagesEnd: HTMLDivElement | undefined = $state();
  let messagesContainerEl: HTMLDivElement | undefined = $state();
  let chatInputEl: HTMLTextAreaElement | undefined = $state();
  let unlisten: UnlistenFn | null = null;
  let loadGen = 0;
  let msgIdCounter = 0;

  const PAGE_SIZE = 100;
  let loadingOlder = $state(false);
  let hasMoreHistory = $state(false);
  // Pagination cursor: the smallest (oldest) DB row id we've loaded. Tracked
  // separately from `messages` because live messages use negative ids and the
  // MAX_LIVE_MESSAGES trim drops oldest-first — in a busy session that can
  // evict every positive (DB) id from the array. Deriving the cursor from the
  // array (the old `messages.find(m => m.id > 0)`) then returned undefined and
  // wrongly hid "load older" even though the DB still had history.
  let oldestDbId: number | null = null;

  $effect(() => {
    if (chatInputEl) {
      requestAnimationFrame(() => chatInputEl?.focus());
    }
  });

  // Whenever the active conversation changes (mounted with new
  // friendHash, or parent reuses this component for a different
  // tab), tear down the previous listener + state and re-fetch.
  $effect(() => {
    // Capture friendHash into a local so the cleanup closure
    // below can save the draft against the conversation we're
    // LEAVING (not the one we're entering). Reading `friendHash`
    // directly inside cleanup would resolve to the new tab's hash
    // because Svelte runs cleanup AFTER the rune has settled to
    // its new value, which would clobber the new tab's draft with
    // text typed in the old tab.
    const hash = friendHash;
    if (hash) {
      sendError = null;
      // Restore any draft the user had typed for THIS conversation
      // before they switched tabs / closed the dock. New drafts
      // are saved in the cleanup below. Empty string is a valid
      // draft (the map slot is deleted on empty so we don't
      // accumulate empty entries from every visited tab).
      inputText = getDraft(hash);
      activeChatHash.set(hash);
      // Drop any unread badge accumulated for this friend BEFORE the
      // chat opened. `markAsRead` clears the DB rows; the global
      // store mirrored those counts and would stay stuck on the
      // pre-open value otherwise.
      clearUnread(hash);
      const gen = ++loadGen;
      if (unlisten) { unlisten(); unlisten = null; }
      messages = [];
      // Reset load state for the new conversation. Without this, the
      // previous tab's `loadError` (or stale `loading`/pagination flags)
      // is shown against the just-cleared (empty) message list during the
      // brief `await setupListener` window before `loadMessages` runs.
      loadError = null;
      loading = true;
      loadingOlder = false;
      hasMoreHistory = false;
      oldestDbId = null;
      // Await the listener registration BEFORE the historical
      // snapshot fetch starts. Otherwise a chat-message that arrives
      // during the (possibly 50–200 ms) `getChatMessages` round trip
      // is dropped on the floor — the listener isn't attached yet,
      // and the snapshot doesn't include rows that were inserted
      // after it began. `loadMessages` then merges its result
      // against any push events that landed in the meantime,
      // deduping by content tuple.
      (async () => {
        await setupListener(gen);
        if (gen !== loadGen) return;
        await loadMessages(gen);
      })();
      markAsRead();
    }
    return () => {
      loadGen++;
      if (unlisten) { unlisten(); unlisten = null; }
      // Save whatever the user has typed-but-not-sent against the
      // hash they were ON when this effect last ran. `inputText`
      // is a $state, so reading it here resolves to the latest
      // keystroke value — exactly what we want to stash.
      if (hash) setDraft(hash, inputText);
      // Clear active-chat tracking when the conversation closes or
      // the friend hash changes, so subsequent chat-message events
      // resume bumping `unreadCounts` as usual.
      activeChatHash.set(null);
    };
  });

  async function setupListener(gen: number) {
    if (gen !== loadGen) return;
    if (unlisten) { unlisten(); unlisten = null; }
    let fn: UnlistenFn;
    try {
      fn = await listen<{ user_hash: string; message: string; direction: string; timestamp: number }>('ember:chat-message', (event) => {
        if (gen !== loadGen) return;
        if (event.payload.user_hash === friendHash) {
          const wasPinned = isPinnedToBottom();
          const next = [...messages, {
            id: --msgIdCounter,
            direction: event.payload.direction as 'sent' | 'received',
            message: event.payload.message,
            timestamp: event.payload.timestamp,
            read: true,
          }];
          messages = next.length > MAX_LIVE_MESSAGES
            ? next.slice(next.length - MAX_LIVE_MESSAGES)
            : next;
          if (event.payload.direction === 'sent' || wasPinned) {
            scrollToBottom();
          }
          if (event.payload.direction === 'received') {
            markAsRead();
          }
        }
      });
    } catch (e) {
      console.warn('ChatConversation: failed to register chat listener', e);
      return;
    }
    if (gen !== loadGen) { fn(); return; }
    unlisten = fn;
  }

  async function loadMessages(gen: number) {
    loading = true;
    loadError = null;
    try {
      const rows = await getChatMessages(friendHash, PAGE_SIZE);
      if (gen !== loadGen) return;
      hasMoreHistory = rows.length >= PAGE_SIZE;
      const snapshot = rows.reverse();
      // snapshot is ascending (oldest first); record the oldest loaded id.
      if (snapshot.length > 0) oldestDbId = snapshot[0].id;
      if (messages.length === 0) {
        messages = snapshot;
      } else {
        const liveSig = new Set(
          messages.map((m) => `${m.timestamp}|${m.direction}|${m.message}`),
        );
        const filteredSnapshot = snapshot.filter(
          (m) => !liveSig.has(`${m.timestamp}|${m.direction}|${m.message}`),
        );
        messages = [...filteredSnapshot, ...messages];
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
    if (loadingOlder || !hasMoreHistory || !friendHash) return;
    loadingOlder = true;
    const gen = loadGen;
    try {
      const cursor = oldestDbId;
      if (cursor === null) {
        hasMoreHistory = false;
        return;
      }
      const rows = await getChatMessages(friendHash, PAGE_SIZE, cursor);
      if (gen !== loadGen) return;
      if (rows.length === 0) {
        hasMoreHistory = false;
        return;
      }
      hasMoreHistory = rows.length >= PAGE_SIZE;
      const olderPage = rows.reverse();
      // Advance the cursor to the new oldest loaded id (ascending order).
      if (olderPage.length > 0) oldestDbId = olderPage[0].id;
      const el = messagesContainerEl;
      const prevScrollHeight = el?.scrollHeight ?? 0;
      const prevScrollTop = el?.scrollTop ?? 0;
      messages = [...olderPage, ...messages];
      requestAnimationFrame(() => {
        if (!messagesContainerEl) return;
        const delta = messagesContainerEl.scrollHeight - prevScrollHeight;
        messagesContainerEl.scrollTop = prevScrollTop + delta;
      });
    } catch (e) {
      console.warn('loadOlderMessages failed:', e);
    } finally {
      if (gen === loadGen) loadingOlder = false;
    }
  }

  async function retryLoad() {
    if (!friendHash) return;
    const gen = ++loadGen;
    if (unlisten) { unlisten(); unlisten = null; }
    await setupListener(gen);
    if (gen !== loadGen) return;
    await loadMessages(gen);
  }

  async function markAsRead() {
    // Capture the hash up front: `friendHash` is a reactive prop that can
    // change while the IPC round-trip is in flight (fast tab switching), and
    // re-reading it after the await would clear unread for the WRONG friend.
    const h = friendHash;
    if (!h) return;
    try {
      await markMessagesRead(h);
      clearUnread(h);
    } catch (e) {
      console.warn('markMessagesRead failed:', e);
    }
  }

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

  async function handleSend() {
    const text = inputText.trim();
    if (!text || sending) return;
    sending = true;
    sendError = null;
    try {
      await sendChatMessage(friendHash, text);
      inputText = '';
      // The cleanup closure of the main $effect would re-stash the
      // (now empty) inputText on the next tab change, but if the
      // user closes the dock or quits the app right after sending
      // we want the draft slot gone immediately. `clearDraft` is a
      // no-op when there's no entry, so this is safe to call
      // unconditionally.
      clearDraft(friendHash);
    } catch (e: unknown) {
      sendError = translateError(e, m.chat_failed_to_send());
    } finally {
      sending = false;
    }
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
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
  });
</script>

<div class="conversation">
  <div class="conv-header">
    <div class="conv-header-info">
      <div class="conv-avatar" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.418 3.582-8 8-8s8 3.582 8 8"/>
        </svg>
      </div>
      <span class="conv-name">
        <span class="sr-only">{m.chat_friend_with_prefix()} </span><bdi>{friendName || friendHash.slice(0, 8) + '\u2026'}</bdi>
      </span>
      {#if isOnline}
        <span class="conv-status verified" title={m.chat_verified_title()} aria-label={m.chat_verified_aria()}>
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M3 8l3 3 7-7"/>
          </svg>
          <span>{m.chat_verified_label()}</span>
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
    </div>
  </div>

  <div class="conv-messages" bind:this={messagesContainerEl}>
    {#if loading}
      <div class="conv-loading">{m.chat_loading_messages()}</div>
    {:else if loadError}
      <div class="conv-load-error" role="alert">
        <span>{m.chat_load_error({ error: loadError })}</span>
        <button class="conv-load-retry" onclick={retryLoad} type="button">{m.common_retry()}</button>
      </div>
    {:else if messages.length === 0}
      <div class="conv-empty">{m.chat_say_hello()}</div>
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
            {loadingOlder ? m.chat_loading_short() : m.chat_load_older()}
          </button>
        </div>
      {/if}
      {#each messages as msg (msg.id)}
        <div class="conv-bubble" class:sent={msg.direction === 'sent'} class:received={msg.direction === 'received'}>
          <!--
            `<bdi>` isolates the message body from the surrounding UI's
            text direction so a peer-supplied RTL/LTR override character
            can't reorder neighbouring elements (a known "Trojan Source"-
            style spoofing class). The text is still rendered exactly as
            written; only its bidi influence is scoped to this element.
          -->
          <div class="bubble-text"><bdi>{msg.message}</bdi></div>
          <div class="bubble-time">{formatTime(msg.timestamp)}</div>
        </div>
      {/each}
    {/if}
    <div bind:this={messagesEnd}></div>
  </div>

  {#if sendError}
    <div class="conv-error">{sendError}</div>
  {/if}

  <div class="conv-input-area">
    <textarea
      class="conv-input"
      bind:value={inputText}
      bind:this={chatInputEl}
      onkeydown={handleKeydown}
      placeholder={m.chat_input_placeholder()}
      maxlength="4096"
      rows="2"
      disabled={sending}
    ></textarea>
    <button class="conv-send" onclick={handleSend} disabled={!inputText.trim() || sending} title={m.chat_send_title_short()} aria-label={m.chat_send_aria()}>
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M3 10l14-7-7 14-2-5z"/><line x1="10" y1="17" x2="17" y2="3"/>
      </svg>
    </button>
  </div>
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
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    line-height: 1;
    flex-shrink: 0;
  }

  .conv-status svg {
    width: 11px;
    height: 11px;
  }

  .conv-status.verified {
    background: color-mix(in srgb, var(--success, #2eb56d) 16%, transparent);
    color: var(--success, #2eb56d);
  }

  .conv-status.offline {
    background: var(--bg-tertiary);
    color: var(--text-muted);
  }

  .conv-messages {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
    display: flex;
    flex-direction: column;
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

  .conv-load-retry {
    padding: 6px 14px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-primary);
    font-size: 12px;
    cursor: pointer;
  }

  .conv-load-retry:hover {
    background: var(--bg-hover);
  }

  .conv-load-older {
    display: flex;
    justify-content: center;
    margin-bottom: 8px;
  }

  .conv-load-older-btn {
    padding: 6px 12px;
    border-radius: 999px;
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

  .conv-bubble {
    max-width: 80%;
    padding: 8px 12px;
    border-radius: 14px;
    font-size: 13px;
    line-height: 1.4;
    word-wrap: break-word;
    overflow-wrap: anywhere;
  }

  .conv-bubble.sent {
    align-self: flex-end;
    background: var(--accent);
    color: #fff;
    border-bottom-right-radius: 4px;
  }

  .conv-bubble.received {
    align-self: flex-start;
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border-bottom-left-radius: 4px;
  }

  .bubble-text {
    white-space: pre-wrap;
  }

  .bubble-time {
    font-size: 10px;
    opacity: 0.65;
    margin-top: 4px;
    text-align: right;
  }

  .conv-error {
    padding: 8px 14px;
    background: color-mix(in srgb, var(--danger) 14%, transparent);
    color: var(--danger);
    font-size: 12px;
    text-align: center;
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
    border-radius: var(--radius-sm);
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
    border: none;
    border-radius: var(--radius-sm);
    background: var(--accent);
    color: #fff;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: background var(--transition-fast), opacity var(--transition-fast);
  }

  .conv-send:hover:not(:disabled) {
    background: var(--accent-hover, var(--accent));
    filter: brightness(1.1);
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
