<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { getChatMessages, sendChatMessage, markMessagesRead, type ChatMessage } from '$lib/api/friends';

  interface Props {
    open: boolean;
    friendHash: string;
    friendName: string;
    onclose: () => void;
  }

  let { open = $bindable(), friendHash, friendName, onclose }: Props = $props();

  /**
   * Hard cap on in-memory chat messages per conversation. Old messages beyond
   * this are trimmed from the front of the array; they remain in the database
   * and can be re-fetched by reopening the conversation. Without the cap a
   * long-running session (or a friend spamming the channel) causes unbounded
   * memory growth.
   */
  const MAX_LIVE_MESSAGES = 500;

  let messages: ChatMessage[] = $state([]);
  let inputText = $state('');
  let loading = $state(false);
  let sending = $state(false);
  let sendError: string | null = $state(null);
  // Surfaced when `loadMessages` fails so users know the empty list
  // isn't actually empty — previously failures became a silent zero.
  let loadError: string | null = $state(null);
  let messagesEnd: HTMLDivElement | undefined = $state();
  let chatInputEl: HTMLTextAreaElement | undefined = $state();
  let panelEl: HTMLDivElement | undefined = $state();
  let unlisten: UnlistenFn | null = null;
  let loadGen = 0;
  let msgIdCounter = 0;
  // Captured opener so focus returns to wherever the user came from
  // when the sidebar closes. Without this, focus snaps back to <body>
  // and keyboard users lose their place in the friends grid.
  let returnFocusEl: HTMLElement | null = null;
  // Stable instance id for `aria-labelledby` so screen readers announce
  // the sidebar with the friend's name when it opens.
  const titleId = `chat-title-${Math.random().toString(36).slice(2, 10)}`;

  $effect(() => {
    if (open && chatInputEl) {
      requestAnimationFrame(() => chatInputEl?.focus());
    }
  });

  // Capture the focused element when the sidebar opens; restore it on close.
  $effect(() => {
    if (open && typeof document !== 'undefined') {
      const active = document.activeElement;
      if (active instanceof HTMLElement && active !== document.body) {
        returnFocusEl = active;
      }
    }
    return () => {
      if (returnFocusEl) {
        const el = returnFocusEl;
        returnFocusEl = null;
        // requestAnimationFrame defers focus until after the panel
        // unmounts, otherwise the browser may reject the focus call
        // because the active element is being torn down.
        requestAnimationFrame(() => {
          if (typeof document !== 'undefined' && document.contains(el)) {
            el.focus();
          }
        });
      }
    };
  });

  // Tab focus trap: keep keyboard focus inside the panel while it's
  // open. Mirrors the trap used in the KAD bootstrap modal so the
  // behaviour is identical across dialog-style overlays.
  function onPanelKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      onclose();
      return;
    }
    if (e.key !== 'Tab' || !panelEl) return;
    const focusables = panelEl.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );
    if (focusables.length === 0) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const active = document.activeElement as HTMLElement | null;
    if (e.shiftKey && active === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  }

  $effect(() => {
    if (open && friendHash) {
      sendError = null;
      inputText = '';
      // Bump both generations at the start so any in-flight loadMessages or
      // setupListener from a previous conversation abandon their work before
      // touching the UI. We pass the captured generation into setupListener
      // so a slow getChatMessages() doesn't re-attach a listener after the
      // user switched friends or closed the sidebar.
      const gen = ++loadGen;
      if (unlisten) { unlisten(); unlisten = null; }
      loadMessages(gen).then(() => {
        if (gen !== loadGen) return;
        setupListener(gen);
      });
      markAsRead();
    }
    return () => {
      loadGen++;
      if (unlisten) { unlisten(); unlisten = null; }
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
          scrollToBottom();
          if (event.payload.direction === 'received') {
            markAsRead();
          }
        }
      });
    } catch (e) {
      // Tauri's IPC bridge can reject `listen()` during teardown or if the
      // backend hasn't finished initialising. Log and fall back to a
      // load-only view; the UI still functions, just without live updates.
      console.warn('ChatSidebar: failed to register chat listener', e);
      return;
    }
    if (gen !== loadGen) { fn(); return; }
    unlisten = fn;
  }

  async function loadMessages(gen: number) {
    loading = true;
    loadError = null;
    try {
      const rows = await getChatMessages(friendHash, 100);
      if (gen !== loadGen) return;
      messages = rows.reverse();
      scrollToBottom();
    } catch (e: unknown) {
      if (gen !== loadGen) return;
      messages = [];
      loadError = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Failed to load messages';
    } finally {
      if (gen === loadGen) loading = false;
    }
  }

  async function retryLoad() {
    if (!friendHash) return;
    const gen = ++loadGen;
    await loadMessages(gen);
    if (gen !== loadGen) return;
    setupListener(gen);
  }

  async function markAsRead() {
    try { await markMessagesRead(friendHash); } catch {}
  }

  function scrollToBottom() {
    requestAnimationFrame(() => {
      messagesEnd?.scrollIntoView({ behavior: 'smooth' });
    });
  }

  async function handleSend() {
    const text = inputText.trim();
    if (!text || sending) return;
    sending = true;
    sendError = null;
    try {
      await sendChatMessage(friendHash, text);
      inputText = '';
    } catch (e: unknown) {
      sendError = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Failed to send';
    } finally {
      sending = false;
    }
  }

  function handleKeydown(e: KeyboardEvent) {
    // Enter sends; Shift+Enter inserts a newline. The textarea handles
    // the newline natively when we don't preventDefault. Escape is
    // handled by the panel-level `onPanelKeydown` (it bubbles up).
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

{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="chat-overlay" onclick={onclose}></div>
  <div
    class="chat-sidebar"
    bind:this={panelEl}
    role="dialog"
    aria-modal="true"
    aria-labelledby={titleId}
    tabindex="-1"
    onkeydown={onPanelKeydown}
  >
    <div class="chat-header">
      <div class="chat-header-info">
        <div class="chat-avatar" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.418 3.582-8 8-8s8 3.582 8 8"/>
          </svg>
        </div>
        <span class="chat-name" id={titleId}>
          <span class="sr-only">Chat with </span>{friendName || friendHash.slice(0, 8) + '\u2026'}
        </span>
      </div>
      <button class="chat-close" onclick={onclose} title="Close chat" aria-label="Close chat">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <line x1="4" y1="4" x2="12" y2="12"/><line x1="12" y1="4" x2="4" y2="12"/>
        </svg>
      </button>
    </div>

    <div class="chat-messages">
      {#if loading}
        <div class="chat-loading">Loading messages...</div>
      {:else if loadError}
        <div class="chat-load-error" role="alert">
          <span>Couldn't load messages — {loadError}</span>
          <button class="chat-load-retry" onclick={retryLoad} type="button">Retry</button>
        </div>
      {:else if messages.length === 0}
        <div class="chat-empty">No messages yet. Say hello!</div>
      {:else}
        {#each messages as msg (msg.id)}
          <div class="chat-bubble" class:sent={msg.direction === 'sent'} class:received={msg.direction === 'received'}>
            <div class="bubble-text">{msg.message}</div>
            <div class="bubble-time">{formatTime(msg.timestamp)}</div>
          </div>
        {/each}
      {/if}
      <div bind:this={messagesEnd}></div>
    </div>

    {#if sendError}
      <div class="chat-error">{sendError}</div>
    {/if}

    <div class="chat-input-area">
      <!-- Multi-line textarea so longer messages don't scroll
           horizontally inside a single-line input. Enter sends,
           Shift+Enter inserts a newline (handled in handleKeydown).
           The hint below the box documents the convention so users
           don't lose work to a stray Enter. -->
      <textarea
        class="chat-input"
        bind:value={inputText}
        bind:this={chatInputEl}
        onkeydown={handleKeydown}
        placeholder="Type a message... (Enter to send, Shift+Enter for newline)"
        maxlength="4096"
        rows="2"
        disabled={sending}
      ></textarea>
      <button class="chat-send" onclick={handleSend} disabled={!inputText.trim() || sending} title="Send (Enter)" aria-label="Send message">
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3 10l14-7-7 14-2-5z"/><line x1="10" y1="17" x2="17" y2="3"/>
        </svg>
      </button>
    </div>
  </div>
{/if}

<style>
  .chat-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.3);
    z-index: 999;
  }

  .chat-sidebar {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    width: 380px;
    max-width: 100vw;
    background: var(--bg-primary);
    border-left: 1px solid var(--border);
    z-index: 1000;
    display: flex;
    flex-direction: column;
    box-shadow: -4px 0 24px rgba(0, 0, 0, 0.2);
  }

  .chat-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
    flex-shrink: 0;
  }

  .chat-header-info {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
  }

  .chat-avatar {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: var(--accent-dim);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--accent);
    flex-shrink: 0;
  }

  .chat-avatar svg {
    width: 16px;
    height: 16px;
  }

  .chat-name {
    font-weight: 600;
    font-size: 14px;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .chat-close {
    width: 28px;
    height: 28px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-primary);
    color: var(--text-primary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .chat-close:hover {
    background: var(--danger);
    border-color: var(--danger);
    color: #fff;
  }

  .chat-close svg {
    width: 12px;
    height: 12px;
  }

  .chat-messages {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .chat-loading,
  .chat-empty {
    text-align: center;
    color: var(--text-muted);
    font-size: 13px;
    padding: 40px 16px;
  }

  .chat-bubble {
    max-width: 80%;
    padding: 8px 12px;
    border-radius: 12px;
    font-size: 13px;
    line-height: 1.45;
    word-break: break-word;
  }

  .chat-bubble.sent {
    align-self: flex-end;
    background: var(--accent);
    color: white;
    border-bottom-right-radius: 4px;
  }

  .chat-bubble.received {
    align-self: flex-start;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    color: var(--text-primary);
    border-bottom-left-radius: 4px;
  }

  .bubble-text {
    white-space: pre-wrap;
  }

  .bubble-time {
    font-size: 10px;
    opacity: 0.7;
    margin-top: 4px;
    text-align: right;
  }

  .chat-error {
    padding: 6px 16px;
    font-size: 12px;
    color: var(--danger);
    background: var(--bg-surface);
    border-top: 1px solid var(--border);
    flex-shrink: 0;
  }

  .chat-input-area {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 16px;
    border-top: 1px solid var(--border);
    background: var(--bg-surface);
    flex-shrink: 0;
  }

  .chat-input {
    flex: 1;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 13px;
    font-family: inherit;
    /* textarea-specific: vertical resize only and a sensible upper
       bound so a long paste doesn't push the input area off-screen. */
    resize: vertical;
    min-height: 38px;
    max-height: 180px;
    line-height: 1.4;
  }

  .chat-input:focus {
    border-color: var(--accent);
    outline: none;
  }

  /* Surfaced when message-history fetch fails. Mirrors the inline
     error pattern used elsewhere (e.g. KAD bootstrap), with a Retry
     button next to the message so users don't have to close + reopen
     the sidebar to recover. */
  .chat-load-error {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 24px 16px;
    color: var(--danger);
    font-size: 13px;
    text-align: center;
  }
  .chat-load-retry {
    padding: 4px 14px;
    font-size: 12px;
  }

  .chat-send {
    width: 36px;
    height: 36px;
    border: none;
    border-radius: var(--radius-md);
    background: var(--accent);
    color: white;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: opacity var(--transition-fast);
  }

  .chat-send:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .chat-send:not(:disabled):hover {
    opacity: 0.85;
  }

  .chat-send svg {
    width: 16px;
    height: 16px;
  }
</style>
