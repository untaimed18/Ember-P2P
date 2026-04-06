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

  let messages: ChatMessage[] = $state([]);
  let inputText = $state('');
  let loading = $state(false);
  let sending = $state(false);
  let sendError: string | null = $state(null);
  let messagesEnd: HTMLDivElement | undefined = $state();
  let chatInputEl: HTMLInputElement | undefined = $state();
  let unlisten: UnlistenFn | null = null;
  let listenerGen = 0;
  let loadGen = 0;
  let msgIdCounter = 0;

  $effect(() => {
    if (open && chatInputEl) {
      requestAnimationFrame(() => chatInputEl?.focus());
    }
  });

  $effect(() => {
    if (open && friendHash) {
      sendError = null;
      inputText = '';
      loadMessages().then(() => setupListener());
      markAsRead();
    }
    return () => {
      listenerGen++;
      if (unlisten) { unlisten(); unlisten = null; }
    };
  });

  async function setupListener() {
    const gen = ++listenerGen;
    if (unlisten) { unlisten(); unlisten = null; }
    const fn = await listen<{ user_hash: string; message: string; direction: string; timestamp: number }>('ember:chat-message', (event) => {
      if (event.payload.user_hash === friendHash) {
        messages = [...messages, {
          id: --msgIdCounter,
          direction: event.payload.direction as 'sent' | 'received',
          message: event.payload.message,
          timestamp: event.payload.timestamp,
          read: true,
        }];
        scrollToBottom();
        if (event.payload.direction === 'received') {
          markAsRead();
        }
      }
    });
    if (gen !== listenerGen) { fn(); return; }
    unlisten = fn;
  }

  async function loadMessages() {
    const gen = ++loadGen;
    loading = true;
    try {
      const rows = await getChatMessages(friendHash, 100);
      if (gen !== loadGen) return;
      messages = rows.reverse();
      scrollToBottom();
    } catch {
      if (gen !== loadGen) return;
      messages = [];
    } finally {
      if (gen === loadGen) loading = false;
    }
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
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
    if (e.key === 'Escape') {
      onclose();
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
  <div class="chat-sidebar">
    <div class="chat-header">
      <div class="chat-header-info">
        <div class="chat-avatar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.418 3.582-8 8-8s8 3.582 8 8"/>
          </svg>
        </div>
        <span class="chat-name">{friendName || friendHash.slice(0, 8) + '\u2026'}</span>
      </div>
      <button class="chat-close" onclick={onclose} title="Close chat">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <line x1="4" y1="4" x2="12" y2="12"/><line x1="12" y1="4" x2="4" y2="12"/>
        </svg>
      </button>
    </div>

    <div class="chat-messages">
      {#if loading}
        <div class="chat-loading">Loading messages...</div>
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
      <input
        type="text"
        class="chat-input"
        bind:value={inputText}
        bind:this={chatInputEl}
        onkeydown={handleKeydown}
        placeholder="Type a message..."
        maxlength="4096"
        disabled={sending}
      />
      <button class="chat-send" onclick={handleSend} disabled={!inputText.trim() || sending} title="Send">
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
  }

  .chat-input:focus {
    border-color: var(--accent);
    outline: none;
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
