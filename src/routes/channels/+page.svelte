<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import { appSettings } from '$lib/stores/settings';
  import { copyToClipboard } from '$lib/utils';
  import { toastError, toastSuccess } from '$lib/stores/toast';
  import { translateError } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';
  import {
    createChannel,
    gatherChannels,
    getChannelInvite,
    getChannelMessages,
    joinChannel,
    leaveChannel,
    listChannelMembers,
    listChannels,
    markChannelMessagesRead,
    sendChannelMessage,
    type ChannelInfo,
    type ChannelMemberInfo,
    type ChannelMessageInfo,
    type GatheredChannelInfo,
  } from '$lib/api/channels';

  const MAX_MESSAGE_BYTES = 4096;

  let channels: ChannelInfo[] = $state([]);
  let selectedId: string | null = $state(null);
  let members: ChannelMemberInfo[] = $state([]);
  let messages: ChannelMessageInfo[] = $state([]);
  let loading = $state(true);
  let sending = $state(false);
  let discovering = $state(false);
  let discovered: GatheredChannelInfo[] = $state([]);
  let inputText = $state('');
  let createName = $state('');
  let createPrivate = $state(false);
  let joinUri = $state('');
  let error: string | null = $state(null);
  let leaveOpen = $state(false);
  let messagesEnd: HTMLDivElement | undefined = $state();

  let emberOff = $derived($appSettings?.ember_native_enabled === false);
  let selected = $derived(channels.find((c) => c.channel_id === selectedId) ?? null);

  onMount(() => {
    const joinParam = $page.url.searchParams.get('join');
    if (joinParam) {
      joinUri = joinParam;
    }
    loadChannels();
    let cancelled = false;
    let unlisten: UnlistenFn | undefined;
    listen<{
      id: number;
      channel_id: string;
      sender_pubkey: string;
      direction: string;
      message: string;
      timestamp: number;
    }>('ember:channel-message', (event) => {
      const payload = event.payload;
      if (payload.channel_id === selectedId) {
        if (messages.some((msg) => msg.id === payload.id)) return;
        messages = [
          ...messages,
          {
            id: payload.id,
            sender_pubkey: payload.sender_pubkey,
            direction: payload.direction,
            message: payload.message,
            timestamp: payload.timestamp,
            read: true,
          },
        ];
        markChannelMessagesRead(payload.channel_id).catch(() => {});
        queueMicrotask(() => messagesEnd?.scrollIntoView({ block: 'end' }));
      } else {
        channels = channels.map((c) =>
          c.channel_id === payload.channel_id ? { ...c, unread: c.unread + 1 } : c,
        );
      }
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  });

  $effect(() => {
    if (emberOff) {
      goto('/ember').catch(() => {});
    }
  });

  async function loadChannels() {
    loading = true;
    error = null;
    try {
      channels = await listChannels();
      if (selectedId && !channels.some((c) => c.channel_id === selectedId)) {
        selectedId = null;
        messages = [];
        members = [];
      }
    } catch (e) {
      error = translateError(e, m.error_operation_failed());
    } finally {
      loading = false;
    }
  }

  async function selectChannel(id: string) {
    selectedId = id;
    inputText = '';
    try {
      const [msgs, mems] = await Promise.all([
        getChannelMessages(id, 100),
        listChannelMembers(id),
      ]);
      messages = msgs.slice().reverse();
      members = mems;
      await markChannelMessagesRead(id);
      channels = channels.map((c) => (c.channel_id === id ? { ...c, unread: 0 } : c));
      queueMicrotask(() => messagesEnd?.scrollIntoView({ block: 'end' }));
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  async function handleCreate() {
    error = null;
    try {
      const invite = await createChannel(createName.trim(), createPrivate);
      createName = '';
      createPrivate = false;
      await loadChannels();
      await selectChannel(invite.channel_id);
      await copyToClipboard(invite.uri);
      toastSuccess(m.channels_invite_copied());
    } catch (e) {
      error = translateError(e, m.error_operation_failed());
    }
  }

  async function handleJoin(uri = joinUri) {
    error = null;
    try {
      const joined = await joinChannel(uri.trim());
      joinUri = '';
      await loadChannels();
      await selectChannel(joined.channel_id);
    } catch (e) {
      error = translateError(e, m.error_operation_failed());
    }
  }

  async function handleLeave() {
    if (!selectedId) return;
    try {
      await leaveChannel(selectedId);
      selectedId = null;
      messages = [];
      members = [];
      await loadChannels();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  async function handleCopyInvite() {
    if (!selectedId) return;
    try {
      const invite = await getChannelInvite(selectedId);
      await copyToClipboard(invite.uri);
      toastSuccess(m.channels_invite_copied());
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  async function handleDiscover() {
    discovering = true;
    try {
      discovered = await gatherChannels();
      if (discovered.length === 0) {
        toastSuccess(m.channels_none_found());
      }
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      discovering = false;
    }
  }

  async function joinDiscovered(item: GatheredChannelInfo) {
    const uri = `ember-channel:${item.channel_id}?pk=${item.pubkey}&name=${encodeURIComponent(item.name)}`;
    await handleJoin(uri);
  }

  async function handleSend() {
    if (!selectedId || sending) return;
    const text = inputText.trim();
    if (!text) return;
    if (new TextEncoder().encode(text).length > MAX_MESSAGE_BYTES) {
      toastError(m.error_channels_message_size_invalid());
      return;
    }
    sending = true;
    try {
      const sent = await sendChannelMessage(selectedId, text);
      messages = [...messages, sent];
      inputText = '';
      queueMicrotask(() => messagesEnd?.scrollIntoView({ block: 'end' }));
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      sending = false;
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  function shortId(id: string): string {
    return id.slice(0, 8) + '\u2026';
  }
</script>

<div class="page-header">
  <h2>{m.nav_channels()}</h2>
  <div class="header-actions">
    <button class="ghost" onclick={handleDiscover} disabled={discovering}>
      {discovering ? m.channels_discovering() : m.channels_discover()}
    </button>
  </div>
</div>

<div class="page-content channels-page">
  <p class="lede">{m.channels_page_subtitle()}</p>

  {#if error}
    <div class="banner error-banner" role="alert">{error}</div>
  {/if}

  {#if emberOff}
    <div class="banner" role="status">
      <strong>{m.channels_disabled_title()}</strong>
      {m.channels_disabled_body()}
    </div>
  {:else}
    <div class="composer-row">
      <form class="create-form" onsubmit={(e) => { e.preventDefault(); handleCreate(); }}>
        <input
          bind:value={createName}
          placeholder={m.channels_name_placeholder()}
          maxlength="64"
          aria-label={m.channels_name_placeholder()}
        />
        <label class="private-toggle">
          <input type="checkbox" bind:checked={createPrivate} />
          {m.channels_private_label()}
        </label>
        <button type="submit" disabled={!createName.trim()}>{m.channels_create()}</button>
      </form>
      <form class="join-form" onsubmit={(e) => { e.preventDefault(); handleJoin(); }}>
        <input
          bind:value={joinUri}
          placeholder={m.channels_join_placeholder()}
          aria-label={m.channels_join_title()}
        />
        <button type="submit" disabled={!joinUri.trim()}>{m.channels_join()}</button>
      </form>
    </div>

    {#if discovered.length > 0}
      <div class="discovered">
        {#each discovered as item}
          <button
            class="disc-row"
            disabled={item.joined}
            onclick={() => joinDiscovered(item)}
          >
            <span class="disc-name">{item.name || shortId(item.channel_id)}</span>
            <span class="badge">{item.joined ? m.channels_joined() : m.channels_public_badge()}</span>
          </button>
        {/each}
      </div>
    {/if}

    <div class="split">
      <aside class="list">
        {#if loading}
          <p class="muted">{m.common_loading()}</p>
        {:else if channels.length === 0}
          <p class="muted">{m.channels_empty()}</p>
        {:else}
          {#each channels as ch}
            <button
              class="chan-row"
              class:active={ch.channel_id === selectedId}
              onclick={() => selectChannel(ch.channel_id)}
            >
              <span class="chan-name">{ch.name}</span>
              <span class="badge">{ch.visibility === 'private' ? m.channels_private_badge() : m.channels_public_badge()}</span>
              {#if ch.unread > 0}
                <span class="unread">{ch.unread}</span>
              {/if}
            </button>
          {/each}
        {/if}
      </aside>

      <section class="conversation">
        {#if !selected}
          <p class="muted pad">{m.channels_no_selection()}</p>
        {:else}
          <header class="conv-header">
            <div>
              <h3>{selected.name}</h3>
              <p class="topic">{selected.topic || selected.welcome || shortId(selected.channel_id)}</p>
            </div>
            <div class="conv-actions">
              <button class="ghost" onclick={handleCopyInvite}>{m.channels_invite()}</button>
              <button class="ghost danger" onclick={() => (leaveOpen = true)}>{m.channels_leave()}</button>
            </div>
          </header>
          <div class="messages">
            {#each messages as msg (msg.id)}
              <div class="bubble" class:mine={msg.direction === 'sent'}>
                <span class="who">{msg.direction === 'sent' ? m.channels_you() : shortId(msg.sender_pubkey)}</span>
                <p>{msg.message}</p>
              </div>
            {/each}
            <div bind:this={messagesEnd}></div>
          </div>
          {#if members.length > 0}
            <p class="members">{m.channels_members()}: {members.map((x) => x.nickname || shortId(x.member_pubkey)).join(', ')}</p>
          {/if}
          <div class="composer">
            <textarea
              bind:value={inputText}
              onkeydown={onKeydown}
              placeholder={m.channels_send_placeholder()}
              maxlength="4096"
              rows="2"
              disabled={sending}
            ></textarea>
            <button onclick={handleSend} disabled={!inputText.trim() || sending}>{m.chat_send_title_short()}</button>
          </div>
        {/if}
      </section>
    </div>
  {/if}
</div>

<ConfirmDialog
  bind:open={leaveOpen}
  title={m.channels_leave_confirm()}
  message={m.channels_leave_confirm_body({ name: selected?.name ?? '' })}
  confirmLabel={m.channels_leave()}
  danger
  onconfirm={handleLeave}
/>

<style>
  .lede {
    color: var(--text-secondary);
    margin: 0 0 16px;
    max-width: 52rem;
  }
  .banner {
    padding: 10px 12px;
    border-radius: 8px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    margin-bottom: 12px;
  }
  .error-banner { border-color: var(--danger, #c44); color: var(--danger, #c44); }
  .composer-row {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 16px;
  }
  .create-form, .join-form {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    flex: 1;
    min-width: 280px;
  }
  input, textarea {
    flex: 1;
    min-width: 0;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    color: var(--text-primary);
    border-radius: 6px;
    padding: 8px 10px;
  }
  .private-toggle {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    color: var(--text-secondary);
  }
  .split {
    display: grid;
    grid-template-columns: minmax(220px, 280px) 1fr;
    gap: 12px;
    min-height: 420px;
  }
  .list, .conversation {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    min-height: 0;
  }
  .list { padding: 8px; overflow: auto; }
  .chan-row, .disc-row {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    text-align: left;
    padding: 8px 10px;
    border: 0;
    background: transparent;
    color: inherit;
    border-radius: 8px;
    cursor: pointer;
  }
  .chan-row.active, .chan-row:hover, .disc-row:hover { background: var(--bg-primary); }
  .chan-name, .disc-name { flex: 1; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .badge {
    font-size: 11px;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 1px 7px;
  }
  .unread {
    min-width: 18px;
    height: 18px;
    border-radius: 9px;
    background: var(--accent);
    color: #fff;
    font-size: 11px;
    display: grid;
    place-items: center;
    padding: 0 5px;
  }
  .conversation { display: flex; flex-direction: column; }
  .conv-header {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
  }
  .conv-header h3 { margin: 0; font-size: 16px; }
  .topic { margin: 2px 0 0; font-size: 12px; color: var(--text-secondary); }
  .conv-actions { display: flex; gap: 8px; }
  .messages { flex: 1; overflow: auto; padding: 12px 14px; display: flex; flex-direction: column; gap: 8px; }
  .bubble {
    max-width: 80%;
    align-self: flex-start;
    background: var(--bg-primary);
    border-radius: 10px;
    padding: 6px 10px;
  }
  .bubble.mine { align-self: flex-end; background: var(--accent-dim, var(--bg-primary)); }
  .who { display: block; font-size: 11px; color: var(--text-secondary); margin-bottom: 2px; }
  .bubble p { margin: 0; white-space: pre-wrap; word-break: break-word; }
  .members { margin: 0; padding: 6px 14px; font-size: 12px; color: var(--text-secondary); border-top: 1px solid var(--border); }
  .composer { display: flex; gap: 8px; padding: 10px 14px; border-top: 1px solid var(--border); }
  .muted { color: var(--text-secondary); }
  .pad { padding: 24px; }
  .danger { color: var(--danger, #c44); }
  .discovered { margin-bottom: 12px; }
  @media (max-width: 800px) {
    .split { grid-template-columns: 1fr; }
  }
</style>
