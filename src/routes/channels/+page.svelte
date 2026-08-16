<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import ChatConversation from '$lib/components/ChatConversation.svelte';
  import { appSettings } from '$lib/stores/settings';
  import { copyToClipboard } from '$lib/utils';
  import { toastError, toastSuccess } from '$lib/stores/toast';
  import { translateError } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';
  import {
    addChannelModerator,
    banChannelMember,
    createChannel,
    gatherChannels,
    getChannelInvite,
    joinChannel,
    leaveChannel,
    listChannelMembers,
    removeChannelModerator,
    transferChannelOwnership,
    unbanChannelMember,
    updateChannelModeration,
    type ChannelMemberInfo,
    type GatheredChannelInfo,
  } from '$lib/api/channels';
  import {
    activeChannelId,
    channels as channelsStore,
    clearChannelUnread,
    refreshChannels,
    replaceChannel,
  } from '$lib/stores/channels';

  let channelList = $derived($channelsStore);
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
  let editTopic = $state('');
  let editWelcome = $state('');
  let editingModeration = $state(false);
  let savingModeration = $state(false);
  let moderatingMember = $state<string | null>(null);
  let transferTarget = $state<ChannelMemberInfo | null>(null);
  let transferOpen = $state(false);

  let emberOff = $derived($appSettings?.ember_native_enabled === false);
  let selected = $derived(channelList.find((c) => c.channel_id === selectedId) ?? null);
  let canModerate = $derived(!!selected && (selected.is_owner || selected.you_are_moderator));
  let memberNames = $derived(
    Object.fromEntries(
      members.map((mem) => [
        mem.member_pubkey,
        mem.is_self ? m.channels_you() : mem.nickname,
      ]),
    ),
  );

  onMount(() => {
    const joinParam = $page.url.searchParams.get('join');
    if (joinParam) {
      joinUri = joinParam;
    }
    loadChannels();
    let cancelled = false;
    let unlistenMembers: UnlistenFn | undefined;
    listen<{ channel_id: string }>('ember:channel-members', (event) => {
      const id = event.payload.channel_id;
      refreshChannels().catch(() => {});
      if (id === selectedId) {
        listChannelMembers(id)
          .then((mems) => {
            members = mems;
          })
          .catch(() => {});
      }
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
      if (id === selectedId) {
        listChannelMembers(id)
          .then((mems) => {
            members = mems;
          })
          .catch(() => {});
      }
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenModeration = fn;
    });
    let unlistenHandoff: UnlistenFn | undefined;
    listen<{ channel_id: string; successor_id?: string }>('ember:channel-handoff', () => {
      refreshChannels()
        .then(() => {
          if (selectedId) {
            listChannelMembers(selectedId)
              .then((mems) => {
                members = mems;
              })
              .catch(() => {});
          }
        })
        .catch(() => {});
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenHandoff = fn;
    });
    return () => {
      cancelled = true;
      unlistenMembers?.();
      unlistenModeration?.();
      unlistenHandoff?.();
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
      await refreshChannels();
      if (selectedId && !$channelsStore.some((c) => c.channel_id === selectedId)) {
        activeChannelId.set(null);
        members = [];
      }
    } catch (e) {
      error = translateError(e, m.error_operation_failed());
    } finally {
      loading = false;
    }
  }

  async function selectChannel(id: string) {
    activeChannelId.set(id);
    try {
      members = await listChannelMembers(id);
      const ch = $channelsStore.find((c) => c.channel_id === id);
      editTopic = ch?.topic ?? '';
      editWelcome = ch?.welcome ?? '';
      editingModeration = false;
      clearChannelUnread(id);
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
      activeChannelId.set(null);
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

  async function handleSaveModeration() {
    if (!selectedId || savingModeration) return;
    savingModeration = true;
    try {
      const updated = await updateChannelModeration(selectedId, editTopic, editWelcome);
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
    if (!selectedId || moderatingMember) return;
    moderatingMember = memberPubkey;
    try {
      await banChannelMember(selectedId, memberPubkey);
      members = await listChannelMembers(selectedId);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      moderatingMember = null;
    }
  }

  async function handleUnban(memberPubkey: string) {
    if (!selectedId || moderatingMember) return;
    moderatingMember = memberPubkey;
    try {
      await unbanChannelMember(selectedId, memberPubkey);
      members = await listChannelMembers(selectedId);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      moderatingMember = null;
    }
  }

  async function handleAddModerator(memberPubkey: string) {
    if (!selectedId || moderatingMember) return;
    moderatingMember = memberPubkey;
    try {
      await addChannelModerator(selectedId, memberPubkey);
      members = await listChannelMembers(selectedId);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      moderatingMember = null;
    }
  }

  async function handleRemoveModerator(memberPubkey: string) {
    if (!selectedId || moderatingMember) return;
    moderatingMember = memberPubkey;
    try {
      await removeChannelModerator(selectedId, memberPubkey);
      members = await listChannelMembers(selectedId);
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
    if (!selectedId || !transferTarget) return;
    try {
      await transferChannelOwnership(selectedId, transferTarget.member_pubkey);
      toastSuccess(m.channels_transfer_started());
      await refreshChannels();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      transferTarget = null;
    }
  }

  async function openSuccessor() {
    const id = selected?.successor_id;
    if (!id) return;
    await refreshChannels().catch(() => {});
    if ($channelsStore.some((c) => c.channel_id === id)) {
      await selectChannel(id);
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
  <p class="limits-note">{m.channels_limits_note()}</p>

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
        {:else if channelList.length === 0}
          <p class="muted">{m.channels_empty()}</p>
        {:else}
          {#each channelList as ch}
            <button
              class="chan-row"
              class:active={ch.channel_id === selectedId}
              onclick={() => selectChannel(ch.channel_id)}
            >
              <span class="chan-name">{ch.name}</span>
              <span class="badge">{ch.visibility === 'private' ? m.channels_private_badge() : m.channels_public_badge()}</span>
              {#if ch.successor_id}
                <span class="badge">{m.channels_transferred_badge()}</span>
              {/if}
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
              {#if selected.topic}
                <p class="topic">{selected.topic}</p>
              {/if}
              {#if selected.welcome}
                <p class="welcome">{selected.welcome}</p>
              {/if}
              {#if !selected.topic && !selected.welcome}
                <p class="topic">{shortId(selected.channel_id)}</p>
              {/if}
            </div>
            <div class="conv-actions">
              <button class="ghost" onclick={handleCopyInvite}>{m.channels_invite()}</button>
              <button class="ghost danger" onclick={() => (leaveOpen = true)}>{m.channels_leave()}</button>
            </div>
          </header>
          {#if selected.successor_id}
            <div class="successor-banner" role="status">
              <span>{m.channels_successor_banner()}</span>
              <button class="ghost" onclick={openSuccessor}>{m.channels_open_successor()}</button>
            </div>
          {/if}
          {#if selected.is_owner}
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
              <button type="submit" disabled={savingModeration}>{m.channels_save_moderation()}</button>
            </form>
          {/if}
          <div class="transcript">
            <ChatConversation
              friendHash=""
              friendName={selected.name}
              channelId={selected.channel_id}
              hideHeader
              youAreBanned={selected.you_are_banned}
              memberNames={memberNames}
            />
          </div>
          {#if members.length > 0}
            <div class="members">
              <p class="members-label">{m.channels_members()}</p>
              <ul class="member-list">
                {#each members as mem (mem.member_pubkey)}
                  <li>
                    <span class="member-name">
                      {mem.is_self ? m.channels_you() : mem.nickname || shortId(mem.member_pubkey)}
                    </span>
                    {#if mem.banned}
                      <span class="badge banned">{m.channels_banned_badge()}</span>
                    {/if}
                    {#if mem.moderator}
                      <span class="badge">{m.channels_moderator_badge()}</span>
                    {/if}
                    {#if canModerate && !mem.is_self}
                      {#if mem.banned}
                        <button
                          class="ghost"
                          disabled={moderatingMember === mem.member_pubkey}
                          onclick={() => handleUnban(mem.member_pubkey)}
                        >
                          {m.channels_unban()}
                        </button>
                      {:else}
                        <button
                          class="ghost danger"
                          disabled={moderatingMember === mem.member_pubkey}
                          onclick={() => handleBan(mem.member_pubkey)}
                        >
                          {m.channels_ban()}
                        </button>
                      {/if}
                    {/if}
                    {#if selected.is_owner && !mem.is_self && !mem.banned && !selected.successor_id}
                      {#if mem.moderator}
                        <button
                          class="ghost"
                          disabled={moderatingMember === mem.member_pubkey}
                          onclick={() => handleRemoveModerator(mem.member_pubkey)}
                        >
                          {m.channels_remove_moderator()}
                        </button>
                      {:else}
                        <button
                          class="ghost"
                          disabled={moderatingMember === mem.member_pubkey}
                          onclick={() => handleAddModerator(mem.member_pubkey)}
                        >
                          {m.channels_add_moderator()}
                        </button>
                      {/if}
                      <button
                        class="ghost"
                        disabled={moderatingMember === mem.member_pubkey}
                        onclick={() => requestTransfer(mem)}
                      >
                        {m.channels_transfer_ownership()}
                      </button>
                    {/if}
                  </li>
                {/each}
              </ul>
            </div>
          {/if}
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

<style>
  .lede {
    color: var(--text-secondary);
    margin: 0 0 8px;
    max-width: 52rem;
  }
  .limits-note {
    color: var(--text-tertiary, var(--text-secondary));
    font-size: 0.85rem;
    margin: 0 0 16px;
    max-width: 52rem;
    line-height: 1.45;
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
  .transcript { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  .conv-header {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
  }
  .conv-header h3 { margin: 0; font-size: 16px; }
  .topic { margin: 2px 0 0; font-size: 12px; color: var(--text-secondary); }
  .welcome { margin: 4px 0 0; font-size: 13px; color: var(--text-secondary); }
  .conv-actions { display: flex; gap: 8px; }
  .successor-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 8px 14px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
    color: var(--text-secondary);
  }
  .moderation-form {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
  }
  .mod-label { margin: 0; font-size: 12px; color: var(--text-secondary); }
  .members { margin: 0; padding: 6px 14px; font-size: 12px; color: var(--text-secondary); border-top: 1px solid var(--border); }
  .members-label { margin: 0 0 6px; }
  .member-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
  .member-list li { display: flex; align-items: center; gap: 8px; }
  .member-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .badge.banned { color: var(--danger, #c44); border-color: var(--danger, #c44); }
  .banned-banner {
    margin: 0;
    padding: 10px 14px;
    border-top: 1px solid var(--border);
    color: var(--danger, #c44);
    font-size: 13px;
  }
  .composer { display: flex; gap: 8px; padding: 10px 14px; border-top: 1px solid var(--border); }
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
  .muted { color: var(--text-secondary); }
  .pad { padding: 24px; }
  .danger { color: var(--danger, #c44); }
  .discovered { margin-bottom: 12px; }
  @media (max-width: 800px) {
    .split { grid-template-columns: 1fr; }
  }
</style>
