<script lang="ts">
  /*
   * A private conversation with a room member, in the chat dock.
   *
   * Messages travel through a room both are in, sealed to the recipient
   * (`network::ember::room_dm`). There is no history to catch up on: a
   * message reaches someone online while it is being sent, and the sender
   * hears back with a receipt or marks it not delivered.
   *
   * The dock remounts this for each member (`{#key}`), so nothing here —
   * the draft above all — can carry over to someone else.
   */
  import { onMount, tick, untrack } from 'svelte';
  import { get } from 'svelte/store';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import {
    answerRoomDmRequest,
    getRoomDmMessages,
    markRoomDmRead,
    retryRoomDm,
    sendRoomDm,
    ROOM_DM_MESSAGE_EVENT,
    ROOM_DM_STATUS_EVENT,
    type RoomDmMessage,
    type RoomDmMessageEvent,
    type RoomDmStatusEvent,
  } from '$lib/api/roomDm';
  import { dmTabKey, dmThreads, keepDmTab, refreshDmThreads, viewingDm } from '$lib/stores/roomDm';
  import { activeChatHash } from '$lib/stores/friends';
  import { appSettings } from '$lib/stores/settings';
  import { toastError } from '$lib/stores/toast';
  import { translateError } from '$lib/i18n';
  import { formatCalendarDate, formatClockTime } from '$lib/utils';
  import * as m from '$lib/paraglide/messages';

  interface Props {
    member: string;
    name: string;
  }
  let { member, name }: Props = $props();

  /** Mirrors `DM_TEXT_MAX_BYTES` in `network/ember/room_dm.rs`: what one
   *  datagram carries, relay envelope and all, once the room's envelope is
   *  counted. */
  const DM_TEXT_MAX_BYTES = 3651;
  const encoder = new TextEncoder();
  const TOO_LONG_ID = `dm-too-long-${Math.random().toString(36).slice(2)}`;

  // Fixed for this instance: the dock remounts for another member.
  const who = untrack(() => member.toLowerCase());

  let messages = $state<RoomDmMessage[]>([]);
  let loading = $state(true);
  let draft = $state('');
  let sending = $state(false);
  let answering = $state(false);
  let listEl: HTMLDivElement | undefined = $state();

  let thread = $derived($dmThreads.find((t) => t.member_pubkey === who) ?? null);
  let shownName = $derived(name.trim() || thread?.name || m.channels_dm_someone());
  let draftBytes = $derived(encoder.encode(draft).length);
  let tooLong = $derived(draftBytes > DM_TEXT_MAX_BYTES);
  let policyOff = $derived($appSettings?.room_dm_policy === 'off');
  /** The user declined this request while it was on screen. Opened later,
   *  a declined conversation offers to write: doing so lifts the refusal. */
  let declinedHere = $state(false);
  let justDeclined = $derived(declinedHere && thread?.state === 'declined');

  /** Why nothing can be written here, or null when something can. */
  let blocked = $derived.by((): string | null => {
    if (thread?.state === 'request') return null;
    if (justDeclined) return m.channels_dm_you_declined({ name: shownName });
    if (thread?.is_friend) return m.channels_dm_is_friend();
    if (policyOff) return m.channels_dm_policy_off();
    if (thread?.peer_state === 'declined') return m.channels_dm_peer_declined({ name: shownName });
    if (thread && !thread.can_send) return m.channels_dm_no_shared_room();
    return null;
  });

  function rowKey(row: RoomDmMessage): string {
    return `${row.direction}:${row.message_id}`;
  }

  /** Rows from storage, with any that arrived or were sent while they were
   *  read: a load must not drop those, nor hold one twice. */
  function merged(stored: RoomDmMessage[], live: RoomDmMessage[]): RoomDmMessage[] {
    const keys = new Set(stored.map(rowKey));
    return [...stored, ...live.filter((row) => !keys.has(rowKey(row)))].sort((a, b) => a.timestamp - b.timestamp);
  }

  function atBottom(): boolean {
    return !listEl || listEl.scrollHeight - listEl.scrollTop - listEl.clientHeight < 48;
  }

  async function scrollToEnd(force = false) {
    const stick = force || atBottom();
    await tick();
    if (listEl && stick) listEl.scrollTop = listEl.scrollHeight;
  }

  let loadSeq = 0;
  /** Read the conversation from storage. `replace` when what is stored may
   *  have lost rows (declined, deleted): only rows that arrived during the
   *  read are kept from the screen. */
  async function load(replace = false) {
    const seq = ++loadSeq;
    const shownBefore = new Set(messages.map(rowKey));
    loading = true;
    try {
      const rows = await getRoomDmMessages(who);
      if (seq !== loadSeq) return;
      messages = merged(rows, replace ? messages.filter((row) => !shownBefore.has(rowKey(row))) : messages);
      await scrollToEnd(true);
    } catch (e) {
      if (seq === loadSeq) toastError(translateError(e, m.error_operation_failed()));
    } finally {
      if (seq === loadSeq) loading = false;
    }
  }

  let marking = false;
  /** Mark the conversation read while something in it is unread and it is
   *  on screen: on arrival, on accept, on coming back to the window. */
  async function markReadIfSeen() {
    const current = get(dmThreads).find((t) => t.member_pubkey === who);
    if (marking || !current || current.state !== 'open' || current.unread === 0 || !viewingDm(who)) return;
    marking = true;
    try {
      await markRoomDmRead(who);
      await refreshDmThreads();
    } catch (e) {
      console.warn('roomDm: could not mark read', e);
    } finally {
      marking = false;
    }
  }

  $effect(() => {
    // Re-run on the counts and the state, not on every refresh.
    void thread?.unread;
    void thread?.state;
    untrack(() => void markReadIfSeen());
  });

  // The conversation changed under us (answered, declined, deleted): read it
  // again. Keyed on the state, so a refresh that changes nothing is not a load.
  let stateKey = $derived(`${thread?.state ?? ''}|${thread?.peer_state ?? ''}`);
  let seenStateKey: string | null = null;
  $effect(() => {
    const key = stateKey;
    if (seenStateKey !== null && key !== seenStateKey) {
      // Declined from the Channels page counts as declined here too.
      if (seenStateKey.startsWith('request|') && key.startsWith('declined|')) declinedHere = true;
      untrack(() => void load(true));
    }
    seenStateKey = key;
  });

  onMount(() => {
    void load();
    // Tells the chat window's presence report, and through it the main
    // window, which conversation is on screen.
    const tabKey = dmTabKey(who);
    activeChatHash.set(tabKey);
    const onSeen = () => void markReadIfSeen();
    document.addEventListener('visibilitychange', onSeen);
    window.addEventListener('focus', onSeen);
    const unlisten: UnlistenFn[] = [];
    let alive = true;
    void (async () => {
      const fns = await Promise.all([
        listen<RoomDmMessageEvent>(ROOM_DM_MESSAGE_EVENT, (event) => {
          const msg = event.payload;
          if (msg.member_pubkey !== who) return;
          const row: RoomDmMessage = {
            message_id: msg.message_id,
            member_pubkey: msg.member_pubkey,
            direction: 'in',
            text: msg.text,
            timestamp: msg.timestamp,
            status: 'received',
          };
          messages = merged(messages, [row]);
          void scrollToEnd();
        }),
        listen<RoomDmStatusEvent>(ROOM_DM_STATUS_EVENT, (event) => {
          const update = event.payload;
          if (update.member_pubkey !== who) return;
          messages = messages.map((row) =>
            row.direction === 'out' && row.message_id === update.message_id ? { ...row, status: update.status } : row,
          );
        }),
      ]);
      if (alive) unlisten.push(...fns);
      else fns.forEach((fn) => fn());
    })();
    return () => {
      alive = false;
      unlisten.forEach((fn) => fn());
      document.removeEventListener('visibilitychange', onSeen);
      window.removeEventListener('focus', onSeen);
      if (get(activeChatHash) === tabKey) activeChatHash.set(null);
    };
  });

  async function send() {
    const text = draft.trim();
    if (!text || tooLong || sending || blocked) return;
    sending = true;
    try {
      const sent = await sendRoomDm(who, text);
      messages = merged(messages, [sent]);
      draft = '';
      void refreshDmThreads();
      await scrollToEnd(true);
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      sending = false;
    }
  }

  async function answer(accept: boolean) {
    if (answering) return;
    answering = true;
    try {
      await answerRoomDmRequest(who, accept);
      if (accept) keepDmTab(who, shownName);
      else {
        declinedHere = true;
        messages = [];
      }
      await refreshDmThreads();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    } finally {
      answering = false;
    }
  }

  async function retry(row: RoomDmMessage) {
    try {
      await retryRoomDm(who, row.message_id);
      messages = messages.map((each) =>
        rowKey(each) === rowKey(row) ? { ...each, status: 'sending' } : each,
      );
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.isComposing || e.keyCode === 229) return;
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void send();
    }
  }

  /** A message's time, with its date when it was not today. */
  function timeOf(ts: number): string {
    const clock = formatClockTime(ts, { hour: 'numeric', minute: '2-digit' });
    const sameDay = new Date(ts * 1000).toDateString() === new Date().toDateString();
    return sameDay ? clock : `${formatCalendarDate(ts)} ${clock}`;
  }

  function statusLabel(row: RoomDmMessage): string {
    if (row.status === 'sending') return m.channels_dm_status_sending();
    if (row.status === 'delivered') return m.channels_dm_status_delivered();
    if (row.status === 'failed') return m.channels_dm_status_failed();
    return '';
  }
</script>

<div class="dm">
  {#if thread?.state === 'request'}
    <div class="dm-banner" role="region" aria-label={m.channels_dm_request_banner({ name: shownName })}>
      <span>{m.channels_dm_request_banner({ name: shownName })}</span>
      <div class="dm-banner-actions">
        <button type="button" class="primary" disabled={answering} onclick={() => void answer(true)}>
          {m.channels_dm_accept()}
        </button>
        <button type="button" class="ghost" disabled={answering} onclick={() => void answer(false)}>
          {m.channels_dm_decline()}
        </button>
      </div>
    </div>
  {/if}

  <div
    class="dm-list"
    bind:this={listEl}
    role="log"
    aria-relevant="additions"
    aria-busy={loading}
    aria-label={m.channels_dm_tab_label({ name: shownName })}
  >
    {#if loading && messages.length === 0}
      <p class="dm-empty">{m.chat_loading_messages()}</p>
    {:else if messages.length === 0 && !justDeclined}
      <p class="dm-empty">{m.channels_dm_empty_hint()}</p>
    {/if}
    {#each messages as row (rowKey(row))}
      <div class="dm-row" class:out={row.direction === 'out'}>
        <div class="dm-bubble">
          <p class="dm-text"><bdi dir="auto">{row.text}</bdi></p>
          <span class="dm-meta">
            {timeOf(row.timestamp)}
            {#if row.direction === 'out' && row.status !== 'received'}
              · <span class:dm-failed={row.status === 'failed'}>{statusLabel(row)}</span>
            {/if}
          </span>
          {#if row.status === 'failed' && !blocked}
            <button
              type="button"
              class="dm-retry"
              aria-label={m.channels_dm_retry_aria({ text: row.text.slice(0, 40) })}
              onclick={() => void retry(row)}
            >{m.channels_dm_retry()}</button>
          {/if}
        </div>
      </div>
    {/each}
  </div>

  {#if blocked}
    <p class="dm-blocked" role="status">{blocked}</p>
  {:else if thread?.state !== 'request'}
    <div class="dm-compose">
      <textarea
        bind:value={draft}
        rows="2"
        placeholder={m.channels_dm_placeholder({ name: shownName })}
        aria-label={m.channels_dm_placeholder({ name: shownName })}
        aria-invalid={tooLong}
        aria-describedby={tooLong ? TOO_LONG_ID : undefined}
        onkeydown={onKeydown}
      ></textarea>
      <button type="button" class="primary" disabled={sending || tooLong || !draft.trim()} onclick={() => void send()}>
        {m.channels_dm_send()}
      </button>
    </div>
    {#if tooLong}
      <p class="dm-too-long" id={TOO_LONG_ID} role="alert">{m.channels_dm_too_long()}</p>
    {/if}
  {/if}
  <p class="dm-privacy">{m.channels_dm_privacy_hint()}</p>
</div>

<style>
  .dm {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
  }

  .dm-banner {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin: 8px 12px 0;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-secondary);
    font-size: var(--font-size-sm);
  }

  .dm-banner-actions {
    display: flex;
    gap: 8px;
  }

  .dm-list {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .dm-empty {
    margin: auto;
    max-width: 30ch;
    text-align: center;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }

  .dm-row {
    display: flex;
  }

  .dm-row.out {
    justify-content: flex-end;
  }

  .dm-bubble {
    max-width: 80%;
    padding: 6px 10px;
    border-radius: var(--bubble-radius, var(--radius-md));
    background: var(--bg-tertiary);
  }

  .dm-row.out .dm-bubble {
    background: var(--accent);
    color: var(--on-accent);
  }

  .dm-text {
    margin: 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  .dm-meta {
    display: block;
    margin-top: 2px;
    font-size: var(--font-size-2xs);
    opacity: 0.75;
  }

  .dm-failed {
    font-weight: 600;
  }

  .dm-retry {
    margin-top: 4px;
    padding: 2px 8px;
    font-size: var(--font-size-xs);
  }

  .dm-compose {
    display: flex;
    gap: 8px;
    padding: 8px 12px 0;
    align-items: flex-end;
  }

  .dm-compose textarea {
    flex: 1;
    resize: none;
    min-height: 2.5em;
    background: var(--bg-input);
    border: 1px solid var(--input-border);
    border-radius: var(--radius-md);
    color: var(--text-primary);
    padding: 6px 8px;
    font: inherit;
  }

  .dm-too-long {
    margin: 4px 12px 0;
    color: var(--danger);
    font-size: var(--font-size-xs);
  }

  .dm-blocked {
    margin: 8px 12px 0;
    color: var(--text-secondary);
    font-size: var(--font-size-sm);
  }

  .dm-privacy {
    margin: 6px 12px 10px;
    color: var(--text-muted);
    font-size: var(--font-size-2xs);
  }
</style>
