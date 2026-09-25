<script lang="ts">
  import {
    CHAT_ATTACHMENT_TERMINAL,
    cancelChatAttachment,
    openChatAttachment,
    respondChatAttachment,
    type ChatAttachment,
  } from '$lib/api/friends';
  import { formatBytes } from '$lib/utils';
  import { toastError } from '$lib/stores/toast';
  import { translateError } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';

  interface Props {
    attachment: ChatAttachment;
    /** Who is on the other end, for the status line. */
    friendName: string;
    /** Already formatted, so the transcript's clock and this one agree. */
    time: string;
  }

  let { attachment, friendName, time }: Props = $props();

  /** One action at a time. Every button here is a round trip that changes the
   *  row, and the next event redraws it — two clicks in flight would race. */
  let busy = $state(false);

  let sent = $derived(attachment.direction === 'sent');
  let percent = $derived(
    attachment.size > 0
      ? Math.min(100, Math.floor((attachment.transferred / attachment.size) * 100))
      : 0,
  );
  let moving = $derived(attachment.status === 'active' || attachment.status === 'accepted');

  /** The line under the file name, in the terms of whoever is looking at it. */
  let statusLine = $derived.by(() => {
    const name = friendName;
    switch (attachment.status) {
      case 'offered':
        return m.chat_attach_waiting({ name });
      case 'awaiting':
        return m.chat_attach_offer_prompt({ name });
      case 'accepted':
        return m.chat_attach_starting();
      case 'active':
        if (sent) return m.chat_attach_sending({ percent });
        // Accepted, but no byte yet: the dial to the sender, and its check of
        // the file, come first. "Receiving 0%" read as a stall.
        return attachment.transferred > 0
          ? m.chat_attach_receiving({ percent })
          : m.chat_attach_connecting();
      case 'complete':
        return sent ? m.chat_attach_sent() : m.chat_attach_received();
      case 'declined':
        return sent ? m.chat_attach_declined_sent({ name }) : m.chat_attach_declined_received();
      case 'too_large':
        return m.chat_attach_too_large({ name });
      case 'busy':
        return m.chat_attach_busy({ name });
      case 'not_allowed':
        return m.chat_attach_not_allowed({ name });
      case 'cancelled':
        return m.chat_attach_cancelled();
      case 'unreachable':
        return m.chat_attach_unreachable({ name });
      case 'source_gone':
        return sent ? m.chat_attach_source_gone_sent() : m.chat_attach_source_gone_received({ name });
      case 'failed':
        return m.chat_attach_failed();
      case 'expired':
        return sent ? m.chat_attach_expired_sent({ name }) : m.chat_attach_expired_received();
    }
  });

  let problem = $derived(
    attachment.status !== 'complete' && CHAT_ATTACHMENT_TERMINAL.has(attachment.status),
  );

  async function run(action: () => Promise<void>) {
    if (busy) return;
    busy = true;
    try {
      await action();
    } catch (e) {
      toastError(translateError(e));
    } finally {
      busy = false;
    }
  }
</script>

<div
  class="attach"
  class:sent
  class:problem
  role="group"
  aria-label={m.chat_attach_aria({ file: attachment.name, size: formatBytes(attachment.size) })}
>
  <div class="attach-head">
    <span class="attach-icon" aria-hidden="true">
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M11.5 2.5H6a1.5 1.5 0 0 0-1.5 1.5v12A1.5 1.5 0 0 0 6 17.5h8a1.5 1.5 0 0 0 1.5-1.5V6.5z"/>
        <path d="M11.5 2.5v4h4"/>
      </svg>
    </span>
    <div class="attach-meta">
      <!-- Peer-chosen, so isolated from the surrounding text direction like any
           message body. -->
      <span class="attach-name" title={attachment.name}><bdi dir="auto">{attachment.name}</bdi></span>
      <span class="attach-size">{formatBytes(attachment.size)}</span>
    </div>
  </div>

  {#if moving}
    <div
      class="attach-bar"
      role="progressbar"
      aria-label={m.chat_attach_progress_aria()}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={percent}
    >
      <span style="width: {percent}%"></span>
    </div>
  {/if}

  <div class="attach-status" aria-live={moving ? 'off' : 'polite'}>{statusLine}</div>

  {#if attachment.status === 'awaiting'}
    <div class="attach-actions">
      <button
        type="button"
        class="attach-primary"
        disabled={busy}
        onclick={() => run(() => respondChatAttachment(attachment.xfer_id, true))}
      >{m.chat_attach_accept()}</button>
      <button
        type="button"
        disabled={busy}
        onclick={() => run(() => respondChatAttachment(attachment.xfer_id, false))}
      >{m.chat_attach_decline()}</button>
    </div>
  {:else if attachment.status === 'offered' || moving}
    <div class="attach-actions">
      <button
        type="button"
        disabled={busy}
        onclick={() => run(() => cancelChatAttachment(attachment.xfer_id))}
      >{m.chat_attach_cancel()}</button>
    </div>
  {:else if attachment.has_file}
    <div class="attach-actions">
      <button
        type="button"
        class="attach-primary"
        disabled={busy}
        onclick={() => run(() => openChatAttachment(attachment.xfer_id, false))}
      >{m.chat_attach_open()}</button>
      <button
        type="button"
        disabled={busy}
        onclick={() => run(() => openChatAttachment(attachment.xfer_id, true))}
      >{m.chat_attach_show()}</button>
    </div>
  {/if}

  {#if time}
    <div class="attach-time">{time}</div>
  {/if}
</div>

<style>
  .attach {
    width: min(320px, 100%);
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-secondary);
    color: var(--text-primary);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .attach.sent {
    background: color-mix(in srgb, var(--accent) 10%, var(--bg-secondary));
    border-color: color-mix(in srgb, var(--accent) 30%, var(--border));
  }

  .attach-head {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
  }

  .attach-icon {
    flex-shrink: 0;
    width: 32px;
    height: 32px;
    border-radius: var(--radius-sm);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    color: var(--accent);
  }

  .attach-icon svg {
    width: 18px;
    height: 18px;
  }

  .attach-meta {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .attach-name {
    font-size: 13px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .attach-size {
    font-size: 11.5px;
    color: var(--text-muted);
  }

  .attach-bar {
    height: 4px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--accent) 16%, transparent);
    overflow: hidden;
  }

  .attach-bar span {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 200ms linear;
  }

  .attach-status {
    font-size: 12px;
    color: var(--text-secondary);
  }

  .attach.problem .attach-status {
    color: var(--text-muted);
    font-style: italic;
  }

  .attach-actions {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }

  .attach-actions button {
    font: inherit;
    font-size: 12px;
    padding: 4px 10px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: transparent;
    color: var(--text-secondary);
    cursor: pointer;
  }

  .attach-actions button:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .attach-actions button.attach-primary {
    border-color: var(--accent);
    background: var(--accent);
    color: var(--on-accent);
  }

  .attach-actions button.attach-primary:hover:not(:disabled) {
    background: var(--accent-hover);
    border-color: var(--accent-hover);
    color: var(--on-accent);
  }

  .attach-actions button:disabled {
    opacity: 0.6;
    cursor: default;
  }

  .attach-actions button:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .attach-time {
    font-size: 10.5px;
    color: var(--text-muted);
    align-self: flex-end;
  }
</style>
