<script lang="ts">
  import { untrack } from 'svelte';
  import {
    CHAT_ATTACHMENT_TERMINAL,
    cancelChatAttachment,
    openChatAttachment,
    respondChatAttachment,
    retryChatAttachment,
    type ChatAttachment,
  } from '$lib/api/friends';
  import { formatBytes, formatDurationSecs, formatLiveSpeed } from '$lib/utils';
  import { extensionFromPath, fileTypeKey } from '$lib/fileTypes';
  import FileTypeIcon from '$lib/components/FileTypeIcon.svelte';
  import { noteXferBytes, xferRate, xferSecondsLeft, type RateSamples } from '$lib/xferRate';
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

  /** A receive retried from this card waits on the sender to offer the file
   *  again; until it does, or for this long, the card says so. */
  const RETRY_ASK_SHOWN_MS = 30_000;
  let askedAt = $state<{ attempt: number; status: string } | null>(null);
  $effect(() => {
    if (!askedAt) return;
    if (attachment.attempt !== askedAt.attempt || attachment.status !== askedAt.status) {
      askedAt = null;
      return;
    }
    const timer = setTimeout(() => (askedAt = null), RETRY_ASK_SHOWN_MS);
    return () => clearTimeout(timer);
  });
  let asking = $derived(askedAt !== null);

  function retry() {
    return run(async () => {
      await retryChatAttachment(attachment.xfer_id);
      if (!sent) askedAt = { attempt: attachment.attempt, status: attachment.status };
    });
  }

  /** The line under the file name, in the terms of whoever is looking at it. */
  let statusLine = $derived.by(() => {
    const name = friendName;
    if (asking) return m.chat_attach_retry_asking({ name });
    switch (attachment.status) {
      case 'offered':
        return m.chat_attach_waiting({ name });
      case 'awaiting':
        return m.chat_attach_offer_prompt({ name });
      case 'accepted':
        return m.chat_attach_starting();
      case 'active':
        if (sent) {
          return attachment.transferred > 0
            ? m.chat_attach_sending({ percent })
            : m.chat_attach_starting();
        }
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
      default:
        return m.chat_attach_failed();
    }
  });

  let problem = $derived(
    attachment.status !== 'complete' && CHAT_ATTACHMENT_TERMINAL.has(attachment.status),
  );
  /** Ended without the file through nobody's choice. Cancelled, declined and
   *  expired stay muted. Keep in step with `XFER_FAILED` on the Channels page. */
  const FAILED_STATUSES = new Set(['failed', 'source_gone', 'unreachable', 'busy', 'too_large', 'not_allowed']);
  let failed = $derived(FAILED_STATUSES.has(attachment.status));
  let done = $derived(attachment.status === 'complete');
  let waitingOnMe = $derived(attachment.status === 'awaiting');
  /** Moving, but nothing through yet: the bar says "working" without a figure. */
  let pending = $derived(moving && attachment.transferred === 0);

  let ext = $derived(extensionFromPath(attachment.name));
  let kind = $derived(fileTypeKey(ext));
  /** Shown beside the size only when it is short enough to be a type. */
  let extLabel = $derived(ext.length > 0 && ext.length <= 5 ? ext.toUpperCase() : '');

  /** Progress arrives every quarter second while bytes move; the speed is
   *  smoothed from those, and dropped once they stop coming. */
  let samples = $state.raw<RateSamples>(new Map());
  $effect(() => {
    const bytes = attachment.transferred;
    if (attachment.status !== 'active') return;
    untrack(() => {
      samples = noteXferBytes(samples, attachment.xfer_id, bytes, Date.now());
    });
  });
  let now = $state(Date.now());
  $effect(() => {
    if (!moving) return;
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });
  let rate = $derived(attachment.status === 'active' ? xferRate(samples, attachment.xfer_id, now) : 0);
  let secondsLeft = $derived(xferSecondsLeft(attachment.size, attachment.transferred, rate));

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
  class:failed
  class:done
  class:waiting={waitingOnMe}
  role="group"
  aria-label={m.chat_attach_aria({ file: attachment.name, size: formatBytes(attachment.size) })}
>
  <div class="attach-head">
    <span class="attach-icon" aria-hidden="true">
      <FileTypeIcon {kind} size={38} />
      <!-- Which way it went, at a glance, on the corner of the tile. -->
      <span class="attach-dir">
        <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          {#if done}
            <path d="m3 6.2 2 2 4-4.4"/>
          {:else if sent}
            <path d="M6 9.5v-7M3.2 5.2 6 2.5l2.8 2.7"/>
          {:else}
            <path d="M6 2.5v7M3.2 6.8 6 9.5l2.8-2.7"/>
          {/if}
        </svg>
      </span>
    </span>
    <div class="attach-meta">
      <!-- Peer-chosen, so isolated from the surrounding text direction like any
           message body. -->
      <span class="attach-name" title={attachment.name}><bdi dir="auto">{attachment.name}</bdi></span>
      <span class="attach-size">
        {#if moving && attachment.transferred > 0}
          {formatBytes(attachment.transferred)} / {formatBytes(attachment.size)}
        {:else}
          {formatBytes(attachment.size)}{#if extLabel}<span class="attach-ext">{extLabel}</span>{/if}
        {/if}
      </span>
    </div>
  </div>

  {#if moving}
    <div
      class="attach-bar"
      class:pending
      role="progressbar"
      aria-label={m.chat_attach_progress_aria()}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={percent}
    >
      <span style="width: {percent}%"></span>
    </div>
  {/if}

  {#if !sent && attachment.risky}
    <p class="file-risk" role="note">
      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M8 1.8 14.6 13.5H1.4z"/>
        <path d="M8 6.2v3.4M8 11.6v.1"/>
      </svg>
      <span>{m.common_risky_file()}</span>
    </p>
  {/if}

  <div class="attach-status" aria-live={moving ? 'off' : 'polite'}>
    {#if problem}
      <svg class="attach-status-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true">
        <circle cx="8" cy="8" r="6.2"/>
        <path d="M8 4.8v3.6M8 11.1v.1"/>
      </svg>
    {/if}
    <span class="attach-status-text">{statusLine}</span>
    {#if rate > 0}
      <span class="attach-speed">{formatLiveSpeed(rate)}</span>
    {/if}
    {#if secondsLeft !== null}
      <span class="attach-left">{m.chat_attach_time_left({ time: formatDurationSecs(secondsLeft) })}</span>
    {/if}
  </div>

  {#if attachment.status === 'awaiting'}
    <div class="attach-actions">
      <button
        type="button"
        class="attach-primary"
        disabled={busy}
        onclick={() => run(() => respondChatAttachment(attachment.xfer_id, true))}
      >
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M8 2.5v8M4.8 7.5 8 10.7l3.2-3.2M3 13.5h10"/>
        </svg>
        {m.chat_attach_accept()}
      </button>
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
        class="attach-cancel"
        disabled={busy}
        onclick={() => run(() => cancelChatAttachment(attachment.xfer_id))}
      >{m.chat_attach_cancel()}</button>
    </div>
  {:else if attachment.retryable}
    <div class="attach-actions">
      <button
        type="button"
        class="attach-primary"
        disabled={busy || asking}
        onclick={retry}
      >
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M13 8a5 5 0 1 1-1.5-3.6M13 2.8v3.4H9.6"/>
        </svg>
        {m.chat_attach_retry()}
      </button>
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
    padding: 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-secondary);
    color: var(--text-primary);
    display: flex;
    flex-direction: column;
    gap: 9px;
    box-shadow: var(--shadow-sm);
  }

  .attach.sent {
    background: color-mix(in srgb, var(--accent) 8%, var(--bg-secondary));
    border-color: color-mix(in srgb, var(--accent) 28%, var(--border));
  }

  /* An offer waiting on this user is the only card that asks for something. */
  .attach.waiting {
    border-color: color-mix(in srgb, var(--accent) 50%, var(--border));
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 12%, transparent);
  }

  .attach-head {
    display: flex;
    align-items: center;
    gap: 11px;
    min-width: 0;
  }

  .attach-icon {
    position: relative;
    flex-shrink: 0;
    display: inline-flex;
  }

  .attach-dir {
    position: absolute;
    right: -4px;
    bottom: -4px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    background: var(--success);
    color: var(--on-success);
    box-shadow: 0 0 0 2px var(--bg-secondary);
  }

  .attach.sent .attach-dir { background: var(--accent); color: var(--on-accent); }
  .attach.done .attach-dir { background: var(--success); color: var(--on-success); }
  .attach.problem .attach-dir { background: var(--text-muted); color: var(--bg-secondary); }
  .attach.failed .attach-dir { background: var(--danger); color: var(--on-danger); }

  .attach-dir svg {
    width: 10px;
    height: 10px;
  }

  .attach-meta {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
  }

  .attach-name {
    font-size: var(--font-size-md);
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .attach-size {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .attach-ext {
    padding: 0 5px;
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--text-muted) 14%, transparent);
    font-size: var(--font-size-2xs);
    font-weight: 600;
    letter-spacing: 0.3px;
    line-height: 16px;
  }

  /* Same track as a Channels transfer card's. */
  .attach-bar {
    position: relative;
    height: 6px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--text-muted) 22%, transparent);
    overflow: hidden;
  }

  /* Reports come four times a second; easing across one makes the bar glide. */
  .attach-bar span {
    display: block;
    height: 100%;
    border-radius: inherit;
    background: linear-gradient(90deg, var(--accent), color-mix(in srgb, var(--accent) 65%, #fff));
    transition: width 250ms linear;
  }

  .attach-bar.pending span { display: none; }

  .attach-bar.pending::after {
    content: '';
    position: absolute;
    inset: 0 auto 0 0;
    width: 35%;
    border-radius: inherit;
    background: var(--accent);
    opacity: 0.7;
    animation: attach-pending 1.3s ease-in-out infinite;
  }

  @keyframes attach-pending {
    from { transform: translateX(-100%); }
    to { transform: translateX(290%); }
  }

  .attach-status {
    display: flex;
    align-items: baseline;
    gap: 8px;
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
  }

  .attach-status-text {
    min-width: 0;
    overflow-wrap: anywhere;
  }

  .attach-status-icon {
    flex-shrink: 0;
    width: 13px;
    height: 13px;
    align-self: center;
  }

  .attach.done .attach-status { color: var(--success); }

  .attach.problem .attach-status { color: var(--text-muted); }
  .attach.failed .attach-status { color: var(--danger); }

  .attach-speed {
    flex-shrink: 0;
    font-weight: 600;
    color: var(--accent);
    white-space: nowrap;
  }

  .attach-left {
    flex-shrink: 0;
    margin-left: auto;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    white-space: nowrap;
  }

  .attach-actions {
    display: flex;
    gap: 6px;
  }

  .attach-actions button {
    flex: 1;
    min-width: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    font: inherit;
    font-size: var(--font-size-sm);
    font-weight: 600;
    padding: 6px 10px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--bg-secondary);
    color: var(--text-primary);
    cursor: pointer;
  }

  .attach-actions button svg {
    width: 13px;
    height: 13px;
    flex-shrink: 0;
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

  .attach-actions button.attach-cancel {
    border-color: color-mix(in srgb, var(--danger) 35%, var(--border));
    background: transparent;
    color: var(--danger);
  }

  .attach-actions button.attach-cancel:hover:not(:disabled) {
    background: color-mix(in srgb, var(--danger) 10%, transparent);
    color: var(--danger);
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
    margin-top: -2px;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    align-self: flex-end;
  }
</style>
