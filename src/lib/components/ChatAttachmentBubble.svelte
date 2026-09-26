<script lang="ts">
  import { untrack } from 'svelte';
  import {
    CHAT_ATTACHMENT_TERMINAL,
    cancelChatAttachment,
    openChatAttachment,
    respondChatAttachment,
    type ChatAttachment,
  } from '$lib/api/friends';
  import { formatBytes, formatDurationSecs, formatSpeed } from '$lib/utils';
  import { extensionFromPath, fileTypeKey } from '$lib/fileTypes';
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
  class:done
  class:waiting={waitingOnMe}
  role="group"
  aria-label={m.chat_attach_aria({ file: attachment.name, size: formatBytes(attachment.size) })}
>
  <div class="attach-head">
    <span
      class="attach-icon"
      class:k-audio={kind === 'Audio'}
      class:k-video={kind === 'Video'}
      class:k-image={kind === 'Image'}
      class:k-archive={kind === 'Archive'}
      class:k-disc={kind === 'CD/DVD'}
      aria-hidden="true"
    >
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        {#if kind === 'Audio'}
          <path d="M8 14.5V4.5l8-1.5v10"/>
          <circle cx="6" cy="14.5" r="2"/>
          <circle cx="14" cy="13" r="2"/>
        {:else if kind === 'Video'}
          <rect x="2.5" y="4.5" width="15" height="11" rx="2"/>
          <path d="m8.5 7.8 4 2.2-4 2.2z"/>
        {:else if kind === 'Image'}
          <rect x="2.5" y="3.5" width="15" height="13" rx="2"/>
          <circle cx="7" cy="8" r="1.5"/>
          <path d="m17.5 13-4-4-8 7.5"/>
        {:else if kind === 'Archive'}
          <rect x="2.5" y="3.5" width="15" height="4" rx="1"/>
          <path d="M4 7.5v8a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1v-8"/>
          <path d="M8.5 11h3"/>
        {:else if kind === 'CD/DVD'}
          <circle cx="10" cy="10" r="7.5"/>
          <circle cx="10" cy="10" r="2"/>
        {:else}
          <path d="M11.5 2.5H6a1.5 1.5 0 0 0-1.5 1.5v12A1.5 1.5 0 0 0 6 17.5h8a1.5 1.5 0 0 0 1.5-1.5V6.5z"/>
          <path d="M11.5 2.5v4h4"/>
          {#if kind === 'Document'}
            <path d="M7.5 10.5h5M7.5 13.5h3.5"/>
          {/if}
        {/if}
      </svg>
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

  <div class="attach-status" aria-live={moving ? 'off' : 'polite'}>
    {#if problem}
      <svg class="attach-status-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true">
        <circle cx="8" cy="8" r="6.2"/>
        <path d="M8 4.8v3.6M8 11.1v.1"/>
      </svg>
    {/if}
    <span class="attach-status-text">{statusLine}</span>
    {#if rate > 0}
      <span class="attach-speed">{formatSpeed(rate)}</span>
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
    border-radius: var(--radius-lg, 12px);
    background: var(--bg-secondary);
    color: var(--text-primary);
    display: flex;
    flex-direction: column;
    gap: 9px;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
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
    --tile: var(--accent);
    position: relative;
    flex-shrink: 0;
    width: 38px;
    height: 38px;
    border-radius: var(--radius-md);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: color-mix(in srgb, var(--tile) 15%, transparent);
    color: var(--tile);
  }

  .attach-icon.k-audio { --tile: #8b5cf6; }
  .attach-icon.k-video { --tile: #e0567a; }
  .attach-icon.k-image { --tile: #14a3a3; }
  .attach-icon.k-archive { --tile: var(--warning); }
  .attach-icon.k-disc { --tile: #6b7a90; }

  .attach-icon > svg {
    width: 20px;
    height: 20px;
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
    color: #fff;
    box-shadow: 0 0 0 2px var(--bg-secondary);
  }

  .attach.sent .attach-dir { background: var(--accent); }
  .attach.done .attach-dir { background: var(--success); }
  .attach.problem .attach-dir { background: var(--text-muted); }

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
    font-size: 13px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .attach-size {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11.5px;
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .attach-ext {
    padding: 0 5px;
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--text-muted) 14%, transparent);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.3px;
    line-height: 16px;
  }

  .attach-bar {
    position: relative;
    height: 6px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--accent) 16%, transparent);
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
    font-size: 12px;
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

  .attach-speed {
    flex-shrink: 0;
    font-weight: 600;
    color: var(--accent);
    white-space: nowrap;
  }

  .attach-left {
    flex-shrink: 0;
    margin-left: auto;
    font-size: 11.5px;
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
    font-size: 12px;
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
    font-size: 10.5px;
    color: var(--text-muted);
    align-self: flex-end;
  }
</style>
