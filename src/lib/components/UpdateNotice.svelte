<script lang="ts">
  // Non-blocking corner card surfaced by the shared `updater` store: the
  // silent startup check populates it, and the user can install/restart or
  // dismiss without leaving their current page. The Settings → About card
  // drives the same store, so progress shown here also reflects a check
  // started from there.
  import * as m from '$lib/paraglide/messages';
  import { fly } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import {
    updater,
    installUpdate,
    restartToUpdate,
    dismissNotice,
  } from '$lib/stores/updater';

  let showNotes = $state(false);

  const visible = $derived(
    !$updater.dismissed &&
      ($updater.phase === 'available' ||
        $updater.phase === 'downloading' ||
        $updater.phase === 'installing' ||
        $updater.phase === 'ready' ||
        ($updater.phase === 'error' && $updater.version !== null)),
  );

  const percent = $derived(
    $updater.total && $updater.total > 0
      ? Math.min(100, Math.round(($updater.downloaded / $updater.total) * 100))
      : null,
  );

  const inProgress = $derived(
    $updater.phase === 'downloading' || $updater.phase === 'installing',
  );

  // Collapse the release-notes section when the notice hides or the target
  // version changes, so a stale expanded state doesn't carry across update
  // cycles (the toggle only renders for `available`, so without this it would
  // reappear pre-expanded on the next available update).
  let notesForVersion: string | null = null;
  $effect(() => {
    if (!visible) {
      showNotes = false;
      notesForVersion = null;
    } else if ($updater.version !== notesForVersion) {
      showNotes = false;
      notesForVersion = $updater.version;
    }
  });
</script>

{#if visible}
  <div
    class="update-notice"
    role="status"
    aria-live="polite"
    transition:fly={{ y: prefersReducedMotion.current ? 0 : 16, duration: prefersReducedMotion.current ? 0 : 220 }}
  >
    <div class="notice-head">
      <span class="notice-spark" aria-hidden="true">
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10 3v9" />
          <polyline points="6,8 10,12 14,8" />
          <line x1="5" y1="16" x2="15" y2="16" />
        </svg>
      </span>
      <div class="notice-title">
        {#if $updater.phase === 'ready'}
          {m.updater_ready_title()}
        {:else if $updater.phase === 'error'}
          {m.updater_error_title()}
        {:else}
          {m.updater_available_title()}
        {/if}
      </div>
      {#if !inProgress}
        <button class="notice-x" onclick={dismissNotice} aria-label={m.updater_dismiss_aria()}>&times;</button>
      {/if}
    </div>

    <p class="notice-body">
      {#if $updater.phase === 'ready'}
        {m.updater_ready_body({ version: $updater.version ?? '' })}
      {:else if $updater.phase === 'installing'}
        {m.updater_installing()}
      {:else if $updater.phase === 'downloading'}
        {percent !== null ? m.updater_downloading_pct({ pct: percent }) : m.updater_downloading()}
      {:else if $updater.phase === 'error'}
        {m.updater_error_body({ detail: $updater.error ?? '' })}
      {:else}
        {m.updater_available_body({ version: $updater.version ?? '' })}
      {/if}
    </p>

    {#if $updater.phase === 'downloading'}
      <div class="notice-progress" class:indeterminate={percent === null}>
        <div class="notice-progress-fill" style={percent !== null ? `width:${percent}%` : undefined}></div>
      </div>
    {/if}

    {#if $updater.phase === 'available' && $updater.notes}
      <button class="notice-notes-toggle" onclick={() => (showNotes = !showNotes)} aria-expanded={showNotes}>
        {m.updater_whats_new()}
      </button>
      {#if showNotes}
        <div class="notice-notes">{$updater.notes}</div>
      {/if}
    {/if}

    {#if !inProgress}
      <div class="notice-actions">
        {#if $updater.phase === 'ready'}
          <button class="ghost" onclick={dismissNotice}>{m.updater_later()}</button>
          <button class="primary" onclick={() => void restartToUpdate()}>{m.updater_restart_now()}</button>
        {:else if $updater.phase === 'error'}
          <button class="ghost" onclick={dismissNotice}>{m.updater_later()}</button>
          <button class="primary" onclick={() => void installUpdate()}>{m.updater_retry()}</button>
        {:else}
          <button class="ghost" onclick={dismissNotice}>{m.updater_later()}</button>
          <button class="primary" onclick={() => void installUpdate()}>{m.updater_install()}</button>
        {/if}
      </div>
    {/if}
  </div>
{/if}

<style>
  .update-notice {
    position: fixed;
    right: 18px;
    bottom: 18px;
    z-index: 9500;
    width: min(340px, calc(100vw - 36px));
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-lg);
    padding: 14px 16px 13px;
    display: flex;
    flex-direction: column;
    gap: 9px;
  }

  .notice-head {
    display: flex;
    align-items: center;
    gap: 9px;
  }

  .notice-spark {
    display: grid;
    place-items: center;
    width: 26px;
    height: 26px;
    border-radius: 7px;
    background: color-mix(in srgb, var(--accent) 16%, transparent);
    color: var(--accent);
    flex-shrink: 0;
  }

  .notice-spark svg {
    width: 15px;
    height: 15px;
  }

  .notice-title {
    flex: 1;
    font-size: 13.5px;
    font-weight: 700;
    color: var(--text-primary);
  }

  .notice-x {
    border: none;
    background: transparent;
    color: var(--text-muted);
    font-size: 18px;
    line-height: 1;
    cursor: pointer;
    padding: 0 2px;
    border-radius: var(--radius-sm);
  }

  .notice-x:hover {
    color: var(--text-primary);
  }

  .notice-body {
    margin: 0;
    font-size: 12.5px;
    line-height: 1.45;
    color: var(--text-secondary);
  }

  .notice-progress {
    height: 6px;
    border-radius: 999px;
    background: var(--bg-tertiary, var(--bg-hover));
    overflow: hidden;
  }

  .notice-progress-fill {
    height: 100%;
    background: var(--accent);
    border-radius: 999px;
    transition: width 0.2s ease;
  }

  .notice-progress.indeterminate .notice-progress-fill {
    width: 35%;
    animation: notice-indeterminate 1.1s ease-in-out infinite;
  }

  @keyframes notice-indeterminate {
    0% { transform: translateX(-120%); }
    100% { transform: translateX(320%); }
  }

  .notice-notes-toggle {
    align-self: flex-start;
    border: none;
    background: transparent;
    color: var(--accent);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    padding: 0;
  }

  .notice-notes {
    max-height: 120px;
    overflow-y: auto;
    font-size: 12px;
    line-height: 1.5;
    color: var(--text-secondary);
    white-space: pre-wrap;
    padding: 8px 10px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }

  .notice-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 2px;
  }

  .notice-actions button {
    padding: 6px 13px;
    font-size: 12.5px;
    font-weight: 600;
    border-radius: var(--radius-md);
    cursor: pointer;
  }

  .notice-actions .ghost {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
  }

  .notice-actions .ghost:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .notice-actions .primary {
    background: var(--accent);
    color: #fff;
    border: 1px solid var(--accent);
  }

  .notice-actions .primary:hover {
    filter: brightness(1.06);
  }
</style>
