<script lang="ts">
  // One friend's settings: their name, and exceptions to the Friends settings
  // for them alone. Every choice offers "Use default", which follows the
  // global setting and says what that is now, so nothing here can quietly
  // disagree with Settings without the user having picked it.
  //
  // Laid out like the File Details window: a header, the friend up front, then
  // each group of choices on its own card.
  import * as m from '$lib/paraglide/messages';
  import { onMount, tick, untrack } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground, trapTabKey } from '$lib/a11y';
  import { translateError } from '$lib/i18n';
  import { plural } from '$lib/plural';
  import { appSettings, setAppSettings } from '$lib/stores/settings';
  import { onlineFriends } from '$lib/stores/friends';
  import { CHAT_DISAPPEAR_CHOICES, disappearLabel } from '$lib/chatDisappear';
  import { setFriendOverrides } from '$lib/api/settings';
  import {
    compactOverrides,
    friendNameTooLong,
    friendOverrides,
    FRIEND_AUTO_ACCEPT_MAX_MB,
    FRIEND_NAME_MAX_CHARS as NAME_MAX_CHARS,
  } from '$lib/friendSettings';
  import type { FriendInfo } from '$lib/api/friends';
  import type { FriendOverrides } from '$lib/types';
  import IconX from './IconX.svelte';

  let {
    friend,
    onrename,
    onclose,
  }: {
    friend: FriendInfo;
    onrename: (hash: string, name: string) => Promise<void>;
    onclose: () => void;
  } = $props();

  type Tri = 'default' | 'on' | 'off';
  type AutoChoice = 'default' | 'never' | 'up_to';

  const instanceId = Math.random().toString(36).slice(2, 10);
  let overlayEl: HTMLDivElement | undefined = $state(undefined);
  let dialogEl: HTMLDivElement | undefined = $state(undefined);
  let nameEl: HTMLInputElement | undefined = $state(undefined);
  let returnFocusEl: HTMLElement | null = null;
  let busy = $state(false);
  let error = $state<string | null>(null);

  // The form starts from what is saved when it opens and is not reset under
  // the user by a save made elsewhere meanwhile.
  const opened = untrack(() => friend);
  const hash = opened.user_hash.toLowerCase();
  const shortId = `${hash.slice(0, 8)}\u2026${hash.slice(-6)}`;
  // Saving replaces the friend's overrides, so a form that started without
  // them must not.
  const loadedAtOpen = $appSettings != null;
  const initial: FriendOverrides = friendOverrides($appSettings, hash);
  const tri = (value: boolean | undefined): Tri => (value === undefined ? 'default' : value ? 'on' : 'off');
  const fromTri = (value: Tri): boolean | undefined => (value === 'default' ? undefined : value === 'on');

  let name = $state(opened.nickname ?? '');
  let chat = $state<Tri>(tri(initial.chat));
  let files = $state<Tri>(tri(initial.files));
  let browse = $state<Tri>(tri(initial.browse));
  let readReceipts = $state<Tri>(tri(initial.read_receipts));
  let notifyOnline = $state<Tri>(tri(initial.notify_online));
  let notifyMessages = $state<Tri>(tri(initial.notify_messages));
  let autoChoice = $state<AutoChoice>(
    initial.auto_accept_mb === undefined ? 'default' : initial.auto_accept_mb === 0 ? 'never' : 'up_to',
  );
  let autoMb = $state<number>(
    initial.auto_accept_mb && initial.auto_accept_mb > 0
      ? initial.auto_accept_mb
      : Math.max(1, $appSettings?.chat_attachment_auto_accept_mb ?? 25),
  );
  /** `'default'`, or a timer in seconds as the select holds it (`'0'` is off). */
  let disappear = $state<string>(
    initial.disappear_secs === undefined ? 'default' : String(initial.disappear_secs),
  );

  // What each default currently is, so "Use default" says what it means.
  let chatDefault = $derived($appSettings?.friend_chat_disabled !== true);
  let chatOn = $derived(chat === 'default' ? chatDefault : chat === 'on');
  let filesDefault = $derived($appSettings?.friend_files_disabled !== true);
  let filesOn = $derived(chatOn && (files === 'default' ? filesDefault : files === 'on'));
  let browseDefault = $derived($appSettings?.friend_browse_disabled !== true);
  let receiptsDefault = $derived($appSettings?.friend_chat_read_receipts !== false);
  let notifyOnlineDefault = $derived($appSettings?.notify_friend_online === true);
  let notifyMessagesDefault = $derived($appSettings?.notify_friend_message === true);
  let notificationsOff = $derived($appSettings?.notifications_enabled === false);
  let autoDefaultMb = $derived($appSettings?.chat_attachment_auto_accept_mb ?? 0);
  let disappearDefault = $derived($appSettings?.chat_disappear_secs ?? 0);
  let disappearOn = $derived((disappear === 'default' ? disappearDefault : Number(disappear)) > 0);

  let online = $derived($onlineFriends.has(hash));
  let displayName = $derived(name.trim() || opened.nickname || shortId);

  let nameTooLong = $derived(friendNameTooLong(name));
  let autoMbValid = $derived(
    autoChoice !== 'up_to' || (Number.isInteger(autoMb) && autoMb >= 1 && autoMb <= FRIEND_AUTO_ACCEPT_MAX_MB),
  );

  /** How many choices differ from the defaults, as the form stands. */
  let customCount = $derived(Object.keys(overridesNow()).length);

  function defaultLabel(on: boolean): string {
    return on ? m.friend_settings_default_on() : m.friend_settings_default_off();
  }

  function autoDefaultLabel(): string {
    return autoDefaultMb > 0
      ? m.friend_settings_auto_accept_default_size({ size: autoDefaultMb })
      : m.friend_settings_auto_accept_default_never();
  }

  function overridesNow(): FriendOverrides {
    return compactOverrides({
      chat: fromTri(chat),
      // Meaningless while chat is off, and kept out so it cannot come back
      // into force unnoticed when chat is turned on again later.
      files: chatOn ? fromTri(files) : undefined,
      auto_accept_mb:
        !filesOn || autoChoice === 'default'
          ? undefined
          : autoChoice === 'never'
            ? 0
            : autoMb,
      browse: fromTri(browse),
      read_receipts: chatOn ? fromTri(readReceipts) : undefined,
      disappear_secs: chatOn && disappear !== 'default' ? Number(disappear) : undefined,
      notify_online: fromTri(notifyOnline),
      notify_messages: fromTri(notifyMessages),
    });
  }

  function reset() {
    chat = files = browse = readReceipts = notifyOnline = notifyMessages = 'default';
    autoChoice = 'default';
    disappear = 'default';
  }

  async function save() {
    if (busy || !loadedAtOpen || nameTooLong || !autoMbValid) return;
    busy = true;
    error = null;
    try {
      const trimmed = name.trim();
      if (trimmed !== (friend.nickname ?? '').trim()) {
        await onrename(friend.user_hash, trimmed);
      }
      const next = overridesNow();
      if (JSON.stringify(next) !== JSON.stringify(compactOverrides(initial))) {
        setAppSettings(await setFriendOverrides(friend.user_hash, next));
      }
      busy = false;
      onclose();
    } catch (e: unknown) {
      error = translateError(e, m.friend_settings_save_failed());
      busy = false;
      await tick();
      nameEl?.focus();
    }
  }

  function close() {
    if (!busy) onclose();
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      close();
      return;
    }
    trapTabKey(e, dialogEl);
  }

  onMount(() => {
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
    requestAnimationFrame(() => nameEl?.focus());
    return () => {
      const el = returnFocusEl;
      if (el) requestAnimationFrame(() => document.contains(el) && el.focus());
    };
  });

  $effect(() => {
    if (!overlayEl) return;
    return inertBackground(overlayEl);
  });
</script>

{#snippet triSelect(id: string, label: string, value: Tri, set: (v: Tri) => void, defaultOn: boolean, disabled = false)}
  <div class="fs-row" class:is-custom={value !== 'default'} class:is-disabled={disabled}>
    <label for={id}>{label}</label>
    <select {id} value={value} {disabled} onchange={(e) => set(e.currentTarget.value as Tri)}>
      <option value="default">{defaultLabel(defaultOn)}</option>
      <option value="on">{m.friend_settings_on()}</option>
      <option value="off">{m.friend_settings_off()}</option>
    </select>
  </div>
{/snippet}

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div
  class="fs-overlay"
  bind:this={overlayEl}
  role="dialog"
  aria-modal="true"
  aria-labelledby="fs-title-{instanceId}"
  aria-describedby="fs-hint-{instanceId}"
  aria-busy={busy}
  tabindex="-1"
  onkeydown={onKeydown}
  onclick={(e) => e.target === e.currentTarget && close()}
  transition:fade={{ duration: prefersReducedMotion.current ? 0 : 140 }}
>
  <div
    class="fs-dialog"
    bind:this={dialogEl}
    transition:scale={{ start: 0.97, opacity: 0, duration: prefersReducedMotion.current ? 0 : 180 }}
  >
    <div class="fs-header">
      <h3 id="fs-title-{instanceId}" class="fs-title">
        {m.friend_settings_title({ name: friend.nickname || shortId })}
      </h3>
      <button
        type="button"
        class="icon-close"
        title={m.common_close()}
        aria-label={m.common_close()}
        disabled={busy}
        onclick={close}
      >
        <IconX size={15} />
      </button>
    </div>

    <form class="fs-form" onsubmit={(e) => { e.preventDefault(); void save(); }}>
      <div class="fs-body">
        <!-- The friend leads, as the file does in File Details: who this is,
             whether they are here, and how far these settings stray from the
             defaults. -->
        <div class="fs-hero">
          <span class="fs-avatar" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="8" r="4" />
              <path d="M4 21c0-4.418 3.582-8 8-8s8 3.582 8 8" />
            </svg>
            <span class="fs-dot" class:online></span>
          </span>
          <div class="fs-hero-text">
            <bdi class="fs-name" dir="auto">{displayName}</bdi>
            <div class="fs-meta">
              <span class="fs-pill" class:online>{online ? m.chat_online_label() : m.chat_offline_label()}</span>
              {#if !friend.mutual}
                <span class="fs-pill waiting">{m.friends_status_waiting_accept()}</span>
              {/if}
              <code class="fs-id" title={friend.user_hash}>{shortId}</code>
            </div>
            <span class="fs-custom" class:has-custom={customCount > 0}>
              {customCount === 0
                ? m.friend_settings_custom_none()
                : plural(customCount, {
                    one: m.friend_settings_custom_one,
                    few: () => m.friend_settings_custom_few({ count: customCount }),
                    other: () => m.friend_settings_custom_other({ count: customCount }),
                  })}
            </span>
          </div>
        </div>

        <p id="fs-hint-{instanceId}" class="fs-note fs-callout">{m.friend_settings_hint()}</p>

        <section class="fs-card">
          <label class="fs-card-title" for="fs-name-{instanceId}">{m.friend_settings_name()}</label>
          <input
            id="fs-name-{instanceId}"
            class="fs-input"
            bind:this={nameEl}
            bind:value={name}
            type="text"
            maxlength="64"
            autocomplete="off"
            spellcheck="false"
            placeholder={shortId}
            aria-describedby="fs-name-hint-{instanceId}"
            aria-invalid={nameTooLong}
            disabled={busy}
          />
          <span id="fs-name-hint-{instanceId}" class="fs-note" class:fs-error-text={nameTooLong}>
            {nameTooLong ? m.friend_settings_name_too_long({ max: NAME_MAX_CHARS }) : m.friend_settings_name_hint()}
          </span>
        </section>

        <section class="fs-card" aria-labelledby="fs-sec-chat-{instanceId}">
          <h4 id="fs-sec-chat-{instanceId}" class="fs-card-title">{m.friend_settings_section_chat()}</h4>
          <fieldset class="fs-fields" disabled={busy}>
            {@render triSelect(`fs-chat-${instanceId}`, m.friend_settings_chat(), chat, (v) => (chat = v), chatDefault)}
            {@render triSelect(`fs-files-${instanceId}`, m.friend_settings_files(), files, (v) => (files = v), filesDefault, !chatOn)}
            <div class="fs-row" class:is-custom={autoChoice !== 'default'} class:is-disabled={!filesOn}>
              <label for="fs-auto-{instanceId}">{m.friend_settings_auto_accept()}</label>
              <select
                id="fs-auto-{instanceId}"
                value={autoChoice}
                disabled={!filesOn}
                onchange={(e) => (autoChoice = e.currentTarget.value as AutoChoice)}
              >
                <option value="default">{autoDefaultLabel()}</option>
                <option value="never">{m.friend_settings_auto_accept_never()}</option>
                <option value="up_to">{m.friend_settings_auto_accept_up_to()}</option>
              </select>
            </div>
            {#if autoChoice === 'up_to' && filesOn}
              <div class="fs-row fs-row-indent">
                <label for="fs-auto-mb-{instanceId}">{m.friend_settings_auto_accept_mb()}</label>
                <span class="fs-unit">
                  <input
                    id="fs-auto-mb-{instanceId}"
                    class="fs-input"
                    type="number"
                    min="1"
                    max={FRIEND_AUTO_ACCEPT_MAX_MB}
                    inputmode="numeric"
                    bind:value={autoMb}
                    aria-invalid={!autoMbValid}
                  />
                  <span>{m.settings_chat_attach_auto_unit()}</span>
                </span>
              </div>
              {#if !autoMbValid}
                <p class="fs-note fs-error-text">{m.friend_settings_auto_accept_range({ max: FRIEND_AUTO_ACCEPT_MAX_MB })}</p>
              {/if}
            {/if}
            {@render triSelect(`fs-receipts-${instanceId}`, m.friend_settings_read_receipts(), readReceipts, (v) => (readReceipts = v), receiptsDefault, !chatOn)}
            <div class="fs-row" class:is-custom={disappear !== 'default'} class:is-disabled={!chatOn}>
              <label for="fs-disappear-{instanceId}">{m.friend_settings_disappear()}</label>
              <select
                id="fs-disappear-{instanceId}"
                value={disappear}
                disabled={!chatOn}
                aria-describedby={chatOn && disappearOn ? `fs-disappear-hint-${instanceId}` : undefined}
                onchange={(e) => (disappear = e.currentTarget.value)}
              >
                <option value="default">{m.friend_settings_default_value({ value: disappearLabel(disappearDefault) })}</option>
                <option value="0">{m.chat_disappear_off()}</option>
                {#each CHAT_DISAPPEAR_CHOICES as secs (secs)}
                  <option value={String(secs)}>{disappearLabel(secs)}</option>
                {/each}
              </select>
            </div>
            {#if chatOn && disappearOn}
              <p id="fs-disappear-hint-{instanceId}" class="fs-note">{m.friend_settings_disappear_hint({ name: displayName })}</p>
            {/if}
            <p class="fs-note">{chatOn ? m.friend_settings_risky_note() : m.friend_settings_needs_chat()}</p>
          </fieldset>
        </section>

        <section class="fs-card" aria-labelledby="fs-sec-sharing-{instanceId}">
          <h4 id="fs-sec-sharing-{instanceId}" class="fs-card-title">{m.friend_settings_section_sharing()}</h4>
          <fieldset class="fs-fields" disabled={busy}>
            {@render triSelect(`fs-browse-${instanceId}`, m.friend_settings_browse(), browse, (v) => (browse = v), browseDefault)}
            {#if !friend.mutual}
              <p class="fs-note">{m.friend_settings_browse_needs_mutual()}</p>
            {/if}
          </fieldset>
        </section>

        <section class="fs-card" aria-labelledby="fs-sec-notify-{instanceId}">
          <h4 id="fs-sec-notify-{instanceId}" class="fs-card-title">{m.friend_settings_section_notify()}</h4>
          <fieldset class="fs-fields" disabled={busy}>
            {@render triSelect(`fs-online-${instanceId}`, m.friend_settings_notify_online(), notifyOnline, (v) => (notifyOnline = v), notifyOnlineDefault)}
            {@render triSelect(`fs-messages-${instanceId}`, m.friend_settings_notify_messages(), notifyMessages, (v) => (notifyMessages = v), notifyMessagesDefault)}
            {#if notificationsOff}
              <p class="fs-note">{m.friend_settings_notify_master_off()}</p>
            {/if}
          </fieldset>
        </section>

        {#if error}
          <p class="fs-note fs-error-text fs-error" role="alert">{error}</p>
        {/if}
      </div>

      <div class="fs-footer">
        <button type="button" class="ghost" disabled={busy || customCount === 0} onclick={reset}>{m.friend_settings_reset()}</button>
        <span class="fs-spacer"></span>
        <button type="button" class="ghost" disabled={busy} onclick={close}>{m.common_cancel()}</button>
        <button type="submit" disabled={busy || !loadedAtOpen || nameTooLong || !autoMbValid}>{m.common_save()}</button>
      </div>
    </form>
  </div>
</div>

<style>
  /* The File Details window's frame, so the app's detail-style dialogs look
     like one family: header, body of cards, footer with the main action last. */
  .fs-overlay {
    position: fixed;
    inset: 0;
    z-index: 10000;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background: var(--overlay-bg);
  }

  .fs-dialog {
    width: min(520px, 100%);
    max-height: min(680px, calc(100vh - 48px));
    display: flex;
    flex-direction: column;
    min-height: 0;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow:
      inset 0 1px 0 var(--surface-highlight),
      var(--shadow-lg);
  }

  .fs-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .fs-title {
    margin: 0;
    min-width: 0;
    font-size: var(--font-size-lg);
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .fs-form {
    display: flex;
    flex-direction: column;
    min-height: 0;
    flex: 1;
  }

  .fs-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 16px;
  }

  .fs-hero {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    margin-bottom: 12px;
  }

  .fs-avatar {
    position: relative;
    flex-shrink: 0;
    width: 44px;
    height: 44px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--accent-dim);
    color: var(--accent);
  }

  .fs-avatar svg {
    width: 22px;
    height: 22px;
  }

  .fs-dot {
    position: absolute;
    right: 0;
    bottom: 0;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 2px solid var(--bg-secondary);
    background: var(--text-muted);
  }

  .fs-dot.online {
    background: var(--success);
  }

  .fs-hero-text {
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
    flex: 1;
  }

  .fs-name {
    font-size: var(--font-size-md);
    font-weight: 600;
    line-height: 1.35;
    overflow-wrap: anywhere;
  }

  .fs-meta {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
  }

  .fs-pill {
    padding: 1px 8px;
    border-radius: var(--radius-pill);
    font-size: var(--font-size-xs);
    font-weight: 600;
    color: var(--text-secondary);
    background: color-mix(in srgb, var(--text-muted) 16%, transparent);
  }

  .fs-pill.online {
    color: var(--success);
    background: color-mix(in srgb, var(--success) 14%, transparent);
  }

  .fs-pill.waiting {
    color: var(--warning);
    background: color-mix(in srgb, var(--warning) 14%, transparent);
  }

  .fs-id {
    font-family: var(--font-mono);
    font-size: var(--font-size-xs);
    color: var(--text-muted);
  }

  .fs-custom {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
  }

  .fs-custom.has-custom {
    color: var(--badge-accent-text);
    font-weight: 600;
  }

  /* Each group of choices on its own card, as File Details groups its figures. */
  .fs-card {
    display: flex;
    flex-direction: column;
    gap: 8px;
    min-width: 0;
    margin: 0 0 12px;
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-primary);
  }

  .fs-card-title {
    margin: 0;
    font-size: var(--font-size-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-secondary);
  }

  /* Only here to disable a card's controls while saving; no frame of its own. */
  .fs-fields {
    display: flex;
    flex-direction: column;
    gap: 8px;
    min-width: 0;
    margin: 0;
    padding: 0;
    border: 0;
  }

  .fs-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 2px 0 2px 10px;
    border-left: 2px solid transparent;
    transition: border-color var(--transition-fast) ease;
  }

  /* A choice that differs from the default is marked, so what makes this
     friend different stands out at a glance. */
  .fs-row.is-custom {
    border-left-color: var(--accent);
  }

  .fs-row.is-disabled label {
    opacity: 0.55;
  }

  .fs-row label {
    flex: 1;
    min-width: 0;
    font-size: var(--font-size-sm);
    color: var(--text-primary);
  }

  .fs-row select {
    flex: 0 0 auto;
    max-width: 55%;
  }

  .fs-row-indent {
    padding-left: 24px;
  }

  .fs-input {
    width: 100%;
    box-sizing: border-box;
  }

  .fs-unit {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
  }

  .fs-unit .fs-input {
    width: 90px;
  }

  .fs-note {
    margin: 0;
    font-size: var(--font-size-xs);
    line-height: 1.45;
    color: var(--text-muted);
  }

  .fs-callout {
    margin-bottom: 12px;
    padding: 10px 12px;
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--accent) 8%, var(--bg-primary));
    border: 1px solid color-mix(in srgb, var(--accent) 25%, var(--border));
    color: var(--text-secondary);
  }

  .fs-error-text {
    color: var(--danger);
  }

  .fs-error {
    font-size: var(--font-size-sm);
  }

  .fs-footer {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 16px;
    border-top: 1px solid var(--border);
    flex-shrink: 0;
  }

  .fs-spacer {
    flex: 1;
  }

  @media (max-width: 760px) {
    .fs-overlay {
      padding: 0;
      align-items: stretch;
    }

    .fs-dialog {
      width: 100%;
      max-height: 100vh;
      border: none;
      border-radius: 0;
    }

    .fs-footer {
      flex-wrap: wrap;
    }
  }
</style>
