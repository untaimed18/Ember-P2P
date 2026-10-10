<script lang="ts">
  // One friend's settings: their name, and exceptions to the Friends settings
  // for them alone. Every choice offers "Use default", which follows the
  // global setting and says what that is now, so nothing here can quietly
  // disagree with Settings without the user having picked it.
  import * as m from '$lib/paraglide/messages';
  import { onMount, tick, untrack } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { inertBackground, trapTabKey } from '$lib/a11y';
  import { translateError } from '$lib/i18n';
  import { appSettings, setAppSettings } from '$lib/stores/settings';
  import { setFriendOverrides } from '$lib/api/settings';
  import {
    compactOverrides,
    friendNameTooLong,
    friendOverrides,
    FRIEND_AUTO_ACCEPT_MAX_MB,
    FRIEND_NAME_MAX_BYTES as NAME_MAX_BYTES,
  } from '$lib/friendSettings';
  import type { FriendInfo } from '$lib/api/friends';
  import type { FriendOverrides } from '$lib/types';

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

  // What each default currently is, so "Use default" says what it means.
  let chatDefault = $derived($appSettings?.friend_chat_disabled !== true);
  let chatOn = $derived(chat === 'default' ? chatDefault : chat === 'on');
  let browseDefault = $derived($appSettings?.friend_browse_disabled !== true);
  let receiptsDefault = $derived($appSettings?.friend_chat_read_receipts !== false);
  let notifyOnlineDefault = $derived($appSettings?.notify_friend_online === true);
  let notifyMessagesDefault = $derived($appSettings?.notify_friend_message === true);
  let notificationsOff = $derived($appSettings?.notifications_enabled === false);
  let autoDefaultMb = $derived($appSettings?.chat_attachment_auto_accept_mb ?? 0);

  let nameTooLong = $derived(friendNameTooLong(name));
  let autoMbValid = $derived(
    autoChoice !== 'up_to' || (Number.isInteger(autoMb) && autoMb >= 1 && autoMb <= FRIEND_AUTO_ACCEPT_MAX_MB),
  );

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
        !chatOn || files === 'off' || autoChoice === 'default'
          ? undefined
          : autoChoice === 'never'
            ? 0
            : autoMb,
      browse: fromTri(browse),
      read_receipts: chatOn ? fromTri(readReceipts) : undefined,
      notify_online: fromTri(notifyOnline),
      notify_messages: fromTri(notifyMessages),
    });
  }

  function reset() {
    chat = files = browse = readReceipts = notifyOnline = notifyMessages = 'default';
    autoChoice = 'default';
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
  <div class="fs-row">
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
  class="confirm-overlay"
  bind:this={overlayEl}
  role="dialog"
  aria-modal="true"
  aria-labelledby="fs-title-{instanceId}"
  aria-describedby="fs-hint-{instanceId}"
  tabindex="-1"
  onkeydown={onKeydown}
  onclick={(e) => e.target === e.currentTarget && close()}
  transition:fade={{ duration: prefersReducedMotion.current ? 0 : 150 }}
>
  <div
    class="confirm-dialog fs-dialog"
    bind:this={dialogEl}
    transition:scale={{ start: 0.96, opacity: 0, duration: prefersReducedMotion.current ? 0 : 200 }}
  >
    <h3 id="fs-title-{instanceId}">
      {m.friend_settings_title({ name: friend.nickname || `${hash.slice(0, 8)}\u2026` })}
    </h3>
    <p id="fs-hint-{instanceId}" class="fs-hint">{m.friend_settings_hint()}</p>

    <form onsubmit={(e) => { e.preventDefault(); void save(); }}>
      <div class="fs-field">
        <label for="fs-name-{instanceId}">{m.friend_settings_name()}</label>
        <input
          id="fs-name-{instanceId}"
          bind:this={nameEl}
          bind:value={name}
          type="text"
          maxlength="64"
          autocomplete="off"
          spellcheck="false"
          placeholder={`${hash.slice(0, 8)}\u2026`}
          aria-describedby="fs-name-hint-{instanceId}"
          aria-invalid={nameTooLong}
          disabled={busy}
        />
        <span id="fs-name-hint-{instanceId}" class="fs-sub" class:fs-error-text={nameTooLong}>
          {nameTooLong ? m.friend_settings_name_too_long({ max: NAME_MAX_BYTES }) : m.friend_settings_name_hint()}
        </span>
      </div>

      <fieldset class="fs-group" disabled={busy}>
        <legend>{m.friend_settings_section_chat()}</legend>
        {@render triSelect(`fs-chat-${instanceId}`, m.friend_settings_chat(), chat, (v) => (chat = v), chatDefault)}
        {@render triSelect(`fs-files-${instanceId}`, m.friend_settings_files(), files, (v) => (files = v), true, !chatOn)}
        <div class="fs-row">
          <label for="fs-auto-{instanceId}">{m.friend_settings_auto_accept()}</label>
          <select
            id="fs-auto-{instanceId}"
            value={autoChoice}
            disabled={!chatOn || files === 'off'}
            onchange={(e) => (autoChoice = e.currentTarget.value as AutoChoice)}
          >
            <option value="default">{autoDefaultLabel()}</option>
            <option value="never">{m.friend_settings_auto_accept_never()}</option>
            <option value="up_to">{m.friend_settings_auto_accept_up_to()}</option>
          </select>
        </div>
        {#if autoChoice === 'up_to' && chatOn && files !== 'off'}
          <div class="fs-row fs-row-indent">
            <label for="fs-auto-mb-{instanceId}">{m.friend_settings_auto_accept_mb()}</label>
            <span class="fs-unit">
              <input
                id="fs-auto-mb-{instanceId}"
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
            <p class="fs-sub fs-error-text">{m.friend_settings_auto_accept_range({ max: FRIEND_AUTO_ACCEPT_MAX_MB })}</p>
          {/if}
        {/if}
        {@render triSelect(`fs-receipts-${instanceId}`, m.friend_settings_read_receipts(), readReceipts, (v) => (readReceipts = v), receiptsDefault, !chatOn)}
        {#if !chatOn}
          <p class="fs-sub">{m.friend_settings_needs_chat()}</p>
        {:else}
          <p class="fs-sub">{m.friend_settings_risky_note()}</p>
        {/if}
      </fieldset>

      <fieldset class="fs-group" disabled={busy}>
        <legend>{m.friend_settings_section_sharing()}</legend>
        {@render triSelect(`fs-browse-${instanceId}`, m.friend_settings_browse(), browse, (v) => (browse = v), browseDefault)}
        {#if !friend.mutual}
          <p class="fs-sub">{m.friend_settings_browse_needs_mutual()}</p>
        {/if}
      </fieldset>

      <fieldset class="fs-group" disabled={busy}>
        <legend>{m.friend_settings_section_notify()}</legend>
        {@render triSelect(`fs-online-${instanceId}`, m.friend_settings_notify_online(), notifyOnline, (v) => (notifyOnline = v), notifyOnlineDefault)}
        {@render triSelect(`fs-messages-${instanceId}`, m.friend_settings_notify_messages(), notifyMessages, (v) => (notifyMessages = v), notifyMessagesDefault)}
        {#if notificationsOff}
          <p class="fs-sub">{m.friend_settings_notify_master_off()}</p>
        {/if}
      </fieldset>

      <div class="fs-error" aria-live="polite">
        {#if error}<span>{error}</span>{/if}
      </div>

      <div class="dialog-actions fs-actions">
        <button type="button" class="ghost fs-reset" disabled={busy} onclick={reset}>{m.friend_settings_reset()}</button>
        <span class="fs-spacer"></span>
        <button type="button" class="ghost" disabled={busy} onclick={close}>{m.common_cancel()}</button>
        <button type="submit" disabled={busy || !loadedAtOpen || nameTooLong || !autoMbValid}>{m.common_save()}</button>
      </div>
    </form>
  </div>
</div>

<style>
  .fs-dialog {
    width: min(480px, calc(100vw - 48px));
    max-width: none;
    max-height: calc(100vh - 48px);
    overflow-y: auto;
  }

  .fs-hint {
    margin: 0 0 14px;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }

  .fs-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-bottom: 14px;
  }

  .fs-field label,
  .fs-row label {
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
  }

  .fs-group {
    margin: 0 0 12px;
    padding: 10px 12px 8px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .fs-group legend {
    padding: 0 4px;
    font-size: var(--font-size-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    color: var(--text-muted);
  }

  .fs-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .fs-row label {
    flex: 1;
    min-width: 0;
  }

  .fs-row select {
    flex: 0 0 auto;
    max-width: 55%;
  }

  .fs-row-indent {
    padding-left: 14px;
  }

  .fs-unit {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
  }

  .fs-unit input {
    width: 90px;
  }

  .fs-sub {
    margin: 0;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
  }

  .fs-error-text {
    color: var(--danger);
  }

  .fs-error {
    min-height: 1.4em;
    margin: 2px 0 10px;
    font-size: var(--font-size-sm);
    color: var(--danger);
  }

  .fs-actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .fs-spacer {
    flex: 1;
  }
</style>
