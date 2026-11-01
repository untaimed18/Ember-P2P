<script lang="ts">
  import { onMount } from 'svelte';
  import ChatDock from '$lib/components/ChatDock.svelte';
  import Toast from '$lib/components/Toast.svelte';
  import { initFriendsStore, cleanupFriendsStore, friendsList, friendsListLoaded, refreshFriendsList } from '$lib/stores/friends';
  import { initRoomDmStore, cleanupRoomDmStore } from '$lib/stores/roomDm';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { loadAppSettings, clearAppSettings, setAppSettings } from '$lib/stores/settings';
  import { SETTINGS_CHANGED_EVENT } from '$lib/api/settings';
  import type { AppSettings } from '$lib/types';
  import { initTheme, cleanupTheme } from '$lib/stores/theme';
  import { clearAllToasts, toastError } from '$lib/stores/toast';
  import { initChatWindowSide } from '$lib/chatPopout';
  import { startUserActivityReporting } from '$lib/userActivity';
  import { translateError } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';

  /**
   * The popped-out chat window: the dock, and only what the dock reads.
   *
   * The main window's shell — sidebar, status bar, polls, the setup wizard,
   * the close-to-tray dialog — belongs to the main window alone. The channel,
   * transfer and search stores are not started here either: the dock shows
   * friend conversations, and every store started twice is another listener
   * answering each event twice.
   */
  let ready = $state(false);
  /** The friend list never arrived. The dock would read the empty list as
   *  having no friends and suggest adding one. */
  let friendsFailed = $state(false);
  let retryingFriends = $state(false);

  async function retryFriends() {
    if (retryingFriends) return;
    retryingFriends = true;
    await refreshFriendsList();
    friendsFailed = !friendsListLoaded();
    retryingFriends = false;
  }

  // A refresh started elsewhere (a friend confirming, say) can land first.
  $effect(() => {
    void $friendsList;
    if (friendsFailed && friendsListLoaded()) friendsFailed = false;
  });

  onMount(() => {
    initTheme();
    let mounted = true;
    let teardown: (() => void) | null = null;
    // Chatting here is using Ember: a silent update waits until nobody is.
    const stopActivityReporting = startUserActivityReporting();

    const onUnhandledRejection = (event: PromiseRejectionEvent) => {
      console.error('Unhandled promise rejection:', event.reason);
      if (mounted) toastError(translateError(event.reason, m.error_operation_failed()));
    };
    window.addEventListener('unhandledrejection', onUnhandledRejection);

    // Per-friend chat, read receipts and notifications are read from these
    // settings. A friend's settings dialog announces its saves; the Settings
    // page does not, and is caught up with when this window is next focused.
    let unlistenSettingsChanged: UnlistenFn | null = null;
    listen<AppSettings>(SETTINGS_CHANGED_EVENT, (event) => {
      if (mounted) setAppSettings(event.payload);
    })
      .then((fn) => {
        if (mounted) unlistenSettingsChanged = fn;
        else fn();
      })
      .catch((e) => console.error('Failed to register settings-changed listener:', e));
    const onFocus = () => void loadAppSettings();
    window.addEventListener('focus', onFocus);

    void (async () => {
      const outcomes = await Promise.allSettled([initFriendsStore(), loadAppSettings(), initRoomDmStore()]);
      for (const outcome of outcomes) {
        if (outcome.status === 'rejected') console.error('Chat window store failed:', outcome.reason);
      }
      const cleanup = await initChatWindowSide();
      if (!mounted) {
        cleanup();
        return;
      }
      teardown = cleanup;
      friendsFailed = !friendsListLoaded();
      ready = true;
    })();

    return () => {
      mounted = false;
      window.removeEventListener('unhandledrejection', onUnhandledRejection);
      window.removeEventListener('focus', onFocus);
      unlistenSettingsChanged?.();
      stopActivityReporting();
      teardown?.();
      cleanupTheme();
      cleanupFriendsStore();
      cleanupRoomDmStore();
      clearAllToasts();
      clearAppSettings();
    };
  });
</script>

{#if ready && friendsFailed}
  <div class="chat-window-loading chat-window-error" role="alert">
    <p>{m.chat_window_friends_load_failed()}</p>
    <button type="button" onclick={() => void retryFriends()} disabled={retryingFriends} aria-busy={retryingFriends}>
      {m.common_retry()}
    </button>
  </div>
{:else if ready}
  <ChatDock windowed />
{:else}
  <div class="chat-window-loading" aria-busy="true">
    <div class="spinner" role="status" aria-label={m.chat_loading_messages()}></div>
  </div>
{/if}
<Toast />

<style>
  .chat-window-loading {
    position: fixed;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-primary);
  }

  .chat-window-error {
    flex-direction: column;
    gap: 12px;
    padding: 24px;
    color: var(--text-secondary);
    text-align: center;
  }

  .chat-window-error p {
    margin: 0;
  }
</style>
