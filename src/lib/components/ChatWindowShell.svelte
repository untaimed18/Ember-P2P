<script lang="ts">
  import { onMount } from 'svelte';
  import ChatDock from '$lib/components/ChatDock.svelte';
  import Toast from '$lib/components/Toast.svelte';
  import { initFriendsStore, cleanupFriendsStore } from '$lib/stores/friends';
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
      const outcomes = await Promise.allSettled([initFriendsStore(), loadAppSettings()]);
      for (const outcome of outcomes) {
        if (outcome.status === 'rejected') console.error('Chat window store failed:', outcome.reason);
      }
      const cleanup = await initChatWindowSide();
      if (!mounted) {
        cleanup();
        return;
      }
      teardown = cleanup;
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
      clearAllToasts();
      clearAppSettings();
    };
  });
</script>

{#if ready}
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
</style>
