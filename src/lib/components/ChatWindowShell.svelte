<script lang="ts">
  import { onMount } from 'svelte';
  import ChatDock from '$lib/components/ChatDock.svelte';
  import Toast from '$lib/components/Toast.svelte';
  import { initFriendsStore, cleanupFriendsStore } from '$lib/stores/friends';
  import { loadAppSettings, clearAppSettings } from '$lib/stores/settings';
  import { initTheme, cleanupTheme } from '$lib/stores/theme';
  import { clearAllToasts, toastError } from '$lib/stores/toast';
  import { initChatWindowSide } from '$lib/chatPopout';
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

    const onUnhandledRejection = (event: PromiseRejectionEvent) => {
      console.error('Unhandled promise rejection:', event.reason);
      if (mounted) toastError(translateError(event.reason, m.error_operation_failed()));
    };
    window.addEventListener('unhandledrejection', onUnhandledRejection);

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
    <div class="spinner"></div>
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
