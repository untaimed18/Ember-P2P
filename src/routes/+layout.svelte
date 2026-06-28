<script lang="ts">
  import '../app.css';
  import Sidebar from '$lib/components/Sidebar.svelte';
  import SplashScreen from '$lib/components/SplashScreen.svelte';
  import SetupWizard from '$lib/components/SetupWizard.svelte';
  import StatusBar from '$lib/components/StatusBar.svelte';
  import Toast from '$lib/components/Toast.svelte';
  import CloseAppDialog from '$lib/components/CloseAppDialog.svelte';
  import DeepLinkHandler from '$lib/components/DeepLinkHandler.svelte';
  import ChatDock from '$lib/components/ChatDock.svelte';
  import UpdateNotice from '$lib/components/UpdateNotice.svelte';

  import { initNetworkStore, cleanupNetworkStore, startStatsPoll } from '$lib/stores/network';
  import { initTransferStore, cleanupTransferStore, startTransferPoll } from '$lib/stores/transfers';
  import { initSearchStore, cleanupSearchStore } from '$lib/stores/search';
  import { initFriendsStore, cleanupFriendsStore } from '$lib/stores/friends';
  import { loadAppSettings, clearAppSettings } from '$lib/stores/settings';
  import { initTheme, cleanupTheme } from '$lib/stores/theme';
  import { applyDocumentLang, translateError } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';
  import { getSettings, hideToTray, quitApp, setCloseBehavior } from '$lib/api/settings';
  import { checkForUpdates } from '$lib/stores/updater';
  import { clearAllToasts, toastWarning } from '$lib/stores/toast';
  import { emberDevToolsEnabled } from '$lib/stores/devTools';
  import type { AppSettings } from '$lib/types';
  import { onMount } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';

  // Sync `<html lang>` to the active Paraglide locale on every
  // mount. Paraglide's strategy chain (localStorage →
  // preferredLanguage → baseLocale) has already resolved by the
  // time the layout renders, so this is just a one-shot DOM write.
  // Locale switches go through `setLocale()` which page-reloads,
  // re-running this on the fresh document.
  applyDocumentLang();

  let { children } = $props();
  let initialized = $state(false);
  let initError = $state('');
  let splashVisible = $state(true);
  let splashExiting = $state(false);
  let showWizard = $state(false);
  let wizardSettings: AppSettings | null = $state(null);
  let showCloseDialog = $state(false);

  async function onWizardComplete(_updated: AppSettings) {
    showWizard = false;
    wizardSettings = null;
  }

  // Close-confirmation dialog handlers. The Tauri side has already called
  // `prevent_close()` by the time we hear the `close-requested` event, so
  // these handlers are responsible for telling the backend what to do
  // next: hide to tray, exit, or (cancel) leave the window visible.
  async function handleCloseToTray(remember: boolean) {
    if (remember) {
      try {
        await setCloseBehavior('tray');
      } catch (e) {
        console.error('Failed to persist close-to-tray preference:', e);
      }
    }
    try {
      await hideToTray();
    } catch (e) {
      console.error('Failed to hide window to tray:', e);
    }
  }

  async function handleCloseExit(remember: boolean) {
    if (remember) {
      try {
        await setCloseBehavior('exit');
      } catch (e) {
        console.error('Failed to persist exit-on-close preference:', e);
      }
    }
    try {
      await quitApp();
    } catch (e) {
      console.error('Failed to quit Ember:', e);
    }
  }

  function handleCloseCancel() {
    // Nothing to do — the window is already visible because the backend
    // called `prevent_close`. Closing the dialog is enough.
  }

  // Register all event listeners immediately — don't wait for onMount/render.
  const storeInitPromise = Promise.all([
    initNetworkStore(),
    initTransferStore(),
    initSearchStore(),
    initFriendsStore(),
    loadAppSettings(),
  ]);

  // The `close-requested` and `config-corrupt-recovered` listeners are
  // registered inside onMount (below) so they're torn down AND re-registered
  // across remounts. onMount runs before the splash floor (~400ms) lifts and
  // before the backend's (delayed) corrupt-config emit, so the
  // "active before the user can act" intent is preserved.
  onMount(() => {
    initTheme();
    const splashStartedAt = performance.now();
    // The splash exists to mask the first paint, not to delay it. Once
    // the stores have initialized we want the app visible immediately;
    // the floor is only there to avoid a sub-frame flash when the init
    // races to completion.
    const minSplashMs = 400;
    const splashExitMs = 260;

    let stopPoll: (() => void) | null = null;
    let stopTransferPoll: (() => void) | null = null;
    let mounted = true;
    let revealTimer: number | undefined;
    let hideTimer: number | undefined;
    let updateCheckTimer: number | undefined;
    let unlistenClose: UnlistenFn | null = null;
    let unlistenConfigCorrupt: UnlistenFn | null = null;

    // Surface the native close confirmation. The splash masks the first frames
    // so the window can't be closed before this lands.
    listen('close-requested', () => {
      showCloseDialog = true;
    })
      .then((fn) => { if (mounted) unlistenClose = fn; else fn(); })
      .catch((e) => console.error('Failed to register close-requested listener:', e));

    // Surface a corrupt-config recovery (backend reset settings to defaults and
    // preserved the original as a .bak). The backend's emit is delayed, so
    // registering here is in time.
    listen<{ backup_path: string }>('config-corrupt-recovered', (event) => {
      const path = event.payload?.backup_path ?? '';
      toastWarning(path ? m.layout_config_corrupt_backup({ path }) : m.layout_config_corrupt());
    })
      .then((fn) => { if (mounted) unlistenConfigCorrupt = fn; else fn(); })
      .catch((e) => console.error('Failed to register config-corrupt listener:', e));

    const revealApp = () => {
      if (!mounted || !splashVisible) return;
      splashExiting = true;
      hideTimer = window.setTimeout(() => {
        if (!mounted) return;
        splashVisible = false;
      }, splashExitMs);
    };

    const releaseSplashWhenReady = () => {
      const elapsed = performance.now() - splashStartedAt;
      const waitMs = Math.max(0, minSplashMs - elapsed);
      revealTimer = window.setTimeout(revealApp, waitMs);
    };

    storeInitPromise
      .then(async () => {
        if (mounted) {
          stopPoll = startStatsPoll();
          stopTransferPoll = startTransferPoll();
          initialized = true;

          // Fetch settings with bounded exponential-backoff retries.
          //
          // Previously a single retry-and-skip landed users in the
          // main app whenever `getSettings()` lost two IPC races in a
          // row: `setup_complete` stayed false on disk, yet no wizard
          // ever rendered and nothing surfaced the failure — the user
          // saw a fully default app (empty nickname, no shared
          // folders, no download folder) with no indication that
          // setup was supposed to run, and the same dice-roll could
          // repeat on every launch.
          //
          // Policy now: retry up to 5 times with short backoff. If
          // we still can't load settings, treat it as a fatal init
          // error (the existing .init-error branch below already
          // renders a blocking Retry button that reloads the window).
          // Never drop into `children()` with `setup_complete === false`
          // and no wizard shown.
          const retryDelaysMs = [150, 300, 600, 1200];
          let settings: AppSettings | null = null;
          let settingsError: unknown = null;
          for (let attempt = 0; attempt <= retryDelaysMs.length; attempt++) {
            if (!mounted) return;
            try {
              settings = await getSettings();
              break;
            } catch (e) {
              settingsError = e;
              if (attempt === retryDelaysMs.length) break;
              console.warn(
                `Settings fetch attempt ${attempt + 1} failed, retrying in ${retryDelaysMs[attempt]}ms...`,
                e,
              );
              await new Promise((r) => setTimeout(r, retryDelaysMs[attempt]));
            }
          }
          if (!mounted) return;

          if (settings) {
            // Seed the dev-console visibility store so the sidebar link
            // reflects the saved preference from first paint.
            emberDevToolsEnabled.set(!!settings.ember_dev_tools_enabled);
            if (!settings.setup_complete) {
              wizardSettings = settings;
              showWizard = true;
            }
          } else {
            console.error('Persistent settings fetch failure; blocking main app entry', settingsError);
            initError = settingsError instanceof Error
              ? m.layout_settings_load_error_detail({ detail: settingsError.message })
              : m.layout_settings_load_error();
          }

          releaseSplashWhenReady();

          // Silent background update check, deferred so it never competes
          // with first paint or store init. Production only: in a dev build
          // the running version is the dev version and the GitHub manifest
          // would spuriously report an "update". Any failure (offline,
          // unreachable manifest) is swallowed by the store's silent mode,
          // and a result surfaces non-blockingly via <UpdateNotice />.
          if (!import.meta.env.DEV) {
            updateCheckTimer = window.setTimeout(() => {
              if (mounted) void checkForUpdates({ silent: true });
            }, 4000);
          }
        } else {
          cleanupNetworkStore();
          cleanupTransferStore();
          cleanupSearchStore();
          cleanupFriendsStore();
        }
      })
      .catch((e) => {
        cleanupNetworkStore();
        cleanupTransferStore();
        cleanupSearchStore();
        cleanupFriendsStore();
        initError = translateError(e, m.layout_init_failed());
        initialized = true;
        releaseSplashWhenReady();
      });

    return () => {
      mounted = false;
      if (revealTimer !== undefined) window.clearTimeout(revealTimer);
      if (hideTimer !== undefined) window.clearTimeout(hideTimer);
      if (updateCheckTimer !== undefined) window.clearTimeout(updateCheckTimer);
      if (stopPoll) stopPoll();
      if (stopTransferPoll) stopTransferPoll();
      cleanupTheme();
      cleanupNetworkStore();
      cleanupTransferStore();
      cleanupSearchStore();
      cleanupFriendsStore();
      clearAllToasts();
      clearAppSettings();
      if (unlistenClose) unlistenClose();
      if (unlistenConfigCorrupt) unlistenConfigCorrupt();
    };
  });
</script>

<a href="#main-content" class="skip-to-content">{m.layout_skip_to_content()}</a>
{#if splashVisible}
  <SplashScreen exiting={splashExiting} />
{/if}
{#if showWizard && wizardSettings}
  <SetupWizard settings={wizardSettings} oncomplete={onWizardComplete} />
{/if}
<div class="app-shell">
  <!--
    Sidebar renders its own <nav aria-label="Primary"> landmark. An
    extra outer <nav> here used to double-announce the navigation
    region to screen readers ("Main navigation" then "Primary") and
    required `nav { display: contents }` to avoid breaking the flex
    layout. Mounting Sidebar directly is simpler and a11y-correct.
  -->
  <Sidebar />
  <div class="main-area">
    <main id="main-content" class="page-container">
      {#if !initialized}
        <div class="init-loading">
          <div class="spinner lg"></div>
          <p>{m.layout_starting()}</p>
        </div>
      {:else if initError}
        <div class="init-error">
          <p>{initError}</p>
          <button onclick={() => location.reload()}>{m.layout_retry()}</button>
        </div>
      {:else}
        {@render children()}
      {/if}
    </main>
    <StatusBar />
  </div>
  <Toast />
  {#if initialized && !initError && !showWizard}
    <!-- Non-blocking auto-update banner, driven by the shared updater store. -->
    <UpdateNotice />
    <!-- Headless: routes OS-delivered ed2k:// links and .emulecollection
    files into the app once the shell is ready (settings loaded, no wizard). -->
    <DeepLinkHandler />
  {/if}
  <!--
    Multi-conversation chat dock. Mounted at the app shell so chats
    persist across route changes — the user can answer a message from
    /transfers or /library without losing their place. Internally
    keyed off the `chatTabs` store, so opening a chat from any page
    just calls `chatTabs.openChat(hash, name)`.
  -->
  <ChatDock />
</div>

<CloseAppDialog
  bind:open={showCloseDialog}
  onhide={handleCloseToTray}
  onexit={handleCloseExit}
  oncancel={handleCloseCancel}
/>

<style>
  .skip-to-content {
    position: absolute;
    top: -40px;
    left: 0;
    z-index: 10000;
    padding: 8px 16px;
    background: var(--accent);
    color: #fff;
    text-decoration: none;
    font-weight: 600;
    font-size: 13px;
    border-radius: 0 0 var(--radius-md) 0;
  }

  .skip-to-content:focus {
    top: 0;
  }

  .app-shell {
    display: flex;
    height: 100dvh;
    height: 100vh;
    width: 100vw;
    overflow: hidden;
  }

  .main-area {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .page-container {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .init-loading {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    color: var(--text-muted);
  }

  .init-error {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    color: var(--danger);
    text-align: center;
    padding: 40px;
  }
</style>
