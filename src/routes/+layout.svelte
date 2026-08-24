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
  import { loadAppSettings, clearAppSettings, setAppSettings } from '$lib/stores/settings';
  import { initTheme, cleanupTheme } from '$lib/stores/theme';
  import { applyDocumentLang, translateError } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';
  import {
    getSettings,
    hideToTray,
    quitApp,
    setCloseBehavior,
    takePendingCloseRequest,
    takePendingEmberDefaultOnNotice,
    takePendingRestoreFailedNotice,
  } from '$lib/api/settings';
  import { checkForUpdates, checkUpdateHandoff, isUpdateCheckDue } from '$lib/stores/updater';
  import {
    acknowledgeSecurityPolicyReset,
    getSecurityPolicyState,
  } from '$lib/api/security';
  import { addToast, clearAllToasts, toastError, toastSuccess, toastWarning } from '$lib/stores/toast';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import { confirmDroppedFolders, dismissDroppedFolders } from '$lib/api/sharing';
  import { takePendingDownloadOverflowNotice } from '$lib/api/transfers';
  import type { AppSettings } from '$lib/types';
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import { fly } from 'svelte/transition';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { inertBackground, trapTabKey } from '$lib/a11y';

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
  /// A dropped file's containing folder(s), awaiting an answer. `token` is all
  /// the backend accepts back — it holds the paths itself, because a dropped
  /// path is authorization only by virtue of the OS handing it to the native
  /// window, and routing it through here would throw that away.
  let dropPrompt = $state<{
    open: boolean;
    token: number;
    folders: string[];
    reason: 'files' | 'broad' | 'many';
  }>({
    open: false,
    token: 0,
    folders: [],
    reason: 'files',
  });
  /// The prompt says what is actually true of the drop. "Broad" is the one that
  /// matters: sharing a folder that contains your home directory hands out
  /// Documents, Desktop and Pictures at once, and it is the mistake a single
  /// careless drag from a file manager's sidebar makes easiest.
  let dropPromptMessage = $derived.by(() => {
    const folders = dropPrompt.folders;
    const summary = folders.slice(0, 3).join(', ') + (folders.length > 3 ? '…' : '');
    if (dropPrompt.reason === 'many') {
      return m.library_drop_many_confirm({ count: folders.length, summary });
    }
    if (dropPrompt.reason === 'broad') {
      return folders.length === 1
        ? m.library_drop_broad_confirm_one({ folder: folders[0] })
        : m.library_drop_broad_confirm_other({ count: folders.length, summary });
    }
    return folders.length === 1
      ? m.library_drop_parent_confirm_one({ folder: folders[0] })
      : m.library_drop_parent_confirm_other({ count: folders.length, summary });
  });
  let policyResetReason = $state<string | null>(null);
  let policyResetPending = $state(false);
  let policyResetError = $state('');
  let policyResetOverlayEl: HTMLDivElement | undefined = $state(undefined);
  let policyResetDialogEl: HTMLDivElement | undefined = $state(undefined);
  let policyResetAckBtn: HTMLButtonElement | undefined = $state(undefined);

  async function acknowledgePolicyReset() {
    if (policyResetPending) return;
    policyResetPending = true;
    policyResetError = '';
    try {
      await acknowledgeSecurityPolicyReset();
      policyResetReason = null;
    } catch (error) {
      policyResetError = translateError(error, m.layout_policy_reset_failed());
    } finally {
      policyResetPending = false;
    }
  }

  function handlePolicyResetKeydown(e: KeyboardEvent) {
    // Blocking gate: Escape must not dismiss. Tab stays inside the dialog.
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      return;
    }
    trapTabKey(e, policyResetDialogEl);
  }

  $effect(() => {
    if (!policyResetReason || !policyResetOverlayEl) return;
    return inertBackground(policyResetOverlayEl);
  });

  $effect(() => {
    if (!policyResetReason) return;
    requestAnimationFrame(() => {
      policyResetAckBtn?.focus();
    });
  });

  async function onWizardComplete(updated: AppSettings) {
    setAppSettings(updated);
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
        setAppSettings(await getSettings());
      } catch (e) {
        console.error('Failed to persist close-to-tray preference:', e);
        // "Remember my choice" silently not sticking means the user is asked
        // again next launch with no idea why.
        toastError(translateError(e, m.settings_save_failed()));
      }
    }
    try {
      await hideToTray();
    } catch (e) {
      console.error('Failed to hide window to tray:', e);
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  async function handleCloseExit(remember: boolean) {
    if (remember) {
      try {
        await setCloseBehavior('exit');
        setAppSettings(await getSettings());
      } catch (e) {
        console.error('Failed to persist exit-on-close preference:', e);
        toastError(translateError(e, m.settings_save_failed()));
      }
    }
    try {
      await quitApp();
    } catch (e) {
      console.error('Failed to quit Ember:', e);
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  function handleCloseCancel() {
    // Nothing to do — the window is already visible because the backend
    // called `prevent_close`. Closing the dialog is enough.
  }

  /**
   * Start every store; fail only on the ones the shell cannot run without.
   *
   * `Promise.all` made startup all-or-nothing. `initTransferStore` and
   * `initFriendsStore` rethrow when an `await listen(...)` registration fails,
   * and the `.catch` below then tears every store down behind the blocking
   * `initError` screen — so one transient failure registering a friend-presence
   * listener gated the whole app behind a manual retry. The non-essential
   * stores each fail closed (they unlisten what they registered and reset their
   * own `initialized` flag), so continuing leaves nothing half-wired, and
   * `allSettled` also means every listener a store *did* register is in its
   * `unlisteners` list before any `cleanup*` runs.
   *
   * Resolves with the reasons of the non-fatal failures so the caller can
   * surface them once it knows the shell is still mounted.
   */
  async function initStores(): Promise<unknown[]> {
    // Essential = what the app shell itself reads: the network store backs the
    // status bar and both polls, and the settings cache gates the wizard, the
    // close behavior and the update check below. The other three each back one
    // feature — and transfers keeps its own `list_transfers` poll — so they
    // degrade to a toast rather than a blank window.
    const stores: Array<{ init: () => Promise<void>; essential: boolean }> = [
      { init: initNetworkStore, essential: true },
      { init: initTransferStore, essential: false },
      { init: initSearchStore, essential: false },
      { init: initFriendsStore, essential: false },
      { init: loadAppSettings, essential: true },
    ];
    const outcomes = await Promise.allSettled(stores.map((s) => s.init()));
    const degraded: unknown[] = [];
    const fatal: unknown[] = [];
    for (const [i, outcome] of outcomes.entries()) {
      if (outcome.status !== 'rejected') continue;
      // Log every failure before deciding, so an essential one doesn't hide
      // the rest from the devtools console.
      console.error('Store initialization failed:', outcome.reason);
      (stores[i].essential ? fatal : degraded).push(outcome.reason);
    }
    if (fatal.length > 0) throw fatal[0];
    return degraded;
  }

  // The `close-requested`, `config-corrupt-recovered`, and
  // `db-corrupt-recovered` listeners are registered inside onMount
  // (below) so they're torn down AND re-registered across remounts.
  // onMount runs before the splash floor (~400ms) lifts and before the
  // backend's (delayed) corrupt-config/db emit, so the
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
    let handoffCheckTimer: number | undefined;
    let unlistenClose: UnlistenFn | null = null;
    let unlistenConfigCorrupt: UnlistenFn | null = null;
    let unlistenDbCorrupt: UnlistenFn | null = null;
    let unlistenPolicyReset: UnlistenFn | null = null;
    let unlistenFoldersAdded: UnlistenFn | null = null;
    let unlistenFoldersFailed: UnlistenFn | null = null;
    let unlistenDropPending: UnlistenFn | null = null;
    let unlistenDropRejected: UnlistenFn | null = null;

    // Last-resort floor for promise rejections nothing else caught. Every
    // `invoke()` rejects whenever its Rust command returns `Err`, so a call
    // that escapes its own handler used to fail completely silently — the
    // reason went to the WebView2 console, which no user ever opens, and the
    // action they triggered just appeared to do nothing.
    const onUnhandledRejection = (event: PromiseRejectionEvent) => {
      console.error('Unhandled promise rejection:', event.reason);
      if (!mounted) return;
      toastError(translateError(event.reason, m.error_operation_failed()));
    };
    window.addEventListener('unhandledrejection', onUnhandledRejection);

    // Register before consuming the native latch. A close can be prevented by
    // Tauri before this async registration resolves; the backend records that
    // request so it is still surfaced exactly once after the listener is live.
    void (async () => {
      try {
        const fn = await listen('close-requested', () => {
          if (!mounted) return;
          showCloseDialog = true;
          // Clear the backend latch for a live event too, preventing a later
          // remount from reopening a dialog the user already dismissed.
          void takePendingCloseRequest().catch((e) =>
            console.error('Failed to consume close-request latch:', e),
          );
        });
        if (!mounted) {
          fn();
          return;
        }
        unlistenClose = fn;
        if (await takePendingCloseRequest()) showCloseDialog = true;
      } catch (e) {
        console.error('Failed to register close-requested listener:', e);
      }
    })();

    // Surface a corrupt-config recovery (backend reset settings to defaults and
    // preserved the original as a .bak). The backend's emit is delayed, so
    // registering here is in time.
    listen<{ backup_path: string }>('config-corrupt-recovered', (event) => {
      const path = event.payload?.backup_path ?? '';
      toastWarning(path ? m.layout_config_corrupt_backup({ path }) : m.layout_config_corrupt());
    })
      .then((fn) => { if (mounted) unlistenConfigCorrupt = fn; else fn(); })
      .catch((e) => console.error('Failed to register config-corrupt listener:', e));

    listen<{ backup_path: string }>('db-corrupt-recovered', (event) => {
      const path = event.payload?.backup_path ?? '';
      toastWarning(path ? m.layout_db_corrupt_backup({ path }) : m.layout_db_corrupt());
    })
      .then((fn) => { if (mounted) unlistenDbCorrupt = fn; else fn(); })
      .catch((e) => console.error('Failed to register db-corrupt listener:', e));

    // The upgrade turned the Ember overlay on for a profile that had it off.
    // There is no stored difference between "off because that was the default"
    // and "off because the user chose it", so say so rather than assume.
    //
    // Pulled from a backend latch rather than pushed as an event: the
    // migration is written to disk during setup and never runs again, so an
    // event fired before this webview finished starting would take the only
    // notice with it. Sticky, because it is a consent notice about joining a
    // network — the default six seconds is not long enough to read it.
    takePendingEmberDefaultOnNotice()
      .then((pending) => {
        if (mounted && pending) addToast('warning', m.layout_ember_default_on(), 0);
      })
      .catch((e) => console.error('Failed to consume the ember-default-on latch:', e));

    takePendingRestoreFailedNotice()
      .then((pending) => {
        if (mounted && pending) addToast('warning', m.layout_restore_failed(), 0);
      })
      .catch((e) => console.error('Failed to consume the restore-failed latch:', e));

    listen<{ loaded: boolean; resetRequired: boolean; reason?: string }>(
      'security-policy-reset-required',
      (event) => {
        if (!mounted) return;
        policyResetReason = event.payload?.reason || m.layout_policy_reset_unknown_reason();
      },
    )
      .then((fn) => { if (mounted) unlistenPolicyReset = fn; else fn(); })
      .catch((e) => console.error('Failed to register security-policy listener:', e));

    // Drag-drop sharing is handled by the backend from the OS event on the
    // window, so it fires wherever the user happens to be. Its acknowledgement
    // and its one question therefore belong here rather than on the Library
    // page: registered there, dropping a folder from any other page shared it
    // with no confirmation shown, and dropping a *file* asked nothing and so
    // did nothing at all.
    listen<{ count?: number }>('shared-folders-added', (event) => {
      if (!mounted) return;
      const count = event.payload?.count ?? 0;
      if (count <= 0) return;
      toastSuccess(
        count === 1 ? m.library_folders_shared_one() : m.library_folders_shared_other({ count }),
      );
    })
      .then((fn) => { if (mounted) unlistenFoldersAdded = fn; else fn(); })
      .catch((e) => console.error('Failed to register shared-folders-added listener:', e));

    // A drop that shared nothing has to say so: it is indistinguishable from a
    // drop the app never received otherwise, and the gesture is the feature.
    listen<{ count?: number }>('shared-folders-add-failed', (event) => {
      if (!mounted) return;
      const count = event.payload?.count ?? 0;
      if (count <= 0) return;
      toastWarning(
        count === 1
          ? m.library_folders_share_failed_one()
          : m.library_folders_share_failed_other({ count }),
      );
    })
      .then((fn) => { if (mounted) unlistenFoldersFailed = fn; else fn(); })
      .catch((e) => console.error('Failed to register shared-folders-add-failed listener:', e));

    listen<{ token?: number; folders?: string[]; reason?: string }>(
      'shared-folder-drop-pending',
      (event) => {
        if (!mounted) return;
        const token = event.payload?.token;
        const folders = event.payload?.folders ?? [];
        if (typeof token !== 'number' || folders.length === 0) return;
        const raw = event.payload?.reason;
        // Unknown reasons fall back to the narrowest wording rather than the
        // scariest, so a future backend value cannot mislabel an ordinary drop.
        const reason = raw === 'broad' || raw === 'many' ? raw : 'files';
        dropPrompt = { open: true, token, folders, reason };
      },
    )
      .then((fn) => { if (mounted) unlistenDropPending = fn; else fn(); })
      .catch((e) => console.error('Failed to register drop-pending listener:', e));

    listen<{ reason?: string; limit?: number }>('shared-folder-drop-rejected', (event) => {
      if (!mounted) return;
      toastWarning(
        event.payload?.reason === 'too_many'
          ? m.library_drop_too_many({ limit: event.payload?.limit ?? 0 })
          : m.library_drop_nothing(),
      );
    })
      .then((fn) => { if (mounted) unlistenDropRejected = fn; else fn(); })
      .catch((e) => console.error('Failed to register drop-rejected listener:', e));

    void getSecurityPolicyState()
      .then((status) => {
        if (mounted && status.resetRequired) {
          policyResetReason = status.reason || m.layout_policy_reset_unknown_reason();
        }
      })
      .catch((e) => console.error('Failed to read security-policy state:', e));

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

    initStores()
      .then(async (degraded) => {
        if (mounted) {
          stopPoll = startStatsPoll();
          stopTransferPoll = startTransferPoll();
          initialized = true;
          // A store that couldn't register its listeners keeps its feature
          // degraded until the next launch, so say so — non-blockingly, since
          // the rest of the app is usable. `layout_init_failed` is reused
          // deliberately: its "restart the app" advice is the remedy here too.
          if (degraded.length > 0) {
            toastError(translateError(degraded[0], m.layout_init_failed()));
          }
          try {
            // Only consume once we know the shell is still alive. The backend
            // command acknowledges+returns the count atomically — there is no
            // peek — so always surface the toast after a successful take.
            if (mounted) {
              const migrated = await takePendingDownloadOverflowNotice();
              if (migrated > 0) {
                toastWarning(
                  migrated === 1
                    ? m.layout_download_overflow_notice_one()
                    : m.layout_download_overflow_notice_other({ count: migrated }),
                );
              }
            }
          } catch (e) {
            console.error('Failed to read pending-download migration notice:', e);
          }

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
            setAppSettings(settings);
            if (!settings.setup_complete) {
              wizardSettings = settings;
              showWizard = true;
            }
          } else {
            console.error('Persistent settings fetch failure; blocking main app entry', settingsError);
            // A rejected Tauri command hands back a bare string, not an Error,
            // so the detail has to come through `translateError` — it also
            // decodes a `coded()` envelope, which would otherwise reach this
            // blocking screen as raw JSON. An empty result means there was no
            // usable text at all, which is what the generic message is for.
            const detail = translateError(settingsError, '');
            initError = detail
              ? m.layout_settings_load_error_detail({ detail })
              : m.layout_settings_load_error();
          }

          releaseSplashWhenReady();

          // Silent background update check, deferred so it never competes
          // with first paint or store init. Production only: in a dev build
          // the running version is the dev version and the GitHub manifest
          // would spuriously report an "update". Gated on the user's
          // auto-update preference and on `isUpdateCheckDue` so the chosen
          // daily/weekly/monthly cadence is honored across launches, not
          // just "once per app start" (falls back to the pre-setting
          // always-on/daily behavior if settings failed to load). Any
          // failure (offline, unreachable manifest) is swallowed by the
          // store's silent mode, and a result surfaces non-blockingly via
          // <UpdateNotice />.
          const autoCheckEnabled = settings?.auto_check_updates ?? true;
          const checkFrequency = settings?.update_check_frequency ?? 'daily';
          if (!import.meta.env.DEV && autoCheckEnabled && isUpdateCheckDue(checkFrequency)) {
            updateCheckTimer = window.setTimeout(() => {
              if (mounted) void checkForUpdates({ silent: true });
            }, 4000);
          }
          // Before any of that: did the last install actually happen? A
          // hand-off to the installer ends this process, so if the installer
          // never ran there was nobody left to say so and the user just saw
          // Ember close. This is the first opportunity to tell them. Runs
          // regardless of the auto-check preference and of the cadence — it
          // reports on something they already asked for — and it resolves to
          // nothing in the normal case where the update landed. Running first
          // is only so the notice appears promptly. Two things in the store stop
          // the check above from overwriting the result, because ordering these
          // timers cannot: an in-flight guard, for the case where this call
          // overruns the 2.5 s gap and the check starts before there is anything
          // to capture, and `takeStagedSnapshot`, for every check after that.
          if (!import.meta.env.DEV) {
            handoffCheckTimer = window.setTimeout(() => {
              if (mounted) void checkUpdateHandoff();
            }, 1500);
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
      window.removeEventListener('unhandledrejection', onUnhandledRejection);
      if (revealTimer !== undefined) window.clearTimeout(revealTimer);
      if (hideTimer !== undefined) window.clearTimeout(hideTimer);
      if (updateCheckTimer !== undefined) window.clearTimeout(updateCheckTimer);
      if (handoffCheckTimer !== undefined) window.clearTimeout(handoffCheckTimer);
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
      if (unlistenDbCorrupt) unlistenDbCorrupt();
      if (unlistenPolicyReset) unlistenPolicyReset();
      if (unlistenFoldersAdded) unlistenFoldersAdded();
      if (unlistenFoldersFailed) unlistenFoldersFailed();
      if (unlistenDropPending) unlistenDropPending();
      if (unlistenDropRejected) unlistenDropRejected();
    };
  });
</script>

<a href="#main-content" class="skip-to-content">{m.layout_skip_to_content()}</a>
{#if splashVisible}
  <SplashScreen exiting={splashExiting} />
{/if}
{#if showWizard && wizardSettings}
  <SetupWizard
    settings={wizardSettings}
    oncomplete={onWizardComplete}
    closeDialogOpen={showCloseDialog}
  />
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
        <!--
          Subtle route transition: a short fade + small rise on each path
          change ties navigation together. Keyed on pathname (not full URL)
          so query-param changes (search tabs, filters) don't re-animate.
          The wrapper mirrors `.page-container`'s flex-column/overflow so the
          pages' `flex: 1` height chain is preserved. The global
          prefers-reduced-motion rule in app.css neutralizes this for users
          who opt out.
        -->
        {#key $page.url.pathname}
          <div class="route-view" in:fly={{ y: 8, duration: 160 }}>
            {@render children()}
          </div>
        {/key}
      {/if}
    </main>
    <StatusBar />
  </div>
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

<!-- Outside `.app-shell` so `CloseAppDialog`'s inert walk, which inerts the
     whole shell, can't reach it. `.app-shell` sets no transform or filter, so
     it is not a containing block for the toast's `position: fixed`. -->
<Toast />

<CloseAppDialog
  bind:open={showCloseDialog}
  onhide={handleCloseToTray}
  onexit={handleCloseExit}
  oncancel={handleCloseCancel}
/>

<ConfirmDialog
  bind:open={dropPrompt.open}
  title={dropPrompt.reason === 'broad'
    ? m.library_drop_broad_confirm_title()
    : dropPrompt.reason === 'many'
      ? m.library_drop_many_confirm_title()
      : m.library_drop_parent_confirm_title()}
  message={dropPromptMessage}
  danger={dropPrompt.reason === 'broad'}
  isolateMessage
  onconfirm={() => {
    const token = dropPrompt.token;
    void confirmDroppedFolders(token).catch((e) =>
      toastError(translateError(e, m.error_operation_failed())),
    );
  }}
  oncancel={() => { void dismissDroppedFolders(dropPrompt.token).catch(() => {}); }}
  ondismiss={() => { void dismissDroppedFolders(dropPrompt.token).catch(() => {}); }}
/>

{#if policyResetReason}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="policy-reset-backdrop"
    bind:this={policyResetOverlayEl}
    role="presentation"
  >
    <div
      class="policy-reset-dialog"
      bind:this={policyResetDialogEl}
      role="alertdialog"
      aria-modal="true"
      aria-busy={policyResetPending}
      aria-labelledby="policy-reset-title"
      aria-describedby="policy-reset-description"
      tabindex="-1"
      onkeydown={handlePolicyResetKeydown}
    >
      <h2 id="policy-reset-title">{m.layout_policy_reset_title()}</h2>
      <p id="policy-reset-description">{m.layout_policy_reset_body()}</p>
      <p class="policy-reset-reason">{policyResetReason}</p>
      {#if policyResetError}<p class="policy-reset-error">{policyResetError}</p>{/if}
      <button
        bind:this={policyResetAckBtn}
        aria-disabled={policyResetPending}
        onclick={acknowledgePolicyReset}
      >
        {policyResetPending
          ? m.layout_policy_reset_working()
          : m.layout_policy_reset_acknowledge()}
      </button>
    </div>
  </div>
{/if}

<style>
  .skip-to-content {
    position: absolute;
    top: -40px;
    left: 0;
    z-index: 10000;
    padding: 8px 16px;
    background: var(--accent);
    color: var(--on-accent);
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

  /*
   * Transition wrapper for the active route. Must replicate
   * `.page-container`'s layout so pages that rely on `flex: 1` to fill the
   * viewport (and their inner scroll areas) behave identically whether or
   * not this wrapper is present. `min-height: 0` lets inner overflow:auto
   * regions shrink correctly inside the flex column.
   */
  .route-view {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: hidden;
  }

  .policy-reset-backdrop {
    position: fixed;
    inset: 0;
    z-index: 20000;
    display: grid;
    place-items: center;
    padding: 24px;
    background: color-mix(in srgb, #000 72%, transparent);
  }

  .policy-reset-dialog {
    width: min(560px, 100%);
    padding: 24px;
    border: 1px solid var(--danger);
    border-radius: var(--radius-lg);
    background: var(--bg-secondary);
    box-shadow: var(--shadow-lg);
  }

  .policy-reset-dialog h2 {
    margin: 0 0 12px;
  }

  .policy-reset-reason,
  .policy-reset-error {
    overflow-wrap: anywhere;
    color: var(--danger);
  }

  .policy-reset-dialog button {
    margin-top: 12px;
  }

  .policy-reset-dialog button[aria-disabled='true'] {
    cursor: wait;
    opacity: 0.65;
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
