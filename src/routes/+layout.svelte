<script lang="ts">
  import '../app.css';
  import Sidebar from '$lib/components/Sidebar.svelte';
  import SplashScreen from '$lib/components/SplashScreen.svelte';
  import SetupWizard from '$lib/components/SetupWizard.svelte';
  import StatusBar from '$lib/components/StatusBar.svelte';
  import Toast from '$lib/components/Toast.svelte';

  import { initNetworkStore, cleanupNetworkStore, startStatsPoll } from '$lib/stores/network';
  import { initTransferStore, cleanupTransferStore, startTransferPoll } from '$lib/stores/transfers';
  import { initSearchStore, cleanupSearchStore } from '$lib/stores/search';
  import { initFriendsStore, cleanupFriendsStore } from '$lib/stores/friends';
  import { initTheme, cleanupTheme } from '$lib/stores/theme';
  import { getSettings } from '$lib/api/settings';
  import type { AppSettings } from '$lib/types';
  import { onMount } from 'svelte';

  let { children } = $props();
  let initialized = $state(false);
  let initError = $state('');
  let splashVisible = $state(true);
  let splashExiting = $state(false);
  let showWizard = $state(false);
  let wizardSettings: AppSettings | null = $state(null);

  async function onWizardComplete(_updated: AppSettings) {
    showWizard = false;
    wizardSettings = null;
  }

  // Register all event listeners immediately — don't wait for onMount/render.
  const storeInitPromise = Promise.all([
    initNetworkStore(),
    initTransferStore(),
    initSearchStore(),
    initFriendsStore(),
  ]);

  onMount(() => {
    initTheme();
    const splashStartedAt = performance.now();
    const minSplashMs = 1200;
    const splashExitMs = 260;

    let stopPoll: (() => void) | null = null;
    let stopTransferPoll: (() => void) | null = null;
    let mounted = true;
    let revealTimer: number | undefined;
    let hideTimer: number | undefined;

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

          try {
            const s = await getSettings();
            if (!s.setup_complete) {
              wizardSettings = s;
              showWizard = true;
            }
          } catch (e) {
            console.warn('Failed to fetch settings for setup wizard, retrying once...', e);
            try {
              await new Promise(r => setTimeout(r, 1000));
              const s = await getSettings();
              if (!s.setup_complete) {
                wizardSettings = s;
                showWizard = true;
              }
            } catch {
              console.error('Settings fetch retry failed, wizard skipped');
            }
          }

          releaseSplashWhenReady();
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
        initError = e instanceof Error ? e.message : 'Failed to initialize. Please restart the app.';
        initialized = true;
        releaseSplashWhenReady();
      });

    return () => {
      mounted = false;
      if (revealTimer !== undefined) window.clearTimeout(revealTimer);
      if (hideTimer !== undefined) window.clearTimeout(hideTimer);
      if (stopPoll) stopPoll();
      if (stopTransferPoll) stopTransferPoll();
      cleanupTheme();
      cleanupNetworkStore();
      cleanupTransferStore();
      cleanupSearchStore();
      cleanupFriendsStore();
    };
  });
</script>

<a href="#main-content" class="skip-to-content">Skip to content</a>
{#if splashVisible}
  <SplashScreen exiting={splashExiting} />
{/if}
{#if showWizard && wizardSettings}
  <SetupWizard settings={wizardSettings} oncomplete={onWizardComplete} />
{/if}
<div class="app-shell">
  <nav aria-label="Main navigation">
    <Sidebar />
  </nav>
  <div class="main-area">
    <main id="main-content" class="page-container">
      {#if !initialized}
        <div class="init-loading">
          <div class="spinner lg"></div>
          <p>Starting Ember...</p>
        </div>
      {:else if initError}
        <div class="init-error">
          <p>{initError}</p>
          <button onclick={() => location.reload()}>Retry</button>
        </div>
      {:else}
        {@render children()}
      {/if}
    </main>
    <StatusBar />
  </div>
  <Toast />
</div>

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

  nav {
    display: contents;
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
