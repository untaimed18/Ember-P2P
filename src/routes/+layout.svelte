<script lang="ts">
  import '../app.css';
  import Sidebar from '$lib/components/Sidebar.svelte';
  import StatusBar from '$lib/components/StatusBar.svelte';
  import { initNetworkStore, cleanupNetworkStore, startStatsPoll } from '$lib/stores/network';
  import { initTransferStore, cleanupTransferStore } from '$lib/stores/transfers';
  import { initSearchStore, cleanupSearchStore } from '$lib/stores/search';
  import { initTheme } from '$lib/stores/theme';
  import { onMount } from 'svelte';

  let { children } = $props();
  let initialized = $state(false);
  let initError = $state('');

  onMount(() => {
    initTheme();

    let stopPoll: (() => void) | null = null;
    let mounted = true;

    Promise.all([initNetworkStore(), initTransferStore(), initSearchStore()])
      .then(() => {
        if (mounted) {
          stopPoll = startStatsPoll();
          initialized = true;
        }
      })
      .catch((e) => {
        initError = e instanceof Error ? e.message : 'Failed to initialize. Please restart the app.';
        initialized = true;
      });

    return () => {
      mounted = false;
      if (stopPoll) stopPoll();
      cleanupNetworkStore();
      cleanupTransferStore();
      cleanupSearchStore();
    };
  });
</script>

<div class="app-shell">
  <nav aria-label="Main navigation">
    <Sidebar />
  </nav>
  <div class="main-area">
    <main class="page-container">
      {#if !initialized}
        <div class="init-loading">
          <div class="spinner lg"></div>
          <p>Starting Nexus...</p>
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
</div>

<style>
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
