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

  onMount(() => {
    initTheme();

    let stopPoll: (() => void) | null = null;
    let mounted = true;

    Promise.all([initNetworkStore(), initTransferStore(), initSearchStore()]).then(() => {
      if (mounted) {
        stopPoll = startStatsPoll();
      }
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
  <Sidebar />
  <div class="main-area">
    <div class="page-container">
      {@render children()}
    </div>
    <StatusBar />
  </div>
</div>

<style>
  .app-shell {
    display: flex;
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
</style>
