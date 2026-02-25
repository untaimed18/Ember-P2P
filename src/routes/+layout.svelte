<script lang="ts">
  import '../app.css';
  import Sidebar from '$lib/components/Sidebar.svelte';
  import StatusBar from '$lib/components/StatusBar.svelte';
  import { initNetworkStore, startStatsPoll } from '$lib/stores/network';
  import { initTransferStore } from '$lib/stores/transfers';
  import { initSearchStore } from '$lib/stores/search';
  import { onMount } from 'svelte';

  let { children } = $props();

  onMount(() => {
    initNetworkStore();
    initTransferStore();
    initSearchStore();

    const stopPoll = startStatsPoll();
    return () => stopPoll();
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
