<script lang="ts">
  // The app's entry route sends the user to Ember Network.
  //
  // `/` used to *be* the KAD contacts table, which meant a product called
  // Ember opened on a peer table for a different network — the second entry in
  // its own sidebar — and the setup wizard never mentioned Ember at all. KAD
  // now lives at `/kad` alongside eD2K Servers, and this stub keeps every
  // bookmark, deep link, and window-restore that targets `/` working.
  //
  // Same shape as the `/kad-network` stub: `replaceState` so the entry route
  // doesn't sit in history as a step the Back button has to walk through, and
  // `/` is listed as an alias of Ember in `navItems` so the sidebar highlights
  // the destination instead of flickering through "nothing active".
  //
  // Nothing renders here: onMount fires before the layout's splash screen
  // lifts (~400ms floor), so the redirect is invisible at launch.
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';

  onMount(() => {
    void goto('/ember', { replaceState: true }).catch(() => {});
  });
</script>
