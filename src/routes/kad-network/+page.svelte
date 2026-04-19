<script lang="ts">
  // Backwards-compatible redirect for the legacy `/kad-network` URL.
  // V2 promoted the KAD network view to the home route (`/`) when the
  // sidebar was reorganised, but bookmarks, external docs, and any
  // shared deep links from the main-branch era still target the old
  // path. Without this stub they'd hit the SPA fallback (`index.html`)
  // and land on the home page anyway, but the URL would stay wrong —
  // breaking back/forward navigation and any "copy link" actions.
  // `replaceState` keeps the bad URL out of history.
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  onMount(() => { goto('/', { replaceState: true }); });
</script>
