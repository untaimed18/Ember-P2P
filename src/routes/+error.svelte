<script lang="ts">
  import { page } from '$app/stores';
  import * as m from '$lib/paraglide/messages';
</script>

<div class="empty-state route-error" role="alert">
  {#if $page.status === 404}
    <p class="empty-title">{m.layout_not_found_title()}</p>
    <p class="empty-sub">{m.layout_not_found_body()}</p>
  {:else}
    <p class="empty-title">{m.layout_render_error_title()}</p>
    <p class="empty-sub">{m.layout_render_error_body()}</p>
  {/if}
  <button class="empty-action" onclick={() => history.back()}>{m.layout_go_back()}</button>
</div>

<style>
  .route-error {
    flex: 1;
  }
</style>
