<script lang="ts">
  // An update's release notes, laid out rather than shown as raw Markdown.
  // Everything renders as text (see `releaseNotes.ts`).
  import { parseReleaseNotes, type NotesInline } from '$lib/releaseNotes';

  let { notes }: { notes: string } = $props();

  const blocks = $derived(parseReleaseNotes(notes));
</script>

{#snippet inline(nodes: NotesInline[])}
  {#each nodes as node, i (i)}
    {#if node.kind === 'text'}{node.text}{:else if node.kind === 'code'}<code>{node.text}</code>{:else if node.kind === 'strong'}<strong>{@render inline(node.children)}</strong>{:else}<em>{@render inline(node.children)}</em>{/if}
  {/each}
{/snippet}

<div class="release-notes">
  {#each blocks as block, i (i)}
    {#if block.kind === 'heading' && block.level === 2}
      <h4>{@render inline(block.inline)}</h4>
    {:else if block.kind === 'heading'}
      <h5>{@render inline(block.inline)}</h5>
    {:else if block.kind === 'list'}
      <ul>
        {#each block.items as item, j (j)}
          <li>{@render inline(item)}</li>
        {/each}
      </ul>
    {:else}
      <p>{@render inline(block.inline)}</p>
    {/if}
  {/each}
</div>

<style>
  .release-notes {
    font-size: var(--font-size-sm);
    line-height: 1.5;
    color: var(--text-secondary);
    overflow-wrap: anywhere;
  }
  .release-notes h4 {
    margin: 10px 0 4px;
    font-size: var(--font-size-md);
    font-weight: 700;
    color: var(--text-primary);
  }
  .release-notes h5 {
    margin: 8px 0 2px;
    font-size: var(--font-size-sm);
    font-weight: 700;
    color: var(--text-primary);
  }
  .release-notes > :first-child {
    margin-top: 0;
  }
  .release-notes ul {
    margin: 2px 0 6px;
    padding-left: 18px;
  }
  .release-notes li {
    margin: 2px 0;
  }
  .release-notes p {
    margin: 4px 0;
  }
  .release-notes strong {
    color: var(--text-primary);
    font-weight: 600;
  }
  .release-notes code {
    font-family: var(--font-mono);
    font-size: 0.92em;
    padding: 0 3px;
    border-radius: var(--radius-sm);
    background: var(--bg-tertiary);
  }
</style>
