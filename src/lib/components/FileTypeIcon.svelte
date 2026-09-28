<script lang="ts">
  import type { FileTypeKey } from '$lib/fileTypes';

  /** A tinted tile with a glyph for the file's Library type category. */
  let { kind, size = 38 }: { kind: FileTypeKey | ''; size?: number } = $props();

  const TONES: Record<FileTypeKey, string> = {
    Audio: 'var(--type-audio)',
    Video: 'var(--type-video)',
    Image: 'var(--type-image)',
    Archive: 'var(--type-archive)',
    Document: 'var(--type-document)',
    'CD/DVD': 'var(--type-disc)',
  };
  let tone = $derived(kind ? TONES[kind] : 'var(--type-document)');
</script>

<span class="file-type-icon" style:--tile={tone} style:--size="{size}px" aria-hidden="true">
  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
    {#if kind === 'Audio'}
      <path d="M8 14.5V4.5l8-1.5v10"/>
      <circle cx="6" cy="14.5" r="2"/>
      <circle cx="14" cy="13" r="2"/>
    {:else if kind === 'Video'}
      <rect x="2.5" y="4.5" width="15" height="11" rx="2"/>
      <path d="m8.5 7.8 4 2.2-4 2.2z"/>
    {:else if kind === 'Image'}
      <rect x="2.5" y="3.5" width="15" height="13" rx="2"/>
      <circle cx="7" cy="8" r="1.5"/>
      <path d="m17.5 13-4-4-8 7.5"/>
    {:else if kind === 'Archive'}
      <rect x="2.5" y="3.5" width="15" height="4" rx="1"/>
      <path d="M4 7.5v8a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1v-8"/>
      <path d="M8.5 11h3"/>
    {:else if kind === 'CD/DVD'}
      <circle cx="10" cy="10" r="7.5"/>
      <circle cx="10" cy="10" r="2"/>
    {:else}
      <path d="M11.5 2.5H6a1.5 1.5 0 0 0-1.5 1.5v12A1.5 1.5 0 0 0 6 17.5h8a1.5 1.5 0 0 0 1.5-1.5V6.5z"/>
      <path d="M11.5 2.5v4h4"/>
      {#if kind === 'Document'}
        <path d="M7.5 10.5h5M7.5 13.5h3.5"/>
      {/if}
    {/if}
  </svg>
</span>

<style>
  .file-type-icon {
    flex-shrink: 0;
    width: var(--size);
    height: var(--size);
    border-radius: var(--radius-md);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: color-mix(in srgb, var(--tile) 15%, transparent);
    color: var(--tile);
  }

  .file-type-icon svg {
    width: calc(var(--size) * 0.53);
    height: calc(var(--size) * 0.53);
  }
</style>
