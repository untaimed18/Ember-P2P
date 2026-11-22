<script lang="ts">
  // The icon of a sidebar page (`navItems` ids), for anywhere that names one
  // of those parts of Ember. Inherits color via `currentColor`; `weight` is
  // the line width in pixels as drawn, as for `IconGear`.
  import IconGear from '$lib/components/IconGear.svelte';

  let { id, size = 20, weight = 1.5 }: { id: string; size?: number; weight?: number } = $props();
</script>

{#if id === 'settings'}
  <IconGear {size} {weight} />
{:else}
  <svg
    viewBox="0 0 20 20"
    fill="none"
    stroke="currentColor"
    stroke-width={(weight * 20) / size}
    stroke-linecap="round"
    stroke-linejoin="round"
    width={size}
    height={size}
    aria-hidden="true"
  >
    {#if id === 'kad'}
      <circle cx="10" cy="4" r="2.5"/>
      <circle cx="4" cy="14" r="2.5"/>
      <circle cx="16" cy="14" r="2.5"/>
      <line x1="10" y1="6.5" x2="5.5" y2="11.5"/>
      <line x1="10" y1="6.5" x2="14.5" y2="11.5"/>
      <line x1="6.5" y1="14" x2="13.5" y2="14"/>
    {:else if id === 'servers'}
      <rect x="3" y="3" width="14" height="5" rx="1"/>
      <rect x="3" y="12" width="14" height="5" rx="1"/>
      <circle cx="6" cy="5.5" r="0.6" fill="currentColor" stroke="none"/>
      <circle cx="6" cy="14.5" r="0.6" fill="currentColor" stroke="none"/>
      <line x1="9" y1="5.5" x2="14" y2="5.5"/>
      <line x1="9" y1="14.5" x2="14" y2="14.5"/>
    {:else if id === 'search'}
      <circle cx="8.5" cy="8.5" r="5.5"/>
      <line x1="12.5" y1="12.5" x2="17" y2="17"/>
    {:else if id === 'transfers'}
      <line x1="7" y1="3" x2="7" y2="17"/>
      <polyline points="3,7 7,3 11,7"/>
      <line x1="13" y1="3" x2="13" y2="17"/>
      <polyline points="9,13 13,17 17,13"/>
    {:else if id === 'library'}
      <path d="M3 4h5l2 2h7v10H3V4z"/>
      <line x1="3" y1="9" x2="17" y2="9"/>
    {:else if id === 'friends'}
      <circle cx="7" cy="6" r="3"/>
      <circle cx="14" cy="7" r="2.5"/>
      <path d="M1 17c0-3.3 2.7-6 6-6s6 2.7 6 6"/>
      <path d="M13 11.5c2.5 0 4.5 2 4.5 4.5"/>
    {:else if id === 'channels'}
      <path d="M4 5h9a2 2 0 012 2v4a2 2 0 01-2 2H9l-3 2.5V13H4a2 2 0 01-2-2V7a2 2 0 012-2z"/>
      <path d="M16 7.5h.5A1.5 1.5 0 0118 9v3.5a1.5 1.5 0 01-1.5 1.5H16v1.5L14.5 14"/>
    {:else if id === 'feeds'}
      <circle cx="5" cy="15" r="1.5" fill="currentColor" stroke="none"/>
      <path d="M4 9a7 7 0 017 7"/>
      <path d="M4 4a12 12 0 0112 12"/>
    {:else if id === 'ember'}
      <path d="M10 2.5C11.5 5.5 14.5 6.5 14.5 11a4.5 4.5 0 0 1-9 0c0-1.6.7-2.8 1.6-3.7C8.3 6.2 8.8 5 8 3.5c1 .4 1.6 1 2 2z"/>
      <path d="M10 16.3a2 2 0 0 0 2-2c0-1.2-1-1.9-2-3.1-1 1.2-2 1.9-2 3.1a2 2 0 0 0 2 2z"/>
    {:else if id === 'statistics'}
      <line x1="4" y1="17" x2="4" y2="10"/>
      <line x1="8" y1="17" x2="8" y2="6"/>
      <line x1="12" y1="17" x2="12" y2="12"/>
      <line x1="16" y1="17" x2="16" y2="3"/>
    {:else if id === 'security'}
      <path d="M10 2L3 6v4c0 4.4 3 8.5 7 10 4-1.5 7-5.6 7-10V6l-7-4z"/>
      <polyline points="7,10 9.5,12.5 13.5,7.5"/>
    {/if}
  </svg>
{/if}
