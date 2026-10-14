<script lang="ts">
  // Shared Settings gear. Inherits color via `currentColor`. `weight` is the
  // line width in pixels as drawn, so the gear keeps the weight of the icons
  // beside it whatever size it is drawn at.
  let { size = 20, weight = 1.5 }: { size?: number; weight?: number } = $props();
</script>

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
  <path d="M8.52 4.08L8.85 1.83L11.15 1.83L11.48 4.08A6.1 6.1 0 0 1 13.14 4.77L14.96 3.41L16.59 5.04L15.23 6.86A6.1 6.1 0 0 1 15.92 8.52L18.17 8.85L18.17 11.15L15.92 11.48A6.1 6.1 0 0 1 15.23 13.14L16.59 14.96L14.96 16.59L13.14 15.23A6.1 6.1 0 0 1 11.48 15.92L11.15 18.17L8.85 18.17L8.52 15.92A6.1 6.1 0 0 1 6.86 15.23L5.04 16.59L3.41 14.96L4.77 13.14A6.1 6.1 0 0 1 4.08 11.48L1.83 11.15L1.83 8.85L4.08 8.52A6.1 6.1 0 0 1 4.77 6.86L3.41 5.04L5.04 3.41L6.86 4.77A6.1 6.1 0 0 1 8.52 4.08Z" />
  <circle cx="10" cy="10" r="2.5" />
</svg>
