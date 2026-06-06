<script lang="ts">
  // Shared crisp close/dismiss glyph. Inherits color via `currentColor`,
  // so each call site keeps its own button styling and only swaps the
  // old Unicode "x" text glyph for a consistent vector icon.
  let { size = 14, strokeWidth = 2.2 }: { size?: number; strokeWidth?: number } = $props();
</script>

<svg
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width={strokeWidth}
  stroke-linecap="round"
  stroke-linejoin="round"
  width={size}
  height={size}
  aria-hidden="true"
>
  <line x1="6" y1="6" x2="18" y2="18" />
  <line x1="18" y1="6" x2="6" y2="18" />
</svg>
