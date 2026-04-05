<script lang="ts">
  let {
    value = $bindable(''),
    placeholder = 'Search...',
    onsubmit,
  }: {
    value?: string;
    placeholder?: string;
    onsubmit?: (query: string) => void;
  } = $props();

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' && onsubmit) {
      onsubmit(value);
    }
  }
</script>

<div class="search-bar">
  <span class="search-icon" aria-hidden="true">
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
      <circle cx="8.5" cy="8.5" r="5.5"/><line x1="12.5" y1="12.5" x2="17" y2="17"/>
    </svg>
  </span>
  <input
    type="text"
    bind:value
    {placeholder}
    onkeydown={handleKeydown}
    aria-label="Search files"
  />
  {#if value}
    <button class="clear-btn" onclick={() => (value = '')} aria-label="Clear search">✕</button>
  {/if}
</div>

<style>
  .search-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    min-height: 42px;
    padding: 0 12px;
    border: 1px solid color-mix(in srgb, var(--border) 84%, transparent);
    border-radius: 999px;
    background: linear-gradient(
      to bottom,
      color-mix(in srgb, var(--bg-input) 95%, #fff 5%),
      var(--bg-input)
    );
    box-shadow: var(--shadow-sm);
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }

  .search-bar:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent-dim) 45%, transparent), var(--shadow-md);
  }

  .search-icon {
    width: 22px;
    height: 22px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: color-mix(in srgb, var(--accent-dim) 35%, transparent);
    color: var(--text-accent);
    font-size: 13px;
    font-weight: 700;
    flex-shrink: 0;
  }

  input {
    flex: 1;
    border: none;
    background: none;
    padding: 10px 0;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-primary);
  }

  input:focus {
    border: none;
  }

  input::placeholder {
    color: color-mix(in srgb, var(--text-muted) 85%, transparent);
    font-weight: 400;
  }

  .clear-btn {
    width: 24px;
    height: 24px;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--text-muted);
    font-size: 12px;
    font-weight: 700;
    line-height: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .clear-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }
</style>
