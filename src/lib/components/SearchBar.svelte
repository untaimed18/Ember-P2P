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
  <span class="search-icon">⌕</span>
  <input
    type="text"
    bind:value
    {placeholder}
    onkeydown={handleKeydown}
  />
  {#if value}
    <button class="clear-btn" onclick={() => (value = '')}>✕</button>
  {/if}
</div>

<style>
  .search-bar {
    display: flex;
    align-items: center;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 0 12px;
    gap: 8px;
    transition: border-color 0.15s;
  }

  .search-bar:focus-within {
    border-color: var(--accent);
  }

  .search-icon {
    color: var(--text-muted);
    font-size: 16px;
  }

  input {
    flex: 1;
    border: none;
    background: none;
    padding: 8px 0;
    font-size: 14px;
  }

  input:focus {
    border: none;
  }

  .clear-btn {
    background: none;
    color: var(--text-muted);
    padding: 4px;
    font-size: 12px;
    line-height: 1;
  }

  .clear-btn:hover {
    color: var(--text-primary);
    background: none;
  }
</style>
