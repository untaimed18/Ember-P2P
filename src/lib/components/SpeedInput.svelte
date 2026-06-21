<script lang="ts">
  import * as m from '$lib/paraglide/messages';

  type Unit = 'B/s' | 'KB/s' | 'MB/s';

  const multipliers: Record<Unit, number> = {
    'B/s': 1,
    'KB/s': 1024,
    'MB/s': 1024 * 1024,
  };

  let {
    value = $bindable(0),
    label = '',
  }: {
    value: number;
    label?: string;
  } = $props();

  let unit: Unit = $state('KB/s');
  let displayValue: string = $state('');
  let focused = $state(false);
  let isUnlimited = $derived(value === 0);
  // Only collapse to the "Unlimited" display when the field isn't being
  // edited. Otherwise clearing the input to retype a value (which momentarily
  // makes `value === 0`) would yank the input out from under the user and
  // replace it with the unlimited placeholder mid-keystroke.
  let showUnlimited = $derived(value === 0 && !focused);
  let internalUpdate = false;
  let lastSyncedValue = -1;

  function syncFromBytes(bytes: number) {
    if (bytes === 0) {
      displayValue = '';
      return;
    }
    if (bytes >= 1024 * 1024 && bytes % (1024 * 1024) === 0) {
      unit = 'MB/s';
      displayValue = String(bytes / (1024 * 1024));
    } else if (bytes >= 1024) {
      unit = 'KB/s';
      displayValue = String(Math.round((bytes / 1024) * 100) / 100);
    } else {
      unit = 'B/s';
      displayValue = String(bytes);
    }
  }

  $effect(() => {
    if (internalUpdate) {
      internalUpdate = false;
      return;
    }
    if (value !== lastSyncedValue) {
      lastSyncedValue = value;
      syncFromBytes(value);
    }
  });

  function handleInput(e: Event) {
    const target = e.target as HTMLInputElement;
    const raw = target.value;
    const num = parseFloat(raw);
    internalUpdate = true;
    if (isNaN(num) || num <= 0) {
      displayValue = raw;
      value = 0;
    } else {
      displayValue = raw;
      value = Math.round(num * multipliers[unit]);
    }
    lastSyncedValue = value;
  }

  function handleUnitChange(e: Event) {
    const target = e.target as HTMLSelectElement;
    const newUnit = target.value as Unit;
    const currentBytes = value;
    unit = newUnit;
    if (currentBytes > 0) {
      displayValue = String(Math.round((currentBytes / multipliers[newUnit]) * 100) / 100);
    }
  }

  function toggleUnlimited() {
    if (isUnlimited) {
      value = 512 * 1024;
    } else {
      value = 0;
    }
    lastSyncedValue = value;
    // Refresh the visible field/unit to match the new value. Without this the
    // `$effect` below skips `syncFromBytes` (because we just set
    // `lastSyncedValue === value`), leaving the numeric input showing the
    // stale/empty `displayValue` while the bound value is actually 512 KB/s.
    syncFromBytes(value);
  }
</script>

{#if label}
  <span class="speed-label">{label}</span>
{/if}
<div class="speed-input" class:unlimited={showUnlimited}>
  {#if showUnlimited}
    <div
      class="unlimited-display"
      role="button"
      tabindex="0"
      aria-label={m.speed_input_unlimited_aria()}
      onclick={toggleUnlimited}
      onkeydown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          toggleUnlimited();
        }
      }}
    >
      <span class="unlimited-text">{m.speed_input_unlimited()}</span>
      <span class="unlimited-hint">{m.speed_input_click_to_set_limit()}</span>
    </div>
  {:else}
    <input
      type="number"
      min="0"
      step="any"
      value={displayValue}
      oninput={handleInput}
      onfocus={() => (focused = true)}
      onblur={() => (focused = false)}
      class="speed-number"
      placeholder="0"
    />
    <select value={unit} onchange={handleUnitChange} class="speed-unit" aria-label={m.speed_input_unit_label()}>
      <option value="B/s">B/s</option>
      <option value="KB/s">KB/s</option>
      <option value="MB/s">MB/s</option>
    </select>
    <button type="button" class="unlimited-btn" onclick={toggleUnlimited} title={m.speed_input_set_unlimited()} aria-label={m.speed_input_set_unlimited()}>
      &infin;
    </button>
  {/if}
</div>

<style>
  .speed-label {
    display: block;
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 6px;
  }

  .speed-input {
    display: flex;
    align-items: stretch;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    overflow: hidden;
    background: var(--bg-input);
    transition: border-color 0.15s;
  }

  .speed-input:focus-within {
    border-color: var(--accent);
  }

  .speed-number {
    flex: 1;
    border: none;
    background: transparent;
    color: var(--text-primary);
    padding: 7px 10px;
    font-size: 13px;
    outline: none;
    min-width: 0;
    font-family: inherit;
  }

  .speed-number::-webkit-inner-spin-button,
  .speed-number::-webkit-outer-spin-button {
    -webkit-appearance: none;
    margin: 0;
  }

  .speed-unit {
    border: none;
    border-left: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-secondary);
    padding: 0 10px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    outline: none;
    font-family: inherit;
    -webkit-appearance: none;
    appearance: none;
  }

  .unlimited-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    border: none;
    border-left: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-muted);
    font-size: 16px;
    cursor: pointer;
    padding: 0;
    border-radius: 0;
    transition: color 0.15s, background 0.15s;
  }

  .unlimited-btn:hover {
    background: var(--bg-hover);
    color: var(--accent);
  }

  .unlimited-display {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 7px 12px;
    cursor: pointer;
  }

  .unlimited-text {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-muted);
  }

  .unlimited-hint {
    font-size: 11px;
    color: var(--text-muted);
    opacity: 0.6;
  }

  .speed-input.unlimited {
    border-style: dashed;
  }
</style>
