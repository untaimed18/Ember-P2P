<script lang="ts">
  // `label` renders a visible string next to the switch AND is used as
  // the accessible name. `ariaLabel` is for callers whose visible text
  // differs from the name the switch should have.
  // `ariaLabelledby` is for callers that render their own visible label
  // in a separate element (e.g. the settings toggle rows, where the title
  // sits in a `.toggle-title`); pair it with `id` so that title can be a
  // `<label for>` and toggle the switch when clicked.
  // `ariaDescribedby` points at a hint describing the setting.
  let {
    checked = $bindable(false),
    disabled = false,
    label = '',
    ariaLabel = '',
    ariaLabelledby = '',
    ariaDescribedby = '',
    id,
    onchange,
  }: {
    checked: boolean;
    disabled?: boolean;
    label?: string;
    ariaLabel?: string;
    ariaLabelledby?: string;
    ariaDescribedby?: string;
    id?: string;
    onchange?: (checked: boolean) => void;
  } = $props();

  let computedAriaLabel = $derived(ariaLabel || label || undefined);
</script>

<label class="toggle" class:disabled>
  <button
    type="button"
    role="switch"
    {id}
    aria-checked={checked}
    aria-label={ariaLabelledby ? undefined : computedAriaLabel}
    aria-labelledby={ariaLabelledby || undefined}
    aria-describedby={ariaDescribedby || undefined}
    {disabled}
    class="track"
    class:on={checked}
    onclick={() => {
      if (disabled) return;
      checked = !checked;
      onchange?.(checked);
    }}
  >
    <span class="knob"></span>
  </button>
  {#if label}
    <span class="toggle-text">{label}</span>
  {/if}
</label>

<style>
  .toggle {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    cursor: pointer;
    user-select: none;
  }

  .toggle.disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .track {
    position: relative;
    width: 40px;
    height: 22px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--text-muted) 28%, var(--bg-tertiary));
    border: none;
    padding: 0;
    cursor: inherit;
    transition: background var(--transition-normal) ease;
    flex-shrink: 0;
  }

  .track:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .track.on {
    background: var(--accent);
  }

  .knob {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--toggle-knob);
    box-shadow: var(--shadow-sm);
    transition: transform var(--transition-normal) ease;
  }

  .track.on .knob {
    transform: translateX(18px);
  }

  .toggle-text {
    font-size: var(--font-size-md);
    color: var(--text-primary);
    line-height: 1.4;
  }
</style>
