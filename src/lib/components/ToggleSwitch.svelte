<script lang="ts">
  // `label` renders a visible string next to the switch AND is used as
  // the accessible name. `ariaLabel` is for callers that already render
  // their own visible label (e.g. the settings toggle rows where the
  // title sits in a separate `.toggle-title` element); they pass an
  // accessible name without duplicating the visible text.
  // `ariaLabelledby` is for callers that have an existing element id
  // they want to use as the accessible name.
  let {
    checked = $bindable(false),
    disabled = false,
    label = '',
    ariaLabel = '',
    ariaLabelledby = '',
  }: {
    checked: boolean;
    disabled?: boolean;
    label?: string;
    ariaLabel?: string;
    ariaLabelledby?: string;
  } = $props();

  let computedAriaLabel = $derived(ariaLabel || label || undefined);
</script>

<label class="toggle" class:disabled>
  <button
    type="button"
    role="switch"
    aria-checked={checked}
    aria-label={ariaLabelledby ? undefined : computedAriaLabel}
    aria-labelledby={ariaLabelledby || undefined}
    {disabled}
    class="track"
    class:on={checked}
    onclick={() => { if (!disabled) checked = !checked; }}
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
    border-radius: 11px;
    background: var(--border-light);
    border: none;
    padding: 0;
    cursor: inherit;
    transition: background 0.2s ease;
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
    background: #fff;
    box-shadow: 0 1px 3px rgba(0,0,0,0.2);
    transition: transform 0.2s ease;
  }

  .track.on .knob {
    transform: translateX(18px);
  }

  .toggle-text {
    font-size: 13px;
    color: var(--text-primary);
    line-height: 1.4;
  }
</style>
