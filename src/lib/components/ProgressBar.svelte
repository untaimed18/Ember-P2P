<script lang="ts">
  let { value = 0, max = 100, color = 'var(--accent)' }: { value?: number; max?: number; color?: string } = $props();

  let percentage = $derived(Math.min(100, max > 0 ? (value / max) * 100 : 0));
</script>

<div
  class="progress-bar"
  role="progressbar"
  aria-valuenow={Math.round(percentage)}
  aria-valuemin={0}
  aria-valuemax={100}
>
  <div
    class="progress-fill"
    style="width: {percentage}%; background: {color};"
  ></div>
  <span class="progress-text">{percentage.toFixed(1)}%</span>
</div>

<style>
  .progress-bar {
    position: relative;
    height: 18px;
    background: var(--bg-input);
    border-radius: 9px;
    overflow: hidden;
    min-width: 100px;
  }

  .progress-fill {
    height: 100%;
    border-radius: 9px;
    transition: width 0.3s ease;
  }

  .progress-text {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-primary);
  }
</style>
