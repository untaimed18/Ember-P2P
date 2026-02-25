<script lang="ts">
  let { value = 0, max = 100, color = 'var(--accent)' }: { value?: number; max?: number; color?: string } = $props();

  let percentage = $derived(Math.min(100, (value / max) * 100));
</script>

<div class="progress-bar">
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
