<script lang="ts">
  let { value = 0, max = 100, color = '', status = '' }: { value?: number; max?: number; color?: string; status?: string } = $props();

  const STATUS_COLORS: Record<string, string> = {
    active: 'var(--accent)',
    completed: 'var(--success)',
    paused: 'var(--warning)',
    stopped: 'var(--text-muted)',
    failed: 'var(--danger)',
    queued: 'var(--text-muted)',
    searching: 'var(--text-muted)',
    verifying: 'var(--accent)',
    completing: 'var(--success)',
    hashing: 'var(--accent)',
  };

  let resolvedColor = $derived(color || STATUS_COLORS[status] || 'var(--accent)');
  let raw = $derived(max > 0 ? (value / max) * 100 : 0);
  let percentage = $derived(Math.min(100, Math.max(0, Number.isFinite(raw) ? raw : 0)));
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
    style="width: {percentage}%; background: {resolvedColor};"
  ></div>
  <span class="progress-text progress-text-track">{percentage.toFixed(1)}%</span>
  <span
    class="progress-text progress-text-fill"
    style="clip-path: inset(0 calc(100% - {percentage}%) 0 0);"
  >{percentage.toFixed(1)}%</span>
</div>

<style>
  .progress-bar {
    position: relative;
    height: 16px;
    background: var(--bg-input);
    border: 1px solid color-mix(in srgb, var(--border) 60%, transparent);
    border-radius: 2px;
    overflow: hidden;
    min-width: 100px;
  }

  .progress-fill {
    position: absolute;
    top: 0;
    left: 0;
    bottom: 0;
    border-radius: 1px;
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
    pointer-events: none;
  }

  .progress-text-track {
    color: var(--text-primary);
    z-index: 1;
  }

  .progress-text-fill {
    color: #fff;
    z-index: 2;
    transition: clip-path 0.3s ease;
  }
</style>
