<script lang="ts">
  import * as m from '$lib/paraglide/messages';
  let { exiting = false } = $props<{ exiting?: boolean }>();
</script>

<div class={`splash ${exiting ? 'exit' : ''}`} role="status" aria-live="polite" aria-label={m.splash_aria_starting()}>
  <div class="content">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">
        <img src="/icon.png" alt="" width="44" height="44" draggable="false" />
      </div>
      <div class="wordmark">
        <h1>EMBER</h1>
        <p class="subtitle">{m.splash_subtitle()}</p>
      </div>
    </div>

    <p class="status">{m.splash_status_init()}</p>

    <div class="progress-track" aria-hidden="true">
      <div class="progress-fill"></div>
    </div>
  </div>
</div>

<style>
  .splash {
    position: fixed;
    inset: 0;
    z-index: 100000;
    display: grid;
    place-items: center;
    background: var(--bg-primary);
    color: var(--text-primary);
    opacity: 1;
    transition: opacity 260ms ease;
    pointer-events: all;
  }

  .splash.exit {
    opacity: 0;
    pointer-events: none;
  }

  .content {
    width: min(520px, 92vw);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-secondary);
    box-shadow: var(--shadow-md);
    padding: 26px 24px 20px;
    animation: card-in 450ms ease-out;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 14px;
  }

  .brand-mark {
    width: 44px;
    height: 44px;
    border-radius: var(--radius-md);
    overflow: hidden;
    flex-shrink: 0;
    box-shadow:
      0 0 0 1px var(--border),
      var(--shadow-sm);
  }

  .brand-mark img {
    width: 100%;
    height: 100%;
    display: block;
    animation: pulse 1.4s ease-in-out infinite;
  }

  .wordmark h1 {
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 1.5px;
    color: var(--accent);
    line-height: 1;
    margin-bottom: 4px;
  }

  .subtitle {
    font-size: 10px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    line-height: 1;
  }

  .status {
    color: var(--text-secondary);
    margin-bottom: 12px;
  }

  .progress-track {
    width: 100%;
    height: 6px;
    border-radius: var(--radius-pill);
    background: var(--bg-tertiary);
    overflow: hidden;
  }

  .progress-fill {
    height: 100%;
    width: 40%;
    border-radius: inherit;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    animation: sweep 1.15s ease-in-out infinite;
  }

  @keyframes sweep {
    0% {
      transform: translateX(-120%);
    }
    100% {
      transform: translateX(260%);
    }
  }

  @keyframes pulse {
    0%, 100% {
      opacity: 0.82;
    }
    50% {
      opacity: 1;
    }
  }

  @keyframes card-in {
    from {
      transform: translateY(8px) scale(0.99);
      opacity: 0;
    }
    to {
      transform: translateY(0) scale(1);
      opacity: 1;
    }
  }

  @media (max-width: 560px) {
    .content {
      padding: 22px 18px 16px;
    }

    .brand {
      gap: 10px;
    }

    .wordmark h1 {
      font-size: 19px;
      letter-spacing: 2px;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .content,
    .brand-mark img,
    .progress-fill {
      animation: none !important;
    }
  }
</style>
