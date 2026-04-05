<script lang="ts">
  let { exiting = false } = $props<{ exiting?: boolean }>();
</script>

<div class={`splash ${exiting ? 'exit' : ''}`} role="status" aria-live="polite" aria-label="Ember is starting">
  <div class="content">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="10" cy="4" r="2.5"></circle>
          <circle cx="4" cy="14" r="2.5"></circle>
          <circle cx="16" cy="14" r="2.5"></circle>
          <line x1="10" y1="6.5" x2="5.5" y2="11.5"></line>
          <line x1="10" y1="6.5" x2="14.5" y2="11.5"></line>
          <line x1="6.5" y1="14" x2="13.5" y2="14"></line>
        </svg>
      </div>
      <div class="wordmark">
        <h1>EMBER</h1>
        <p class="subtitle">eMule KAD Network</p>
      </div>
    </div>

    <p class="status">Initializing network services...</p>

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
    border-radius: 12px;
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
    border-radius: 10px;
    display: grid;
    place-items: center;
    border: 1px solid var(--border);
    color: var(--accent);
    background: var(--bg-tertiary);
  }

  .brand-mark svg {
    width: 26px;
    height: 26px;
    animation: pulse 1.4s ease-in-out infinite;
  }

  .wordmark h1 {
    font-size: 22px;
    font-weight: 800;
    letter-spacing: 3px;
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
    border-radius: 999px;
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
      opacity: 0.75;
      transform: scale(1);
    }
    50% {
      opacity: 1;
      transform: scale(1.04);
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
    .brand-mark svg,
    .progress-fill {
      animation: none !important;
    }
  }
</style>
