<script lang="ts">
  // The project's Buy Me a Coffee page, in that service's own yellow so it
  // reads as what it is at a glance. The address is fixed in the backend
  // (`open_support_page`); this only asks for it to be opened.
  import * as m from '$lib/paraglide/messages';
  import { openSupportPage } from '$lib/api/settings';
  import { translateError } from '$lib/i18n';

  let { size = 'md' }: { size?: 'md' | 'sm' } = $props();

  let error = $state('');
  let opening = $state(false);

  async function open() {
    if (opening) return;
    error = '';
    opening = true;
    try {
      await openSupportPage();
    } catch (e) {
      error = translateError(e);
    } finally {
      opening = false;
    }
  }
</script>

<span class="coffee">
  <button
    type="button"
    class="coffee-btn"
    class:sm={size === 'sm'}
    title={m.support_button_title()}
    onclick={() => void open()}
  >
    <svg class="cup" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path class="steam" d="M8.5 2.8c-.9 1-.9 2.2 0 3.2" />
      <path class="steam steam-late" d="M12 2.8c-.9 1-.9 2.2 0 3.2" />
      <path d="M4 9.5h12v4.25A5.25 5.25 0 0 1 10.75 19h-1.5A5.25 5.25 0 0 1 4 13.75z" fill="currentColor" fill-opacity="0.14" />
      <path d="M16 11h1.25a2.75 2.75 0 0 1 0 5.5H15.4" />
      <path d="M3 21.5h14" />
    </svg>
    <span>{m.support_button()}</span>
  </button>
  {#if error}
    <span class="coffee-error" role="alert">{error}</span>
  {/if}
</span>

<style>
  .coffee {
    display: inline-flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 6px;
  }

  /* Buy Me a Coffee's yellow and ink, kept in both themes: it is their mark,
     and dark ink on that yellow stays legible on either background. */
  .coffee-btn {
    --coffee-yellow: #ffdd00;
    --coffee-yellow-hover: #ffe53d;
    --coffee-ink: #0d0c22;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 9px 18px 9px 14px;
    border: 1px solid color-mix(in srgb, var(--coffee-yellow) 70%, #000);
    border-radius: var(--radius-pill);
    background: var(--coffee-yellow);
    color: var(--coffee-ink);
    font-family: inherit;
    font-size: var(--font-size-md);
    font-weight: 700;
    letter-spacing: 0.1px;
    line-height: 1.2;
    white-space: nowrap;
    cursor: pointer;
    box-shadow:
      inset 0 1px 0 rgba(255, 255, 255, 0.55),
      0 1px 2px rgba(0, 0, 0, 0.12),
      0 2px 8px rgba(255, 196, 0, 0.18);
    transition:
      background-color var(--transition-fast, 120ms) ease,
      box-shadow var(--transition-fast, 120ms) ease,
      transform var(--transition-fast, 120ms) ease;
  }

  .coffee-btn:hover {
    background: var(--coffee-yellow-hover);
    color: var(--coffee-ink);
    transform: translateY(-1px);
    box-shadow:
      inset 0 1px 0 rgba(255, 255, 255, 0.6),
      0 2px 4px rgba(0, 0, 0, 0.14),
      0 6px 16px rgba(255, 196, 0, 0.32);
  }

  .coffee-btn:active {
    transform: translateY(0);
    box-shadow:
      inset 0 1px 2px rgba(0, 0, 0, 0.12),
      0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .coffee-btn:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .coffee-btn.sm {
    gap: 6px;
    padding: 6px 13px 6px 10px;
    font-size: var(--font-size-sm);
  }

  .cup {
    width: 18px;
    height: 18px;
    flex-shrink: 0;
    overflow: visible;
  }

  .coffee-btn.sm .cup {
    width: 16px;
    height: 16px;
  }

  /* Steam rises while the pointer is on the button. */
  .steam {
    opacity: 0.55;
    transform-box: fill-box;
  }

  .coffee-btn:hover .steam {
    animation: steam 1.4s ease-in-out infinite;
  }

  .coffee-btn:hover .steam-late {
    animation-delay: 0.35s;
  }

  @keyframes steam {
    0% { opacity: 0; transform: translateY(2px); }
    40% { opacity: 0.9; }
    100% { opacity: 0; transform: translateY(-2.5px); }
  }

  @media (prefers-reduced-motion: reduce) {
    .coffee-btn,
    .coffee-btn:hover,
    .coffee-btn:active {
      transform: none;
    }
    .coffee-btn:hover .steam {
      animation: none;
    }
  }

  .coffee-error {
    color: var(--danger);
    font-size: var(--font-size-sm);
  }
</style>
