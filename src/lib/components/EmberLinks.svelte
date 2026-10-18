<script lang="ts">
  // The project's own pages, shared by the About dialog and Settings → About
  // so the two always offer the same places in the same order.
  import * as m from '$lib/paraglide/messages';
  import { openEmberLink, type EmberLink } from '$lib/api/settings';
  import { translateError } from '$lib/i18n';

  let failed = $state<{ target: EmberLink; message: string } | null>(null);

  const links: { target: EmberLink; title: () => string; desc: () => string }[] = [
    { target: 'website', title: () => m.about_link_website_title(), desc: () => m.about_link_website_desc() },
    { target: 'github', title: () => m.about_link_github_title(), desc: () => m.about_link_github_desc() },
    { target: 'reddit', title: () => m.about_link_reddit_title(), desc: () => m.about_link_reddit_desc() },
  ];

  async function open(target: EmberLink) {
    failed = null;
    try {
      await openEmberLink(target);
    } catch (e) {
      failed = { target, message: translateError(e) };
    }
  }
</script>

<ul class="ember-links">
  {#each links as link (link.target)}
    <li>
      <button type="button" class="ember-link {link.target}" onclick={() => void open(link.target)}>
        <span class="ember-link-icon" aria-hidden="true">
          {#if link.target === 'website'}
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="8" cy="8" r="6" />
              <path d="M2.2 6.4h11.6M2.2 9.6h11.6" />
              <path d="M8 2c-1.8 2-1.8 10 0 12 1.8-2 1.8-10 0-12z" />
            </svg>
          {:else if link.target === 'github'}
            <svg viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
            </svg>
          {:else}
            <!-- Reddit's mascot, drawn in the same stroke style as the other
                 icons here rather than as the filled brand mark. -->
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">
              <ellipse cx="8" cy="9.6" rx="5.6" ry="4" />
              <path d="M8 5.6 9 2l3 .7" />
              <circle cx="12.8" cy="2.8" r="1" />
              <circle cx="2.9" cy="7" r="1.1" />
              <circle cx="13.1" cy="7" r="1.1" />
              <circle cx="6" cy="9.2" r=".4" fill="currentColor" />
              <circle cx="10" cy="9.2" r=".4" fill="currentColor" />
              <path d="M6 11.4c1.2.8 2.8.8 4 0" />
            </svg>
          {/if}
        </span>
        <span class="ember-link-body">
          <span class="ember-link-title">{link.title()}</span>
          <span class="ember-link-desc">{link.desc()}</span>
          {#if failed?.target === link.target}
            <span class="ember-link-error" role="alert">{failed.message}</span>
          {/if}
        </span>
        <span class="ember-link-go" aria-hidden="true">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
            <path d="M9.5 2H14v4.5" />
            <path d="M14 2 7.5 8.5" />
            <path d="M6.5 3.5H3.5A1.5 1.5 0 0 0 2 5v7.5A1.5 1.5 0 0 0 3.5 14H11a1.5 1.5 0 0 0 1.5-1.5V9.5" />
          </svg>
        </span>
      </button>
    </li>
  {/each}
</ul>

<style>
  .ember-links {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .ember-link {
    --link-tint: var(--accent);
    display: flex;
    align-items: center;
    gap: 12px;
    width: 100%;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
    color: inherit;
    font-family: inherit;
    font-weight: 400;
    text-align: left;
    cursor: pointer;
    transition:
      background-color var(--transition-fast) ease,
      border-color var(--transition-fast) ease;
  }

  /* Each place in its own colour, so the three read apart at a glance. */
  .ember-link.github {
    --link-tint: var(--text-primary);
  }

  .ember-link.reddit {
    --link-tint: #ff4500;
  }

  .ember-link:hover,
  .ember-link:focus-visible {
    background: var(--bg-hover);
    color: inherit;
    border-color: color-mix(in srgb, var(--link-tint) 45%, var(--border));
  }

  .ember-link:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }

  .ember-link-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 32px;
    height: 32px;
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--link-tint) 13%, transparent);
    color: var(--link-tint);
  }

  .ember-link-icon svg {
    width: 17px;
    height: 17px;
  }

  .ember-link-body {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .ember-link-title {
    font-size: var(--font-size-md);
    font-weight: 600;
    color: var(--text-primary);
  }

  .ember-link-desc {
    font-size: var(--font-size-sm);
    line-height: 1.4;
    color: var(--text-secondary);
  }

  .ember-link-error {
    font-size: var(--font-size-sm);
    color: var(--danger);
  }

  .ember-link-go {
    display: inline-flex;
    flex-shrink: 0;
    color: var(--text-muted);
    transition: color var(--transition-fast) ease;
  }

  .ember-link-go svg {
    width: 14px;
    height: 14px;
  }

  .ember-link:hover .ember-link-go,
  .ember-link:focus-visible .ember-link-go {
    color: var(--link-tint);
  }
</style>
