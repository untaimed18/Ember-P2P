<script lang="ts">
  // Cheat-sheet modal listing every keyboard shortcut the app
  // supports. Opened via ? or F1 (see Sidebar's global handler).
  // Grouped by scope so users can quickly scan to the shortcuts that
  // apply to where they are in the app.
  import * as m from '$lib/paraglide/messages';
  import IconX from './IconX.svelte';
  import { fade, scale } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';

  type Shortcut = { keys: string[]; label: () => string };
  type Group = { title: () => string; shortcuts: Shortcut[] };

  let { open = $bindable(false) }: { open?: boolean } = $props();

  let panelEl: HTMLDivElement | undefined = $state();

  // Auto-focus the panel when it opens so Escape works without the
  // user having to click inside first. Matches AboutDialog's pattern.
  $effect(() => {
    if (open) {
      requestAnimationFrame(() => {
        panelEl?.focus();
      });
    }
  });

  // Group/shortcut labels are stored as thunks so the table re-
  // renders in the active locale on each open without us needing
  // to rebuild the array on locale changes (locale changes
  // trigger a full page reload anyway, but the thunk form is
  // future-proof if we ever opt out of the reload).
  const groups: Group[] = [
    {
      title: () => m.shortcuts_section_global(),
      shortcuts: [
        { keys: ['?'], label: () => m.shortcuts_show_shortcuts() },
        { keys: ['F1'], label: () => m.shortcuts_show_shortcuts() },
        { keys: ['Ctrl', 'B'], label: () => m.shortcuts_toggle_sidebar() },
        { keys: ['Alt', '1'], label: () => m.shortcuts_jump_kad() },
        { keys: ['Alt', '2'], label: () => m.shortcuts_jump_servers() },
        { keys: ['Alt', '3'], label: () => m.shortcuts_jump_search() },
        { keys: ['Alt', '4'], label: () => m.shortcuts_jump_transfers() },
        { keys: ['Alt', '5'], label: () => m.shortcuts_jump_library() },
        { keys: ['Alt', '6'], label: () => m.shortcuts_jump_friends() },
        { keys: ['Alt', '7'], label: () => m.shortcuts_jump_statistics() },
        { keys: ['Alt', '8'], label: () => m.shortcuts_jump_security() },
        { keys: ['Alt', '9'], label: () => m.shortcuts_jump_settings() },
      ],
    },
    {
      title: () => m.shortcuts_section_dialogs(),
      shortcuts: [
        { keys: ['Esc'], label: () => m.shortcuts_modal_close() },
        { keys: ['Ctrl', 'Enter'], label: () => m.shortcuts_modal_confirm() },
        { keys: ['Tab'], label: () => m.shortcuts_modal_cycle_focus() },
        { keys: ['Enter'], label: () => m.shortcuts_modal_submit_form() },
      ],
    },
    {
      title: () => m.shortcuts_section_tables(),
      shortcuts: [
        { keys: ['Click'], label: () => m.shortcuts_table_sort() },
        { keys: ['Shift', 'Click'], label: () => m.shortcuts_table_multiselect() },
        { keys: ['Double-click'], label: () => m.shortcuts_table_open() },
        { keys: ['Right-click'], label: () => m.shortcuts_table_context() },
      ],
    },
  ];

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      open = false;
    }
  }
</script>

{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div class="shortcut-overlay" onclick={() => (open = false)} onkeydown={onKeydown} transition:fade={{ duration: prefersReducedMotion.current ? 0 : 150 }}>
    <div
      class="shortcut-panel"
      role="dialog"
      aria-modal="true"
      aria-labelledby="kbd-shortcut-title"
      onclick={(e) => e.stopPropagation()}
      tabindex="-1"
      bind:this={panelEl}
      transition:scale={{ start: 0.96, opacity: 0, duration: prefersReducedMotion.current ? 0 : 200 }}
    >
      <div class="shortcut-header">
        <h3 id="kbd-shortcut-title">{m.shortcuts_dialog_title()}</h3>
        <button class="shortcut-close" aria-label={m.common_close()} onclick={() => (open = false)}><IconX size={16} /></button>
      </div>
      <div class="shortcut-body">
        {#each groups as group, gi (gi)}
          <section class="shortcut-group">
            <h4>{group.title()}</h4>
            <dl>
              {#each group.shortcuts as shortcut, i (gi + '-' + i)}
                <div class="shortcut-row">
                  <dt>
                    {#each shortcut.keys as key, j (j + '-' + key)}
                      {#if j > 0}<span class="shortcut-plus">+</span>{/if}
                      <kbd>{key}</kbd>
                    {/each}
                  </dt>
                  <dd>{shortcut.label()}</dd>
                </div>
              {/each}
            </dl>
          </section>
        {/each}
      </div>
      <div class="shortcut-footer">
        <span class="shortcut-hint">{m.shortcuts_dialog_hint_press()} <kbd>Esc</kbd> {m.shortcuts_dialog_hint_to_close()}</span>
      </div>
    </div>
  </div>
{/if}

<style>
  .shortcut-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.45);
    z-index: 10000;
    display: flex;
    align-items: center;
    justify-content: center;
    backdrop-filter: blur(2px);
  }
  :global([data-theme="dark"]) .shortcut-overlay {
    background: rgba(8, 10, 13, 0.55);
    backdrop-filter: blur(6px) saturate(1.15);
  }

  .shortcut-panel {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: 0 16px 48px rgba(0, 0, 0, 0.35);
    width: min(640px, calc(100vw - 40px));
    max-height: min(80vh, 720px);
    display: flex;
    flex-direction: column;
  }
  :global([data-theme="dark"]) .shortcut-panel {
    box-shadow:
      inset 0 1px 0 0 rgba(255, 255, 255, 0.05),
      0 16px 48px rgba(0, 0, 0, 0.55);
  }

  .shortcut-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
  }

  .shortcut-header h3 {
    margin: 0;
    font-size: 15px;
    font-weight: 600;
  }

  .shortcut-close {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    background: none;
    border: 1px solid transparent;
    border-radius: 7px;
    color: var(--text-muted);
    cursor: pointer;
    padding: 0;
    transition: background 0.12s, border-color 0.12s, color 0.12s;
  }

  .shortcut-close:hover {
    color: var(--danger);
    border-color: color-mix(in srgb, var(--danger) 35%, var(--border));
    background: color-mix(in srgb, var(--danger) 12%, transparent);
  }

  .shortcut-body {
    padding: 16px 20px;
    overflow-y: auto;
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .shortcut-group h4 {
    margin: 0 0 8px 0;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--text-muted);
  }

  .shortcut-group dl {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin: 0;
  }

  .shortcut-row {
    display: grid;
    grid-template-columns: 180px 1fr;
    align-items: center;
    gap: 12px;
    padding: 5px 0;
    border-bottom: 1px dashed color-mix(in srgb, var(--border) 55%, transparent);
  }

  .shortcut-row:last-child {
    border-bottom: none;
  }

  .shortcut-row dt {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    flex-wrap: wrap;
    margin: 0;
  }

  .shortcut-row dd {
    margin: 0;
    font-size: 13px;
    color: var(--text-secondary);
  }

  .shortcut-plus {
    color: var(--text-muted);
    font-size: 11px;
    padding: 0 1px;
  }

  kbd {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 22px;
    height: 22px;
    padding: 0 7px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-bottom-width: 2px;
    border-radius: 4px;
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 600;
    color: var(--text-primary);
    line-height: 1;
    box-shadow: 0 1px 0 rgba(0, 0, 0, 0.04);
  }

  :global([data-theme="dark"]) kbd {
    background: var(--bg-tertiary);
    box-shadow:
      inset 0 1px 0 0 rgba(255, 255, 255, 0.04),
      0 1px 0 rgba(0, 0, 0, 0.3);
  }

  .shortcut-footer {
    padding: 10px 20px;
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: flex-end;
    color: var(--text-muted);
    font-size: 12px;
  }

  .shortcut-hint kbd {
    min-width: auto;
    height: 18px;
    font-size: 10px;
    padding: 0 5px;
    margin: 0 2px;
  }
</style>
