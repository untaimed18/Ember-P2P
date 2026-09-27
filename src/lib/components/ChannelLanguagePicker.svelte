<script lang="ts">
  import { tick } from 'svelte';
  import * as m from '$lib/paraglide/messages';
  import { portal } from '$lib/actions/portal';
  import {
    type ChannelLanguage,
    channelLanguageFlagSrc,
    channelLanguageName,
    channelLanguageNativeName,
    channelLanguageSearchText,
    sortedChannelLanguages,
  } from '$lib/channelLanguages';

  let {
    value = $bindable(null),
    disabled = false,
    describedby,
    onchange,
  }: {
    value?: ChannelLanguage | null;
    /** Rendered as `aria-disabled`, not `disabled`: a save that disables the
     *  trigger right after a choice would otherwise drop focus to <body>. */
    disabled?: boolean;
    describedby?: string;
    onchange?: (value: ChannelLanguage | null) => void;
  } = $props();

  type Option = { code: ChannelLanguage | null; name: string; native: string; search: string };

  const uid = Math.random().toString(36).slice(2, 8);
  const listId = `channel-lang-list-${uid}`;
  const optionId = (i: number) => `channel-lang-opt-${uid}-${i}`;

  const allOptions: Option[] = [
    { code: null, name: m.channels_language_none(), native: '', search: '' },
    ...sortedChannelLanguages().map((code) => {
      const name = channelLanguageName(code);
      const native = channelLanguageNativeName(code);
      return {
        code,
        name,
        native: native === name ? '' : native,
        search: channelLanguageSearchText(code),
      };
    }),
  ];

  let open = $state(false);
  let query = $state('');
  let active = $state(0);
  let triggerEl = $state<HTMLButtonElement>();
  let popoverEl = $state<HTMLDivElement>();
  let searchEl = $state<HTMLInputElement>();
  let listEl = $state<HTMLDivElement>();
  let placement = $state<{ top: number; left: number; width: number; maxHeight: number; above: boolean }>({
    top: 0,
    left: 0,
    width: 280,
    maxHeight: 320,
    above: false,
  });

  let options = $derived.by(() => {
    const q = query.trim().toLocaleLowerCase();
    if (!q) return allOptions;
    return allOptions.filter((o) => o.code !== null && o.search.includes(q));
  });

  let selectedName = $derived(value ? channelLanguageName(value) : m.channels_language_none());

  function place() {
    if (!triggerEl) return;
    const r = triggerEl.getBoundingClientRect();
    const margin = 8;
    const width = Math.max(r.width, 280);
    const below = window.innerHeight - r.bottom - margin;
    const aboveSpace = r.top - margin;
    const above = below < 260 && aboveSpace > below;
    const maxHeight = Math.min(360, Math.max(160, (above ? aboveSpace : below) - 4));
    const left = Math.min(Math.max(margin, r.left), window.innerWidth - width - margin);
    placement = {
      top: above ? r.top - 4 : r.bottom + 4,
      left,
      width,
      maxHeight,
      above,
    };
  }

  async function openPicker() {
    if (disabled || open) return;
    query = '';
    active = Math.max(0, allOptions.findIndex((o) => o.code === value));
    place();
    open = true;
    await tick();
    searchEl?.focus();
    scrollActiveIntoView('center');
  }

  function closePicker(refocus = true) {
    if (!open) return;
    open = false;
    if (refocus) triggerEl?.focus();
  }

  function choose(option: Option) {
    const changed = option.code !== value;
    value = option.code;
    closePicker();
    if (changed) onchange?.(option.code);
  }

  function scrollActiveIntoView(block: ScrollLogicalPosition = 'nearest') {
    listEl?.querySelector<HTMLElement>(`#${optionId(active)}`)?.scrollIntoView({ block });
  }

  function onSearchKeydown(e: KeyboardEvent) {
    if (e.isComposing || e.keyCode === 229) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (options.length === 0) return;
      const step = e.key === 'ArrowDown' ? 1 : -1;
      active = (active + step + options.length) % options.length;
      scrollActiveIntoView();
    } else if (e.key === 'Home' && !query) {
      e.preventDefault();
      active = 0;
      scrollActiveIntoView();
    } else if (e.key === 'End' && !query) {
      e.preventDefault();
      active = options.length - 1;
      scrollActiveIntoView();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const option = options[active];
      if (option) choose(option);
    } else if (e.key === 'Tab') {
      // Back on the trigger before the browser moves focus, so Tab carries on
      // from there rather than from the end of <body>, where this input lives.
      closePicker();
    }
  }

  function onTriggerKeydown(e: KeyboardEvent) {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      void openPicker();
    }
  }

  $effect(() => {
    if (!open) return;
    // The popover lives under <body> (see `portal`), so Escape has to be
    // caught natively before any page-level Escape handler closes a panel.
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !e.isComposing) {
        e.preventDefault();
        e.stopPropagation();
        closePicker();
      }
    };
    const outside = (t: EventTarget | null) =>
      !(t instanceof Node && (popoverEl?.contains(t) || triggerEl?.contains(t)));
    const onPointer = (e: PointerEvent) => {
      if (outside(e.target)) closePicker(false);
    };
    // Focus can leave without a click — a page shortcut focusing another field.
    const onFocusIn = (e: FocusEvent) => {
      if (outside(e.target)) closePicker(false);
    };
    const onReflow = () => place();
    window.addEventListener('keydown', onKey, true);
    window.addEventListener('pointerdown', onPointer, true);
    window.addEventListener('focusin', onFocusIn, true);
    window.addEventListener('resize', onReflow);
    window.addEventListener('scroll', onReflow, true);
    return () => {
      window.removeEventListener('keydown', onKey, true);
      window.removeEventListener('pointerdown', onPointer, true);
      window.removeEventListener('focusin', onFocusIn, true);
      window.removeEventListener('resize', onReflow);
      window.removeEventListener('scroll', onReflow, true);
    };
  });
</script>

<span class="lang-picker">
<button
  bind:this={triggerEl}
  type="button"
  class="lang-trigger"
  class:open
  aria-disabled={disabled}
  aria-label={value ? m.channels_language_flag_title({ language: selectedName }) : m.channels_language_none()}
  aria-haspopup="listbox"
  aria-expanded={open}
  aria-controls={open ? listId : undefined}
  aria-describedby={describedby}
  onclick={() => (open ? closePicker() : void openPicker())}
  onkeydown={onTriggerKeydown}
>
  {#if value}
    <img class="flag" src={channelLanguageFlagSrc(value)} alt="" />
  {:else}
    <span class="flag flag-none" aria-hidden="true">
      <svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.4">
        <circle cx="8" cy="8" r="6.25" />
        <path d="M1.75 8h12.5M8 1.75c1.9 1.8 2.8 3.9 2.8 6.25S9.9 12.45 8 14.25M8 1.75C6.1 3.55 5.2 5.65 5.2 8s.9 4.45 2.8 6.25" />
      </svg>
    </span>
  {/if}
  <span class="lang-trigger-label" class:muted={!value}>{selectedName}</span>
  <svg class="chevron" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M4 6l4 4 4-4" />
  </svg>
</button>

<div use:portal>
  {#if open}
    <div
      bind:this={popoverEl}
      class="lang-popover"
      class:above={placement.above}
      style:top="{placement.top}px"
      style:left="{placement.left}px"
      style:width="{placement.width}px"
      style:max-height="{placement.maxHeight}px"
      role="presentation"
      onmousedown={(e) => {
        if (e.target !== searchEl) e.preventDefault();
      }}
    >
      <div class="lang-search">
        <svg viewBox="0 0 20 20" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
          <circle cx="8.5" cy="8.5" r="5.5" /><line x1="12.5" y1="12.5" x2="17" y2="17" />
        </svg>
        <input
          bind:this={searchEl}
          bind:value={query}
          type="text"
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-activedescendant={options.length ? optionId(active) : undefined}
          aria-autocomplete="list"
          aria-label={m.channels_language_search()}
          placeholder={m.channels_language_search()}
          autocomplete="off"
          spellcheck="false"
          oninput={() => (active = 0)}
          onkeydown={onSearchKeydown}
        />
      </div>
      <div bind:this={listEl} id={listId} class="lang-list" role="listbox" aria-label={m.channels_language_label()}>
        {#each options as option, i (option.code ?? 'none')}
          <!-- Keyboard choice happens in the search box, which owns the
               highlight through aria-activedescendant. -->
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <div
            id={optionId(i)}
            class="lang-option"
            class:active={i === active}
            class:selected={option.code === value}
            class:none-option={option.code === null}
            role="option"
            aria-selected={option.code === value}
            tabindex="-1"
            onpointermove={() => (active = i)}
            onclick={() => choose(option)}
          >
            {#if option.code}
              <img class="flag" src={channelLanguageFlagSrc(option.code)} alt="" loading="lazy" />
            {:else}
              <span class="flag flag-none" aria-hidden="true">
                <svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.4">
                  <circle cx="8" cy="8" r="6.25" />
                  <path d="M1.75 8h12.5M8 1.75c1.9 1.8 2.8 3.9 2.8 6.25S9.9 12.45 8 14.25M8 1.75C6.1 3.55 5.2 5.65 5.2 8s.9 4.45 2.8 6.25" />
                </svg>
              </span>
            {/if}
            <span class="lang-name">{option.name}</span>
            {#if option.native}
              <span class="lang-native" lang={option.code ?? undefined}>{option.native}</span>
            {/if}
            {#if option.code === value}
              <svg class="check" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <polyline points="3.5,8.5 6.5,11.5 12.5,4.5" />
              </svg>
            {/if}
          </div>
        {/each}
      </div>
      {#if options.length === 0}
        <p class="lang-empty" role="status">{m.channels_language_no_match()}</p>
      {/if}
    </div>
  {/if}
</div>
</span>

<style>
  .lang-trigger {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    min-width: 200px;
    max-width: 100%;
    padding: 6px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-input);
    color: var(--text-primary);
    font: inherit;
    font-weight: 400;
    text-align: left;
    cursor: pointer;
    transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
  }

  .lang-picker {
    display: inline-flex;
    max-width: 100%;
  }

  .lang-trigger:hover:not([aria-disabled='true']) {
    background: var(--bg-input);
    color: var(--text-primary);
    border-color: var(--border-light);
  }

  .lang-trigger.open,
  .lang-trigger:focus-visible {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-halo);
    outline: none;
  }

  .lang-trigger[aria-disabled='true'] {
    background: var(--bg-disabled);
    color: var(--text-disabled);
    cursor: not-allowed;
  }

  .lang-trigger[aria-disabled='true']:active {
    transform: none;
  }

  .lang-trigger-label {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .lang-trigger-label.muted {
    color: var(--text-muted);
  }

  .chevron {
    flex-shrink: 0;
    color: var(--text-muted);
    transition: transform var(--transition-fast);
  }

  .lang-trigger.open .chevron {
    transform: rotate(180deg);
  }

  .flag {
    flex-shrink: 0;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    box-shadow: 0 0 0 1px color-mix(in srgb, var(--text-primary) 12%, transparent);
  }

  .flag-none {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-tertiary);
    color: var(--text-muted);
  }

  .lang-popover {
    position: fixed;
    z-index: 1000;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    background: var(--ctx-surface);
    border: 1px solid var(--ctx-border);
    border-radius: var(--radius-lg);
    box-shadow: var(--ctx-shadow);
    animation: lang-pop-in 120ms ease-out;
  }

  .lang-popover.above {
    transform: translateY(-100%);
    animation-name: lang-pop-in-above;
  }

  @keyframes lang-pop-in {
    from { opacity: 0; transform: translateY(-4px); }
    to { opacity: 1; transform: translateY(0); }
  }

  @keyframes lang-pop-in-above {
    from { opacity: 0; transform: translateY(calc(-100% + 4px)); }
    to { opacity: 1; transform: translateY(-100%); }
  }

  @media (prefers-reduced-motion: reduce) {
    .lang-popover { animation: none; }
    .chevron { transition: none; }
  }

  .lang-search {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border-bottom: 1px solid var(--ctx-divider);
    color: var(--text-muted);
  }

  .lang-search input {
    flex: 1;
    min-width: 0;
    padding: 2px 0;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font: inherit;
    outline: none;
    box-shadow: none;
  }

  .lang-list {
    flex: 1;
    min-height: 0;
    padding: 4px;
    overflow-y: auto;
  }

  .lang-option {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 6px 8px;
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    cursor: pointer;
  }

  .lang-option.active {
    background: var(--bg-hover);
  }

  .lang-option.selected .lang-name {
    font-weight: 600;
  }

  .lang-option.none-option {
    margin-bottom: 4px;
    border-bottom: 1px solid var(--ctx-divider);
    border-radius: var(--radius-sm) var(--radius-sm) 0 0;
    padding-bottom: 8px;
  }

  .lang-name {
    white-space: nowrap;
  }

  .lang-native {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-muted);
    font-size: 0.92em;
  }

  .check {
    flex-shrink: 0;
    margin-left: auto;
    color: var(--accent);
  }

  .lang-empty {
    margin: 0;
    padding: 14px 8px;
    color: var(--text-muted);
    text-align: center;
  }
</style>
