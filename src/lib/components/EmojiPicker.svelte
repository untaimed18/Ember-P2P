<script lang="ts">
  import { onMount } from 'svelte';
  import * as m from '$lib/paraglide/messages';
  import {
    EMOJI_CATEGORIES,
    loadRecentEmoji,
    noteRecentEmoji,
    type EmojiCategoryId,
  } from '$lib/emojiPicker';

  interface Props {
    id: string;
    onpick: (emoji: string) => void;
    onclose: () => void;
  }

  let { id, onpick, onclose }: Props = $props();

  type Section = EmojiCategoryId | 'recent';

  /** Must match `grid-template-columns` below; arrow keys move by it. */
  const COLUMNS = 8;
  /** Read once per opening, so the row does not reshuffle under the pointer. */
  const recent = loadRecentEmoji();
  const LABELS: Record<Section, () => string> = {
    recent: () => m.chat_emoji_recent(),
    smileys: () => m.chat_emoji_smileys(),
    people: () => m.chat_emoji_people(),
    nature: () => m.chat_emoji_nature(),
    food: () => m.chat_emoji_food(),
    activities: () => m.chat_emoji_activities(),
    objects: () => m.chat_emoji_objects(),
    symbols: () => m.chat_emoji_symbols(),
  };
  const sections: { id: Section; icon: string; emoji: readonly string[] }[] = [
    ...(recent.length > 0 ? [{ id: 'recent' as const, icon: '🕘', emoji: recent }] : []),
    ...EMOJI_CATEGORIES,
  ];

  let section = $state<Section>(sections[0].id);
  let shown = $derived(sections.find((entry) => entry.id === section)?.emoji ?? []);
  let gridEl: HTMLDivElement | undefined = $state();

  function cells(): HTMLButtonElement[] {
    return gridEl ? [...gridEl.querySelectorAll<HTMLButtonElement>('button')] : [];
  }

  onMount(() => {
    cells()[0]?.focus();
  });

  function pick(emoji: string) {
    noteRecentEmoji(emoji);
    onpick(emoji);
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      // Only the picker, not the room's own Escape handling.
      e.preventDefault();
      e.stopPropagation();
      onclose();
      return;
    }
    const list = cells();
    const at = list.indexOf(document.activeElement as HTMLButtonElement);
    if (at < 0) return;
    let next: number;
    switch (e.key) {
      case 'ArrowRight':
        next = at + 1;
        break;
      case 'ArrowLeft':
        next = at - 1;
        break;
      case 'ArrowDown':
        next = at + COLUMNS;
        break;
      case 'ArrowUp':
        next = at - COLUMNS;
        break;
      case 'Home':
        next = 0;
        break;
      case 'End':
        next = list.length - 1;
        break;
      default:
        return;
    }
    e.preventDefault();
    list[Math.max(0, Math.min(next, list.length - 1))]?.focus();
  }
</script>

<!-- Focusable itself, so a click on its padding keeps focus inside and the
     composer's focus-out test does not take it for a click away. -->
<div
  class="emoji-picker"
  {id}
  role="dialog"
  aria-label={m.chat_emoji_button()}
  tabindex="-1"
  onkeydown={handleKeydown}
>
  <div class="emoji-sections">
    {#each sections as entry (entry.id)}
      <button
        type="button"
        class="emoji-section"
        class:active={section === entry.id}
        aria-pressed={section === entry.id}
        title={LABELS[entry.id]()}
        aria-label={LABELS[entry.id]()}
        onclick={() => (section = entry.id)}
      ><span aria-hidden="true">{entry.icon}</span></button>
    {/each}
  </div>
  <div class="emoji-heading" aria-hidden="true">{LABELS[section]()}</div>
  <div class="emoji-grid" role="group" aria-label={LABELS[section]()} bind:this={gridEl}>
    {#each shown as emoji (emoji)}
      <button type="button" class="emoji-cell" onclick={() => pick(emoji)}>{emoji}</button>
    {/each}
  </div>
</div>

<style>
  .emoji-picker {
    position: absolute;
    bottom: calc(100% - 4px);
    inset-inline-end: 14px;
    z-index: 5;
    display: flex;
    flex-direction: column;
    gap: 4px;
    width: 304px;
    max-width: calc(100% - 28px);
    padding: 6px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-surface);
    box-shadow: var(--shadow-md);
    color: var(--text-primary);
  }

  .emoji-picker:focus {
    outline: none;
  }

  .emoji-sections {
    display: flex;
    gap: 2px;
    padding-bottom: 4px;
    border-bottom: 1px solid var(--border);
  }

  .emoji-section {
    flex: 1;
    min-width: 0;
    height: 28px;
    padding: 0;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    font-size: 16px;
    line-height: 1;
    cursor: pointer;
    opacity: 0.6;
    filter: grayscale(0.6);
  }

  .emoji-section:hover,
  .emoji-section.active {
    background: var(--bg-hover);
    opacity: 1;
    filter: none;
  }

  .emoji-heading {
    padding: 2px 4px 0;
    color: var(--text-muted);
    font-size: var(--font-size-xs);
    font-weight: 600;
  }

  .emoji-grid {
    display: grid;
    grid-template-columns: repeat(8, 1fr);
    gap: 2px;
    max-height: 216px;
    overflow-y: auto;
  }

  .emoji-cell {
    aspect-ratio: 1;
    min-width: 0;
    padding: 0;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    font-size: 20px;
    line-height: 1;
    cursor: pointer;
  }

  .emoji-cell:hover,
  .emoji-cell:focus-visible {
    background: var(--bg-hover);
  }

  .emoji-section:focus-visible,
  .emoji-cell:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }
</style>
