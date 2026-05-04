<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import ChatConversation from '$lib/components/ChatConversation.svelte';
  import {
    chatTabs,
    activeChatTab,
    chatDockOpen,
    closeTab,
    setActiveTab,
    closeDock,
    cycleTab,
  } from '$lib/stores/chatTabs';
  import { unreadCounts, onlineFriends } from '$lib/stores/friends';
  import * as m from '$lib/paraglide/messages';

  let panelEl: HTMLDivElement | undefined = $state();
  let returnFocusEl: HTMLElement | null = null;

  // Activate the dock as a focus context so screen readers announce
  // it as a dialog and Tab cycling stays in scope. We bail early if
  // the dock is closed so the rest of the app keeps full focus.
  $effect(() => {
    if ($chatDockOpen && panelEl) {
      const active = typeof document !== 'undefined' ? document.activeElement : null;
      if (active instanceof HTMLElement && active !== document.body) {
        returnFocusEl = active;
      }
      // Defer focus until after the slide-in transition lands; an
      // immediate `focus()` during the same frame the panel mounts
      // can be vetoed by the browser.
      requestAnimationFrame(() => panelEl?.focus());
    }
    return () => {
      if (!$chatDockOpen && returnFocusEl) {
        const el = returnFocusEl;
        returnFocusEl = null;
        requestAnimationFrame(() => {
          if (typeof document !== 'undefined' && document.contains(el)) el.focus();
        });
      }
    };
  });

  // Active tab metadata, looked up once per render so the
  // `<ChatConversation>` doesn't have to know about the tab list.
  let activeTab = $derived(
    $activeChatTab ? $chatTabs.find((t) => t.hash === $activeChatTab) ?? null : null,
  );

  function isTypingTarget(t: EventTarget | null): boolean {
    if (!(t instanceof HTMLElement)) return false;
    const tag = t.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
    if (t.isContentEditable) return true;
    return false;
  }

  // Global hotkeys, scoped to "dock is open". Esc closes the dock
  // (preserves tabs); Ctrl+Tab / Ctrl+Shift+Tab cycles tabs without
  // leaving the dock; Ctrl+W closes the active tab. Ctrl+Tab is
  // intercepted only when the dock is open so it doesn't fight with
  // the OS-level browser tab cycle in the rest of the app.
  function onKeydown(e: KeyboardEvent) {
    if (!$chatDockOpen) return;
    // Esc — close the dock. Allowed even from inputs because users
    // press it instinctively to dismiss overlays.
    if (e.key === 'Escape') {
      e.preventDefault();
      closeDock();
      return;
    }
    if (!(e.ctrlKey || e.metaKey)) return;
    if (e.key === 'Tab') {
      // Tab cycling shouldn't fire while typing in an input — users
      // need the regular Tab semantics to escape the textarea — but
      // Ctrl+Tab is the universal cycle gesture, so honour it
      // everywhere inside the dock.
      e.preventDefault();
      cycleTab(e.shiftKey ? -1 : 1);
      return;
    }
    if ((e.key === 'w' || e.key === 'W') && !isTypingTarget(e.target)) {
      // Ctrl+W is "close window" in the OS, but here it's "close
      // tab" — the dock isn't a real window so we can safely repurpose
      // it. Disabled while typing so a user mid-message doesn't lose
      // their conversation by reflex.
      e.preventDefault();
      const active = $activeChatTab;
      if (active) closeTab(active);
      return;
    }
  }

  onMount(() => {
    window.addEventListener('keydown', onKeydown);
    return () => window.removeEventListener('keydown', onKeydown);
  });

  function unreadFor(hash: string): number {
    return $unreadCounts.get(hash) ?? 0;
  }

  function isOnline(hash: string): boolean {
    return $onlineFriends.has(hash);
  }

  // Keyboard activation for the role=tab elements. Enter and Space
  // are the canonical keys for activating a tab in WAI-ARIA's tab
  // pattern. The outer is a div (not a button) because we need to
  // nest a real `<button>` for close-X and HTML disallows nesting
  // buttons.
  function onTabKeydown(e: KeyboardEvent, hash: string) {
    // Activate the focused tab on Enter/Space (in case the user
    // tab-focused into an inactive tab — they almost never can,
    // since only the active tab has tabindex=0, but it costs
    // nothing to support).
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setActiveTab(hash);
      return;
    }
    // WAI-ARIA tab pattern: Left/Right arrows move focus AND
    // activate the previous/next tab. Home/End jump to first/last.
    // Delete closes the focused tab. We don't intercept Up/Down
    // (vertical lists aren't in play here).
    const tabs = $chatTabs;
    if (tabs.length === 0) return;
    const idx = tabs.findIndex((t) => t.hash === hash);
    if (idx === -1) return;
    let target = -1;
    if (e.key === 'ArrowRight') target = (idx + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') target = (idx - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') target = 0;
    else if (e.key === 'End') target = tabs.length - 1;
    else if (e.key === 'Delete') {
      e.preventDefault();
      closeTab(hash);
      return;
    }
    if (target === -1) return;
    e.preventDefault();
    const targetHash = tabs[target].hash;
    setActiveTab(targetHash);
    // Move DOM focus to the new tab so further arrow presses
    // advance from there. The active tab is the only one with
    // tabindex=0, so a re-render is needed before we can focus —
    // queue the focus on the next frame.
    requestAnimationFrame(() => {
      if (typeof document === 'undefined') return;
      const next = document.querySelector<HTMLElement>(
        `.dock-tab[data-hash="${CSS.escape(targetHash)}"]`,
      );
      next?.focus();
    });
  }

  function handleNewChat() {
    // Sending users to the Friends page is the most discoverable
    // way to start a new conversation today: every friend card has
    // a chat button and the existing search/filter UI helps locate
    // the right person. We DON'T close the dock — leaving it open
    // means the user can click the friend on /friends and see their
    // chat appear right next to the friend list.
    goto('/friends');
  }
</script>

{#if $chatDockOpen}
  <!--
    No backdrop overlay: the dock is intentionally non-modal so the
    user can keep clicking through to /friends, /transfers, /library
    while a conversation stays alive on the right side of the
    screen. Dismissal is via the explicit close-X, the Esc hotkey,
    or the Ctrl+/ toggle in the sidebar — all signposted by tooltips
    and keyboard hints.
  -->
  <!--
    `role="complementary"` (rather than `dialog`) is the right
    landmark for a persistent panel that supports — but doesn't
    interrupt — the main page. `aria-modal` only carries meaning on
    dialog/alertdialog, so we omit it here. `aria-keyshortcuts`
    nudges screen readers to announce the Esc/Ctrl+/ dismiss
    affordance, which is the only escape hatch now that there's no
    backdrop to click.
  -->
  <div
    class="chat-dock"
    bind:this={panelEl}
    role="complementary"
    aria-label={m.chat_dock_aria_label()}
    aria-keyshortcuts="Escape Control+/"
    tabindex="-1"
  >
    <div class="dock-tabs" role="tablist" aria-label={m.chat_dock_tablist_aria()}>
      {#if $chatTabs.length === 0}
        <div class="dock-empty-tabs">{m.chat_dock_no_open()}</div>
      {:else}
        {#each $chatTabs as tab (tab.hash)}
          <div
            role="tab"
            class="dock-tab"
            class:active={tab.hash === $activeChatTab}
            class:online={isOnline(tab.hash)}
            aria-selected={tab.hash === $activeChatTab}
            tabindex={tab.hash === $activeChatTab ? 0 : -1}
            data-hash={tab.hash}
            title={tab.name}
            onclick={() => setActiveTab(tab.hash)}
            onkeydown={(e) => onTabKeydown(e, tab.hash)}
          >
            <span class="dock-tab-presence" aria-hidden="true"></span>
            <span class="dock-tab-name"><bdi>{tab.name}</bdi></span>
            {#if unreadFor(tab.hash) > 0}
              <span
                class="dock-tab-unread"
                aria-label={unreadFor(tab.hash) === 1
                  ? m.chat_dock_unread_aria_one()
                  : m.chat_dock_unread_aria_other({ count: unreadFor(tab.hash) })}
              >{unreadFor(tab.hash) > 99 ? '99+' : unreadFor(tab.hash)}</span>
            {/if}
            <button
              type="button"
              class="dock-tab-close"
              tabindex="-1"
              aria-label={m.chat_dock_close_tab({ name: tab.name })}
              title={m.chat_dock_close_tab_title()}
              onclick={(e) => { e.stopPropagation(); closeTab(tab.hash); }}
            >
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M4 4l8 8M12 4l-8 8"/>
              </svg>
            </button>
          </div>
        {/each}
      {/if}
      <button
        type="button"
        class="dock-new"
        title={m.chat_dock_new_chat()}
        aria-label={m.chat_dock_new_chat()}
        onclick={handleNewChat}
      >
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <line x1="8" y1="3" x2="8" y2="13"/>
          <line x1="3" y1="8" x2="13" y2="8"/>
        </svg>
      </button>
      <button
        type="button"
        class="dock-close"
        title={m.chat_dock_close_title()}
        aria-label={m.chat_dock_close_aria()}
        onclick={closeDock}
      >
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M3.5 3.5l9 9M12.5 3.5l-9 9"/>
        </svg>
      </button>
    </div>

    <div class="dock-body">
      {#if activeTab}
        <ChatConversation friendHash={activeTab.hash} friendName={activeTab.name} />
      {:else}
        <div class="dock-empty-state">
          <div class="empty-illustration" aria-hidden="true">
            <svg viewBox="0 0 64 64" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 18a6 6 0 016-6h28a6 6 0 016 6v18a6 6 0 01-6 6H30l-10 10v-10h-2a6 6 0 01-6-6V18z"/>
              <line x1="22" y1="26" x2="40" y2="26"/>
              <line x1="22" y1="32" x2="36" y2="32"/>
            </svg>
          </div>
          <p class="empty-title">{m.chat_dock_empty_title()}</p>
          <p class="empty-hint">{m.chat_dock_empty_hint()}</p>
          <button type="button" class="empty-cta" onclick={handleNewChat}>{m.chat_dock_empty_cta()}</button>
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .chat-dock {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    width: 420px;
    max-width: 100vw;
    background: var(--bg-primary);
    border-left: 1px solid var(--border);
    z-index: 1000;
    display: flex;
    flex-direction: column;
    box-shadow: -4px 0 24px rgba(0, 0, 0, 0.2);
    outline: none;
  }

  .dock-tabs {
    display: flex;
    align-items: stretch;
    gap: 2px;
    padding: 6px 6px 0;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
    scrollbar-width: thin;
    flex-shrink: 0;
  }

  .dock-tabs::-webkit-scrollbar {
    height: 6px;
  }

  .dock-tabs::-webkit-scrollbar-thumb {
    background: var(--border);
    border-radius: 3px;
  }

  .dock-empty-tabs {
    display: flex;
    align-items: center;
    padding: 0 12px;
    color: var(--text-muted);
    font-size: 12px;
    font-style: italic;
  }

  .dock-tab {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px 8px 12px;
    border: none;
    border-radius: var(--radius-sm) var(--radius-sm) 0 0;
    background: transparent;
    color: var(--text-secondary);
    font-size: 12.5px;
    font-family: inherit;
    cursor: pointer;
    max-width: 180px;
    min-width: 0;
    flex-shrink: 0;
    position: relative;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .dock-tab:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .dock-tab.active {
    background: var(--bg-primary);
    color: var(--text-primary);
    font-weight: 600;
  }

  .dock-tab.active::after {
    content: '';
    position: absolute;
    left: 0;
    right: 0;
    bottom: -1px;
    height: 2px;
    background: var(--accent);
  }

  .dock-tab-presence {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-muted);
    flex-shrink: 0;
    transition: background var(--transition-fast), box-shadow var(--transition-fast);
  }

  .dock-tab.online .dock-tab-presence {
    background: #3ccf6d;
    box-shadow: 0 0 0 2px color-mix(in srgb, #3ccf6d 22%, transparent);
  }

  .dock-tab-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  .dock-tab-unread {
    background: var(--accent);
    color: #fff;
    font-size: 10px;
    font-weight: 700;
    padding: 1px 6px;
    border-radius: 999px;
    min-width: 18px;
    text-align: center;
    line-height: 1.2;
    flex-shrink: 0;
  }

  .dock-tab-close {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    flex-shrink: 0;
    opacity: 0;
    font: inherit;
    transition: background var(--transition-fast), color var(--transition-fast), opacity var(--transition-fast);
  }

  .dock-tab:hover .dock-tab-close,
  .dock-tab.active .dock-tab-close {
    opacity: 1;
  }

  .dock-tab-close:hover {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }

  .dock-tab-close svg {
    width: 10px;
    height: 10px;
  }

  .dock-new,
  .dock-close {
    width: 32px;
    height: 32px;
    margin: 4px 0;
    padding: 0;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .dock-new {
    margin-left: 4px;
  }

  .dock-close {
    margin-left: auto;
  }

  .dock-new:hover,
  .dock-close:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .dock-new:focus-visible,
  .dock-close:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .dock-new svg,
  .dock-close svg {
    width: 14px;
    height: 14px;
  }

  .dock-body {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: hidden;
  }

  .dock-empty-state {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 32px;
    text-align: center;
    gap: 12px;
    color: var(--text-muted);
  }

  .empty-illustration {
    color: var(--text-muted);
    opacity: 0.55;
  }

  .empty-illustration svg {
    width: 64px;
    height: 64px;
  }

  .empty-title {
    margin: 4px 0 0;
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .empty-hint {
    margin: 0;
    font-size: 12.5px;
    line-height: 1.5;
    max-width: 280px;
  }

  .empty-cta {
    margin-top: 8px;
    padding: 8px 14px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-primary);
    font-size: 13px;
    font-family: inherit;
    cursor: pointer;
    transition: background var(--transition-fast);
  }

  .empty-cta:hover {
    background: var(--bg-hover);
  }
</style>
