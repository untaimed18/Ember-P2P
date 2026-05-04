<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import AboutDialog from '$lib/components/AboutDialog.svelte';
  import KeyboardShortcutsDialog from '$lib/components/KeyboardShortcutsDialog.svelte';
  import { transfers } from '$lib/stores/transfers';
  import { networkStats } from '$lib/stores/network';
  import { friendRequests } from '$lib/stores/friends';
  import { totalUnread, toggleDock as toggleChatDock, chatDockOpen } from '$lib/stores/chatTabs';
  import * as m from '$lib/paraglide/messages';
  import { onMount } from 'svelte';

  let aboutOpen = $state(false);
  let shortcutsOpen = $state(false);

  // Persist collapsed state across sessions. Read synchronously on
  // script init so the first render doesn't briefly flash expanded
  // for a user who prefers collapsed.
  const STORAGE_COLLAPSED = 'sidebar-collapsed';
  function loadCollapsed(): boolean {
    try {
      return localStorage.getItem(STORAGE_COLLAPSED) === '1';
    } catch {
      return false;
    }
  }
  let isCollapsed = $state(loadCollapsed());

  function toggleCollapsed() {
    isCollapsed = !isCollapsed;
    try { localStorage.setItem(STORAGE_COLLAPSED, isCollapsed ? '1' : '0'); } catch { /* ignore */ }
  }

  let activeDownloadCount = $derived(
    $transfers.filter(t => t.direction === 'download' && t.status !== 'completed' && t.status !== 'failed').length
  );

  // Pending incoming friend-request count. Mirrors the transfers badge
  // pattern so users notice new requests without leaving the current
  // page. Uses the same friends store the Friends page consumes, so
  // the badge clears the moment the request is accepted/rejected.
  let pendingFriendRequestCount = $derived($friendRequests.length);

  // Sum of unread chat messages across all friends. The Chats toggle
  // surfaces this so users can spot new messages from any page —
  // previously the only signal was per-friend badges on /friends,
  // which required navigating there to notice activity.
  let totalUnreadChats = $derived($totalUnread);

  type NavItem = {
    href: string;
    /** Function returning the localized label. We keep `label` as a
     *  thunk (rather than a pre-resolved string) so the array can
     *  remain a top-level `const` while still picking up locale
     *  changes — Paraglide message functions read the current
     *  locale on each call. */
    label: () => string;
    id: string;
    /** Legacy URLs that should highlight this item (and short-circuit
     *  re-navigation) until the route-level redirect fires. The KAD
     *  view used to live at `/kad-network`; we keep the alias so the
     *  sidebar doesn't flicker between "no item active" and "KAD
     *  active" on the brief detour through the redirect stub. */
    aliases?: string[];
  };

  const navItems: NavItem[] = [
    { href: '/', label: () => m.nav_kad_network(), id: 'kad', aliases: ['/kad-network'] },
    { href: '/servers', label: () => m.nav_ed2k_servers(), id: 'servers' },
    { href: '/search', label: () => m.nav_search(), id: 'search' },
    { href: '/transfers', label: () => m.nav_transfers(), id: 'transfers' },
    { href: '/library', label: () => m.nav_library(), id: 'library' },
    { href: '/friends', label: () => m.nav_friends(), id: 'friends' },
    { href: '/statistics', label: () => m.nav_statistics(), id: 'statistics' },
    { href: '/security', label: () => m.nav_security(), id: 'security' },
    { href: '/settings', label: () => m.nav_settings(), id: 'settings' },
  ];

  // Developer-only diagnostic page for the Ember-native transport.
  // Rendered as a footer entry rather than mixed into the main nav so
  // it doesn't take an Alt+N keyboard slot away from the user-facing
  // pages and reads visually as "tooling, not a feature page".
  const devNavItem: NavItem = { href: '/dev/ember', label: 'Ember Dev', id: 'dev-ember' };

  function isActive(item: NavItem, pathname: string): boolean {
    return pathname === item.href || (item.aliases?.includes(pathname) ?? false);
  }

  function navigateTo(href: string) {
    const current = $page.url.pathname;
    if (current === href) return;
    // If we're already on a legacy alias of the target, don't re-issue
    // the navigation — the route redirect will land us on `href`
    // momentarily and a parallel goto would race with it.
    const item = navItems.find((i) => i.href === href);
    if (item?.aliases?.includes(current)) return;
    goto(href).catch(() => {
      window.location.href = href;
    });
  }

  function navigate(e: MouseEvent, href: string) {
    e.preventDefault();
    navigateTo(href);
  }

  // Alt+1..9 jumps to the corresponding sidebar entry. Mirrors the
  // workspace-switching convention from Discord/Slack/etc., and stays
  // out of the way of in-page Ctrl-shortcuts (Ctrl+S in settings,
  // Ctrl+A/C/D in library, etc.). Skipped while the user is typing in
  // an input/textarea/contenteditable so it doesn't eat regular Alt
  // keystrokes (special characters, menu access keys).
  function isTypingTarget(t: EventTarget | null): boolean {
    if (!(t instanceof HTMLElement)) return false;
    const tag = t.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
    if (t.isContentEditable) return true;
    return false;
  }

  function onShortcutKey(e: KeyboardEvent) {
    // "?" or F1 — open the keyboard shortcuts cheat-sheet. F1 is the
    // legacy desktop help key; "?" matches GitHub/Slack/Linear
    // conventions. Blocked while typing so users can still type "?"
    // into search fields.
    if ((e.key === '?' || e.key === 'F1') && !e.ctrlKey && !e.metaKey && !e.altKey) {
      if (isTypingTarget(e.target)) return;
      e.preventDefault();
      shortcutsOpen = !shortcutsOpen;
      return;
    }
    // Ctrl/Cmd+B toggles the sidebar. Matches VS Code/Slack/Discord
    // convention and frees up horizontal space for data-dense pages
    // without the user needing to reach for the mouse. Blocked while
    // typing so it doesn't fight with rich-text bold shortcuts.
    if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (e.key === 'b' || e.key === 'B')) {
      if (isTypingTarget(e.target)) return;
      e.preventDefault();
      toggleCollapsed();
      return;
    }
    // Ctrl/Cmd+/ toggles the chat dock. "/" sits next to ".", which
    // is intuitive for "open chats" without colliding with any
    // existing browser/app shortcut and stays out of typing flows.
    if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key === '/') {
      if (isTypingTarget(e.target)) return;
      e.preventDefault();
      toggleChatDock();
      return;
    }
    if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
    if (isTypingTarget(e.target)) return;
    const n = Number.parseInt(e.key, 10);
    if (!Number.isFinite(n) || n < 1 || n > navItems.length) return;
    e.preventDefault();
    navigateTo(navItems[n - 1].href);
  }

  onMount(() => {
    window.addEventListener('keydown', onShortcutKey);
    return () => window.removeEventListener('keydown', onShortcutKey);
  });
</script>

<nav class="sidebar" class:collapsed={isCollapsed} aria-label={m.sidebar_aria_primary()}>
  <div class="sidebar-header">
    <a href="/" class="logo" onclick={(e) => navigate(e, '/')} title={m.sidebar_logo_title()}>
      <span class="logo-text">EMBER</span>
      <span class="logo-sub">{m.app_tagline()}</span>
    </a>
  </div>

  <ul class="nav-list">
    {#each navItems as item, i}
      <li>
        <a
          href={item.href}
          class:active={isActive(item, $page.url.pathname)}
          aria-current={isActive(item, $page.url.pathname) ? 'page' : undefined}
          aria-keyshortcuts={i < 9 ? `Alt+${i + 1}` : undefined}
          onclick={(e: MouseEvent) => navigate(e, item.href)}
          title={i < 9 ? m.sidebar_nav_with_shortcut_title({ label: item.label(), n: i + 1 }) : item.label()}
        >
          <span class="nav-icon" aria-hidden="true">
            {#if item.id === 'kad'}
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="10" cy="4" r="2.5"/>
                <circle cx="4" cy="14" r="2.5"/>
                <circle cx="16" cy="14" r="2.5"/>
                <line x1="10" y1="6.5" x2="5.5" y2="11.5"/>
                <line x1="10" y1="6.5" x2="14.5" y2="11.5"/>
                <line x1="6.5" y1="14" x2="13.5" y2="14"/>
              </svg>
            {:else if item.id === 'servers'}
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="3" width="14" height="5" rx="1"/>
                <rect x="3" y="12" width="14" height="5" rx="1"/>
                <circle cx="6" cy="5.5" r="0.6" fill="currentColor" stroke="none"/>
                <circle cx="6" cy="14.5" r="0.6" fill="currentColor" stroke="none"/>
                <line x1="9" y1="5.5" x2="14" y2="5.5"/>
                <line x1="9" y1="14.5" x2="14" y2="14.5"/>
              </svg>
            {:else if item.id === 'search'}
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="8.5" cy="8.5" r="5.5"/>
                <line x1="12.5" y1="12.5" x2="17" y2="17"/>
              </svg>
            {:else if item.id === 'transfers'}
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <line x1="7" y1="3" x2="7" y2="17"/>
                <polyline points="3,7 7,3 11,7"/>
                <line x1="13" y1="3" x2="13" y2="17"/>
                <polyline points="9,13 13,17 17,13"/>
              </svg>
            {:else if item.id === 'library'}
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M3 4h5l2 2h7v10H3V4z"/>
                <line x1="3" y1="9" x2="17" y2="9"/>
              </svg>
            {:else if item.id === 'friends'}
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="7" cy="6" r="3"/>
                <circle cx="14" cy="7" r="2.5"/>
                <path d="M1 17c0-3.3 2.7-6 6-6s6 2.7 6 6"/>
                <path d="M13 11.5c2.5 0 4.5 2 4.5 4.5"/>
              </svg>
            {:else if item.id === 'statistics'}
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <line x1="4" y1="17" x2="4" y2="10"/>
                <line x1="8" y1="17" x2="8" y2="6"/>
                <line x1="12" y1="17" x2="12" y2="12"/>
                <line x1="16" y1="17" x2="16" y2="3"/>
              </svg>
            {:else if item.id === 'security'}
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10 2L3 6v4c0 4.4 3 8.5 7 10 4-1.5 7-5.6 7-10V6l-7-4z"/>
                <polyline points="7,10 9.5,12.5 13.5,7.5"/>
              </svg>
            {:else if item.id === 'settings'}
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="10" cy="10" r="2.5"/>
                <path d="M10 1.5v2M10 16.5v2M1.5 10h2M16.5 10h2M3.9 3.9l1.4 1.4M14.7 14.7l1.4 1.4M3.9 16.1l1.4-1.4M14.7 5.3l1.4-1.4"/>
              </svg>
            {/if}
          </span>
          <span class="nav-label">{item.label()}</span>
          {#if item.id === 'kad'}
            <span
              class="nav-dot {$networkStats.status}"
              title={
                $networkStats.status === 'connected' ? m.network_status_connected() :
                $networkStats.status === 'connecting' ? m.network_status_connecting() :
                $networkStats.status === 'disconnected' ? m.network_status_disconnected() :
                m.network_status_unknown()
              }
            ></span>
          {/if}
          {#if item.id === 'transfers' && activeDownloadCount > 0}
            <span class="nav-badge">{activeDownloadCount}</span>
          {/if}
          {#if item.id === 'friends' && pendingFriendRequestCount > 0}
            <span
              class="nav-badge nav-badge-attention"
              title={pendingFriendRequestCount === 1
                ? m.sidebar_friend_requests_title_one()
                : m.sidebar_friend_requests_title_other({ count: pendingFriendRequestCount })}
            >{pendingFriendRequestCount}</span>
          {/if}
        </a>
      </li>
    {/each}
  </ul>

  <div class="sidebar-footer">
    <a
      href={devNavItem.href}
      class="about-btn dev-link"
      class:active={isActive(devNavItem, $page.url.pathname)}
      onclick={(e: MouseEvent) => navigate(e, devNavItem.href)}
      title="Ember-native transport diagnostics (developer)"
    >
      <span class="about-icon" aria-hidden="true">
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="6 7 2 10 6 13"/>
          <polyline points="14 7 18 10 14 13"/>
          <line x1="11" y1="4" x2="9" y2="16"/>
        </svg>
      </span>
      <span>{devNavItem.label}</span>
    </a>
    <button
      type="button"
      class="about-btn chats-btn"
      class:active={$chatDockOpen}
      onclick={toggleChatDock}
      title={$chatDockOpen ? m.sidebar_chats_close() : m.sidebar_chats_open()}
      aria-pressed={$chatDockOpen}
      aria-keyshortcuts="Control+/"
    >
      <span class="about-icon" aria-hidden="true">
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3 5a2 2 0 012-2h10a2 2 0 012 2v7a2 2 0 01-2 2h-5l-4 3v-3H5a2 2 0 01-2-2V5z"/>
          <line x1="6.5" y1="8" x2="13.5" y2="8"/>
          <line x1="6.5" y1="10.5" x2="11.5" y2="10.5"/>
        </svg>
      </span>
      <span class="chats-label">{m.sidebar_chats_label()}</span>
      {#if totalUnreadChats > 0}
        <span
          class="nav-badge nav-badge-attention chats-badge"
          title={totalUnreadChats === 1
            ? m.sidebar_chats_unread_title_one()
            : m.sidebar_chats_unread_title_other({ count: totalUnreadChats })}
        >{totalUnreadChats > 99 ? '99+' : totalUnreadChats}</span>
      {/if}
    </button>
    <button
      type="button"
      class="about-btn"
      onclick={() => (shortcutsOpen = true)}
      title={m.sidebar_keyboard_shortcuts_title()}
      aria-keyshortcuts="?"
    >
      <span class="about-icon" aria-hidden="true">
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <rect x="1.5" y="5" width="17" height="10" rx="2"/>
          <line x1="5" y1="8.5" x2="5.01" y2="8.5"/>
          <line x1="8" y1="8.5" x2="8.01" y2="8.5"/>
          <line x1="11" y1="8.5" x2="11.01" y2="8.5"/>
          <line x1="14" y1="8.5" x2="14.01" y2="8.5"/>
          <line x1="5" y1="11.5" x2="14" y2="11.5"/>
        </svg>
      </span>
      <span>{m.sidebar_shortcuts_label()}</span>
    </button>
    <button type="button" class="about-btn" onclick={() => (aboutOpen = true)} title={m.sidebar_about_title()}>
      <span class="about-icon" aria-hidden="true">
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="10" cy="10" r="7.5"/>
          <line x1="10" y1="9" x2="10" y2="14"/>
          <circle cx="10" cy="6" r="1" fill="currentColor" stroke="none"/>
        </svg>
      </span>
      <span>{m.sidebar_about()}</span>
    </button>
    <button
      type="button"
      class="about-btn collapse-btn"
      onclick={toggleCollapsed}
      title={isCollapsed ? m.sidebar_expand() : m.sidebar_collapse()}
      aria-label={isCollapsed ? m.sidebar_expand_aria() : m.sidebar_collapse_aria()}
      aria-keyshortcuts="Control+B"
    >
      <span class="about-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          {#if isCollapsed}
            <polyline points="13 17 18 12 13 7"></polyline><polyline points="6 17 11 12 6 7"></polyline>
          {:else}
            <polyline points="11 17 6 12 11 7"></polyline><polyline points="18 17 13 12 18 7"></polyline>
          {/if}
        </svg>
      </span>
      <span>{isCollapsed ? m.sidebar_expand_label() : m.sidebar_collapse_label()}</span>
    </button>
  </div>

  <AboutDialog bind:open={aboutOpen} />
  <KeyboardShortcutsDialog bind:open={shortcutsOpen} />
</nav>

<style>
  .sidebar {
    width: var(--sidebar-width);
    height: 100%;
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    transition: width var(--transition-normal) ease;
  }

  .sidebar.collapsed {
    width: 64px;
  }

  .sidebar-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
    position: relative;
  }

  .logo {
    padding: 20px 16px;
    display: flex;
    flex-direction: column;
    text-decoration: none;
    cursor: pointer;
    overflow: hidden;
    white-space: nowrap;
    flex: 1;
    min-width: 0;
  }

  .sidebar.collapsed .logo {
    padding: 20px 8px;
    align-items: center;
  }

  /* Scale transform instead of font-size so the shrink animation
     doesn't reflow every frame. Origin is the left edge so the logo
     glyphs collapse in-place toward the icon column. */
  .sidebar.collapsed .logo-text {
    transform: scale(0.65);
    letter-spacing: 1px;
  }

  .sidebar.collapsed .logo-sub {
    display: none;
  }

  .collapse-btn svg {
    width: 20px;
    height: 20px;
  }

  .logo-text {
    font-size: 22px;
    font-weight: 800;
    letter-spacing: 3px;
    color: var(--accent);
    transform-origin: center;
    transition: transform var(--transition-normal) ease, letter-spacing var(--transition-normal) ease;
  }

  .logo-sub {
    font-size: 10px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 2px;
  }

  .nav-list {
    list-style: none;
    padding: 8px 0;
    flex: 1;
    min-height: 0;
  }

  .sidebar-footer {
    border-top: 1px solid var(--border);
    padding: 8px 12px 12px;
    flex-shrink: 0;
  }

  .about-btn {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 10px 16px;
    border: none;
    border-radius: var(--radius-md, 6px);
    background: transparent;
    color: var(--text-muted);
    font-size: 13px;
    font-family: inherit;
    cursor: pointer;
    text-align: left;
    transition: background-color var(--transition-normal), color var(--transition-normal);
  }

  .about-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .about-btn:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }

  /* Developer-page entry. Visually demoted compared to the main
     nav (smaller font, dotted edge) so it reads as tooling rather
     than a regular page. Active highlight reuses the accent colour
     so navigating there still feels consistent with the rest of
     the sidebar. */
  .about-btn.dev-link {
    text-decoration: none;
    font-size: 12px;
    border: 1px dashed transparent;
    margin-bottom: 4px;
  }
  .about-btn.dev-link.active {
    color: var(--accent);
    border-color: color-mix(in srgb, var(--accent) 35%, transparent);
    background: color-mix(in srgb, var(--accent) 8%, transparent);
  }

  /*
   * Active state for the Chats toggle so users see at a glance whether
   * the dock is currently open. Mirrors the active treatment of nav
   * items (left accent stripe via ::before is overkill here, just tint
   * the bg + text).
   */
  .chats-btn.active {
    background: var(--bg-tertiary);
    color: var(--accent);
  }

  .chats-btn {
    position: relative;
  }

  .chats-badge {
    margin-left: auto;
  }

  .sidebar.collapsed .chats-badge {
    position: absolute;
    top: 2px;
    right: 2px;
    margin: 0;
    min-width: 14px;
    height: 14px;
    font-size: 8px;
    padding: 0 3px;
  }

  .sidebar.collapsed .chats-label {
    display: none;
  }

  .about-icon {
    width: 20px;
    height: 20px;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .about-icon svg {
    width: 20px;
    height: 20px;
  }

  .nav-list li a {
    position: relative;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 16px;
    color: var(--text-secondary);
    text-decoration: none;
    transition: background-color var(--transition-normal), color var(--transition-normal), padding var(--transition-normal);
    font-size: 14px;
    overflow: hidden;
  }

  .sidebar.collapsed .nav-list li a {
    padding: 10px 0;
    justify-content: center;
  }

  .sidebar.collapsed .nav-label {
    display: none;
  }

  .sidebar.collapsed .nav-dot {
    position: absolute;
    top: 6px;
    right: 6px;
    margin: 0;
    width: 6px;
    height: 6px;
  }

  .sidebar.collapsed .nav-badge {
    position: absolute;
    top: 2px;
    right: 2px;
    margin: 0;
    min-width: 14px;
    height: 14px;
    font-size: 8px;
    padding: 0 3px;
  }

  .sidebar.collapsed .about-btn span:not(.about-icon) {
    display: none;
  }

  .sidebar.collapsed .about-btn {
    padding: 10px 0;
    justify-content: center;
  }

  .sidebar.collapsed .sidebar-footer {
    padding: 8px 4px 12px;
  }

  /*
   * Active indicator rendered as a dedicated pseudo-element so it can have
   * rounded ends, slight vertical inset, and fade in/out independently of
   * the row's background. Reserves 3px on the left via a transparent
   * border so hover/active rows don't shift horizontally.
   */
  .nav-list li a::before {
    content: '';
    position: absolute;
    left: 0;
    top: 6px;
    bottom: 6px;
    width: 3px;
    border-radius: 0 3px 3px 0;
    background: var(--accent);
    opacity: 0;
    transform: scaleY(0.5);
    transition: opacity var(--transition-normal) ease, transform var(--transition-normal) ease;
  }

  .nav-list li a:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .nav-list li a:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
    background: var(--bg-hover);
  }

  .nav-list li a.active {
    background: var(--bg-tertiary);
    color: var(--accent);
  }

  .nav-list li a.active::before {
    opacity: 1;
    transform: scaleY(1);
    box-shadow: 0 0 10px 0 var(--accent-halo);
  }

  .nav-icon {
    width: 20px;
    height: 20px;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .nav-icon svg {
    width: 20px;
    height: 20px;
  }

  .nav-badge {
    margin-left: auto;
    min-width: 20px;
    height: 18px;
    padding: 0 5px;
    border-radius: 9px;
    background: var(--accent);
    color: #fff;
    font-size: 10px;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    line-height: 1;
    flex-shrink: 0;
  }

  /* Pending friend requests use the warning hue so they read as
     "needs your attention" rather than just "running activity" — the
     same visual rule as the connecting-state KAD dot. The accent
     badge stays for transfer counts (steady-state work). */
  .nav-badge.nav-badge-attention {
    background: var(--warning);
    color: #1a1a1a;
  }

  .nav-dot {
    margin-left: auto;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
    background: var(--text-muted);
    position: relative;
    transition: background-color var(--transition-normal) ease, box-shadow var(--transition-normal) ease;
  }

  .nav-dot.connected {
    background: #3ccf6d;
    box-shadow:
      0 0 0 2px color-mix(in srgb, #3ccf6d 22%, transparent),
      0 0 8px color-mix(in srgb, #3ccf6d 55%, transparent);
  }

  .nav-dot.connecting {
    background: #f0b93f;
    box-shadow:
      0 0 0 2px color-mix(in srgb, #f0b93f 22%, transparent),
      0 0 8px color-mix(in srgb, #f0b93f 55%, transparent);
    animation: nav-dot-pulse 1.5s ease-in-out infinite;
  }

  @media (prefers-reduced-motion: reduce) {
    .nav-dot.connecting {
      animation: none;
    }
  }

  .nav-dot.disconnected {
    background: #e06a5f;
    box-shadow:
      0 0 0 2px color-mix(in srgb, #e06a5f 18%, transparent),
      0 0 6px color-mix(in srgb, #e06a5f 40%, transparent);
  }

  @keyframes nav-dot-pulse {
    0%, 100% {
      box-shadow:
        0 0 0 2px color-mix(in srgb, #f0b93f 22%, transparent),
        0 0 8px color-mix(in srgb, #f0b93f 55%, transparent);
    }
    50% {
      box-shadow:
        0 0 0 4px color-mix(in srgb, #f0b93f 10%, transparent),
        0 0 14px color-mix(in srgb, #f0b93f 40%, transparent);
    }
  }
</style>
