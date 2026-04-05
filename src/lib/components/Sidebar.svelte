<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import AboutDialog from '$lib/components/AboutDialog.svelte';
  import { transfers } from '$lib/stores/transfers';
  import { networkStats } from '$lib/stores/network';

  let aboutOpen = $state(false);

  let activeDownloadCount = $derived(
    $transfers.filter(t => t.direction === 'download' && t.status !== 'completed' && t.status !== 'failed').length
  );

  const navItems = [
    { href: '/', label: 'KAD Network', id: 'kad', aliases: ['/kad-network'] },
    { href: '/search', label: 'Search', id: 'search' },
    { href: '/transfers', label: 'Transfers', id: 'transfers' },
    { href: '/library', label: 'Library', id: 'library' },
    { href: '/friends', label: 'Friends', id: 'friends' },
    { href: '/statistics', label: 'Statistics', id: 'statistics' },
    { href: '/servers', label: 'Servers', id: 'servers' },
    { href: '/security', label: 'Security', id: 'security' },
    { href: '/settings', label: 'Settings', id: 'settings' },
  ];

  function isActive(item: typeof navItems[0], pathname: string): boolean {
    return pathname === item.href || (item.aliases?.some((a) => pathname === a) ?? false);
  }

  function navigate(e: MouseEvent, href: string) {
    e.preventDefault();
    if ($page.url.pathname === href) return;
    goto(href).catch(() => {
      window.location.href = href;
    });
  }
</script>

<nav class="sidebar" aria-label="Primary">
  <a href="/" class="logo" onclick={(e) => navigate(e, '/')} title="Go to KAD Network home">
    <span class="logo-text">EMBER</span>
    <span class="logo-sub">P2P File Sharing</span>
  </a>

  <ul class="nav-list">
    {#each navItems as item}
      <li>
        <a
          href={item.href}
          class:active={isActive(item, $page.url.pathname)}
          aria-current={isActive(item, $page.url.pathname) ? 'page' : undefined}
          onclick={(e: MouseEvent) => navigate(e, item.href)}
          title={item.label}
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
                <rect x="3" y="2" width="14" height="5" rx="1"/>
                <rect x="3" y="9" width="14" height="5" rx="1"/>
                <circle cx="6" cy="4.5" r="0.75" fill="currentColor" stroke="none"/>
                <circle cx="6" cy="11.5" r="0.75" fill="currentColor" stroke="none"/>
                <line x1="10" y1="16" x2="10" y2="18"/>
                <line x1="7" y1="18" x2="13" y2="18"/>
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
          <span class="nav-label">{item.label}</span>
          {#if item.id === 'kad'}
            <span class="nav-dot {$networkStats.status}" title="{$networkStats.status}"></span>
          {/if}
          {#if item.id === 'transfers' && activeDownloadCount > 0}
            <span class="nav-badge">{activeDownloadCount}</span>
          {/if}
        </a>
      </li>
    {/each}
  </ul>

  <div class="sidebar-footer">
    <button type="button" class="about-btn" onclick={() => (aboutOpen = true)} title="About Ember">
      <span class="about-icon" aria-hidden="true">
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="10" cy="10" r="7.5"/>
          <line x1="10" y1="9" x2="10" y2="14"/>
          <circle cx="10" cy="6" r="1" fill="currentColor" stroke="none"/>
        </svg>
      </span>
      <span>About</span>
    </button>
  </div>

  <AboutDialog bind:open={aboutOpen} />
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
  }

  .logo {
    padding: 20px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    text-decoration: none;
    cursor: pointer;
  }

  .logo-text {
    font-size: 22px;
    font-weight: 800;
    letter-spacing: 3px;
    color: var(--accent);
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
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 16px;
    color: var(--text-secondary);
    text-decoration: none;
    transition: background-color var(--transition-normal), color var(--transition-normal), border-color var(--transition-normal);
    font-size: 14px;
    border-left: 3px solid transparent;
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
    border-left-color: var(--accent);
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

  .nav-dot {
    margin-left: auto;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
    background: var(--text-muted);
  }

  .nav-dot.connected {
    background: #22c55e;
    box-shadow: 0 0 4px #22c55e80;
  }

  .nav-dot.connecting {
    background: #eab308;
    box-shadow: 0 0 4px #eab30880;
  }

  .nav-dot.disconnected {
    background: #ef4444;
    box-shadow: 0 0 3px #ef444460;
  }
</style>
