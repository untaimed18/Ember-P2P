<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';

  const navItems = [
    { href: '/', label: 'KAD Network', id: 'kad' },
    { href: '/servers', label: 'Servers', id: 'servers' },
    { href: '/search', label: 'Search', id: 'search' },
    { href: '/transfers', label: 'Transfers', id: 'transfers' },
    { href: '/library', label: 'Library', id: 'library' },
    { href: '/statistics', label: 'Statistics', id: 'statistics' },
    { href: '/security', label: 'Security', id: 'security' },
    { href: '/settings', label: 'Settings', id: 'settings' },
  ];

  function navigate(e: MouseEvent, href: string) {
    e.preventDefault();
    if ($page.url.pathname === href) return;
    goto(href).catch(() => {
      window.location.href = href;
    });
  }
</script>

<nav class="sidebar">
  <div class="logo">
    <span class="logo-text">NEXUS</span>
    <span class="logo-sub">eMule KAD Network</span>
  </div>

  <ul class="nav-list">
    {#each navItems as item}
      <li>
        <a
          href={item.href}
          class:active={$page.url.pathname === item.href}
          aria-current={$page.url.pathname === item.href ? 'page' : undefined}
          onclick={(e: MouseEvent) => navigate(e, item.href)}
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
        </a>
      </li>
    {/each}
  </ul>
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
  }

  .nav-list li a {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 16px;
    color: var(--text-secondary);
    text-decoration: none;
    transition: all 0.15s;
    font-size: 14px;
  }

  .nav-list li a:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .nav-list li a.active {
    background: var(--bg-tertiary);
    color: var(--accent);
    border-right: 3px solid var(--accent);
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
</style>
