<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';

  const navItems = [
    { href: '/', label: 'KAD Network', icon: '⊛' },
    { href: '/servers', label: 'Servers', icon: '⊞' },
    { href: '/search', label: 'Search', icon: '⌕' },
    { href: '/transfers', label: 'Transfers', icon: '⇅' },
    { href: '/sharing', label: 'Sharing', icon: '⊕' },
    { href: '/statistics', label: 'Statistics', icon: '📊' },
    { href: '/security', label: 'Security', icon: '🛡' },
    { href: '/settings', label: 'Settings', icon: '⚙' },
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
          <span class="nav-icon" aria-hidden="true">{item.icon}</span>
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
    gap: 10px;
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
    font-size: 16px;
    width: 24px;
    text-align: center;
  }
</style>
