<script lang="ts">
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import {
    getServerList,
    getConnectedServer,
    connectToServer,
    disconnectServer,
    addServer,
    removeServer,
    downloadServerMet,
  } from '$lib/api/server';
  import type { ServerInfo } from '$lib/types';
  import { onMount, untrack } from 'svelte';
  import { listen } from '@tauri-apps/api/event';

  let servers: ServerInfo[] = $state([]);
  let connectedServer: ServerInfo | null = $state(null);
  let loading = $state(true);
  let error: string | null = $state(null);
  let successMsg: string | null = $state(null);
  let confirmRemoveAll = $state(false);
  let logMessages: string[] = $state([]);

  // Add server form
  let newIp = $state('');
  let newPort = $state('4661');
  let newName = $state('');

  // Update server.met form. The default points at eMule Security's
  // curated "safe server list" — the same operator Ember already trusts
  // for ipfilter.zip (`commands/security.rs`) and nodes.dat
  // (`commands/settings.rs`). It's served over HTTPS (no MITM risk),
  // updated daily, and explicitly vetted against fake/spam servers.
  // Previously this was `http://www.gruk.org/server.met` — plain HTTP
  // and increasingly unreliable in 2026.
  let serverMetUrl = $state('https://upd.emule-security.org/server.met');
  let serverFilter = $state('');

  // Sorting — persisted to localStorage so a user who prefers
  // "Users, descending" or "Files, descending" doesn't have to re-pick
  // it every time they open the page or restart the app. Same approach
  // the library and search pages use for their filter/sort prefs.
  const SORT_PREFS_KEY = 'servers-sort-prefs';
  // Whitelist matches the columns the table renders + sorts on (see
  // `sortedServers` switch below). Any other persisted value is
  // ignored on load so a stale or hand-edited localStorage entry
  // can't break the table.
  const VALID_SORT_COLS = new Set([
    'name', 'ip', 'description', 'users', 'files', 'failed', 'static',
  ]);
  let sortCol: string = $state('name');
  let sortAsc = $state(true);
  let sortPrefsLoaded = $state(false);

  function loadSortPrefs() {
    if (typeof localStorage === 'undefined') return;
    try {
      const raw = localStorage.getItem(SORT_PREFS_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        if (typeof parsed.col === 'string' && VALID_SORT_COLS.has(parsed.col)) {
          sortCol = parsed.col;
        }
        if (typeof parsed.asc === 'boolean') {
          sortAsc = parsed.asc;
        }
      }
    } catch {
      // Corrupt entry — drop it so we don't keep failing every load.
      try { localStorage.removeItem(SORT_PREFS_KEY); } catch { /* ignore */ }
    }
  }

  // Persist whenever either field changes. Guarded by `sortPrefsLoaded`
  // so the initial defaults aren't written back over a saved value
  // before `loadSortPrefs()` has a chance to apply it.
  $effect(() => {
    void sortCol; void sortAsc;
    if (!sortPrefsLoaded || typeof localStorage === 'undefined') return;
    try {
      localStorage.setItem(SORT_PREFS_KEY, JSON.stringify({ col: sortCol, asc: sortAsc }));
    } catch { /* quota — non-fatal */ }
  });

  // Selection (multi-select support)
  let selectedServer: ServerInfo | null = $state(null);
  let selectedServers: Set<string> = $state(new Set());
  let lastClickedKey: string | null = $state(null);

  // Context menu
  let ctxMenu: { x: number; y: number; server: ServerInfo } | null = $state(null);

  let connecting = $state(false);
  let refreshInProgress = false;
  let pendingRefresh = false;
  let mounted = false;
  let logArea: HTMLDivElement | undefined = $state(undefined);

  onMount(() => {
    mounted = true;
    // Restore the user's sort choice BEFORE the first refresh paints
    // so the initial table render is already in their preferred order
    // rather than flashing the default "name asc" first.
    loadSortPrefs();
    sortPrefsLoaded = true;
    refresh();
    const interval = setInterval(refresh, 5000);

    const unlisteners: Array<() => void> = [];
    let destroyed = false;

    (async () => {
      const [u1, u2] = await Promise.all([
        listen<{ message: string }>('server-log', (event) => {
          if (!mounted) return;
          log(event.payload.message);
          requestAnimationFrame(() => {
            if (logArea) logArea.scrollTop = logArea.scrollHeight;
          });
        }),
        listen<{ status: 'connected' | 'connecting' | 'disconnected' }>('server-status-changed', (_event) => {
          if (!mounted) return;
          refresh();
        }),
      ]);
      if (destroyed) { u1(); u2(); } else { unlisteners.push(u1, u2); }
    })();

    return () => {
      mounted = false;
      destroyed = true;
      clearInterval(interval);
      clearTimeout(flashTimer);
      for (const u of unlisteners) u();
    };
  });

  function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
    return Promise.race([
      promise,
      new Promise<T>((_, reject) => setTimeout(() => reject(new Error('timeout')), ms)),
    ]);
  }

  async function refresh() {
    if (!mounted) return;
    if (refreshInProgress) {
      pendingRefresh = true;
      return;
    }
    refreshInProgress = true;
    pendingRefresh = false;
    try {
      const [list, connected] = await Promise.allSettled([
        withTimeout(getServerList(), 4000),
        withTimeout(getConnectedServer(), 4000),
      ]);
      if (!mounted) return;
      let hadFailure = false;
      if (list.status === 'fulfilled') {
        servers = list.value;
      } else {
        hadFailure = true;
      }
      if (connected.status === 'fulfilled') {
        connectedServer = connected.value;
      } else {
        hadFailure = true;
      }
      if (hadFailure) {
        error = 'Failed to refresh server state';
      } else {
        error = null;
      }
    } catch (e: unknown) {
      error = toErrorMsg(e);
    } finally {
      loading = false;
      refreshInProgress = false;
      if (pendingRefresh && mounted) {
        pendingRefresh = false;
        void refresh();
      }
    }
  }

  function toErrorMsg(e: unknown): string {
    return e instanceof Error ? e.message : typeof e === 'string' ? e : 'Operation failed';
  }

  let flashTimer: ReturnType<typeof setTimeout> | undefined;
  function flash(msg: string) {
    successMsg = msg;
    clearTimeout(flashTimer);
    flashTimer = setTimeout(() => { if (mounted) successMsg = null; }, 4000);
  }

  function log(msg: string) {
    const ts = new Date().toLocaleTimeString();
    logMessages = [...logMessages.slice(-199), `[${ts}] ${msg}`];
  }

  async function handleConnect(server?: ServerInfo) {
    const target = server || selectedServer;
    if (!target) return;
    if (connecting) return;
    if (connectedServer?.ip === target.ip && connectedServer?.port === target.port) {
      flash(`Already connected to ${target.name || target.ip}:${target.port}`);
      return;
    }
    connecting = true;
    error = null;
    try {
      if (connectedServer && (connectedServer.ip !== target.ip || connectedServer.port !== target.port)) {
        log(`Switching from ${connectedServer.ip}:${connectedServer.port} to ${target.ip}:${target.port}...`);
      }
      await connectToServer(target.ip, target.port);
    } catch (e: unknown) {
      const msg = toErrorMsg(e);
      error = msg;
      log(`Connection failed: ${msg}`);
    } finally {
      connecting = false;
    }
  }

  async function handleDisconnect() {
    error = null;
    const prev = connectedServer;
    try {
      const msg = await disconnectServer();
      log(msg);
      flash(msg);
      await refresh();
      if (!selectedServer && prev) {
        const key = serverKey(prev);
        const found = servers.find(s => serverKey(s) === key);
        if (found) {
          selectedServer = found;
          selectedServers = new Set([key]);
          lastClickedKey = key;
        }
      }
    } catch (e: unknown) {
      error = toErrorMsg(e);
    }
  }

  async function handleAddServer() {
    const ip = newIp.trim();
    const portStr = newPort.trim();
    const portNum = portStr ? parseInt(portStr, 10) : 4661;
    const name = newName.trim();

    if (!ip) {
      error = 'Server IP/address is required';
      return;
    }
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      error = 'Port must be a number between 1 and 65535';
      return;
    }
    const port = portNum;

    error = null;
    try {
      const msg = await addServer(ip, port, name);
      log(msg);
      flash(msg);
      newIp = '';
      newPort = '4661';
      newName = '';
      await refresh();
    } catch (e: unknown) {
      error = toErrorMsg(e);
    }
  }

  async function handleRemoveServer(server: ServerInfo) {
    error = null;
    try {
      const msg = await removeServer(server.ip, server.port);
      log(msg);
      flash(msg);
      const key = serverKey(server);
      if (selectedServers.has(key)) {
        const next = new Set(selectedServers);
        next.delete(key);
        selectedServers = next;
      }
      if (selectedServer?.ip === server.ip && selectedServer?.port === server.port) {
        selectedServer = null;
      }
      if (lastClickedKey === key) lastClickedKey = null;
      await refresh();
    } catch (e: unknown) {
      error = toErrorMsg(e);
    }
  }

  function handleRemoveAll() {
    confirmRemoveAll = true;
  }

  async function doRemoveAll() {
    error = null;
    const results = await Promise.allSettled(
      [...servers].map(s => removeServer(s.ip, s.port))
    );
    const removed = results.filter((r) => r.status === 'fulfilled').length;
    const failedCount = results.filter((r) => r.status === 'rejected').length;
    selectedServer = null;
    selectedServers = new Set();
    lastClickedKey = null;
    const msg = `Removed ${removed} server${removed !== 1 ? 's' : ''}`;
    log(msg);
    if (failedCount > 0) {
      error = `${msg}, ${failedCount} failed to remove`;
    } else {
      flash(msg);
    }
    await refresh();
  }

  async function handleUpdateServerMet() {
    const url = serverMetUrl.trim();
    if (!url || !url.includes('://')) {
      error = 'Please enter a valid server.met URL';
      return;
    }
    error = null;
    log(`Downloading server.met from ${url}...`);
    try {
      const result = await downloadServerMet(url);
      flash(result);
      log(result);
      await refresh();
    } catch (e: unknown) {
      const msg = toErrorMsg(e);
      error = msg;
      log(`Failed: ${msg}`);
    }
  }

  function serverKey(s: ServerInfo): string {
    return `${s.ip}:${s.port}`;
  }

  function handleDoubleClick(server: ServerInfo) {
    handleConnect(server);
  }

  function selectServer(server: ServerInfo, e: MouseEvent) {
    const key = serverKey(server);
    if (e.ctrlKey || e.metaKey) {
      const next = new Set(selectedServers);
      if (next.has(key)) next.delete(key); else next.add(key);
      selectedServers = next;
      selectedServer = next.has(key) ? server : next.size === 0 ? null : selectedServer;
      if (next.size === 0) lastClickedKey = null;
      else lastClickedKey = key;
    } else if (e.shiftKey && lastClickedKey) {
      const keys = filteredServers.map(serverKey);
      const startIdx = keys.indexOf(lastClickedKey);
      const endIdx = keys.indexOf(key);
      if (startIdx >= 0 && endIdx >= 0) {
        const lo = Math.min(startIdx, endIdx);
        const hi = Math.max(startIdx, endIdx);
        const next = new Set(selectedServers);
        for (let i = lo; i <= hi; i++) next.add(keys[i]);
        selectedServers = next;
      }
      selectedServer = server;
    } else {
      selectedServers = new Set([key]);
      selectedServer = server;
      lastClickedKey = key;
    }
  }

  function isSelected(server: ServerInfo): boolean {
    return selectedServers.has(serverKey(server));
  }

  function isConnected(server: ServerInfo): boolean {
    return connectedServer?.ip === server.ip && connectedServer?.port === server.port;
  }

  function handleContextMenu(e: MouseEvent, server: ServerInfo) {
    e.preventDefault();
    const key = serverKey(server);
    if (!selectedServers.has(key)) {
      selectedServers = new Set([key]);
      selectedServer = server;
      lastClickedKey = key;
    }
    const margin = 8;
    const x = Math.max(margin, Math.min(e.clientX, window.innerWidth - 220 - margin));
    const y = Math.max(margin, Math.min(e.clientY, window.innerHeight - 200 - margin));
    ctxMenu = { x, y, server };
  }

  function closeContextMenu() {
    ctxMenu = null;
  }

  async function ctxAction(action: string) {
    const target = ctxMenu?.server;
    closeContextMenu();
    if (action === 'connect' && target) {
      await handleConnect(target);
    } else if (action === 'disconnect') {
      await handleDisconnect();
    } else if (action === 'remove') {
      await handleRemoveSelected();
    } else if (action === 'copy_ip' && target) {
      try { await navigator.clipboard.writeText(`${target.ip}:${target.port}`); flash('Copied to clipboard'); } catch {}
    } else if (action === 'copy_ed2k' && target) {
      try { await navigator.clipboard.writeText(`ed2k://|server|${target.ip}|${target.port}|/`); flash('eD2K link copied'); } catch {}
    }
  }

  async function handleRemoveSelected() {
    error = null;
    const toRemove = servers.filter(s => selectedServers.has(serverKey(s)));
    const results = await Promise.allSettled(
      toRemove.map(s => removeServer(s.ip, s.port))
    );
    const count = results.filter((r) => r.status === 'fulfilled').length;
    selectedServers = new Set();
    selectedServer = null;
    lastClickedKey = null;
    log(`Removed ${count} server${count !== 1 ? 's' : ''}`);
    flash(`Removed ${count} server${count !== 1 ? 's' : ''}`);
    await refresh();
  }

  function toggleSort(col: string) {
    if (sortCol === col) sortAsc = !sortAsc;
    else { sortCol = col; sortAsc = true; }
  }

  function sortIndicator(col: string): string {
    if (sortCol !== col) return '';
    return sortAsc ? ' \u25B2' : ' \u25BC';
  }

  function ariaSortValue(col: string): 'ascending' | 'descending' | 'none' {
    if (sortCol !== col) return 'none';
    return sortAsc ? 'ascending' : 'descending';
  }

  function sortOnKey(e: KeyboardEvent, fn: () => void) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fn(); }
  }

  let sortedServers = $derived.by(() => {
    const sorted = [...servers];
    sorted.sort((a, b) => {
      let cmp = 0;
      switch (sortCol) {
        case 'name': cmp = a.name.localeCompare(b.name); break;
        case 'ip': {
          const pa = a.ip.split('.').map(Number);
          const pb = b.ip.split('.').map(Number);
          const aIsIPv4 = pa.length === 4 && pa.every(n => !isNaN(n));
          const bIsIPv4 = pb.length === 4 && pb.every(n => !isNaN(n));
          if (aIsIPv4 && bIsIPv4) {
            for (let i = 0; i < 4 && cmp === 0; i++) cmp = pa[i] - pb[i];
          } else {
            cmp = a.ip.localeCompare(b.ip);
          }
          if (cmp === 0) cmp = a.port - b.port;
          break;
        }
        case 'description': cmp = a.description.localeCompare(b.description); break;
        case 'users': cmp = a.user_count - b.user_count; break;
        case 'files': cmp = a.file_count - b.file_count; break;
        case 'failed': cmp = a.fail_count - b.fail_count; break;
        case 'static': cmp = Number(a.is_static) - Number(b.is_static); break;
      }
      return sortAsc ? cmp : -cmp;
    });
    return sorted;
  });

  let filteredServers = $derived.by(() => {
    const query = serverFilter.trim().toLowerCase();
    if (!query) return sortedServers;
    return sortedServers.filter((server) => {
      const target = `${server.name} ${server.ip}:${server.port} ${server.description}`.toLowerCase();
      return target.includes(query);
    });
  });

  function formatCount(n: number): string {
    if (n === 0) return '—';
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
    return n.toLocaleString();
  }

  function handleKeydownAdd(e: KeyboardEvent) {
    if (e.key === 'Enter') handleAddServer();
  }

  function handleKeydownMet(e: KeyboardEvent) {
    if (e.key === 'Enter') handleUpdateServerMet();
  }

  let selectionCount = $derived(selectedServers.size);
  let failedServerCount = $derived(servers.filter((s) => s.fail_count >= 3).length);
  let totalListedUsers = $derived(servers.reduce((sum, s) => sum + s.user_count, 0));
  let totalListedFiles = $derived(servers.reduce((sum, s) => sum + s.file_count, 0));

  async function handleManualRefresh() {
    await refresh();
    if (!error) flash('Server list refreshed');
  }

  $effect(() => {
    const validKeys = new Set(servers.map(serverKey));
    untrack(() => {
      const next = new Set([...selectedServers].filter((key) => validKeys.has(key)));
      if (next.size !== selectedServers.size) {
        selectedServers = next;
      }
      if (selectedServer && !validKeys.has(serverKey(selectedServer))) {
        selectedServer = null;
      }
      if (lastClickedKey && !validKeys.has(lastClickedKey)) {
        lastClickedKey = null;
      }
    });
  });
</script>

<svelte:document onclick={closeContextMenu} onkeydown={(e) => {
  if (e.key === 'Escape' && ctxMenu) { closeContextMenu(); e.preventDefault(); }
}} />

<div class="page-header">
  <h2>Servers</h2>
  <div class="header-actions">
    <button class="ghost" onclick={handleManualRefresh} disabled={loading}>Refresh</button>
    {#if selectionCount > 1}
      <button class="danger" onclick={handleRemoveSelected}>Remove {selectionCount} Servers</button>
    {/if}
    {#if connectedServer || connecting}
      <button class="danger" onclick={handleDisconnect}>{connecting && !connectedServer ? 'Cancel' : 'Disconnect'}</button>
    {:else if selectedServer}
      <button onclick={() => handleConnect()}>Connect</button>
    {:else}
      <button disabled>Connect</button>
    {/if}
  </div>
</div>

<div class="page-content servers-page">
  {#if error}
    <div class="banner error-banner">
      <span>{error}</span>
      <button class="ghost" onclick={() => (error = null)}>Dismiss</button>
    </div>
  {/if}
  {#if successMsg}
    <div class="banner success-banner">
      <span>{successMsg}</span>
    </div>
  {/if}

  <div class="stats-row">
    <div class="stat-card">
      <div class="label">Servers In List</div>
      <div class="value">{servers.length.toLocaleString()}</div>
    </div>
    <div class="stat-card">
      <div class="label">Connected</div>
      <div class="value">{connectedServer ? 'Yes' : connecting ? '...' : 'No'}</div>
      {#if connectedServer}
        <div class="sub">{connectedServer.name || `${connectedServer.ip}:${connectedServer.port}`}</div>
      {/if}
    </div>
    <div class="stat-card">
      <div class="label">Selected</div>
      <div class="value">{selectionCount.toLocaleString()}</div>
    </div>
    <div class="stat-card">
      <div class="label">High Failure</div>
      <div class="value">{failedServerCount.toLocaleString()}</div>
      <div class="sub">Users {formatCount(totalListedUsers)} · Files {formatCount(totalListedFiles)}</div>
    </div>
  </div>

  <div class="server-layout">
  <!-- Main area: server list (left) + side panel (right) -->
  <div class="server-upper">
    <div class="server-list-area">
      <div class="panel-toolbar">
        <span class="toolbar-label">
          Server List
          <span class="toolbar-count">
            ({filteredServers.length}{serverFilter.trim() ? ` / ${servers.length}` : ''})
          </span>
        </span>
        <div class="toolbar-actions">
          <div class="server-filter-wrap">
            <input
              type="text"
              class="server-filter-input"
              bind:value={serverFilter}
              placeholder="Filter name, IP, description..."
              aria-label="Filter servers"
            />
            {#if serverFilter}
              <button class="ghost btn-sm filter-clear" onclick={() => (serverFilter = '')} title="Clear filter">✕</button>
            {/if}
          </div>
          <button class="ghost btn-sm" onclick={handleRemoveAll} disabled={servers.length === 0}>Remove All</button>
        </div>
      </div>

      <div class="server-table-wrap">
        {#if loading && servers.length === 0}
          <div class="empty-state compact">
            <div class="spinner lg"></div>
            <p>Loading server list...</p>
          </div>
        {:else if servers.length === 0}
          <div class="empty-state compact">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="48" height="48" aria-hidden="true">
              <rect x="2" y="3" width="20" height="7" rx="1.5"></rect>
              <rect x="2" y="14" width="20" height="7" rx="1.5"></rect>
              <line x1="6" y1="6.5" x2="6.01" y2="6.5"></line>
              <line x1="6" y1="17.5" x2="6.01" y2="17.5"></line>
              <line x1="10" y1="6.5" x2="16" y2="6.5"></line>
              <line x1="10" y1="17.5" x2="16" y2="17.5"></line>
            </svg>
            <p>No servers in list</p>
            <p class="sub">Add a server using the form on the right, or download a server.met file</p>
          </div>
        {:else if filteredServers.length === 0}
          <div class="empty-state compact">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="48" height="48" aria-hidden="true">
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              <line x1="11" y1="8" x2="11" y2="14"></line>
              <line x1="8" y1="11" x2="14" y2="11"></line>
            </svg>
            <p>No servers match this filter</p>
            <p class="sub">Try a different search term or clear the filter.</p>
          </div>
        {:else}
          <table class="server-table">
            <thead>
              <tr>
                <th class="sortable" tabindex="0" role="columnheader" aria-sort={ariaSortValue('name')} onclick={() => toggleSort('name')} onkeydown={(e) => sortOnKey(e, () => toggleSort('name'))}>
                  Server Name{sortIndicator('name')}
                </th>
                <th class="sortable" tabindex="0" role="columnheader" aria-sort={ariaSortValue('ip')} onclick={() => toggleSort('ip')} onkeydown={(e) => sortOnKey(e, () => toggleSort('ip'))}>
                  IP : Port{sortIndicator('ip')}
                </th>
                <th class="sortable" tabindex="0" role="columnheader" aria-sort={ariaSortValue('description')} onclick={() => toggleSort('description')} onkeydown={(e) => sortOnKey(e, () => toggleSort('description'))}>
                  Description{sortIndicator('description')}
                </th>
                <th class="sortable num" tabindex="0" role="columnheader" aria-sort={ariaSortValue('users')} onclick={() => toggleSort('users')} onkeydown={(e) => sortOnKey(e, () => toggleSort('users'))}>
                  Users{sortIndicator('users')}
                </th>
                <th class="sortable num" tabindex="0" role="columnheader" aria-sort={ariaSortValue('files')} onclick={() => toggleSort('files')} onkeydown={(e) => sortOnKey(e, () => toggleSort('files'))}>
                  Files{sortIndicator('files')}
                </th>
                <th class="sortable num" tabindex="0" role="columnheader" aria-sort={ariaSortValue('failed')} onclick={() => toggleSort('failed')} onkeydown={(e) => sortOnKey(e, () => toggleSort('failed'))}>
                  Failed{sortIndicator('failed')}
                </th>
                <th class="sortable" tabindex="0" role="columnheader" aria-sort={ariaSortValue('static')} onclick={() => toggleSort('static')} onkeydown={(e) => sortOnKey(e, () => toggleSort('static'))}>
                  Static{sortIndicator('static')}
                </th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each filteredServers as server (`${server.ip}:${server.port}`)}
                <tr
                  class:connected={isConnected(server)}
                  class:selected={isSelected(server)}
                  class:failed-server={server.fail_count >= 3}
                  onclick={(e: MouseEvent) => selectServer(server, e)}
                  ondblclick={() => handleDoubleClick(server)}
                  oncontextmenu={(e: MouseEvent) => handleContextMenu(e, server)}
                >
                  <td class="name-cell">
                    <span class="server-icon" class:connected-icon={isConnected(server)}>S</span>
                    {server.name || '(unnamed)'}
                  </td>
                  <td class="ip-cell">{server.ip} : {server.port}</td>
                  <td class="desc-cell" title={server.description}>{server.description || '—'}</td>
                  <td class="num">{formatCount(server.user_count)}</td>
                  <td class="num">{formatCount(server.file_count)}</td>
                  <td class="num" class:fail-warn={server.fail_count > 0}>
                    {server.fail_count > 0 ? server.fail_count : '—'}
                  </td>
                  <td>{server.is_static ? 'Yes' : '—'}</td>
                  <td>
                    <button class="ghost danger btn-sm" onclick={(e: MouseEvent) => { e.stopPropagation(); handleRemoveServer(server); }} title="Remove">✕</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    </div>

    <!-- Right side panel: Add Server, server.met, My Info -->
    <div class="server-side-panel">
      <!-- Add Server -->
      <div class="side-section">
        <div class="side-title">New Server</div>
        <div class="form-stack">
          <div class="form-field">
            <label for="server-ip">IP / Address</label>
            <input
              id="server-ip"
              type="text"
              bind:value={newIp}
              placeholder="192.168.1.1"
              onkeydown={handleKeydownAdd}
            />
          </div>
          <div class="form-row">
            <div class="form-field flex-1">
              <label for="server-port">Port</label>
              <input
                id="server-port"
                type="text"
                bind:value={newPort}
                placeholder="4661"
                maxlength="5"
                onkeydown={handleKeydownAdd}
              />
            </div>
            <div class="form-field flex-2">
              <label for="server-name">Name</label>
              <input
                id="server-name"
                type="text"
                bind:value={newName}
                placeholder="(optional)"
                onkeydown={handleKeydownAdd}
              />
            </div>
          </div>
          <button class="add-btn" onclick={handleAddServer}>Add Server</button>
        </div>
      </div>

      <!-- Update server.met -->
      <div class="side-section">
        <div class="side-title">Update server.met</div>
        <div class="form-stack">
          <div class="form-field">
            <label for="met-url">URL</label>
            <input
              id="met-url"
              type="text"
              bind:value={serverMetUrl}
              placeholder="https://upd.emule-security.org/server.met"
              onkeydown={handleKeydownMet}
            />
          </div>
          <button class="add-btn" onclick={handleUpdateServerMet}>Update</button>
        </div>
      </div>

      <!-- My Info / Connected Server -->
      <div class="side-section info-section">
        <div class="side-title">My Info</div>
        <div class="info-rows">
          {#if connectedServer}
            <div class="info-row">
              <span class="info-label">Status</span>
              <span class="badge connected">Connected</span>
            </div>
            <div class="info-row">
              <span class="info-label">Server</span>
              <span class="info-value">{connectedServer.name || connectedServer.ip}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Address</span>
              <span class="info-value mono">{connectedServer.ip}:{connectedServer.port}</span>
            </div>
            <div class="info-row">
              <span class="info-label">eD2K ID</span>
              <span class="info-value">
                {#if connectedServer.client_id}
                  <span class="mono">{connectedServer.client_id}</span>
                  {#if connectedServer.is_low_id}
                    <span class="badge lowid">LowID</span>
                  {:else}
                    <span class="badge highid">HighID</span>
                  {/if}
                {:else}
                  <span class="muted">Pending...</span>
                {/if}
              </span>
            </div>
            <div class="info-row">
              <span class="info-label">Users</span>
              <span class="info-value">{connectedServer.user_count.toLocaleString()}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Files</span>
              <span class="info-value">{connectedServer.file_count.toLocaleString()}</span>
            </div>
          {:else if connecting}
            <div class="info-row">
              <span class="info-label">Status</span>
              <span class="badge connecting"><span class="connect-spinner"></span> Connecting</span>
            </div>
            <div class="info-row muted">
              <span>Establishing connection...</span>
            </div>
          {:else}
            <div class="info-row">
              <span class="info-label">Status</span>
              <span class="badge disconnected">Disconnected</span>
            </div>
            <div class="info-row muted">
              <span>Not connected to any eD2K server</span>
            </div>
          {/if}
        </div>
      </div>
    </div>
  </div>

  <!-- Bottom: Server log messages -->
  <div class="server-lower">
    <div class="log-toolbar">
      <span class="toolbar-label">Server Log</span>
      <button class="ghost btn-sm" onclick={() => (logMessages = [])}>Clear</button>
    </div>
    <div class="log-area" bind:this={logArea}>
      {#if logMessages.length === 0}
        <span class="log-placeholder">Server messages will appear here...</span>
      {:else}
        {#each logMessages as msg (msg)}
          <div class="log-line">{msg}</div>
        {/each}
      {/if}
    </div>
  </div>
</div>
</div>

{#if ctxMenu}
  <div class="context-menu" style="left: {ctxMenu.x}px; top: {ctxMenu.y}px;">
    {#if !isConnected(ctxMenu.server)}
      <button class="ctx-item" onclick={() => ctxAction('connect')}>Connect</button>
    {:else}
      <button class="ctx-item" onclick={() => ctxAction('disconnect')}>Disconnect</button>
    {/if}
    <div class="ctx-sep"></div>
    <button class="ctx-item danger" onclick={() => ctxAction('remove')}>
      {selectionCount > 1 ? `Remove ${selectionCount} Servers` : 'Remove Server'}
    </button>
    <div class="ctx-sep"></div>
    <button class="ctx-item" onclick={() => ctxAction('copy_ip')}>Copy IP:Port</button>
    <button class="ctx-item" onclick={() => ctxAction('copy_ed2k')}>Copy eD2K Link</button>
  </div>
{/if}

<ConfirmDialog
  bind:open={confirmRemoveAll}
  title="Remove All Servers"
  message="Remove all {servers.length} servers from the list? This cannot be undone."
  confirmLabel="Remove All"
  danger={true}
  onconfirm={doRemoveAll}
/>

<style>
  .header-actions {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 20px;
    font-size: 13px;
  }

  .error-banner {
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--danger);
    color: var(--danger);
  }

  .success-banner {
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--success);
    color: var(--success);
  }

  .server-layout {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .server-upper {
    display: flex;
    flex: 1;
    min-height: 0;
    border-bottom: 1px solid var(--border);
  }

  .server-list-area {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    border-right: 1px solid var(--border);
  }

  .panel-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0;
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
    flex-shrink: 0;
  }

  .toolbar-label {
    padding: 8px 16px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-secondary);
  }

  .toolbar-actions {
    display: flex;
    gap: 8px;
    padding-right: 8px;
    align-items: center;
  }

  .btn-sm {
    padding: 3px 10px;
    font-size: 12px;
  }

  .toolbar-count {
    color: var(--text-muted);
    font-weight: 500;
    margin-left: 2px;
  }

  .server-filter-wrap {
    display: flex;
    align-items: center;
    min-width: 240px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md, 8px);
    background: var(--bg-input, var(--bg-surface));
    overflow: hidden;
    transition: border-color 0.15s ease;
  }

  .server-filter-wrap:focus-within {
    border-color: var(--accent);
  }

  .server-filter-input {
    width: 100%;
    border: none;
    outline: none;
    background: transparent;
    font-size: 12px;
    padding: 6px 8px;
    color: var(--text-primary);
  }

  .filter-clear {
    border-radius: 0;
    padding: 4px 9px;
  }

  .server-table-wrap {
    flex: 1;
    overflow: auto;
    min-height: 0;
  }

  .server-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }

  .server-table th {
    padding: 6px 10px;
    font-size: 11px;
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
  }

  .server-table td {
    padding: 5px 10px;
    font-size: 12px;
    cursor: default;
    /* Global app.css adds td border-bottom; keep only the header row line */
    border-bottom: none;
  }

  /* Separate Name/IP columns with spacing instead of a divider line */
  .server-table th:first-child,
  .server-table td.name-cell {
    padding-right: 16px;
  }

  .server-table th:nth-child(2),
  .server-table td.ip-cell {
    padding-left: 14px;
  }

  .server-table th.num,
  .server-table td.num {
    text-align: right;
  }

  .server-table tbody tr {
    transition: background 0.1s;
  }

  .server-table tbody tr:hover {
    background: var(--bg-hover);
  }

  .server-table tbody tr:nth-child(even):not(.selected):not(.connected) {
    background: color-mix(in srgb, var(--bg-secondary) 84%, var(--bg-primary));
  }

  .server-table tbody tr.selected {
    background: color-mix(in srgb, var(--accent-dim) 72%, transparent);
  }

  .server-table tbody tr.connected td {
    color: var(--accent);
    font-weight: 500;
  }

  .server-table tbody tr.failed-server {
    opacity: 0.5;
  }

  .name-cell {
    display: flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
  }

  .server-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    border-radius: 3px;
    background: var(--bg-tertiary);
    color: var(--text-muted);
    font-size: 10px;
    font-weight: 700;
    flex-shrink: 0;
  }

  .server-icon.connected-icon {
    background: var(--accent);
    color: #fff;
  }

  .ip-cell {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
    white-space: nowrap;
  }

  .desc-cell {
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-secondary);
  }

  .fail-warn {
    color: var(--danger);
    font-weight: 600;
  }

  /* Side panel */
  .server-side-panel {
    width: 300px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
  }

  .side-section {
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
  }

  .side-title {
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    margin-bottom: 10px;
  }

  .form-stack {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .form-field label {
    font-size: 11px;
    color: var(--text-muted);
    font-weight: 500;
  }

  .form-field input {
    font-size: 12px;
    padding: 5px 8px;
  }

  .form-row {
    display: flex;
    gap: 8px;
  }

  .flex-1 { flex: 1; }
  .flex-2 { flex: 2; }

  .add-btn {
    align-self: flex-end;
    font-size: 12px;
    padding: 5px 16px;
  }

  .info-section {
    flex: 1;
  }

  .info-rows {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .info-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 12px;
    padding: 2px 0;
  }

  .info-row.muted {
    justify-content: flex-start;
    color: var(--text-muted);
    font-style: italic;
    padding: 8px 0;
  }

  .info-label {
    color: var(--text-muted);
    font-weight: 500;
  }

  .info-value {
    color: var(--text-primary);
    font-weight: 600;
  }

  .info-value.mono {
    font-family: var(--font-mono);
    font-size: 11px;
  }

  /* Bottom log area */
  .server-lower {
    flex: 0 0 auto;
    max-height: 30%;
    min-height: 100px;
    display: flex;
    flex-direction: column;
  }

  .log-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .log-area {
    flex: 1;
    overflow-y: auto;
    padding: 8px 16px;
    font-family: var(--font-mono);
    font-size: 11px;
    background: var(--bg-primary);
    min-height: 0;
  }

  .log-placeholder {
    color: var(--text-muted);
    font-style: italic;
  }

  .log-line {
    color: var(--text-secondary);
    padding: 1px 0;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .icon-lg {
    font-size: 40px;
    font-weight: 800;
    color: var(--text-muted);
    opacity: 0.2;
  }

  .empty-state.compact {
    padding: 40px 16px;
  }

  .empty-state.compact p {
    font-size: 13px;
  }

  .sub {
    font-size: 12px;
    color: var(--text-muted);
  }

  /* Context menu */
  .context-menu {
    position: fixed;
    z-index: 1000;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-md, 6px);
    box-shadow: var(--shadow-lg, 0 4px 12px rgba(0,0,0,0.15));
    padding: 4px 0;
    min-width: 180px;
  }

  .ctx-item {
    display: block;
    width: 100%;
    text-align: left;
    padding: 6px 14px;
    font-size: 12px;
    background: none;
    border: none;
    color: var(--text-primary);
    cursor: pointer;
    white-space: nowrap;
  }

  .ctx-item:hover {
    background: var(--bg-hover);
  }

  .ctx-item.danger {
    color: var(--danger, #e74c3c);
  }

  .ctx-sep {
    height: 1px;
    background: var(--border);
    margin: 3px 0;
  }

  .connect-spinner {
    display: inline-block;
    width: 10px;
    height: 10px;
    border: 2px solid var(--border);
    border-top-color: var(--accent, #3498db);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    vertical-align: middle;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
  }

  .badge.connected {
    background: rgba(46, 204, 113, 0.15);
    color: #2ecc71;
  }

  .badge.connecting {
    background: rgba(52, 152, 219, 0.15);
    color: var(--accent, #3498db);
  }

  .badge.disconnected {
    background: rgba(200, 200, 200, 0.1);
    color: var(--text-muted);
  }

  .badge.lowid {
    background: rgba(231, 76, 60, 0.15);
    color: #e74c3c;
    font-size: 10px;
    padding: 1px 6px;
  }

  .badge.highid {
    background: rgba(46, 204, 113, 0.15);
    color: #2ecc71;
    font-size: 10px;
    padding: 1px 6px;
  }

  .servers-page {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: 12px 16px 14px;
    overflow: auto;
  }

  .stats-row {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
  }

  .stats-row .stat-card {
    min-width: 0;
    padding: 12px 14px;
  }

  .stats-row .stat-card .value {
    font-size: 20px;
    line-height: 1.15;
  }

  .stats-row .stat-card {
    border: 1px solid color-mix(in srgb, var(--border) 85%, transparent);
    background: linear-gradient(
      180deg,
      color-mix(in srgb, var(--bg-surface) 86%, transparent),
      color-mix(in srgb, var(--bg-secondary) 92%, transparent)
    );
  }

  .stats-row .stat-card .sub {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .server-layout {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-sm);
    min-height: 540px;
  }

  .panel-toolbar,
  .log-toolbar {
    background: var(--bg-surface);
  }

  .side-section {
    padding: 16px;
  }

  .side-title {
    margin-bottom: 12px;
  }

  .form-field label {
    font-size: 12px;
  }

  .form-field input {
    padding: 7px 10px;
  }

  .server-table td {
    padding-top: 7px;
    padding-bottom: 7px;
  }

  .log-area {
    background: color-mix(in srgb, var(--bg-primary) 70%, var(--bg-secondary));
  }

  @media (max-width: 1200px) {
    .stats-row {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }

  @media (max-width: 980px) {
    .servers-page {
      padding: 10px 12px 12px;
    }

    .server-upper {
      flex-direction: column;
    }

    .server-list-area {
      border-right: 0;
      border-bottom: 1px solid var(--border);
      min-height: 300px;
    }

    .server-side-panel {
      width: 100%;
      max-height: 42vh;
      flex-direction: row;
      overflow: auto;
    }

    .side-section {
      min-width: 280px;
      border-bottom: 0;
      border-right: 1px solid var(--border);
    }

    .toolbar-actions {
      width: 100%;
      justify-content: space-between;
      padding: 6px 8px;
    }

    .server-filter-wrap {
      min-width: 180px;
      flex: 1;
    }
  }

  @media (max-width: 720px) {
    .page-header {
      align-items: flex-start;
      gap: 10px;
      flex-direction: column;
    }

    .header-actions {
      width: 100%;
      flex-wrap: wrap;
    }

    .stats-row {
      grid-template-columns: 1fr;
    }

    .server-lower {
      max-height: 220px;
    }
  }
</style>
