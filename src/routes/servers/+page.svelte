<script lang="ts">
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
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';

  let servers: ServerInfo[] = $state([]);
  let connectedServer: ServerInfo | null = $state(null);
  let loading = $state(true);
  let error: string | null = $state(null);
  let successMsg: string | null = $state(null);
  let logMessages: string[] = $state([]);

  // Add server form
  let newIp = $state('');
  let newPort = $state('4661');
  let newName = $state('');

  // Update server.met form
  let serverMetUrl = $state('http://www.gruk.org/server.met');

  // Sorting
  let sortCol: string = $state('name');
  let sortAsc = $state(true);

  // Selection (multi-select support)
  let selectedServer: ServerInfo | null = $state(null);
  let selectedServers: Set<string> = $state(new Set());
  let lastClickedKey: string | null = $state(null);

  // Context menu
  let ctxMenu: { x: number; y: number; server: ServerInfo } | null = $state(null);

  let connecting = $state(false);
  let refreshInProgress = false;
  let mounted = true;
  let logArea: HTMLDivElement | undefined = $state(undefined);

  onMount(() => {
    refresh();
    const interval = setInterval(refresh, 5000);

    const unlisteners: Array<() => void> = [];

    (async () => {
      unlisteners.push(await listen<{ message: string }>('server-log', (event) => {
        if (!mounted) return;
        log(event.payload.message);
        requestAnimationFrame(() => {
          if (logArea) logArea.scrollTop = logArea.scrollHeight;
        });
      }));

      unlisteners.push(await listen<{ connected: boolean }>('server-status-changed', (event) => {
        if (!mounted) return;
        if (!event.payload.connected) connecting = false;
        refresh();
      }));
    })();

    return () => {
      mounted = false;
      clearInterval(interval);
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
    if (refreshInProgress || !mounted) return;
    refreshInProgress = true;
    try {
      const [list, connected] = await Promise.allSettled([
        withTimeout(getServerList(), 4000),
        withTimeout(getConnectedServer(), 4000),
      ]);
      if (!mounted) return;
      if (list.status === 'fulfilled') servers = list.value;
      if (connected.status === 'fulfilled') connectedServer = connected.value;
    } catch (e: unknown) {
      if (servers.length === 0) {
        error = toErrorMsg(e);
      }
    } finally {
      loading = false;
      refreshInProgress = false;
    }
  }

  function toErrorMsg(e: unknown): string {
    return e instanceof Error ? e.message : typeof e === 'string' ? e : 'Operation failed';
  }

  function flash(msg: string) {
    successMsg = msg;
    setTimeout(() => (successMsg = null), 4000);
  }

  function log(msg: string) {
    const ts = new Date().toLocaleTimeString();
    logMessages = [...logMessages.slice(-199), `[${ts}] ${msg}`];
  }

  async function handleConnect(server?: ServerInfo) {
    const target = server || selectedServer;
    if (!target) return;
    connecting = true;
    error = null;
    try {
      await connectToServer(target.ip, target.port);
    } catch (e: unknown) {
      const msg = toErrorMsg(e);
      error = msg;
      log(`Connection failed: ${msg}`);
      connecting = false;
    }
  }

  async function handleDisconnect() {
    error = null;
    try {
      const msg = await disconnectServer();
      log(msg);
      flash(msg);
      await refresh();
    } catch (e: unknown) {
      error = toErrorMsg(e);
    }
  }

  async function handleAddServer() {
    const ip = newIp.trim();
    const port = parseInt(newPort.trim()) || 4661;
    const name = newName.trim();

    if (!ip) {
      error = 'Server IP/address is required';
      return;
    }

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
      if (selectedServer?.ip === server.ip && selectedServer?.port === server.port) {
        selectedServer = null;
      }
      await refresh();
    } catch (e: unknown) {
      error = toErrorMsg(e);
    }
  }

  async function handleRemoveAll() {
    error = null;
    await Promise.allSettled(
      [...servers].map(s => removeServer(s.ip, s.port))
    );
    selectedServer = null;
    log('Removed all servers');
    flash('Removed all servers');
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
      const msg = String(e);
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
      selectedServer = server;
      lastClickedKey = key;
    } else if (e.shiftKey && lastClickedKey) {
      const keys = sortedServers.map(serverKey);
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
    ctxMenu = { x: e.clientX, y: e.clientY, server };
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
    await Promise.allSettled(
      toRemove.map(s => removeServer(s.ip, s.port))
    );
    const count = toRemove.length;
    selectedServers = new Set();
    selectedServer = null;
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

  let sortedServers = $derived.by(() => {
    const sorted = [...servers];
    sorted.sort((a, b) => {
      let cmp = 0;
      switch (sortCol) {
        case 'name': cmp = a.name.localeCompare(b.name); break;
        case 'ip': cmp = a.ip.localeCompare(b.ip) || a.port - b.port; break;
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

  let connectButtonLabel = $derived(connectedServer ? 'Disconnect' : 'Connect');
  let selectionCount = $derived(selectedServers.size);
</script>

<svelte:document onclick={closeContextMenu} />

<div class="page-header">
  <h2>Servers</h2>
  <div class="header-actions">
    {#if selectionCount > 1}
      <button class="danger" onclick={handleRemoveSelected}>Remove {selectionCount} Servers</button>
    {/if}
    {#if connectedServer}
      <button class="danger" onclick={handleDisconnect}>Disconnect</button>
    {:else if selectedServer}
      <button onclick={() => handleConnect()} disabled={connecting}>
        {#if connecting}<span class="connect-spinner"></span>{/if}
        {connecting ? 'Connecting...' : 'Connect'}
      </button>
    {:else}
      <button disabled>Connect</button>
    {/if}
  </div>
</div>

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

<div class="server-layout">
  <!-- Main area: server list (left) + side panel (right) -->
  <div class="server-upper">
    <div class="server-list-area">
      <div class="panel-toolbar">
        <span class="toolbar-label">Server List ({servers.length})</span>
        <div class="toolbar-actions">
          <button class="ghost btn-sm" onclick={handleRemoveAll} disabled={servers.length === 0}>Remove All</button>
        </div>
      </div>

      <div class="server-table-wrap">
        {#if loading && servers.length === 0}
          <div class="empty-state compact">
            <p>Loading server list...</p>
          </div>
        {:else if servers.length === 0}
          <div class="empty-state compact">
            <div class="icon-lg">⬡</div>
            <p>No servers in list</p>
            <p class="sub">Add a server using the form on the right, or download a server.met file</p>
          </div>
        {:else}
          <table class="server-table">
            <thead>
              <tr>
                <th class="sortable" onclick={() => toggleSort('name')}>
                  Server Name{sortIndicator('name')}
                </th>
                <th class="sortable" onclick={() => toggleSort('ip')}>
                  IP : Port{sortIndicator('ip')}
                </th>
                <th class="sortable" onclick={() => toggleSort('description')}>
                  Description{sortIndicator('description')}
                </th>
                <th class="sortable num" onclick={() => toggleSort('users')}>
                  Users{sortIndicator('users')}
                </th>
                <th class="sortable num" onclick={() => toggleSort('files')}>
                  Files{sortIndicator('files')}
                </th>
                <th class="sortable num" onclick={() => toggleSort('failed')}>
                  Failed{sortIndicator('failed')}
                </th>
                <th class="sortable" onclick={() => toggleSort('static')}>
                  Static{sortIndicator('static')}
                </th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each sortedServers as server (`${server.ip}:${server.port}`)}
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
              placeholder="http://www.gruk.org/server.met"
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
        {#each logMessages as msg}
          <div class="log-line">{msg}</div>
        {/each}
      {/if}
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
    gap: 4px;
    padding-right: 8px;
  }

  .btn-sm {
    padding: 3px 10px;
    font-size: 12px;
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
  }

  .server-table td {
    padding: 5px 10px;
    font-size: 12px;
    cursor: default;
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

  .server-table tbody tr.selected {
    background: var(--accent-dim);
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
</style>
