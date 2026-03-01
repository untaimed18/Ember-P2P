<script lang="ts">
  import {
    kadConnect,
    kadDisconnect,
    kadBootstrapIp,
    kadBootstrapUrl,
    kadBootstrapClients,
    kadRecheckFirewall,
    getKadContacts,
    getKadSearches,
  } from '$lib/api/kad';
  import { networkStats } from '$lib/stores/network';
  import type { KadContact, KadSearchEntry } from '$lib/types';
  import { onMount } from 'svelte';

  let contacts: KadContact[] = $state([]);
  let searches: KadSearchEntry[] = $state([]);
  let loading = $state(true);
  let kadError: string | null = $state(null);

  let bootstrapMode: 'ip' | 'url' | 'clients' = $state('clients');
  let bootstrapIp = $state('');
  let bootstrapPort = $state('');
  let bootstrapUrl = $state('');
  let bootstrapping = $state(false);

  let contactSortCol: 'id' | 'type' | 'distance' = $state('type');
  let contactSortAsc = $state(true);
  let searchSortCol: string = $state('id');
  let searchSortAsc = $state(true);

  let contactPage = $state(0);
  const CONTACTS_PER_PAGE = 200;

  let refreshInProgress = false;
  let mounted = true;

  onMount(() => {
    mounted = true;
    refreshInProgress = false;
    loading = true;
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  });

  $effect(() => {
    if (!loading) return;
    const safety = setTimeout(() => { loading = false; }, 6000);
    return () => clearTimeout(safety);
  });

  function arraysEqual(a: KadContact[], b: KadContact[]): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i].id !== b[i].id || a[i].type !== b[i].type) return false;
    }
    return true;
  }

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
      const [c, s] = await Promise.allSettled([
        withTimeout(getKadContacts(), 4000),
        withTimeout(getKadSearches(), 4000),
      ]);
      if (!mounted) return;

      if (c.status === 'fulfilled' && !arraysEqual(contacts, c.value)) {
        contacts = c.value;
      }
      if (s.status === 'fulfilled') {
        if (searches.length !== s.value.length ||
            searches.some((v, i) => v.id !== s.value[i].id || v.responses !== s.value[i].responses)) {
          searches = s.value;
        }
      }

      if (c.status === 'rejected' || s.status === 'rejected') {
        const raw = c.status === 'rejected' ? (c as PromiseRejectedResult).reason : (s as PromiseRejectedResult).reason;
        const msg = raw instanceof Error ? raw.message : String(raw);
        if (msg !== 'timeout' && contacts.length === 0) {
          kadError = msg;
        }
      } else {
        kadError = null;
      }
    } finally {
      loading = false;
      refreshInProgress = false;
    }
  }

  async function handleConnect() {
    kadError = null;
    try {
      if ($networkStats.status === 'connected' || $networkStats.status === 'connecting') {
        await kadDisconnect();
      } else {
        await kadConnect();
      }
      await refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Connection failed';
      kadError = msg;
    }
  }

  async function handleRecheckFirewall() {
    kadError = null;
    try {
      await kadRecheckFirewall();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Firewall recheck failed';
      kadError = msg;
    }
  }

  async function handleBootstrap() {
    kadError = null;
    bootstrapping = true;
    try {
      if (bootstrapMode === 'ip') {
        let ip = bootstrapIp.trim();
        let port = parseInt(bootstrapPort.trim());
        const colonIdx = ip.indexOf(':');
        if (colonIdx >= 0 && !bootstrapPort.trim()) {
          port = parseInt(ip.substring(colonIdx + 1));
          ip = ip.substring(0, colonIdx);
        }
        if (!ip || ip.length < 7 || !port || port <= 0) {
          kadError = 'Please enter a valid IP address and port';
          return;
        }
        await kadBootstrapIp(ip, port);
      } else if (bootstrapMode === 'url') {
        if (!bootstrapUrl.trim() || !bootstrapUrl.includes('://')) {
          kadError = 'Please enter a valid URL';
          return;
        }
        await kadBootstrapUrl(bootstrapUrl.trim());
      } else {
        await kadBootstrapClients();
      }
      await refresh();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Bootstrap failed';
      kadError = msg;
    } finally {
      bootstrapping = false;
    }
  }

  function getConnectButtonLabel(): string {
    if ($networkStats.status === 'connected') return 'Disconnect';
    if ($networkStats.status === 'connecting') return 'Cancel';
    return 'Connect';
  }

  function getContactTypeLabel(contact: KadContact): string {
    if (contact.bootstrap) return 'Bootstrap';
    const v = contact.version ? `(${contact.version})` : '';
    if (contact.type === 0) return `0${v}`;
    if (contact.type === 1) return `1${v}`;
    if (contact.type === 2) return `2${v}`;
    if (contact.type === 3) return `3${v}`;
    if (contact.type === 4) return `4${v}`;
    return `${contact.type}${v}`;
  }

  let sortedContacts = $derived.by(() => {
    const sorted = [...contacts];
    sorted.sort((a, b) => {
      let cmp = 0;
      if (contactSortCol === 'id') cmp = a.id.localeCompare(b.id);
      else if (contactSortCol === 'type') {
        cmp = a.type - b.type;
        if (cmp === 0) cmp = a.version - b.version;
      }
      else if (contactSortCol === 'distance') cmp = a.distance.localeCompare(b.distance);
      return contactSortAsc ? cmp : -cmp;
    });
    const start = contactPage * CONTACTS_PER_PAGE;
    return sorted.slice(start, start + CONTACTS_PER_PAGE);
  });

  let totalContactPages = $derived(Math.max(1, Math.ceil(contacts.length / CONTACTS_PER_PAGE)));

  let sortedSearches = $derived.by(() => {
    const sorted = [...searches];
    sorted.sort((a, b) => {
      let cmp = 0;
      if (searchSortCol === 'id') cmp = a.id - b.id;
      else if (searchSortCol === 'target') cmp = a.target.localeCompare(b.target);
      else if (searchSortCol === 'type') cmp = a.type.localeCompare(b.type);
      else if (searchSortCol === 'name') cmp = a.name.localeCompare(b.name);
      else if (searchSortCol === 'status') cmp = a.status.localeCompare(b.status);
      else if (searchSortCol === 'load') cmp = a.load - b.load;
      else if (searchSortCol === 'packets_sent') cmp = a.packets_sent - b.packets_sent;
      else if (searchSortCol === 'responses') cmp = a.responses - b.responses;
      return searchSortAsc ? cmp : -cmp;
    });
    return sorted;
  });

  function sortContacts(col: 'id' | 'type' | 'distance') {
    if (contactSortCol === col) contactSortAsc = !contactSortAsc;
    else { contactSortCol = col; contactSortAsc = true; }
  }

  function sortSearches(col: string) {
    if (searchSortCol === col) searchSortAsc = !searchSortAsc;
    else { searchSortCol = col; searchSortAsc = true; }
  }

  function getSortArrow(current: string, col: string, asc: boolean): string {
    if (current !== col) return '';
    return asc ? ' \u25B2' : ' \u25BC';
  }

  let isConnected = $derived($networkStats.status === 'connected');
  let isBootstrapDisabled = $derived.by(() => {
    if (isConnected || bootstrapping) return true;
    const mode: string = bootstrapMode;
    if (mode === 'ip' && !bootstrapIp.trim()) return true;
    if (mode === 'url' && !bootstrapUrl.trim()) return true;
    return false;
  });
</script>

<div class="page-header">
  <h2>KAD Network</h2>
  <div class="header-actions">
    <button
      class="ghost"
      onclick={handleRecheckFirewall}
      disabled={!isConnected}
      title="Recheck Firewall"
    >
      Recheck Firewall
    </button>
    <button
      class={$networkStats.status === 'connected' ? 'danger' : ''}
      onclick={handleConnect}
    >
      {getConnectButtonLabel()}
    </button>
  </div>
</div>

{#if kadError}
  <div class="error-banner">
    <span>{kadError}</span>
    <button class="ghost" onclick={() => kadError = null}>Dismiss</button>
  </div>
{/if}

<div class="kad-layout">
  <!-- Upper: Contacts list + Bootstrap/Status panel (matches eMule layout) -->
  <div class="kad-upper">
    <div class="kad-upper-left">
      <div class="panel-toolbar">
        <span class="toolbar-label">Contacts ({contacts.length})</span>
        {#if totalContactPages > 1}
          <div class="pager">
            <button class="pager-btn" disabled={contactPage === 0} onclick={() => contactPage--}>&lt;</button>
            <span class="pager-info">{contactPage + 1}/{totalContactPages}</span>
            <button class="pager-btn" disabled={contactPage >= totalContactPages - 1} onclick={() => contactPage++}>&gt;</button>
          </div>
        {/if}
      </div>

      <div class="panel-content scrollable">
        {#if loading}
          <div class="empty-state compact">
            <p>Loading contacts...</p>
          </div>
        {:else if contacts.length === 0}
          <div class="empty-state compact">
            <p>No KAD contacts</p>
            <p class="sub">Connect to the KAD network or bootstrap to populate contacts</p>
          </div>
        {:else}
          <table class="compact-table">
            <thead>
              <tr>
                <th class="sortable" onclick={() => sortContacts('id')}>
                  ID{getSortArrow(contactSortCol, 'id', contactSortAsc)}
                </th>
                <th class="sortable" onclick={() => sortContacts('type')}>
                  Type{getSortArrow(contactSortCol, 'type', contactSortAsc)}
                </th>
                <th class="sortable" onclick={() => sortContacts('distance')}>
                  Distance{getSortArrow(contactSortCol, 'distance', contactSortAsc)}
                </th>
              </tr>
            </thead>
            <tbody>
              {#each sortedContacts as contact (contact.id)}
                <tr>
                  <td class="contact-id" title={contact.id}>{contact.id.slice(0, 16)}…</td>
                  <td>
                    <span class="contact-type type-{contact.bootstrap ? 'bootstrap' : contact.type}" class:unverified={!contact.ip_verified && contact.type < 3 && !contact.bootstrap}>
                      {getContactTypeLabel(contact)}
                    </span>
                  </td>
                  <td class="distance" title={contact.distance}>{contact.distance.slice(0, 24)}…</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    </div>

    <div class="kad-upper-right">
      <div class="bootstrap-panel">
        <div class="panel-title">Bootstrap</div>
        <div class="bootstrap-options">
          <label class="radio-row" class:selected={bootstrapMode === 'ip'}>
            <input type="radio" bind:group={bootstrapMode} value="ip" />
            <div class="radio-fields">
              <div class="field-row">
                <div class="field-group">
                  <span class="field-label">IP or Address:</span>
                  <input
                    type="text"
                    bind:value={bootstrapIp}
                    placeholder="192.168.1.1 or host:port"
                    onfocus={() => bootstrapMode = 'ip'}
                    class="sm-input"
                  />
                </div>
                <div class="field-group">
                  <span class="field-label">Port:</span>
                  <input
                    type="text"
                    bind:value={bootstrapPort}
                    placeholder="4672"
                    onfocus={() => bootstrapMode = 'ip'}
                    class="sm-input port-input"
                  />
                </div>
              </div>
            </div>
          </label>

          <label class="radio-row" class:selected={bootstrapMode === 'url'}>
            <input type="radio" bind:group={bootstrapMode} value="url" />
            <div class="radio-fields">
              <span class="field-label">Nodes.dat from URL:</span>
              <input
                type="text"
                bind:value={bootstrapUrl}
                placeholder="https://example.com/nodes.dat"
                onfocus={() => bootstrapMode = 'url'}
                class="sm-input"
              />
            </div>
          </label>

          <label class="radio-row" class:selected={bootstrapMode === 'clients'}>
            <input type="radio" bind:group={bootstrapMode} value="clients" />
            <span class="radio-label">From connected clients</span>
          </label>

          <button
            class="bootstrap-btn"
            onclick={handleBootstrap}
            disabled={isBootstrapDisabled}
          >
            {bootstrapping ? 'Bootstrapping...' : 'Bootstrap'}
          </button>
        </div>
      </div>

      <div class="stats-panel">
        <div class="panel-title">Network Status</div>
        <div class="stat-rows">
          <div class="stat-row">
            <span class="stat-label">Status</span>
            <span class="badge {$networkStats.status}">{$networkStats.status}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Contacts</span>
            <span class="stat-value">{contacts.length}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">External IP</span>
            <span class="stat-value">{$networkStats.status === 'disconnected' ? 'Unknown' : ($networkStats.external_ip || 'Detecting...')}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Firewall</span>
            {#if $networkStats.status === 'disconnected'}
              <span class="badge unknown">Unknown</span>
            {:else if $networkStats.status === 'connecting'}
              <span class="badge unknown">Checking...</span>
            {:else}
              <span class="badge {$networkStats.firewalled ? 'firewalled' : 'open'}">
                {$networkStats.firewalled ? 'Firewalled' : 'Open'}
              </span>
            {/if}
          </div>
          <div class="stat-row">
            <span class="stat-label">UPnP</span>
            <span class="stat-value">{$networkStats.upnp_mapped ? 'Mapped' : 'Not Mapped'}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Buddy</span>
            <span class="stat-value">
              {$networkStats.buddy_status === 'none' ? 'None' :
               $networkStats.buddy_status.startsWith('connected') ? 'Connected' :
               $networkStats.buddy_status.startsWith('serving') ? 'Serving' :
               $networkStats.buddy_status}
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Lower: Searches list (always visible, matches eMule) -->
  <div class="kad-lower">
    <div class="section-header">
      <span class="section-icon">⊕</span>
      <span>Searches ({searches.length})</span>
    </div>
    <div class="panel-content scrollable">
      {#if searches.length === 0}
        <div class="empty-state compact">
          <p>No active KAD searches</p>
        </div>
      {:else}
        <table class="compact-table">
          <thead>
            <tr>
              <th class="sortable" onclick={() => sortSearches('id')}>
                #{getSortArrow(searchSortCol, 'id', searchSortAsc)}
              </th>
              <th class="sortable" onclick={() => sortSearches('target')}>
                Key{getSortArrow(searchSortCol, 'target', searchSortAsc)}
              </th>
              <th class="sortable" onclick={() => sortSearches('type')}>
                Type{getSortArrow(searchSortCol, 'type', searchSortAsc)}
              </th>
              <th class="sortable" onclick={() => sortSearches('name')}>
                Name{getSortArrow(searchSortCol, 'name', searchSortAsc)}
              </th>
              <th class="sortable" onclick={() => sortSearches('status')}>
                Status{getSortArrow(searchSortCol, 'status', searchSortAsc)}
              </th>
              <th class="sortable" onclick={() => sortSearches('load')}>
                Load{getSortArrow(searchSortCol, 'load', searchSortAsc)}
              </th>
              <th class="sortable" onclick={() => sortSearches('packets_sent')}>
                Packets{getSortArrow(searchSortCol, 'packets_sent', searchSortAsc)}
              </th>
              <th class="sortable" onclick={() => sortSearches('responses')}>
                Responses{getSortArrow(searchSortCol, 'responses', searchSortAsc)}
              </th>
            </tr>
          </thead>
          <tbody>
            {#each sortedSearches as search (search.id)}
              <tr>
                <td>{search.id}</td>
                <td class="contact-id" title={search.target}>{search.target.slice(0, 16)}…</td>
                <td>{search.type}</td>
                <td>{search.name || '—'}</td>
                <td>
                  <span class="badge {search.status}">
                    {search.status === 'active' ? 'Active' : 'Stopping'}
                  </span>
                </td>
                <td>{search.load} ({search.load_response}/{search.load_total})</td>
                <td>{search.packets_sent} / {search.request_answer}</td>
                <td>{search.responses}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  </div>
</div>

<style>
  .header-actions {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .error-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 20px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--danger, #e74c3c);
    color: var(--danger, #e74c3c);
    font-size: 13px;
  }

  .kad-layout {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    padding: 0;
  }

  .kad-upper {
    display: flex;
    flex: 1;
    min-height: 0;
    border-bottom: 1px solid var(--border);
  }

  .kad-upper-left {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    border-right: 1px solid var(--border);
  }

  .kad-upper-right {
    width: 320px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
  }

  .panel-toolbar {
    display: flex;
    align-items: center;
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

  .pager {
    display: flex;
    align-items: center;
    gap: 4px;
    margin-left: auto;
    padding-right: 8px;
  }

  .pager-btn {
    padding: 2px 6px;
    font-size: 11px;
    min-width: 0;
    line-height: 1;
  }

  .pager-info {
    font-size: 11px;
    color: var(--text-muted);
  }

  .panel-content {
    flex: 1;
    min-height: 0;
  }

  .panel-content.scrollable {
    overflow: auto;
  }

  .bootstrap-panel {
    border-bottom: 1px solid var(--border);
    padding: 12px 16px;
  }

  .panel-title {
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    margin-bottom: 10px;
  }

  .bootstrap-options {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .radio-row {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 6px 8px;
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: background 0.15s;
  }

  .radio-row:hover {
    background: var(--bg-hover);
  }

  .radio-row.selected {
    background: var(--bg-tertiary);
  }

  .radio-row input[type="radio"] {
    margin-top: 3px;
    flex-shrink: 0;
  }

  .radio-fields {
    display: flex;
    flex-direction: column;
    gap: 4px;
    flex: 1;
    min-width: 0;
  }

  .field-row {
    display: flex;
    gap: 8px;
  }

  .field-group {
    display: flex;
    flex-direction: column;
    gap: 2px;
    flex: 1;
    min-width: 0;
  }

  .field-group:last-child {
    flex: 0 0 70px;
  }

  .field-label {
    font-size: 11px;
    color: var(--text-muted);
  }

  .sm-input {
    font-size: 12px;
    padding: 4px 8px;
    width: 100%;
    min-width: 0;
  }

  .port-input {
    width: 70px;
  }

  .radio-label {
    font-size: 13px;
    color: var(--text-primary);
    padding-top: 1px;
  }

  .bootstrap-btn {
    align-self: flex-end;
    font-size: 12px;
    padding: 5px 16px;
    margin-top: 4px;
  }

  .bootstrap-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .stats-panel {
    padding: 12px 16px;
    flex: 1;
  }

  .stat-rows {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .stat-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 12px;
    padding: 3px 0;
  }

  .stat-label {
    color: var(--text-muted);
    font-weight: 500;
  }

  .stat-value {
    color: var(--text-primary);
    font-weight: 600;
  }

  .kad-lower {
    flex: 0 0 auto;
    max-height: 40%;
    display: flex;
    flex-direction: column;
    min-height: 120px;
  }

  .section-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 16px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-secondary);
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .section-icon {
    font-size: 14px;
    opacity: 0.6;
  }

  .compact-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }

  .compact-table th {
    padding: 6px 10px;
    font-size: 11px;
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--bg-secondary);
  }

  .compact-table td {
    padding: 4px 10px;
    font-size: 12px;
  }

  .contact-id {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-muted);
  }

  .distance {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
  }

  .contact-type {
    font-size: 11px;
    font-weight: 500;
  }

  .type-0, .type-1 {
    color: var(--success);
  }

  .type-2 {
    color: var(--accent);
  }

  .type-3 {
    color: var(--warning);
  }

  .type-4 {
    color: var(--danger);
  }

  .type-bootstrap {
    color: var(--text-muted);
    font-style: italic;
  }

  .unverified {
    opacity: 0.6;
  }

  .empty-state.compact {
    padding: 30px 16px;
  }

  .empty-state.compact p {
    font-size: 13px;
  }

  .sub {
    font-size: 12px;
    color: var(--text-muted);
  }

  .badge.open {
    background: var(--success);
    color: #fff;
  }

  .badge.firewalled {
    background: var(--warning);
    color: #fff;
  }

  .badge.unknown {
    background: var(--bg-tertiary);
    color: var(--text-muted);
  }

  .badge.stopping {
    background: var(--warning);
    color: #fff;
  }
</style>
