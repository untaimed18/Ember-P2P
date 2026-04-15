<script lang="ts">
  import {
    kadConnect,
    kadDisconnect,
    kadRecheckFirewall,
    getKadContacts,
    getKadSearches,
  } from '$lib/api/kad';
  import { getSettings } from '$lib/api/settings';
  import { networkError, networkStats } from '$lib/stores/network';
  import type { KadContact, KadSearchEntry } from '$lib/types';
  import { onMount, untrack } from 'svelte';

  let contacts: KadContact[] = $state([]);
  let searches: KadSearchEntry[] = $state([]);
  let loading = $state(true);
  let kadError: string | null = $state(null);

  let contactSortCol: 'id' | 'type' | 'distance' = $state('type');
  let contactSortAsc = $state(true);
  let searchSortCol: string = $state('id');
  let searchSortAsc = $state(true);

  let contactPage = $state(0);
  const CONTACTS_PER_PAGE = 200;

  let refreshInProgress = false;
  let mounted = $state(false);

  let refreshTimer: ReturnType<typeof setInterval> | undefined;
  let upnpEnabled = $state(true);

  onMount(() => {
    mounted = true;
    refreshInProgress = false;
    void loadUpnpSetting();
    const isConnected = $networkStats.status === 'connected' || $networkStats.status === 'connecting';
    loading = isConnected;
    if (isConnected) {
      refresh();
      refreshTimer = setInterval(refresh, 5000);
    }
    return () => {
      mounted = false;
      clearInterval(refreshTimer);
      refreshTimer = undefined;
    };
  });

  $effect(() => {
    const connected = $networkStats.status === 'connected' || $networkStats.status === 'connecting';
    if (connected && !refreshTimer && mounted) {
      refresh();
      refreshTimer = setInterval(refresh, 5000);
    } else if (!connected && refreshTimer) {
      clearInterval(refreshTimer);
      refreshTimer = undefined;
    }
  });

  $effect(() => {
    if (!loading) return;
    const safety = setTimeout(() => { loading = false; }, 6000);
    return () => clearTimeout(safety);
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
      const [c, s] = await Promise.allSettled([
        withTimeout(getKadContacts(), 4000),
        withTimeout(getKadSearches(), 4000),
      ]);
      if (!mounted) return;

      if (c.status === 'fulfilled') {
        contacts = c.value;
      }
      if (s.status === 'fulfilled') {
        searches = s.value;
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

  async function loadUpnpSetting() {
    try {
      const settings = await getSettings();
      upnpEnabled = settings.upnp_enabled;
    } catch {
      // Keep existing state when settings can't be fetched.
    }
  }

  async function handleConnect() {
    kadError = null;
    networkError.set(null);
    try {
      if ($networkStats.status === 'connected' || $networkStats.status === 'connecting') {
        await kadDisconnect();
      } else {
        await kadConnect();
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Connection failed';
      kadError = msg;
    }
  }

  async function handleRecheckFirewall() {
    kadError = null;
    networkError.set(null);
    try {
      await kadRecheckFirewall();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Firewall recheck failed';
      kadError = msg;
    }
  }

  function getConnectButtonLabel(): string {
    if ($networkStats.status === 'connected') return 'Disconnect';
    if ($networkStats.status === 'connecting') return 'Cancel';
    return 'Connect';
  }

  const CONTACT_TYPE_NAMES: Record<number, string> = {
    0: 'Active',
    1: 'Verified',
    2: 'Expiring',
    3: 'New',
    4: 'Dead',
  };

  function getContactTypeLabel(contact: KadContact): string {
    if (contact.bootstrap) return 'Bootstrap';
    const name = CONTACT_TYPE_NAMES[contact.type] || `Type ${contact.type}`;
    const v = contact.version ? ` v${contact.version}` : '';
    return `${name}${v}`;
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
    contactPage = 0;
  }

  function sortSearches(col: string) {
    if (searchSortCol === col) searchSortAsc = !searchSortAsc;
    else { searchSortCol = col; searchSortAsc = true; }
  }

  function getSortArrow(current: string, col: string, asc: boolean): string {
    if (current !== col) return ' \u00A0';
    return asc ? ' \u25B2' : ' \u25BC';
  }

  let isConnected = $derived($networkStats.status === 'connected');

  let lastNetworkError: string | null = null;
  $effect(() => {
    const ne = $networkError;
    if (ne) {
      kadError = ne;
      lastNetworkError = ne;
    } else if (lastNetworkError && kadError === lastNetworkError) {
      kadError = null;
      lastNetworkError = null;
    }
  });

  $effect(() => {
    if ($networkStats.status === 'disconnected') {
      contacts = [];
      searches = [];
      contactPage = 0;
    }
  });

  $effect(() => {
    const maxPage = totalContactPages;
    untrack(() => {
      if (contactPage >= maxPage) {
        contactPage = Math.max(0, maxPage - 1);
      }
    });
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
    <button class="ghost" onclick={() => { kadError = null; networkError.set(null); }}>Dismiss</button>
  </div>
{/if}

<div class="kad-layout">
  <!-- Upper: Contacts list + Status panel -->
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
        {#if $networkStats.status !== 'connected' && $networkStats.status !== 'connecting'}
          <div class="empty-state compact">
            <p>Not connected</p>
            <p class="sub">Press Connect to join the KAD network</p>
            <button class="empty-action" onclick={handleConnect}>Connect</button>
          </div>
        {:else if loading}
          <div class="empty-state compact">
            <div class="spinner"></div>
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
                <th class="sortable" tabindex="0" role="columnheader" aria-sort={contactSortCol === 'id' ? (contactSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortContacts('id')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortContacts('id'))}>
                  ID{getSortArrow(contactSortCol, 'id', contactSortAsc)}
                </th>
                <th class="sortable" tabindex="0" role="columnheader" aria-sort={contactSortCol === 'type' ? (contactSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortContacts('type')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortContacts('type'))}>
                  Type{getSortArrow(contactSortCol, 'type', contactSortAsc)}
                </th>
                <th class="sortable" tabindex="0" role="columnheader" aria-sort={contactSortCol === 'distance' ? (contactSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortContacts('distance')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortContacts('distance'))}>
                  Distance{getSortArrow(contactSortCol, 'distance', contactSortAsc)}
                </th>
              </tr>
            </thead>
            <tbody>
              {#each sortedContacts as contact (contact.id)}
                <tr>
                  <td class="contact-id" title={contact.id}>{contact.id.length > 16 ? contact.id.slice(0, 16) + '…' : contact.id}</td>
                  <td>
                    <span class="contact-type type-{contact.bootstrap ? 'bootstrap' : contact.type}" class:unverified={!contact.ip_verified && contact.type < 3 && !contact.bootstrap}>
                      {getContactTypeLabel(contact)}
                    </span>
                  </td>
                  <td class="distance" title={contact.distance}>{contact.distance.length > 24 ? contact.distance.slice(0, 24) + '…' : contact.distance}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    </div>

    <div class="kad-upper-right">
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
            <span class="stat-label">Health</span>
            <span class="stat-value">
              {$networkStats.stale ? 'Stale' : $networkStats.degraded ? ($networkStats.degraded_reason || 'Degraded') : 'Healthy'}
            </span>
          </div>
          <div class="stat-row">
            <span class="stat-label">TCP Reachability</span>
            <span class="stat-value">{$networkStats.tcp_status || 'Unknown'}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">UDP Reachability</span>
            <span class="stat-value">{$networkStats.udp_status || 'Unknown'}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">UPnP</span>
            <span class="stat-value">{!upnpEnabled ? 'Disabled' : $networkStats.upnp_mapped ? 'Mapped' : 'Not Mapped'}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Buddy</span>
            <span class="stat-value">
              {!$networkStats.buddy_status || $networkStats.buddy_status === 'none' ? 'None' :
               $networkStats.buddy_status.startsWith('connected') ? 'Connected' :
               $networkStats.buddy_status.startsWith('connecting') ? 'Connecting' :
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
      <span class="section-icon">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="14" height="14">
          <circle cx="8" cy="8" r="6.5"/><line x1="8" y1="4.5" x2="8" y2="11.5"/><line x1="4.5" y1="8" x2="11.5" y2="8"/>
        </svg>
      </span>
      <span>Searches ({searches.length})</span>
    </div>
    <div class="panel-content scrollable">
      {#if $networkStats.status !== 'connected' && $networkStats.status !== 'connecting'}
        <div class="empty-state compact">
          <p>Not connected</p>
          <p class="sub">Connect to the KAD network to see active searches</p>
          <button class="empty-action" onclick={handleConnect}>Connect</button>
        </div>
      {:else if searches.length === 0}
        <div class="empty-state compact">
          <p>No active KAD searches</p>
          <p class="sub">Searches will appear here when initiated from the Search page</p>
        </div>
      {:else}
        <table class="compact-table">
          <thead>
            <tr>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'id' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('id')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('id'))}>
                #{getSortArrow(searchSortCol, 'id', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'target' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('target')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('target'))}>
                Key{getSortArrow(searchSortCol, 'target', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'type' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('type')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('type'))}>
                Type{getSortArrow(searchSortCol, 'type', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'name' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('name')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('name'))}>
                Name{getSortArrow(searchSortCol, 'name', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'status' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('status')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('status'))}>
                Status{getSortArrow(searchSortCol, 'status', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'load' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('load')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('load'))}>
                Load{getSortArrow(searchSortCol, 'load', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'packets_sent' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('packets_sent')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('packets_sent'))}>
                Packets{getSortArrow(searchSortCol, 'packets_sent', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'responses' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('responses')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('responses'))}>
                Responses{getSortArrow(searchSortCol, 'responses', searchSortAsc)}
              </th>
            </tr>
          </thead>
          <tbody>
            {#each sortedSearches as search (search.id)}
              <tr>
                <td>{search.id}</td>
                <td class="contact-id" title={search.target}>{search.target.length > 16 ? search.target.slice(0, 16) + '…' : search.target}</td>
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
    padding: 12px;
    gap: 12px;
    background: var(--bg-primary);
  }

  .kad-upper {
    display: flex;
    flex: 1;
    min-height: 0;
    gap: 12px;
  }

  .kad-upper-left {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
    background: var(--bg-secondary);
    box-shadow: var(--shadow-sm);
  }

  .kad-upper-right {
    width: 340px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    gap: 12px;
    overflow-y: auto;
  }

  .panel-toolbar {
    display: flex;
    align-items: center;
    padding: 0;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
    flex-shrink: 0;
  }

  .toolbar-label {
    padding: 9px 14px;
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
    padding: 1px 6px;
    font-size: 10px;
    min-width: 0;
    line-height: 1;
  }

  .pager-info {
    font-size: 10px;
    color: var(--text-muted);
  }

  .panel-content {
    flex: 1;
    min-height: 0;
  }

  .panel-content.scrollable {
    overflow: auto;
  }

  .panel-title {
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    margin-bottom: 10px;
  }

  .stats-panel {
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-secondary);
    box-shadow: var(--shadow-sm);
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
    padding: 4px 0;
    border-bottom: 1px dashed color-mix(in srgb, var(--border) 60%, transparent);
  }

  .stat-row:last-child {
    border-bottom: none;
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
    flex: 0 0 38%;
    max-height: 42%;
    display: flex;
    flex-direction: column;
    min-height: 120px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
    background: var(--bg-secondary);
    box-shadow: var(--shadow-sm);
  }

  .section-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 9px 14px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-secondary);
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .section-icon {
    display: inline-flex;
    align-items: center;
    opacity: 0.6;
  }

  .empty-action {
    margin-top: 10px;
    font-size: 12px;
    padding: 5px 16px;
  }

  .compact-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 11px;
  }

  .compact-table th {
    padding: 5px 8px;
    font-size: 10px;
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--bg-secondary);
    letter-spacing: 0.2px;
  }

  .compact-table td {
    padding: 3px 8px;
    font-size: 11px;
    line-height: 1.2;
  }

  .compact-table tbody tr {
    height: 26px;
  }

  .compact-table tbody tr:nth-child(even) td {
    background: color-mix(in srgb, var(--bg-secondary) 88%, var(--bg-primary));
  }

  .contact-id {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-muted);
  }

  .distance {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-secondary);
  }

  .contact-type {
    font-size: 10px;
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
    padding: 34px 16px;
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

  @media (max-width: 1050px) {
    .kad-layout {
      padding: 10px;
      gap: 10px;
    }

    .kad-upper {
      flex-direction: column;
      gap: 10px;
    }

    .kad-upper-right {
      width: 100%;
      max-height: 45%;
      flex-direction: row;
      align-items: stretch;
    }

    .stats-panel {
      flex: 1;
      min-width: 0;
    }

    .kad-lower {
      flex: 1;
      max-height: none;
      min-height: 180px;
    }
  }

  @media (max-width: 760px) {
    .kad-upper-right {
      flex-direction: column;
      max-height: none;
    }
  }

</style>
