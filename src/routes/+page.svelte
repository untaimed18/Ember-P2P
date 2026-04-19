<script lang="ts">
  import {
    kadConnect,
    kadDisconnect,
    kadRecheckFirewall,
    kadBootstrapIp,
    kadBootstrapUrl,
    kadBootstrapClients,
    getKadContacts,
    getKadSearches,
    kadCancelSearch,
  } from '$lib/api/kad';
  import { getSettings } from '$lib/api/settings';
  import { networkError, networkStats } from '$lib/stores/network';
  import { toastSuccess, toastError, toast as toastInfo } from '$lib/stores/toast';
  import { goto } from '$app/navigation';
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

  let contactFilter = $state('');
  // K31: with thousands of contacts, typing into the filter was laggy
  // because every keystroke recomputed the filtered list. We store the
  // raw input separately and debounce it into `contactFilter`, which is
  // what the derived list actually reads. 150ms is short enough to feel
  // instant but lets multi-char bursts collapse into a single repaint.
  let contactFilterInput = $state('');
  let contactFilterTimer: ReturnType<typeof setTimeout> | undefined;
  type ContactTypeFilter = 'all' | 'bootstrap' | '0' | '1' | '2' | '3' | '4';
  let contactTypeFilter: ContactTypeFilter = $state('all');

  let contactPage = $state(0);
  const CONTACTS_PER_PAGE = 200;

  let refreshInProgress = false;
  let mounted = $state(false);
  let pageVisible = $state(true);

  let refreshTimer: ReturnType<typeof setInterval> | undefined = $state();
  // Last `Date.now()` we fired the "empty contacts → refresh again
  // sooner than the 5s timer" branch. Throttles that branch to once
  // per 2s so a stuck-empty contact list can't trigger an
  // effect-reentrancy refresh storm. Plain `let`, not `$state`,
  // because it's read inside the same effect that writes it — a
  // reactive cell would loop the effect.
  let lastEmptyRefresh = 0;
  let upnpEnabled = $state(true);
  let rechecking = $state(false);
  let recheckTimer: ReturnType<typeof setTimeout> | undefined;

  let bootstrapOpen = $state(false);
  let bootstrapMode: 'ip' | 'url' | 'clients' = $state('ip');
  let bootstrapIpHost = $state('');
  let bootstrapIpPort = $state('4672');
  let bootstrapUrl = $state('');
  let bootstrapPending = $state(false);

  // K25: debounce Connect/Disconnect so a user who double-clicks the
  // button doesn't queue two conflicting commands.
  let connectPending = $state(false);

  onMount(() => {
    mounted = true;
    refreshInProgress = false;
    void loadUpnpSetting();
    const connected = $networkStats.status === 'connected' || $networkStats.status === 'connecting';
    loading = connected;
    // K26: only the $effect below drives refreshes. Kicking a refresh
    // from onMount and from the effect caused a double refresh on
    // mount-while-already-connected.
    if (connected) {
      refreshTimer = setInterval(tickRefresh, 5000);
    }

    const onVisibility = () => { pageVisible = document.visibilityState === 'visible'; };
    pageVisible = document.visibilityState === 'visible';
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      mounted = false;
      document.removeEventListener('visibilitychange', onVisibility);
      if (refreshTimer) clearInterval(refreshTimer);
      refreshTimer = undefined;
      if (recheckTimer) { clearTimeout(recheckTimer); recheckTimer = undefined; }
      if (contactFilterTimer) { clearTimeout(contactFilterTimer); contactFilterTimer = undefined; }
    };
  });

  function tickRefresh() {
    if (!pageVisible) return;
    void refresh();
  }

  $effect(() => {
    const connected = $networkStats.status === 'connected' || $networkStats.status === 'connecting';
    if (!mounted) return;
    if (connected && !refreshTimer) {
      // Show the spinner immediately on a fresh connect so the user doesn't
      // see "No KAD contacts" flash before the first refresh lands.
      untrack(() => {
        if (contacts.length === 0) loading = true;
      });
      void refresh();
      refreshTimer = setInterval(tickRefresh, 5000);
    } else if (connected && refreshTimer && contacts.length === 0) {
      // We're connected, the timer is already ticking, and we still
      // have nothing to show — fire one refresh so the initial paint
      // isn't blocked by the full 5s interval. Covers the mount path
      // above (which no longer calls refresh() directly).
      //
      // Throttle: this branch is reactive on `contacts.length`, and
      // `refresh()` itself reassigns `contacts`. If a refresh
      // resolves with another empty array (brand-new node, network
      // partition), the effect re-runs immediately and we'd hammer
      // the backend in a tight loop until contacts arrive. Only fire
      // one refresh per 2s here — the regular 5s timer handles the
      // steady state.
      const now = Date.now();
      if (now - lastEmptyRefresh > 2000) {
        lastEmptyRefresh = now;
        void refresh();
      }
    } else if (!connected && refreshTimer) {
      clearInterval(refreshTimer);
      refreshTimer = undefined;
    }
  });

  // When we regain visibility, kick off one refresh so the UI reflects activity
  // that accumulated while the tab was hidden. setInterval has been skipping
  // ticks via pageVisible, so the data can be up to interval-minutes stale.
  $effect(() => {
    if (pageVisible && refreshTimer) void refresh();
  });

  async function refresh() {
    if (refreshInProgress || !mounted) return;
    refreshInProgress = true;
    const wasEmpty = contacts.length === 0;
    try {
      const [c, s] = await Promise.allSettled([
        getKadContacts(),
        getKadSearches(),
      ]);
      if (!mounted) return;

      if (c.status === 'fulfilled') contacts = c.value;
      if (s.status === 'fulfilled') searches = s.value;

      if (c.status === 'rejected' || s.status === 'rejected') {
        const raw = c.status === 'rejected'
          ? (c as PromiseRejectedResult).reason
          : (s as PromiseRejectedResult).reason;
        const msg = raw instanceof Error ? raw.message : String(raw);
        // Only surface the banner if we don't already have data to show; a
        // transient failure mid-session shouldn't stomp a healthy list.
        if (wasEmpty) kadError = msg;
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

  function toErrMsg(e: unknown, fallback: string): string {
    return e instanceof Error ? e.message : typeof e === 'string' ? e : fallback;
  }

  async function handleConnect() {
    // K25: ignore re-entrant clicks while a connect/disconnect is in
    // flight. Without this an eager user who double-clicks flips the
    // state twice and can end up with the backend in an unexpected mode.
    if (connectPending) return;
    connectPending = true;
    kadError = null;
    try {
      if ($networkStats.status === 'connected' || $networkStats.status === 'connecting') {
        await kadDisconnect();
      } else {
        loading = true;
        await kadConnect();
      }
    } catch (e: unknown) {
      kadError = toErrMsg(e, 'Connection failed');
      loading = false;
    } finally {
      connectPending = false;
    }
  }

  async function handleRecheckFirewall() {
    if (rechecking) return;
    rechecking = true;
    // K28: keep error surfaces consistent. The page-level `kadError`
    // banner is reserved for things that affect all the data shown on
    // the page (connect failure, initial data load failure). Transient
    // errors from button actions (firewall recheck, bootstrap, etc) go
    // through toasts instead.
    try {
      await kadRecheckFirewall();
      toastSuccess('Firewall recheck initiated');
    } catch (e: unknown) {
      toastError(toErrMsg(e, 'Firewall recheck failed'));
    } finally {
      // Leave the button disabled briefly so the user can see the action
      // registered and to match the backend's internal cooldown. Track the
      // timer id so we can clear it on unmount.
      if (recheckTimer) clearTimeout(recheckTimer);
      recheckTimer = setTimeout(() => {
        rechecking = false;
        recheckTimer = undefined;
      }, 2500);
    }
  }

  async function handleBootstrap() {
    if (bootstrapPending) return;
    bootstrapPending = true;
    // K0: show success toasts only after the backend confirms the work
    // (packet sent / download parsed / contacts inserted). Prior behaviour
    // toasted on command-enqueue, so a failed URL download still looked
    // like success in the UI.
    try {
      if (bootstrapMode === 'ip') {
        const host = bootstrapIpHost.trim();
        const portNum = Number.parseInt(bootstrapIpPort, 10);
        if (!host) { toastError('Host or IP address is required'); return; }
        if (!Number.isFinite(portNum) || portNum < 1 || portNum > 65535) {
          toastError('Port must be between 1 and 65535');
          return;
        }
        const msg = await kadBootstrapIp(host, portNum);
        toastSuccess(msg || `Bootstrapping from ${host}:${portNum}`);
      } else if (bootstrapMode === 'url') {
        const url = bootstrapUrl.trim();
        if (!url) { toastError('URL is required'); return; }
        if (!/^https?:\/\//i.test(url)) {
          toastError('Only http:// or https:// URLs are allowed');
          return;
        }
        const msg = await kadBootstrapUrl(url);
        toastSuccess(msg || 'Loaded nodes.dat from URL');
      } else {
        await kadBootstrapClients();
        toastSuccess('Re-bootstrapping from known contacts');
      }
      bootstrapOpen = false;
      // Kick an immediate refresh so new contacts show quickly.
      void refresh();
    } catch (e: unknown) {
      // Show the concrete backend error so the user knows whether the
      // URL 404'd, the parse failed, the IP was unreachable, etc.
      toastError(toErrMsg(e, 'Bootstrap failed'));
    } finally {
      bootstrapPending = false;
    }
  }

  let bootstrapHostInput: HTMLInputElement | undefined = $state();
  let bootstrapUrlInput: HTMLInputElement | undefined = $state();

  function openBootstrap(mode: 'ip' | 'url' | 'clients' = 'ip') {
    bootstrapMode = mode;
    bootstrapOpen = true;
    // Give the DOM a tick to mount the modal, then move focus so keyboard
    // shortcuts (Escape / Ctrl+Enter) work without a preceding click.
    queueMicrotask(() => {
      setTimeout(() => {
        if (mode === 'ip') bootstrapHostInput?.focus();
        else if (mode === 'url') bootstrapUrlInput?.focus();
      }, 0);
    });
  }

  // K30: cancel an active search from the row-level action button. We
  // optimistically remove it from the local list so the row disappears
  // immediately; the next periodic refresh confirms it's gone server-side.
  async function handleCancelSearch(id: number) {
    try {
      await kadCancelSearch(id);
      searches = searches.filter((s) => s.id !== id);
      toastSuccess('Search cancelled');
    } catch (e: unknown) {
      toastError(toErrMsg(e, 'Failed to cancel search'));
    }
  }

  // K30: formats "started_at" (unix seconds) into a short relative age
  // string like "1m 23s" / "3h 5m" for the Age column.
  function formatSearchAge(startedAt: number): string {
    if (!startedAt) return '—';
    const diff = Math.max(0, Math.floor(Date.now() / 1000) - startedAt);
    if (diff < 60) return `${diff}s`;
    const m = Math.floor(diff / 60);
    const s = diff % 60;
    if (m < 60) return s > 0 ? `${m}m ${s}s` : `${m}m`;
    const h = Math.floor(m / 60);
    const mr = m % 60;
    return `${h}h ${mr}m`;
  }

  async function copyText(text: string, label = 'Copied') {
    try {
      await navigator.clipboard.writeText(text);
      toastInfo(`${label}`);
    } catch {
      toastError('Clipboard unavailable');
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

  // Single-letter sigils paired with the color so type can be parsed
  // without relying on hue (WCAG "use of color" — color must not be
  // the only visual means of conveying information).
  const CONTACT_TYPE_GLYPHS: Record<number, string> = {
    0: 'A',
    1: 'V',
    2: 'E',
    3: 'N',
    4: 'D',
  };

  function getContactTypeLabel(contact: KadContact): string {
    if (contact.bootstrap) return 'Bootstrap';
    const name = CONTACT_TYPE_NAMES[contact.type] || `Type ${contact.type}`;
    const v = contact.version ? ` v${contact.version}` : '';
    return `${name}${v}`;
  }

  function getContactTypeGlyph(contact: KadContact): string {
    if (contact.bootstrap) return 'B';
    return CONTACT_TYPE_GLYPHS[contact.type] || '?';
  }

  // Plain string compare works consistently for fixed-length hex — localeCompare
  // can shuffle case-insensitive in some locales (e.g. 'a' vs 'B'), which is
  // confusing for bit-distance ordering.
  function hexCmp(a: string, b: string): number {
    const al = a.toLowerCase();
    const bl = b.toLowerCase();
    return al < bl ? -1 : al > bl ? 1 : 0;
  }

  let filteredContacts = $derived.by(() => {
    const needle = contactFilter.trim().toLowerCase();
    return contacts.filter((c) => {
      if (contactTypeFilter === 'bootstrap' && !c.bootstrap) return false;
      if (contactTypeFilter !== 'all' && contactTypeFilter !== 'bootstrap') {
        if (c.bootstrap) return false;
        if (c.type !== Number.parseInt(contactTypeFilter, 10)) return false;
      }
      if (needle && !c.id.toLowerCase().includes(needle) && !c.distance.toLowerCase().includes(needle)) {
        return false;
      }
      return true;
    });
  });

  let sortedContacts = $derived.by(() => {
    const sorted = [...filteredContacts];
    sorted.sort((a, b) => {
      let cmp = 0;
      if (contactSortCol === 'id') cmp = hexCmp(a.id, b.id);
      else if (contactSortCol === 'type') {
        // Bootstrap rows cluster at the top so the legend colors group.
        if (a.bootstrap !== b.bootstrap) cmp = a.bootstrap ? -1 : 1;
        else {
          cmp = a.type - b.type;
          if (cmp === 0) cmp = a.version - b.version;
        }
      }
      else if (contactSortCol === 'distance') cmp = hexCmp(a.distance, b.distance);
      return contactSortAsc ? cmp : -cmp;
    });
    const start = contactPage * CONTACTS_PER_PAGE;
    return sorted.slice(start, start + CONTACTS_PER_PAGE);
  });

  let totalContactPages = $derived(Math.max(1, Math.ceil(filteredContacts.length / CONTACTS_PER_PAGE)));
  let visibleContactRange = $derived.by(() => {
    if (filteredContacts.length === 0) return { start: 0, end: 0 };
    const start = contactPage * CONTACTS_PER_PAGE;
    const end = Math.min(filteredContacts.length, start + CONTACTS_PER_PAGE);
    return { start: start + 1, end };
  });

  // Reset pager when filter or type changes so the user lands on page 1.
  $effect(() => {
    void contactFilter; void contactTypeFilter;
    untrack(() => { contactPage = 0; });
  });

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
      else if (searchSortCol === 'started_at') cmp = a.started_at - b.started_at;
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

  // V2 keeps the cross-page mirroring of the global `networkError` store
  // so a connect/listen failure raised elsewhere (e.g. by the network
  // initializer in onMount of +layout) still surfaces here. Main's KAD
  // page reverted this for separation-of-concerns; V2 prefers the
  // single-pane visibility, so the dismiss button clears both stores.
  $effect(() => {
    if ($networkError) {
      kadError = $networkError;
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
      onclick={() => openBootstrap('ip')}
      disabled={$networkStats.status === 'disconnected'}
      title="Bootstrap from a specific node, URL, or known contacts"
    >
      Bootstrap&hellip;
    </button>
    <button
      class="ghost"
      onclick={handleRecheckFirewall}
      disabled={!isConnected || rechecking}
      title={rechecking ? 'Firewall recheck in progress' : 'Run a fresh firewall test via remote KAD peers'}
    >
      {#if rechecking}
        <span class="spinner-inline" aria-hidden="true"></span> Rechecking&hellip;
      {:else}
        Recheck Firewall
      {/if}
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
        <span class="toolbar-label">
          Contacts
          {#if contactFilter.trim() || contactTypeFilter !== 'all'}
            ({filteredContacts.length.toLocaleString()} of {contacts.length.toLocaleString()})
          {:else}
            ({contacts.length.toLocaleString()})
          {/if}
        </span>
        <input
          type="search"
          class="filter-input"
          placeholder="Filter by ID or distance…"
          value={contactFilterInput}
          oninput={(e) => {
            contactFilterInput = (e.currentTarget as HTMLInputElement).value;
            if (contactFilterTimer) clearTimeout(contactFilterTimer);
            contactFilterTimer = setTimeout(() => {
              contactFilter = contactFilterInput;
              contactPage = 0;
            }, 150);
          }}
          disabled={contacts.length === 0}
          aria-label="Filter contacts by ID or distance"
        />
        <select
          class="filter-select"
          bind:value={contactTypeFilter}
          disabled={contacts.length === 0}
          aria-label="Filter by contact type"
        >
          <option value="all">All types</option>
          <option value="bootstrap">Bootstrap</option>
          <option value="0">Active</option>
          <option value="1">Verified</option>
          <option value="2">Expiring</option>
          <option value="3">New</option>
          <option value="4">Dead</option>
        </select>
        {#if totalContactPages > 1}
          <div class="pager">
            <button class="pager-btn" disabled={contactPage === 0} onclick={() => contactPage--} aria-label="Previous page">&lt;</button>
            <span class="pager-info" title="Showing items {visibleContactRange.start}–{visibleContactRange.end} of {filteredContacts.length.toLocaleString()}">
              {visibleContactRange.start.toLocaleString()}–{visibleContactRange.end.toLocaleString()}
            </span>
            <button class="pager-btn" disabled={contactPage >= totalContactPages - 1} onclick={() => contactPage++} aria-label="Next page">&gt;</button>
          </div>
        {/if}
      </div>

      <div class="panel-content scrollable scroll-shadows">
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
            <p class="sub">The routing table is empty. Bootstrap from a known node to join the network.</p>
            <div class="empty-actions">
              <button class="empty-action" onclick={() => openBootstrap('clients')}>Bootstrap from Clients</button>
              <button class="empty-action ghost" onclick={() => openBootstrap('url')}>From URL…</button>
              <button class="empty-action ghost" onclick={() => openBootstrap('ip')}>By IP…</button>
            </div>
          </div>
        {:else if filteredContacts.length === 0}
          <div class="empty-state compact">
            <p>No contacts match the filter</p>
            <p class="sub">Try a shorter prefix or a different type.</p>
            <button class="empty-action ghost" onclick={() => { contactFilterInput = ''; contactFilter = ''; contactTypeFilter = 'all'; }}>Clear Filters</button>
          </div>
        {:else}
          <table class="compact-table">
            <thead>
              <tr>
                <th class="sortable" tabindex="0" role="columnheader" aria-sort={contactSortCol === 'id' ? (contactSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortContacts('id')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortContacts('id'))}>
                  ID{getSortArrow(contactSortCol, 'id', contactSortAsc)}
                </th>
                <th
                  class="sortable"
                  tabindex="0"
                  role="columnheader"
                  aria-sort={contactSortCol === 'type' ? (contactSortAsc ? 'ascending' : 'descending') : 'none'}
                  onclick={() => sortContacts('type')}
                  onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortContacts('type'))}
                  title={'Contact lifecycle:\n  Active — recently responsive\n  Verified — IP verified by KAD challenge\n  Expiring — nearing timeout, awaiting refresh\n  New — added recently, not yet validated\n  Dead — unresponsive, will be removed\n  Bootstrap — seed node, not counted against routing table'}
                >
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
                  <td
                    class="contact-id"
                    title={`${contact.id}\nDouble-click to copy`}
                    ondblclick={() => copyText(contact.id, 'Copied contact ID')}
                  >{contact.id}</td>
                  <td>
                    <span class="contact-type type-{contact.bootstrap ? 'bootstrap' : contact.type}" class:unverified={!contact.ip_verified && contact.type < 3 && !contact.bootstrap}>
                      <span class="type-glyph" aria-hidden="true">{getContactTypeGlyph(contact)}</span>
                      {getContactTypeLabel(contact)}
                    </span>
                  </td>
                  <td
                    class="distance"
                    title={`${contact.distance}\nDouble-click to copy`}
                    ondblclick={() => copyText(contact.distance, 'Copied distance')}
                  >{contact.distance}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    </div>

    <div class="kad-upper-right scroll-shadows">
      <div class="stats-panel">
        <div class="panel-title">Network Status</div>
        <div class="stat-rows">
          <div class="stat-row">
            <span class="stat-label">Status</span>
            <span class="badge {$networkStats.status}">{$networkStats.status}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Contacts</span>
            <span class="stat-value">{contacts.length.toLocaleString()}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label" title="Estimated number of KAD users worldwide, derived from routing-table density">KAD users (est.)</span>
            <span class="stat-value">
              {$networkStats.status === 'disconnected' || !$networkStats.kad_users_estimate
                ? '—'
                : $networkStats.kad_users_estimate.toLocaleString()}
            </span>
          </div>
          <div class="stat-row">
            <span class="stat-label" title="Ember-aware peers discovered in this session">Ember peers</span>
            <span class="stat-value">{($networkStats.ember_peers ?? 0).toLocaleString()}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label" title="Sources learned via EPX (Ember Peer Exchange)">EPX sources</span>
            <span class="stat-value">{($networkStats.epx_sources_received ?? 0).toLocaleString()}</span>
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
              <span
                class="badge {$networkStats.firewalled ? 'firewalled' : 'open'}"
                role="status"
                aria-label={$networkStats.firewalled
                  ? 'Firewall status: firewalled. Inbound TCP connections are blocked; KAD operates via UDP callbacks.'
                  : 'Firewall status: open. Inbound TCP connections succeed; full KAD participation is available.'}
              >
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
            {#if !upnpEnabled}
              <button
                type="button"
                class="stat-link"
                onclick={() => goto('/settings')}
                title="UPnP is disabled in Settings — click to open Settings"
              >Disabled</button>
            {:else}
              <span class="stat-value">{$networkStats.upnp_mapped ? 'Mapped' : 'Not Mapped'}</span>
            {/if}
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

  {#if bootstrapOpen}
    <!--
      K34: simple focus trap. The overlay has tabindex="-1" so clicking
      it focuses the container (unlocks Escape / Ctrl+Enter) and the
      Tab / Shift+Tab handler wraps focus within the first/last
      focusable descendants so the user can't tab out to the background
      page while the modal is open. `aria-busy` advertises the in-flight
      network call to assistive tech.
    -->
    <div
      class="modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="kad-bootstrap-title"
      aria-busy={bootstrapPending}
      tabindex="-1"
      onkeydown={(e) => {
        if (e.key === 'Escape') { bootstrapOpen = false; return; }
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && !bootstrapPending) {
          e.preventDefault();
          void handleBootstrap();
          return;
        }
        if (e.key === 'Tab') {
          const container = e.currentTarget as HTMLElement;
          const focusables = container.querySelectorAll<HTMLElement>(
            'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
          );
          if (focusables.length === 0) return;
          const first = focusables[0];
          const last = focusables[focusables.length - 1];
          const active = document.activeElement as HTMLElement | null;
          if (e.shiftKey && active === first) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && active === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }}
    >
      <div class="modal-content bootstrap-modal">
        <div class="modal-header">
          <h3 id="kad-bootstrap-title">Bootstrap KAD</h3>
          <button class="modal-close" aria-label="Close" onclick={() => (bootstrapOpen = false)}>×</button>
        </div>
        <div class="modal-body">
          <div class="bootstrap-tabs" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={bootstrapMode === 'ip'}
              class:active={bootstrapMode === 'ip'}
              onclick={() => (bootstrapMode = 'ip')}
            >By IP / Host</button>
            <button
              type="button"
              role="tab"
              aria-selected={bootstrapMode === 'url'}
              class:active={bootstrapMode === 'url'}
              onclick={() => (bootstrapMode = 'url')}
            >From URL</button>
            <button
              type="button"
              role="tab"
              aria-selected={bootstrapMode === 'clients'}
              class:active={bootstrapMode === 'clients'}
              onclick={() => (bootstrapMode = 'clients')}
            >Known Contacts</button>
          </div>

          {#if bootstrapMode === 'ip'}
            <p class="bootstrap-hint">Send a bootstrap request to a single KAD node. Use the node's public IP or hostname and its KAD (UDP) port.</p>
            <div class="form-row">
              <label class="form-label" for="kad-bs-host">Host / IP</label>
              <input
                id="kad-bs-host"
                type="text"
                class="form-input"
                bind:value={bootstrapIpHost}
                bind:this={bootstrapHostInput}
                placeholder="kad.example.com or 203.0.113.42"
                autocomplete="off"
                onkeydown={(e) => { if (e.key === 'Enter' && !bootstrapPending && bootstrapIpHost.trim()) { e.preventDefault(); void handleBootstrap(); } }}
              />
            </div>
            <div class="form-row">
              <label class="form-label" for="kad-bs-port">Port</label>
              <input
                id="kad-bs-port"
                type="number"
                min="1"
                max="65535"
                class="form-input port-input"
                bind:value={bootstrapIpPort}
                placeholder="4672"
              />
            </div>
          {:else if bootstrapMode === 'url'}
            <p class="bootstrap-hint">Fetch a <code>nodes.dat</code> file from a URL and bootstrap from its contents. URLs are validated against SSRF rules before fetch.</p>
            <div class="form-row">
              <label class="form-label" for="kad-bs-url">URL</label>
              <input
                id="kad-bs-url"
                type="url"
                class="form-input"
                bind:value={bootstrapUrl}
                bind:this={bootstrapUrlInput}
                placeholder="https://example.com/nodes.dat"
                autocomplete="off"
                onkeydown={(e) => { if (e.key === 'Enter' && !bootstrapPending && bootstrapUrl.trim()) { e.preventDefault(); void handleBootstrap(); } }}
              />
            </div>
          {:else}
            <p class="bootstrap-hint">Re-bootstrap by re-pinging KAD contacts currently in this session's routing table. Useful when the network looks idle but some verified peers are still cached from earlier activity. Won't help on a completely fresh start — use IP or URL bootstrap first.</p>
          {/if}
        </div>
        <div class="modal-footer">
          <button class="ghost" onclick={() => (bootstrapOpen = false)} disabled={bootstrapPending}>Cancel</button>
          <button
            class="primary"
            onclick={handleBootstrap}
            disabled={bootstrapPending
              || (bootstrapMode === 'ip' && !bootstrapIpHost.trim())
              || (bootstrapMode === 'url' && !bootstrapUrl.trim())}
          >
            {#if bootstrapPending}
              <span class="spinner-inline" aria-hidden="true"></span> Working&hellip;
            {:else}
              Bootstrap
            {/if}
          </button>
        </div>
      </div>
    </div>
  {/if}

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
    <div class="panel-content scrollable scroll-shadows">
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
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'started_at' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('started_at')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('started_at'))}>
                Age{getSortArrow(searchSortCol, 'started_at', searchSortAsc)}
              </th>
              <th aria-label="Actions"></th>
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
                <td title={new Date(search.started_at * 1000).toLocaleString()}>{formatSearchAge(search.started_at)}</td>
                <td>
                  {#if search.status === 'active'}
                    <button
                      class="ghost cancel-btn"
                      title="Cancel this search"
                      aria-label={`Cancel search ${search.id}`}
                      onclick={() => handleCancelSearch(search.id)}
                    >Cancel</button>
                  {/if}
                </td>
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
    white-space: nowrap;
  }

  .filter-input {
    flex: 1 1 120px;
    min-width: 80px;
    max-width: 280px;
    margin: 4px 6px 4px 0;
    padding: 4px 8px;
    font-size: 12px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm, 4px);
  }
  .filter-input:focus {
    outline: none;
    border-color: var(--accent);
  }
  .filter-input:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .filter-select {
    margin: 4px 6px 4px 0;
    padding: 4px 8px;
    font-size: 12px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm, 4px);
  }
  .filter-select:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .empty-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    justify-content: center;
    margin-top: 10px;
  }

  .stat-link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    font: inherit;
    font-weight: 600;
    cursor: pointer;
    text-decoration: underline dotted;
    text-underline-offset: 2px;
  }
  .stat-link:hover { color: var(--accent-hover, var(--accent)); }

  .spinner-inline {
    display: inline-block;
    width: 10px;
    height: 10px;
    border: 2px solid var(--text-muted);
    border-top-color: transparent;
    border-radius: 50%;
    animation: spinner-rotate 0.9s linear infinite;
    vertical-align: -1px;
    margin-right: 4px;
  }
  @keyframes spinner-rotate { to { transform: rotate(360deg); } }

  /* --- Modal --- */
  .modal-overlay {
    position: fixed;
    inset: 0;
    z-index: 10000;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .modal-content {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow:
      inset 0 1px 0 0 rgba(255, 255, 255, 0.05),
      0 16px 48px rgba(0, 0, 0, 0.45);
    display: flex;
    flex-direction: column;
    max-height: 80vh;
  }
  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
  }
  .modal-header h3 { margin: 0; font-size: 14px; font-weight: 600; }
  .modal-close {
    font-size: 18px;
    line-height: 1;
    padding: 0 4px;
    cursor: pointer;
    border: none;
    background: none;
    color: var(--text-muted);
  }
  .modal-close:hover { color: var(--text-primary); }
  .modal-body { padding: 16px; overflow-y: auto; flex: 1; }
  .modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 12px 16px;
    border-top: 1px solid var(--border);
  }
  .form-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 10px;
  }
  .form-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    width: 80px;
    flex-shrink: 0;
  }
  .form-input {
    flex: 1;
    padding: 5px 8px;
    font-size: 12px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-secondary);
    color: inherit;
    outline: none;
  }
  .form-input:focus { border-color: var(--accent, #3498db); }

  /* Bootstrap modal */
  .bootstrap-modal {
    width: min(520px, calc(100vw - 40px));
  }
  .bootstrap-tabs {
    display: flex;
    gap: 2px;
    margin-bottom: 12px;
    border-bottom: 1px solid var(--border);
  }
  .bootstrap-tabs button {
    flex: 1;
    padding: 8px 10px;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
  }
  .bootstrap-tabs button:hover {
    color: var(--text-primary);
  }
  .bootstrap-tabs button.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }
  .bootstrap-hint {
    font-size: 12px;
    color: var(--text-muted);
    margin: 0 0 12px 0;
    line-height: 1.5;
  }
  .bootstrap-hint code {
    font-family: var(--font-mono);
    background: var(--bg-tertiary);
    padding: 1px 4px;
    border-radius: 3px;
  }
  .port-input {
    width: 110px;
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
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }

  /* Single-letter sigil that pairs with the type color so the contact
     state is distinguishable without relying on hue. Sized to mimic a
     small chip; inherits its hue from `.contact-type`'s color rule so
     type-{n} colors flow through automatically. */
  .type-glyph {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 14px;
    height: 14px;
    border-radius: 3px;
    font-size: 9px;
    font-weight: 700;
    line-height: 1;
    background: color-mix(in srgb, currentColor 18%, transparent);
    border: 1px solid color-mix(in srgb, currentColor 32%, transparent);
    text-transform: uppercase;
    flex-shrink: 0;
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

  /* Per-row Cancel button: small ghost variant that lines up with the
     compact table's tight 26-px row height. Uses V2's existing `.ghost`
     button class for the base look so the visual language stays
     consistent across the app. */
  .cancel-btn {
    padding: 2px 8px;
    font-size: 10px;
    line-height: 1.4;
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
