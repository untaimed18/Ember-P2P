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
  import { networkError, networkStats, upnpAutoDisabled } from '$lib/stores/network';
  import { toastSuccess, toastError, toast as toastInfo } from '$lib/stores/toast';
  import { goto } from '$app/navigation';
  import { passiveScroll } from '$lib/actions/passiveScroll';
  import type { KadContact, KadSearchEntry } from '$lib/types';
  import { onMount, untrack } from 'svelte';
  import * as m from '$lib/paraglide/messages';
  import { translateError, degradedReasonText, firewallStatusText } from '$lib/i18n';

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

  let contactScrollContainer: HTMLDivElement | undefined = $state();
  let contactScrollTop = $state(0);
  let contactViewportHeight = $state(400);
  const CONTACT_ROW_HEIGHT = 26;
  const CONTACT_OVERSCAN = 15;

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
    // K26: the $effect below is the single owner of the refresh timer.
    // onMount must NOT also create one — when the effect runs first and
    // sets `refreshTimer`, an unconditional assignment here would
    // overwrite the handle and leak the effect's interval (duplicate
    // polling until unmount). The effect fires on mount too, so a
    // connected-at-mount page still starts polling immediately.

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
  let wasHidden = false;
  $effect(() => {
    if (!pageVisible) {
      wasHidden = true;
      return;
    }
    // Only refresh on a genuine hidden→visible transition — not when the
    // refresh timer is (re)created while the page is already visible, which
    // the connect effect already refreshes for.
    if (wasHidden && refreshTimer) {
      wasHidden = false;
      void refresh();
    }
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

      // If we disconnected while these fetches were in flight, the
      // disconnect effect has already cleared the lists — don't let a
      // stale in-flight result repopulate them onto the disconnected view.
      if ($networkStats.status === 'disconnected') return;

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
    return translateError(e, fallback);
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
      kadError = toErrMsg(e, m.kad_connection_failed());
      loading = false;
    } finally {
      connectPending = false;
    }
  }

  async function handleRecheckFirewall() {
    if (rechecking) return;
    rechecking = true;
    try {
      await kadRecheckFirewall();
    } catch (e: unknown) {
      toastError(toErrMsg(e, m.kad_firewall_recheck_failed()));
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
        if (!host) { toastError(m.kad_bootstrap_host_required()); return; }
        if (!Number.isFinite(portNum) || portNum < 1 || portNum > 65535) {
          toastError(m.kad_bootstrap_port_range());
          return;
        }
        const result = await kadBootstrapIp(host, portNum);
        toastSuccess(result || m.kad_bootstrap_from_host({ host, port: portNum }));
      } else if (bootstrapMode === 'url') {
        const url = bootstrapUrl.trim();
        if (!url) { toastError(m.kad_bootstrap_url_required()); return; }
        if (!/^https:\/\//i.test(url)) {
          toastError(m.kad_bootstrap_url_must_be_https());
          return;
        }
        const result = await kadBootstrapUrl(url);
        toastSuccess(result || m.kad_bootstrap_loaded_url());
      } else {
        await kadBootstrapClients();
        toastSuccess(m.kad_bootstrap_from_known());
      }
      bootstrapOpen = false;
      // Kick an immediate refresh so new contacts show quickly.
      void refresh();
    } catch (e: unknown) {
      // Show the concrete backend error so the user knows whether the
      // URL 404'd, the parse failed, the IP was unreachable, etc.
      toastError(toErrMsg(e, m.kad_bootstrap_failed()));
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
        if (!mounted) return;
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
      toastSuccess(m.kad_search_cancelled());
    } catch (e: unknown) {
      toastError(toErrMsg(e, m.kad_failed_to_cancel_search()));
    }
  }

  // K30: formats "started_at" (unix seconds) into a short relative age
  // string like "1m 23s" / "3h 5m" for the Age column.
  function formatSearchAge(startedAt: number): string {
    if (!startedAt) return '—';
    const diff = Math.max(0, Math.floor(Date.now() / 1000) - startedAt);
    if (diff < 60) return `${diff}s`;
    const mins = Math.floor(diff / 60);
    const secs = diff % 60;
    if (mins < 60) return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
    const hrs = Math.floor(mins / 60);
    const mr = mins % 60;
    return `${hrs}h ${mr}m`;
  }

  async function copyText(text: string, label?: string) {
    try {
      await navigator.clipboard.writeText(text);
      toastInfo(label ?? m.common_copied());
    } catch {
      toastError(m.kad_clipboard_unavailable());
    }
  }

  function getConnectButtonLabel(): string {
    if ($networkStats.status === 'connected') return m.servers_disconnect();
    if ($networkStats.status === 'connecting') return m.common_cancel();
    return m.servers_connect();
  }

  function contactTypeName(t: number): string {
    switch (t) {
      case 0: return m.kad_type_active();
      case 1: return m.kad_type_verified();
      case 2: return m.kad_type_expiring();
      case 3: return m.kad_type_new();
      case 4: return m.kad_type_dead();
      default: return m.kad_type_unknown({ type: t });
    }
  }

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
    if (contact.bootstrap) return m.kad_type_bootstrap();
    const name = contactTypeName(contact.type);
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
    return sorted;
  });

  let virtualContacts = $derived.by(() => {
    const total = sortedContacts.length;
    if (total === 0) return { visible: [], startIdx: 0, topPad: 0, bottomPad: 0 };
    const firstVisible = Math.floor(contactScrollTop / CONTACT_ROW_HEIGHT);
    const visibleCount = Math.ceil(contactViewportHeight / CONTACT_ROW_HEIGHT);
    const startIdx = Math.max(0, firstVisible - CONTACT_OVERSCAN);
    const endIdx = Math.min(total, firstVisible + visibleCount + CONTACT_OVERSCAN);
    return {
      visible: sortedContacts.slice(startIdx, endIdx),
      startIdx,
      topPad: startIdx * CONTACT_ROW_HEIGHT,
      bottomPad: (total - endIdx) * CONTACT_ROW_HEIGHT
    };
  });

  $effect(() => {
    if (!contactScrollContainer) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        contactViewportHeight = entry.contentRect.height;
      }
    });
    ro.observe(contactScrollContainer);
    contactViewportHeight = contactScrollContainer.clientHeight;
    return () => ro.disconnect();
  });

  // Reset scroll when filter or type changes so the user lands at top.
  $effect(() => {
    void contactFilter; void contactTypeFilter;
    untrack(() => {
      if (contactScrollContainer) contactScrollContainer.scrollTop = 0;
      contactScrollTop = 0;
    });
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
    if (contactScrollContainer) contactScrollContainer.scrollTop = 0;
    contactScrollTop = 0;
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
  let lastNetworkError: string | null = null;
  $effect(() => {
    const ne = $networkError;
    // Mirror both directions: raise the banner when the global network error
    // is set, and clear it when that error is cleared elsewhere. Tracking the
    // previous value means a local (connect) error set while `networkError`
    // didn't change is left intact.
    if (ne !== lastNetworkError) {
      lastNetworkError = ne;
      kadError = ne;
    }
  });

  $effect(() => {
    if ($networkStats.status === 'disconnected') {
      contacts = [];
      searches = [];
      if (contactScrollContainer) contactScrollContainer.scrollTop = 0;
      contactScrollTop = 0;
    }
  });
</script>

<div class="page-header">
  <h2>{m.nav_kad_network()}</h2>
  <div class="header-actions">
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
    <button class="ghost" onclick={() => { kadError = null; networkError.set(null); }}>{m.common_dismiss()}</button>
  </div>
{/if}

<div class="kad-layout">
  <!-- Upper: Contacts list + Status panel -->
  <div class="kad-upper">
    <div class="kad-upper-left">
      <div class="panel-toolbar">
        <span class="toolbar-label">
          {m.kad_contacts_label()}
          {#if contactFilter.trim() || contactTypeFilter !== 'all'}
            ({m.kad_contacts_count_filtered({ filtered: filteredContacts.length.toLocaleString(), total: contacts.length.toLocaleString() })})
          {:else}
            ({contacts.length.toLocaleString()})
          {/if}
        </span>
        <input
          type="search"
          class="filter-input"
          placeholder={m.kad_filter_placeholder()}
          value={contactFilterInput}
          oninput={(e) => {
            contactFilterInput = (e.currentTarget as HTMLInputElement).value;
            if (contactFilterTimer) clearTimeout(contactFilterTimer);
            contactFilterTimer = setTimeout(() => {
              contactFilter = contactFilterInput;
              if (contactScrollContainer) contactScrollContainer.scrollTop = 0;
              contactScrollTop = 0;
            }, 150);
          }}
          disabled={contacts.length === 0}
          aria-label={m.kad_filter_aria()}
        />
        <select
          class="filter-select"
          bind:value={contactTypeFilter}
          disabled={contacts.length === 0}
          aria-label={m.kad_filter_type_aria()}
        >
          <option value="all">{m.kad_filter_all_types()}</option>
          <option value="bootstrap">{m.kad_type_bootstrap()}</option>
          <option value="0">{m.kad_type_active()}</option>
          <option value="1">{m.kad_type_verified()}</option>
          <option value="2">{m.kad_type_expiring()}</option>
          <option value="3">{m.kad_type_new()}</option>
          <option value="4">{m.kad_type_dead()}</option>
        </select>
      </div>

      <div
        class="panel-content scrollable scroll-shadows"
        bind:this={contactScrollContainer}
        use:passiveScroll={(e) => { contactScrollTop = (e.target as HTMLDivElement).scrollTop; }}
      >
        {#if $networkStats.status !== 'connected' && $networkStats.status !== 'connecting'}
          <div class="empty-state compact">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="48" height="48"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path><line x1="8" y1="12" x2="16" y2="12"></line><line x1="2" y1="2" x2="22" y2="22"></line></svg>
            <p>{m.kad_not_connected()}</p>
            <p class="sub">{m.kad_press_connect()}</p>
            <button class="empty-action" onclick={handleConnect}>{m.servers_connect()}</button>
          </div>
        {:else if loading}
          <div class="empty-state compact">
            <div class="spinner lg"></div>
            <p>{m.kad_loading_contacts()}</p>
          </div>
        {:else if contacts.length === 0}
          <div class="empty-state compact">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="48" height="48"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            <p>{m.kad_empty_no_contacts()}</p>
            <p class="sub">{m.kad_empty_no_contacts_sub()}</p>
            <div class="empty-actions">
              <button class="empty-action" onclick={() => openBootstrap('clients')}>{m.kad_bootstrap_from_clients()}</button>
              <button class="empty-action ghost" onclick={() => openBootstrap('url')}>{m.kad_from_url()}</button>
              <button class="empty-action ghost" onclick={() => openBootstrap('ip')}>{m.kad_by_ip()}</button>
            </div>
          </div>
        {:else if filteredContacts.length === 0}
          <div class="empty-state compact">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="48" height="48"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg>
            <p>{m.kad_empty_no_matches()}</p>
            <p class="sub">{m.kad_empty_no_matches_sub()}</p>
            <button class="empty-action ghost" onclick={() => { contactFilterInput = ''; contactFilter = ''; contactTypeFilter = 'all'; }}>{m.kad_clear_filters()}</button>
          </div>
        {:else}
          <table class="compact-table">
            <thead>
              <tr>
                <th class="sortable" tabindex="0" role="columnheader" aria-sort={contactSortCol === 'id' ? (contactSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortContacts('id')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortContacts('id'))}>
                  {m.kad_col_id()}{getSortArrow(contactSortCol, 'id', contactSortAsc)}
                </th>
                <th
                  class="sortable"
                  tabindex="0"
                  role="columnheader"
                  aria-sort={contactSortCol === 'type' ? (contactSortAsc ? 'ascending' : 'descending') : 'none'}
                  onclick={() => sortContacts('type')}
                  onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortContacts('type'))}
                  title={m.kad_type_lifecycle_help()}
                >
                  {m.kad_col_type()}{getSortArrow(contactSortCol, 'type', contactSortAsc)}
                </th>
                <th class="sortable" tabindex="0" role="columnheader" aria-sort={contactSortCol === 'distance' ? (contactSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortContacts('distance')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortContacts('distance'))}>
                  {m.kad_col_distance()}{getSortArrow(contactSortCol, 'distance', contactSortAsc)}
                </th>
              </tr>
            </thead>
            <tbody>
              {#if virtualContacts.topPad > 0}
                <tr class="spacer-row" style="height: {virtualContacts.topPad}px; border: none; background: transparent;"><td colspan="3" style="padding: 0; border: none; background: transparent;"></td></tr>
              {/if}
              {#each virtualContacts.visible as contact, i (contact.id)}
                <tr class="virtual-row" class:row-alt={(virtualContacts.startIdx + i) % 2 === 1}>
                  <td class="contact-id">
                    <!-- svelte-ignore a11y_no_static_element_interactions -->
                    <span class="cell-content" title={m.kad_double_click_to_copy({ value: contact.id })} ondblclick={() => copyText(contact.id, m.kad_copied_contact_id())}>{contact.id}</span>
                    <button class="ghost copy-btn" aria-label={m.kad_copy_id()} onclick={() => copyText(contact.id, m.kad_copied_contact_id())} title={m.kad_copy_id()}>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    </button>
                  </td>
                  <td>
                    <span class="contact-type type-{contact.bootstrap ? 'bootstrap' : contact.type}" class:unverified={!contact.ip_verified && contact.type < 3 && !contact.bootstrap}>
                      <span class="type-glyph" aria-hidden="true">{getContactTypeGlyph(contact)}</span>
                      {getContactTypeLabel(contact)}
                    </span>
                  </td>
                  <td class="distance">
                    <!-- svelte-ignore a11y_no_static_element_interactions -->
                    <span class="cell-content" title={m.kad_double_click_to_copy({ value: contact.distance })} ondblclick={() => copyText(contact.distance, m.kad_copied_distance())}>{contact.distance}</span>
                    <button class="ghost copy-btn" aria-label={m.kad_copy_distance()} onclick={() => copyText(contact.distance, m.kad_copied_distance())} title={m.kad_copy_distance()}>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    </button>
                  </td>
                </tr>
              {/each}
              {#if virtualContacts.bottomPad > 0}
                <tr class="spacer-row" style="height: {virtualContacts.bottomPad}px; border: none; background: transparent;"><td colspan="3" style="padding: 0; border: none; background: transparent;"></td></tr>
              {/if}
            </tbody>
          </table>
        {/if}
      </div>
    </div>

    <div class="kad-upper-right scroll-shadows">
      <div class="stats-panel">
        <div class="panel-title">{m.kad_network_status()}</div>

        <div class="stat-group">
          <div class="stat-tile tile-wide">
            <span class="stat-label">{m.kad_stat_status()}</span>
            <span class="badge {$networkStats.status}">
              <span class="badge-glyph" aria-hidden="true">
                {#if $networkStats.status === 'connected'}&#x2713;{:else if $networkStats.status === 'connecting'}&#x25CB;{:else}&#x2715;{/if}
              </span>
              {$networkStats.status === 'connected'
                ? m.kad_status_connected()
                : $networkStats.status === 'connecting'
                  ? m.kad_status_connecting()
                  : m.kad_status_disconnected()}
            </span>
          </div>
          <div class="stat-tile tile-wide">
            <span class="stat-label">{m.kad_stat_health()}</span>
            <span class="stat-value">
              {$networkStats.stale
                ? m.kad_health_stale()
                : $networkStats.degraded
                  ? (degradedReasonText($networkStats.degraded_reason) || m.kad_health_degraded())
                  : m.kad_health_healthy()}
            </span>
          </div>
        </div>

        <div class="stat-group stat-group-grid">
          <div class="stat-tile">
            <span class="stat-label">{m.kad_stat_contacts()}</span>
            <span class="stat-value stat-numeric">{contacts.length.toLocaleString()}</span>
          </div>
          <div class="stat-tile">
            <span class="stat-label" title={m.kad_stat_kad_users_title()}>{m.kad_stat_kad_users()}</span>
            <span class="stat-value stat-numeric">
              {$networkStats.status === 'disconnected' || $networkStats.kad_users_estimate == null
                ? '—'
                : $networkStats.kad_users_estimate.toLocaleString()}
            </span>
          </div>
          <div class="stat-tile">
            <span class="stat-label" title={m.kad_stat_ember_peers_title()}>{m.kad_stat_ember_peers()}</span>
            <span class="stat-value stat-numeric">{($networkStats.ember_peers ?? 0).toLocaleString()}</span>
          </div>
          <div class="stat-tile">
            <span class="stat-label" title={m.kad_stat_epx_sources_title()}>{m.kad_stat_epx_sources()}</span>
            <span class="stat-value stat-numeric">{($networkStats.epx_sources_received ?? 0).toLocaleString()}</span>
          </div>
        </div>

        <div class="stat-group">
          <div class="stat-tile tile-wide">
            <span class="stat-label">{m.kad_stat_external_ip()}</span>
            <span class="stat-value stat-ip">{$networkStats.status === 'disconnected' ? m.common_unknown() : ($networkStats.external_ip || m.kad_detecting())}</span>
          </div>
          <div class="stat-tile tile-wide">
            <span class="stat-label">{m.kad_stat_firewall()}</span>
            {#if $networkStats.status === 'disconnected'}
              <span class="badge unknown"><span class="badge-glyph" aria-hidden="true">?</span> {m.common_unknown()}</span>
            {:else if $networkStats.status === 'connecting'}
              <span class="badge unknown"><span class="badge-glyph" aria-hidden="true">&#x25CB;</span> {m.kad_checking()}</span>
            {:else}
              <span
                class="badge {$networkStats.firewalled ? 'firewalled' : 'open'}"
                role="status"
                aria-label={$networkStats.firewalled
                  ? m.kad_firewall_aria_firewalled()
                  : m.kad_firewall_aria_open()}
              >
                <span class="badge-glyph" aria-hidden="true">
                  {#if $networkStats.firewalled}&#x26A0;{:else}&#x2713;{/if}
                </span>
                {$networkStats.firewalled ? m.kad_firewall_firewalled() : m.kad_firewall_open()}
              </span>
            {/if}
          </div>
        </div>

        <div class="stat-group stat-group-grid">
          <div class="stat-tile">
            <span class="stat-label">{m.kad_stat_tcp()}</span>
            <span class="stat-value">{firewallStatusText($networkStats.tcp_status)}</span>
          </div>
          <div class="stat-tile">
            <span class="stat-label">{m.kad_stat_udp()}</span>
            <span class="stat-value">{firewallStatusText($networkStats.udp_status)}</span>
          </div>
          <div class="stat-tile">
            <span class="stat-label">{m.kad_stat_upnp()}</span>
            {#if !upnpEnabled || $upnpAutoDisabled}
              <button
                type="button"
                class="stat-link"
                onclick={() => goto('/settings')}
                title={m.kad_upnp_disabled_title()}
              >{m.kad_upnp_disabled()}</button>
            {:else}
              <span class="stat-value">{$networkStats.upnp_mapped ? m.kad_upnp_mapped() : m.kad_upnp_not_mapped()}</span>
            {/if}
          </div>
          <div class="stat-tile">
            <span class="stat-label">{m.kad_stat_buddy()}</span>
            <span class="stat-value">
              {!$networkStats.buddy_status || $networkStats.buddy_status === 'none' ? m.kad_buddy_none() :
               $networkStats.buddy_status.startsWith('connected') ? m.kad_buddy_connected() :
               $networkStats.buddy_status.startsWith('connecting') ? m.kad_buddy_connecting() :
               $networkStats.buddy_status.startsWith('serving') ? m.kad_buddy_serving() :
               $networkStats.buddy_status}
            </span>
          </div>
        </div>

        <div class="stats-actions">
          <button
            class="ghost"
            onclick={() => openBootstrap('ip')}
            disabled={$networkStats.status === 'disconnected'}
            title={m.kad_bootstrap_title()}
          >
            {m.kad_bootstrap_button()}
          </button>
          <button
            class="ghost"
            onclick={handleRecheckFirewall}
            disabled={!isConnected || rechecking}
            title={rechecking ? m.kad_firewall_in_progress() : m.kad_firewall_recheck_title()}
          >
            {#if rechecking}
              <span class="spinner-inline" aria-hidden="true"></span> {m.kad_rechecking()}
            {:else}
              {m.kad_recheck_firewall()}
            {/if}
          </button>
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
          <h3 id="kad-bootstrap-title">{m.kad_bootstrap_modal_title()}</h3>
          <button class="modal-close" aria-label={m.common_close()} onclick={() => (bootstrapOpen = false)}>×</button>
        </div>
        <div class="modal-body">
          <div class="bootstrap-tabs" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={bootstrapMode === 'ip'}
              class:active={bootstrapMode === 'ip'}
              onclick={() => (bootstrapMode = 'ip')}
            >{m.kad_bootstrap_tab_ip()}</button>
            <button
              type="button"
              role="tab"
              aria-selected={bootstrapMode === 'url'}
              class:active={bootstrapMode === 'url'}
              onclick={() => (bootstrapMode = 'url')}
            >{m.kad_bootstrap_tab_url()}</button>
            <button
              type="button"
              role="tab"
              aria-selected={bootstrapMode === 'clients'}
              class:active={bootstrapMode === 'clients'}
              onclick={() => (bootstrapMode = 'clients')}
            >{m.kad_bootstrap_tab_clients()}</button>
          </div>

          {#if bootstrapMode === 'ip'}
            <p class="bootstrap-hint">{m.kad_bootstrap_hint_ip()}</p>
            <div class="form-row">
              <label class="form-label" for="kad-bs-host">{m.kad_bootstrap_host_label()}</label>
              <input
                id="kad-bs-host"
                type="text"
                class="form-input"
                bind:value={bootstrapIpHost}
                bind:this={bootstrapHostInput}
                placeholder={m.kad_bootstrap_host_placeholder()}
                autocomplete="off"
                onkeydown={(e) => { if (e.key === 'Enter' && !bootstrapPending && bootstrapIpHost.trim()) { e.preventDefault(); void handleBootstrap(); } }}
              />
            </div>
            <div class="form-row">
              <label class="form-label" for="kad-bs-port">{m.servers_port()}</label>
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
            <p class="bootstrap-hint">
              {m.kad_bootstrap_hint_url_prefix()}
              <code>nodes.dat</code>
              {m.kad_bootstrap_hint_url_suffix()}
            </p>
            <div class="form-row">
              <label class="form-label" for="kad-bs-url">{m.servers_url_label()}</label>
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
            <p class="bootstrap-hint">{m.kad_bootstrap_hint_clients()}</p>
          {/if}
        </div>
        <div class="modal-footer">
          <button class="ghost" onclick={() => (bootstrapOpen = false)} disabled={bootstrapPending}>{m.common_cancel()}</button>
          <button
            class="primary"
            onclick={handleBootstrap}
            disabled={bootstrapPending
              || (bootstrapMode === 'ip' && !bootstrapIpHost.trim())
              || (bootstrapMode === 'url' && !bootstrapUrl.trim())}
          >
            {#if bootstrapPending}
              <span class="spinner-inline" aria-hidden="true"></span> {m.kad_working()}
            {:else}
              {m.kad_bootstrap_action()}
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
      <span>{m.kad_searches_section({ count: searches.length })}</span>
    </div>
    <div class="panel-content scrollable scroll-shadows">
      {#if $networkStats.status !== 'connected' && $networkStats.status !== 'connecting'}
        <div class="empty-state compact">
          <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="48" height="48"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path><line x1="8" y1="12" x2="16" y2="12"></line><line x1="2" y1="2" x2="22" y2="22"></line></svg>
          <p>{m.kad_not_connected()}</p>
          <p class="sub">{m.kad_searches_empty_disconnected_sub()}</p>
          <button class="empty-action" onclick={handleConnect}>{m.servers_connect()}</button>
        </div>
      {:else if searches.length === 0}
        <div class="empty-state compact">
          <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="48" height="48"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
          <p>{m.kad_searches_empty_title()}</p>
          <p class="sub">{m.kad_searches_empty_sub()}</p>
        </div>
      {:else}
        <table class="compact-table">
          <thead>
            <tr>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'id' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('id')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('id'))}>
                #{getSortArrow(searchSortCol, 'id', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'target' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('target')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('target'))}>
                {m.kad_search_col_key()}{getSortArrow(searchSortCol, 'target', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'type' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('type')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('type'))}>
                {m.kad_search_col_type()}{getSortArrow(searchSortCol, 'type', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'name' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('name')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('name'))}>
                {m.kad_search_col_name()}{getSortArrow(searchSortCol, 'name', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'status' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('status')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('status'))}>
                {m.kad_search_col_status()}{getSortArrow(searchSortCol, 'status', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'load' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('load')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('load'))}>
                {m.kad_search_col_load()}{getSortArrow(searchSortCol, 'load', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'packets_sent' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('packets_sent')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('packets_sent'))}>
                {m.kad_search_col_packets()}{getSortArrow(searchSortCol, 'packets_sent', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'responses' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('responses')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('responses'))}>
                {m.kad_search_col_responses()}{getSortArrow(searchSortCol, 'responses', searchSortAsc)}
              </th>
              <th class="sortable" tabindex="0" role="columnheader" aria-sort={searchSortCol === 'started_at' ? (searchSortAsc ? 'ascending' : 'descending') : 'none'} onclick={() => sortSearches('started_at')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortSearches('started_at'))}>
                {m.kad_search_col_age()}{getSortArrow(searchSortCol, 'started_at', searchSortAsc)}
              </th>
              <th aria-label={m.servers_col_actions()}></th>
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
                    {search.status === 'active' ? m.kad_search_status_active() : m.kad_search_status_stopping()}
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
                      title={m.kad_search_cancel_title()}
                      aria-label={m.kad_search_cancel_aria({ id: search.id })}
                      onclick={() => handleCancelSearch(search.id)}
                    >
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
                    </button>
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
    /* Inside a flex-column tile the default button width stretches
       to the tile's full width and `text-align: center` centers the
       label. Align-self keeps the button at its intrinsic width so
       the link lines up with the label above it. */
    align-self: flex-start;
    text-align: left;
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

  /*
   * Stats panel redesigned as stacked "stat tiles" grouped into three
   * logical sections: overall health, peer counts, and reachability.
   * Each tile stacks its label above its value so long values (badges,
   * IP addresses, "Not Mapped") get the full tile width and never
   * truncate. Group separators replace per-row dashed borders so the
   * card reads calmer and more scannable.
   *
   * Container-query responsive: two / four columns when the panel is
   * wide, one / two columns when it's narrow (sidebar-constrained).
   */
  .stats-panel {
    container-type: inline-size;
  }

  .stat-group {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2px 12px;
    padding: 6px 0;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 55%, transparent);
  }

  .stat-group:first-of-type {
    padding-top: 0;
  }

  .stat-group:last-of-type {
    padding-bottom: 0;
    border-bottom: none;
  }

  /* Action row at the foot of the Network Status panel (Bootstrap /
     Recheck Firewall). */
  .stats-actions {
    display: flex;
    gap: 8px;
    margin-top: 14px;
  }

  .stats-actions button {
    flex: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    font-size: 12px;
    padding: 7px 10px;
    white-space: nowrap;
  }

  .stat-group-grid {
    grid-template-columns: repeat(4, 1fr);
    gap: 2px 8px;
  }

  .stat-tile {
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 6px 0;
    min-width: 0;
  }

  .tile-wide {
    grid-column: span 1;
  }

  /* At narrow panel widths, collapse the 4-up numeric group to 2-up
     and the 2-up groups stay 2-up (labels are short enough). Below
     ~220px everything stacks single column. */
  @container (max-width: 330px) {
    .stat-group-grid {
      grid-template-columns: repeat(2, 1fr);
    }
  }

  @container (max-width: 220px) {
    .stat-group,
    .stat-group-grid {
      grid-template-columns: 1fr;
    }
  }

  .stat-label {
    color: var(--text-muted);
    font-weight: 500;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .stat-value {
    color: var(--text-primary);
    font-weight: 600;
    font-size: 13px;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* Numeric readouts get the larger "stat card" treatment so peer
     counts read at a glance. Tabular numerals keep digits aligned
     across rows. */
  .stat-numeric {
    font-size: 18px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    letter-spacing: -0.3px;
  }

  .stat-ip {
    font-family: var(--font-mono);
    font-size: 12px;
  }

  /* Badges inside tiles shouldn't stretch — they sit at their natural
     width so the tile column stays flexible. */
  .stat-tile .badge {
    align-self: flex-start;
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

  .compact-table tbody tr.row-alt td,
  .compact-table tbody tr:nth-child(even):not(.virtual-row):not(.spacer-row) td {
    background: color-mix(in srgb, var(--bg-secondary) 88%, var(--bg-primary));
  }

  /*
   * `.contact-id` and `.distance` are reused by the Searches table's
   * Key column (monospace hex + muted color). The Contacts table
   * additionally wants a flex layout so the hover-revealed Copy button
   * can sit on the right edge — but turning `<td>` into `display: flex`
   * breaks table column alignment everywhere else the class is used.
   *
   * Solution: keep the base style as plain table-cell, and only switch
   * to flex layout when the cell has a `.cell-content` + `.copy-btn`
   * wrapper inside (i.e. only the Contacts table rows).
   */
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

  .contact-id:has(> .copy-btn),
  .distance:has(> .copy-btn) {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .cell-content {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .copy-btn {
    padding: 2px !important;
    min-width: 0;
    width: 18px;
    height: 18px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    opacity: 0;
    transition: opacity 0.1s;
    color: var(--text-muted);
  }

  .copy-btn svg {
    width: 12px;
    height: 12px;
  }

  tr:hover .copy-btn,
  .copy-btn:focus-visible {
    opacity: 1;
  }

  .copy-btn:hover {
    color: var(--text-primary);
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

  /* Local badge variants. Follow the same tinted-chip recipe as the
     global badges in app.css so the KAD page matches in both themes. */
  .badge.open {
    background: color-mix(in srgb, var(--success) 15%, transparent);
    border-color: color-mix(in srgb, var(--success) 30%, transparent);
    color: color-mix(in srgb, var(--success) 85%, #000);
  }

  .badge.firewalled {
    background: color-mix(in srgb, var(--warning) 15%, transparent);
    border-color: color-mix(in srgb, var(--warning) 30%, transparent);
    color: color-mix(in srgb, var(--warning) 80%, #000);
  }

  .badge.unknown {
    background: color-mix(in srgb, var(--text-muted) 18%, transparent);
    border-color: color-mix(in srgb, var(--text-muted) 32%, transparent);
    color: var(--text-secondary);
  }

  .badge.stopping {
    background: color-mix(in srgb, var(--warning) 15%, transparent);
    border-color: color-mix(in srgb, var(--warning) 30%, transparent);
    color: color-mix(in srgb, var(--warning) 80%, #000);
  }

  :global([data-theme="dark"]) .badge.open {
    background: color-mix(in srgb, var(--success) 18%, transparent);
    border-color: color-mix(in srgb, var(--success) 32%, transparent);
    color: #8fd9a3;
  }
  :global([data-theme="dark"]) .badge.firewalled,
  :global([data-theme="dark"]) .badge.stopping {
    background: color-mix(in srgb, var(--warning) 18%, transparent);
    border-color: color-mix(in srgb, var(--warning) 32%, transparent);
    color: #f0c37a;
  }
  :global([data-theme="dark"]) .badge.unknown {
    background: color-mix(in srgb, var(--text-muted) 22%, transparent);
    border-color: color-mix(in srgb, var(--text-muted) 38%, transparent);
    color: var(--text-secondary);
  }

  /* Per-row Cancel button: small ghost variant that lines up with the
     compact table's tight 26-px row height. Uses V2's existing `.ghost`
     button class for the base look so the visual language stays
     consistent across the app. */
  .cancel-btn {
    padding: 2px !important;
    min-width: 0;
    width: 20px;
    height: 20px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: var(--text-muted);
  }

  .cancel-btn svg {
    width: 14px;
    height: 14px;
  }

  .cancel-btn:hover {
    color: var(--danger);
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
