<script lang="ts">
  /*
   * "Ember Network" page, and the one the app opens on. The network status
   * panel comes first — status, reachability and sharing in plain language,
   * then the counters — and the routing contacts and protocol tables wait
   * under a collapsed "Technical details". Only what is on screen is polled:
   * while that section is open, the contacts and the table of the open tab.
   *
   * The overlay is always on.
   */
  import { onMount } from 'svelte';
  import {
    getEmberDiagnostics,
    getEmberDhtContacts,
    getEmberDhtSearches,
    getEmberDhtStore,
  } from '$lib/api/ember';
  import type {
    EmberDiagnostics,
    EmberDhtContact,
    EmberDhtSearchEntry,
    EmberDhtStoreEntry,
  } from '$lib/types';
  import { copyToClipboard, formatDurationSecs, formatNumber } from '$lib/utils';
  import { getLocale, translateError } from '$lib/i18n';
  import { plural } from '$lib/plural';
  import { EMBER_DIAG_FAILURE_THRESHOLD } from '$lib/emberJoin';
  import { emberJoinTimedOut } from '$lib/stores/emberJoin';
  import { checkForUpdates, installUpdate, restartToUpdate, updater } from '$lib/stores/updater';
  import NetworkStatusTiles from '$lib/components/NetworkStatusTiles.svelte';
  import PortTest from '$lib/components/PortTest.svelte';
  import { appSettings } from '$lib/stores/settings';
  import { networkStats } from '$lib/stores/network';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import IconX from '$lib/components/IconX.svelte';
  import { relaunch } from '@tauri-apps/plugin-process';
  import { flushToastActionsBeforeExit } from '$lib/stores/toast';
  import * as m from '$lib/paraglide/messages';

  let diag = $state<EmberDiagnostics | null>(null);
  let contacts = $state<EmberDhtContact[]>([]);
  /** A contacts fetch has answered since Technical details was opened, so an
   *  empty `contacts` means no peers rather than not asked yet or failing. */
  let contactsLoaded = $state(false);
  /** The last contacts fetch failed, so a panel with nothing loaded says so
   *  rather than spinning while the call keeps failing. */
  let contactsFailed = $state(false);
  let searches = $state<EmberDhtSearchEntry[]>([]);
  let storeEntries = $state<EmberDhtStoreEntry[]>([]);
  let contactFilter = $state('');
  let metricFilter = $state('');

  // Device-local view state, like collapsed sections elsewhere: not carried
  // by a profile backup.
  const LOWER_TAB_KEY = 'ember.page.lower-tab.v1';
  const GROWING_DISMISSED_KEY = 'ember.page.growing-dismissed.v1';
  const DETAILS_OPEN_KEY = 'ember.page.details-open.v1';
  type LowerTab = 'searches' | 'store' | 'stats' | 'identity';
  const LOWER_TABS: LowerTab[] = ['searches', 'store', 'stats', 'identity'];
  function readFlag(key: string): boolean {
    try {
      return typeof localStorage !== 'undefined' && localStorage.getItem(key) === '1';
    } catch {
      return false;
    }
  }
  function writeFlag(key: string, on: boolean) {
    try {
      if (on) localStorage.setItem(key, '1');
      else localStorage.removeItem(key);
    } catch {
      // Storage disabled: the choice holds for this visit.
    }
  }
  function readLowerTab(): LowerTab {
    try {
      const saved = typeof localStorage !== 'undefined' ? localStorage.getItem(LOWER_TAB_KEY) : null;
      return LOWER_TABS.includes(saved as LowerTab) ? (saved as LowerTab) : 'searches';
    } catch {
      return 'searches';
    }
  }
  let lowerTab = $state<LowerTab>(readLowerTab());
  function selectLowerTab(tab: LowerTab) {
    if (tab === lowerTab) return;
    lowerTab = tab;
    try {
      localStorage.setItem(LOWER_TAB_KEY, tab);
    } catch {
      // Storage disabled: the choice holds for this visit.
    }
    void refreshLists();
  }
  /** Arrow keys move between tabs, the tablist pattern. */
  function onTabKeydown(e: KeyboardEvent) {
    const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    const edge = e.key === 'Home' ? 0 : e.key === 'End' ? LOWER_TABS.length - 1 : -1;
    if (!step && edge < 0) return;
    e.preventDefault();
    const at = LOWER_TABS.indexOf(lowerTab);
    const next = edge >= 0 ? edge : (at + step + LOWER_TABS.length) % LOWER_TABS.length;
    selectLowerTab(LOWER_TABS[next]);
    document.getElementById(`ember-tab-${LOWER_TABS[next]}`)?.focus();
  }
  let growingDismissed = $state(readFlag(GROWING_DISMISSED_KEY));
  function dismissGrowing() {
    growingDismissed = true;
    writeFlag(GROWING_DISMISSED_KEY, true);
  }
  let detailsOpen = $state(readFlag(DETAILS_OPEN_KEY));
  function onDetailsToggle(e: Event) {
    const open = (e.currentTarget as HTMLDetailsElement).open;
    if (open === detailsOpen) return;
    detailsOpen = open;
    writeFlag(DETAILS_OPEN_KEY, open);
    if (open) void refreshLists();
    else {
      contactsLoaded = false;
      contactsFailed = false;
    }
  }
  let showRestartPrompt = $state(false);
  let restarting = $state(false);
  let restartError = $state('');

  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let unmounted = false;
  let inFlightDiag = false;
  let inFlightLists = false;

  // Diagnostics-health state. `diagStale` raises a banner once polling has
  // failed several times in a row (the service is down, not just a transient
  // blip), so the numbers below aren't silently mistaken for live ones. The
  // join timeout is the app-wide `emberJoinTimedOut`, shared with the status
  // bar, so opening this page cannot restart a grace period the status bar
  // has already given up on.
  let diagStale = $state(false);
  let diagFailures = 0;
  const DIAG_FAILURE_THRESHOLD = EMBER_DIAG_FAILURE_THRESHOLD;

  async function refreshDiag() {
    if (unmounted || inFlightDiag) return;
    inFlightDiag = true;
    try {
      diag = await getEmberDiagnostics();
      diagFailures = 0;
      diagStale = false;
    } catch {
      // Tolerate transient blips (keep the previous snapshot), but surface
      // a banner once the service has been unreachable for several polls.
      diagFailures += 1;
      if (diagFailures >= DIAG_FAILURE_THRESHOLD) diagStale = true;
    } finally {
      inFlightDiag = false;
    }
    await refreshLists();
  }

  // The contacts are on screen while Technical details is open; the search
  // and store snapshots only under their own tab, so each tick asks for those
  // alone. Guarded
  // separately from the diagnostics poll, so switching tabs fills the table
  // at once unless a list fetch is already in flight, which the next tick
  // then completes.
  async function refreshLists() {
    if (unmounted || inFlightLists) return;
    if (!diag?.ember_native_enabled) {
      contacts = [];
      contactsLoaded = true;
      searches = [];
      storeEntries = [];
      return;
    }
    if (!detailsOpen) return;
    inFlightLists = true;
    const tab = lowerTab;
    let contactsFetched = false;
    let contactsRefused = false;
    try {
      const [c, s, st] = await Promise.all([
        getEmberDhtContacts().then(
          (list) => {
            contactsFetched = true;
            return list;
          },
          () => {
            contactsRefused = true;
            return contacts;
          },
        ),
        tab === 'searches' ? getEmberDhtSearches().catch(() => searches) : Promise.resolve(searches),
        tab === 'store' ? getEmberDhtStore().catch(() => storeEntries) : Promise.resolve(storeEntries),
      ]);
      if (!unmounted) {
        contacts = c;
        if (contactsFetched && detailsOpen) contactsLoaded = true;
        if (detailsOpen) contactsFailed = contactsRefused;
        searches = s;
        storeEntries = st;
      }
    } finally {
      inFlightLists = false;
    }
  }

  // Sorted like the KAD page's contacts: a header click picks the column, a
  // second reverses it. By default, contacts that have answered come first,
  // most recently heard first; the rest keep the routing table's order.
  type ContactSortCol = 'node' | 'answered' | 'seen' | 'distance';
  let contactSortCol = $state<ContactSortCol>('answered');
  let contactSortAsc = $state(true);
  let contactScrollEl = $state<HTMLDivElement>();

  function sortContactsBy(col: ContactSortCol) {
    if (contactSortCol === col) contactSortAsc = !contactSortAsc;
    else {
      contactSortCol = col;
      contactSortAsc = true;
    }
    if (contactScrollEl) contactScrollEl.scrollTop = 0;
  }

  /** Most recently heard first; never heard from last. */
  function bySeen(a: EmberDhtContact, b: EmberDhtContact): number {
    const seenA = a.last_seen ?? 0;
    const seenB = b.last_seen ?? 0;
    if ((seenA > 0) !== (seenB > 0)) return seenA > 0 ? -1 : 1;
    return seenB - seenA;
  }

  function compareContacts(a: EmberDhtContact, b: EmberDhtContact): number {
    switch (contactSortCol) {
      case 'node':
        return a.node_id.localeCompare(b.node_id);
      case 'distance':
        // Hex of one length, so text order is numeric order; unknown last.
        if (!a.distance || !b.distance) return a.distance ? -1 : b.distance ? 1 : 0;
        return a.distance.localeCompare(b.distance);
      case 'seen':
        return bySeen(a, b);
      case 'answered': {
        const answeredA = contactAnswered(a);
        const answeredB = contactAnswered(b);
        if (answeredA !== answeredB) return answeredA ? -1 : 1;
        return answeredA ? bySeen(a, b) : 0;
      }
    }
  }

  let sortedContacts = $derived.by(() => {
    const dir = contactSortAsc ? 1 : -1;
    return [...contacts].sort((a, b) => dir * compareContacts(a, b));
  });

  let filteredContacts = $derived.by(() => {
    const q = contactFilter.trim().toLowerCase();
    if (!q) return sortedContacts;
    return sortedContacts.filter(
      (c) =>
        c.node_id.toLowerCase().includes(q) ||
        (c.distance ?? '').toLowerCase().includes(q),
    );
  });

  function emberSearchTypeLabel(type: string): string {
    switch (type) {
      case 'Node': return m.ember_dht_search_type_node();
      case 'Value': return m.ember_dht_search_type_value();
      default: return type;
    }
  }

  let copiedKey = $state<string | null>(null);
  let copyTimer: ReturnType<typeof setTimeout> | null = null;

  // Same relaunch as a port change in Settings: confirm first, paint the
  // full-screen "Restarting Ember" overlay, then Tauri's relaunch().
  async function performRestart() {
    showRestartPrompt = false;
    restartError = '';
    restarting = true;
    try {
      // Also sends anything still behind an Undo toast.
      await Promise.all([new Promise((r) => setTimeout(r, 600)), flushToastActionsBeforeExit()]);
      await relaunch();
    } catch (e) {
      restarting = false;
      restartError = m.settings_restart_failed({ error: translateError(e) });
    }
  }

  async function copyText(value: string, key: string) {
    if (!value) return;
    // See `copyToClipboard`: the webview API alone fails on platforms where
    // the OS clipboard is fine.
    copiedKey = (await copyToClipboard(value)) ? key : `${key}:error`;
    if (copyTimer) clearTimeout(copyTimer);
    copyTimer = setTimeout(() => { copiedKey = null; }, 1500);
  }

  let isActive = $derived(!!diag?.ember_native_enabled);
  let versionPeerNewer = $derived(diag?.ember_dht_version_peer_newer ?? 0);
  let versionPeerOlder = $derived(diag?.ember_dht_version_peer_older ?? 0);
  let versionMismatch = $derived(diag?.ember_dht_version_mismatch ?? 0);
  // Split counters are new; an older diagnostics payload only has the total.
  // Treat a positive total with no split as the previous "they should update" banner.
  let showNewerVersionBanner = $derived(isActive && versionPeerNewer > 0);
  let showOlderVersionBanner = $derived(
    isActive &&
      (versionPeerOlder > 0 ||
        (versionMismatch > 0 && versionPeerNewer === 0 && versionPeerOlder === 0)),
  );
  // The corner UpdateNotice stays silent for "up to date", for a failed check
  // with no version yet, and for a version the user dismissed — so the
  // banner's own "Check for updates" reports the outcome next to the button.
  let updateResult = $derived(
    $updater.phase === 'uptodate'
      ? m.updater_uptodate()
      : $updater.phase === 'available'
        ? m.updater_available_status({ version: $updater.version ?? '' })
        : $updater.phase === 'ready'
          ? m.updater_ready_body({ version: $updater.version ?? '' })
          : $updater.phase === 'error' || $updater.signatureMissing
            ? m.updater_error_body({ detail: $updater.error ?? m.updater_signature_missing() })
            : '',
  );
  let peerCount = $derived(diag?.ember_dht_contacts ?? 0);
  let verifiedCount = $derived(diag?.ember_dht_verified_contacts ?? 0);
  let publishedCount = $derived(diag?.ember_dht_published_files ?? 0);
  let publishableCount = $derived(diag?.ember_dht_publishable_files ?? 0);
  // Never show "200 of 50": a live advert can briefly outlast the share list
  // (TTL) or the publish manager can still be empty while hydrated stamps
  // already light badges.
  let publishedTotal = $derived(Math.max(publishableCount, publishedCount));
  // From diagnostics, so the tab counts hold while their tables are not polled.
  let activeSearches = $derived(diag?.ember_dht_active_searches ?? 0);
  let storedKeys = $derived(diag?.ember_dht_stored_keys ?? 0);
  let publishedInProgress = $derived(publishedTotal > 0 && publishedCount < publishedTotal);
  let joining = $derived(isActive && verifiedCount === 0 && !$emberJoinTimedOut);
  let isConnected = $derived(isActive && verifiedCount > 0);

  // No "off" state: the backend forces the overlay on at load and on every
  // settings save, so a diagnostics reply never reports it disabled.
  type HeroState = 'loading' | 'connecting' | 'connected' | 'no_peers';
  let heroState: HeroState = $derived(
    diag === null
      ? 'loading'
      : isConnected
        ? 'connected'
        : joining
          ? 'connecting'
          : 'no_peers',
  );

  // Until the first diagnostics land we genuinely don't know the state.
  let statusLabel = $derived(
    heroState === 'loading'
      ? m.common_loading()
      : heroState === 'connected'
        ? m.ember_status_connected()
        : heroState === 'connecting'
          ? m.ember_status_connecting()
          : m.ember_status_no_peers(),
  );

  let statusHint = $derived(
    heroState === 'loading'
      ? ''
      : heroState === 'connected'
        ? m.ember_status_connected_hint()
        : heroState === 'connecting'
          ? m.ember_joining_hint()
          : m.ember_no_contacts_hint(),
  );

  // "Checking" outranks "relayed": without a known external address the
  // firewall verdict isn't settled yet, so claiming a relay is in use
  // would be guessing. Before the flags have been evaluated at all they
  // all read false, which must not be taken for "direct".
  type Reachability = 'direct' | 'relayed' | 'checking' | 'waiting_buddy';
  let reachability: Reachability = $derived(
    diag?.ember_dht_udp_unreachable || !diag?.ember_dht_reachability_known
      ? 'checking'
      : diag?.ember_dht_waiting_buddy
        ? 'waiting_buddy'
        : diag?.ember_dht_firewalled_publishing
          ? 'relayed'
          : 'direct',
  );

  let reachabilityLabel = $derived(
    reachability === 'direct'
      ? m.ember_health_direct()
      : reachability === 'relayed'
        ? m.ember_health_relayed()
        : reachability === 'waiting_buddy'
          ? m.ember_health_waiting_buddy()
          : m.kad_checking(),
  );

  let reachabilityHint = $derived(
    reachability === 'direct'
      ? m.ember_health_direct_hint()
      : reachability === 'relayed'
        ? m.ember_dht_firewalled_publishing_hint()
        : reachability === 'waiting_buddy'
          ? m.ember_dht_waiting_buddy_hint()
          : m.ember_dht_udp_unreachable_hint(),
  );

  // The Network Status card's relay tile, in place of KAD's buddy. Reachable:
  // the firewalled Ember users we are relaying for now. Firewalled: whether
  // someone relays for us. Follows the reachability verdict, so the two agree.
  let relayingFor = $derived(diag?.ember_dht_relaying_for ?? 0);
  let emberRelayValue = $derived(
    !diag
      ? m.common_unknown()
      : reachability === 'checking'
        ? m.kad_checking()
        : reachability === 'waiting_buddy'
          ? m.ember_relay_looking()
          : reachability === 'relayed'
            ? m.ember_relay_using()
            : relayingFor > 0
              ? plural(relayingFor, {
                  one: () => m.ember_relay_relaying_for_one({ count: formatNumber(relayingFor) }),
                  oneShowsCount: true,
                  few: () => m.ember_relay_relaying_for_few({ count: formatNumber(relayingFor) }),
                  other: () => m.ember_relay_relaying_for_other({ count: formatNumber(relayingFor) }),
                })
              : m.ember_relay_none(),
  );
  let emberRelayTitle = $derived(
    reachability === 'waiting_buddy' || reachability === 'relayed'
      ? m.ember_relay_firewalled_title()
      : m.ember_relay_open_title(),
  );

  // What a relayed user can do about it. Forwarding on the router does nothing
  // while traffic leaves through a VPN (the backend has stood UPnP down for
  // exactly that), and is no advice at all once UPnP has already forwarded
  // the ports, so those cases point elsewhere.
  let relayedFix = $derived.by(() => {
    if (reachability !== 'relayed' || !$appSettings) return '';
    const ports = { tcp: $appSettings.tcp_port, udp: $appSettings.udp_port };
    if (!$appSettings.upnp_enabled) return m.ember_health_relayed_fix_upnp_off(ports);
    if ($networkStats.upnp_stood_down) return m.ember_health_relayed_fix_vpn(ports);
    if ($networkStats.upnp_mapped) return m.ember_health_relayed_fix_forwarded();
    return m.ember_health_relayed_fix(ports);
  });

  // Deliberately the live count of files with a placed source record, not the
  // session `*_published` counters: those only ever climb, so they would keep
  // claiming "Published" after the user unshared everything, and a keyword ack
  // alone would flip the pill before the source record that actually makes the
  // file fetchable. This is the same set behind the Library's Ember badge.
  let sharingPublished = $derived(publishedCount > 0);

  type PillTone = 'ok' | 'warn' | 'muted';

  let reachabilityTone: PillTone = $derived(
    reachability === 'direct' ? 'ok' : reachability === 'relayed' || reachability === 'waiting_buddy' ? 'warn' : 'muted',
  );

  let sharingPillLabel = $derived(
    publishedTotal > 0
      ? m.ember_overview_published_of({ published: formatNumber(publishedCount), total: formatNumber(publishedTotal) })
      : sharingPublished
        ? m.ember_health_sharing_published_count({ count: formatNumber(publishedCount) })
        : m.ember_health_sharing_waiting(),
  );
  // A green "Published" next to "Connecting…" is a contradiction: the count
  // is restored from the last successful STORE (still inside TTL) even
  // while this session has nobody who has answered. Warn until a live peer
  // exists so the badge is not read as "you are on the network".
  let sharingTone: PillTone = $derived(
    publishedTotal === 0 && !sharingPublished
      ? 'muted'
      : publishedInProgress || !isConnected
        ? 'warn'
        : 'ok',
  );
  let sharingHint = $derived(
    publishedTotal === 0 && !sharingPublished
      ? m.ember_health_sharing_waiting_hint()
      : publishedInProgress && isConnected
        ? m.ember_health_sharing_publishing_hint({
            remaining: formatNumber(publishedTotal - publishedCount),
          })
        : isConnected
          ? m.ember_health_sharing_published_hint()
          : m.ember_health_sharing_published_rejoining_hint(),
  );

  // The estimate is a density measurement, so it is shown as approximate and
  // as unknown until the backend has enough answered contacts to make one.
  let estimatedNodes = $derived(
    (diag?.ember_dht_estimated_nodes ?? 0) > 0
      ? `~${formatNumber(diag?.ember_dht_estimated_nodes ?? 0)}`
      : '\u2014',
  );
  // Null means nothing has ever arrived, which reads as unknown; zero is a
  // frame this second.
  let lastInboundLabel = $derived.by(() => {
    const secs = diag?.ember_dht_seconds_since_inbound;
    return secs == null ? '\u2014' : formatDurationSecs(secs);
  });

  const msFormat = new Intl.NumberFormat(getLocale(), {
    style: 'unit',
    unit: 'millisecond',
    unitDisplay: 'short',
    maximumFractionDigits: 0,
  });
  // The storer's load byte is a percentage of its per-key capacity.
  const percentFormat = new Intl.NumberFormat(getLocale(), {
    style: 'percent',
    maximumFractionDigits: 0,
  });

  function searchAvg(sum: number | undefined, outcomes: number): string {
    if (outcomes <= 0) return '\u2014';
    return formatNumber(Math.round((sum ?? 0) / outcomes));
  }

  function contactAnswered(c: EmberDhtContact): boolean {
    return (c.last_seen ?? 0) > 0;
  }

  function contactLastSeen(c: EmberDhtContact): string {
    const ts = c.last_seen ?? 0;
    if (ts <= 0) return m.ember_dht_never_seen();
    return formatDurationSecs(Math.max(0, Math.floor(Date.now() / 1000) - ts));
  }

  // `id` exists so the `{#each}` below is keyed on something stable. Keying
  // on the label would put a translator in a position to crash the page:
  // two of these strings colliding in one locale is a duplicate-key error.
  let metrics = $derived.by(() => {
    const outcomes = diag?.ember_dht_search_outcomes ?? 0;
    return [
    { id: 'contacts', k: m.ember_stat_contacts(), v: formatNumber(peerCount) },
    { id: 'verified-contacts', k: m.ember_stat_verified_contacts(), v: formatNumber(diag?.ember_dht_verified_contacts ?? 0) },
    { id: 'verified-peak-today', k: m.ember_stat_verified_peak_today(), v: formatNumber(diag?.ember_dht_verified_highwater_today ?? 0) },
    { id: 'verified-peak-all', k: m.ember_stat_verified_peak_alltime(), v: formatNumber(diag?.ember_dht_verified_highwater ?? 0) },
    { id: 'network-size', k: m.ember_stat_network_size(), v: estimatedNodes },
    { id: 'last-inbound', k: m.ember_stat_last_inbound(), v: lastInboundLabel },
    { id: 'republish-backlog', k: m.ember_stat_republish_backlog(), v: formatNumber(diag?.ember_dht_republish_backlog ?? 0) },
    { id: 'cached-contacts', k: m.ember_stat_cached_contacts(), v: formatNumber(diag?.ember_dht_cached_contacts ?? 0) },
    { id: 'session-contacts', k: m.ember_stat_session_contacts(), v: formatNumber(diag?.ember_dht_session_contacts ?? 0) },
    { id: 'contacts-evicted', k: m.ember_stat_contacts_evicted(), v: formatNumber(diag?.ember_dht_contacts_evicted ?? 0) },
    { id: 'contacts-demoted', k: m.ember_stat_contacts_demoted(), v: formatNumber(diag?.ember_dht_contacts_demoted ?? 0) },
    { id: 'peer-lists', k: m.ember_stat_peer_lists_received(), v: formatNumber(diag?.ember_dht_peer_lists_received ?? 0) },
    { id: 'gossip-contacts', k: m.ember_stat_gossip_contacts(), v: formatNumber(diag?.ember_dht_gossip_contacts ?? 0) },
    { id: 'gossip-new', k: m.ember_stat_gossip_new(), v: formatNumber(diag?.ember_dht_gossip_new ?? 0) },
    { id: 'gossip-refused', k: m.ember_stat_gossip_refused(), v: formatNumber(diag?.ember_dht_gossip_refused ?? 0) },
    { id: 'gossip-rationed', k: m.ember_stat_gossip_leads_rationed(), v: formatNumber(diag?.ember_dht_gossip_leads_rationed ?? 0) },
    { id: 'gossip-introducers-rationed', k: m.ember_stat_gossip_introducers_rationed(), v: formatNumber(diag?.ember_dht_gossip_introducers_rationed ?? 0) },
    { id: 'friend-contact-asks', k: m.ember_stat_friend_contact_asks(), v: formatNumber(diag?.ember_dht_friend_contact_asks ?? 0) },
    { id: 'friend-contacts-learned', k: m.ember_stat_friend_contacts_learned(), v: formatNumber(diag?.ember_dht_friend_contacts_learned ?? 0) },
    { id: 'friend-meets', k: m.ember_stat_friend_meets(), v: formatNumber(diag?.ember_dht_friend_meets ?? 0) },
    { id: 'friend-meets-converted', k: m.ember_stat_friend_meets_converted(), v: formatNumber(diag?.ember_dht_friend_meets_converted ?? 0) },
    { id: 'liveness-pings', k: m.ember_stat_liveness_pings(), v: formatNumber(diag?.ember_dht_liveness_pings_sent ?? 0) },
    { id: 'pongs-received', k: m.ember_stat_pongs_received(), v: formatNumber(diag?.ember_dht_pongs_received ?? 0) },
    { id: 'peers', k: m.ember_stat_peers(), v: formatNumber(diag?.ember_peers_known ?? 0) },
    { id: 'sessions', k: m.ember_stat_sessions(), v: formatNumber(diag?.ember_sessions ?? 0) },
    { id: 'records', k: m.ember_stat_records(), v: formatNumber(diag?.ember_dht_stored_records ?? 0) },
    { id: 'published-files', k: m.ember_stat_published_files(), v: publishedTotal > 0 ? m.ember_overview_published_of({ published: formatNumber(publishedCount), total: formatNumber(publishedTotal) }) : formatNumber(publishedCount) },
    { id: 'stored-keys', k: m.ember_stat_stored_keys(), v: formatNumber(diag?.ember_dht_stored_keys ?? 0) },
    { id: 'stored-for-others', k: m.ember_stat_stored_for_others(), v: formatNumber(diag?.ember_dht_stored_for_others_records ?? 0) },
    { id: 'publishes', k: m.ember_stat_active_publishes(), v: formatNumber(diag?.ember_dht_active_publishes ?? 0) },
    { id: 'searches', k: m.ember_stat_active_searches(), v: formatNumber(diag?.ember_dht_active_searches ?? 0) },
    { id: 'search-hits', k: m.ember_stat_search_hits(), v: formatNumber(diag?.ember_dht_search_hits ?? 0) },
    { id: 'search-misses', k: m.ember_stat_search_misses(), v: formatNumber(diag?.ember_dht_search_misses ?? 0) },
    { id: 'search-avg-nodes', k: m.ember_stat_search_avg_nodes(), v: searchAvg(diag?.ember_dht_search_nodes_answered, outcomes) },
    { id: 'search-avg-ms', k: m.ember_stat_search_avg_ms(), v: outcomes <= 0 ? '\u2014' : msFormat.format(Math.round((diag?.ember_dht_search_elapsed_ms_sum ?? 0) / outcomes)) },
    { id: 'search-avg-records', k: m.ember_stat_search_avg_records(), v: searchAvg(diag?.ember_dht_search_records_sum, outcomes) },
    { id: 'store-acks', k: m.ember_stat_stores_acked(), v: formatNumber(diag?.ember_dht_stores_acked ?? 0) },
    { id: 'store-fails', k: m.ember_stat_stores_failed(), v: formatNumber(diag?.ember_dht_stores_failed ?? 0) },
    { id: 'replication', k: m.ember_stat_avg_replication(), v: formatNumber(diag?.ember_dht_avg_replication ?? 0) },
    { id: 'search-rounds', k: m.ember_stat_search_rounds(), v: formatNumber(diag?.ember_dht_search_rounds ?? 0) },
    { id: 'find-values', k: m.ember_stat_find_values_sent(), v: formatNumber(diag?.ember_dht_find_values_sent ?? 0) },
    { id: 'serve-hits', k: m.ember_stat_serve_hits(), v: formatNumber(diag?.ember_dht_find_value_hits ?? 0) },
    { id: 'serve-misses', k: m.ember_stat_serve_misses(), v: formatNumber(diag?.ember_dht_find_value_misses ?? 0) },
    { id: 'serve-truncated', k: m.ember_stat_truncated_answers(), v: formatNumber(diag?.ember_dht_found_value_truncated ?? 0) },
    { id: 'serve-withheld', k: m.ember_stat_withheld_records(), v: formatNumber(diag?.ember_dht_found_value_withheld ?? 0) },
    { id: 'buddy-pub', k: m.ember_stat_buddy_publishes(), v: formatNumber(diag?.ember_dht_buddy_publishes ?? 0) },
    { id: 'buddy-fwd', k: m.ember_stat_buddy_forwards(), v: formatNumber(diag?.ember_dht_buddy_forwards ?? 0) },
    { id: 'buddy-unendorsed', k: m.ember_stat_buddy_unendorsed(), v: formatNumber(diag?.ember_dht_buddy_unendorsed ?? 0) },
    { id: 'callback-sent', k: m.ember_stat_callback_sent(), v: formatNumber(diag?.ember_dht_callback_sent ?? 0) },
    { id: 'callback-fwd', k: m.ember_stat_callback_forwards(), v: formatNumber(diag?.ember_dht_callback_forwards ?? 0) },
    { id: 'callback-conn', k: m.ember_stat_callback_connects(), v: formatNumber(diag?.ember_dht_callback_connects ?? 0) },
    { id: 'malformed', k: m.ember_stat_malformed(), v: formatNumber(diag?.ember_dht_malformed ?? 0) },
    { id: 'version-mismatch', k: m.ember_stat_version_mismatch(), v: formatNumber(diag?.ember_dht_version_mismatch ?? 0) },
    { id: 'version-peer-older', k: m.ember_stat_version_peer_older(), v: formatNumber(diag?.ember_dht_version_peer_older ?? 0) },
    { id: 'version-peer-newer', k: m.ember_stat_version_peer_newer(), v: formatNumber(diag?.ember_dht_version_peer_newer ?? 0) },
    { id: 'rendezvous-listed', k: m.ember_stat_rendezvous_listed(), v: formatNumber(diag?.ember_dht_rendezvous_last_peers ?? 0) },
    { id: 'rendezvous-lookups', k: m.ember_stat_rendezvous_lookups(), v: formatNumber(diag?.ember_dht_rendezvous_lookups ?? 0) },
    { id: 'rendezvous-empty', k: m.ember_stat_rendezvous_empty(), v: formatNumber(diag?.ember_dht_rendezvous_empty ?? 0) },
    { id: 'rendezvous-key-load', k: m.ember_stat_rendezvous_key_load(), v: percentFormat.format((diag?.ember_dht_rendezvous_key_load ?? 0) / 100) },
    { id: 'observed-votes', k: m.ember_stat_observed_votes(), v: formatNumber(diag?.ember_dht_observed_votes ?? 0) },
    { id: 'observed-addr', k: m.ember_stat_observed_addr(), v: diag?.ember_dht_observed_addr || '—' },
    { id: 'epx-events', k: m.ember_stat_epx_events(), v: formatNumber(diag?.epx_events_received ?? 0) },
    { id: 'epx-offered', k: m.ember_stat_epx_sources_offered(), v: formatNumber(diag?.epx_sources_offered ?? 0) },
    { id: 'epx-filtered', k: m.ember_stat_epx_sources_filtered(), v: formatNumber(diag?.epx_sources_filtered ?? 0) },
    { id: 'epx-udp-oversized', k: m.ember_stat_epx_udp_oversized(), v: formatNumber(diag?.epx_udp_oversized_skipped ?? 0) },
    { id: 'store-key-cap', k: m.ember_stat_store_key_cap(), v: formatNumber(diag?.ember_dht_store_key_cap_rejections ?? 0) },
    { id: 'reject-verify', k: m.ember_stat_store_reject_verify(), v: formatNumber(diag?.ember_dht_store_reject_verify ?? 0) },
    { id: 'reject-sig', k: m.ember_stat_store_reject_signature(), v: formatNumber(diag?.ember_dht_store_reject_signature ?? 0) },
    { id: 'reject-time', k: m.ember_stat_store_reject_timestamp(), v: formatNumber(diag?.ember_dht_store_reject_timestamp ?? 0) },
    { id: 'reject-ip', k: m.ember_stat_store_reject_source_ip(), v: formatNumber(diag?.ember_dht_store_reject_source_ip ?? 0) },
    { id: 'reject-ip-cap', k: m.ember_stat_store_reject_source_ip_cap(), v: formatNumber(diag?.ember_dht_store_reject_source_ip_cap ?? 0) },
    { id: 'reject-pub', k: m.ember_stat_store_reject_publisher_cap(), v: formatNumber(diag?.ember_dht_store_reject_publisher_cap ?? 0) },
    { id: 'reject-key', k: m.ember_stat_store_reject_per_key_cap(), v: formatNumber(diag?.ember_dht_store_reject_per_key_cap ?? 0) },
    { id: 'reject-prox', k: m.ember_stat_store_reject_proximity(), v: formatNumber(diag?.ember_dht_store_reject_proximity ?? 0) },
    { id: 'keyword-key-off-name', k: m.ember_stat_keyword_key_off_name(), v: formatNumber(diag?.ember_dht_keyword_key_off_name ?? 0) },
    { id: 'unknown-record-types', k: m.ember_stat_unknown_record_types(), v: formatNumber(diag?.ember_dht_unknown_record_types ?? 0) },
    { id: 'version-advertisers', k: m.ember_stat_version_advertisers(), v: formatNumber(diag?.ember_dht_version_advertisers ?? 0) },
    { id: 'recall-searches', k: m.ember_stat_recall_searches(), v: formatNumber(diag?.ember_dht_recall_searches ?? 0) },
    { id: 'recall-both', k: m.ember_stat_recall_both(), v: formatNumber(diag?.ember_dht_recall_both ?? 0) },
    { id: 'recall-kad-only', k: m.ember_stat_recall_kad_only(), v: formatNumber(diag?.ember_dht_recall_kad_only ?? 0) },
    { id: 'recall-ember-only', k: m.ember_stat_recall_ember_only(), v: formatNumber(diag?.ember_dht_recall_ember_only ?? 0) },
    { id: 'rate-limited', k: m.ember_stat_rate_limited(), v: formatNumber(diag?.ember_dht_rate_limited ?? 0) },
    { id: 'store-addr-ceiling', k: m.ember_stat_store_addr_ceiling(), v: formatNumber(diag?.ember_dht_store_addr_ceiling ?? 0) },
    { id: 'udp-dropped-banned', k: m.ember_stat_udp_dropped_banned(), v: formatNumber(diag?.ember_udp_dropped_banned ?? 0) },
    { id: 'udp-dropped-rate', k: m.ember_stat_udp_dropped_rate_limited(), v: formatNumber(diag?.ember_udp_dropped_rate_limited ?? 0) },
    { id: 'udp-dropped-filtered', k: m.ember_stat_udp_dropped_filtered(), v: formatNumber(diag?.ember_udp_dropped_filtered ?? 0) },
    { id: 'refused-ip-policy', k: m.ember_stat_refused_ip_policy(), v: formatNumber(diag?.ember_dht_refused_ip_policy ?? 0) },
    { id: 'refused-subnet', k: m.ember_stat_refused_subnet(), v: formatNumber(diag?.ember_dht_refused_subnet ?? 0) },
    { id: 'refused-per-ip', k: m.ember_stat_refused_per_ip(), v: formatNumber(diag?.ember_dht_refused_per_ip ?? 0) },
    ];
  });

  let filteredMetrics = $derived.by(() => {
    const q = metricFilter.trim().toLowerCase();
    if (!q) return metrics;
    return metrics.filter((metric) => metric.k.toLowerCase().includes(q));
  });

  /** Everything this page shows, as plain text for a bug report. */
  function diagnosticsText(): string {
    const lines = [
      `${m.nav_ember_network()} — ${new Date().toISOString()}`,
      `${statusLabel}${statusHint ? ` — ${statusHint}` : ''}`,
      `${m.ember_health_reachability()}: ${reachabilityLabel}`,
      `${m.ember_health_sharing()}: ${sharingPillLabel}`,
      `${m.ember_node_id_label()}: ${diag?.ember_dht_node_id || '—'}`,
      '',
      ...metrics.map((metric) => `${metric.k}: ${metric.v}`),
    ];
    return lines.join('\n');
  }

  onMount(() => {
    refreshDiag();
    // Skip the poll while the window is hidden, like every other poll in the
    // app, and catch up on the way back so a restored window is not showing
    // diagnostics from whenever it was minimized.
    const visible = () =>
      typeof document === 'undefined' || document.visibilityState === 'visible';
    pollTimer = setInterval(() => {
      if (visible()) refreshDiag();
    }, 2500);
    const onVisibility = () => {
      if (visible()) refreshDiag();
    };
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', onVisibility);
    }
    return () => {
      unmounted = true;
      if (typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', onVisibility);
      }
      if (pollTimer) clearInterval(pollTimer);
      if (copyTimer) clearTimeout(copyTimer);
    };
  });
</script>

<svelte:head><title>{m.nav_ember_network()} — Ember</title></svelte:head>

<!-- `h2` and `.page-header` to match every other page: this was the only page
     with an `h1`, which put the same chrome at two different heading levels
     and two different type sizes depending on where you'd navigated from. -->
<header class="page-header">
  <div class="page-heading">
    <h2>{m.nav_ember_network()}</h2>
    <p class="page-subtitle">{m.ember_page_subtitle()}</p>
  </div>
  <div class="header-actions">
    {#if isActive}
      <button type="button" class="ghost" onclick={() => copyText(diagnosticsText(), 'diagnostics')}>
        {#if copiedKey === 'diagnostics'}{m.ember_copied()}
        {:else if copiedKey === 'diagnostics:error'}{m.ember_copy_failed()}
        {:else}{m.ember_copy_diagnostics()}{/if}
      </button>
    {/if}
    <button
      type="button"
      class="ghost"
      onclick={() => { restartError = ''; showRestartPrompt = true; }}
      disabled={restarting}
    >
      {m.ember_restart_button()}
    </button>
  </div>
</header>

<div class="ember-layout">
  {#if restartError}
    <div class="banner banner-error" role="alert">{restartError}</div>
  {/if}
  {#if !growingDismissed}
    <div class="banner banner-info banner-dismissable" role="note">
      <span>{m.ember_network_growing()}</span>
      <button
        type="button"
        class="banner-dismiss"
        onclick={dismissGrowing}
        title={m.common_dismiss()}
        aria-label={m.common_dismiss()}
      >
        <IconX size={11} />
      </button>
    </div>
  {/if}
  {#if diagStale}
    <div class="banner banner-error" role="alert">{m.ember_stats_unavailable()}</div>
  {/if}
  {#if showNewerVersionBanner}
    <div class="banner banner-warn banner-with-action" role="status">
      <div class="banner-text">
        <span>{m.ember_version_newer_banner()}</span>
        {#if updateResult}<span class="banner-result">{updateResult}</span>{/if}
      </div>
      {#if $updater.phase === 'available'}
        <button type="button" class="banner-action" onclick={() => void installUpdate()}>
          {m.updater_install()}
        </button>
      {:else if $updater.phase === 'ready'}
        <button type="button" class="banner-action" onclick={() => void restartToUpdate()}>
          {m.updater_restart_now()}
        </button>
      {:else}
        <button
          type="button"
          class="banner-action"
          onclick={() => void checkForUpdates()}
          disabled={$updater.phase === 'checking' || $updater.phase === 'downloading' || $updater.phase === 'installing'}
        >
          {$updater.phase === 'checking' ? m.updater_checking() : m.settings_about_check_btn()}
        </button>
      {/if}
    </div>
  {/if}
  {#if showOlderVersionBanner}
    <div class="banner banner-warn" role="status">{m.ember_version_mismatch_banner()}</div>
  {/if}

  <!-- The answer to "is Ember working?" first and largest, with the four
       numbers that back it up beside it. -->
  <section
    class="hero"
    class:hero-ok={heroState === 'connected'}
    class:hero-warn={heroState === 'connecting' || heroState === 'no_peers'}
    aria-label={m.kad_stat_status()}
  >
    <div class="hero-status">
      <span class="hero-icon" class:hero-icon-busy={joining} aria-hidden="true">
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10 2.5C11.5 5.5 14.5 6.5 14.5 11a4.5 4.5 0 0 1-9 0c0-1.6.7-2.8 1.6-3.7C8.3 6.2 8.8 5 8 3.5c1 .4 1.6 1 2 2z"/>
          <path d="M10 16.3a2 2 0 0 0 2-2c0-1.2-1-1.9-2-3.1-1 1.2-2 1.9-2 3.1a2 2 0 0 0 2 2z"/>
        </svg>
      </span>
      <div class="hero-text" aria-live="polite">
        <span class="hero-eyebrow">{m.kad_stat_status()}</span>
        <span class="hero-title">{statusLabel}</span>
        {#if statusHint}<p class="hero-hint">{statusHint}</p>{/if}
      </div>
    </div>

    {#if isActive}
      <!-- `dt` before `dd` for the reading order; the column is reversed so
           the number sits above its label. -->
      <dl class="hero-stats">
        <div class="hero-stat">
          <dt>{m.ember_overview_contacts()}</dt>
          <dd>{formatNumber(verifiedCount)}</dd>
        </div>
        <div class="hero-stat">
          <dt>{m.ember_stat_network_size()}</dt>
          <dd>{estimatedNodes}</dd>
        </div>
        <div
          class="hero-stat"
          title={publishedTotal > 0 ? m.ember_overview_published_of_hint({ published: formatNumber(publishedCount), total: formatNumber(publishedTotal) }) : undefined}
        >
          <dt>{m.ember_overview_published()}</dt>
          <dd>{publishedTotal > 0 ? m.ember_overview_published_of({ published: formatNumber(publishedCount), total: formatNumber(publishedTotal) }) : formatNumber(publishedCount)}</dd>
        </div>
        <div class="hero-stat">
          <dt>{m.ember_stat_active_searches()}</dt>
          <dd>{formatNumber(activeSearches)}</dd>
        </div>
      </dl>
    {/if}
  </section>

  {#if isActive}
    <div class="health-cards">
      <section class="health-card" aria-labelledby="ember-reachability-label">
        <!-- Only the reachability verdict is announced. The sharing count moves
             on every poll while a library publishes, and PortTest announces
             its own result. -->
        <div aria-live="polite">
          <div class="health-head">
            <span class="stat-label-text" id="ember-reachability-label">{m.ember_health_reachability()}</span>
            <span class="badge" class:tone-success={reachabilityTone === 'ok'} class:tone-warning={reachabilityTone === 'warn'} class:tone-muted={reachabilityTone === 'muted'}>{reachabilityLabel}</span>
          </div>
          <p class="health-hint">{reachabilityHint}</p>
          {#if relayedFix}<p class="health-hint">{relayedFix}</p>{/if}
        </div>
        <div class="health-tool"><PortTest /></div>
      </section>

      <section class="health-card" aria-labelledby="ember-sharing-label">
        <div class="health-head">
          <span class="stat-label-text" id="ember-sharing-label">{m.ember_health_sharing()}</span>
          <span class="badge" class:tone-success={sharingTone === 'ok'} class:tone-warning={sharingTone === 'warn'} class:tone-muted={sharingTone === 'muted'}>{sharingPillLabel}</span>
        </div>
        {#if publishedTotal > 0}
          <div
            class="publish-meter"
            class:meter-ok={sharingTone === 'ok'}
            role="progressbar"
            aria-label={m.ember_overview_published()}
            aria-valuemin={0}
            aria-valuemax={publishedTotal}
            aria-valuenow={Math.min(publishedCount, publishedTotal)}
            aria-valuetext={sharingPillLabel}
          >
            <span style:width="{(Math.min(publishedCount, publishedTotal) / publishedTotal) * 100}%"></span>
          </div>
        {/if}
        <p class="health-hint">{sharingHint}</p>
      </section>
    </div>
  {/if}

  <!--
    The readings behind the reachability verdict. Shown whatever the
    overlay's state, because external IP, firewall and port mapping
    describe this machine's connection rather than Ember. Same component
    as the KAD page's panel, so the two cannot drift. The firewall and
    IP come from KAD's own checks, which can disagree with Ember's
    verdict above, so here they say so.
  -->
  <section class="stats-panel" aria-labelledby="ember-network-status-label">
    <div class="panel-title" id="ember-network-status-label">{m.kad_network_status()}</div>
    <NetworkStatusTiles
      kadSourced
      relayTile={{
        label: m.ember_relay_label(),
        help: m.ember_relay_help(),
        value: emberRelayValue,
        title: emberRelayTitle,
      }}
    />
  </section>

  <!-- Routing contacts and protocol tables: for diagnosing, not for knowing
       whether Ember works, so they stay folded away until asked for. -->
  <details class="ember-details" open={detailsOpen} ontoggle={onDetailsToggle}>
    <summary class="details-summary">{m.ember_details_summary()}</summary>
    <div class="details-body">
    <section class="ember-contacts" aria-labelledby="ember-contacts-label">
      <div class="panel-toolbar">
        <span class="toolbar-label" id="ember-contacts-label">
          {m.ember_dht_contacts_title()}
          <span class="toolbar-count">
            {contactFilter.trim() ? `${formatNumber(filteredContacts.length)} / ` : ''}{formatNumber(contacts.length)}
          </span>
        </span>
        <input
          class="filter-input"
          type="search"
          bind:value={contactFilter}
          placeholder={m.ember_dht_contacts_filter()}
          aria-label={m.ember_dht_contacts_filter()}
          disabled={contacts.length === 0}
        />
      </div>
      <div class="panel-content scrollable scroll-shadows" bind:this={contactScrollEl}>
        {#if (diag === null && diagStale) || (contactsFailed && !contactsLoaded && contacts.length === 0)}
          <div class="empty-state compact" role="status">
            <p class="empty-title">{m.transfers_load_unavailable()}</p>
          </div>
        {:else if diag === null || (!contactsLoaded && contacts.length === 0)}
          <div class="empty-state compact">
            <div class="spinner lg"></div>
            <p>{m.common_loading()}</p>
          </div>
        {:else if contacts.length === 0}
          <div class="empty-state compact">
            {#if joining}
              <div class="spinner lg"></div>
              <p class="empty-title">{m.ember_status_connecting()}</p>
              <p class="empty-sub">{m.ember_joining_hint()}</p>
            {:else}
              <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="48" height="48" aria-hidden="true"><circle cx="12" cy="5" r="2.5" /><circle cx="5" cy="18" r="2.5" /><circle cx="19" cy="18" r="2.5" /><path d="M10.8 7.2 6.4 15.6M13.2 7.2l4.4 8.4M7.5 18h9" stroke-dasharray="2 2.5" /></svg>
              <p class="empty-title">{m.ember_status_no_peers()}</p>
              <p class="empty-sub">{m.ember_no_contacts_hint()}</p>
            {/if}
          </div>
        {:else if filteredContacts.length === 0}
          <div class="empty-state compact">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="48" height="48" aria-hidden="true"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg>
            <p class="empty-title">{m.kad_empty_no_matches()}</p>
            <p class="empty-sub">{m.kad_empty_no_matches_sub()}</p>
            <button class="empty-action ghost" onclick={() => (contactFilter = '')}>{m.common_clear_filters()}</button>
          </div>
        {:else}
          {#snippet sortHeader(col: ContactSortCol, label: string, cls: string)}
            <th
              class="sortable {cls}"
              tabindex="0"
              aria-sort={contactSortCol === col ? (contactSortAsc ? 'ascending' : 'descending') : 'none'}
              onclick={() => sortContactsBy(col)}
              onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), sortContactsBy(col))}
            >
              {label}<span class="sort-arrow" aria-hidden="true">{contactSortCol === col ? (contactSortAsc ? '▲' : '▼') : ''}</span>
            </th>
          {/snippet}
          <table class="compact-table">
            <thead>
              <tr>
                {@render sortHeader('node', m.ember_dht_col_node_id(), '')}
                {@render sortHeader('answered', m.ember_dht_col_answered(), 'col-answered')}
                {@render sortHeader('seen', m.ember_dht_col_last_seen(), 'col-seen')}
                {@render sortHeader('distance', m.ember_dht_col_distance(), '')}
              </tr>
            </thead>
            <tbody>
              {#each filteredContacts as c (c.node_id)}
                {@const answered = contactAnswered(c)}
                <tr class:unanswered={!answered}>
                  <td class="mono-cell">
                    <div class="cell-inner">
                      <span class="cell-content" title={c.node_id}>{c.node_id}</span>
                      <button
                        type="button"
                        class="icon-copy"
                        onclick={() => copyText(c.node_id, `node:${c.node_id}`)}
                        title={m.ember_copy_aria({ label: m.ember_dht_col_node_id() })}
                        aria-label={m.ember_copy_aria({ label: m.ember_dht_col_node_id() })}
                      >
                        {#if copiedKey === `node:${c.node_id}`}
                          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3.5,8.5 6.5,11.5 12.5,4.5" /></svg>
                        {:else}
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                        {/if}
                      </button>
                    </div>
                  </td>
                  <td>
                    <span class="answered" class:yes={answered}>
                      <span class="answered-dot" aria-hidden="true"></span>
                      {answered ? m.common_yes() : m.common_no()}
                    </span>
                  </td>
                  <td class="muted-cell">{contactLastSeen(c)}</td>
                  <td class="mono-cell distance">{c.distance || '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    </section>

    <!-- Protocol tables, where the KAD page keeps its searches. -->
    <section class="ember-lower" aria-label={m.ember_details_summary()}>
    <div class="lower-header">
      <div class="lower-tabs" role="tablist" aria-label={m.ember_details_summary()}>
        {#each [
          { id: 'searches' as const, label: m.ember_dht_searches_title(), count: isActive ? activeSearches : null },
          { id: 'store' as const, label: m.ember_dht_store_title(), count: isActive ? storedKeys : null },
          { id: 'stats' as const, label: m.ember_dht_status_title(), count: null },
          { id: 'identity' as const, label: m.ember_identity_title(), count: null },
        ] as tab (tab.id)}
          <button
            type="button"
            role="tab"
            id={`ember-tab-${tab.id}`}
            class="lower-tab"
            class:active={lowerTab === tab.id}
            aria-selected={lowerTab === tab.id}
            aria-controls="ember-lower-panel"
            tabindex={lowerTab === tab.id ? 0 : -1}
            onclick={() => selectLowerTab(tab.id)}
            onkeydown={onTabKeydown}
          >
            {tab.label}
            {#if tab.count !== null}<span class="tab-count">{formatNumber(tab.count)}</span>{/if}
          </button>
        {/each}
      </div>
      {#if lowerTab === 'stats' && isActive}
        <input
          class="filter-input lower-filter"
          type="search"
          bind:value={metricFilter}
          placeholder={m.ember_metrics_filter()}
          aria-label={m.ember_metrics_filter()}
        />
      {/if}
    </div>

    <div
      class="panel-content scrollable scroll-shadows"
      id="ember-lower-panel"
      role="tabpanel"
      aria-labelledby={`ember-tab-${lowerTab}`}
      tabindex="-1"
    >
      {#if lowerTab === 'identity'}
        <div class="lower-pad">
          <p class="panel-note">{m.ember_identity_hint()}</p>
          {#each [
            { key: 'node', label: m.ember_node_id_label(), value: diag?.ember_dht_node_id ?? '' },
            { key: 'noise', label: m.ember_noise_key_label(), value: diag?.local_noise_public_key ?? '' },
            { key: 'ed', label: m.ember_ed25519_key_label(), value: diag?.local_ed25519_public_key ?? '' },
          ] as row (row.key)}
            <div class="kv">
              <div class="k">{row.label}</div>
              <div class="v pubkey-row">
                <code class="pubkey">{row.value || '—'}</code>
                {#if row.value}
                  <!-- The label is only set while idle: during feedback the
                       visible "Copied" / "Copy failed" must be the accessible name. -->
                  <button
                    type="button"
                    class="copy-btn"
                    onclick={() => copyText(row.value, row.key)}
                    title={m.ember_copy_aria({ label: row.label })}
                    aria-label={copiedKey === row.key || copiedKey === `${row.key}:error` ? undefined : m.ember_copy_aria({ label: row.label })}
                  >
                    {#if copiedKey === row.key}{m.ember_copied()}
                    {:else if copiedKey === `${row.key}:error`}{m.ember_copy_failed()}
                    {:else}{m.ember_copy()}{/if}
                  </button>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      {:else if !isActive}
        <div class="empty-state compact">
          <div class="spinner lg"></div>
          <p>{m.common_loading()}</p>
        </div>
      {:else if lowerTab === 'stats'}
        <div class="metric-grid lower-pad">
          {#each filteredMetrics as metric (metric.id)}
            <div class="metric">
              <span class="metric-k">{metric.k}</span>
              <span class="metric-v">{metric.v}</span>
            </div>
          {:else}
            <p class="panel-note metric-empty">{m.ember_metrics_filter_empty()}</p>
          {/each}
        </div>
      {:else if lowerTab === 'searches'}
        {#if searches.length === 0}
          <div class="empty-state compact">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="48" height="48" aria-hidden="true"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            <p class="empty-sub">{m.ember_dht_searches_empty()}</p>
          </div>
        {:else}
          <table class="compact-table">
            <thead>
              <tr>
                <th class="col-id">{m.ember_dht_search_col_id()}</th>
                <th class="col-type">{m.ember_dht_search_col_type()}</th>
                <th>{m.ember_dht_search_col_target()}</th>
                <th class="num col-num">{m.ember_dht_search_col_results()}</th>
                <th class="col-progress">{m.ember_dht_search_col_progress()}</th>
                <th class="num col-age">{m.ember_dht_search_col_age()}</th>
              </tr>
            </thead>
            <tbody>
              {#each searches as s (s.id)}
                <tr>
                  <td class="muted-cell">{s.id}</td>
                  <td>
                    <span class="badge sm tone-accent">{emberSearchTypeLabel(s.type)}{#if s.keyword_count > 1} ({s.keyword_count}){/if}</span>
                  </td>
                  <td class="mono-cell">{s.target || '—'}</td>
                  <td class="num">{formatNumber(s.results)}</td>
                  <td title={m.ember_dht_search_progress_title({ responded: s.responded, queried: s.queried, in_flight: s.in_flight, pending: s.pending })}>
                    <span class="progress-cell">
                      <span class="progress-bar" aria-hidden="true">
                        <span class="progress-fill" style={`width: ${s.queried > 0 ? Math.min(100, Math.round((s.responded / s.queried) * 100)) : 0}%`}></span>
                      </span>
                      <span class="progress-text">{s.responded}/{s.queried} · {s.in_flight}↑ · {s.pending}…</span>
                    </span>
                  </td>
                  <td class="num muted-cell">{formatDurationSecs(s.age_secs)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      {:else if lowerTab === 'store'}
        {#if storeEntries.length === 0}
          <div class="empty-state compact">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="48" height="48" aria-hidden="true"><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" /></svg>
            <p class="empty-sub">{m.ember_dht_store_empty()}</p>
          </div>
        {:else}
          <p class="panel-note table-note">{m.ember_dht_store_hint()}</p>
          <table class="compact-table">
            <thead>
              <tr>
                <th>{m.ember_dht_store_col_key()}</th>
                <th class="num col-num">{m.ember_dht_store_col_records()}</th>
                <th class="num col-num">{m.ember_dht_store_col_keyword()}</th>
                <th class="num col-num">{m.ember_dht_store_col_source()}</th>
              </tr>
            </thead>
            <tbody>
              {#each storeEntries as e (e.key)}
                <tr>
                  <td class="mono-cell">{e.key || '—'}</td>
                  <td class="num">{formatNumber(e.record_count)}</td>
                  <td class="num">{formatNumber(e.keyword_records)}</td>
                  <td class="num">{formatNumber(e.source_records)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      {/if}
    </div>
    </section>
    </div>
  </details>
</div>

<!--
  Confirmed like the port-change prompt in Settings, with the same
  "Restart now" label and the same relaunch overlay.
-->
<ConfirmDialog
  bind:open={showRestartPrompt}
  title={m.ember_restart_dialog_title()}
  message={m.ember_restart_dialog_message()}
  confirmLabel={m.settings_restart_now()}
  cancelLabel={m.common_cancel()}
  onconfirm={performRestart}
/>

{#if restarting}
  <div class="restart-overlay" role="status" aria-label={m.settings_restarting_aria()}>
    <div class="restart-card">
      <div class="spinner lg"></div>
      <h2 class="restart-title">{m.settings_restarting_title()}</h2>
      <p class="restart-sub">{m.ember_restarting_sub()}</p>
    </div>
  </div>
{/if}

<style>
  /*
   * A fixed header, then the network status panel and the folded technical
   * details, scrolling together. The tables inside the details keep fixed
   * heights and scroll inside themselves.
   */
  .page-header {
    gap: 16px;
  }

  .page-heading {
    min-width: 0;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }

  .page-header h2 {
    margin: 0;
  }

  .ember-layout {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    /* The hero lays itself out against the width the page has, which the
       sidebar's collapse changes as much as the window does. */
    container-type: inline-size;
    overflow-y: auto;
    padding: var(--workspace-padding);
    gap: 12px;
    background: var(--bg-primary);
  }

  .ember-layout > * {
    flex-shrink: 0;
  }

  /* --- Technical details: the routing table and protocol tables, folded --- */

  .ember-details {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-secondary);
    box-shadow: var(--shadow-sm);
  }

  .details-summary {
    padding: 11px 14px;
    font-size: var(--font-size-base);
    font-weight: 600;
    color: var(--text-secondary);
    cursor: pointer;
    border-radius: var(--radius-lg);
  }

  .details-summary:hover {
    color: var(--text-primary);
  }

  .details-summary:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }

  .details-body {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: 0 12px 12px;
  }

  .ember-contacts {
    height: 360px;
    display: flex;
    flex-direction: column;
    min-width: 0;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
    background: var(--bg-secondary);
  }

  /* --- Panel chrome, as on the KAD page --- */

  .panel-toolbar {
    display: flex;
    align-items: center;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
    flex-shrink: 0;
  }

  .toolbar-label {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    font-size: var(--font-size-base);
    font-weight: 600;
    color: var(--text-secondary);
    white-space: nowrap;
  }

  .toolbar-count,
  .tab-count {
    padding: 0 7px;
    border-radius: var(--radius-pill);
    background: var(--bg-tertiary);
    color: var(--text-muted);
    font-size: var(--font-size-sm);
    font-weight: 600;
    line-height: 1.6;
    font-variant-numeric: tabular-nums;
  }

  .filter-input {
    flex: 1 1 120px;
    min-width: 80px;
    max-width: 280px;
    margin: 5px 8px 5px auto;
    padding: 6px 12px;
    font-size: var(--font-size-md);
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--input-border);
    border-radius: var(--radius-pill);
  }

  .filter-input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .filter-input:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .panel-content {
    flex: 1;
    min-height: 0;
  }

  .panel-content.scrollable {
    overflow: auto;
  }

  .panel-content:focus {
    outline: none;
  }

  .panel-title {
    font-size: var(--font-size-sm);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    margin-bottom: 6px;
  }

  .stats-panel {
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-secondary);
    box-shadow: var(--shadow-sm);
    container-type: inline-size;
  }

  /* --- Hero: the status verdict and the headline numbers --- */

  /* The state colours the card itself, faintly, so the answer reads before a
     single word does: green when connected, amber while it is not yet. */
  .hero {
    --hero-tone: var(--text-muted);
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 18px 32px;
    padding: 20px 22px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background:
      linear-gradient(
        120deg,
        color-mix(in srgb, var(--hero-tone) 9%, var(--bg-secondary)) 0%,
        var(--bg-secondary) 55%
      );
    box-shadow: var(--shadow-sm);
  }

  .hero.hero-ok {
    --hero-tone: var(--success);
  }

  .hero.hero-warn {
    --hero-tone: var(--warning);
  }

  .hero-status {
    display: flex;
    align-items: center;
    gap: 16px;
    flex: 1 1 280px;
    min-width: 0;
  }

  .hero-icon {
    position: relative;
    flex-shrink: 0;
    width: 52px;
    height: 52px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    color: var(--hero-tone);
    background: color-mix(in srgb, var(--hero-tone) 14%, transparent);
    box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--hero-tone) 28%, transparent);
  }

  .hero-icon svg {
    width: 26px;
    height: 26px;
  }

  /* While joining, a ring turns round the flame in place of the badge spinner
     the status used to carry. */
  .hero-icon-busy::after {
    content: '';
    position: absolute;
    inset: -3px;
    border-radius: 50%;
    border: 2px solid transparent;
    border-top-color: var(--hero-tone);
    animation: hero-spin 1.1s linear infinite;
  }

  @keyframes hero-spin {
    to { transform: rotate(360deg); }
  }

  @media (prefers-reduced-motion: reduce) {
    .hero-icon-busy::after {
      animation: none;
      border-color: color-mix(in srgb, var(--hero-tone) 45%, transparent);
    }
  }

  .hero-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .hero-eyebrow {
    font-size: var(--font-size-2xs);
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--text-muted);
  }

  .hero-title {
    margin-top: 2px;
    font-size: var(--font-size-3xl);
    font-weight: 700;
    line-height: 1.15;
    letter-spacing: -0.3px;
    color: var(--text-primary);
  }

  .hero-hint {
    margin: 4px 0 0;
    font-size: var(--font-size-md);
    line-height: 1.45;
    color: var(--text-secondary);
  }

  .hero-stats {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, auto));
    gap: 8px 28px;
    margin: 0;
    flex: 0 1 auto;
  }

  .hero-stat {
    display: flex;
    flex-direction: column-reverse;
    gap: 2px;
    min-width: 0;
  }

  .hero-stat dd {
    margin: 0;
    font-size: var(--font-size-3xl);
    font-weight: 700;
    line-height: 1.1;
    letter-spacing: -0.4px;
    font-variant-numeric: tabular-nums;
    color: var(--text-primary);
    white-space: nowrap;
  }

  /* Allowed to wrap: the German and Polish captions run well past the
     English, and a clipped caption no longer says what the number is. */
  .hero-stat dt {
    font-size: var(--font-size-2xs);
    font-weight: 600;
    line-height: 1.3;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-muted);
  }

  /* Below the status rather than beside it once the row is too narrow for
     both, and two by two when even four across will not fit. */
  @container (max-width: 860px) {
    .hero-stats {
      flex-basis: 100%;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      padding-top: 14px;
      border-top: 1px solid color-mix(in srgb, var(--border) 55%, transparent);
    }

    /* A quarter of the row can be narrower than "12,345 of 23,456". */
    .hero-stat dd {
      font-size: var(--font-size-2xl);
      white-space: normal;
      overflow-wrap: anywhere;
    }
  }

  @container (max-width: 520px) {
    .hero-stats {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }

  /* --- Health: reachability and sharing, side by side --- */

  .health-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 12px;
  }

  .health-card {
    padding: 14px 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-secondary);
    box-shadow: var(--shadow-sm);
    min-width: 0;
  }

  .health-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }

  .stat-label-text {
    color: var(--text-muted);
    font-weight: 700;
    font-size: var(--font-size-2xs);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    white-space: nowrap;
  }

  .health-head .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .health-hint {
    margin: 8px 0 0;
    font-size: var(--font-size-sm);
    line-height: 1.45;
    color: var(--text-muted);
  }

  .health-tool {
    margin-top: 12px;
  }

  /* How much of what you share is advertised, under the count it draws. */
  .publish-meter {
    height: 6px;
    margin-top: 12px;
    border-radius: var(--radius-pill);
    background: var(--bg-tertiary);
    overflow: hidden;
  }

  .publish-meter span {
    display: block;
    height: 100%;
    border-radius: inherit;
    background: var(--warning);
    transition: width var(--transition-normal) ease;
  }

  .publish-meter.meter-ok span {
    background: var(--success);
  }

  /* --- Tables --- */

  .compact-table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--font-size-sm);
  }

  .compact-table th {
    padding: 7px 10px;
    font-size: var(--font-size-xs);
    font-weight: 600;
    text-align: left;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    color: var(--text-muted);
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  .compact-table td {
    padding: 4px 10px;
    line-height: 1.25;
    white-space: nowrap;
  }

  .compact-table tbody tr {
    height: 30px;
    transition: background-color var(--transition-fast) ease;
  }

  .compact-table tbody tr:nth-child(even) td {
    background: var(--table-row-alt);
  }

  .compact-table tbody tr:hover td {
    background: var(--bg-hover);
  }

  .compact-table .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }

  /* A fixed slot, so the header text does not shift as the arrow comes and goes. */
  .sort-arrow {
    display: inline-block;
    width: 1.2em;
    margin-inline-start: 2px;
    font-size: 0.85em;
    color: var(--accent);
  }

  /* The short columns keep their size and the key column takes the slack, so
     a row's readings sit together instead of across the whole panel. */
  .col-answered { width: 110px; }
  .col-seen { width: 110px; }
  .col-id { width: 70px; }
  .col-type { width: 110px; }
  .col-num { width: 110px; }
  .col-progress { width: 260px; }
  .col-age { width: 90px; }

  .mono-cell {
    font-family: var(--font-mono);
    font-size: var(--font-size-xs);
    color: var(--text-secondary);
  }

  .mono-cell.distance {
    color: var(--text-muted);
  }

  /* Never heard from: still in the table, but the live rows read first. */
  tr.unanswered .mono-cell {
    color: var(--text-muted);
  }

  tr.unanswered .mono-cell.distance {
    color: color-mix(in srgb, var(--text-muted) 75%, transparent);
  }

  .muted-cell {
    color: var(--text-muted);
  }

  .cell-inner {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .cell-content {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* Revealed on the row, like the KAD contact list's copy buttons. */
  .icon-copy {
    flex-shrink: 0;
    width: 20px;
    height: 20px;
    padding: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text-secondary);
    cursor: pointer;
    opacity: 0;
    transition: opacity var(--transition-fast), color var(--transition-fast), background var(--transition-fast);
  }

  .icon-copy svg {
    width: 12px;
    height: 12px;
  }

  tr:hover .icon-copy,
  .icon-copy:focus-visible {
    opacity: 1;
  }

  .icon-copy:hover {
    color: var(--text-primary);
    background: var(--bg-tertiary);
  }

  @media (hover: none) {
    .icon-copy { opacity: 1; }
  }

  .answered {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--text-muted);
  }

  .answered-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: color-mix(in srgb, var(--text-muted) 55%, transparent);
  }

  .answered.yes {
    color: var(--text-secondary);
  }

  .answered.yes .answered-dot {
    background: var(--success);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--success) 20%, transparent);
  }

  .progress-cell {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }

  .progress-bar {
    width: 56px;
    height: 5px;
    border-radius: var(--radius-pill);
    background: var(--bg-tertiary);
    overflow: hidden;
    flex-shrink: 0;
  }

  .progress-fill {
    display: block;
    height: 100%;
    border-radius: inherit;
    background: var(--accent);
    transition: width var(--transition-normal) ease;
  }

  .progress-text {
    font-variant-numeric: tabular-nums;
    color: var(--text-secondary);
  }

  /* --- Lower: the protocol tables in tabs --- */

  .ember-lower {
    height: 360px;
    display: flex;
    flex-direction: column;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
    background: var(--bg-secondary);
  }

  .lower-header {
    display: flex;
    align-items: center;
    gap: 8px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
    flex-shrink: 0;
    min-width: 0;
  }

  .lower-tabs {
    display: flex;
    min-width: 0;
    overflow-x: auto;
    scrollbar-width: none;
  }

  .lower-tab {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 9px 14px;
    border: none;
    border-radius: 0;
    background: transparent;
    color: var(--text-muted);
    font-size: var(--font-size-base);
    font-weight: 600;
    white-space: nowrap;
    cursor: pointer;
    transition: color var(--transition-fast) ease, background-color var(--transition-fast) ease;
  }

  .lower-tab:hover {
    color: var(--text-primary);
    background: color-mix(in srgb, var(--text-primary) 4%, transparent);
  }

  .lower-tab.active {
    color: var(--text-primary);
  }

  .lower-tab::after {
    content: '';
    position: absolute;
    left: 10px;
    right: 10px;
    bottom: -1px;
    height: 2px;
    border-radius: 2px 2px 0 0;
    background: var(--accent);
    transform: scaleX(0);
    transition: transform var(--transition-normal) ease;
  }

  .lower-tab.active::after {
    transform: scaleX(1);
  }

  .lower-tab.active .tab-count {
    background: color-mix(in srgb, var(--accent) 16%, transparent);
    color: var(--text-accent);
  }

  .lower-tab:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }

  .lower-filter {
    max-width: 240px;
  }

  .lower-pad {
    padding: 10px 14px 14px;
  }

  .panel-note {
    margin: 0 0 8px;
    font-size: var(--font-size-md);
    line-height: 1.45;
    color: var(--text-muted);
  }

  .table-note {
    margin: 0;
    padding: 8px 10px 6px;
  }

  .metric-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 0 28px;
  }

  .metric {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    padding: 5px 0;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 55%, transparent);
    min-width: 0;
  }

  .metric-k {
    font-size: var(--font-size-md);
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .metric-v {
    font-size: var(--font-size-md);
    font-weight: 600;
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }

  .metric-empty {
    grid-column: 1 / -1;
    margin-top: 6px;
  }

  .kv {
    display: grid;
    grid-template-columns: 160px 1fr;
    gap: 10px;
    align-items: center;
    padding: 8px 0;
    border-top: 1px solid color-mix(in srgb, var(--border) 70%, transparent);
  }

  .kv:first-of-type {
    border-top: none;
  }

  .k {
    font-size: var(--font-size-md);
    color: var(--text-muted);
  }

  .pubkey-row {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }

  .pubkey {
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    overflow-wrap: anywhere;
    min-width: 0;
  }

  .copy-btn {
    flex-shrink: 0;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    border-radius: var(--radius-md);
    padding: 3px 10px;
    font-size: var(--font-size-sm);
    cursor: pointer;
    transition: background var(--transition-normal) ease, color var(--transition-normal) ease, border-color var(--transition-normal) ease;
  }

  .copy-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
    border-color: var(--accent);
  }

  /* --- Banners --- */

  .banner {
    flex-shrink: 0;
    border-radius: var(--radius-md);
    padding: 9px 14px;
    font-size: var(--font-size-md);
    line-height: 1.5;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .banner-dismissable {
    justify-content: space-between;
  }

  .banner-dismiss {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    padding: 0;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    transition: background var(--transition-fast) ease, color var(--transition-fast) ease;
  }

  .banner-dismiss:hover {
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    color: var(--text-primary);
  }

  .banner-error {
    background: color-mix(in srgb, var(--danger) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--danger) 35%, transparent);
    color: var(--badge-danger-text);
  }

  .banner-warn {
    background: color-mix(in srgb, var(--warning) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--warning) 35%, transparent);
    color: var(--badge-warning-text);
  }

  .banner-info {
    background: color-mix(in srgb, var(--accent) 10%, transparent);
    border: 1px solid color-mix(in srgb, var(--accent) 28%, transparent);
    color: var(--text-secondary);
  }

  .banner-with-action {
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px 12px;
  }

  .banner-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .banner-result {
    font-weight: 600;
  }

  .banner-action {
    flex-shrink: 0;
    border: 1px solid color-mix(in srgb, var(--warning) 45%, var(--border));
    background: color-mix(in srgb, var(--warning) 16%, var(--bg-secondary));
    color: inherit;
    border-radius: var(--radius-sm, 6px);
    padding: 4px 10px;
    font-size: var(--font-size-sm);
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
  }

  .banner-action:hover:not(:disabled) {
    background: color-mix(in srgb, var(--warning) 24%, var(--bg-secondary));
  }

  .banner-action:disabled {
    opacity: 0.6;
    cursor: default;
  }

  @media (prefers-reduced-motion: reduce) {
    .lower-tab::after,
    .progress-fill,
    .compact-table tbody tr { transition: none; }
  }

  /* Same overlay as a port-change restart in Settings. */
  .restart-overlay {
    position: fixed;
    inset: 0;
    z-index: 99999;
    display: grid;
    place-items: center;
    background: var(--bg-primary);
    padding: 20px;
  }

  .restart-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
  }

  .restart-title {
    font-size: 22px;
    font-weight: 700;
    color: var(--accent);
    margin: 0;
  }

  .restart-sub {
    font-size: var(--font-size-base);
    color: var(--text-muted);
    margin: 0;
  }

  /* --- Smaller windows, the KAD page's breakpoints --- */

  @media (max-width: 1200px) {
    .ember-layout {
      padding: 10px;
      gap: 10px;
    }

    .ember-contacts {
      height: 300px;
    }
  }

  @media (max-width: 760px) {
    .page-header {
      align-items: flex-start;
      flex-direction: column;
    }

    .kv {
      grid-template-columns: 1fr;
      gap: 4px;
    }
  }
</style>
