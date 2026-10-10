<script lang="ts">
  /*
   * User-facing "Ember Network" page. The default view answers only the
   * questions a user actually has — is it on, am I connected, can people
   * reach me, are my shared files findable — in plain language. Every
   * protocol-level counter and table lives behind the "Technical
   * details" disclosure, which is also the only thing that polls the
   * contact / search / store snapshots, so the common case costs one
   * command per tick instead of four.
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
  let searches = $state<EmberDhtSearchEntry[]>([]);
  let storeEntries = $state<EmberDhtStoreEntry[]>([]);
  let contactFilter = $state('');
  let metricFilter = $state('');
  let detailsOpen = $state(false);

  // Device-local view state, like collapsed sections elsewhere: not carried
  // by a profile backup.
  const DETAILS_OPEN_KEY = 'ember.page.details-open.v1';
  const GROWING_DISMISSED_KEY = 'ember.page.growing-dismissed.v1';
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
  const detailsInitiallyOpen = readFlag(DETAILS_OPEN_KEY);
  let growingDismissed = $state(readFlag(GROWING_DISMISSED_KEY));
  function dismissGrowing() {
    growingDismissed = true;
    writeFlag(GROWING_DISMISSED_KEY, true);
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

  // The contact / search / store snapshots are three extra commands per
  // tick and only render inside "Technical details", so they are fetched
  // only while that section is open. Guarded separately from the
  // diagnostics poll so opening the section can fill the tables at once
  // instead of being swallowed by an in-flight poll and waiting out a tick.
  async function refreshLists() {
    if (unmounted || inFlightLists) return;
    if (!detailsOpen || !diag?.ember_native_enabled) {
      contacts = [];
      searches = [];
      storeEntries = [];
      return;
    }
    inFlightLists = true;
    try {
      const [c, s, st] = await Promise.all([
        getEmberDhtContacts().catch(() => contacts),
        getEmberDhtSearches().catch(() => searches),
        getEmberDhtStore().catch(() => storeEntries),
      ]);
      // Re-check: the user can close the section while these are in flight,
      // and the close path has already cleared the lists.
      if (!unmounted && detailsOpen) {
        contacts = c;
        searches = s;
        storeEntries = st;
      }
    } finally {
      inFlightLists = false;
    }
  }

  function onDetailsToggle(e: Event & { currentTarget: HTMLDetailsElement }) {
    detailsOpen = e.currentTarget.open;
    writeFlag(DETAILS_OPEN_KEY, detailsOpen);
    void refreshLists();
  }

  let filteredContacts = $derived.by(() => {
    const q = contactFilter.trim().toLowerCase();
    if (!q) return contacts;
    return contacts.filter(
      (c) =>
        c.node_id.toLowerCase().includes(q) ||
        (c.distance ?? '').toLowerCase().includes(q),
    );
  });

  function shortHex(hex: string, head = 8, tail = 4): string {
    if (hex.length <= head + tail + 1) return hex || '—';
    return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
  }

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
                  one: m.ember_relay_relaying_for_one,
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
      ? m.ember_overview_published_of({ published: publishedCount, total: publishedTotal })
      : sharingPublished
        ? m.ember_health_sharing_published_count({ count: publishedCount })
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
            remaining: publishedTotal - publishedCount,
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
    { id: 'published-files', k: m.ember_stat_published_files(), v: publishedTotal > 0 ? m.ember_overview_published_of({ published: publishedCount, total: publishedTotal }) : String(publishedCount) },
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
    <button
      type="button"
      class="secondary"
      onclick={() => { restartError = ''; showRestartPrompt = true; }}
      disabled={restarting}
    >
      {m.ember_restart_button()}
    </button>
  </div>
</header>

<div class="page-content">
  <div class="ember-inner">
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

  <section class="hero" class:state-off={heroState === 'loading'} class:state-connecting={heroState === 'connecting'} class:state-connected={heroState === 'connected'} class:state-no-peers={heroState === 'no_peers'} aria-live="polite">
    <div class="hero-glow" aria-hidden="true"></div>
    <div class="hero-main">
      <span
        class="status-dot"
        class:on={heroState === 'connected'}
        class:pending={heroState === 'connecting'}
        class:warn={heroState === 'no_peers'}
      ></span>
      <div class="hero-text">
        <div class="status-label">
          {statusLabel}
          {#if joining}<span class="spinner sm" aria-hidden="true"></span>{/if}
        </div>
        {#if statusHint}<p class="hint">{statusHint}</p>{/if}
      </div>
    </div>
  </section>

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

  {#if isActive}
    <section class="stat-grid" aria-label={m.ember_overview_aria()}>
      <div class="stat-card stat" title={peerCount > verifiedCount ? m.ember_overview_peers_of_hint({ verified: verifiedCount, total: peerCount }) : undefined}>
        <div class="value">
          {#if peerCount > verifiedCount}
            {m.ember_overview_peers_of({ verified: verifiedCount, total: peerCount })}
          {:else}
            {verifiedCount}
          {/if}
        </div>
        <div class="label">{m.ember_overview_peers()}</div>
      </div>
      <div class="stat-card stat" title={publishedTotal > 0 ? m.ember_overview_published_of_hint({ published: publishedCount, total: publishedTotal }) : undefined}>
        <div class="value">
          {#if publishedTotal > 0}
            {m.ember_overview_published_of({ published: publishedCount, total: publishedTotal })}
          {:else}
            {publishedCount}
          {/if}
        </div>
        <div class="label">{m.ember_overview_published()}</div>
      </div>
    </section>

    <section class="card checklist">
      <h2>{m.ember_health_title()}</h2>

      <div class="check-row">
        <div class="check-indicator" class:ok={reachabilityTone === 'ok'} class:warn={reachabilityTone === 'warn'} class:muted={reachabilityTone === 'muted'} aria-hidden="true">
          {#if reachabilityTone === 'ok'}
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3.5,8.5 6.5,11.5 12.5,4.5" /></svg>
          {:else if reachabilityTone === 'warn'}
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3l6 10H2L8 3z" /><path d="M8 7v3M8 11.5h.01" /></svg>
          {:else}
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="8" cy="8" r="5.5" /><path d="M5.5 8h5" /></svg>
          {/if}
        </div>
        <div class="check-body">
          <div class="check-head">
            <span class="check-label">{m.ember_health_reachability()}</span>
            <span class="badge" class:tone-success={reachabilityTone === 'ok'} class:tone-warning={reachabilityTone === 'warn'} class:tone-muted={reachabilityTone === 'muted'}>{reachabilityLabel}</span>
          </div>
          <p class="hint">{reachabilityHint}</p>
          {#if relayedFix}
            <p class="hint">{relayedFix}</p>
          {/if}
          <PortTest />
        </div>
      </div>

      <div class="check-row">
        <div class="check-indicator" class:ok={sharingTone === 'ok'} class:warn={sharingTone === 'warn'} class:muted={sharingTone === 'muted'} aria-hidden="true">
          {#if sharingTone === 'ok'}
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3.5,8.5 6.5,11.5 12.5,4.5" /></svg>
          {:else if sharingTone === 'warn'}
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3l6 10H2L8 3z" /><path d="M8 7v3M8 11.5h.01" /></svg>
          {:else}
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="8" cy="8" r="5.5" /><path d="M5.5 8h5" /></svg>
          {/if}
        </div>
        <div class="check-body">
          <div class="check-head">
            <span class="check-label">{m.ember_health_sharing()}</span>
            <span class="badge" class:tone-success={sharingTone === 'ok'} class:tone-warning={sharingTone === 'warn'} class:tone-muted={sharingTone === 'muted'}>{sharingPillLabel}</span>
          </div>
          <p class="hint">{sharingHint}</p>
        </div>
      </div>
    </section>
  {/if}

  <!--
    The reachability check above gives the verdict; these are the readings
    behind it. Shown regardless of the overlay's state, because external IP,
    firewall and port mapping describe this machine's connection rather than
    Ember, and they're most worth reading when something is off. Same
    component as the KAD page's Network Status panel, so the two can't drift.
  -->
  <section class="card">
    <h2>{m.kad_network_status()}</h2>
    <NetworkStatusTiles
      relayTile={{
        label: m.ember_relay_label(),
        help: m.ember_relay_help(),
        value: emberRelayValue,
        title: emberRelayTitle,
      }}
    />
  </section>

  <!--
    Everything below is protocol-level diagnostics. Collapsed by default,
    and `onDetailsToggle` is what starts/stops polling the three snapshot
    commands that feed the tables.
  -->
  <details class="card advanced" open={detailsInitiallyOpen} ontoggle={onDetailsToggle}>
    <summary>
      <span class="chevron" aria-hidden="true">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" width="12" height="12">
          <polyline points="6,3 11,8 6,13" />
        </svg>
      </span>
      <span class="summary-text">
        <span class="summary-title">{m.ember_details_summary()}</span>
        <span class="summary-hint">{m.ember_details_hint()}</span>
      </span>
    </summary>

    <div class="advanced-body">
      <section class="sub-card">
        <h3>{m.ember_identity_title()}</h3>
        <p class="hint">{m.ember_identity_hint()}</p>
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
      </section>

      {#if isActive}
        <section class="sub-card">
          <div class="panel-head">
            <h3>{m.ember_dht_status_title()}</h3>
            <div class="panel-tools">
              <input
                class="filter-input"
                type="search"
                bind:value={metricFilter}
                placeholder={m.ember_metrics_filter()}
                aria-label={m.ember_metrics_filter()}
              />
              <button
                type="button"
                class="copy-btn"
                onclick={() => copyText(diagnosticsText(), 'diagnostics')}
              >
                {#if copiedKey === 'diagnostics'}{m.ember_copied()}
                {:else if copiedKey === 'diagnostics:error'}{m.ember_copy_failed()}
                {:else}{m.ember_copy_diagnostics()}{/if}
              </button>
            </div>
          </div>
          <div class="metric-grid">
            {#each filteredMetrics as metric (metric.id)}
              <div class="metric">
                <span class="metric-k">{metric.k}</span>
                <span class="metric-v">{metric.v}</span>
              </div>
            {:else}
              <p class="hint metric-empty">{m.ember_metrics_filter_empty()}</p>
            {/each}
          </div>
        </section>

        <section class="sub-card">
          <div class="panel-head">
            <h3>
              {m.ember_dht_contacts_title()}
              <span class="count-pill">{contactFilter.trim() ? `${formatNumber(filteredContacts.length)} / ` : ''}{formatNumber(contacts.length)}</span>
            </h3>
            <input
              class="filter-input"
              type="search"
              bind:value={contactFilter}
              placeholder={m.ember_dht_contacts_filter()}
              aria-label={m.ember_dht_contacts_filter()}
            />
          </div>
          <div class="table-wrap">
            <table class="dht-table">
              <thead>
                <tr>
                  <th>{m.ember_dht_col_node_id()}</th>
                  <th>{m.ember_dht_col_answered()}</th>
                  <th>{m.ember_dht_col_last_seen()}</th>
                  <th>{m.ember_dht_col_distance()}</th>
                </tr>
              </thead>
              <tbody>
                {#each filteredContacts as c (c.node_id)}
                  <tr>
                    <td title={c.node_id}><code>{shortHex(c.node_id)}</code></td>
                    <td>{contactAnswered(c) ? m.common_yes() : m.common_no()}</td>
                    <td>{contactLastSeen(c)}</td>
                    <td title={c.distance ?? ''}><code>{shortHex(c.distance ?? '', 6, 4)}</code></td>
                  </tr>
                {:else}
                  <tr><td colspan="4" class="empty">{m.ember_dht_contacts_empty()}</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>

        <section class="sub-card">
          <h3>{m.ember_dht_searches_title()} <span class="count-pill">{formatNumber(searches.length)}</span></h3>
          <div class="table-wrap">
            <table class="dht-table">
              <thead>
                <tr>
                  <th>{m.ember_dht_search_col_id()}</th>
                  <th>{m.ember_dht_search_col_type()}</th>
                  <th>{m.ember_dht_search_col_target()}</th>
                  <th>{m.ember_dht_search_col_results()}</th>
                  <th>{m.ember_dht_search_col_progress()}</th>
                  <th>{m.ember_dht_search_col_age()}</th>
                </tr>
              </thead>
              <tbody>
                {#each searches as s (s.id)}
                  <tr>
                    <td>{s.id}</td>
                    <td>{emberSearchTypeLabel(s.type)}{#if s.keyword_count > 1} ({s.keyword_count}){/if}</td>
                    <td title={s.target}><code>{shortHex(s.target)}</code></td>
                    <td>{s.results}</td>
                    <td title={m.ember_dht_search_progress_title({ responded: s.responded, queried: s.queried, in_flight: s.in_flight, pending: s.pending })}>{s.responded}/{s.queried} · {s.in_flight}↑ · {s.pending}…</td>
                    <td>{formatDurationSecs(s.age_secs)}</td>
                  </tr>
                {:else}
                  <tr><td colspan="6" class="empty">{m.ember_dht_searches_empty()}</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>

        <section class="sub-card">
          <h3>{m.ember_dht_store_title()} <span class="count-pill">{formatNumber(storeEntries.length)}</span></h3>
          <p class="hint">{m.ember_dht_store_hint()}</p>
          <div class="table-wrap">
            <table class="dht-table">
              <thead>
                <tr>
                  <th>{m.ember_dht_store_col_key()}</th>
                  <th>{m.ember_dht_store_col_records()}</th>
                  <th>{m.ember_dht_store_col_keyword()}</th>
                  <th>{m.ember_dht_store_col_source()}</th>
                </tr>
              </thead>
              <tbody>
                {#each storeEntries as e (e.key)}
                  <tr>
                    <td title={e.key}><code>{shortHex(e.key)}</code></td>
                    <td>{e.record_count}</td>
                    <td>{e.keyword_records}</td>
                    <td>{e.source_records}</td>
                  </tr>
                {:else}
                  <tr><td colspan="4" class="empty">{m.ember_dht_store_empty()}</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>
      {/if}
    </div>
  </details>
  </div>
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
   * Fixed `.page-header` + scrollable `.page-content` (the app-wide
   * pattern); `.ember-inner` is the centered column inside the scroll
   * area so content is never clipped by the layout's `overflow: hidden`.
   */
  .ember-inner {
    padding: var(--page-padding);
    max-width: 900px;
    margin: 0 auto;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .page-header {
    gap: 16px;
  }

  .page-heading {
    min-width: 0;
  }

  .header-actions {
    display: flex;
    align-items: center;
    flex-shrink: 0;
  }

  /* Size/weight come from the global `.page-header h2` rule; only the layout
     bits this page adds (icon alignment, and room for the subtitle) live here. */
  .page-header h2 {
    margin: 0;
    display: flex;
    align-items: center;
    gap: 10px;
  }


  .card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 18px 20px;
  }

  .card h2 {
    font-size: var(--font-size-base);
    font-weight: 600;
    color: var(--text-primary);
    margin: 0 0 12px;
  }

  /* --- Status hero --- */

  .hero {
    position: relative;
    overflow: hidden;
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 22px 24px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    transition:
      background var(--transition-slow) ease,
      border-color var(--transition-slow) ease,
      box-shadow var(--transition-slow) ease;
  }

  .hero-glow {
    position: absolute;
    inset: -40% -20% auto auto;
    width: 55%;
    height: 140%;
    pointer-events: none;
    background: radial-gradient(
      ellipse at center,
      color-mix(in srgb, var(--ember-color, #c2185b) 18%, transparent) 0%,
      transparent 70%
    );
    opacity: 0;
    transition: opacity 0.4s ease;
  }

  .hero.state-connected {
    border-color: color-mix(in srgb, var(--ember-color, #c2185b) 28%, var(--border));
    background:
      linear-gradient(
        135deg,
        color-mix(in srgb, var(--ember-color, #c2185b) 7%, var(--bg-secondary)) 0%,
        var(--bg-secondary) 55%
      );
    box-shadow: 0 1px 0 color-mix(in srgb, var(--ember-color, #c2185b) 12%, transparent);
  }

  .hero.state-connected .hero-glow {
    opacity: 1;
  }

  .hero.state-connecting {
    border-color: color-mix(in srgb, var(--warning) 32%, var(--border));
    background:
      linear-gradient(
        135deg,
        color-mix(in srgb, var(--warning) 8%, var(--bg-secondary)) 0%,
        var(--bg-secondary) 60%
      );
  }

  .hero.state-no-peers {
    border-color: color-mix(in srgb, var(--warning) 28%, var(--border));
  }

  .hero-main {
    position: relative;
    display: flex;
    align-items: center;
    gap: 16px;
    min-width: 0;
    flex: 1;
  }

  .status-dot {
    width: 14px;
    height: 14px;
    border-radius: 50%;
    flex-shrink: 0;
    background: var(--text-muted);
    transition: background var(--transition-slow) ease, box-shadow var(--transition-slow) ease;
  }

  .status-dot.pending {
    background: var(--warning);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--warning) 18%, transparent);
  }

  .status-dot.warn {
    background: var(--warning);
  }

  .status-dot.on {
    background: var(--success);
    box-shadow:
      0 0 0 3px color-mix(in srgb, var(--success) 20%, transparent),
      0 0 14px color-mix(in srgb, var(--ember-color, #c2185b) 35%, transparent);
  }

  .status-label {
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 10px;
    line-height: 1.2;
  }

  .hero-text .hint {
    margin: 6px 0 0;
    max-width: 56ch;
  }

  .hint {
    color: var(--text-muted);
    font-size: var(--font-size-md);
    line-height: 1.5;
  }

  /* --- Glance metrics --- */

  .stat-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
  }

  /* The shared `.stat-card`, centred with the number above its label and in
     the Ember colour. */
  .stat {
    text-align: center;
    transition: border-color var(--transition-normal) ease;
  }

  .stat:hover {
    border-color: color-mix(in srgb, var(--ember-color) 22%, var(--border));
  }

  .stat .value {
    margin-top: 0;
    color: var(--ember-color);
  }

  .stat .label {
    margin-top: 6px;
  }

  /* --- Health checklist --- */

  .checklist {
    padding-top: 16px;
    padding-bottom: 8px;
  }

  .check-row {
    display: flex;
    gap: 14px;
    padding: 14px 0;
    border-top: 1px solid color-mix(in srgb, var(--border) 80%, transparent);
  }

  .check-row:first-of-type {
    border-top: none;
    padding-top: 2px;
  }

  .check-indicator {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    margin-top: 1px;
    color: var(--text-muted);
    background: color-mix(in srgb, var(--text-muted) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--text-muted) 22%, transparent);
  }

  .check-indicator.ok {
    color: var(--badge-success-text);
    background: color-mix(in srgb, var(--success) 14%, transparent);
    border-color: color-mix(in srgb, var(--success) 28%, transparent);
  }

  .check-indicator.warn {
    color: var(--badge-warning-text);
    background: color-mix(in srgb, var(--warning) 14%, transparent);
    border-color: color-mix(in srgb, var(--warning) 28%, transparent);
  }

  .check-indicator.muted {
    color: var(--text-secondary);
    background: color-mix(in srgb, var(--text-muted) 12%, transparent);
    border-color: color-mix(in srgb, var(--text-muted) 22%, transparent);
  }

  .check-body {
    min-width: 0;
    flex: 1;
  }

  .check-head {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }

  .check-label {
    font-size: var(--font-size-md);
    font-weight: 600;
    color: var(--text-primary);
  }

  .check-row .hint {
    margin: 5px 0 0;
    max-width: 70ch;
  }

  /* --- Technical details disclosure --- */

  .advanced {
    padding: 0;
  }

  .advanced summary {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 14px 20px;
    cursor: pointer;
    list-style: none;
    border-radius: var(--radius-lg);
  }

  .advanced summary::-webkit-details-marker {
    display: none;
  }

  .advanced summary:hover .summary-title {
    color: var(--accent);
  }

  .advanced summary:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }

  .chevron {
    display: inline-flex;
    color: var(--text-muted);
    transition: transform var(--transition-normal) ease;
    flex-shrink: 0;
  }

  .advanced[open] .chevron {
    transform: rotate(90deg);
  }

  .summary-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .summary-title {
    font-size: var(--font-size-base);
    font-weight: 600;
    color: var(--text-primary);
  }

  .summary-hint {
    font-size: var(--font-size-sm);
    color: var(--text-muted);
  }

  .advanced-body {
    display: flex;
    flex-direction: column;
    gap: 18px;
    padding: 4px 20px 20px;
    border-top: 1px solid var(--border);
    margin-top: -1px;
  }

  .advanced-body .sub-card:first-child {
    padding-top: 14px;
  }

  .sub-card h3 {
    font-size: var(--font-size-md);
    font-weight: 600;
    color: var(--text-primary);
    margin: 0 0 4px;
  }

  .sub-card .hint {
    margin: 0 0 8px;
  }

  .metric-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0 24px;
    margin-top: 6px;
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
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .metric-v {
    font-size: var(--font-size-sm);
    font-weight: 600;
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }

  .panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 8px;
  }

  .panel-head h3 {
    margin: 0;
  }

  .panel-tools {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    justify-content: flex-end;
    min-width: 0;
  }

  .count-pill {
    display: inline-block;
    margin-left: 6px;
    padding: 0 7px;
    border-radius: var(--radius-pill);
    background: var(--bg-tertiary);
    color: var(--text-muted);
    font-size: var(--font-size-xs);
    font-weight: 600;
    line-height: 1.6;
    vertical-align: 1px;
    font-variant-numeric: tabular-nums;
  }

  .metric-empty {
    grid-column: 1 / -1;
    margin: 6px 0 0;
  }

  .filter-input {
    flex: 1;
    min-width: 140px;
    max-width: 260px;
    padding: 6px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-pill);
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: var(--font-size-md);
  }

  .table-wrap {
    overflow: auto;
    max-height: 280px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
  }

  .dht-table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--font-size-sm);
  }

  .dht-table th,
  .dht-table td {
    padding: 6px 10px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  .dht-table th {
    position: sticky;
    top: 0;
    background: var(--bg-secondary);
    color: var(--text-muted);
    font-weight: 600;
    font-size: var(--font-size-xs);
    text-transform: uppercase;
    letter-spacing: 0.4px;
  }

  .dht-table code {
    font-size: var(--font-size-xs);
  }

  .dht-table .empty {
    color: var(--text-muted);
    text-align: center;
    padding: 16px;
  }

  .kv {
    display: grid;
    grid-template-columns: 160px 1fr;
    gap: 10px;
    align-items: center;
    padding: 8px 0;
    border-top: 1px solid var(--border);
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
    padding: 4px 10px;
    font-size: var(--font-size-sm);
    cursor: pointer;
    transition: background var(--transition-normal) ease, color var(--transition-normal) ease, border-color var(--transition-normal) ease;
  }

  .copy-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
    border-color: var(--accent);
  }

  .banner {
    border-radius: var(--radius-md);
    padding: 10px 14px;
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
    .chevron,
    .hero,
    .hero-glow,
    .status-dot,
    .stat { transition: none; }
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

  @media (max-width: 760px) {
    .page-header {
      align-items: flex-start;
      flex-direction: column;
    }

    .stat-grid {
      grid-template-columns: 1fr 1fr;
    }
    .metric-grid {
      grid-template-columns: 1fr;
    }
    .kv {
      grid-template-columns: 1fr;
      gap: 4px;
    }
    .status-label {
      font-size: var(--font-size-2xl);
    }
  }
</style>
