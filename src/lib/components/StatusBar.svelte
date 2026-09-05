<script lang="ts">
  import { onMount } from 'svelte';
  import { get } from 'svelte/store';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { listen } from '@tauri-apps/api/event';
  import { networkStats, serverStatus } from '$lib/stores/network';
  import { getSharedFileCount } from '$lib/api/sharing';
  import { formatBytes, formatSpeed } from '$lib/utils';
  import { addToast } from '$lib/stores/toast';
  import { EMBER_JOIN_TIMEOUT_MS } from '$lib/emberJoin';
  import * as m from '$lib/paraglide/messages';

  // Count / total size of files the user is actively sharing (the `shared`
  // flag is set), which is intentionally distinct from the total number of
  // files in the Library — unshared files are indexed but not counted here.
  let sharedCount = $state(0);
  let sharedBytes = $state(0);
  let sharedRefreshGen = 0;
  let sharedRefreshFailedToast = false;
  let emberJoinTimedOut = $state(false);
  let emberJoinSince: number | null = null;
  let emberJoinTimer: ReturnType<typeof setTimeout> | null = null;

  function recomputeEmberJoin(stats: typeof $networkStats) {
    const enabled = !!stats.ember_native_enabled;
    const verified = stats.ember_dht_verified_contacts ?? 0;
    if (!enabled || verified > 0) {
      if (emberJoinTimer) {
        clearTimeout(emberJoinTimer);
        emberJoinTimer = null;
      }
      emberJoinSince = null;
      emberJoinTimedOut = false;
      return;
    }
    if (emberJoinSince === null) {
      emberJoinSince = Date.now();
      emberJoinTimedOut = false;
      emberJoinTimer = setTimeout(() => {
        emberJoinTimedOut = true;
        emberJoinTimer = null;
      }, EMBER_JOIN_TIMEOUT_MS);
    }
  }

  $effect(() => {
    recomputeEmberJoin($networkStats);
  });

  function openPage(href: string) {
    if (get(page).url.pathname === href) return;
    void goto(href).catch((e) => console.warn('StatusBar: navigation failed', e));
  }

  function sharedTitle(count: number, bytes: number): string {
    const size = formatBytes(bytes);
    return count === 1
      ? m.statusbar_shared_title_one({ size })
      : m.statusbar_shared_title_other({ count: count.toLocaleString(), size });
  }

  onMount(() => {
    let active = true;

    async function refreshSharedCount() {
      const gen = ++sharedRefreshGen;
      try {
        const stats = await getSharedFileCount();
        // Ignore stale responses from overlapping shared-files-changed bursts.
        if (active && gen === sharedRefreshGen) {
          sharedCount = stats.count;
          sharedBytes = stats.total_bytes;
        }
      } catch (e) {
        console.warn('StatusBar: getSharedFileCount failed', e);
        if (!sharedRefreshFailedToast) {
          sharedRefreshFailedToast = true;
          addToast('warning', m.statusbar_shared_refresh_failed());
        }
      }
    }

    void refreshSharedCount();

    // The library indexer emits this whenever files are shared, unshared,
    // added, removed, or finish hashing, so the bottom-bar count stays in
    // sync without polling.
    const unlistenPromise = listen('shared-files-changed', () => {
      void refreshSharedCount();
    }).catch((e) => {
      console.warn('StatusBar: shared-files-changed listen failed', e);
      if (!sharedRefreshFailedToast) {
        sharedRefreshFailedToast = true;
        addToast('warning', m.statusbar_shared_refresh_failed());
      }
      return () => {};
    });

    return () => {
      active = false;
      if (emberJoinTimer) {
        clearTimeout(emberJoinTimer);
        emberJoinTimer = null;
      }
      void unlistenPromise
        .then((unlisten) => unlisten())
        .catch((e) => console.error('Failed to unlisten shared-files-changed:', e));
    };
  });

  // Source exchange rides the Ember overlay, not KAD. Keying this off
  // `stats.status` (the KAD light) made the Ember tooltip say "network
  // offline" while Ember itself was connected.
  function epxStatus(stats: typeof $networkStats): 'active' | 'idle' | 'inactive' {
    if (!stats.ember_native_enabled) return 'inactive';
    return stats.ember_peers > 0 ? 'active' : 'idle';
  }

  function emberDhtStatus(stats: typeof $networkStats): 'connected' | 'connecting' | 'disconnected' {
    if (!stats.ember_native_enabled) return 'disconnected';
    if ((stats.ember_dht_verified_contacts ?? 0) > 0) return 'connected';
    return emberJoinTimedOut ? 'disconnected' : 'connecting';
  }

  function emberDhtTitle(stats: typeof $networkStats): string {
    const status = emberDhtStatus(stats);
    let base: string;
    if (status === 'connected') {
      const peers = stats.ember_dht_verified_contacts ?? 0;
      base = peers === 1
        ? m.statusbar_ember_dht_title_peers_one({ status: statusLabel(status) })
        : m.statusbar_ember_dht_title_peers_other({ status: statusLabel(status), count: peers });
    } else if (stats.ember_native_enabled && emberJoinTimedOut) {
      base = m.statusbar_ember_dht_title_no_peers();
    } else {
      base = m.statusbar_ember_dht_title({ status: statusLabel(status) });
    }
    return `${base} · ${epxTitle(stats)}`;
  }

  // Localized status string for the tri-state network/server dots.
  // Keep the mapping co-located with the status-bar specifically
  // (instead of pulling from `network_status_*`) because the
  // status-bar shows "Connected/Connecting/Disconnected" while
  // some pages use the Spanish equivalents in different
  // grammatical positions; the mapping is identical today but may
  // diverge for accessibility tweaks per surface.
  function statusLabel(s: string): string {
    switch (s) {
      case 'connected': return m.network_status_connected();
      case 'connecting': return m.network_status_connecting();
      case 'disconnected': return m.network_status_disconnected();
      default: return m.network_status_unknown();
    }
  }

  // Two-axis plural for the source-exchange tooltip. English/Spanish both
  // distinguish singular/plural; we render one of four templates
  // rather than concatenating fragments so translators control
  // word order.
  function epxTitle(stats: typeof $networkStats): string {
    const status = epxStatus(stats);
    if (status === 'inactive') return m.statusbar_epx_title_offline();
    if (status === 'idle') return m.statusbar_epx_title_idle();
    const p = stats.ember_peers;
    const s = stats.epx_sources_received;
    if (p === 1 && s === 1) return m.statusbar_epx_title_active_one_one();
    if (p === 1) return m.statusbar_epx_title_active_one_other({ sources: s });
    if (s === 1) return m.statusbar_epx_title_active_other_one({ peers: p });
    return m.statusbar_epx_title_active_other_other({ peers: p, sources: s });
  }
</script>

<footer class="statusbar">
  <!--
    Each indicator navigates to the page that can do something about it. A red
    dot is the app's most common "something is wrong" signal and it used to be
    a dead end: the detail was tooltip-only, and the user had to know which of
    Ember / KAD / eD2K Servers owned the problem before they could act.
  -->
  <div class="status-left">
    <!--
      The live region is the three network states, not the whole cluster. It
      used to wrap the shared-files counter too, so an ordinary library
      re-index re-announced every connection alongside it.
    -->
    <div class="status-networks" role="status" aria-live="polite">
      <button
        type="button"
        class="status-label"
        title={emberDhtTitle($networkStats)}
        onclick={() => openPage('/ember')}
      >
        {m.statusbar_ember_dht_label()}
        <span class="dot {emberDhtStatus($networkStats)}" aria-label={statusLabel(emberDhtStatus($networkStats))}></span>
      </button>
      <button
        type="button"
        class="status-label"
        title={m.statusbar_kad_title({ status: statusLabel($networkStats.status) })}
        onclick={() => openPage('/kad')}
      >
        {m.statusbar_kad_label()}
        <span class="dot {$networkStats.status}" aria-label={statusLabel($networkStats.status)}></span>
      </button>
      <button
        type="button"
        class="status-label"
        title={m.statusbar_ed2k_title({ status: statusLabel($serverStatus) })}
        onclick={() => openPage('/servers')}
      >
        {m.statusbar_ed2k_label()}
        <span class="dot {$serverStatus}" aria-label={statusLabel($serverStatus)}></span>
      </button>
    </div>
    <button
      type="button"
      class="status-label status-shared"
      title={sharedTitle(sharedCount, sharedBytes)}
      onclick={() => openPage('/library')}
    >
      <span class="shared-label">{m.statusbar_shared_label()}</span>
      <span class="shared-count">{sharedCount.toLocaleString()}</span>
      <span class="shared-size">({formatBytes(sharedBytes)})</span>
    </button>
  </div>

  <div class="status-right" aria-label={m.statusbar_speeds_aria()}>
    <!--
      Status bar rates/totals are file-transfer payload only (BandwidthLimiter).
      Protocol overhead (server, KAD, source exchange, EPX, Ember DHT, reasks)
      is tracked on the Statistics page — these numbers intentionally differ
      from a full "network bytes" view.
    -->
    <span class="status-item upload" title={m.statusbar_upload_title()}>
      <span aria-hidden="true">↑</span>
      <span class="sr-only">{m.statusbar_upload_sr()}</span>
      {formatSpeed($networkStats.upload_speed)}
    </span>
    <span class="status-item download" title={m.statusbar_download_title()}>
      <span aria-hidden="true">↓</span>
      <span class="sr-only">{m.statusbar_download_sr()}</span>
      {formatSpeed($networkStats.download_speed)}
    </span>
    <span class="status-item muted status-totals" title={m.statusbar_total_transferred({ up: formatBytes($networkStats.total_uploaded), down: formatBytes($networkStats.total_downloaded) })} aria-label={m.statusbar_total_transferred({ up: formatBytes($networkStats.total_uploaded), down: formatBytes($networkStats.total_downloaded) })}>
      <span aria-hidden="true">↑</span> {formatBytes($networkStats.total_uploaded)} / <span aria-hidden="true">↓</span> {formatBytes($networkStats.total_downloaded)}
    </span>
  </div>
</footer>

<style>
  .statusbar {
    min-height: var(--statusbar-height);
    background: var(--bg-secondary);
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 0 16px;
    font-size: 12px;
    flex-shrink: 0;
    overflow: hidden;
  }

  .status-left, .status-right {
    display: flex;
    align-items: center;
    gap: 16px;
    min-width: 0;
  }

  .status-right {
    flex-shrink: 0;
  }

  .status-networks {
    display: flex;
    align-items: center;
    gap: 16px;
    min-width: 0;
  }

  /* These are <button>s now, so the global button paint (accent fill, 7px
     padding, 600 weight) has to be undone — they must still read as status
     text, with the interactivity showing on hover/focus. */
  .status-label {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 4px;
    margin: 0 -4px;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-secondary);
    font: inherit;
    font-weight: 400;
    cursor: pointer;
    white-space: nowrap;
  }

  .status-label:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .status-label:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
    flex-shrink: 0;
  }

  .shared-count,
  .shared-size {
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
  }

  .shared-size {
    color: var(--text-muted);
  }

  .dot.connected {
    background: var(--status-connected);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--status-connected) 18%, transparent);
  }

  .dot.connecting {
    background: var(--status-connecting);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--status-connecting) 18%, transparent);
    animation: status-pulse 1.5s ease-in-out infinite;
  }

  .dot.disconnected {
    background: var(--status-disconnected);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--status-disconnected) 16%, transparent);
  }

  .status-item {
    color: var(--text-secondary);
    white-space: nowrap;
  }

  .status-item.upload {
    color: var(--warning);
  }

  .status-item.download {
    color: var(--accent);
  }

  .status-item.muted {
    color: var(--text-muted);
  }

  @keyframes status-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.45; }
  }

  /* Laptop / mid-width: keep connection dots + live rates; tuck secondary
     size labels and session totals behind tooltips-only (title still set). */
  @media (max-width: 1200px) {
    .statusbar {
      padding: 0 10px;
      gap: 8px;
    }

    .status-left, .status-right, .status-networks {
      gap: 10px;
    }

    .shared-size,
    .status-totals {
      display: none;
    }
  }

  @media (max-width: 980px) {
    /* The shared count stays — it was dropped entirely here, which left no
       trace of it at all on a laptop window. Only the word goes, and it goes
       visually rather than semantically: `display: none` would take it out of
       the button's accessible name, leaving a control announced as a bare
       number. Same recipe as the global `.sr-only`, inlined because scoped
       styles can't reach a global class. */
    .status-shared .shared-label {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border-width: 0;
    }

    .status-left, .status-right, .status-networks {
      gap: 8px;
    }
  }
</style>
