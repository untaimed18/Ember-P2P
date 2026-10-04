<script lang="ts">
  import { onMount } from 'svelte';
  import { get } from 'svelte/store';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { listen } from '@tauri-apps/api/event';
  import { networkStats, serverStatus } from '$lib/stores/network';
  import { getSharedFileCount } from '$lib/api/sharing';
  import { formatBytes, formatNumber, formatSpeed } from '$lib/utils';
  import { addToast } from '$lib/stores/toast';
  import { emberJoinTimedOut } from '$lib/stores/emberJoin';
  import { isUploadCounterPhase } from '$lib/sharedFileStats';
  import { plural } from '$lib/plural';
  import * as m from '$lib/paraglide/messages';

  // Count / total size of files the user is actively sharing (the `shared`
  // flag is set), which is intentionally distinct from the total number of
  // files in the Library — unshared files are indexed but not counted here.
  let sharedCount = $state(0);
  let sharedBytes = $state(0);
  let sharedRefreshGen = 0;
  let sharedRefreshFailedToast = false;

  function openPage(href: string) {
    if (get(page).url.pathname === href) return;
    void goto(href).catch((e) => console.warn('StatusBar: navigation failed', e));
  }

  function sharedTitle(count: number, bytes: number): string {
    const size = formatBytes(bytes);
    const n = formatNumber(count);
    return plural(count, {
      one: () => m.statusbar_shared_title_one({ size }),
      few: () => m.statusbar_shared_title_few({ count: n, size }),
      other: () => m.statusbar_shared_title_other({ count: n, size }),
    });
  }

  onMount(() => {
    let active = true;
    // `getSharedFileCount` walks the whole library, so a burst of events costs
    // at most the call in flight plus one more after it, and nothing while
    // the window is hidden — the `visibilitychange` handler catches up.
    let sharedRefreshInFlight = false;
    let sharedRefreshDirty = false;

    async function refreshSharedCount() {
      if (!active) return;
      if (sharedRefreshInFlight || document.visibilityState !== 'visible') {
        sharedRefreshDirty = true;
        return;
      }
      sharedRefreshInFlight = true;
      sharedRefreshDirty = false;
      const gen = ++sharedRefreshGen;
      try {
        const stats = await getSharedFileCount();
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
      } finally {
        sharedRefreshInFlight = false;
        if (sharedRefreshDirty) void refreshSharedCount();
      }
    }

    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible' && sharedRefreshDirty) {
        void refreshSharedCount();
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);

    void refreshSharedCount();

    // The library indexer emits this whenever files are shared, unshared,
    // added, removed, or finish hashing, so the bottom-bar count stays in
    // sync without polling. Upload counters never change the count or size.
    const unlistenPromise = listen('shared-files-changed', (event) => {
      if (isUploadCounterPhase(event.payload)) return;
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
      document.removeEventListener('visibilitychange', onVisibilityChange);
      void unlistenPromise
        .then((unlisten) => unlisten())
        .catch((e) => console.error('Failed to unlisten shared-files-changed:', e));
    };
  });

  // HighID/LowID while connected to an eD2K server, nothing otherwise.
  const ed2kId = $derived(
    $serverStatus === 'connected' && typeof $networkStats.ed2k_low_id === 'boolean'
      ? ($networkStats.ed2k_low_id ? 'low' : 'high')
      : null,
  );

  function ed2kTitle(status: string, id: 'low' | 'high' | null): string {
    const base = m.statusbar_ed2k_title({ status: statusLabel(status) });
    if (!id) return base;
    return `${base} · ${id === 'low' ? m.servers_lowid() : m.servers_highid()}`;
  }

  // Source exchange rides the Ember overlay, not KAD. Keying this off
  // `stats.status` (the KAD light) made the Ember tooltip say "network
  // offline" while Ember itself was connected.
  function epxStatus(stats: typeof $networkStats): 'active' | 'idle' | 'inactive' {
    if (!stats.ember_native_enabled) return 'inactive';
    return stats.ember_peers > 0 ? 'active' : 'idle';
  }

  // A join that timed out is the Ember page's amber "No peers found", not a
  // red disconnect: the overlay is running and still looking.
  function emberDhtStatus(
    stats: typeof $networkStats,
    timedOut: boolean,
  ): 'connected' | 'connecting' | 'no_peers' | 'disconnected' {
    if (!stats.ember_native_enabled) return 'disconnected';
    if ((stats.ember_dht_verified_contacts ?? 0) > 0) return 'connected';
    return timedOut ? 'no_peers' : 'connecting';
  }

  function emberDhtTitle(stats: typeof $networkStats, timedOut: boolean): string {
    const status = emberDhtStatus(stats, timedOut);
    let base: string;
    if (status === 'connected') {
      const peers = stats.ember_dht_verified_contacts ?? 0;
      const label = statusLabel(status);
      base = plural(peers, {
        one: () => m.statusbar_ember_dht_title_peers_one({ status: label }),
        few: () => m.statusbar_ember_dht_title_peers_few({ status: label, count: peers }),
        other: () => m.statusbar_ember_dht_title_peers_other({ status: label, count: peers }),
      });
    } else if (status === 'no_peers') {
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
      case 'no_peers': return m.ember_status_no_peers();
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
    return plural(p, {
      one: () => plural(s, {
        one: m.statusbar_epx_title_active_one_one,
        other: () => m.statusbar_epx_title_active_one_other({ sources: s }),
      }),
      other: () => plural(s, {
        one: () => m.statusbar_epx_title_active_other_one({ peers: p }),
        other: () => m.statusbar_epx_title_active_other_other({ peers: p, sources: s }),
      }),
    });
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
        title={emberDhtTitle($networkStats, $emberJoinTimedOut)}
        onclick={() => openPage('/ember')}
      >
        {m.statusbar_ember_dht_label()}
        <span class="dot {emberDhtStatus($networkStats, $emberJoinTimedOut)}" aria-label={statusLabel(emberDhtStatus($networkStats, $emberJoinTimedOut))}></span>
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
        title={ed2kTitle($serverStatus, ed2kId)}
        onclick={() => openPage('/servers')}
      >
        {m.statusbar_ed2k_label()}
        <span class="dot {$serverStatus}" aria-label={statusLabel($serverStatus)}></span>
        {#if ed2kId}
          <!-- The one number eMule users check first: a LowID is why
               downloads crawl, and it used to live only on the Servers page. -->
          <span class="ed2k-id" class:low={ed2kId === 'low'}>
            {ed2kId === 'low' ? m.servers_lowid() : m.servers_highid()}
          </span>
        {/if}
      </button>
    </div>
    <button
      type="button"
      class="status-label status-shared"
      title={sharedTitle(sharedCount, sharedBytes)}
      onclick={() => openPage('/library')}
    >
      <span class="shared-label">{m.statusbar_shared_label()}</span>
      <span class="shared-count">{formatNumber(sharedCount)}</span>
      <span class="shared-size">({formatBytes(sharedBytes)})</span>
    </button>
  </div>

  <div class="status-right" role="group" aria-label={m.statusbar_speeds_aria()}>
    <!--
      Status bar rates/totals are file-transfer payload only (BandwidthLimiter).
      Protocol overhead (server, KAD, source exchange, EPX, Ember DHT, reasks)
      is tracked on the Statistics page — these numbers intentionally differ
      from a full "network bytes" view.
    -->
    <!-- Buttons like the network dots: "why is it slow?" is answered on
         Transfers, so the rates go there. -->
    <button type="button" class="status-label status-item upload" title={m.statusbar_upload_title()} onclick={() => openPage('/transfers')}>
      <span aria-hidden="true">↑</span>
      <span class="sr-only">{m.statusbar_upload_sr()}</span>
      {formatSpeed($networkStats.upload_speed)}
    </button>
    <button type="button" class="status-label status-item download" title={m.statusbar_download_title()} onclick={() => openPage('/transfers')}>
      <span aria-hidden="true">↓</span>
      <span class="sr-only">{m.statusbar_download_sr()}</span>
      {formatSpeed($networkStats.download_speed)}
    </button>
    <span class="status-item muted status-totals" role="img" title={m.statusbar_total_transferred({ up: formatBytes($networkStats.total_uploaded), down: formatBytes($networkStats.total_downloaded) })} aria-label={m.statusbar_total_transferred({ up: formatBytes($networkStats.total_uploaded), down: formatBytes($networkStats.total_downloaded) })}>
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
    font-size: var(--font-size-sm);
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

  .ed2k-id {
    font-size: var(--font-size-2xs);
    font-weight: 600;
    color: var(--status-connected);
  }

  .ed2k-id.low {
    color: var(--warning);
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

  .dot.no_peers {
    background: transparent;
    box-shadow: inset 0 0 0 2px var(--warning), 0 0 0 2px color-mix(in srgb, var(--warning) 18%, transparent);
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

  .status-item.upload:hover,
  .status-item.download:hover {
    color: var(--text-primary);
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
