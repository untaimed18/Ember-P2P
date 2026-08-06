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
   * The toggle persists through `update_settings` and the backend applies
   * it live, though a node that starts with an empty routing table only
   * fills it once the maintenance tick runs the KAD bridge — there is no
   * central pool to fetch from.
   */
  import { onMount, untrack } from 'svelte';
  import { getSettings, updateSettings } from '$lib/api/settings';
  import {
    getEmberDiagnostics,
    getEmberDhtContacts,
    getEmberDhtSearches,
    getEmberDhtStore,
  } from '$lib/api/ember';
  import type {
    AppSettings,
    EmberDiagnostics,
    EmberDhtContact,
    EmberDhtSearchEntry,
    EmberDhtStoreEntry,
  } from '$lib/types';
  import { translateError } from '$lib/i18n';
  import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
  import * as m from '$lib/paraglide/messages';

  let settings = $state<AppSettings | null>(null);
  let diag = $state<EmberDiagnostics | null>(null);
  let contacts = $state<EmberDhtContact[]>([]);
  let searches = $state<EmberDhtSearchEntry[]>([]);
  let storeEntries = $state<EmberDhtStoreEntry[]>([]);
  let contactFilter = $state('');
  let loadError = $state<string | null>(null);
  let toggleError = $state<string | null>(null);
  let detailsOpen = $state(false);

  // `enabled` is the toggle's bound value; `lastAppliedEnabled` is the
  // last value we successfully persisted. The `$effect` below applies a
  // change only when the two diverge (i.e. the user moved the switch),
  // which keeps the initial load and the failure-revert from re-entering
  // the save path. Mirrors the antileech toggle pattern in Settings.
  let enabled = $state(false);
  let lastAppliedEnabled = $state<boolean | null>(null);
  let applying = $state(false);

  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let unmounted = false;
  let inFlightDiag = false;
  let inFlightLists = false;

  // Diagnostics-health + join-progress state. `diagStale` raises a banner
  // once polling has failed several times in a row (the service is down,
  // not just a transient blip), so the numbers below aren't silently
  // mistaken for live ones. The join timer flips `joinTimedOut` so the
  // "connecting…" state can't linger forever when no peers are reachable.
  let diagStale = $state(false);
  let joinTimedOut = $state(false);
  let diagFailures = 0;
  let activeSince: number | null = null;
  let joinTimer: ReturnType<typeof setTimeout> | null = null;
  const DIAG_FAILURE_THRESHOLD = 3;
  // Long enough to span a couple of backend maintenance ticks (60s each),
  // which is what actually drives the bridge that finds our first contacts.
  // A shorter window used to be fine when joining kicked an immediate fetch
  // from a central pool; without one, a fresh node can legitimately sit at
  // zero contacts for a minute or two, and giving up at 30s made a healthy
  // node look broken.
  const JOINING_TIMEOUT_MS = 150_000;

  async function refreshDiag() {
    if (unmounted || inFlightDiag) return;
    inFlightDiag = true;
    try {
      diag = await getEmberDiagnostics();
      diagFailures = 0;
      diagStale = false;
      reconcileToggle();
      recomputeJoinState();
    } catch {
      // Tolerate transient blips (keep the previous snapshot; the toggle
      // still works), but surface a banner once the service has been
      // unreachable for several polls in a row.
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
    void refreshLists();
  }

  let filteredContacts = $derived.by(() => {
    const q = contactFilter.trim().toLowerCase();
    if (!q) return contacts;
    return contacts.filter(
      (c) =>
        c.node_id.toLowerCase().includes(q) ||
        c.addr.toLowerCase().includes(q) ||
        (c.distance ?? '').toLowerCase().includes(q),
    );
  });

  function shortHex(hex: string, head = 8, tail = 4): string {
    if (hex.length <= head + tail + 1) return hex || '—';
    return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
  }

  // Keep the switch honest with the backend's *actual* state. Ember can
  // also be flipped from the Settings page, and the backend can refuse or
  // revert a change; when we're not mid-apply and the user has no pending
  // move (switch matches last-applied), adopt whatever the live
  // diagnostics report so the control never lies about reality.
  function reconcileToggle() {
    if (applying || !diag) return;
    if (enabled !== lastAppliedEnabled) return;
    const live = !!diag.ember_native_enabled;
    if (live !== enabled) {
      enabled = live;
      lastAppliedEnabled = live;
      if (settings) settings = { ...settings, ember_native_enabled: live };
    }
  }

  // Drive the join-progress timer off each diagnostics snapshot (a plain
  // function, not a reactive `$effect`, so there's no write-read feedback
  // loop on `joinTimedOut`). While active with zero contacts we run a
  // one-shot timer; finding a contact — or turning Ember off — resets it.
  function recomputeJoinState() {
    const active = !!diag?.ember_native_enabled;
    const contacts = diag?.ember_dht_contacts ?? 0;
    if (!active || contacts > 0) {
      if (joinTimer) { clearTimeout(joinTimer); joinTimer = null; }
      activeSince = null;
      joinTimedOut = false;
      return;
    }
    if (activeSince === null) {
      activeSince = Date.now();
      joinTimedOut = false;
      joinTimer = setTimeout(() => { joinTimedOut = true; joinTimer = null; }, JOINING_TIMEOUT_MS);
    }
  }

  async function applyToggle(want: boolean) {
    if (!settings) return;
    applying = true;
    toggleError = null;
    try {
      const next: AppSettings = { ...settings, ember_native_enabled: want };
      await updateSettings(next);
      settings = next;
      lastAppliedEnabled = want;
      await refreshDiag();
    } catch (e) {
      toggleError = m.ember_toggle_failed({ error: translateError(e) });
      // Roll the switch back to the persisted value.
      enabled = lastAppliedEnabled ?? false;
    } finally {
      applying = false;
    }
  }

  // Fire `applyToggle` only on a real user-driven change.
  $effect(() => {
    const want = enabled;
    if (lastAppliedEnabled === null) return;
    if (want === lastAppliedEnabled) return;
    untrack(() => { void applyToggle(want); });
  });

  let copiedKey = $state<string | null>(null);
  let copyTimer: ReturnType<typeof setTimeout> | null = null;

  async function copyText(value: string, key: string) {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      copiedKey = key;
    } catch {
      copiedKey = `${key}:error`;
    }
    if (copyTimer) clearTimeout(copyTimer);
    copyTimer = setTimeout(() => { copiedKey = null; }, 1500);
  }

  let isActive = $derived(!!diag?.ember_native_enabled);
  let peerCount = $derived(diag?.ember_dht_contacts ?? 0);
  let joining = $derived(isActive && peerCount === 0 && !joinTimedOut);
  let isConnected = $derived(isActive && peerCount > 0);

  // Until the first diagnostics land we genuinely don't know the state, and
  // an enabled node would otherwise be announced as "Off" with a "turn it
  // on" hint for a round trip.
  let statusLabel = $derived(
    diag === null
      ? m.common_loading()
      : !isActive
        ? m.ember_status_disabled()
        : isConnected
          ? m.ember_status_connected()
          : joining
            ? m.ember_status_connecting()
            : m.ember_status_no_peers(),
  );

  let statusHint = $derived(
    diag === null
      ? ''
      : !isActive
        ? m.ember_disabled_explainer()
        : isConnected
          ? m.ember_status_connected_hint()
          : joining
            ? m.ember_joining_hint()
            : m.ember_no_contacts_hint(),
  );

  // "Checking" outranks "relayed": without a known external address the
  // firewall verdict isn't settled yet, so claiming a relay is in use
  // would be guessing.
  type Reachability = 'direct' | 'relayed' | 'checking';
  let reachability: Reachability = $derived(
    diag?.ember_dht_udp_unreachable
      ? 'checking'
      : diag?.ember_dht_firewalled_publishing
        ? 'relayed'
        : 'direct',
  );

  let reachabilityLabel = $derived(
    reachability === 'direct'
      ? m.ember_health_direct()
      : reachability === 'relayed'
        ? m.ember_health_relayed()
        : m.kad_checking(),
  );

  let reachabilityHint = $derived(
    reachability === 'direct'
      ? m.ember_health_direct_hint()
      : reachability === 'relayed'
        ? m.ember_dht_firewalled_publishing_hint()
        : m.ember_dht_udp_unreachable_hint(),
  );

  // Deliberately the live count of files with a placed source record, not the
  // session `*_published` counters: those only ever climb, so they would keep
  // claiming "Published" after the user unshared everything, and a keyword ack
  // alone would flip the pill before the source record that actually makes the
  // file fetchable. This is the same set behind the Library's Ember badge.
  let sharingPublished = $derived((diag?.ember_dht_published_files ?? 0) > 0);

  // `id` exists so the `{#each}` below is keyed on something stable. Keying
  // on the label would put a translator in a position to crash the page:
  // two of these strings colliding in one locale is a duplicate-key error.
  let metrics = $derived([
    { id: 'contacts', k: m.ember_stat_contacts(), v: String(peerCount) },
    { id: 'peers', k: m.ember_stat_peers(), v: String(diag?.ember_peers_known ?? 0) },
    { id: 'sessions', k: m.ember_stat_sessions(), v: String(diag?.ember_sessions ?? 0) },
    { id: 'records', k: m.ember_stat_records(), v: String(diag?.ember_dht_stored_records ?? 0) },
    { id: 'published-files', k: m.ember_stat_published_files(), v: String(diag?.ember_dht_published_files ?? 0) },
    { id: 'stored-keys', k: m.ember_stat_stored_keys(), v: String(diag?.ember_dht_stored_keys ?? 0) },
    { id: 'publishes', k: m.ember_stat_active_publishes(), v: String(diag?.ember_dht_active_publishes ?? 0) },
    { id: 'searches', k: m.ember_stat_active_searches(), v: String(diag?.ember_dht_active_searches ?? 0) },
    { id: 'search-hits', k: m.ember_stat_search_hit_miss(), v: `${diag?.ember_dht_search_hits ?? 0}/${diag?.ember_dht_search_misses ?? 0}` },
    { id: 'store-acks', k: m.ember_stat_store_ack_fail(), v: `${diag?.ember_dht_stores_acked ?? 0}/${diag?.ember_dht_stores_failed ?? 0}` },
    { id: 'replication', k: m.ember_stat_avg_replication(), v: String(diag?.ember_dht_avg_replication ?? 0) },
    { id: 'search-rounds', k: m.ember_stat_search_rounds(), v: String(diag?.ember_dht_search_rounds ?? 0) },
    { id: 'find-values', k: m.ember_stat_find_values_sent(), v: String(diag?.ember_dht_find_values_sent ?? 0) },
    { id: 'serve-hits', k: m.ember_stat_serve_hit_miss(), v: `${diag?.ember_dht_find_value_hits ?? 0}/${diag?.ember_dht_find_value_misses ?? 0}` },
    { id: 'buddy', k: m.ember_stat_buddy_pub_fwd(), v: `${diag?.ember_dht_buddy_publishes ?? 0}/${diag?.ember_dht_buddy_forwards ?? 0}` },
    { id: 'malformed', k: m.ember_stat_malformed(), v: String(diag?.ember_dht_malformed ?? 0) },
    { id: 'observed-votes', k: m.ember_stat_observed_votes(), v: String(diag?.ember_dht_observed_votes ?? 0) },
    { id: 'observed-addr', k: m.ember_stat_observed_addr(), v: diag?.ember_dht_observed_addr || '—' },
  ]);

  onMount(() => {
    getSettings()
      .then((s) => {
        settings = s;
        enabled = s.ember_native_enabled;
        lastAppliedEnabled = s.ember_native_enabled;
      })
      .catch((e) => { loadError = m.ember_load_failed({ error: translateError(e) }); });
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
      if (joinTimer) clearTimeout(joinTimer);
    };
  });
</script>

<svelte:head><title>{m.nav_ember_network()} — Ember</title></svelte:head>

<header class="page-header">
  <div>
    <h1>
      {m.nav_ember_network()}
      <span class="badge-experimental">{m.ember_experimental()}</span>
    </h1>
    <p class="subtitle">{m.ember_page_subtitle()}</p>
  </div>
</header>

<div class="page-content">
  <div class="ember-inner">
  {#if loadError}
    <div class="banner banner-error" role="alert">{loadError}</div>
  {/if}

  <!-- Status + power switch -->
  <section class="card hero">
    <div class="hero-main">
      <span class="status-dot" class:on={isConnected} class:pending={isActive && !isConnected}></span>
      <div class="hero-text">
        <div class="status-label">
          {statusLabel}
          {#if joining}<span class="spinner" aria-hidden="true"></span>{/if}
        </div>
        {#if statusHint}<p class="hint">{statusHint}</p>{/if}
      </div>
    </div>
    <div class="hero-toggle">
      <ToggleSwitch
        bind:checked={enabled}
        disabled={applying || settings === null}
        ariaLabel={m.ember_enable_label()}
      />
    </div>
  </section>

  {#if toggleError}
    <div class="banner banner-error" role="alert">{toggleError}</div>
  {/if}

  {#if diagStale}
    <div class="banner banner-error" role="alert">{m.ember_stats_unavailable()}</div>
  {/if}

  {#if isActive}
    <section class="stat-grid">
      <div class="stat">
        <div class="stat-value">{peerCount}</div>
        <div class="stat-label">{m.ember_overview_peers()}</div>
      </div>
      <div class="stat">
        <div class="stat-value">{diag?.ember_sessions ?? 0}</div>
        <div class="stat-label">{m.ember_overview_connections()}</div>
      </div>
      <div class="stat">
        <div class="stat-value">{diag?.ember_dht_active_searches ?? 0}</div>
        <div class="stat-label">{m.ember_overview_searches()}</div>
      </div>
    </section>

    <section class="card">
      <h2>{m.ember_health_title()}</h2>
      <div class="health-row">
        <div class="health-head">
          <span class="health-label">{m.ember_health_reachability()}</span>
          <span
            class="pill"
            class:ok={reachability === 'direct'}
            class:warn={reachability === 'relayed'}
            class:muted={reachability === 'checking'}
          >{reachabilityLabel}</span>
        </div>
        <p class="hint">{reachabilityHint}</p>
      </div>
      <div class="health-row">
        <div class="health-head">
          <span class="health-label">{m.ember_health_sharing()}</span>
          <span
            class="pill"
            class:ok={sharingPublished}
            class:muted={!sharingPublished}
          >{sharingPublished ? m.ember_health_sharing_published() : m.ember_health_sharing_waiting()}</span>
        </div>
        <p class="hint">{sharingPublished ? m.ember_health_sharing_published_hint() : m.ember_health_sharing_waiting_hint()}</p>
      </div>
    </section>
  {/if}

  <!-- About -->
  <section class="card">
    <h2>{m.ember_about_title()}</h2>
    <p class="about-text">{m.ember_about_text()}</p>
  </section>

  <!--
    Everything below is protocol-level diagnostics. Collapsed by default,
    and `onDetailsToggle` is what starts/stops polling the three snapshot
    commands that feed the tables.
  -->
  <details class="card advanced" ontoggle={onDetailsToggle}>
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
                <button type="button" class="copy-btn" onclick={() => copyText(row.value, row.key)} title={m.ember_copy()}>
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
          <h3>{m.ember_dht_status_title()}</h3>
          <div class="metric-grid">
            {#each metrics as metric (metric.id)}
              <div class="metric">
                <span class="metric-k">{metric.k}</span>
                <span class="metric-v">{metric.v}</span>
              </div>
            {/each}
          </div>
        </section>

        <section class="sub-card">
          <div class="panel-head">
            <h3>{m.ember_dht_contacts_title()}</h3>
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
                  <th>{m.ember_dht_col_addr()}</th>
                  <th>{m.ember_dht_col_distance()}</th>
                  <th>{m.ember_dht_col_fails()}</th>
                </tr>
              </thead>
              <tbody>
                {#each filteredContacts as c (c.node_id + c.addr)}
                  <tr>
                    <td title={c.node_id}><code>{shortHex(c.node_id)}</code></td>
                    <td><code>{c.addr}</code></td>
                    <td title={c.distance ?? ''}><code>{shortHex(c.distance ?? '', 6, 4)}</code></td>
                    <td>{c.failed_queries}</td>
                  </tr>
                {:else}
                  <tr><td colspan="4" class="empty">{m.ember_dht_contacts_empty()}</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>

        <section class="sub-card">
          <h3>{m.ember_dht_searches_title()}</h3>
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
                    <td>{s.type}{#if s.keyword_count > 1} ({s.keyword_count}){/if}</td>
                    <td title={s.target}><code>{shortHex(s.target)}</code></td>
                    <td>{s.results}</td>
                    <td>{s.responded}/{s.queried} · {s.in_flight}↑ · {s.pending}…</td>
                    <td>{s.age_secs}s</td>
                  </tr>
                {:else}
                  <tr><td colspan="6" class="empty">{m.ember_dht_searches_empty()}</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>

        <section class="sub-card">
          <h3>{m.ember_dht_store_title()}</h3>
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

<style>
  /*
   * Fixed `.page-header` + scrollable `.page-content` (the app-wide
   * pattern); `.ember-inner` is the centered column inside the scroll
   * area so content is never clipped by the layout's `overflow: hidden`.
   */
  .ember-inner {
    padding: 24px;
    max-width: 900px;
    margin: 0 auto;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .page-header h1 {
    font-size: 24px;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0;
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .subtitle {
    margin: 6px 0 0;
    color: var(--text-muted);
    font-size: 14px;
    line-height: 1.5;
    max-width: 70ch;
  }

  .badge-experimental {
    display: inline-block;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    padding: 2px 8px;
    border-radius: 8px;
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    vertical-align: middle;
  }

  .card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg, 10px);
    padding: 18px 20px;
  }

  .card h2 {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0 0 4px;
  }

  .hero {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  .hero-main {
    display: flex;
    align-items: center;
    gap: 14px;
    min-width: 0;
  }

  .status-dot {
    width: 14px;
    height: 14px;
    border-radius: 50%;
    flex-shrink: 0;
    background: var(--text-muted);
    transition: background 0.2s ease, box-shadow 0.2s ease;
  }

  .status-dot.pending {
    background: var(--warning, #d9a441);
  }

  .status-dot.on {
    background: #3ccf6d;
    box-shadow:
      0 0 0 3px color-mix(in srgb, #3ccf6d 20%, transparent),
      0 0 12px color-mix(in srgb, #3ccf6d 55%, transparent);
  }

  .status-label {
    font-size: 17px;
    font-weight: 700;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .hero-text .hint {
    margin: 2px 0 0;
    max-width: 62ch;
  }

  .hint {
    color: var(--text-muted);
    font-size: 13px;
    line-height: 1.5;
  }

  .stat-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
  }

  .stat {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg, 10px);
    padding: 16px;
    text-align: center;
  }

  .stat-value {
    font-size: 26px;
    font-weight: 700;
    color: var(--accent);
    line-height: 1.1;
    font-variant-numeric: tabular-nums;
  }

  .stat-label {
    margin-top: 4px;
    font-size: 12px;
    color: var(--text-muted);
  }

  /* --- Connection health --- */

  .health-row {
    padding: 10px 0;
    border-top: 1px solid var(--border);
  }

  .health-row:first-of-type {
    border-top: none;
    padding-top: 8px;
  }

  .health-row:last-of-type {
    padding-bottom: 0;
  }

  .health-head {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .health-label {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .health-row .hint {
    margin: 4px 0 0;
    max-width: 70ch;
  }

  .pill {
    font-size: 11px;
    font-weight: 600;
    padding: 2px 9px;
    border-radius: 999px;
    border: 1px solid transparent;
    white-space: nowrap;
  }

  .pill.ok {
    color: var(--badge-success-text, #3ccf6d);
    background: color-mix(in srgb, var(--success, #3ccf6d) 15%, transparent);
    border-color: color-mix(in srgb, var(--success, #3ccf6d) 30%, transparent);
  }

  .pill.warn {
    color: var(--badge-warning-text, #d9a441);
    background: color-mix(in srgb, var(--warning, #d9a441) 15%, transparent);
    border-color: color-mix(in srgb, var(--warning, #d9a441) 30%, transparent);
  }

  .pill.muted {
    color: var(--text-secondary);
    background: color-mix(in srgb, var(--text-muted) 15%, transparent);
    border-color: color-mix(in srgb, var(--text-muted) 28%, transparent);
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
    border-radius: var(--radius-lg, 10px);
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
    transition: transform 0.15s ease;
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
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .summary-hint {
    font-size: 12px;
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
    font-size: 13px;
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
    font-size: 12px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .metric-v {
    font-size: 12px;
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

  .filter-input {
    flex: 1;
    min-width: 140px;
    max-width: 260px;
    padding: 6px 10px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 13px;
  }

  .table-wrap {
    overflow: auto;
    max-height: 280px;
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  .dht-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
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
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.4px;
  }

  .dht-table code {
    font-size: 11px;
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
    font-size: 13px;
    color: var(--text-muted);
  }

  .pubkey-row {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }

  .pubkey {
    font-family: var(--font-mono, ui-monospace, monospace);
    font-size: 12px;
    color: var(--text-secondary);
    overflow-wrap: anywhere;
    min-width: 0;
  }

  .copy-btn {
    flex-shrink: 0;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    border-radius: var(--radius-md, 6px);
    padding: 4px 10px;
    font-size: 12px;
    cursor: pointer;
    transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease;
  }

  .copy-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
    border-color: var(--accent);
  }

  .about-text {
    margin: 0;
    color: var(--text-secondary);
    font-size: 13px;
    line-height: 1.6;
  }

  .banner {
    border-radius: var(--radius-md, 6px);
    padding: 10px 14px;
    font-size: 13px;
    line-height: 1.5;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .banner-error {
    background: color-mix(in srgb, var(--error, #e06a5f) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--error, #e06a5f) 35%, transparent);
    color: var(--error, #e06a5f);
  }

  .spinner {
    width: 13px;
    height: 13px;
    border-radius: 50%;
    border: 2px solid color-mix(in srgb, var(--accent) 30%, transparent);
    border-top-color: var(--accent);
    animation: spin 0.8s linear infinite;
    flex-shrink: 0;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  @media (prefers-reduced-motion: reduce) {
    .spinner { animation: none; }
    .chevron { transition: none; }
  }

  @media (max-width: 640px) {
    .stat-grid {
      grid-template-columns: 1fr;
    }
    .metric-grid {
      grid-template-columns: 1fr;
    }
    .kv {
      grid-template-columns: 1fr;
      gap: 4px;
    }
  }
</style>
