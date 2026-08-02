<script lang="ts">
  /*
   * User-facing "Ember Network" page: a single power switch for the
   * Ember-native overlay plus an at-a-glance status read-out (routing
   * contacts, in-flight searches, local store). The toggle persists through
   * `update_settings` and the backend applies it live, though a node that
   * starts with an empty routing table only fills it once the maintenance
   * tick runs the KAD bridge — there is no central pool to fetch from.
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

  // Diagnostics-health + join-progress state. `diagStale` raises a banner
  // once polling has failed several times in a row (the service is down,
  // not just a transient blip), so the numbers below aren't silently
  // mistaken for live ones. The join timer flips `joinTimedOut` so the
  // "joining…" spinner can't spin forever when no peers are reachable.
  let diagStale = $state(false);
  let joinTimedOut = $state(false);
  let diagFailures = 0;
  let activeSince: number | null = null;
  let joinTimer: ReturnType<typeof setTimeout> | null = null;
  const DIAG_FAILURE_THRESHOLD = 3;
  const JOINING_TIMEOUT_MS = 30_000;

  async function refreshDiag() {
    if (unmounted || inFlightDiag) return;
    inFlightDiag = true;
    try {
      diag = await getEmberDiagnostics();
      if (diag.ember_native_enabled) {
        const [c, s, st] = await Promise.all([
          getEmberDhtContacts().catch(() => contacts),
          getEmberDhtSearches().catch(() => searches),
          getEmberDhtStore().catch(() => storeEntries),
        ]);
        if (!unmounted) {
          contacts = c;
          searches = s;
          storeEntries = st;
        }
      } else if (!unmounted) {
        contacts = [];
        searches = [];
        storeEntries = [];
      }
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
  let joining = $derived(isActive && (diag?.ember_dht_contacts ?? 0) === 0 && !joinTimedOut);

  onMount(() => {
    getSettings()
      .then((s) => {
        settings = s;
        enabled = s.ember_native_enabled;
        lastAppliedEnabled = s.ember_native_enabled;
      })
      .catch((e) => { loadError = m.ember_load_failed({ error: translateError(e) }); });
    refreshDiag();
    pollTimer = setInterval(refreshDiag, 2500);
    return () => {
      unmounted = true;
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
      <span class="status-dot" class:on={isActive}></span>
      <div class="hero-text">
        <div class="status-label">
          {isActive ? m.ember_status_active() : m.ember_status_disabled()}
        </div>
        <p class="hint">{m.ember_enable_hint()}</p>
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

  {#if !isActive}
    <div class="banner banner-muted" role="status">{m.ember_disabled_explainer()}</div>
  {:else if joining}
    <div class="banner banner-info" role="status">
      <span class="spinner" aria-hidden="true"></span>
      {m.ember_joining_hint()}
    </div>
  {:else if (diag?.ember_dht_contacts ?? 0) === 0}
    <div class="banner banner-muted" role="status">{m.ember_no_contacts_hint()}</div>
  {/if}

  {#if isActive && diag?.ember_dht_udp_unreachable}
    <div class="banner banner-info" role="status">{m.ember_dht_udp_unreachable_hint()}</div>
  {:else if isActive && diag?.ember_dht_firewalled_publishing}
    <div class="banner banner-muted" role="status">{m.ember_dht_firewalled_publishing_hint()}</div>
  {/if}

  <!-- Live stats -->
  <section class="stat-grid" class:dimmed={!isActive}>
    <div class="stat">
      <div class="stat-value">{diag?.ember_dht_contacts ?? 0}</div>
      <div class="stat-label">{m.ember_stat_contacts()}</div>
    </div>
    <div class="stat">
      <div class="stat-value">{diag?.ember_sessions ?? 0}</div>
      <div class="stat-label">{m.ember_stat_sessions()}</div>
    </div>
    <div class="stat">
      <div class="stat-value">{diag?.ember_peers_known ?? 0}</div>
      <div class="stat-label">{m.ember_stat_peers()}</div>
    </div>
    <div class="stat">
      <div class="stat-value">{diag?.ember_dht_stored_records ?? 0}</div>
      <div class="stat-label">{m.ember_stat_records()}</div>
    </div>
  </section>

  {#if isActive}
    <section class="stat-grid secondary" class:dimmed={!isActive}>
      <div class="stat">
        <div class="stat-value">{diag?.ember_dht_search_hits ?? 0}/{diag?.ember_dht_search_misses ?? 0}</div>
        <div class="stat-label">{m.ember_stat_search_hit_miss()}</div>
      </div>
      <div class="stat">
        <div class="stat-value">{diag?.ember_dht_stores_acked ?? 0}/{diag?.ember_dht_stores_failed ?? 0}</div>
        <div class="stat-label">{m.ember_stat_store_ack_fail()}</div>
      </div>
      <div class="stat">
        <div class="stat-value">{diag?.ember_dht_avg_replication ?? 0}</div>
        <div class="stat-label">{m.ember_stat_avg_replication()}</div>
      </div>
      <div class="stat">
        <div class="stat-value">{diag?.ember_dht_active_searches ?? 0}</div>
        <div class="stat-label">{m.ember_stat_active_searches()}</div>
      </div>
    </section>

    <div class="dht-layout">
      <section class="card dht-panel">
        <div class="panel-head">
          <h2>{m.ember_dht_contacts_title()}</h2>
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

      <section class="card dht-panel">
        <h2>{m.ember_dht_status_title()}</h2>
        <div class="kv compact">
          <div class="k">{m.ember_stat_stored_keys()}</div>
          <div class="v">{diag?.ember_dht_stored_keys ?? 0}</div>
        </div>
        <div class="kv compact">
          <div class="k">{m.ember_stat_active_publishes()}</div>
          <div class="v">{diag?.ember_dht_active_publishes ?? 0}</div>
        </div>
        <div class="kv compact">
          <div class="k">{m.ember_stat_search_rounds()}</div>
          <div class="v">{diag?.ember_dht_search_rounds ?? 0}</div>
        </div>
        <div class="kv compact">
          <div class="k">{m.ember_stat_find_values_sent()}</div>
          <div class="v">{diag?.ember_dht_find_values_sent ?? 0}</div>
        </div>
        <div class="kv compact">
          <div class="k">{m.ember_stat_serve_hit_miss()}</div>
          <div class="v">{diag?.ember_dht_find_value_hits ?? 0}/{diag?.ember_dht_find_value_misses ?? 0}</div>
        </div>
        <div class="kv compact">
          <div class="k">{m.ember_stat_buddy_pub_fwd()}</div>
          <div class="v">{diag?.ember_dht_buddy_publishes ?? 0}/{diag?.ember_dht_buddy_forwards ?? 0}</div>
        </div>
        <div class="kv compact">
          <div class="k">{m.ember_stat_malformed()}</div>
          <div class="v">{diag?.ember_dht_malformed ?? 0}</div>
        </div>
        <div class="kv compact">
          <div class="k">{m.ember_stat_observed_votes()}</div>
          <div class="v">{diag?.ember_dht_observed_votes ?? 0}</div>
        </div>
        <div class="kv compact">
          <div class="k">{m.ember_stat_observed_addr()}</div>
          <div class="v"><code>{diag?.ember_dht_observed_addr || '—'}</code></div>
        </div>
      </section>
    </div>

    <section class="card">
      <h2>{m.ember_dht_searches_title()}</h2>
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

    <section class="card">
      <h2>{m.ember_dht_store_title()}</h2>
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

  <!-- Local identity -->
  <section class="card">
    <h2>{m.ember_identity_title()}</h2>
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

  <!-- About -->
  <section class="card">
    <h2>{m.ember_about_title()}</h2>
    <p class="about-text">{m.ember_about_text()}</p>
  </section>
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
    max-width: 1100px;
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
  }

  .hero-text .hint {
    margin: 2px 0 0;
  }

  .hint {
    color: var(--text-muted);
    font-size: 13px;
    line-height: 1.5;
  }

  .stat-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    transition: opacity 0.2s ease;
  }

  .stat-grid.dimmed {
    opacity: 0.5;
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

  .stat-grid.secondary .stat-value {
    font-size: 18px;
  }

  .dht-layout {
    display: grid;
    grid-template-columns: 1.6fr 1fr;
    gap: 16px;
  }

  .dht-panel {
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }

  .panel-head h2 {
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

  .kv.compact {
    margin: 0;
    padding: 4px 0;
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

  .banner-info {
    background: color-mix(in srgb, var(--accent) 10%, transparent);
    border: 1px solid color-mix(in srgb, var(--accent) 30%, transparent);
    color: var(--text-secondary);
  }

  .banner-muted {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    color: var(--text-muted);
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
  }

  @media (max-width: 640px) {
    .stat-grid {
      grid-template-columns: repeat(2, 1fr);
    }
    .dht-layout {
      grid-template-columns: 1fr;
    }
    .kv {
      grid-template-columns: 1fr;
      gap: 4px;
    }
  }
</style>
