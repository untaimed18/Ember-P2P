<script lang="ts">
  /*
   * User-facing "Ember Network" page. Unlike the developer panel at
   * `/dev/ember` (routing-table inspection, manual seeding, DHT
   * ping/find/publish harness forms), this page is the everyday surface:
   * a single power switch for the Ember-native overlay plus an at-a-glance
   * status read-out. The toggle persists through `update_settings` and the
   * backend applies it live — turning it on kicks a rendezvous bootstrap so
   * the node joins the DHT without a restart.
   */
  import { onMount, untrack } from 'svelte';
  import { goto } from '$app/navigation';
  import { getSettings, updateSettings } from '$lib/api/settings';
  import { getEmberDiagnostics } from '$lib/api/ember';
  import type { AppSettings, EmberDiagnostics } from '$lib/types';
  import { translateError } from '$lib/i18n';
  import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
  import * as m from '$lib/paraglide/messages';

  let settings = $state<AppSettings | null>(null);
  let diag = $state<EmberDiagnostics | null>(null);
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

  async function refreshDiag() {
    if (unmounted || inFlightDiag) return;
    inFlightDiag = true;
    try {
      diag = await getEmberDiagnostics();
    } catch {
      // Non-fatal — keep the previous snapshot; the toggle still works.
    } finally {
      inFlightDiag = false;
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
  let joining = $derived(isActive && (diag?.ember_dht_contacts ?? 0) === 0);

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
    };
  });
</script>

<svelte:head><title>{m.nav_ember_network()} — Ember</title></svelte:head>

<div class="page">
  <header class="page-header">
    <div>
      <h1>
        {m.nav_ember_network()}
        <span class="badge-experimental">{m.ember_experimental()}</span>
      </h1>
      <p class="subtitle">{m.ember_page_subtitle()}</p>
    </div>
  </header>

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

  {#if !isActive}
    <div class="banner banner-muted" role="status">{m.ember_disabled_explainer()}</div>
  {:else if joining}
    <div class="banner banner-info" role="status">
      <span class="spinner" aria-hidden="true"></span>
      {m.ember_joining_hint()}
    </div>
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

  {#if isActive && !joining && (diag?.ember_dht_contacts ?? 0) === 0}
    <p class="hint muted soft-note">{m.ember_no_contacts_hint()}</p>
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

  <!-- Advanced -->
  <section class="card advanced">
    <div>
      <h2>{m.ember_advanced_title()}</h2>
      <p class="hint">{m.ember_advanced_desc()}</p>
    </div>
    <button type="button" class="ghost-btn" onclick={() => goto('/dev/ember')}>
      {m.ember_advanced_link()}
    </button>
  </section>
</div>

<style>
  .page {
    padding: 24px;
    max-width: 880px;
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

  .hint.muted {
    opacity: 0.85;
  }

  .soft-note {
    margin: -4px 2px 0;
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

  .copy-btn,
  .ghost-btn {
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

  .copy-btn:hover,
  .ghost-btn:hover {
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

  .advanced {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  .advanced .ghost-btn {
    padding: 8px 14px;
    font-size: 13px;
    white-space: nowrap;
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
    .kv {
      grid-template-columns: 1fr;
      gap: 4px;
    }
  }
</style>
