<script lang="ts">
  import { onMount } from 'svelte';
  import { getEmberDiagnostics, emberPingPeer, emberRequestSources } from '$lib/api/ember';
  import { getSettings } from '$lib/api/settings';
  import { translateError } from '$lib/i18n';
  import type { EmberDiagnostics, EmberPingResult } from '$lib/types';

  /**
   * Dev-only panel for the Ember-native transport. Shows live
   * diagnostic counters, the local Noise public key (with a
   * copy-to-clipboard helper), and a ping form whose pubkey field is
   * optional — when blank the backend looks the peer's pubkey up in
   * the cache populated by KAD source publishes.
   *
   * Reachable from the sidebar's "Ember Dev" entry. Production users
   * who land here see the same panel; if `ember_native_enabled` is
   * false they get a clear banner explaining what to flip.
   */

  let diag = $state<EmberDiagnostics | null>(null);
  let diagError = $state<string | null>(null);
  let refreshTimer: ReturnType<typeof setInterval> | null = null;
  let unmounted = false;
  let inFlightDiag = false;

  // Local UDP port read once on mount from `get_settings`. Surfaced
  // next to the ping form so the user can see at a glance which port
  // belongs to *this* node, and so the form can warn when they
  // accidentally type it as the peer port (the most common cause of
  // a "ping always times out" report — the packet loops back, lands
  // in `handle_transport` with no matching session, and is dropped).
  let localUdpPort = $state<number | null>(null);

  async function refreshLocalSettings() {
    try {
      const s = await getSettings();
      if (unmounted) return;
      localUdpPort = s.udp_port;
    } catch {
      // Non-fatal — the form still works, just without the port hint.
    }
  }

  async function refreshDiag() {
    if (unmounted || inFlightDiag) return;
    inFlightDiag = true;
    try {
      const d = await getEmberDiagnostics();
      if (unmounted) return;
      diag = d;
      diagError = null;
    } catch (e) {
      if (unmounted) return;
      diagError = translateError(e);
    } finally {
      inFlightDiag = false;
    }
  }

  // Ping form state.
  let formIp = $state('127.0.0.1');
  let formPort = $state<number | ''>(4772);
  let formPubkeyHex = $state('');
  let formTimeoutMs = $state<number | ''>(5000);
  let pinging = $state(false);
  let pingResult = $state<EmberPingResult | null>(null);

  async function submitPing(e: Event) {
    e.preventDefault();
    if (pinging) return;
    if (!formIp.trim()) return;
    if (formPort === '' || formPort <= 0) return;
    pinging = true;
    pingResult = null;
    try {
      const result = await emberPingPeer({
        peerIp: formIp.trim(),
        peerPort: Number(formPort),
        peerPubkeyHex: formPubkeyHex.trim() || undefined,
        timeoutMs: formTimeoutMs === '' ? undefined : Number(formTimeoutMs),
      });
      if (unmounted) return;
      pingResult = result;
    } catch (e) {
      if (unmounted) return;
      pingResult = {
        success: false,
        error: translateError(e),
      };
    } finally {
      if (!unmounted) {
        pinging = false;
        // Counter changes show up immediately on the next refresh tick.
        refreshDiag();
      }
    }
  }

  // "Request sources" reuses the ping form's IP / port / pubkey fields.
  let requesting = $state(false);
  let exchangeResult = $state<{ ok: boolean; message: string } | null>(null);

  async function submitExchangeRequest() {
    if (requesting) return;
    if (!formIp.trim()) return;
    if (formPort === '' || formPort <= 0) return;
    requesting = true;
    exchangeResult = null;
    try {
      await emberRequestSources({
        peerIp: formIp.trim(),
        peerPort: Number(formPort),
        peerPubkeyHex: formPubkeyHex.trim() || undefined,
      });
      if (unmounted) return;
      exchangeResult = {
        ok: true,
        message: 'Request sent — watch "Exchange data received" / "Mesh peers known" above.',
      };
    } catch (e) {
      if (unmounted) return;
      exchangeResult = { ok: false, message: translateError(e) };
    } finally {
      if (!unmounted) {
        requesting = false;
        refreshDiag();
      }
    }
  }

  let copyState = $state<'idle' | 'copied' | 'error'>('idle');
  let copyResetTimer: ReturnType<typeof setTimeout> | null = null;

  async function copyLocalPubkey() {
    if (!diag?.local_noise_public_key) return;
    try {
      await navigator.clipboard.writeText(diag.local_noise_public_key);
      copyState = 'copied';
    } catch {
      copyState = 'error';
    }
    if (copyResetTimer) clearTimeout(copyResetTimer);
    copyResetTimer = setTimeout(() => { copyState = 'idle'; }, 1500);
  }

  onMount(() => {
    refreshDiag();
    refreshLocalSettings();
    refreshTimer = setInterval(refreshDiag, 2000);
    return () => {
      unmounted = true;
      if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
      if (copyResetTimer) { clearTimeout(copyResetTimer); copyResetTimer = null; }
    };
  });

  let pingsSelf = $derived.by(() => {
    if (localUdpPort === null) return false;
    if (formPort === '' || formPort === null) return false;
    if (Number(formPort) !== localUdpPort) return false;
    // Only flag IPv4 / IPv6 loopback and the unspecified address —
    // pinging another machine on the same port is a perfectly normal
    // scenario (two harness nodes on different hosts using the same
    // default UDP port).
    const host = formIp.trim();
    return host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '0.0.0.0';
  });
</script>

<svelte:head><title>Ember Dev — Ember</title></svelte:head>

<div class="page">
  <header class="page-header">
    <div>
      <h1>Ember Dev</h1>
      <p class="subtitle">
        Live diagnostics for the Ember-native Noise transport. Use this
        page to verify the harness flow without devtools.
      </p>
    </div>
  </header>

  {#if diag && !diag.ember_native_enabled}
    <div class="banner banner-warn" role="status">
      <strong>Ember-native transport is disabled.</strong>
      Set <code>ember_native_enabled: true</code> in this node's
      <code>config.json</code> (or via <code>update_settings</code>)
      to enable the Ping/Pong path. The diagnostic counters below stay
      at zero until it's on.
    </div>
  {/if}

  {#if diagError}
    <div class="banner banner-error" role="alert">
      Failed to load diagnostics: {diagError}
    </div>
  {/if}

  <section class="card">
    <h2>Local identity</h2>
    {#if diag}
      <div class="kv">
        <div class="k">Noise public key</div>
        <div class="v pubkey-row">
          <code class="pubkey">{diag.local_noise_public_key || '—'}</code>
          {#if diag.local_noise_public_key}
            <button
              type="button"
              class="copy-btn"
              onclick={copyLocalPubkey}
              title="Copy to clipboard"
            >
              {#if copyState === 'copied'}Copied{:else if copyState === 'error'}Failed{:else}Copy{/if}
            </button>
          {/if}
        </div>
      </div>
      <p class="hint">
        Other Ember-native peers need this 32-byte X25519 key to dial us
        directly. KAD source publishes carry it automatically; copy
        here for the harness fast-path (paste into another node's
        ping form below).
      </p>
    {:else}
      <p class="hint muted">Loading…</p>
    {/if}
  </section>

  <section class="card">
    <h2>Counters</h2>
    {#if diag}
      <div class="counters">
        <div class="counter">
          <div class="counter-label">Active sessions</div>
          <div class="counter-value">{diag.ember_sessions}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Pings sent</div>
          <div class="counter-value">{diag.ember_pings_sent}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Pings received</div>
          <div class="counter-value">{diag.ember_pings_received}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Pongs received</div>
          <div class="counter-value">{diag.ember_pongs_received}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Exchange requests in</div>
          <div class="counter-value">{diag.ember_exchange_requests_received}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Exchange data sent</div>
          <div class="counter-value">{diag.ember_exchange_sent}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Exchange data received</div>
          <div class="counter-value">{diag.ember_exchange_received}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Mesh peers known</div>
          <div class="counter-value">{diag.ember_peers_known}</div>
        </div>
        <div class="counter">
          <div class="counter-label">EPX events</div>
          <div class="counter-value">{diag.epx_events_received}</div>
        </div>
        <div class="counter counter-wide">
          <div class="counter-label">Broker punch (success / attempts / failures)</div>
          <div class="counter-value">
            {diag.broker_punch_successes} / {diag.broker_punch_attempts} / {diag.broker_punch_failures}
          </div>
        </div>
        <div class="counter counter-wide">
          <div class="counter-label">Broker relay (success / attempts / failures)</div>
          <div class="counter-value">
            {diag.broker_relay_successes} / {diag.broker_relay_attempts} / {diag.broker_relay_failures}
          </div>
        </div>
        <div class="counter">
          <div class="counter-label">Broker active attempts</div>
          <div class="counter-value">{diag.broker_active_attempts}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Relay candidates</div>
          <div class="counter-value">{diag.broker_relay_candidates}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Oldest attempt age (s)</div>
          <div class="counter-value">{diag.broker_oldest_attempt_age_secs}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Relay sessions (bridging)</div>
          <div class="counter-value">{diag.relay_sessions_active}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Relay bytes served</div>
          <div class="counter-value">{diag.relay_bytes_relayed}</div>
        </div>
      </div>
      <p class="hint muted">Auto-refreshes every 2s.</p>
    {:else}
      <p class="hint muted">Loading…</p>
    {/if}
  </section>

  <section class="card">
    <h2>Ping a peer</h2>
    {#if localUdpPort !== null}
      <p class="hint">
        This node's UDP port is <code>{localUdpPort}</code>. Use the
        <em>other</em> node's UDP port below — pinging your own port
        loops the packet back to this process and silently times out.
      </p>
    {/if}
    {#if pingsSelf}
      <div class="banner banner-warn" role="alert">
        <strong>Heads up:</strong> the form is pointing at this node's own
        UDP port (<code>{localUdpPort}</code>) on a loopback address.
        The packet will return to this process, find no matching
        session, and get dropped. Set the port to the <em>other</em>
        node's UDP port (e.g. <code>4672</code> for node A,
        <code>4772</code> for node B).
      </div>
    {/if}
    <form onsubmit={submitPing} class="ping-form">
      <label>
        <span>Peer IP</span>
        <input
          type="text"
          bind:value={formIp}
          placeholder="127.0.0.1"
          required
          autocomplete="off"
        />
      </label>
      <label>
        <span>Peer UDP port</span>
        <input
          type="number"
          bind:value={formPort}
          min="1"
          max="65535"
          required
        />
      </label>
      <label class="full">
        <span>
          Peer Noise pubkey (hex)
          <span class="optional">— optional, leave blank to use the KAD-fed cache</span>
        </span>
        <input
          type="text"
          bind:value={formPubkeyHex}
          placeholder="64 hex chars, or leave blank"
          autocomplete="off"
          spellcheck="false"
        />
      </label>
      <label>
        <span>Timeout (ms)</span>
        <input
          type="number"
          bind:value={formTimeoutMs}
          min="100"
          max="60000"
          step="100"
        />
      </label>
      <div class="form-actions">
        <button
          type="button"
          class="secondary"
          onclick={submitExchangeRequest}
          disabled={requesting || !formIp || formPort === ''}
          title="Send an Ember ExchangeRequest; the peer replies with its EPX source/peer payload"
        >
          {requesting ? 'Requesting…' : 'Request Sources'}
        </button>
        <button type="submit" disabled={pinging || !formIp || formPort === ''}>
          {pinging ? 'Pinging…' : 'Send Ping'}
        </button>
      </div>
    </form>

    {#if pingResult}
      <div class="result {pingResult.success ? 'result-ok' : 'result-fail'}">
        {#if pingResult.success}
          <strong>OK</strong>
          {#if pingResult.rtt_ms !== undefined && pingResult.rtt_ms !== null && Number.isFinite(pingResult.rtt_ms)}
            <span class="rtt">{pingResult.rtt_ms.toFixed(2)} ms</span>
          {/if}
        {:else}
          <strong>Failed</strong>
          <span class="err">{pingResult.error ?? 'Unknown error'}</span>
        {/if}
      </div>
    {/if}

    {#if exchangeResult}
      <div class="result {exchangeResult.ok ? 'result-ok' : 'result-fail'}">
        <strong>{exchangeResult.ok ? 'Exchange' : 'Failed'}</strong>
        <span class="err">{exchangeResult.message}</span>
      </div>
    {/if}
  </section>
</div>

<style>
  .page {
    padding: 24px;
    max-width: 980px;
    margin: 0 auto;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }
  .page-header h1 {
    margin: 0;
    font-size: 22px;
  }
  .subtitle {
    margin: 4px 0 0;
    color: var(--text-muted);
    font-size: 13px;
    max-width: 720px;
  }

  .banner {
    border-radius: var(--radius-md, 6px);
    padding: 12px 14px;
    font-size: 13px;
    line-height: 1.4;
    border: 1px solid transparent;
  }
  .banner code {
    font-size: 12px;
    background: var(--bg-tertiary);
    padding: 1px 5px;
    border-radius: 3px;
  }
  .banner-warn {
    background: color-mix(in srgb, var(--warning) 15%, transparent);
    border-color: color-mix(in srgb, var(--warning) 35%, transparent);
    color: var(--text-primary);
  }
  .banner-error {
    background: color-mix(in srgb, #e06a5f 15%, transparent);
    border-color: color-mix(in srgb, #e06a5f 35%, transparent);
    color: var(--text-primary);
  }

  .card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-md, 8px);
    padding: 16px 18px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .card h2 {
    margin: 0;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    font-weight: 600;
  }

  .kv { display: grid; grid-template-columns: 160px 1fr; gap: 8px 16px; align-items: center; }
  .k { color: var(--text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
  .v { color: var(--text-primary); font-size: 13px; }
  .pubkey-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .pubkey {
    font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace);
    font-size: 12px;
    background: var(--bg-tertiary);
    padding: 4px 8px;
    border-radius: 4px;
    word-break: break-all;
  }

  .hint { margin: 0; font-size: 12px; color: var(--text-secondary); }
  .hint.muted { color: var(--text-muted); }

  .copy-btn {
    border: 1px solid var(--border);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 12px;
    cursor: pointer;
  }
  .copy-btn:hover { background: var(--bg-hover); }

  .counters {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
  }
  .counter {
    background: var(--bg-tertiary);
    border-radius: var(--radius-md, 6px);
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .counter-wide { grid-column: span 2; }
  .counter-label { color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; }
  .counter-value {
    color: var(--accent);
    font-size: 18px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
  }

  .ping-form {
    display: grid;
    grid-template-columns: 1fr 160px;
    gap: 12px 16px;
  }
  .ping-form label {
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-size: 12px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.6px;
  }
  .ping-form label .optional {
    text-transform: none;
    letter-spacing: 0;
    color: var(--text-muted);
    font-weight: normal;
  }
  .ping-form label.full { grid-column: 1 / -1; }
  .ping-form input {
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 10px;
    color: var(--text-primary);
    font-size: 13px;
    font-family: inherit;
  }
  .ping-form input:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
  .form-actions { grid-column: 1 / -1; display: flex; justify-content: flex-end; gap: 10px; }
  .form-actions button {
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 4px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
  }
  .form-actions button.secondary {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
  }
  .form-actions button.secondary:hover:not(:disabled) { background: var(--bg-hover); }
  .form-actions button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .result {
    margin-top: 4px;
    padding: 10px 12px;
    border-radius: var(--radius-md, 6px);
    font-size: 13px;
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  .result-ok {
    background: color-mix(in srgb, #3ccf6d 18%, transparent);
    border: 1px solid color-mix(in srgb, #3ccf6d 35%, transparent);
  }
  .result-fail {
    background: color-mix(in srgb, #e06a5f 15%, transparent);
    border: 1px solid color-mix(in srgb, #e06a5f 35%, transparent);
  }
  .rtt {
    font-family: var(--font-mono, ui-monospace, monospace);
    font-size: 13px;
    color: var(--text-primary);
  }
  .err { color: var(--text-primary); }
</style>
