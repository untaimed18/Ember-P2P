<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getEmberDiagnostics,
    emberPingPeer,
    emberRequestSources,
    getEmberDhtContacts,
    addEmberDhtContact,
    emberDhtPingPeer,
    emberDhtFindNode,
    emberDhtIterativeFindNode,
    emberDhtPublishKeyword,
    emberDhtFindValue,
    emberDhtRunMaintenance,
  } from '$lib/api/ember';
  import { getSettings } from '$lib/api/settings';
  import { translateError } from '$lib/i18n';
  import type {
    EmberDiagnostics,
    EmberDhtContact,
    EmberDhtFindResult,
    EmberDhtFindValueResult,
    EmberDhtMaintenanceResult,
    EmberDhtPublishResult,
    EmberPingResult,
  } from '$lib/types';

  /**
   * Dev-only panel for the Ember-native transport. Shows live
   * diagnostic counters, the local Noise public key (with a
   * copy-to-clipboard helper), and a ping form whose pubkey field is
   * optional — when blank the backend looks the peer's pubkey up in
   * the cache populated by KAD source publishes.
   *
   * Reachable from the sidebar's "Ember Dev" entry in development. In a
   * production build the panel is replaced by a short notice (see `isDev`
   * below) so the diagnostics tooling and local Noise key are not exposed.
   */

  // Dev diagnostics ship in the bundle but must not be reachable as live
  // tooling in production: `import.meta.env.DEV` is statically `false` in a
  // release build, so the panel below renders a notice instead and `onMount`
  // skips all backend polling / settings reads.
  const isDev = import.meta.env.DEV;

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

  let dhtContacts = $state<EmberDhtContact[]>([]);

  async function refreshDhtContacts() {
    try {
      dhtContacts = await getEmberDhtContacts();
    } catch {
      // Non-fatal — keep the previous snapshot.
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

  // Keyed copy indicator so each copyable value (Noise key, Ed25519
  // key) shows its own "Copied" feedback.
  let copiedKey = $state<string | null>(null);

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

  let copyResetTimer: ReturnType<typeof setTimeout> | null = null;

  async function copyText(value: string, key: string) {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      copiedKey = key;
    } catch {
      copiedKey = `${key}:error`;
    }
    if (copyResetTimer) clearTimeout(copyResetTimer);
    copyResetTimer = setTimeout(() => { copiedKey = null; }, 1500);
  }

  // Seed-contact form.
  let addIp = $state('127.0.0.1');
  let addPort = $state<number | ''>(4772);
  let addEd25519 = $state('');
  let addNoise = $state('');
  let adding = $state(false);
  let addResult = $state<{ ok: boolean; message: string } | null>(null);

  async function submitAddContact(e: Event) {
    e.preventDefault();
    if (adding) return;
    if (!addIp.trim() || addPort === '' || addPort <= 0) return;
    adding = true;
    addResult = null;
    try {
      await addEmberDhtContact({
        peerIp: addIp.trim(),
        peerPort: Number(addPort),
        ed25519PubkeyHex: addEd25519.trim(),
        noisePubkeyHex: addNoise.trim(),
      });
      addResult = { ok: true, message: 'Contact added to the routing table.' };
      refreshDiag();
      refreshDhtContacts();
    } catch (err) {
      addResult = { ok: false, message: translateError(err) };
    } finally {
      adding = false;
    }
  }

  // DHT ping form (distinct from the control ping above).
  let dhtIp = $state('127.0.0.1');
  let dhtPort = $state<number | ''>(4772);
  let dhtPubkeyHex = $state('');
  let dhtTimeoutMs = $state<number | ''>(5000);
  let dhtPinging = $state(false);
  let dhtPingResult = $state<EmberPingResult | null>(null);

  async function submitDhtPing(e: Event) {
    e.preventDefault();
    if (dhtPinging) return;
    if (!dhtIp.trim()) return;
    if (dhtPort === '' || dhtPort <= 0) return;
    dhtPinging = true;
    dhtPingResult = null;
    try {
      dhtPingResult = await emberDhtPingPeer({
        peerIp: dhtIp.trim(),
        peerPort: Number(dhtPort),
        peerPubkeyHex: dhtPubkeyHex.trim() || undefined,
        timeoutMs: dhtTimeoutMs === '' ? undefined : Number(dhtTimeoutMs),
      });
    } catch (err) {
      dhtPingResult = { success: false, error: translateError(err) };
    } finally {
      dhtPinging = false;
      refreshDiag();
      refreshDhtContacts();
    }
  }

  // DHT find-node form (single hop): ask one peer for its k closest
  // contacts to a target ID. Blank target ⇒ the backend picks a random
  // one, so the operator just sees "what does this peer know".
  let findIp = $state('127.0.0.1');
  let findPort = $state<number | ''>(4772);
  let findTargetHex = $state('');
  let findPubkeyHex = $state('');
  let findTimeoutMs = $state<number | ''>(5000);
  let finding = $state(false);
  let findResult = $state<EmberDhtFindResult | null>(null);

  async function submitFindNode(e: Event) {
    e.preventDefault();
    if (finding) return;
    if (!findIp.trim()) return;
    if (findPort === '' || findPort <= 0) return;
    finding = true;
    findResult = null;
    try {
      findResult = await emberDhtFindNode({
        peerIp: findIp.trim(),
        peerPort: Number(findPort),
        targetHex: findTargetHex.trim() || undefined,
        peerPubkeyHex: findPubkeyHex.trim() || undefined,
        timeoutMs: findTimeoutMs === '' ? undefined : Number(findTimeoutMs),
      });
    } catch (err) {
      findResult = { success: false, contacts: [], error: translateError(err) };
    } finally {
      finding = false;
      // A FIND_NODE seeds our table with the returned contacts (and the
      // responder), so refresh both views.
      refreshDiag();
      refreshDhtContacts();
    }
  }

  // Iterative (multi-hop) lookup form. No peer address — it seeds from
  // the local routing table and walks the network.
  let lookupTargetHex = $state('');
  let lookupTimeoutMs = $state<number | ''>(30000);
  let lookingUp = $state(false);
  let lookupResult = $state<EmberDhtFindResult | null>(null);

  async function submitLookup(e: Event) {
    e.preventDefault();
    if (lookingUp) return;
    lookingUp = true;
    lookupResult = null;
    try {
      lookupResult = await emberDhtIterativeFindNode({
        targetHex: lookupTargetHex.trim() || undefined,
        timeoutMs: lookupTimeoutMs === '' ? undefined : Number(lookupTimeoutMs),
      });
    } catch (err) {
      lookupResult = { success: false, contacts: [], error: translateError(err) };
    } finally {
      lookingUp = false;
      // The lookup populates our routing table along the way.
      refreshDiag();
      refreshDhtContacts();
    }
  }

  // Publish a signed keyword record onto the closest nodes we know.
  let publishKeyword = $state('');
  let publishFileName = $state('');
  let publishFileSize = $state<number | ''>(0);
  let publishFileHashHex = $state('');
  let publishTimeoutMs = $state<number | ''>(30000);
  let publishing = $state(false);
  let publishResult = $state<EmberDhtPublishResult | null>(null);

  async function submitPublish(e: Event) {
    e.preventDefault();
    if (publishing) return;
    publishing = true;
    publishResult = null;
    try {
      publishResult = await emberDhtPublishKeyword({
        keyword: publishKeyword.trim(),
        fileName: publishFileName.trim(),
        fileSize: publishFileSize === '' ? 0 : Number(publishFileSize),
        fileHashHex: publishFileHashHex.trim() || undefined,
        timeoutMs: publishTimeoutMs === '' ? undefined : Number(publishTimeoutMs),
      });
    } catch (err) {
      publishResult = { success: false, key: '', stored_on: 0, targets: 0, error: translateError(err) };
    } finally {
      publishing = false;
      refreshDiag();
    }
  }

  // Iterative FIND_VALUE for a keyword — returns the verified records.
  let findValueKeyword = $state('');
  let findValueTimeoutMs = $state<number | ''>(30000);
  let findingValue = $state(false);
  let findValueResult = $state<EmberDhtFindValueResult | null>(null);

  async function submitFindValue(e: Event) {
    e.preventDefault();
    if (findingValue) return;
    findingValue = true;
    findValueResult = null;
    try {
      findValueResult = await emberDhtFindValue({
        keyword: findValueKeyword.trim(),
        timeoutMs: findValueTimeoutMs === '' ? undefined : Number(findValueTimeoutMs),
      });
    } catch (err) {
      findValueResult = { success: false, records: [], error: translateError(err) };
    } finally {
      findingValue = false;
      refreshDiag();
      refreshDhtContacts();
    }
  }

  // Force one DHT maintenance cycle (slice 6): refresh stale buckets,
  // liveness-ping stale contacts, republish stored records.
  let runningMaintenance = $state(false);
  let maintenanceResult = $state<EmberDhtMaintenanceResult | null>(null);

  async function runMaintenance() {
    if (runningMaintenance) return;
    runningMaintenance = true;
    maintenanceResult = null;
    try {
      maintenanceResult = await emberDhtRunMaintenance();
    } catch (err) {
      maintenanceResult = {
        success: false,
        buckets_refreshed: 0,
        liveness_pings_sent: 0,
        records_republished: 0,
        kad_bridge_pings_sent: 0,
        error: translateError(err),
      };
    } finally {
      runningMaintenance = false;
      refreshDiag();
      refreshDhtContacts();
    }
  }

  onMount(() => {
    if (!isDev) return;
    refreshDiag();
    refreshDhtContacts();
    refreshLocalSettings();
    refreshTimer = setInterval(() => { refreshDiag(); refreshDhtContacts(); }, 2000);
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

{#if !isDev}
  <header class="page-header">
    <div><h1>Ember Dev</h1></div>
  </header>
  <div class="page-content">
    <div class="dev-inner">
      <p class="subtitle">This diagnostics page is only available in development builds.</p>
    </div>
  </div>
{:else}
<header class="page-header">
  <div>
    <h1>Ember Dev</h1>
    <p class="subtitle">
      Live diagnostics for the Ember-native Noise transport. Use this
      page to verify the harness flow without devtools.
    </p>
  </div>
</header>

<div class="page-content">
  <div class="dev-inner">
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
              onclick={() => copyText(diag?.local_noise_public_key ?? '', 'noise')}
              title="Copy to clipboard"
            >
              {#if copiedKey === 'noise'}Copied{:else if copiedKey === 'noise:error'}Failed{:else}Copy{/if}
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
    <h2>Ember DHT</h2>
    {#if diag}
      <div class="kv">
        <div class="k">Node ID</div>
        <div class="v"><code class="pubkey">{diag.ember_dht_node_id || '—'}</code></div>
        <div class="k">Ed25519 key</div>
        <div class="v pubkey-row">
          <code class="pubkey">{diag.local_ed25519_public_key || '—'}</code>
          {#if diag.local_ed25519_public_key}
            <button
              type="button"
              class="copy-btn"
              onclick={() => copyText(diag?.local_ed25519_public_key ?? '', 'ed')}
              title="Copy to clipboard"
            >
              {#if copiedKey === 'ed'}Copied{:else if copiedKey === 'ed:error'}Failed{:else}Copy{/if}
            </button>
          {/if}
        </div>
      </div>
      <div class="counters">
        <div class="counter">
          <div class="counter-label">Routing contacts</div>
          <div class="counter-value">{diag.ember_dht_contacts}</div>
        </div>
        <div class="counter">
          <div class="counter-label">DHT pings sent</div>
          <div class="counter-value">{diag.ember_dht_pings_sent}</div>
        </div>
        <div class="counter">
          <div class="counter-label">DHT pings received</div>
          <div class="counter-value">{diag.ember_dht_pings_received}</div>
        </div>
        <div class="counter">
          <div class="counter-label">DHT pongs received</div>
          <div class="counter-value">{diag.ember_dht_pongs_received}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Find-node sent</div>
          <div class="counter-value">{diag.ember_dht_find_nodes_sent}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Find-node received</div>
          <div class="counter-value">{diag.ember_dht_find_nodes_received}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Active lookups</div>
          <div class="counter-value">{diag.ember_dht_active_searches}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Stored records</div>
          <div class="counter-value">{diag.ember_dht_stored_records}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Stored keys</div>
          <div class="counter-value">{diag.ember_dht_stored_keys}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Stores received</div>
          <div class="counter-value">{diag.ember_dht_stores_received}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Find-value received</div>
          <div class="counter-value">{diag.ember_dht_find_values_received}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Active publishes</div>
          <div class="counter-value">{diag.ember_dht_active_publishes}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Bucket refreshes</div>
          <div class="counter-value">{diag.ember_dht_refreshes}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Liveness pings sent</div>
          <div class="counter-value">{diag.ember_dht_liveness_pings_sent}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Contacts evicted</div>
          <div class="counter-value">{diag.ember_dht_contacts_evicted}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Records republished</div>
          <div class="counter-value">{diag.ember_dht_records_republished}</div>
        </div>
        <div class="counter">
          <div class="counter-label">KAD-bridge pings</div>
          <div class="counter-value">{diag.ember_dht_kad_bridge_pings}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Sources published</div>
          <div class="counter-value">{diag.ember_dht_sources_published}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Source searches</div>
          <div class="counter-value">{diag.ember_dht_source_searches}</div>
        </div>
        <div class="counter">
          <div class="counter-label">Source records found</div>
          <div class="counter-value">{diag.ember_dht_source_records_found}</div>
        </div>
      </div>

      <div class="maint-row">
        <button class="maint-btn" onclick={runMaintenance} disabled={runningMaintenance}>
          {runningMaintenance ? 'Running…' : 'Run maintenance'}
        </button>
        <span class="hint muted">
          Forces one cycle: refresh stale buckets, liveness-ping stale
          contacts, republish stored records. Runs automatically every 60 s.
        </span>
      </div>
      {#if maintenanceResult}
        {#if maintenanceResult.success}
          <div class="result result-ok">
            <strong>OK</strong>
            <span class="rtt">
              {maintenanceResult.buckets_refreshed} bucket{maintenanceResult.buckets_refreshed === 1 ? '' : 's'} refreshed,
              {maintenanceResult.liveness_pings_sent} ping{maintenanceResult.liveness_pings_sent === 1 ? '' : 's'} sent,
              {maintenanceResult.records_republished} record{maintenanceResult.records_republished === 1 ? '' : 's'} republished,
              {maintenanceResult.kad_bridge_pings_sent} KAD-bridge ping{maintenanceResult.kad_bridge_pings_sent === 1 ? '' : 's'}
            </span>
          </div>
        {:else}
          <div class="result result-fail">
            <strong>Failed</strong>
            <span class="err">{maintenanceResult.error ?? 'Unknown error'}</span>
          </div>
        {/if}
      {/if}

      <h3 class="subhead">Routing table ({dhtContacts.length})</h3>
      {#if dhtContacts.length === 0}
        <p class="hint muted">
          No contacts yet. Seed one below, or DHT-ping a peer — a
          successful round trip adds both ends automatically.
        </p>
      {:else}
        <div class="contacts">
          <table>
            <thead>
              <tr><th>Node ID</th><th>Address</th><th>Last seen</th><th>Fails</th></tr>
            </thead>
            <tbody>
              {#each dhtContacts as c (c.node_id)}
                <tr>
                  <td><code>{c.node_id.slice(0, 16)}…</code></td>
                  <td>{c.addr}</td>
                  <td>{c.last_seen > 0 ? new Date(c.last_seen * 1000).toLocaleTimeString() : '—'}</td>
                  <td>{c.failed_queries}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {:else}
      <p class="hint muted">Loading…</p>
    {/if}
  </section>

  <div class="forms-grid">
  <section class="card">
    <h2>Seed a DHT contact</h2>
    <p class="hint">
      Paste the other node's address and the two keys from its
      <em>Local identity</em> and <em>Ember DHT</em> cards. The node ID
      is derived from the Ed25519 key.
    </p>
    <form onsubmit={submitAddContact} class="ping-form">
      <label>
        <span>Peer IP</span>
        <input type="text" bind:value={addIp} placeholder="127.0.0.1" required autocomplete="off" />
      </label>
      <label>
        <span>Peer UDP port</span>
        <input type="number" bind:value={addPort} min="1" max="65535" required />
      </label>
      <label class="full">
        <span>Ed25519 pubkey (hex)</span>
        <input type="text" bind:value={addEd25519} placeholder="64 hex chars" autocomplete="off" spellcheck="false" required />
      </label>
      <label class="full">
        <span>Noise pubkey (hex)</span>
        <input type="text" bind:value={addNoise} placeholder="64 hex chars" autocomplete="off" spellcheck="false" required />
      </label>
      <div class="form-actions">
        <button type="submit" disabled={adding || !addIp || addPort === ''}>
          {adding ? 'Adding…' : 'Add contact'}
        </button>
      </div>
    </form>
    {#if addResult}
      <div class="result {addResult.ok ? 'result-ok' : 'result-fail'}">
        <strong>{addResult.ok ? 'OK' : 'Failed'}</strong>
        <span class="err">{addResult.message}</span>
      </div>
    {/if}
  </section>

  <section class="card">
    <h2>DHT ping a peer</h2>
    <p class="hint">
      Sends a signed DHT <code>PING</code> over the Noise transport.
      Unlike the control ping below, a successful round trip <em>also</em>
      seeds both nodes' routing tables. The pubkey is the peer's Noise
      key; leave blank to use the KAD-fed cache.
    </p>
    <form onsubmit={submitDhtPing} class="ping-form">
      <label>
        <span>Peer IP</span>
        <input type="text" bind:value={dhtIp} placeholder="127.0.0.1" required autocomplete="off" />
      </label>
      <label>
        <span>Peer UDP port</span>
        <input type="number" bind:value={dhtPort} min="1" max="65535" required />
      </label>
      <label class="full">
        <span>Peer Noise pubkey (hex) <span class="optional">— optional</span></span>
        <input type="text" bind:value={dhtPubkeyHex} placeholder="64 hex chars, or leave blank" autocomplete="off" spellcheck="false" />
      </label>
      <label>
        <span>Timeout (ms)</span>
        <input type="number" bind:value={dhtTimeoutMs} min="100" max="60000" step="100" />
      </label>
      <div class="form-actions">
        <button type="submit" disabled={dhtPinging || !dhtIp || dhtPort === ''}>
          {dhtPinging ? 'Pinging…' : 'Send DHT Ping'}
        </button>
      </div>
    </form>
    {#if dhtPingResult}
      <div class="result {dhtPingResult.success ? 'result-ok' : 'result-fail'}">
        {#if dhtPingResult.success}
          <strong>OK</strong>
          {#if dhtPingResult.rtt_ms !== undefined && dhtPingResult.rtt_ms !== null}
            <span class="rtt">{dhtPingResult.rtt_ms.toFixed(2)} ms</span>
          {/if}
        {:else}
          <strong>Failed</strong>
          <span class="err">{dhtPingResult.error ?? 'Unknown error'}</span>
        {/if}
      </div>
    {/if}
  </section>

  <section class="card">
    <h2>Find node on a peer</h2>
    <p class="hint">
      Sends a single signed <code>FIND_NODE</code> and shows the
      <code>k</code> contacts that peer returns closest to the target —
      one hop of Kademlia lookup. Leave the target blank to use a random
      ID (just see what the peer knows). Returned contacts are also
      merged into <em>this</em> node's routing table. The pubkey is the
      peer's Noise key; leave blank to use the KAD-fed cache.
    </p>
    <form onsubmit={submitFindNode} class="ping-form">
      <label>
        <span>Peer IP</span>
        <input type="text" bind:value={findIp} placeholder="127.0.0.1" required autocomplete="off" />
      </label>
      <label>
        <span>Peer UDP port</span>
        <input type="number" bind:value={findPort} min="1" max="65535" required />
      </label>
      <label class="full">
        <span>Target node ID (hex) <span class="optional">— optional, 32 hex chars; blank = random</span></span>
        <input type="text" bind:value={findTargetHex} placeholder="32 hex chars, or leave blank" autocomplete="off" spellcheck="false" />
      </label>
      <label class="full">
        <span>Peer Noise pubkey (hex) <span class="optional">— optional</span></span>
        <input type="text" bind:value={findPubkeyHex} placeholder="64 hex chars, or leave blank" autocomplete="off" spellcheck="false" />
      </label>
      <label>
        <span>Timeout (ms)</span>
        <input type="number" bind:value={findTimeoutMs} min="100" max="60000" step="100" />
      </label>
      <div class="form-actions">
        <button type="submit" disabled={finding || !findIp || findPort === ''}>
          {finding ? 'Finding…' : 'Send FIND_NODE'}
        </button>
      </div>
    </form>
    {#if findResult}
      {#if findResult.success}
        <div class="result result-ok">
          <strong>OK</strong>
          <span class="rtt">
            {findResult.contacts.length} contact{findResult.contacts.length === 1 ? '' : 's'}
            {#if findResult.rtt_ms !== undefined && findResult.rtt_ms !== null}
              · ~{findResult.rtt_ms.toFixed(0)} ms
            {/if}
          </span>
        </div>
        {#if findResult.contacts.length > 0}
          <div class="contacts">
            <table>
              <thead>
                <tr><th>Node ID</th><th>Address</th><th>Last seen</th><th>Fails</th></tr>
              </thead>
              <tbody>
                {#each findResult.contacts as c (c.node_id)}
                  <tr>
                    <td><code>{c.node_id.slice(0, 16)}…</code></td>
                    <td>{c.addr}</td>
                    <td>{c.last_seen > 0 ? new Date(c.last_seen * 1000).toLocaleTimeString() : '—'}</td>
                    <td>{c.failed_queries}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {:else}
          <p class="hint muted">The peer returned no contacts (its routing table is empty for that target).</p>
        {/if}
      {:else}
        <div class="result result-fail">
          <strong>Failed</strong>
          <span class="err">{findResult.error ?? 'Unknown error'}</span>
        </div>
      {/if}
    {/if}
  </section>

  <section class="card">
    <h2>Iterative lookup</h2>
    <p class="hint">
      Multi-hop discovery: seeds from <em>this</em> node's routing table
      and loops <code>FIND_NODE</code> across the closest contacts it
      learns until the search converges, then lists the closest contacts
      that responded. Needs at least one contact to start — seed or
      DHT-ping a peer first. Leave the target blank for a random
      self-style probe that broadens the table.
    </p>
    <form onsubmit={submitLookup} class="ping-form">
      <label class="full">
        <span>Target node ID (hex) <span class="optional">— optional, 32 hex chars; blank = random</span></span>
        <input type="text" bind:value={lookupTargetHex} placeholder="32 hex chars, or leave blank" autocomplete="off" spellcheck="false" />
      </label>
      <label>
        <span>Timeout (ms)</span>
        <input type="number" bind:value={lookupTimeoutMs} min="100" max="60000" step="100" />
      </label>
      <div class="form-actions">
        <button type="submit" disabled={lookingUp}>
          {lookingUp ? 'Looking up…' : 'Run lookup'}
        </button>
      </div>
    </form>
    {#if lookupResult}
      {#if lookupResult.success}
        <div class="result result-ok">
          <strong>OK</strong>
          <span class="rtt">
            {lookupResult.contacts.length} contact{lookupResult.contacts.length === 1 ? '' : 's'} responded
            {#if lookupResult.rtt_ms !== undefined && lookupResult.rtt_ms !== null}
              · {lookupResult.rtt_ms.toFixed(0)} ms
            {/if}
          </span>
        </div>
        {#if lookupResult.contacts.length > 0}
          <div class="contacts">
            <table>
              <thead>
                <tr><th>Node ID</th><th>Address</th><th>Last seen</th><th>Fails</th></tr>
              </thead>
              <tbody>
                {#each lookupResult.contacts as c (c.node_id)}
                  <tr>
                    <td><code>{c.node_id.slice(0, 16)}…</code></td>
                    <td>{c.addr}</td>
                    <td>{c.last_seen > 0 ? new Date(c.last_seen * 1000).toLocaleTimeString() : '—'}</td>
                    <td>{c.failed_queries}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {:else}
          <p class="hint muted">
            No contacts responded. With an empty routing table there's
            nothing to query — seed or DHT-ping a peer, then retry.
          </p>
        {/if}
      {:else}
        <div class="result result-fail">
          <strong>Failed</strong>
          <span class="err">{lookupResult.error ?? 'Unknown error'}</span>
        </div>
      {/if}
    {/if}
  </section>

  <section class="card">
    <h2>Publish keyword record</h2>
    <p class="hint">
      Sign a keyword record with <em>this</em> node's identity and
      <code>STORE</code> it on the closest contacts we know. Returns the
      DHT key it landed under (re-use it from another node's
      <strong>Find value</strong> form) and how many nodes acked. Needs at
      least one contact — seed or DHT-ping a peer first.
    </p>
    <form onsubmit={submitPublish} class="ping-form">
      <label>
        <span>Keyword</span>
        <input type="text" bind:value={publishKeyword} placeholder="e.g. ubuntu" autocomplete="off" spellcheck="false" maxlength="128" required />
      </label>
      <label>
        <span>File name</span>
        <input type="text" bind:value={publishFileName} placeholder="e.g. ubuntu-24.04.iso" autocomplete="off" spellcheck="false" maxlength="255" />
      </label>
      <label>
        <span>File size (bytes)</span>
        <input type="number" bind:value={publishFileSize} min="0" step="1" />
      </label>
      <label class="full">
        <span>File hash (hex) <span class="optional">— optional, 32 hex chars; blank = random</span></span>
        <input type="text" bind:value={publishFileHashHex} placeholder="32 hex chars, or leave blank" autocomplete="off" spellcheck="false" />
      </label>
      <label>
        <span>Timeout (ms)</span>
        <input type="number" bind:value={publishTimeoutMs} min="100" max="60000" step="100" />
      </label>
      <div class="form-actions">
        <button type="submit" disabled={publishing}>
          {publishing ? 'Publishing…' : 'Publish'}
        </button>
      </div>
    </form>
    {#if publishResult}
      {#if publishResult.success}
        <div class="result result-ok">
          <strong>OK</strong>
          <span class="rtt">stored on {publishResult.stored_on} / {publishResult.targets} node{publishResult.targets === 1 ? '' : 's'}</span>
        </div>
        <p class="hint muted">Key: <code>{publishResult.key}</code></p>
      {:else}
        <div class="result result-fail">
          <strong>Failed</strong>
          <span class="err">{publishResult.error ?? 'Unknown error'}</span>
        </div>
        {#if publishResult.key}
          <p class="hint muted">Key: <code>{publishResult.key}</code></p>
        {/if}
      {/if}
    {/if}
  </section>

  <section class="card">
    <h2>Find value</h2>
    <p class="hint">
      Iterative <code>FIND_VALUE</code> for a keyword: seeds from this
      node's routing table and walks toward the keyword's key, gathering
      signed records and surfacing the ones whose publisher signature
      verifies. Seed or DHT-ping a peer first.
    </p>
    <form onsubmit={submitFindValue} class="ping-form">
      <label class="full">
        <span>Keyword</span>
        <input type="text" bind:value={findValueKeyword} placeholder="e.g. ubuntu" autocomplete="off" spellcheck="false" maxlength="128" required />
      </label>
      <label>
        <span>Timeout (ms)</span>
        <input type="number" bind:value={findValueTimeoutMs} min="100" max="60000" step="100" />
      </label>
      <div class="form-actions">
        <button type="submit" disabled={findingValue}>
          {findingValue ? 'Searching…' : 'Find value'}
        </button>
      </div>
    </form>
    {#if findValueResult}
      {#if findValueResult.success}
        <div class="result result-ok">
          <strong>OK</strong>
          <span class="rtt">
            {findValueResult.records.length} record{findValueResult.records.length === 1 ? '' : 's'}
            {#if findValueResult.rtt_ms !== undefined && findValueResult.rtt_ms !== null}
              · {findValueResult.rtt_ms.toFixed(0)} ms
            {/if}
          </span>
        </div>
        {#if findValueResult.records.length > 0}
          <div class="contacts">
            <table>
              <thead>
                <tr><th>File name</th><th>Size</th><th>File hash</th><th>Publisher</th></tr>
              </thead>
              <tbody>
                {#each findValueResult.records as r (r.publisher + r.file_hash)}
                  <tr>
                    <td>{r.file_name || '—'}</td>
                    <td>{r.file_size}</td>
                    <td><code>{r.file_hash.slice(0, 16)}…</code></td>
                    <td><code>{r.publisher.slice(0, 16)}…</code></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {:else}
          <p class="hint muted">
            No records found for that keyword. Publish one (from this or
            another node), then retry — the search needs contacts that
            hold the record.
          </p>
        {/if}
      {:else}
        <div class="result result-fail">
          <strong>Failed</strong>
          <span class="err">{findValueResult.error ?? 'Unknown error'}</span>
        </div>
      {/if}
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
  </div>
</div>
{/if}

<style>
  /*
   * The page root is now the global fixed `.page-header` + scrollable
   * `.page-content` pair (matching every other route). `.dev-inner`
   * is the centered, padded column inside the scroll area — without a
   * scroll container the lower cards were clipped by the layout's
   * `overflow: hidden` page wrapper and could not be reached.
   */
  .dev-inner {
    max-width: 1040px;
    margin: 0 auto;
    padding: 20px 20px 48px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  /*
   * The read-out cards (identity, counters, DHT + routing table) stay
   * full width; the action forms flow into a responsive grid so the
   * page is a compact dashboard instead of one very tall column.
   */
  .forms-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(330px, 1fr));
    gap: 16px;
    align-items: start;
  }
  /* Let grid cards shrink below their content width so wide result
     tables scroll inside the card (`.contacts` is overflow-x: auto)
     rather than forcing the whole track wider. */
  .forms-grid > .card { min-width: 0; }
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

  .subhead {
    margin: 6px 0 0;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-muted);
    font-weight: 600;
  }
  .contacts { overflow-x: auto; }
  .contacts table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .contacts th {
    text-align: left;
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    font-size: 11px;
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
  }
  .contacts td {
    padding: 5px 8px;
    border-bottom: 1px solid var(--border);
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
  }
  .contacts td code {
    font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace);
    font-size: 11px;
  }
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

  .maint-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 14px;
    flex-wrap: wrap;
  }
  .maint-btn {
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 4px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
  }
  .maint-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .maint-row .hint {
    flex: 1;
    min-width: 220px;
    margin: 0;
  }
</style>
