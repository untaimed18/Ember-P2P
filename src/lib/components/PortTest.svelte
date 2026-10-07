<script lang="ts">
  /*
   * "Test my ports": asks a few KAD peers to connect back to this computer's
   * TCP and UDP ports and reports what that one check saw. The lasting
   * firewall status never falls back from Open, so it cannot answer "did the
   * forward I just set up work?"; this can.
   */
  import { onDestroy } from 'svelte';
  import { runPortTest, PortTestTimeout, type PortTestResult, type PortVerdict } from '$lib/portTest';
  import * as m from '$lib/paraglide/messages';

  let running = $state(false);
  let result = $state<PortTestResult | null>(null);
  let failure = $state('');
  let destroyed = false;
  onDestroy(() => {
    destroyed = true;
  });

  async function start() {
    if (running) return;
    running = true;
    result = null;
    failure = '';
    try {
      const outcome = await runPortTest();
      if (!destroyed) result = outcome;
    } catch (e) {
      if (!destroyed) failure = e instanceof PortTestTimeout ? m.port_test_timeout() : m.port_test_failed();
    } finally {
      running = false;
    }
  }

  function line(protocol: string, port: number, verdict: PortVerdict): string {
    return verdict === 'open'
      ? m.port_test_open({ protocol, port })
      : verdict === 'closed'
        ? m.port_test_closed({ protocol, port })
        : m.port_test_untested({ protocol, port });
  }

  let summary = $derived(
    !result
      ? ''
      : result.tcp === 'closed' || result.udp === 'closed'
        ? m.port_test_some_closed()
        : result.tcp === 'open' && result.udp === 'open'
          ? m.port_test_all_open()
          : m.port_test_partly_untested(),
  );
</script>

<div class="port-test">
  <div class="port-test-row">
    <button type="button" class="secondary" onclick={() => void start()} disabled={running}>
      {#if running}
        <span class="spinner xs current" aria-hidden="true"></span> {m.port_test_running()}
      {:else}
        {m.port_test_button()}
      {/if}
    </button>
    {#if !result && !failure}
      <span class="port-test-hint">{m.port_test_hint()}</span>
    {/if}
  </div>
  <div role="status" aria-live="polite">
    {#if result}
      <ul class="port-test-results">
        <li class:open={result.tcp === 'open'} class:closed={result.tcp === 'closed'}>{line('TCP', result.tcpPort, result.tcp)}</li>
        <li class:open={result.udp === 'open'} class:closed={result.udp === 'closed'}>{line('UDP', result.udpPort, result.udp)}</li>
      </ul>
      <p class="port-test-summary">{summary}</p>
    {:else if failure}
      <p class="port-test-summary">{failure}</p>
    {/if}
  </div>
</div>

<style>
  .port-test {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin-top: 8px;
  }

  .port-test-row {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
  }

  .port-test-row button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    font-size: var(--font-size-sm);
  }

  .port-test-hint,
  .port-test-summary {
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    margin: 0;
  }

  .port-test-results {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-wrap: wrap;
    gap: 4px 16px;
    font-size: var(--font-size-sm);
    font-variant-numeric: tabular-nums;
    color: var(--text-secondary);
  }

  .port-test-results li.open {
    color: var(--success);
  }

  .port-test-results li.closed {
    color: var(--warning);
  }
</style>
