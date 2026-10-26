<script lang="ts">
  /*
   * The connection doctor: one check of everything that decides whether other
   * people can reach this computer, in plain words. What works, what does not,
   * what Ember already does about it, and at most three things worth trying,
   * the likeliest first.
   */
  import { onDestroy } from 'svelte';
  import {
    connectionDoctorAction,
    runConnectionCheck,
    type ConnectionFix,
    type ConnectionReport,
  } from '$lib/api/connectionDoctor';
  import { translateError } from '$lib/i18n';
  import { toast } from '$lib/stores/toast';
  import { copyToClipboard } from '$lib/utils';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import * as m from '$lib/paraglide/messages';

  interface Props {
    /** Bring the port fields into view, for a port another program holds. */
    onMovePorts?: () => void;
    /** Turn UPnP on in the settings being edited. */
    onEnableUpnp?: () => void;
  }
  let { onMovePorts, onEnableUpnp }: Props = $props();

  let running = $state(false);
  let report = $state<ConnectionReport | null>(null);
  let failure = $state('');
  let acting = $state<string | null>(null);
  let confirmFirewall = $state(false);
  let includeAddresses = $state(false);
  let destroyed = false;
  onDestroy(() => {
    destroyed = true;
  });

  type FixParams = { tcp: number; udp: number; lan: string };
  /** The report names checks, outcomes and fixes by id; these say them. An id
   *  this build has no text for shows as the id itself. */
  const VERDICT: Record<string, [() => string, () => string]> = {
    reachable: [m.doctor_verdict_reachable, m.doctor_verdict_reachable_body],
    relayed: [m.doctor_verdict_relayed, m.doctor_verdict_relayed_body],
    limited: [m.doctor_verdict_limited, m.doctor_verdict_limited_body],
    checking: [m.doctor_verdict_checking, m.doctor_verdict_checking_body],
    untested: [m.doctor_verdict_untested, m.doctor_verdict_untested_body],
    offline: [m.doctor_verdict_offline, m.doctor_verdict_offline_body],
  };
  const HELPING: Record<string, () => string> = {
    relay: m.doctor_helping_relay,
    buddy: m.doctor_helping_buddy,
    punch: m.doctor_helping_punch,
  };
  const FIX: Record<string, [(p: FixParams) => string, (p: FixParams) => string]> = {
    restart: [m.doctor_fix_restart, m.doctor_fix_restart_body],
    port_in_use: [m.doctor_fix_port_in_use, m.doctor_fix_port_in_use_body],
    windows_firewall: [m.doctor_fix_windows_firewall, m.doctor_fix_windows_firewall_body],
    carrier_nat: [m.doctor_fix_carrier_nat, m.doctor_fix_carrier_nat_body],
    vpn: [m.doctor_fix_vpn, m.doctor_fix_vpn_body],
    enable_upnp: [m.doctor_fix_enable_upnp, m.doctor_fix_enable_upnp_body],
    router_upnp: [m.doctor_fix_router_upnp, m.doctor_fix_router_upnp_body],
    forward_ports: [m.doctor_fix_forward_ports, m.doctor_fix_forward_ports_body],
    offline: [m.doctor_fix_offline, m.doctor_fix_offline_body],
    checking: [m.doctor_fix_checking, m.doctor_fix_checking_body],
    untested: [m.doctor_fix_untested, m.doctor_fix_untested_body],
    clock: [m.doctor_fix_clock, m.doctor_fix_clock_body],
  };
  const ACTION: Record<string, () => string> = {
    move_ports: m.doctor_action_move_ports,
    add_firewall_rules: m.doctor_action_add_firewall_rules,
    enable_upnp: m.doctor_action_enable_upnp,
    retry_upnp: m.doctor_action_retry_upnp,
    recheck: m.doctor_action_recheck,
  };
  const CHECK: Record<string, () => string> = {
    listen_ports: m.doctor_check_listen_ports,
    windows_firewall: m.doctor_check_windows_firewall,
    upnp: m.doctor_check_upnp,
    router_wan: m.doctor_check_router_wan,
    outside_tcp: m.doctor_check_outside_tcp,
    outside_udp: m.doctor_check_outside_udp,
    kad_firewall: m.doctor_check_kad_firewall,
    server_id: m.doctor_check_server_id,
    nat_type: m.doctor_check_nat_type,
    ember_dht: m.doctor_check_ember_dht,
    clock: m.doctor_check_clock,
  };
  const DETAIL: Record<string, () => string> = {
    ok: m.doctor_detail_ok,
    tcp_taken: m.doctor_detail_tcp_taken,
    udp_moved: m.doctor_detail_udp_moved,
    missing: m.doctor_detail_missing,
    check_failed: m.doctor_detail_check_failed,
    not_windows: m.doctor_detail_not_windows,
    off: m.doctor_detail_off,
    stood_down: m.doctor_detail_stood_down,
    mapped: m.doctor_detail_mapped,
    not_mapped: m.doctor_detail_not_mapped,
    carrier_nat: m.doctor_detail_carrier_nat,
    public: m.doctor_detail_public,
    unknown: m.doctor_detail_unknown,
    open: m.doctor_detail_open,
    closed: m.doctor_detail_closed,
    filtered: m.doctor_detail_filtered,
    not_run: m.doctor_detail_not_run,
    rate_limited: m.doctor_detail_rate_limited,
    busy: m.doctor_detail_busy,
    another_program: m.doctor_detail_another_program,
    checking: m.doctor_detail_checking,
    firewalled: m.doctor_detail_firewalled,
    partly: m.doctor_detail_partly,
    high_id: m.doctor_detail_high_id,
    low_id: m.doctor_detail_low_id,
    not_connected: m.doctor_detail_not_connected,
    symmetric: m.doctor_detail_symmetric,
    no_contacts: m.doctor_detail_no_contacts,
    skewed: m.doctor_detail_skewed,
  };
  const STATUS: Record<string, () => string> = {
    pass: m.doctor_status_pass,
    warn: m.doctor_status_warn,
    fail: m.doctor_status_fail,
    skip: m.doctor_status_skip,
  };

  let params: FixParams = $derived(
    report
      ? { tcp: report.tcp_port, udp: report.udp_port, lan: report.lan_ip || m.doctor_this_computer() }
      : { tcp: 0, udp: 0, lan: '' },
  );

  async function run() {
    if (running) return;
    running = true;
    failure = '';
    try {
      const next = await runConnectionCheck();
      if (!destroyed) report = next;
    } catch (e) {
      if (!destroyed) failure = m.doctor_failed({ error: translateError(e, m.error_operation_failed()) });
    } finally {
      running = false;
    }
  }

  async function act(fix: ConnectionFix) {
    const action = fix.action;
    if (!action || acting) return;
    if (action === 'move_ports') {
      onMovePorts?.();
      return;
    }
    if (action === 'enable_upnp') {
      onEnableUpnp?.();
      return;
    }
    acting = action;
    try {
      const done = await connectionDoctorAction(action);
      if (destroyed) return;
      if (action === 'add_firewall_rules' && !done) {
        toast(m.doctor_action_declined());
        return;
      }
      toast(m.doctor_action_done());
      // What the fix changed shows in a fresh check, once it has had a
      // moment: a UPnP pass takes several seconds to ask the router.
      if (action === 'retry_upnp') {
        setTimeout(() => {
          if (!destroyed) void run();
        }, 10_000);
      } else {
        void run();
      }
    } catch (e) {
      if (!destroyed) toast(translateError(e, m.error_operation_failed()));
    } finally {
      acting = null;
    }
  }

  /** Addresses masked unless the user chose to include them: a report is for
   *  pasting into a support thread. */
  function address(value: string): string {
    if (!value) return '-';
    if (includeAddresses) return value;
    // IPv6: the first three groups name a provider's /48, never one home.
    if (value.includes(':')) return `${value.split(':').slice(0, 3).join(':')}:x`;
    return value.replace(/\d+$/, 'x');
  }

  function reportText(r: ConnectionReport): string {
    const lines = [
      `${m.doctor_title()}: ${VERDICT[r.verdict]?.[0]() ?? r.verdict}`,
      m.doctor_report_ports({
        tcp: r.tcp_port,
        udp: r.udp_port,
        lan: address(r.lan_ip),
        ip: address(r.public_ip),
      }),
      ...r.checks.map(
        (c) =>
          `[${STATUS[c.status]?.() ?? c.status}] ${CHECK[c.id]?.() ?? c.id}: ${DETAIL[c.detail]?.() ?? c.detail}`,
      ),
      ...r.fixes.map((f) => `-> ${FIX[f.id]?.[0](params) ?? f.id}`),
    ];
    return lines.join('\n');
  }

  async function copyReport() {
    if (!report) return;
    toast((await copyToClipboard(reportText(report))) ? m.doctor_copied() : m.error_operation_failed());
  }

  const statusIcon: Record<string, string> = { pass: '✓', warn: '!', fail: '✕', skip: '–' };
</script>

<div class="doctor">
  <div class="doctor-row">
    <button type="button" class="secondary" onclick={() => void run()} disabled={running}>
      {#if running}
        <span class="spinner xs current" aria-hidden="true"></span> {m.doctor_running()}
      {:else}
        {m.doctor_run()}
      {/if}
    </button>
    {#if !report && !failure}
      <span class="doctor-hint">{m.doctor_intro()}</span>
    {/if}
  </div>

  <div role="status" aria-live="polite">
    {#if failure}
      <p class="doctor-hint">{failure}</p>
    {:else if report}
      <div class="doctor-verdict {report.verdict}">
        <strong>{VERDICT[report.verdict]?.[0]() ?? report.verdict}</strong>
        <span>{VERDICT[report.verdict]?.[1]() ?? ''}</span>
      </div>
    {/if}
  </div>

  {#if report}
    {#if report.helping.length > 0}
      <div class="doctor-block">
        <h5>{m.doctor_helping_title()}</h5>
        <ul class="doctor-list">
          {#each report.helping as help (help)}
            <li>{HELPING[help]?.() ?? help}</li>
          {/each}
        </ul>
      </div>
    {/if}

    {#if report.fixes.length > 0}
      <div class="doctor-block">
        <h5>{m.doctor_fixes_title()}</h5>
        <ol class="doctor-fixes">
          {#each report.fixes as fix (fix.id)}
            <li>
              <strong>{FIX[fix.id]?.[0](params) ?? fix.id}</strong>
              <span>{FIX[fix.id]?.[1](params) ?? ''}</span>
              {#if fix.action && (fix.action !== 'move_ports' || onMovePorts) && (fix.action !== 'enable_upnp' || onEnableUpnp)}
                <button
                  type="button"
                  class="secondary small"
                  onclick={() => {
                    // Asking Windows for permission is a step the user has to
                    // see coming.
                    if (fix.action === 'add_firewall_rules') confirmFirewall = true;
                    else void act(fix);
                  }}
                  disabled={acting !== null}
                >
                  {acting === fix.action ? m.doctor_running() : (ACTION[fix.action]?.() ?? fix.action)}
                </button>
              {/if}
            </li>
          {/each}
        </ol>
      </div>
    {/if}

    <details class="doctor-block">
      <summary>{m.doctor_checks_title()}</summary>
      <ul class="doctor-checks">
        {#each report.checks as check (check.id)}
          <li class={check.status}>
            <span class="doctor-icon" role="img" aria-label={STATUS[check.status]?.() ?? check.status}>{statusIcon[check.status]}</span>
            <span class="doctor-check-label">{CHECK[check.id]?.() ?? check.id}</span>
            <span class="doctor-check-detail">{DETAIL[check.detail]?.() ?? check.detail}</span>
          </li>
        {/each}
      </ul>
      {#if !report.probed}
        <p class="doctor-hint">{m.doctor_not_probed()}</p>
      {/if}
      <div class="doctor-row">
        <button type="button" class="secondary small" onclick={() => void copyReport()}>{m.doctor_copy_report()}</button>
        <label class="doctor-include">
          <input type="checkbox" bind:checked={includeAddresses} />
          {m.doctor_copy_include_addresses()}
        </label>
      </div>
    </details>
  {/if}
</div>

<ConfirmDialog
  bind:open={confirmFirewall}
  title={m.doctor_fix_windows_firewall()}
  message={m.doctor_firewall_confirm()}
  confirmLabel={m.doctor_action_add_firewall_rules()}
  onconfirm={() => {
    const fix = report?.fixes.find((f) => f.action === 'add_firewall_rules');
    if (fix) void act(fix);
  }}
/>

<style>
  .doctor {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-top: 8px;
  }

  .doctor-row {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
  }

  .doctor-row button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    font-size: var(--font-size-sm);
  }

  .doctor-hint {
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    margin: 0;
  }

  .doctor-verdict {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 10px 12px;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
  }

  .doctor-verdict.reachable {
    border-color: color-mix(in srgb, var(--success) 45%, var(--border));
  }

  .doctor-verdict.relayed,
  .doctor-verdict.checking,
  .doctor-verdict.untested {
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
  }

  .doctor-verdict.limited,
  .doctor-verdict.offline {
    border-color: color-mix(in srgb, var(--warning) 50%, var(--border));
  }

  .doctor-verdict strong {
    color: var(--text-primary);
  }

  .doctor-block h5,
  .doctor-block summary {
    margin: 0 0 4px;
    font-size: var(--font-size-sm);
    font-weight: 600;
    color: var(--text-primary);
    cursor: default;
  }

  .doctor-block summary {
    cursor: pointer;
  }

  .doctor-list,
  .doctor-fixes,
  .doctor-checks {
    margin: 0;
    padding-left: 18px;
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .doctor-fixes li {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
  }

  .doctor-fixes strong {
    color: var(--text-primary);
  }

  .doctor-checks {
    list-style: none;
    padding-left: 0;
    gap: 3px;
  }

  .doctor-checks li {
    display: grid;
    grid-template-columns: 18px minmax(120px, 30%) 1fr;
    gap: 8px;
    align-items: baseline;
  }

  .doctor-icon {
    font-weight: 700;
    text-align: center;
  }

  .doctor-checks li.pass .doctor-icon {
    color: var(--success);
  }

  .doctor-checks li.warn .doctor-icon,
  .doctor-checks li.fail .doctor-icon {
    color: var(--warning);
  }

  .doctor-checks li.skip {
    color: var(--text-muted);
  }

  .doctor-check-label {
    color: var(--text-primary);
  }

  .doctor-include {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
  }
</style>
