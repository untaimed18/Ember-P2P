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

  type MessageFn = (params?: Record<string, unknown>) => string;
  const messages = m as unknown as Record<string, MessageFn | undefined>;
  /** A message by key, or `fallback` for one this build has no text for. */
  function text(key: string, params: Record<string, unknown> = {}, fallback = ''): string {
    const fn = messages[key];
    return fn ? fn(params) : fallback;
  }

  let params = $derived(
    report ? { tcp: report.tcp_port, udp: report.udp_port, lan: report.lan_ip || m.doctor_this_computer() } : {},
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
      // What the fix changed shows in a fresh check, once it has had a moment.
      if (action !== 'retry_upnp') void run();
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
    return value.includes(':') ? value.replace(/[^:]+$/, 'x') : value.replace(/\d+$/, 'x');
  }

  function reportText(r: ConnectionReport): string {
    const lines = [
      `${m.doctor_title()}: ${text(`doctor_verdict_${r.verdict}`)}`,
      `TCP ${r.tcp_port}, UDP ${r.udp_port}; LAN ${address(r.lan_ip)}; public ${address(r.public_ip)}`,
      ...r.checks.map(
        (c) => `[${c.status}] ${text(`doctor_check_${c.id}`, {}, c.id)}: ${text(`doctor_detail_${c.detail}`, {}, c.detail)}`,
      ),
      ...r.fixes.map((f) => `-> ${text(`doctor_fix_${f.id}`, params, f.id)}`),
    ];
    return lines.join('\n');
  }

  async function copyReport() {
    if (!report) return;
    try {
      await navigator.clipboard.writeText(reportText(report));
      toast(m.doctor_copied());
    } catch {
      toast(m.error_operation_failed());
    }
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
        <strong>{text(`doctor_verdict_${report.verdict}`)}</strong>
        <span>{text(`doctor_verdict_${report.verdict}_body`)}</span>
      </div>
    {/if}
  </div>

  {#if report}
    {#if report.helping.length > 0}
      <div class="doctor-block">
        <h5>{m.doctor_helping_title()}</h5>
        <ul class="doctor-list">
          {#each report.helping as help (help)}
            <li>{text(`doctor_helping_${help}`)}</li>
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
              <strong>{text(`doctor_fix_${fix.id}`, params, fix.id)}</strong>
              <span>{text(`doctor_fix_${fix.id}_body`, params)}</span>
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
                  {acting === fix.action ? m.doctor_running() : text(`doctor_action_${fix.action}`)}
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
            <span class="doctor-icon" role="img" aria-label={text(`doctor_status_${check.status}`)}>{statusIcon[check.status]}</span>
            <span class="doctor-check-label">{text(`doctor_check_${check.id}`, {}, check.id)}</span>
            <span class="doctor-check-detail">{text(`doctor_detail_${check.detail}`, {}, check.detail)}</span>
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

  .doctor-verdict.relayed {
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
