<script lang="ts">
  /*
   * Reachability readout: external IP, firewall verdict, TCP/UDP state, port
   * mapping and buddy. Shared by the KAD page's Network Status panel and the
   * Ember page — Ember is the default landing view now, so "can people reach
   * me?" has to be answerable there without first knowing KAD exists.
   *
   * Column count comes from a container query on `.tiles`, so the same markup
   * fills a full-width card on Ember and collapses to 2-up (then 1-up) inside
   * KAD's narrow right-hand column.
   */
  import { goto } from '$app/navigation';
  import { networkStats, upnpAutoDisabled } from '$lib/stores/network';
  import { appSettings } from '$lib/stores/settings';
  import { firewallStatusText } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';

  // `appSettings` is null until the layout's first load lands; treat that as
  // enabled so the tile doesn't flash "Disabled" during start-up.
  let upnpOff = $derived($appSettings?.upnp_enabled === false || $upnpAutoDisabled);
  let buddyStatus = $derived($networkStats.buddy_status || 'none');
</script>

<div class="tiles">
  <div class="stat-group">
    <div class="stat-tile">
      <span class="stat-label">{m.kad_stat_external_ip()}</span>
      <span class="stat-value stat-ip">{$networkStats.status === 'disconnected' ? m.common_unknown() : ($networkStats.external_ip || m.kad_detecting())}</span>
    </div>
    <div class="stat-tile">
      <span class="stat-label">{m.kad_stat_firewall()}</span>
      {#if $networkStats.status === 'disconnected'}
        <span class="badge unknown"><span class="badge-glyph" aria-hidden="true">?</span> {m.common_unknown()}</span>
      {:else if $networkStats.status === 'connecting'}
        <span class="badge unknown"><span class="badge-glyph" aria-hidden="true">&#x25CB;</span> {m.kad_checking()}</span>
      {:else}
        <span
          class="badge {$networkStats.firewalled ? 'firewalled' : 'open'}"
          role="status"
          aria-label={$networkStats.firewalled
            ? m.kad_firewall_aria_firewalled()
            : m.kad_firewall_aria_open()}
        >
          <span class="badge-glyph" aria-hidden="true">
            {#if $networkStats.firewalled}&#x26A0;{:else}&#x2713;{/if}
          </span>
          {$networkStats.firewalled ? m.kad_firewall_firewalled() : m.kad_firewall_open()}
        </span>
      {/if}
    </div>
  </div>

  <div class="stat-group stat-group-grid">
    <div class="stat-tile">
      <span class="stat-label">{m.kad_stat_tcp()}</span>
      <span class="stat-value">{firewallStatusText($networkStats.tcp_status)}</span>
    </div>
    <div class="stat-tile">
      <span class="stat-label">{m.kad_stat_udp()}</span>
      <span class="stat-value">{firewallStatusText($networkStats.udp_status)}</span>
    </div>
    <div class="stat-tile">
      <span class="stat-label">{m.kad_stat_upnp()}</span>
      {#if upnpOff}
        <button
          type="button"
          class="stat-link"
          onclick={() => void goto('/settings?section=network').catch((e) => console.warn('Failed to open settings:', e))}
          title={m.kad_upnp_disabled_title()}
        >{m.kad_upnp_disabled()}</button>
      {:else}
        <span class="stat-value">{$networkStats.upnp_mapped ? m.kad_upnp_mapped() : m.kad_upnp_not_mapped()}</span>
      {/if}
    </div>
    <div class="stat-tile">
      <span class="stat-label">{m.kad_stat_stun_keepalive()}</span>
      <span class="stat-value">{$networkStats.stun_keepalive_active ? m.kad_stun_active() : m.kad_stun_inactive()}</span>
    </div>
    <div class="stat-tile">
      <span class="stat-label">{m.kad_stat_public_ports()}</span>
      <span class="stat-value">
        {#if ($networkStats.public_tcp_port || 0) > 0 || ($networkStats.public_udp_port || 0) > 0}
          TCP {$networkStats.public_tcp_port || '—'} / UDP {$networkStats.public_udp_port || '—'}
        {:else}
          —
        {/if}
      </span>
    </div>
    <div class="stat-tile">
      <!-- "Buddy" is eMule vocabulary with no meaning outside it, so the
           label carries its own explanation. -->
      <span class="stat-label" title={m.kad_stat_buddy_help()}>{m.kad_stat_buddy()}</span>
      <span class="stat-value">
        {buddyStatus === 'none' ? m.kad_buddy_none() :
         buddyStatus.startsWith('connected') ? m.kad_buddy_connected() :
         buddyStatus.startsWith('connecting') ? m.kad_buddy_connecting() :
         buddyStatus.startsWith('serving') ? m.kad_buddy_serving() :
         m.common_unknown()}
      </span>
    </div>
  </div>
</div>

<style>
  .tiles {
    container-type: inline-size;
  }

  /*
   * Each tile stacks its label above its value so long values (badges, IP
   * addresses, "Not Mapped") get the full tile width and never truncate.
   * Group separators replace per-row dashed borders so the block reads
   * calmer and more scannable.
   */
  .stat-group {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2px 12px;
    padding: 6px 0;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 55%, transparent);
  }

  .stat-group:last-of-type {
    padding-bottom: 0;
    border-bottom: none;
  }

  .stat-group-grid {
    grid-template-columns: repeat(4, 1fr);
    gap: 2px 8px;
  }

  .stat-tile {
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 6px 0;
    min-width: 0;
  }

  /* At narrow widths, collapse the 4-up group to 2-up (the 2-up group stays
     as-is, its labels are short enough). Below ~220px everything stacks. */
  @container (max-width: 330px) {
    .stat-group-grid {
      grid-template-columns: repeat(2, 1fr);
    }
  }

  @container (max-width: 220px) {
    .stat-group,
    .stat-group-grid {
      grid-template-columns: 1fr;
    }
  }

  .stat-label {
    color: var(--text-muted);
    font-weight: 500;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .stat-value {
    color: var(--text-primary);
    font-weight: 600;
    font-size: 13px;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .stat-ip {
    font-family: var(--font-mono);
    font-size: 12px;
  }

  .stat-link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    font: inherit;
    font-weight: 600;
    cursor: pointer;
    text-decoration: underline dotted;
    text-underline-offset: 2px;
    /* Inside a flex-column tile the default button width stretches to the
       tile's full width and `text-align: center` centers the label.
       Align-self keeps the button at its intrinsic width so the link lines
       up with the label above it. */
    align-self: flex-start;
    text-align: left;
  }

  .stat-link:hover { color: var(--accent-hover, var(--accent)); }

  /* Badges inside tiles shouldn't stretch — they sit at their natural width
     so the tile column stays flexible. */
  .stat-tile .badge {
    align-self: flex-start;
  }

  .badge.open {
    background: color-mix(in srgb, var(--success) 15%, transparent);
    border-color: color-mix(in srgb, var(--success) 30%, transparent);
    color: var(--badge-success-text);
  }

  .badge.firewalled {
    background: color-mix(in srgb, var(--warning) 15%, transparent);
    border-color: color-mix(in srgb, var(--warning) 30%, transparent);
    color: var(--badge-warning-text);
  }

  .badge.unknown {
    background: color-mix(in srgb, var(--text-muted) 18%, transparent);
    border-color: color-mix(in srgb, var(--text-muted) 32%, transparent);
    color: var(--text-secondary);
  }
</style>
