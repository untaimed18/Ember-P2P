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
  import { networkStats } from '$lib/stores/network';
  import { appSettings } from '$lib/stores/settings';
  import { firewallStatusText } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';

  // `appSettings` is null until the layout's first load lands; treat that as
  // enabled so the tile doesn't flash "Disabled" during start-up.
  let upnpOff = $derived($appSettings?.upnp_enabled === false);
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
        <span class="badge tone-muted"><span class="badge-glyph" aria-hidden="true">?</span> {m.common_unknown()}</span>
      {:else if $networkStats.status === 'connecting'}
        <span class="badge tone-muted"><span class="badge-glyph" aria-hidden="true">&#x25CB;</span> {m.kad_checking()}</span>
      {:else}
        <span
          class="badge {$networkStats.firewalled ? 'tone-warning' : 'tone-success'}"
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
      {:else if $networkStats.upnp_stood_down}
        <span class="stat-value" title={m.kad_upnp_not_in_use_title()}>{m.kad_upnp_not_in_use()}</span>
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

  /* Tiles, groups and their collapse come from app.css. */
  .stat-group:last-of-type {
    padding-bottom: 0;
    border-bottom: none;
  }

  .stat-ip {
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
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

  .stat-link:hover { color: var(--accent-hover); }
</style>
