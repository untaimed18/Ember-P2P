<script lang="ts">
  import { getPeers, banPeer, unbanPeer } from '$lib/api/peers';
  import type { PeerInfo } from '$lib/types';
  import { onMount } from 'svelte';

  let peers: PeerInfo[] = $state([]);
  let loading = $state(true);

  onMount(() => {
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  });

  async function refresh() {
    try {
      peers = await getPeers();
    } catch (e) {
      console.error('Failed to get peers:', e);
    } finally {
      loading = false;
    }
  }

  async function handleBan(peerId: string) {
    const confirmed = confirm(`Ban peer ${peerId.slice(0, 16)}...? This will block all communication with this peer.`);
    if (!confirmed) return;
    try {
      await banPeer(peerId);
      await refresh();
    } catch (e) {
      console.error('Ban failed:', e);
    }
  }

  async function handleUnban(peerId: string) {
    try {
      await unbanPeer(peerId);
      await refresh();
    } catch (e) {
      console.error('Unban failed:', e);
    }
  }

  function formatTime(ts: number): string {
    if (ts === 0) return '—';
    return new Date(ts * 1000).toLocaleString();
  }
</script>

<div class="page-header">
  <h2>Peers</h2>
  <span class="count">{peers.length} connected</span>
</div>

<div class="page-content">
  {#if loading}
    <div class="empty-state">
      <p>Loading peers...</p>
    </div>
  {:else if peers.length === 0}
    <div class="empty-state">
      <div class="icon">⊛</div>
      <p>No peers connected</p>
      <p class="sub">Peers will appear here when others join the network</p>
    </div>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Peer ID</th>
          <th>Addresses</th>
          <th>Nickname</th>
          <th>Last Seen</th>
          <th>Files</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each peers as peer (peer.id)}
          <tr class:banned={peer.banned}>
            <td class="peer-id" title={peer.id}>{peer.id.slice(0, 16)}…</td>
            <td class="addresses">
              {#each peer.addresses.slice(0, 2) as addr}
                <span class="addr">{addr}</span>
              {/each}
              {#if peer.addresses.length > 2}
                <span class="more">+{peer.addresses.length - 2} more</span>
              {/if}
            </td>
            <td>{peer.nickname || '—'}</td>
            <td>{formatTime(peer.last_seen)}</td>
            <td>{peer.files_shared}</td>
            <td>
              {#if peer.banned}
                <button onclick={() => handleUnban(peer.id)}>Unban</button>
              {:else}
                <button class="danger" onclick={() => handleBan(peer.id)}>Ban</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .count {
    font-size: 13px;
    color: var(--text-muted);
  }

  .peer-id {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-muted);
  }

  .addresses {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .addr {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
  }

  .more {
    font-size: 11px;
    color: var(--text-muted);
  }

  .banned td {
    opacity: 0.5;
  }

  .sub {
    font-size: 13px;
    color: var(--text-muted);
  }
</style>
