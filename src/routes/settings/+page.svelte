<script lang="ts">
  import { getSettings, updateSettings, downloadNodesDat, downloadIpfilter } from '$lib/api/settings';
  import type { AppSettings } from '$lib/types';
  import { onMount } from 'svelte';

  let settings: AppSettings | null = $state(null);
  let saving = $state(false);
  let saveMessage: string | null = $state(null);
  let saveIsWarning = $state(false);
  let downloadingNodes = $state(false);
  let nodesResult: string | null = $state(null);
  let nodesError: string | null = $state(null);
  let downloadingFilter = $state(false);
  let filterResult: string | null = $state(null);
  let filterError: string | null = $state(null);

  onMount(async () => {
    try {
      settings = await getSettings();
    } catch (e) {
      console.error('Failed to load settings:', e);
    }
  });

  async function handleSave() {
    if (!settings) return;
    saving = true;
    saveMessage = null;
    try {
      const result = await updateSettings(settings);
      saveIsWarning = result.includes('restart');
      saveMessage = result;
      setTimeout(() => (saveMessage = null), saveIsWarning ? 8000 : 3000);
    } catch (e) {
      console.error('Failed to save:', e);
      saveMessage = 'Failed to save settings';
      saveIsWarning = true;
      setTimeout(() => (saveMessage = null), 5000);
    } finally {
      saving = false;
    }
  }

  async function pickDownloadFolder() {
    if (!settings) return;
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({ directory: true, multiple: false });
      if (selected) {
        settings.download_folder = selected as string;
      }
    } catch (e) {
      console.error('Folder pick failed:', e);
    }
  }

  async function handleDownloadFilter() {
    downloadingFilter = true;
    filterResult = null;
    filterError = null;
    try {
      filterResult = await downloadIpfilter();
      setTimeout(() => (filterResult = null), 5000);
    } catch (e: any) {
      filterError = typeof e === 'string' ? e : e?.message ?? 'Download failed';
      setTimeout(() => (filterError = null), 5000);
    } finally {
      downloadingFilter = false;
    }
  }

  async function handleDownloadNodes() {
    downloadingNodes = true;
    nodesResult = null;
    nodesError = null;
    try {
      nodesResult = await downloadNodesDat();
      setTimeout(() => (nodesResult = null), 5000);
    } catch (e: any) {
      nodesError = typeof e === 'string' ? e : e?.message ?? 'Download failed';
      setTimeout(() => (nodesError = null), 5000);
    } finally {
      downloadingNodes = false;
    }
  }

  function formatSpeed(bytesPerSec: number): string {
    if (bytesPerSec === 0) return 'Unlimited';
    if (bytesPerSec < 1024) return `${bytesPerSec} B/s`;
    if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(0)} KB/s`;
    return `${(bytesPerSec / 1024 / 1024).toFixed(1)} MB/s`;
  }
</script>

<div class="page-header">
  <h2>Settings</h2>
  <div class="header-actions">
    {#if saveMessage}
      <span class="saved-msg" class:warning={saveIsWarning}>{saveMessage}</span>
    {/if}
    <button onclick={handleSave} disabled={saving || !settings}>
      {saving ? 'Saving...' : 'Save'}
    </button>
  </div>
</div>

<div class="page-content">
  {#if !settings}
    <div class="empty-state">
      <p>Loading settings...</p>
    </div>
  {:else}
    <div class="settings-grid">
      <section class="settings-section">
        <h3>Identity</h3>
        <div class="field">
          <label for="nickname">Nickname</label>
          <input id="nickname" bind:value={settings.nickname} />
        </div>
      </section>

      <section class="settings-section">
        <h3>Downloads</h3>
        <div class="field">
          <label>Download Folder</label>
          <div class="folder-pick">
            <input value={settings.download_folder} readonly />
            <button onclick={pickDownloadFolder}>Browse</button>
          </div>
        </div>
        <div class="field">
          <label for="max-concurrent">Max Concurrent Downloads</label>
          <input
            id="max-concurrent"
            type="number"
            min="1"
            max="20"
            bind:value={settings.max_concurrent_downloads}
          />
        </div>
      </section>

      <section class="settings-section">
        <h3>Bandwidth</h3>
        <div class="field">
          <label for="max-upload">Max Upload Speed (bytes/sec, 0 = unlimited)</label>
          <input id="max-upload" type="number" min="0" bind:value={settings.max_upload_speed} />
          <span class="field-hint">{formatSpeed(settings.max_upload_speed)}</span>
        </div>
        <div class="field">
          <label for="max-download">Max Download Speed (bytes/sec, 0 = unlimited)</label>
          <input
            id="max-download"
            type="number"
            min="0"
            bind:value={settings.max_download_speed}
          />
          <span class="field-hint">{formatSpeed(settings.max_download_speed)}</span>
        </div>
      </section>

      <section class="settings-section">
        <h3>Network (eMule KAD)</h3>
        <div class="field">
          <label for="tcp-port">TCP Port (peer-to-peer file transfer)</label>
          <input id="tcp-port" type="number" min="1" max="65535" bind:value={settings.tcp_port} />
          <span class="field-hint">Default: 4662. Used for peer-to-peer file transfers with other KAD clients.</span>
        </div>
        <div class="field">
          <label for="udp-port">UDP Port (KAD protocol)</label>
          <input id="udp-port" type="number" min="1" max="65535" bind:value={settings.udp_port} />
          <span class="field-hint">Default: 4672. Used for Kademlia DHT communication.</span>
        </div>
        <div class="field">
          <label for="nodes-dat">nodes.dat Path (optional)</label>
          <input id="nodes-dat" bind:value={settings.nodes_dat_path} placeholder="Auto-detected" />
          <span class="field-hint">Path to a nodes.dat file for bootstrapping. Leave blank for auto.</span>
        </div>
        <div class="field toggle-field">
          <label class="toggle-label">
            <input type="checkbox" bind:checked={settings.upnp_enabled} />
            <span>Use UPnP to setup ports</span>
          </label>
          <span class="field-hint">
            Automatically map TCP/UDP ports on your router via UPnP.
            Disable if your router doesn't support UPnP or you have manually forwarded ports.
            Requires restart to take effect.
          </span>
        </div>
        <div class="field toggle-field">
          <label class="toggle-label">
            <input type="checkbox" bind:checked={settings.nat_traversal_enabled} />
            <span>NAT Traversal (Firewall Detection, Buddy System)</span>
          </label>
          <span class="field-hint">
            Enable firewall probing and the buddy relay system for firewalled clients.
            Disable if you don't need NAT traversal assistance.
            Requires restart to take effect.
          </span>
        </div>
        <div class="field">
          <label>Update Bootstrap Nodes</label>
          <div class="nodes-download">
            <button onclick={handleDownloadNodes} disabled={downloadingNodes}>
              {downloadingNodes ? 'Downloading...' : 'Download Latest nodes.dat'}
            </button>
            {#if nodesResult}
              <span class="nodes-success">{nodesResult}</span>
            {/if}
            {#if nodesError}
              <span class="nodes-error">{nodesError}</span>
            {/if}
          </div>
          <span class="field-hint">
            Fetches the latest nodes.dat from emule-security.org and loads bootstrap contacts.
          </span>
        </div>
      </section>

      <section class="settings-section">
        <h3>Security</h3>
        <div class="field toggle-field">
          <label class="toggle-label">
            <input type="checkbox" bind:checked={settings.obfuscation_enabled} />
            <span>Protocol Obfuscation</span>
          </label>
          <span class="field-hint">
            Encrypt KAD UDP packets using RC4 when communicating with peers that support it.
            Compatible with eMule's protocol obfuscation.
            Requires restart to take effect.
          </span>
        </div>
        <div class="field toggle-field">
          <label class="toggle-label">
            <input type="checkbox" bind:checked={settings.ip_filter_enabled} />
            <span>IP Filter (ipfilter.dat)</span>
          </label>
          <span class="field-hint">
            Block known-bad IP ranges using an ipfilter.dat file (eMule compatible format).
            Requires restart to take effect.
          </span>
          <div class="nodes-download" style="margin-top: 6px;">
            <button onclick={handleDownloadFilter} disabled={downloadingFilter}>
              {downloadingFilter ? 'Downloading...' : 'Download ipfilter.dat'}
            </button>
            {#if filterResult}
              <span class="nodes-success">{filterResult}</span>
            {/if}
            {#if filterError}
              <span class="nodes-error">{filterError}</span>
            {/if}
          </div>
        </div>
        <div class="field toggle-field">
          <label class="toggle-label">
            <input type="checkbox" bind:checked={settings.block_private_ips} />
            <span>Block Private/Reserved IPs</span>
          </label>
          <span class="field-hint">
            Prevent private network IPs (10.x.x.x, 192.168.x.x, etc.) from being
            added to the KAD routing table. Protects against routing table poisoning attacks.
            Requires restart to take effect.
          </span>
        </div>
      </section>
    </div>
  {/if}
</div>

<style>
  .header-actions {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .saved-msg {
    color: var(--success);
    font-size: 13px;
    font-weight: 600;
  }

  .saved-msg.warning {
    color: var(--warning, #f0ad4e);
  }

  .settings-grid {
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 24px;
    max-width: 700px;
  }

  .settings-section h3 {
    font-size: 15px;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }

  .field {
    margin-bottom: 14px;
  }

  .field label {
    display: block;
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 4px;
  }

  .field input {
    width: 100%;
  }

  .field-hint {
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 2px;
    display: block;
  }

  .folder-pick {
    display: flex;
    gap: 8px;
  }

  .folder-pick input {
    flex: 1;
  }

  .toggle-field {
    margin-bottom: 14px;
  }

  .toggle-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: var(--text-primary);
    cursor: pointer;
    user-select: none;
  }

  .toggle-label input[type='checkbox'] {
    width: 16px;
    height: 16px;
    accent-color: var(--accent, #3b82f6);
    cursor: pointer;
  }

  .nodes-download {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }

  .nodes-success {
    color: var(--success);
    font-size: 12px;
    font-weight: 500;
  }

  .nodes-error {
    color: var(--error, #e74c3c);
    font-size: 12px;
    font-weight: 500;
  }
</style>
