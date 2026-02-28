<script lang="ts">
  import { getSettings, updateSettings, downloadNodesDat, downloadIpfilter } from '$lib/api/settings';
  import type { AppSettings } from '$lib/types';
  import { onMount } from 'svelte';
  import { theme, applyTheme, type Theme } from '$lib/stores/theme';
  import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
  import SpeedInput from '$lib/components/SpeedInput.svelte';

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
      saveMessage = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Failed to save settings';
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
    } catch (e: unknown) {
      filterError = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Download failed';
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
    } catch (e: unknown) {
      nodesError = e instanceof Error ? e.message : typeof e === 'string' ? e : 'Download failed';
      setTimeout(() => (nodesError = null), 5000);
    } finally {
      downloadingNodes = false;
    }
  }

  function setTheme(t: Theme) {
    theme.set(t);
    applyTheme(t);
  }
</script>

<div class="page-header sticky-header">
  <h2>Settings</h2>
  <div class="header-actions">
    {#if saveMessage}
      <span class="toast" class:warning={saveIsWarning}>{saveMessage}</span>
    {/if}
    <button class="save-btn" onclick={handleSave} disabled={saving || !settings}>
      {#if saving}
        <span class="spinner"></span> Saving...
      {:else}
        Save Changes
      {/if}
    </button>
  </div>
</div>

<div class="page-content">
  {#if !settings}
    <div class="empty-state">
      <p>Loading settings...</p>
    </div>
  {:else}
    <div class="cards-grid">

      <!-- General -->
      <section class="card">
        <div class="card-header">
          <span class="card-icon">&#9775;</span>
          <div>
            <h3>General</h3>
            <p class="card-desc">Theme and identity</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field">
            <span class="field-label">Theme</span>
            <div class="theme-picker">
              <button
                class="theme-swatch"
                class:selected={$theme === 'light'}
                onclick={() => setTheme('light')}
                aria-label="Light theme"
              >
                <div class="swatch-preview light-swatch">
                  <div class="swatch-sidebar"></div>
                  <div class="swatch-content">
                    <div class="swatch-line"></div>
                    <div class="swatch-line short"></div>
                  </div>
                </div>
                {#if $theme === 'light'}<span class="swatch-check">&#10003;</span>{/if}
                <span class="swatch-label">Light</span>
              </button>
              <button
                class="theme-swatch"
                class:selected={$theme === 'dark'}
                onclick={() => setTheme('dark')}
                aria-label="Dark theme"
              >
                <div class="swatch-preview dark-swatch">
                  <div class="swatch-sidebar"></div>
                  <div class="swatch-content">
                    <div class="swatch-line"></div>
                    <div class="swatch-line short"></div>
                  </div>
                </div>
                {#if $theme === 'dark'}<span class="swatch-check">&#10003;</span>{/if}
                <span class="swatch-label">Dark</span>
              </button>
            </div>
          </div>
          <div class="field">
            <label for="nickname">Nickname</label>
            <input id="nickname" bind:value={settings.nickname} placeholder="Your display name" />
          </div>
        </div>
      </section>

      <!-- Downloads -->
      <section class="card">
        <div class="card-header">
          <span class="card-icon">&#8615;</span>
          <div>
            <h3>Downloads</h3>
            <p class="card-desc">Storage and concurrency</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field">
            <label for="download-folder">Download Folder</label>
            <div class="folder-input">
              <input id="download-folder" value={settings.download_folder} readonly />
              <button class="folder-btn" onclick={pickDownloadFolder}>Browse</button>
            </div>
          </div>
          <div class="field-row">
            <div class="field half">
              <label for="max-concurrent">Max Downloads</label>
              <input id="max-concurrent" type="number" min="1" max="20" bind:value={settings.max_concurrent_downloads} />
            </div>
            <div class="field half">
              <label for="max-uploads">
                Max Uploads
                <span class="restart-badge">Restart</span>
              </label>
              <input id="max-uploads" type="number" min="1" max="20" bind:value={settings.max_concurrent_uploads} />
            </div>
          </div>
        </div>
      </section>

      <!-- Bandwidth -->
      <section class="card">
        <div class="card-header">
          <span class="card-icon">&#8693;</span>
          <div>
            <h3>Bandwidth</h3>
            <p class="card-desc">Upload and download speed limits</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field">
            <SpeedInput label="Max Upload Speed" bind:value={settings.max_upload_speed} />
          </div>
          <div class="field">
            <SpeedInput label="Max Download Speed" bind:value={settings.max_download_speed} />
          </div>
        </div>
      </section>

      <!-- Network -->
      <section class="card">
        <div class="card-header">
          <span class="card-icon">&#8942;</span>
          <div>
            <h3>Network</h3>
            <p class="card-desc">Ports, UPnP, and bootstrap nodes</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field-row">
            <div class="field half">
              <label for="tcp-port">
                TCP Port
                <span class="restart-badge">Restart</span>
              </label>
              <input id="tcp-port" type="number" min="1" max="65535" bind:value={settings.tcp_port} />
              <span class="hint">File transfers (default 4662)</span>
            </div>
            <div class="field half">
              <label for="udp-port">
                UDP Port
                <span class="restart-badge">Restart</span>
              </label>
              <input id="udp-port" type="number" min="1" max="65535" bind:value={settings.udp_port} />
              <span class="hint">KAD DHT (default 4672)</span>
            </div>
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">UPnP Port Mapping <span class="restart-badge">Restart</span></span>
              <span class="hint">Auto-configure router ports. Disable for manual forwarding.</span>
            </div>
            <ToggleSwitch bind:checked={settings.upnp_enabled} />
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">Auto-Connect KAD <span class="restart-badge">Restart</span></span>
              <span class="hint">Automatically bootstrap KAD on startup. When off, press Connect to start.</span>
            </div>
            <ToggleSwitch bind:checked={settings.auto_connect_kad} />
          </div>

          <div class="divider"></div>

          <div class="field">
            <label for="nodes-dat">Bootstrap Path</label>
            <input id="nodes-dat" bind:value={settings.nodes_dat_path} placeholder="Auto-detected" />
            <span class="hint">Custom nodes.dat path. Leave blank for auto.</span>
          </div>
          <div class="field">
            <div class="action-row">
              <button class="action-btn" onclick={handleDownloadNodes} disabled={downloadingNodes}>
                {downloadingNodes ? 'Downloading...' : 'Download nodes.dat'}
              </button>
              {#if nodesResult}<span class="feedback success">{nodesResult}</span>{/if}
              {#if nodesError}<span class="feedback error">{nodesError}</span>{/if}
            </div>
            <span class="hint">Fetch latest bootstrap nodes from emule-security.org</span>
          </div>
        </div>
      </section>

      <!-- Security -->
      <section class="card">
        <div class="card-header">
          <span class="card-icon">&#128737;</span>
          <div>
            <h3>Security</h3>
            <p class="card-desc">Obfuscation and IP filtering</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">Protocol Obfuscation <span class="restart-badge">Restart</span></span>
              <span class="hint">Encrypt KAD UDP traffic with RC4. Compatible with eMule.</span>
            </div>
            <ToggleSwitch bind:checked={settings.obfuscation_enabled} />
          </div>

          <div class="divider"></div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">IP Filter <span class="restart-badge">Restart</span></span>
              <span class="hint">Block known-bad IP ranges via ipfilter.dat</span>
            </div>
            <ToggleSwitch bind:checked={settings.ip_filter_enabled} />
          </div>
          {#if settings.ip_filter_enabled}
            <div class="field nested">
              <div class="action-row">
                <button class="action-btn" onclick={handleDownloadFilter} disabled={downloadingFilter}>
                  {downloadingFilter ? 'Downloading...' : 'Download ipfilter.dat'}
                </button>
                {#if filterResult}<span class="feedback success">{filterResult}</span>{/if}
                {#if filterError}<span class="feedback error">{filterError}</span>{/if}
              </div>
            </div>
          {/if}

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">Block Private IPs <span class="restart-badge">Restart</span></span>
              <span class="hint">Reject 10.x, 192.168.x, etc. from the routing table.</span>
            </div>
            <ToggleSwitch bind:checked={settings.block_private_ips} />
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">Filter Servers by IP</span>
              <span class="hint">Apply IP filter to ed2k server connections.</span>
            </div>
            <ToggleSwitch bind:checked={settings.filter_servers_by_ip} />
          </div>
        </div>
      </section>

      <!-- Server -->
      <section class="card">
        <div class="card-header">
          <span class="card-icon">&#9881;</span>
          <div>
            <h3>Server</h3>
            <p class="card-desc">ed2k server list management</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">Auto-Connect Server <span class="restart-badge">Restart</span></span>
              <span class="hint">Automatically connect to an ed2k server on startup. When off, press Connect to start.</span>
            </div>
            <ToggleSwitch bind:checked={settings.auto_connect_server} />
          </div>
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">Update List From Servers</span>
              <span class="hint">Accept new servers from the connected server.</span>
            </div>
            <ToggleSwitch bind:checked={settings.add_servers_from_server} />
          </div>
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">Update List From Clients</span>
              <span class="hint">Accept new servers from ed2k peers during transfers.</span>
            </div>
            <ToggleSwitch bind:checked={settings.add_servers_from_clients} />
          </div>
        </div>
      </section>

    </div>
  {/if}
</div>

<style>
  /* ── Sticky header ─────────────────────────────── */
  .sticky-header {
    position: sticky;
    top: 0;
    z-index: 10;
    background: var(--bg-primary);
    border-bottom: 1px solid var(--border);
    box-shadow: var(--shadow-sm);
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .save-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 7px 20px;
    font-weight: 600;
    font-size: 13px;
    border-radius: var(--radius-md);
  }

  .spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    border: 2px solid rgba(255,255,255,0.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .toast {
    font-size: 13px;
    font-weight: 600;
    color: var(--success);
    padding: 4px 12px;
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--success) 12%, transparent);
  }

  .toast.warning {
    color: var(--warning);
    background: color-mix(in srgb, var(--warning) 12%, transparent);
  }

  /* ── Card grid ─────────────────────────────────── */
  .cards-grid {
    padding: 24px;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(420px, 1fr));
    gap: 20px;
    max-width: 1100px;
  }

  .card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-sm);
    overflow: hidden;
  }

  .card-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
  }

  .card-icon {
    font-size: 20px;
    width: 36px;
    height: 36px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    border-radius: var(--radius-md);
    flex-shrink: 0;
  }

  .card-header h3 {
    font-size: 15px;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0;
    line-height: 1.2;
  }

  .card-desc {
    font-size: 12px;
    color: var(--text-muted);
    margin: 0;
    line-height: 1.3;
  }

  .card-body {
    padding: 18px 20px;
  }

  /* ── Fields ────────────────────────────────────── */
  .field {
    margin-bottom: 16px;
  }

  .field:last-child {
    margin-bottom: 0;
  }

  .field > label,
  .field > .field-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 6px;
    font-weight: 500;
  }

  .field input[type='number'],
  .field input:not([type]) {
    width: 100%;
  }

  .field-row {
    display: flex;
    gap: 14px;
    margin-bottom: 16px;
  }

  .field.half {
    flex: 1;
    margin-bottom: 0;
  }

  .hint {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 4px;
    display: block;
    line-height: 1.4;
  }

  /* ── Restart badge ─────────────────────────────── */
  .restart-badge {
    display: inline-block;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    padding: 1px 6px;
    border-radius: 8px;
    color: var(--warning);
    background: color-mix(in srgb, var(--warning) 14%, transparent);
    vertical-align: middle;
    line-height: 1.5;
  }

  /* ── Toggle row ────────────────────────────────── */
  .toggle-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  .toggle-info {
    flex: 1;
    min-width: 0;
  }

  .toggle-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    font-weight: 500;
    color: var(--text-primary);
    line-height: 1.4;
  }

  .toggle-info .hint {
    margin-top: 2px;
  }

  .nested {
    margin-left: 0;
    margin-top: -8px;
    padding-left: 4px;
  }

  .divider {
    height: 1px;
    background: var(--border);
    margin: 14px 0;
    opacity: 0.6;
  }

  /* ── Folder input ──────────────────────────────── */
  .folder-input {
    display: flex;
    align-items: stretch;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    overflow: hidden;
    background: var(--bg-input);
    transition: border-color 0.15s;
  }

  .folder-input:focus-within {
    border-color: var(--accent);
  }

  .folder-input input {
    flex: 1;
    border: none;
    background: transparent;
    padding: 7px 10px;
    font-size: 13px;
    color: var(--text-primary);
    outline: none;
    min-width: 0;
  }

  .folder-btn {
    border: none;
    border-left: 1px solid var(--border);
    border-radius: 0;
    background: var(--bg-surface);
    color: var(--text-secondary);
    padding: 0 14px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
    white-space: nowrap;
  }

  .folder-btn:hover {
    background: var(--bg-hover);
    color: var(--accent);
  }

  /* ── Action buttons + feedback ─────────────────── */
  .action-row {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }

  .action-btn {
    font-size: 12px;
    font-weight: 600;
    padding: 6px 14px;
    background: var(--bg-surface);
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    transition: background 0.15s, color 0.15s, border-color 0.15s;
  }

  .action-btn:hover {
    background: var(--bg-hover);
    color: var(--accent);
    border-color: var(--accent);
  }

  .feedback {
    font-size: 12px;
    font-weight: 500;
  }

  .feedback.success { color: var(--success); }
  .feedback.error { color: var(--danger); }

  /* ── Theme picker ──────────────────────────────── */
  .theme-picker {
    display: flex;
    gap: 12px;
  }

  .theme-swatch {
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 0;
    border: 2px solid var(--border);
    border-radius: var(--radius-md);
    background: transparent;
    cursor: pointer;
    transition: border-color 0.2s, box-shadow 0.2s;
    overflow: hidden;
    width: 120px;
  }

  .theme-swatch:hover {
    border-color: var(--border-light);
    box-shadow: var(--shadow-md);
  }

  .theme-swatch.selected {
    border-color: var(--accent);
    box-shadow: 0 0 0 1px var(--accent);
  }

  .swatch-preview {
    width: 100%;
    height: 64px;
    display: flex;
    overflow: hidden;
  }

  .swatch-sidebar {
    width: 24px;
    flex-shrink: 0;
  }

  .swatch-content {
    flex: 1;
    padding: 10px 8px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .swatch-line {
    height: 6px;
    border-radius: 3px;
    width: 100%;
  }

  .swatch-line.short {
    width: 60%;
  }

  /* Light swatch colors */
  .light-swatch {
    background: #f5f6fa;
  }
  .light-swatch .swatch-sidebar {
    background: #ffffff;
    border-right: 1px solid #dadce0;
  }
  .light-swatch .swatch-line {
    background: #dadce0;
  }

  /* Dark swatch colors */
  .dark-swatch {
    background: #1a1a2e;
  }
  .dark-swatch .swatch-sidebar {
    background: #16213e;
    border-right: 1px solid #2a3456;
  }
  .dark-swatch .swatch-line {
    background: #2a3456;
  }

  .swatch-check {
    position: absolute;
    top: 6px;
    right: 6px;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--accent);
    color: #fff;
    font-size: 11px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
  }

  .swatch-label {
    font-size: 12px;
    font-weight: 500;
    color: var(--text-secondary);
    padding: 6px 0 8px;
  }
</style>
