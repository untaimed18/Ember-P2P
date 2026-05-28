<script lang="ts">
  import { open } from '@tauri-apps/plugin-dialog';
  import { invoke } from '@tauri-apps/api/core';
  import { relaunch } from '@tauri-apps/plugin-process';
  import { onDestroy, untrack } from 'svelte';
  import { theme, applyTheme, getInitialTheme, type Theme } from '$lib/stores/theme';
  import type { AppSettings } from '$lib/types';
  import ToggleSwitch from './ToggleSwitch.svelte';
  import SpeedInput from './SpeedInput.svelte';
  import { updateSettings as saveSettings, downloadNodesDat, downloadIpfilter } from '$lib/api/settings';
  import * as m from '$lib/paraglide/messages';

  function fmtSpeedShort(bytesPerSec: number): string {
    return bytesPerSec > 0
      ? m.wizard_speed_kbps({ kb: Math.round(bytesPerSec / 1024) })
      : m.wizard_summary_unlimited();
  }

  let {
    settings,
    oncomplete,
  }: {
    settings: AppSettings;
    oncomplete: (updated: AppSettings) => Promise<void>;
  } = $props();

  const TOTAL_STEPS = 8;
  let step = $state(1);
  let transitioning = $state(false);

  const _init = untrack(() => ({ ...settings }));
  let nickname = $state(_init.nickname);
  let downloadFolder = $state(_init.download_folder);
  let tcpPort = $state(_init.tcp_port);
  let udpPort = $state(_init.udp_port);
  let upnpEnabled = $state(_init.upnp_enabled);
  let maxUploadSpeed = $state(_init.max_upload_speed);
  let maxDownloadSpeed = $state(_init.max_download_speed);
  let autoConnectKad = $state(_init.auto_connect_kad);
  let selectedTheme: Theme = $state(getInitialTheme());

  let speedTestRunning = $state(false);
  let speedTestResult = $state('');
  let saving = $state(false);
  let saveError = $state('');
  let relaunching = $state(false);

  type DlStatus = 'idle' | 'pending' | 'ok' | 'error';
  let dlNodesStatus = $state<DlStatus>('idle');
  let dlIpStatus = $state<DlStatus>('idle');
  let downloading = $state(false);

  let stepTimer: ReturnType<typeof setTimeout> | undefined;
  onDestroy(() => clearTimeout(stepTimer));

  function clampInt(v: unknown, min: number, max: number, fallback: number): number {
    const n = typeof v === 'number' ? v : parseInt(String(v ?? ''), 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, Math.trunc(n)));
  }

  /** Whether the current step's required fields pass validation. */
  let canAdvance = $derived.by(() => {
    switch (step) {
      case 2: // Identity
        return nickname.trim().length > 0;
      case 3: // Storage
        return downloadFolder.trim().length > 0;
      case 4: // Network
        // TCP and UDP are independent protocols and the OS keeps two
        // separate port tables, so reusing the same number on both is
        // fine — useful when a VPN only forwards a single port.
        return (
          tcpPort >= 1 && tcpPort <= 65535 &&
          udpPort >= 1 && udpPort <= 65535
        );
      default:
        return true;
    }
  });

  function goNext() {
    if (step >= TOTAL_STEPS) return;
    if (!canAdvance) return;
    transitioning = true;
    clearTimeout(stepTimer);
    stepTimer = setTimeout(() => {
      step++;
      transitioning = false;
    }, 180);
  }

  function goBack() {
    if (step <= 1) return;
    transitioning = true;
    clearTimeout(stepTimer);
    stepTimer = setTimeout(() => {
      step--;
      transitioning = false;
    }, 180);
  }

  async function pickFolder() {
    try {
      const selected = await open({ directory: true, multiple: false, title: m.wizard_pick_folder_dialog_title() });
      if (selected && typeof selected === 'string') {
        downloadFolder = selected;
      }
    } catch {
      // User cancelled the dialog or plugin error — no action needed.
    }
  }

  async function runSpeedTest() {
    speedTestRunning = true;
    speedTestResult = '';
    try {
      const result: { recommended_upload_limit: number; recommended_download_limit: number } = await invoke('run_speed_test');
      maxUploadSpeed = result.recommended_upload_limit;
      maxDownloadSpeed = result.recommended_download_limit;
      speedTestResult = m.wizard_speed_test_recommended({
        up: fmtSpeedShort(maxUploadSpeed),
        down: fmtSpeedShort(maxDownloadSpeed),
      });
    } catch {
      speedTestResult = m.wizard_speed_test_failed();
    } finally {
      speedTestRunning = false;
    }
  }

  function selectTheme(t: Theme) {
    selectedTheme = t;
    applyTheme(t);
    theme.set(t);
  }

  async function finish() {
    if (saving || downloading) return;
    // Final validation before writing any settings to disk. Prevents an
    // empty-nickname or port=0 config from sneaking past the per-step guard
    // if the user somehow reaches the last step with invalid state.
    if (!nickname.trim()) { saveError = m.wizard_validation_nickname(); step = 2; return; }
    if (!downloadFolder.trim()) { saveError = m.wizard_validation_folder(); step = 3; return; }
    const tcp = clampInt(tcpPort, 1, 65535, 4662);
    const udp = clampInt(udpPort, 1, 65535, 4672);
    // TCP and UDP on the same port number is allowed: they're different
    // transport protocols so there's no socket collision, and UPnP maps
    // them as separate entries. This matters for users on VPNs that
    // forward one port number for both protocols.
    tcpPort = tcp;
    udpPort = udp;
    saving = true;
    saveError = '';
    // Keep setup_complete=false across the first save so that if the user
    // kills the app mid-bootstrap (or it crashes during downloads) the wizard
    // reappears on next launch and can retry. Only flip to true after the
    // optional bootstrap downloads finish.
    const partial: AppSettings = {
      ...settings,
      nickname: nickname.trim(),
      download_folder: downloadFolder,
      tcp_port: tcpPort,
      udp_port: udpPort,
      upnp_enabled: upnpEnabled,
      max_upload_speed: maxUploadSpeed,
      max_download_speed: maxDownloadSpeed,
      auto_connect_kad: autoConnectKad,
      auto_connect_server: false,
      setup_complete: false,
    };

    try {
      await saveSettings(partial);
    } catch (e) {
      saveError = e instanceof Error ? e.message : String(e);
      saving = false;
      return;
    }
    saving = false;

    downloading = true;
    dlNodesStatus = 'pending';
    dlIpStatus = 'pending';

    const [nodesResult, ipResult] = await Promise.allSettled([
      downloadNodesDat(),
      downloadIpfilter(),
    ]);

    dlNodesStatus = nodesResult.status === 'fulfilled' ? 'ok' : 'error';
    dlIpStatus = ipResult.status === 'fulfilled' ? 'ok' : 'error';

    // Brief pause so the user can see the green checkmarks
    await new Promise(r => setTimeout(r, 900));
    downloading = false;

    // Bootstrap is complete (success or user-acknowledged failure). Persist
    // setup_complete=true now so the wizard doesn't reappear next launch.
    const final: AppSettings = { ...partial, setup_complete: true };
    try {
      await saveSettings(final);
    } catch (e) {
      // If this second save fails the wizard will show again — annoying but
      // safe. Surface the error.
      saveError = e instanceof Error ? e.message : String(e);
      return;
    }

    relaunching = true;
    try {
      await new Promise(r => setTimeout(r, 600));
      await relaunch();
    } catch {
      relaunching = false;
      await oncomplete(final);
    }
  }

  const stepLabels: (() => string)[] = [
    () => m.wizard_step_welcome(),
    () => m.wizard_step_identity(),
    () => m.wizard_step_storage(),
    () => m.wizard_step_network(),
    () => m.wizard_step_bandwidth(),
    () => m.wizard_step_connection(),
    () => m.wizard_step_theme(),
    () => m.wizard_step_ready(),
  ];
</script>

{#if relaunching}
<div class="wizard-overlay" role="status" aria-label={m.wizard_restarting_aria()}>
  <div class="relaunch-card">
    <div class="spinner lg"></div>
    <h2 class="relaunch-title">{m.wizard_restarting_title()}</h2>
    <p class="relaunch-sub">{m.wizard_restarting_sub()}</p>
  </div>
</div>
{:else}
<div class="wizard-overlay" role="dialog" aria-modal="true" aria-label={m.wizard_aria()}>
  <div class="wizard-card" class:transitioning>
    <!-- Progress -->
    <div class="wizard-progress">
      {#each stepLabels as label, i}
        <div class="progress-dot" class:active={i + 1 === step} class:done={i + 1 < step}>
          <div class="dot">
            {#if i + 1 < step}
              <svg viewBox="0 0 16 16" fill="currentColor" width="10" height="10"><path d="M6.5 12.5l-4-4 1.4-1.4 2.6 2.6 5.6-5.6 1.4 1.4z"/></svg>
            {:else}
              {i + 1}
            {/if}
          </div>
          <span class="dot-label">{label()}</span>
        </div>
        {#if i < stepLabels.length - 1}
          <div class="progress-line" class:filled={i + 1 < step}></div>
        {/if}
      {/each}
    </div>

    <!-- Step content -->
    <div class="wizard-body">
      {#if step === 1}
        <div class="step-content">
          <div class="brand-row">
            <div class="brand-icon" aria-hidden="true">
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="10" cy="4" r="2.5"></circle>
                <circle cx="4" cy="14" r="2.5"></circle>
                <circle cx="16" cy="14" r="2.5"></circle>
                <line x1="10" y1="6.5" x2="5.5" y2="11.5"></line>
                <line x1="10" y1="6.5" x2="14.5" y2="11.5"></line>
                <line x1="6.5" y1="14" x2="13.5" y2="14"></line>
              </svg>
            </div>
            <div>
              <h2 class="step-title welcome-title">{m.wizard_welcome_title()}</h2>
              <p class="welcome-subtitle">{m.wizard_welcome_subtitle()}</p>
            </div>
          </div>

          <p class="step-desc">{m.wizard_welcome_desc()}</p>

          <div class="info-cards">
            <div class="info-card">
              <div class="info-icon">
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10 2v16M2 10h16"/></svg>
              </div>
              <div>
                <strong>{m.wizard_feature_dual_title()}</strong>
                <span>{m.wizard_feature_dual_desc()}</span>
              </div>
            </div>
            <div class="info-card">
              <div class="info-icon epx">
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 10l4 4 10-10"/></svg>
              </div>
              <div>
                <strong>{m.wizard_feature_epx_title()}</strong>
                <span>{m.wizard_feature_epx_desc()}</span>
              </div>
            </div>
            <div class="info-card">
              <div class="info-icon">
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="5" width="14" height="10" rx="2"/><path d="M7 9h6M7 12h4"/></svg>
              </div>
              <div>
                <strong>{m.wizard_feature_secure_title()}</strong>
                <span>{m.wizard_feature_secure_desc()}</span>
              </div>
            </div>
          </div>

          <p class="step-hint">{m.wizard_welcome_hint()}</p>
        </div>

      {:else if step === 2}
        <div class="step-content">
          <h2 class="step-title">{m.wizard_nickname_title()}</h2>
          <p class="step-desc">{m.wizard_nickname_desc()}</p>
          <div class="field">
            <label for="nickname">{m.wizard_nickname_label()}</label>
            <input id="nickname" type="text" bind:value={nickname} maxlength="128" class="text-input" placeholder={m.wizard_nickname_placeholder()} />
          </div>
          <p class="step-hint">{m.wizard_nickname_hint()}</p>
        </div>

      {:else if step === 3}
        <div class="step-content">
          <h2 class="step-title">{m.wizard_folder_title()}</h2>
          <p class="step-desc">{m.wizard_folder_desc()}</p>
          <div class="field">
            <label for="dl-folder">{m.wizard_folder_label()}</label>
            <div class="folder-picker">
              <input id="dl-folder" type="text" bind:value={downloadFolder} class="text-input folder-input" readonly />
              <button type="button" class="browse-btn" onclick={pickFolder}>{m.wizard_folder_browse()}</button>
            </div>
          </div>
        </div>

      {:else if step === 4}
        <div class="step-content">
          <h2 class="step-title">{m.wizard_ports_title()}</h2>
          <p class="step-desc">{m.wizard_ports_desc()}</p>
          <div class="fields-row">
            <div class="field">
              <label for="tcp-port">{m.wizard_ports_tcp()}</label>
              <input id="tcp-port" type="number" bind:value={tcpPort} min="1" max="65535" class="text-input port-input" />
            </div>
            <div class="field">
              <label for="udp-port">{m.wizard_ports_udp()}</label>
              <input id="udp-port" type="number" bind:value={udpPort} min="1" max="65535" class="text-input port-input" />
            </div>
          </div>
          <div class="toggle-row">
            <ToggleSwitch bind:checked={upnpEnabled} label={m.wizard_ports_upnp_label()} />
          </div>
          <p class="step-hint">{m.wizard_ports_hint()}</p>
        </div>

      {:else if step === 5}
        <div class="step-content">
          <h2 class="step-title">{m.wizard_bandwidth_title()}</h2>
          <p class="step-desc">{m.wizard_bandwidth_desc()}</p>
          <div class="fields-col">
            <div class="field">
              <SpeedInput bind:value={maxUploadSpeed} label={m.wizard_bandwidth_upload_label()} />
            </div>
            <div class="field">
              <SpeedInput bind:value={maxDownloadSpeed} label={m.wizard_bandwidth_download_label()} />
            </div>
          </div>
          <button type="button" class="speed-test-btn" onclick={runSpeedTest} disabled={speedTestRunning}>
            {speedTestRunning ? m.wizard_speed_test_running() : m.wizard_speed_test_run()}
          </button>
          {#if speedTestResult}
            <p class="speed-result">{speedTestResult}</p>
          {/if}
        </div>

      {:else if step === 6}
        <div class="step-content">
          <h2 class="step-title">{m.wizard_connect_title()}</h2>
          <p class="step-desc">{m.wizard_connect_desc()}</p>
          <div class="connect-options">
            <div class="connect-option">
              <ToggleSwitch bind:checked={autoConnectKad} />
              <div>
                <strong>{m.wizard_connect_kad_title()}</strong>
                <span>{m.wizard_connect_kad_desc()}</span>
              </div>
            </div>
          </div>
          <p class="step-hint">{m.wizard_connect_hint()}</p>
        </div>

      {:else if step === 7}
        <div class="step-content">
          <h2 class="step-title">{m.wizard_theme_title()}</h2>
          <p class="step-desc">{m.wizard_theme_desc()}</p>
          <div class="theme-options">
            <button
              type="button"
              class="theme-card"
              class:selected={selectedTheme === 'dark'}
              onclick={() => selectTheme('dark')}
            >
              <div class="theme-preview dark-preview">
                <div class="tp-sidebar"></div>
                <div class="tp-main">
                  <div class="tp-bar"></div>
                  <div class="tp-row"></div>
                  <div class="tp-row short"></div>
                </div>
              </div>
              <span>{m.wizard_theme_dark()}</span>
            </button>
            <button
              type="button"
              class="theme-card"
              class:selected={selectedTheme === 'light'}
              onclick={() => selectTheme('light')}
            >
              <div class="theme-preview light-preview">
                <div class="tp-sidebar"></div>
                <div class="tp-main">
                  <div class="tp-bar"></div>
                  <div class="tp-row"></div>
                  <div class="tp-row short"></div>
                </div>
              </div>
              <span>{m.wizard_theme_light()}</span>
            </button>
          </div>
        </div>

      {:else if step === 8}
        <div class="step-content">
          <h2 class="step-title">{m.wizard_ready_title()}</h2>
          <p class="step-desc">{m.wizard_ready_desc()}</p>
          <div class="summary">
            <div class="summary-row">
              <span class="summary-label">{m.wizard_summary_nickname()}</span>
              <span class="summary-value">{nickname}</span>
            </div>
            <div class="summary-row">
              <span class="summary-label">{m.wizard_summary_folder()}</span>
              <span class="summary-value mono">{downloadFolder}</span>
            </div>
            <div class="summary-row">
              <span class="summary-label">{m.wizard_summary_ports()}</span>
              <span class="summary-value">
                {upnpEnabled
                  ? m.wizard_summary_ports_value_upnp({ tcp: tcpPort, udp: udpPort })
                  : m.wizard_summary_ports_value({ tcp: tcpPort, udp: udpPort })}
              </span>
            </div>
            <div class="summary-row">
              <span class="summary-label">{m.wizard_summary_upload_limit()}</span>
              <span class="summary-value">{maxUploadSpeed === 0 ? m.wizard_summary_unlimited() : m.wizard_speed_kbps({ kb: Math.round(maxUploadSpeed / 1024) })}</span>
            </div>
            <div class="summary-row">
              <span class="summary-label">{m.wizard_summary_download_limit()}</span>
              <span class="summary-value">{maxDownloadSpeed === 0 ? m.wizard_summary_unlimited() : m.wizard_speed_kbps({ kb: Math.round(maxDownloadSpeed / 1024) })}</span>
            </div>
            <div class="summary-row">
              <span class="summary-label">{m.wizard_summary_autoconnect()}</span>
              <span class="summary-value">{autoConnectKad ? m.common_yes() : m.common_no()}</span>
            </div>
            <div class="summary-row">
              <span class="summary-label">{m.wizard_summary_theme()}</span>
              <span class="summary-value">{selectedTheme === 'dark' ? m.wizard_theme_dark() : m.wizard_theme_light()}</span>
            </div>
          </div>
          {#if saveError}
            <p class="save-error">{saveError}</p>
          {/if}

          {#if downloading || dlNodesStatus !== 'idle' || dlIpStatus !== 'idle'}
            <div class="dl-progress">
              <p class="dl-heading">{m.wizard_setup_progress_heading()}</p>
              <div class="dl-item">
                {#if dlNodesStatus === 'pending'}
                  <span class="spinner xs" aria-hidden="true"></span>
                {:else if dlNodesStatus === 'ok'}
                  <svg class="dl-icon ok" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M6.5 12.5l-4-4 1.4-1.4 2.6 2.6 5.6-5.6 1.4 1.4z"/></svg>
                {:else if dlNodesStatus === 'error'}
                  <svg class="dl-icon err" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm.75 3.5v4h-1.5v-4h1.5zm0 5.5v1.5h-1.5V10h1.5z"/></svg>
                {:else}
                  <span class="dl-icon placeholder" aria-hidden="true"></span>
                {/if}
                <span>{m.wizard_dl_nodes_label()}</span>
                {#if dlNodesStatus === 'error'}<span class="dl-warn">{m.wizard_dl_nodes_skipped()}</span>{/if}
              </div>
              <div class="dl-item">
                {#if dlIpStatus === 'pending'}
                  <span class="spinner xs" aria-hidden="true"></span>
                {:else if dlIpStatus === 'ok'}
                  <svg class="dl-icon ok" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M6.5 12.5l-4-4 1.4-1.4 2.6 2.6 5.6-5.6 1.4 1.4z"/></svg>
                {:else if dlIpStatus === 'error'}
                  <svg class="dl-icon err" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm.75 3.5v4h-1.5v-4h1.5zm0 5.5v1.5h-1.5V10h1.5z"/></svg>
                {:else}
                  <span class="dl-icon placeholder" aria-hidden="true"></span>
                {/if}
                <span>{m.wizard_dl_ipfilter_label()}</span>
                {#if dlIpStatus === 'error'}<span class="dl-warn">{m.wizard_dl_ipfilter_skipped()}</span>{/if}
              </div>
            </div>
          {/if}
        </div>
      {/if}
    </div>

    <!-- Footer -->
    <div class="wizard-footer">
      {#if step > 1 && !saving}
        <button type="button" class="btn-back" onclick={goBack}>{m.common_back()}</button>
      {:else}
        <div></div>
      {/if}

      <div class="footer-right">
        {#if step < TOTAL_STEPS}
          <button type="button" class="btn-next" onclick={goNext} disabled={!canAdvance}>
            {step === 1 ? m.wizard_get_started() : m.common_next()}
          </button>
        {:else}
          <button type="button" class="btn-finish" onclick={finish} disabled={saving || downloading}>
            {#if saving}
              <span class="spinner sm"></span> {m.wizard_saving()}
            {:else if downloading}
              <span class="spinner sm"></span> {m.wizard_downloading()}
            {:else}
              {m.wizard_launch()}
            {/if}
          </button>
        {/if}
      </div>
    </div>
  </div>
</div>
{/if}

<style>
  .wizard-overlay {
    position: fixed;
    inset: 0;
    z-index: 99999;
    display: grid;
    place-items: center;
    background: var(--bg-primary);
    padding: 20px;
  }

  .relaunch-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    animation: wizard-in 400ms ease-out;
  }

  .relaunch-title {
    font-size: 22px;
    font-weight: 700;
    color: var(--accent);
    margin: 0;
  }

  .relaunch-sub {
    font-size: 14px;
    color: var(--text-muted);
    margin: 0;
  }

  .wizard-card {
    width: min(680px, 100%);
    max-height: calc(100vh - 40px);
    display: flex;
    flex-direction: column;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    box-shadow: var(--shadow-md);
    animation: wizard-in 400ms ease-out;
    overflow: hidden;
  }

  .wizard-card.transitioning .wizard-body {
    opacity: 0;
    transform: translateY(6px);
  }

  /* Progress bar */
  .wizard-progress {
    display: flex;
    align-items: center;
    gap: 0;
    padding: 20px 28px 0;
    flex-shrink: 0;
  }

  .progress-dot {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
  }

  .dot {
    width: 26px;
    height: 26px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    font-weight: 700;
    border: 2px solid var(--border);
    color: var(--text-muted);
    background: var(--bg-surface);
    transition: all 0.2s ease;
  }

  .progress-dot.active .dot {
    border-color: var(--accent);
    background: var(--accent);
    color: #fff;
  }

  .progress-dot.done .dot {
    border-color: var(--success);
    background: var(--success);
    color: #fff;
  }

  .dot-label {
    font-size: 9px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.3px;
    white-space: nowrap;
  }

  .progress-dot.active .dot-label {
    color: var(--accent);
  }

  .progress-dot.done .dot-label {
    color: var(--success);
  }

  .progress-line {
    flex: 1;
    height: 2px;
    background: var(--border);
    margin: 0 2px;
    margin-bottom: 18px;
    transition: background 0.2s ease;
  }

  .progress-line.filled {
    background: var(--success);
  }

  /* Body */
  .wizard-body {
    flex: 1;
    overflow-y: auto;
    padding: 24px 28px;
    transition: opacity 0.18s ease, transform 0.18s ease;
  }

  .step-content {
    animation: step-in 0.25s ease-out;
  }

  .step-title {
    font-size: 20px;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0 0 6px;
  }

  .welcome-title {
    font-size: 24px;
    color: var(--accent);
    margin: 0;
  }

  .welcome-subtitle {
    font-size: 11px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin: 2px 0 0;
  }

  .brand-row {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 16px;
  }

  .brand-icon {
    width: 48px;
    height: 48px;
    border-radius: 12px;
    display: grid;
    place-items: center;
    border: 1px solid var(--border);
    background: var(--bg-tertiary);
    color: var(--accent);
    flex-shrink: 0;
  }

  .brand-icon svg {
    width: 28px;
    height: 28px;
  }

  .step-desc {
    font-size: 13px;
    color: var(--text-secondary);
    line-height: 1.6;
    margin: 0 0 16px;
  }

  .step-hint {
    font-size: 12px;
    color: var(--text-muted);
    margin: 12px 0 0;
  }

  /* Info cards (welcome) */
  .info-cards {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-bottom: 8px;
  }

  .info-card {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px 14px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 8px;
  }

  .info-icon {
    width: 32px;
    height: 32px;
    border-radius: 8px;
    display: grid;
    place-items: center;
    background: var(--accent-dim);
    color: var(--accent);
    flex-shrink: 0;
  }

  .info-icon.epx {
    background: color-mix(in srgb, var(--success) 20%, transparent);
    color: var(--success);
  }

  .info-icon svg {
    width: 16px;
    height: 16px;
  }

  .info-card strong {
    display: block;
    font-size: 13px;
    color: var(--text-primary);
    margin-bottom: 2px;
  }

  .info-card span {
    font-size: 12px;
    color: var(--text-secondary);
    line-height: 1.5;
  }

  /* Fields */
  .field {
    margin-bottom: 14px;
  }

  .field label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    margin-bottom: 6px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .text-input {
    width: 100%;
    padding: 9px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 14px;
    font-family: inherit;
    outline: none;
    transition: border-color 0.15s;
    box-sizing: border-box;
  }

  .text-input:focus {
    border-color: var(--accent);
  }

  .port-input {
    width: 120px;
  }

  .port-input::-webkit-inner-spin-button,
  .port-input::-webkit-outer-spin-button {
    -webkit-appearance: none;
    margin: 0;
  }

  .folder-picker {
    display: flex;
    gap: 8px;
  }

  .folder-input {
    flex: 1;
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: 12px;
  }

  .browse-btn {
    padding: 0 16px;
    border: 1px solid var(--accent);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--accent);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
    white-space: nowrap;
  }

  .browse-btn:hover {
    background: var(--accent);
    color: #fff;
  }

  .fields-row {
    display: flex;
    gap: 16px;
  }

  .fields-col {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .toggle-row {
    margin: 14px 0 4px;
  }

  /* Speed test */
  .speed-test-btn {
    margin-top: 12px;
    padding: 8px 20px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    color: var(--text-secondary);
    font-size: 13px;
    cursor: pointer;
    transition: border-color 0.15s, color 0.15s;
  }

  .speed-test-btn:hover:not(:disabled) {
    border-color: var(--accent);
    color: var(--accent);
  }

  .speed-test-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .speed-result {
    font-size: 12px;
    color: var(--success);
    margin: 8px 0 0;
  }

  /* Connection options */
  .connect-options {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-top: 4px;
  }

  .connect-option {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    padding: 14px 16px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 8px;
  }

  .connect-option strong {
    display: block;
    font-size: 13px;
    color: var(--text-primary);
    margin-bottom: 2px;
  }

  .connect-option span {
    font-size: 12px;
    color: var(--text-secondary);
    line-height: 1.5;
  }

  /* Theme cards */
  .theme-options {
    display: flex;
    gap: 16px;
    margin-top: 4px;
  }

  .theme-card {
    flex: 1;
    border: 2px solid var(--border);
    border-radius: 10px;
    padding: 14px;
    background: var(--bg-surface);
    cursor: pointer;
    transition: border-color 0.2s, box-shadow 0.2s;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .theme-card:hover {
    border-color: var(--accent);
  }

  .theme-card.selected {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 25%, transparent);
  }

  .theme-preview {
    width: 100%;
    height: 80px;
    border-radius: 6px;
    display: flex;
    overflow: hidden;
    border: 1px solid rgba(128,128,128,0.2);
  }

  .dark-preview {
    background: #1a1a2e;
  }

  .dark-preview .tp-sidebar {
    width: 30%;
    background: #16213e;
    border-right: 1px solid #2a3456;
  }

  .dark-preview .tp-main {
    flex: 1;
    padding: 8px;
  }

  .dark-preview .tp-bar {
    height: 8px;
    border-radius: 3px;
    background: #0f3460;
    margin-bottom: 6px;
  }

  .dark-preview .tp-row {
    height: 6px;
    border-radius: 2px;
    background: #253255;
    margin-bottom: 4px;
  }

  .dark-preview .tp-row.short {
    width: 60%;
  }

  .light-preview {
    background: #f5f6fa;
  }

  .light-preview .tp-sidebar {
    width: 30%;
    background: #ffffff;
    border-right: 1px solid #dadce0;
  }

  .light-preview .tp-main {
    flex: 1;
    padding: 8px;
  }

  .light-preview .tp-bar {
    height: 8px;
    border-radius: 3px;
    background: #e8ecf4;
    margin-bottom: 6px;
  }

  .light-preview .tp-row {
    height: 6px;
    border-radius: 2px;
    background: #eceef5;
    margin-bottom: 4px;
  }

  .light-preview .tp-row.short {
    width: 60%;
  }

  /* Summary */
  .summary {
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }

  .summary-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
  }

  .summary-row:last-child {
    border-bottom: none;
  }

  .summary-row:nth-child(even) {
    background: var(--bg-surface);
  }

  .summary-label {
    font-size: 13px;
    color: var(--text-secondary);
    font-weight: 500;
  }

  .summary-value {
    font-size: 13px;
    color: var(--text-primary);
    font-weight: 600;
    text-align: right;
    max-width: 60%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .summary-value.mono {
    font-family: var(--font-mono);
    font-size: 11px;
  }

  /* Footer */
  .wizard-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 28px;
    border-top: 1px solid var(--border);
    flex-shrink: 0;
  }

  .btn-back {
    padding: 8px 20px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-secondary);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: border-color 0.15s, color 0.15s;
  }

  .btn-back:hover {
    border-color: var(--text-primary);
    color: var(--text-primary);
  }

  .footer-right {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .btn-next, .btn-finish {
    padding: 9px 28px;
    border: none;
    border-radius: var(--radius-sm);
    background: var(--accent);
    color: #fff;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
  }

  .btn-next:hover, .btn-finish:hover {
    background: var(--accent-hover);
  }

  .btn-finish {
    padding: 10px 32px;
    font-size: 15px;
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }

  .btn-finish:disabled {
    opacity: 0.7;
    cursor: not-allowed;
  }

  .save-error {
    margin-top: 12px;
    padding: 10px 14px;
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--danger) 12%, transparent);
    color: var(--danger);
    font-size: 13px;
    line-height: 1.4;
  }

  .dl-progress {
    margin-top: 14px;
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .dl-heading {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin: 0 0 2px;
  }

  .dl-item {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: var(--text-primary);
  }

  .dl-icon {
    width: 16px;
    height: 16px;
    flex-shrink: 0;
  }

  .dl-icon.ok {
    color: var(--success);
  }

  .dl-icon.err {
    color: var(--danger);
  }

  .dl-icon.placeholder {
    display: inline-block;
  }

  .dl-warn {
    font-size: 12px;
    color: var(--text-muted);
  }

  .spinner.xs {
    width: 14px;
    height: 14px;
    border-width: 2px;
    flex-shrink: 0;
  }

  /* Animations */
  @keyframes wizard-in {
    from {
      transform: translateY(12px) scale(0.98);
      opacity: 0;
    }
    to {
      transform: translateY(0) scale(1);
      opacity: 1;
    }
  }

  @keyframes step-in {
    from {
      opacity: 0;
      transform: translateY(8px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .wizard-card,
    .step-content {
      animation: none !important;
    }
    .wizard-card.transitioning .wizard-body {
      transition: none;
    }
  }

  @media (max-width: 700px) {
    .wizard-progress {
      padding: 16px 16px 0;
    }

    .dot-label {
      display: none;
    }

    .wizard-body {
      padding: 20px 16px;
    }

    .wizard-footer {
      padding: 14px 16px;
    }

    .fields-row {
      flex-direction: column;
      gap: 0;
    }

    .port-input {
      width: 100%;
    }

    .theme-options {
      flex-direction: column;
    }
  }
</style>
