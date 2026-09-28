<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import { pickDownloadFolder } from '$lib/api/settings';
  import { relaunch } from '@tauri-apps/plugin-process';
  import { onDestroy, untrack } from 'svelte';
  import { theme, applyTheme, getInitialTheme, type Theme } from '$lib/stores/theme';
  import type { AppSettings } from '$lib/types';
  import ToggleSwitch from './ToggleSwitch.svelte';
  import SpeedInput from './SpeedInput.svelte';
  import EmuleImport from './EmuleImport.svelte';
  import {
    stageEmuleImport,
    type EmuleImportSelection,
    type EmulePreview,
    type EmuleStageProgress,
  } from '$lib/api/emuleImport';
  import {
    updateSettings as saveSettings,
    getSettings,
    downloadNodesDat,
    downloadIpfilter,
    type NodesDatDownloadResult,
    type IpFilterDownloadResult,
  } from '$lib/api/settings';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';
  import { inertBackground, trapTabKey } from '$lib/a11y';
  import { formatSpeed } from '$lib/utils';

  function fmtSpeedShort(bytesPerSec: number): string {
    return bytesPerSec > 0 ? formatSpeed(bytesPerSec) : m.wizard_summary_unlimited();
  }

  let {
    settings,
    oncomplete,
    closeDialogOpen = false,
  }: {
    settings: AppSettings;
    oncomplete: (updated: AppSettings) => Promise<void>;
    closeDialogOpen?: boolean;
  } = $props();

  const TOTAL_STEPS = 9;
  const IMPORT_STEP = 2;
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
  let selectedTheme: Theme = $state(getInitialTheme());

  let emuleSelection: EmuleImportSelection | null = $state(null);
  let emulePreview: EmulePreview | null = $state(null);
  let importing = $state(false);

  /** What importing filled in from eMule's settings, so the later steps can
   *  say where a value came from, and starting fresh after all can put back
   *  whatever the user has not edited since. */
  type Prefill = {
    nickname?: string;
    downloadFolder?: string;
    tcpPort?: number;
    udpPort?: number;
    maxUpload?: number;
    maxDownload?: number;
  };
  let prefill = $state<Prefill | null>(null);

  // Only fields still at their defaults are filled in.
  function applyPrefill(p: EmulePreview) {
    const filled: Prefill = {};
    const nick = p.nickname?.trim();
    if (nick && nickname === _init.nickname) nickname = filled.nickname = nick;
    if (p.incoming_dir && downloadFolder === _init.download_folder) {
      downloadFolder = filled.downloadFolder = p.incoming_dir;
    }
    if (p.tcp_port && tcpPort === _init.tcp_port) tcpPort = filled.tcpPort = p.tcp_port;
    if (p.udp_port && udpPort === _init.udp_port) udpPort = filled.udpPort = p.udp_port;
    if (p.max_upload != null && maxUploadSpeed === _init.max_upload_speed) {
      maxUploadSpeed = filled.maxUpload = p.max_upload;
    }
    if (p.max_download != null && maxDownloadSpeed === _init.max_download_speed) {
      maxDownloadSpeed = filled.maxDownload = p.max_download;
    }
    prefill = filled;
  }

  function revertPrefill() {
    if (!prefill) return;
    if (prefill.nickname !== undefined && nickname === prefill.nickname) nickname = _init.nickname;
    if (prefill.downloadFolder !== undefined && downloadFolder === prefill.downloadFolder) {
      downloadFolder = _init.download_folder;
    }
    if (prefill.tcpPort !== undefined && tcpPort === prefill.tcpPort) tcpPort = _init.tcp_port;
    if (prefill.udpPort !== undefined && udpPort === prefill.udpPort) udpPort = _init.udp_port;
    if (prefill.maxUpload !== undefined && maxUploadSpeed === prefill.maxUpload) {
      maxUploadSpeed = _init.max_upload_speed;
    }
    if (prefill.maxDownload !== undefined && maxDownloadSpeed === prefill.maxDownload) {
      maxDownloadSpeed = _init.max_download_speed;
    }
    prefill = null;
  }

  $effect(() => {
    const preview = emulePreview;
    const chosen = emuleSelection !== null;
    untrack(() => {
      if (chosen && preview && !prefill) applyPrefill(preview);
      else if (!chosen && prefill) revertPrefill();
    });
  });

  function onEmulePreview(preview: EmulePreview) {
    // Another profile, or this one read again: its values are applied afresh.
    revertPrefill();
    emulePreview = preview;
  }

  let nicknameFromEmule = $derived(prefill?.nickname !== undefined && nickname === prefill.nickname);
  let folderFromEmule = $derived(
    prefill?.downloadFolder !== undefined && downloadFolder === prefill.downloadFolder,
  );
  let portsFromEmule = $derived(
    (prefill?.tcpPort !== undefined && tcpPort === prefill.tcpPort) ||
      (prefill?.udpPort !== undefined && udpPort === prefill.udpPort),
  );
  let speedsFromEmule = $derived(
    (prefill?.maxUpload !== undefined && maxUploadSpeed === prefill.maxUpload) ||
      (prefill?.maxDownload !== undefined && maxDownloadSpeed === prefill.maxDownload),
  );

  let speedTestRunning = $state(false);
  let speedTestResult = $state('');
  let speedTestFailed = $state(false);
  let saving = $state(false);
  let saveError = $state('');
  let relaunching = $state(false);
  let overlayEl: HTMLDivElement | undefined = $state(undefined);
  let cardEl: HTMLDivElement | undefined = $state(undefined);

  $effect(() => {
    if (!overlayEl || closeDialogOpen) return;
    return inertBackground(overlayEl);
  });
  $effect(() => {
    step;
    requestAnimationFrame(() => {
      const focusable = cardEl?.querySelectorAll<HTMLElement>(
        'input:not([disabled]), button:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      const visible = Array.from(focusable ?? []).filter((el) => !el.closest('[hidden]'));
      (visible.find((el) => el.hasAttribute('data-autofocus')) ?? visible[0])?.focus();
    });
  });

  type DlStatus = 'idle' | 'pending' | 'ok' | 'deferred' | 'failed' | 'error';
  let dlNodesStatus = $state<DlStatus>('idle');
  let dlIpStatus = $state<DlStatus>('idle');
  let downloading = $state(false);

  function structuredDownloadStatus(
    result: NodesDatDownloadResult | IpFilterDownloadResult,
  ): DlStatus {
    switch (result.outcome) {
      case 'applied':
        return 'ok';
      case 'failed':
        return 'failed';
      default:
        return 'deferred';
    }
  }

  let stepTimer: ReturnType<typeof setTimeout> | undefined;
  onDestroy(() => clearTimeout(stepTimer));

  function clampInt(v: unknown, min: number, max: number, fallback: number): number {
    const n = typeof v === 'number' ? v : parseInt(String(v ?? ''), 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, Math.trunc(n)));
  }

  // The backend caps a nickname at 128 bytes, not characters; `maxlength` on
  // the input counts UTF-16 units, so multi-byte text can pass it and still be
  // refused on the final save.
  let nicknameTooLong = $derived(new TextEncoder().encode(nickname.trim()).length > 128);

  /** Whether the current step's required fields pass validation. */
  let canAdvance = $derived.by(() => {
    switch (step) {
      case 3: // Identity
        return nickname.trim().length > 0 && !nicknameTooLong;
      case 4: // Storage
        return downloadFolder.trim().length > 0;
      case 5: // Network
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

  let nextDisabledReason = $derived.by(() => {
    switch (step) {
      case 3:
        if (!nickname.trim()) return m.wizard_validation_nickname();
        return nicknameTooLong ? m.error_settings_nickname_too_long() : '';
      case 4:
        return downloadFolder.trim().length > 0 ? '' : m.wizard_validation_folder();
      case 5:
        return tcpPort >= 1 && tcpPort <= 65535 && udpPort >= 1 && udpPort <= 65535
          ? ''
          : m.wizard_validation_ports();
      default:
        return '';
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

  let folderError = $state('');

  async function pickFolder() {
    folderError = '';
    try {
      // Backend picker, so the path is authorized where it is chosen: saving a
      // changed download folder the renderer named on its own is refused.
      const selected = await pickDownloadFolder();
      // A user cancel resolves to null and is handled by this check, so the
      // catch below only ever sees a real plugin/permission failure — which
      // previously made the Browse button look simply dead.
      if (selected) {
        downloadFolder = selected;
      }
    } catch (e) {
      folderError = translateError(e, m.settings_folder_picker_generic_error());
    }
  }

  async function runSpeedTest() {
    speedTestRunning = true;
    speedTestResult = '';
    speedTestFailed = false;
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
      speedTestFailed = true;
    } finally {
      speedTestRunning = false;
    }
  }

  function selectTheme(t: Theme) {
    selectedTheme = t;
    applyTheme(t);
    theme.set(t);
  }

  let importStatus = $state<'idle' | 'pending' | 'ok'>('idle');
  let importPercent: number | null = $state(null);

  /** Stage the chosen import once the download folder it needs is saved. */
  async function stageImport(selection: EmuleImportSelection): Promise<boolean> {
    importStatus = 'pending';
    importPercent = null;
    const unlisten = await listen<EmuleStageProgress>('emule-import-progress', (event) => {
      const { done, total } = event.payload;
      importPercent = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : null;
    }).catch(() => null);
    try {
      await stageEmuleImport(selection);
      importStatus = 'ok';
      return true;
    } catch (e) {
      importStatus = 'idle';
      saveError = m.wizard_import_failed({ error: translateError(e, m.emule_import_stage_failed()) });
      return false;
    } finally {
      unlisten?.();
      importPercent = null;
    }
  }

  async function finish() {
    if (saving || downloading || importing) return;
    // Final validation before writing any settings to disk. Prevents an
    // empty-nickname or port=0 config from sneaking past the per-step guard
    // if the user somehow reaches the last step with invalid state.
    if (!nickname.trim()) { saveError = m.wizard_validation_nickname(); step = 3; return; }
    if (nicknameTooLong) { saveError = m.error_settings_nickname_too_long(); step = 3; return; }
    if (!downloadFolder.trim()) { saveError = m.wizard_validation_folder(); step = 4; return; }
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

    // Bootstrap downloads (ipfilter enable) bump `settings_revision` out of
    // band. Always start from the live revision so a retry after a partial
    // finish doesn't fail with `settings_stale_revision`.
    let base: AppSettings;
    try {
      base = await getSettings();
    } catch (e) {
      saveError = translateError(e, m.settings_save_failed());
      saving = false;
      return;
    }

    // Keep setup_complete=false across the first save so that if the user
    // kills the app mid-bootstrap (or it crashes during downloads) the wizard
    // reappears on next launch and can retry. Only flip to true after the
    // optional bootstrap downloads finish.
    const partial: AppSettings = {
      ...base,
      nickname: nickname.trim(),
      download_folder: downloadFolder,
      tcp_port: tcpPort,
      udp_port: udpPort,
      upnp_enabled: upnpEnabled,
      max_upload_speed: maxUploadSpeed,
      max_download_speed: maxDownloadSpeed,
      auto_connect_server: false,
      setup_complete: false,
    };

    try {
      const first = await saveSettings(partial);
      Object.assign(partial, first.settings);
    } catch (e) {
      saveError = translateError(e, m.settings_save_failed());
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

    dlNodesStatus = nodesResult.status === 'fulfilled'
      ? structuredDownloadStatus(nodesResult.value)
      : 'error';
    dlIpStatus = ipResult.status === 'fulfilled'
      ? structuredDownloadStatus(ipResult.value)
      : 'error';

    // Brief pause so the user can see the green checkmarks
    await new Promise(r => setTimeout(r, 900));

    // Staged before `setup_complete` flips, so a failure leaves the wizard up
    // to retry or skip it, and the relaunch below is the one that applies it.
    if (emuleSelection && importStatus !== 'ok') {
      importing = true;
      downloading = false;
      const staged = await stageImport(emuleSelection);
      if (!staged) {
        importing = false;
        return;
      }
    }
    // Hand the guard back to `saving` rather than dropping it: both flags being
    // false through the final read-modify-write re-enables the Finish button
    // mid-flight, and a second `finish()` can then write `setup_complete: false`
    // after this one has written `true`.
    saving = true;
    downloading = false;
    importing = false;

    // `download_ipfilter` persists `ip_filter_enabled` and bumps the revision.
    // Re-read before flipping setup_complete so the final save isn't rejected
    // as stale — that left the wizard stuck with a "settings changed" error
    // and never reached the automatic relaunch.
    let latest: AppSettings;
    try {
      latest = await getSettings();
    } catch (e) {
      saveError = translateError(e, m.settings_save_failed());
      saving = false;
      return;
    }

    const final: AppSettings = {
      ...partial,
      settings_revision: latest.settings_revision,
      ip_filter_enabled: latest.ip_filter_enabled,
      setup_complete: true,
    };
    try {
      const second = await saveSettings(final);
      Object.assign(final, second.settings);
    } catch (e) {
      // If this second save fails the wizard will show again — annoying but
      // safe. Surface the error.
      saveError = translateError(e, m.settings_save_failed());
      saving = false;
      return;
    }

    saving = false;
    relaunching = true;
    try {
      await new Promise(r => setTimeout(r, 600));
      await relaunch();
    } catch (e) {
      relaunching = false;
      saveError = m.settings_restart_failed({ error: translateError(e) });
      // Settings are already persisted with setup_complete=true; dismiss the
      // wizard so the user can use the app and restart manually if needed.
      await oncomplete(final);
    }
  }

  const stepLabels: (() => string)[] = [
    () => m.wizard_step_welcome(),
    () => m.wizard_step_import(),
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
<div
  class="wizard-overlay"
  bind:this={overlayEl}
  role="dialog"
  aria-modal="true"
  aria-label={m.wizard_aria()}
  tabindex="-1"
  onkeydown={(event) => trapTabKey(event, cardEl)}
>
  <div class="wizard-card" class:transitioning bind:this={cardEl}>
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
              <img src="/icon.png" alt="" width="48" height="48" draggable="false" />
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

      {:else if step === IMPORT_STEP}
        <!-- Rendered below, outside this chain, so detection and choices survive Back and Next. -->

      {:else if step === 3}
        <div class="step-content">
          <h2 class="step-title">{m.wizard_nickname_title()}</h2>
          <p class="step-desc">{m.wizard_nickname_desc()}</p>
          <div class="field">
            <label for="nickname">{m.wizard_nickname_label()}</label>
            <input id="nickname" type="text" bind:value={nickname} maxlength="128" class="text-input" placeholder={m.wizard_nickname_placeholder()} />
          </div>
          {#if nicknameFromEmule}
            <p class="step-hint from-emule">{m.wizard_from_emule()}</p>
          {/if}
          <p class="step-hint">{m.wizard_nickname_hint()}</p>
        </div>

      {:else if step === 4}
        <div class="step-content">
          <h2 class="step-title">{m.wizard_folder_title()}</h2>
          <p class="step-desc">{m.wizard_folder_desc()}</p>
          <div class="field">
            <label for="dl-folder">{m.wizard_folder_label()}</label>
            <!--
              Read-only path display + explicit Browse, matching Settings →
              Downloads. This used to be a field with `cursor: pointer` and a
              click handler: it had the same chrome as the editable nickname
              and port inputs one step either side of it, so it invited typing
              or pasting a path — neither of which did anything, since the
              backend only accepts a folder the native picker authorized.
              The value stays selectable so the path can still be copied.
            -->
            <div class="folder-picker">
              <input
                id="dl-folder"
                type="text"
                value={downloadFolder}
                class="text-input folder-input"
                readonly
              />
              <button type="button" class="browse-btn" onclick={pickFolder}>{m.wizard_folder_browse()}</button>
            </div>
            {#if folderFromEmule}
              <p class="step-hint from-emule">{m.wizard_folder_from_emule()}</p>
            {/if}
            <p class="step-hint">{m.wizard_folder_picker_hint()}</p>
            {#if folderError}
              <p class="save-error">{folderError}</p>
            {/if}
          </div>
        </div>

      {:else if step === 5}
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
          {#if portsFromEmule}
            <p class="step-hint from-emule">{m.wizard_ports_from_emule()}</p>
          {/if}
          <p class="step-hint">{m.wizard_ports_hint()}</p>
        </div>

      {:else if step === 6}
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
          {#if speedsFromEmule}
            <p class="step-hint from-emule">{m.wizard_from_emule()}</p>
          {/if}
          <button type="button" class="speed-test-btn" onclick={runSpeedTest} disabled={speedTestRunning}>
            {speedTestRunning ? m.wizard_speed_test_running() : m.wizard_speed_test_run()}
          </button>
          {#if speedTestResult}
            <p class="speed-result" class:error={speedTestFailed}>{speedTestResult}</p>
          {/if}
        </div>

      {:else if step === 7}
        <!--
          No switches left on this step, and it stays anyway: it is the one
          screen that tells a new user which networks the app is about to join
          on their behalf. Dropping it would make that disclosure happen
          silently, which is the wrong trade even for a shorter wizard.
        -->
        <div class="step-content">
          <h2 class="step-title">{m.wizard_connect_title()}</h2>
          <p class="step-desc">{m.wizard_connect_desc()}</p>
          <div class="connect-options">
            <div class="connect-option connect-option-static">
              <div class="connect-always-on" aria-hidden="true">
                <svg viewBox="0 0 16 16" fill="currentColor"><path d="M6.5 12.5l-4-4 1.4-1.4 2.6 2.6 5.6-5.6 1.4 1.4z"/></svg>
              </div>
              <div>
                <strong>{m.nav_ember_network()}</strong>
                <span>{m.wizard_connect_ember_desc()}</span>
              </div>
            </div>
            <div class="connect-option connect-option-static">
              <div class="connect-always-on" aria-hidden="true">
                <svg viewBox="0 0 16 16" fill="currentColor"><path d="M6.5 12.5l-4-4 1.4-1.4 2.6 2.6 5.6-5.6 1.4 1.4z"/></svg>
              </div>
              <div>
                <strong>{m.wizard_connect_kad_title()}</strong>
                <span>{m.wizard_connect_kad_desc()}</span>
              </div>
            </div>
          </div>
          <p class="step-hint">{m.wizard_connect_hint()}</p>
        </div>

      {:else if step === 8}
        <div class="step-content">
          <h2 class="step-title">{m.wizard_theme_title()}</h2>
          <p class="step-desc">{m.wizard_theme_desc()}</p>
          <div class="theme-options">
            <button
              type="button"
              class="theme-card"
              class:selected={selectedTheme === 'dark'}
              aria-pressed={selectedTheme === 'dark'}
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
              aria-pressed={selectedTheme === 'light'}
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

      {:else if step === 9}
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
              <span class="summary-value">{fmtSpeedShort(maxUploadSpeed)}</span>
            </div>
            <div class="summary-row">
              <span class="summary-label">{m.wizard_summary_download_limit()}</span>
              <span class="summary-value">{fmtSpeedShort(maxDownloadSpeed)}</span>
            </div>
            <div class="summary-row">
              <span class="summary-label">{m.wizard_summary_theme()}</span>
              <span class="summary-value">{selectedTheme === 'dark' ? m.wizard_theme_dark() : m.wizard_theme_light()}</span>
            </div>
            <div class="summary-row">
              <span class="summary-label">{m.wizard_summary_import()}</span>
              <span class="summary-value">{emuleSelection ? m.wizard_summary_import_yes() : m.wizard_summary_import_no()}</span>
            </div>
          </div>
          <!-- Said before the button rather than discovered after it: the
               finish step restarts the app, which is alarming if unannounced. -->
          <p class="step-hint">{m.wizard_ready_restart_note()}</p>
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
                {:else if dlNodesStatus === 'error' || dlNodesStatus === 'failed' || dlNodesStatus === 'deferred'}
                  <svg class="dl-icon err" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm.75 3.5v4h-1.5v-4h1.5zm0 5.5v1.5h-1.5V10h1.5z"/></svg>
                {:else}
                  <span class="dl-icon placeholder" aria-hidden="true"></span>
                {/if}
                <span>{m.wizard_dl_nodes_label()}</span>
                {#if dlNodesStatus === 'error'}
                  <span class="dl-warn">{m.wizard_dl_nodes_skipped()}</span>
                {:else if dlNodesStatus === 'deferred'}
                  <span class="dl-warn">{m.wizard_dl_nodes_deferred()}</span>
                {:else if dlNodesStatus === 'failed'}
                  <span class="dl-warn">{m.wizard_dl_nodes_failed()}</span>
                {/if}
              </div>
              <div class="dl-item">
                {#if dlIpStatus === 'pending'}
                  <span class="spinner xs" aria-hidden="true"></span>
                {:else if dlIpStatus === 'ok'}
                  <svg class="dl-icon ok" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M6.5 12.5l-4-4 1.4-1.4 2.6 2.6 5.6-5.6 1.4 1.4z"/></svg>
                {:else if dlIpStatus === 'error' || dlIpStatus === 'failed' || dlIpStatus === 'deferred'}
                  <svg class="dl-icon err" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm.75 3.5v4h-1.5v-4h1.5zm0 5.5v1.5h-1.5V10h1.5z"/></svg>
                {:else}
                  <span class="dl-icon placeholder" aria-hidden="true"></span>
                {/if}
                <span>{m.wizard_dl_ipfilter_label()}</span>
                {#if dlIpStatus === 'error'}
                  <span class="dl-warn">{m.wizard_dl_ipfilter_skipped()}</span>
                {:else if dlIpStatus === 'deferred'}
                  <span class="dl-warn">{m.wizard_dl_ipfilter_deferred()}</span>
                {:else if dlIpStatus === 'failed'}
                  <span class="dl-warn">{m.wizard_dl_ipfilter_failed()}</span>
                {/if}
              </div>
              {#if emuleSelection}
                <div class="dl-item">
                  {#if importStatus === 'pending'}
                    <span class="spinner xs" aria-hidden="true"></span>
                  {:else if importStatus === 'ok'}
                    <svg class="dl-icon ok" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M6.5 12.5l-4-4 1.4-1.4 2.6 2.6 5.6-5.6 1.4 1.4z"/></svg>
                  {:else}
                    <span class="dl-icon placeholder" aria-hidden="true"></span>
                  {/if}
                  <span>
                    {importPercent === null
                      ? m.wizard_import_progress()
                      : m.wizard_import_progress_percent({ percent: importPercent })}
                  </span>
                </div>
              {/if}
            </div>
          {/if}
        </div>
      {/if}

      <div class="step-content" hidden={step !== IMPORT_STEP}>
        <h2 class="step-title">{m.wizard_import_title()}</h2>
        <p class="step-desc">{m.wizard_import_desc()}</p>
        <EmuleImport
          mode="wizard"
          bind:selection={emuleSelection}
          downloadFolderIsIncoming={!!emulePreview?.incoming_dir && downloadFolder === emulePreview.incoming_dir}
          onpreview={onEmulePreview}
        />
      </div>
    </div>

    <!-- Footer -->
    <div class="wizard-footer">
      {#if step > 1 && !saving && !downloading && !importing}
        <button type="button" class="btn-back" onclick={goBack}>{m.common_back()}</button>
      {:else}
        <div></div>
      {/if}

      <div class="footer-right">
        {#if step < TOTAL_STEPS}
          {#if nextDisabledReason}
            <span id="wizard-next-reason" class="next-reason">{nextDisabledReason}</span>
          {/if}
          <button
            type="button"
            class="btn-next"
            onclick={goNext}
            disabled={!canAdvance}
            aria-describedby={nextDisabledReason ? 'wizard-next-reason' : undefined}
          >
            {step === 1 ? m.wizard_get_started() : m.common_next()}
          </button>
        {:else}
          <button type="button" class="btn-finish" onclick={finish} disabled={saving || downloading || importing}>
            {#if saving}
              <span class="spinner sm"></span> {m.wizard_saving()}
            {:else if downloading}
              <span class="spinner sm"></span> {m.wizard_downloading()}
            {:else if importing}
              <span class="spinner sm"></span> {m.wizard_importing()}
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
    z-index: 9999;
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
    font-size: var(--font-size-base);
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
    border-radius: var(--radius-lg);
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
    font-size: var(--font-size-xs);
    font-weight: 700;
    border: 2px solid var(--border);
    color: var(--text-muted);
    background: var(--bg-surface);
    transition: all var(--transition-normal) ease;
  }

  .progress-dot.active .dot {
    border-color: var(--accent);
    background: var(--accent);
    color: var(--on-accent);
  }

  .progress-dot.done .dot {
    border-color: var(--success);
    background: var(--success);
    color: var(--on-success);
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
    transition: background var(--transition-normal) ease;
  }

  .progress-line.filled {
    background: var(--success);
  }

  /* Body */
  .wizard-body {
    flex: 1;
    overflow-y: auto;
    padding: 24px 28px;
    transition: opacity var(--transition-normal) ease, transform var(--transition-normal) ease;
  }

  .step-content {
    animation: step-in 0.25s ease-out;
  }

  .step-title {
    font-size: var(--font-size-2xl);
    font-weight: 700;
    color: var(--text-primary);
    margin: 0 0 6px;
  }

  .welcome-title {
    font-size: var(--font-size-3xl);
    color: var(--accent);
    margin: 0;
  }

  .welcome-subtitle {
    font-size: var(--font-size-xs);
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
    border-radius: var(--radius-md);
    overflow: hidden;
    flex-shrink: 0;
    box-shadow:
      0 0 0 1px var(--border),
      var(--shadow-sm);
  }

  .brand-icon img {
    width: 100%;
    height: 100%;
    display: block;
  }

  .step-desc {
    font-size: var(--font-size-md);
    color: var(--text-secondary);
    line-height: 1.6;
    margin: 0 0 16px;
  }

  .step-hint {
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    margin: 12px 0 0;
  }

  .step-hint.from-emule {
    color: var(--accent);
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
    border-radius: var(--radius-md);
  }

  .info-icon {
    width: 32px;
    height: 32px;
    border-radius: var(--radius-md);
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
    font-size: var(--font-size-md);
    color: var(--text-primary);
    margin-bottom: 2px;
  }

  .info-card span {
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    line-height: 1.5;
  }

  /* Fields */
  .field {
    margin-bottom: 14px;
  }

  .field label {
    display: block;
    font-size: var(--font-size-sm);
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
    font-size: var(--font-size-base);
    font-family: inherit;
    outline: none;
    transition: border-color var(--transition-normal);
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
    min-width: 0;
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
  }

  .browse-btn {
    padding: 0 16px;
    border: 1px solid var(--accent);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--accent);
    font-size: var(--font-size-md);
    font-weight: 600;
    cursor: pointer;
    transition: background var(--transition-normal), color var(--transition-normal);
    white-space: nowrap;
  }

  .browse-btn:hover {
    background: var(--accent);
    color: var(--on-accent);
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
    font-size: var(--font-size-md);
    cursor: pointer;
    transition: border-color var(--transition-normal), color var(--transition-normal);
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
    font-size: var(--font-size-sm);
    color: var(--success);
    margin: 8px 0 0;
  }

  .speed-result.error {
    color: var(--danger);
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
    border-radius: var(--radius-md);
  }

  .connect-option strong {
    display: block;
    font-size: var(--font-size-md);
    color: var(--text-primary);
    margin-bottom: 2px;
  }

  .connect-option span {
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
    line-height: 1.5;
  }

  /* No control, so it gets the success accent instead of a switch — it must
     not look like a toggle someone forgot to make interactive. */
  .connect-option-static {
    border-color: color-mix(in srgb, var(--success) 40%, var(--border));
  }

  .connect-always-on {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 20px;
    height: 20px;
    border-radius: 50%;
    background: var(--success);
    color: var(--on-success);
  }

  .connect-always-on svg {
    width: 14px;
    height: 14px;
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
    border-radius: var(--radius-lg);
    padding: 14px;
    background: var(--bg-surface);
    cursor: pointer;
    transition: border-color var(--transition-normal), box-shadow var(--transition-normal);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
    font-size: var(--font-size-base);
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
    border-radius: var(--radius-sm);
    display: flex;
    overflow: hidden;
    border: 1px solid rgba(128,128,128,0.2);
  }

  .dark-preview {
    background: var(--preview-dark-canvas);
  }

  .dark-preview .tp-sidebar {
    width: 30%;
    background: var(--preview-dark-panel);
    border-right: 1px solid var(--preview-dark-border);
  }

  .dark-preview .tp-main {
    flex: 1;
    padding: 8px;
  }

  .dark-preview .tp-bar {
    height: 8px;
    border-radius: 3px;
    background: var(--preview-dark-accent-dim);
    margin-bottom: 6px;
  }

  .dark-preview .tp-row {
    height: 6px;
    border-radius: 2px;
    background: var(--preview-dark-hover);
    margin-bottom: 4px;
  }

  .dark-preview .tp-row.short {
    width: 60%;
  }

  .light-preview {
    background: var(--preview-light-canvas);
  }

  .light-preview .tp-sidebar {
    width: 30%;
    background: var(--preview-light-panel);
    border-right: 1px solid var(--preview-light-border);
  }

  .light-preview .tp-main {
    flex: 1;
    padding: 8px;
  }

  .light-preview .tp-bar {
    height: 8px;
    border-radius: 3px;
    background: var(--preview-light-surface);
    margin-bottom: 6px;
  }

  .light-preview .tp-row {
    height: 6px;
    border-radius: 2px;
    background: var(--preview-light-hover);
    margin-bottom: 4px;
  }

  .light-preview .tp-row.short {
    width: 60%;
  }

  /* Summary */
  .summary {
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
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
    font-size: var(--font-size-md);
    color: var(--text-secondary);
    font-weight: 500;
  }

  .summary-value {
    font-size: var(--font-size-md);
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
    font-size: var(--font-size-xs);
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
    font-size: var(--font-size-md);
    font-weight: 600;
    cursor: pointer;
    transition: border-color var(--transition-normal), color var(--transition-normal);
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
    color: var(--on-accent);
    font-size: var(--font-size-base);
    font-weight: 600;
    cursor: pointer;
    transition: background var(--transition-normal);
  }

  .next-reason {
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    text-align: right;
  }

  .btn-next:disabled {
    pointer-events: none;
  }

  .btn-next:hover, .btn-finish:hover {
    background: var(--accent-hover);
  }

  .btn-finish {
    padding: 10px 32px;
    font-size: var(--font-size-base);
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
    font-size: var(--font-size-md);
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
    font-size: var(--font-size-sm);
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
    font-size: var(--font-size-md);
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
    font-size: var(--font-size-sm);
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

  /*
   * Nine 9px uppercase labels in one row is a lot of type for a narrow
   * card, and they only disappeared at 700px — so there was a band where
   * they were on screen, touching, and unreadable. Between here and there,
   * label just the step you are on: that is the only one that answers
   * "where am I", and the rest are still countable as dots.
   */
  @media (max-width: 900px) {
    .progress-dot:not(.active) .dot-label {
      display: none;
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
