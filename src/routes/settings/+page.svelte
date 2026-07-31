<script lang="ts">
  import {
    getSettings,
    updateSettings,
    downloadNodesDat,
    downloadIpfilter,
    openEmberWebsite,
    type UpdateSettingsResult,
    type NodesDatDownloadResult,
    type IpFilterDownloadResult,
  } from '$lib/api/settings';
  import { setAppSettings, appSettings } from '$lib/stores/settings';
  import { get } from 'svelte/store';
  import { getSpamStats, resetSpamFilter, clearDownloadHistory, getDownloadHistoryStats } from '$lib/api/search';
  import {
    getAntileechPatterns,
    setAntileechPatterns,
    setAntileechEnabled,
    resetAntileechToDefaults,
  } from '$lib/api/security';
  import type { AntiLeechSnapshot } from '$lib/types';
  import { invoke } from '@tauri-apps/api/core';
  import { goto } from '$app/navigation';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { relaunch } from '@tauri-apps/plugin-process';
  import {
    discardPendingRestore,
    exportBackup,
    importBackup,
    pendingRestoreStatus,
    previewBackup,
    type BackupPreview,
    type PendingRestoreStatus,
    type RestoreSummary,
  } from '$lib/api/backup';
  import { formatSize } from '$lib/utils';
  import type { AppSettings, SpamStats, DownloadHistoryStats } from '$lib/types';
  import { onMount, untrack } from 'svelte';
  import { theme, applyTheme, type Theme } from '$lib/stores/theme';
  import { emberDevToolsEnabled } from '$lib/stores/devTools';
  import {
    locales,
    getLocale,
    setLocale,
    languageLabel,
    localeFlagSrc,
    hasExplicitLocale,
    useSystemLocale,
    systemLocale,
    translateError,
    type Locale,
  } from '$lib/i18n';
  import * as m from '$lib/paraglide/messages';
  import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
  import SpeedInput from '$lib/components/SpeedInput.svelte';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import { updater, checkForUpdates, installUpdate, restartToUpdate } from '$lib/stores/updater';

  const appVersion = import.meta.env.VITE_APP_VERSION;
  const appLicense = import.meta.env.VITE_APP_LICENSE;

  function updateSettingsOutcomeMessage(result: UpdateSettingsResult): string {
    switch (result.outcome) {
      case 'restart_required':
        return m.settings_save_restart_required();
      case 'deferred':
        return m.settings_save_live_apply_deferred();
      default:
        return m.settings_save_success();
    }
  }

  function nodesDownloadOutcomeMessage(result: NodesDatDownloadResult): string {
    return result.outcome === 'applied' && result.appliedCount !== undefined
      ? m.settings_nodes_downloaded_applied({
          parsed: result.parsedCount,
          applied: result.appliedCount,
          bytes: result.byteCount,
        })
      : m.settings_nodes_downloaded_deferred({
          parsed: result.parsedCount,
          bytes: result.byteCount,
        });
  }

  function ipFilterDownloadOutcomeMessage(result: IpFilterDownloadResult): string {
    switch (result.outcome) {
      case 'applied':
        return m.settings_ipfilter_downloaded_applied({
            entries: result.entryCount,
            bytes: result.byteCount,
          });
      case 'failed':
        return m.settings_ipfilter_downloaded_failed({
            entries: result.entryCount,
            bytes: result.byteCount,
          });
      default:
        return m.settings_ipfilter_downloaded_deferred({
            entries: result.entryCount,
            bytes: result.byteCount,
          });
    }
  }

  // Download progress percent for the About card, when a content length is known.
  let aboutPercent = $derived(
    $updater.total && $updater.total > 0
      ? Math.min(100, Math.round(($updater.downloaded / $updater.total) * 100))
      : null,
  );
  let websiteOpenError = $state('');

  async function openWebsite() {
    websiteOpenError = '';
    try {
      await openEmberWebsite();
    } catch (e) {
      websiteOpenError = translateError(e);
    }
  }

  // Active locale, kept in component state so the radio group has
  // a reactive `selected` source. Updating this state goes through
  // `setLocale()` which triggers a full page reload — by the time
  // the user sees the change, the entire app shell has re-rendered
  // in the new language and there's no need to thread reactivity
  // through every translated component.
  let currentLocale: Locale = $state(getLocale());
  // Whether the active locale is being followed from the OS (no
  // explicit choice in localStorage) vs. picked by the user. Drives
  // which radio in the picker shows as selected: the "System" entry
  // is selected iff there's no explicit choice, even though Paraglide
  // has already resolved that to a concrete locale underneath.
  let followingSystem = $state(!hasExplicitLocale());
  const systemPreviewLocale: Locale = systemLocale();

  function pickLocale(next: Locale) {
    if (!followingSystem && next === currentLocale) return;
    currentLocale = next;
    followingSystem = false;
    setLocale(next);
  }

  function pickSystemLocale() {
    if (followingSystem) return;
    useSystemLocale();
  }

  let settings: AppSettings | null = $state(null);
  let pageContentEl: HTMLDivElement | null = $state(null);
  let originalSettings: string = $state('');
  let saving = $state(false);
  let saveMessage: string | null = $state(null);
  let saveIsWarning = $state(false);
  let loadError: string | null = $state(null);
  let downloadingNodes = $state(false);
  let nodesResult: string | null = $state(null);
  let nodesResultWarning = $state(false);
  let nodesError: string | null = $state(null);

  // Restart-prompt state. Populated by `handleSave` when a save changes
  // either the TCP or UDP port — those are the two settings that the
  // network stack only reads once at startup (the upload listener binds
  // them in `start_upload_server` before any settings hot-reload path
  // can touch them), so a port change has no effect until the process
  // is restarted. Using the same `relaunch` flow as `SetupWizard.svelte`
  // so the experience is identical to first-time setup.
  let showRestartPrompt = $state(false);
  let restarting = $state(false);
  let pendingRestartReason = $state('');

  // --- Backup / restore ---
  // A restore cannot be applied while the app is running (SQLite holds the
  // database open, and identity/config are already in memory), so the backend
  // stages it and the swap happens during the next launch. That makes the
  // restart part of the operation rather than an optional follow-up.
  let backupPassphrase = $state('');
  let backupPassphraseConfirm = $state('');
  let backupBusy = $state(false);
  let backupMessage: string | null = $state(null);
  let backupIsError = $state(false);
  let restorePassphrase = $state('');
  let restoreSource: string | null = $state(null);
  let restorePreview: BackupPreview | null = $state(null);
  let restoreStaged: RestoreSummary | null = $state(null);
  let pendingRestore: PendingRestoreStatus | null = $state(null);

  function showBackupMsg(msg: string, isError: boolean) {
    backupMessage = msg;
    backupIsError = isError;
  }

  async function refreshPendingRestore() {
    try {
      pendingRestore = await pendingRestoreStatus();
    } catch (e) {
      // Only a status read; a failure here must not make the section unusable.
      console.error('Pending-restore check failed:', e);
    }
  }

  // Lazily checked the first time the Backup section is opened (or on load if
  // it is the active one), matching how the Security section defers its own
  // snapshot. A staged restore survives restarts, so this has to be shown
  // whenever the user comes back - not just after the import that created it.
  let pendingRestoreChecked = false;
  $effect(() => {
    if (activeSection !== 'backup' || pendingRestoreChecked) return;
    pendingRestoreChecked = true;
    void refreshPendingRestore();
  });

  async function handleDiscardPendingRestore() {
    if (backupBusy) return;
    backupBusy = true;
    try {
      await discardPendingRestore();
      pendingRestore = null;
      restoreStaged = null;
      showBackupMsg(m.settings_backup_pending_discarded(), false);
    } catch (e) {
      showBackupMsg(translateError(e, m.settings_backup_restore_failed()), true);
    } finally {
      backupBusy = false;
    }
  }

  function clearRestoreState() {
    restoreSource = null;
    restorePreview = null;
    restorePassphrase = '';
  }

  async function handleExportBackup() {
    if (backupBusy) return;
    if (backupPassphrase !== backupPassphraseConfirm) {
      showBackupMsg(m.settings_backup_passphrase_mismatch(), true);
      return;
    }
    let dest: string | null = null;
    try {
      const { save } = await import('@tauri-apps/plugin-dialog');
      dest = await save({
        defaultPath: `ember-backup-${new Date().toISOString().slice(0, 10)}.emberbackup`,
        filters: [{ name: m.settings_backup_file_kind(), extensions: ['emberbackup'] }],
      });
    } catch (e) {
      showBackupMsg(translateError(e, m.settings_backup_export_failed()), true);
      return;
    }
    if (!dest) return;
    // Not every platform's save dialog appends the filter's extension, and the
    // backend insists on it. Adding it here beats rejecting the user's choice.
    if (!dest.toLowerCase().endsWith('.emberbackup')) dest = `${dest}.emberbackup`;
    backupBusy = true;
    showBackupMsg(m.settings_backup_exporting(), false);
    try {
      const summary = await exportBackup(dest, backupPassphrase);
      backupPassphrase = '';
      backupPassphraseConfirm = '';
      showBackupMsg(
        m.settings_backup_export_done({
          files: summary.files,
          size: formatSize(summary.bytes),
          path: summary.path,
        }),
        false,
      );
    } catch (e) {
      showBackupMsg(translateError(e, m.settings_backup_export_failed()), true);
    } finally {
      backupBusy = false;
    }
  }

  async function handlePickBackupFile() {
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({
        multiple: false,
        directory: false,
        filters: [{ name: m.settings_backup_file_kind(), extensions: ['emberbackup'] }],
      });
      if (typeof selected === 'string') {
        restoreSource = selected;
        restorePreview = null;
        backupMessage = null;
      }
    } catch (e) {
      showBackupMsg(translateError(e, m.settings_backup_restore_failed()), true);
    }
  }

  /** Decrypt and describe the chosen backup without touching anything, so the
   *  user can see what they are about to overwrite before committing. */
  async function handlePreviewBackup() {
    if (backupBusy || !restoreSource) return;
    backupBusy = true;
    showBackupMsg(m.settings_backup_reading(), false);
    try {
      restorePreview = await previewBackup(restoreSource, restorePassphrase);
      backupMessage = null;
      if (restorePreview.schema_too_new) {
        showBackupMsg(m.settings_backup_schema_too_new(), true);
      }
    } catch (e) {
      restorePreview = null;
      showBackupMsg(translateError(e, m.settings_backup_restore_failed()), true);
    } finally {
      backupBusy = false;
    }
  }

  async function handleImportBackup() {
    if (backupBusy || !restoreSource) return;
    backupBusy = true;
    showBackupMsg(m.settings_backup_restoring(), false);
    try {
      restoreStaged = await importBackup(restoreSource, restorePassphrase);
      clearRestoreState();
      backupMessage = null;
      await refreshPendingRestore();
      showRestoreRestartPrompt = true;
    } catch (e) {
      showBackupMsg(translateError(e, m.settings_backup_restore_failed()), true);
    } finally {
      backupBusy = false;
    }
  }

  let showRestoreRestartPrompt = $state(false);

  let historyClearMsg: string | null = $state(null);
  let historyStats: DownloadHistoryStats | null = $state(null);
  let historyStatsLoading = $state(false);
  let historyStatsError: string | null = $state(null);

  async function refreshHistoryStats() {
    historyStatsLoading = true;
    historyStatsError = null;
    try {
      const s = await getDownloadHistoryStats();
      if (unmounted) return;
      historyStats = s;
    } catch (e) {
      if (unmounted) return;
      historyStatsError = translateError(e, m.settings_history_stats_failed());
    } finally {
      if (!unmounted) historyStatsLoading = false;
    }
  }

  // History clear uses ConfirmDialog (same pattern as spam reset) so a
  // misclick cannot wipe completed/cancelled rows without an explicit OK.
  let historyClearConfirmOpen = $state(false);
  let pendingHistoryClear: 'completed' | 'cancelled' | 'all' | null = $state(null);

  function requestClearHistory(status: 'completed' | 'cancelled' | 'all') {
    pendingHistoryClear = status;
    historyClearConfirmOpen = true;
  }

  async function confirmClearHistory() {
    const status = pendingHistoryClear;
    if (!status) return;
    // Leave `pendingHistoryClear` set so the ConfirmDialog outro keeps the
    // correct title/message; the next `requestClearHistory` overwrites it.
    try {
      await clearDownloadHistory(status);
      historyClearMsg = status === 'all'
        ? m.settings_history_cleared_all()
        : status === 'completed'
          ? m.settings_history_cleared_completed()
          : m.settings_history_cleared_cancelled();
      trackedTimeout(() => { historyClearMsg = null; }, 3000);
      await refreshHistoryStats();
    } catch (e) {
      historyClearMsg = m.settings_history_clear_failed({ error: translateError(e) });
    }
  }

  let historyClearDialogTitle = $derived(
    pendingHistoryClear === 'all' ? m.settings_history_clear_all_dialog_title()
      : pendingHistoryClear === 'completed' ? m.settings_history_clear_completed_dialog_title()
        : pendingHistoryClear === 'cancelled' ? m.settings_history_clear_cancelled_dialog_title()
          : ''
  );
  let historyClearDialogMessage = $derived(
    pendingHistoryClear === 'all' ? m.settings_history_clear_all_dialog_message()
      : pendingHistoryClear === 'completed' ? m.settings_history_clear_completed_dialog_message()
        : pendingHistoryClear === 'cancelled' ? m.settings_history_clear_cancelled_dialog_message()
          : ''
  );

  let speedTesting = $state(false);
  let speedResult: { download_speed: number; upload_speed: number; recommended_upload_limit: number; recommended_download_limit: number } | null = $state(null);
  let speedError: string | null = $state(null);

  async function runSpeedTest() {
    speedTesting = true;
    speedResult = null;
    speedError = null;
    try {
      speedResult = await invoke('run_speed_test');
    } catch (e: unknown) {
      speedError = translateError(e, m.settings_speed_test_failed());
    } finally {
      speedTesting = false;
    }
  }

  function applyRecommended() {
    if (!settings || !speedResult) return;
    settings.max_upload_speed = speedResult.recommended_upload_limit;
    settings.max_download_speed = speedResult.recommended_download_limit;
  }

  function formatSpeed(bytesPerSec: number): string {
    if (bytesPerSec >= 1024 * 1024) return `${(bytesPerSec / (1024 * 1024)).toFixed(1)} MB/s`;
    if (bytesPerSec >= 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
    return `${bytesPerSec} B/s`;
  }
  let downloadingFilter = $state(false);
  let filterResult: string | null = $state(null);
  let filterResultWarning = $state(false);
  let filterError: string | null = $state(null);
  let spamStats: SpamStats | null = $state(null);
  let spamStatsLoading = $state(false);
  let spamStatsError: string | null = $state(null);
  let spamResetting = $state(false);
  type SettingsSection = 'general' | 'downloads' | 'bandwidth' | 'network' | 'security' | 'friends' | 'search' | 'backup' | 'about';
  let activeSection: SettingsSection = $state('general');

  const sections: SettingsSection[] = [
    'general',
    'downloads',
    'bandwidth',
    'network',
    'security',
    'friends',
    'search',
    'backup',
    'about',
  ];

  function sectionLabel(id: SettingsSection): string {
    switch (id) {
      case 'general': return m.settings_section_general();
      case 'downloads': return m.settings_section_downloads();
      case 'bandwidth': return m.settings_section_bandwidth();
      case 'network': return m.settings_section_network();
      case 'security': return m.settings_section_security();
      case 'friends': return m.settings_section_friends();
      case 'search': return m.settings_section_search();
      case 'backup': return m.settings_section_backup();
      case 'about': return m.settings_section_about();
    }
  }

  let unmounted = false;
  onMount(() => {
    let unlistenIpFilterReload: UnlistenFn | null = null;
    let unlistenNodesBootstrap: UnlistenFn | null = null;
    listen<{ outcome: 'applied' | 'failed'; entry_count: number; byte_count: number }>(
      'ipfilter-reload-result',
      (event) => {
        if (unmounted) return;
        const { outcome, entry_count, byte_count } = event.payload;
        if (
          (outcome !== 'applied' && outcome !== 'failed')
          || !Number.isFinite(entry_count)
          || !Number.isFinite(byte_count)
        ) return;
        showIpFilterDownloadOutcome({
          outcome,
          entryCount: entry_count,
          byteCount: byte_count,
        });
      },
    )
      .then((fn) => {
        if (unmounted) fn();
        else unlistenIpFilterReload = fn;
      })
      .catch((e) => console.error('Failed to register IP-filter reload listener:', e));
    listen<{ outcome: 'applied'; parsed_count: number; applied_count: number; byte_count: number }>(
      'nodes-bootstrap-result',
      (event) => {
        if (unmounted) return;
        const { parsed_count, applied_count, byte_count } = event.payload;
        if (
          !Number.isFinite(parsed_count)
          || !Number.isFinite(applied_count)
          || !Number.isFinite(byte_count)
        ) return;
        showNodesDownloadOutcome({
          outcome: 'applied',
          parsedCount: parsed_count,
          appliedCount: applied_count,
          byteCount: byte_count,
        });
      },
    )
      .then((fn) => {
        if (unmounted) fn();
        else unlistenNodesBootstrap = fn;
      })
      .catch((e) => console.error('Failed to register nodes bootstrap listener:', e));

    refreshSpamStats();
    refreshHistoryStats();
    getSettings()
      .then((s) => {
        if (unmounted) return;
        // Seed the antileech toggle baseline BEFORE assigning `settings`
        // so the sync `$effect` below treats the persisted value as
        // already-applied and doesn't fire a redundant
        // `setAntileechEnabled(persistedValue)`. Without this, an IPC
        // failure on that redundant call could flip `settings.antileech_enabled`
        // in the catch handler and the next effect run would actually
        // disable the filter the user never asked to disable.
        lastAppliedAntileechToggle = s.antileech_enabled;
        settings = s;
        originalSettings = JSON.stringify(s);
      })
      .catch((e) => { loadError = translateError(e, m.settings_load_failed()); });

    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (hasUnsavedChanges) e.preventDefault();
    };
    const handleKeyboardSave = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        if (hasUnsavedChanges) handleSave();
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    window.addEventListener('keydown', handleKeyboardSave);
    return () => {
      unmounted = true;
      unlistenIpFilterReload?.();
      unlistenNodesBootstrap?.();
      window.removeEventListener('beforeunload', handleBeforeUnload);
      window.removeEventListener('keydown', handleKeyboardSave);
      for (const id of activeTimers) clearTimeout(id);
    };
  });

  const activeTimers = new Set<ReturnType<typeof setTimeout>>();
  function trackedTimeout(fn: () => void, ms: number) {
    const id = setTimeout(() => { activeTimers.delete(id); fn(); }, ms);
    activeTimers.add(id);
  }

  let saveTimer: ReturnType<typeof setTimeout> | undefined;
  function showSaveMsg(msg: string, isWarning: boolean, ms: number) {
    if (saveTimer !== undefined) { clearTimeout(saveTimer); activeTimers.delete(saveTimer); }
    saveMessage = msg;
    saveIsWarning = isWarning;
    // Mirror trackedTimeout: delete the id from activeTimers when the
    // timer fires, otherwise the Set retains stale ids (clearTimeout
    // on a fired id is a no-op but the bookkeeping drifts and on
    // long-lived sessions activeTimers grows monotonically).
    const id = setTimeout(() => {
      saveMessage = null;
      activeTimers.delete(id);
      if (saveTimer === id) saveTimer = undefined;
    }, ms);
    saveTimer = id;
    activeTimers.add(id);
  }

  function clampInt(v: unknown, min: number, max: number, fallback: number): number {
    const n = typeof v === 'number' ? v : parseInt(String(v ?? ''), 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, Math.trunc(n)));
  }

  function clampNonNegInt(v: unknown, max: number, fallback: number): number {
    const n = typeof v === 'number' ? v : parseInt(String(v ?? ''), 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(0, Math.trunc(n)));
  }

  /** Validate and clamp numeric fields to the ranges documented in AppSettings.
   *  Returns an error message on hard failure (mutates nothing in that case).
   *  Otherwise mutates `s` in place and reports whether any numeric field was
   *  outside its valid range and silently adjusted, so the caller can tell
   *  the user rather than saving a different value than what they typed with
   *  no feedback at all. */
  function validateSettings(s: AppSettings): { error: string | null; adjusted: boolean } {
    if (!s.nickname.trim()) {
      return { error: m.settings_validation_nickname_empty(), adjusted: false };
    }
    // Mirror the backend's 128-byte cap (commands/settings.rs) so an oversized
    // nickname is rejected here with a clear message instead of only failing on
    // save. `maxlength` on the input is a coarse char guard; this is the
    // authoritative byte check (multi-byte UTF-8 can exceed it).
    if (new TextEncoder().encode(s.nickname).length > 128) {
      return { error: m.error_settings_nickname_too_long(), adjusted: false };
    }
    if (!s.download_folder.trim()) {
      return { error: m.settings_validation_folder_empty(), adjusted: false };
    }
    s.rendezvous_url = s.rendezvous_url.trim();
    if (new TextEncoder().encode(s.rendezvous_url).length > 2048) {
      return {
        error: m.error_settings_rendezvous_url_too_long({ detail: '2048' }),
        adjusted: false,
      };
    }
    if (s.rendezvous_url) {
      let rendezvous: URL;
      try {
        rendezvous = new URL(s.rendezvous_url);
      } catch {
        return { error: m.error_settings_rendezvous_url_no_host(), adjusted: false };
      }
      if (rendezvous.protocol !== 'https:') {
        return { error: m.error_settings_rendezvous_url_not_https(), adjusted: false };
      }
      if (!rendezvous.hostname) {
        return { error: m.error_settings_rendezvous_url_no_host(), adjusted: false };
      }
      if (rendezvous.username || rendezvous.password) {
        return {
          error: m.error_settings_rendezvous_url_has_credentials(),
          adjusted: false,
        };
      }
    }
    let adjusted = false;
    // Thin wrappers around the shared clamp helpers that additionally flag
    // `adjusted` when the clamped result differs from what was actually
    // typed (including "unparseable/empty" — that path returns `fallback`,
    // which reliably differs from a NaN `original`).
    const ci = (v: unknown, min: number, max: number, fallback: number): number => {
      const result = clampInt(v, min, max, fallback);
      if (result !== (typeof v === 'number' ? v : parseInt(String(v ?? ''), 10))) adjusted = true;
      return result;
    };
    const cn = (v: unknown, max: number, fallback: number): number => {
      const result = clampNonNegInt(v, max, fallback);
      if (result !== (typeof v === 'number' ? v : parseInt(String(v ?? ''), 10))) adjusted = true;
      return result;
    };
    s.tcp_port = ci(s.tcp_port, 1, 65535, 4662);
    s.udp_port = ci(s.udp_port, 1, 65535, 4672);
    // TCP and UDP are separate protocols on the OS and on the IGD/UPnP
    // side, so reusing the same port number for both is fully supported
    // (eMule has always allowed this too). This matters for users on a
    // VPN that only forwards a single port for both protocols. The only
    // thing we still require is that the port is in the 1-65535 range.
    s.max_upload_speed = cn(s.max_upload_speed, 2_147_483_647, 0);
    s.max_download_speed = cn(s.max_download_speed, 2_147_483_647, 0);
    s.max_concurrent_downloads = ci(s.max_concurrent_downloads, 1, 50, 3);
    s.max_concurrent_uploads = ci(s.max_concurrent_uploads, 1, 50, 4);
    s.max_sources_per_file = ci(s.max_sources_per_file, 1, 2000, 1000);
    s.max_connections = ci(s.max_connections, 1, 2000, 500);
    s.download_queue_wait_secs = ci(s.download_queue_wait_secs, 60, 14400, 600);
    s.multisource_retry_rounds = ci(s.multisource_retry_rounds, 1, 20, 3);
    s.download_part_retry_rounds = ci(s.download_part_retry_rounds, 1, 20, 3);
    s.max_download_file_size_gib = ci(s.max_download_file_size_gib, 1, 593, 593);
    s.search_timeout_secs = ci(s.search_timeout_secs, 30, 600, 120);
    s.max_friends = ci(s.max_friends, 1, 500, 100);
    return { error: null, adjusted };
  }

  function sameSettingValue(a: unknown, b: unknown): boolean {
    return JSON.stringify(a) === JSON.stringify(b);
  }

  /**
   * Apply only fields changed in this page's draft over the latest persisted
   * snapshot. This keeps unrelated out-of-band changes while preserving every
   * unsaved field the user has edited here.
   */
  function mergeDraftOntoLatest(draft: AppSettings, latest: AppSettings): AppSettings {
    let baseline: AppSettings | null = null;
    try {
      baseline = originalSettings ? JSON.parse(originalSettings) as AppSettings : null;
    } catch {
      // With no trustworthy baseline we cannot distinguish changed fields, so
      // preserve the full visible draft and refresh only its concurrency token.
    }

    if (!baseline) {
      return { ...draft, settings_revision: latest.settings_revision };
    }

    const merged = JSON.parse(JSON.stringify(latest)) as AppSettings;
    const draftFields = draft as unknown as Record<string, unknown>;
    const baselineFields = baseline as unknown as Record<string, unknown>;
    const mergedFields = merged as unknown as Record<string, unknown>;
    for (const key of Object.keys(draftFields)) {
      if (key === 'settings_revision') continue;
      if (!sameSettingValue(draftFields[key], baselineFields[key])) {
        mergedFields[key] = draftFields[key];
      }
    }
    merged.settings_revision = latest.settings_revision;
    return merged;
  }

  function isSettingsRevisionConflict(error: unknown): boolean {
    const raw = error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : '';
    if (!raw || raw[0] !== '{') return false;
    try {
      const parsed = JSON.parse(raw) as { __coded?: unknown; code?: unknown };
      return parsed.__coded === true && parsed.code === 'settings_stale_revision';
    } catch {
      return false;
    }
  }

  /** Friend toggles apply immediately (frontend store + persist) so Chat /
   * online toasts / browse gate don't wait for the page Save button.
   * Session encryption is always kept on from this UI path. */
  let friendTogglePersistInFlight = false;
  let friendTogglePersistPending = false;
  async function applyFriendTogglesLive() {
    if (!settings) return;
    settings.friend_session_encryption = true;
    // Optimistic: push only friend fields so unsaved draft edits on other
    // settings keys are not leaked into the process-wide store.
    const cached = get(appSettings);
    if (cached) {
      setAppSettings({
        ...cached,
        friend_require_approval: settings.friend_require_approval,
        friend_chat_disabled: settings.friend_chat_disabled,
        friend_browse_disabled: settings.friend_browse_disabled,
        friend_session_encryption: true,
      });
    }
    if (friendTogglePersistInFlight) {
      // A later toggle flipped while we were writing — coalesce and re-run
      // with the latest values once the in-flight persist finishes.
      friendTogglePersistPending = true;
      return;
    }
    friendTogglePersistInFlight = true;
    try {
      do {
        friendTogglePersistPending = false;
        for (let attempt = 0; attempt < 2; attempt++) {
          const latest = await getSettings();
          const candidate = {
            ...latest,
            friend_require_approval: settings.friend_require_approval,
            friend_chat_disabled: settings.friend_chat_disabled,
            friend_browse_disabled: settings.friend_browse_disabled,
            friend_session_encryption: true,
          };
          try {
            const result = await updateSettings(candidate);
            setAppSettings(result.settings);
            settings.settings_revision = result.settings.settings_revision;
            if (originalSettings) {
              const baseline = JSON.parse(originalSettings) as AppSettings;
              baseline.friend_require_approval = result.settings.friend_require_approval;
              baseline.friend_chat_disabled = result.settings.friend_chat_disabled;
              baseline.friend_browse_disabled = result.settings.friend_browse_disabled;
              baseline.friend_session_encryption = true;
              baseline.settings_revision = result.settings.settings_revision;
              originalSettings = JSON.stringify(baseline);
            }
            break;
          } catch (e) {
            if (attempt === 0 && isSettingsRevisionConflict(e)) continue;
            throw e;
          }
        }
      } while (friendTogglePersistPending);
    } catch {
      // Optimistic UI already updated; full Save can still persist.
    } finally {
      friendTogglePersistInFlight = false;
      if (friendTogglePersistPending) {
        void applyFriendTogglesLive();
      }
    }
  }

  /**
   * Fold the persisted snapshot back into untouched form fields after save.
   * Fields edited again while IPC was in flight remain as unsaved changes.
   */
  function reconcileSavedSettings(draft: AppSettings, saved: AppSettings): void {
    if (!settings) return;
    const currentFields = settings as unknown as Record<string, unknown>;
    const draftFields = draft as unknown as Record<string, unknown>;
    const savedFields = saved as unknown as Record<string, unknown>;
    for (const key of Object.keys(savedFields)) {
      if (key === 'settings_revision') continue;
      if (sameSettingValue(currentFields[key], draftFields[key])) {
        currentFields[key] = savedFields[key];
      }
    }
    settings.settings_revision = saved.settings_revision;
  }

  async function handleSave() {
    if (!settings || saving) return;
    const validation = validateSettings(settings);
    if (validation.error) {
      showSaveMsg(validation.error, true, 5000);
      return;
    }
    saving = true;
    saveMessage = null;
    // Deep-clone at save-start, and send/compare against that clone rather
    // than the live `settings` object for the rest of this function. `settings`
    // stays bound to the form inputs while `updateSettings` is in flight, so
    // without this a mid-flight edit could change what gets attributed as
    // "saved" — leaving `originalSettings` (and the tcp/udp restart-prompt
    // comparison below) reflecting whatever `settings` drifted to by the time
    // the await resolves, not what this save actually persisted.
    const snapshot = JSON.stringify(settings);
    const draft = JSON.parse(snapshot) as AppSettings;
    // Friend session encryption is not user-toggleable in Settings; keep it on.
    draft.friend_session_encryption = true;
    settings.friend_session_encryption = true;
    try {
      let result: UpdateSettingsResult | null = null;
      let saved: AppSettings | null = null;
      let latestBeforeSave: AppSettings | null = null;

      // Refresh immediately before each write. Another command may have saved
      // settings while this page was open, and the backend correctly rejects
      // an old revision. Retry one genuine revision race with a fresh merge.
      for (let attempt = 0; attempt < 2; attempt++) {
        const latest = await getSettings();
        latestBeforeSave = latest;
        setAppSettings(latest);
        if (settings) settings.settings_revision = latest.settings_revision;
        const candidate = mergeDraftOntoLatest(draft, latest);
        candidate.friend_session_encryption = true;
        try {
          result = await updateSettings(candidate);
          saved = result.settings;
          break;
        } catch (e) {
          if (attempt === 0 && isSettingsRevisionConflict(e)) continue;
          if (isSettingsRevisionConflict(e)) {
            // Keep the page's token current even when sustained concurrent
            // writers win both attempts; never replace the user's draft.
            try {
              const refreshed = await getSettings();
              setAppSettings(refreshed);
              if (settings) settings.settings_revision = refreshed.settings_revision;
            } catch {
              // Preserve the original conflict as the actionable error.
            }
          }
          throw e;
        }
      }
      if (!result || !saved || !latestBeforeSave) return;

      // Keep the process-wide settings cache in step with the just-saved
      // values so runtime consumers (friend online-notification toast, chat
      // "disabled" state) react immediately instead of next launch.
      setAppSettings(saved);
      reconcileSavedSettings(draft, saved);
      originalSettings = JSON.stringify(saved);
      // Reflect the dev-console preference immediately so the sidebar link
      // appears/disappears without waiting for a reload.
      emberDevToolsEnabled.set(!!saved.ember_dev_tools_enabled);
      // `validation.adjusted` means at least one numeric field was outside
      // its valid range and got silently clamped by `validateSettings`
      // above — surface that alongside the normal save result instead of
      // saving a different value than what was typed with no feedback.
      const outcomeMessage = updateSettingsOutcomeMessage(result);
      const message = validation.adjusted
        ? `${outcomeMessage} ${m.settings_values_adjusted()}`
        : outcomeMessage;
      const isWarn = result.outcome !== 'applied' || validation.adjusted;
      showSaveMsg(message, isWarn, isWarn ? 8000 : 3000);

      // Compare against the authoritative pre-save snapshot, so an unrelated
      // out-of-band port change does not look like a change made by this save.
      // The TCP/UDP ports drive `start_upload_server` (TCP listen socket)
      // and the KAD/server UDP socket; both are bound exactly once during
      // app startup, so a hot save here updates the persisted value but
      // not the running listener. Prompt the user to restart.
      const previousTcpPort = latestBeforeSave.tcp_port;
      const previousUdpPort = latestBeforeSave.udp_port;
      const tcpChanged = previousTcpPort !== saved.tcp_port;
      const udpChanged = previousUdpPort !== saved.udp_port;
      if (tcpChanged || udpChanged) {
        if (tcpChanged && udpChanged) {
          pendingRestartReason = m.settings_restart_reason_both({
            tcp_from: String(previousTcpPort),
            tcp_to: String(saved.tcp_port),
            udp_from: String(previousUdpPort),
            udp_to: String(saved.udp_port),
          });
        } else if (tcpChanged) {
          pendingRestartReason = m.settings_restart_reason_tcp_only({
            from: String(previousTcpPort),
            to: String(saved.tcp_port),
          });
        } else {
          pendingRestartReason = m.settings_restart_reason_udp_only({
            from: String(previousUdpPort),
            to: String(saved.udp_port),
          });
        }
        showRestartPrompt = true;
      }
    } catch (e) {
      console.error('Failed to save:', e);
      showSaveMsg(translateError(e, m.settings_save_failed()), true, 5000);
    } finally {
      saving = false;
    }
  }

  /// Triggered from the restart confirmation modal. Mirrors SetupWizard's
  /// final-step behaviour: show a full-screen "Restarting Ember" overlay
  /// for ~600ms (so the user sees acknowledgement, not just an instant
  /// window disappearance), then call Tauri's `relaunch()` which kills
  /// the current process and spawns a fresh one. If `relaunch` fails for
  /// any reason (rare — usually only when the user lacks permission to
  /// re-spawn) we surface the error and let them save again or restart
  /// manually.
  async function performRestart() {
    showRestartPrompt = false;
    restarting = true;
    try {
      // Brief delay so the overlay has time to paint before the process
      // dies — purely cosmetic, matches the wizard.
      await new Promise(r => setTimeout(r, 600));
      await relaunch();
    } catch (e) {
      restarting = false;
      showSaveMsg(
        m.settings_restart_failed({ error: translateError(e) }),
        true,
        10000,
      );
    }
  }

  function dismissRestartPrompt() {
    showRestartPrompt = false;
    showSaveMsg(
      m.settings_restart_deferred(),
      true,
      6000,
    );
  }

  function resetChanges() {
    if (!settings || !originalSettings) return;
    try {
      settings = JSON.parse(originalSettings) as AppSettings;
      // The anti-leech pattern textarea is edited via its own `antileechDraft`
      // state (saved with a dedicated button), so a plain settings revert
      // wouldn't touch it. Revert it to the last loaded/saved snapshot too so
      // "Discard" reverts everything the user sees as pending.
      if (antileechSnapshot) antileechDraft = antileechSnapshot.patterns.join('\n');
      showSaveMsg(m.settings_changes_reverted(), false, 2000);
    } catch (e) {
      // `originalSettings` should always be valid JSON we serialized
      // ourselves, but a storage glitch or an upstream bug elsewhere
      // could leave it corrupt — surface the error and re-fetch from
      // disk rather than crashing the Revert button.
      console.error('resetChanges: originalSettings parse failed', e);
      showSaveMsg(
        m.settings_revert_failed(),
        true,
        3000,
      );
      void getSettings()
        .then((s) => {
          settings = s;
          originalSettings = JSON.stringify(s);
        })
        .catch((err) => {
          showSaveMsg(m.settings_reload_failed({ error: translateError(err) }), true, 4000);
        });
    }
  }

  async function refreshSpamStats() {
    spamStatsLoading = true;
    spamStatsError = null;
    try {
      const s = await getSpamStats();
      if (unmounted) return;
      spamStats = s;
    } catch (e: unknown) {
      if (unmounted) return;
      spamStatsError = translateError(e, m.settings_spam_load_failed());
    } finally {
      if (!unmounted) spamStatsLoading = false;
    }
  }

  // Spam reset uses the themed `ConfirmDialog` (rather than the
  // browser's `window.confirm`) so the prompt matches every other
  // destructive confirmation in Ember (transfers cancel, library
  // delete, IP-filter range remove, etc.) — same focus trap, same dark
  // theme, same Escape-to-cancel.
  let spamResetConfirmOpen = $state(false);

  function handleResetSpamData() {
    spamResetConfirmOpen = true;
  }

  async function confirmResetSpamData() {
    spamResetting = true;
    try {
      await resetSpamFilter();
      await refreshSpamStats();
      showSaveMsg(m.settings_spam_reset_success(), false, 3000);
    } catch (e: unknown) {
      showSaveMsg(translateError(e, m.settings_spam_reset_failed()), true, 5000);
    } finally {
      spamResetting = false;
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
      // Surface the failure in the same toast row that other settings
      // actions use; previously this only logged to the console, so a
      // denied permission or a missing dialog plugin looked silent to
      // the user.
      console.error('Folder pick failed:', e);
      const msg = translateError(e, m.settings_folder_picker_generic_error());
      showSaveMsg(m.settings_folder_picker_failed({ error: msg }), true, 5000);
    }
  }

  function showIpFilterDownloadOutcome(result: IpFilterDownloadResult) {
    const message = ipFilterDownloadOutcomeMessage(result);
    if (result.outcome === 'failed') {
      filterResult = null;
      filterResultWarning = false;
      filterError = message;
      trackedTimeout(() => (filterError = null), 5000);
      return;
    }
    filterError = null;
    filterResult = message;
    filterResultWarning = result.outcome === 'deferred';
    trackedTimeout(() => {
      filterResult = null;
      filterResultWarning = false;
    }, 5000);
  }

  async function handleDownloadFilter() {
    downloadingFilter = true;
    filterResult = null;
    filterResultWarning = false;
    filterError = null;
    try {
      showIpFilterDownloadOutcome(await downloadIpfilter());
    } catch (e: unknown) {
      filterError = translateError(e, m.settings_download_failed());
      trackedTimeout(() => (filterError = null), 5000);
    } finally {
      downloadingFilter = false;
    }
  }

  function showNodesDownloadOutcome(result: NodesDatDownloadResult) {
    nodesError = null;
    nodesResult = nodesDownloadOutcomeMessage(result);
    nodesResultWarning = result.outcome !== 'applied';
    trackedTimeout(() => {
      nodesResult = null;
      nodesResultWarning = false;
    }, 5000);
  }

  // Anti-leech filter state — loaded lazily when the Security section
  // is first opened so the rest of Settings doesn't pay the IPC round
  // trip. The textarea below is bound to `antileechDraft` (newline-
  // joined patterns); we only push to the backend when the user clicks
  // Save, so the pattern list isn't recompiled on every keystroke.
  let antileechSnapshot: AntiLeechSnapshot | null = $state(null);
  let antileechDraft = $state('');
  let antileechSaving = $state(false);
  let antileechMessage: { kind: 'ok' | 'warn' | 'err'; text: string } | null = $state(null);
  let antileechCompileErrors: Array<[string, string]> = $state([]);
  let antileechLoaded = $state(false);
  // The anti-leech textarea has its own dedicated Save button
  // (`handleSaveAntileech`) and isn't part of `settings`, so it needs its
  // own dirty check folded into `hasUnsavedChanges` above — otherwise edits
  // here are invisible to the "unsaved changes" indicator, `beforeunload`,
  // and Discard (which reverts `antileechDraft` in `resetChanges` below,
  // but stayed disabled unless `settings` itself also had changes).
  let antileechDraftDirty = $derived.by(() => {
    // Narrow via a local const first — TS doesn't reliably narrow a
    // `$state`-backed getter read directly inside a ternary the way it
    // would a plain variable.
    const snap = antileechSnapshot;
    return antileechLoaded && snap ? antileechDraft !== snap.patterns.join('\n') : false;
  });
  // Declared here (rather than alongside `settings`/`originalSettings`
  // above) so `antileechDraftDirty`'s declaration precedes its use — Svelte's
  // `$derived` is lazy and immune to ordering at runtime, but the type
  // checker still applies plain TDZ analysis to the referenced binding.
  let hasUnsavedChanges = $derived(
    (settings ? JSON.stringify(settings) !== originalSettings : false) || antileechDraftDirty
  );

  async function loadAntileech() {
    antileechMessage = null;
    try {
      const snap = await getAntileechPatterns();
      if (unmounted) return;
      antileechSnapshot = snap;
      antileechDraft = snap.patterns.join('\n');
      antileechLoaded = true;
    } catch (e: unknown) {
      if (unmounted) return;
      antileechMessage = {
        kind: 'err',
        text: m.settings_antileech_load_failed({ error: translateError(e) }),
      };
    }
  }

  async function handleSaveAntileech() {
    antileechSaving = true;
    antileechMessage = null;
    antileechCompileErrors = [];
    try {
      const patterns = antileechDraft
        .split(/\r?\n/)
        .map((line) => line.trim())
        // Backend ignores blanks + #-comments too, but stripping them
        // here keeps the on-disk file clean when round-tripped.
        .filter((line) => line.length > 0 && !line.startsWith('#'));
      const result = await setAntileechPatterns(patterns);
      antileechSnapshot = result.snapshot;
      antileechDraft = result.snapshot.patterns.join('\n');
      antileechCompileErrors = result.compile_errors;
      if (result.compile_errors.length > 0) {
        const savedCount = result.snapshot.pattern_count;
        const rejected = String(result.compile_errors.length);
        antileechMessage = {
          kind: 'warn',
          text: savedCount === 1
            ? m.settings_antileech_saved_rejected_one({ rejected })
            : m.settings_antileech_saved_rejected_other({ count: savedCount, rejected }),
        };
      } else {
        const savedCount = result.snapshot.pattern_count;
        antileechMessage = {
          kind: 'ok',
          text: savedCount === 1
            ? m.settings_antileech_saved_one()
            : m.settings_antileech_saved_other({ count: savedCount }),
        };
        trackedTimeout(() => (antileechMessage = null), 4000);
      }
    } catch (e: unknown) {
      antileechMessage = {
        kind: 'err',
        text: m.settings_antileech_save_failed({ error: translateError(e) }),
      };
    } finally {
      antileechSaving = false;
    }
  }

  async function handleAntileechToggle(checked: boolean, gen: number) {
    try {
      await setAntileechEnabled(checked);
      // A newer toggle superseded this one while the IPC was in flight, or the
      // page unmounted — stop so a slow earlier response can't clobber the
      // latest state (or write to a torn-down page).
      if (unmounted || gen !== antileechToggleGen) return;
      if (settings) settings.antileech_enabled = checked;
      // The toggle is applied + persisted independently of the Save button, so
      // fold it into the saved baseline too. Otherwise `hasUnsavedChanges` (a
      // JSON diff against `originalSettings`) reports a phantom unsaved change
      // — and the beforeunload guard fires — for a change already on disk.
      // Patch only this one field so other genuinely-unsaved edits stay flagged.
      if (originalSettings) {
        try {
          const base = JSON.parse(originalSettings) as AppSettings;
          base.antileech_enabled = checked;
          originalSettings = JSON.stringify(base);
        } catch { /* malformed baseline; leave as-is */ }
      }
      // Also refresh the snapshot so the on-disk badge stays in sync.
      if (antileechLoaded) {
        const snap = await getAntileechPatterns();
        if (unmounted || gen !== antileechToggleGen) return;
        antileechSnapshot = snap;
      }
    } catch (e: unknown) {
      if (unmounted || gen !== antileechToggleGen) return;
      const text = m.settings_antileech_toggle_failed({ error: translateError(e) });
      antileechMessage = {
        kind: 'err',
        text,
      };
      showSaveMsg(text, true, 5000);
      // Revert UI toggle state since the backend refused the change. Keep the
      // sync-effect baseline aligned with the reverted value so the effect does
      // NOT immediately re-fire with the opposite `want` — otherwise a backend
      // that keeps failing would make the toggle oscillate, hammering the
      // backend with alternating enable/disable calls.
      if (settings) settings.antileech_enabled = !checked;
      lastAppliedAntileechToggle = !checked;
    }
  }

  let antileechResetConfirmOpen = $state(false);

  function handleResetAntileech() {
    antileechResetConfirmOpen = true;
  }

  async function confirmResetAntileech() {
    antileechSaving = true;
    antileechMessage = null;
    antileechCompileErrors = [];
    try {
      const snap = await resetAntileechToDefaults();
      antileechSnapshot = snap;
      antileechDraft = snap.patterns.join('\n');
      antileechMessage = {
        kind: 'ok',
        text: snap.pattern_count === 1
          ? m.settings_antileech_restored_one()
          : m.settings_antileech_restored_other({ count: snap.pattern_count }),
      };
      trackedTimeout(() => (antileechMessage = null), 4000);
    } catch (e: unknown) {
      antileechMessage = {
        kind: 'err',
        text: m.settings_antileech_reset_failed({ error: translateError(e) }),
      };
    } finally {
      antileechSaving = false;
    }
  }

  // Lazy-load the snapshot the first time the Security section is opened
  // (or on initial load if it's the active section). Avoids paying the
  // backend round-trip just to render the rest of Settings.
  $effect(() => {
    if (activeSection === 'security' && !antileechLoaded) {
      loadAntileech();
    }
  });

  // Push the enabled-flag to the backend whenever the toggle moves.
  // Done as an effect so the ToggleSwitch can stay generic
  // (`bind:checked`) without needing an onchange prop. The baseline
  // is seeded from the loaded settings in `onMount` so the initial
  // assignment of `settings` is treated as already-applied and we do
  // not re-push the persisted value on first paint (which used to
  // race with `handleAntileechToggle`'s catch path and could flip the
  // backend off if that redundant call ever failed).
  let lastAppliedAntileechToggle: boolean | null = $state(null);
  // Monotonic id so only the most recent toggle's async response is allowed
  // to mutate state — guards against rapid toggling resolving out of order.
  let antileechToggleGen = 0;
  $effect(() => {
    if (!settings) return;
    const want = settings.antileech_enabled;
    if (lastAppliedAntileechToggle === want) return;
    lastAppliedAntileechToggle = want;
    void handleAntileechToggle(want, ++antileechToggleGen);
  });

  async function handleDownloadNodes() {
    downloadingNodes = true;
    nodesResult = null;
    nodesResultWarning = false;
    nodesError = null;
    try {
      showNodesDownloadOutcome(await downloadNodesDat());
    } catch (e: unknown) {
      nodesError = translateError(e, m.settings_download_failed());
      trackedTimeout(() => (nodesError = null), 5000);
    } finally {
      downloadingNodes = false;
    }
  }

  function setTheme(t: Theme) {
    theme.set(t);
    applyTheme(t);
  }

  // Local helper used by the close-behavior radio cards. The arrow
  // callbacks the buttons emit lose the `settings != null` narrowing
  // svelte-check derives from the surrounding `{:else}` branch, so we
  // route the assignment through a function with an explicit guard.
  function pickCloseBehavior(behavior: 'ask' | 'tray' | 'exit') {
    if (!settings) return;
    settings.close_to_tray_behavior = behavior;
  }

  function handleRadioGroupKey(
    event: KeyboardEvent,
    values: string[],
    current: string,
    select: (value: string) => void,
  ) {
    let nextIndex: number;
    const currentIndex = Math.max(0, values.indexOf(current));
    switch (event.key) {
      case 'ArrowRight':
      case 'ArrowDown':
        nextIndex = (currentIndex + 1) % values.length;
        break;
      case 'ArrowLeft':
      case 'ArrowUp':
        nextIndex = (currentIndex - 1 + values.length) % values.length;
        break;
      case 'Home':
        nextIndex = 0;
        break;
      case 'End':
        nextIndex = values.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    const next = values[nextIndex];
    select(next);
    const group = (event.currentTarget as HTMLElement).closest('[role="radiogroup"]');
    requestAnimationFrame(() => {
      const radios = group?.querySelectorAll<HTMLElement>('[role="radio"]') ?? [];
      Array.from(radios)
        .find((radio) => radio.dataset.radioValue === next)
        ?.focus();
    });
  }

  const languageRadioValues = ['system', ...locales];
  const closeBehaviorValues = ['ask', 'tray', 'exit'];

  $effect(() => {
    activeSection;
    untrack(() => {
      if (pageContentEl) pageContentEl.scrollTop = 0;
    });
  });

  // USS needs a non-zero upload cap. Clear the flag when the user switches
  // to Unlimited so save can't persist an inert/invalid combo.
  $effect(() => {
    if (settings && settings.max_upload_speed === 0 && settings.uss_enabled) {
      settings.uss_enabled = false;
    }
  });
</script>

<div class="page-header sticky-header">
  <h2>{m.settings_title()}</h2>
  <div class="header-actions">
    {#if saveMessage}
      <span class="save-status" class:warning={saveIsWarning} role="status">{saveMessage}</span>
    {/if}
    {#if hasUnsavedChanges}
      <span class="unsaved-indicator">{m.settings_unsaved_changes()}</span>
    {/if}
    <button class="ghost" onclick={resetChanges} disabled={!hasUnsavedChanges || !settings}>
      {m.settings_discard()}
    </button>
    <button class="save-btn" onclick={handleSave} disabled={saving || !settings}>
      {#if saving}
        <span class="spinner"></span> {m.settings_saving()}
      {:else}
        {m.settings_save_changes()}
      {/if}
    </button>
  </div>
</div>

<div class="page-content" bind:this={pageContentEl}>
  {#if loadError}
    <div class="empty-state">
      <p style="color: var(--danger)">{loadError}</p>
      <button onclick={() => { loadError = null; location.reload(); }}>{m.layout_retry()}</button>
    </div>
  {:else if !settings}
    <div class="empty-state">
      <div class="spinner lg"></div>
      <p>{m.settings_loading()}</p>
    </div>
  {:else}
    <div class="settings-layout">
      <aside class="settings-nav" aria-label={m.settings_nav_aria()}>
        <div class="settings-nav-title">{m.settings_title()}</div>
        {#each sections as section}
          <button
            class="settings-nav-item"
            class:active={activeSection === section}
            aria-current={activeSection === section ? 'page' : undefined}
            onclick={() => activeSection = section}
          >
            <span class="settings-nav-icon" aria-hidden="true">
              {#if section === 'general'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <line x1="3" y1="5.5" x2="17" y2="5.5"/>
                  <line x1="3" y1="10" x2="17" y2="10"/>
                  <line x1="3" y1="14.5" x2="17" y2="14.5"/>
                </svg>
              {:else if section === 'downloads'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <line x1="10" y1="3" x2="10" y2="13"/>
                  <polyline points="6,9.5 10,13.5 14,9.5"/>
                  <line x1="4" y1="17" x2="16" y2="17"/>
                </svg>
              {:else if section === 'bandwidth'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <line x1="7" y1="3" x2="7" y2="17"/>
                  <polyline points="3.5,6.5 7,3 10.5,6.5"/>
                  <line x1="13" y1="3" x2="13" y2="17"/>
                  <polyline points="9.5,13.5 13,17 16.5,13.5"/>
                </svg>
              {:else if section === 'network'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="10" cy="4" r="2"/>
                  <circle cx="4" cy="15" r="2"/>
                  <circle cx="16" cy="15" r="2"/>
                  <line x1="10" y1="6" x2="5" y2="13"/>
                  <line x1="10" y1="6" x2="15" y2="13"/>
                  <line x1="6" y1="15" x2="14" y2="15"/>
                </svg>
              {:else if section === 'security'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M10 2L3 6v4c0 4.4 3 8.5 7 10 4-1.5 7-5.6 7-10V6l-7-4z"/>
                  <polyline points="7,10 9.5,12.5 13.5,7.5"/>
                </svg>
              {:else if section === 'friends'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="7" cy="6" r="3"/>
                  <circle cx="14" cy="7" r="2.5"/>
                  <path d="M1 17c0-3.3 2.7-6 6-6s6 2.7 6 6"/>
                  <path d="M13 11.5c2.5 0 4.5 2 4.5 4.5"/>
                </svg>
              {:else if section === 'search'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="8.5" cy="8.5" r="5.5"/>
                  <line x1="12.5" y1="12.5" x2="17" y2="17"/>
                </svg>
              {:else if section === 'backup'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="2.5" y="4" width="15" height="4" rx="1"/>
                  <path d="M4 8v7.5c0 .6.4 1 1 1h10c.6 0 1-.4 1-1V8"/>
                  <line x1="8" y1="11.5" x2="12" y2="11.5"/>
                </svg>
              {:else if section === 'about'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="10" cy="10" r="7.5"/>
                  <line x1="10" y1="9" x2="10" y2="14"/>
                  <circle cx="10" cy="6.5" r="0.6" fill="currentColor"/>
                </svg>
              {/if}
            </span>
            <span>{sectionLabel(section)}</span>
          </button>
        {/each}
      </aside>

      <div class="cards-grid">

      <!-- General -->
      <section class="card" class:hidden={activeSection !== 'general'}>
        <div class="card-header">
          <span class="card-icon">&#9775;</span>
          <div>
            <h3>{m.settings_section_general()}</h3>
            <p class="card-desc">{m.settings_general_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field">
            <span class="field-label">{m.settings_theme_label()}</span>
            <div class="theme-picker">
              <button
                class="theme-swatch"
                class:selected={$theme === 'light'}
                onclick={() => setTheme('light')}
                aria-label={m.settings_theme_light_aria()}
              >
                <div class="swatch-preview light-swatch">
                  <div class="swatch-sidebar"></div>
                  <div class="swatch-content">
                    <div class="swatch-line"></div>
                    <div class="swatch-line short"></div>
                  </div>
                </div>
                {#if $theme === 'light'}<span class="swatch-check">&#10003;</span>{/if}
                <span class="swatch-label">{m.settings_theme_light()}</span>
              </button>
              <button
                class="theme-swatch"
                class:selected={$theme === 'dark'}
                onclick={() => setTheme('dark')}
                aria-label={m.settings_theme_dark_aria()}
              >
                <div class="swatch-preview dark-swatch">
                  <div class="swatch-sidebar"></div>
                  <div class="swatch-content">
                    <div class="swatch-line"></div>
                    <div class="swatch-line short"></div>
                  </div>
                </div>
                {#if $theme === 'dark'}<span class="swatch-check">&#10003;</span>{/if}
                <span class="swatch-label">{m.settings_theme_dark()}</span>
              </button>
            </div>
          </div>
          <div class="field">
            <span class="field-label">{m.settings_language_label()}</span>
            <span class="hint">{m.settings_language_description()}</span>
            <!--
              Radio-style locale picker. We render one button per
              compiled locale (Paraglide exports the canonical list
              as `locales`) so adding a new language to the project
              automatically grows the picker — no UI edit needed.
              Each label uses `languageLabel(locale)` which renders
              the language name in its OWN language ("Español", not
              "Spanish") because users recognize their native
              language faster than a translation of it.
            -->
            <div class="behavior-picker" role="radiogroup" aria-label={m.settings_language_label()}>
              <!--
                "System" radio: clears the explicit localStorage
                choice and reloads, letting Paraglide's strategy
                chain fall through to navigator.language / baseLocale.
                Without this entry, a user who tried Spanish once
                would be stuck on Spanish even if their OS locale
                changed — there'd be no way back to "just follow the
                OS" short of clearing localStorage by hand.
              -->
              <button
                type="button"
                role="radio"
                data-radio-value="system"
                tabindex={followingSystem ? 0 : -1}
                aria-checked={followingSystem}
                class="behavior-card lang-card"
                class:selected={followingSystem}
                onclick={pickSystemLocale}
                onkeydown={(e) =>
                  handleRadioGroupKey(
                    e,
                    languageRadioValues,
                    followingSystem ? 'system' : currentLocale,
                    (value) => value === 'system' ? pickSystemLocale() : pickLocale(value as Locale),
                  )}
              >
                <span class="behavior-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="9" />
                    <path d="M3 12h18" />
                    <path d="M12 3a14 14 0 0 1 0 18" />
                    <path d="M12 3a14 14 0 0 0 0 18" />
                  </svg>
                </span>
                <span class="behavior-title">{m.settings_language_system()}</span>
                <span class="behavior-desc">{languageLabel(systemPreviewLocale)}</span>
                {#if followingSystem}<span class="behavior-check" aria-hidden="true">&#10003;</span>{/if}
              </button>
              {#each locales as loc (loc)}
                <button
                  type="button"
                  role="radio"
                  data-radio-value={loc}
                  tabindex={!followingSystem && currentLocale === loc ? 0 : -1}
                  aria-checked={!followingSystem && currentLocale === loc}
                  class="behavior-card lang-card"
                  class:selected={!followingSystem && currentLocale === loc}
                  onclick={() => pickLocale(loc)}
                  onkeydown={(e) =>
                    handleRadioGroupKey(
                      e,
                      languageRadioValues,
                      followingSystem ? 'system' : currentLocale,
                      (value) => value === 'system' ? pickSystemLocale() : pickLocale(value as Locale),
                    )}
                >
                  {#if localeFlagSrc(loc)}
                    <span class="behavior-icon lang-flag-icon" aria-hidden="true">
                      <img class="lang-flag" src={localeFlagSrc(loc)} alt="" />
                    </span>
                  {/if}
                  <span class="behavior-title">{languageLabel(loc)}</span>
                  <span class="behavior-desc">{loc.toUpperCase()}</span>
                  {#if !followingSystem && currentLocale === loc}<span class="behavior-check" aria-hidden="true">&#10003;</span>{/if}
                </button>
              {/each}
            </div>
          </div>
          <div class="field">
            <label for="nickname">{m.settings_nickname_label()}</label>
            <input id="nickname" bind:value={settings.nickname} maxlength="128" placeholder={m.settings_nickname_placeholder()} />
          </div>
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_launch_maximized_label()}</span>
              <span class="hint">{m.settings_launch_maximized_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.launch_maximized} ariaLabel={m.settings_launch_maximized_label()} />
          </div>
          <div class="field">
            <span class="field-label">{m.settings_close_behavior_label()}</span>
            <span class="hint">
              {m.settings_close_behavior_hint()}
            </span>
            <div class="behavior-picker" role="radiogroup" aria-label={m.settings_close_behavior_label()}>
              <button
                type="button"
                role="radio"
                data-radio-value="ask"
                tabindex={settings.close_to_tray_behavior === 'ask' ? 0 : -1}
                aria-checked={settings.close_to_tray_behavior === 'ask'}
                class="behavior-card"
                class:selected={settings.close_to_tray_behavior === 'ask'}
                onclick={() => pickCloseBehavior('ask')}
                onkeydown={(e) =>
                  handleRadioGroupKey(
                    e,
                    closeBehaviorValues,
                    settings?.close_to_tray_behavior ?? 'ask',
                    (value) => pickCloseBehavior(value as 'ask' | 'tray' | 'exit'),
                  )}
              >
                <span class="behavior-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M4 5.5A1.5 1.5 0 0 1 5.5 4h13A1.5 1.5 0 0 1 20 5.5v9A1.5 1.5 0 0 1 18.5 16H13l-4 4v-4H5.5A1.5 1.5 0 0 1 4 14.5z"/>
                    <path d="M9.5 8.5a2.5 2.5 0 1 1 3.7 2.2c-.7.4-1.2.9-1.2 1.6"/>
                    <circle cx="12" cy="14" r="0.6" fill="currentColor"/>
                  </svg>
                </span>
                <span class="behavior-title">{m.settings_close_behavior_ask()}</span>
                <span class="behavior-desc">{m.settings_close_behavior_ask_desc()}</span>
                {#if settings.close_to_tray_behavior === 'ask'}<span class="behavior-check" aria-hidden="true">&#10003;</span>{/if}
              </button>

              <button
                type="button"
                role="radio"
                data-radio-value="tray"
                tabindex={settings.close_to_tray_behavior === 'tray' ? 0 : -1}
                aria-checked={settings.close_to_tray_behavior === 'tray'}
                class="behavior-card"
                class:selected={settings.close_to_tray_behavior === 'tray'}
                onclick={() => pickCloseBehavior('tray')}
                onkeydown={(e) =>
                  handleRadioGroupKey(
                    e,
                    closeBehaviorValues,
                    settings?.close_to_tray_behavior ?? 'ask',
                    (value) => pickCloseBehavior(value as 'ask' | 'tray' | 'exit'),
                  )}
              >
                <span class="behavior-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3.5" y="3.5" width="17" height="11" rx="2"/>
                    <line x1="12" y1="6.5" x2="12" y2="13"/>
                    <polyline points="9,10.5 12,13.5 15,10.5"/>
                    <line x1="3.5" y1="19" x2="20.5" y2="19"/>
                  </svg>
                </span>
                <span class="behavior-title">{m.settings_close_behavior_tray()}</span>
                <span class="behavior-desc">{m.settings_close_behavior_tray_desc()}</span>
                {#if settings.close_to_tray_behavior === 'tray'}<span class="behavior-check" aria-hidden="true">&#10003;</span>{/if}
              </button>

              <button
                type="button"
                role="radio"
                data-radio-value="exit"
                tabindex={settings.close_to_tray_behavior === 'exit' ? 0 : -1}
                aria-checked={settings.close_to_tray_behavior === 'exit'}
                class="behavior-card"
                class:selected={settings.close_to_tray_behavior === 'exit'}
                onclick={() => pickCloseBehavior('exit')}
                onkeydown={(e) =>
                  handleRadioGroupKey(
                    e,
                    closeBehaviorValues,
                    settings?.close_to_tray_behavior ?? 'ask',
                    (value) => pickCloseBehavior(value as 'ask' | 'tray' | 'exit'),
                  )}
              >
                <span class="behavior-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M13 4h5a1.5 1.5 0 0 1 1.5 1.5v13A1.5 1.5 0 0 1 18 20h-5"/>
                    <line x1="15" y1="12" x2="4" y2="12"/>
                    <polyline points="7.5,8.5 4,12 7.5,15.5"/>
                  </svg>
                </span>
                <span class="behavior-title">{m.settings_close_behavior_exit()}</span>
                <span class="behavior-desc">{m.settings_close_behavior_exit_desc()}</span>
                {#if settings.close_to_tray_behavior === 'exit'}<span class="behavior-check" aria-hidden="true">&#10003;</span>{/if}
              </button>
            </div>
          </div>
        </div>
      </section>

      <!-- Transfers -->
      <section class="card" class:hidden={activeSection !== 'downloads'}>
        <div class="card-header">
          <span class="card-icon">&#8615;</span>
          <div>
            <h3>{m.settings_section_downloads()}</h3>
            <p class="card-desc">{m.settings_downloads_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field">
            <label for="download-folder">{m.settings_download_folder_label()}</label>
            <div class="folder-input">
              <input id="download-folder" value={settings.download_folder} readonly />
              <button class="folder-btn" onclick={pickDownloadFolder}>{m.settings_browse()}</button>
            </div>
            <span class="field-hint">{m.settings_folder_layout_hint({ folder: settings.download_folder })}</span>
          </div>
          <div class="field-row">
            <div class="field half">
              <label for="max-concurrent">{m.settings_max_downloads()}</label>
              <input id="max-concurrent" type="number" min="1" max="50" bind:value={settings.max_concurrent_downloads} />
            </div>
            <div class="field half">
              <label for="max-uploads">{m.settings_max_uploads()}</label>
              <input id="max-uploads" type="number" min="1" max="50" bind:value={settings.max_concurrent_uploads} />
            </div>
          </div>

          <div class="field">
            <label for="max-dl-gib">{m.settings_max_file_size_label()}</label>
            <input id="max-dl-gib" type="number" min="1" max="593" bind:value={settings.max_download_file_size_gib} />
            <span class="hint">{m.settings_max_file_size_hint()}</span>
          </div>

          <!-- Protocol budget / retry knobs (max_sources, max_connections,
               queue wait, retry rounds) stay in AppSettings for config.json
               and backend clamps, but are intentionally not exposed here. -->

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_add_paused()}</span>
              <span class="hint">{m.settings_add_paused_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.add_downloads_paused} ariaLabel={m.settings_add_paused()} />
          </div>
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_auto_remove()}</span>
              <span class="hint">{m.settings_auto_remove_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.remove_finished_downloads} ariaLabel={m.settings_auto_remove()} />
          </div>
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_preview_priority_all()}</span>
              <span class="hint">{m.settings_preview_priority_all_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.preview_priority_all} ariaLabel={m.settings_preview_priority_all()} />
          </div>
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_skip_compress_video()}</span>
              <span class="hint">{m.settings_skip_compress_video_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.skip_compress_video} ariaLabel={m.settings_skip_compress_video()} />
          </div>

          <div class="field">
            <span class="toggle-title">{m.settings_download_history()}</span>
            <span class="field-hint">
              {m.settings_download_history_hint()}
            </span>
            <div class="history-grid">
              <div class="history-card">
                <div class="history-stat-body">
                  <span class="history-stat-label">{m.settings_history_stat_completed()}</span>
                  <strong class="history-stat-value" class:is-loading={historyStatsLoading}>
                    {historyStatsLoading ? m.settings_history_stats_loading() : historyStatsError ? '—' : historyStats?.completed ?? 0}
                  </strong>
                </div>
                <button class="history-clear-btn" onclick={() => requestClearHistory('completed')}>{m.settings_clear_completed()}</button>
              </div>
              <div class="history-card">
                <div class="history-stat-body">
                  <span class="history-stat-label">{m.settings_history_stat_cancelled()}</span>
                  <strong class="history-stat-value" class:is-loading={historyStatsLoading}>
                    {historyStatsLoading ? m.settings_history_stats_loading() : historyStatsError ? '—' : historyStats?.cancelled ?? 0}
                  </strong>
                </div>
                <button class="history-clear-btn" onclick={() => requestClearHistory('cancelled')}>{m.settings_clear_cancelled()}</button>
              </div>
              <div class="history-card history-card-total">
                <div class="history-stat-body">
                  <span class="history-stat-label">{m.settings_history_stat_total()}</span>
                  <strong class="history-stat-value" class:is-loading={historyStatsLoading}>
                    {historyStatsLoading ? m.settings_history_stats_loading() : historyStatsError ? '—' : historyStats?.total ?? 0}
                  </strong>
                </div>
                <button class="history-clear-btn" onclick={() => requestClearHistory('all')}>{m.settings_clear_all_history()}</button>
              </div>
            </div>
            {#if historyStatsError}
              <span class="hint" style="margin-top: 4px; color: var(--danger);">{historyStatsError}</span>
            {/if}
            {#if historyClearMsg}
              <span class="hint" style="margin-top: 4px;">{historyClearMsg}</span>
            {/if}
          </div>
        </div>
      </section>

      <!-- Search -->
      <section class="card" class:hidden={activeSection !== 'search'}>
        <div class="card-header">
          <span class="card-icon">&#x1F50D;</span>
          <div>
            <h3>{m.settings_section_search()}</h3>
            <p class="card-desc">{m.settings_search_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_spam_filter()}</span>
              <span class="hint">{m.settings_spam_filter_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.spam_filter_enabled} ariaLabel={m.settings_spam_filter()} />
          </div>
          <div class="field">
            <label for="spam-filter-profile">{m.settings_spam_profile_label()}</label>
            <span class="hint">{m.settings_spam_profile_hint()}</span>
            <select
              id="spam-filter-profile"
              bind:value={settings.spam_filter_profile}
              disabled={!settings.spam_filter_enabled}
            >
              <option value="relaxed">{m.settings_spam_profile_relaxed()}</option>
              <option value="balanced">{m.settings_spam_profile_balanced()}</option>
              <option value="aggressive">{m.settings_spam_profile_aggressive()}</option>
            </select>
          </div>
          <div class="field">
            <span class="field-label">{m.settings_spam_db_label()}</span>
            <span class="hint">{m.settings_spam_db_hint()}</span>
            {#if spamStatsLoading}
              <span class="hint">{m.settings_spam_loading()}</span>
            {:else if spamStatsError}
              <span class="hint" style="color: var(--danger)">{spamStatsError}</span>
            {:else if spamStats}
              <div class="spam-stats-grid">
                <div class="spam-stat"><span>{m.settings_spam_stat_hashes()}</span><strong>{spamStats.spam_hashes}</strong></div>
                <div class="spam-stat"><span>{m.settings_spam_stat_not_spam_hashes()}</span><strong>{spamStats.not_spam_hashes}</strong></div>
                <div class="spam-stat"><span>{m.settings_spam_stat_names()}</span><strong>{spamStats.spam_filenames}</strong></div>
                <div class="spam-stat"><span>{m.settings_spam_stat_source_ips()}</span><strong>{spamStats.spam_source_ips}</strong></div>
              </div>
            {/if}
            <div class="action-row" style="margin-top:8px;">
              <button class="action-btn" onclick={refreshSpamStats} disabled={spamStatsLoading || spamResetting}>{m.settings_refresh_stats()}</button>
              <button class="danger" onclick={handleResetSpamData} disabled={spamResetting}>
                {spamResetting ? m.settings_resetting() : m.settings_reset_spam_data()}
              </button>
            </div>
          </div>
          <div class="field">
            <label for="search-timeout-secs">{m.settings_search_timeout_label()}</label>
            <span class="hint">{m.settings_search_timeout_hint()}</span>
            <input
              id="search-timeout-secs"
              type="number"
              min="30"
              max="600"
              step="1"
              bind:value={settings.search_timeout_secs}
            />
          </div>
          <div class="field">
            <label for="filename-cleanups">{m.settings_filename_cleanups_label()}</label>
            <span class="hint">{m.settings_filename_cleanups_hint_prefix()} <code>{m.settings_filename_cleanups_placeholder()}</code>{m.settings_filename_cleanups_hint_suffix()}</span>
            <input id="filename-cleanups" type="text" bind:value={settings.filename_cleanups} placeholder={m.settings_filename_cleanups_placeholder()} />
          </div>
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_save_search_history()}</span>
              <span class="hint">{m.settings_save_search_history_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.save_search_history} ariaLabel={m.settings_save_search_history()} />
          </div>
        </div>
      </section>

      <!-- Bandwidth -->
      <section class="card" class:hidden={activeSection !== 'bandwidth'}>
        <div class="card-header">
          <span class="card-icon">&#8693;</span>
          <div>
            <h3>{m.settings_section_bandwidth()}</h3>
            <p class="card-desc">{m.settings_bandwidth_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field">
            <SpeedInput label={m.settings_max_upload_speed()} bind:value={settings.max_upload_speed} />
          </div>
          <div class="field">
            <SpeedInput label={m.settings_max_download_speed()} bind:value={settings.max_download_speed} />
          </div>
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_uss_label()}</span>
              <span class="hint">{m.settings_uss_hint()}</span>
            </div>
            <ToggleSwitch
              bind:checked={settings.uss_enabled}
              disabled={settings.max_upload_speed === 0}
              ariaLabel={m.settings_uss_label()}
            />
          </div>
          <div class="field speed-test-section">
            <div class="speed-test-header">
              <span class="toggle-title">{m.settings_speed_test_label()}</span>
              <button class="speed-test-btn" onclick={runSpeedTest} disabled={speedTesting}>
                {speedTesting ? m.settings_speed_testing() : m.settings_run_speed_test()}
              </button>
            </div>
            <span class="hint">{m.settings_speed_test_hint()}</span>
            {#if speedResult}
              <div class="speed-results">
                <div class="speed-row">
                  <span>{m.settings_speed_download()}</span>
                  <span class="speed-value">{formatSpeed(speedResult.download_speed)}</span>
                </div>
                <div class="speed-row">
                  <span>{m.settings_speed_upload()}</span>
                  <span class="speed-value">{formatSpeed(speedResult.upload_speed)}</span>
                </div>
                <div class="speed-row recommended">
                  <span>{m.settings_speed_recommended_upload()}</span>
                  <span class="speed-value">{formatSpeed(speedResult.recommended_upload_limit)}</span>
                </div>
                <button class="apply-btn" onclick={applyRecommended}>{m.settings_apply_recommended()}</button>
              </div>
            {/if}
            {#if speedError}
              <span class="speed-error">{speedError}</span>
            {/if}
          </div>
        </div>
      </section>

      <!-- Network -->
      <section class="card" class:hidden={activeSection !== 'network'}>
        <div class="card-header">
          <span class="card-icon">&#8942;</span>
          <div>
            <h3>{m.settings_section_network()}</h3>
            <p class="card-desc">{m.settings_network_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field-row">
            <div class="field half">
              <label for="tcp-port">
                {m.settings_tcp_port()}
                <span class="restart-badge">{m.settings_restart_badge()}</span>
              </label>
              <input id="tcp-port" type="number" min="1" max="65535" bind:value={settings.tcp_port} />
              <span class="hint">{m.settings_tcp_port_hint()}</span>
            </div>
            <div class="field half">
              <label for="udp-port">
                {m.settings_udp_port()}
                <span class="restart-badge">{m.settings_restart_badge()}</span>
              </label>
              <input id="udp-port" type="number" min="1" max="65535" bind:value={settings.udp_port} />
              <span class="hint">{m.settings_udp_port_hint()}</span>
            </div>
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_upnp_label()} <span class="restart-badge">{m.settings_restart_badge()}</span></span>
              <span class="hint">{m.settings_upnp_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.upnp_enabled} ariaLabel={m.settings_upnp_label()} />
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_stun_keepalive_label()}</span>
              <span class="hint">{m.settings_stun_keepalive_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.stun_keepalive_enabled} ariaLabel={m.settings_stun_keepalive_label()} />
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_ember_native_label()} <span class="badge-experimental">{m.ember_experimental()}</span></span>
              <span class="hint">{m.settings_ember_native_hint()} <a href="/ember" onclick={(e) => { e.preventDefault(); goto('/ember'); }}>{m.settings_ember_open_page()}</a></span>
            </div>
            <ToggleSwitch bind:checked={settings.ember_native_enabled} ariaLabel={m.settings_ember_native_label()} />
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_ember_devtools_label()} <span class="badge-experimental">{m.settings_advanced_badge()}</span></span>
              <span class="hint">{m.settings_ember_devtools_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.ember_dev_tools_enabled} ariaLabel={m.settings_ember_devtools_label()} />
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_auto_connect_kad()} <span class="restart-badge">{m.settings_restart_badge()}</span></span>
              <span class="hint">{m.settings_auto_connect_kad_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.auto_connect_kad} ariaLabel={m.settings_auto_connect_kad()} />
          </div>

          <div class="field nested">
            <div class="action-row">
              <button class="action-btn" onclick={handleDownloadNodes} disabled={downloadingNodes}>
                {downloadingNodes ? m.settings_downloading() : m.settings_download_nodes_btn()}
              </button>
              {#if nodesResult}
                <span class:warning={nodesResultWarning} class:success={!nodesResultWarning} class="feedback">{nodesResult}</span>
              {/if}
              {#if nodesError}<span class="feedback error">{nodesError}</span>{/if}
            </div>
            <span class="hint">{m.settings_nodes_hint()}</span>
          </div>

          <div class="divider"></div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_auto_connect_server()} <span class="restart-badge">{m.settings_restart_badge()}</span></span>
              <span class="hint">{m.settings_auto_connect_server_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.auto_connect_server} />
          </div>

          <!--
            eD2K server-list discovery. These mirror the three eMule
            options under Options -> Servers. New-server admission from
            server/client lists is read live after Save; purging already-
            listed servers when "filter servers by IP" turns on also runs
            on Save (and at startup / IP-filter reload).
          -->
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_update_servers_label()}</span>
              <span class="hint">{m.settings_update_servers_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.add_servers_from_server} ariaLabel={m.settings_update_servers_aria()} />
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_update_servers_clients_label()}</span>
              <span class="hint">{m.settings_update_servers_clients_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.add_servers_from_clients} ariaLabel={m.settings_update_servers_clients_label()} />
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_filter_servers_label()}</span>
              <span class="hint">{m.settings_filter_servers_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.filter_servers_by_ip} ariaLabel={m.settings_filter_servers_label()} />
          </div>

          <!--
            Relaying for other peers. Previously implicit for any reachable
            node; now a choice, because relay attestations travel between
            friends and a reachable node can be asked to carry traffic for
            pairs it never traded with. The session ceiling stays in
            config.json (`max_relay_sessions`), like max_friends — the
            on/off decision is the one worth surfacing.
          -->
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_relay_for_peers_label()}</span>
              <span class="hint">{m.settings_relay_for_peers_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.relay_for_peers} ariaLabel={m.settings_relay_for_peers_label()} />
          </div>

        </div>
      </section>

      <!-- Security -->
      <section class="card" class:hidden={activeSection !== 'security'}>
        <div class="card-header">
          <span class="card-icon">&#128737;</span>
          <div>
            <h3>{m.settings_section_security()}</h3>
            <p class="card-desc">{m.settings_security_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_obfuscation_label()}</span>
              <span class="hint">{m.settings_obfuscation_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.obfuscation_enabled} ariaLabel={m.settings_obfuscation_label()} />
          </div>

          <div class="divider"></div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_ip_filter_label()}</span>
              <span class="hint">{m.settings_ip_filter_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.ip_filter_enabled} ariaLabel={m.settings_ip_filter_label()} />
          </div>
          {#if settings.ip_filter_enabled}
            <div class="field nested">
              <div class="action-row">
                <button class="action-btn" onclick={handleDownloadFilter} disabled={downloadingFilter}>
                  {downloadingFilter ? m.settings_downloading() : m.settings_download_ipfilter_btn()}
                </button>
                {#if filterResult}
                  <span class:warning={filterResultWarning} class:success={!filterResultWarning} class="feedback">{filterResult}</span>
                {/if}
                {#if filterError}<span class="feedback error">{filterError}</span>{/if}
              </div>
            </div>
          {/if}

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_filter_incoming_label()}</span>
              <span class="hint">{m.settings_filter_incoming_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.filter_incoming_connections} ariaLabel={m.settings_filter_incoming_label()} />
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_block_private_label()}</span>
              <span class="hint">{m.settings_block_private_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.block_private_ips} ariaLabel={m.settings_block_private_label()} />
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_allow_shared_browse_label()}</span>
              <span class="hint">{m.settings_allow_shared_browse_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.allow_shared_files_browse} ariaLabel={m.settings_allow_shared_browse_label()} />
          </div>

          <div class="divider"></div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_antileech_label()}</span>
              <span class="hint">
                {m.settings_antileech_hint()}
              </span>
            </div>
            <ToggleSwitch bind:checked={settings.antileech_enabled} ariaLabel={m.settings_antileech_label()} />
          </div>
          {#if settings.antileech_enabled}
            <div class="field nested antileech-block">
              {#if !antileechLoaded}
                {#if antileechMessage && antileechMessage.kind === 'err'}
                  <span class="feedback error">{antileechMessage.text}</span>
                  <button class="action-btn ghost" onclick={loadAntileech}>{m.common_retry()}</button>
                {:else}
                  <div class="hint">{m.settings_antileech_loading()}</div>
                {/if}
              {:else}
                <label for="antileech-textarea" class="antileech-label">
                  {m.settings_antileech_patterns_prefix()} <code>#</code> {m.settings_antileech_patterns_suffix()}
                </label>
                <textarea
                  id="antileech-textarea"
                  class="antileech-textarea"
                  bind:value={antileechDraft}
                  rows="10"
                  spellcheck="false"
                  placeholder={m.settings_antileech_placeholder()}
                ></textarea>
                <div class="antileech-actions">
                  <button class="action-btn" onclick={handleSaveAntileech} disabled={antileechSaving}>
                    {antileechSaving ? m.settings_saving() : m.settings_antileech_save_btn()}
                  </button>
                  <button class="action-btn ghost" onclick={handleResetAntileech} disabled={antileechSaving}>
                    {m.settings_antileech_restore_btn()}
                  </button>
                  {#if antileechSnapshot}
                    <span class="hint antileech-path" title={antileechSnapshot.file_path}>
                      {m.settings_antileech_file_label({ path: antileechSnapshot.file_path })}
                    </span>
                  {/if}
                </div>
                {#if antileechMessage}
                  <span class="feedback {antileechMessage.kind === 'err' ? 'error' : antileechMessage.kind === 'warn' ? 'warning' : 'success'}">
                    {antileechMessage.text}
                  </span>
                {/if}
                {#if antileechCompileErrors.length > 0}
                  <div class="antileech-errors">
                    <div class="antileech-errors-title">{m.settings_antileech_errors_title()}</div>
                    <ul>
                      {#each antileechCompileErrors as [pattern, error]}
                        <li><code>{pattern}</code> - {error}</li>
                      {/each}
                    </ul>
                  </div>
                {/if}
              {/if}
            </div>
          {/if}

        </div>
      </section>

      <!-- Friends -->
      <section class="card" class:hidden={activeSection !== 'friends'}>
        <div class="card-header">
          <span class="card-icon">&#128101;</span>
          <div>
            <h3>{m.settings_section_friends()}</h3>
            <p class="card-desc">{m.settings_friends_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_friend_require_approval()}</span>
              <span class="hint">{m.settings_friend_require_approval_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.friend_require_approval} ariaLabel={m.settings_friend_require_approval()} onchange={() => void applyFriendTogglesLive()} />
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_friend_chat_disabled()}</span>
              <span class="hint">{m.settings_friend_chat_disabled_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.friend_chat_disabled} ariaLabel={m.settings_friend_chat_disabled()} onchange={() => void applyFriendTogglesLive()} />
          </div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_friend_browse_disabled()}</span>
              <span class="hint">{m.settings_friend_browse_disabled_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.friend_browse_disabled} ariaLabel={m.settings_friend_browse_disabled()} onchange={() => void applyFriendTogglesLive()} />
          </div>

          <!-- Friend session encryption stays forced on (see handleSave /
               applyFriendTogglesLive). Max friends + rendezvous URL remain
               in AppSettings for config.json only — not everyday controls. -->

        </div>
      </section>

      <!-- Backup & Restore -->
      <section class="card" class:hidden={activeSection !== 'backup'}>
        <div class="card-header">
          <span class="card-icon">&#128190;</span>
          <div>
            <h3>{m.settings_section_backup()}</h3>
            <p class="card-desc">{m.settings_backup_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          {#if pendingRestore?.pending}
            <div class="field pending-restore" role="status">
              <span class="field-label">{m.settings_backup_pending_title()}</span>
              <span class="hint">
                {m.settings_backup_pending_message({
                  files: pendingRestore.files,
                  version: pendingRestore.app_version,
                  when: new Date(pendingRestore.staged_at * 1000).toLocaleString(),
                })}
              </span>
              <div class="action-row">
                <button class="action-btn" onclick={performRestart} disabled={backupBusy}>
                  {m.settings_restart_now()}
                </button>
                <button class="danger" onclick={handleDiscardPendingRestore} disabled={backupBusy}>
                  {m.settings_backup_pending_discard()}
                </button>
              </div>
            </div>
          {/if}
          <div class="field">
            <span class="field-label">{m.settings_backup_contents_label()}</span>
            <span class="hint">{m.settings_backup_contents_hint()}</span>
            <span class="hint">{m.settings_backup_excludes_hint()}</span>
          </div>

          <div class="field">
            <label for="backup-passphrase">{m.settings_backup_passphrase_label()}</label>
            <span class="hint">{m.settings_backup_passphrase_hint()}</span>
            <input
              id="backup-passphrase"
              type="password"
              autocomplete="new-password"
              bind:value={backupPassphrase}
              placeholder={m.settings_backup_passphrase_placeholder()}
            />
          </div>
          <div class="field">
            <label for="backup-passphrase-confirm">{m.settings_backup_passphrase_confirm_label()}</label>
            <input
              id="backup-passphrase-confirm"
              type="password"
              autocomplete="new-password"
              bind:value={backupPassphraseConfirm}
            />
          </div>
          <div class="action-row">
            <button
              class="action-btn"
              onclick={handleExportBackup}
              disabled={backupBusy || backupPassphrase.length === 0}
            >{m.settings_backup_export()}</button>
          </div>

          <!-- Hidden while a restore is staged: importing a second one is
               refused by the backend, so the banner's Restart / Discard pair
               is the only sensible next step. -->
          <div class="field" class:hidden={pendingRestore?.pending}>
            <span class="field-label">{m.settings_backup_restore_label()}</span>
            <span class="hint">{m.settings_backup_restore_hint()}</span>
            <div class="action-row">
              <button class="action-btn" onclick={handlePickBackupFile} disabled={backupBusy}>
                {m.settings_backup_choose_file()}
              </button>
            </div>
            {#if restoreSource}
              <span class="hint backup-path" title={restoreSource}>{restoreSource}</span>
              <label for="restore-passphrase">{m.settings_backup_restore_passphrase_label()}</label>
              <input
                id="restore-passphrase"
                type="password"
                autocomplete="current-password"
                bind:value={restorePassphrase}
              />
              <div class="action-row">
                <button
                  class="action-btn"
                  onclick={handlePreviewBackup}
                  disabled={backupBusy || restorePassphrase.length === 0}
                >{m.settings_backup_inspect()}</button>
                {#if restorePreview && !restorePreview.schema_too_new}
                  <button class="danger" onclick={handleImportBackup} disabled={backupBusy}>
                    {m.settings_backup_restore_now()}
                  </button>
                {/if}
                <button class="action-btn" onclick={clearRestoreState} disabled={backupBusy}>
                  {m.common_cancel()}
                </button>
              </div>
            {/if}
            {#if restorePreview}
              <div class="backup-preview">
                <div class="spam-stat">
                  <span>{m.settings_backup_preview_created()}</span>
                  <strong>{new Date(restorePreview.created_at * 1000).toLocaleString()}</strong>
                </div>
                <div class="spam-stat">
                  <span>{m.settings_backup_preview_version()}</span>
                  <strong>{restorePreview.app_version}</strong>
                </div>
                <div class="spam-stat">
                  <span>{m.settings_backup_preview_files()}</span>
                  <strong>{restorePreview.files.length}</strong>
                </div>
                <div class="spam-stat">
                  <span>{m.settings_backup_preview_size()}</span>
                  <strong>{formatSize(restorePreview.total_bytes)}</strong>
                </div>
                <div class="spam-stat">
                  <span>{m.settings_backup_preview_identity()}</span>
                  <strong>{restorePreview.includes_identity ? m.common_yes() : m.common_no()}</strong>
                </div>
              </div>
              <span class="hint">{m.settings_backup_restore_warning()}</span>
            {/if}
          </div>

          {#if backupMessage}
            <span class="hint" style={backupIsError ? 'color: var(--danger)' : 'color: var(--success)'}>
              {backupMessage}
            </span>
          {/if}
        </div>
      </section>

      <!-- About & Updates -->
      <section class="card" class:hidden={activeSection !== 'about'}>
        <div class="card-header">
          <span class="card-icon">&#9432;</span>
          <div>
            <h3>{m.settings_section_about()}</h3>
            <p class="card-desc">{m.settings_about_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="about-identity">
            <div class="about-identity-top">
              <div class="about-mark" aria-hidden="true">
                <img src="/icon.png" alt="" width="44" height="44" />
              </div>
              <div class="about-identity-copy">
                <p class="about-wordmark">EMBER</p>
                <p class="about-tagline">{m.app_tagline()}</p>
                <p class="about-version-chip">{m.about_dialog_version({ version: appVersion })}</p>
              </div>
            </div>
            <p class="about-description">{m.about_dialog_description()}</p>
            <p class="about-license">{m.about_dialog_license({ license: appLicense })}</p>
            <div class="about-website-row">
              <button type="button" class="about-website-link" onclick={() => void openWebsite()}>
                <span>{m.settings_about_website_btn()}</span>
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M6.5 3.5H3.5A1.5 1.5 0 0 0 2 5v7.5A1.5 1.5 0 0 0 3.5 14H11a1.5 1.5 0 0 0 1.5-1.5V9.5" />
                  <path d="M9.5 2H14v4.5" />
                  <path d="M14 2 7.5 8.5" />
                </svg>
              </button>
              <span class="hint about-website-hint">{m.settings_about_website_hint()}</span>
            </div>
            {#if websiteOpenError}
              <span class="feedback error" role="alert">{websiteOpenError}</span>
            {/if}
          </div>

          <div class="divider"></div>

          <div class="field toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.settings_auto_check_updates_label()}</span>
              <span class="hint">{m.settings_auto_check_updates_hint()}</span>
            </div>
            <ToggleSwitch bind:checked={settings.auto_check_updates} ariaLabel={m.settings_auto_check_updates_label()} />
          </div>
          <div class="field" class:about-frequency-disabled={!settings.auto_check_updates}>
            <label for="update-check-frequency">{m.settings_update_check_frequency_label()}</label>
            <span class="hint">{m.settings_update_check_frequency_hint()}</span>
            <select
              id="update-check-frequency"
              bind:value={settings.update_check_frequency}
              disabled={!settings.auto_check_updates}
            >
              <option value="daily">{m.settings_update_frequency_daily()}</option>
              <option value="weekly">{m.settings_update_frequency_weekly()}</option>
              <option value="monthly">{m.settings_update_frequency_monthly()}</option>
            </select>
          </div>

          <div class="divider"></div>

          <div class="about-update-panel">
            <div class="action-row">
              <button
                class="action-btn"
                onclick={() => void checkForUpdates()}
                disabled={$updater.phase === 'checking' || $updater.phase === 'downloading' || $updater.phase === 'installing'}
              >
                {$updater.phase === 'checking' ? m.updater_checking() : m.settings_about_check_btn()}
              </button>

              {#if $updater.phase === 'available'}
                <button class="action-btn primary" onclick={() => void installUpdate()}>
                  {m.updater_install()}
                </button>
              {:else if $updater.phase === 'ready'}
                <button class="action-btn primary" onclick={() => void restartToUpdate()}>
                  {m.updater_restart_now()}
                </button>
              {/if}
            </div>

            <div
              class="about-update-status"
              class:success={$updater.phase === 'uptodate' || $updater.phase === 'available' || $updater.phase === 'ready'}
              class:error={$updater.phase === 'error'}
              class:busy={$updater.phase === 'checking' || $updater.phase === 'downloading' || $updater.phase === 'installing'}
            >
              {#if $updater.phase === 'uptodate'}
                <span class="feedback success">{m.updater_uptodate()}</span>
              {:else if $updater.phase === 'available'}
                <span class="feedback success">{m.updater_available_status({ version: $updater.version ?? '' })}</span>
              {:else if $updater.phase === 'downloading'}
                <span class="hint">{aboutPercent !== null ? m.updater_downloading_pct({ pct: aboutPercent }) : m.updater_downloading()}</span>
                {#if aboutPercent !== null}
                  <div class="about-progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={aboutPercent}>
                    <div class="about-progress-fill" style="width: {aboutPercent}%"></div>
                  </div>
                {/if}
              {:else if $updater.phase === 'installing'}
                <span class="hint">{m.updater_installing()}</span>
              {:else if $updater.phase === 'ready'}
                <span class="feedback success">{m.updater_ready_body({ version: $updater.version ?? '' })}</span>
              {:else if $updater.phase === 'error'}
                <span class="feedback error">{m.updater_error_body({ detail: $updater.error ?? '' })}</span>
              {:else}
                <span class="hint">{m.settings_about_check_hint()}</span>
              {/if}
            </div>
          </div>
        </div>
      </section>

      </div>
    </div>
  {/if}
</div>

<!--
  Restart confirmation prompt — fires after `handleSave` notices the
  user changed `tcp_port` or `udp_port`. Both ports are bound only at
  process startup, so a hot save persists the value but the active
  listener keeps using the old port until restart. Same UX as the
  setup wizard's "Launch Ember" relaunch step.
-->
<ConfirmDialog
  bind:open={showRestartPrompt}
  title={m.settings_restart_dialog_title()}
  message={m.settings_restart_dialog_message({ reason: pendingRestartReason })}
  confirmLabel={m.settings_restart_now()}
  cancelLabel={m.settings_restart_later()}
  onconfirm={performRestart}
  oncancel={dismissRestartPrompt}
/>

<!--
  The staged restore is only applied while nothing has the database, config or
  identity open, which means during startup. Restarting now is therefore the
  normal path; declining just defers the swap to the next launch.
-->
<ConfirmDialog
  bind:open={showRestoreRestartPrompt}
  title={m.settings_backup_restore_staged_title()}
  message={m.settings_backup_restore_staged_message({
    files: restoreStaged?.staged.length ?? 0,
    version: restoreStaged?.app_version ?? '',
  })}
  confirmLabel={m.settings_restart_now()}
  cancelLabel={m.settings_restart_later()}
  onconfirm={performRestart}
/>

<ConfirmDialog
  bind:open={spamResetConfirmOpen}
  title={m.settings_spam_reset_dialog_title()}
  message={m.settings_spam_reset_dialog_message()}
  confirmLabel={m.settings_spam_reset_confirm()}
  danger={true}
  onconfirm={confirmResetSpamData}
/>

<ConfirmDialog
  bind:open={historyClearConfirmOpen}
  title={historyClearDialogTitle}
  message={historyClearDialogMessage}
  confirmLabel={m.settings_history_clear_confirm()}
  danger={true}
  onconfirm={confirmClearHistory}
  oncancel={() => { pendingHistoryClear = null; }}
/>

<ConfirmDialog
  bind:open={antileechResetConfirmOpen}
  title={m.settings_antileech_restore_dialog_title()}
  message={m.settings_antileech_restore_dialog_message()}
  confirmLabel={m.settings_antileech_restore_confirm()}
  danger={true}
  onconfirm={confirmResetAntileech}
/>

<!--
  Full-screen "Restarting Ember" overlay shown while `relaunch()` is in
  flight. Identical layout/copy to SetupWizard's relaunch overlay so
  the visual transition feels the same in both places.
-->
{#if restarting}
  <div class="restart-overlay" role="status" aria-label={m.settings_restarting_aria()}>
    <div class="restart-card">
      <div class="restart-spinner"></div>
      <h2 class="restart-title">{m.settings_restarting_title()}</h2>
      <p class="restart-sub">{m.settings_restarting_sub()}</p>
    </div>
  </div>
{/if}

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

  .unsaved-indicator {
    font-size: 12px;
    color: var(--warning);
    font-weight: 500;
    animation: pulse 2s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  .spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    border: 2px solid color-mix(in srgb, currentColor 30%, transparent);
    border-top-color: currentColor;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .save-status {
    font-size: 13px;
    font-weight: 600;
    color: var(--success);
    padding: 4px 12px;
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--success) 12%, transparent);
  }

  .save-status.warning {
    color: var(--warning);
    background: color-mix(in srgb, var(--warning) 12%, transparent);
  }

  /* ── Card grid ─────────────────────────────────── */
  .settings-layout {
    display: grid;
    grid-template-columns: 220px minmax(0, 1fr);
    gap: 20px;
    padding: 8px 24px 20px;
    max-width: 1200px;
    width: 100%;
    box-sizing: border-box;
    min-width: 0;
  }

  .settings-nav {
    align-self: start;
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-secondary);
  }

  .settings-nav-title {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    color: var(--text-muted);
    font-weight: 700;
    padding: 2px 8px 8px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 4px;
  }

  .settings-nav-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 8px 10px;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-secondary);
    font-size: 13px;
    text-align: left;
    cursor: pointer;
  }

  .settings-nav-item:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .settings-nav-item.active {
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    border-color: color-mix(in srgb, var(--accent) 30%, var(--border));
    color: var(--text-primary);
    font-weight: 600;
  }

  .settings-nav-icon {
    width: 18px;
    height: 18px;
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    opacity: 0.85;
    transition: opacity var(--transition-normal) ease, color var(--transition-normal) ease;
  }

  .settings-nav-icon :global(svg) {
    width: 18px;
    height: 18px;
    display: block;
  }

  .settings-nav-item:hover .settings-nav-icon,
  .settings-nav-item.active .settings-nav-icon {
    opacity: 1;
  }

  .cards-grid {
    min-width: 0;
    display: block;
    min-height: calc(100vh - 190px);
  }

  .card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-sm);
    overflow: hidden;
    overflow-anchor: none;
    /*
     * Subtle section-switch fade+rise. Sections are toggled via
     * `.hidden { display: none }` (not mount/unmount), and CSS animations
     * restart whenever an element flips from display:none back to shown — so
     * this replays each time a section becomes active without any structural
     * change. No `forwards` fill on purpose: we must not leave a lingering
     * non-`none` transform, which would turn the card into the containing
     * block for any position:fixed popover inside it. The keyframe ends at the
     * card's natural resting state, so dropping the fill causes no snap. The
     * global prefers-reduced-motion rule neutralizes it.
     */
    animation: settings-card-in var(--transition-slow) ease;
  }

  @keyframes settings-card-in {
    from { opacity: 0; transform: translateY(6px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .card.hidden,
  .field.hidden {
    display: none;
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

  .badge-experimental {
    display: inline-block;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    padding: 1px 6px;
    border-radius: 8px;
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
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

  .field-hint {
    display: block;
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 4px;
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

  .action-btn.primary {
    background: var(--accent);
    color: var(--on-accent);
    border-color: var(--accent);
  }

  .action-btn.primary:hover {
    filter: brightness(1.06);
    color: var(--on-accent);
  }

  .about-identity {
    padding: 14px 14px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background:
      linear-gradient(
        160deg,
        color-mix(in srgb, var(--accent) 8%, transparent) 0%,
        transparent 55%
      ),
      var(--bg-surface);
  }

  .about-identity-top {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 12px;
  }

  .about-mark {
    width: 44px;
    height: 44px;
    border-radius: 10px;
    overflow: hidden;
    flex-shrink: 0;
    box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--border) 70%, transparent);
  }

  .about-mark img {
    width: 100%;
    height: 100%;
    display: block;
  }

  .about-identity-copy {
    min-width: 0;
  }

  .about-wordmark {
    margin: 0 0 3px;
    font-size: 18px;
    font-weight: 800;
    letter-spacing: 2.5px;
    color: var(--accent);
    line-height: 1;
  }

  .about-tagline {
    margin: 0 0 8px;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.9px;
    text-transform: uppercase;
    color: var(--text-muted);
    line-height: 1.2;
  }

  .about-version-chip {
    display: inline-block;
    margin: 0;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 600;
    color: var(--badge-accent-text);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    border: 1px solid color-mix(in srgb, var(--accent) 22%, transparent);
    border-radius: 999px;
    line-height: 1.4;
  }

  .about-description {
    margin: 0 0 6px;
    font-size: 13px;
    line-height: 1.45;
    color: var(--text-secondary);
  }

  .about-license {
    margin: 0 0 12px;
    font-size: 12px;
    color: var(--text-muted);
  }

  .about-website-row {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 8px 14px;
  }

  .about-website-link {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 0;
    border: none;
    background: transparent;
    color: var(--accent);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    text-decoration: underline;
    text-underline-offset: 2px;
  }

  .about-website-link svg {
    width: 13px;
    height: 13px;
    flex-shrink: 0;
  }

  .about-website-link:hover {
    filter: brightness(1.08);
  }

  .about-website-link:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
    border-radius: var(--radius-sm);
  }

  .about-website-hint {
    margin: 0;
  }

  .about-frequency-disabled {
    opacity: 0.55;
  }

  .about-update-panel {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .about-update-status {
    padding: 10px 12px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--bg-surface);
  }

  .about-update-status.success {
    border-color: color-mix(in srgb, var(--success) 28%, var(--border));
    background: color-mix(in srgb, var(--success) 8%, var(--bg-surface));
  }

  .about-update-status.error {
    border-color: color-mix(in srgb, var(--danger) 28%, var(--border));
    background: color-mix(in srgb, var(--danger) 8%, var(--bg-surface));
  }

  .about-update-status.busy {
    border-color: color-mix(in srgb, var(--accent) 24%, var(--border));
    background: color-mix(in srgb, var(--accent) 6%, var(--bg-surface));
  }

  .about-progress {
    margin-top: 8px;
    height: 4px;
    border-radius: 999px;
    background: color-mix(in srgb, var(--accent) 16%, var(--bg-input));
    overflow: hidden;
  }

  .about-progress-fill {
    height: 100%;
    border-radius: inherit;
    background: var(--accent);
    transition: width 0.2s ease;
  }

  .action-btn:disabled {
    opacity: 0.55;
    cursor: not-allowed;
    pointer-events: none;
  }

  .feedback {
    font-size: 12px;
    font-weight: 500;
  }

  .feedback.success { color: var(--success); }
  .feedback.error { color: var(--danger); }
  .feedback.warning { color: var(--warning); }

  /* ── Anti-Leech filter editor ────────────────────── */
  .antileech-block {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .antileech-label {
    font-size: 12px;
    color: var(--text-muted);
  }
  .antileech-textarea {
    width: 100%;
    min-height: 180px;
    padding: 8px 10px;
    font-family: var(--font-mono, ui-monospace, 'Cascadia Code', Consolas, monospace);
    font-size: 12px;
    line-height: 1.4;
    color: var(--text-primary);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    resize: vertical;
  }
  .antileech-textarea:focus {
    outline: none;
    border-color: var(--accent);
  }
  .antileech-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .antileech-path {
    font-size: 11px;
    margin-left: auto;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 50%;
  }
  .antileech-errors {
    margin-top: 6px;
    padding: 8px 10px;
    background: var(--bg-secondary);
    border: 1px solid var(--danger);
    border-radius: var(--radius-sm);
    font-size: 12px;
  }
  .antileech-errors-title {
    color: var(--danger);
    font-weight: 600;
    margin-bottom: 4px;
  }
  .antileech-errors ul {
    margin: 0;
    padding-left: 18px;
  }
  .antileech-errors code {
    font-family: var(--font-mono, ui-monospace, monospace);
    color: var(--text-primary);
  }
  .action-btn.ghost {
    background: transparent;
  }

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
    background: var(--preview-light-canvas);
  }
  .light-swatch .swatch-sidebar {
    background: var(--preview-light-panel);
    border-right: 1px solid var(--preview-light-border);
  }
  .light-swatch .swatch-line {
    background: var(--preview-light-border);
  }

  /* Dark swatch colors */
  .dark-swatch {
    background: var(--preview-dark-canvas);
  }
  .dark-swatch .swatch-sidebar {
    background: var(--preview-dark-panel);
    border-right: 1px solid var(--preview-dark-border);
  }
  .dark-swatch .swatch-line {
    background: var(--preview-dark-hover);
  }

  .swatch-check {
    position: absolute;
    top: 6px;
    right: 6px;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--accent);
    color: var(--on-accent);
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

  /* ── Close-behavior picker ─────────────────────── */
  .behavior-picker {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
    margin-top: 8px;
  }

  .behavior-card {
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 6px;
    padding: 14px 14px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
    color: var(--text-primary);
    text-align: left;
    cursor: pointer;
    transition: border-color 0.15s ease, background 0.15s ease, box-shadow 0.15s ease, transform 0.15s ease;
  }

  .behavior-card:hover {
    border-color: color-mix(in srgb, var(--accent) 35%, var(--border));
    background: var(--bg-hover);
  }

  .behavior-card:focus-visible {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 30%, transparent);
  }

  .behavior-card.selected {
    border-color: var(--accent);
    background: color-mix(in srgb, var(--accent) 10%, var(--bg-surface));
    box-shadow: 0 0 0 1px var(--accent);
  }

  .behavior-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    color: var(--accent);
    margin-bottom: 2px;
  }

  .behavior-icon :global(svg) {
    width: 18px;
    height: 18px;
    display: block;
  }

  .behavior-card.selected .behavior-icon {
    background: var(--accent);
    color: var(--on-accent);
  }

  /* Language picker: keep the circle plate, but let the flag fill it
     without the selected-state color wash tinting the SVG. */
  .lang-flag-icon {
    padding: 0;
    overflow: hidden;
    background: transparent;
  }

  .behavior-card.selected .lang-flag-icon {
    background: transparent;
  }

  .lang-flag {
    width: 100%;
    height: 100%;
    display: block;
    object-fit: cover;
    border-radius: inherit;
  }

  .behavior-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
    line-height: 1.25;
  }

  .behavior-desc {
    font-size: 11.5px;
    color: var(--text-muted);
    line-height: 1.35;
  }

  .behavior-check {
    position: absolute;
    top: 8px;
    right: 8px;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--accent);
    color: var(--on-accent);
    font-size: 11px;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: var(--shadow-sm);
  }

  @media (max-width: 640px) {
    .behavior-picker {
      grid-template-columns: 1fr;
    }
  }

  .speed-test-section {
    border-top: 1px solid var(--border);
    padding-top: 12px;
    margin-top: 4px;
  }

  .speed-test-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 4px;
  }

  .speed-test-btn {
    padding: 4px 12px;
    font-size: 12px;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    cursor: pointer;
  }

  .speed-test-btn:hover:not(:disabled) {
    background: var(--bg-hover);
  }

  .speed-test-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .speed-results {
    margin-top: 8px;
    padding: 8px 12px;
    background: var(--bg-tertiary);
    border-radius: 6px;
    font-size: 13px;
  }

  .speed-row {
    display: flex;
    justify-content: space-between;
    padding: 2px 0;
    color: var(--text-secondary);
  }

  .speed-row.recommended {
    border-top: 1px solid var(--border);
    margin-top: 4px;
    padding-top: 6px;
    color: var(--text-primary);
    font-weight: 600;
  }

  .speed-value {
    font-weight: 600;
    color: var(--text-primary);
  }

  .apply-btn {
    margin-top: 8px;
    width: 100%;
    padding: 6px;
    font-size: 12px;
    font-weight: 600;
    border-radius: 6px;
    border: none;
    background: var(--accent);
    color: var(--on-accent);
    cursor: pointer;
  }

  .apply-btn:hover {
    opacity: 0.9;
  }

  .speed-error {
    display: block;
    margin-top: 6px;
    color: var(--danger);
    font-size: 12px;
  }

  .spam-stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 8px;
    margin-top: 8px;
  }

  .spam-stat {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .spam-stat span {
    font-size: 11px;
    color: var(--text-muted);
  }

  .spam-stat strong {
    font-size: 15px;
    color: var(--text-primary);
  }

  .backup-preview {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 8px;
    margin-top: 8px;
  }

  .pending-restore {
    border: 1px solid var(--warning);
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--warning) 10%, transparent);
    padding: 10px;
  }

  .backup-path {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: var(--font-mono, monospace);
  }

  .history-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 10px;
    margin-top: 10px;
  }

  .history-card {
    display: flex;
    flex-direction: column;
    border: 1px solid var(--border);
    border-top: 2px solid var(--accent);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    overflow: hidden;
    min-width: 0;
  }

  .history-stat-body {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 12px 14px 10px;
  }

  .history-stat-label {
    font-size: 11px;
    font-weight: 500;
    color: var(--text-muted);
    letter-spacing: 0.01em;
  }

  .history-stat-value {
    font-size: 24px;
    font-weight: 700;
    line-height: 1.1;
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
  }

  .history-stat-value.is-loading {
    font-size: 12px;
    font-weight: 500;
    color: var(--text-muted);
  }

  .history-clear-btn {
    margin-top: auto;
    width: 100%;
    padding: 8px 12px;
    border: none;
    border-top: 1px solid var(--border);
    border-radius: 0;
    background: color-mix(in srgb, var(--bg-primary) 55%, transparent);
    color: var(--text-secondary);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    text-align: left;
    transition: background 0.15s, color 0.15s;
  }

  .history-clear-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .history-clear-btn:active:not(:disabled) {
    transform: none;
  }

  .history-card-total .history-clear-btn:hover {
    color: var(--danger);
  }

  @media (max-width: 1200px) {
    .settings-layout {
      padding: 8px 16px 16px;
      gap: 14px;
    }
  }

  @media (max-width: 980px) {
    .settings-layout {
      grid-template-columns: 1fr;
      gap: 12px;
      padding: 12px;
      max-width: none;
    }

    .settings-nav {
      position: static;
      flex-direction: row;
      flex-wrap: wrap;
      padding: 8px;
      overflow-x: auto;
      max-width: 100%;
    }

    .settings-nav-title {
      display: none;
    }

    .settings-nav-item {
      width: auto;
      padding: 7px 10px;
      font-size: 12px;
      flex-shrink: 0;
    }
  }

  /* Restart overlay (matches SetupWizard's relaunch screen) */
  .restart-overlay {
    position: fixed;
    inset: 0;
    z-index: 99999;
    display: grid;
    place-items: center;
    background: var(--bg-primary);
    padding: 20px;
  }

  .restart-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
  }

  .restart-spinner {
    width: 40px;
    height: 40px;
    border: 4px solid color-mix(in srgb, var(--border-light) 45%, transparent);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }

  .restart-title {
    font-size: 22px;
    font-weight: 700;
    color: var(--accent);
    margin: 0;
  }

  .restart-sub {
    font-size: 14px;
    color: var(--text-muted);
    margin: 0;
  }
</style>
