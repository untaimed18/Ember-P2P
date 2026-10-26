<script lang="ts">
  import {
    getSettings,
    getLaunchSettings,
    updateSettings,
    getLogFolderPath,
    openLogFolder,
    pickDownloadFolder as pickDownloadFolderDialog,
    pickPreviewPlayer as pickPreviewPlayerDialog,
    importWebServicesFile,
    getExampleWebService,
    SETTINGS_CHANGED_EVENT,
    type LaunchSettings,
    type UpdateSettingsResult,
  } from '$lib/api/settings';
  import type { WebService } from '$lib/types';
  import { openChatFilesFolder } from '$lib/api/friends';
  import {
    CHANNEL_USERNAME_MAX,
    isValidChannelUsername,
    openChannelFilesFolder,
    recoverOwnedChannels,
    sanitizeChannelUsernameInput,
  } from '$lib/api/channels';
  import {
    type ChannelLanguage,
    channelLanguageFlagSrc,
    channelLanguageName,
    isChannelLanguage,
    suggestedChannelLanguage,
  } from '$lib/channelLanguages';
  import ChannelLanguagePicker from '$lib/components/ChannelLanguagePicker.svelte';
  import { setAppSettings, appSettings } from '$lib/stores/settings';
  import { transfers } from '$lib/stores/transfers';
  import CategoriesDialog from '$lib/components/CategoriesDialog.svelte';
  import { BUILTIN_DOWNLOAD_CATEGORIES, downloadCategoryLabel } from '$lib/downloadCategories';
  import {
    addUserCategory,
    countDownloadCategories,
    isCategoryTaken,
    removeUserCategory,
    setCategoryFolder,
  } from '$lib/categorySettings';
  import {
    channels as channelsStore,
    hiddenChannels,
    ignoredMembers,
    channelNotifyLevels,
    channelSnoozes,
    setChannelNotifyLevel,
    toggleMemberIgnore,
    unhideChannel,
  } from '$lib/stores/channels';
  import { get } from 'svelte/store';
  import { getSpamStats, resetSpamFilter, clearDownloadHistory, getDownloadHistoryStats } from '$lib/api/search';
  import { notifySpamFilterReset } from '$lib/stores/search';
  import {
    getAntileechPatterns,
    setAntileechPatterns,
    setAntileechEnabled,
    resetAntileechToDefaults,
    setBlockPrivateIps,
    setIpFilterAutoUpdate,
    setIpFilterEnabled,
  } from '$lib/api/security';
  import type { AntiLeechSnapshot } from '$lib/types';
  import { invoke } from '@tauri-apps/api/core';
  import { afterNavigate, goto, replaceState } from '$app/navigation';
  import { page } from '$app/stores';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { relaunch } from '@tauri-apps/plugin-process';
  import { flushToastActionsBeforeExit } from '$lib/stores/toast';
  import BuyCoffeeButton from '$lib/components/BuyCoffeeButton.svelte';
  import EmberLinks from '$lib/components/EmberLinks.svelte';
  import {
    discardPendingRestore,
    exportBackup,
    importBackup,
    pickBackupFile,
    clearPickedBackup,
    pendingRestoreStatus,
    previewBackup,
    type BackupPreview,
    type PendingRestoreStatus,
    type RestoreSummary,
  } from '$lib/api/backup';
  import { collectBackupPrefs } from '$lib/backupPrefs';
  import { lastBackupAt, noteBackupMade } from '$lib/backupReminder';
  import { CHAT_DISAPPEAR_CHOICES, disappearLabel } from '$lib/chatDisappear';
  import { AUTO_AWAY_CHOICES } from '$lib/friendSettings';
  import { idleAwaySupported } from '$lib/stores/friends';
  import {
    clampInputUtf8Bytes,
    formatDateTime,
    formatSize,
    formatSpeed,
    NICKNAME_MAX_BYTES,
    shortPubkey,
  } from '$lib/utils';
  import { getRuntimeStatus } from '$lib/api/system';
  import {
    MAX_RULE_LABEL_CHARS,
    MAX_SCHEDULE_RULES,
    endTimeValueToMinutes,
    hasDay,
    isOvernight,
    MAX_CONFIGURED_SPEED_BPS,
    minutesToTimeValue,
    newScheduleRule,
    ruleProblem,
    scheduleProblem,
    timeValueToMinutes,
    toggleDay,
  } from '$lib/bandwidthSchedule';
  import type {
    AppSettings,
    BandwidthScheduleRule,
    RuntimeStatus,
    SpamStats,
    DownloadHistoryStats,
  } from '$lib/types';
  import { onMount, tick, untrack } from 'svelte';
  import { beforeNavigate } from '$app/navigation';
  import { theme, applyTheme, followSystemTheme, themeFollowsSystem, type Theme } from '$lib/stores/theme';
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
  import { plural } from '$lib/plural';
  import ToggleSwitch from '$lib/components/ToggleSwitch.svelte';
  import PortTest from '$lib/components/PortTest.svelte';
  import ConnectionDoctor from '$lib/components/ConnectionDoctor.svelte';
  import { highlightMatches } from '$lib/stores/highlight';
  import SpeedInput from '$lib/components/SpeedInput.svelte';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import EmuleImport from '$lib/components/EmuleImport.svelte';
  import {
    updater,
    checkForUpdates,
    installUpdate,
    restartToUpdate,
    runStagedInstaller,
  } from '$lib/stores/updater';
  import { silentUpdate, silentUpdateResume } from '$lib/stores/silentUpdate';
  import { toastError } from '$lib/stores/toast';
  import { networkStats } from '$lib/stores/network';
  import { isShortcutLetter } from '$lib/shortcutKey';

  const appVersion = import.meta.env.VITE_APP_VERSION;
  const appLicense = import.meta.env.VITE_APP_LICENSE;

  // Silent updates. `supported` is the backend's answer for this install;
  // the status line describes what the saved setting is doing right now.
  const silentSupported = $derived($silentUpdate?.supported ?? false);
  const silentUnsupportedHint = $derived.by(() => {
    switch ($silentUpdate?.unsupportedReason) {
      case 'deb':
        return m.settings_silent_update_unsupported_deb();
      case 'msi':
        return m.settings_silent_update_unsupported_msi();
      default:
        return m.settings_silent_update_unsupported_other();
    }
  });
  const silentStatusText = $derived.by(() => {
    const s = $silentUpdate;
    if (!s || !s.supported) return '';
    const version = s.version ?? '';
    const lastSuccess = s.lastSuccess
      ? m.silent_update_status_last_success({
          version: s.lastSuccess.to,
          date: formatDateTime(Math.floor(s.lastSuccess.at / 1000), {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
          }),
        })
      : '';
    if (!s.enabled) return lastSuccess;
    switch (s.phase) {
      case 'preparing':
        return s.prepareFailed
          ? m.silent_update_status_prepare_failed({ version })
          : m.silent_update_status_preparing({ version });
      case 'waiting':
        return m.silent_update_status_waiting({ version });
      case 'postponed':
        return m.silent_update_status_postponed({
          version,
          time: formatDateTime(Math.floor((s.postponedUntil ?? 0) / 1000), {
            weekday: 'short',
            hour: 'numeric',
            minute: '2-digit',
          }),
        });
      case 'held':
        return m.silent_update_status_held({ version });
      case 'countdown':
        return m.silent_update_status_countdown({ version });
      case 'installing':
        return m.silent_update_status_installing({ version });
      default:
        return lastSuccess;
    }
  });

  async function resumeSilentUpdate() {
    try {
      await silentUpdateResume();
    } catch (e) {
      toastError(translateError(e, m.error_operation_failed()));
    }
  }

  /** A restart is reported by the banner and prompt instead, which know
   *  whether the change is still waiting for one. */
  function updateSettingsOutcomeMessage(result: UpdateSettingsResult): string {
    return result.outcome === 'deferred'
      ? m.settings_save_live_apply_deferred()
      : m.settings_save_success();
  }

  // Download progress percent for the About card, when a content length is known.
  let aboutPercent = $derived(
    $updater.total && $updater.total > 0
      ? Math.min(100, Math.round(($updater.downloaded / $updater.total) * 100))
      : null,
  );

  /** Where `ember.log` lives. Resolved once so the path is on screen to copy
   *  into a bug report whether or not the folder will open. */
  let logFolderPath = $state('');
  let logsOpenError = $state('');

  $effect(() => {
    getLogFolderPath()
      .then((path) => {
        logFolderPath = path;
      })
      .catch(() => {
        // Only the displayed path is lost; the button still works.
      });
  });

  $effect(() => {
    getExampleWebService()
      .then((service) => {
        exampleWebService = service;
      })
      .catch(() => {
        // Only the "add the example" shortcut is lost; the list and the manual
        // add form are unaffected.
      });
  });

  async function revealLogs() {
    logsOpenError = '';
    try {
      await openLogFolder();
    } catch (e) {
      logsOpenError = translateError(e);
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

  // --- Download categories ---
  let categoriesOpen = $state(false);
  let userCategories = $derived($appSettings?.download_categories ?? []);
  let categoryCounts = $derived(countDownloadCategories($transfers));

  /** The dialog saves the categories itself, so take what it saved into the
   *  form and its baseline: they are not a change waiting to be applied. */
  function foldCategorySettings() {
    const saved = $appSettings;
    if (!saved || !settings) return;
    settings.download_categories = saved.download_categories;
    settings.download_category_folders = saved.download_category_folders;
    settings.settings_revision = saved.settings_revision;
    if (!originalSettings) return;
    try {
      const base = JSON.parse(originalSettings) as AppSettings;
      base.download_categories = saved.download_categories;
      base.download_category_folders = saved.download_category_folders;
      base.settings_revision = saved.settings_revision;
      originalSettings = JSON.stringify(base);
    } catch { /* malformed baseline; leave as-is */ }
  }

  async function addCategory(name: string, ownFolder: boolean) {
    try {
      const { folderError } = await addUserCategory(name, ownFolder);
      if (folderError) throw folderError;
    } finally {
      foldCategorySettings();
    }
  }
  async function removeCategory(name: string) {
    try {
      await removeUserCategory(name);
    } finally {
      foldCategorySettings();
    }
  }
  async function saveCategoryFolder(category: string, folder: string | null) {
    try {
      await setCategoryFolder(category, folder);
    } finally {
      foldCategorySettings();
    }
  }

  /** "Warn when free space is below", besides off. The backend caps it at 100 GB. */
  const LOW_DISK_CHOICES_MB = [512, 1024, 2048, 5120, 10240];
  let pageContentEl: HTMLDivElement | null = $state(null);
  let originalSettings: string = $state('');
  let saveMessage: string | null = $state(null);
  let saveIsWarning = $state(false);
  let loadError: string | null = $state(null);

  // The ports and UPnP are read once, when the network stack starts (the
  // upload listener binds the TCP port in `start_upload_server` before any
  // settings hot-reload path can touch it), so a saved change to one of them
  // waits for a restart. Restarting uses the same `relaunch` flow as
  // `SetupWizard.svelte` so the experience is identical to first-time setup.
  let launchSettings: LaunchSettings | null = $state(null);
  let showRestartPrompt = $state(false);
  let restarting = $state(false);

  // --- Backup / restore ---
  // A restore cannot be applied while the app is running (SQLite holds the
  // database open, and identity/config are already in memory), so the backend
  // stages it and the swap happens during the next launch. That makes the
  // restart part of the operation rather than an optional follow-up.
  let backupPassphrase = $state('');
  let backupPassphraseConfirm = $state('');
  let backupBusy = $state(false);
  let backupMessage: string | null = $state(null);
  let backupMessageKind: 'progress' | 'success' | 'error' = $state('progress');
  let restorePassphrase = $state('');
  let restoreSource: string | null = $state(null);
  let restorePreview: BackupPreview | null = $state(null);
  let restoreStaged: RestoreSummary | null = $state(null);
  let pendingRestore: PendingRestoreStatus | null = $state(null);

  /** Milliseconds; this install's own record, so a restored profile shows
   *  "no backup yet" until one is made here. */
  let lastBackupMs: number | null = $state(readLastBackup());

  function readLastBackup(): number | null {
    try {
      return lastBackupAt(localStorage);
    } catch {
      return null;
    }
  }

  function showBackupMsg(msg: string, kind: 'progress' | 'success' | 'error') {
    backupMessage = msg;
    backupMessageKind = kind;
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
      showBackupMsg(m.settings_backup_pending_discarded(), 'success');
    } catch (e) {
      showBackupMsg(translateError(e, m.settings_backup_restore_failed()), 'error');
    } finally {
      backupBusy = false;
    }
  }

  function resetLocalRestoreFields() {
    restoreSource = null;
    restorePreview = null;
    restorePassphrase = '';
  }

  async function clearRestoreState() {
    resetLocalRestoreFields();
    try {
      await clearPickedBackup();
    } catch (e) {
      showBackupMsg(translateError(e, m.settings_backup_restore_failed()), 'error');
    }
  }

  async function handleExportBackup() {
    if (backupBusy) return;
    if (backupPassphrase !== backupPassphraseConfirm) {
      showBackupMsg(m.settings_backup_passphrase_mismatch(), 'error');
      return;
    }
    backupBusy = true;
    showBackupMsg(m.settings_backup_exporting(), 'progress');
    try {
      const summary = await exportBackup(
        backupPassphrase,
        collectBackupPrefs(typeof localStorage === 'undefined' ? null : localStorage, {
          searchHistory: $appSettings?.save_search_history,
        }),
      );
      if (!summary) {
        backupMessage = null;
        return;
      }
      backupPassphrase = '';
      backupPassphraseConfirm = '';
      try {
        noteBackupMade(localStorage, Date.now());
      } catch {
        // Only the reminder's clock is lost.
      }
      lastBackupMs = readLastBackup();
      const done = m.settings_backup_export_done({
        files: summary.files,
        size: formatSize(summary.bytes),
        path: summary.path,
      });
      showBackupMsg(
        summary.skipped.length > 0 ? `${done} ${m.settings_backup_export_skipped_chat_key()}` : done,
        'success',
      );
    } catch (e) {
      showBackupMsg(translateError(e, m.settings_backup_export_failed()), 'error');
    } finally {
      backupBusy = false;
    }
  }

  async function handlePickBackupFile() {
    try {
      const selected = await pickBackupFile();
      if (typeof selected === 'string') {
        restoreSource = selected;
        restorePreview = null;
        backupMessage = null;
      }
    } catch (e) {
      showBackupMsg(translateError(e, m.settings_backup_restore_failed()), 'error');
    }
  }

  /** Decrypt and describe the chosen backup without touching anything, so the
   *  user can see what they are about to overwrite before committing. */
  async function handlePreviewBackup() {
    if (backupBusy || !restoreSource) return;
    backupBusy = true;
    showBackupMsg(m.settings_backup_reading(), 'progress');
    try {
      restorePreview = await previewBackup(restorePassphrase);
      backupMessage = null;
      if (restorePreview.schema_too_new) {
        showBackupMsg(m.settings_backup_schema_too_new(), 'error');
      }
    } catch (e) {
      restorePreview = null;
      showBackupMsg(translateError(e, m.settings_backup_restore_failed()), 'error');
    } finally {
      backupBusy = false;
    }
  }

  async function handleImportBackup() {
    if (backupBusy || !restoreSource) return;
    backupBusy = true;
    showBackupMsg(m.settings_backup_restoring(), 'progress');
    try {
      restoreStaged = await importBackup(restorePassphrase);
      resetLocalRestoreFields();
      backupMessage = null;
      // Import already succeeded. Clearing the picker mutex must not reuse
      // the restore-failed toast — a stuck mutex is not a failed restore.
      await clearPickedBackup().catch(() => {});
      await refreshPendingRestore();
      showRestoreRestartPrompt = true;
    } catch (e) {
      showBackupMsg(translateError(e, m.settings_backup_restore_failed()), 'error');
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
      // Without a timeout the failure text outlives the page, where the
      // success text clears after 3s — so a failure ends up looking permanent.
      trackedTimeout(() => { historyClearMsg = null; }, 6000);
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

  /** The last saved fixed number, so turning Auto off brings it back. */
  let lastFixedUploads = 5;

  /** Auto is a switch, so it applies at once and, like the others, flips
   *  back if the save fails. Turning it off restores the last saved fixed
   *  number, which the number box then edits. An unapplied edit in the box is
   *  dropped rather than saved by the switch. */
  function setMaxUploadsAuto(auto: boolean) {
    if (!settings) return;
    const saved = savedSettings?.max_concurrent_uploads ?? 0;
    if (auto && saved > 0) lastFixedUploads = saved;
    settings.max_concurrent_uploads = auto ? 0 : lastFixedUploads;
    // Checked when the save runs, not now: a second flip while the first is
    // in flight must still be saved once the first lands.
    const fields = ['max_concurrent_uploads'] as const;
    void enqueueSave(async () =>
      fieldsDirty(fields) ? saveFields(fields, { revertOnFailure: true }) : true,
    );
  }

  function applyRecommended() {
    if (!settings || !speedResult) return;
    settings.max_upload_speed = speedResult.recommended_upload_limit;
    settings.max_download_speed = speedResult.recommended_download_limit;
    void applyFields(['max_upload_speed', 'max_download_speed']);
  }

  // ---------------------------------------------------------------------
  // Runtime status: the bandwidth window in force and the sleep inhibitor.
  //
  // Both change on a clock with nobody at the keyboard, so the page seeds from
  // a command and then follows `ember:runtime-status`, which the backend emits
  // only when something actually changes.
  // ---------------------------------------------------------------------
  let runtimeStatus: RuntimeStatus | null = $state(null);

  // ---------------------------------------------------------------------
  // Bandwidth schedule editing.
  //
  // Rules are edited in place on `settings.bandwidth_schedule` and saved
  // together by the schedule's Apply button, like a typed field, so a rule is
  // never saved half-edited. Nothing here
  // applies a limit — the backend resolves the timetable once a second, and
  // `runtimeStatus` is what says which rule won.
  // ---------------------------------------------------------------------

  /** Monday-first labels for the day toggles, in bit order. */
  const weekdayLabels = $derived([
    m.schedule_day_mon(),
    m.schedule_day_tue(),
    m.schedule_day_wed(),
    m.schedule_day_thu(),
    m.schedule_day_fri(),
    m.schedule_day_sat(),
    m.schedule_day_sun(),
  ]);

  function addScheduleRule() {
    if (!settings) return;
    if (settings.bandwidth_schedule.length >= MAX_SCHEDULE_RULES) return;
    settings.bandwidth_schedule = [
      ...settings.bandwidth_schedule,
      newScheduleRule(settings.max_upload_speed, settings.max_download_speed),
    ];
  }

  function removeScheduleRule(id: string) {
    if (!settings) return;
    settings.bandwidth_schedule = settings.bandwidth_schedule.filter((r) => r.id !== id);
  }

  /** Move a rule up or down. Order is priority — the first open window wins —
   *  so this is the only way to resolve two rules that overlap. */
  function moveScheduleRule(index: number, delta: -1 | 1) {
    if (!settings) return;
    const next = [...settings.bandwidth_schedule];
    const target = index + delta;
    if (index < 0 || index >= next.length || target < 0 || target >= next.length) return;
    [next[index], next[target]] = [next[target], next[index]];
    settings.bandwidth_schedule = next;
  }

  // The three field editors below mutate the rule in place rather than mapping
  // the array to fresh objects. The name and enabled switch use `bind:`, which
  // is a mutation, so replacing the array underneath them would mean two
  // different update styles racing over the same keyed `{#each}` row. Deep
  // `$state` proxying makes an in-place write reactive either way.
  function ruleById(id: string): BandwidthScheduleRule | undefined {
    return settings?.bandwidth_schedule.find((r) => r.id === id);
  }

  /** Accessible name for one of a rule's controls. Every rule has the same set,
   *  so the action alone would name a dozen buttons identically. */
  function ruleControlLabel(action: string, rule: BandwidthScheduleRule, index: number): string {
    return m.schedule_rule_control_aria({
      action,
      rule: rule.label.trim() || m.schedule_unnamed_rule(),
      position: index + 1,
    });
  }

  function setRuleDays(id: string, weekday: number) {
    const rule = ruleById(id);
    if (rule) rule.days = toggleDay(rule.days, weekday);
  }

  /**
   * A time field the user cleared (or left half-typed) parses to nothing.
   * Keeping the old minute is right — a rule always has a window — but the
   * input is now visibly blank, and Svelte will not re-apply an attribute whose
   * bound value did not change. So put the stored time back on screen.
   */
  function restoreTimeInput(input: HTMLInputElement, minute: number) {
    input.value = minutesToTimeValue(minute);
  }

  function setRuleStart(id: string, input: HTMLInputElement) {
    const rule = ruleById(id);
    if (!rule) return;
    const minute = timeValueToMinutes(input.value);
    if (minute === null) {
      restoreTimeInput(input, rule.start_minute);
      return;
    }
    rule.start_minute = minute;
  }

  function setRuleEnd(id: string, input: HTMLInputElement) {
    const rule = ruleById(id);
    if (!rule) return;
    const minute = endTimeValueToMinutes(input.value);
    if (minute === null) {
      restoreTimeInput(input, rule.end_minute);
      return;
    }
    rule.end_minute = minute;
  }

  /** Localized reason a rule would be refused, or `null` if it is fine. */
  function scheduleRuleError(rule: BandwidthScheduleRule): string | null {
    switch (ruleProblem(rule)) {
      case 'no_days': return m.schedule_error_no_days();
      case 'empty_window': return m.schedule_error_empty_window();
      case 'invalid_window': return m.schedule_error_invalid_window();
      case 'label_too_long': return m.schedule_error_label_too_long({ max: MAX_RULE_LABEL_CHARS });
      case 'speed_too_high': return m.schedule_error_speed_too_high();
      case 'invalid_id': return m.schedule_error_invalid_id();
      default: return null;
    }
  }

  // Both read a `$state` binding through a local const first, for the reason
  // spelled out at `antileechDraftDirty` below: TS does not narrow a
  // `$state`-backed getter read directly inside the expression.

  /** The saved rule the backend says is in force, if any. Compared by id so a
   *  rule the user is mid-edit stops being marked active the moment its window
   *  no longer matches what was saved. */
  let activeScheduleRuleId = $derived.by(() => {
    const status = runtimeStatus;
    return status?.schedule?.id ?? null;
  });

  /**
   * Whether the schedule would be refused by the backend, which blocks its
   * Apply button.
   *
   * The list-level checks are here as well as the per-rule ones. A duplicate id
   * or an over-long list is refused by `schedule::validate` exactly as a
   * malformed rule is, and without them Apply stayed enabled and the failure
   * came back as a page-level error naming no rule at all.
   */
  let scheduleHasError = $derived.by(() => {
    const current = settings;
    if (!current) return false;
    return (
      scheduleProblem(current.bandwidth_schedule) !== null
      || current.bandwidth_schedule.some((rule) => ruleProblem(rule) !== null)
    );
  });

  let spamStats: SpamStats | null = $state(null);
  let spamStatsLoading = $state(false);
  let spamStatsError: string | null = $state(null);
  let spamResetting = $state(false);
  type SettingsSection = 'general' | 'notifications' | 'downloads' | 'bandwidth' | 'network' | 'security' | 'friends' | 'channels' | 'search' | 'webservices' | 'backup' | 'about';

  /// Sidebar order, and the order the cards are declared in below. Keep them
  /// in step: while filtering, every matching card is on screen in DOM order,
  /// and the arrow-key handling below walks this array, so a mismatch makes
  /// the keyboard order disagree with what is on screen.
  const sections: SettingsSection[] = [
    'general',
    'notifications',
    'downloads',
    'search',
    'webservices',
    'bandwidth',
    'network',
    'security',
    'friends',
    'channels',
    'backup',
    'about',
  ];

  /** Section ids that links and the session may still carry. Import was its
   *  own section before it joined Backup. */
  function knownSection(value: string | null | undefined): SettingsSection | null {
    if (value === 'import') return 'backup';
    return value && (sections as string[]).includes(value) ? (value as SettingsSection) : null;
  }

  /**
   * `?section=network` opens straight to that card. Pages that send the user
   * here are pointing at one specific setting — the Ember page's "off" state
   * means "turn the overlay back on in Network" — and dropping them on
   * General left them to find it. Without one, Settings reopens on the
   * section last open this session, so stepping out to check something and
   * coming back does not mean finding your place again. Unknown values fall
   * back to General, so a stale link can't land on a blank page.
   *
   * Read once at init rather than tracked: this is an entry point, not a
   * binding, and re-syncing would fight the nav buttons.
   */
  function initialSection(): SettingsSection {
    try {
      const requested = knownSection(get(page).url.searchParams.get('section'));
      if (requested) return requested;
    } catch {
      /* no URL available — fall through */
    }
    try {
      const remembered = knownSection(sessionStorage.getItem(LAST_SECTION_KEY));
      if (remembered) return remembered;
    } catch {
      /* storage disabled — General is the safe default */
    }
    return 'general';
  }

  const LAST_SECTION_KEY = 'settings-last-section';
  let activeSection: SettingsSection = $state(initialSection());
  $effect(() => {
    const section = activeSection;
    try {
      sessionStorage.setItem(LAST_SECTION_KEY, section);
    } catch {
      /* storage disabled — Settings just opens on General next time */
    }
  });
  // A link to a section followed while already on Settings (the status bar's
  // "More in Settings") reuses this page, so `initialSection` never sees it.
  // Only real navigations land here: `selectSection` writes the URL with
  // `replaceState`, which does not.
  afterNavigate((navigation) => {
    const requested = knownSection(navigation.to?.url.searchParams.get('section'));
    if (requested && requested !== activeSection) {
      activeSection = requested;
      // The link names the section; the filter's last-used field must not
      // override it when the filter clears.
      filterFocusField = null;
      settingsFilter = '';
    }
  });
  /// The import group scans eMule's folder when it mounts, so it waits until
  /// its section is first opened rather than running on every Settings visit.
  let importOpened = $state(false);
  $effect(() => {
    if (activeSection === 'backup') importOpened = true;
  });

  /**
   * Free-text filter across every control on the page.
   *
   * A dozen sections and around sixty controls is past the point where
   * scanning works, and "which section is the obfuscation toggle in?" has no
   * good answer until you have already found it.
   *
   * Matching reads the *rendered* text of each field rather than a hand-kept
   * registry of labels, so it cannot drift out of step with the markup the
   * way a parallel list would. `textContent` covers the label, the toggle
   * title and the hint — everything that describes a control — and excludes
   * input values, which is what we want: filtering by a port number someone
   * happens to have typed would be noise.
   */
  let settingsFilter = $state('');
  let filterQuery = $derived(settingsFilter.trim().toLowerCase());
  let filtering = $derived(filterQuery.length > 0);
  /// Set by the effect below, which is the only thing that can count matches
  /// (it has to read the DOM). Drives the result count and the empty state.
  let filterMatchCount = $state(0);
  let cardsGridEl: HTMLDivElement | undefined = $state(undefined);

  /**
   * Show only the fields that match, and only the sections that still have
   * one.
   *
   * Done imperatively because the thing being matched is rendered text, which
   * is not available to a `$derived`. The attributes written here
   * (`data-filtered`) are ones Svelte never manages, so this cannot fight the
   * `class:hidden` binding on the cards — that stays in charge of which
   * single section shows when no filter is active.
   */
  $effect(() => {
    const query = filterQuery;
    const grid = cardsGridEl;
    if (!grid) return;
    // Referenced so the effect re-runs once the sections have rendered their
    // contents, not just when the query changes.
    void settings;
    const cards = grid.querySelectorAll<HTMLElement>('.card');
    if (!query) {
      for (const card of cards) {
        card.removeAttribute('data-filtered');
        // Clear by attribute rather than by selector list. The marking pass
        // below reaches more kinds of element than the three it used to, and
        // a cleanup that names them individually is one edit away from
        // stranding something permanently hidden.
        for (const el of card.querySelectorAll<HTMLElement>('[data-filtered]')) {
          el.removeAttribute('data-filtered');
        }
      }
      filterMatchCount = 0;
      return;
    }
    let matches = 0;
    for (const card of cards) {
      // A section whose own name matches keeps all of its fields, so
      // searching "backup" shows the Backup section rather than only the
      // rows that happen to repeat the word.
      const heading = card.querySelector('.card-header')?.textContent?.toLowerCase() ?? '';
      const wholeCard = heading.includes(query);
      let cardMatches = 0;
      for (const field of card.querySelectorAll<HTMLElement>('.field')) {
        // Likewise a group's heading: "power" finds the setting under Power.
        const groupHeading = field.closest('.settings-group')?.querySelector(':scope > .subsection-title');
        const wholeGroup = groupHeading?.textContent?.toLowerCase().includes(query) ?? false;
        const hit = wholeCard || wholeGroup || (field.textContent?.toLowerCase().includes(query) ?? false);
        if (hit) {
          field.removeAttribute('data-filtered');
          cardMatches += 1;
        } else {
          field.setAttribute('data-filtered', 'out');
        }
      }
      // One rule for every wrapper: a two-up row and a named group are both
      // just containers, and a container is worth showing only while it still
      // holds something.
      //
      // Order within this loop does not matter, even though a group encloses
      // a row: the test looks for a surviving *field*, and every field was
      // decided by the loop above. A container asking about its child
      // containers would have had to run innermost-first.
      for (const box of card.querySelectorAll<HTMLElement>('.field-row, .settings-group')) {
        if (box.querySelector('.field:not([data-filtered])')) box.removeAttribute('data-filtered');
        else box.setAttribute('data-filtered', 'out');
      }
      // Everything else the body holds. Plenty of a card is not a `.field`:
      // About's identity block and updater panel, Backup's action rows,
      // Bandwidth's active-schedule banner. Judging the card on fields alone
      // made all of that both unfindable — a query matching only such text
      // scored zero and hid the whole card, putting eight controls out of
      // reach, among them "Open log folder", "Choose Backup File…" and the
      // updater's Install button — and unhideable, since nothing ever marked
      // it, so it leaked into every card that survived on some other match.
      const body = card.querySelector<HTMLElement>('.card-body');
      for (const block of body ? (Array.from(body.children) as HTMLElement[]) : []) {
        if (block.matches('.field, .field-row, .settings-group')) continue;
        if (block.querySelector('.field')) {
          // Holds fields the loops above already ruled on; follow them.
          if (block.querySelector('.field:not([data-filtered])')) {
            block.removeAttribute('data-filtered');
          } else {
            block.setAttribute('data-filtered', 'out');
          }
          continue;
        }
        const hit = wholeCard || (block.textContent?.toLowerCase().includes(query) ?? false);
        if (hit) {
          block.removeAttribute('data-filtered');
          cardMatches += 1;
        } else {
          block.setAttribute('data-filtered', 'out');
        }
      }
      if (cardMatches > 0) card.removeAttribute('data-filtered');
      else card.setAttribute('data-filtered', 'out');
      matches += cardMatches;
    }
    filterMatchCount = matches;
  });

  function sectionLabel(id: SettingsSection): string {
    switch (id) {
      case 'general': return m.settings_section_general();
      case 'notifications': return m.settings_section_notifications();
      case 'downloads': return m.settings_section_downloads();
      case 'bandwidth': return m.settings_section_bandwidth();
      case 'network': return m.settings_section_network();
      case 'security': return m.settings_section_security();
      case 'friends': return m.settings_section_friends();
      case 'channels': return m.settings_section_channels();
      case 'search': return m.settings_section_search();
      case 'webservices': return m.webservices_title();
      case 'backup': return m.settings_section_backup();
      case 'about': return m.settings_section_about();
    }
  }

  /// Ids for the tab/panel pairing, so each panel names the tab that controls
  /// it and vice versa.
  function tabId(id: SettingsSection): string {
    return `settings-tab-${id}`;
  }
  function panelId(id: SettingsSection): string {
    return `settings-panel-${id}`;
  }

  /**
   * Switch section, and keep `?section=` pointing at what is on screen.
   *
   * The query parameter was read on load but never written, so it went stale
   * the moment the user clicked anything: arriving from another page's
   * "change this in Network" link and then moving to Backup left the URL
   * saying `network`, and a reload silently jumped back there. Writing it
   * also makes the section the user is looking at linkable.
   *
   * `replaceState` rather than `goto`/`pushState`: switching a panel is not a
   * navigation, and stacking a history entry per tab would turn Back into a
   * tour of the sidebar instead of a way out of Settings. It also stays clear
   * of `beforeNavigate`, which guards unsaved edits — a section switch must
   * not trip the leave prompt.
   */
  function selectSection(id: SettingsSection) {
    activeSection = id;
    settingsFilter = '';
    if (typeof window === 'undefined') return;
    try {
      const url = new URL(window.location.href);
      url.searchParams.set('section', id);
      replaceState(url, {});
    } catch {
      /* Non-fatal: the panel is already switched, only the URL is stale. */
    }
  }

  /**
   * Arrow-key movement between tabs, as the tabs pattern requires.
   *
   * Roving tabindex means only the selected tab is in the tab order, so
   * without this the other eleven would be unreachable from the keyboard.
   */
  function onTabKeydown(event: KeyboardEvent, index: number) {
    const last = sections.length - 1;
    let next: number | null = null;
    if (event.key === 'ArrowDown' || event.key === 'ArrowRight') next = index === last ? 0 : index + 1;
    else if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') next = index === 0 ? last : index - 1;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = last;
    if (next === null) return;
    event.preventDefault();
    selectSection(sections[next]);
    // Selection follows focus in this pattern, so move focus with it.
    document.getElementById(tabId(sections[next]))?.focus();
  }

  // In a narrow window the tabs are one row that scrolls sideways, and the
  // selected one can sit off the edge — after arriving from a link, say.
  $effect(() => {
    const id = tabId(activeSection);
    if (filtering) return;
    void tick().then(() => {
      document.getElementById(id)?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    });
  });

  let settingsFilterEl: HTMLInputElement | null = $state(null);

  /** Ctrl/Cmd+F, or "/" when not typing, finds a setting — the same keys
   *  that focus the search box on Library, Search and Channels. */
  function handleFindKey(e: KeyboardEvent) {
    if (e.defaultPrevented || document.querySelector('[aria-modal="true"]')) return;
    if (e.target instanceof Element && e.target.closest('.chat-dock')) return;
    const target = e.target instanceof HTMLElement ? e.target : null;
    const typing =
      !!target && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName));
    const findKey =
      (e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && isShortcutLetter(e, 'f');
    if (!findKey && (typing || e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey)) return;
    if (!settingsFilterEl) return;
    e.preventDefault();
    settingsFilterEl.focus();
    settingsFilterEl.select();
  }

  // While filtering, the section of the setting last used. Clearing the
  // filter opens it, rather than dropping back to whatever section was open
  // before the search and leaving the setting just changed out of sight.
  let filterFocusField: HTMLElement | null = null;
  function noteFilterFocus(e: FocusEvent) {
    if (filtering && e.target instanceof HTMLElement && e.target.closest('.card')) {
      filterFocusField = e.target;
    }
  }

  let wasFiltering = false;
  $effect(() => {
    const now = filtering;
    untrack(() => {
      const field = !now && wasFiltering ? filterFocusField : null;
      wasFiltering = now;
      if (!now) filterFocusField = null;
      const cardId = field?.isConnected ? field.closest('.card')?.id : undefined;
      const section = sections.find((s) => panelId(s) === cardId);
      if (!field || !section) return;
      selectSection(section);
      // Switching sections scrolls to the top; bring the setting back.
      void tick().then(() => field.scrollIntoView({ block: 'center' }));
    });
  });

  let unmounted = false;
  onMount(() => {
    // Seed the schedule/sleep snapshot, then follow it. The event fires only on
    // change, so without the seed a page opened between two boundaries would
    // show nothing at all until the next one.
    let unlistenRuntimeStatus: UnlistenFn | null = null;
    getRuntimeStatus()
      .then((status) => {
        if (unmounted) return;
        runtimeStatus = status;
      })
      .catch((e) => console.warn('Settings: runtime status unavailable', e));
    listen<RuntimeStatus>('ember:runtime-status', (event) => {
      if (unmounted) return;
      runtimeStatus = event.payload;
    })
      .then((fn) => {
        if (unmounted) fn();
        else unlistenRuntimeStatus = fn;
      })
      .catch((e) => console.error('Failed to register runtime-status listener:', e));

    let unlistenSettingsChanged: UnlistenFn | null = null;
    listen<AppSettings>(SETTINGS_CHANGED_EVENT, (event) => {
      if (!unmounted) foldQuickLimits(event.payload);
    })
      .then((fn) => {
        if (unmounted) fn();
        else unlistenSettingsChanged = fn;
      })
      .catch((e) => console.error('Failed to register settings-changed listener:', e));

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
    getLaunchSettings()
      .then((launch) => {
        if (!unmounted) launchSettings = launch;
      })
      // Only the restart banner is lost; every setting still saves.
      .catch((e) => console.warn('Settings: launch settings unavailable', e));

    // Only covers window close/reload. In-app routing is guarded by the
    // `beforeNavigate` hook below, which is the path a desktop user actually
    // takes (the sidebar navigates with `goto`).
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (hasUnsavedChanges) e.preventDefault();
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    window.addEventListener('keydown', handleFindKey);
    return () => {
      unmounted = true;
      window.removeEventListener('keydown', handleFindKey);
      unlistenRuntimeStatus?.();
      unlistenSettingsChanged?.();
      window.removeEventListener('beforeunload', handleBeforeUnload);
      for (const id of activeTimers) clearTimeout(id);
    };
  });

  const activeTimers = new Set<ReturnType<typeof setTimeout>>();
  function trackedTimeout(fn: () => void, ms: number) {
    const id = setTimeout(() => { activeTimers.delete(id); fn(); }, ms);
    activeTimers.add(id);
  }

  let recoveringRooms = $state(false);
  /** Look for rooms this identity owns. Rooms put back are announced by the
   *  app-wide notice the backend's event raises, so only the other two
   *  outcomes are said here. */
  async function findOwnedRooms() {
    if (recoveringRooms) return;
    recoveringRooms = true;
    try {
      const scan = await recoverOwnedChannels();
      const sure = scan.confirmed && scan.unsettled === 0;
      if (!sure) {
        showSaveMsg(m.settings_channels_recover_unsure(), true, 6000);
      } else if (scan.recovered === 0) {
        showSaveMsg(m.settings_channels_recover_none(), false, 6000);
      }
    } catch (e) {
      showSaveMsg(translateError(e), true, 6000);
    } finally {
      recoveringRooms = false;
    }
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

  function clampNicknameInput(event: Event) {
    if (settings) settings.nickname = clampInputUtf8Bytes(event, NICKNAME_MAX_BYTES, settings.nickname);
  }

  /** The name eMule users see, as `ed2k_nickname` in `src-tauri/src/types.rs`
   *  builds it. */
  let ed2kNickname = $derived.by(() => {
    const nickname = settings?.nickname ?? '';
    const base = nickname.trimEnd();
    if (!settings?.nickname_site_tag || !base.trim() || base.toLowerCase().includes('emberp2p.org')) {
      return nickname;
    }
    return `${base} [https://emberp2p.org]`;
  });

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
    // Mirror the backend's 128-byte cap (commands/settings.rs). The input
    // already stops at it; this catches a value that arrived another way.
    if (new TextEncoder().encode(s.nickname).length > NICKNAME_MAX_BYTES) {
      return { error: m.error_settings_nickname_too_long(), adjusted: false };
    }
    if (s.channel_username.trim() && !isValidChannelUsername(s.channel_username)) {
      return { error: m.error_channels_username_invalid(), adjusted: false };
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
    // `bind:value` on `<input type="number">` yields `null` for an empty box,
    // and the clamp helpers below map that to the field's factory default —
    // silently persisting 4662 for a port the user only meant to retype, and
    // popping the restart prompt for an edit they never made. Reject instead.
    const numericFields = [
      'tcp_port', 'udp_port', 'max_upload_speed', 'max_download_speed',
      'max_concurrent_downloads', 'max_concurrent_uploads', 'max_sources_per_file',
      'max_connections', 'max_connections_per_five_secs',
      'download_queue_wait_secs', 'multisource_retry_rounds',
      'max_download_file_size_gib', 'search_timeout_secs', 'max_friends', 'chat_attachment_auto_accept_mb',
    ] as const;
    const numericValues = s as unknown as Record<string, unknown>;
    for (const key of numericFields) {
      const v = numericValues[key];
      if (v === null || v === undefined || (typeof v === 'number' && !Number.isFinite(v))) {
        return { error: m.settings_validation_number_empty(), adjusted: false };
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
    s.max_upload_speed = cn(s.max_upload_speed, MAX_CONFIGURED_SPEED_BPS, 0);
    // USS needs a non-zero upload cap, so applying Unlimited turns it off.
    if (s.max_upload_speed === 0) s.uss_enabled = false;
    s.max_download_speed = cn(s.max_download_speed, MAX_CONFIGURED_SPEED_BPS, 0);
    s.max_concurrent_downloads = ci(s.max_concurrent_downloads, 1, 50, 5);
    // 0 is Auto, not an empty box — `numericFields` above rejects those.
    if (s.max_concurrent_uploads !== 0) s.max_concurrent_uploads = ci(s.max_concurrent_uploads, 1, 50, 5);
    s.max_sources_per_file = ci(s.max_sources_per_file, 50, 2000, 400);
    s.max_connections = ci(s.max_connections, 1, 2000, 500);
    // Lower bound 0: that is the documented "no burst gate" value, not an
    // empty box — `numericFields` above already rejects those.
    s.max_connections_per_five_secs = ci(s.max_connections_per_five_secs, 0, 500, 20);
    s.download_queue_wait_secs = ci(s.download_queue_wait_secs, 60, 14400, 1800);
    s.multisource_retry_rounds = ci(s.multisource_retry_rounds, 1, 20, 3);
    s.max_download_file_size_gib = ci(s.max_download_file_size_gib, 1, 593, 593);
    s.search_timeout_secs = ci(s.search_timeout_secs, 30, 600, 120);
    s.max_friends = ci(s.max_friends, 1, 500, 200);
    // 0 is "always ask", not an empty box; the ceiling is the attachment cap.
    s.chat_attachment_auto_accept_mb = cn(s.chat_attachment_auto_accept_mb, 2048, 25);
    return { error: null, adjusted };
  }

  function sameSettingValue(a: unknown, b: unknown): boolean {
    return JSON.stringify(a) === JSON.stringify(b);
  }

  // `uss_enabled` too: an Unlimited upload set there turns USS off.
  // `friend_overrides` is saved only from a friend's settings dialog, and
  // `close_to_tray_behavior` also by "Remember my choice" in the close dialog.
  const QUICK_LIMIT_KEYS = [
    'alt_speed_enabled',
    'max_upload_speed',
    'max_download_speed',
    'alt_max_upload_speed',
    'alt_max_download_speed',
    'uss_enabled',
    'friend_overrides',
    'close_to_tray_behavior',
  ] as const;

  /** The tray, the status bar, a friend's settings dialog or the close dialog
   *  saved while this page was open. Show it, except in a field already edited
   *  here, which stays a change to apply. */
  function foldQuickLimits(saved: AppSettings): void {
    if (!settings || !originalSettings) return;
    let baseline: AppSettings;
    try {
      baseline = JSON.parse(originalSettings) as AppSettings;
    } catch {
      return;
    }
    const current = settings as unknown as Record<string, unknown>;
    const base = baseline as unknown as Record<string, unknown>;
    const incoming = saved as unknown as Record<string, unknown>;
    for (const key of QUICK_LIMIT_KEYS) {
      if (sameSettingValue(current[key], base[key])) current[key] = incoming[key];
      base[key] = incoming[key];
    }
    settings.settings_revision = saved.settings_revision;
    baseline.settings_revision = saved.settings_revision;
    originalSettings = JSON.stringify(baseline);
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

  /**
   * Typed into a box, so each waits for its Apply button (or Enter) rather
   * than saving a half-typed value on every keystroke. The schedule is here
   * too: a rule is several fields that only make sense together.
   */
  const APPLY_FIELDS = [
    'nickname',
    'max_concurrent_downloads',
    'max_concurrent_uploads',
    'max_connections',
    'max_connections_per_five_secs',
    'max_sources_per_file',
    'max_download_file_size_gib',
    'search_timeout_secs',
    'filename_cleanups',
    'max_upload_speed',
    'max_download_speed',
    'alt_max_upload_speed',
    'alt_max_download_speed',
    'bandwidth_schedule',
    'tcp_port',
    'udp_port',
    'chat_attachment_auto_accept_mb',
    'max_friends',
    'channel_username',
  ] as const satisfies readonly (keyof AppSettings)[];
  type ApplyField = (typeof APPLY_FIELDS)[number];
  const APPLY_FIELD_SET: ReadonlySet<string> = new Set(APPLY_FIELDS);

  /**
   * Fields the automatic save leaves alone. The anti-leech and IP switches
   * have commands of their own that apply them to the running filters, and
   * the download folder is saved by its picker, which is the only place the
   * save may ask to re-approve it.
   */
  const SEPARATELY_SAVED_FIELDS: ReadonlySet<string> = new Set([
    'settings_revision',
    'antileech_enabled',
    'ip_filter_enabled',
    'ip_filter_auto_update',
    'block_private_ips',
    'download_folder',
  ]);

  /** What is on disk, as of this page's last load or save. */
  let savedSettings = $derived.by((): AppSettings | null => {
    if (!originalSettings) return null;
    try {
      return JSON.parse(originalSettings) as AppSettings;
    } catch {
      return null;
    }
  });

  // True only while editing a fixed number: both the saved and the edited
  // value are non-zero. Flipping Auto changes one of them to or from 0, so the
  // Apply button never flashes while that switch is saving.
  let maxUploadsEditingNumber = $derived.by(() => {
    const current = settings;
    const saved = savedSettings;
    return current?.max_concurrent_uploads !== 0 && saved?.max_concurrent_uploads !== 0;
  });

  function fieldValue(source: AppSettings, key: string): unknown {
    return (source as unknown as Record<string, unknown>)[key];
  }

  function cloneValue<T>(value: T): T {
    return value === undefined ? value : (JSON.parse(JSON.stringify(value)) as T);
  }

  function fieldsDirty(fields: readonly string[]): boolean {
    const current = settings;
    const saved = savedSettings;
    if (!current || !saved) return false;
    return fields.some((key) => !sameSettingValue(fieldValue(current, key), fieldValue(saved, key)));
  }

  /** Fields that save the moment they change, and have changed. */
  function pendingAutoFields(): string[] {
    const current = settings;
    const saved = savedSettings;
    if (!current || !saved) return [];
    return Object.keys(current).filter(
      (key) =>
        !APPLY_FIELD_SET.has(key)
        && !SEPARATELY_SAVED_FIELDS.has(key)
        && !sameSettingValue(fieldValue(current, key), fieldValue(saved, key)),
    );
  }

  // Saves run one at a time, in the order they were asked for, so each starts
  // from the revision the one before it left.
  let saveQueue: Promise<unknown> = Promise.resolve();
  function enqueueSave<T>(task: () => Promise<T>): Promise<T> {
    const run = saveQueue.then(task, task);
    saveQueue = run.catch(() => {});
    return run;
  }

  /** Why the last Apply failed, shown under the field it was for until the
   *  value that failed is edited. */
  let applyError: { fields: string; attempt: string; message: string } | null = $state(null);

  function fieldsSnapshot(fields: readonly string[], source: Record<string, unknown>): string {
    return JSON.stringify(fields.map((key) => source[key]));
  }

  function applyErrorFor(fields: readonly string[]): string | null {
    const error = applyError;
    const current = settings as unknown as Record<string, unknown> | null;
    if (!error || !current || error.fields !== fields.join(',')) return null;
    return error.attempt === fieldsSnapshot(fields, current) ? error.message : null;
  }

  function applyFields(fields: readonly ApplyField[]): Promise<boolean> {
    if (!fieldsDirty(fields)) return Promise.resolve(true);
    return enqueueSave(() => saveFields(fields, { reportInline: true }));
  }

  /** Enter applies a typed field; Escape puts it back as it is saved. */
  function applyOnEnter(event: KeyboardEvent, fields: readonly ApplyField[]) {
    if (event.isComposing || !fieldsDirty(fields)) return;
    if (event.key === 'Enter') {
      event.preventDefault();
      void applyFields(fields);
    } else if (event.key === 'Escape') {
      event.preventDefault();
      const current = settings as unknown as Record<string, unknown> | null;
      const saved = savedSettings;
      if (!current || !saved) return;
      for (const key of fields) current[key] = cloneValue(fieldValue(saved, key));
      if (applyError?.fields === fields.join(',')) applyError = null;
    }
  }

  // One queued run covers every switch flipped before it starts: it reads the
  // changed fields when it runs, not when it was queued.
  let autoSaveQueued = false;
  function scheduleAutoSave() {
    if (autoSaveQueued || pendingAutoFields().length === 0) return;
    autoSaveQueued = true;
    void enqueueSave(async () => {
      autoSaveQueued = false;
      const fields = pendingAutoFields();
      if (fields.length > 0) await saveFields(fields, { revertOnFailure: true });
    });
  }

  $effect(() => {
    if (!settings || !originalSettings) return;
    // Read deeply so a change anywhere in the form re-runs this.
    JSON.stringify(settings);
    untrack(scheduleAutoSave);
  });

  type RestartField = 'tcp_port' | 'udp_port' | 'upnp_enabled';

  /** Saved values the running network stack has not picked up yet. */
  let pendingRestart = $derived.by((): { field: RestartField; reason: string }[] => {
    const saved = savedSettings;
    const launch = launchSettings;
    if (!saved || !launch) return [];
    const pending: { field: RestartField; reason: string }[] = [];
    if (saved.tcp_port !== launch.tcp_port) {
      pending.push({
        field: 'tcp_port',
        reason: m.settings_restart_reason_tcp_only({
          from: String(launch.tcp_port),
          to: String(saved.tcp_port),
        }),
      });
    }
    if (saved.udp_port !== launch.udp_port) {
      pending.push({
        field: 'udp_port',
        reason: m.settings_restart_reason_udp_only({
          from: String(launch.udp_port),
          to: String(saved.udp_port),
        }),
      });
    }
    if (saved.upnp_enabled !== launch.upnp_enabled) {
      pending.push({
        field: 'upnp_enabled',
        reason: saved.upnp_enabled
          ? m.settings_restart_reason_upnp_on()
          : m.settings_restart_reason_upnp_off(),
      });
    }
    return pending;
  });

  let restartReason = $derived(
    new Intl.ListFormat(getLocale(), { type: 'conjunction' }).format(
      pendingRestart.map((p) => p.reason),
    ),
  );

  function restartPending(field: RestartField): boolean {
    return pendingRestart.some((p) => p.field === field);
  }

  interface SaveFieldsOptions {
    /** Put the fields back as they are on disk if the save fails, so a
     *  switch never shows a state that is not in force. */
    revertOnFailure?: boolean;
    /** Show a failure under the field rather than in the header. */
    reportInline?: boolean;
    reapproveDownloadRoot?: boolean;
  }

  /**
   * Save `fields` as the page has them over the latest settings on disk,
   * leaving every other field as it is there. Re-reading first keeps changes
   * made elsewhere (the tray, the status bar, another command) instead of
   * overwriting them with this page's copy, and lets one revision race retry.
   */
  async function saveFields(
    fields: readonly string[],
    options: SaveFieldsOptions = {},
  ): Promise<boolean> {
    if (!settings) return false;
    // Taken at the start: the form stays live while the save is in flight,
    // and a field edited again meanwhile must stay a pending change.
    const sent = cloneValue(settings as unknown as Record<string, unknown>);
    const errorKey = fields.join(',');
    const fail = (message: string) => {
      if (options.revertOnFailure) revertFields(fields, sent);
      if (options.reportInline) {
        applyError = { fields: errorKey, attempt: fieldsSnapshot(fields, sent), message };
      }
      else showSaveMsg(message, true, 6000);
    };
    try {
      let result: UpdateSettingsResult | null = null;
      let adjusted = false;
      for (let attempt = 0; attempt < 2; attempt++) {
        const latest = await getSettings();
        const candidate = cloneValue(latest);
        const candidateFields = candidate as unknown as Record<string, unknown>;
        for (const key of fields) candidateFields[key] = sent[key];
        // Friend session encryption is not user-toggleable in Settings.
        candidate.friend_session_encryption = true;
        const validation = validateSettings(candidate);
        if (validation.error) {
          fail(validation.error);
          return false;
        }
        adjusted = validation.adjusted;
        try {
          result = await updateSettings(candidate, {
            reapproveDownloadRoot: options.reapproveDownloadRoot,
          });
          break;
        } catch (e) {
          if (attempt === 0 && isSettingsRevisionConflict(e)) continue;
          throw e;
        }
      }
      if (!result) return false;
      if (applyError?.fields === errorKey) applyError = null;
      // Keep the process-wide settings cache in step with the just-saved
      // values so runtime consumers (friend online-notification toast, chat
      // "disabled" state) react immediately.
      setAppSettings(result.settings);
      foldSaved(result.settings, fields, sent);
      // `adjusted` means a typed number was outside its valid range and was
      // clamped, so say so rather than saving a different value silently.
      const outcome = updateSettingsOutcomeMessage(result);
      const isWarn = result.outcome === 'deferred' || adjusted;
      showSaveMsg(
        adjusted ? `${outcome} ${m.settings_values_adjusted()}` : outcome,
        isWarn,
        isWarn ? 8000 : 2000,
      );
      // No prompt here: the ports and UPnP are usually changed together, and
      // asking after each one interrupted the user mid-edit and made them
      // dismiss it before touching the next. The badge and the header banner
      // say a restart is pending; the prompt waits until they leave Settings.
      if (!restartReason) showRestartPrompt = false;
      return true;
    } catch (e) {
      console.error('Failed to save settings:', e);
      fail(translateError(e, m.settings_save_failed()));
      return false;
    }
  }

  /**
   * Take a save's result into the form. A field the save sent, or one with no
   * pending change, shows what is now on disk; one edited again while the
   * save was in flight keeps the newer edit, still waiting to be saved.
   */
  function foldSaved(saved: AppSettings, fields: readonly string[], sent: Record<string, unknown>) {
    if (!settings) return;
    const baseline = savedSettings;
    const current = settings as unknown as Record<string, unknown>;
    const incoming = cloneValue(saved) as unknown as Record<string, unknown>;
    const sentSet = new Set(fields);
    for (const key of Object.keys(incoming)) {
      if (key === 'settings_revision') continue;
      const reference = sentSet.has(key)
        ? sent[key]
        : baseline
          ? fieldValue(baseline, key)
          : current[key];
      if (
        sameSettingValue(current[key], reference)
        && !sameSettingValue(current[key], incoming[key])
      ) {
        current[key] = incoming[key];
      }
    }
    settings.settings_revision = saved.settings_revision;
    originalSettings = JSON.stringify(saved);
  }

  function revertFields(fields: readonly string[], sent: Record<string, unknown>) {
    const current = settings as unknown as Record<string, unknown> | null;
    const saved = savedSettings;
    if (!current || !saved) return;
    for (const key of fields) {
      if (sameSettingValue(current[key], sent[key])) {
        current[key] = cloneValue(fieldValue(saved, key));
      }
    }
  }

  /// Triggered from the restart prompt and banner. Mirrors SetupWizard's
  /// final-step behaviour: show a full-screen "Restarting Ember" overlay
  /// for ~600ms (so the user sees acknowledgement, not just an instant
  /// window disappearance), then call Tauri's `relaunch()` which kills
  /// the current process and spawns a fresh one. If `relaunch` fails for
  /// any reason (rare — usually only when the user lacks permission to
  /// re-spawn) we surface the error and let them restart manually.
  async function performRestart() {
    showRestartPrompt = false;
    restarting = true;
    try {
      // Brief delay so the overlay has time to paint before the process
      // dies — purely cosmetic, matches the wizard. Spent sending anything
      // still behind an Undo toast.
      await Promise.all([new Promise(r => setTimeout(r, 600)), flushToastActionsBeforeExit()]);
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
  let ignoredClearConfirmOpen = $state(false);
  let mutedClearConfirmOpen = $state(false);
  let hiddenClearConfirmOpen = $state(false);

  /**
   * Room name for a stored preference id, falling back to a short id.
   *
   * Silenced and removed rooms were shown as a bare count with one bulk
   * "Clear", so the only thing the user could do about a single room was wipe
   * every preference and start over. Names come from the joined-rooms store;
   * a room only ever seen in Discover has no row there, hence the fallback —
   * a truncated id is still enough to tell two entries apart and undo the
   * right one.
   */
  let channelNamesById = $derived(
    new Map($channelsStore.map((c) => [c.channel_id.toLowerCase(), c.name])),
  );

  function channelLabel(channelId: string): string {
    const name = channelNamesById.get(channelId.toLowerCase())?.trim();
    return name || shortPubkey(channelId);
  }

  /** Rooms turned down from "All messages", with the level each is at. */
  let quietRooms = $derived(Object.entries($channelNotifyLevels));

  function handleResetSpamData() {
    spamResetConfirmOpen = true;
  }

  async function confirmResetSpamData() {
    spamResetting = true;
    try {
      await resetSpamFilter();
      await notifySpamFilterReset();
      await refreshSpamStats();
      showSaveMsg(m.settings_spam_reset_success(), false, 3000);
    } catch (e: unknown) {
      showSaveMsg(translateError(e, m.settings_spam_reset_failed()), true, 5000);
    } finally {
      spamResetting = false;
    }
  }

  async function pickPreviewPlayer() {
    if (!settings) return;
    try {
      // Backend picker, so the path is authorized where it is chosen — saving
      // a player the renderer named on its own is refused.
      const selected = await pickPreviewPlayerDialog();
      if (selected) {
        settings.preview_player = selected;
      }
    } catch (e) {
      const msg = translateError(e, m.settings_preview_player_pick_failed());
      showSaveMsg(msg, true, 5000);
    }
  }

  async function pickDownloadFolder() {
    if (!settings) return;
    try {
      // Backend picker: the chosen path is authorized where it is chosen, so
      // saving a folder the renderer named on its own is refused.
      const selected = await pickDownloadFolderDialog();
      if (selected) {
        settings.download_folder = selected;
        // Saved even when the same folder is picked again: that is how a
        // folder Ember stopped recognising (moved, drive reconnected) is
        // re-approved, and it is not a change the automatic save would see.
        void enqueueSave(() =>
          saveFields(['download_folder'], { reapproveDownloadRoot: true, revertOnFailure: true }),
        );
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

  /** The two subfolders the backend creates under the download folder
   *  (`Downloads` and `Temp`), joined with the folder's own separator so a
   *  Windows path does not end in a forward slash. */
  function folderLayoutHint(folder: string): string {
    const sep = folder.includes('\\') ? '\\' : '/';
    const base = folder.replace(/[\\/]+$/, '');
    return m.settings_folder_layout_hint({
      downloads: `${base}${sep}Downloads`,
      temp: `${base}${sep}Temp`,
    });
  }

  // Anti-leech filter state — loaded lazily when the Security section
  // is first opened so the rest of Settings doesn't pay the IPC round
  // trip. The textarea below is bound to `antileechDraft` (newline-
  // joined patterns); we only push to the backend when the user clicks
  // Save, so the pattern list isn't recompiled on every keystroke.
  // Mirrors `webservices::MAX_WEB_SERVICES`. The backend truncates regardless;
  // this is only so the form can say why an add did nothing.
  const MAX_WEB_SERVICES = 32;

  // --- Web services (eMule's right-click → Web services) ---
  //
  // Edited straight into `settings.web_services`, so each add or remove saves
  // like any other setting, without a second persistence path. The backend
  // re-validates and de-duplicates on save regardless; the
  // checks here exist to give a reason next to the field the user typed in
  // rather than a silent drop.
  let newWebServiceName = $state('');
  let newWebServiceUrl = $state('');
  let webServiceMessage: { kind: 'ok' | 'err'; text: string } | null = $state(null);
  // Loaded from the backend so the offer cannot drift from the validator, and
  // so the button can hide itself once the entry is present rather than being
  // clickable only to report a duplicate.
  let exampleWebService: WebService | null = $state(null);
  // Narrowed via local consts first, for the reason `antileechDraftDirty`
  // records: TS does not reliably narrow a `$state`-backed getter read inside
  // an expression the way it would a plain variable.
  let canAddExample = $derived.by(() => {
    const example = exampleWebService;
    const current = settings;
    if (!example || !current) return false;
    return !current.web_services.some((s) => s.url === example.url);
  });

  function looksLikeWebServiceUrl(url: string): boolean {
    // A template's `#hashid` is a URL fragment until it is substituted, so the
    // strict check belongs at open time in the backend. This only rules out
    // what could never work.
    const trimmed = url.trim();
    if (!/^https?:\/\//i.test(trimmed)) return false;
    if (/[\s\u0000-\u001f]/.test(trimmed)) return false;
    try {
      const parsed = new URL(trimmed);
      if (!parsed.host || parsed.username || parsed.password) return false;
      // Mirrors the backend's save check: a placeholder straight after the
      // address (`https://x.test#name`) fills into the host, so the backend
      // drops the entry on save and the form must not look as if it took it.
      const filled = new URL(
        trimmed.replace(/#(cleanfilename|cleanname|filename|filesize|hashid|name)/g, 'a1'),
      );
      return filled.protocol === parsed.protocol && filled.host === parsed.host;
    } catch {
      return false;
    }
  }

  function addWebServiceEntry(name: string, url: string): 'added' | 'duplicate' | 'invalid' | 'full' {
    const current = settings;
    if (!current) return 'invalid';
    const trimmedName = name.trim();
    const trimmedUrl = url.trim();
    if (!trimmedName || !looksLikeWebServiceUrl(trimmedUrl)) return 'invalid';
    if (current.web_services.some((s) => s.url === trimmedUrl)) return 'duplicate';
    if (current.web_services.length >= MAX_WEB_SERVICES) return 'full';
    current.web_services = [...current.web_services, { name: trimmedName, url: trimmedUrl }];
    return 'added';
  }

  function addWebService() {
    switch (addWebServiceEntry(newWebServiceName, newWebServiceUrl)) {
      case 'added':
        newWebServiceName = '';
        newWebServiceUrl = '';
        webServiceMessage = null;
        break;
      case 'duplicate':
        webServiceMessage = { kind: 'err', text: m.webservices_import_duplicate() };
        break;
      case 'full':
        webServiceMessage = { kind: 'err', text: m.webservices_full({ max: MAX_WEB_SERVICES }) };
        break;
      default:
        webServiceMessage = { kind: 'err', text: m.webservices_invalid() };
    }
  }

  function removeWebService(index: number) {
    const current = settings;
    if (!current) return;
    current.web_services = current.web_services.filter((_, i) => i !== index);
    webServiceMessage = null;
  }

  function addExampleWebService() {
    try {
      const example = exampleWebService;
      if (!example) return;
      const outcome = addWebServiceEntry(example.name, example.url);
      webServiceMessage =
        outcome === 'duplicate'
          ? { kind: 'err', text: m.webservices_import_duplicate() }
          : outcome === 'full'
            ? { kind: 'err', text: m.webservices_full({ max: MAX_WEB_SERVICES }) }
            : null;
    } catch (e: unknown) {
      webServiceMessage = { kind: 'err', text: translateError(e) };
    }
  }

  async function handleImportWebServices() {
    try {
      const imported = await importWebServicesFile();
      // Null is a dismissed picker, which is not a failure and not worth a
      // message.
      if (imported === null) return;
      const outcomes = imported.map((service) => addWebServiceEntry(service.name, service.url));
      const added = outcomes.filter((o) => o === 'added').length;
      const full = outcomes.includes('full') ? m.webservices_full({ max: MAX_WEB_SERVICES }) : null;
      if (added === 0) {
        webServiceMessage = {
          kind: 'err',
          text:
            full ??
            (outcomes.includes('duplicate') ? m.webservices_import_duplicate() : m.webservices_import_none()),
        };
      } else {
        const addedText = plural(added, {
          one: m.webservices_imported_one,
          other: () => m.webservices_imported_other({ count: added }),
        });
        webServiceMessage = { kind: 'ok', text: full ? `${addedText} ${full}` : addedText };
      }
    } catch (e: unknown) {
      webServiceMessage = { kind: 'err', text: translateError(e) };
    }
  }

  let antileechSnapshot: AntiLeechSnapshot | null = $state(null);
  let antileechDraft = $state('');
  let antileechSaving = $state(false);
  let antileechMessage: { kind: 'ok' | 'warn' | 'err'; text: string } | null = $state(null);
  let antileechCompileErrors: Array<[string, string]> = $state([]);
  let antileechLoaded = $state(false);
  // The anti-leech textarea has its own dedicated Save button
  // (`handleSaveAntileech`) and isn't part of `settings`. A dirty draft
  // arms the leave guard, like a typed field that hasn't been applied.
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
  let hasUnsavedChanges = $derived(fieldsDirty(APPLY_FIELDS) || antileechDraftDirty);

  // In-app routing (the sidebar uses `goto`) would otherwise discard typed
  // edits not yet applied with no prompt — `beforeunload` never fires for it. `nav.cancel()`
  // must be called synchronously, so confirm out-of-band and re-issue the
  // navigation once the user agrees.
  let leaveConfirmOpen = $state(false);
  let pendingLeaveHref: string | null = null;
  let leaveConfirmed = false;
  // The pending-restart reason the leave prompt last asked about, so "Later"
  // is asked once per set of changes rather than on every visit's exit.
  let restartAskedFor: string | null = null;

  beforeNavigate((nav) => {
    if (leaveConfirmed) return;
    // A document unload is already covered by `beforeunload`, and `goto` could
    // not re-issue it anyway. This covers both `leave` and link navigations to
    // non-SvelteKit routes, which are also flagged `willUnload`.
    if (nav.willUnload) return;
    const to = nav.to?.url;
    if (!to) return;
    // Hash/query navigation within the same route (the skip-to-content link)
    // isn't leaving the form, so there is nothing to discard.
    if (to.pathname === nav.from?.url.pathname) return;
    if (hasUnsavedChanges) {
      nav.cancel();
      pendingLeaveHref = to.href;
      leaveConfirmOpen = true;
      return;
    }
    // Leaving is when the user has finished with the ports, so this is where
    // a restart they still need is offered — once, whichever of them changed.
    if (restartReason && restartReason !== restartAskedFor && !restarting) {
      nav.cancel();
      restartAskedFor = restartReason;
      pendingLeaveHref = to.href;
      showRestartPrompt = true;
    }
  });

  /** Carry on to wherever the user was going when a leave prompt stopped them. */
  function resumeLeave() {
    const href = pendingLeaveHref;
    pendingLeaveHref = null;
    if (!href) return;
    leaveConfirmed = true;
    void goto(href).catch((e) => {
      leaveConfirmed = false;
      console.error('Navigation after leaving settings failed:', e);
    });
  }

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
          text: plural(savedCount, {
            one: () => m.settings_antileech_saved_rejected_one({ rejected }),
            other: () => m.settings_antileech_saved_rejected_other({ count: savedCount, rejected }),
          }),
        };
      } else {
        const savedCount = result.snapshot.pattern_count;
        antileechMessage = {
          kind: 'ok',
          text: plural(savedCount, {
            one: m.settings_antileech_saved_one,
            other: () => m.settings_antileech_saved_other({ count: savedCount }),
          }),
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

  /**
   * The IP filter switches apply the moment they flip, as the same switches on
   * the Security page do. Queued so a quick on-off-on reaches the backend in
   * the order it was clicked.
   */
  let ipToggleQueue: Promise<void> = Promise.resolve();
  function applyIpToggleLive(
    field: 'ip_filter_enabled' | 'ip_filter_auto_update' | 'block_private_ips',
    next: boolean,
  ) {
    ipToggleQueue = ipToggleQueue.then(async () => {
      try {
        if (field === 'ip_filter_enabled') await setIpFilterEnabled(next);
        else if (field === 'ip_filter_auto_update') await setIpFilterAutoUpdate(next);
        else await setBlockPrivateIps(next);
        if (unmounted) return;
        // Already on disk, so it is not a pending change. Patch only this
        // field so other pending edits stay pending.
        if (originalSettings) {
          try {
            const base = JSON.parse(originalSettings) as AppSettings;
            base[field] = next;
            originalSettings = JSON.stringify(base);
          } catch { /* malformed baseline; leave as-is */ }
        }
        const persisted = await getSettings().catch(() => null);
        if (persisted) setAppSettings(persisted);
        showSaveMsg(m.settings_save_success(), false, 2000);
      } catch (e: unknown) {
        if (unmounted) return;
        if (settings) settings[field] = !next;
        showSaveMsg(translateError(e, m.settings_save_failed()), true, 6000);
      }
    });
  }

  async function handleAntileechToggle(checked: boolean, gen: number) {
    try {
      await setAntileechEnabled(checked);
      // A newer toggle superseded this one while the IPC was in flight, or the
      // page unmounted — stop so a slow earlier response can't clobber the
      // latest state (or write to a torn-down page).
      if (unmounted || gen !== antileechToggleGen) return;
      if (settings) settings.antileech_enabled = checked;
      // The toggle is applied + persisted by its own command, so fold it into
      // the saved baseline too. Patch only this one field so other pending
      // edits stay pending.
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
      // Confirmed like every other switch. Worth it for a control that turns
      // protection off in one click.
      showSaveMsg(m.settings_save_success(), false, 2000);
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
        text: plural(snap.pattern_count, {
          one: m.settings_antileech_restored_one,
          other: () => m.settings_antileech_restored_other({ count: snap.pattern_count }),
        }),
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

  /** The master switch, which every notification event depends on. */
  let notifyOff = $derived.by(() => {
    const current = settings;
    return current?.notifications_enabled === false;
  });

  // The stored fields are "disabled" flags; the switches read the other way.
  // Chat off refuses files too, so the files controls follow it.
  let friendChatOn = $derived.by(() => {
    const current = settings;
    return current?.friend_chat_disabled !== true;
  });
  let friendFilesOn = $derived.by(() => {
    const current = settings;
    return friendChatOn && current?.friend_files_disabled !== true;
  });

  type WindowOnLaunch = 'remember' | 'maximized' | 'default';

  /** Launching maximized overrides the remembered window at startup
   *  (`window_state::for_launch`), so the two settings are one choice. */
  let windowOnLaunch = $derived.by((): WindowOnLaunch => {
    const current = settings;
    if (!current) return 'remember';
    if (current.launch_maximized) return 'maximized';
    return current.remember_window_position ? 'remember' : 'default';
  });

  function setWindowOnLaunch(choice: WindowOnLaunch) {
    if (!settings) return;
    settings.launch_maximized = choice === 'maximized';
    // Maximized leaves the remembered position alone: it is still where the
    // window goes when it is restored down.
    if (choice !== 'maximized') settings.remember_window_position = choice === 'remember';
  }

  /** Strips as you type, so the field can only ever hold a legal handle. A
   *  named function rather than an inline handler: inside the template the
   *  callback outlives the `{#if settings}` narrowing around it.
   *
   *  The box is one-way bound, and when the stripped text equals what is
   *  already stored Svelte has nothing to re-render, so the rejected
   *  characters would stay on screen — hence the direct write-back. */
  function setChannelUsername(input: HTMLInputElement) {
    if (!settings) return;
    const clean = sanitizeChannelUsernameInput(input.value);
    settings.channel_username = clean;
    if (input.value !== clean) input.value = clean;
  }

  /** Null for none, and for a code from a later build's longer list, which
   *  stays stored untouched until a language is picked here. */
  let channelLanguageValue = $derived.by((): ChannelLanguage | null => {
    const code = settings?.channel_language;
    return isChannelLanguage(code) ? code : null;
  });

  /** Offered while no language is set. The app language when one was chosen,
   *  then the system's, which is the better guess for anyone whose language
   *  Ember is not translated into. */
  const channelLanguageSuggestion = suggestedChannelLanguage([
    ...(hasExplicitLocale() ? [getLocale()] : []),
    ...(typeof navigator === 'undefined' ? [] : navigator.languages ?? [navigator.language]),
    getLocale(),
  ]);

  /** Saves at once, like every other picker on this page. */
  function setChannelLanguage(code: ChannelLanguage | null) {
    if (!settings) return;
    settings.channel_language = code ?? '';
  }

  /** The suggestion button goes away once a language is set, so focus moves
   *  to the picker rather than falling back to <body>. */
  async function applySuggestedChannelLanguage(code: ChannelLanguage) {
    setChannelLanguage(code);
    await tick();
    document.getElementById('channel-language')?.focus();
  }

  function handleRadioGroupKey(
    event: KeyboardEvent,
    values: string[],
    current: string,
    select: (value: string) => void,
    // Committing a language reloads the whole app, so for that group arrows
    // must only move focus. The cards are real <button>s, so Enter and Space
    // still commit natively via onclick.
    focusOnly = false,
  ) {
    let nextIndex: number;
    // Track the focused card rather than the selected value; with `focusOnly`
    // the selection doesn't move, so using it would make arrows bounce.
    const focusedValue = (event.currentTarget as HTMLElement).dataset.radioValue;
    const currentIndex = Math.max(0, values.indexOf(focusedValue ?? current));
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
    if (!focusOnly) select(next);
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

  // USS needs a non-zero upload cap. Applying Unlimited turns it off in the
  // same save (`validateSettings`); this covers a config that already pairs
  // the two on disk. Folded into the baseline, patching only this field: it
  // is a correction, not an edit, and saving it automatically would rewrite
  // the config of someone who only opened the page. The next save carries it.
  $effect(() => {
    const saved = savedSettings;
    if (settings && saved && saved.max_upload_speed === 0 && saved.uss_enabled && settings.uss_enabled) {
      settings.uss_enabled = false;
      untrack(() => {
        if (!originalSettings) return;
        try {
          const base = JSON.parse(originalSettings) as AppSettings;
          base.uss_enabled = false;
          originalSettings = JSON.stringify(base);
        } catch { /* malformed baseline; leave as-is */ }
      });
    }
  });
</script>

<div class="page-header sticky-header">
  <h2>{m.settings_title()}</h2>
  <div class="header-actions">
    {#if saveMessage}
      <span class="save-status" class:warning={saveIsWarning} role="status">{saveMessage}</span>
    {/if}
  </div>
  {#if restartReason}
    <!-- Stays until the restart, or until the change is undone: "Later" on
         the prompt must not leave a saved port silently not in force. -->
    <div class="restart-pending-banner" role="status">
      <span>{m.settings_restart_pending_banner({ reason: restartReason })}</span>
      <button type="button" class="action-btn primary" onclick={performRestart}>
        {m.settings_restart_now()}
      </button>
    </div>
  {/if}
</div>

{#snippet applyButton(fields: readonly ApplyField[], name: string, blocked = false)}
  {#if fieldsDirty(fields)}
    {@const error = applyErrorFor(fields)}
    <button
      type="button"
      class="action-btn primary field-apply"
      disabled={blocked}
      onclick={() => void applyFields(fields)}
      aria-label={m.settings_apply_field_aria({ name })}
    >{m.settings_apply()}</button>
    {#if error}
      <span class="field-apply-error" role="alert">{error}</span>
    {/if}
  {/if}
{/snippet}

<div class="page-content" bind:this={pageContentEl}>
  {#if loadError}
    <div class="empty-state">
      <p class="empty-title" role="alert">{loadError}</p>
      <button type="button" class="empty-action" onclick={() => { loadError = null; location.reload(); }}>{m.layout_retry()}</button>
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
        <div class="settings-filter">
          <input
            type="search"
            class="settings-filter-input"
            placeholder={m.settings_filter_placeholder()}
            aria-label={m.settings_filter_placeholder()}
            aria-keyshortcuts="Control+F /"
            bind:value={settingsFilter}
            bind:this={settingsFilterEl}
          />
        </div>
        <!-- The tablist is hidden while filtering, because results span every
             section and a tablist that claims one tab is selected would be
             describing something that is no longer on screen. This is also
             how the editors people are used to behave: filtering replaces the
             tree with results. -->
        {#if !filtering}
        <div class="settings-tablist" role="tablist" aria-orientation="vertical" aria-label={m.settings_nav_aria()}>
        {#each sections as section, sectionIndex}
          <button
            class="settings-nav-item"
            class:active={activeSection === section}
            role="tab"
            id={tabId(section)}
            aria-selected={activeSection === section}
            aria-controls={panelId(section)}
            tabindex={activeSection === section ? 0 : -1}
            onkeydown={(e) => onTabKeydown(e, sectionIndex)}
            onclick={() => selectSection(section)}
          >
            <span class="settings-nav-icon" aria-hidden="true">
              {#if section === 'general'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <line x1="3" y1="5.5" x2="17" y2="5.5"/>
                  <line x1="3" y1="10" x2="17" y2="10"/>
                  <line x1="3" y1="14.5" x2="17" y2="14.5"/>
                </svg>
              {:else if section === 'notifications'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M10 2.5a4.5 4.5 0 0 0-4.5 4.5c0 3.5-1.5 4.5-1.5 5.5h12c0-1-1.5-2-1.5-5.5A4.5 4.5 0 0 0 10 2.5z"/>
                  <path d="M8.25 15a1.75 1.75 0 0 0 3.5 0"/>
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
              {:else if section === 'channels'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <line x1="7.5" y1="3" x2="6" y2="17"/>
                  <line x1="14" y1="3" x2="12.5" y2="17"/>
                  <line x1="3" y1="7.5" x2="16.5" y2="7.5"/>
                  <line x1="2.5" y1="12.5" x2="16" y2="12.5"/>
                </svg>
              {:else if section === 'search'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="8.5" cy="8.5" r="5.5"/>
                  <line x1="12.5" y1="12.5" x2="17" y2="17"/>
                </svg>
              {:else if section === 'webservices'}
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="10" cy="10" r="7.5"/>
                  <line x1="2.5" y1="10" x2="17.5" y2="10"/>
                  <path d="M10 2.5c2.2 2 3.4 4.7 3.4 7.5s-1.2 5.5-3.4 7.5c-2.2-2-3.4-4.7-3.4-7.5S7.8 4.5 10 2.5z"/>
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
        </div>
        {:else}
          <p class="settings-filter-status" role="status">
            {plural(filterMatchCount, {
              one: m.settings_filter_one_result,
              other: () => m.settings_filter_results({ count: filterMatchCount }),
            })}
          </p>
          <button type="button" class="ghost settings-filter-clear" onclick={() => (settingsFilter = '')}>
            {m.common_clear_filters()}
          </button>
        {/if}
      </aside>

      <div class="cards-grid" class:filtering bind:this={cardsGridEl} onfocusin={noteFilterFocus}>

      <!-- General -->
      <!-- `role` and `aria-labelledby` only apply in tab mode: while filtering
           there is no tablist on screen, so a panel claiming to be controlled
           by a tab would be pointing at nothing. -->
      <section class="card" class:hidden={!filtering && activeSection !== 'general'} id={panelId('general')} role={filtering ? undefined : 'tabpanel'} aria-labelledby={filtering ? undefined : tabId('general')}>
        <div class="card-header">
          <span class="card-icon" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <line x1="3" y1="5.5" x2="17" y2="5.5"/>
              <line x1="3" y1="10" x2="17" y2="10"/>
              <line x1="3" y1="14.5" x2="17" y2="14.5"/>
            </svg>
          </span>
          <div>
            <h3>{m.settings_section_general()}</h3>
            <p class="card-desc">{m.settings_general_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_appearance()}</h4>
            <div class="field">
              <span class="field-label">{m.settings_theme_label()}</span>
              <div class="theme-picker">
                <button
                  type="button"
                  class="theme-swatch"
                  class:selected={$themeFollowsSystem}
                  onclick={followSystemTheme}
                  aria-label={m.settings_theme_system_aria()}
                  aria-pressed={$themeFollowsSystem}
                >
                  <div class="swatch-preview system-swatch">
                    <div class="swatch-half light-swatch">
                      <div class="swatch-sidebar"></div>
                      <div class="swatch-content">
                        <div class="swatch-line"></div>
                        <div class="swatch-line short"></div>
                      </div>
                    </div>
                    <div class="swatch-half dark-swatch">
                      <div class="swatch-content">
                        <div class="swatch-line"></div>
                        <div class="swatch-line short"></div>
                      </div>
                    </div>
                  </div>
                  {#if $themeFollowsSystem}<span class="swatch-check">&#10003;</span>{/if}
                  <span class="swatch-label">{m.settings_theme_system()}</span>
                </button>
              <button
                type="button"
                class="theme-swatch"
                class:selected={!$themeFollowsSystem && $theme === 'light'}
                onclick={() => setTheme('light')}
                aria-label={m.settings_theme_light_aria()}
                aria-pressed={!$themeFollowsSystem && $theme === 'light'}
              >
                  <div class="swatch-preview light-swatch">
                    <div class="swatch-sidebar"></div>
                    <div class="swatch-content">
                      <div class="swatch-line"></div>
                      <div class="swatch-line short"></div>
                    </div>
                  </div>
                  {#if !$themeFollowsSystem && $theme === 'light'}<span class="swatch-check">&#10003;</span>{/if}
                  <span class="swatch-label">{m.settings_theme_light()}</span>
                </button>
                <button
                  type="button"
                  class="theme-swatch"
                  class:selected={!$themeFollowsSystem && $theme === 'dark'}
                  onclick={() => setTheme('dark')}
                  aria-label={m.settings_theme_dark_aria()}
                  aria-pressed={!$themeFollowsSystem && $theme === 'dark'}
                >
                  <div class="swatch-preview dark-swatch">
                    <div class="swatch-sidebar"></div>
                    <div class="swatch-content">
                      <div class="swatch-line"></div>
                      <div class="swatch-line short"></div>
                    </div>
                  </div>
                  {#if !$themeFollowsSystem && $theme === 'dark'}<span class="swatch-check">&#10003;</span>{/if}
                  <span class="swatch-label">{m.settings_theme_dark()}</span>
                </button>
              </div>
            </div>
            <div class="field">
              <span class="field-label">{m.settings_language_label()}</span>
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
              <div class="behavior-picker lang-picker" role="radiogroup" aria-label={m.settings_language_label()}>
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
                      true,
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
                  <span class="lang-text">
                    <span class="behavior-title">{m.settings_language_system()}</span>
                    <span class="behavior-desc">{languageLabel(systemPreviewLocale)}</span>
                  </span>
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
                        true,
                      )}
                  >
                    {#if localeFlagSrc(loc)}
                      <span class="behavior-icon lang-flag-icon" aria-hidden="true">
                        <img class="lang-flag" src={localeFlagSrc(loc)} alt="" />
                      </span>
                    {/if}
                    <span class="lang-text">
                      <span class="behavior-title">{languageLabel(loc)}</span>
                      <span class="behavior-desc">{loc.toUpperCase()}</span>
                    </span>
                    {#if !followingSystem && currentLocale === loc}<span class="behavior-check" aria-hidden="true">&#10003;</span>{/if}
                  </button>
                {/each}
              </div>
              <span class="hint">{m.settings_language_description()}</span>
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_identity()}</h4>
            <div class="field">
              <label for="nickname">{m.settings_nickname_label()}</label>
              <div class="apply-input">
                <input
                  id="nickname"
                  value={settings.nickname}
                  maxlength="128"
                  oninput={clampNicknameInput}
                  oncompositionend={clampNicknameInput}
                  onkeydown={(e) => applyOnEnter(e, ['nickname'])}
                  placeholder={m.settings_nickname_placeholder()}
                />
                {@render applyButton(['nickname'], m.settings_nickname_label())}
              </div>
              <span class="hint">{m.settings_nickname_hint()}</span>
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="nickname-site-tag-label" for="nickname-site-tag-switch">{m.settings_nickname_site_tag()}</label>
                <span class="hint" id="nickname-site-tag-hint">
                  {m.settings_nickname_site_tag_hint({ name: ed2kNickname })}
                </span>
              </div>
              <ToggleSwitch
                id="nickname-site-tag-switch"
                bind:checked={settings.nickname_site_tag}
                ariaLabelledby="nickname-site-tag-label"
                ariaDescribedby="nickname-site-tag-hint"
              />
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_startup()}</h4>
            <div class="field">
              <label for="window-on-launch">{m.settings_window_on_launch_label()}</label>
              <select
                id="window-on-launch"
                value={windowOnLaunch}
                onchange={(e) => setWindowOnLaunch(e.currentTarget.value as WindowOnLaunch)}
              >
                <option value="remember">{m.settings_window_on_launch_remember()}</option>
                <option value="maximized">{m.settings_window_on_launch_maximized()}</option>
                <option value="default">{m.settings_window_on_launch_default()}</option>
              </select>
              <span class="hint">{m.settings_window_on_launch_hint()}</span>
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="launch-at-login-label" for="launch-at-login-switch">{m.settings_launch_at_login_label()}</label>
                <span class="hint" id="launch-at-login-hint">{m.settings_launch_at_login_hint()}</span>
              </div>
              <ToggleSwitch
                id="launch-at-login-switch"
                bind:checked={settings.launch_at_login}
                ariaLabelledby="launch-at-login-label"
                ariaDescribedby="launch-at-login-hint"
              />
            </div>
            <div class="field toggle-row nested" class:is-disabled={!settings.launch_at_login}>
              <div class="toggle-info">
                <label class="toggle-title" id="start-hidden-label" for="start-hidden-switch">{m.settings_start_hidden_at_login_label()}</label>
                <span class="hint" id="start-hidden-hint">{m.settings_start_hidden_at_login_hint()}</span>
              </div>
              <ToggleSwitch
                id="start-hidden-switch"
                bind:checked={settings.start_hidden_at_login}
                disabled={!settings.launch_at_login}
                ariaLabelledby="start-hidden-label"
                ariaDescribedby="start-hidden-hint"
              />
            </div>
            <div class="field">
              <span class="field-label">{m.settings_close_behavior_label()}</span>
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
              <span class="hint">{m.settings_close_behavior_hint()}</span>
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="minimize-to-tray-label" for="minimize-to-tray-switch">{m.settings_minimize_to_tray_label()}</label>
                <span class="hint" id="minimize-to-tray-hint">{m.settings_minimize_to_tray_hint()}</span>
              </div>
              <ToggleSwitch
                id="minimize-to-tray-switch"
                bind:checked={settings.minimize_to_tray}
                ariaLabelledby="minimize-to-tray-label"
                ariaDescribedby="minimize-to-tray-hint"
              />
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_power()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="prevent-sleep-label" for="prevent-sleep-switch">{m.settings_prevent_sleep_label()}</label>
                <span class="hint" id="prevent-sleep-hint">
                  {#if runtimeStatus && !runtimeStatus.sleep_inhibit_supported}
                    {m.settings_prevent_sleep_unsupported()}
                  {:else}
                    {m.settings_prevent_sleep_hint()}
                  {/if}
                </span>
                {#if runtimeStatus?.sleep_inhibit_held}
                  <span class="live-badge">{m.settings_prevent_sleep_active()}</span>
                {/if}
              </div>
              <ToggleSwitch
                id="prevent-sleep-switch"
                bind:checked={settings.prevent_sleep_while_active}
                disabled={!!runtimeStatus && !runtimeStatus.sleep_inhibit_supported}
                ariaLabelledby="prevent-sleep-label"
                ariaDescribedby="prevent-sleep-hint"
              />
            </div>
          </div>
        </div>
      </section>

      <!-- Notifications -->
      <section class="card" class:hidden={!filtering && activeSection !== 'notifications'} id={panelId('notifications')} role={filtering ? undefined : 'tabpanel'} aria-labelledby={filtering ? undefined : tabId('notifications')}>
        <div class="card-header">
          <span class="card-icon" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10 2.5a4.5 4.5 0 0 0-4.5 4.5c0 3.5-1.5 4.5-1.5 5.5h12c0-1-1.5-2-1.5-5.5A4.5 4.5 0 0 0 10 2.5z"/>
              <path d="M8.25 15a1.75 1.75 0 0 0 3.5 0"/>
            </svg>
          </span>
          <div>
            <h3>{m.settings_section_notifications()}</h3>
            <p class="card-desc">{m.settings_notifications_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_delivery()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="notifications-enabled-label" for="notifications-enabled-switch">{m.settings_notifications_enabled_label()}</label>
                <span class="hint" id="notifications-enabled-hint">{m.settings_notifications_enabled_hint()}</span>
              </div>
              <ToggleSwitch
                id="notifications-enabled-switch"
                bind:checked={settings.notifications_enabled}
                ariaLabelledby="notifications-enabled-label"
                ariaDescribedby="notifications-enabled-hint"
              />
            </div>
            <div class="field toggle-row nested" class:is-disabled={notifyOff}>
              <div class="toggle-info">
                <label class="toggle-title" id="notifications-unfocused-label" for="notifications-unfocused-switch">{m.settings_notifications_unfocused_label()}</label>
                <span class="hint" id="notifications-unfocused-hint">{m.settings_notifications_unfocused_hint()}</span>
              </div>
              <ToggleSwitch
                id="notifications-unfocused-switch"
                bind:checked={settings.notifications_only_when_unfocused}
                disabled={notifyOff}
                ariaLabelledby="notifications-unfocused-label"
                ariaDescribedby="notifications-unfocused-hint"
              />
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_notifications_events_label()}</h4>
            <div class="field toggle-row" class:is-disabled={notifyOff}>
              <div class="toggle-info">
                <label class="toggle-title" id="notify-download-complete-label" for="notify-download-complete-switch">{m.settings_notify_download_complete()}</label>
              </div>
              <ToggleSwitch
                id="notify-download-complete-switch"
                bind:checked={settings.notify_download_complete}
                disabled={notifyOff}
                ariaLabelledby="notify-download-complete-label"
              />
            </div>
            <div class="field toggle-row" class:is-disabled={notifyOff}>
              <div class="toggle-info">
                <label class="toggle-title" id="notify-download-failed-label" for="notify-download-failed-switch">{m.settings_notify_download_failed()}</label>
              </div>
              <ToggleSwitch
                id="notify-download-failed-switch"
                bind:checked={settings.notify_download_failed}
                disabled={notifyOff}
                ariaLabelledby="notify-download-failed-label"
              />
            </div>
            <div class="field toggle-row" class:is-disabled={notifyOff}>
              <div class="toggle-info">
                <label class="toggle-title" id="notify-friend-online-label" for="notify-friend-online-switch">{m.settings_notify_friend_online()}</label>
              </div>
              <ToggleSwitch
                id="notify-friend-online-switch"
                bind:checked={settings.notify_friend_online}
                disabled={notifyOff}
                ariaLabelledby="notify-friend-online-label"
              />
            </div>
            <div class="field toggle-row" class:is-disabled={notifyOff}>
              <div class="toggle-info">
                <label class="toggle-title" id="notify-friend-message-label" for="notify-friend-message-switch">{m.settings_notify_friend_message()}</label>
                <span class="hint" id="notify-friend-message-hint">{m.settings_notify_friend_message_hint()}</span>
              </div>
              <ToggleSwitch
                id="notify-friend-message-switch"
                bind:checked={settings.notify_friend_message}
                disabled={notifyOff}
                ariaLabelledby="notify-friend-message-label"
                ariaDescribedby="notify-friend-message-hint"
              />
            </div>
            <div class="field toggle-row" class:is-disabled={notifyOff}>
              <div class="toggle-info">
                <label class="toggle-title" id="notify-friend-request-label" for="notify-friend-request-switch">{m.settings_notify_friend_request()}</label>
              </div>
              <ToggleSwitch
                id="notify-friend-request-switch"
                bind:checked={settings.notify_friend_request}
                disabled={notifyOff}
                ariaLabelledby="notify-friend-request-label"
              />
            </div>
            <div class="field toggle-row" class:is-disabled={notifyOff}>
              <div class="toggle-info">
                <label class="toggle-title" id="notify-shares-browsed-label" for="notify-shares-browsed-switch">{m.settings_notify_shares_browsed()}</label>
                <span class="hint" id="notify-shares-browsed-hint">{m.settings_notify_shares_browsed_hint()}</span>
              </div>
              <ToggleSwitch
                id="notify-shares-browsed-switch"
                bind:checked={settings.notify_shares_browsed}
                disabled={notifyOff}
                ariaLabelledby="notify-shares-browsed-label"
                ariaDescribedby="notify-shares-browsed-hint"
              />
            </div>
            <div class="field toggle-row" class:is-disabled={notifyOff}>
              <div class="toggle-info">
                <label class="toggle-title" id="notify-channel-message-label" for="notify-channel-message-switch">{m.settings_notify_channel_message()}</label>
                <span class="hint" id="notify-channel-message-hint">
                  {m.settings_notify_channel_message_hint()}
                  <button type="button" class="link-btn" onclick={() => selectSection('channels')}>
                    {m.settings_notify_channel_manage()}
                  </button>
                </span>
              </div>
              <ToggleSwitch
                id="notify-channel-message-switch"
                bind:checked={settings.notify_channel_message}
                disabled={notifyOff}
                ariaLabelledby="notify-channel-message-label"
                ariaDescribedby="notify-channel-message-hint"
              />
            </div>
          </div>
        </div>
      </section>

      <!-- Transfers -->
      <section class="card" class:hidden={!filtering && activeSection !== 'downloads'} id={panelId('downloads')} role={filtering ? undefined : 'tabpanel'} aria-labelledby={filtering ? undefined : tabId('downloads')}>
        <div class="card-header">
          <span class="card-icon" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <line x1="10" y1="3" x2="10" y2="13"/>
              <polyline points="6,9.5 10,13.5 14,9.5"/>
              <line x1="4" y1="17" x2="16" y2="17"/>
            </svg>
          </span>
          <div>
            <h3>{m.settings_section_downloads()}</h3>
            <p class="card-desc">{m.settings_downloads_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <!-- Every section is built from these groups. Each is a container
               rather than a heading followed by loose siblings, so the filter
               can decide a group's visibility with the same rule it uses for
               everything else: show it if it still holds a visible field.
               Deciding it by walking forward from a heading to the next
               heading is what it did first, and that missed the fields nested
               inside a `.field-row`. -->
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_destination()}</h4>
            <div class="field">
              <label for="download-folder">{m.settings_download_folder_label()}</label>
              <div class="folder-input">
                <input id="download-folder" value={settings.download_folder} readonly />
                <button class="folder-btn" onclick={pickDownloadFolder}>{m.settings_browse()}</button>
              </div>
              <span class="hint">{folderLayoutHint(settings.download_folder)}</span>
            </div>
            <div class="field">
              <span class="field-label">{m.settings_category_folders_label()}</span>
              <div class="category-manage">
                <button type="button" class="secondary" onclick={() => (categoriesOpen = true)}>
                  {m.settings_category_folders_manage()}
                </button>
              </div>
              <span class="hint">{m.settings_category_folders_hint()}</span>
            </div>
            <div class="field">
              <label for="low-disk-warning">{m.settings_low_disk_label()}</label>
              <select id="low-disk-warning" bind:value={settings.low_disk_warning_mb}>
                <option value={0}>{m.settings_low_disk_off()}</option>
                {#each LOW_DISK_CHOICES_MB as mb (mb)}
                  <option value={mb}>{formatSize(mb * 1024 * 1024)}</option>
                {/each}
                {#if settings.low_disk_warning_mb !== 0 && !LOW_DISK_CHOICES_MB.includes(settings.low_disk_warning_mb)}
                  <option value={settings.low_disk_warning_mb}>{formatSize(settings.low_disk_warning_mb * 1024 * 1024)}</option>
                {/if}
              </select>
              <span class="hint">{m.settings_low_disk_hint()}</span>
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_limits()}</h4>
            <div class="field-row">
              <div class="field half">
                <label for="max-concurrent">{m.settings_max_downloads()}</label>
                <div class="apply-input">
                  <input id="max-concurrent" type="number" min="1" max="50" bind:value={settings.max_concurrent_downloads} onkeydown={(e) => applyOnEnter(e, ['max_concurrent_downloads'])} />
                  {@render applyButton(['max_concurrent_downloads'], m.settings_max_downloads())}
                </div>
                <!-- The only two numeric inputs on the page that had no hint,
                     and the pair most in need of one: "Max Uploads" counts
                     slots, which is easy to read as a speed when the actual
                     speed limits live in a different section entirely. -->
                <span class="hint">{m.settings_max_downloads_hint()}</span>
              </div>
              <div class="field half">
                <label for="max-uploads">{m.settings_max_uploads()}</label>
                <div class="apply-input">
                  <span class="auto-switch">
                    <ToggleSwitch
                      checked={settings.max_concurrent_uploads === 0}
                      label={m.settings_max_uploads_auto()}
                      onchange={setMaxUploadsAuto}
                    />
                  </span>
                  <!-- The box stays put and just dims while Auto is on, so
                       toggling never shifts the layout. Apply is only offered
                       for edits to a fixed number, not for the Auto switch
                       itself, which saves on its own. -->
                  <input
                    id="max-uploads"
                    type="number"
                    min="1"
                    max="50"
                    placeholder={m.settings_max_uploads_auto()}
                    disabled={settings.max_concurrent_uploads === 0}
                    value={settings.max_concurrent_uploads === 0 ? '' : settings.max_concurrent_uploads}
                    oninput={(e) => {
                      const box = e.currentTarget;
                      const n = box.valueAsNumber;
                      // 0 means Auto, which only the switch may set.
                      if (n < 1) box.value = '1';
                      settings!.max_concurrent_uploads = (Number.isNaN(n) ? null : Math.max(n, 1)) as number;
                    }}
                    onkeydown={(e) => applyOnEnter(e, ['max_concurrent_uploads'])}
                  />
                  {#if maxUploadsEditingNumber}
                    {@render applyButton(['max_concurrent_uploads'], m.settings_max_uploads())}
                  {/if}
                </div>
                <span class="hint">{m.settings_max_uploads_hint()}</span>
              </div>
            </div>

            <!-- eMule's `MaxSourcesPerFile` is a knob its users tune for rare
                 files, so it sits here beside the other limits. Applied live
                 on save to every download's source list and the source
                 cache; the backend floor is 50. -->
            <div class="field-row">
              <div class="field half">
                <label for="max-sources">{m.settings_max_sources_label()}</label>
                <div class="apply-input">
                  <input id="max-sources" type="number" min="50" max="2000" bind:value={settings.max_sources_per_file} onkeydown={(e) => applyOnEnter(e, ['max_sources_per_file'])} />
                  {@render applyButton(['max_sources_per_file'], m.settings_max_sources_label())}
                </div>
                <span class="hint">{m.settings_max_sources_hint()}</span>
              </div>
              <div class="field half">
                <label for="max-dl-gib">{m.settings_max_file_size_label()}</label>
                <div class="apply-input">
                  <input id="max-dl-gib" class="compact-number" type="number" min="1" max="593" bind:value={settings.max_download_file_size_gib} onkeydown={(e) => applyOnEnter(e, ['max_download_file_size_gib'])} />
                  {@render applyButton(['max_download_file_size_gib'], m.settings_max_file_size_label())}
                </div>
                <span class="hint">{m.settings_max_file_size_hint()}</span>
              </div>
            </div>
          </div>

          <!-- The remaining protocol budget / retry knobs (queue wait, retry
               rounds) stay in AppSettings for config.json and backend clamps,
               but are intentionally not exposed here. `max_sources_per_file`
               is above and `max_connections` is under Network, because eMule
               has always exposed both. -->

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_behavior()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="add-paused-label" for="add-paused-switch">{m.settings_add_paused()}</label>
                <span class="hint" id="add-paused-hint">{m.settings_add_paused_hint()}</span>
              </div>
              <ToggleSwitch
                id="add-paused-switch"
                bind:checked={settings.add_downloads_paused}
                ariaLabelledby="add-paused-label"
                ariaDescribedby="add-paused-hint"
              />
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="auto-remove-label" for="auto-remove-switch">{m.settings_auto_remove()}</label>
                <span class="hint" id="auto-remove-hint">{m.settings_auto_remove_hint()}</span>
              </div>
              <ToggleSwitch
                id="auto-remove-switch"
                bind:checked={settings.remove_finished_downloads}
                ariaLabelledby="auto-remove-label"
                ariaDescribedby="auto-remove-hint"
              />
            </div>
            <!-- Turning it on raises a native confirmation from the backend;
                 declining it leaves the save holding the Recycle Bin, which
                 the switch then shows again. -->
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="delete-permanently-label" for="delete-permanently-switch">{m.settings_delete_permanently()}</label>
                <span class="hint" id="delete-permanently-hint">{m.settings_delete_permanently_hint()}</span>
              </div>
              <ToggleSwitch
                id="delete-permanently-switch"
                bind:checked={settings.delete_permanently}
                ariaLabelledby="delete-permanently-label"
                ariaDescribedby="delete-permanently-hint"
              />
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="watch-clipboard-label" for="watch-clipboard-switch">{m.settings_watch_clipboard_label()}</label>
                <span class="hint" id="watch-clipboard-hint">{m.settings_watch_clipboard_hint()}</span>
              </div>
              <ToggleSwitch
                id="watch-clipboard-switch"
                bind:checked={settings.watch_clipboard_links}
                ariaLabelledby="watch-clipboard-label"
                ariaDescribedby="watch-clipboard-hint"
              />
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="web-sources-label" for="web-sources-switch">{m.settings_web_sources_label()}</label>
                <span class="hint" id="web-sources-hint">{m.settings_web_sources_hint()}</span>
              </div>
              <ToggleSwitch
                id="web-sources-switch"
                bind:checked={settings.web_sources_enabled}
                ariaLabelledby="web-sources-label"
                ariaDescribedby="web-sources-hint"
              />
            </div>
          </div>

          <!-- Shared folders are chosen in the Library, so this only points
               there; the switch is about what we send when uploading. -->
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_sharing()}</h4>
            <div class="field">
              <span class="field-label">{m.settings_shared_folders_label()}</span>
              <span class="hint">
                {m.settings_shared_folders_hint()}
                <a href="/library" onclick={(e) => { e.preventDefault(); void goto('/library'); }}>{m.settings_open_page({ page: m.nav_library() })}</a>
              </span>
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="skip-compress-video-label" for="skip-compress-video-switch">{m.settings_skip_compress_video()}</label>
                <span class="hint" id="skip-compress-video-hint">{m.settings_skip_compress_video_hint()}</span>
              </div>
              <ToggleSwitch
                id="skip-compress-video-switch"
                bind:checked={settings.skip_compress_video}
                ariaLabelledby="skip-compress-video-label"
                ariaDescribedby="skip-compress-video-hint"
              />
            </div>
          </div>

          <!-- Both automatic uses of the tag, under one explanation of what the
               tag is, so neither switch has to be understood on its own. -->
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_name_tag()}</h4>
            <p class="hint section-intro">{m.settings_name_tag_intro()}</p>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="tag-downloads-label" for="tag-downloads-switch">{m.settings_tag_downloads()}</label>
                <span class="hint" id="tag-downloads-hint">{m.settings_tag_downloads_hint()}</span>
              </div>
              <ToggleSwitch
                id="tag-downloads-switch"
                bind:checked={settings.tag_completed_downloads}
                ariaLabelledby="tag-downloads-label"
                ariaDescribedby="tag-downloads-hint"
              />
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="tag-imports-label" for="tag-imports-switch">{m.settings_tag_imports()}</label>
                <span class="hint" id="tag-imports-hint">{m.settings_tag_imports_hint()}</span>
              </div>
              <ToggleSwitch
                id="tag-imports-switch"
                bind:checked={settings.tag_shared_imports}
                ariaLabelledby="tag-imports-label"
                ariaDescribedby="tag-imports-hint"
              />
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_preview()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="preview-priority-all-label" for="preview-priority-all-switch">{m.settings_preview_priority_all()}</label>
                <span class="hint" id="preview-priority-all-hint">{m.settings_preview_priority_all_hint()}</span>
              </div>
              <ToggleSwitch
                id="preview-priority-all-switch"
                bind:checked={settings.preview_priority_all}
                ariaLabelledby="preview-priority-all-label"
                ariaDescribedby="preview-priority-all-hint"
              />
            </div>
            <div class="field">
              <label for="preview-player">{m.settings_preview_player_label()}</label>
              <div class="folder-input">
                <!-- Read-only for the same reason the download folder is: the
                     value has to come from the backend picker, and a typed
                     path would be refused on save anyway. -->
                <input id="preview-player" value={settings.preview_player} readonly placeholder={m.settings_preview_player_placeholder()} />
                <button class="folder-btn" onclick={pickPreviewPlayer}>{m.settings_browse()}</button>
                {#if settings.preview_player}
                  <button class="folder-btn" onclick={() => (settings && (settings.preview_player = ''))}>{m.common_clear()}</button>
                {/if}
              </div>
              <span class="hint">{m.settings_preview_player_hint()}</span>
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_history()}</h4>
            <div class="field">
              <span class="field-label">{m.settings_download_history()}</span>
              <div class="stat-grid">
                <div class="stat">
                  <span>{m.settings_history_stat_completed()}</span>
                  <strong class:is-loading={historyStatsLoading}>
                    {historyStatsLoading ? m.settings_history_stats_loading() : historyStatsError ? '—' : historyStats?.completed ?? 0}
                  </strong>
                </div>
                <div class="stat">
                  <span>{m.settings_history_stat_cancelled()}</span>
                  <strong class:is-loading={historyStatsLoading}>
                    {historyStatsLoading ? m.settings_history_stats_loading() : historyStatsError ? '—' : historyStats?.cancelled ?? 0}
                  </strong>
                </div>
                <div class="stat">
                  <span>{m.settings_history_stat_total()}</span>
                  <strong class:is-loading={historyStatsLoading}>
                    {historyStatsLoading ? m.settings_history_stats_loading() : historyStatsError ? '—' : historyStats?.total ?? 0}
                  </strong>
                </div>
              </div>
              <div class="action-row">
                <button class="action-btn danger" onclick={() => requestClearHistory('completed')}>{m.settings_clear_completed()}</button>
                <button class="action-btn danger" onclick={() => requestClearHistory('cancelled')}>{m.settings_clear_cancelled()}</button>
                <button class="action-btn danger" onclick={() => requestClearHistory('all')}>{m.settings_clear_all_history()}</button>
              </div>
              <span class="hint">{m.settings_download_history_hint()}</span>
              {#if historyStatsError}
                <span class="hint hint-error" role="alert">{historyStatsError}</span>
              {/if}
              {#if historyClearMsg}
                <span class="hint" role="status">{historyClearMsg}</span>
              {/if}
            </div>
          </div>
        </div>
      </section>

      <!-- Search -->
      <section class="card" class:hidden={!filtering && activeSection !== 'search'} id={panelId('search')} role={filtering ? undefined : 'tabpanel'} aria-labelledby={filtering ? undefined : tabId('search')}>
        <div class="card-header">
          <span class="card-icon" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="8.5" cy="8.5" r="5.5"/>
              <line x1="12.5" y1="12.5" x2="17" y2="17"/>
            </svg>
          </span>
          <div>
            <h3>{m.settings_section_search()}</h3>
            <p class="card-desc">{m.settings_search_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_spam_filter()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="spam-filter-label" for="spam-filter-switch">{m.settings_spam_filter()}</label>
                <span class="hint" id="spam-filter-hint">{m.settings_spam_filter_hint()}</span>
              </div>
              <ToggleSwitch
                id="spam-filter-switch"
                bind:checked={settings.spam_filter_enabled}
                ariaLabelledby="spam-filter-label"
                ariaDescribedby="spam-filter-hint"
              />
            </div>
            <div class="field nested" class:is-disabled={!settings.spam_filter_enabled}>
              <label for="spam-filter-profile">{m.settings_spam_profile_label()}</label>
              <select
                id="spam-filter-profile"
                bind:value={settings.spam_filter_profile}
                disabled={!settings.spam_filter_enabled}
              >
                <option value="relaxed">{m.settings_spam_profile_relaxed()}</option>
                <option value="balanced">{m.settings_spam_profile_balanced()}</option>
                <option value="aggressive">{m.settings_spam_profile_aggressive()}</option>
              </select>
              <span class="hint">{m.settings_spam_profile_hint()}</span>
            </div>
            <div class="field">
              <span class="field-label">{m.settings_spam_db_label()}</span>
              {#if spamStatsLoading}
                <span class="hint">{m.settings_spam_loading()}</span>
              {:else if spamStatsError}
                <span class="hint hint-error" role="alert">{spamStatsError}</span>
              {:else if spamStats}
                <div class="stat-grid">
                  <div class="stat"><span>{m.settings_spam_stat_hashes()}</span><strong>{spamStats.spam_hashes}</strong></div>
                  <div class="stat"><span>{m.settings_spam_stat_not_spam_hashes()}</span><strong>{spamStats.not_spam_hashes}</strong></div>
                  <div class="stat"><span>{m.settings_spam_stat_names()}</span><strong>{spamStats.spam_filenames}</strong></div>
                  <div class="stat"><span>{m.settings_spam_stat_source_ips()}</span><strong>{spamStats.spam_source_ips}</strong></div>
                </div>
              {/if}
              <div class="action-row">
                <button class="action-btn" onclick={refreshSpamStats} disabled={spamStatsLoading || spamResetting}>{m.settings_refresh_stats()}</button>
                <button class="action-btn danger" onclick={handleResetSpamData} disabled={spamResetting}>
                  {spamResetting ? m.settings_resetting() : m.settings_reset_spam_data()}
                </button>
              </div>
              <span class="hint">{m.settings_spam_db_hint()}</span>
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_results()}</h4>
            <div class="field">
              <label for="search-timeout-secs">{m.settings_search_timeout_label()}</label>
              <div class="apply-input">
                <input
                  id="search-timeout-secs"
                  class="compact-number"
                  type="number"
                  min="30"
                  max="600"
                  step="1"
                  bind:value={settings.search_timeout_secs}
                  onkeydown={(e) => applyOnEnter(e, ['search_timeout_secs'])}
                />
                {@render applyButton(['search_timeout_secs'], m.settings_search_timeout_label())}
              </div>
              <span class="hint">{m.settings_search_timeout_hint()}</span>
            </div>
            <div class="field">
              <label for="filename-cleanups">{m.settings_filename_cleanups_label()}</label>
              <div class="apply-input">
                <input id="filename-cleanups" type="text" bind:value={settings.filename_cleanups} onkeydown={(e) => applyOnEnter(e, ['filename_cleanups'])} placeholder={m.settings_filename_cleanups_placeholder()} />
                {@render applyButton(['filename_cleanups'], m.settings_filename_cleanups_label())}
              </div>
              <span class="hint">{m.settings_filename_cleanups_hint_prefix()} <code>{m.settings_filename_cleanups_placeholder()}</code>{m.settings_filename_cleanups_hint_suffix()}</span>
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="highlight-matches-label" for="highlight-matches-switch">{m.settings_highlight_matches()}</label>
                <span class="hint" id="highlight-matches-hint">{m.settings_highlight_matches_hint()}</span>
              </div>
              <ToggleSwitch
                id="highlight-matches-switch"
                checked={$highlightMatches}
                onchange={(on) => highlightMatches.set(on)}
                ariaLabelledby="highlight-matches-label"
                ariaDescribedby="highlight-matches-hint"
              />
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_history()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="save-search-history-label" for="save-search-history-switch">{m.settings_save_search_history()}</label>
                <span class="hint" id="save-search-history-hint">{m.settings_save_search_history_hint()}</span>
              </div>
              <ToggleSwitch
                id="save-search-history-switch"
                bind:checked={settings.save_search_history}
                ariaLabelledby="save-search-history-label"
                ariaDescribedby="save-search-history-hint"
              />
            </div>
          </div>
        </div>
      </section>

      <!-- Web services -->
      <!-- Its own section rather than a group inside Transfers: it is reached
           from a file's right-click menu in Search, Library and Transfers
           alike, and it is the only setting that sends a file's details to a
           third party, which is worth being able to find on its own. Next to
           Search because looking a file up is what it is for. -->
      <section class="card" class:hidden={!filtering && activeSection !== 'webservices'} id={panelId('webservices')} role={filtering ? undefined : 'tabpanel'} aria-labelledby={filtering ? undefined : tabId('webservices')}>
        <div class="card-header">
          <span class="card-icon" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="10" cy="10" r="7.5"/>
              <line x1="2.5" y1="10" x2="17.5" y2="10"/>
              <path d="M10 2.5c2.2 2 3.4 4.7 3.4 7.5s-1.2 5.5-3.4 7.5c-2.2-2-3.4-4.7-3.4-7.5S7.8 4.5 10 2.5z"/>
            </svg>
          </span>
          <div>
            <h3>{m.webservices_title()}</h3>
            <p class="card-desc">{m.settings_webservices_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_web_sites()}</h4>
            <div class="field">
              <!-- What it is and what using it discloses, ahead of the list
                   they describe. -->
              <span class="hint">{m.webservices_desc()} {m.webservices_privacy_note()}</span>
              {#if settings.web_services.length === 0}
                <span class="hint">{m.webservices_empty()}</span>
              {:else}
                <ul class="webservice-list">
                  {#each settings.web_services as service, index (service.url)}
                    <li class="webservice-row">
                      <div class="webservice-text">
                        <span class="webservice-name"><bdi dir="auto">{service.name}</bdi></span>
                        <span class="hint webservice-url" title={service.url}>{service.url}</span>
                      </div>
                      <button
                        class="action-btn ghost webservice-remove"
                        onclick={() => removeWebService(index)}
                        aria-label={m.settings_webservice_remove_aria({ name: service.name })}
                      >{m.webservices_remove()}</button>
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_web_add()}</h4>
            <div class="field">
              <div class="webservice-add">
                <label class="webservice-field">
                  <span class="hint">{m.webservices_name_label()}</span>
                  <input
                    type="text"
                    bind:value={newWebServiceName}
                    maxlength="64"
                    spellcheck="false"
                    placeholder={m.webservices_name_placeholder()}
                  />
                </label>
                <label class="webservice-field webservice-field-url">
                  <span class="hint">{m.webservices_url_label()}</span>
                  <input
                    type="text"
                    bind:value={newWebServiceUrl}
                    maxlength="512"
                    spellcheck="false"
                    placeholder={m.webservices_url_placeholder()}
                  />
                </label>
                <button class="action-btn" onclick={addWebService}>{m.webservices_add()}</button>
              </div>
              <span class="hint">{m.webservices_placeholders()}</span>
              <div class="action-row">
                {#if canAddExample}
                  <button class="action-btn ghost" onclick={addExampleWebService}>
                    {m.webservices_add_example()}
                  </button>
                {/if}
                <button class="action-btn ghost" onclick={handleImportWebServices}>
                  {m.webservices_import()}
                </button>
              </div>
              {#if webServiceMessage}
                <span class="feedback {webServiceMessage.kind === 'err' ? 'error' : 'success'}">
                  {webServiceMessage.text}
                </span>
              {/if}
            </div>
          </div>
        </div>
      </section>

      <!-- Bandwidth -->
      <section class="card" class:hidden={!filtering && activeSection !== 'bandwidth'} id={panelId('bandwidth')} role={filtering ? undefined : 'tabpanel'} aria-labelledby={filtering ? undefined : tabId('bandwidth')}>
        <div class="card-header">
          <span class="card-icon" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <line x1="7" y1="3" x2="7" y2="17"/>
              <polyline points="3.5,6.5 7,3 10.5,6.5"/>
              <line x1="13" y1="3" x2="13" y2="17"/>
              <polyline points="9.5,13.5 13,17 16.5,13.5"/>
            </svg>
          </span>
          <div>
            <h3>{m.settings_section_bandwidth()}</h3>
            <p class="card-desc">{m.settings_bandwidth_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <!-- Rendered under the alternative download limit while those limits
               are on, under the manual one otherwise. -->
          {#snippet downloadRatioCapNote()}
            {#if runtimeStatus?.download_ratio_cap}
              <span class="hint download-ratio-cap" role="status">
                {m.settings_download_ratio_cap_note({
                  limit: formatSpeed(runtimeStatus.download_ratio_cap.limit),
                  ratio: runtimeStatus.download_ratio_cap.ratio,
                  upload: formatSpeed(runtimeStatus.download_ratio_cap.upload_below),
                })}
              </span>
            {/if}
          {/snippet}
          {#if runtimeStatus?.schedule}
            <!-- Without this, a user whose overnight rule is open sees the
                 manual number in the field and a different speed everywhere
                 else, and concludes the limit is broken. -->
            <div class="schedule-active-banner" role="status">
              <span class="live-dot" aria-hidden="true"></span>
              <span>
                {m.schedule_active_banner({
                  name: runtimeStatus.schedule.label || m.schedule_unnamed_rule(),
                  until: minutesToTimeValue(runtimeStatus.schedule.end_minute),
                })}
              </span>
              <span class="schedule-active-limits">
                {m.schedule_active_limits({
                  up: runtimeStatus.effective_upload_speed === 0
                    ? m.schedule_unlimited()
                    : formatSpeed(runtimeStatus.effective_upload_speed),
                  down: runtimeStatus.effective_download_speed === 0
                    ? m.schedule_unlimited()
                    : formatSpeed(runtimeStatus.effective_download_speed),
                })}
              </span>
            </div>
          {:else if runtimeStatus?.alt_speed}
            <!-- Switched on from the tray or the status bar, the alternative
                 limits replace the fields below and the schedule, which
                 otherwise look as if they had stopped working. -->
            <div class="schedule-active-banner" role="status">
              <span class="live-dot" aria-hidden="true"></span>
              <span>{m.settings_alt_speed_active_banner()}</span>
              <span class="schedule-active-limits">
                {m.schedule_active_limits({
                  up: runtimeStatus.effective_upload_speed === 0
                    ? m.schedule_unlimited()
                    : formatSpeed(runtimeStatus.effective_upload_speed),
                  down: runtimeStatus.effective_download_speed === 0
                    ? m.schedule_unlimited()
                    : formatSpeed(runtimeStatus.effective_download_speed),
                })}
              </span>
            </div>
          {/if}
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_speed_limits()}</h4>
            <div class="field manual-speed-limit" class:is-inactive={settings.alt_speed_enabled}>
              <div class="apply-input">
                <div class="apply-grow">
                  <SpeedInput label={m.settings_max_upload_speed()} bind:value={settings.max_upload_speed} onenter={() => void applyFields(['max_upload_speed'])} />
                </div>
                {@render applyButton(['max_upload_speed'], m.settings_max_upload_speed())}
              </div>
              <span class="hint">{m.settings_max_upload_speed_hint()}</span>
            </div>
            <div class="field manual-speed-limit" class:is-inactive={settings.alt_speed_enabled}>
              <div class="apply-input">
                <div class="apply-grow">
                  <SpeedInput label={m.settings_max_download_speed()} bind:value={settings.max_download_speed} onenter={() => void applyFields(['max_download_speed'])} />
                </div>
                {@render applyButton(['max_download_speed'], m.settings_max_download_speed())}
              </div>
              <span class="hint">{m.settings_max_download_speed_hint()}</span>
              {#if !runtimeStatus?.alt_speed}
                {@render downloadRatioCapNote()}
              {/if}
            </div>
            <div class="field toggle-row" class:is-disabled={savedSettings?.max_upload_speed === 0}>
              <div class="toggle-info">
                <label class="toggle-title" id="uss-label" for="uss-switch">{m.settings_uss_label()}</label>
                <span class="hint" id="uss-hint">{m.settings_uss_hint()}</span>
              </div>
              <ToggleSwitch
                id="uss-switch"
                bind:checked={settings.uss_enabled}
                disabled={savedSettings?.max_upload_speed === 0}
                ariaLabelledby="uss-label"
                ariaDescribedby="uss-hint"
              />
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_alt_limits()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="alt-speed-label" for="alt-speed-switch">{m.settings_alt_speed_label()}</label>
                <span class="hint" id="alt-speed-hint">{m.settings_alt_speed_hint()}</span>
              </div>
              <ToggleSwitch
                id="alt-speed-switch"
                bind:checked={settings.alt_speed_enabled}
                ariaLabelledby="alt-speed-label"
                ariaDescribedby="alt-speed-hint"
              />
            </div>
            <!-- Editable while off, so the limits can be ready before they are
                 switched on from the tray; dimmed because they are not in force. -->
            <div class="field nested alt-speed-limits" class:is-inactive={!settings.alt_speed_enabled}>
              <div class="apply-input">
                <div class="apply-grow">
                  <SpeedInput label={m.settings_alt_max_upload_speed()} bind:value={settings.alt_max_upload_speed} idScope="alt" onenter={() => void applyFields(['alt_max_upload_speed'])} />
                </div>
                {@render applyButton(['alt_max_upload_speed'], m.settings_alt_max_upload_speed())}
              </div>
              <div class="apply-input">
                <div class="apply-grow">
                  <SpeedInput label={m.settings_alt_max_download_speed()} bind:value={settings.alt_max_download_speed} idScope="alt" onenter={() => void applyFields(['alt_max_download_speed'])} />
                </div>
                {@render applyButton(['alt_max_download_speed'], m.settings_alt_max_download_speed())}
              </div>
              {#if runtimeStatus?.alt_speed}
                {@render downloadRatioCapNote()}
              {/if}
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_schedule()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="schedule-label" for="schedule-switch">{m.settings_schedule_label()}</label>
                <span class="hint" id="schedule-hint">{m.settings_schedule_hint()}</span>
              </div>
              <ToggleSwitch
                id="schedule-switch"
                bind:checked={settings.bandwidth_schedule_enabled}
                ariaLabelledby="schedule-label"
                ariaDescribedby="schedule-hint"
              />
            </div>

            <!-- Hidden while the feature is off: the rules are not in force, and
                 a timetable nobody is using is a card of controls that do
                 nothing. They are kept, not discarded — flipping the toggle back
                 brings them straight back.

                 The exception is a rule the backend would refuse. `validate`
                 checks the list whether or not the feature is enabled, so such a
                 rule blocks Apply either way, and hiding it would leave Apply
                 blocked with nothing on screen to fix. Shown dimmed in that case:
                 still not in force, but reachable. -->
            {#if settings.bandwidth_schedule_enabled || scheduleHasError}
              <div class="field schedule-editor" class:is-inactive={!settings.bandwidth_schedule_enabled || settings.alt_speed_enabled}>
                {#if settings.bandwidth_schedule.length === 0}
                  <p class="schedule-empty">{m.schedule_empty()}</p>
                {:else}
                  <p class="hint">{m.schedule_order_hint()}</p>
                {/if}

                {#each settings.bandwidth_schedule as rule, index (rule.id)}
                  {@const problem = scheduleRuleError(rule)}
                  {@const isActive = settings.bandwidth_schedule_enabled && rule.id === activeScheduleRuleId}
                  <div class="schedule-rule" class:is-active={isActive} class:has-error={!!problem}>
                    <div class="schedule-rule-head">
                      <ToggleSwitch
                        bind:checked={rule.enabled}
                        ariaLabel={ruleControlLabel(m.schedule_rule_enabled_aria(), rule, index)}
                      />
                      <input
                        class="schedule-name"
                        type="text"
                        bind:value={rule.label}
                        maxlength={MAX_RULE_LABEL_CHARS}
                        placeholder={m.schedule_name_placeholder()}
                        aria-label={m.schedule_name_placeholder()}
                      />
                      {#if isActive}
                        <span class="live-badge">{m.schedule_active_now()}</span>
                      {/if}
                      <div class="schedule-rule-actions">
                        <button
                          type="button"
                          class="icon-btn"
                          onclick={() => moveScheduleRule(index, -1)}
                          disabled={index === 0}
                          aria-label={ruleControlLabel(m.schedule_move_up(), rule, index)}
                          title={m.schedule_move_up()}
                        >&#9650;</button>
                        <button
                          type="button"
                          class="icon-btn"
                          onclick={() => moveScheduleRule(index, 1)}
                          disabled={index === settings.bandwidth_schedule.length - 1}
                          aria-label={ruleControlLabel(m.schedule_move_down(), rule, index)}
                          title={m.schedule_move_down()}
                        >&#9660;</button>
                        <button
                          type="button"
                          class="icon-btn danger"
                          onclick={() => removeScheduleRule(rule.id)}
                          aria-label={ruleControlLabel(m.schedule_remove_rule(), rule, index)}
                          title={m.schedule_remove_rule()}
                        >&times;</button>
                      </div>
                    </div>

                    <div class="schedule-days" role="group" aria-label={ruleControlLabel(m.schedule_days_label(), rule, index)}>
                      {#each weekdayLabels as dayLabel, weekday (weekday)}
                        <button
                          type="button"
                          class="day-chip"
                          class:selected={hasDay(rule.days, weekday)}
                          aria-pressed={hasDay(rule.days, weekday)}
                          onclick={() => setRuleDays(rule.id, weekday)}
                        >{dayLabel}</button>
                      {/each}
                    </div>

                    <div class="schedule-times">
                      <label class="schedule-time">
                        <span>{m.schedule_from()}</span>
                        <input
                          type="time"
                          value={minutesToTimeValue(rule.start_minute)}
                          onchange={(e) => setRuleStart(rule.id, e.currentTarget)}
                        />
                      </label>
                      <label class="schedule-time">
                        <span>{m.schedule_to()}</span>
                        <input
                          type="time"
                          value={minutesToTimeValue(rule.end_minute)}
                          onchange={(e) => setRuleEnd(rule.id, e.currentTarget)}
                        />
                      </label>
                      {#if isOvernight(rule)}
                        <span class="schedule-overnight">{m.schedule_overnight()}</span>
                      {/if}
                    </div>

                    <div class="schedule-limits">
                      <!-- `idScope` keeps each rule's two fields from colliding
                           with every other rule's, and with the manual limits
                           above, which all share these labels. -->
                      <SpeedInput
                        label={m.settings_max_upload_speed()}
                        idScope={rule.id}
                        bind:value={rule.max_upload_speed}
                      />
                      <SpeedInput
                        label={m.settings_max_download_speed()}
                        idScope={rule.id}
                        bind:value={rule.max_download_speed}
                      />
                    </div>

                    {#if problem}
                      <span class="schedule-error">{problem}</span>
                    {/if}
                  </div>
                {/each}

                <div class="schedule-footer">
                  <button
                    type="button"
                    class="action-btn"
                    onclick={addScheduleRule}
                    disabled={settings.bandwidth_schedule.length >= MAX_SCHEDULE_RULES}
                  >
                    {settings.bandwidth_schedule.length >= MAX_SCHEDULE_RULES
                      ? m.schedule_add_full({ max: MAX_SCHEDULE_RULES })
                      : m.schedule_add_rule()}
                  </button>
                  <!-- The backend refuses the whole schedule for one malformed
                       rule, and the rejection names no rule. Blocking here
                       instead points at the row that is wrong, which is already
                       showing its own reason. -->
                  {@render applyButton(['bandwidth_schedule'], m.settings_schedule_label(), scheduleHasError)}
                </div>
              </div>
            {/if}
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_speed_test_label()}</h4>
            <div class="field">
              <div class="action-row">
                <button class="action-btn" onclick={runSpeedTest} disabled={speedTesting}>
                  {speedTesting ? m.settings_speed_testing() : m.settings_run_speed_test()}
                </button>
              </div>
              {#if speedResult}
                <div class="stat-grid speed-result-grid">
                  <div class="stat"><span>{m.settings_speed_download()}</span><strong>{formatSpeed(speedResult.download_speed)}</strong></div>
                  <div class="stat"><span>{m.settings_speed_upload()}</span><strong>{formatSpeed(speedResult.upload_speed)}</strong></div>
                  <div class="stat"><span>{m.settings_speed_recommended_upload()}</span><strong>{formatSpeed(speedResult.recommended_upload_limit)}</strong></div>
                  <div class="stat"><span>{m.settings_speed_recommended_download()}</span><strong>{formatSpeed(speedResult.recommended_download_limit)}</strong></div>
                </div>
                <div class="action-row">
                  <button class="action-btn primary" onclick={applyRecommended}>{m.settings_apply_recommended()}</button>
                </div>
              {/if}
              {#if speedError}
                <span class="feedback error" role="alert">{speedError}</span>
              {/if}
              <span class="hint">{m.settings_speed_test_hint()}</span>
            </div>
          </div>
        </div>
      </section>

      <!-- Network -->
      <section class="card" class:hidden={!filtering && activeSection !== 'network'} id={panelId('network')} role={filtering ? undefined : 'tabpanel'} aria-labelledby={filtering ? undefined : tabId('network')}>
        <div class="card-header">
          <span class="card-icon" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="10" cy="4" r="2"/>
              <circle cx="4" cy="15" r="2"/>
              <circle cx="16" cy="15" r="2"/>
              <line x1="10" y1="6" x2="5" y2="13"/>
              <line x1="10" y1="6" x2="15" y2="13"/>
              <line x1="6" y1="15" x2="14" y2="15"/>
            </svg>
          </span>
          <div>
            <h3>{m.settings_section_network()}</h3>
            <p class="card-desc">{m.settings_network_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="settings-group" id="connection-check">
            <h4 class="subsection-title">{m.doctor_title()}</h4>
            <ConnectionDoctor
              onMovePorts={() => {
                const field = document.getElementById('tcp-port') as HTMLInputElement | null;
                field?.scrollIntoView({ block: 'center' });
                field?.focus();
                field?.select();
              }}
              onEnableUpnp={() => {
                if (settings) settings.upnp_enabled = true;
              }}
            />
          </div>
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_ports()}</h4>
            <div class="field-row">
              <div class="field half">
                <!-- The badge is hidden from the label's accessible name, which
                     would otherwise read "TCP port Restart required", and
                     announced as the input's description instead. -->
                <label for="tcp-port">
                  {m.settings_tcp_port()}
                  <span class="restart-badge" class:pending={restartPending('tcp_port')} id="tcp-port-restart" aria-hidden="true">{m.settings_restart_badge()}</span>
                </label>
                <div class="apply-input">
                  <input id="tcp-port" type="number" min="1" max="65535" aria-describedby="tcp-port-restart" bind:value={settings.tcp_port} onkeydown={(e) => applyOnEnter(e, ['tcp_port'])} />
                  {@render applyButton(['tcp_port'], m.settings_tcp_port())}
                </div>
                <span class="hint">{m.settings_tcp_port_hint()}</span>
              </div>
              <div class="field half">
                <label for="udp-port">
                  {m.settings_udp_port()}
                  <span class="restart-badge" class:pending={restartPending('udp_port')} id="udp-port-restart" aria-hidden="true">{m.settings_restart_badge()}</span>
                </label>
                <div class="apply-input">
                  <input id="udp-port" type="number" min="1" max="65535" aria-describedby="udp-port-restart" bind:value={settings.udp_port} onkeydown={(e) => applyOnEnter(e, ['udp_port'])} />
                  {@render applyButton(['udp_port'], m.settings_udp_port())}
                </div>
                <span class="hint">{m.settings_udp_port_hint()}</span>
              </div>
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="upnp-label" for="upnp-switch">{m.settings_upnp_label()} <span class="restart-badge" class:pending={restartPending('upnp_enabled')} id="upnp-restart" aria-hidden="true">{m.settings_restart_badge()}</span></label>
                <span class="hint" id="upnp-hint">{m.settings_upnp_hint()}</span>
              </div>
              <ToggleSwitch
                id="upnp-switch"
                bind:checked={settings.upnp_enabled}
                ariaLabelledby="upnp-label"
                ariaDescribedby="upnp-restart upnp-hint"
              />
            </div>
            <div class="field">
              <PortTest />
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="stun-keepalive-label" for="stun-keepalive-switch">{m.settings_stun_keepalive_label()}</label>
                <span class="hint" id="stun-keepalive-hint">{m.settings_stun_keepalive_hint()}</span>
              </div>
              <ToggleSwitch
                id="stun-keepalive-switch"
                bind:checked={settings.stun_keepalive_enabled}
                ariaLabelledby="stun-keepalive-label"
                ariaDescribedby="stun-keepalive-hint"
              />
            </div>
          </div>

          <!-- eMule's Connection page keeps `maxconnections` and
               `MaxConnectionsPerFiveSeconds` in front of the user, and the
               first of the two decides how many peers can be waiting in your
               upload queue at all. Both are about what the router can take,
               which is why they sit with the ports. -->
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_connections()}</h4>
            <div class="field-row">
              <div class="field half">
                <label for="max-connections">{m.settings_max_connections()}</label>
                <div class="apply-input">
                  <input id="max-connections" type="number" min="1" max="2000" bind:value={settings.max_connections} onkeydown={(e) => applyOnEnter(e, ['max_connections'])} />
                  {@render applyButton(['max_connections'], m.settings_max_connections())}
                </div>
                <span class="hint">{m.settings_max_connections_hint()}</span>
              </div>
              <div class="field half">
                <label for="max-conn-per-five">{m.settings_max_conn_per_five()}</label>
                <div class="apply-input">
                  <input id="max-conn-per-five" type="number" min="0" max="500" bind:value={settings.max_connections_per_five_secs} onkeydown={(e) => applyOnEnter(e, ['max_connections_per_five_secs'])} />
                  {@render applyButton(['max_connections_per_five_secs'], m.settings_max_conn_per_five())}
                </div>
                <span class="hint">{m.settings_max_conn_per_five_hint()}</span>
              </div>
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_networks()}</h4>
            <!-- Neither network has a switch: Ember's DHT bootstraps from other
                 clients and Ember depends on KAD staying connected. One line
                 says so and points at their pages, rather than two rows that
                 look like settings and offer nothing. -->
            <div class="field">
              <span class="field-label">{m.settings_networks_label()}</span>
              <span class="hint">
                {m.settings_networks_hint()}
                <a href="/ember" onclick={(e) => { e.preventDefault(); void goto('/ember'); }}>{m.settings_open_page({ page: m.nav_ember_network() })}</a>
                ·
                <a href="/kad" onclick={(e) => { e.preventDefault(); void goto('/kad'); }}>{m.settings_open_page({ page: m.nav_kad_network() })}</a>
              </span>
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
                <label class="toggle-title" id="relay-for-peers-label" for="relay-for-peers-switch">{m.settings_relay_for_peers_label()}</label>
                <span class="hint" id="relay-for-peers-hint">{m.settings_relay_for_peers_hint()}</span>
              </div>
              <ToggleSwitch
                id="relay-for-peers-switch"
                bind:checked={settings.relay_for_peers}
                ariaLabelledby="relay-for-peers-label"
                ariaDescribedby="relay-for-peers-hint"
              />
            </div>
          </div>

          <!--
            eD2K server-list discovery, after eMule's Options -> Servers.
            New-server admission from server lists is read live once saved;
            purging already-listed servers when "filter servers by IP" turns
            on also runs on save (and at startup / IP-filter reload). eMule's
            third option, servers learned from clients, has no switch here:
            nothing in the backend adds servers from clients, so a toggle for
            it would only claim to do something.
          -->
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_ed2k_servers()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="auto-connect-server-label" for="auto-connect-server-switch">{m.settings_auto_connect_server()}</label>
                <span class="hint" id="auto-connect-server-hint">{m.settings_auto_connect_server_hint()}</span>
              </div>
              <ToggleSwitch
                id="auto-connect-server-switch"
                bind:checked={settings.auto_connect_server}
                ariaLabelledby="auto-connect-server-label"
                ariaDescribedby="auto-connect-server-hint"
              />
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" for="update-servers-switch">{m.settings_update_servers_label()}</label>
                <span class="hint" id="update-servers-hint">{m.settings_update_servers_hint()}</span>
              </div>
              <ToggleSwitch
                id="update-servers-switch"
                bind:checked={settings.add_servers_from_server}
                ariaLabel={m.settings_update_servers_aria()}
                ariaDescribedby="update-servers-hint"
              />
            </div>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="filter-servers-label" for="filter-servers-switch">{m.settings_filter_servers_label()}</label>
                <span class="hint" id="filter-servers-hint">{m.settings_filter_servers_hint()}</span>
              </div>
              <ToggleSwitch
                id="filter-servers-switch"
                bind:checked={settings.filter_servers_by_ip}
                ariaLabelledby="filter-servers-label"
                ariaDescribedby="filter-servers-hint"
              />
            </div>
          </div>
        </div>
      </section>

      <!-- Security -->
      <section class="card" class:hidden={!filtering && activeSection !== 'security'} id={panelId('security')} role={filtering ? undefined : 'tabpanel'} aria-labelledby={filtering ? undefined : tabId('security')}>
        <div class="card-header">
          <span class="card-icon" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10 2L3 6v4c0 4.4 3 8.5 7 10 4-1.5 7-5.6 7-10V6l-7-4z"/>
              <polyline points="7,10 9.5,12.5 13.5,7.5"/>
            </svg>
          </span>
          <div>
            <h3>{m.settings_section_security()}</h3>
            <p class="card-desc">{m.settings_security_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          {#if $networkStats.secident_status === 'broken'}
            <div class="field">
              <span class="feedback error" role="alert">{m.secident_key_unreadable()}</span>
            </div>
          {/if}
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_traffic()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="obfuscation-label" for="obfuscation-switch">{m.settings_obfuscation_label()}</label>
                <span class="hint" id="obfuscation-hint">{m.settings_obfuscation_hint()}</span>
              </div>
              <ToggleSwitch
                id="obfuscation-switch"
                bind:checked={settings.obfuscation_enabled}
                ariaLabelledby="obfuscation-label"
                ariaDescribedby="obfuscation-hint"
              />
            </div>
          </div>

          <!-- The list itself — downloading, importing, editing ranges — lives
               on the Security page; these are the switches that decide how it
               is used, and they apply at once like the ones there. -->
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_blocking()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="ip-filter-label" for="ip-filter-switch">{m.settings_ip_filter_label()}</label>
                <span class="hint" id="ip-filter-hint">
                  {m.settings_ip_filter_hint()}
                  <a href="/security" onclick={(e) => { e.preventDefault(); void goto('/security'); }}>{m.settings_open_page({ page: m.nav_security() })}</a>
                </span>
              </div>
              <ToggleSwitch
                id="ip-filter-switch"
                bind:checked={settings.ip_filter_enabled}
                ariaLabelledby="ip-filter-label"
                ariaDescribedby="ip-filter-hint"
                onchange={(v) => applyIpToggleLive('ip_filter_enabled', v)}
              />
            </div>
            <div class="field toggle-row nested" class:is-disabled={!settings.ip_filter_enabled}>
              <div class="toggle-info">
                <label class="toggle-title" id="ip-filter-auto-update-label" for="ip-filter-auto-update-switch">{m.settings_ip_filter_auto_update_label()}</label>
                <span class="hint" id="ip-filter-auto-update-hint">{m.security_auto_update_title()}</span>
              </div>
              <ToggleSwitch
                id="ip-filter-auto-update-switch"
                bind:checked={settings.ip_filter_auto_update}
                disabled={!settings.ip_filter_enabled}
                ariaLabelledby="ip-filter-auto-update-label"
                ariaDescribedby="ip-filter-auto-update-hint"
                onchange={(v) => applyIpToggleLive('ip_filter_auto_update', v)}
              />
            </div>

            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="filter-incoming-label" for="filter-incoming-switch">{m.settings_filter_incoming_label()}</label>
                <span class="hint" id="filter-incoming-hint">{m.settings_filter_incoming_hint()}</span>
              </div>
              <ToggleSwitch
                id="filter-incoming-switch"
                bind:checked={settings.filter_incoming_connections}
                ariaLabelledby="filter-incoming-label"
                ariaDescribedby="filter-incoming-hint"
              />
            </div>

            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="block-private-label" for="block-private-switch">{m.settings_block_private_label()}</label>
                <span class="hint" id="block-private-hint">{m.settings_block_private_hint()}</span>
              </div>
              <ToggleSwitch
                id="block-private-switch"
                bind:checked={settings.block_private_ips}
                ariaLabelledby="block-private-label"
                ariaDescribedby="block-private-hint"
                onchange={(v) => applyIpToggleLive('block_private_ips', v)}
              />
            </div>

            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="antileech-label" for="antileech-switch">{m.settings_antileech_label()}</label>
                <span class="hint" id="antileech-hint">{m.settings_antileech_hint()}</span>
              </div>
              <ToggleSwitch
                id="antileech-switch"
                bind:checked={settings.antileech_enabled}
                ariaLabelledby="antileech-label"
                ariaDescribedby="antileech-hint"
              />
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
                  <!-- Named by the switch above it; the format note is its
                       description, under the box like every other hint. -->
                  <textarea
                    id="antileech-textarea"
                    class="antileech-textarea"
                    bind:value={antileechDraft}
                    rows="8"
                    spellcheck="false"
                    aria-label={m.settings_antileech_label()}
                    aria-describedby="antileech-patterns-hint"
                    placeholder={m.settings_antileech_placeholder()}
                  ></textarea>
                  <div class="action-row">
                    <button class="action-btn primary" onclick={handleSaveAntileech} disabled={antileechSaving}>
                      {antileechSaving ? m.settings_saving() : m.settings_antileech_save_btn()}
                    </button>
                    <button class="action-btn ghost" onclick={handleResetAntileech} disabled={antileechSaving}>
                      {m.settings_antileech_restore_btn()}
                    </button>
                  </div>
                  <span id="antileech-patterns-hint" class="hint">
                    {m.settings_antileech_patterns_prefix()} <code>#</code> {m.settings_antileech_patterns_suffix()}
                  </span>
                  {#if antileechSnapshot}
                    <span class="hint antileech-path" title={antileechSnapshot.file_path}>
                      {m.settings_antileech_file_label({ path: antileechSnapshot.file_path })}
                    </span>
                  {/if}
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

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_visibility()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="allow-shared-browse-label" for="allow-shared-browse-switch">{m.settings_allow_shared_browse_label()}</label>
                <span class="hint" id="allow-shared-browse-hint">{m.settings_allow_shared_browse_hint()}</span>
              </div>
              <ToggleSwitch
                id="allow-shared-browse-switch"
                bind:checked={settings.allow_shared_files_browse}
                ariaLabelledby="allow-shared-browse-label"
                ariaDescribedby="allow-shared-browse-hint"
              />
            </div>
          </div>
        </div>
      </section>

      <!-- Friends -->
      <section class="card" class:hidden={!filtering && activeSection !== 'friends'} id={panelId('friends')} role={filtering ? undefined : 'tabpanel'} aria-labelledby={filtering ? undefined : tabId('friends')}>
        <div class="card-header">
          <span class="card-icon" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="7" cy="6" r="3"/>
              <circle cx="14" cy="7" r="2.5"/>
              <path d="M1 17c0-3.3 2.7-6 6-6s6 2.7 6 6"/>
              <path d="M13 11.5c2.5 0 4.5 2 4.5 4.5"/>
            </svg>
          </span>
          <div>
            <h3>{m.settings_section_friends()}</h3>
            <p class="card-desc">{m.settings_friends_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <!-- What being a friend allows, and that each friend can differ.
               What a "Verified" request means is explained beside the requests
               themselves, on the Friends page. -->
          <p class="hint section-intro">{m.settings_friend_overrides_hint()}</p>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_status()}</h4>
            <div class="field" class:is-disabled={!$idleAwaySupported}>
              <label for="auto-away">{m.settings_auto_away_label()}</label>
              <select
                id="auto-away"
                bind:value={settings.auto_away_minutes}
                disabled={!$idleAwaySupported}
                aria-describedby="auto-away-hint"
              >
                <option value={0}>{m.settings_auto_away_off()}</option>
                {#each AUTO_AWAY_CHOICES as minutes (minutes)}
                  <option value={minutes}>{m.settings_auto_away_after({ count: minutes })}</option>
                {/each}
              </select>
              <span id="auto-away-hint" class="hint">
                {$idleAwaySupported ? m.settings_auto_away_hint() : m.settings_auto_away_unsupported()}
              </span>
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_chat()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="friend-chat-label" for="friend-chat-switch">{m.settings_friend_chat_label()}</label>
                <span class="hint" id="friend-chat-hint">{m.settings_friend_chat_hint()}</span>
              </div>
              <ToggleSwitch
                id="friend-chat-switch"
                checked={friendChatOn}
                onchange={(on) => { if (settings) settings.friend_chat_disabled = !on; }}
                ariaLabelledby="friend-chat-label"
                ariaDescribedby="friend-chat-hint"
              />
            </div>
            <div class="field toggle-row nested" class:is-disabled={!friendChatOn}>
              <div class="toggle-info">
                <label class="toggle-title" id="read-receipts-label" for="read-receipts-switch">{m.settings_friend_chat_read_receipts()}</label>
                <span class="hint" id="read-receipts-hint">{m.settings_friend_chat_read_receipts_hint()}</span>
              </div>
              <ToggleSwitch
                id="read-receipts-switch"
                bind:checked={settings.friend_chat_read_receipts}
                disabled={!friendChatOn}
                ariaLabelledby="read-receipts-label"
                ariaDescribedby="read-receipts-hint"
              />
            </div>
            <div class="field toggle-row nested" class:is-disabled={!friendChatOn}>
              <div class="toggle-info">
                <label class="toggle-title" id="chat-mailbox-label" for="chat-mailbox-switch">{m.settings_chat_mailbox_label()}</label>
                <span class="hint" id="chat-mailbox-hint">{m.settings_chat_mailbox_hint()}</span>
              </div>
              <ToggleSwitch
                id="chat-mailbox-switch"
                bind:checked={settings.chat_mailbox_enabled}
                disabled={!friendChatOn}
                ariaLabelledby="chat-mailbox-label"
                ariaDescribedby="chat-mailbox-hint"
              />
            </div>
            <div class="field nested" class:is-disabled={!friendChatOn}>
              <label for="chat-disappear">{m.settings_chat_disappear_label()}</label>
              <select
                id="chat-disappear"
                bind:value={settings.chat_disappear_secs}
                disabled={!friendChatOn}
                aria-describedby="chat-disappear-hint"
              >
                <option value={0}>{m.chat_disappear_off()}</option>
                {#each CHAT_DISAPPEAR_CHOICES as secs (secs)}
                  <option value={secs}>{disappearLabel(secs)}</option>
                {/each}
              </select>
              <span id="chat-disappear-hint" class="hint">{m.settings_chat_disappear_hint()}</span>
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_files()}</h4>
            <div class="field toggle-row" class:is-disabled={!friendChatOn}>
              <div class="toggle-info">
                <label class="toggle-title" id="friend-files-label" for="friend-files-switch">{m.settings_friend_files_label()}</label>
                <span class="hint" id="friend-files-hint">{m.settings_friend_files_hint()}</span>
              </div>
              <ToggleSwitch
                id="friend-files-switch"
                checked={friendFilesOn}
                disabled={!friendChatOn}
                onchange={(on) => { if (settings) settings.friend_files_disabled = !on; }}
                ariaLabelledby="friend-files-label"
                ariaDescribedby="friend-files-hint"
              />
            </div>
            <div class="field nested" class:is-disabled={!friendFilesOn}>
              <label for="chat-attach-auto">{m.settings_chat_attach_auto_label()}</label>
              <div class="chat-attach-row">
                <div class="apply-input">
                  <div class="unit-input">
                    <input
                      id="chat-attach-auto"
                      type="number"
                      min="0"
                      max="2048"
                      inputmode="numeric"
                      aria-describedby="chat-attach-auto-unit chat-attach-auto-hint"
                      disabled={!friendFilesOn}
                      bind:value={settings.chat_attachment_auto_accept_mb}
                      onkeydown={(e) => applyOnEnter(e, ['chat_attachment_auto_accept_mb'])}
                    />
                    <span id="chat-attach-auto-unit" class="unit-input-suffix">{m.settings_chat_attach_auto_unit()}</span>
                  </div>
                  {@render applyButton(['chat_attachment_auto_accept_mb'], m.settings_chat_attach_auto_label())}
                </div>
                <button type="button" class="action-btn chat-files-btn" onclick={() => void openChatFilesFolder().catch((e) => showSaveMsg(translateError(e), true, 6000))}>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M2.5 5.5a1.5 1.5 0 0 1 1.5-1.5h3.6l1.8 2H16a1.5 1.5 0 0 1 1.5 1.5v7A1.5 1.5 0 0 1 16 16H4a1.5 1.5 0 0 1-1.5-1.5z"/>
                  </svg>
                  {m.settings_chat_attach_open_folder()}
                </button>
              </div>
              <span id="chat-attach-auto-hint" class="hint">{m.settings_chat_attach_auto_hint()}</span>
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_sharing()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <label class="toggle-title" id="friend-browse-label" for="friend-browse-switch">{m.settings_friend_browse_label()}</label>
                <span class="hint" id="friend-browse-hint">{m.settings_friend_browse_hint()}</span>
              </div>
              <ToggleSwitch
                id="friend-browse-switch"
                checked={settings.friend_browse_disabled !== true}
                onchange={(on) => { if (settings) settings.friend_browse_disabled = !on; }}
                ariaLabelledby="friend-browse-label"
                ariaDescribedby="friend-browse-hint"
              />
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_limits()}</h4>
            <div class="field">
              <label for="max-friends">{m.settings_max_friends()}</label>
              <div class="apply-input">
                <input
                  id="max-friends"
                  class="compact-number"
                  type="number"
                  min="1"
                  max="500"
                  bind:value={settings.max_friends}
                  onkeydown={(e) => applyOnEnter(e, ['max_friends'])}
                />
                {@render applyButton(['max_friends'], m.settings_max_friends())}
              </div>
              <span class="hint">{m.settings_max_friends_hint()}</span>
            </div>
          </div>

          <!-- Friend session encryption stays forced on (see `saveFields`).
               Rendezvous URL remains in AppSettings
               for config.json only. Channel file offers live in the Channels
               section. -->
        </div>
      </section>

      <!-- Channels -->
      <section class="card" class:hidden={!filtering && activeSection !== 'channels'} id={panelId('channels')} role={filtering ? undefined : 'tabpanel'} aria-labelledby={filtering ? undefined : tabId('channels')}>
        <div class="card-header">
          <span class="card-icon" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <line x1="7.5" y1="3" x2="6" y2="17"/>
              <line x1="14" y1="3" x2="12.5" y2="17"/>
              <line x1="3" y1="7.5" x2="16.5" y2="7.5"/>
              <line x1="2.5" y1="12.5" x2="16" y2="12.5"/>
            </svg>
          </span>
          <div>
            <h3>{m.settings_section_channels()}</h3>
            <p class="card-desc">{m.settings_channels_desc()}</p>
          </div>
        </div>
        <div class="card-body">
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_identity()}</h4>
            <div class="field">
              <label for="channel_username">{m.settings_channel_username_label()}</label>
              <div class="apply-input">
                <input
                  id="channel_username"
                  value={settings.channel_username}
                  maxlength={CHANNEL_USERNAME_MAX}
                  spellcheck="false"
                  autocomplete="username"
                  autocapitalize="off"
                  placeholder={m.settings_channel_username_placeholder()}
                  oninput={(e) => setChannelUsername(e.currentTarget)}
                  onkeydown={(e) => applyOnEnter(e, ['channel_username'])}
                />
                {@render applyButton(['channel_username'], m.settings_channel_username_label())}
              </div>
              <span class="hint">{m.settings_channel_username_hint()}</span>
            </div>
            <div class="field">
              <label for="channel-language">{m.settings_channel_language_label()}</label>
              <div class="channel-language-row">
                <ChannelLanguagePicker
                  id="channel-language"
                  bind:value={() => channelLanguageValue, setChannelLanguage}
                  describedby="channel-language-hint"
                  noneLabel={m.settings_channel_language_none()}
                  noneAriaLabel={m.settings_channel_language_value({ language: m.settings_channel_language_none() })}
                  valueLabel={(language) => m.settings_channel_language_value({ language })}
                  listLabel={m.settings_channel_language_label()}
                />
                {#if !channelLanguageValue && channelLanguageSuggestion}
                  {@const suggestion = channelLanguageSuggestion}
                  <button
                    type="button"
                    class="action-btn channel-language-suggest"
                    onclick={() => applySuggestedChannelLanguage(suggestion)}
                  >
                    <img class="channel-language-suggest-flag" src={channelLanguageFlagSrc(suggestion)} alt="" />
                    {m.settings_channel_language_suggest({ language: channelLanguageName(suggestion) })}
                  </button>
                {/if}
              </div>
              <span class="hint" id="channel-language-hint">{m.settings_channel_language_hint()}</span>
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_files()}</h4>
            <div class="field">
              <label for="channel-file-offers">{m.settings_channel_file_offers()}</label>
              <div class="chat-attach-row channel-offers-row">
                <select
                  id="channel-file-offers"
                  bind:value={settings.channel_file_offers}
                >
                  <option value="everyone">{m.settings_channel_file_offers_everyone()}</option>
                  <option value="friends">{m.settings_channel_file_offers_friends()}</option>
                  <option value="nobody">{m.settings_channel_file_offers_nobody()}</option>
                </select>
                <button type="button" class="action-btn chat-files-btn" onclick={() => void openChannelFilesFolder().catch((e) => showSaveMsg(translateError(e), true, 6000))}>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M2.5 5.5a1.5 1.5 0 0 1 1.5-1.5h3.6l1.8 2H16a1.5 1.5 0 0 1 1.5 1.5v7A1.5 1.5 0 0 1 16 16H4a1.5 1.5 0 0 1-1.5-1.5z"/>
                  </svg>
                  {m.settings_channel_files_open_folder()}
                </button>
              </div>
              <span class="hint">{m.settings_channel_file_offers_hint()}</span>
            </div>
            <div class="field">
              <label for="room-dm-policy">{m.settings_room_dm_policy()}</label>
              <select id="room-dm-policy" bind:value={settings.room_dm_policy}>
                <option value="ask">{m.settings_room_dm_policy_ask()}</option>
                <option value="anyone">{m.settings_room_dm_policy_anyone()}</option>
                <option value="off">{m.settings_room_dm_policy_off()}</option>
              </select>
              <span class="hint">{m.settings_room_dm_policy_hint()}</span>
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_rooms()}</h4>
            <div class="field toggle-row">
              <div class="toggle-info">
                <span class="toggle-title">{m.settings_channels_recover()}</span>
                <span class="hint">{m.settings_channels_recover_hint()}</span>
              </div>
              <button
                type="button"
                class="action-btn"
                disabled={recoveringRooms}
                onclick={() => void findOwnedRooms()}
              >{recoveringRooms ? m.settings_channels_recovering() : m.settings_channels_recover_btn()}</button>
            </div>
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_this_device()}</h4>
            <!-- Silencing, ignoring and removing are per-device preferences kept
                 in localStorage, not room state, so nothing else in the app
                 lists them and this is the only place they can be undone.
                 All three are applied a row at a time somewhere else — from a
                 room's menu, or a member's — so all three are undoable a row at
                 a time here. Silenced and removed rooms used to be a bare count
                 with one bulk Clear, which meant reversing a single mistaken
                 mute cost the user every other one they had set. -->
            <div class="field ignored-field">
              <div class="toggle-row">
                <div class="toggle-info">
                  <span class="toggle-title">{m.settings_channels_muted_rooms()}</span>
                  <span class="hint">{m.settings_channels_muted_rooms_hint()}</span>
                </div>
                <div class="channels-pref-action">
                  <span class="channels-pref-count">{quietRooms.length}</span>
                  <button
                    type="button"
                    class="action-btn danger"
                    disabled={quietRooms.length === 0}
                    onclick={() => { mutedClearConfirmOpen = true; }}
                  >{m.settings_channels_clear()}</button>
                </div>
              </div>
              {#if quietRooms.length > 0}
                <ul class="ignored-list">
                  {#each quietRooms as [channelId, level] (channelId)}
                    <li>
                      <span class="ignored-name">
                        <bdi dir="auto">{channelLabel(channelId)}</bdi>
                        <span class="ignored-scope">{level === 'mentions'
                          ? m.channels_notify_mentions()
                          : m.channels_notify_none()}</span>
                      </span>
                      <button
                        type="button"
                        class="action-btn ghost"
                        onclick={() => setChannelNotifyLevel(channelId, 'all')}
                      >{m.channels_unmute()}</button>
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>

            <div class="field ignored-field">
              <div class="toggle-row">
                <div class="toggle-info">
                  <span class="toggle-title">{m.settings_channels_ignored_members()}</span>
                  <span class="hint">{m.settings_channels_ignored_members_hint()}</span>
                </div>
                <div class="channels-pref-action">
                  <span class="channels-pref-count">{$ignoredMembers.length}</span>
                  <button
                    type="button"
                    class="action-btn danger"
                    disabled={$ignoredMembers.length === 0}
                    onclick={() => { ignoredClearConfirmOpen = true; }}
                  >{m.settings_channels_clear()}</button>
                </div>
              </div>
              {#if $ignoredMembers.length > 0}
                <ul class="ignored-list">
                  {#each $ignoredMembers as entry (entry.pubkey)}
                    <li>
                      <span class="ignored-name">
                        <bdi dir="auto">{entry.name.trim() || shortPubkey(entry.pubkey)}</bdi>
                        <!-- Named rooms rather than a bare count: this list is
                             the only place a scope set inside a room the user
                             has since left can still be read or undone. -->
                        {#if entry.rooms}
                          <span class="ignored-scope">{m.settings_channels_ignored_in({
                            rooms: entry.rooms.map(channelLabel).join(', '),
                          })}</span>
                        {/if}
                      </span>
                      <button
                        type="button"
                        class="action-btn ghost"
                        onclick={() => toggleMemberIgnore(entry.pubkey)}
                      >{m.channels_unignore()}</button>
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>

            <div class="field ignored-field">
              <div class="toggle-row">
                <div class="toggle-info">
                  <span class="toggle-title">{m.settings_channels_hidden_rooms()}</span>
                  <span class="hint">{m.settings_channels_hidden_rooms_hint()}</span>
                </div>
                <div class="channels-pref-action">
                  <span class="channels-pref-count">{$hiddenChannels.length}</span>
                  <button
                    type="button"
                    class="action-btn danger"
                    disabled={$hiddenChannels.length === 0}
                    onclick={() => { hiddenClearConfirmOpen = true; }}
                  >{m.settings_channels_clear()}</button>
                </div>
              </div>
              {#if $hiddenChannels.length > 0}
                <ul class="ignored-list">
                  {#each $hiddenChannels as channelId (channelId)}
                    <li>
                      <span class="ignored-name">
                        <bdi dir="auto">{channelLabel(channelId)}</bdi>
                      </span>
                      <button
                        type="button"
                        class="action-btn ghost"
                        onclick={() => unhideChannel(channelId)}
                      >{m.channels_unignore()}</button>
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>
          </div>
        </div>
      </section>

      <!-- Backup & import -->
      <section class="card" class:hidden={!filtering && activeSection !== 'backup'} id={panelId('backup')} role={filtering ? undefined : 'tabpanel'} aria-labelledby={filtering ? undefined : tabId('backup')}>
        <div class="card-header">
          <span class="card-icon" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <rect x="2.5" y="4" width="15" height="4" rx="1"/>
              <path d="M4 8v7.5c0 .6.4 1 1 1h10c.6 0 1-.4 1-1V8"/>
              <line x1="8" y1="11.5" x2="12" y2="11.5"/>
            </svg>
          </span>
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
                  when: formatDateTime(pendingRestore.staged_at),
                })}
              </span>
              {#if pendingRestore.expires_at > 0}
                <span class="hint">
                  {m.settings_backup_pending_expires({
                    when: formatDateTime(pendingRestore.expires_at),
                  })}
                </span>
              {/if}
              <div class="action-row">
                <button class="action-btn primary" onclick={performRestart} disabled={backupBusy}>
                  {m.settings_restart_now()}
                </button>
                <button class="action-btn danger" onclick={handleDiscardPendingRestore} disabled={backupBusy}>
                  {m.settings_backup_pending_discard()}
                </button>
              </div>
            </div>
          {/if}

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_backup()}</h4>
            <div class="field">
              <span class="field-label">{m.settings_backup_contents_label()}</span>
              <span class="hint">{m.settings_backup_contents_hint()}</span>
              <span class="hint">{m.settings_backup_excludes_hint()}</span>
            </div>
            <div class="field">
              <label for="backup-passphrase">{m.settings_backup_passphrase_label()}</label>
              <input
                id="backup-passphrase"
                type="password"
                autocomplete="new-password"
                bind:value={backupPassphrase}
                placeholder={m.settings_backup_passphrase_placeholder()}
              />
              <span class="hint">{m.settings_backup_passphrase_hint()}</span>
            </div>
            <div class="field">
              <label for="backup-passphrase-confirm">{m.settings_backup_passphrase_confirm_label()}</label>
              <input
                id="backup-passphrase-confirm"
                type="password"
                autocomplete="new-password"
                bind:value={backupPassphraseConfirm}
              />
              <div class="action-row">
                <button
                  class="action-btn primary"
                  onclick={handleExportBackup}
                  disabled={backupBusy || backupPassphrase.length === 0}
                >{m.settings_backup_export()}</button>
              </div>
              <p class="backup-callout" role="note">
                <span class="backup-callout-icon" aria-hidden="true">!</span>
                <strong>{m.settings_backup_where_hint()}</strong>
              </p>
              <span class="hint">
                {lastBackupMs !== null
                  ? m.settings_backup_last({ when: formatDateTime(Math.floor(lastBackupMs / 1000)) })
                  : m.settings_backup_never()}
              </span>
            </div>
          </div>

          <!-- Hidden while a restore is staged: importing a second one is
               refused by the backend, so the banner's Restart / Discard pair
               is the only sensible next step. -->
          <div class="settings-group" class:hidden={pendingRestore?.pending}>
            <h4 class="subsection-title">{m.settings_backup_restore_label()}</h4>
            <div class="field">
              <div class="action-row">
                <button class="action-btn" onclick={handlePickBackupFile} disabled={backupBusy}>
                  {m.settings_backup_choose_file()}
                </button>
              </div>
              {#if restoreSource}
                <span class="hint backup-path" title={restoreSource}>{restoreSource}</span>
              {/if}
              <span class="hint">{m.settings_backup_restore_hint()}</span>
            </div>
            {#if restoreSource}
              <div class="field">
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
                    <button class="action-btn danger" onclick={handleImportBackup} disabled={backupBusy}>
                      {m.settings_backup_restore_now()}
                    </button>
                  {/if}
                  <button class="action-btn ghost" onclick={clearRestoreState} disabled={backupBusy}>
                    {m.common_cancel()}
                  </button>
                </div>
              </div>
            {/if}
            {#if restorePreview}
              <div class="field">
                <div class="stat-grid">
                  <div class="stat">
                    <span>{m.settings_backup_preview_created()}</span>
                    <strong>{formatDateTime(restorePreview.created_at)}</strong>
                  </div>
                  <div class="stat">
                    <span>{m.settings_backup_preview_version()}</span>
                    <strong>{restorePreview.app_version}</strong>
                  </div>
                  <div class="stat">
                    <span>{m.settings_backup_preview_files()}</span>
                    <strong>{restorePreview.files.length}</strong>
                  </div>
                  <div class="stat">
                    <span>{m.settings_backup_preview_size()}</span>
                    <strong>{formatSize(restorePreview.total_bytes)}</strong>
                  </div>
                  <div class="stat">
                    <span>{m.settings_backup_preview_identity()}</span>
                    <strong>{restorePreview.includes_identity ? m.common_yes() : m.common_no()}</strong>
                  </div>
                </div>
                {#if restorePreview.missing.length > 0}
                  <span class="hint">
                    {m.settings_backup_preview_missing({ files: restorePreview.missing.join(', ') })}
                  </span>
                {/if}
                {#if restorePreview.chat_key_set_aside}
                  <span class="hint">{m.settings_backup_preview_chat_key_set_aside()}</span>
                {/if}
                <span class="hint">{m.settings_backup_restore_warning()}</span>
              </div>
            {/if}
          </div>

          {#if backupMessage}
            <span
              class={backupMessageKind === 'progress' ? 'hint' : `feedback ${backupMessageKind}`}
              role={backupMessageKind === 'error' ? 'alert' : 'status'}
            >
              {backupMessage}
            </span>
          {/if}

          <!-- Joined Backup because both move a whole profile in. The scan of
               eMule's folder waits for the section to open (`importOpened`). -->
          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_import()}</h4>
            <div class="field">
              <span class="hint">{m.settings_import_desc()}</span>
              {#if importOpened}
                <EmuleImport mode="settings" onrestart={performRestart} />
              {:else}
                <span class="hint">{m.settings_import_hint()}</span>
              {/if}
            </div>
          </div>
        </div>
      </section>

      <!-- About & Updates -->
      <section class="card" class:hidden={!filtering && activeSection !== 'about'} id={panelId('about')} role={filtering ? undefined : 'tabpanel'} aria-labelledby={filtering ? undefined : tabId('about')}>
        <div class="card-header">
          <span class="card-icon" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="10" cy="10" r="7.5"/>
              <line x1="10" y1="9" x2="10" y2="14"/>
              <circle cx="10" cy="6.5" r="0.6" fill="currentColor"/>
            </svg>
          </span>
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
            <!-- One row per action, each with its own description beneath the
                 label. Laid out as rows rather than link-plus-inline-hint: the
                 two descriptions differ enough in length that side by side they
                 left a ragged column, and the log path had nowhere to sit but
                 loose under both of them. -->
            <div class="about-actions">
              <!-- The same links, in the same order, as the About dialog. -->
              <EmberLinks />
              <button type="button" class="about-action" onclick={() => void revealLogs()}>
                <span class="about-action-icon" aria-hidden="true">
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M2 4.5A1.5 1.5 0 0 1 3.5 3h3l1.5 2h4.5A1.5 1.5 0 0 1 14 6.5v5A1.5 1.5 0 0 1 12.5 13h-9A1.5 1.5 0 0 1 2 11.5z" />
                  </svg>
                </span>
                <span class="about-action-body">
                  <span class="about-action-title">{m.settings_about_logs_btn()}</span>
                  <span class="about-action-desc">{m.settings_about_logs_hint()}</span>
                  <!-- Inside the row it belongs to, and selectable: copying it
                       into a bug report is the reason it is on screen at all. -->
                  {#if logFolderPath}
                    <code class="about-action-path">{logFolderPath}</code>
                  {/if}
                  {#if logsOpenError}
                    <span class="feedback error" role="alert">{logsOpenError}</span>
                  {/if}
                </span>
                <span class="about-action-go" aria-hidden="true">
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M6 4l4 4-4 4" />
                  </svg>
                </span>
              </button>
            </div>
          </div>

          <div class="about-support">
            <span class="about-support-mark" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                <path d="M8.5 2.8c-.9 1-.9 2.2 0 3.2M12 2.8c-.9 1-.9 2.2 0 3.2" />
                <path d="M4 9.5h12v4.25A5.25 5.25 0 0 1 10.75 19h-1.5A5.25 5.25 0 0 1 4 13.75z" fill="currentColor" fill-opacity="0.18" />
                <path d="M16 11h1.25a2.75 2.75 0 0 1 0 5.5H15.4" />
                <path d="M3 21.5h14" />
              </svg>
            </span>
            <div class="about-support-copy">
              <p class="about-support-title">{m.support_title()}</p>
              <p class="about-support-text">{m.support_body()}</p>
            </div>
            <BuyCoffeeButton />
          </div>

          <div class="settings-group">
            <h4 class="subsection-title">{m.settings_group_updates()}</h4>

            <!-- A `.field`, so the filter can find the check and install
                 buttons by their text. -->
            <div class="field about-update-panel">
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
                {:else if $updater.phase === 'stalled' && $updater.installerReady}
                  <!-- Without this the phase was a dead end here: checking for
                       updates finds the same version, which deliberately keeps the
                       staged offer rather than re-downloading it, so this card
                       showed the generic hint and no way to act on it. -->
                  <button class="action-btn primary" onclick={() => void runStagedInstaller()}>
                    {m.updater_stalled_run()}
                  </button>
                {/if}
              </div>

              <div
                class="about-update-status"
                class:success={$updater.phase === 'uptodate' || $updater.phase === 'available' || $updater.phase === 'ready'}
                class:error={$updater.phase === 'error' || $updater.phase === 'stalled' || $updater.signatureMissing}
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
                {:else if $updater.phase === 'stalled'}
                  <span class="feedback error">
                    {$updater.installerReady
                      ? m.updater_stalled_body({ version: $updater.version ?? '' })
                      : m.updater_stalled_body_gone({ version: $updater.version ?? '' })}
                  </span>
                  <!-- `restoreStaged(staged, true)` sets both flags at once, so
                       the `signatureMissing` branch below can never be reached
                       from a re-offered staged installer. Say it here instead:
                       the reason we fell back to the staged copy is that the
                       newer release could not be verified, and that is exactly
                       the user who is about to run an installer. -->
                  {#if $updater.signatureMissing}
                    <span class="feedback error about-update-note">{m.updater_signature_missing()}</span>
                  {/if}
                {:else if $updater.phase === 'error' || $updater.signatureMissing}
                  <span class="feedback error">{m.updater_error_body({ detail: $updater.error ?? m.updater_signature_missing() })}</span>
                {:else}
                  <span class="hint">{m.settings_about_check_hint()}</span>
                {/if}
              </div>
              <!-- Checks have no setting, so the schedule is said here, under
                   whatever the last one found. -->
              {#if $updater.phase !== 'idle'}
                <span class="hint">{m.settings_about_check_hint()}</span>
              {/if}
            </div>

            <div class="field toggle-row" class:is-disabled={!silentSupported}>
              <div class="toggle-info">
                <label class="toggle-title" id="silent-update-label" for="silent-update-switch">{m.settings_silent_update_label()}</label>
                <span class="hint" id="silent-update-hint">
                  {silentSupported ? m.settings_silent_update_hint() : silentUnsupportedHint}
                </span>
                {#if silentSupported && silentStatusText}
                  <span class="hint silent-update-status" id="silent-update-status">
                    {silentStatusText}
                    {#if $silentUpdate?.enabled && $silentUpdate.phase === 'postponed'}
                      <button type="button" class="silent-update-resume" onclick={() => void resumeSilentUpdate()}>
                        {m.silent_update_resume_btn()}
                      </button>
                    {/if}
                  </span>
                {/if}
              </div>
              <ToggleSwitch
                id="silent-update-switch"
                bind:checked={settings.silent_update_enabled}
                disabled={!silentSupported}
                ariaLabelledby="silent-update-label"
                ariaDescribedby="silent-update-hint silent-update-status"
              />
            </div>
          </div>
        </div>
      </section>

      <!-- A filter that matches nothing would otherwise leave the pane blank
           with no explanation, which reads as the page having broken. -->
      {#if filtering && filterMatchCount === 0}
        <p class="settings-no-results">{m.settings_filter_no_results({ query: settingsFilter.trim() })}</p>
      {/if}

      </div>
    </div>
  {/if}
</div>

<CategoriesDialog
  bind:open={categoriesOpen}
  categories={userCategories}
  builtins={BUILTIN_DOWNLOAD_CATEGORIES}
  labelFor={downloadCategoryLabel}
  folders={$appSettings?.download_category_folders ?? {}}
  counts={categoryCounts}
  isTaken={(name) => isCategoryTaken(name, userCategories)}
  onadd={addCategory}
  onremove={removeCategory}
  onfolder={saveCategoryFolder}
/>

<!--
  Restart confirmation prompt — asked when the user leaves Settings while the
  saved ports or UPnP differ from what Ember started with. The network stack
  reads them only at startup, so the save persists the value but the running
  listener keeps the old one until restart. "Later" carries on to where they
  were going and leaves the banner; Escape stays on Settings. Same UX as the
  setup wizard's "Launch Ember" relaunch step.
-->
<ConfirmDialog
  bind:open={showRestartPrompt}
  title={m.settings_restart_dialog_title()}
  message={m.settings_restart_dialog_message({ reason: restartReason })}
  confirmLabel={m.settings_restart_now()}
  cancelLabel={m.settings_restart_later()}
  onconfirm={() => { pendingLeaveHref = null; void performRestart(); }}
  oncancel={resumeLeave}
  ondismiss={() => { pendingLeaveHref = null; restartAskedFor = null; }}
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
  bind:open={ignoredClearConfirmOpen}
  title={m.settings_channels_clear_ignored_title()}
  message={m.settings_channels_clear_ignored_message()}
  confirmLabel={m.settings_channels_clear()}
  danger={true}
  onconfirm={() => { ignoredMembers.set([]); showSaveMsg(m.settings_channels_cleared(), false, 2000); }}
/>

<!-- Confirmed like the ignored list: these are one-click wipes of a
     preference the user built up a room at a time, and there is no undo. -->
<ConfirmDialog
  bind:open={mutedClearConfirmOpen}
  title={m.settings_channels_clear_muted_title()}
  message={m.settings_channels_clear_muted_message()}
  confirmLabel={m.settings_channels_clear()}
  danger={true}
  onconfirm={() => {
    // A snooze is the same silence for a while; leaving it would keep rooms
    // quiet that this list, and the user, now believe are back to normal.
    channelNotifyLevels.set({});
    channelSnoozes.set({});
    showSaveMsg(m.settings_channels_cleared(), false, 2000);
  }}
/>

<ConfirmDialog
  bind:open={hiddenClearConfirmOpen}
  title={m.settings_channels_clear_hidden_title()}
  message={m.settings_channels_clear_hidden_message()}
  confirmLabel={m.settings_channels_clear()}
  danger={true}
  onconfirm={() => { hiddenChannels.set([]); showSaveMsg(m.settings_channels_cleared(), false, 2000); }}
/>

<ConfirmDialog
  bind:open={historyClearConfirmOpen}
  title={historyClearDialogTitle}
  message={historyClearDialogMessage}
  confirmLabel={m.settings_history_clear_confirm()}
  danger={true}
  onconfirm={confirmClearHistory}
/>

<ConfirmDialog
  bind:open={antileechResetConfirmOpen}
  title={m.settings_antileech_restore_dialog_title()}
  message={m.settings_antileech_restore_dialog_message()}
  confirmLabel={m.settings_antileech_restore_confirm()}
  danger={true}
  onconfirm={confirmResetAntileech}
/>

<ConfirmDialog
  bind:open={leaveConfirmOpen}
  title={m.settings_unsaved_leave_title()}
  message={m.settings_unsaved_leave_message()}
  confirmLabel={m.settings_unsaved_leave_confirm()}
  danger={true}
  onconfirm={resumeLeave}
  oncancel={() => { pendingLeaveHref = null; }}
/>

<!--
  Full-screen "Restarting Ember" overlay shown while `relaunch()` is in
  flight. Identical layout/copy to SetupWizard's relaunch overlay so
  the visual transition feels the same in both places.
-->
{#if restarting}
  <div class="restart-overlay" role="status" aria-label={m.settings_restarting_aria()}>
    <div class="restart-card">
      <div class="spinner lg"></div>
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

  .sticky-header {
    flex-wrap: wrap;
    row-gap: 12px;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .restart-pending-banner {
    flex-basis: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 8px 8px 12px;
    border: 1px solid color-mix(in srgb, var(--warning) 40%, var(--border));
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--warning) 10%, transparent);
    font-size: var(--font-size-md);
    color: var(--text-primary);
  }

  .restart-pending-banner .action-btn {
    flex-shrink: 0;
  }

  .save-status {
    font-size: var(--font-size-md);
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
    /* Stays in view down a long section, so switching never means scrolling
       back up first. Capped so a short window can still reach every tab. */
    position: sticky;
    top: 8px;
    max-height: calc(100vh - 160px);
    overflow-y: auto;
  }

  .settings-nav-title {
    font-size: var(--font-size-xs);
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
    font-size: var(--font-size-md);
    text-align: left;
    cursor: pointer;
  }

  .settings-nav-item:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  /* Same active and focus language as the sidebar's nav items. */
  .settings-nav-item.active {
    background: var(--accent-fill);
    color: var(--accent);
    font-weight: 600;
  }

  .settings-nav-item:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
    background: var(--bg-hover);
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

  .card.hidden {
    display: none;
  }

  /* Filter mode. `data-filtered` is written by the effect that reads rendered
     text; Svelte never manages it, so the two cannot fight over the same
     attribute.
     `:global` on the matched element is load-bearing, not stylistic: the
     attribute only ever appears at runtime, so Svelte's CSS pruning removed
     these three rules as unused and the filter hid nothing at all. The
     `.cards-grid` prefix stays scoped, which keeps the escape hatch confined
     to this page. */
  .cards-grid :global([data-filtered='out']) {
    display: none;
  }

  /* Several cards are on screen at once while filtering, so they need the
     separation the single-card layout never had to provide. */
  .cards-grid.filtering .card + .card {
    margin-top: 12px;
  }

  .settings-filter {
    padding: 0 8px 8px;
  }

  .settings-filter-input {
    width: 100%;
    box-sizing: border-box;
  }

  .settings-filter-status {
    margin: 0 8px 8px;
    font-size: var(--font-size-sm);
    color: var(--text-secondary);
  }

  .settings-filter-clear {
    margin: 0 8px;
  }

  /* A group has to lay its own children out, not just contain them. `.card-body`
     is a flex column with an 18px gap and `.field` carries no margin of its
     own, so once these wrappers became the flex children the gap applied
     between *groups* and the fields inside each one collapsed against each
     other — which is why this section alone looked wrong. Same axis, same gap,
     so a field sits exactly where it does in every other section. */
  .settings-group {
    display: flex;
    flex-direction: column;
    gap: 18px;
  }

  /* Names the run of fields under it. */
  .subsection-title {
    margin: 0;
    font-size: var(--font-size-xs);
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-secondary);
  }

  /* A heading belongs to the controls beneath it, so it sits nearer them than
     they sit to one another. Pulling it in against the group's own gap keeps
     one number in charge of the rhythm. */
  .settings-group > .subsection-title {
    margin-bottom: -7px;
  }

  /* A hairline between groups, with the heading saying what each one
     introduces. The first group needs none — the card header is already that
     boundary. `~` rather than `+`, so a status line or banner between two
     groups does not drop the rule above the second. */
  .card-body > .settings-group ~ .settings-group {
    border-top: 1px solid color-mix(in srgb, var(--border) 60%, transparent);
    margin-top: 2px;
    padding-top: 20px;
  }

  /* A filter that drops the first group would leave the next one's rule
     stranded directly under the card header, reading as a stray line. The
     groups on screen while filtering are a subset anyway, so a rule claiming
     to divide them says nothing true — the card-body gap is separation
     enough. */
  .cards-grid.filtering .card-body > .settings-group ~ .settings-group {
    border-top: none;
    margin-top: 0;
    padding-top: 0;
  }

  .settings-group.hidden {
    display: none;
  }

  /* A line of context ahead of a section's groups, where what it says covers
     all of them rather than one control. */
  .section-intro {
    margin: 0;
  }

  .settings-no-results {
    padding: 24px;
    text-align: center;
    color: var(--text-secondary);
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
    font-size: var(--font-size-2xl);
    width: 36px;
    height: 36px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    border-radius: var(--radius-md);
    flex-shrink: 0;
    color: var(--accent);
  }

  .card-icon svg {
    width: 18px;
    height: 18px;
  }

  .card-header h3 {
    font-size: var(--font-size-base);
    font-weight: 600;
    color: var(--text-primary);
    margin: 0;
    line-height: 1.2;
  }

  .card-desc {
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    margin: 0;
    line-height: 1.3;
  }

  .card-body {
    display: flex;
    flex-direction: column;
    gap: 18px;
    padding: 20px 20px 24px;
  }

  /* ── Fields ────────────────────────────────────── */
  .field {
    margin-bottom: 0;
  }

  .field:not(.toggle-row) {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  /* Same weight and colour as `.toggle-title`, so a labelled box and a switch
     read as the same kind of row. */
  .field > label,
  .field > .field-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--font-size-md);
    color: var(--text-primary);
    margin-bottom: 0;
    font-weight: 500;
    line-height: 1.4;
  }

  .field input[type='number'],
  .field input[type='text'],
  .field input:not([type]),
  .field > select {
    width: 100%;
  }

  .field input[type='password'] {
    width: 100%;
    max-width: 28rem;
  }

  .field-row {
    display: flex;
    gap: 14px;
    margin-bottom: 0;
  }

  .field.half {
    flex: 1;
    margin-bottom: 0;
  }

  .hint {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    margin-top: 0;
    display: block;
    line-height: 1.5;
  }

  .hint.hint-error {
    color: var(--badge-danger-text);
  }

  /* Counts and sizes want a few digits, not the whole card; specific enough
     to beat the `.field input[type='number']` full-width rule above. */
  .field input[type='number'].compact-number {
    width: 120px;
  }

  /* A typed field and the Apply button that appears once it is edited. */
  .apply-input {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: 8px;
  }

  .apply-input > input:not(.compact-number),
  .apply-input > .apply-grow {
    flex: 1;
    min-width: 0;
  }

  .field-apply {
    flex-shrink: 0;
    padding: 7px 14px;
  }

  /* The Auto switch sits beside the number box, vertically centred on it. */
  .auto-switch {
    display: inline-flex;
    align-self: center;
    white-space: nowrap;
  }

  /* Wraps onto its own line under the field and its Apply button. */
  .field-apply-error {
    flex-basis: 100%;
    color: var(--danger);
    font-size: var(--font-size-sm);
  }

  /* ── Restart badge ─────────────────────────────── */
  .restart-badge {
    display: inline-block;
    font-size: var(--font-size-2xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    padding: 1px 6px;
    border-radius: var(--radius-pill);
    color: var(--warning);
    background: color-mix(in srgb, var(--warning) 14%, transparent);
    vertical-align: middle;
    line-height: 1.5;
  }

  /* Saved, and waiting for the restart the header banner offers. */
  .restart-badge.pending {
    background: color-mix(in srgb, var(--warning) 26%, transparent);
    box-shadow: inset 0 0 0 1px var(--warning);
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
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .toggle-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--font-size-md);
    font-weight: 500;
    color: var(--text-primary);
    line-height: 1.4;
  }

  label.toggle-title {
    cursor: pointer;
  }

  .toggle-row:has(:global(button[role='switch']:disabled)) label.toggle-title {
    cursor: default;
  }

  .toggle-info .hint {
    margin-top: 0;
  }

  /* A setting that only means something while the one above it is on. */
  .nested {
    margin-left: 0;
    margin-top: -8px;
    padding-left: 12px;
    border-left: 2px solid color-mix(in srgb, var(--border) 70%, transparent);
  }

  /* Its control is disabled; the words go quiet with it. The control dims
     itself, so dimming the whole row would dim it twice. */
  .field.is-disabled > .toggle-info,
  .field.is-disabled > label,
  .field.is-disabled > .hint {
    opacity: 0.55;
  }

  /* An in-text action that switches section rather than navigating, so it
     is a button, but it reads as the links beside it. */
  .link-btn {
    display: inline;
    padding: 0;
    border: none;
    background: none;
    color: var(--accent);
    font: inherit;
    cursor: pointer;
  }

  .link-btn:hover {
    background: none;
    color: var(--accent);
    text-decoration: underline;
  }

  .category-manage {
    display: flex;
  }

  /* ── Folder input ──────────────────────────────── */
  .folder-input {
    display: flex;
    align-items: stretch;
    border: 1px solid var(--input-border);
    border-radius: var(--radius-sm);
    overflow: hidden;
    background: var(--bg-input);
    transition: border-color var(--transition-normal);
  }

  .folder-input:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-halo);
  }

  .folder-input input {
    flex: 1;
    border: none;
    background: transparent;
    padding: 7px 10px;
    font-size: var(--font-size-md);
    color: var(--text-primary);
    outline: none;
    box-shadow: none;
    min-width: 0;
  }


  .folder-btn {
    border: none;
    border-left: 1px solid var(--border);
    border-radius: 0;
    background: var(--bg-surface);
    color: var(--text-secondary);
    padding: 0 14px;
    font-size: var(--font-size-sm);
    font-weight: 600;
    cursor: pointer;
    transition: background var(--transition-normal), color var(--transition-normal);
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
    font-size: var(--font-size-sm);
    font-weight: 600;
    padding: 6px 14px;
    background: var(--bg-surface);
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    transition: background var(--transition-normal), color var(--transition-normal), border-color var(--transition-normal);
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

  /* Deletes or resets something with no undo. Outlined rather than filled:
     the confirmation that follows is where the weight belongs, and a row of
     solid red buttons would drown out everything else in the section. */
  .action-btn.danger {
    color: var(--danger);
    border-color: color-mix(in srgb, var(--danger) 45%, var(--border));
  }

  .action-btn.danger:hover {
    color: var(--danger);
    border-color: var(--danger);
    background: color-mix(in srgb, var(--danger) 10%, var(--bg-surface));
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
    border-radius: var(--radius-md);
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
    font-size: var(--font-size-xl);
    font-weight: 700;
    letter-spacing: 1.5px;
    color: var(--accent);
    line-height: 1;
  }

  .about-tagline {
    margin: 0 0 8px;
    font-size: var(--font-size-2xs);
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
    font-size: var(--font-size-xs);
    font-weight: 600;
    color: var(--badge-accent-text);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    border: 1px solid color-mix(in srgb, var(--accent) 22%, transparent);
    border-radius: var(--radius-pill);
    line-height: 1.4;
  }

  .about-description {
    margin: 0 0 6px;
    font-size: var(--font-size-md);
    line-height: 1.45;
    color: var(--text-secondary);
  }

  .about-license {
    margin: 0 0 12px;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
  }

  .channels-pref-action {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
  }

  .channels-pref-count {
    font-size: var(--font-size-md);
    font-weight: 600;
    font-variant-numeric: tabular-nums;
    color: var(--text-secondary);
    min-width: 1.5ch;
    text-align: right;
  }

  .ignored-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .ignored-list li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 6px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
  }

  .ignored-name {
    font-size: var(--font-size-md);
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .ignored-scope {
    display: block;
    margin-top: 2px;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .about-actions {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .about-action {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    width: 100%;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
    color: inherit;
    font-family: inherit;
    font-weight: 400;
    text-align: left;
    cursor: pointer;
    transition:
      background-color var(--transition-fast) ease,
      border-color var(--transition-fast) ease;
  }

  .about-action:hover,
  .about-action:focus-visible {
    background: var(--bg-hover);
    border-color: var(--accent-dim);
  }

  /* Sized like the link rows above it (`EmberLinks`), so the column of icons
     lines up. */
  .about-action-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 32px;
    height: 32px;
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--accent) 13%, transparent);
    color: var(--accent);
  }

  .about-action-icon svg { width: 17px; height: 17px; }

  .about-action-body {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .about-action-title {
    font-size: var(--font-size-md);
    font-weight: 600;
    color: var(--text-primary);
  }

  .about-action-desc {
    font-size: var(--font-size-sm);
    line-height: 1.45;
    color: var(--text-secondary);
  }

  .about-action-path {
    margin-top: 2px;
    font-size: var(--font-size-xs);
    color: var(--text-muted);
    user-select: text;
    overflow-wrap: anywhere;
  }

  .about-action-go {
    display: inline-flex;
    align-items: center;
    flex-shrink: 0;
    align-self: center;
    color: var(--text-muted);
  }

  .about-action-go svg { width: 14px; height: 14px; }

  .about-action:hover .about-action-go { color: var(--accent); }

  /* Warm, in Buy Me a Coffee's yellow, but a panel rather than a banner: it
     sits beside the rest of the card and does not shout over it. */
  .about-support {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-top: 10px;
    padding: 14px 16px;
    border: 1px solid color-mix(in srgb, #ffdd00 35%, var(--border));
    border-radius: var(--radius-md);
    background: linear-gradient(
      120deg,
      color-mix(in srgb, #ffdd00 14%, transparent) 0%,
      color-mix(in srgb, #ffdd00 3%, transparent) 75%
    );
  }

  .about-support-mark {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 40px;
    height: 40px;
    border-radius: var(--radius-md);
    background: #ffdd00;
    color: #0d0c22;
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.5), 0 1px 3px rgba(0, 0, 0, 0.12);
  }

  .about-support-mark svg { width: 24px; height: 24px; }

  .about-support-copy {
    flex: 1;
    min-width: 0;
  }

  .about-support-title {
    margin: 0 0 2px;
    font-size: var(--font-size-md);
    font-weight: 600;
    color: var(--text-primary);
  }

  .about-support-text {
    margin: 0;
    font-size: var(--font-size-sm);
    line-height: 1.45;
    color: var(--text-secondary);
  }

  /* Narrow window: the button drops under the text rather than squeezing it. */
  @media (max-width: 720px) {
    .about-support { flex-wrap: wrap; }
  }


  .silent-update-status {
    display: block;
    margin-top: 4px;
    color: var(--text-primary);
  }

  .silent-update-resume {
    border: none;
    background: transparent;
    padding: 0;
    margin-left: 6px;
    color: var(--accent);
    font-size: inherit;
    font-weight: 600;
    cursor: pointer;
  }

  .silent-update-resume:hover {
    text-decoration: underline;
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

  .about-update-note {
    display: block;
    margin-top: 6px;
  }

  .about-progress {
    margin-top: 8px;
    height: 4px;
    border-radius: var(--radius-pill);
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
    font-size: var(--font-size-sm);
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
  .antileech-textarea {
    width: 100%;
    box-sizing: border-box;
    min-height: 140px;
    padding: 8px 10px;
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
    line-height: 1.5;
    color: var(--text-primary);
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    resize: vertical;
  }
  .antileech-textarea:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-halo);
  }
  .antileech-block .hint code {
    font-family: var(--font-mono);
    padding: 0 4px;
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    color: var(--text-primary);
  }
  /* Web services list + add form. */
  .webservice-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  /* `--bg-surface` rather than `--bg-secondary`, which is the card's own
     colour: a row painted in it reads as a hairline outline on the card
     instead of an object sitting on it. Matches `.ignored-list li`, the other
     removable-entry list on this page. */
  .webservice-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 10px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    transition: border-color var(--transition-fast) ease;
  }
  .webservice-row:hover {
    border-color: var(--accent-dim);
  }
  .webservice-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
    flex: 1;
  }
  .webservice-name {
    font-size: var(--font-size-md);
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  /* A URL is long and is the part worth inspecting, so it truncates rather
     than wrapping the row to three lines; the full value is in the row's
     `title`. Monospaced to match the Address field it was typed into, which
     is also what makes a `#hashid` placeholder legible as a placeholder. */
  .webservice-url {
    font-family: var(--font-mono);
    font-size: var(--font-size-xs);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  /* Removing is the one destructive control here, and the shared hover turns
     everything accent-coloured. */
  .webservice-remove {
    flex-shrink: 0;
  }
  .webservice-remove:hover {
    color: var(--danger);
    border-color: var(--danger);
    background: color-mix(in srgb, var(--danger) 8%, transparent);
  }
  .webservice-add {
    display: flex;
    align-items: flex-end;
    gap: 8px;
    flex-wrap: wrap;
  }
  .webservice-field {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 140px;
  }
  .webservice-field-url {
    flex: 1;
    min-width: 220px;
  }
  .webservice-field input {
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
    padding: 6px 8px;
    color: var(--text-primary);
    background: var(--bg-secondary);
    border: 1px solid var(--input-border);
    border-radius: var(--radius-sm);
  }
  .webservice-field input:focus {
    outline: none;
    border-color: var(--accent);
  }
  /* Secondary ways in, so they sit further from the form than its own note. */
  .antileech-path {
    font-family: var(--font-mono);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .antileech-errors {
    margin-top: 6px;
    padding: 8px 10px;
    background: var(--bg-secondary);
    border: 1px solid var(--danger);
    border-radius: var(--radius-sm);
    font-size: var(--font-size-sm);
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
    font-family: var(--font-mono);
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
    transition: border-color var(--transition-normal), box-shadow var(--transition-normal);
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

  .system-swatch .swatch-half {
    flex: 1;
    display: flex;
    min-width: 0;
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
    font-size: var(--font-size-xs);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
  }

  .swatch-label {
    font-size: var(--font-size-sm);
    font-weight: 500;
    color: var(--text-secondary);
    padding: 6px 0 8px;
  }

  /* ── Close-behavior picker ─────────────────────── */
  .behavior-picker {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
    margin-top: 0;
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
    transition: border-color var(--transition-normal) ease, background var(--transition-normal) ease, box-shadow var(--transition-normal) ease, transform var(--transition-normal) ease;
  }

  .behavior-card:hover {
    border-color: color-mix(in srgb, var(--accent) 35%, var(--border));
    background: var(--bg-hover);
  }

  .behavior-card:focus-visible {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-halo);
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

  /* Ten languages as full-size cards took four rows of the section. As
     one-line chips — flag beside the name — they fit in two or three, and
     as many per row as the width allows. */
  .lang-picker {
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 8px;
  }

  .lang-card {
    flex-direction: row;
    align-items: center;
    gap: 10px;
    /* Room on the right for the check mark. */
    padding: 8px 30px 8px 10px;
  }

  .lang-card .behavior-icon {
    width: 24px;
    height: 24px;
    flex-shrink: 0;
    margin-bottom: 0;
  }

  .lang-card .behavior-icon :global(svg) {
    width: 14px;
    height: 14px;
  }

  .lang-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .lang-text .behavior-title,
  .lang-text .behavior-desc {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .lang-text .behavior-desc {
    font-size: var(--font-size-xs);
  }

  .lang-card .behavior-check {
    top: 50%;
    right: 8px;
    width: 16px;
    height: 16px;
    transform: translateY(-50%);
  }

  .behavior-title {
    font-size: var(--font-size-md);
    font-weight: 600;
    color: var(--text-primary);
    line-height: 1.25;
  }

  .behavior-desc {
    font-size: var(--font-size-sm);
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
    font-size: var(--font-size-xs);
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: var(--shadow-sm);
  }

  @media (max-width: 760px) {
    .behavior-picker {
      grid-template-columns: 1fr;
    }

    /* Chips are small enough to keep sharing a row. */
    .lang-picker {
      grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    }

    /* Paired fields (ports, limits) stack rather than squeeze side by side. */
    .field-row {
      flex-direction: column;
    }
  }

  /* Shared "this is happening right now" marker: the sleep inhibitor being
     held, and the schedule rule currently in force. */
  .live-badge {
    align-self: flex-start;
    margin-top: 4px;
    padding: 1px 7px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--accent) 16%, transparent);
    color: var(--accent);
    font-size: var(--font-size-xs);
    font-weight: 600;
    white-space: nowrap;
  }

  .schedule-active-banner {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 14px;
    padding: 10px 12px;
    border: 1px solid color-mix(in srgb, var(--accent) 35%, var(--border));
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--accent) 8%, transparent);
    font-size: var(--font-size-md);
  }

  .live-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--accent);
    flex-shrink: 0;
  }

  .schedule-active-limits {
    margin-left: auto;
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .schedule-editor {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  /* Only reachable now when the feature is off *and* a rule would block the
     save, so the editor is showing solely to be corrected. Dimmed to keep
     saying what it said before: these rules are not in force. */
  .schedule-editor.is-inactive,
  .alt-speed-limits.is-inactive,
  .manual-speed-limit.is-inactive {
    opacity: 0.62;
  }

  .alt-speed-limits {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
  }

  .schedule-empty {
    margin: 0;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }

  .schedule-rule {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
  }

  .schedule-rule.is-active {
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
  }

  .schedule-rule.has-error {
    border-color: var(--danger);
  }

  .schedule-rule-head {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .schedule-name {
    flex: 1;
    min-width: 0;
  }

  .schedule-rule-actions {
    display: flex;
    gap: 4px;
    margin-left: auto;
  }

  .icon-btn {
    width: 26px;
    height: 26px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    color: var(--text-muted);
    font-size: var(--font-size-sm);
    line-height: 1;
    cursor: pointer;
  }

  .icon-btn:hover:not(:disabled) {
    color: var(--text-primary);
    border-color: var(--accent);
  }

  .icon-btn.danger:hover:not(:disabled) {
    color: var(--danger);
    border-color: var(--danger);
  }

  .icon-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .schedule-days {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .day-chip {
    padding: 4px 9px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
    cursor: pointer;
  }

  .day-chip.selected {
    border-color: var(--accent);
    background: color-mix(in srgb, var(--accent) 16%, transparent);
    color: var(--accent);
    font-weight: 600;
  }

  .schedule-times {
    display: flex;
    align-items: flex-end;
    flex-wrap: wrap;
    gap: 10px;
  }

  .schedule-time {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: var(--font-size-sm);
    color: var(--text-muted);
  }

  .schedule-time input {
    font-variant-numeric: tabular-nums;
  }

  .schedule-overnight {
    padding-bottom: 6px;
    color: var(--text-muted);
    font-size: var(--font-size-sm);
  }

  .schedule-limits {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
    gap: 10px;
  }

  .schedule-error {
    color: var(--danger);
    font-size: var(--font-size-sm);
  }

  .schedule-footer {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }

  /* Every set of figures on the page — spam data, download history, the
     speed test, a backup's contents — in the same tiles. */
  .stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 8px;
  }

  /* The two recommended-limit cards carry the longest labels, so they take a
     larger share than Download and Upload; "Recommended download limit" no
     longer wraps onto a second line. Narrow windows go back to two columns. */
  .stat-grid.speed-result-grid {
    grid-template-columns: 1fr 1fr 1.25fr 1.5fr;
  }

  @media (max-width: 760px) {
    .stat-grid.speed-result-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }

  .stat {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    padding: 8px 10px;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .stat span {
    font-size: var(--font-size-xs);
    color: var(--text-muted);
  }

  .stat strong {
    font-size: var(--font-size-lg);
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
    overflow-wrap: anywhere;
  }

  .stat strong.is-loading {
    font-size: var(--font-size-sm);
    font-weight: 500;
    color: var(--text-muted);
  }

  /* Where to keep the file is the one piece of backup advice that decides
     whether the backup is any use, so it stands out from the grey hints. */
  .backup-callout {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 2px 0 0;
    padding: 9px 12px;
    max-width: 68ch;
    border: 1px solid color-mix(in srgb, var(--accent) 40%, var(--border));
    border-left: 3px solid var(--accent);
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--accent) 10%, var(--bg-surface));
    font-size: var(--font-size-sm);
    line-height: 1.45;
    color: var(--text-primary);
  }

  .backup-callout strong {
    font-weight: 700;
  }

  .backup-callout-icon {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: var(--accent);
    color: var(--on-accent);
    font-size: 14px;
    font-weight: 800;
    line-height: 1;
    box-shadow: 0 0 0 3px var(--accent-halo);
  }

  .pending-restore {
    display: flex;
    flex-direction: column;
    gap: 10px;
    border: 1px solid color-mix(in srgb, var(--warning) 40%, var(--border));
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--warning) 8%, var(--bg-surface));
    padding: 12px 14px;
    margin-bottom: 0;
  }

  .backup-path {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: var(--font-mono);
    max-width: 68ch;
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

    /* The search box, then the tabs as one row that scrolls sideways,
       pinned to the top. Stacked, a dozen tabs pushed every setting below
       the fold before the first one could be reached. */
    .settings-nav {
      top: 0;
      z-index: 5;
      gap: 8px;
      padding: 8px;
      max-height: none;
      overflow: visible;
      max-width: 100%;
    }

    .settings-nav-title {
      display: none;
    }

    .settings-filter {
      padding: 0;
    }

    .settings-tablist {
      display: flex;
      gap: 4px;
      overflow-x: auto;
      scrollbar-width: thin;
    }

    .settings-nav-item {
      width: auto;
      padding: 7px 10px;
      font-size: var(--font-size-sm);
      flex-shrink: 0;
      white-space: nowrap;
    }

    .settings-filter-status,
    .settings-filter-clear {
      margin: 0;
    }

    .settings-filter-clear {
      align-self: flex-start;
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

  .restart-title {
    font-size: 22px;
    font-weight: 700;
    color: var(--accent);
    margin: 0;
  }

  .restart-sub {
    font-size: var(--font-size-base);
    color: var(--text-muted);
    margin: 0;
  }

  .chat-attach-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }

  /* A number with its unit attached, styled like `.folder-input`. */
  .unit-input {
    display: inline-flex;
    align-items: stretch;
    border: 1px solid var(--input-border);
    border-radius: var(--radius-sm);
    overflow: hidden;
    background: var(--bg-input);
    transition: border-color var(--transition-normal);
  }

  .unit-input:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-halo);
  }

  /* Specific enough to beat `.field input[type='number'] { width: 100% }`. */
  .field .unit-input input[type='number'] {
    width: 96px;
    border: none;
    border-radius: 0;
    background: transparent;
    box-shadow: none;
    padding: 7px 10px;
    text-align: right;
    font-variant-numeric: tabular-nums;
  }

  .unit-input-suffix {
    display: flex;
    align-items: center;
    padding: 0 12px;
    border-left: 1px solid var(--border);
    background: var(--bg-surface);
    color: var(--text-secondary);
    font-size: var(--font-size-sm);
    font-weight: 600;
  }

  .chat-files-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .chat-files-btn svg {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
  }

  .channel-offers-row select {
    flex: 1;
    min-width: 200px;
  }

  .channel-language-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .channel-language-suggest {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .channel-language-suggest-flag {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
    border-radius: 50%;
    box-shadow: 0 0 0 1px color-mix(in srgb, var(--text-primary) 14%, transparent);
  }
</style>
