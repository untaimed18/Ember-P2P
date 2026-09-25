<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';
  import { formatSize } from '$lib/utils';
  import ToggleSwitch from './ToggleSwitch.svelte';
  import {
    detectEmuleInstalls,
    discardEmuleImport,
    getEmuleImportReport,
    pendingEmuleImport,
    pickEmuleFolder,
    previewEmuleImport,
    stageEmuleImport,
    type EmuleDownload,
    type EmuleImportReport,
    type EmuleImportSelection,
    type EmuleInstall,
    type EmulePreview,
    type EmuleStageProgress,
  } from '$lib/api/emuleImport';

  /**
   * One import UI for both places it is offered.
   *
   * `wizard`: nothing is written here. The chosen selection is handed to the
   * wizard, which stages it while finishing, once the download folder it
   * saves is final. Preferences are not part of it: the preview prefills the
   * wizard's own nickname, port and folder steps instead.
   *
   * `settings`: this stages the import itself and asks for the restart that
   * applies it.
   */
  let {
    mode,
    selection = $bindable(null),
    downloadFolderIsIncoming = false,
    onpreview,
    onrestart,
  }: {
    mode: 'wizard' | 'settings';
    selection?: EmuleImportSelection | null;
    /** Wizard only: its download folder is eMule's incoming folder, which is
     *  where downloads will be placed. Settings mode has its own checkbox. */
    downloadFolderIsIncoming?: boolean;
    onpreview?: (preview: EmulePreview) => void;
    onrestart?: () => void;
  } = $props();

  let installs: EmuleInstall[] = $state([]);
  let detecting = $state(true);
  let reading = $state(false);
  let error = $state('');
  let preview = $state<EmulePreview | null>(null);

  let wantPreferences = $state(false);
  let wantIncoming = $state(false);
  let wantLibrary = $state(true);
  let wantIdentity = $state(false);
  let wantCredits = $state(true);
  let wantServers = $state(true);
  let wantNodes = $state(true);
  let wantIpfilter = $state(false);
  let folderChoice: boolean[] = $state([]);
  let downloadChoice: boolean[] = $state([]);

  /** Wizard: bring this eMule profile along. On by default once one is found;
   *  `declined` keeps an explicit "start fresh" through a re-read. */
  let importChosen = $state(false);
  let declined = $state(false);
  let staging = $state(false);
  let progress: EmuleStageProgress | null = $state(null);
  let staged = $state(false);
  let pending = $state(false);
  let report: EmuleImportReport | null = $state(null);
  let unlistenProgress: UnlistenFn | null = null;

  const importableFolder = (status: string) => status === 'ready' || status === 'drive_root';

  let targetIsIncoming = $derived(mode === 'settings' ? wantIncoming : downloadFolderIsIncoming);

  /** A download on another volume than where it goes is copied, not moved. */
  function copied(download: EmuleDownload): boolean {
    const same = targetIsIncoming
      ? download.same_volume_as_incoming
      : download.same_volume_as_download_folder;
    return same === false;
  }

  let copyBytes = $derived(
    preview?.downloads.reduce(
      (sum, d, i) => (downloadChoice[i] && d.status === 'ready' && copied(d) ? sum + d.part_bytes : sum),
      0,
    ) ?? 0,
  );
  let downloadFree = $derived(
    preview ? (targetIsIncoming ? preview.free_incoming : preview.free_download_folder) : null,
  );
  let libraryShort = $derived(
    !!preview && wantLibrary && preview.free_data_dir !== null && preview.known2_bytes > preview.free_data_dir,
  );
  /** eMule holds its downloads open while it runs, so any in use means it is. */
  let emuleRunning = $derived(preview?.downloads.some((d) => d.status === 'in_use') ?? false);

  /** A folder inside another listed one is shared with it, when that one is. */
  function includedWithParent(index: number): boolean {
    const folders = preview?.shared_folders ?? [];
    const path = folders[index]?.path.toLowerCase() ?? '';
    return folders.some((outer, j) => {
      if (j === index || !folderChoice[j] || !importableFolder(outer.status)) return false;
      const prefix = outer.path.toLowerCase().replace(/[\\/]+$/, '');
      return path.startsWith(prefix + '\\') || path.startsWith(prefix + '/');
    });
  }

  function setChoice(importIt: boolean) {
    importChosen = importIt;
    declined = !importIt;
  }

  async function load(install: EmuleInstall) {
    reading = true;
    error = '';
    try {
      const result = await previewEmuleImport(install.id);
      preview = result;
      // A whole drive is left for the user to tick, knowing what it means;
      // ticking it also brings up the native confirmation when staging.
      folderChoice = result.shared_folders.map((f) => f.status === 'ready');
      downloadChoice = result.downloads.map((d) => d.status === 'ready');
      wantIpfilter = result.ipfilter;
      wantIdentity = mode === 'wizard' && result.identity;
      importChosen = mode === 'wizard' && !declined;
      onpreview?.(result);
    } catch (e) {
      error = translateError(e, m.emule_import_read_failed());
    } finally {
      reading = false;
    }
  }

  async function pickFolder() {
    error = '';
    try {
      const picked = await pickEmuleFolder();
      if (picked) {
        installs = [...installs.filter((i) => i.id !== picked.id), picked];
        await load(picked);
      }
    } catch (e) {
      error = translateError(e, m.emule_import_read_failed());
    }
  }

  function currentSelection(): EmuleImportSelection | null {
    if (!preview) return null;
    return {
      token: preview.token,
      preferences: mode === 'settings' && wantPreferences,
      incoming_as_download_folder: mode === 'settings' && wantIncoming,
      library: wantLibrary,
      shared_folders: folderChoice.flatMap((on, i) => (on ? [i] : [])),
      identity: wantIdentity && preview.identity,
      credits: wantCredits,
      downloads: downloadChoice.flatMap((on, i) => (on ? [i] : [])),
      servers: wantServers,
      nodes: wantNodes,
      ipfilter: wantIpfilter,
    };
  }

  $effect(() => {
    if (mode === 'wizard') selection = importChosen ? currentSelection() : null;
  });

  async function stageNow() {
    const chosen = currentSelection();
    if (!chosen || staging) return;
    staging = true;
    error = '';
    progress = null;
    try {
      await stageEmuleImport(chosen);
      staged = true;
      pending = true;
      // Its downloads have moved, so this preview cannot be staged again.
      preview = null;
    } catch (e) {
      error = translateError(e, m.emule_import_stage_failed());
    } finally {
      staging = false;
      progress = null;
    }
  }

  async function discard() {
    error = '';
    try {
      await discardEmuleImport();
      pending = false;
      staged = false;
    } catch (e) {
      error = translateError(e);
    }
  }

  let progressText = $derived.by(() => {
    if (!progress || progress.total === 0) return m.emule_import_staging();
    const percent = Math.min(100, Math.round((progress.done / progress.total) * 100));
    return progress.phase === 'known2'
      ? m.emule_import_progress_known2({ percent })
      : m.emule_import_progress_downloads({ percent });
  });

  function reportLabel(kind: string): string {
    switch (kind) {
      case 'identity': return m.emule_import_identity_title();
      case 'credits': return m.emule_import_credits_title();
      case 'known_files': return m.emule_import_report_known_files();
      case 'aich_hashes': return m.emule_import_report_aich();
      case 'servers': return m.emule_import_report_servers();
      case 'nodes': return m.emule_import_report_nodes();
      case 'ipfilter': return m.emule_import_ipfilter();
      case 'settings': return m.emule_import_report_settings();
      case 'downloads': return m.emule_import_downloads_title();
      case 'manifest': return m.emule_import_report_manifest();
      default: return kind;
    }
  }

  function reportOutcome(item: EmuleImportReport['items'][number]): string {
    if (!item.ok) return m.emule_import_report_failed({ detail: item.detail ?? '' });
    return item.kind === 'identity' || item.kind === 'settings'
      ? m.emule_import_report_applied()
      : m.emule_import_report_ok({ count: item.count });
  }

  function folderNote(status: string): string {
    switch (status) {
      case 'drive_root': return m.emule_import_folder_drive_root();
      case 'refused': return m.emule_import_folder_refused();
      case 'missing': return m.emule_import_folder_missing();
      case 'covered': return m.emule_import_folder_covered();
      case 'already_shared': return m.emule_import_folder_already();
      case 'contains_shared': return m.emule_import_folder_contains_shared();
      default: return '';
    }
  }

  function downloadNote(status: string): string {
    switch (status) {
      case 'missing_data': return m.emule_import_download_missing();
      case 'already_downloading': return m.emule_import_download_already();
      case 'already_have': return m.emule_import_download_have();
      case 'in_use': return m.emule_import_download_in_use();
      default: return '';
    }
  }

  let destroyed = false;

  onMount(async () => {
    const unlisten = await listen<EmuleStageProgress>('emule-import-progress', (event) => {
      progress = event.payload;
    }).catch(() => null);
    if (destroyed) {
      unlisten?.();
      return;
    }
    unlistenProgress = unlisten;
    if (mode === 'settings') {
      pending = await pendingEmuleImport().catch(() => false);
      report = await getEmuleImportReport(false).catch(() => null);
    }
    try {
      installs = await detectEmuleInstalls();
      if (installs.length === 1) await load(installs[0]);
    } catch {
      installs = [];
    } finally {
      detecting = false;
    }
  });

  onDestroy(() => {
    destroyed = true;
    unlistenProgress?.();
  });
</script>

<div class="emule-import" class:settings={mode === 'settings'}>
  {#if mode === 'settings' && pending}
    <div class="notice" role="status">
      <span class="notice-title">{staged ? m.emule_import_staged_title() : m.emule_import_pending()}</span>
      <span class="hint">{m.emule_import_staged_message()}</span>
      <div class="action-row">
        <button type="button" class="action-btn primary" onclick={() => onrestart?.()}>{m.settings_restart_now()}</button>
        <button type="button" class="action-btn danger" onclick={discard}>{m.emule_import_discard()}</button>
      </div>
    </div>
  {/if}

  {#if mode === 'settings'}
    <!-- The same read-only path and Browse pair as the download folder: the
         folder comes from the picker or detection, never from typing. -->
    <div class="group">
      <h4 class="subsection-title">{m.emule_import_group_source()}</h4>
      <div class="row">
        <span class="row-label">{m.emule_import_folder_label()}</span>
        <div class="folder-input">
          <input
            readonly
            value={preview?.source.path ?? ''}
            placeholder={detecting ? m.emule_import_detecting() : ''}
            aria-label={m.emule_import_folder_label()}
          />
          <button type="button" class="folder-btn" onclick={pickFolder} disabled={reading || staging}>
            {m.settings_browse()}
          </button>
        </div>
        {#if reading}
          <span class="hint">{m.emule_import_reading()}</span>
        {:else if preview}
          <span class="hint">
            {m.emule_import_found({ client: preview.source.client === 'amule' ? 'aMule' : 'eMule' })}
          </span>
        {:else if !detecting && installs.length === 0}
          <span class="hint">{m.emule_import_none_found()}</span>
        {/if}
      </div>
      {#if preview && emuleRunning}
        {@render runningNotice(preview)}
      {/if}
      {#if installs.length > 1}
        <ul class="item-list">
          {#each installs as install (install.id)}
            <li>
              <label>
                <input
                  type="radio"
                  name="emule-source"
                  checked={preview?.source.id === install.id}
                  onchange={() => load(install)}
                  disabled={reading || staging}
                />
                <span class="item-text">
                  <span class="item-name">{install.client === 'amule' ? 'aMule' : 'eMule'}</span>
                  <span class="item-meta mono">{install.path}</span>
                </span>
              </label>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  {:else if detecting}
    <p class="hint">{m.emule_import_detecting()}</p>
  {:else}
    {#if installs.length === 0}
      <p class="hint">{m.emule_import_none_found()}</p>
    {/if}
    <div class="sources">
      {#if installs.length > 1 || (installs.length === 1 && !preview)}
        {#each installs as install (install.id)}
          <button
            type="button"
            class="source"
            class:selected={preview?.source.id === install.id}
            onclick={() => load(install)}
            disabled={reading || staging}
          >
            <span class="source-client">{install.client === 'amule' ? 'aMule' : 'eMule'}</span>
            <span class="source-path mono">{install.path}</span>
          </button>
        {/each}
      {/if}
      {#if !preview}
        <button type="button" class="ghost" onclick={pickFolder} disabled={reading || staging}>
          {m.emule_import_choose()}
        </button>
      {/if}
    </div>
  {/if}

  {#if mode === 'wizard' && reading && !preview}
    <p class="hint">{m.emule_import_reading()}</p>
  {/if}
  {#if error}
    <p class="error" role="alert">{error}</p>
  {/if}

  {#snippet runningNotice(preview: EmulePreview)}
    <div class="notice running" role="alert">
      <div class="notice-copy">
        <span class="notice-title">{m.emule_import_running_title()}</span>
        <span class="hint">{m.emule_import_running_desc()}</span>
      </div>
      <button type="button" class="action-btn" onclick={() => load(preview.source)} disabled={reading || staging}>
        {reading ? m.emule_import_reading() : m.emule_import_check_again()}
      </button>
    </div>
  {/snippet}

  <!-- Laid out as the Settings page lays out its own sections: named groups,
       a switch per thing to bring over, and a bordered row per folder or
       download to pick from. -->
  {#snippet checklist(preview: EmulePreview)}
    {#if preview.known_files > 0 || preview.known2_sets > 0 || preview.shared_folders.length > 0}
      <div class="group">
        <h4 class="subsection-title">{m.emule_import_stat_files()}</h4>
        {#if preview.known_files > 0 || preview.known2_sets > 0}
          <div class="toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.emule_import_library_title()}</span>
              <span class="hint">
                {m.emule_import_library_desc({
                  files: preview.known_files,
                  sets: preview.known2_sets,
                  size: formatSize(preview.known2_bytes),
                })}
              </span>
              {#if libraryShort}
                <span class="hint warn">{m.emule_import_library_no_space({ size: formatSize(preview.free_data_dir ?? 0) })}</span>
              {/if}
            </div>
            <ToggleSwitch bind:checked={wantLibrary} ariaLabel={m.emule_import_library_title()} />
          </div>
        {/if}
        {#if preview.shared_folders.length > 0}
          <div class="row">
            <span class="row-label">{m.emule_import_folders_title()}</span>
            <ul class="item-list">
              {#each preview.shared_folders as folder, i (i)}
                <li class:disabled={!importableFolder(folder.status)}>
                  <label>
                    {#if folder.status === 'covered'}
                      <input type="checkbox" checked={includedWithParent(i)} disabled />
                    {:else}
                      <input
                        type="checkbox"
                        bind:checked={folderChoice[i]}
                        disabled={!importableFolder(folder.status)}
                      />
                    {/if}
                    <span class="item-text">
                      <span class="item-name mono">{folder.path}</span>
                      {#if folderNote(folder.status)}
                        <span class="item-meta" class:warn={folder.status === 'drive_root'}>{folderNote(folder.status)}</span>
                      {/if}
                      {#if folder.newly_shared_subfolders > 0}
                        <span class="item-meta warn">
                          {folder.subfolder_count_capped
                            ? m.emule_import_folder_subfolders_capped({ count: folder.newly_shared_subfolders })
                            : m.emule_import_folder_subfolders({ count: folder.newly_shared_subfolders })}
                        </span>
                      {/if}
                    </span>
                  </label>
                </li>
              {/each}
            </ul>
          </div>
        {/if}
      </div>
    {/if}

    <div class="group">
      <h4 class="subsection-title">{m.emule_import_group_identity()}</h4>
      <div class="toggle-row" class:disabled={!preview.identity}>
        <div class="toggle-info">
          <span class="toggle-title">{m.emule_import_identity_title()}</span>
          <span class="hint">{preview.identity ? m.emule_import_identity_desc() : m.emule_import_identity_missing()}</span>
          {#if wantIdentity && preview.identity}
            <span class="hint warn">{m.emule_import_same_identity_warning()}</span>
          {/if}
        </div>
        <ToggleSwitch bind:checked={wantIdentity} disabled={!preview.identity} ariaLabel={m.emule_import_identity_title()} />
      </div>
      {#if preview.credits > 0}
        <div class="toggle-row">
          <div class="toggle-info">
            <span class="toggle-title">{m.emule_import_credits_title()}</span>
            <span class="hint">
              {m.emule_import_credits_desc({ count: preview.credits })}
              {#if preview.expired_credits > 0}
                {m.emule_import_credits_expired({ count: preview.expired_credits })}
              {/if}
            </span>
          </div>
          <ToggleSwitch bind:checked={wantCredits} ariaLabel={m.emule_import_credits_title()} />
        </div>
      {/if}
    </div>

    {#if preview.downloads.length > 0}
      <div class="group">
        <h4 class="subsection-title">{m.emule_import_downloads_title()}</h4>
        <div class="row">
          <span class="hint">{m.emule_import_downloads_note()}</span>
          <ul class="item-list">
            {#each preview.downloads as download, i (i)}
              <li class:disabled={download.status !== 'ready'}>
                <label>
                  <input
                    type="checkbox"
                    bind:checked={downloadChoice[i]}
                    disabled={download.status !== 'ready'}
                  />
                  <span class="item-text">
                    <span class="item-name">{download.name}</span>
                    <span class="item-meta" class:warn={download.status === 'in_use'}>
                      {m.emule_import_download_done({ done: formatSize(download.done), size: formatSize(download.size) })}
                      {#if downloadNote(download.status)}· {downloadNote(download.status)}
                      {:else if copied(download)}· {m.emule_import_download_copied()}{/if}
                    </span>
                  </span>
                </label>
              </li>
            {/each}
          </ul>
          {#if copyBytes > 0}
            <span class="hint" class:warn={downloadFree !== null && copyBytes > downloadFree}>
              {downloadFree !== null && copyBytes > downloadFree
                ? m.emule_import_downloads_no_space({ size: formatSize(copyBytes), free: formatSize(downloadFree) })
                : m.emule_import_downloads_copy_total({ size: formatSize(copyBytes) })}
            </span>
          {/if}
        </div>
      </div>
    {/if}

    {#if preview.servers > 0 || preview.nodes > 0 || preview.ipfilter}
      <div class="group">
        <h4 class="subsection-title">{m.emule_import_group_network()}</h4>
        {#if preview.servers > 0}
          <div class="toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.emule_import_servers({ count: preview.servers })}</span>
            </div>
            <ToggleSwitch bind:checked={wantServers} ariaLabel={m.emule_import_report_servers()} />
          </div>
        {/if}
        {#if preview.nodes > 0}
          <div class="toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.emule_import_nodes({ count: preview.nodes })}</span>
            </div>
            <ToggleSwitch bind:checked={wantNodes} ariaLabel={m.emule_import_report_nodes()} />
          </div>
        {/if}
        {#if preview.ipfilter}
          <div class="toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.emule_import_ipfilter()}</span>
              <span class="hint">{m.emule_import_ipfilter_desc()}</span>
            </div>
            <ToggleSwitch bind:checked={wantIpfilter} ariaLabel={m.emule_import_ipfilter()} />
          </div>
        {/if}
      </div>
    {/if}

    {#if mode === 'settings' && (preview.nickname || preview.tcp_port || preview.incoming_dir)}
      <div class="group">
        <h4 class="subsection-title">{m.emule_import_preferences_title()}</h4>
        {#if preview.nickname || preview.tcp_port}
          <div class="toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.emule_import_preferences_toggle()}</span>
              <span class="hint">
                {m.emule_import_preferences_desc({
                  nickname: preview.nickname ?? '—',
                  tcp: preview.tcp_port ?? '—',
                  udp: preview.udp_port ?? '—',
                })}
              </span>
            </div>
            <ToggleSwitch bind:checked={wantPreferences} ariaLabel={m.emule_import_preferences_toggle()} />
          </div>
        {/if}
        {#if preview.incoming_dir}
          <div class="toggle-row">
            <div class="toggle-info">
              <span class="toggle-title">{m.emule_import_incoming()}</span>
              <span class="hint mono">{preview.incoming_dir}</span>
            </div>
            <ToggleSwitch bind:checked={wantIncoming} ariaLabel={m.emule_import_incoming()} />
          </div>
        {/if}
      </div>
    {/if}
  {/snippet}

  <!-- Kept on screen while "Check again" re-reads, rather than flickering out. -->
  {#if preview}
    {#if mode === 'wizard'}
    <div class="found">
      <div class="found-head">
        <div>
          <strong>{m.emule_import_found({ client: preview.source.client === 'amule' ? 'aMule' : 'eMule' })}</strong>
          <span class="source-path mono">{preview.source.path}</span>
        </div>
        <button type="button" class="link" onclick={pickFolder} disabled={staging}>
          {m.emule_import_choose_other()}
        </button>
      </div>
      <ul class="stats">
        {#if preview.known_files > 0}
          <li><span class="stat-value">{preview.known_files}</span><span class="stat-label">{m.emule_import_stat_files()}</span></li>
        {/if}
        {#if preview.credits > 0}
          <li><span class="stat-value">{preview.credits}</span><span class="stat-label">{m.emule_import_credits_title()}</span></li>
        {/if}
        {#if preview.downloads.length > 0}
          <li><span class="stat-value">{preview.downloads.length}</span><span class="stat-label">{m.emule_import_stat_downloads()}</span></li>
        {/if}
        {#if preview.servers > 0}
          <li><span class="stat-value">{preview.servers}</span><span class="stat-label">{m.emule_import_stat_servers()}</span></li>
        {/if}
        {#if preview.identity}
          <li><span class="stat-value" aria-hidden="true">✓</span><span class="stat-label">{m.emule_import_stat_identity()}</span></li>
        {/if}
      </ul>
    </div>
    {/if}

    {#if emuleRunning && mode === 'wizard'}
      {@render runningNotice(preview)}
    {/if}

    {#if mode === 'wizard'}
      <div class="choices" role="radiogroup" aria-label={m.wizard_import_title()}>
        <button
          type="button"
          role="radio"
          class="choice"
          class:selected={importChosen}
          aria-checked={importChosen}
          data-autofocus={importChosen ? '' : undefined}
          onclick={() => setChoice(true)}
        >
          <strong>{m.emule_import_choice_import()}</strong>
          <span>{m.emule_import_choice_import_desc()}</span>
        </button>
        <button
          type="button"
          role="radio"
          class="choice"
          class:selected={!importChosen}
          aria-checked={!importChosen}
          data-autofocus={importChosen ? undefined : ''}
          onclick={() => setChoice(false)}
        >
          <strong>{m.emule_import_choice_fresh()}</strong>
          <span>{m.emule_import_choice_fresh_desc()}</span>
        </button>
      </div>
      {#if importChosen}
        <details class="customize">
          <summary>{m.emule_import_customize()}</summary>
          {@render checklist(preview)}
        </details>
      {/if}
    {:else}
      {@render checklist(preview)}
      <div class="group">
        <div class="action-row">
          <button type="button" class="action-btn primary" onclick={stageNow} disabled={staging || reading}>
            {staging ? progressText : m.emule_import_start()}
          </button>
          {#if !emuleRunning}
            <span class="hint">{m.emule_import_close_emule()}</span>
          {/if}
        </div>
      </div>
    {/if}
  {/if}

  {#if mode === 'settings' && report}
    <div class="group">
      <h4 class="subsection-title">
        {m.emule_import_report_heading({ when: new Date(report.applied_at * 1000).toLocaleString() })}
      </h4>
      <ul class="item-list">
        {#each report.items as item (item.kind)}
          <li class="report-row">
            <span class="item-name">{reportLabel(item.kind)}</span>
            <span class="item-meta" class:failed={!item.ok}>{reportOutcome(item)}</span>
          </li>
        {/each}
      </ul>
    </div>
  {/if}
</div>

<style>
  /* Sizes and spacing follow the Settings page's own sections (`.settings-group`,
     `.toggle-row`, `.folder-input`, `.action-btn`), which cannot reach inside
     a component, so that this card reads as one of them. */
  .emule-import {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .emule-import.settings {
    gap: 18px;
  }
  .hint {
    display: block;
    margin: 0;
    font-size: 11px;
    line-height: 1.5;
    color: var(--text-muted);
  }
  .warn {
    color: var(--warning);
  }
  .error {
    margin: 0;
    font-size: 12px;
    color: var(--danger);
  }
  .mono {
    font-family: var(--font-mono, monospace);
    word-break: break-all;
  }

  .group {
    display: flex;
    flex-direction: column;
    gap: 18px;
  }
  .group + .group {
    border-top: 1px solid color-mix(in srgb, var(--border) 60%, transparent);
    margin-top: 2px;
    padding-top: 20px;
  }
  .subsection-title {
    margin: 0 0 -7px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-secondary);
  }
  .row {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .row-label {
    font-size: 13px;
    font-weight: 500;
    color: var(--text-secondary);
  }

  .toggle-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }
  .toggle-row.disabled {
    opacity: 0.6;
  }
  .toggle-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .toggle-title {
    font-size: 13px;
    font-weight: 500;
    line-height: 1.4;
    color: var(--text-primary);
  }

  .item-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .item-list li {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
  }
  .item-list li.disabled {
    opacity: 0.6;
  }
  .item-list label {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 7px 10px;
    cursor: pointer;
  }
  .item-list li.disabled label {
    cursor: default;
  }
  .item-list input {
    margin: 2px 0 0;
    flex-shrink: 0;
  }
  .item-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .item-name {
    font-size: 13px;
    color: var(--text-primary);
    overflow-wrap: anywhere;
  }
  .item-name.mono {
    font-size: 12px;
  }
  .item-meta {
    font-size: 11.5px;
    color: var(--text-muted);
  }
  .item-meta.warn {
    color: var(--warning);
  }
  .item-meta.failed {
    color: var(--danger);
  }
  .report-row {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    padding: 7px 10px;
  }
  .report-row .item-meta {
    text-align: right;
  }

  .folder-input {
    display: flex;
    align-items: stretch;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    overflow: hidden;
    background: var(--bg-input);
  }
  .folder-input input {
    flex: 1;
    min-width: 0;
    border: none;
    background: transparent;
    padding: 7px 10px;
    font-size: 13px;
    color: var(--text-primary);
    outline: none;
    box-shadow: none;
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
    white-space: nowrap;
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
  }
  .folder-btn:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--accent);
  }

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
    white-space: nowrap;
    transition: background 0.15s, color 0.15s, border-color 0.15s;
  }
  .action-btn:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--accent);
    border-color: var(--accent);
  }
  .action-btn.primary {
    background: var(--accent);
    color: var(--on-accent);
    border-color: var(--accent);
  }
  .action-btn.primary:hover:not(:disabled) {
    filter: brightness(1.06);
    color: var(--on-accent);
  }
  .action-btn.danger {
    background: var(--danger);
    color: var(--on-danger);
    border-color: var(--danger);
  }
  .action-btn.danger:hover:not(:disabled) {
    background: var(--danger-hover);
    border-color: var(--danger-hover);
    color: var(--on-danger);
  }
  .action-btn:disabled {
    opacity: 0.55;
    cursor: not-allowed;
  }

  /* The pending-restore box in Backup, for the same kind of message. */
  .notice {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px 14px;
    border: 1px solid color-mix(in srgb, var(--warning) 40%, var(--border));
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--warning) 8%, var(--bg-surface));
  }
  .notice.running {
    flex-direction: row;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .notice-copy {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }
  .notice-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .sources {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
  }
  .source {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 2px;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
    color: var(--text-primary);
    cursor: pointer;
    text-align: left;
  }
  .source.selected {
    border-color: var(--accent);
  }
  .source-client {
    font-weight: 600;
  }
  .source-path {
    display: block;
    font-size: 0.8em;
    color: var(--text-muted);
  }
  .found {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
  }
  .found-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
  }
  .found-head > div {
    min-width: 0;
  }
  button.link {
    flex-shrink: 0;
    padding: 0;
    border: none;
    background: none;
    color: var(--accent);
    font-size: 0.85em;
    cursor: pointer;
  }
  button.link:hover:not(:disabled) {
    text-decoration: underline;
  }
  .stats {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 18px;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .stats li {
    display: flex;
    flex-direction: column;
  }
  .stat-value {
    font-size: 1.15em;
    font-weight: 700;
    color: var(--text-primary);
  }
  .stat-label {
    font-size: 0.8em;
    color: var(--text-muted);
  }
  .choices {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }
  .choice {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
    color: var(--text-primary);
    text-align: left;
    cursor: pointer;
  }
  .choice span {
    color: var(--text-muted);
    font-size: 0.85em;
  }
  .choice.selected {
    border-color: var(--accent);
    box-shadow: 0 0 0 1px var(--accent);
  }
  .customize summary {
    cursor: pointer;
    color: var(--accent);
    font-size: 0.9em;
  }
  .customize[open] summary {
    margin-bottom: 10px;
  }
  @media (max-width: 520px) {
    .choices {
      grid-template-columns: 1fr;
    }
    .notice.running {
      flex-direction: column;
      align-items: flex-start;
    }
  }
</style>
