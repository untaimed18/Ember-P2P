import { invoke } from '@tauri-apps/api/core';
import * as m from '$lib/paraglide/messages';

/** An eMule or aMule folder the backend found or the user picked. `id` is what
 *  every later call names it by; the path is for display only. */
export interface EmuleInstall {
  id: number;
  path: string;
  client: 'emule' | 'amule';
}

export type EmuleFolderStatus =
  | 'ready'
  | 'drive_root'
  | 'refused'
  | 'missing'
  | 'covered'
  | 'already_shared'
  | 'contains_shared';

export interface EmuleSharedFolder {
  path: string;
  status: EmuleFolderStatus;
  /** Subfolders Ember shares that eMule did not: eMule shares exactly the
   *  listed folders, Ember a folder and everything in it. */
  newly_shared_subfolders: number;
  subfolder_count_capped: boolean;
}

export type EmuleDownloadStatus =
  | 'ready'
  | 'missing_data'
  | 'already_downloading'
  | 'already_have'
  | 'in_use';

export interface EmuleDownload {
  name: string;
  size: number;
  done: number;
  paused: boolean;
  status: EmuleDownloadStatus;
  /** Size of the `.part` on disk, which a copy writes in full. */
  part_bytes: number;
  /** Same volume as the target, so it is moved rather than copied; `null`
   *  when that could not be told. */
  same_volume_as_download_folder: boolean | null;
  same_volume_as_incoming: boolean | null;
}

export interface EmulePreview {
  token: number;
  source: EmuleInstall;
  nickname: string | null;
  tcp_port: number | null;
  udp_port: number | null;
  incoming_dir: string | null;
  /** Bytes per second, 0 for unlimited. */
  max_upload: number | null;
  max_download: number | null;
  identity: boolean;
  credits: number;
  expired_credits: number;
  known_files: number;
  known2_sets: number;
  known2_bytes: number;
  shared_folders: EmuleSharedFolder[];
  downloads: EmuleDownload[];
  servers: number;
  nodes: number;
  ipfilter: boolean;
  /** Free bytes where copied downloads and the staged hash sets would go. */
  free_download_folder: number | null;
  free_incoming: number | null;
  free_data_dir: number | null;
}

/** What to import. Folders and downloads are indices into the preview. */
export interface EmuleImportSelection {
  token: number;
  preferences: boolean;
  incoming_as_download_folder: boolean;
  library: boolean;
  shared_folders: number[];
  identity: boolean;
  credits: boolean;
  downloads: number[];
  servers: boolean;
  nodes: boolean;
  ipfilter: boolean;
}

export interface EmuleStageSummary {
  shared_folders: number;
  downloads: number;
  copied_downloads: number;
  identity: boolean;
  credits: number;
  known_files: number;
  known2_sets: number;
  restart_required: boolean;
}

/** Payload of `emule-import-progress` while staging copies. */
export interface EmuleStageProgress {
  phase: 'known2' | 'downloads';
  done: number;
  total: number;
}

export interface EmuleImportReportItem {
  kind: string;
  ok: boolean;
  count: number;
  detail: string | null;
}

export interface EmuleImportReport {
  applied_at: number;
  source_dir: string;
  items: EmuleImportReportItem[];
  seen: boolean;
}

export async function detectEmuleInstalls(): Promise<EmuleInstall[]> {
  return invoke('detect_emule_installs');
}

/** Native folder picker; `null` when cancelled. */
export async function pickEmuleFolder(): Promise<EmuleInstall | null> {
  return invoke('pick_emule_folder', { title: m.picker_emule_folder() });
}

export async function previewEmuleImport(sourceId: number): Promise<EmulePreview> {
  return invoke('preview_emule_import', { sourceId });
}

/** Converts and places the selection for the next launch. Can take minutes on
 *  a large library, so no timeout; progress arrives as events. */
export async function stageEmuleImport(selection: EmuleImportSelection): Promise<EmuleStageSummary> {
  return invoke('stage_emule_import', { selection });
}

export async function discardEmuleImport(): Promise<void> {
  return invoke('discard_emule_import');
}

export async function pendingEmuleImport(): Promise<boolean> {
  return invoke('pending_emule_import');
}

export async function getEmuleImportReport(markSeen: boolean): Promise<EmuleImportReport | null> {
  return invoke('get_emule_import_report', { markSeen });
}
