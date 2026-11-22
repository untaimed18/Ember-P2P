import { invoke } from '@tauri-apps/api/core';
import * as m from '$lib/paraglide/messages';
import { isServer } from '$lib/runtime';

/*
 * Room libraries: folders a member keeps for one private room alone, which
 * the room's other members may browse and fetch from while it is open. They
 * are never shared on eD2K, KAD or Ember. A fetched file arrives as a room
 * transfer, in the room's transfer list.
 */

/** What the user's own library for a room holds, as its last walk found. */
export interface RoomLibraryStats {
  files: number;
  folders: number;
  bytes: number;
  /** Files left out for being over what a room transfer carries. */
  too_large: number;
  /** The walk stopped at its cap. */
  truncated: boolean;
  /** Library folders that could not be read. */
  unreadable: string[];
}

export interface RoomLibraryInfo {
  open: boolean;
  folders: string[];
  stats: RoomLibraryStats;
}

/** One row of a member's library. */
export interface RoomLibraryEntry {
  id: string;
  is_folder: boolean;
  name: string;
  size: number;
  /** How many folders and files a folder holds. */
  items: number;
  /** Unix seconds; 0 when unknown. */
  modified: number;
  /** For a search result, the folder it is in. */
  folder: string;
  risky: boolean;
}

export interface RoomLibraryPage {
  /** Their library is not open to this room. */
  closed: boolean;
  /** The folder is no longer in it. */
  missing: boolean;
  total: number;
  offset: number;
  entries: RoomLibraryEntry[];
}

/** A member's library opened or closed: `{ channel_id, member_pubkey, open }`. */
export const ROOM_LIBRARY_EVENT = 'ember:room-library';
/** A fetched file could not be taken in: `{ xfer_id, channel_id, error }`. */
export const ROOM_LIBRARY_ERROR_EVENT = 'ember:room-library-error';

export async function getRoomLibrary(channelId: string): Promise<RoomLibraryInfo> {
  return invoke('get_room_library', { channelId });
}

export async function setRoomLibraryOpen(channelId: string, open: boolean): Promise<RoomLibraryInfo> {
  return invoke('set_room_library_open', { channelId, open });
}

/** Add a folder to the room's library. The desktop app picks it in the
 *  system's folder dialog, since picking it is what allows it to be read;
 *  `null` means the dialog was dismissed. emberd takes a folder on the
 *  server, typed in. */
export async function addRoomLibraryFolder(
  channelId: string,
  serverPath?: string,
): Promise<RoomLibraryInfo | null> {
  if (isServer) {
    return invoke('add_room_library_folder_path', { channelId, path: serverPath ?? '' });
  }
  return invoke('pick_room_library_folder', { channelId, title: m.channels_library_pick_folder() });
}

export async function removeRoomLibraryFolder(channelId: string, path: string): Promise<RoomLibraryInfo> {
  return invoke('remove_room_library_folder', { channelId, path });
}

/** Members whose libraries are open to the room, by member key. */
export async function listRoomLibraryMembers(channelId: string): Promise<string[]> {
  return invoke('list_room_library_members', { channelId });
}

/** A page of a member's library: a folder's, the top's when `folder` is
 *  null, or with a query, the matching files anywhere in it. */
export async function browseRoomLibrary(
  channelId: string,
  memberPubkey: string,
  folder: string | null,
  query: string,
  offset: number,
): Promise<RoomLibraryPage> {
  return invoke('browse_room_library', { channelId, memberPubkey, folder, query, offset });
}

/** Fetch a file from a member's library. Returns the id of the room transfer
 *  it arrives as. */
export async function fetchRoomLibraryFile(
  channelId: string,
  memberPubkey: string,
  entry: RoomLibraryEntry,
): Promise<string> {
  return invoke('fetch_room_library_file', {
    channelId,
    memberPubkey,
    entryId: entry.id,
    name: entry.name,
    size: entry.size,
  });
}
