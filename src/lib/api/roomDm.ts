import { invoke } from '@tauri-apps/api/core';

/** A private conversation with one room member. */
export interface RoomDmThread {
  member_pubkey: string;
  name: string;
  /** `request`: they wrote first and wait for an answer. `open`: talking.
   *  `declined`: refused, for a while. */
  state: 'request' | 'open' | 'declined';
  /** What they said to us: nothing yet, `accepted` or `declined`. */
  peer_state: '' | 'accepted' | 'declined';
  /** The room it goes through. */
  channel_id: string;
  updated_at: number;
  unread: number;
  last_text: string;
  last_at: number;
  /** A room both are still in carries it. */
  can_send: boolean;
  /** They are a friend: friend chat is the place to talk. */
  is_friend: boolean;
}

export interface RoomDmMessage {
  message_id: string;
  member_pubkey: string;
  direction: 'in' | 'out';
  text: string;
  timestamp: number;
  /** Ours: `sending`, `delivered`, `failed`. Theirs: `received`. */
  status: 'sending' | 'delivered' | 'failed' | 'received';
}

export const ROOM_DM_MESSAGE_EVENT = 'ember:dm-message';
export const ROOM_DM_STATUS_EVENT = 'ember:dm-status';
export const ROOM_DM_THREAD_EVENT = 'ember:dm-thread';

export interface RoomDmMessageEvent {
  member_pubkey: string;
  name: string;
  message_id: string;
  text: string;
  timestamp: number;
  request: boolean;
  new_thread: boolean;
}

export interface RoomDmStatusEvent {
  member_pubkey: string;
  message_id: string;
  status: RoomDmMessage['status'];
}

export function listRoomDmThreads(): Promise<RoomDmThread[]> {
  return invoke('list_room_dm_threads');
}

export function getRoomDmMessages(member: string, before?: number, limit?: number): Promise<RoomDmMessage[]> {
  return invoke('get_room_dm_messages', { member, before: before ?? null, limit: limit ?? null });
}

export function sendRoomDm(member: string, text: string): Promise<RoomDmMessage> {
  return invoke('send_room_dm', { member, text });
}

export function answerRoomDmRequest(member: string, accept: boolean): Promise<void> {
  return invoke('answer_room_dm_request', { member, accept });
}

export function markRoomDmRead(member: string): Promise<void> {
  return invoke('mark_room_dm_read', { member });
}

export function deleteRoomDmThread(member: string): Promise<void> {
  return invoke('delete_room_dm_thread', { member });
}

/** Remove someone's request here and send them nothing: for a member being
 *  ignored, who then sees their messages go undelivered. */
export function dropRoomDmRequest(member: string): Promise<void> {
  return invoke('drop_room_dm_request', { member });
}

export function retryRoomDm(member: string, messageId: string): Promise<void> {
  return invoke('retry_room_dm', { member, messageId });
}
