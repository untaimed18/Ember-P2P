import { invoke } from '@tauri-apps/api/core';

export interface FriendInfo {
  user_hash: string;
  nickname: string;
  added_at: number;
  last_ip: string;
  last_port: number;
  last_seen: number;
  mutual: boolean;
}

export interface FriendRequestInfo {
  sender_hash: string;
  sender_nickname: string;
  received_at: number;
  /**
   * True iff the peer's advertised Ed25519 public key
   * BLAKE3-bound to `sender_hash` at request-emit time
   * (the offline `verify_ember_hash_binding` check). The
   * Friends page surfaces this as a "Verified" badge so users
   * can distinguish requests over a binding-consistent channel
   * from peers that didn't advertise a pubkey or whose advertised
   * pubkey didn't match.
   *
   * NOTE: this is identity-binding only, not proof of
   * possession. An attacker who has observed the victim's pubkey
   * on the wire could replay it and pass this check; the full
   * Ed25519 challenge-response is FUTURE_WORK.md F2 Phase 2.
   * Even with a Verified badge, users should still only accept
   * friend requests from people they recognise.
   */
  verified: boolean;
}

export interface ChatMessage {
  id: number;
  direction: 'sent' | 'received';
  message: string;
  timestamp: number;
  read: boolean;
}

export async function getFriends(): Promise<FriendInfo[]> {
  return invoke('get_friends');
}

export async function addFriend(userHashHex: string, nickname?: string): Promise<void> {
  return invoke('add_friend', { userHashHex, nickname: nickname || null });
}

export async function removeFriend(userHashHex: string): Promise<void> {
  return invoke('remove_friend', { userHashHex });
}

export async function updateFriendNickname(userHashHex: string, nickname: string): Promise<void> {
  return invoke('update_friend_nickname', { userHashHex, nickname });
}

export async function getMyEmberHash(): Promise<string> {
  return invoke('get_my_ember_hash');
}

export async function sendChatMessage(userHashHex: string, message: string): Promise<void> {
  return invoke('send_chat_message', { userHashHex, message });
}

export async function getChatMessages(friendHash: string, limit?: number, beforeId?: number): Promise<ChatMessage[]> {
  return invoke('get_chat_messages', { friendHash, limit: limit ?? 50, beforeId: beforeId ?? null });
}

export async function markMessagesRead(friendHash: string): Promise<void> {
  return invoke('mark_messages_read', { friendHash });
}

export async function getUnreadMessageCounts(): Promise<[string, number][]> {
  return invoke('get_unread_message_counts');
}

export async function retryFriendSearch(userHashHex: string): Promise<void> {
  return invoke('retry_friend_search', { userHashHex });
}

export async function isFriendDiscoverable(): Promise<boolean> {
  return invoke('is_friend_discoverable');
}

export async function browseFriend(userHashHex: string): Promise<void> {
  return invoke('browse_friend', { userHashHex });
}

export async function getFriendRequests(): Promise<FriendRequestInfo[]> {
  return invoke('get_friend_requests');
}

export async function acceptFriendRequest(senderHash: string): Promise<void> {
  return invoke('accept_friend_request', { senderHash });
}

export async function rejectFriendRequest(senderHash: string): Promise<void> {
  return invoke('reject_friend_request', { senderHash });
}

export interface BrowseFileEntry {
  hash: string;
  size: number;
  name: string;
}
