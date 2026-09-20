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

export interface BlockedInfo {
  user_hash: string;
  /** Last known name, copied out of the friend or request row before
   *  blocking deleted it. Empty if none was ever recorded. */
  nickname: string;
  blocked_at: number;
}

export interface FriendRequestInfo {
  sender_hash: string;
  sender_nickname: string;
  received_at: number;
  /**
   * True iff the peer's identity passed cryptographic
   * verification on the session this request arrived on. The
   * exact strength depends on the originating session type:
   *
   *  - Friend-connect dial-back (the path that fires when the
   *    user accepts a request and the app dials the peer for
   *    a dedicated friend session): full Ed25519 proof of
   *    possession via `friend_connect::perform_ember_auth`.
   *  - Regular upload / multi-source download session: offline
   *    BLAKE3 identity-binding check — the peer's advertised
   *    pubkey matches their advertised hash, but we did not
   *    challenge them to sign a fresh nonce on this session.
   *
   * False means the peer didn't advertise an Ed25519 pubkey
   * (older Ember release, or the single-source transfer.rs
   * download path), the binding check failed, or the
   * challenge-response failed. Either way the Friends page
   * shows an "Unverified" badge and users should only accept
   * if they recognise the requester.
   */
  verified: boolean;
}

/**
 * Delivery state of an outbound message. Received messages are always
 * `delivered`; only messages we sent can be waiting or abandoned.
 */
export type ChatDelivery = 'delivered' | 'queued' | 'failed';

export interface ChatMessage {
  id: number;
  direction: 'sent' | 'received';
  message: string;
  timestamp: number;
  read: boolean;
  delivery: ChatDelivery;
  /** The friend has opened this outbound message. Incoming rows are false. */
  seen?: boolean;
}

export interface ChatSendResult {
  delivery: ChatDelivery;
  /** Durable row id for queued sends; null when the message was delivered live. */
  id: number | null;
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

/** Remove them and refuse anything further from that identity. Unlike
 *  `removeFriend`, the decision survives: they cannot request their way
 *  back in. Deletes the chat history, same as removal. */
export async function blockFriend(userHashHex: string): Promise<void> {
  return invoke('block_friend', { userHashHex });
}

/** Lift a block. Does not restore the friendship — the two have to add
 *  each other again. */
export async function unblockFriend(userHashHex: string): Promise<void> {
  return invoke('unblock_friend', { userHashHex });
}

export async function getBlockedFriends(): Promise<BlockedInfo[]> {
  return invoke('get_blocked_friends');
}

/** True when chat history is sealed because its encryption key could not be
 *  recovered. Everything else in the app works; conversations read as
 *  unavailable and sending fails until the key file is restored. */
export async function isChatLocked(): Promise<boolean> {
  return invoke('is_chat_locked');
}

export async function updateFriendNickname(userHashHex: string, nickname: string): Promise<void> {
  return invoke('update_friend_nickname', { userHashHex, nickname });
}

export async function getMyEmberHash(): Promise<string> {
  return invoke('get_my_ember_hash');
}

/**
 * Send a message. Resolves with `queued` rather than rejecting when the friend
 * is unreachable — the message is stored and flushed on the next session.
 */
export async function sendChatMessage(
  userHashHex: string,
  message: string,
): Promise<ChatSendResult> {
  return invoke('send_chat_message', { userHashHex, message });
}

export async function getChatMessages(friendHash: string, limit?: number, beforeId?: number): Promise<ChatMessage[]> {
  return invoke('get_chat_messages', { friendHash, limit: limit ?? 50, beforeId: beforeId ?? null });
}

export async function markMessagesRead(friendHash: string): Promise<void> {
  return invoke('mark_messages_read', { friendHash });
}

/** Live composing signal. Resolves even if the friend is offline — the packet is dropped. */
export async function sendChatTyping(userHashHex: string, typing: boolean): Promise<void> {
  return invoke('send_chat_typing', { userHashHex, typing });
}

export async function getUnreadMessageCounts(): Promise<[string, number][]> {
  return invoke('get_unread_message_counts');
}

/** Per-friend count of outbound messages still waiting for a session. */
export async function getPendingChatCounts(): Promise<Record<string, number>> {
  return invoke('get_pending_chat_counts');
}

/**
 * Offer one of our shared files to a friend. Sends an invitation only — the
 * friend chooses whether to download it.
 */
export async function offerFileToFriend(userHashHex: string, fileHash: string): Promise<void> {
  return invoke('offer_file_to_friend', { userHashHex, fileHash });
}

/** Payload of the `ember:file-offer` event. */
export interface IncomingFileOffer {
  user_hash: string;
  file_hash: string;
  file_name: string;
  file_size: number;
  ember_file_hash?: string;
}

export async function retryFriendSearch(userHashHex: string): Promise<void> {
  return invoke('retry_friend_search', { userHashHex });
}

export async function isFriendDiscoverable(): Promise<boolean> {
  return invoke('is_friend_discoverable');
}

/** Hex hashes of friends the backend currently considers online. Used to seed
 *  the online set at startup so friends don't all show offline until the next
 *  `ember:friend-online` transition. */
export async function getOnlineFriends(): Promise<string[]> {
  return invoke('get_online_friends');
}

export async function browseFriend(
  userHashHex: string,
  requestId: string,
): Promise<void> {
  return invoke('browse_friend', { userHashHex, requestId });
}

export async function cancelBrowseFriend(
  userHashHex: string,
  requestId: string,
): Promise<void> {
  return invoke('cancel_browse_friend', { userHashHex, requestId });
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
  /** Optional 40-char hex AICH root when the peer includes it. */
  aich_hash?: string;
  /** Optional 64-char hex BLAKE3 digest when the peer includes it. */
  ember_file_hash?: string;
}
