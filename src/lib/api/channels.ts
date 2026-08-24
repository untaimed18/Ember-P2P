import { invoke } from '@tauri-apps/api/core';

export interface ChannelInfo {
  channel_id: string;
  pubkey: string;
  name: string;
  visibility: 'public' | 'private' | string;
  is_owner: boolean;
  topic: string;
  welcome: string;
  joined_at: number;
  last_active: number;
  member_count: number;
  unread: number;
  you_are_banned: boolean;
  you_are_moderator: boolean;
  successor_id: string;
  predecessor_id: string;
  successor_nominee: string;
  claim_after_days: number;
  /** When the owner last republished; the claim window counts from here. */
  moderation_updated_at: number;
  /** This device is the nominee and the owner has been silent past the window. */
  can_claim: boolean;
  /** The room's key has rotated past what we hold, so new messages are unreadable. */
  key_behind: boolean;
}

export interface ChannelMemberInfo {
  member_pubkey: string;
  nickname: string;
  last_seen: number;
  banned: boolean;
  is_self: boolean;
  moderator: boolean;
}

export interface ChannelMessageInfo {
  id: number;
  sender_pubkey: string;
  direction: 'sent' | 'received' | string;
  message: string;
  timestamp: number;
  read: boolean;
}

export interface ChannelInviteInfo {
  uri: string;
  channel_id: string;
  name: string;
  private: boolean;
}

export interface GatheredChannelInfo {
  channel_id: string;
  pubkey: string;
  name: string;
  private: boolean;
  joined: boolean;
}

export async function listChannels(): Promise<ChannelInfo[]> {
  return invoke('list_channels');
}

export async function createChannel(name: string, privateChannel: boolean): Promise<ChannelInviteInfo> {
  return invoke('create_channel', { name, private: privateChannel });
}

export async function joinChannel(uri: string): Promise<ChannelInfo> {
  return invoke('join_channel', { uri });
}

export async function leaveChannel(channelId: string): Promise<void> {
  return invoke('leave_channel', { channelId });
}

export async function getChannelInvite(channelId: string): Promise<ChannelInviteInfo> {
  return invoke('get_channel_invite', { channelId });
}

export async function listChannelMembers(channelId: string): Promise<ChannelMemberInfo[]> {
  return invoke('list_channel_members', { channelId });
}

export async function getChannelMessages(
  channelId: string,
  limit?: number,
  beforeId?: number,
): Promise<ChannelMessageInfo[]> {
  return invoke('get_channel_messages', {
    channelId,
    limit: limit ?? 50,
    beforeId: beforeId ?? null,
  });
}

export async function sendChannelMessage(
  channelId: string,
  message: string,
): Promise<ChannelMessageInfo> {
  return invoke('send_channel_message', { channelId, message });
}

export async function markChannelMessagesRead(channelId: string): Promise<void> {
  return invoke('mark_channel_messages_read', { channelId });
}

/** Substring search over this device's stored history for one room. Local
 *  only — nothing is asked of the network. */
export async function searchChannelMessages(
  channelId: string,
  query: string,
  limit?: number,
): Promise<ChannelMessageInfo[]> {
  return invoke('search_channel_messages', { channelId, query, limit: limit ?? 50 });
}

/** Remove one message from this device. Does not propagate: the protocol has
 *  no redaction, so every other member keeps their copy. */
export async function deleteChannelMessage(
  channelId: string,
  messageId: number,
): Promise<void> {
  return invoke('delete_channel_message', { channelId, messageId });
}

export async function gatherChannels(): Promise<GatheredChannelInfo[]> {
  return invoke('gather_channels');
}

export async function updateChannelModeration(
  channelId: string,
  topic: string,
  welcome: string,
): Promise<ChannelInfo> {
  return invoke('update_channel_moderation', { channelId, topic, welcome });
}

export async function banChannelMember(channelId: string, memberPubkey: string): Promise<void> {
  return invoke('ban_channel_member', { channelId, memberPubkey });
}

export async function unbanChannelMember(channelId: string, memberPubkey: string): Promise<void> {
  return invoke('unban_channel_member', { channelId, memberPubkey });
}

export async function addChannelModerator(channelId: string, memberPubkey: string): Promise<void> {
  return invoke('add_channel_moderator', { channelId, memberPubkey });
}

export async function removeChannelModerator(channelId: string, memberPubkey: string): Promise<void> {
  return invoke('remove_channel_moderator', { channelId, memberPubkey });
}

export async function transferChannelOwnership(
  channelId: string,
  memberPubkey: string,
): Promise<void> {
  return invoke('transfer_channel_ownership', { channelId, memberPubkey });
}

export async function setChannelSuccessorNominee(
  channelId: string,
  memberPubkey: string | null,
  claimAfterDays: number | null,
): Promise<ChannelInfo> {
  return invoke('set_channel_successor_nominee', { channelId, memberPubkey, claimAfterDays });
}

export async function claimChannelOwnership(channelId: string): Promise<ChannelInfo> {
  return invoke('claim_channel_ownership', { channelId });
}

/** `ember2:<hash>:<pubkey>` for a room member, ready to hand to `addFriend`.
 *  The hash is derived from the member's Ed25519 key on the backend, which is
 *  the one place that binding is implemented. */
export async function channelMemberFriendCode(memberPubkey: string): Promise<string> {
  return invoke('channel_member_friend_code', { memberPubkey });
}

/** Direction and stage of one Ember Transfer. `awaiting` is an offer sitting
 *  in front of the user; `offered` is one we sent and nobody has answered. */
export type ChannelTransferStatus =
  | 'offered'
  | 'awaiting'
  | 'accepted'
  | 'active'
  | 'complete'
  | 'declined'
  | 'cancelled'
  | 'stalled'
  | 'expired'
  | 'failed'
  | 'busy'
  | 'too_large'
  | 'not_allowed'
  | 'source_gone';

export interface ChannelTransferInfo {
  xfer_id: string;
  channel_id: string;
  peer_pubkey: string;
  direction: 'send' | 'receive';
  name: string;
  size: number;
  transferred: number;
  status: ChannelTransferStatus;
}

/** Offer one file to one member. Returns the transfer id. Nothing is sent
 *  until they accept. */
export async function offerChannelTransfer(
  channelId: string,
  memberPubkey: string,
  path: string,
): Promise<string> {
  return invoke('offer_channel_transfer', { channelId, memberPubkey, path });
}

export async function respondChannelTransfer(xferId: string, accept: boolean): Promise<void> {
  return invoke('respond_channel_transfer', { xferId, accept });
}

export async function cancelChannelTransfer(xferId: string): Promise<void> {
  return invoke('cancel_channel_transfer', { xferId });
}

export async function listChannelTransfers(): Promise<ChannelTransferInfo[]> {
  return invoke('list_channel_transfers');
}

