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

export async function offerChannelFile(channelId: string, path: string): Promise<ChannelMessageInfo> {
  return invoke('offer_channel_file', { channelId, path });
}

export async function requestChannelFile(channelId: string, digest: string): Promise<void> {
  return invoke('request_channel_file', { channelId, digest });
}

export async function getChannelFile(
  channelId: string,
  digest: string,
): Promise<{ file_name: string; contents: number[] }> {
  return invoke('get_channel_file', { channelId, digest });
}

export async function saveChannelFile(
  channelId: string,
  digest: string,
  dest: string,
): Promise<void> {
  return invoke('save_channel_file', { channelId, digest, dest });
}
