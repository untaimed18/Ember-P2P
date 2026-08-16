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
}

export interface ChannelMemberInfo {
  member_pubkey: string;
  nickname: string;
  last_seen: number;
  banned: boolean;
  is_self: boolean;
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
