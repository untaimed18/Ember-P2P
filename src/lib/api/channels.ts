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
  /** Owner's user pubkey, empty until a signed moderation record naming them arrives. */
  owner_pubkey: string;
  /** This device is currently inside the room. */
  in_room: boolean;
  /** Owner has permanently deleted this room. */
  deleted: boolean;
  /** Only the owner may hand out invites. A guard against a careless re-share,
   *  not against a member who patches their client — they hold the key too. */
  invites_owner_only: boolean;
  /** Seconds a member must wait between messages; 0 when slow mode is off. */
  slow_mode_secs: number;
}

/** Slow-mode delays an owner can pick, mirroring `SLOW_MODE_CHOICES` in
 *  `src-tauri/src/commands/channels.rs`. The backend refuses anything else, so
 *  the two lists have to agree. */
export const SLOW_MODE_CHOICES = [0, 5, 10, 30, 60, 300] as const;

export interface ChannelMemberInfo {
  member_pubkey: string;
  nickname: string;
  last_seen: number;
  banned: boolean;
  is_self: boolean;
  moderator: boolean;
}

/** The windows the roster's presence dots are drawn with.
 *
 *  Read from the backend rather than declared here. The same numbers decide
 *  which members this device gossips to, so a copy in the UI is one that can
 *  drift from the one the protocol runs on. */
export interface ChannelPresenceConfig {
  /** Heard from on the live mesh within this many seconds: online. */
  mesh_fresh_secs: number;
  /** Heard from by any means within this many seconds: recently here. */
  dht_fresh_secs: number;
  /** How often a member announces itself. */
  beat_secs: number;
}

/** Payload of `ember:channel-presence`: rows whose `last_seen` moved.
 *
 *  Distinct from `ember:channel-members`, which means the roster changed shape
 *  and costs a full re-read. Presence moves far more often than membership
 *  does, so it travels as a delta. */
export interface ChannelPresenceDelta {
  channel_id: string;
  members: { member_pubkey: string; last_seen: number }[];
}

export interface ChannelMessageInfo {
  id: number;
  sender_pubkey: string;
  direction: 'sent' | 'received' | string;
  message: string;
  timestamp: number;
  read: boolean;
  /** When the author last revised this line, or 0 if they never did. */
  edited_at: number;
  /**
   * Wire identity of the line, shared by every member. Reactions and edits
   * arriving from the network name a message this way — the local row id is
   * meaningless to the peer that sent it — so the UI needs this to match them up.
   */
  msg_id: string;
}

/** Wire values for a reaction. `None` withdraws one. */
export const REACTION_NONE = 0;
export const REACTION_UP = 1;
export const REACTION_DOWN = 2;
export const REACTION_HEART = 3;

/** Reaction tally for one line, counted by the backend. */
export interface ChannelReactionInfo {
  msg_id: string;
  up: number;
  down: number;
  heart: number;
  /** This device's own reaction, so its button can show as pressed. 0 is none. */
  mine: number;
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
  /** Members announcing themselves right now, or null when we could not find
   *  out. A confirmed 0 is not the same as an unanswered probe. */
  member_count: number | null;
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

export async function enterChannel(channelId: string): Promise<ChannelInfo> {
  return invoke('enter_channel', { channelId });
}

export async function leaveChannel(channelId: string): Promise<void> {
  return invoke('leave_channel', { channelId });
}

/** Drop a room we have left off this device, along with its saved messages. */
export async function forgetChannel(channelId: string): Promise<void> {
  return invoke('forget_channel', { channelId });
}

export const CHANNEL_USERNAME_MIN = 2;
export const CHANNEL_USERNAME_MAX = 12;

/** Letters and numbers only; keeps the typed casing. */
export function sanitizeChannelUsernameInput(raw: string): string {
  return raw.replace(/[^A-Za-z0-9]/g, '').slice(0, CHANNEL_USERNAME_MAX);
}

export function isValidChannelUsername(raw: string): boolean {
  const trimmed = raw.trim();
  return (
    trimmed.length >= CHANNEL_USERNAME_MIN &&
    trimmed.length <= CHANNEL_USERNAME_MAX &&
    /^[A-Za-z0-9]+$/.test(trimmed) &&
    trimmed.toLowerCase() !== 'anonymous'
  );
}

export async function claimChannelUsername(name: string): Promise<string> {
  return invoke('claim_channel_username', { name });
}

export async function deleteOwnedChannel(channelId: string): Promise<void> {
  return invoke('delete_owned_channel', { channelId });
}

export async function getChannelInvite(channelId: string): Promise<ChannelInviteInfo> {
  return invoke('get_channel_invite', { channelId });
}

export async function listChannelMembers(channelId: string): Promise<ChannelMemberInfo[]> {
  return invoke('list_channel_members', { channelId });
}

export async function channelPresenceConfig(): Promise<ChannelPresenceConfig> {
  return invoke('channel_presence_config');
}

/** Name the room on screen so the backend walks its presence at the rate
 *  somebody watching it would expect. `null` when no room is open. */
export async function setChannelFocus(channelId: string | null): Promise<void> {
  return invoke('set_channel_focus', { channelId });
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

/**
 * Revise one of your own messages. Unlike deleting, this *does* propagate: the
 * revision is signed and flooded, and every member checks for themselves that it
 * came from the line's author and arrived inside the edit window.
 *
 * Members who were offline get it on their next catch-up. One who has had the
 * original on screen past the window will keep showing what they were sent —
 * there is no arbiter of time in a room, so refusing is the safe side.
 */
export async function editChannelMessage(
  channelId: string,
  messageId: number,
  message: string,
): Promise<ChannelMessageInfo> {
  return invoke('edit_channel_message', { channelId, messageId, message });
}

/** Set or withdraw this device's reaction to a message. */
export async function setChannelMessageReaction(
  channelId: string,
  messageId: number,
  reaction: number,
): Promise<void> {
  return invoke('set_channel_message_reaction', { channelId, messageId, reaction });
}

/** Every live reaction tally in a room, in one read rather than one per bubble. */
export async function getChannelReactions(
  channelId: string,
): Promise<ChannelReactionInfo[]> {
  return invoke('get_channel_reactions', { channelId });
}

/** Walk the public index. Each shard is also emitted on `ember:channels-found`
 *  as it lands, so a caller can fill the list in rather than wait for the
 *  slowest walk; the resolved value is still the complete set.
 *
 *  `walk` is echoed on every one of those events. Shards from a finished walk
 *  can still arrive after the next one has started, and without a token there is
 *  nothing to tell them apart — they merged into the newer walk's results as
 *  though just found. The caller names the walk because the events begin before
 *  this promise settles. */
export async function gatherChannels(walk: string): Promise<GatheredChannelInfo[]> {
  return invoke('gather_channels', { walk });
}

/** One `ember:channels-found` payload. */
export interface GatheredChannelBatch {
  walk: string;
  channels: GatheredChannelInfo[];
}

/** What the last walk found, from the local cache and without touching the
 *  network. Hints only — the walk that follows is what confirms them. */
export async function cachedChannels(): Promise<GatheredChannelInfo[]> {
  return invoke('cached_channels');
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

/** Mint a fresh content key for a private room. Every invite handed out before
 *  this stops working, which is the point — it is the remedy for a leaked
 *  link. Owner only, and meaningless on a public room. */
export async function rotateChannelRoomKey(channelId: string): Promise<ChannelInfo> {
  return invoke('rotate_channel_room_key', { channelId });
}

/** Owner only. Rides the signed moderation snapshot, so members learn it the
 *  same way they learn bans. */
export async function setChannelInvitePolicy(
  channelId: string,
  ownerOnly: boolean,
): Promise<ChannelInfo> {
  return invoke('set_channel_invite_policy', { channelId, ownerOnly });
}

/** Owner only. Seconds a member must wait between messages, 0 to turn it off.
 *  Rides the same signed snapshot as the invite policy above. */
export async function setChannelSlowMode(
  channelId: string,
  secs: number,
): Promise<ChannelInfo> {
  return invoke('set_channel_slow_mode', { channelId, secs });
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

