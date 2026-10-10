/**
 * Per-friend settings as the UI reads them: each answer is the friend's own
 * override when it has one, and the global setting otherwise. The same rules
 * as the `AppSettings` helpers in `src-tauri/src/types.rs`, which are what is
 * enforced; these only decide what the UI shows and offers.
 */
import type { AppSettings, FriendOverrides } from '$lib/types';

/** Highest per-friend auto-accept ceiling, in MB. Matches the global one. */
export const FRIEND_AUTO_ACCEPT_MAX_MB = 2048;

/** The backend's limit on a friend's name, in UTF-8 bytes. */
export const FRIEND_NAME_MAX_BYTES = 64;

/** Whether a name, as it will be saved, is over {@link FRIEND_NAME_MAX_BYTES}. */
export function friendNameTooLong(name: string): boolean {
  return new TextEncoder().encode(name.trim()).length > FRIEND_NAME_MAX_BYTES;
}

type Settings = AppSettings | null | undefined;

export function friendOverrides(settings: Settings, friendHash: string): FriendOverrides {
  return settings?.friend_overrides?.[friendHash.toLowerCase()] ?? {};
}

/** Chat with this friend, both ways. */
export function chatAllowedWith(settings: Settings, friendHash: string): boolean {
  return friendOverrides(settings, friendHash).chat ?? settings?.friend_chat_disabled !== true;
}

/** Files from this friend. Never while chat with them is off. */
export function filesAllowedFrom(settings: Settings, friendHash: string): boolean {
  return chatAllowedWith(settings, friendHash) && (friendOverrides(settings, friendHash).files ?? true);
}

/** The ceiling under which this friend's files download without asking, in MB. */
export function autoAcceptMbFor(settings: Settings, friendHash: string): number {
  const mb = friendOverrides(settings, friendHash).auto_accept_mb ?? settings?.chat_attachment_auto_accept_mb ?? 0;
  return Math.min(Math.max(0, mb), FRIEND_AUTO_ACCEPT_MAX_MB);
}

/** Whether this friend may browse our shared files. */
export function browseAllowedFor(settings: Settings, friendHash: string): boolean {
  return friendOverrides(settings, friendHash).browse ?? settings?.friend_browse_disabled !== true;
}

/** Read receipts with this friend, both ways. Never while chat is off. */
export function readReceiptsWith(settings: Settings, friendHash: string): boolean {
  return (
    chatAllowedWith(settings, friendHash) &&
    (friendOverrides(settings, friendHash).read_receipts ?? settings?.friend_chat_read_receipts !== false)
  );
}

/** Whether this friend's online, message and file notifications are wanted,
 *  before the master switch and the focus rule `shouldNotify` also applies. */
export function friendNotifies(
  settings: Settings,
  friendHash: string,
  kind: 'online' | 'messages',
): boolean {
  const own = friendOverrides(settings, friendHash);
  return kind === 'online'
    ? own.notify_online ?? settings?.notify_friend_online === true
    : own.notify_messages ?? settings?.notify_friend_message === true;
}

/** Overrides with nothing set removed, ready to save. */
export function compactOverrides(overrides: FriendOverrides): FriendOverrides {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(overrides)) {
    if (value !== undefined && value !== null) out[key] = value;
  }
  return out as FriendOverrides;
}
