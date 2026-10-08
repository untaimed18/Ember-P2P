import { describe, expect, it } from 'vitest';
import type { AppSettings, FriendOverrides } from '$lib/types';
import {
  autoAcceptMbFor,
  browseAllowedFor,
  chatAllowedWith,
  compactOverrides,
  filesAllowedFrom,
  friendNotifies,
  friendOverrides,
  FRIEND_AUTO_ACCEPT_MAX_MB,
  readReceiptsWith,
} from './friendSettings';

const ANA = '0123456789abcdef0123456789abcdef';
const BEN = 'fedcba9876543210fedcba9876543210';

function settingsWith(
  patch: Partial<AppSettings> = {},
  overrides: Record<string, FriendOverrides> = {},
): AppSettings {
  return {
    friend_chat_disabled: false,
    friend_browse_disabled: false,
    friend_chat_read_receipts: true,
    chat_attachment_auto_accept_mb: 25,
    notify_friend_online: false,
    notify_friend_message: true,
    friend_overrides: overrides,
    ...patch,
  } as AppSettings;
}

describe('friend settings', () => {
  it('follows the global settings for a friend with no overrides', () => {
    const s = settingsWith({ friend_chat_disabled: true, friend_browse_disabled: true });
    expect(chatAllowedWith(s, ANA)).toBe(false);
    expect(filesAllowedFrom(s, ANA)).toBe(false);
    expect(readReceiptsWith(s, ANA)).toBe(false);
    expect(browseAllowedFor(s, ANA)).toBe(false);
    expect(autoAcceptMbFor(s, ANA)).toBe(25);
    expect(friendNotifies(s, ANA, 'online')).toBe(false);
    expect(friendNotifies(s, ANA, 'messages')).toBe(true);
  });

  it('lets one friend differ from the global settings either way', () => {
    const s = settingsWith(
      { friend_chat_disabled: true },
      { [ANA]: { chat: true, browse: false, notify_online: true, notify_messages: false } },
    );
    expect(chatAllowedWith(s, ANA)).toBe(true);
    expect(chatAllowedWith(s, BEN)).toBe(false);
    expect(browseAllowedFor(s, ANA)).toBe(false);
    expect(browseAllowedFor(s, BEN)).toBe(true);
    expect(friendNotifies(s, ANA, 'online')).toBe(true);
    expect(friendNotifies(s, ANA, 'messages')).toBe(false);
    expect(friendNotifies(s, BEN, 'messages')).toBe(true);
  });

  it('never allows files or read receipts while chat with the friend is off', () => {
    const s = settingsWith({}, { [ANA]: { chat: false, files: true, read_receipts: true } });
    expect(filesAllowedFrom(s, ANA)).toBe(false);
    expect(readReceiptsWith(s, ANA)).toBe(false);
  });

  it('turns files off for one friend without touching chat', () => {
    const s = settingsWith({}, { [ANA]: { files: false } });
    expect(chatAllowedWith(s, ANA)).toBe(true);
    expect(filesAllowedFrom(s, ANA)).toBe(false);
    expect(filesAllowedFrom(s, BEN)).toBe(true);
  });

  it('reads an auto-accept of 0 as always ask, and caps it like the global one', () => {
    expect(autoAcceptMbFor(settingsWith({}, { [ANA]: { auto_accept_mb: 0 } }), ANA)).toBe(0);
    expect(autoAcceptMbFor(settingsWith({}, { [ANA]: { auto_accept_mb: 1_000_000 } }), ANA)).toBe(
      FRIEND_AUTO_ACCEPT_MAX_MB,
    );
  });

  it('matches a friend however their hash is cased', () => {
    const s = settingsWith({}, { [ANA]: { chat: false } });
    expect(chatAllowedWith(s, ANA.toUpperCase())).toBe(false);
    expect(friendOverrides(s, ANA.toUpperCase())).toEqual({ chat: false });
  });

  it('answers safely before the settings have loaded', () => {
    expect(chatAllowedWith(null, ANA)).toBe(true);
    expect(friendNotifies(undefined, ANA, 'messages')).toBe(false);
    expect(autoAcceptMbFor(null, ANA)).toBe(0);
  });

  it('drops unset fields before saving, keeping false and 0', () => {
    expect(
      compactOverrides({ chat: undefined, files: false, auto_accept_mb: 0, browse: undefined }),
    ).toEqual({ files: false, auto_accept_mb: 0 });
    expect(compactOverrides({ chat: undefined })).toEqual({});
  });
});
