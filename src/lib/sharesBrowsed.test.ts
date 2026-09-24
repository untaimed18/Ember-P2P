import { describe, expect, it } from 'vitest';
import {
  SHARES_BROWSED_TOAST_GAP_MS,
  cleanPeerName,
  describePeer,
  parseSharesBrowsed,
  sharesBrowsedToastDue,
} from './sharesBrowsed';

const FRIEND = '0123456789abcdef0123456789abcdef';
const noFriends = () => '';

describe('parseSharesBrowsed', () => {
  it('names an ed2k client by nickname, with address and client as details', () => {
    const notice = parseSharesBrowsed(
      {
        via: 'ed2k',
        allowed: true,
        peer_name: 'Luigi',
        peer_ip: '203.0.113.7',
        client_software: 'eMule v0.50a',
      },
      noFriends,
    );
    expect(notice).toMatchObject({ via: 'ed2k', allowed: true, name: 'Luigi' });
    expect(describePeer(notice!)).toBe('Luigi (203.0.113.7, eMule v0.50a)');
  });

  it('falls back to the address when the client announced no nickname', () => {
    const notice = parseSharesBrowsed(
      { via: 'ed2k', allowed: false, peer_name: '  ', peer_ip: '203.0.113.7', client_software: '' },
      noFriends,
    );
    expect(notice?.name).toBe('203.0.113.7');
    // The address is already the name, so it is not repeated as a detail.
    expect(describePeer(notice!)).toBe('203.0.113.7');
  });

  it('names a friend by their display name and shows no address', () => {
    const notice = parseSharesBrowsed(
      { via: 'friend', allowed: true, friend_hash: FRIEND.toUpperCase() },
      (hash) => (hash === FRIEND ? 'Ana' : ''),
    );
    expect(notice).toMatchObject({ via: 'friend', name: 'Ana', friendHash: FRIEND, details: '' });
    expect(describePeer(notice!)).toBe('Ana');
  });

  it('drops anything malformed rather than showing it half-filled', () => {
    expect(parseSharesBrowsed(null, noFriends)).toBeNull();
    expect(parseSharesBrowsed({ via: 'ed2k', allowed: true }, noFriends)).toBeNull();
    expect(
      parseSharesBrowsed({ via: 'ed2k', allowed: true, peer_ip: 'not an address' }, noFriends),
    ).toBeNull();
    expect(parseSharesBrowsed({ via: 'friend', allowed: true, friend_hash: 'zz' }, noFriends)).toBeNull();
    expect(parseSharesBrowsed({ via: 'ed2k', peer_ip: '203.0.113.7' }, noFriends)).toBeNull();
    expect(parseSharesBrowsed({ via: 'other', allowed: true }, noFriends)).toBeNull();
  });
});

describe('cleanPeerName', () => {
  it('keeps a remote nickname to one short line', () => {
    expect(cleanPeerName('evil\nname\u0007 here')).toBe('evil name here');
    const long = 'x'.repeat(200);
    const cleaned = cleanPeerName(long);
    expect(Array.from(cleaned)).toHaveLength(48);
    expect(cleaned.endsWith('\u2026')).toBe(true);
    expect(cleanPeerName(42)).toBe('');
  });
});

describe('sharesBrowsedToastDue', () => {
  it('spaces toasts out so a burst of browsers is one interruption', () => {
    expect(sharesBrowsedToastDue(0, 1_000_000)).toBe(true);
    expect(sharesBrowsedToastDue(1_000_000, 1_000_000 + SHARES_BROWSED_TOAST_GAP_MS - 1)).toBe(false);
    expect(sharesBrowsedToastDue(1_000_000, 1_000_000 + SHARES_BROWSED_TOAST_GAP_MS)).toBe(true);
  });
});
