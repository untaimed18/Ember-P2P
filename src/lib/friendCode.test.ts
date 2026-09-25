import { describe, expect, it } from 'vitest';
import {
  carriesIntroSecret,
  friendHashFromCode,
  isAcceptedFriendInput,
  isFriendPublicKey,
} from './friendCode';

const HASH = '0123456789abcdef0123456789abcdef';
const KEY = 'ab'.repeat(32);
const SECRET = 'c3'.repeat(16);

describe('friend code parsing', () => {
  it('reads the Friend ID from every form that names one', () => {
    expect(friendHashFromCode(`ember3:${HASH}:${KEY}:${SECRET}`)).toBe(HASH);
    expect(friendHashFromCode(`ember2:${HASH}:${KEY}`)).toBe(HASH);
    expect(friendHashFromCode(HASH)).toBe(HASH);
    expect(friendHashFromCode(`  EMBER3:${HASH.toUpperCase()}:${KEY}:${SECRET}  `)).toBe(HASH);
    expect(friendHashFromCode(`Ember2:${HASH}:${KEY}`)).toBe(HASH);
  });

  it('leaves a bare public key to the backend', () => {
    expect(friendHashFromCode(KEY)).toBeNull();
    expect(isFriendPublicKey(KEY)).toBe(true);
    expect(isAcceptedFriendInput(KEY)).toBe(true);
  });

  it('refuses malformed codes', () => {
    for (const bad of [
      '',
      'ember3:',
      `ember3:${HASH}:${KEY}`,
      `ember3:${HASH}:${KEY}:`,
      `ember3:${HASH}:${KEY}:${SECRET}:`,
      `ember3:${HASH}:${KEY}:${SECRET.slice(2)}`,
      `ember3:${HASH}:${KEY}:${'zz'.repeat(16)}`,
      `ember2:${HASH}:${KEY}:${SECRET}`,
      `ember2:${HASH}`,
      `ember4:${HASH}:${KEY}:${SECRET}`,
      HASH.slice(2),
      'zz'.repeat(16),
    ]) {
      expect(isAcceptedFriendInput(bad), bad).toBe(false);
    }
  });

  it('knows which forms carry an intro secret', () => {
    expect(carriesIntroSecret(`ember3:${HASH}:${KEY}:${SECRET}`)).toBe(true);
    expect(carriesIntroSecret(` Ember3:${HASH}:${KEY}:${SECRET} `)).toBe(true);
    expect(carriesIntroSecret(`ember2:${HASH}:${KEY}`)).toBe(false);
    expect(carriesIntroSecret(HASH)).toBe(false);
    expect(carriesIntroSecret(KEY)).toBe(false);
  });
});
