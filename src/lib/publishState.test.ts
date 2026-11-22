import { describe, expect, it } from 'vitest';
import { unpublishedReason } from './publishState';

const none = { kad: false, server: false, ember: false };

describe('unpublishedReason', () => {
  it('names friends-only first: such a file is never published', () => {
    expect(unpublishedReason(true, { kad: true, server: true, ember: true })).toBe('friends_only');
    expect(unpublishedReason(true, none)).toBe('friends_only');
  });

  it('waits for a network while none is connected', () => {
    expect(unpublishedReason(false, none)).toBe('offline');
  });

  it('is on its way once any network is connected', () => {
    for (const network of ['kad', 'server', 'ember'] as const) {
      expect(unpublishedReason(false, { ...none, [network]: true })).toBe('publishing');
    }
  });
});
