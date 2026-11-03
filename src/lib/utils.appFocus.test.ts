import { afterEach, describe, expect, it, vi } from 'vitest';
import { isAppFocused, isAppVisible } from '$lib/utils';

function stubDocument(visibilityState: 'visible' | 'hidden', focused: boolean) {
  vi.stubGlobal('document', { visibilityState, hasFocus: () => focused });
}

describe('isAppFocused', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('is true only when the window is visible and focused', () => {
    stubDocument('visible', true);
    expect(isAppFocused()).toBe(true);
  });

  it('is false for a window on screen behind another app', () => {
    stubDocument('visible', false);
    expect(isAppVisible()).toBe(true);
    expect(isAppFocused()).toBe(false);
  });

  it('is false for a hidden window', () => {
    stubDocument('hidden', true);
    expect(isAppFocused()).toBe(false);
  });

  it('falls back to visibility where focus cannot be asked', () => {
    vi.stubGlobal('document', { visibilityState: 'visible' });
    expect(isAppFocused()).toBe(true);
  });
});
