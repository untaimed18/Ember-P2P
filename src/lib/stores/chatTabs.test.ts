import { beforeEach, describe, expect, it } from 'vitest';
import {
  chatDockOpen,
  chatTabs,
  closeTab,
  getDraft,
  openChat,
  setDraft,
} from './chatTabs';

const FRIEND = 'aa'.repeat(16);
const ROOM = `ch:${'11'.repeat(16)}`;

beforeEach(() => {
  chatTabs.set([]);
  chatDockOpen.set(false);
  setDraft(FRIEND, '');
  setDraft(ROOM, '');
});

describe('setDraft', () => {
  it('keeps a channel draft even when no friend tab is open', () => {
    setDraft(ROOM, 'hello room');
    expect(getDraft(ROOM)).toBe('hello room');
  });

  it('drops a friend draft when that tab is not open', () => {
    setDraft(FRIEND, 'hello');
    expect(getDraft(FRIEND)).toBe('');
  });

  it('keeps a friend draft only while its tab is open', () => {
    openChat(FRIEND, 'Ada');
    setDraft(FRIEND, 'hello');
    expect(getDraft(FRIEND)).toBe('hello');
    closeTab(FRIEND);
    expect(getDraft(FRIEND)).toBe('');
  });

  it('does not resurrect a friend draft after closeTab', () => {
    openChat(FRIEND, 'Ada');
    setDraft(FRIEND, 'hello');
    closeTab(FRIEND);
    setDraft(FRIEND, 'hello');
    expect(getDraft(FRIEND)).toBe('');
  });
});
