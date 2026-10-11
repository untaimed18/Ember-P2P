import { beforeEach, describe, expect, it } from 'vitest';
import {
  backupReminderDue,
  FIRST_REMINDER_AFTER_MS,
  noteBackupMade,
  noteBackupReminderShown,
  QUIET_AFTER_REMINDER_MS,
  REMIND_AGAIN_AFTER_MS,
} from './backupReminder';

const DAY = 24 * 60 * 60 * 1000;
const START = 1_790_000_000_000;

const values = new Map<string, string>();
const storage = {
  getItem: (key: string) => values.get(key) ?? null,
  setItem: (key: string, value: string) => void values.set(key, value),
};

beforeEach(() => values.clear());

describe('backup reminder', () => {
  it('leaves a new install alone for its first two weeks', () => {
    expect(backupReminderDue(storage, START)).toBe(false);
    expect(backupReminderDue(storage, START + FIRST_REMINDER_AFTER_MS - DAY)).toBe(false);
    expect(backupReminderDue(storage, START + FIRST_REMINDER_AFTER_MS)).toBe(true);
  });

  it('waits a month after a reminder, whatever the user did with it', () => {
    backupReminderDue(storage, START);
    const shownAt = START + FIRST_REMINDER_AFTER_MS;
    noteBackupReminderShown(storage, shownAt);
    expect(backupReminderDue(storage, shownAt + QUIET_AFTER_REMINDER_MS - DAY)).toBe(false);
    expect(backupReminderDue(storage, shownAt + QUIET_AFTER_REMINDER_MS)).toBe(true);
  });

  it('stays quiet for three months after a backup', () => {
    backupReminderDue(storage, START);
    const backedUpAt = START + 20 * DAY;
    noteBackupMade(storage, backedUpAt);
    expect(backupReminderDue(storage, backedUpAt + REMIND_AGAIN_AFTER_MS - DAY)).toBe(false);
    expect(backupReminderDue(storage, backedUpAt + REMIND_AGAIN_AFTER_MS)).toBe(true);
  });

  it('starts the clock again when stored times are unreadable or in the future', () => {
    values.set('ember.backup.firstSeenAt', 'nonsense');
    expect(backupReminderDue(storage, START)).toBe(false);
    values.set('ember.backup.firstSeenAt', String(START + 365 * DAY));
    expect(backupReminderDue(storage, START)).toBe(false);
    expect(backupReminderDue(storage, START + FIRST_REMINDER_AFTER_MS)).toBe(true);
  });
});
