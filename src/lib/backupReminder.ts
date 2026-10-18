/**
 * When to remind someone to back up their profile.
 *
 * A lost profile cannot be rebuilt from anywhere: the identity behind upload
 * credits, friendships and owned rooms exists only in it. Nothing prompts
 * people to back it up, so most first think of it after the disk has gone.
 *
 * The rules, all per install (none of these keys are in a backup — restoring
 * someone else's reminder state onto this machine would say nothing true):
 *  - A profile is left alone for its first two weeks, before it holds much.
 *  - After that, one reminder while it has never been backed up, and again
 *    once the last backup is three months old.
 *  - Shown or dismissed, it then waits a month, so it never becomes a nag.
 */

type StorageLike = Pick<Storage, 'getItem' | 'setItem'>;

const DAY_MS = 24 * 60 * 60 * 1000;

const FIRST_SEEN_KEY = 'ember.backup.firstSeenAt';
const LAST_BACKUP_KEY = 'ember.backup.lastAt';
const QUIET_UNTIL_KEY = 'ember.backup.quietUntil';

export const FIRST_REMINDER_AFTER_MS = 14 * DAY_MS;
export const REMIND_AGAIN_AFTER_MS = 90 * DAY_MS;
export const QUIET_AFTER_REMINDER_MS = 30 * DAY_MS;

function readTime(storage: StorageLike, key: string): number | null {
  const raw = storage.getItem(key);
  const value = raw === null ? NaN : Number(raw);
  return Number.isFinite(value) && value > 0 ? value : null;
}

function writeTime(storage: StorageLike, key: string, at: number): void {
  storage.setItem(key, String(Math.floor(at)));
}

/**
 * Whether a reminder should show now. The first call on an install starts its
 * clock, so a profile that predates this check gets its two weeks too.
 */
export function backupReminderDue(storage: StorageLike, now: number): boolean {
  const firstSeen = readTime(storage, FIRST_SEEN_KEY);
  if (firstSeen === null || firstSeen > now) {
    writeTime(storage, FIRST_SEEN_KEY, now);
    return false;
  }
  const quietUntil = readTime(storage, QUIET_UNTIL_KEY);
  if (quietUntil !== null && quietUntil > now) return false;
  const lastBackup = readTime(storage, LAST_BACKUP_KEY);
  if (lastBackup !== null && lastBackup > now) {
    // Made while the clock ran ahead. It is still a backup: count it from now
    // rather than as none.
    writeTime(storage, LAST_BACKUP_KEY, now);
    return false;
  }
  if (lastBackup !== null) {
    return now - lastBackup >= REMIND_AGAIN_AFTER_MS;
  }
  return now - firstSeen >= FIRST_REMINDER_AFTER_MS;
}

/** A reminder was shown: whatever the user does with it, wait a month. */
export function noteBackupReminderShown(storage: StorageLike, now: number): void {
  writeTime(storage, QUIET_UNTIL_KEY, now + QUIET_AFTER_REMINDER_MS);
}

/** A backup was written, which restarts the three-month clock. */
export function noteBackupMade(storage: StorageLike, now: number): void {
  writeTime(storage, LAST_BACKUP_KEY, now);
}

/** When this install last wrote a backup (milliseconds), if it has. */
export function lastBackupAt(storage: StorageLike): number | null {
  return readTime(storage, LAST_BACKUP_KEY);
}
