/**
 * Format a byte count as a human-readable string (e.g. "1.5 MB").
 * Handles zero, negative, and NaN inputs safely.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

/** Alias for formatBytes -- used in file-size contexts. */
export const formatSize = formatBytes;

/** Format bytes/sec as a speed string (e.g. "1.5 MB/s"). */
export function formatSpeed(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

/**
 * Format a speed for the settings page where 0 means "Unlimited".
 */
export function formatSpeedSetting(bytesPerSec: number): string {
  if (bytesPerSec === 0) return 'Unlimited';
  return formatSpeed(bytesPerSec);
}
