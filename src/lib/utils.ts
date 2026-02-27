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

/** Format remaining time given total size, transferred bytes, and current speed. */
export function formatEta(totalSize: number, transferred: number, speed: number): string {
  if (speed <= 0 || transferred >= totalSize) return '\u2014';
  const remaining = totalSize - transferred;
  const secs = Math.round(remaining / speed);
  if (secs < 60) return '< 1m';
  const days = Math.floor(secs / 86400);
  const hrs = Math.floor((secs % 86400) / 3600);
  const mins = Math.floor((secs % 3600) / 60);
  if (days > 0) return `${days}d ${hrs}h`;
  if (hrs > 0) return `${hrs}h ${mins}m`;
  return `${mins}m`;
}

/** Format a unix timestamp as a short date string. */
export function formatDate(ts: number): string {
  if (!ts || ts <= 0) return '\u2014';
  const d = new Date(ts * 1000);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/**
 * Format a speed for the settings page where 0 means "Unlimited".
 */
export function formatSpeedSetting(bytesPerSec: number): string {
  if (bytesPerSec === 0) return 'Unlimited';
  return formatSpeed(bytesPerSec);
}
