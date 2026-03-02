/**
 * Format a byte count as a human-readable string (e.g. "1.5 MB").
 * Uses iterative division to avoid floating-point edge cases.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let val = bytes;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i++;
  }
  return `${val.toFixed(1)} ${units[i]}`;
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
 * Format milliseconds as HH:MM (eMule CastSecondsToHM style).
 * Returns "\u2014" for zero or invalid values.
 */
export function formatDuration(ms: number): string {
  if (!ms || ms <= 0) return '\u2014';
  const totalSecs = Math.floor(ms / 1000);
  const hrs = Math.floor(totalSecs / 3600);
  const mins = Math.floor((totalSecs % 3600) / 60);
  if (hrs > 0) return `${hrs}:${String(mins).padStart(2, '0')}`;
  return `${mins} min`;
}

/** Format seconds as a human-readable duration (e.g. "2h 15m"). */
export function formatDurationSecs(secs: number): string {
  if (!secs || secs <= 0) return '\u2014';
  const days = Math.floor(secs / 86400);
  const hrs = Math.floor((secs % 86400) / 3600);
  const mins = Math.floor((secs % 3600) / 60);
  if (days > 0) return `${days}d ${hrs}h`;
  if (hrs > 0) return `${hrs}h ${mins}m`;
  return `${mins}m`;
}

/** Format remaining size + ETA combined (eMule Remaining column style). */
export function formatRemaining(totalSize: number, transferred: number, speed: number): string {
  if (transferred >= totalSize) return '\u2014';
  const remaining = totalSize - transferred;
  const remainStr = formatBytes(remaining);
  if (speed <= 0) return remainStr;
  const secs = Math.round(remaining / speed);
  const days = Math.floor(secs / 86400);
  const hrs = Math.floor((secs % 86400) / 3600);
  const mins = Math.floor((secs % 3600) / 60);
  let timeStr: string;
  if (days > 0) timeStr = `${days}d ${hrs}h`;
  else if (hrs > 0) timeStr = `${hrs}h ${mins}m`;
  else if (mins > 0) timeStr = `${mins}m`;
  else timeStr = '< 1m';
  return `${timeStr} (${remainStr})`;
}

/**
 * Format a speed for the settings page where 0 means "Unlimited".
 */
export function formatSpeedSetting(bytesPerSec: number): string {
  if (bytesPerSec === 0) return 'Unlimited';
  return formatSpeed(bytesPerSec);
}

/** Format a percentage with smart decimal handling. */
export function formatPercent(value: number, decimals = 1): string {
  if (value <= 0) return '0%';
  if (value >= 100) return '100%';
  return `${value.toFixed(decimals)}%`;
}

/** Truncate a hex hash with ellipsis. */
export function truncateHash(hash: string, len = 16): string {
  if (hash.length <= len) return hash;
  return `${hash.slice(0, len)}\u2026`;
}

/** Pluralize a noun based on count. */
export function pluralize(count: number, singular: string, plural?: string): string {
  return count === 1 ? `${count} ${singular}` : `${count} ${plural || singular + 's'}`;
}

/** Copy text to clipboard with fallback. */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
