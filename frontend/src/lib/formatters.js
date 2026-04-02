/**
 * Pure formatting helpers used across the REX dashboard.
 *
 * All functions are null-safe -- they return a sensible fallback string
 * when given missing or invalid input.  They never fabricate data.
 */

/* ---------- time-ago ---------- */

const MINUTE = 60;
const HOUR = 3600;
const DAY = 86400;

/**
 * Human-friendly relative timestamp.
 * @param {string|number|Date|null} input  ISO string, epoch-ms, or Date.
 * @returns {string}
 */
export function timeAgo(input) {
  if (input == null) return '--';
  const date = input instanceof Date ? input : new Date(input);
  if (isNaN(date.getTime())) return '--';

  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 0) return 'just now';
  if (seconds < 10) return 'just now';
  if (seconds < MINUTE) return `${seconds}s ago`;
  if (seconds < HOUR) return `${Math.floor(seconds / MINUTE)}m ago`;
  if (seconds < DAY) return `${Math.floor(seconds / HOUR)}h ago`;
  const days = Math.floor(seconds / DAY);
  return days === 1 ? '1d ago' : `${days}d ago`;
}

/* ---------- timestamps ---------- */

/**
 * Format a date to locale time string.
 * @param {string|number|Date|null} input
 * @returns {string}
 */
export function formatTime(input) {
  if (input == null) return '--';
  const date = input instanceof Date ? input : new Date(input);
  if (isNaN(date.getTime())) return '--';
  return date.toLocaleTimeString();
}

/**
 * Format a date to locale date+time string.
 * @param {string|number|Date|null} input
 * @returns {string}
 */
export function formatDateTime(input) {
  if (input == null) return '--';
  const date = input instanceof Date ? input : new Date(input);
  if (isNaN(date.getTime())) return '--';
  return date.toLocaleString();
}

/* ---------- percentages ---------- */

/**
 * Format a 0-1 or 0-100 number as a percentage string.
 * @param {number|null} value
 * @param {Object}      [opts]
 * @param {number}      [opts.decimals=0]  Decimal places.
 * @param {boolean}     [opts.zeroToOne=false]  If true, treat 0-1 input as ratio.
 * @returns {string}
 */
export function formatPercent(value, { decimals = 0, zeroToOne = false } = {}) {
  if (value == null || !Number.isFinite(value)) return '--';
  const pct = zeroToOne ? value * 100 : value;
  return `${pct.toFixed(decimals)}%`;
}

/* ---------- uptime ---------- */

/**
 * Convert seconds to a human-readable uptime string.
 * @param {number|null} seconds
 * @returns {string}
 */
export function formatUptime(seconds) {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return '--';
  const d = Math.floor(seconds / DAY);
  const h = Math.floor((seconds % DAY) / HOUR);
  const m = Math.floor((seconds % HOUR) / MINUTE);
  const parts = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  parts.push(`${m}m`);
  return parts.join(' ');
}

/* ---------- bytes ---------- */

/**
 * Format bytes to a human-readable string.
 * @param {number|null} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
  if (bytes == null || !Number.isFinite(bytes) || bytes < 0) return '--';
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/* ---------- counts ---------- */

/**
 * Safe number display.  Returns '--' for null/undefined.
 * @param {number|null} n
 * @returns {string}
 */
export function formatCount(n) {
  if (n == null || !Number.isFinite(n)) return '--';
  return n.toLocaleString();
}
