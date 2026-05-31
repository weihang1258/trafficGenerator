/**
 * Format bytes with human-readable units (base-1024).
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
}

/**
 * Format large numbers with K/M/G suffixes (base-1000).
 */
export function formatNumber(num: number): string {
  if (num >= 1_000_000_000) return (num / 1_000_000_000).toFixed(2) + 'G'
  if (num >= 1_000_000) return (num / 1_000_000).toFixed(2) + 'M'
  if (num >= 1_000) return (num / 1_000).toFixed(1) + 'K'
  return num.toString()
}

/**
 * Format throughput in bits-per-second with bps/Kbps/Mbps/Gbps units.
 */
export function formatBps(bps: number): string {
  if (bps === 0) return '0 bps'
  const k = 1000
  const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps']
  const i = Math.floor(Math.log(bps) / Math.log(k))
  return `${(bps / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
}

/**
 * Format throughput in packets-per-second with K/M suffixes.
 */
export function formatPps(pps: number): string {
  if (pps >= 1_000_000) return (pps / 1_000_000).toFixed(2) + 'M'
  if (pps >= 1_000) return (pps / 1_000).toFixed(2) + 'K'
  return pps.toString()
}

/**
 * Format seconds into human-readable uptime (e.g., "2d 3h 15m").
 */
export function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

/**
 * Format a duration in seconds to HH:MM:SS or MM:SS.
 */
export function formatDuration(secs: number): string {
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = secs % 60
  if (h > 0) return `${h}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`
  return `${m}:${s.toString().padStart(2, '0')}`
}

/**
 * Format a task duration from start/end timestamps (Unix seconds).
 * Returns "2h 3m 15s", "15m 3s", "3s", or "-" if no start time.
 */
export function formatTaskDuration(start?: number, end?: number): string {
  if (!start) return '-'
  const endTime = end || Math.floor(Date.now() / 1000)
  const seconds = Math.max(0, Math.floor(endTime - start))
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const secs = seconds % 60
  if (hours > 0) return `${hours}h ${minutes}m ${secs}s`
  if (minutes > 0) return `${minutes}m ${secs}s`
  return `${secs}s`
}
