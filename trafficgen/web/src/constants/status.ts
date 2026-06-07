/**
 * Task status → Element Plus tag type mapping
 * Used by TaskStatusTag component and inline status displays
 */
export const TASK_STATUS_TYPE: Record<string, string> = {
  pending: 'info',
  created: 'info',
  starting: '',
  running: 'success',
  completed: 'success',
  failed: 'danger',
  error: 'danger',
  stopped: 'warning',
  paused: 'warning'
}

/**
 * Task status → el-progress status
 * Used by progress bars in TaskList, History, Dashboard, TaskDetail
 */
export function getProgressStatus(status: string): '' | 'success' | 'warning' | 'exception' {
  if (status === 'completed') return 'success'
  if (status === 'failed' || status === 'error') return 'exception'
  if (status === 'stopped' || status === 'paused') return 'warning'
  return ''
}

/**
 * User role → Element Plus tag type mapping
 * Used by UserList role column
 */
export const ROLE_TAG_TYPE: Record<string, string> = {
  admin: 'danger',
  user: 'primary',
  guest: 'info'
}
