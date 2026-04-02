import request from './index'

export interface Task {
  id: string
  name: string
  protocol: string
  status: string
  config: Record<string, any>
  output?: Record<string, any>
  created_at: string
  updated_at: string
}

export interface TaskCreate {
  name: string
  protocol: string
  config: Record<string, any>
  output?: Record<string, any>
}

export interface TaskStats {
  packets_sent: number
  bytes_sent: number
  packets_dropped: number
  duration: number
  rate: number
  throughput: number
}

export interface TaskListParams {
  status?: string
  protocol?: string
  page?: number
  page_size?: number
}

export interface TaskListResponse {
  tasks: Task[]
  total: number
  page: number
  page_size: number
}

/**
 * 获取任务列表
 */
export function listTasks(params?: TaskListParams): Promise<TaskListResponse> {
  return request({
    url: '/tasks',
    method: 'get',
    params
  })
}

/**
 * 获取任务详情
 */
export function getTask(taskId: string): Promise<Task> {
  return request({
    url: `/tasks/${taskId}`,
    method: 'get'
  })
}

/**
 * 创建任务
 */
export function createTask(data: TaskCreate): Promise<Task> {
  return request({
    url: '/tasks',
    method: 'post',
    data
  })
}

/**
 * 删除任务
 */
export function deleteTask(taskId: string): Promise<void> {
  return request({
    url: `/tasks/${taskId}`,
    method: 'delete'
  })
}

/**
 * 启动任务
 */
export function startTask(taskId: string): Promise<Task> {
  return request({
    url: `/tasks/${taskId}/start`,
    method: 'post'
  })
}

/**
 * 停止任务
 */
export function stopTask(taskId: string): Promise<Task> {
  return request({
    url: `/tasks/${taskId}/stop`,
    method: 'post'
  })
}

/**
 * 获取任务统计信息
 */
export function getTaskStats(taskId: string): Promise<TaskStats> {
  return request({
    url: `/tasks/${taskId}/stats`,
    method: 'get'
  })
}

/**
 * 批量删除任务
 */
export function batchDeleteTasks(taskIds: string[]): Promise<void> {
  return request({
    url: '/tasks/batch',
    method: 'delete',
    data: { task_ids: taskIds }
  })
}

/**
 * 批量启动任务
 */
export function batchStartTasks(taskIds: string[]): Promise<void> {
  return request({
    url: '/tasks/batch/start',
    method: 'post',
    data: { task_ids: taskIds }
  })
}

/**
 * 批量停止任务
 */
export function batchStopTasks(taskIds: string[]): Promise<void> {
  return request({
    url: '/tasks/batch/stop',
    method: 'post',
    data: { task_ids: taskIds }
  })
}
