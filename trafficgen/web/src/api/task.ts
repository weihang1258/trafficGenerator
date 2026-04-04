import request from './index'

export interface FlowControl {
  type: string  // "flows", "cps", "bps", "ratio", "time"
  value: number
}

export interface OutputConfig {
  port_group_id?: string
  pcap_path?: string
}

export interface Task {
  id: string
  user_id: string
  name: string
  strategy_ids: string[]
  output_type: string  // "port_group" or "pcap"
  output_config: OutputConfig
  flow_control?: FlowControl
  status: string  // "pending", "running", "stopped", "completed", "error"
  error_message?: string
  progress: number
  created_at: number
  updated_at: number
  started_at?: number
  completed_at?: number
}

export interface TaskCreate {
  name: string
  strategy_ids: string[]
  output_type: string
  output_config: OutputConfig
  flow_control?: FlowControl
}

export interface TaskListParams {
  status?: string
  page?: number
  page_size?: number
}

export interface TaskStats {
  total_packets: number
  total_bytes: number
  duration: number
  errors: number
}

/**
 * 获取任务列表
 */
export function listTasks(params?: TaskListParams): Promise<Task[]> {
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
 * 创建任务（幂等）
 */
export function createTask(data: TaskCreate): Promise<{ id: string; message?: string }> {
  return request({
    url: '/tasks',
    method: 'post',
    data
  })
}

/**
 * 启动任务
 */
export function startTask(taskId: string): Promise<void> {
  return request({
    url: `/tasks/${taskId}/start`,
    method: 'post'
  })
}

/**
 * 停止任务
 */
export function stopTask(taskId: string): Promise<void> {
  return request({
    url: `/tasks/${taskId}/stop`,
    method: 'post'
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
