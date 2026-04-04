import request from './index'

export interface FlowControl {
  type: string  // "flows", "cps", "bps", "ratio", "time"
  value: number
}

export interface Strategy {
  id: string
  user_id: string
  name: string
  protocol: string
  config: Record<string, any>
  flow_control: FlowControl
  created_at: number
  updated_at: number
}

export interface StrategyCreate {
  name: string
  protocol: string
  config: Record<string, any>
  flow_control?: FlowControl
}

/**
 * 获取策略列表
 */
export function listStrategies(): Promise<Strategy[]> {
  return request({
    url: '/strategies',
    method: 'get'
  })
}

/**
 * 获取策略详情
 */
export function getStrategy(strategyId: string): Promise<Strategy> {
  return request({
    url: `/strategies/${strategyId}`,
    method: 'get'
  })
}

/**
 * 创建策略（幂等）
 */
export function createStrategy(data: StrategyCreate): Promise<{ id: string; message?: string }> {
  return request({
    url: '/strategies',
    method: 'post',
    data
  })
}

/**
 * 更新策略
 */
export function updateStrategy(strategyId: string, data: StrategyCreate): Promise<void> {
  return request({
    url: `/strategies/${strategyId}`,
    method: 'put',
    data
  })
}

/**
 * 删除策略
 */
export function deleteStrategy(strategyId: string): Promise<void> {
  return request({
    url: `/strategies/${strategyId}`,
    method: 'delete'
  })
}
