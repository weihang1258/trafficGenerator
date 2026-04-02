import request from './index'

export interface Strategy {
  id: string
  name: string
  description?: string
  config: Record<string, any>
  created_at: string
  updated_at: string
}

export interface StrategyCreate {
  name: string
  description?: string
  config: Record<string, any>
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
 * 创建策略
 */
export function createStrategy(data: StrategyCreate): Promise<Strategy> {
  return request({
    url: '/strategies',
    method: 'post',
    data
  })
}

/**
 * 更新策略
 */
export function updateStrategy(strategyId: string, data: StrategyCreate): Promise<Strategy> {
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
