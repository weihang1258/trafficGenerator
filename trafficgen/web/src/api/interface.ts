import request from './index'

export interface Interface {
  name: string
  mac: string
  ip: string
  netmask: string
  status: 'up' | 'down'
  mtu: number
}

export interface PortAllocation {
  port: number
  task_id: string
  allocated_at: string
}

/**
 * 获取网卡列表
 */
export function listInterfaces(): Promise<Interface[]> {
  return request({
    url: '/interfaces',
    method: 'get'
  })
}

/**
 * 获取网卡详情
 */
export function getInterface(interfaceName: string): Promise<Interface> {
  return request({
    url: `/interfaces/${interfaceName}`,
    method: 'get'
  })
}

/**
 * 刷新网卡列表
 */
export function refreshInterfaces(): Promise<Interface[]> {
  return request({
    url: '/interfaces/refresh',
    method: 'post'
  })
}

/**
 * 获取端口分配情况
 */
export function getPortAllocations(interfaceName?: string): Promise<PortAllocation[]> {
  return request({
    url: '/ports/allocations',
    method: 'get',
    params: { interface: interfaceName }
  })
}

/**
 * 获取端口统计信息
 */
export function getPortStats(): Promise<{
  allocations: number
  wait_queue: number
}> {
  return request({
    url: '/ports/stats',
    method: 'get'
  })
}
