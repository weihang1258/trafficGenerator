import request from './index'

export interface PortConfig {
  interface: string
  weight: number
}

export interface PortGroup {
  id: string
  name: string
  ports_config: PortConfig[]
  created_at: number
  updated_at: number
}

export interface PortGroupCreate {
  ports: PortConfig[]
}

export interface Port {
  id: string
  name: string
  type: string  // "libpcap" or "dpdk"
  pci_address: string
  status: string  // "idle", "using", "maintenance"
  current_task_id: string
  created_at: number
  updated_at: number
}

/**
 * 获取端口列表
 */
export function listPorts(): Promise<Port[]> {
  return request({
    url: '/ports',
    method: 'get'
  })
}

/**
 * 获取端口组列表
 */
export function listPortGroups(): Promise<PortGroup[]> {
  return request({
    url: '/port-groups',
    method: 'get'
  })
}

/**
 * 获取端口组详情
 */
export function getPortGroup(portGroupId: string): Promise<PortGroup> {
  return request({
    url: `/port-groups/${portGroupId}`,
    method: 'get'
  })
}

/**
 * 创建端口组（幂等）
 */
export function createPortGroup(data: PortGroupCreate): Promise<{ id: string; name: string; message?: string }> {
  return request({
    url: '/port-groups',
    method: 'post',
    data
  })
}

/**
 * 删除端口组
 */
export function deletePortGroup(portGroupId: string): Promise<void> {
  return request({
    url: `/port-groups/${portGroupId}`,
    method: 'delete'
  })
}
