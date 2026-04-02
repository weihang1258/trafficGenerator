import request from './index'

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  token: string
  expires_at: string
}

export interface User {
  id: string
  username: string
  email?: string
  role?: string
}

/**
 * 用户登录
 */
export function login(data: LoginRequest): Promise<LoginResponse> {
  return request({
    url: '/auth/login',
    method: 'post',
    data
  })
}

/**
 * 用户登出
 */
export function logout(): Promise<void> {
  return request({
    url: '/auth/logout',
    method: 'post'
  })
}

/**
 * 刷新 Token
 */
export function refreshToken(): Promise<LoginResponse> {
  return request({
    url: '/auth/refresh',
    method: 'post'
  })
}

/**
 * 获取当前用户信息
 */
export function getCurrentUser(): Promise<User> {
  return request({
    url: '/auth/me',
    method: 'get'
  })
}

/**
 * 修改密码
 */
export function changePassword(data: {
  old_password: string
  new_password: string
}): Promise<void> {
  return request({
    url: '/auth/password',
    method: 'put',
    data
  })
}
