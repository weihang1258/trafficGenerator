import request from './index'

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  token: string
  expires_at: number
  user_id: string
  username: string
}

export interface RegisterRequest {
  username: string
  password: string
  email: string
}

export interface User {
  id: string
  username: string
  email?: string
  role?: string
}

/**
 * 用户注册
 */
export function register(data: RegisterRequest): Promise<User> {
  return request({
    url: '/auth/register',
    method: 'post',
    data
  })
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
 * 验证 Token
 */
export function validateToken(): Promise<{ valid: boolean; user_id: string; username: string }> {
  return request({
    url: '/auth/validate',
    method: 'get'
  })
}
