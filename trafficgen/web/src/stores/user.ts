import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { authApi, type LoginResponse } from '@/api'

export const useUserStore = defineStore('user', () => {
  const token = ref<string | null>(localStorage.getItem('token'))
  const username = ref<string | null>(localStorage.getItem('username'))
  const expiresAt = ref<number | null>(null)

  const isLoggedIn = computed(() => !!token.value)

  function setAuth(data: LoginResponse, user: string) {
    token.value = data.token
    expiresAt.value = data.expires_at
    username.value = user
    localStorage.setItem('token', data.token)
    localStorage.setItem('username', user)
  }

  function clearAuth() {
    token.value = null
    username.value = null
    expiresAt.value = null
    localStorage.removeItem('token')
    localStorage.removeItem('username')
  }

  async function login(username: string, password: string) {
    const res = await authApi.login({ username, password })
    if (res.data) {
      setAuth(res.data, username)
    }
    return res
  }

  async function logout() {
    await authApi.logout()
    clearAuth()
  }

  return {
    token,
    username,
    expiresAt,
    isLoggedIn,
    login,
    logout,
    setAuth,
    clearAuth
  }
})
