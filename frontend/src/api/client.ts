/**
 * axios 实例。
 *
 * Mock 模式通过替换 adapter 实现（而非在业务代码里写分支），
 * 因此 `endpoints.ts` 与真实后端调用完全一致 —— 切后端只改 `.env`。
 */
import axios from 'axios'
import type { AxiosError } from 'axios'

import { mockAdapter } from './mock'

export const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true'

const TOKEN_KEY = 'asa_token'

export const tokenStore = {
  get: (): string | null => localStorage.getItem(TOKEN_KEY),
  set: (t: string): void => localStorage.setItem(TOKEN_KEY, t),
  clear: (): void => localStorage.removeItem(TOKEN_KEY),
}

export const http = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? '/api/v1',
  timeout: 30_000,
  ...(USE_MOCK ? { adapter: mockAdapter } : {}),
})

http.interceptors.request.use((config) => {
  const token = tokenStore.get()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

http.interceptors.response.use(
  (response) => response,
  (error: AxiosError<{ detail?: string }>) => {
    if (error.response?.status === 401) {
      tokenStore.clear()
      // 用 location 而非 router：拦截器在 React 树之外，拿不到 navigate
      if (!window.location.pathname.startsWith('/login')) {
        window.location.replace('/login')
      }
    }
    return Promise.reject(error)
  },
)

/** 把 axios 错误压成一句可直接展示给用户的中文提示 */
export function errorMessage(error: unknown): string {
  const err = error as AxiosError<{ detail?: string }>
  if (err?.response?.data?.detail) return err.response.data.detail
  if (err?.code === 'ECONNABORTED') return '请求超时，请稍后重试'
  if (err?.message) return err.message
  return '请求失败'
}
