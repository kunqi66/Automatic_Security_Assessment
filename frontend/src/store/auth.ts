/**
 * 登录态。token 存 localStorage，启动时用 /auth/me 校验一次 —— 避免拿着过期 token
 * 进到界面里、每个请求都 401。
 */
import { create } from 'zustand'

import { tokenStore } from '@/api/client'
import { authApi } from '@/api/endpoints'
import type { LoginRequest, User } from '@/api/types'

interface AuthState {
  user: User | null
  /** 启动时校验 token 是否仍然有效 */
  booting: boolean
  login: (payload: LoginRequest) => Promise<void>
  logout: () => void
  bootstrap: () => Promise<void>
}

export const useAuth = create<AuthState>()((set) => ({
  user: null,
  booting: true,

  login: async (payload) => {
    const res = await authApi.login(payload)
    tokenStore.set(res.access_token)
    set({ user: res.user })
  },

  logout: () => {
    tokenStore.clear()
    set({ user: null })
  },

  bootstrap: async () => {
    if (!tokenStore.get()) {
      set({ booting: false })
      return
    }
    try {
      const user = await authApi.me()
      set({ user, booting: false })
    } catch {
      tokenStore.clear()
      set({ user: null, booting: false })
    }
  },
}))
