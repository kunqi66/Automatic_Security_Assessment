import { Spin } from 'antd'
import { Suspense, lazy, useEffect } from 'react'
import type { ReactNode } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'

import { AppLayout } from '@/components/AppLayout'
import { useAuth } from '@/store/auth'

/**
 * 路由级懒加载。
 *
 * 这不是过度优化：四个页面各自拖着很重的依赖 —— 工作台带 Monaco 编辑器与
 * React Flow，大盘带 ECharts。不拆的话首屏要一次性下载全部，单个 chunk 接近 3 MB。
 * 拆完之后首屏只加载登录与当前页，其余按需拉取。
 */
const Dashboard = lazy(() => import('@/pages/Dashboard'))
const Workbench = lazy(() => import('@/pages/Workbench'))
const ReportCenter = lazy(() => import('@/pages/ReportCenter'))
const SandboxConfig = lazy(() => import('@/pages/SandboxConfig'))
const Login = lazy(() => import('@/pages/Login'))

function PageLoading(): ReactNode {
  return (
    <div style={{ display: 'grid', placeItems: 'center', minHeight: 320 }}>
      <Spin tip="加载中…">
        <div style={{ padding: 32 }} />
      </Spin>
    </div>
  )
}

function BootLoading(): ReactNode {
  return (
    <div style={{ display: 'grid', placeItems: 'center', height: '100vh' }}>
      <Spin size="large" tip="正在校验登录态…">
        <div style={{ padding: 40 }} />
      </Spin>
    </div>
  )
}

export default function App(): ReactNode {
  const user = useAuth((s) => s.user)
  const booting = useAuth((s) => s.booting)
  const bootstrap = useAuth((s) => s.bootstrap)

  useEffect(() => {
    void bootstrap()
  }, [bootstrap])

  if (booting) return <BootLoading />

  return (
    <Suspense fallback={<PageLoading />}>
      <Routes>
        <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />
        <Route element={user ? <AppLayout /> : <Navigate to="/login" replace />}>
          <Route index element={<Dashboard />} />
          <Route path="/workbench" element={<Workbench />} />
          <Route path="/reports" element={<ReportCenter />} />
          <Route path="/settings" element={<SandboxConfig />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  )
}
