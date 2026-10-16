import {
  BugOutlined,
  DashboardOutlined,
  FileTextOutlined,
  LogoutOutlined,
  SettingOutlined,
  UserOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Alert, Avatar, Dropdown, Layout, Menu, Space, Tag, Typography } from 'antd'
import type { ReactNode } from 'react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'

import { USE_MOCK } from '@/api/client'
import { adminApi } from '@/api/endpoints'
import { useAuth } from '@/store/auth'

const { Header, Sider, Content } = Layout

const MENU = [
  { key: '/', icon: <DashboardOutlined />, label: '概览大盘' },
  { key: '/workbench', icon: <BugOutlined />, label: '安全评估工作台' },
  { key: '/reports', icon: <FileTextOutlined />, label: '安全报告中心' },
  { key: '/settings', icon: <SettingOutlined />, label: '沙箱与环境配置' },
]

export function AppLayout(): ReactNode {
  const location = useLocation()
  const navigate = useNavigate()
  const user = useAuth((s) => s.user)
  const logout = useAuth((s) => s.logout)

  // L4 可降级不阻断：模型不可用时全站显式标注「模板生成」，不假装是模型产出
  const { data: llm } = useQuery({
    queryKey: ['llm-config'],
    queryFn: adminApi.getLlmConfig,
    staleTime: 60_000,
  })

  const selected = MENU.map((m) => m.key)
    .filter((k) => (k === '/' ? location.pathname === '/' : location.pathname.startsWith(k)))
    .slice(0, 1)

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider theme="dark" width={216} breakpoint="lg" collapsedWidth={64}>
        <div
          style={{
            height: 56,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '0 16px',
            color: '#fff',
            fontWeight: 600,
            letterSpacing: 0.5,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
          }}
        >
          <BugOutlined style={{ fontSize: 18 }} />
          自动化安全评估
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={selected.length ? selected : ['/']}
          items={MENU.map((m) => ({ ...m, label: <Link to={m.key}>{m.label}</Link> }))}
        />
      </Sider>

      <Layout>
        <Header
          style={{
            background: '#fff',
            borderBottom: '1px solid #f0f0f0',
            paddingInline: 24,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <Space size={8}>
            <Typography.Text strong style={{ fontSize: 15 }}>
              {MENU.find((m) => m.key === selected[0])?.label ?? '概览大盘'}
            </Typography.Text>
            {USE_MOCK && <Tag color="purple">Mock 数据</Tag>}
          </Space>

          <Space size={16}>
            {llm && !llm.available && (
              <Tag color="warning" icon={<WarningOutlined />}>
                模型不可用 · 模板降级
              </Tag>
            )}
            <Dropdown
              menu={{
                items: [
                  {
                    key: 'logout',
                    icon: <LogoutOutlined />,
                    label: '退出登录',
                    onClick: () => {
                      logout()
                      navigate('/login')
                    },
                  },
                ],
              }}
            >
              <Space style={{ cursor: 'pointer' }}>
                <Avatar size="small" icon={<UserOutlined />} />
                <span>{user?.username ?? '未登录'}</span>
              </Space>
            </Dropdown>
          </Space>
        </Header>

        <Content style={{ padding: 20 }}>
          {llm && !llm.available && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
              message="大语言模型当前不可用，报告与描述已降级为模板生成"
              description="判定结论、漏洞等级、攻击链拓扑与整改排序均不受影响 —— 它们由确定性代码产出，不经过模型。降级只影响自然语言措辞。"
            />
          )}
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
