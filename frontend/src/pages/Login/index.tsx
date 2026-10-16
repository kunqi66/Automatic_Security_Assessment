import { LockOutlined, UserOutlined } from '@ant-design/icons'
import { Alert, Button, Card, Form, Input, Typography } from 'antd'
import { useState } from 'react'
import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'

import { USE_MOCK, errorMessage } from '@/api/client'
import type { LoginRequest } from '@/api/types'
import { useAuth } from '@/store/auth'

export default function Login(): ReactNode {
  const login = useAuth((s) => s.login)
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const onFinish = async (values: LoginRequest): Promise<void> => {
    setLoading(true)
    setError(null)
    try {
      await login(values)
      navigate('/', { replace: true })
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'grid',
        placeItems: 'center',
        background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      }}
    >
      <Card style={{ width: 380 }} styles={{ body: { padding: 32 } }}>
        <Typography.Title level={3} style={{ marginTop: 0, marginBottom: 4 }}>
          自动化安全评估系统
        </Typography.Title>
        <Typography.Paragraph type="secondary" style={{ marginBottom: 24 }}>
          可控多智能体 · 源码审计与攻击路径推演
        </Typography.Paragraph>

        {USE_MOCK && (
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
            message="Mock 模式"
            description="后端未启动，使用前端内置数据。演示账号 admin / admin123"
          />
        )}

        {error && <Alert type="error" showIcon style={{ marginBottom: 16 }} message={error} />}

        <Form<LoginRequest>
          layout="vertical"
          initialValues={USE_MOCK ? { username: 'admin', password: 'admin123' } : undefined}
          onFinish={(v) => void onFinish(v)}
        >
          <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input prefix={<UserOutlined />} placeholder="用户名" size="large" autoComplete="username" />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password
              prefix={<LockOutlined />}
              placeholder="密码"
              size="large"
              autoComplete="current-password"
            />
          </Form.Item>
          <Button type="primary" htmlType="submit" size="large" block loading={loading}>
            登录
          </Button>
        </Form>
      </Card>
    </div>
  )
}
