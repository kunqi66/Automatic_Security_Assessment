/**
 * 概览大盘（路由 `/`）。
 *
 * 数据只从一个接口来：`GET /dashboard/stats`，一次拿全，避免四个卡片各发一个请求
 * 导致同一屏出现四个不同时刻的数字。
 *
 * ⚠️ 本页体现系统的核心设计原则 —— **LLM 只产出自然语言文案，一切判定与数字由确定性代码产出**。
 * 所以这里的每一个数字（项目数、四态计数、等级分布、严重度分布）都是后端算好的值，
 * 前端只做两件事：取数、呈现。**不做任何求和、求占比、排序、排名**：
 * 一旦前端开始算，判定权就从确定性代码漂回了展示层，这条原则就破了。
 *
 * 图表组件全部取自 `@/modules/dashboard`，本文件只负责取数、加载态与栅格布局。
 */
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Card, Col, Row, Skeleton, Space, Tooltip, Typography } from 'antd'
import { useState } from 'react'
import type { ReactNode } from 'react'

import { errorMessage } from '@/api/client'
import { dashboardApi } from '@/api/endpoints'
import { can } from '@/api/types'
import { ROLE_LABELS } from '@/constants'
import { NewAssessmentModal } from '@/modules/assessment/NewAssessmentModal'
import { GradeChart } from '@/modules/dashboard/GradeChart'
import { RecentTasks } from '@/modules/dashboard/RecentTasks'
import { SeverityChart } from '@/modules/dashboard/SeverityChart'
import { StatCards } from '@/modules/dashboard/StatCards'
import { StatusChart } from '@/modules/dashboard/StatusChart'
import { useAuth } from '@/store/auth'

export default function Dashboard(): ReactNode {
  const user = useAuth((s) => s.user)
  const [creating, setCreating] = useState(false)

  const { data, isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: dashboardApi.stats,
  })

  // 「新建评估」需要 `assessment:create`，按需求 2.5.2 它只给了安全工程师 ——
  // **管理员没有**。权限码来自 `/auth/me`，不在这里按 role 推导（见 `User.permissions`）。
  const mayCreate = can(user, 'assessment:create')

  if (isLoading) {
    // 骨架屏按最终版式排布，加载完不会整页跳一下
    return (
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card>
            <Skeleton active paragraph={{ rows: 2 }} />
          </Card>
        </Col>
        <Col span={24}>
          <Card>
            <Skeleton active paragraph={{ rows: 6 }} />
          </Card>
        </Col>
      </Row>
    )
  }

  if (isError) {
    return (
      <Alert
        type="error"
        showIcon
        message="概览数据加载失败"
        description={errorMessage(error)}
        action={
          <Button size="small" onClick={() => void refetch()}>
            重试
          </Button>
        }
      />
    )
  }

  if (!data) return null

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: 16,
        }}
      >
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>
            安全评估概览
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            本页所有数字均来自后端确定性统计，前端不做任何推算或聚合。
          </Typography.Text>
        </div>
        <Space>
          {/* 无权限时**不隐藏按钮**，而是禁用 + 说明原因。
              直接藏掉的话，管理员会以为「这个系统根本不能新建评估」——
              而实际上他缺的只是一个角色。禁用的按钮配一句为什么，
              比一个不存在的按钮有信息量。 */}
          <Tooltip
            title={
              mayCreate
                ? ''
                : `当前角色（${user ? ROLE_LABELS[user.role] : '未知'}）没有创建评估的权限，该操作需要安全工程师`
            }
          >
            <Button
              type="primary"
              icon={<PlusOutlined />}
              disabled={!mayCreate}
              onClick={() => setCreating(true)}
            >
              新建评估
            </Button>
          </Tooltip>
          <Button icon={<ReloadOutlined />} loading={isFetching} onClick={() => void refetch()}>
            刷新
          </Button>
        </Space>
      </div>

      <NewAssessmentModal open={creating} onClose={() => setCreating(false)} />

      <StatCards summary={data} />

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={12}>
          <GradeChart distribution={data.grade_distribution} />
        </Col>
        <Col xs={24} xl={12}>
          <SeverityChart distribution={data.vuln_by_severity} />
        </Col>
        <Col xs={24}>
          <StatusChart distribution={data.vuln_by_status} />
        </Col>
        <Col xs={24}>
          <RecentTasks assessments={data.recent_assessments} />
        </Col>
      </Row>
    </Space>
  )
}
