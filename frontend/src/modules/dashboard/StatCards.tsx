/**
 * 指标卡片行：项目数 / 评估任务数 / 运行中任务数 / 漏洞总数。
 *
 * 四个数字全部是 `DashboardSummary` 上的现成字段，**前端不做任何聚合**。
 * 「运行中任务数」尤其不要自己拿 recent_assessments 去 filter ——
 * `recent_assessments` 只是最近若干条，用它统计会得出一个错的数。
 */
import {
  BugOutlined,
  DeploymentUnitOutlined,
  ProjectOutlined,
  SyncOutlined,
} from '@ant-design/icons'
import { Card, Col, Row, Statistic } from 'antd'
import type { ReactNode } from 'react'

import type { DashboardSummary } from '@/api/types'

import { INK } from './shared'

interface StatCard {
  key: string
  title: string
  value: number
  icon: ReactNode
  /** 图标底色，纯装饰 */
  tint: string
  hint: string
}

export function StatCards({ summary }: { summary: DashboardSummary }): ReactNode {
  const cards: StatCard[] = [
    {
      key: 'projects',
      title: '项目数',
      value: summary.project_count,
      icon: <ProjectOutlined />,
      tint: '#e6f4ff',
      hint: '已纳管的源码项目',
    },
    {
      key: 'assessments',
      title: '评估任务数',
      value: summary.assessment_count,
      icon: <DeploymentUnitOutlined />,
      tint: '#f9f0ff',
      hint: '累计发起的评估',
    },
    {
      key: 'running',
      title: '运行中任务数',
      value: summary.running_count,
      icon: <SyncOutlined />,
      tint: '#fff7e6',
      hint: '正在流水线中执行',
    },
    {
      key: 'vulns',
      title: '漏洞总数',
      value: summary.vuln_total,
      icon: <BugOutlined />,
      tint: '#fff1f0',
      hint: '含全部四态',
    },
  ]

  return (
    <Row gutter={[16, 16]}>
      {cards.map((card) => (
        <Col key={card.key} xs={24} sm={12} xl={6}>
          <Card styles={{ body: { padding: 20 } }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <span
                aria-hidden="true"
                style={{
                  display: 'grid',
                  placeItems: 'center',
                  width: 44,
                  height: 44,
                  borderRadius: 10,
                  background: card.tint,
                  fontSize: 20,
                  flex: '0 0 auto',
                }}
              >
                {card.icon}
              </span>
              <Statistic
                title={card.title}
                value={card.value}
                valueStyle={{ fontSize: 26, fontWeight: 600 }}
              />
            </div>
            <div style={{ marginTop: 12, fontSize: 12, color: INK.muted }}>{card.hint}</div>
          </Card>
        </Col>
      ))}
    </Row>
  )
}
