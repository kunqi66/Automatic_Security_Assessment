/**
 * 最近评估任务表。
 *
 * 点任意一行进入工作台：`/workbench?assessmentId=<id>` —— 工作台靠这个查询参数
 * 决定加载哪次评估，所以这里只是**带参跳转**，不往 store 里塞任何东西。
 *
 * 「项目综合等级」可能为 null（任务尚未跑完），此时显示「—」而不是给个默认等级：
 * 没算出来就是没算出来，不能替后端编一个结论。
 */
import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  MinusCircleOutlined,
  SyncOutlined,
} from '@ant-design/icons'
import { Card, Progress, Table, Tag, Tooltip, Typography } from 'antd'
import type { TableProps } from 'antd'
import dayjs from 'dayjs'
import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'

import type { Assessment, AssessmentStatus, SecurityGrade, StageName } from '@/api/types'
import { SecurityGradeTag } from '@/components/tags'
import { STAGE_LABELS } from '@/constants'

import { INK } from './shared'

// ---------------------------------------------------------------------------
// 评估任务状态标签
// ---------------------------------------------------------------------------

/**
 * 这个标签刻意放在本地而不是 `components/tags.tsx`：后者是全站定稿的基础设施，
 * 里面提供的是漏洞/阶段/等级标签，没有「评估任务状态」这一种。
 * 为了不改动那个文件，这里按同一套规则（颜色 + 文字 + 图标三重编码，绝不只靠颜色）实现一份。
 */
const ASSESSMENT_STATUS: Record<
  AssessmentStatus,
  { color: string; label: string; icon: ReactNode; tip: string }
> = {
  created: {
    color: 'default',
    label: '已创建',
    icon: <ClockCircleOutlined />,
    tip: '任务行已创建，等待 worker 开跑',
  },
  running: {
    color: 'processing',
    label: '运行中',
    icon: <SyncOutlined spin />,
    tip: '流水线正在执行',
  },
  completed: {
    color: 'success',
    label: '已完成',
    icon: <CheckCircleOutlined />,
    tip: '五个阶段全部执行完毕',
  },
  failed: {
    color: 'error',
    label: '失败',
    icon: <CloseCircleOutlined />,
    tip: '流水线执行失败，详见工作台日志',
  },
  stopped: {
    color: 'warning',
    label: '已终止',
    icon: <MinusCircleOutlined />,
    tip: '被人工终止：沙箱已销毁，已产出的数据保留',
  },
}

function AssessmentStatusTag({ value }: { value: AssessmentStatus }): ReactNode {
  const spec = ASSESSMENT_STATUS[value]
  return (
    <Tooltip title={spec.tip}>
      <Tag color={spec.color} icon={spec.icon}>
        {spec.label}
      </Tag>
    </Tooltip>
  )
}

/** 进度条状态：只有真正在跑的时候才用 active 动画，别让排队中的任务也转起来 */
const PROGRESS_STATUS: Record<AssessmentStatus, 'normal' | 'active' | 'success' | 'exception'> = {
  created: 'normal',
  running: 'active',
  completed: 'success',
  failed: 'exception',
  stopped: 'normal',
}

/** 未产出结论时统一显示这个占位符 */
const EMPTY = <span style={{ color: INK.muted }}>—</span>

// ---------------------------------------------------------------------------

export function RecentTasks({ assessments }: { assessments: Assessment[] }): ReactNode {
  const navigate = useNavigate()

  const columns: TableProps<Assessment>['columns'] = [
    {
      title: '项目名',
      dataIndex: 'project_name',
      key: 'project_name',
      width: 220,
      ellipsis: true,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 108,
      render: (value: AssessmentStatus) => <AssessmentStatusTag value={value} />,
    },
    {
      title: '当前阶段',
      dataIndex: 'current_stage',
      key: 'current_stage',
      width: 116,
      render: (value: StageName | null) => (value ? STAGE_LABELS[value] : EMPTY),
    },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      width: 160,
      render: (value: number, record: Assessment) => (
        <Progress
          percent={value}
          size="small"
          status={PROGRESS_STATUS[record.status]}
          style={{ marginBottom: 0 }}
        />
      ),
    },
    {
      title: '项目综合等级',
      dataIndex: 'security_grade',
      key: 'security_grade',
      width: 136,
      render: (value: SecurityGrade | null) =>
        value ? <SecurityGradeTag value={value} /> : EMPTY,
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 168,
      render: (value: string) => (
        <span style={{ whiteSpace: 'nowrap' }}>{dayjs(value).format('YYYY-MM-DD HH:mm')}</span>
      ),
    },
  ]

  return (
    <Card
      title="最近评估任务"
      extra={
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          点击任意一行进入工作台
        </Typography.Text>
      }
    >
      <Table<Assessment>
        rowKey="id"
        size="middle"
        columns={columns}
        dataSource={assessments}
        pagination={false}
        scroll={{ x: 908 }}
        onRow={(record) => ({
          onClick: () => navigate(`/workbench?assessmentId=${record.id}`),
          style: { cursor: 'pointer' },
        })}
      />
    </Card>
  )
}
