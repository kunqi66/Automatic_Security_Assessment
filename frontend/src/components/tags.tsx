/**
 * 全站状态标签。
 *
 * ⚠️ 一律 **颜色 + 文字 + 图标** 三重编码，不允许只靠颜色区分状态（F4 §7 D10 无障碍要求）。
 * 色盲用户、黑白打印、截图转灰都要能读出状态。
 */
import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  EyeOutlined,
  MinusCircleOutlined,
  QuestionCircleOutlined,
  StopOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import { Tag, Tooltip } from 'antd'
import type { ReactNode } from 'react'

import type {
  SecurityGrade,
  Severity,
  StageStatus,
  VerificationStatus,
  VulnStatus,
} from '@/api/types'

interface TagSpec {
  color: string
  label: string
  icon: ReactNode
  tip: string
}

// ---------------------------------------------------------------------------
// 漏洞严重度（severity）—— 与「项目综合等级」是两回事，文案上必须区分
// ---------------------------------------------------------------------------

const SEVERITY: Record<Severity, TagSpec> = {
  critical: {
    color: 'red',
    label: '严重',
    icon: <ThunderboltOutlined />,
    tip: '漏洞严重度：严重（CVSS 9.0–10.0）',
  },
  high: {
    color: 'volcano',
    label: '高危',
    icon: <ExclamationCircleOutlined />,
    tip: '漏洞严重度：高危（CVSS 7.0–8.9）',
  },
  medium: {
    color: 'gold',
    label: '中危',
    icon: <ExclamationCircleOutlined />,
    tip: '漏洞严重度：中危（CVSS 4.0–6.9）',
  },
  low: {
    color: 'blue',
    label: '低危',
    icon: <MinusCircleOutlined />,
    tip: '漏洞严重度：低危（CVSS 0.1–3.9）',
  },
}

export function SeverityTag({ value }: { value: Severity }): ReactNode {
  const s = SEVERITY[value]
  return (
    <Tooltip title={s.tip}>
      <Tag color={s.color} icon={s.icon}>
        {s.label}
      </Tag>
    </Tooltip>
  )
}

// ---------------------------------------------------------------------------
// 漏洞四态（需求 2.5.4）—— F3 提供给 F4 的组件，两个区域共用同一份渲染
// ---------------------------------------------------------------------------

const VULN_STATUS: Record<VulnStatus, TagSpec> = {
  verified: {
    color: 'success',
    label: '已验证',
    icon: <CheckCircleOutlined />,
    tip: '已在沙箱内动态验证：探针实际命中，证据充分',
  },
  potential: {
    color: 'warning',
    label: '潜在',
    icon: <QuestionCircleOutlined />,
    tip: '静态命中但未通过动态验证（含被 HarmlessGuard 拦下），存在风险但证据不足',
  },
  unverified: {
    color: 'processing',
    label: '待验证',
    icon: <ClockCircleOutlined />,
    tip: '静态审计已标记，尚未进入动态验证环节',
  },
  rejected: {
    color: 'default',
    label: '已排除',
    icon: <StopOutlined />,
    tip: '经复核判定为误报（例如上游已有净化函数），不计入风险统计',
  },
}

export function VulnStatusTag({ value }: { value: VulnStatus }): ReactNode {
  const s = VULN_STATUS[value]
  return (
    <Tooltip title={s.tip}>
      <Tag color={s.color} icon={s.icon}>
        {s.label}
      </Tag>
    </Tooltip>
  )
}

// ---------------------------------------------------------------------------
// 项目综合等级（security_grade）—— 整个项目的结论，不是单条漏洞的
// ---------------------------------------------------------------------------

const GRADE: Record<SecurityGrade, TagSpec> = {
  critical: { color: 'red', label: '严重', icon: <ThunderboltOutlined />, tip: '项目综合等级：严重' },
  high: { color: 'volcano', label: '高危', icon: <ExclamationCircleOutlined />, tip: '项目综合等级：高危' },
  medium: { color: 'gold', label: '中危', icon: <ExclamationCircleOutlined />, tip: '项目综合等级：中危' },
  safe: { color: 'success', label: '安全', icon: <CheckCircleOutlined />, tip: '项目综合等级：安全' },
}

export function SecurityGradeTag({ value }: { value: SecurityGrade }): ReactNode {
  const s = GRADE[value]
  return (
    <Tooltip title={s.tip}>
      <Tag color={s.color} icon={s.icon}>
        综合 {s.label}
      </Tag>
    </Tooltip>
  )
}

// ---------------------------------------------------------------------------
// 攻击链节点的验证状态（Q24 定案 = 方案 A）
// 这个标签是报告可信度的关键：inferred 表示该环**并未实际执行**，只是推演
// ---------------------------------------------------------------------------

const VERIFICATION: Record<VerificationStatus, TagSpec> = {
  verified: {
    color: 'success',
    label: '已验证',
    icon: <EyeOutlined />,
    tip: '该攻击环节已在沙箱内实际执行并观测到预期结果',
  },
  inferred: {
    color: 'warning',
    label: '推演',
    icon: <QuestionCircleOutlined />,
    tip: '该环节由规则引擎推演得出，**并未实际执行**。报告中会显式声明该环未经验证',
  },
}

export function VerificationTag({ value }: { value: VerificationStatus }): ReactNode {
  const s = VERIFICATION[value]
  return (
    <Tooltip title={s.tip}>
      <Tag color={s.color} icon={s.icon}>
        {s.label}
      </Tag>
    </Tooltip>
  )
}

// ---------------------------------------------------------------------------
// 阶段状态
// ---------------------------------------------------------------------------

const STAGE_STATUS: Record<StageStatus, TagSpec> = {
  pending: { color: 'default', label: '等待', icon: <ClockCircleOutlined />, tip: '尚未开始' },
  running: { color: 'processing', label: '进行中', icon: <ClockCircleOutlined />, tip: '正在执行' },
  completed: { color: 'success', label: '完成', icon: <CheckCircleOutlined />, tip: '执行成功' },
  failed: { color: 'error', label: '失败', icon: <CloseCircleOutlined />, tip: '执行失败' },
  skipped: {
    color: 'warning',
    label: '跳过',
    icon: <MinusCircleOutlined />,
    tip: '前置条件不满足（如源码同步失败），本阶段被跳过 —— 并非成功',
  },
}

export function StageStatusTag({ value }: { value: StageStatus }): ReactNode {
  const s = STAGE_STATUS[value]
  return (
    <Tooltip title={s.tip}>
      <Tag color={s.color} icon={s.icon}>
        {s.label}
      </Tag>
    </Tooltip>
  )
}
