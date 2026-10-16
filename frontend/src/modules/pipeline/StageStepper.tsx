/**
 * 流水线阶段进度 —— 按 STAGE_ORDER 固定顺序展示五个阶段。
 *
 * 与「可控多智能体」原则的关系：五阶段里**有且只有 report_gen（报告生成）**会调用大模型，
 * 且模型只负责自然语言措辞；漏洞判定、综合等级、攻击链拓扑、整改顺序全部由确定性代码产出。
 * 所以本组件只做「后端编排状态的可视化」：stages 直接来自 Assessment.stages，
 * 前端不推断、不补全、不把缺失阶段脑补成成功。
 *
 * ⚠️ skipped ≠ success：跳过是因为前置条件不满足（例如源码同步失败），该阶段根本没有产出，
 * 结论不可视为「已确认」。因此 skipped 用独立的图标/颜色，并把 StageState.note 里的原因
 * 显式写出来 —— 否则读者会误以为整条流水线跑完整了。
 */
import { MinusCircleOutlined } from '@ant-design/icons'
import { Steps, Tooltip, Typography } from 'antd'
import type { ReactNode } from 'react'

import type { StageName, StageState, StageStatus } from '@/api/types'
import { StageStatusTag } from '@/components/tags'
import { STAGE_DESCRIPTIONS, STAGE_LABELS, STAGE_ORDER } from '@/constants'

/** 阶段状态 → AntD Steps 的视觉状态（一一映射，不做任何业务推断） */
function toStepStatus(status: StageStatus): 'wait' | 'process' | 'finish' | 'error' {
  switch (status) {
    case 'completed':
      return 'finish'
    case 'failed':
      return 'error'
    case 'running':
      return 'process'
    case 'pending':
    case 'skipped':
      return 'wait'
  }
}

/** note 的含义随状态而变：失败是失败原因，跳过是跳过原因，成功则一般是校验说明 */
function notePrefix(status: StageStatus): string {
  if (status === 'skipped') return '跳过原因：'
  if (status === 'failed') return '失败原因：'
  return ''
}

export function StageStepper({ stages }: { stages: StageState[] }): ReactNode {
  // 后端只返回「已开始过的阶段」，缺失的即为 pending —— 在这里补齐成完整五步
  const byStage = new Map<StageName, StageState>(
    stages.map((s): [StageName, StageState] => [s.stage, s]),
  )

  // 当前阶段：优先取 running；没有 running 时按「已了结的阶段数」定位，
  // 这样 failed / skipped 的步骤也能停在正确的位置上（其 status 会被下面的覆盖为 error）
  const runningIndex = STAGE_ORDER.findIndex((s) => byStage.get(s)?.status === 'running')
  const settledCount = STAGE_ORDER.filter((s) => {
    const st = byStage.get(s)?.status
    return st === 'completed' || st === 'failed' || st === 'skipped'
  }).length
  const current = runningIndex >= 0 ? runningIndex : settledCount

  const hasSkipped = stages.some((s) => s.status === 'skipped')

  const items = STAGE_ORDER.map((stage) => {
    const state = byStage.get(stage)
    const status: StageStatus = state?.status ?? 'pending'
    const note = state?.note ?? null

    return {
      title: (
        <Tooltip title={STAGE_DESCRIPTIONS[stage]}>
          <span style={{ fontWeight: status === 'running' ? 600 : 400 }}>
            {STAGE_LABELS[stage]}
          </span>
        </Tooltip>
      ),
      status: toStepStatus(status),
      // skipped 单独给图标 —— 不能落回 pending 的灰圈，也不能借用 success 的绿勾
      icon: status === 'skipped' ? <MinusCircleOutlined style={{ color: '#faad14' }} /> : undefined,
      description: (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, paddingBottom: 4 }}>
          <StageStatusTag value={status} />
          {note && (
            <Typography.Text
              type={status === 'failed' ? 'danger' : 'secondary'}
              style={{ fontSize: 12 }}
            >
              {notePrefix(status)}
              {note}
            </Typography.Text>
          )}
        </div>
      ),
    }
  })

  return (
    <div>
      <Steps size="small" direction="vertical" current={current} items={items} />
      {hasSkipped && (
        <Typography.Text type="warning" style={{ fontSize: 12, display: 'block', marginTop: 8 }}>
          注意：「跳过」不等于「完成」。被跳过的阶段没有产出，其结论为空缺而非已验证。
        </Typography.Text>
      )}
    </div>
  )
}
