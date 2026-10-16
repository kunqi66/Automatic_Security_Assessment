/**
 * 实时日志流（深色终端风格）。
 *
 * 数据源是 useLogStream —— 它用 fetch + ReadableStream 手动解析 SSE（而不是 EventSource，
 * 因为 EventSource 无法带 Authorization 头，只能把 JWT 放进查询串，等于泄露凭证），
 * 断线时回传 Last-Event-ID 从 Redis Stream 重放，保证断线期间不丢日志。本组件只负责渲染。
 *
 * 「可控多智能体」原则的可见证据：整条日志里唯一与大模型相关的行都出现在 report_gen 阶段，
 * 且紧跟着是实体白名单校验、攻击链节点集合比对 —— 模型只写自然语言，不参与任何判定。
 * 日志中的「第 ④ 道校验」指：补丁打上后重跑污点引擎，确认该条污点路径确实消失；
 * 这是补丁验收的唯一硬标准（另三道是格式/窗口/干跑，见 PatchValidation）。前端原样展示，不做过滤。
 */
import { CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons'
import { Button, Flex, Space, Typography } from 'antd'
import dayjs from 'dayjs'
import { useEffect, useRef } from 'react'
import type { ReactNode } from 'react'

import type { LogEvent } from '@/api/types'
import { useLogStream } from '@/api/useLogStream'
import { STAGE_LABELS } from '@/constants'

const MONO_FONT =
  'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace'

/** 按 level 着色：debug 暗灰 / info 浅灰 / warn 黄 / error 红 */
const LEVEL_COLOR: Record<LogEvent['level'], string> = {
  debug: '#7f7f7f',
  info: '#d4d4d4',
  warn: '#e5c07b',
  error: '#f07178',
}

/** 距底部多少像素以内算「贴着底」—— 用于判断用户是否手动往上滚了 */
const STICK_THRESHOLD_PX = 24

function Dot({ color }: { color: string }): ReactNode {
  return (
    <span
      style={{
        display: 'inline-block',
        width: 8,
        height: 8,
        borderRadius: '50%',
        background: color,
        flexShrink: 0,
      }}
    />
  )
}

function stageLabel(stage: LogEvent['stage']): string {
  return stage === 'system' ? '系统' : STAGE_LABELS[stage]
}

function formatTime(ts: string): string {
  const d = dayjs(ts)
  return d.isValid() ? d.format('HH:mm:ss') : ts
}

export function LogStream({
  assessmentId,
  enabled,
}: {
  assessmentId: number | null
  enabled: boolean
}): ReactNode {
  const { logs, connected, finished, error, clear } = useLogStream(assessmentId, enabled)

  const boxRef = useRef<HTMLDivElement>(null)
  /** 是否「用户还贴着底部」。默认 true；用户一旦往上滚就置 false，此时新日志不再强制拉回 */
  const stickToBottomRef = useRef(true)

  // 切换任务时重置跟随状态，否则上个任务滚上去过会让新任务也不跟随
  useEffect(() => {
    stickToBottomRef.current = true
  }, [assessmentId])

  // 新日志到达：只有在用户仍贴着底部时才自动滚动。
  // 用 scrollTop 直接赋值（而非 scrollIntoView），避免带动外层页面一起滚动。
  useEffect(() => {
    const el = boxRef.current
    if (!el || !stickToBottomRef.current) return
    el.scrollTop = el.scrollHeight
  }, [logs])

  const onScroll = (): void => {
    const el = boxRef.current
    if (!el) return
    stickToBottomRef.current =
      el.scrollHeight - el.scrollTop - el.clientHeight < STICK_THRESHOLD_PX
  }

  let indicator: ReactNode
  if (error) {
    indicator = (
      <Space size={6}>
        <CloseCircleOutlined style={{ color: '#ff4d4f' }} />
        <Typography.Text type="danger" style={{ fontSize: 12 }}>
          {error}
        </Typography.Text>
      </Space>
    )
  } else if (connected) {
    indicator = (
      <Space size={6}>
        <Dot color="#52c41a" />
        <Typography.Text style={{ fontSize: 12 }}>已连接</Typography.Text>
      </Space>
    )
  } else if (finished) {
    indicator = (
      <Space size={6}>
        <CheckCircleOutlined style={{ color: '#8c8c8c' }} />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          已结束
        </Typography.Text>
      </Space>
    )
  } else {
    indicator = (
      <Space size={6}>
        <Dot color="#bfbfbf" />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {enabled ? '连接中…' : '未订阅（任务不在运行中）'}
        </Typography.Text>
      </Space>
    )
  }

  return (
    <div>
      <Flex align="center" justify="space-between" style={{ marginBottom: 8 }} gap={12}>
        {indicator}
        <Space size={8}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {logs.length} 行
          </Typography.Text>
          <Button size="small" onClick={clear} disabled={logs.length === 0}>
            清空
          </Button>
        </Space>
      </Flex>

      <div
        ref={boxRef}
        onScroll={onScroll}
        style={{
          background: '#1e1e1e',
          color: '#d4d4d4',
          fontFamily: MONO_FONT,
          fontSize: 12,
          lineHeight: 1.7,
          padding: '10px 12px',
          height: 320,
          overflowY: 'auto',
          borderRadius: 6,
        }}
      >
        {logs.length === 0 ? (
          <div style={{ color: '#6a737d' }}>
            {enabled ? '等待日志…' : '暂无日志：任务未处于运行状态时不会订阅日志流。'}
          </div>
        ) : (
          logs.map((l) => (
            <div key={l.id} style={{ display: 'flex', gap: 8, whiteSpace: 'pre-wrap' }}>
              <span style={{ color: '#6a737d', flexShrink: 0 }}>{formatTime(l.ts)}</span>
              <span style={{ color: '#555555', flexShrink: 0 }}>|</span>
              <span style={{ color: '#569cd6', flexShrink: 0 }}>{stageLabel(l.stage)}</span>
              <span style={{ color: '#555555', flexShrink: 0 }}>|</span>
              <span style={{ color: LEVEL_COLOR[l.level], wordBreak: 'break-word' }}>
                {l.message}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
