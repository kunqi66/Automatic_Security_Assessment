/**
 * 污点步进时间线（F3 详情页的核心可视化）。
 *
 * 一条污点路径本身就是「外部输入如何一路走到危险操作」的因果链，所以用 Timeline
 * 而不是表格 —— 顺序即语义，sanitizer 出现在哪一步决定了这条命中是不是误报。
 *
 * 四类节点用 **图标 + 配色 + 文字标签** 三重编码（tags.tsx 的同一原则）：
 *   source 蓝 · propagate 灰 · sanitize 绿 · sink 红
 */
import {
  AimOutlined,
  ImportOutlined,
  RetweetOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { Alert, Space, Tag, Timeline, Tooltip, Typography } from 'antd'
import type { ReactNode } from 'react'

import type { TaintStep } from '@/api/types'

const { Text } = Typography

type StepKind = TaintStep['step_type']

interface StepMeta {
  label: string
  icon: ReactNode
  /** 同时用作 Tag 底色与时间轴圆点颜色 */
  color: string
  hint: string
}

const STEP_META: Record<StepKind, StepMeta> = {
  source: {
    label: '污点源',
    icon: <ImportOutlined />,
    color: '#1677ff',
    hint: '外部可控输入从这一步进入程序',
  },
  propagate: {
    label: '传播',
    icon: <RetweetOutlined />,
    color: '#8c8c8c',
    hint: '污点沿数据流被传递到下游（赋值、拼接、传参）',
  },
  sanitize: {
    label: '净化',
    icon: <SafetyCertificateOutlined />,
    color: '#52c41a',
    hint: '污点在这一步被截断 —— 有它就说明后面的下沉点收不到可控输入',
  },
  sink: {
    label: '下沉点',
    icon: <AimOutlined />,
    color: '#cf1322',
    hint: '危险操作真正发生的地方（SQL 执行、命令执行、文件写入……）',
  },
}

export function TaintTimeline({ steps }: { steps: TaintStep[] }): ReactNode {
  if (steps.length === 0) {
    return (
      <Text type="secondary">
        该条漏洞没有可展示的污点路径（例如硬编码凭证这类「命中即为事实」的规则型漏洞）。
      </Text>
    )
  }

  const sanitized = steps.some((s) => s.step_type === 'sanitize')

  return (
    <div>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="怎么读这条路径"
        description="source 是外部可控输入的进入点，sink 是危险操作的发生点；路径上若出现 sanitizer，则污点已被净化。"
      />

      {sanitized && (
        <Alert
          type="success"
          showIcon
          style={{ marginBottom: 12 }}
          message="路径上存在净化函数：污点已被截断"
          description="下游虽然仍有危险调用，但它收到的已不是原始可控输入，这条命中通常会被判为误报（已排除）。"
        />
      )}

      <Timeline
        items={steps.map((step) => {
          const meta = STEP_META[step.step_type]
          return {
            key: step.step_index,
            color: meta.color,
            // 这里放的是已经构造好的元素（不是组件类型）—— 直接渲染，不要写成 <meta.icon />
            // 外面包一层 span 上色：AntD 图标用 currentColor，颜色随 kind 走
            dot: <span style={{ color: meta.color }}>{meta.icon}</span>,
            children: (
              <div>
                <Space wrap size={8} align="center">
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    第 {step.step_index + 1} 步
                  </Text>
                  <Tooltip title={meta.hint}>
                    <Tag color={meta.color} icon={meta.icon}>
                      {meta.label}
                    </Tag>
                  </Tooltip>
                  <Text strong className="vuln-mono">
                    {step.symbol}
                  </Text>
                </Space>

                <div>
                  <Text type="secondary" className="vuln-mono">
                    {step.file_path}:{step.line}
                  </Text>
                </div>

                <pre className="vuln-code">{step.code_snippet}</pre>

                {step.note && (
                  <div style={{ marginTop: 4 }}>
                    <Text type="secondary">{step.note}</Text>
                  </div>
                )}
              </div>
            ),
          }
        })}
      />
    </div>
  )
}
