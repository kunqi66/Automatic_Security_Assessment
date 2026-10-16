/**
 * 图例：颜色 + 线型 + **文字** 三重编码。
 *
 * 颜色只用于辅助识别节点类型；「已验证 / 推演」这一层信息不能只靠颜色区分，
 * 必须有文字说明 —— 色盲用户、黑白打印、截图转灰都要能读出来
 * （与 components/tags.tsx 的全站三重编码约定一致）。
 *
 * 节点类型的配色与中文名一律取自 constants.ts 的 CHAIN_NODE_META，不在这里另写一份。
 */
import { Card, Space } from 'antd'
import type { ReactNode } from 'react'

import type { ChainNodeType } from '@/api/types'
import { CHAIN_NODE_META } from '@/constants'

import { EDGE_DASH_ARRAY } from './layout'

/** 固定顺序，避免依赖对象键顺序导致图例次序漂移 */
const NODE_TYPE_ORDER: ChainNodeType[] = [
  'entry',
  'vuln',
  'credential',
  'shell',
  'host',
  'impact',
]

/** 线型示意图：用的就是画布上真实的线宽/虚线参数，图例与图严格一致 */
function LineSample({ dashed }: { dashed: boolean }): ReactNode {
  return (
    <svg width={34} height={8} aria-hidden="true" style={{ flex: '0 0 auto' }}>
      <line
        x1={1}
        y1={4}
        x2={33}
        y2={4}
        stroke={dashed ? '#bfbfbf' : '#595959'}
        strokeWidth={dashed ? 1.4 : 1.6}
        strokeDasharray={dashed ? EDGE_DASH_ARRAY : undefined}
      />
    </svg>
  )
}

function LegendRow({ children }: { children: ReactNode }): ReactNode {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, lineHeight: '18px' }}>
      {children}
    </div>
  )
}

export function TopologyLegend(): ReactNode {
  return (
    <Card
      size="small"
      title="图例"
      style={{ width: 252, background: 'rgba(255, 255, 255, 0.95)' }}
      styles={{ header: { minHeight: 32, fontSize: 12 }, body: { padding: '8px 12px' } }}
    >
      <Space direction="vertical" size={4} style={{ width: '100%' }}>
        {NODE_TYPE_ORDER.map((type) => {
          const meta = CHAIN_NODE_META[type]
          return (
            <LegendRow key={type}>
              <span
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: 2,
                  background: meta.color,
                  flex: '0 0 auto',
                }}
              />
              <span style={{ color: '#262626' }}>{meta.label}</span>
            </LegendRow>
          )
        })}

        {/* 分隔：上面是「节点类型」（颜色），下面是「是否实测」（线型） */}
        <div style={{ borderTop: '1px solid #f0f0f0', margin: '4px 0' }} />

        <LegendRow>
          <LineSample dashed={false} />
          <span style={{ color: '#262626' }}>
            <b>实线</b> = 已验证（沙箱内实际执行）
          </span>
        </LegendRow>
        <LegendRow>
          <LineSample dashed />
          <span style={{ color: '#262626' }}>
            <b>虚线</b> = 含推演环节（未实际执行）
          </span>
        </LegendRow>

        <div style={{ marginTop: 4, fontSize: 11, color: '#8c8c8c', lineHeight: '16px' }}>
          颜色只区分节点类型；<b>边框虚实</b>与「推演·未实测」角标才表示该环节是否真的跑过。
        </div>
      </Space>
    </Card>
  )
}
