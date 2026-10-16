/**
 * 漏洞四态分布 —— 横向条形图 + 逐态含义说明。
 *
 * 四态是本系统里最容易看错的一处：光看「已验证 3 条」不知道 3 条意味着什么，
 * 所以这里除了条形图，每一态都配一句含义（已验证 = 沙箱内实际命中；
 * 潜在 = 静态命中但未过动态验证；待验证 = 尚未验证；已排除 = 经复核为误报）。
 *
 * 数据 `summary.vuln_by_status` 来自后端，前端不做任何重分类或合并。
 */
import { Card, Empty } from 'antd'
import type { EChartsOption } from 'echarts'
import ReactECharts from 'echarts-for-react'
import { useMemo } from 'react'
import type { ReactNode } from 'react'

import type { VulnStatus } from '@/api/types'

import {
  AXIS_LINE_STYLE,
  CHART_GRID,
  INK,
  SPLIT_LINE_STYLE,
  VULN_STATUS_META,
  VULN_STATUS_ORDER,
} from './shared'

interface StatusChartProps {
  distribution: Record<VulnStatus, number>
}

export function StatusChart({ distribution }: StatusChartProps): ReactNode {
  const option = useMemo<EChartsOption>(
    () => ({
      grid: CHART_GRID,
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: '{b}：{c} 条漏洞' },
      xAxis: {
        type: 'value',
        minInterval: 1,
        splitLine: SPLIT_LINE_STYLE,
        axisLabel: { color: INK.muted, fontSize: 12 },
      },
      yAxis: {
        type: 'category',
        // inverse：让「已验证」排在最上面，与下方说明列表的顺序一致
        inverse: true,
        data: VULN_STATUS_ORDER.map((status) => VULN_STATUS_META[status].label),
        axisLine: AXIS_LINE_STYLE,
        axisTick: { show: false },
        axisLabel: { color: INK.muted, fontSize: 12 },
      },
      series: [
        {
          type: 'bar',
          barMaxWidth: 22,
          // 横向柱的圆头在右端
          itemStyle: { borderRadius: [0, 4, 4, 0] },
          label: { show: true, position: 'right', color: INK.secondary, fontSize: 12 },
          data: VULN_STATUS_ORDER.map((status) => ({
            value: distribution[status],
            itemStyle: { color: VULN_STATUS_META[status].color },
          })),
        },
      ],
    }),
    [distribution],
  )

  const hasData = VULN_STATUS_ORDER.some((status) => distribution[status] > 0)

  return (
    <Card title="漏洞四态">
      {hasData ? (
        <ReactECharts option={option} style={{ height: 168 }} notMerge />
      ) : (
        <div style={{ height: 168, display: 'grid', placeItems: 'center' }}>
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无漏洞记录" />
        </div>
      )}

      {/* 说明列表：既是图例（色块 + 名称 + 数量），也是每个状态的定义 */}
      <ul style={{ listStyle: 'none', margin: '12px 0 0', padding: 0 }}>
        {VULN_STATUS_ORDER.map((status) => {
          const meta = VULN_STATUS_META[status]
          return (
            <li
              key={status}
              style={{
                display: 'flex',
                gap: 8,
                alignItems: 'baseline',
                padding: '7px 0',
                borderTop: '1px solid rgba(0, 0, 0, 0.06)',
              }}
            >
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  flex: '0 0 auto',
                  minWidth: 92,
                  fontSize: 13,
                  fontWeight: 600,
                  // 文字用中性墨色、图标才用状态色：状态色作正文在浅底上对比度不达标
                  // （中危金约 2:1），身份由图标 + 文字共同承担，不必让文字也染色
                  color: INK.primary,
                }}
              >
                <span aria-hidden="true" style={{ display: 'inline-flex', color: meta.color }}>
                  {meta.icon}
                </span>
                {meta.label}
              </span>
              <strong style={{ color: INK.primary, minWidth: 28, textAlign: 'right' }}>
                {distribution[status]}
              </strong>
              <span style={{ fontSize: 12, color: INK.muted, lineHeight: 1.6 }}>
                {meta.meaning}
              </span>
            </li>
          )
        })}
      </ul>
    </Card>
  )
}
