/**
 * 漏洞严重度分布 —— ECharts 条形图。
 *
 * 这里用条形图而不是环形图，是因为严重度是**有序量**（严重 > 高危 > 中危 > 低危）：
 * 柱子的高低能直接读出量级关系，顺序本身就是信息。
 *
 * 数据 `summary.vuln_by_severity` 由后端统计，前端只负责染色与标注。
 */
import { Card, Empty, Typography } from 'antd'
import type { EChartsOption } from 'echarts'
import ReactECharts from 'echarts-for-react'
import { useMemo } from 'react'
import type { ReactNode } from 'react'

import type { Severity } from '@/api/types'

import {
  AXIS_LINE_STYLE,
  CHART_GRID,
  ChartLegend,
  INK,
  SEVERITY_COLOR,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  SPLIT_LINE_STYLE,
} from './shared'
import type { LegendItem } from './shared'

interface SeverityChartProps {
  distribution: Record<Severity, number>
}

export function SeverityChart({ distribution }: SeverityChartProps): ReactNode {
  const items: LegendItem[] = SEVERITY_ORDER.map((severity) => ({
    color: SEVERITY_COLOR[severity],
    label: SEVERITY_LABEL[severity],
    value: distribution[severity],
  }))

  const option = useMemo<EChartsOption>(
    () => ({
      grid: CHART_GRID,
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: '{b}：{c} 条漏洞' },
      xAxis: {
        type: 'category',
        data: SEVERITY_ORDER.map((severity) => SEVERITY_LABEL[severity]),
        axisLine: AXIS_LINE_STYLE,
        axisTick: { show: false },
        axisLabel: { color: INK.muted, fontSize: 12 },
      },
      yAxis: {
        type: 'value',
        // 计数值是整数，禁止出现 0.5 这样的刻度
        minInterval: 1,
        splitLine: SPLIT_LINE_STYLE,
        axisLabel: { color: INK.muted, fontSize: 12 },
      },
      series: [
        {
          type: 'bar',
          barMaxWidth: 48,
          // 4px 圆头，锚在基线上
          itemStyle: { borderRadius: [4, 4, 0, 0] },
          label: { show: true, position: 'top', color: INK.secondary, fontSize: 12 },
          data: SEVERITY_ORDER.map((severity) => ({
            value: distribution[severity],
            itemStyle: { color: SEVERITY_COLOR[severity] },
          })),
        },
      ],
    }),
    [distribution],
  )

  const hasData = items.some((item) => item.value > 0)

  return (
    <Card title="漏洞严重度">
      {hasData ? (
        <ReactECharts option={option} style={{ height: 236 }} notMerge />
      ) : (
        <div style={{ height: 236, display: 'grid', placeItems: 'center' }}>
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无漏洞记录" />
        </div>
      )}

      <div style={{ marginTop: 12 }}>
        <ChartLegend items={items} />
      </div>

      <Typography.Paragraph
        type="secondary"
        style={{ marginTop: 10, marginBottom: 0, fontSize: 12, lineHeight: 1.6 }}
      >
        描述的是<strong>单条漏洞</strong>本身的危险程度（依据 CVSS 分值），
        与左侧「项目综合等级」不是一回事。
      </Typography.Paragraph>
    </Card>
  )
}
