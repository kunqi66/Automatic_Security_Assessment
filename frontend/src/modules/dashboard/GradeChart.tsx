/**
 * 项目综合等级分布 —— ECharts 环形图。
 *
 * ⚠️ 这张图说的是**整个项目**的结论（security_grade），不是单条漏洞的严重度。
 * 两者恰好都能取到「严重 / 高危 / 中危」这些字眼，所以在卡片里显式写清楚区别，
 * 免得看的人把环形图和旁边的严重度图当成同一件事。
 *
 * 数据 `summary.grade_distribution` 是后端算好的各等级项目数，前端原样画出来。
 */
import { Card, Empty, Typography } from 'antd'
import type { EChartsOption } from 'echarts'
import ReactECharts from 'echarts-for-react'
import { useMemo } from 'react'
import type { ReactNode } from 'react'

import type { SecurityGrade } from '@/api/types'

import { ChartLegend, GRADE_COLOR, GRADE_LABEL, GRADE_ORDER, INK } from './shared'
import type { LegendItem } from './shared'

interface GradeChartProps {
  distribution: Record<SecurityGrade, number>
}

export function GradeChart({ distribution }: GradeChartProps): ReactNode {
  // 按固定顺序取色与取名，不重排、不合并、不计算占比
  const items: LegendItem[] = GRADE_ORDER.map((grade) => ({
    color: GRADE_COLOR[grade],
    label: GRADE_LABEL[grade],
    value: distribution[grade],
  }))

  const option = useMemo<EChartsOption>(
    () => ({
      tooltip: { trigger: 'item', formatter: '{b}：{c} 个项目' },
      series: [
        {
          type: 'pie',
          radius: ['54%', '76%'],
          center: ['50%', '50%'],
          avoidLabelOverlap: true,
          // 2px 表面间隙：相邻扇区之间留白，边界不靠颜色硬碰硬
          itemStyle: { borderColor: '#fff', borderWidth: 2 },
          label: { color: INK.secondary, fontSize: 12, formatter: '{b} {c}' },
          labelLine: { length: 8, length2: 10, lineStyle: { color: 'rgba(0, 0, 0, 0.25)' } },
          data: GRADE_ORDER.map((grade) => ({
            name: GRADE_LABEL[grade],
            value: distribution[grade],
            itemStyle: { color: GRADE_COLOR[grade] },
          })),
        },
      ],
    }),
    [distribution],
  )

  // 纯展示判空：全部为 0 时画布上什么都没有，不如直接给个空状态
  const hasData = items.some((item) => item.value > 0)

  return (
    <Card title="项目综合等级">
      {hasData ? (
        <ReactECharts option={option} style={{ height: 236 }} notMerge />
      ) : (
        <div style={{ height: 236, display: 'grid', placeItems: 'center' }}>
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无已完成评估的项目" />
        </div>
      )}

      <div style={{ marginTop: 12 }}>
        <ChartLegend items={items} />
      </div>

      <Typography.Paragraph
        type="secondary"
        style={{ marginTop: 10, marginBottom: 0, fontSize: 12, lineHeight: 1.6 }}
      >
        这是<strong>整个项目</strong>的结论：由项目内全部漏洞按确定性评分规则汇总得出。
        它与「漏洞严重度」是<strong>两个不同概念</strong> —— 后者描述的是单条漏洞本身的危险程度。
      </Typography.Paragraph>
    </Card>
  )
}
