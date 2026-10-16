/**
 * 沙箱资源采样曲线（双 Y 轴：CPU 使用率 % 与 内存占用 MB，X 轴为采样时间 ts）。
 *
 * 采的是**沙箱容器**（poc_verify 阶段动态验证用的那个容器）的资源占用，
 * 不是宿主机全局指标 —— 容器销毁后即停止采样，所以已完成任务的曲线长度是有限的，
 * 这一点在图表下方有一行说明，避免被误读成「机器整体负载」。
 *
 * 资源数据来自后端采样表，与 LLM 无关：模型不可用不影响本图（可控多智能体原则）。
 */
import { useQuery } from '@tanstack/react-query'
import { Alert, Empty, Spin, Typography } from 'antd'
import type { EChartsOption } from 'echarts'
import ReactECharts from 'echarts-for-react'
import dayjs from 'dayjs'
import type { ReactNode } from 'react'

import { errorMessage } from '@/api/client'
import { assessmentApi } from '@/api/endpoints'

const CPU_COLOR = '#1677ff'
const MEM_COLOR = '#d48806'

export function ResourceMetrics({ assessmentId }: { assessmentId: number | null }): ReactNode {
  const { data, isPending, isError, error } = useQuery({
    queryKey: ['assessment-metrics', assessmentId],
    queryFn: async () => {
      if (assessmentId === null) return []
      return assessmentApi.metrics(assessmentId)
    },
    enabled: assessmentId !== null,
    // 采样是持续写入的，轮询让曲线在任务运行期间保持「活」；任务结束后后端不再追加采样点
    refetchInterval: 5000,
  })

  if (assessmentId === null) {
    return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="请先选择一个评估任务" />
  }

  if (isPending) {
    return (
      <div style={{ textAlign: 'center', padding: 24 }}>
        <Spin />
      </div>
    )
  }

  if (isError) {
    return <Alert type="error" showIcon message="资源采样加载失败" description={errorMessage(error)} />
  }

  const samples = data ?? []
  if (samples.length === 0) {
    return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚未产生资源采样" />
  }

  const option: EChartsOption = {
    animation: false,
    tooltip: { trigger: 'axis' },
    legend: {
      data: ['CPU 使用率', '内存占用'],
      bottom: 0,
      itemHeight: 8,
      textStyle: { fontSize: 12 },
    },
    grid: { left: 56, right: 64, top: 16, bottom: 48 },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: samples.map((s) => dayjs(s.ts).format('HH:mm:ss')),
      axisLabel: { fontSize: 11 },
    },
    yAxis: [
      {
        type: 'value',
        name: 'CPU %',
        min: 0,
        max: 100,
        nameTextStyle: { fontSize: 11 },
        axisLabel: { fontSize: 11, formatter: '{value}%' },
        splitLine: { show: false },
      },
      {
        type: 'value',
        name: '内存 MB',
        min: 0,
        nameTextStyle: { fontSize: 11 },
        axisLabel: { fontSize: 11 },
        splitLine: { lineStyle: { type: 'dashed' } },
      },
    ],
    series: [
      {
        name: 'CPU 使用率',
        type: 'line',
        yAxisIndex: 0,
        smooth: true,
        showSymbol: false,
        data: samples.map((s) => Math.round(s.cpu_percent * 10) / 10),
        lineStyle: { width: 2, color: CPU_COLOR },
        itemStyle: { color: CPU_COLOR },
      },
      {
        name: '内存占用',
        type: 'line',
        yAxisIndex: 1,
        smooth: true,
        showSymbol: false,
        data: samples.map((s) => Math.round(s.memory_mb)),
        lineStyle: { width: 2, color: MEM_COLOR },
        itemStyle: { color: MEM_COLOR },
      },
    ],
  }

  return (
    <div>
      <ReactECharts option={option} style={{ height: 220 }} />
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        以上为沙箱容器的资源采样（cpu_percent / memory_mb），非宿主机全局负载；共 {samples.length} 个采样点。
      </Typography.Text>
    </div>
  )
}
