/**
 * 安全评估工作台 —— 单任务视角的三区布局。
 *
 *   顶部：任务选择器（选中项写进 URL 查询参数 ?assessmentId=<id>，刷新后保持）
 *   区一（左，约 1/3）：流水线监控 —— 阶段进度 / 实时日志 / 沙箱资源
 *   区二（右上）：攻击链拓扑图谱（由 topology 模块提供）
 *   区三（右下）：漏洞视窗与修复建议（由 vuln 模块提供）
 *
 * 关于「可控多智能体」原则：本页只做「展示」与「选择」，不含任何判定逻辑。
 * 综合等级、进度、阶段状态全部来自后端 Assessment；五个阶段里只有 report_gen 会调模型，
 * 且模型只产出自然语言，拿掉模型这些字段照样成立。前端不重算、不猜测、不美化。
 *
 * 任务处于 running 时才订阅日志流：SSE 连着是有成本的（服务端持有 Redis Stream 游标），
 * 终态任务不会再产生日志，没必要保持长连接。
 */
import { useQuery } from '@tanstack/react-query'
import { Alert, Card, Col, Empty, Flex, Progress, Row, Select, Space, Tag, Typography } from 'antd'
import type { ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'

import { errorMessage } from '@/api/client'
import { assessmentApi } from '@/api/endpoints'
import { SecurityGradeTag } from '@/components/tags'
import { LogStream } from '@/modules/pipeline/LogStream'
import { ResourceMetrics } from '@/modules/pipeline/ResourceMetrics'
import { StageStepper } from '@/modules/pipeline/StageStepper'
import { TopologyPanel } from '@/modules/topology'
import { VulnPanel } from '@/modules/vuln'

const EMPTY_HINT = '请先在上方选择一个评估任务'

function ZoneEmpty(): ReactNode {
  return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={EMPTY_HINT} style={{ padding: '24px 0' }} />
}

export default function Workbench(): ReactNode {
  const [searchParams, setSearchParams] = useSearchParams()

  // 以 URL 为唯一真源：刷新、分享链接、前进后退都保持一致，不用额外的本地 state 同步
  const rawId = searchParams.get('assessmentId')
  const parsed = rawId === null ? Number.NaN : Number(rawId)
  const currentId = Number.isInteger(parsed) && parsed > 0 ? parsed : null

  const { data: list, isPending: listPending } = useQuery({
    queryKey: ['assessments'],
    queryFn: assessmentApi.list,
  })

  // 列表项只用于下拉选项；当前任务的实时字段（stages/progress/grade）另外取 detail，
  // 运行中的任务每 3s 刷新一次，以便阶段推进和进度条跟着走
  const {
    data: current,
    isError: currentIsError,
    error: currentError,
  } = useQuery({
    queryKey: ['assessment', currentId],
    queryFn: async () => {
      if (currentId === null) throw new Error('缺少 assessmentId')
      return assessmentApi.get(currentId)
    },
    enabled: currentId !== null,
    // 用回调而非直接读 current：后者会让 current 在自己的初始化里引用自己（TS7022）。
    // 回调拿到的是 query 自身，语义相同且不构成循环。
    refetchInterval: (query) => (query.state.data?.status === 'running' ? 3000 : false),
  })

  const options = (list?.items ?? []).map((a) => ({
    value: a.id,
    label: `${a.project_name} #${a.id}`,
  }))

  const onSelect = (value: number | undefined): void => {
    const next = new URLSearchParams(searchParams)
    if (value === undefined) next.delete('assessmentId')
    else next.set('assessmentId', String(value))
    // replace 而不是 push：切换任务不该在浏览器历史里堆一长串记录
    setSearchParams(next, { replace: true })
  }

  const progressStatus =
    current?.status === 'failed'
      ? 'exception'
      : current?.status === 'completed'
        ? 'success'
        : current?.status === 'running'
          ? 'active'
          : 'normal'

  return (
    <Flex vertical gap={16}>
      <Card size="small" styles={{ body: { padding: 12 } }}>
        <Flex wrap align="center" justify="space-between" gap={12}>
          <Space size={8} wrap>
            <Typography.Text strong>评估任务</Typography.Text>
            <Select
              style={{ width: 280 }}
              placeholder="请选择评估任务"
              loading={listPending}
              options={options}
              value={currentId ?? undefined}
              onChange={onSelect}
              allowClear
              showSearch
              optionFilterProp="label"
            />
          </Space>

          {current && (
            <Space size={16} wrap>
              {current.security_grade ? (
                <SecurityGradeTag value={current.security_grade} />
              ) : (
                <Tag>综合等级未定</Tag>
              )}
              <Progress
                percent={current.progress}
                size="small"
                status={progressStatus}
                style={{ width: 180, marginBottom: 0 }}
              />
            </Space>
          )}
        </Flex>
      </Card>

      {currentIsError && (
        <Alert
          type="error"
          showIcon
          message="评估任务加载失败"
          description={errorMessage(currentError)}
        />
      )}

      <Row gutter={[16, 16]}>
        {/* 区一：流水线监控（左，约 1/3 宽） */}
        <Col xs={24} xl={8}>
          <Flex vertical gap={16}>
            <Card title="流水线阶段" size="small">
              {currentId !== null ? (
                <StageStepper stages={current?.stages ?? []} />
              ) : (
                <ZoneEmpty />
              )}
            </Card>

            <Card title="实时日志" size="small" styles={{ body: { padding: 12 } }}>
              {currentId !== null ? (
                <LogStream
                  assessmentId={currentId}
                  enabled={current?.status === 'running'}
                />
              ) : (
                <ZoneEmpty />
              )}
            </Card>

            <Card title="沙箱资源占用" size="small">
              {currentId !== null ? <ResourceMetrics assessmentId={currentId} /> : <ZoneEmpty />}
            </Card>
          </Flex>
        </Col>

        {/* 区二 / 区三：拓扑与漏洞（右，约 2/3 宽，纵向堆叠） */}
        <Col xs={24} xl={16}>
          <Flex vertical gap={16}>
            <Card title="攻击链拓扑图谱" size="small">
              {currentId !== null ? <TopologyPanel assessmentId={currentId} /> : <ZoneEmpty />}
            </Card>

            <Card title="漏洞视窗与修复建议" size="small">
              {currentId !== null ? <VulnPanel assessmentId={currentId} /> : <ZoneEmpty />}
            </Card>
          </Flex>
        </Col>
      </Row>
    </Flex>
  )
}
