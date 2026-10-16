/**
 * F3 左侧：漏洞列表（筛选栏 + 表格），同时是 F3↔F4 联动的「接收端」。
 *
 * 联动全部经由 `useVulnSelection` 这个 store，本组件与拓扑模块之间**零 import**：
 *   - 点图谱上的漏洞节点 → 拓扑模块调用 selectVuln(id) → 本组件高亮并滚动到该行；
 *     若该行被当前筛选条件挡住，则自动清空筛选把它露出来（见下方 effect）。
 *   - hover 表格行 → hoverVuln(id) → 图谱弱高亮对应节点（反之亦然）。
 *   - focusedNodeId 由拓扑模块在点节点时设置，与 selectedVulnId 成对变化，
 *     这里把它当作「滚动定位」的触发信号使用。
 * **节点 → 漏洞的映射由拓扑模块负责**（它手里才有攻击链），本组件只消费选中的 id。
 */
import { useQuery } from '@tanstack/react-query'
import { Alert, Input, Select, Space, Table, Tooltip, Typography } from 'antd'
import type { TableColumnsType } from 'antd'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'

import { vulnApi } from '@/api/endpoints'
import type { Severity, Vulnerability, VulnQuery, VulnStatus } from '@/api/types'
import { SeverityTag, VulnStatusTag } from '@/components/tags'
import { useVulnSelection } from '@/store/vulnSelection'

const { Text } = Typography

const STATUS_OPTIONS: Array<{ value: VulnStatus; label: string }> = [
  { value: 'unverified', label: '待验证' },
  { value: 'verified', label: '已验证' },
  { value: 'potential', label: '潜在' },
  { value: 'rejected', label: '已排除' },
]

const SEVERITY_OPTIONS: Array<{ value: Severity; label: string }> = [
  { value: 'critical', label: '严重' },
  { value: 'high', label: '高危' },
  { value: 'medium', label: '中危' },
  { value: 'low', label: '低危' },
]

const COLUMNS: TableColumnsType<Vulnerability> = [
  {
    title: '漏洞类型',
    dataIndex: 'vuln_type',
    key: 'vuln_type',
    width: 132,
    ellipsis: true,
    render: (value: string) => (
      <Tooltip title={value}>
        <span>{value}</span>
      </Tooltip>
    ),
  },
  {
    title: '严重度',
    dataIndex: 'severity',
    key: 'severity',
    width: 84,
    render: (value: Severity) => <SeverityTag value={value} />,
  },
  {
    title: '状态',
    dataIndex: 'status',
    key: 'status',
    width: 92,
    render: (value: VulnStatus) => <VulnStatusTag value={value} />,
  },
  {
    title: '位置',
    key: 'location',
    width: 168,
    ellipsis: true,
    render: (_, record) => {
      const text = `${record.file_path}:${record.line_start}`
      return (
        <Tooltip title={`${record.file_path}:${record.line_start}-${record.line_end}`}>
          <span className="vuln-mono">{text}</span>
        </Tooltip>
      )
    },
  },
  {
    title: 'CVSS',
    dataIndex: 'cvss_score',
    key: 'cvss_score',
    width: 72,
    sorter: (a, b) => a.cvss_score - b.cvss_score,
    render: (value: number) => <span className="vuln-mono">{value.toFixed(1)}</span>,
  },
  {
    title: '下沉点',
    dataIndex: 'sink_symbol',
    key: 'sink_symbol',
    width: 140,
    ellipsis: true,
    render: (value: string) => (
      <Tooltip title={value}>
        <span className="vuln-mono">{value}</span>
      </Tooltip>
    ),
  },
]

export function VulnList({ assessmentId }: { assessmentId: number | null }): ReactNode {
  const selectedVulnId = useVulnSelection((s) => s.selectedVulnId)
  const hoveredVulnId = useVulnSelection((s) => s.hoveredVulnId)
  const focusedNodeId = useVulnSelection((s) => s.focusedNodeId)
  const selectVuln = useVulnSelection((s) => s.selectVuln)
  const hoverVuln = useVulnSelection((s) => s.hoverVuln)

  const [status, setStatus] = useState<VulnStatus | undefined>(undefined)
  const [severity, setSeverity] = useState<Severity | undefined>(undefined)
  /** 输入框里正在敲的字 —— 与下面真正提交给后端的 keyword 分开，避免每敲一个字就打一次接口 */
  const [keywordInput, setKeywordInput] = useState('')
  const [keyword, setKeyword] = useState('')

  const query = useMemo<VulnQuery>(
    () => ({
      status,
      severity,
      keyword: keyword.trim() || undefined,
      // 一次性取够：图谱联动要求「选中的那行一定在表里」，分页会把目标行切到别的页上去
      page_size: 200,
    }),
    [status, severity, keyword],
  )

  const { data, isFetching, isError, error } = useQuery({
    queryKey: ['vulns', assessmentId, query],
    // 评估 id 走路径（列表挂在评估任务下），故作为第一个参数传入
    queryFn: () => vulnApi.list(assessmentId as number, query),
    // assessmentId 为 null 时不发请求（外层还没选评估任务）
    enabled: assessmentId !== null,
  })

  const items = useMemo(() => data?.items ?? [], [data])
  const hasFilter = status !== undefined || severity !== undefined || keyword !== ''

  // --- 联动①：外部（拓扑图谱）选中的漏洞若被筛选条件挡住，自动收起筛选把它露出来 ---
  // 刻意写成「渲染期调整 state」而不是放在 effect 里：effect 要先提交一版「列表里
  // 没有这一行」的界面再清筛选，会闪一下并多跑一轮渲染。这里让 React 直接丢弃这版
  // 结果重渲染，用户看不到中间态。
  // 不会死循环：清空后 hasFilter 变 false，下一轮这个条件就不成立了。
  if (
    selectedVulnId != null &&
    !isFetching &&
    hasFilter &&
    !items.some((v) => v.id === selectedVulnId)
  ) {
    setStatus(undefined)
    setSeverity(undefined)
    setKeyword('')
    setKeywordInput('')
  }

  // --- 联动②：选中项变化（或图谱点了节点）→ 把对应行滚进可视区 ---
  const tableWrapRef = useRef<HTMLDivElement | null>(null)
  useEffect(() => {
    if (selectedVulnId == null) return
    const row = tableWrapRef.current?.querySelector<HTMLElement>(
      `tr[data-row-key="${selectedVulnId}"]`,
    )
    row?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }, [selectedVulnId, focusedNodeId, items])

  // --- 高亮：选中态 + 悬停态（悬停来自图谱 hover，也是本表自身 hover） ---
  const rowClassName = (record: Vulnerability): string => {
    const classes: string[] = []
    if (record.id === selectedVulnId) classes.push('vuln-row-selected')
    else if (record.id === hoveredVulnId) classes.push('vuln-row-hovered')
    return classes.join(' ')
  }

  return (
    <div>
      <Space wrap size={8} style={{ marginBottom: 10 }}>
        <Select<VulnStatus>
          placeholder="状态（全部）"
          allowClear
          style={{ width: 128 }}
          value={status}
          options={STATUS_OPTIONS}
          onChange={(value: VulnStatus | undefined) => setStatus(value)}
        />
        <Select<Severity>
          placeholder="严重度（全部）"
          allowClear
          style={{ width: 132 }}
          value={severity}
          options={SEVERITY_OPTIONS}
          onChange={(value: Severity | undefined) => setSeverity(value)}
        />
        <Input.Search
          placeholder="搜索类型 / 路径 / 符号"
          allowClear
          style={{ width: 210 }}
          value={keywordInput}
          onChange={(event) => setKeywordInput(event.target.value)}
          // 回车 / 点放大镜 / 点清空才真正发起查询（走后端 keyword 参数）
          onSearch={(value: string) => setKeyword(value)}
        />
        <Text type="secondary" style={{ fontSize: 12 }}>
          共 {data?.total ?? 0} 条
        </Text>
      </Space>

      {isError && (
        <Alert
          style={{ marginBottom: 10 }}
          type="error"
          showIcon
          message="漏洞列表加载失败"
          description={error instanceof Error ? error.message : '未知错误'}
        />
      )}

      <div ref={tableWrapRef}>
        <Table<Vulnerability>
          rowKey="id"
          size="small"
          columns={COLUMNS}
          dataSource={items}
          loading={isFetching}
          // 关掉分页，保证「图谱点中的那条」永远能在当前渲染的列表里被高亮到
          pagination={false}
          scroll={{ y: 'calc(100vh - 400px)', x: 700 }}
          rowClassName={rowClassName}
          onRow={(record: Vulnerability) => ({
            onClick: () => selectVuln(record.id),
            onMouseEnter: () => hoverVuln(record.id),
            onMouseLeave: () => hoverVuln(null),
            style: { cursor: 'pointer' as const },
          })}
        />
      </div>
    </div>
  )
}
