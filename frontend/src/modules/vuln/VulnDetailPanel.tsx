/**
 * F3 右侧：漏洞详情（三个页签）。
 *
 * 详情单独按 id 拉一次 `vulnApi.get`，而不是复用列表里那一行对象：
 * 列表将来会分页/裁剪字段，详情要的 taint_trace 与 patch 可能很重，
 * 分开取也让「人工复核改了状态」后的刷新范围更清晰（invalidate ['vuln', id]）。
 */
import { useQuery } from '@tanstack/react-query'
import { Alert, Divider, Empty, Space, Spin, Tabs, Tag, Typography } from 'antd'
import type { TabsProps } from 'antd'
import { useState } from 'react'
import type { ReactNode } from 'react'

import { vulnApi } from '@/api/endpoints'
import type { Vulnerability } from '@/api/types'
import { SeverityTag, VulnStatusTag } from '@/components/tags'
import { useVulnSelection } from '@/store/vulnSelection'
import { PatchSection } from './PatchSection'
import { ReviewPanel } from './ReviewPanel'
import { TaintTimeline } from './TaintTimeline'

const { Title, Text, Paragraph } = Typography

// ---------------------------------------------------------------------------
// Tab 1：漏洞详情
// ---------------------------------------------------------------------------

function DetailTab({ vuln }: { vuln: Vulnerability }): ReactNode {
  const sameLine = vuln.line_start === vuln.line_end
  const location = `${vuln.file_path}:${vuln.line_start}${sameLine ? '' : `-${vuln.line_end}`}`

  return (
    <div>
      <Space wrap size={8} align="center">
        <Title level={4} style={{ margin: 0 }}>
          {vuln.vuln_type}
        </Title>
        <SeverityTag value={vuln.severity} />
        <VulnStatusTag value={vuln.status} />
        <Tag className="vuln-mono">CVSS {vuln.cvss_score.toFixed(1)}</Tag>
      </Space>

      <div style={{ margin: '8px 0 12px' }}>
        <Text className="vuln-mono" copyable={{ text: location }}>
          {location}
        </Text>
        <Text type="secondary" className="vuln-mono" style={{ marginLeft: 12 }}>
          下沉点 {vuln.sink_symbol}
        </Text>
      </div>

      {vuln.guard_blocked && (
        <Alert
          style={{ marginBottom: 12 }}
          type="warning"
          showIcon
          message="该条命中被 HarmlessGuard 载荷闸门拦截，未在沙箱内实际执行"
          description="探针载荷没有通过闸门校验，因此并未真正打到目标 —— 状态停留在「潜在」而非「已验证」。风险存在，但证据不足。"
        />
      )}

      <Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 4 }}>{vuln.description}</Paragraph>
      <Text type="secondary" style={{ fontSize: 12 }}>
        以上描述文字由大模型撰写。漏洞类型、严重度、CVSS 与验证状态全部由确定性代码产出，模型不参与任何判定。
      </Text>

      <Divider orientation="left" style={{ marginTop: 20 }}>
        污点步进
      </Divider>
      <TaintTimeline steps={vuln.taint_trace} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Tab 2：修复建议
// ---------------------------------------------------------------------------

function RemediationTab({ vuln }: { vuln: Vulnerability }): ReactNode {
  return (
    <div>
      <Title level={5} style={{ marginTop: 0 }}>
        整改建议
      </Title>
      <Paragraph style={{ whiteSpace: 'pre-wrap' }}>{vuln.remediation_note}</Paragraph>
      <Text type="secondary" style={{ fontSize: 12 }}>
        提醒：整改顺序由后端 scoring.py 按确定性规则排序，与本段文案无关 —— 模型只负责把结论讲清楚。
      </Text>

      <Divider style={{ margin: '16px 0' }} />

      {vuln.patch == null ? (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="该漏洞未生成补丁" />
      ) : (
        <PatchSection patch={vuln.patch} />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 主体
// ---------------------------------------------------------------------------

/**
 * 页签容器。由调用方用 `key={vuln.id}` 挂载 —— 换一条漏洞时整棵子树重挂，
 * 页签自然回到「漏洞详情」，不需要再写一个「props 变化就 setState」的 effect。
 */
function VulnTabs({ vuln }: { vuln: Vulnerability }): ReactNode {
  const [activeKey, setActiveKey] = useState('detail')

  const items: TabsProps['items'] = [
    { key: 'detail', label: '漏洞详情', children: <DetailTab vuln={vuln} /> },
    { key: 'fix', label: '修复建议', children: <RemediationTab vuln={vuln} /> },
    { key: 'review', label: '人工复核', children: <ReviewPanel vuln={vuln} /> },
  ]

  return <Tabs activeKey={activeKey} onChange={setActiveKey} items={items} />
}

export function VulnDetailPanel(): ReactNode {
  const selectedVulnId = useVulnSelection((s) => s.selectedVulnId)

  const { data: vuln, isLoading, isError, error } = useQuery({
    queryKey: ['vuln', selectedVulnId],
    queryFn: () => {
      if (selectedVulnId == null) throw new Error('未选中漏洞')
      return vulnApi.get(selectedVulnId)
    },
    enabled: selectedVulnId != null,
  })

  if (selectedVulnId == null) {
    return (
      <Empty
        description="从左侧列表选择一条漏洞，或在拓扑图谱上点击漏洞节点"
        style={{ marginTop: 48 }}
      />
    )
  }

  if (isLoading) {
    return (
      <div style={{ padding: 48, textAlign: 'center' }}>
        <Spin />
      </div>
    )
  }

  if (isError || vuln === undefined) {
    return (
      <Alert
        type="error"
        showIcon
        message="漏洞详情加载失败"
        description={error instanceof Error ? error.message : '未知错误'}
      />
    )
  }

  return <VulnTabs key={vuln.id} vuln={vuln} />
}
