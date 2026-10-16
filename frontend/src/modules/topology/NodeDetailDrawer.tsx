/**
 * 节点详情（点击图谱节点后从右侧滑出）。
 *
 * 展示的每个字段都直接来自后端节点对象，前端不做补全、不做推断。
 * 若该节点是 `inferred`，详情里额外用一段文字解释「未实际执行验证」——
 * 报告的可信度靠的就是这种显式声明，而不是让人误以为全是实测结果。
 */
import { Alert, Descriptions, Drawer, Space, Tag, Typography } from 'antd'
import type { ReactNode } from 'react'

import type { AttackChainNode } from '@/api/types'
import { VerificationTag } from '@/components/tags'
import { CHAIN_NODE_META } from '@/constants'

const { Paragraph } = Typography

export function NodeDetailDrawer({
  node,
  onClose,
}: {
  node: AttackChainNode | null
  onClose: () => void
}): ReactNode {
  const meta = node ? CHAIN_NODE_META[node.node_type] : null
  const inferred = node?.verification_status === 'inferred'

  return (
    <Drawer
      open={node !== null}
      onClose={onClose}
      placement="right"
      width={420}
      mask={false}
      title={node ? `攻击链节点 · ${node.label}` : '攻击链节点'}
      styles={{ body: { padding: 16 } }}
    >
      {node && meta && (
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          {inferred && (
            <Alert
              type="warning"
              showIcon
              message="该环节为推演结果，未实际执行验证"
              description="它由 exploit_chain 阶段的规则引擎（R1–R8）依据已确认的前置条件推导得到，并未在沙箱内实际执行。报告与结论中会显式声明该环未经验证，请勿据此判断漏洞已被利用。"
            />
          )}

          <Descriptions
            column={1}
            size="small"
            bordered
            items={[
              {
                key: 'label',
                label: '节点名称',
                children: node.label,
              },
              {
                key: 'node_type',
                label: '节点类型',
                children: <Tag color={CHAIN_NODE_META[node.node_type].color}>{meta.label}</Tag>,
              },
              {
                key: 'verification',
                label: '验证状态',
                children: <VerificationTag value={node.verification_status} />,
              },
              {
                key: 'rule',
                label: '命中规则',
                children: node.rule_id ? (
                  <Tag style={{ fontFamily: 'monospace' }}>{node.rule_id}</Tag>
                ) : (
                  <span style={{ color: '#8c8c8c' }}>无（根节点由入口识别产出，不命中推演规则）</span>
                ),
              },
              {
                key: 'vuln',
                label: '关联漏洞',
                children:
                  node.vuln_id !== null ? (
                    `#${node.vuln_id}（点击该节点会在左侧漏洞表格中选中它）`
                  ) : (
                    <span style={{ color: '#8c8c8c' }}>无 —— 该环节不对应单条漏洞</span>
                  ),
              },
              {
                key: 'detail',
                label: '环节说明',
                children: node.detail,
              },
              {
                key: 'id',
                label: '节点 ID',
                children: <span style={{ fontFamily: 'monospace' }}>{node.id}</span>,
              },
            ]}
          />

          <Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 0 }}>
            节点与边由 R1–R8 确定性规则引擎产出，边由 parent_node_id 推导；LLM 只负责把这条链写成
            自然语言叙述，且需通过「节点集合比对」校验，不会新增或遗漏节点。
          </Paragraph>
        </Space>
      )}
    </Drawer>
  )
}
