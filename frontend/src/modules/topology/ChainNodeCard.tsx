/**
 * 攻击链节点的自定义渲染（React Flow 自定义 node type：`'chain'`）。
 *
 * ── 本模块最重要的一条信息：这个环节到底跑没跑过 ──────────────────────
 * `verification_status` 的两种取值必须在视觉上一眼可分，因为它决定了报告的可信度：
 *   - `verified`：**实线边框** + 正常饱和度 + 实心色点 → 该环节已在沙箱内实际执行；
 *   - `inferred`：**虚线边框** + 降饱和度（saturate 0.45）+ 半透明 + 右上角「推演」文字角标
 *                 → 该环节**并未实际执行**，只是规则引擎的推演结果。
 * 角标坚持用**文字**而非只靠颜色/虚实：色盲用户、黑白打印、截图转灰都要能读出这层区别
 * （与 components/tags.tsx 的三重编码约定一致）。
 *
 * 节点卡片里展示的每个字段都直接来自后端节点对象，前端不做任何推断或补全。
 */
import { Handle, Position } from '@xyflow/react'
import type { NodeProps } from '@xyflow/react'
import { Tag, Tooltip } from 'antd'
import type { CSSProperties, ReactNode } from 'react'

import { CHAIN_NODE_META } from '@/constants'

import { NODE_HEIGHT, NODE_WIDTH } from './layout'
import type { ChainFlowNode } from './layout'

/** 连接点：保持可见但低调，只用于让边端点有落点 */
const HANDLE_STYLE: CSSProperties = {
  width: 5,
  height: 5,
  background: '#bfbfbf',
  border: 'none',
}

/** 只做单行截断，节点尺寸固定，不因文本长短抖动 */
const ELLIPSIS: CSSProperties = {
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
}

export function ChainNodeCard({ data, selected }: NodeProps<ChainFlowNode>): ReactNode {
  const { chain, highlight } = data
  // 节点类型理论上一定在 CHAIN_NODE_META 里；真遇到后端多出来的新类型也不让整张图崩掉
  const meta = CHAIN_NODE_META[chain.node_type] ?? { label: chain.node_type, color: '#8c8c8c' }
  const inferred = chain.verification_status === 'inferred'

  // 联动高亮（来自漏洞表格）与 React Flow 自身选中态合并成一种「选中」表现
  const isSelected = selected === true || highlight === 'selected'
  const isHovered = highlight === 'hovered'

  const cardStyle: CSSProperties = {
    position: 'relative',
    height: '100%',
    boxSizing: 'border-box',
    padding: '8px 10px',
    borderRadius: 8,
    background: '#fff',
    // 边框虚实 = 是否实测；边框颜色 = 节点类型；边框粗细/光晕 = 联动选中态
    borderStyle: inferred ? 'dashed' : 'solid',
    borderWidth: isSelected ? 2.5 : inferred ? 1.5 : 2,
    borderColor: isSelected ? '#1677ff' : meta.color,
    boxShadow: isSelected
      ? '0 0 0 3px rgba(22, 119, 255, 0.25)'
      : isHovered
        ? '0 0 0 3px rgba(22, 119, 255, 0.12)'
        : '0 1px 2px rgba(0, 0, 0, 0.06)',
    // 推演环节整体降饱和 + 半透明：视觉上「虚」下去，与实测环节拉开层级
    opacity: inferred ? 0.78 : 1,
    filter: inferred ? 'saturate(0.45)' : undefined,
    cursor: 'pointer',
  }

  return (
    <div style={{ position: 'relative', width: NODE_WIDTH, height: NODE_HEIGHT }}>
      <Handle type="target" position={Position.Top} style={HANDLE_STYLE} />

      <div style={cardStyle}>
        {/* 第一行：节点类型（色点 + 中文名）+ 关联漏洞标记 + 命中规则编号 */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, height: 18 }}>
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: 2,
              background: meta.color,
              flex: '0 0 auto',
            }}
          />
          <span style={{ fontSize: 11, color: '#595959', flex: '0 0 auto' }}>{meta.label}</span>

          {chain.vuln_id !== null && (
            <Tooltip
              title={`关联漏洞 #${chain.vuln_id} —— 点击本节点会在左侧漏洞表格中选中它`}
            >
              <Tag
                color="red"
                style={{ margin: 0, fontSize: 10, lineHeight: '16px', padding: '0 4px' }}
              >
                关联漏洞 #{chain.vuln_id}
              </Tag>
            </Tooltip>
          )}

          {chain.rule_id !== null && (
            <span
              style={{
                marginLeft: 'auto',
                fontSize: 10,
                color: '#8c8c8c',
                fontFamily: 'monospace',
              }}
            >
              {chain.rule_id}
            </span>
          )}
        </div>

        {/* 第二行：节点主标题 */}
        <div
          style={{
            ...ELLIPSIS,
            marginTop: 4,
            fontSize: 13,
            fontWeight: 600,
            color: inferred ? '#434343' : '#262626',
          }}
          title={chain.label}
        >
          {chain.label}
        </div>

        {/* 第三行：节点细节（如 app.py:42 · cursor.execute） */}
        <div
          style={{ ...ELLIPSIS, marginTop: 2, fontSize: 11, color: '#8c8c8c' }}
          title={chain.detail}
        >
          {chain.detail}
        </div>
      </div>

      {/*
        「推演」角标刻意放在降饱和的卡片**外面**，否则它自己也会被 filter 掉颜色。
        它是文字而不是图标：这是整张图可信度的关键标注。
      */}
      {inferred && (
        <span
          style={{
            position: 'absolute',
            top: -8,
            right: -6,
            padding: '0 6px',
            height: 16,
            lineHeight: '16px',
            fontSize: 10,
            borderRadius: 8,
            background: '#fff7e6',
            border: '1px solid #ffd591',
            color: '#d46b08',
            whiteSpace: 'nowrap',
          }}
        >
          推演 · 未实测
        </span>
      )}

      <Handle type="source" position={Position.Bottom} style={HANDLE_STYLE} />
    </div>
  )
}
