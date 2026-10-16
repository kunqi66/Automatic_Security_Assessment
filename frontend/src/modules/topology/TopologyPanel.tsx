/**
 * F4 攻击链拓扑图谱。
 *
 * ── 这一屏为什么值得单独做 ─────────────────────────────────────────────
 * 图谱回答的是一个别处回答不了的问题：「这些漏洞串起来能打到哪一步？」
 * 而它同时又最容易说过头 —— 所以本面板把「哪些环节真的跑过、哪些只是推演」
 * 放在第一位：顶部一行显式统计 + 节点边框虚实 + 「推演 · 未实测」角标 + 图例文字说明，
 * 四重声明，杜绝让人误以为整条链都是实测结果。
 *
 * ── 可信度：节点与边都不是模型编的（可控多智能体第一性原则）──────────
 * LLM 只产出自然语言、绝不参与判定。攻击链的节点与边**完全由 R1–R8 确定性规则引擎产出**，
 * 边由 parent_node_id 推导（见 api/types.ts 注释）；LLM 只负责把这条链写成一段人话叙述，
 * 写完后还要做「节点集合比对」校验，确认模型没有新增或遗漏节点。
 * 因此图上任何一个节点、任何一条边都是规则引擎的产物，可被重放验证。
 *
 * 数据流（单向，无隐藏状态）：
 *   assessmentApi.chain() → buildGraph()（纯函数，dagre 布局）→ decorateGraph()（叠加联动高亮）
 *   → React Flow 渲染；交互只通过 store/vulnSelection 与外部通信。
 */
import '@xyflow/react/dist/style.css'

import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
} from '@xyflow/react'
import type { Node } from '@xyflow/react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Empty, Flex, Skeleton } from 'antd'
import { useCallback, useEffect, useMemo, useState } from 'react'
import type { MouseEvent as ReactMouseEvent, ReactNode } from 'react'

import { errorMessage } from '@/api/client'
import { assessmentApi } from '@/api/endpoints'
import type { AttackChainNode } from '@/api/types'
import { CHAIN_NODE_META } from '@/constants'
import { useVulnSelection } from '@/store/vulnSelection'

import { ChainNodeCard } from './ChainNodeCard'
import { TopologyLegend } from './Legend'
import { NodeDetailDrawer } from './NodeDetailDrawer'
import { buildGraph, countByVerification, decorateGraph } from './layout'
import type { ChainGraph, ChainNodeData } from './layout'

/** 自定义节点类型注册表，模块级常量 —— 每次 render 新建对象会让 React Flow 反复重建节点 */
const NODE_TYPES = { chain: ChainNodeCard }

/**
 * F4 对外唯一出口。签名由 src/pages/Workbench/index.tsx 约定，不可改动。
 * 用 ReactFlowProvider 包一层，是为了让内层能用 useReactFlow() 拿到实例做命令式聚焦。
 */
export function TopologyPanel({ assessmentId }: { assessmentId: number | null }): ReactNode {
  return (
    <ReactFlowProvider>
      <TopologyCanvas assessmentId={assessmentId} />
    </ReactFlowProvider>
  )
}

function TopologyCanvas({ assessmentId }: { assessmentId: number | null }): ReactNode {
  // 命令式聚焦用（fitView）；useReactFlow 必须在 ReactFlowProvider 之内调用
  const { fitView } = useReactFlow()

  /** 当前打开详情的节点 */
  const [activeNodeId, setActiveNodeId] = useState<string | null>(null)

  // ── F3 ↔ F4 联动契约：只通过 store 通信，不 import 漏洞模块的组件 ──
  const selectedVulnId = useVulnSelection((s) => s.selectedVulnId)
  const hoveredVulnId = useVulnSelection((s) => s.hoveredVulnId)
  const focusedNodeId = useVulnSelection((s) => s.focusedNodeId)
  const selectVuln = useVulnSelection((s) => s.selectVuln)
  const hoverVuln = useVulnSelection((s) => s.hoverVuln)
  const focusNode = useVulnSelection((s) => s.focusNode)

  const { data, isPending, isError, error } = useQuery({
    queryKey: ['chain', assessmentId],
    queryFn: () => assessmentApi.chain(assessmentId as number),
    // assessmentId 为 null 时不发请求（外层还没选评估任务）
    enabled: assessmentId !== null,
  })

  const chainNodes = useMemo<AttackChainNode[]>(() => data ?? [], [data])

  // 布局只跟数据有关 —— 交互引起的重渲染不会重新跑 dagre
  const baseGraph = useMemo<ChainGraph>(() => buildGraph(chainNodes), [chainNodes])

  // 高亮只跟联动状态有关 —— 与布局解耦，切换选中不重算坐标
  const graph = useMemo(
    () => decorateGraph(baseGraph, { selectedVulnId, hoveredVulnId, focusedNodeId }),
    [baseGraph, selectedVulnId, hoveredVulnId, focusedNodeId],
  )

  const stats = useMemo(() => countByVerification(chainNodes), [chainNodes])

  const activeNode = useMemo(
    // activeNodeId 是 React Flow 的字符串 id，而后端节点主键是整数 —— 比较前统一字符串化
    () => chainNodes.find((node) => String(node.id) === activeNodeId) ?? null,
    [chainNodes, activeNodeId],
  )

  // ── 联动 ①：点节点 → 选中对应漏洞（若有关联）+ 聚焦 + 打开详情 ──
  const handleNodeClick = useCallback(
    (_event: ReactMouseEvent, node: Node): void => {
      const chain = (node.data as ChainNodeData).chain
      setActiveNodeId(node.id)
      focusNode(node.id)
      // 没有关联漏洞的环节（如「公网入口」）不改变表格选中态，避免把用户的选中清掉
      if (chain.vuln_id !== null) selectVuln(chain.vuln_id)
    },
    [focusNode, selectVuln],
  )

  // 联动 ②：悬停节点 → 写 hoveredVulnId（弱高亮），与「选中」区分开
  const handleNodeMouseEnter = useCallback(
    (_event: ReactMouseEvent, node: Node): void => {
      const chain = (node.data as ChainNodeData).chain
      if (chain.vuln_id !== null) hoverVuln(chain.vuln_id)
    },
    [hoverVuln],
  )

  const handleNodeMouseLeave = useCallback((): void => {
    hoverVuln(null)
  }, [hoverVuln])

  const handlePaneClick = useCallback((): void => {
    setActiveNodeId(null)
  }, [])

  const handleCloseDetail = useCallback((): void => {
    setActiveNodeId(null)
  }, [])

  // ── 联动 ③：漏洞表格选中某条漏洞 → 平滑聚焦到图谱里对应的节点 ──
  // 只在 selectedVulnId（或图数据本身）变化时触发；悬停引起的重渲染不会触发聚焦。
  useEffect(() => {
    if (selectedVulnId === null) return
    const target = baseGraph.nodes.find(
      (node) => node.data.chain.vuln_id === selectedVulnId,
    )
    if (!target) return
    void fitView({ nodes: [{ id: target.id }], duration: 600, padding: 0.5, maxZoom: 1.5 })
  }, [selectedVulnId, baseGraph, fitView])

  // ── 联动 ④：focusedNodeId 变化（本组件点击，或外部反向定位）→ 聚焦该节点 ──
  useEffect(() => {
    if (focusedNodeId === null) return
    if (!baseGraph.nodes.some((node) => node.id === focusedNodeId)) return
    void fitView({ nodes: [{ id: focusedNodeId }], duration: 600, padding: 0.5, maxZoom: 1.5 })
  }, [focusedNodeId, baseGraph, fitView])

  if (assessmentId === null) {
    return (
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description="请先在上方选择一个评估任务，再查看其攻击链拓扑"
      />
    )
  }

  if (isPending) {
    return <Skeleton active title={false} paragraph={{ rows: 6 }} />
  }

  if (isError) {
    return (
      <Alert
        type="error"
        showIcon
        message="攻击链加载失败"
        description={errorMessage(error)}
      />
    )
  }

  const hasInferred = stats.inferred > 0

  return (
    <Flex vertical gap={12} style={{ height: '100%', minHeight: 520 }}>
      {/*
        顶部显式声明：这条链里有多少环节是真跑过的、多少是推演。
        有推演环节时用 warning 而不是 info —— 它确实是需要读者留意的前提。
      */}
      <Alert
        type={hasInferred ? 'warning' : 'success'}
        showIcon
        message={`共 ${stats.total} 个节点，其中已验证 ${stats.verified} 个、推演 ${stats.inferred} 个`}
        description="推演环节表示该攻击步骤由规则引擎推导得出、并未在沙箱内实际执行；报告中会显式声明。"
      />

      {stats.total === 0 ? (
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description="本次评估未产出攻击链节点（exploit_chain 阶段未执行，或 R1–R8 规则未命中）"
        />
      ) : (
        <div
          style={{
            flex: 1,
            minHeight: 420,
            border: '1px solid #f0f0f0',
            borderRadius: 8,
            background: '#fcfcfc',
            overflow: 'hidden',
          }}
        >
          <ReactFlow
            nodes={graph.nodes}
            edges={graph.edges}
            nodeTypes={NODE_TYPES}
            onNodeClick={handleNodeClick}
            onNodeMouseEnter={handleNodeMouseEnter}
            onNodeMouseLeave={handleNodeMouseLeave}
            onPaneClick={handlePaneClick}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.3}
            maxZoom={2}
            // 只读拓扑：不允许拖拽/连线，避免与外部 props 驱动的坐标打架
            nodesDraggable={false}
            nodesConnectable={false}
          >
            <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#d9d9d9" />
            <Controls showInteractive={false} />
            <MiniMap
              nodeColor={minimapNodeColor}
              nodeStrokeWidth={2}
              maskColor="rgba(0, 0, 0, 0.06)"
              pannable
              zoomable
            />
            {/* 图例钉在画布右上角：颜色=节点类型，虚实=是否实测，且都有文字 */}
            <Panel position="top-right">
              <TopologyLegend />
            </Panel>
          </ReactFlow>
        </div>
      )}

      <NodeDetailDrawer node={activeNode} onClose={handleCloseDetail} />
    </Flex>
  )
}

/** 缩略图用节点类型主色；数据缺失时退回灰色，绝不因为脏数据抛错 */
function minimapNodeColor(node: Node): string {
  const chain = (node.data as Partial<ChainNodeData>).chain
  if (!chain) return '#d9d9d9'
  return CHAIN_NODE_META[chain.node_type]?.color ?? '#d9d9d9'
}
