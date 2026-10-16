/**
 * 攻击链 → React Flow 图的**纯函数**转换层（不 import React、不产生副作用）。
 *
 * ── 为什么单独抽一个文件 ────────────────────────────────────────────────
 * 图的结构完全由数据决定，与渲染无关。抽成纯函数后：输入相同 ⇒ 输出必然相同，
 * 可以直接单测（不需要挂载组件、不需要 mock React Flow），渲染层只负责把结果喂给画布。
 *
 * ── 可信度来源：节点与边都不是模型编的（可控多智能体第一性原则）───────
 * 「LLM 只产出自然语言，绝不参与判定」在本模块的落地是：
 *   1. 节点集合 = 后端 `exploit_chain` 阶段 R1–R8 确定性规则引擎的输出（AttackChainNode[]）；
 *   2. **边没有独立边表**，全部由 `parent_node_id` 推导（见 api/types.ts 中该字段的注释）；
 *   3. LLM 只把这条链写成人话叙述，且写完后还要做「节点集合比对」校验，
 *      确认模型没有新增或遗漏节点 —— 所以图上不会出现模型"生成"的节点或边。
 * 换句话说：本文件里所有 x/y 坐标与所有边都可由规则输出重放得到，与模型无关。
 */
import { graphlib, layout as dagreLayout } from 'dagre'
import { Position } from '@xyflow/react'
import type { Edge, Node, XYPosition } from '@xyflow/react'

import type { AttackChainNode } from '@/api/types'

// ---------------------------------------------------------------------------
// 尺寸常量
// ---------------------------------------------------------------------------

/**
 * 自定义节点卡片的尺寸。dagre 必须先知道尺寸才能算出不重叠的分层坐标，
 * 所以这里作为**唯一真源**导出，由 ChainNodeCard 的样式与 buildGraph 共用。
 */
export const NODE_WIDTH = 224
export const NODE_HEIGHT = 88

/** 虚线样式：与「推演」语义绑定，图例里的示意图也复用这个常量，保证图例与画布一致 */
export const EDGE_DASH_ARRAY = '6 4'

/** 边的两种形态配色 —— 实线=全链实测；虚线=中途存在推演环节 */
const EDGE_STROKE_VERIFIED = '#595959'
const EDGE_STROKE_INFERRED = '#bfbfbf'

// ---------------------------------------------------------------------------
// React Flow 侧的节点 / 边数据类型
// ---------------------------------------------------------------------------

/** 联动高亮态：selected 是「选中」（加粗+发光），hovered 只是弱高亮，两者不可混淆 */
export type ChainHighlight = 'none' | 'selected' | 'hovered'

export type ChainNodeData = {
  /** 后端原始节点 —— 展示所需的一切都从这里取，前端不做任何二次推断 */
  chain: AttackChainNode
  /** 与漏洞表格联动产生的高亮态 */
  highlight: ChainHighlight
}

/** 自定义 node type 固定为 'chain'，与 TopologyPanel 里的 nodeTypes 键名一一对应 */
export type ChainFlowNode = Node<ChainNodeData, 'chain'>

export type ChainEdgeData = {
  /** 命中的推演规则编号（R1–R8），边上会标注出来 */
  ruleId: string | null
  /** 该边是否跨了「推演」环节 —— 供样式与单测断言使用 */
  inferred: boolean
}

export type ChainFlowEdge = Edge<ChainEdgeData, 'smoothstep'>

export type ChainGraph = {
  nodes: ChainFlowNode[]
  edges: ChainFlowEdge[]
}

/** 联动入参：来自 store/vulnSelection（F3↔F4 的唯一契约） */
export interface ChainGraphFocus {
  selectedVulnId: number | null
  hoveredVulnId: number | null
  focusedNodeId: string | null
}

// ---------------------------------------------------------------------------
// 主入口
// ---------------------------------------------------------------------------

/**
 * 把后端返回的攻击链节点数组转成 React Flow 的 `{ nodes, edges }`。
 *
 * 纯函数：不读 store、不碰时钟、不依赖随机数；同一份入参永远得到同一份出参。
 * 对脏数据做了三类防御（自环 / 悬挂 parent / 重复 id），任何一类都不会让页面崩掉。
 */
export function buildGraph(chainNodes: AttackChainNode[]): ChainGraph {
  const nodes = dedupeById(chainNodes)
  if (nodes.length === 0) {
    return { nodes: [], edges: [] }
  }

  // React Flow 的节点 id 必须是字符串，而后端主键是整数 —— 转换只在这一层做一次，
  // 内部所有 Map/边的键统一用字符串 id，避免 `1` 与 `'1'` 两套键在比较时对不上
  const byId = new Map(nodes.map((node) => [String(node.id), node]))
  const links = deriveLinks(nodes, byId)
  const positions = buildPositions(nodes, links)

  const flowNodes: ChainFlowNode[] = nodes.map((chain) => ({
    id: String(chain.id),
    type: 'chain',
    position: positions.get(String(chain.id)) ?? { x: 0, y: 0 },
    data: { chain, highlight: 'none' },
    // 布局是 TB（自上而下），所以入边挂在顶部、出边挂在底部
    sourcePosition: Position.Bottom,
    targetPosition: Position.Top,
    // 提前把尺寸告诉 React Flow：fitView 不必等 ResizeObserver 量完就能算对包围盒
    initialWidth: NODE_WIDTH,
    initialHeight: NODE_HEIGHT,
    style: { width: NODE_WIDTH },
    // 只读拓扑图：不拖拽，避免「拖完又被 props 重置」的状态打架
    draggable: false,
    selectable: true,
  }))

  const flowEdges: ChainFlowEdge[] = links.map((link) => ({
    id: `${link.source}->${link.target}`,
    type: 'smoothstep',
    source: link.source,
    target: link.target,
    data: { ruleId: link.ruleId, inferred: link.inferred },
    // 边上标注命中的规则编号（R2 / R4 …），让「这条边为什么存在」有据可查
    label: link.ruleId ?? undefined,
    labelShowBg: true,
    labelBgStyle: { fill: '#ffffff', fillOpacity: 0.85 },
    labelBgPadding: [4, 2],
    labelBgBorderRadius: 4,
    labelStyle: {
      fontSize: 11,
      fontFamily: 'monospace',
      fill: link.inferred ? '#8c8c8c' : '#434343',
    },
    // 只要有一端是「推演」，这条边就没有被实测确认过 → 虚线
    style: link.inferred
      ? { stroke: EDGE_STROKE_INFERRED, strokeWidth: 1.4, strokeDasharray: EDGE_DASH_ARRAY }
      : { stroke: EDGE_STROKE_VERIFIED, strokeWidth: 1.6 },
    markerEnd: {
      type: 'arrowclosed',
      width: 16,
      height: 16,
      color: link.inferred ? EDGE_STROKE_INFERRED : EDGE_STROKE_VERIFIED,
    },
  }))

  return { nodes: flowNodes, edges: flowEdges }
}

/**
 * 把「漏洞表格 ↔ 图谱」的联动状态叠加到图上，返回**新的**图（不改原对象）。
 * 与 buildGraph 分离，是为了让布局保持纯粹：布局只跟数据有关，高亮只跟交互有关。
 * 没有任何节点需要变化时原样返回原引用，避免每次 render 都触发 React Flow 重算。
 */
export function decorateGraph(graph: ChainGraph, focus: ChainGraphFocus): ChainGraph {
  let changed = false

  const nodes = graph.nodes.map((node, index) => {
    const vulnId = node.data.chain.vuln_id

    const isSelected =
      (focus.selectedVulnId !== null && vulnId === focus.selectedVulnId) ||
      (focus.focusedNodeId !== null && node.id === focus.focusedNodeId)

    const highlight: ChainHighlight = isSelected
      ? 'selected'
      : focus.hoveredVulnId !== null && vulnId === focus.hoveredVulnId
        ? 'hovered'
        : 'none'

    if (highlight === graph.nodes[index].data.highlight) return node
    changed = true
    return { ...node, data: { ...node.data, highlight } }
  })

  return changed ? { nodes, edges: graph.edges } : graph
}

/**
 * 头部那句话的数据来源：共 N 个节点，其中已验证 X、推演 Y。
 * 刻意做成纯函数，测试可以直接断言统计口径（total = verified + inferred 恒成立）。
 */
export function countByVerification(chainNodes: AttackChainNode[]): {
  total: number
  verified: number
  inferred: number
} {
  let verified = 0
  for (const node of chainNodes) {
    if (node.verification_status === 'verified') verified += 1
  }
  return { total: chainNodes.length, verified, inferred: chainNodes.length - verified }
}

// ---------------------------------------------------------------------------
// 内部实现
// ---------------------------------------------------------------------------

interface ChainLink {
  source: string
  target: string
  ruleId: string | null
  inferred: boolean
}

/** 防御 ①：重复 id —— 同名节点会让 dagre 与 React Flow 都行为异常，保留首次出现的那条 */
function dedupeById(chainNodes: AttackChainNode[]): AttackChainNode[] {
  const seen = new Set<number>()
  const unique: AttackChainNode[] = []
  for (const node of chainNodes) {
    if (seen.has(node.id)) continue
    seen.add(node.id)
    unique.push(node)
  }
  return unique
}

/**
 * **边由 parent_node_id 推导**：每个节点最多只有一个父节点，父 → 子构成一条有向边。
 * 后端不返回边表，这里就是「构边」的唯一实现。键一律用字符串化的 id。
 */
function deriveLinks(
  nodes: AttackChainNode[],
  byId: Map<string, AttackChainNode>,
): ChainLink[] {
  const links: ChainLink[] = []
  const seen = new Set<string>()

  for (const child of nodes) {
    // 显式写成可空联合：字段缺失（undefined）与显式 null 都要按「无父节点」处理
    const parentId: number | null | undefined = child.parent_node_id

    // 根节点（parent_node_id 为 null）本就是链的起点，没有入边
    if (parentId === null || parentId === undefined) continue

    // 防御 ②：自环 —— 自己不能是自己的前置，语义上不成立，dagre 也无法处理 v === w
    if (parentId === child.id) continue

    const parent = byId.get(String(parentId))

    // 防御 ③：悬挂 parent —— 父节点不存在（数据被裁剪/写入脏数据）。
    // 此时丢弃这条边但**保留子节点**：否则 React Flow 会因为找不到边端点而报错，
    // 整张图都渲染不出来，代价远大于少画一条边。
    if (parent === undefined) continue

    const key = `${parent.id}->${child.id}`
    // 防御 ④：重边（同一个孩子只会有一个 parent，重边只可能来自脏数据）
    if (seen.has(key)) continue
    seen.add(key)

    links.push({
      source: String(parent.id),
      target: String(child.id),
      ruleId: child.rule_id,
      // 只要有一端是推演，这条边就没有被实测确认过
      inferred:
        parent.verification_status === 'inferred' || child.verification_status === 'inferred',
    })
  }

  return links
}

/** 先试 dagre 分层布局；拿不到完整坐标时用网格兜底，保证「图一定能画出来」 */
function buildPositions(
  nodes: AttackChainNode[],
  links: ChainLink[],
): Map<string, XYPosition> {
  const positions = dagrePositions(nodes, links) ?? new Map<string, XYPosition>()

  const missing = nodes.filter((node) => !positions.has(String(node.id)))
  missing.forEach((node, index) => {
    positions.set(String(node.id), {
      x: (index % 4) * (NODE_WIDTH + 48),
      y: Math.floor(index / 4) * (NODE_HEIGHT + 72),
    })
  })

  return positions
}

/**
 * dagre 分层布局（TB）。
 * 失败时返回 null 而不是抛错：脏数据（例如环形依赖）下宁可降级排布，也不能让整页崩掉。
 */
function dagrePositions(
  nodes: AttackChainNode[],
  links: ChainLink[],
): Map<string, XYPosition> | null {
  try {
    const graph = new graphlib.Graph()
    graph.setGraph({
      rankdir: 'TB',
      nodesep: 56, // 同层节点间距：卡片宽 224，56 足够让「关联漏洞」标签不打架
      ranksep: 76, // 层间距：留出边上的规则编号标签（R2/R4）的空间
      marginx: 24,
      marginy: 24,
    })
    graph.setDefaultEdgeLabel(() => ({}))

    for (const node of nodes) {
      graph.setNode(String(node.id), { width: NODE_WIDTH, height: NODE_HEIGHT })
    }
    for (const link of links) {
      graph.setEdge(link.source, link.target)
    }

    dagreLayout(graph)

    const positions = new Map<string, XYPosition>()
    for (const node of nodes) {
      const point = graph.node(String(node.id))
      if (!point || !Number.isFinite(point.x) || !Number.isFinite(point.y)) continue
      // dagre 给的是**中心点**坐标，React Flow 要的是节点左上角
      positions.set(String(node.id), {
        x: point.x - NODE_WIDTH / 2,
        y: point.y - NODE_HEIGHT / 2,
      })
    }
    return positions
  } catch {
    return null
  }
}
