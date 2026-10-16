/**
 * 攻击链拓扑图谱模块（F4）统一出口。
 *
 * 页面只从这里 import：`import { TopologyPanel } from '@/modules/topology'`。
 * layout.ts 中的纯函数一并导出 —— 它们不依赖 React，单测可以直接对着它们断言
 * 布局与构边结果（含自环、悬挂 parent 等脏数据的防御分支）。
 */
export { TopologyPanel } from './TopologyPanel'
export { buildGraph, countByVerification, decorateGraph, EDGE_DASH_ARRAY, NODE_HEIGHT, NODE_WIDTH } from './layout'
export type {
  ChainEdgeData,
  ChainFlowEdge,
  ChainFlowNode,
  ChainGraph,
  ChainGraphFocus,
  ChainHighlight,
  ChainNodeData,
} from './layout'
