/**
 * 漏洞选中态 —— **F3（漏洞视窗）与 F4（拓扑图谱）之间的唯一契约**。
 *
 * PRD §8.1 ② 定案：漏洞表格与 DAG 同属一区、由 F4 承载；F3 只提供 `VulnStatusTag`
 * 组件与详情内容。两者要联动，靠的就是这个 store —— 而不是互相 import 对方组件。
 *
 * 联动是双向的：
 * - 点图谱节点 → 表格滚动定位到对应漏洞并选中
 * - 选表格行   → 图谱把对应节点高亮（`hoveredVulnId` 供 hover 预览用）
 */
import { create } from 'zustand'

interface VulnSelectionState {
  /** 当前选中的漏洞 ID；null 表示未选中 */
  selectedVulnId: number | null
  /** 鼠标悬停的漏洞 ID（图谱弱高亮用，不改变选中态） */
  hoveredVulnId: number | null
  /** 当前聚焦的攻击链节点 ID —— 点表格行时反向定位图谱 */
  focusedNodeId: string | null

  selectVuln: (id: number | null) => void
  hoverVuln: (id: number | null) => void
  focusNode: (nodeId: string | null) => void
  reset: () => void
}

export const useVulnSelection = create<VulnSelectionState>()((set) => ({
  selectedVulnId: null,
  hoveredVulnId: null,
  focusedNodeId: null,

  selectVuln: (id) => set({ selectedVulnId: id }),
  hoverVuln: (id) => set({ hoveredVulnId: id }),
  focusNode: (nodeId) => set({ focusedNodeId: nodeId }),
  reset: () => set({ selectedVulnId: null, hoveredVulnId: null, focusedNodeId: null }),
}))
