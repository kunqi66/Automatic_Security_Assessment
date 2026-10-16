/**
 * F3 漏洞视窗 —— 左表右详情的工作台主体。
 *
 * 分工：
 *   VulnList        左侧，查列表 + 筛选 + 与拓扑图谱联动（接收端）
 *   VulnDetailPanel 右侧，详情 / 修复建议 / 人工复核 三个页签
 *
 * 第一性原则（可控多智能体）：**LLM 只产出自然语言文本，绝不参与任何判定**。
 * 漏洞有无、类型、严重度、CVSS、验证状态、整改顺序全部由确定性代码产出；
 * LLM 在本系统里只有两处用武之地 —— 写描述/整改建议文案，以及生成补丁草案，
 * 而补丁草案必须通过四道校验才算数。所以本模块的 UI 始终把「结论」和
 * 「模型产出的建议」摆在不同层级上：`SeverityTag` / `VulnStatusTag` 是结论，
 * 补丁区则被一条「建议补丁 · 绝不自动应用」的横幅隔开。
 */
import { Card } from 'antd'
import type { ReactNode } from 'react'

import { VulnDetailPanel } from './VulnDetailPanel'
import { VulnList } from './VulnList'
import './vuln.css'

export function VulnPanel({ assessmentId }: { assessmentId: number | null }): ReactNode {
  return (
    <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
      {/* 左 45%：漏洞列表 */}
      <div style={{ flex: '0 0 45%', minWidth: 0 }}>
        <Card size="small" title="漏洞列表" styles={{ body: { padding: 12 } }}>
          <VulnList assessmentId={assessmentId} />
        </Card>
      </div>

      {/* 右 55%：漏洞详情 */}
      <div style={{ flex: '1 1 auto', minWidth: 0 }}>
        <Card size="small" title="漏洞详情" styles={{ body: { padding: 12 } }}>
          <VulnDetailPanel />
        </Card>
      </div>
    </div>
  )
}
