/**
 * 漏洞视窗模块（F3）对外出口。
 *
 * 只暴露页面真正需要的东西：
 *   - `VulnPanel`        工作台挂载的组件（签名由 src/pages/Workbench 决定）
 *   - `applyUnifiedDiff` / `originalFromDiff`  纯函数，可脱离 UI 单测
 */
export { VulnPanel } from './VulnPanel'
export { applyUnifiedDiff, originalFromDiff } from './applyUnifiedDiff'
export type { ApplyUnifiedDiffResult } from './applyUnifiedDiff'
