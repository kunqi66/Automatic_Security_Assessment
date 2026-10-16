/** 全站共享的展示元数据（阶段名、节点类型等）—— 避免各模块各写一份中文名 */
import type { ChainNodeType, StageName, UserRole } from '@/api/types'

/**
 * 角色的中文名。与后端 `api/deps.py` 的 `_role_label` 保持同一套措辞 ——
 * 前端说「安全工程师」而后端错误信息里说「工程师」，用户会以为是两个人。
 */
export const ROLE_LABELS: Record<UserRole, string> = {
  security_engineer: '安全工程师',
  developer: '研发人员',
  admin: '系统管理员',
}

export const STAGE_ORDER: StageName[] = [
  'recon',
  'code_audit',
  'poc_verify',
  'exploit_chain',
  'report_gen',
]

export const STAGE_LABELS: Record<StageName, string> = {
  recon: '环境侦察',
  code_audit: '静态审计',
  poc_verify: '动态验证',
  exploit_chain: '路径推演',
  report_gen: '报告生成',
}

export const STAGE_DESCRIPTIONS: Record<StageName, string> = {
  recon: '识别技术栈、入口点与可达攻击面',
  code_audit: 'tree-sitter 解析 + 污点分析，产出候选漏洞',
  poc_verify: '沙箱内无害探针验证；含 HarmlessGuard 四道闸门',
  exploit_chain: 'R1–R8 规则推演攻击链，标注权限跃迁',
  report_gen: '汇总结论、渲染报告；LLM 仅负责自然语言表述',
}

export const CHAIN_NODE_META: Record<ChainNodeType, { label: string; color: string }> = {
  entry: { label: '入口', color: '#1677ff' },
  vuln: { label: '漏洞', color: '#cf1322' },
  credential: { label: '凭证', color: '#d48806' },
  shell: { label: '立足点', color: '#722ed1' },
  host: { label: '宿主机', color: '#eb2f96' },
  impact: { label: '影响', color: '#595959' },
}
