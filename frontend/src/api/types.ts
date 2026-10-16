/**
 * 与后端 DTO 一一对应的类型定义（对应 PRD §6 数据模型 / §9 API）。
 *
 * 约定：
 * - 全部使用字符串字面量联合而非 enum —— tsconfig 开了 erasableSyntaxOnly，
 *   且联合类型在 JSON 边界上更贴合实际（后端返回的就是字符串）。
 * - 所有路径字段均为 **相对 workspace 根目录的 POSIX 路径**（总纲 §7.4 全局路径规范）。
 */

// ---------------------------------------------------------------------------
// 基础枚举
// ---------------------------------------------------------------------------

/** 项目综合等级（PRD §6 security_grade）—— 注意与「漏洞严重度」是两个概念 */
export type SecurityGrade = 'critical' | 'high' | 'medium' | 'safe'

/** 漏洞严重度（PRD §6 severity） */
export type Severity = 'critical' | 'high' | 'medium' | 'low'

/** 漏洞四态（需求 2.5.4） */
export type VulnStatus = 'unverified' | 'verified' | 'potential' | 'rejected'

/** 攻击链节点的验证状态（总纲 §12.2 Q24 定案 = 方案 A） */
export type VerificationStatus = 'verified' | 'inferred'

/** 流水线五阶段（需求 2.5 / PRD §7.5） */
export type StageName = 'recon' | 'code_audit' | 'poc_verify' | 'exploit_chain' | 'report_gen'

/** 阶段状态。注意是 `completed`（不是 success）—— 与评估任务状态同名同义，避免两套词 */
export type StageStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped'

/**
 * 评估任务状态（总纲 §5.1 状态机 / PRD §6 assessments.status）。
 * `created` 是「行已建、worker 还没开跑」，与 `running` 不同义；
 * `stopped` 是人工终止（杀沙箱、留数据），不是「作废」，故不叫 canceled。
 */
export type AssessmentStatus = 'created' | 'running' | 'completed' | 'failed' | 'stopped'

/**
 * 补丁来源（PRD §7.6 L4 / F3 R7）—— 三态必须在前端可区分：
 * - `llm`             正常产出（且已过 L3 四道校验）
 * - `template`        模型不可用时的模板降级，**排序与结论不变，只有措辞变**
 * - `validate_failed` 模型产出了补丁但**没过第 ④ 道校验**（打完污点路径仍在）→ 必须红字告警
 */
export type PatchSource = 'llm' | 'template' | 'validate_failed'

/** 沙箱网络策略（PRD §6 sandbox_configs.network_policy，默认 internal） */
export type NetworkPolicy = 'none' | 'internal' | 'bridge'

// ---------------------------------------------------------------------------
// 实体
// ---------------------------------------------------------------------------

/**
 * 三个角色（需求 2.5.2）：安全工程师 / 研发 / 管理员。
 *
 * **刻意不是「管理员 + 普通用户」两档** —— 三者的权限是互补而非包含关系：
 * 管理员**不能**创建评估，工程师**不能**采纳补丁。所以任何
 * 「管理员权限最大」的假设都是错的，包括「管理员能看到所有按钮」。
 */
export type UserRole = 'security_engineer' | 'developer' | 'admin'

export interface User {
  id: number
  username: string
  role: UserRole
  /**
   * 该角色拥有的功能权限码，如 `['assessment:create', 'vuln:view', ...]`。
   *
   * **由后端返回，前端不得自己按 `role` 推导。** 那份 role→权限 的映射
   * （`backend/app/api/deps.py` 的 `ROLE_PERMISSIONS`）只准有一份实现：
   * 在这里再抄一遍，后端调整权限后前端会**静默**分叉成
   * 「按钮在、点了 403」或「按钮没了、功能其实还能用」。
   *
   * 判定一律走 {@link can}，不要在各处写 `includes` 字面量。
   */
  permissions: string[]
  created_at: string
}

/**
 * 功能权限码。与 `backend/app/api/deps.py` 的 `Permission` 枚举一一对应。
 *
 * 这里只列出**前端会用来决定显不显示**的那几个 —— 不做全量镜像，
 * 因为全量镜像意味着后端加一个权限就要同步改这里，而漏改的症状是
 * 「某个按钮永远不出现」且不报错。用不到的权限码不必有名字。
 */
export type PermissionCode =
  | 'assessment:create'
  | 'vuln:review'
  | 'report:export'
  | 'patch:accept'
  | 'sandbox:manage'
  | 'llm:manage'
  | 'audit:view'

/**
 * 当前用户是否拥有某项功能权限。**唯一的判定入口**（见 `User.permissions`）。
 *
 * `?? []` 是给**版本错配**兜底的：前端是个静态包，后端可以单独重启或回滚，
 * 所以线上存在「新前端 + 旧后端」的窗口 —— 那时响应里根本没有 `permissions`。
 * 不兜底的话 `undefined.includes` 会抛异常，而它是在渲染期被调的，
 * 症状是**整页白屏**，而不是「按钮没出现」。
 *
 * 兜底成空集是正确的降级方向：按钮不显示，功能仍由后端独立鉴权兜住
 * （安全红线 7：每个写接口独立校验权限，不依赖前端藏按钮）。
 */
export function can(user: User | null, permission: PermissionCode): boolean {
  return (user?.permissions ?? []).includes(permission)
}

export interface Project {
  id: number
  name: string
  source_type: 'git' | 'upload'
  source_url: string | null
  /** PRD §6 projects.source_branch —— 只有 git 来源才有 */
  source_branch: string | null
  /**
   * 控制面源码工作区路径（PRD §6 projects.storage_path）。
   *
   * ⚠️ **可为 null**，而且这正是「建档」与「补传」两步分开的直接后果：
   * `source_type=upload` 的建档只写一条占位记录，源码要等
   * `POST /projects/{id}/upload` 才落盘。**此时启动评估会被后端 400 拒绝**
   * （"该项目还没有源码"），所以选项目的界面必须能区分这两种状态。
   */
  storage_path: string | null
  description: string | null
  /** recon 阶段回填（B1 建档时不填） */
  tech_stack: Record<string, string> | null
  total_loc: number | null
  status: 'created' | 'running' | 'completed' | 'failed' | 'stopped'
  /** 建档/导入失败原因 */
  error_message: string | null
  created_at: string
}

/**
 * `GET /projects/{id}/source` 返回的源码片段。
 * 后端读文件前会做路径穿越校验（符号链接 / `..` 一律拒绝），
 * 这里拿到的 `path` 始终是**相对 workspace 根目录的 POSIX 路径**。
 */
export interface SourceSnippet {
  path: string
  /** 起始行号（1-based，含） */
  start: number
  /** 结束行号（1-based，含） */
  end: number
  content: string
}

export interface Assessment {
  id: number
  project_id: number
  project_name: string
  status: AssessmentStatus
  current_stage: StageName | null
  /** 0–100 */
  progress: number
  /** 项目综合等级；未完成时为 null */
  security_grade: SecurityGrade | null
  /** 各阶段状态，未开始的阶段不出现 */
  stages: StageState[]
  started_at: string | null
  finished_at: string | null
  created_at: string
}

export interface StageState {
  stage: StageName
  status: StageStatus
  started_at: string | null
  finished_at: string | null
  /** 阶段失败原因或 skip 原因（例如源码同步失败 → skipped） */
  note: string | null
}

/** 污点传播的一步（F3 漏洞视窗的「污点步进」）。字段名对齐 PRD §6 taint_paths */
export interface TaintStep {
  /** 从 0 开始 */
  step_index: number
  /** 总纲 §7.3 固定的四步类型；`propagate` / `sanitize` 是动词形态 */
  step_type: 'source' | 'propagate' | 'sanitize' | 'sink'
  symbol: string
  file_path: string
  line: number
  /** 该步对应的源码片段（PRD §6 taint_paths.code_snippet） */
  code_snippet: string
  note: string | null
}

/** L3 补丁四道校验的结果（PRD §7.6 L3） */
export interface PatchValidation {
  /** ① 是否为合法的 unified diff */
  valid_diff: boolean
  /** ② 是否只改动了 ±20 行窗口 */
  window_ok: boolean
  /** ③ `git apply --check` 干跑是否通过 */
  apply_check_ok: boolean
  /** ④ 打上补丁后重跑污点引擎，本条污点路径是否消失 —— 唯一真正的验收标准 */
  taint_cleared: boolean
  /** 任一道失败时的说明 */
  failure_reason: string | null
}

export interface PatchSuggestion {
  source: PatchSource
  /** unified diff 文本，交给 Monaco DiffEditor 渲染（只读） */
  diff: string
  target_file: string
  validation: PatchValidation
}

export interface Vulnerability {
  id: number
  assessment_id: number
  vuln_type: string
  severity: Severity
  status: VulnStatus
  file_path: string
  line_start: number
  line_end: number
  /** 下沉点符号名 —— 补丁复验的身份锚点之一（B4 §3.4） */
  sink_symbol: string
  /** 可能为 null：LLM 不可用时降级为模板文案，此处仍应有值 */
  description: string
  /** 整改建议正文。**注意：整改顺序由后端 scoring.py 确定性产出，不由文案决定** */
  remediation_note: string
  cvss_score: number
  /** 是否被 HarmlessGuard 拦截过（闸门 2–4） */
  guard_blocked: boolean
  taint_trace: TaintStep[]
  patch: PatchSuggestion | null
}

export type ChainNodeType = 'entry' | 'vuln' | 'credential' | 'shell' | 'host' | 'impact'

/**
 * 攻击链节点。**注意：边不存在独立的边表里**，DAG 的边由 `parent_node_id` 推导
 * （总纲 §8 / B5 设计）。前端构边时按此展开。
 *
 * id 与 parent_node_id 是**数据库自增主键（整数）**；React Flow 要求节点 id 是字符串，
 * 该转换由渲染层（topology/layout.ts 的 buildGraph）用 `String(id)` 完成，
 * 不让 API 类型迁就 UI —— 否则 `1` 与 `'1'` 的混淆会一路渗进比较逻辑。
 */
export interface AttackChainNode {
  id: number
  /** PRD §6 attack_chain_nodes.chain_id —— 节点挂在**链**下，不是评估下（一次评估可推演出多条链） */
  chain_id: number
  parent_node_id: number | null
  node_type: ChainNodeType
  label: string
  detail: string
  /** verified = 实际执行过；inferred = 引擎推演，报告须声明该环未实际执行 */
  verification_status: VerificationStatus
  /** PRD §6 attack_chain_nodes.vuln_id */
  vuln_id: number | null
  /** 命中的推演规则编号 R1–R8 */
  rule_id: string | null
}

export interface Report {
  id: number
  assessment_id: number
  /** 派生字段（report → assessment → project.name），表里无此列，后端照常返回 */
  project_name: string
  title: string
  /** PRD §6 reports.format —— Markdown 一律写作 `md`（不是 `markdown`） */
  format: 'html' | 'md' | 'pdf'
  status: 'generating' | 'ready' | 'failed'
  /** PRD §6 reports.content_path；status !== 'ready' 时为 null */
  content_path: string | null
  size_bytes: number | null
  /** PRD §6 reports.generated_at */
  generated_at: string
}

export interface ResourceSample {
  ts: string
  cpu_percent: number
  /** PRD §6 resource_metrics.memory_mb */
  memory_mb: number
}

export interface SandboxConfig {
  id: number
  name: string
  base_image: string
  network_policy: NetworkPolicy
  cpu_limit: number
  /** PRD §6 sandbox_configs.memory_limit_mb */
  memory_limit_mb: number
  timeout_seconds: number
  /**
   * 调度并发数。**只读**：调度由 worker 固定为 1（总纲 §8.1），
   * 引擎侧没有对应的执行参数。所以它出现在这里（看得见）但不在
   * `SandboxConfigUpdate` 里（改不了）—— 做成可编辑就是一个假控件。
   */
  max_concurrency: number
  is_default: boolean
}

/**
 * 沙箱配置的可改字段。**与 `SandboxConfig` 的差集就是「改不了的」**：
 * `max_concurrency` 不在其中（见上）。
 */
export interface SandboxConfigUpdate {
  id: number
  name?: string
  base_image?: string
  network_policy?: NetworkPolicy
  cpu_limit?: number
  memory_limit_mb?: number
  timeout_seconds?: number
  is_default?: boolean
}

/**
 * LLM 推理参数（需求 2.5.2）。
 * ⚠️ 刻意不含 api_key —— 密钥只从后端 `.env` 的 `DEEPSEEK_API_KEY` 读取，不入库、不回传前端。
 */
export interface LlmConfig {
  provider: string
  base_url: string
  model: string
  temperature: number
  max_tokens: number
  timeout_seconds: number
  max_retries: number
  is_default: boolean
  /** 后端探测到的可用性；false 时全站走模板降级（L4） */
  available: boolean
  updated_at: string
}

/**
 * 审计日志（`GET /admin/audit-logs`）—— 谁在什么时候对哪个资源做了什么。
 * 人工复核漏洞、改 LLM 参数、改沙箱配置等**会改变结论的操作**都必须留痕（PRD §11.3）。
 */
export interface AuditLog {
  id: number
  user_id: number
  action: string
  target_type: string
  target_id: number | null
  detail: Record<string, unknown> | null
  ip: string | null
  created_at: string
}

// ---------------------------------------------------------------------------
// 仪表盘聚合
// ---------------------------------------------------------------------------

export interface DashboardSummary {
  project_count: number
  assessment_count: number
  running_count: number
  vuln_total: number
  /** 各严重度漏洞数 */
  vuln_by_severity: Record<Severity, number>
  /** 各综合等级项目数 */
  grade_distribution: Record<SecurityGrade, number>
  /** 各状态漏洞数（四态） */
  vuln_by_status: Record<VulnStatus, number>
  recent_assessments: Assessment[]
}

// ---------------------------------------------------------------------------
// 分页 / 查询
// ---------------------------------------------------------------------------

export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export interface VulnQuery {
  status?: VulnStatus
  severity?: Severity
  keyword?: string
  page?: number
  page_size?: number
}

// ---------------------------------------------------------------------------
// SSE 日志事件（对应 Redis Stream 的日志流，支持 Last-Event-ID 断线重放）
// ---------------------------------------------------------------------------

export interface LogEvent {
  /** Redis Stream 的消息 ID，断线重连时作为 Last-Event-ID 回传 */
  id: string
  ts: string
  stage: StageName | 'system'
  level: 'debug' | 'info' | 'warn' | 'error'
  message: string
}

/**
 * 后端 SSE 推过来的**原始信封**（`app/orchestrator/events.py` 的 `LogEvent`）。
 *
 * ⚠️ 它与上面的 `LogEvent` **同名但不是同一个东西**，这里刻意叫 `StreamEvent`
 * 是为了让两者在代码里一眼可分：上面那个是**渲染模型**（渲染器只认它），
 * 这个才是**线上格式**（服务端只产它）。
 *
 * 三种事件共用一个信封，所以 `level` / `message` / `snapshot` / `metric`
 * 都是**按 `type` 才有值**的可选字段 —— 直接把它 spread 进渲染模型，
 * 阶段事件就会带着 `level: null` 和一个空 message 进列表，
 * 症状是日志面板里出现几行没有文字的空白行。转换见 `toLogEvents`。
 */
export interface StreamEvent {
  type: 'log' | 'stage' | 'metric'
  assessment_id: number
  stage: StageName
  /** 仅 type='log' */
  level?: 'debug' | 'info' | 'warn' | 'error' | null
  /** 仅 type='log' */
  message?: string | null
  /** 仅 type='stage' —— **完整快照**，不是增量 */
  snapshot?: StageRecord | null
  /** 仅 type='metric' */
  metric?: ResourceSample | null
  extra?: Record<string, unknown>
  ts: string
}

/** 阶段状态快照。断线重连后拿到任意一个就能就地重建整条进度条。 */
export interface StageRecord {
  stage: StageName
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped'
  started_at?: string | null
  finished_at?: string | null
  duration_ms?: number | null
  /** 失败原因或降级原因 —— `skipped` 不是错误，但也要说明为什么没跑 */
  note?: string | null
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  access_token: string
  token_type: string
  user: User
}
