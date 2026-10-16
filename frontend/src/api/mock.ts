/**
 * Mock 适配器 —— 挂在 axios 的 adapter 上，而不是在各处写 `if (USE_MOCK)`。
 *
 * 这样做的好处：`endpoints.ts` 里的每个请求函数与真实后端调用**完全一致**，
 * 切到真后端只需把 `VITE_USE_MOCK` 置 false，业务代码零改动。
 *
 * 未命中的路由一律返回 404，避免「以为通了其实没通」。
 */
import { AxiosError, AxiosHeaders } from 'axios'
import type { AxiosAdapter, AxiosResponse, InternalAxiosRequestConfig } from 'axios'

import {
  ASSESSMENTS,
  CHAIN_NODES,
  DASHBOARD,
  LLM_CONFIG,
  METRICS,
  MOCK_USER,
  PROJECTS,
  REPORTS,
  SANDBOX_CONFIGS,
  VULNERABILITIES,
} from './fixtures'
import type {
  Assessment,
  LlmConfig,
  Project,
  Report,
  SandboxConfigUpdate,
  StageState,
  Vulnerability,
} from './types'

// --- 会话内可变副本：mock 期间的新建/修改能即时反映到界面 ---------------------

const state = {
  projects: [...PROJECTS],
  assessments: [...ASSESSMENTS],
  vulns: VULNERABILITIES.map((v) => ({ ...v })),
  reports: [...REPORTS],
  sandboxConfigs: SANDBOX_CONFIGS.map((c) => ({ ...c })),
  llmConfig: { ...LLM_CONFIG },
  seq: 1000,
}

const nextId = (): number => ++state.seq

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

// --- 路由表 ------------------------------------------------------------------

interface Ctx {
  /** 已剥掉 baseURL 的请求路径，如 `/assessments/101/chains` */
  path: string
  params: Record<string, string>
  query: Record<string, unknown>
  body: Record<string, unknown>
}

type Handler = (ctx: Ctx) => unknown

interface Route {
  method: string
  pattern: RegExp
  handler: Handler
}

const routes: Route[] = []

const route = (method: string, path: string, handler: Handler): void => {
  // /assessments/:id/chains  →  ^/assessments/([^/]+)/chains$
  const pattern = new RegExp(
    '^' + path.replace(/:[A-Za-z_]+/g, '([^/]+)').replace(/\//g, '\\/') + '$',
  )
  const keys = [...path.matchAll(/:([A-Za-z_]+)/g)].map((m) => m[1])
  routes.push({
    method,
    pattern,
    handler: (ctx) => {
      const m = pattern.exec(ctx.path)
      if (!m) return undefined
      keys.forEach((k, i) => {
        ctx.params[k] = decodeURIComponent(m[i + 1])
      })
      return handler(ctx)
    },
  })
}

// —— 认证 ——

route('POST', '/auth/login', ({ body }) => {
  if (body.username !== 'admin' || body.password !== 'admin123') {
    throw mockError(401, '用户名或密码错误')
  }
  return { access_token: 'mock-jwt-token', token_type: 'bearer', user: MOCK_USER }
})

route('GET', '/auth/me', () => MOCK_USER)

// —— 项目 ——

route('GET', '/projects', () => ({ items: state.projects, total: state.projects.length }))

route('POST', '/projects', ({ body }) => {
  const sourceType = (body.source_type as Project['source_type']) ?? 'git'
  const id = nextId()
  const p: Project = {
    id,
    name: String(body.name ?? '未命名项目'),
    source_type: sourceType,
    source_url: (body.source_url as string) ?? null,
    source_branch: (body.source_branch as string) ?? null,
    // 与真后端一致：`source_type=upload` 的建档**只写占位记录**，源码等补传。
    // mock 里也留 null，否则「未上传源码不能启动」那条分支在 mock 下永远走不到，
    // 于是它到底对不对，切到真后端才发现。
    storage_path: sourceType === 'git' ? `workspaces/project-${id}` : null,
    description: (body.description as string) ?? null,
    tech_stack: null,
    total_loc: null,
    status: 'created',
    error_message: null,
    created_at: new Date().toISOString(),
  }
  state.projects.unshift(p)
  return p
})

route('GET', '/projects/:id', ({ params }) => {
  const p = state.projects.find((x) => String(x.id) === params.id)
  if (!p) throw mockError(404, '项目不存在')
  return p
})

route('DELETE', '/projects/:id', ({ params }) => {
  state.projects = state.projects.filter((p) => String(p.id) !== params.id)
  return { ok: true }
})

// multipart 补传源码包：mock 拿不到真实文件，但**必须模拟出「源码已落盘」这个效果**。
// 原样返回的话，项目会永远停在 `storage_path: null`，
// 于是「上传 → 启动评估」这条主路径在 mock 下走不通 —— 而 mock 的用处正是
// 在没有后端时把主路径走一遍。
route('POST', '/projects/:id/upload', ({ params }) => {
  const p = state.projects.find((x) => String(x.id) === params.id)
  if (!p) throw mockError(404, '项目不存在')
  // 与实测对齐（2026-10-16，`ranges/ecommerce`，项目 #17）：
  // 补传后 `storage_path` 变成**字符串形式的工作区目录名**、`total_loc` 就算出来了，
  // 但 `tech_stack` 仍是 null —— 它是 recon 阶段回填的，**不在上传这一步**。
  // `status` 也停在 `created`：后端在成功路径上根本不写 running/completed
  // （`projects/service.py` 只在失败时写 FAILED），详见本文档的「已知限制」。
  p.storage_path = String(p.id)
  p.total_loc = p.total_loc ?? 648
  return p
})

route('GET', '/projects/:id/source', ({ query }) => {
  const start = Number(query.start ?? 1)
  const end = Number(query.end ?? start + 6)
  return {
    path: String(query.path ?? 'app.py'),
    start,
    end,
    content: [
      "keyword = request.args.get('keyword', '')",
      'sql = f"SELECT * FROM products WHERE name LIKE \'%{keyword}%\'"',
      'cursor.execute(sql)',
    ].join('\n'),
  }
})

// —— 评估任务 ——

route('GET', '/assessments', () => ({ items: state.assessments, total: state.assessments.length }))

route('GET', '/assessments/:id', ({ params }) => {
  const a = state.assessments.find((x) => String(x.id) === params.id)
  if (!a) throw mockError(404, '评估任务不存在')
  return a
})

// 启动评估：项目 id 在路径上
route('POST', '/projects/:id/assessments', ({ params }) => {
  const project = state.projects.find((p) => String(p.id) === params.id)
  const stages: StageState[] = (
    ['recon', 'code_audit', 'poc_verify', 'exploit_chain', 'report_gen'] as const
  ).map((stage, i) => ({
    stage,
    status: i === 0 ? 'running' : 'pending',
    started_at: i === 0 ? new Date().toISOString() : null,
    finished_at: null,
    note: null,
  }))
  const a: Assessment = {
    id: nextId(),
    project_id: Number(params.id),
    project_name: project?.name ?? '未知项目',
    status: 'running',
    current_stage: 'recon',
    progress: 4,
    security_grade: null,
    stages,
    started_at: new Date().toISOString(),
    finished_at: null,
    created_at: new Date().toISOString(),
  }
  state.assessments.unshift(a)
  return a
})

route('POST', '/assessments/:id/stop', ({ params }) => {
  const a = state.assessments.find((x) => String(x.id) === params.id)
  if (!a) throw mockError(404, '评估任务不存在')
  a.status = 'stopped'
  a.finished_at = new Date().toISOString()
  return a
})

route('GET', '/assessments/:id/metrics', () => METRICS)

route('GET', '/assessments/:id/chains', () => CHAIN_NODES)

// —— 漏洞 ——

// 列表挂在评估任务下：评估 id 在路径上，status/severity/keyword 走 query
route('GET', '/assessments/:id/vulnerabilities', ({ params, query }) => {
  let items = state.vulns.filter((v) => String(v.assessment_id) === params.id)
  if (query.status) items = items.filter((v) => v.status === query.status)
  if (query.severity) items = items.filter((v) => v.severity === query.severity)
  if (query.keyword) {
    const kw = String(query.keyword).toLowerCase()
    items = items.filter(
      (v) =>
        v.vuln_type.toLowerCase().includes(kw) ||
        v.file_path.toLowerCase().includes(kw) ||
        v.sink_symbol.toLowerCase().includes(kw),
    )
  }
  return { items, total: items.length }
})

route('GET', '/vulnerabilities/:id', ({ params }) => {
  const v = state.vulns.find((x) => String(x.id) === params.id)
  if (!v) throw mockError(404, '漏洞不存在')
  return v
})

route('PATCH', '/vulnerabilities/:id', ({ params, body }) => {
  const v: Vulnerability | undefined = state.vulns.find((x) => String(x.id) === params.id)
  if (!v) throw mockError(404, '漏洞不存在')
  if (body.status) v.status = body.status as Vulnerability['status']
  return v
})

// 重新生成补丁：mock 不造新 diff，直接回当前这条（真实后端会重跑 L3 四道校验）
route('POST', '/vulnerabilities/:id/patch/generate', ({ params }) => {
  const v = state.vulns.find((x) => String(x.id) === params.id)
  if (!v) throw mockError(404, '漏洞不存在')
  return v
})

// 采纳补丁：只落「人已核对」，不自动合入
route('POST', '/vulnerabilities/:id/patch/accept', ({ params }) => {
  const v = state.vulns.find((x) => String(x.id) === params.id)
  if (!v) throw mockError(404, '漏洞不存在')
  return v
})

// —— 报告 ——

route('GET', '/reports', () => ({ items: state.reports, total: state.reports.length }))

/** 报告挂在评估任务下（fixtures 里用 report.assessment_id 匹配），不是 report id */
const reportOfAssessment = (assessmentId: string): Report => {
  const r = state.reports.find((x) => String(x.assessment_id) === assessmentId)
  if (!r) throw mockError(404, '该评估任务还没有报告')
  return r
}

// 在线预览：format 走 query
route('GET', '/assessments/:id/report', ({ params, query }) => {
  const r = reportOfAssessment(params.id)
  return { ...r, format: (query.format as Report['format']) ?? r.format }
})

// 导出：第一个参数是 assessmentId，format 走 query（不是 body）
route('POST', '/assessments/:id/report/export', ({ params, query }) => {
  const r = reportOfAssessment(params.id)
  return { ...r, format: (query.format as Report['format']) ?? r.format }
})

// 下载已导出的文件：返回字节流，不是 JSON
route('GET', '/assessments/:id/report/download/:fmt', ({ params }) => {
  reportOfAssessment(params.id)
  return new Blob([`mock report (${params.fmt})`], { type: 'application/octet-stream' })
})

// —— 管理与仪表盘 ——

route('GET', '/admin/llm/config', () => state.llmConfig)

route('PUT', '/admin/llm/config', ({ body }) => {
  // 注意：api_key 永远不在这里 —— 密钥只存在于后端 .env
  state.llmConfig = { ...state.llmConfig, ...(body as Partial<LlmConfig>), updated_at: new Date().toISOString() }
  return state.llmConfig
})

// 裸数组，不是 {items,total} —— 与后端 `list[SandboxConfigOut]` 一致
route('GET', '/admin/sandbox/configs', () => state.sandboxConfigs.map((c) => ({ ...c })))

// PUT 的 body 是**数组**，按每项的 id 定位（后端是 `list[SandboxConfigUpdate]`）
route('PUT', '/admin/sandbox/configs', ({ body }) => {
  for (const patch of body as unknown as SandboxConfigUpdate[]) {
    const idx = state.sandboxConfigs.findIndex((c) => String(c.id) === String(patch.id))
    if (idx < 0) throw mockError(404, '沙箱配置不存在')

    // mock 必须和后端**同一套可改字段**。写成 `{...old, ...patch}` 看着更短，
    // 但那会让 mock 模式「什么都改得动」而真实后端改不动 —— 两边的差别
    // 正好落在最不容易被发现的地方。
    const next = { ...state.sandboxConfigs[idx] }
    if (patch.name !== undefined) next.name = patch.name
    if (patch.base_image !== undefined) next.base_image = patch.base_image
    if (patch.network_policy !== undefined) next.network_policy = patch.network_policy
    if (patch.cpu_limit !== undefined) next.cpu_limit = patch.cpu_limit
    if (patch.memory_limit_mb !== undefined) next.memory_limit_mb = patch.memory_limit_mb
    if (patch.timeout_seconds !== undefined) next.timeout_seconds = patch.timeout_seconds
    if (patch.is_default !== undefined) next.is_default = patch.is_default

    // is_default 是单选语义，后端在写接口里强制 —— mock 不跟着做的话，
    // 演示时会看到两行同时是「默认」，而真实环境永远不会。
    if (patch.is_default === true) {
      state.sandboxConfigs.forEach((c, i) => {
        if (i !== idx) c.is_default = false
      })
    }

    state.sandboxConfigs[idx] = next
  }
  return state.sandboxConfigs.map((c) => ({ ...c }))
})

// 审计日志：mock 不造假记录，返回空集合
route('GET', '/admin/audit-logs', () => ({ items: [], total: 0 }))

route('GET', '/dashboard/stats', () => ({
  ...DASHBOARD,
  project_count: state.projects.length,
  assessment_count: state.assessments.length,
  running_count: state.assessments.filter((a) => a.status === 'running').length,
  recent_assessments: state.assessments.slice(0, 5),
}))

// --- 错误构造 ----------------------------------------------------------------

function mockError(status: number, detail: string): AxiosError {
  const response = {
    data: { detail },
    status,
    statusText: detail,
    headers: {},
    config: {} as InternalAxiosRequestConfig,
  } as AxiosResponse
  return new AxiosError(detail, String(status), undefined, undefined, response)
}

// --- 适配器 ------------------------------------------------------------------

export const mockAdapter: AxiosAdapter = async (config) => {
  const method = (config.method ?? 'get').toUpperCase()

  // 去掉 baseURL 前缀，只留 /auth/login 这样的路径
  const base = config.baseURL ?? ''
  const raw = config.url ?? ''
  const full = raw.startsWith('http') ? new URL(raw).pathname : raw
  const path = (base && full.startsWith(base) ? full.slice(base.length) : full) || '/'

  const ctx: Ctx = {
    path,
    params: {},
    query: (config.params as Record<string, unknown>) ?? {},
    body: parseBody(config.data),
  }

  await sleep(120 + Math.random() * 260)

  for (const r of routes) {
    if (r.method !== method) continue
    if (!r.pattern.test(path)) continue
    const data = r.handler(ctx)
    if (data === undefined) continue
    return {
      data,
      status: 200,
      statusText: 'OK',
      headers: new AxiosHeaders(),
      config,
    }
  }

  throw mockError(404, `[mock] 未定义的路由：${method} ${path}`)
}

function parseBody(data: unknown): Record<string, unknown> {
  if (!data) return {}
  if (typeof data === 'string') {
    try {
      return JSON.parse(data) as Record<string, unknown>
    } catch {
      return {}
    }
  }
  if (typeof data === 'object') return data as Record<string, unknown>
  return {}
}
