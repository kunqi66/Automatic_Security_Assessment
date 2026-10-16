/**
 * 全部后端端点（对应 PRD §9 API 契约）。
 *
 * 每个函数只负责「发请求 + 定型」，不含任何业务判断 —— 判断在页面/store 里。
 */
import { http } from './client'
import type {
  Assessment,
  AttackChainNode,
  AuditLog,
  DashboardSummary,
  LlmConfig,
  LoginRequest,
  LoginResponse,
  Page,
  Project,
  Report,
  ResourceSample,
  SandboxConfig,
  SandboxConfigUpdate,
  SourceSnippet,
  User,
  Vulnerability,
  VulnQuery,
  VulnStatus,
} from './types'

// ---------------------------------------------------------------------------
// 认证
// ---------------------------------------------------------------------------

export const authApi = {
  login: async (payload: LoginRequest): Promise<LoginResponse> =>
    (await http.post<LoginResponse>('/auth/login', payload)).data,

  me: async (): Promise<User> => (await http.get<User>('/auth/me')).data,
}

// ---------------------------------------------------------------------------
// 项目（B1）
// ---------------------------------------------------------------------------

export interface CreateProjectPayload {
  name: string
  source_type: 'git' | 'upload'
  source_url?: string | null
  /** 不填则用仓库的默认分支 */
  source_branch?: string | null
  description?: string | null
}

/**
 * `POST /projects` 的超时。
 *
 * 🔴 **必须比 axios 的默认 30s 长很多**，因为 `source_type=git` 时后端是
 * **同步克隆**的（`projects/fetcher.py` 的 `CLONE_TIMEOUT_SECONDS = 300`）。
 * 用默认超时的话，客户端会在 30 秒时报「请求超时」，**而服务端的克隆还在继续**，
 * 最后项目真的建出来了 —— 用户以为失败了，其实成功了，
 * 于是很可能再点一次，得到一个重复项目。
 *
 * 350s = 后端克隆上限 300s + 建索引与扫描的余量。
 * `source_type=upload` 的建档是纯写库，用不到这个值，但多等无妨（不会真等）。
 */
const CREATE_PROJECT_TIMEOUT_MS = 350_000

export const projectApi = {
  list: async (): Promise<Page<Project>> => (await http.get<Page<Project>>('/projects')).data,

  create: async (payload: CreateProjectPayload): Promise<Project> =>
    (
      await http.post<Project>('/projects', payload, {
        timeout: payload.source_type === 'git' ? CREATE_PROJECT_TIMEOUT_MS : undefined,
      })
    ).data,

  get: async (id: number): Promise<Project> => (await http.get<Project>(`/projects/${id}`)).data,

  remove: async (id: number): Promise<void> => {
    await http.delete(`/projects/${id}`)
  },

  /**
   * 补传源码包 —— 必须走 multipart，不能把 File 塞进 JSON body。
   * 这里显式构造 FormData，让浏览器自带 boundary；手写 Content-Type 反而会丢掉 boundary。
   */
  upload: async (id: number, file: File): Promise<Project> => {
    const form = new FormData()
    form.append('file', file)
    // 同样是**同步**处理：后端在这一请求里解包 + 扫全树 + 写 manifest
    // （`projects/service.py` 的 `ingest_archive`），归档上限 500MB。
    // 用 30s 默认值会让「上传大包」稳定失败在一次本可以成功的请求上。
    return (await http.post<Project>(`/projects/${id}/upload`, form, { timeout: 350_000 })).data
  },

  /** 读源码片段。参数走 query（PRD §9 明确定义为 `?path=&start=&end=`） */
  source: async (
    id: number,
    path: string,
    start?: number,
    end?: number,
  ): Promise<SourceSnippet> =>
    (await http.get<SourceSnippet>(`/projects/${id}/source`, { params: { path, start, end } }))
      .data,
}

// ---------------------------------------------------------------------------
// 评估任务（B3 编排）
// ---------------------------------------------------------------------------

export const assessmentApi = {
  list: async (): Promise<Page<Assessment>> =>
    (await http.get<Page<Assessment>>('/assessments')).data,

  get: async (id: number): Promise<Assessment> =>
    (await http.get<Assessment>(`/assessments/${id}`)).data,

  /** 启动评估：项目 id 在路径上，故不需要 body */
  create: async (projectId: number): Promise<Assessment> =>
    (await http.post<Assessment>(`/projects/${projectId}/assessments`)).data,

  /** 终止任务。语义是 stop（杀沙箱、留数据），与「作废」不同，故不叫 cancel */
  stop: async (id: number): Promise<Assessment> =>
    (await http.post<Assessment>(`/assessments/${id}/stop`)).data,

  metrics: async (id: number): Promise<ResourceSample[]> =>
    (await http.get<ResourceSample[]>(`/assessments/${id}/metrics`)).data,

  /** 攻击链节点。边由 parent_node_id 推导，后端不返回独立边表。路径是 chains（复数） */
  chain: async (id: number): Promise<AttackChainNode[]> =>
    (await http.get<AttackChainNode[]>(`/assessments/${id}/chains`)).data,
}

// ---------------------------------------------------------------------------
// 漏洞（B4 分析 / B5 验证）
// ---------------------------------------------------------------------------

export const vulnApi = {
  /** 漏洞列表挂在评估任务下（`/assessments/{id}/vulnerabilities`），故评估 id 走路径而非 query */
  list: async (assessmentId: number, query: VulnQuery = {}): Promise<Page<Vulnerability>> =>
    (await http.get<Page<Vulnerability>>(`/assessments/${assessmentId}/vulnerabilities`, {
      params: query,
    })).data,

  get: async (id: number): Promise<Vulnerability> =>
    (await http.get<Vulnerability>(`/vulnerabilities/${id}`)).data,

  /** 人工复核：把某条漏洞标记为 rejected / potential 等 */
  updateStatus: async (id: number, status: VulnStatus): Promise<Vulnerability> =>
    (await http.patch<Vulnerability>(`/vulnerabilities/${id}`, { status })).data,

  /** 重新生成补丁（L3 四道校验在服务端跑） */
  patchGenerate: async (id: number): Promise<Vulnerability> =>
    (await http.post<Vulnerability>(`/vulnerabilities/${id}/patch/generate`)).data,

  /**
   * 采纳补丁。注意这只落「研发已核对」这件事，**后端不会自动应用补丁** ——
   * 补丁始终是建议，是否合入由人决定。
   */
  patchAccept: async (id: number): Promise<Vulnerability> =>
    (await http.post<Vulnerability>(`/vulnerabilities/${id}/patch/accept`)).data,
}

// ---------------------------------------------------------------------------
// 报告（B6）
// ---------------------------------------------------------------------------

export const reportApi = {
  list: async (): Promise<Page<Report>> => (await http.get<Page<Report>>('/reports')).data,

  /** 在线预览：报告正文由后端按 format 渲染，前端只拿元数据 */
  preview: async (assessmentId: number, format: Report['format'] = 'html'): Promise<Report> =>
    (await http.get<Report>(`/assessments/${assessmentId}/report`, { params: { format } })).data,

  /**
   * 导出。**报告挂在评估任务下**，故第一个参数是 assessmentId 而不是 report id；
   * format 走 query（PRD §9 定义为 `?format=pdf|md|html`），不放 body。
   */
  export: async (assessmentId: number, format: Report['format']): Promise<Report> =>
    (await http.post<Report>(`/assessments/${assessmentId}/report/export`, null, {
      params: { format },
    })).data,

  /** 下载已导出的文件：走后端返回的字节流，故 responseType 必须是 blob */
  download: async (assessmentId: number, fmt: Report['format']): Promise<Blob> =>
    (await http.get<Blob>(`/assessments/${assessmentId}/report/download/${fmt}`, {
      responseType: 'blob',
    })).data,
}

// ---------------------------------------------------------------------------
// 管理（LLM 参数 / 沙箱配置）
// ---------------------------------------------------------------------------

export const adminApi = {
  /** ⚠️ 响应中永远不含 api_key —— 密钥只在后端 .env，不入库、不外传 */
  getLlmConfig: async (): Promise<LlmConfig> => (await http.get<LlmConfig>('/admin/llm/config')).data,

  updateLlmConfig: async (payload: Partial<LlmConfig>): Promise<LlmConfig> =>
    (await http.put<LlmConfig>('/admin/llm/config', payload)).data,

  /**
   * 沙箱配置集合。
   *
   * ⚠️ 后端返回的是**裸数组**，不是 `Page<T>`：`sandbox_configs` 是个小集合
   * （通常就一两行），没有分页的意义。原先这里按 `Page<T>` 标，页面读
   * `data.items` 于是恒为 undefined，表格永远显示「暂无沙箱配置」——
   * 数据在库里、接口也返回了，只是没人接得住。一个不报错的静默失败。
   */
  sandboxConfigs: async (): Promise<SandboxConfig[]> =>
    (await http.get<SandboxConfig[]>('/admin/sandbox/configs')).data,

  /**
   * 改沙箱配置。**body 是数组**，后端按每项的 `id` 定位（`list[SandboxConfigUpdate]`）。
   * 返回更新后的**全量集合**，调用方可以直接拿它刷新缓存。
   *
   * 原先这里传的是单个对象 —— 后端会 400。但当时没有任何组件调用它，
   * 所以这个错误一直没被暴露出来。
   */
  updateSandboxConfig: async (payload: SandboxConfigUpdate[]): Promise<SandboxConfig[]> =>
    (await http.put<SandboxConfig[]>('/admin/sandbox/configs', payload)).data,

  /** 审计日志：谁改了结论（复核漏洞、改参数）都在这查得到 */
  auditLogs: async (): Promise<Page<AuditLog>> =>
    (await http.get<Page<AuditLog>>('/admin/audit-logs')).data,
}

// ---------------------------------------------------------------------------
// 仪表盘
// ---------------------------------------------------------------------------

export const dashboardApi = {
  stats: async (): Promise<DashboardSummary> =>
    (await http.get<DashboardSummary>('/dashboard/stats')).data,
}
