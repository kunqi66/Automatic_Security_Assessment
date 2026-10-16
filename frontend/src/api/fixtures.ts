/**
 * Mock 假数据 —— 仅供后端未就绪时前端自测。
 *
 * 数据刻意贴合需求 2.5.9 的演示攻击链：
 *   SQL 注入 → 管理员凭证 → WebShell → 宿主机 RCE
 * 并且覆盖漏洞四态、补丁三来源、节点两验证态，方便把每条 UI 分支都点到。
 *
 * ⚠️ 接入真实后端后本文件与 mock.ts 可整体删除（VITE_USE_MOCK=false 即不再引用）。
 */
import type {
  Assessment,
  AttackChainNode,
  DashboardSummary,
  LlmConfig,
  LogEvent,
  PatchSuggestion,
  Project,
  Report,
  ResourceSample,
  SandboxConfig,
  SecurityGrade,
  Severity,
  StageState,
  TaintStep,
  User,
  Vulnerability,
  VulnStatus,
} from './types'

/** 相对当前时间的 ISO 时间戳，让 mock 数据看起来「刚刚发生」 */
const ago = (minutes: number): string =>
  new Date(Date.now() - minutes * 60_000).toISOString()

const ahead = (minutes: number): string =>
  new Date(Date.now() + minutes * 60_000).toISOString()

/**
 * mock 用户。
 *
 * `permissions` **必须与 `backend/app/api/deps.py` 的 `ROLE_PERMISSIONS[ADMIN]` 逐项对齐** ——
 * mock 模式下前端就是靠它决定按钮显不显示。对不齐的症状是：
 * mock 里能看到「新建评估」按钮，切到真后端就没有，而两边都不报错。
 * 注意这里**没有** `assessment:create`：管理员本来就没有（需求 2.5.2）。
 */
export const MOCK_USER: User = {
  id: 1,
  username: 'admin',
  role: 'admin',
  permissions: ['sandbox:manage', 'llm:manage', 'audit:view'],
  created_at: ago(60 * 24 * 30),
}

// ---------------------------------------------------------------------------
// 项目
// ---------------------------------------------------------------------------

export const PROJECTS: Project[] = [
  {
    id: 1,
    name: '靶场一 · 电商后台',
    source_type: 'git',
    source_url: 'https://github.com/example/vuln-ecommerce.git',
    source_branch: 'main',
    storage_path: 'workspaces/project-1',
    description: 'Flask + SQLite 的教学靶场，内置 SQL 注入与文件上传漏洞',
    tech_stack: { language: 'Python', framework: 'Flask', total_loc: '648' },
    total_loc: 648,
    status: 'completed',
    error_message: null,
    created_at: ago(60 * 24 * 7),
  },
  {
    id: 2,
    name: '靶场二 · 微服务用户中心',
    source_type: 'git',
    source_url: 'https://github.com/example/vuln-usercenter.git',
    source_branch: null,
    storage_path: 'workspaces/project-2',
    description: '多服务靶场，覆盖越权与 SSRF',
    tech_stack: { language: 'Python', framework: '', total_loc: '346' },
    total_loc: 346,
    status: 'completed',
    error_message: null,
    created_at: ago(60 * 24 * 3),
  },
  {
    id: 3,
    name: '内部管理系统（上传包）',
    source_type: 'upload',
    source_url: null,
    source_branch: null,
    storage_path: 'workspaces/project-3',
    description: '用户上传的源码压缩包',
    tech_stack: null,
    total_loc: null,
    status: 'created',
    error_message: null,
    created_at: ago(60 * 5),
  },
  {
    // 建档了但源码没补传 —— `storage_path` 为 null，**启动评估会被后端 400 拒绝**。
    // 这条数据的存在是为了让「未上传源码」那个状态在 mock 下也能被看见，
    // 否则选项目的下拉永远只显示正常项目，那段提示文案就成了死代码。
    id: 4,
    name: '刚建档 · 还没传源码',
    source_type: 'upload',
    source_url: null,
    source_branch: null,
    storage_path: null,
    description: null,
    tech_stack: null,
    total_loc: null,
    status: 'created',
    error_message: null,
    created_at: ago(2),
  },
]

// ---------------------------------------------------------------------------
// 评估任务
// ---------------------------------------------------------------------------

const stagesOf = (
  done: number,
  currentNote: string | null = null,
  failedAt: number | null = null,
): StageState[] => {
  const names = ['recon', 'code_audit', 'poc_verify', 'exploit_chain', 'report_gen'] as const
  return names.map((stage, i) => {
    if (failedAt !== null && i === failedAt) {
      return {
        stage,
        status: 'failed' as const,
        started_at: ago(30 - i * 5),
        finished_at: ago(28 - i * 5),
        note: currentNote,
      }
    }
    if (i < done) {
      return {
        stage,
        status: 'completed' as const,
        started_at: ago(40 - i * 6),
        finished_at: ago(34 - i * 6),
        note: i === 2 ? currentNote : null,
      }
    }
    if (i === done) {
      return { stage, status: 'running' as const, started_at: ago(3), finished_at: null, note: null }
    }
    return { stage, status: 'pending' as const, started_at: null, finished_at: null, note: null }
  })
}

export const ASSESSMENTS: Assessment[] = [
  {
    id: 101,
    project_id: 1,
    project_name: PROJECTS[0].name,
    status: 'completed',
    current_stage: 'report_gen',
    progress: 100,
    security_grade: 'critical',
    stages: stagesOf(5, '第 ④ 道校验：补丁打上后污点路径已消失'),
    started_at: ago(52),
    finished_at: ago(21),
    created_at: ago(55),
  },
  {
    id: 102,
    project_id: 2,
    project_name: PROJECTS[1].name,
    status: 'running',
    current_stage: 'poc_verify',
    progress: 62,
    security_grade: null,
    stages: stagesOf(2),
    started_at: ago(8),
    finished_at: null,
    created_at: ago(10),
  },
  {
    id: 103,
    project_id: 3,
    project_name: PROJECTS[2].name,
    status: 'failed',
    current_stage: 'poc_verify',
    progress: 45,
    security_grade: null,
    stages: stagesOf(2, '源码 tar 流同步至 ECS 失败：连接超时，本阶段跳过', 2),
    started_at: ago(120),
    finished_at: ago(112),
    created_at: ago(125),
  },
]

// ---------------------------------------------------------------------------
// 漏洞
// ---------------------------------------------------------------------------

const sqlInjectionTrace: TaintStep[] = [
  {
    step_index: 0,
    step_type: 'source',
    symbol: 'request.args.get',
    file_path: 'app.py',
    line: 42,
    code_snippet: "    keyword = request.args.get('keyword', '')",
    note: '外部可控输入进入函数',
  },
  {
    step_index: 1,
    step_type: 'propagate',
    symbol: 'f-string 拼接',
    file_path: 'app.py',
    line: 43,
    code_snippet: "    sql = f\"SELECT * FROM products WHERE name LIKE '%{keyword}%'\"",
    note: '未做参数化，污点进入 SQL 语句',
  },
  {
    step_index: 2,
    step_type: 'sink',
    symbol: 'cursor.execute',
    file_path: 'app.py',
    line: 44,
    code_snippet: '    cursor.execute(sql)',
    note: 'SQL 执行点 —— 污点在此未净化落地',
  },
]

const cmdInjectionTrace: TaintStep[] = [
  {
    step_index: 0,
    step_type: 'source',
    symbol: 'request.form.get',
    file_path: 'admin.py',
    line: 88,
    code_snippet: "    host = request.form.get('host')",
    note: null,
  },
  {
    step_index: 1,
    step_type: 'sanitize',
    symbol: 'shlex.quote',
    file_path: 'admin.py',
    line: 89,
    code_snippet: '    host = shlex.quote(host)',
    note: '命中净化函数，污点在此被截断',
  },
  {
    step_index: 2,
    step_type: 'sink',
    symbol: 'os.system',
    file_path: 'admin.py',
    line: 90,
    code_snippet: '    os.system(f"ping -c 1 {host}")',
    note: '虽有下沉点，但上游已净化 —— 故判 rejected',
  },
]

const patchOk = (diff: string, target: string): PatchSuggestion => ({
  source: 'llm',
  diff,
  target_file: target,
  validation: {
    valid_diff: true,
    window_ok: true,
    apply_check_ok: true,
    taint_cleared: true,
    failure_reason: null,
  },
})

/** 模板降级补丁 —— 模型不可用（L4）时由确定性模板产出。结论与排序不变，只有措辞与这行 TODO 不同 */
const patchTemplate: PatchSuggestion = {
  source: 'template',
  diff: [
    '--- a/user_service/views.py',
    '+++ b/user_service/views.py',
    '@@ -71,4 +71,4 @@ def profile(request):',
    "     uid = request.args.get('user_id')",
    '+    # TODO: 将归属校验下推到查询条件，避免依赖上层中间件',
    '-    user = User.objects.get(id=uid)',
    '+    user = User.objects.get(id=uid, owner=request.user)',
    '     return JsonResponse(serialize(user))',
  ].join('\n'),
  target_file: 'user_service/views.py',
  validation: {
    valid_diff: true,
    window_ok: true,
    apply_check_ok: true,
    taint_cleared: true,
    failure_reason: null,
  },
}

/** 第 ④ 道校验失败的补丁 —— F3 必须红字区分，不能与模板降级显示成一回事 */
const patchValidateFailed: PatchSuggestion = {
  source: 'validate_failed',
  diff: [
    '--- a/upload.py',
    '+++ b/upload.py',
    '@@ -57,3 +57,3 @@ def upload():',
    "     name = request.files['file'].filename",
    '-    path = os.path.join(UPLOAD_DIR, name)',
    '+    path = os.path.join(UPLOAD_DIR, name.replace("..", ""))',
    '     f.save(path)',
  ].join('\n'),
  target_file: 'upload.py',
  validation: {
    valid_diff: true,
    window_ok: true,
    apply_check_ok: true,
    taint_cleared: false,
    failure_reason:
      '打上补丁后重跑污点引擎，路径穿越路径仍然可达（`..\\` 变体未被过滤），本条未通过第 ④ 道校验',
  },
}

export const VULNERABILITIES: Vulnerability[] = [
  {
    id: 1001,
    assessment_id: 101,
    vuln_type: 'SQL 注入',
    severity: 'critical',
    status: 'verified',
    file_path: 'app.py',
    line_start: 42,
    line_end: 44,
    sink_symbol: 'cursor.execute',
    description:
      '商品搜索接口将用户可控的 keyword 直接以 f-string 拼入 SQL 语句，攻击者可构造闭合引号并注入任意 SQL，进而读取 users 表的管理员口令哈希。',
    remediation_note:
      '改用参数化查询（占位符 + 参数元组），不要用字符串拼接构造 SQL。若确需动态表名，应对其做白名单校验而非转义。',
    cvss_score: 9.8,
    guard_blocked: false,
    taint_trace: sqlInjectionTrace,
    patch: patchOk(
      [
        '--- a/app.py',
        '+++ b/app.py',
        '@@ -42,3 +42,4 @@ def search():',
        "     keyword = request.args.get('keyword', '')",
        '-    sql = f"SELECT * FROM products WHERE name LIKE \'%{keyword}%\'"',
        '+    sql = "SELECT * FROM products WHERE name LIKE ?"',
        '+    params = (f"%{keyword}%",)',
        '-    cursor.execute(sql)',
        '+    cursor.execute(sql, params)',
      ].join('\n'),
      'app.py',
    ),
  },
  {
    id: 1002,
    assessment_id: 101,
    vuln_type: '路径穿越',
    severity: 'high',
    status: 'potential',
    file_path: 'upload.py',
    line_start: 57,
    line_end: 59,
    sink_symbol: 'f.save',
    description:
      '文件上传接口直接使用客户端提供的 filename 拼接保存路径，未做规范化与白名单校验，存在写入任意路径的可能。',
    remediation_note:
      '保存前对文件名做 basename 提取 + 扩展名白名单，并用 os.path.realpath 确认最终路径仍位于上传目录之内。',
    cvss_score: 7.5,
    guard_blocked: true,
    taint_trace: [
      {
        step_index: 0,
        step_type: 'source',
        symbol: 'request.files',
        file_path: 'upload.py',
        line: 57,
        code_snippet: "    name = request.files['file'].filename",
        note: null,
      },
      {
        step_index: 1,
        step_type: 'sink',
        symbol: 'f.save',
        file_path: 'upload.py',
        line: 59,
        code_snippet: '    f.save(path)',
        note: '闸门 2 载荷校验未通过，未进入动态验证，故停留 potential',
      },
    ],
    patch: patchValidateFailed,
  },
  {
    id: 1003,
    assessment_id: 101,
    vuln_type: '命令注入',
    severity: 'medium',
    status: 'rejected',
    file_path: 'admin.py',
    line_start: 88,
    line_end: 90,
    sink_symbol: 'os.system',
    description:
      '诊断接口将 host 参数拼入系统命令，但上游已调用 shlex.quote 做转义，静态规则命中后经人工规则复核判定为误报。',
    remediation_note:
      '当前实现已做转义，建议进一步改为 subprocess.run 传列表参数，彻底避免 shell 解析。',
    cvss_score: 3.1,
    guard_blocked: false,
    taint_trace: cmdInjectionTrace,
    patch: null,
  },
  {
    id: 1004,
    assessment_id: 101,
    vuln_type: '硬编码凭证',
    severity: 'high',
    status: 'verified',
    file_path: 'config.py',
    line_start: 12,
    line_end: 12,
    sink_symbol: 'SECRET_KEY',
    description: '配置文件中硬编码了 Flask SECRET_KEY 与数据库口令，随源码一并泄露，可直接用于伪造会话。',
    remediation_note: '改为从环境变量读取，并将已泄露的密钥全部轮换。',
    cvss_score: 8.1,
    guard_blocked: false,
    taint_trace: [
      {
        step_index: 0,
        step_type: 'sink',
        symbol: 'SECRET_KEY',
        file_path: 'config.py',
        line: 12,
        code_snippet: 'SECRET_KEY = "s3cr3t-k3y-d0-n0t-share"',
        note: '字面量常量即可判定，无需传播链',
      },
    ],
    patch: patchOk(
      [
        '--- a/config.py',
        '+++ b/config.py',
        '@@ -10,3 +10,3 @@',
        ' import os',
        ' ',
        '-SECRET_KEY = "s3cr3t-k3y-d0-n0t-share"',
        '+SECRET_KEY = os.environ["SECRET_KEY"]',
      ].join('\n'),
      'config.py',
    ),
  },
  {
    id: 1005,
    assessment_id: 101,
    vuln_type: '存储型 XSS',
    severity: 'medium',
    status: 'unverified',
    file_path: 'templates/comment.html',
    line_start: 23,
    line_end: 23,
    sink_symbol: '|safe',
    description: '评论内容以 |safe 过滤器渲染，关闭了 Jinja2 的自动转义，用户提交的脚本会在他人页面执行。',
    remediation_note: '移除 |safe 过滤器；确需渲染富文本时，改用白名单式的 HTML 净化库处理后再输出。',
    cvss_score: 6.1,
    guard_blocked: false,
    taint_trace: [
      {
        step_index: 0,
        step_type: 'source',
        symbol: 'comment.body',
        file_path: 'templates/comment.html',
        line: 23,
        code_snippet: '    <div>{{ comment.body|safe }}</div>',
        note: null,
      },
      {
        step_index: 1,
        step_type: 'sink',
        symbol: '|safe',
        file_path: 'templates/comment.html',
        line: 23,
        code_snippet: '    <div>{{ comment.body|safe }}</div>',
        note: '待动态验证',
      },
    ],
    patch: null,
  },
  {
    id: 1006,
    assessment_id: 102,
    vuln_type: '越权访问',
    severity: 'high',
    status: 'verified',
    file_path: 'user_service/views.py',
    line_start: 71,
    line_end: 74,
    sink_symbol: 'User.objects.get',
    description: '查询用户资料时仅校验登录态、未校验目标 user_id 的归属，任意登录用户可遍历读取他人资料。',
    remediation_note: '在查询条件中强制加入当前登录用户 ID，或引入对象级权限校验装饰器。',
    cvss_score: 7.1,
    guard_blocked: false,
    taint_trace: [
      {
        step_index: 0,
        step_type: 'source',
        symbol: 'request.args.get',
        file_path: 'user_service/views.py',
        line: 71,
        code_snippet: "    uid = request.args.get('user_id')",
        note: null,
      },
      {
        step_index: 1,
        step_type: 'sink',
        symbol: 'User.objects.get',
        file_path: 'user_service/views.py',
        line: 74,
        code_snippet: '    user = User.objects.get(id=uid)',
        note: null,
      },
    ],
    patch: patchTemplate,
  },
  {
    id: 1007,
    assessment_id: 102,
    vuln_type: 'SSRF',
    severity: 'critical',
    status: 'unverified',
    file_path: 'gateway/proxy.py',
    line_start: 33,
    line_end: 36,
    sink_symbol: 'requests.get',
    description: '网关的图片抓取接口直接请求用户传入的 URL，未限制内网地址，可用于探测云元数据服务。',
    remediation_note: '对目标地址做协议白名单 + 解析后 IP 的内网段黑名单校验，并禁止跟随重定向。',
    cvss_score: 9.1,
    guard_blocked: false,
    taint_trace: [
      {
        step_index: 0,
        step_type: 'source',
        symbol: 'request.json',
        file_path: 'gateway/proxy.py',
        line: 33,
        code_snippet: "    url = request.json.get('url')",
        note: null,
      },
      {
        step_index: 1,
        step_type: 'sink',
        symbol: 'requests.get',
        file_path: 'gateway/proxy.py',
        line: 36,
        code_snippet: '    resp = requests.get(url, timeout=5)',
        note: null,
      },
    ],
    patch: null,
  },
]

// ---------------------------------------------------------------------------
// 攻击链（需求 2.5.9 演示链）
// 边由 parent_node_id 推导，无独立边表
// ---------------------------------------------------------------------------

export const CHAIN_NODES: AttackChainNode[] = [
  {
    id: 1,
    chain_id: 101,
    parent_node_id: null,
    node_type: 'entry',
    label: '公网入口 · 商品搜索接口',
    detail: '未认证可达，攻击面入口',
    verification_status: 'verified',
    vuln_id: null,
    rule_id: 'R1',
  },
  {
    id: 2,
    chain_id: 101,
    parent_node_id: 1,
    node_type: 'vuln',
    label: 'SQL 注入',
    detail: 'app.py:42 · cursor.execute',
    verification_status: 'verified',
    vuln_id: 1001,
    rule_id: 'R2',
  },
  {
    id: 3,
    chain_id: 101,
    parent_node_id: 2,
    node_type: 'credential',
    label: '获取管理员口令哈希',
    detail: 'users 表暴露，离线破解得到 admin 口令',
    verification_status: 'verified',
    vuln_id: null,
    rule_id: 'R4',
  },
  {
    id: 4,
    chain_id: 101,
    parent_node_id: 3,
    node_type: 'shell',
    label: '上传 WebShell',
    detail: '利用管理后台文件上传，落盘 shell.php',
    verification_status: 'verified',
    vuln_id: 1002,
    rule_id: 'R5',
  },
  {
    id: 5,
    chain_id: 101,
    parent_node_id: 4,
    node_type: 'host',
    label: '宿主机 RCE',
    detail: 'WebShell 执行容器内命令，经挂载卷逃逸至宿主机',
    verification_status: 'verified',
    vuln_id: null,
    rule_id: 'R7',
  },
  {
    id: 6,
    chain_id: 101,
    parent_node_id: 5,
    node_type: 'impact',
    label: '核心数据可读写',
    detail: '可读取全部订单与用户数据',
    verification_status: 'inferred',
    vuln_id: null,
    rule_id: 'R8',
  },
  // 第二条链：从 SSRF 出发的推演链，全部为 inferred
  {
    id: 7,
    chain_id: 101,
    parent_node_id: 1,
    node_type: 'vuln',
    label: 'SSRF（未验证）',
    detail: 'gateway/proxy.py:33 · 静态命中，动态验证未通过',
    verification_status: 'inferred',
    vuln_id: 1007,
    rule_id: 'R3',
  },
  {
    id: 8,
    chain_id: 101,
    parent_node_id: 7,
    node_type: 'credential',
    label: '云元数据凭证（推演）',
    detail: '若可达 169.254.169.254 则可获取实例角色凭证',
    verification_status: 'inferred',
    vuln_id: null,
    rule_id: 'R6',
  },
]

// ---------------------------------------------------------------------------
// 报告
// ---------------------------------------------------------------------------

export const REPORTS: Report[] = [
  {
    id: 201,
    assessment_id: 101,
    project_name: PROJECTS[0].name,
    title: '靶场一 · 电商后台 安全评估报告',
    format: 'html',
    status: 'ready',
    content_path: 'workspaces/project-1/reports/assessment-101.html',
    size_bytes: 486_233,
    generated_at: ago(21),
  },
  {
    id: 202,
    assessment_id: 101,
    project_name: PROJECTS[0].name,
    title: '靶场一 · 电商后台 安全评估报告（PDF）',
    format: 'pdf',
    status: 'ready',
    content_path: 'workspaces/project-1/reports/assessment-101.pdf',
    size_bytes: 1_204_887,
    generated_at: ago(20),
  },
  {
    id: 203,
    assessment_id: 103,
    project_name: PROJECTS[2].name,
    title: '内部管理系统 安全评估报告',
    format: 'html',
    status: 'failed',
    content_path: null,
    size_bytes: null,
    generated_at: ago(112),
  },
]

// ---------------------------------------------------------------------------
// 资源采样 / 日志
// ---------------------------------------------------------------------------

export const METRICS: ResourceSample[] = Array.from({ length: 40 }, (_, i) => {
  const wave = Math.sin(i / 4) * 18 + Math.cos(i / 2.5) * 7
  return {
    ts: ago(40 - i),
    cpu_percent: Math.max(2, Math.min(96, 38 + wave + (i % 5) * 2)),
    memory_mb: Math.max(120, Math.min(1800, 640 + wave * 11 + (i % 7) * 24)),
  }
})

const LOG_SCRIPT: Array<[LogEvent['stage'], LogEvent['level'], string]> = [
  ['recon', 'info', '环境侦察开始：识别项目技术栈与入口点'],
  ['recon', 'info', '识别到 Flask 2.3 + SQLite，共 14 个路由，其中 6 个未认证可达'],
  ['recon', 'info', '阶段 recon 完成，耗时 4.2s'],
  ['code_audit', 'info', '静态审计开始：tree-sitter 解析 23 个文件'],
  ['code_audit', 'info', '污点分析命中 source 18 处、sink 31 处'],
  ['code_audit', 'warn', 'app.py:42 检测到 SQL 注入（source → sink 路径完整）'],
  ['code_audit', 'warn', 'upload.py:57 检测到路径穿越'],
  ['code_audit', 'info', 'admin.py:88 命令注入候选被净化函数 shlex.quote 截断，降级为 rejected'],
  ['code_audit', 'info', '阶段 code_audit 完成，产出 5 条候选漏洞'],
  ['poc_verify', 'info', '动态验证开始：同步源码至 ECS'],
  ['poc_verify', 'info', 'tar 流推送完成，共 1.8 MB，耗时 2.1s'],
  ['poc_verify', 'info', '创建沙箱容器（镜像 asa/sandbox-base:py312，网络策略 internal）'],
  ['poc_verify', 'info', '闸门 2 载荷校验通过（无外连、无破坏性指令）'],
  ['poc_verify', 'info', '容器内 exec 执行探针，nonce 匹配成功 → verified'],
  ['poc_verify', 'warn', 'upload.py 路径穿越：闸门 2 拦截载荷，未执行，状态置 potential'],
  ['poc_verify', 'info', '沙箱销毁，容器与源码目录已清理'],
  ['poc_verify', 'info', '阶段 poc_verify 完成：verified 3 / potential 1 / rejected 1'],
  ['exploit_chain', 'info', '攻击链推演开始：加载 R1–R8 规则集'],
  ['exploit_chain', 'info', 'R2 匹配：SQL 注入可作为初始访问点'],
  ['exploit_chain', 'info', 'R4 匹配：凭证获取 → 权限跃迁至管理员'],
  ['exploit_chain', 'info', 'R5 匹配：管理员权限 + 文件上传 → WebShell'],
  ['exploit_chain', 'info', 'R7 匹配：WebShell → 宿主机 RCE（跨边界跃迁）'],
  ['exploit_chain', 'warn', 'R6 推演链标记为 inferred：SSRF 未通过动态验证，该环未实际执行'],
  ['exploit_chain', 'info', '阶段 exploit_chain 完成：产出 8 个节点、2 条链'],
  ['report_gen', 'info', '报告生成开始'],
  ['report_gen', 'info', 'LLM 调用：生成漏洞描述与整改建议（temperature=0.2）'],
  ['report_gen', 'info', '实体白名单校验通过：输出未引入输入外的事实'],
  ['report_gen', 'info', '攻击链叙事节点集合比对通过：无新增/缺失节点'],
  ['report_gen', 'info', '补丁四道校验：①合法 diff ✓ ②±20 行窗口 ✓ ③git apply --check ✓ ④污点路径消失 ✓'],
  ['report_gen', 'warn', 'upload.py 补丁第 ④ 道校验未通过（路径仍可达），标记为「校验未通过」'],
  ['report_gen', 'info', '渲染 HTML 报告并生成 PDF'],
  ['report_gen', 'info', '阶段 report_gen 完成，评估任务结束'],
  ['system', 'info', '评估完成：项目综合等级 = critical'],
]

export const LOGS: LogEvent[] = LOG_SCRIPT.map(([stage, level, message], i) => ({
  id: `${1700000000000 + i}-0`,
  ts: ago(52 - Math.floor(i * 1.4)),
  stage,
  level,
  message,
}))

/** 供 mock SSE 流式吐出：只吐「当前阶段及之后」的日志，模拟进行中的任务 */
export const RUNNING_LOGS: LogEvent[] = LOG_SCRIPT.slice(9).map(([stage, level, message], i) => ({
  id: `${1700000900000 + i}-0`,
  ts: ahead(0),
  stage,
  level,
  message,
}))

// ---------------------------------------------------------------------------
// 配置类
// ---------------------------------------------------------------------------

export const SANDBOX_CONFIGS: SandboxConfig[] = [
  {
    id: 1,
    name: '默认沙箱（Python 3.12）',
    base_image: 'asa/sandbox-base:py312',
    network_policy: 'internal',
    cpu_limit: 1,
    memory_limit_mb: 1024,
    timeout_seconds: 300,
    // 总纲 §8.1：调度并发恒为 1，界面上只读。mock 里也照实写 1，
    // 免得演示时看到一个真实系统里不可能出现的并发数。
    max_concurrency: 1,
    is_default: true,
  },
  {
    id: 2,
    name: '轻量沙箱（Node 20）',
    base_image: 'asa/sandbox-base:node20',
    network_policy: 'internal',
    cpu_limit: 1,
    memory_limit_mb: 768,
    timeout_seconds: 180,
    max_concurrency: 1,
    is_default: false,
  },
]

export const LLM_CONFIG: LlmConfig = {
  provider: 'deepseek',
  base_url: 'https://api.deepseek.com/v1',
  model: 'deepseek-chat',
  temperature: 0.2,
  max_tokens: 2048,
  timeout_seconds: 15,
  max_retries: 1,
  is_default: true,
  available: true,
  updated_at: ago(60 * 26),
}

// ---------------------------------------------------------------------------
// 仪表盘聚合
// ---------------------------------------------------------------------------

export const DASHBOARD: DashboardSummary = {
  project_count: PROJECTS.length,
  assessment_count: ASSESSMENTS.length,
  running_count: ASSESSMENTS.filter((a) => a.status === 'running').length,
  vuln_total: VULNERABILITIES.length,
  vuln_by_severity: {
    critical: 2,
    high: 3,
    medium: 2,
    low: 0,
  } satisfies Record<Severity, number>,
  grade_distribution: {
    critical: 1,
    high: 1,
    medium: 0,
    safe: 1,
  } satisfies Record<SecurityGrade, number>,
  vuln_by_status: {
    verified: 3,
    potential: 1,
    rejected: 1,
    unverified: 2,
  } satisfies Record<VulnStatus, number>,
  recent_assessments: ASSESSMENTS,
}
