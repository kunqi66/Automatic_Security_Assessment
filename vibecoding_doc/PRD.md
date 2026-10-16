# PRD — 自动化安全评估系统（Automatic Security Assessment）

> 版本：v1.0
> 日期：2026-10-16
> 状态：需求已冻结，待进入开发

---

## 0. 一句话定义

面向代码工程的自动化安全评估系统：**用多 Agent 流水线对一个源码工程做「侦察 → 静态污点审计 → 沙箱内动态无害验证 → 攻击链推演 → 报告生成」，输出可复现的漏洞证据、Diff 修复补丁与结构化评估报告。**

---

## 1. 项目定位与成功标准

### 1.1 定位

**求职面试作品集项目**，不是毕设演示、不是生产产品。这决定了两条根本原则：

1. **真实度优先于覆盖面**。面试官会扒代码问「你的污点分析怎么实现的」「怎么保证 PoC 无害」「四个 Agent 之间怎么通信」。宁可只支持 4 类漏洞但每类都真做，也不要支持 10 类但靠正则和预置 JSON。
2. **可复现优先于功能多**。一条命令能起来的系统 >> 功能多但要手动配三小时才能跑。面试官没耐心。

### 1.2 成功标准（硬指标）

| 指标 | 目标值 | 验证方式 |
|---|---|---|
| 静态分析召回率 | ≥ 85% | 对自研靶场 8 个已知漏洞（GROUND_TRUTH.yaml）做回归 |
| 静态分析误报数 | ≤ 3 个 | 同上 |
| 动态验证误报剔除率 | ≥ 90% | 验证前后 Unverified 数量对比 |
| 最终精确率 | ≥ 90% | （真漏洞 / 报告出的全部漏洞） |
| 单靶场端到端耗时 | ≤ 8 分钟 | 计时 |
| 报告生成耗时 | ≤ 30 秒 | 计时 |
| 一键启动 | 1 条命令 | `deploy/start.ps1` |

---

## 2. 环境与约束（已探明的硬事实）

### 2.1 开发机（Windows 11 Home）

| 项 | 值 | 影响 |
|---|---|---|
| Python | **未安装全局**，但有 `uv 0.11.30` | 用 `uv python install 3.12` 自管 |
| Node / pnpm | v24.18.1 / 11.18.0 | ✅ |
| Docker | **未安装** | 沙箱必须走远程 |
| C 盘 | 剩 24G（89% 满） | ⚠️ **所有缓存/依赖必须放 D 盘** |
| D 盘 | 剩 195G | ✅ 项目与缓存都放这 |

**必须设置的环境变量**（否则 C 盘会被吃穿）：
```
UV_CACHE_DIR=D:\myself_complete_code\.cache\uv
UV_PYTHON_INSTALL_DIR=D:\myself_complete_code\.cache\uv-python
PNPM_STORE_DIR=D:\myself_complete_code\.cache\pnpm-store
PLAYWRIGHT_BROWSERS_PATH=D:\myself_complete_code\.cache\ms-playwright
```

### 2.2 执行机（阿里云 ECS）

| 项 | 值 | 影响 |
|---|---|---|
| 架构 / 系统 | x86_64 / Ubuntu 22.04.5 LTS | ✅ 镜像无障碍 |
| Docker | 29.8.1 | ✅ |
| **CPU** | **2 vCPU** | ⚠️ 沙箱并发度上限 1 |
| **内存** | **7.3G，已用 2.2G，0 swap** | ⚠️ 实际余量约 3-4G，**必须加 swap** |
| 磁盘 | 40G，剩 19G | ⚠️ 镜像要省 |
| 已占端口 | 8000(未知) / **19530(Milvus)** / 3306(MySQL) / 6379(Redis) | 后端改用 **8010**；Milvus/MySQL/Redis 复用不新建 |

**动作项（开发前完成）**：
- [ ] 阿里云加 2G swap：`fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile` + 写 `/etc/fstab`
- [ ] 确认 MySQL/Redis 是否被 `rag_manager_agent` 占用；若是，**新建独立 database + 独立账号 + Redis db=3**
- [ ] 生成 SSH 密钥对用于 Docker over SSH，**不使用密码登录**

---

## 3. 架构总览

```
┌────────────────────────── Windows 开发机（控制面） ──────────────────────────┐
│                                                                              │
│   React + TS + Vite (5173)                                                   │
│        │  REST + SSE                                                         │
│        ▼                                                                     │
│   FastAPI 后端 (8010)                                                        │
│        ├── 多 Agent 编排引擎 ─── 5 个 Agent                                   │
│        ├── 污点追踪引擎 (tree-sitter)                                         │
│        ├── PoC 构造与验证引擎                                                 │
│        ├── 攻击链规则引擎                                                     │
│        ├── 报告汇编 (Jinja2 + Playwright)                                     │
│        └── 沙箱执行器客户端 ──┐                                               │
│                               │                                              │
└───────────────────────────────┼──────────────────────────────────────────────┘
                                │ ① MySQL 3306 (业务数据)
                                │ ② Redis 6379 db=3 (任务队列 / 日志流)
                                │ ③ Docker over SSH (沙箱容器)
                                ▼
┌────────────────────────── 阿里云 ECS（数据面） ──────────────────────────────┐
│   MySQL 3306 ── security_assessment 库                                       │
│   Redis 6379 ── db=3: Stream(task:queue) + Stream(log:{assessment_id})       │
│   Docker 29.8.1 ── docker-proxy ──┬── 靶场容器（每任务一个独立 network）        │
│                                   └── PoC 执行容器                            │
│   已有：Milvus 19530 / 未知服务 8000（不动）                                   │
└──────────────────────────────────────────────────────────────────────────────┘
```

**架构叙事（面试可讲）**：控制面/数据面分离。控制面持有编排逻辑与 LLM 凭证，数据面只负责执行不可信代码。演进路径：`RemoteDockerExecutor`（当前）→ 独立 `sandbox-runner` 服务（预留接口）。

---

## 4. 技术选型（全部已决策）

| 层 | 选型 | 决策理由 |
|---|---|---|
| 后端语言 | **Python 3.12（uv 管理）** | tree-sitter / Docker SDK / Playwright 全在 Python 生态 |
| 后端框架 | **FastAPI + SQLAlchemy 2.0 + Alembic + Pydantic v2** | 异步原生，跟 `rag_manager_agent` 一致 |
| 实时通道 | **SSE (sse-starlette)** | 需求全是服务端单向推送，SSE 代码量约为 WS 一半 |
| 任务队列 / 日志流 | **Redis Stream** | 天然带消费确认，后端重启可续跑；日志用它而非 Pub/Sub，才能配合 SSE 的 `Last-Event-ID` 做断线补齐；不用 Celery（多进程在 2 核上是负担） |
| 业务库 | **MySQL 8（阿里云，独立 database）** | 复用现成，省资源 |
| 静态分析 | **tree-sitter + tree-sitter-python 自研** | 核心竞争点，绝不外包给 semgrep |
| 沙箱 | **Docker SDK over SSH → 远程 daemon** | 本机无 Docker |
| LLM | **DeepSeek（OpenAI 兼容层）+ 降级模板** | 统一协议，换模型只改 base_url |
| 编排 | **自研 asyncio 状态机** | 确定性 5 阶段流水线，LangGraph 是杀鸡用牛刀 |
| 前端 | **React 18 + TS + Vite + Ant Design 5** | AntD 覆盖需求 2.5.5 全部基础组件 |
| 状态/请求 | **Zustand + TanStack Query** | 轻量，不引 Redux |
| 攻击链图 | **React Flow** | React 原生、DAG 开箱、节点联动好接 |
| 代码 Diff | **Monaco Editor DiffEditor** | VSCode 同款，面试官认得，未来可加「点击采纳」 |
| PDF 导出 | **Playwright/Chromium 打印** | 避开 WeasyPrint 的 Windows GTK 地狱 |
| 报告模板 | **Jinja2（一套数据 → HTML/PDF/MD 三格式）** | 单一数据源 |

---

## 5. 目录结构

```
Automatic_Security_Assessment/
├── vibecoding_doc/                    # 本文档
│   └── PRD.md
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI 入口
│   │   ├── core/
│   │   │   ├── config.py              # Pydantic Settings，读 .env
│   │   │   ├── security.py            # bcrypt + JWT
│   │   │   ├── logging.py
│   │   │   └── events.py              # Redis Stream 封装（任务队列 + 日志流）
│   │   ├── db/
│   │   │   ├── base.py                # DeclarativeBase
│   │   │   └── session.py             # async engine
│   │   ├── models/                    # SQLAlchemy ORM（见 §6）
│   │   ├── schemas/                   # Pydantic DTO
│   │   ├── api/
│   │   │   ├── deps.py                # 认证依赖、RBAC 装饰器
│   │   │   └── v1/
│   │   │       ├── auth.py  projects.py  assessments.py
│   │   │       ├── vulnerabilities.py   chains.py
│   │   │       ├── reports.py  admin.py  dashboard.py
│   │   ├── projects/                  # ★ B1 项目管理模块（L3）
│   │   │   ├── service.py             # ProjectService 门面
│   │   │   ├── fetcher.py             # Git 克隆 / 压缩包安全解包
│   │   │   ├── workspace.py           # 源码工作区与统一路径规范
│   │   │   └── sync.py                # 源码 → ECS tar 流同步（Q23 定案 = 方案 A）
│   │   ├── agents/
│   │   │   ├── base.py                # BaseAgent 抽象
│   │   │   ├── recon.py               # 环境侦察
│   │   │   ├── code_audit.py          # 静态审计
│   │   │   ├── poc_verify.py          # 动态验证
│   │   │   ├── exploit_chain.py       # 路径推演
│   │   │   └── report.py              # 报告生成
│   │   ├── orchestrator/
│   │   │   ├── engine.py              # 阶段状态机
│   │   │   ├── context.py             # AssessmentContext
│   │   │   └── queue.py               # Redis Stream 消费
│   │   ├── analysis/                  # ★ 核心：污点追踪引擎
│   │   │   ├── parser.py              # tree-sitter 封装
│   │   │   ├── symbols.py             # 符号表 / 调用图
│   │   │   ├── sources.py             # Source 点定义
│   │   │   ├── sinks.py               # Sink 点定义
│   │   │   ├── sanitizers.py          # 净化函数定义
│   │   │   ├── taint.py               # 传播分析主逻辑
│   │   │   ├── summary.py             # 函数摘要（跨函数用）
│   │   │   └── cvss.py                # CVSS 评分映射
│   │   ├── sandbox/
│   │   │   ├── base.py                # SandboxExecutor 抽象
│   │   │   ├── remote_docker.py       # Docker over SSH 实现
│   │   │   └── metrics.py             # 资源指标采集
│   │   ├── verify/
│   │   │   ├── guard.py               # ★ HarmlessGuard 无害化闸门（归 B5，非 B2）
│   │   │   ├── probe.py               # 探针构造（按漏洞类型）
│   │   │   ├── runner.py              # 执行 + 响应匹配
│   │   │   └── fingerprints.py        # 特征响应库
│   │   ├── chain/
│   │   │   ├── rules.py               # 攻击链组合规则
│   │   │   └── builder.py             # DAG 构建
│   │   ├── report/
│   │   │   ├── assembler.py           # 按 assessment_id 聚合快照 → ReportData（缺字段打降级标记）
│   │   │   ├── scoring.py             # 纯函数：漏洞集合 → security_score / security_grade
│   │   │   ├── charts.py              # 内联 SVG 图表（以 Jinja2 全局函数注入模板，不依赖外部 CDN）
│   │   │   ├── pdf.py                 # Chromium 单例 + 分页参数（仅导出 PDF 时调用）
│   │   │   ├── templates/             # Jinja2: report.html.j2, report.md.j2
│   │   │   └── exporter.py            # 格式分发 + 落盘 + 写库；HTML/MD 同步产出，PDF 惰性生成
│   │   └── llm/
│   │       ├── client.py              # OpenAI 兼容客户端
│   │       ├── prompts/               # 提示词模板
│   │       └── fallback.py            # 无 key 降级模板
│   ├── alembic/
│   ├── tests/
│   │   ├── test_taint.py              # ★ 污点分析回归测试
│   │   ├── test_chain.py
│   │   └── benchmark.py               # 对靶场算召回率/误报率
│   └── pyproject.toml
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard/             # 项目概览大盘
│   │   │   ├── Workbench/             # 安全评估工作台（3 区）
│   │   │   ├── ReportCenter/          # 安全报告中心
│   │   │   └── SandboxConfig/         # 沙箱与环境配置
│   │   ├── modules/                   # 需求 2.5.5 的 5 个模块
│   │   │   ├── dashboard/             # 概览大盘模块
│   │   │   ├── pipeline/              # 流水线监控模块（Steps + LogStream + 指标）
│   │   │   ├── vuln/                  # 漏洞视窗模块（高亮 + 污点步进 + Monaco Diff）
│   │   │   ├── topology/              # 拓扑图谱模块（React Flow）
│   │   │   └── report/                # 报告导出模块
│   │   ├── api/                       # axios 客户端 + SSE hook
│   │   ├── components/
│   │   └── store/
│   └── package.json
├── ranges/                            # ★ 示例靶场工程集
│   ├── ecommerce/                     # 靶场一：电商后台
│   │   ├── app.py  models.py  db.py
│   │   ├── templates/  static/
│   │   ├── seed.sql
│   │   ├── GROUND_TRUTH.yaml          # ★ 答案：漏洞清单+行号+期望特征
│   │   ├── Dockerfile
│   │   └── README.md
│   └── usercenter/                    # 靶场二：微服务用户中心
│       └── （同构）
├── sandbox/
│   └── base/Dockerfile                # python:3.12-slim + flask + 依赖
├── deploy/
│   ├── docker-compose.yml             # 后端 + 前端 + Nginx（可选，最终部署用）
│   ├── nginx/
│   └── start.ps1                      # ★ Windows 一键启动
├── .env.example
└── README.md
```

---

## 6. 数据模型

```
users
  id, username(uk), password_hash, role(enum: security_engineer|developer|admin),
  created_at, last_login_at

projects
  id, name, description(str, nullable),        # 建档表单填写，非必填
  source_type(enum: git|upload), source_url, source_branch,
  credential_ref,                      # 指向密钥存储的引用，不落明文口令
  storage_path,                        # 控制面源码工作区路径（D 盘）
  tech_stack(json),                    # B1 只建列不填值，由 B3 在 recon 阶段回填
  total_loc, status(enum: created|running|completed|failed|stopped),
  error_message(text),                 # 建档失败原因（含 remediation 指引）
  created_by(fk users), created_at, updated_at

assessments                                   # 一次评估 = 一个 project 的一次运行
  id, project_id(fk),
  status(enum: created|running|completed|failed|stopped),   # 需求 2.5.4 状态流转
  current_stage, progress(int 0-100),
  security_score(float 0-100),                # 由 B6 scoring 在 report_gen 阶段写回
  security_grade(enum: critical|high|medium|safe),          # 项目综合等级（见下方术语说明）
  started_at, finished_at, error_message, stats(json), created_at

assessment_stages                             # 阶段级持久化（支持断点续跑）
  id, assessment_id(fk), stage(enum: recon|code_audit|poc_verify|exploit_chain|report_gen),
  status(enum: pending|running|completed|failed|skipped),
  started_at, finished_at, result_ref(json), log_excerpt(text),
  note(text)                           # 阶段失败或 skip 的原因（skip 不是错误，故不叫 error_message）

vulnerabilities
  id, assessment_id(fk), code(uk, 如 VULN-2026-0001), title,
  vuln_type(str, 如 sql_injection|path_traversal|hardcoded_secret|broken_access_control),
  severity(enum: critical|high|medium|low),
  cvss_score(float), cvss_vector(str),
  status(enum: unverified|verified|potential|rejected),   # ★ 需求 2.5.4 判定规则，四态
  file_path, line_start, line_end, code_snippet(text),
  sink_symbol(str),                    # 下沉点符号名 —— 补丁复验时校验「该条污点路径是否消失」的身份锚点
  description(text),                   # 漏洞描述（LLM 或模板生成，表达层）
  remediation_note(text),              # 整改建议正文；整改**顺序**由 B6 scoring 确定性产出，与此字段无关
  confidence(float 0-1),
  detection_method(enum: taint_intra|taint_inter|pattern),
  created_at

taint_paths                                   # ★ Source-to-Sink 传播轨迹
  id, vulnerability_id(fk), step_index, 
  step_type(enum: source|propagate|sanitize|sink),
  file_path, line, symbol, code_snippet, note

poc_attempts
  id, vulnerability_id(fk), payload(text), technique(str 如 boolean_blind),
  request_raw(text), response_raw(text),
  expected_pattern, matched(bool), elapsed_ms, http_status,
  harmless_guard_passed(bool),
  failure_reason(text),                # 未通过验证的原因 / 被闸门拦截的原因
  created_at

attack_chains
  id, assessment_id(fk), name, description,
  severity, entry_point, target_asset, confidence(float),
  narrative(text)                             # LLM 生成，降级时用模板

attack_chain_nodes
  id, chain_id(fk),
  node_type(enum: entry|vuln|credential|shell|host|impact),  # 需求 2.5.9 的演示链需要区分凭证 / Shell / 宿主
  vuln_id(fk nullable),
  parent_node_id(fk self, nullable),   # DAG 的边由此自引用派生，不单独建边表
  order_index, stage_name,
  precondition, postcondition, label, detail(text),
  rule_id(str, 命中的推演规则编号 R1–R8),
  verification_status(enum: verified|inferred)   # Q24 定案 = 方案 A：标注该环是「沙箱已验证」还是「推演推断」

patches
  id, vulnerability_id(fk), target_file, diff_content(text),
  status(enum: suggested|accepted|rejected),
  source(enum: llm|template|validate_failed),   # 产出源；validate_failed = 四道校验没过，仅供人工参考
  llm_model, rationale(text),
  # ↓ L3 四道校验的逐道结果，必须留痕：报告与前端据此解释「为什么这条只是建议、绝不自动应用」
  valid_diff(bool), window_ok(bool), apply_check_ok(bool), taint_cleared(bool),
  failure_reason(text),                # 首道未通过时的说明
  created_at

reports
  id, assessment_id(fk), format(enum: html|md|pdf), title,
  status(enum: generating|ready|failed),   # HTML/MD 同步产出，PDF 惰性生成 —— 必须有中间态
  content_path, size_bytes, summary(json), generated_at
  # 唯一约束: uk(assessment_id, format)

sandbox_configs                               # 需求 2.5.3 沙箱配置页
  id, name, base_image, network_policy(enum: none|internal|bridge),   # 默认 internal（禁出站，仅可 localhost 探测）
  timeout_seconds, max_concurrency, cpu_limit, memory_limit_mb,
  is_default(bool), updated_at

llm_configs                                   # 需求 2.5.2 管理员管理大语言模型推理参数
  id, provider(default: deepseek), base_url, model, temperature(default 0.2),
  max_tokens, timeout_seconds(default 15), max_retries(default 1),
  is_default(bool), updated_at
  # ⚠️ API Key 不入库：只从 .env 的 DEEPSEEK_API_KEY 读取（用户自行填写），
  #    避免密钥随数据库备份/导出泄露

resource_metrics
  id, assessment_id(fk), stage, container_id,
  cpu_percent, memory_mb, recorded_at

audit_logs
  id, user_id(fk), action, target_type, target_id, detail(json), ip, created_at
```

**本节相对初稿的修订记录**：初稿是意向性草图（例如 `category(enum)` 根本没给候选值），
与前端已落地的 DTO 对账后补齐为**可实现的精确定义**。规则同 §9：**对不上改代码，不改本节**；
但本节自身缺字段的，在此补齐并留痕。

| 表.字段 | 变更 | 理由 |
|---|---|---|
| `projects.description` | 新增（可空） | 建档表单需要一句话说明；不影响任何判定 |
| `assessments.created_at` | 新增 | 与 `started_at` 不同义：行创建即 `created`，`started_at` 是 worker 真正开跑的时刻 |
| `assessment_stages.error_message` → `note` | 改名 | 该字段也承载 **skip 原因**，而 skip 不是错误（总纲 §9.1 L3） |
| `vulnerabilities.category` → `vuln_type` | 改名 + 去 enum | 初稿列了 `(enum)` 却没给值集；实际类型集合随规则库演进，用字符串 + 规则库常量约束更合适 |
| `vulnerabilities.sink_symbol` | 新增 | 补丁第四道校验要回答「**这条**污点路径消失了吗」，需要一个稳定的身份锚点 |
| `vulnerabilities.remediation_note` | 新增 | 整改建议是 LLM 四个用点之一（总纲 §8.5），此前无处存放 |
| `attack_chain_nodes.node_type` | 值集扩充 | 原 `vuln\|asset\|goal` 无法表达需求 2.5.9 演示链中的「管理员凭证 / WebShell / 宿主机」，F4 也需按类型着色 |
| `attack_chain_nodes.detail` / `rule_id` | 新增 | 前者供 F4 节点展开；后者让「这条边是 R3 推出来的」可被追问、可被复查 |
| `patches.target_file` | 新增 | 补丁要落到哪个文件，前端 Monaco DiffEditor 需要 |
| `patches.source` | 新增 | 与 `status` 语义不同：`status` 是**人**采纳与否，`source` 是**产出源**（LLM / 模板 / 校验失败降级） |
| `patches` 四道校验列 | 新增 | 总纲 §8.5 L3 要求逐道留痕；没有这些列，「补丁为什么只是建议」就无从解释 |
| `reports.title` / `status` / `size_bytes` | 新增 | PDF 惰性生成必有中间态；报告中心要展示标题与体积 |
| `sandbox_configs.docker_image` → `base_image` | 改名 | 该字段是**基础镜像**，叫 docker_image 会与「容器镜像全名」混淆 |

**关键设计说明**

**1. 漏洞状态四态**（`vulnerabilities.status`）直接对应需求 2.5.4 的判定规则：

| 状态 | 产出阶段 | 判定依据 |
|---|---|---|
| `unverified` | 仅 `code_audit` | 静态污点分析命中：存在 source→sink 且未经净化的路径 |
| `verified` | 仅 `poc_verify` | 沙箱内无害探针在响应中匹配到 nonce 特征 |
| `potential` | 仅 `poc_verify` | 未通过动态验证，但风险模式仍成立（中低危隐患，防止误报干扰） |
| `rejected` | 仅 `poc_verify` | 静态误判被动态证伪 |

⚠️ **`potential` 只由动态阶段产出。** 静态阶段「部分路径被净化」这个信号**不由状态承载**，而由 `confidence ×0.6` 承载；最终状态一律由 B5 裁决。B4 是纯分析引擎，不产出任何状态字段。

**2. 两套「四级」术语不可混用**：

- **项目综合等级** `assessments.security_grade`：`critical` / `high` / `medium` / `safe`，对应需求 2.5.8 的「极高危 / 高危 / 中危 / 安全」，由 B6 的 `scoring.py` 计算，含高危一票否决
- **单漏洞严重度** `vulnerabilities.severity`：`critical` / `high` / `medium` / `low`

报告中项目级一律表述为「项目综合等级」，漏洞级表述为「漏洞严重度」。

---

## 7. 核心引擎设计

### 7.1 污点追踪引擎（★ 项目技术核心）

**能力边界（明确不做全程序指针分析）**：函数内传播 + **单层跨函数**传播。这一层覆盖了真实漏洞的绝大多数形态，且能在面试中完整讲清算法。

**流水线**：

```
① 解析    tree-sitter 解析所有 .py，得 AST + 行号映射
② 符号表  收集函数定义（名/形参/默认值/装饰器）、类、模块级赋值
③ Source 识别
    Flask:  request.args.get / request.form[] / request.json / request.get_json()
            request.values / request.cookies / request.headers
    通用:   sys.argv / os.environ / input()
    FastAPI: Request 对象 / Depends 注入参数
    → 产出 TaintedVar(symbol, file, line, origin)

④ 函数内传播（intra-procedural）
    - 赋值:      x = tainted                → x tainted
    - 字符串拼接: f"{t}..." / "%s" % t / t + "..." / "...".format(t)  → 结果 tainted
    - 容器:      [t] / {"k": t} / t.append(x) → 元素 tainted
    - 属性访问:   t.attr                    → tainted（保守）
    - 分支会合:   if/else 任一分支 tainted   → 汇合后 tainted
    - 下标:      t[0]                       → tainted

⑤ Sanitizer 消解（关键，决定误报率）
    整型化:   int() / intval 类转换
    文件名:   werkzeug.utils.secure_filename
    命令:     shlex.quote
    SQL:      参数化查询（execute 的 SQL 是常量字面量 + 独立 params 参数）
    白名单:   与常量集合做 in / == 比较后取常量分支
    转义:     html.escape / markupsafe.escape
    ORM:      SQLAlchemy filter_by / filter 且列名来自常量
    → 命中 sanitizer 则该变量标记 clean，并在 taint_paths 落一条 sanitize 步骤
    → 若 source 与 sink 之间**全部路径**都被净化，则不报漏洞
    → 部分路径净化时**仍报，但置信度 ×0.6**，状态保持 unverified
      （`potential` 是动态阶段的产物，静态阶段不产出该状态 —— 见 §6 关键设计说明 1）

⑥ Sink 匹配
    SQL 注入:   cursor.execute(sql) 中 sql 含 tainted 且非参数化
                db.session.execute(text(...))
    命令执行:   os.system / os.popen / subprocess.*(shell=True) / eval / exec
    文件操作:   open(path, 'w') / shutil.copy / 上传接口的 .save() 缺后缀白名单
    反序列化:   pickle.loads / yaml.load（无 SafeLoader）
    路径穿越:   send_file / os.path.join 后进 open（缺 secure_filename）
    越权(IDOR): 路由有 path/query 的 id 参数但函数体内**无任何鉴权判断**
                （检测模式：无 @login_required / 无 current_user 校验 / 无 owner 比对）
    → 命中即产出 Finding(source, sink, path, sanitized_paths)

⑦ 单层跨函数传播（inter-procedural, depth=1）
    a. 为每个函数生成**摘要**：形参 i → 是否到达某个 sink / 是否被净化
       例: def query(uid): cursor.execute("... " + uid)  
           → summary = {param0: {reaches_sink: sql_injection, sanitized: false}}
    b. 在调用点：若有 tainted 实参传入某形参，且该形参摘要显示可达 sink
       → 产出跨函数 Finding，路径 = source → 调用点(实参) → 形参 → sink
    c. 只展开一层。第二层调用记录为 "未展开" 并在报告中标注，避免虚假精确

⑧ 置信度与 CVSS
    confidence 计算：
      基础 0.9
      × 0.9  若为跨函数（间接性）
      × 0.6  若路径上存在部分净化
      × 1.1  若 sink 为 RCE 类高危函数（封顶 1.0）
    CVSS 3.1 base score 用规则映射表（漏洞类型 × 是否需要认证 × 是否可远程触发），
    在 poc_verify 通过后按验证结果上调（如从 7.5 → 9.8）
```

**测试策略**：`tests/test_taint.py` 直接对 `ranges/` 靶场跑，断言「8 个已知漏洞检出 ≥ 7 个」「误报 ≤ 3 个」。这是面试时最硬的证据。

---

### 7.2 沙箱执行器

**抽象接口**（Q9 的 C 方案，为演进到独立服务预留）：

```python
class SandboxExecutor(ABC):
    async def create(self, spec: SandboxSpec) -> SandboxHandle: ...
    async def exec(self, h: SandboxHandle, cmd: list[str], timeout: int) -> ExecResult: ...
    async def expose(self, h: SandboxHandle, container_port: int) -> int: ...  # 返回可访问的主机端口
    async def metrics(self, h: SandboxHandle) -> ResourceSample: ...
    async def destroy(self, h: SandboxHandle) -> None: ...
    async def reap_orphans(self, tag: str) -> int: ...    # 清理僵尸容器
```

**RemoteDockerExecutor 实现要点**：
- 连接：`docker.DockerClient(base_url="ssh://root@<host>", use_ssh_client=True)`，静默重试 3 次
- 每个评估任务创建**独立 docker network**（`--internal` 优先，仅在同网络内容器互通）
- 容器配额硬限：`mem_limit=256m, nano_cpus=5e8 (0.5核), pids_limit=128`
- **只读挂载源码**：bind mount 路径由**远端 daemon**（阿里云 ECS）解析，而源码克隆在 Windows 控制面，因此**源码必须先同步到 ECS 侧**才能挂载。**Q23 已定案（方案 A）**：B1 以 tar 流推送至 `/srv/asa/tasks/{assessment_id}/src/`，再 `volumes={"/srv/asa/tasks/{id}/src": {"bind": "/workspace", "mode": "ro"}}`；同步作为 `poc_verify` 阶段的**前置步骤**执行，销毁沙箱时同步删除该目录（详见总纲 §12.2）
- **探针不发布端口**：容器在 internal network，Windows 控制面无法直连。探针改为**容器内 `exec` 执行**——payload 经 base64 传入脚本，脚本用 Python 标准库请求容器自身的 `localhost:<port>`，响应经 stdout 回传。**不暴露端口、不需要 SSH 隧道、不需要 sidecar 容器**
- 打标签 `asa.task_id=<id>`，启动时 `reap_orphans` 清理历史残留
- 需求 2.5.4 的「终止任务立即注销测试进程」→ `handle.destroy()` 强制 kill 容器，但**阶段数据已在 MySQL 持久化，不受影响**

**并发策略（受 2 vCPU 限制）**：Redis Stream 单 worker 串行消费，**同一时刻只跑 1 个沙箱容器**。配置页仍暴露并发数参数（需求 2.5.3），默认值 1，并在报告中注明当前配额。

---

### 7.3 PoC 构造与无害化验证（★ 面试必问，务必做实）

**无害化四道闸门**：

1. **网络闸门**：容器在独立 internal network，探针目标硬白名单（只允许容器内靶场服务的 IP:Port），禁止出站到公网。
   ⚠️ **推论：运行期禁止 `pip install`** —— 装依赖必须联网，与禁止出站互斥。所有依赖**预置进镜像**（`sandbox/base/Dockerfile`）。需求 2.5.7 的「部署临时最小化运行环境」落实为「**选预置镜像 + 注入源码 + 起服务**」，不再运行期安装。
2. **载荷闸门**（`verify/guard.py` 中的 `HarmlessGuard`，**归 B5，非 B2**）：
   - 黑名单拒绝：`DROP|DELETE|UPDATE|INSERT|TRUNCATE|ALTER|GRANT|SHUTDOWN|rm -rf|mkfs|dd if=|:(){`
   - 禁止反弹 shell（`nc -e` / `/dev/tcp/` / `bash -i`）
   - 禁止写入靶场源码目录（只读挂载本身也拦住了）
   - 载荷长度上限 8KB，单漏洞探针数上限 20
3. **行为闸门**：
   - SQL 注入：只读探测。布尔盲注 `AND 1=1` vs `AND 1=2`，或 `UNION SELECT version()` 读取版本号
   - 命令执行：**不执行任何有副作用的命令**。用 `sleep 3` 做时间盲注，或 `echo <nonce>` 匹配回显
   - 文件上传：只传一个 `<nonce>.txt` 标记文件并尝试读回，**不传 WebShell**
   - 越权：只遍历自己造的模拟数据，不碰真实数据
4. **特征闸门**：每个载荷携带唯一 **nonce**，只有响应中匹配到该 nonce（或时间差落在预期窗口）才判定 Verified。这同时解决误报问题——靶场返回 500 不算成功。

**验证流程**：
```
for finding in unverified_findings:
    guard.check(payload)                        # 闸门 2（B5 verify/guard.py）
    if not guard.passed: → 标记 potential，记录原因
    # ↓ deploy_minimal_env / http_probe 是 B5 基于 B2 原语（create/exec/destroy）的组合封装，
    #   不是 SandboxExecutor 的方法（总纲 §6.1）——B2 只提供执行能力，不感知「探针」
    env  = b5.deploy_minimal_env(ctx.sandbox, finding)  # 选预置镜像 + 注入源码 + 起服务（运行期不 pip）
    resp = b5.http_probe(env, payload)                  # 容器内 exec 执行探针，不发布端口，响应经 stdout 回传
    if fingerprint.match(resp, nonce):                  # 闸门 4
        vuln.status = verified; vuln.cvss_score = upgraded_score
    else:
        vuln.status = potential if risk_pattern_exists else rejected
    ctx.sandbox.destroy(env)
```

**证据留存**：`poc_attempts` 完整保存 request_raw / response_raw，前端「漏洞详情与修复区」直接渲染报文（需求 2.5.3）。

---

### 7.4 攻击链推演（规则引擎，不是 if-else 硬编码）

**漏洞原子建模**：每个已验证漏洞抽象为 `(所需权限, 获得权限, 可利用资产, 产出)`。

**规则集**（`chain/rules.py`，预定义 8 条，让系统真去匹配）：

| # | 规则名 | 前置条件 | 权限跃迁 | 出口 |
|---|---|---|---|---|
| R1 | SQLi → 凭证泄露 | SQL 注入(已验证) + 查询可达 users 表 | anonymous → user | 明文/哈希凭证 |
| R2 | 凭证泄露 → 后台登录 | R1 产出 + 存在后台登录接口 | user → admin | 管理员会话 |
| R3 | 管理员 + 文件上传 → RCE | admin 会话 + 任意文件上传 | admin → 宿主机 | 代码执行 |
| R4 | IDOR → 敏感数据泄露 | 平行越权(已验证) | user → 全量用户数据 | 批量隐私数据 |
| R5 | 敏感信息泄露 → 数据库直连 | 配置/密钥泄露 | anonymous → DB | 数据库权限 |
| R6 | 命令注入 → RCE | 命令注入(已验证) | 任意 → 宿主机 | 代码执行 |
| R7 | 未授权访问 + 文件上传 → RCE | R3 的无 admin 变体 | anonymous → 宿主机 | 代码执行 |
| R8 | 任意文件读取 → 源码泄露 → 密钥泄露 | 文件读取(已验证) + 读得到配置 | anonymous → 密钥 | 凭据 |

**匹配算法**：以已验证漏洞为节点建属性图 → 对每条规则做前置条件匹配 → 命中则连边（记录权限跃迁）→ 得到有向图 → 拓扑排序提取「从 anonymous 出发、能到达最高权限出口」的路径 → 输出为 `attack_chains` + `attack_chain_nodes` → 前端 React Flow 渲染 DAG。

**LLM 的角色**：只为已匹配出的链生成**中文攻击叙事**（`narrative`），**不参与图的构建**。降级时用规则自带的 `narrative_template`。这样图的正确性不依赖 LLM——面试时这是个加分论证。

---

### 7.5 多 Agent 编排引擎

```python
class BaseAgent(ABC, Generic[InT, OutT]):
    name: str
    stage: Stage
    async def run(self, ctx: AssessmentContext, inp: InT) -> OutT: ...
    async def emit(self, level, msg, **extra) -> None:   # 写 Redis Stream → SSE
```

| Agent | 阶段 | 输入 | 输出 | 依赖 |
|---|---|---|---|---|
| `ReconAgent` | `recon` | 源码路径 | `TechStack`（语言/框架/依赖清单/入口点/推荐扫描顺序） | 解析 requirements.txt / pyproject.toml / package.json / pom.xml |
| `CodeAuditAgent` | `code_audit` | `TechStack` | `list[Finding]` | 污点追踪引擎 + LLM 生成中文描述与修复草案（**补丁须过 §7.6 L3 四道校验**） |
| `PocVerifyAgent` | `poc_verify` | `list[Finding]` | `list[Finding]`（含 status 更新 + `PocAttempt`） | 沙箱执行器 + 探针引擎 |
| `ExploitChainAgent` | `exploit_chain` | 已验证 Findings | `list[AttackChain]` | 规则引擎 + LLM 叙事 |
| `ReportAgent` | `report_gen` | 全量数据 | `Report` | Jinja2 + Playwright |

**编排引擎关键能力**（面试可讲的三点）：
1. **阶段持久化**：每个阶段完成后写 `assessment_stages`，后端崩溃重启后从最后未完成阶段续跑。
2. **可中断**：收到 stop → 置 `status=stopped` → 调 `sandbox.destroy()` 杀容器 → **已产出数据保留**（需求 2.5.4 明确要求）。
3. **可插拔**：新增第 6 个 Agent 只需实现 `BaseAgent` 并在阶段枚举里注册，编排引擎本身不改。

**实时推送**：Agent 通过 `emit()` 写 **Redis Stream** `log:{assessment_id}`（**不是 Pub/Sub** —— Pub/Sub 即发即弃、无历史，SSE 断线期间的日志会永久丢失）；后端 SSE 端点用 `XRANGE` 读取并转发，重连时依据浏览器自动携带的 `Last-Event-ID` 头**续读补齐断线期间的日志**。同时采集 `resource_metrics` 一并推送。

---

### 7.6 LLM 接入与可控性约束

> **本节是本项目的核心设计立场。** 项目定位是**可控多智能体**。多智能体系统最容易被质疑的三件事——结论随模型抖动、编造不存在的事实、产出无法验证的补丁——本节逐条封死。

#### 7.6.1 接入方式

- **统一 OpenAI 兼容客户端**：`base_url=https://api.deepseek.com`，模型 `deepseek-chat`。API Key 读 `.env` 的 `DEEPSEEK_API_KEY`（**用户自行填写**）。
- **参数固化**（对应需求 2.5.2「系统管理员管理大语言模型推理参数」）：`temperature=0.2`、`max_tokens` 设上限、单次调用 **15s 超时**、最多重试 1 次。参数由 admin 角色调整（`GET/PUT /api/v1/admin/llm/config`）。
- **缓存**：按 `(vuln_type, code_hash)` 缓存到 Redis，同项目重跑不重复调用。
- **只送必要上下文**：命中的代码片段（±20 行）与污点路径，**不发送整个文件**。

#### 7.6.2 四条铁律

**L1 · 不参与判定 —— LLM 不做结论**

漏洞有无、漏洞类型、严重度、CVSS 评分、验证状态（`verified`/`potential`/`rejected`）、攻击链的节点与边、项目综合等级、整改顺序 —— **全部由确定性代码产出**。

LLM 只产出**自然语言文本**。推论：**LLM 的输出永不进入控制流** —— 不决定阶段跳转、不决定是否继续、不决定重试、不决定状态。

> **判据**：拿掉 LLM，系统的**结论**必须一字不变，只有措辞会变。做不到，就说明 LLM 越界了。

**L2 · 不引入事实 —— LLM 不做检索**

LLM 输出中不得出现输入里没有的**文件路径、行号、CVE 编号、函数名、漏洞编码、依赖名**。

- **结构化字段一律由代码填充**，LLM 只填自由文本字段（`description` / `narrative` / `remediation_note`）。
- Prompt 只给「已确定的事实 + 要求改写为中文」，**不给「请分析这段代码有什么问题」这类开放任务**。

**L3 · 输出必校验 —— LLM 输出不可信**

LLM 输出与外部输入同等对待，进系统前必须过校验：

| 用点 | 校验规则 | 不过怎么办 |
|---|---|---|
| ① 漏洞描述 | 实体白名单：文中出现的 file_path / 行号 / CVE / 漏洞编码必须**在输入里存在** | 拒收 → 模板 |
| ② 修复补丁 | 见下方四道校验 | 拒收 → 通用修复建议 |
| ③ 攻击链叙事 | 叙事中提到的漏洞编码集合 **⊆ 该链的实际节点集合** | 拒收 → `narrative_template` |
| ④ 整改建议文案 | 只校验实体白名单；**顺序不校验，因为顺序不由 LLM 决定** | 拒收 → 类型模板 |

**②的补丁四道校验**（本设计最有价值的一环）：

1. **格式** —— 是合法 unified diff，可被解析
2. **范围** —— 只允许修改触发行 ±20 行窗口内的行（防止「顺手重构」）
3. **可应用** —— `git apply --check` 干跑通过
4. **有效** —— **把打完补丁的源码重新过一遍污点引擎，确认该条污点路径消失**

> 第 4 条是这套设计的核心主张：**补丁不是「LLM 说修好了」，而是「打上之后污点引擎不再报这一条」**。补丁有效性因此**可复现、可回归**——这是把 LLM 产出拉回工程可控范围的关键一步。
>
> 四道校验全部在**控制面**完成（源码工作区本就在控制面），**不需要沙箱**，代价是毫秒级。

**L4 · 可降级不阻断**

任何 LLM 失败 —— 无 key / 15s 超时 / 限流 / 校验不过 —— 都**不中断流水线**：降级产出 + 标注来源。

- 降级模板：`llm/fallback.py`，按漏洞类型预置中文模板 + 通用修复建议。
- **来源标注**：`llm_model` 字段区分 `deepseek-chat` / `template`，前端与报告**显式标注「模板生成」**，不假装是模型产出。
- 这直接对应「防 demo 翻车」：**系统任何功能不因 LLM 不可用而中断**。

#### 7.6.3 LLM 用点清单（封闭集合）

**新增用点必须在此登记并经评审，否则不允许引入。** 四个用点全部位于**表达层**：

| # | 用点 | 输入（全部来自确定性分析） | 输出 | 降级 | 归属 |
|---|---|---|---|---|---|
| ① | 漏洞中文描述与危害说明 | `vuln_type` + 污点路径 + ±20 行片段 | `description` (text) | 类型模板 | `CodeAuditAgent`（B3）经 `llm/` |
| ② | Diff 修复补丁 | 同上 + 上下文行 | `patch` (unified diff) | 通用修复建议 | 同上 |
| ③ | 攻击链中文叙事 | 已匹配的链（节点 + 命中规则 + 权限跃迁） | `narrative` (text) | `narrative_template` | B5 `chain/narrative.py` |
| ④ | 整改建议文案 | **已完成排序**的整改项 | `remediation_note` (text) | 类型模板 | B6 |

**注意 ④ 的措辞**：整改**顺序**由代码按 `等级 × 可达性 × 修复成本` 确定，LLM **只写文案，不排序**。

#### 7.6.4 面试问答预备

> **问**：「你这不是把大模型阉了吗？那还用多智能体干什么？」
>
> **答**：LLM 负责**表达**，不负责**结论**。安全工具的结论必须可复现、可回归、可解释——如果漏洞清单随模型温度变化，这工具就没法用，也没人敢用它的报告。LLM 的不可替代性在两处：把结构化事实翻译成人能读的中文，以及生成**待验证的**补丁草案。而补丁是否有效，**由污点引擎复验，不由模型自证**。

> **问**：「不用 LLM 模板也能生成描述，那 LLM 不是可有可无？」
>
> **答**：模板能说「此处存在 SQL 注入」，但说不清「该注入点位于订单查询接口、参数经字符串拼接直入 `execute`、因缺少参数化查询而可被构造读出 `users` 表」——这种**结合具体污点路径的自然语言表达**是模板写不出来的。降级模板保证**不中断**，不保证**同等质量**；两者的差距正是 LLM 的价值所在。

---

## 8. 前端设计

### 8.1 四个页面（需求 2.5.3）

**① 项目概览大盘页** — `Dashboard`
- 顶部统计卡：项目总数 / 高危漏洞总数 / 评估中任务数 / 平均安全评分（AntD Statistic）
- 全局安全态势图：CVSS 分布柱状图 + 漏洞类型占比饼图（AntD Charts / ECharts）
- 工程卡片列表：项目名 / 技术栈标签 / 最新评估时间 / 高·中·低危数徽标 / 状态徽标
- 「新建评估项目」弹窗：Tab 切换 Git 地址（可带分支、凭证）或 上传源码包（zip/tar.gz）

**② 安全评估工作台** — `Workbench`（三区布局，可拖拽分栏）
- **流水线监控区**：AntD `Steps` 五阶段步进器 + 实时终端日志流（**等宽深底滚动视窗**，SSE + `Last-Event-ID` 断线续读，非 xterm.js 库）+ 资源消耗指标（CPU/内存迷你折线图）
- **漏洞与攻击链路区**（模块归属 **F4**）：漏洞表格（CVSS 评分、分类、Verified/Unverified/Potential 状态标签、严重度色条）+ React Flow 攻击路径 DAG（节点可点击 → 联动侧滑漏洞详情）。**漏洞表格与 DAG 同属本区，均由 F4 承载**；F3 是「漏洞详情与修复区」的 owner，仅向本区提供 `VulnStatusTag` 组件（状态徽标的唯一实现，含 CVSS 联动色与 tooltip）。区域归属即模块归属，避免同一张表格两个模块各写一遍
- **漏洞详情与修复区**：源码上下文高亮（触发行 ±20 行）+ 污点传播步进标记（Source → …sanitize… → Sink 的可视化步进条）+ PoC 请求/响应报文（AntD Tabs）+ Monaco DiffEditor 渲染 AI 补丁 + 「一键复制 / 采纳导出」

**③ 安全报告中心页** — `ReportCenter`
- 左侧报告目录树，右侧合规文书样式渲染（衬线字体、A4 版心、页眉页脚）
- 内容：项目概况与执行信息 / 安全评分与风险大盘 / 已验证漏洞清单（完整证据链）/ 多步攻击路径推演 / 安全整改建议
- 顶部「一键导出」下拉：PDF / HTML / Markdown

**④ 沙箱与环境配置页** — `SandboxConfig`（仅 admin 可见）
- 沙箱镜像维护（镜像名、构建状态、重新构建按钮）
- 网络隔离策略（none / restricted / bridge）
- 扫描超时限制、并发任务数、CPU/内存配额
- 系统审计日志表格

### 8.2 五个前端模块（需求 2.5.5）

| 模块 | 目录 | 职责 | 关键依赖 |
|---|---|---|---|
| 概览大盘模块 | `modules/dashboard/` | 工程卡片、全局态势统计图、新建任务表单 | AntD Card/Statistic/Charts |
| 流水线监控模块 | `modules/pipeline/` | Agent 进度步进器、实时日志滚动视窗、状态徽标 | AntD Steps + 自研 `useSSE` |
| 漏洞视窗模块 | `modules/vuln/` | 源码上下文高亮、污点传播步进标记、Diff 渲染 | Monaco DiffEditor + 自研 TaintPathStepper |
| 拓扑图谱模块 | `modules/topology/` | 攻击路径有向图渲染、节点点击联动、漏洞详情侧滑 | React Flow + dagre 布局 |
| 报告导出模块 | `modules/report/` | Markdown/HTML 报告排版、在线预览、格式导出 | react-markdown + iframe 预览 |

---

## 9. API 接口清单

> **本清单是接口路径的唯一来源（SSOT）。** 前端 `src/api/endpoints.ts` 与后端 `app/api/v1/*` 都必须与之一致；
> 对不上时**改代码，不改本清单**。确需新增端点，先在本节登记、说明理由，再实现。

```
认证
  POST   /api/v1/auth/login                     登录 → JWT
  GET    /api/v1/auth/me                        当前用户
  GET    /api/v1/health                         存活与依赖探针（不鉴权，不返回业务数据）

项目
  GET    /api/v1/projects                       概览大盘列表（含统计）
  POST   /api/v1/projects                       创建（Git 或上传）
  GET    /api/v1/projects/{id}
  DELETE /api/v1/projects/{id}
  POST   /api/v1/projects/{id}/upload           补传源码包（multipart）
  GET    /api/v1/projects/{id}/source           ★ 读源码片段 ?path=&start=&end=（含路径穿越校验）

评估
  POST   /api/v1/projects/{id}/assessments      启动评估
  GET    /api/v1/assessments                    评估列表（分页）
  GET    /api/v1/assessments/{id}               状态 + 阶段列表 + 进度
  POST   /api/v1/assessments/{id}/stop          终止（杀沙箱、留数据）
  GET    /api/v1/assessments/{id}/stream        ★ SSE：日志/阶段/指标
  GET    /api/v1/assessments/{id}/metrics       资源指标快照（SSE 只推增量，首屏历史走这里）

漏洞
  GET    /api/v1/assessments/{id}/vulnerabilities   列表（可筛选 status/severity）
  GET    /api/v1/vulnerabilities/{id}               详情（含 taint_paths + poc_attempts + patch）
  PATCH  /api/v1/vulnerabilities/{id}               人工复核：覆盖 status（记录操作者，见 §11.3）
  POST   /api/v1/vulnerabilities/{id}/patch/generate 重新生成补丁
  POST   /api/v1/vulnerabilities/{id}/patch/accept   采纳补丁

攻击链
  GET    /api/v1/assessments/{id}/chains        攻击链 DAG（nodes + edges）

报告
  GET    /api/v1/reports                              报告列表（分页）
  GET    /api/v1/assessments/{id}/report              ?format=html|md，在线预览
  POST   /api/v1/assessments/{id}/report/export       ?format=pdf|md|html（PDF 惰性生成）
  GET    /api/v1/assessments/{id}/report/download/{fmt} 下载已导出的文件

仪表盘
  GET    /api/v1/dashboard/stats

管理（admin）
  GET/PUT /api/v1/admin/sandbox/configs          沙箱配置集合（表 sandbox_configs 有多行 + is_default，
                                                 故为复数集合资源；PUT 按 body.id 定位单条）
  POST   /api/v1/admin/sandbox/image/rebuild
  GET/PUT /api/v1/admin/llm/config               LLM 推理参数（temperature / max_tokens / timeout）
  GET    /api/v1/admin/audit-logs
```

**本节相对初稿的修订记录**（均为「需求已要求、初稿遗漏」或「资源语义写错」两类，非新增功能）：

| 端点 | 变更 | 理由 |
|---|---|---|
| `GET /assessments` | 新增 | 工作台与大盘需要跨项目的评估列表 |
| `GET /assessments/{id}/metrics` | 新增 | 总纲 §6.3 定「SSE 只推增量、快照走 REST」，指标曲线首屏必须有 REST 来源 |
| `PATCH /vulnerabilities/{id}` | 新增 | 需求 2.5.4 的人工复核要能覆盖 `status`，初稿只有补丁相关端点 |
| `GET /reports` | 新增 | 需求 2.5.3 的「安全报告中心」页需要报告列表 |
| `/admin/sandbox/config` → `configs` | 改为复数 | 配置页是**多行表格**，`sandbox_configs` 表本身多行且带 `is_default`，单数资源语义不成立 |

### 9.1 响应体约定

**成功**：直接返回资源 JSON，**不套 `{code, message, data}` 信封**。

理由：前端 axios 拦截器不做解包（`client.ts`），信封会让「哪一层负责剥壳」变成每个
调用点各自判断的事——这正是最常见的前后端集成 bug 来源。分页统一为
`{ items, total, page, page_size }`。

**失败**：HTTP 状态码表达分类，body 为

```json
{
  "detail": "无法连接远程 Docker daemon（ssh://root@ecs）",
  "error": {
    "stage": "poc_verify",
    "error_code": "SANDBOX_UNREACHABLE",
    "message": "无法连接远程 Docker daemon（ssh://root@ecs）",
    "remediation": "检查阿里云安全组 SSH 放行与密钥权限",
    "retryable": true,
    "occurred_at": "2026-10-16T10:00:00+08:00"
  }
}
```

`detail` 保持字符串，是为了兼容 FastAPI 原生形状与前端既有的 `errorMessage()`
（它读 `response.data.detail`）；总纲 §9.2 要求的**四要素**放在同级的 `error` 里，
供前端在需要时展示修复指引。两者冗余是刻意的：一个给人看，一个给程序看。

---

## 10. 靶场工程设计

### 10.1 靶场一：`ranges/ecommerce` — 电商后台

Python/Flask + SQLite（沙箱内零依赖），约 500 行。

| 漏洞 | 类型 | 位置（示意） | 严重度 | 攻击链角色 |
|---|---|---|---|---|
| V1 订单查询 SQL 注入 | SQLi | `app.py` `/api/order/query` 字符串拼接进 `cursor.execute` | 高 | R1 入口 |
| V2 后台任意文件上传 | 文件上传 | `app.py` `/admin/upload` 无后缀白名单 | 高 | R3 出口 |
| V3 配置硬编码密钥 | 敏感信息泄露 | `config.py` 硬编码 `SECRET_KEY` / DB 口令 | 中 | R5 |
| V4 后台登录弱校验 | 认证绕过 | `app.py` `/admin/login` 可被注入绕过 | 中 | R2 |

**演示攻击链**：`SQLi 读 admin 凭证 → 登录后台 → 上传 .py WebShell → 宿主机 RCE`
（对应需求 2.5.9 场景一）

### 10.2 靶场二：`ranges/usercenter` — 微服务用户中心

| 漏洞 | 类型 | 位置 | 严重度 | 攻击链角色 |
|---|---|---|---|---|
| V5 用户资料接口 IDOR | 平行越权 | `/api/user/<id>/profile` 无 owner 校验 | 高 | R4 |
| V6 用户列表未授权访问 | 未授权访问 | `/api/user/list` 无鉴权装饰器 | 高 | R4 |
| V7 手机号明文返回 | 敏感信息泄露 | 序列化未脱敏 | 中 | R4 |
| V8 调试接口未关闭 | 敏感信息泄露 | `/debug/config` 暴露配置 | 中 | R5 |

（对应需求 2.5.9 场景二）

### 10.3 靶场提供的路由 = PRD 规定的 ∪ 探针契约要求的

⚠️ **靶场不是"只提供上表那几条路由"**，而是提供两份清单的**并集**：

- 上两张表 = **PRD §10 规定的漏洞**（要能被发现）；
- `backend/app/verify/probe.py::PROBE_TEMPLATES` = **探针契约要求的端点**
  （要能被验证）。

两者**不重合**，而且不重合的部分是有意的。探针按漏洞**类别**给出固定的
路由与形态（例如 sqli 类的模板打 `/search?q=`），所以靶场必须额外提供
`/search`、`/api/ping`、`/api/file`、`/api/download`、`/api/upload`、
`/.env`、`/debug/config`、`/api/deserialize` 这些端点 —— 它们**不在**上面两张表里，
但缺了它们，对应类别的探针永远只能落 `unverified`，攻击链也就点不着。

**逐条对应表见 [`ranges/README.md` § 与探针契约的对应关系](../ranges/README.md)。**

之所以要在这里写一句：只读 PRD §10 的人会以为靶场只有 8 个漏洞端点，
进而觉得「探针打的那个路由靶场里没有」是靶场写错了 —— 实际是**这份 PRD
原先没把并集关系写出来**。对照 `ranges/README.md` 与
`GROUND_TRUTH.yaml` 的 `prd_mapping` 可以逐个核。

### 10.4 `GROUND_TRUTH.yaml`（★ 量化指标的基准）

每个靶场根目录放置，标注每个漏洞的：`id / category / file / line_start / line_end / expected_payload_technique / expected_response_pattern / cvss`。

`tests/benchmark.py` 读它跑回归，输出：
```
静态分析：  召回 7/8 (87.5%)   误报 2
动态验证后：误报剔除 2/2       最终精确率 8/8 (100%)
```

**这份基准数据是整个项目最有说服力的产出**——它把「我觉得我的工具还行」变成了可复现的数字。

---

## 11. 里程碑排期（业余 4-6 周）

| 周 | 目标 | 交付物 | 验收 |
|---|---|---|---|
| **W1** | 地基 | uv 环境 + FastAPI 骨架 + MySQL 连接 + Alembic 首版迁移 + JWT 认证 + Vite/AntD 前端骨架 + 登录页 + `start.ps1` + 阿里云 swap/独立库就绪 | `start.ps1` 一条命令起前后端，能登录 |
| **W2** | 静态分析核心 | tree-sitter 解析 + source/sink/sanitizer + 函数内传播 + 单层跨函数 + CVSS 映射 + `test_taint.py` | 对靶场跑出 ≥7 个漏洞，误报 ≤3 |
| **W3** | 沙箱 + 动态验证 | RemoteDockerExecutor + 靶场镜像化 + HarmlessGuard + 探针构造 + 特征匹配 | 靶场容器在阿里云跑起来，SQLi 探针成功匹配 nonce |
| **W4** | 编排 + 攻击链 + LLM | 编排引擎 + 阶段持久化 + 5 个 Agent + 攻击链规则引擎 + DeepSeek 补丁生成 + 降级模板 | 端到端跑通一次，产出 Verified 漏洞 + 1 条攻击链 |
| **W5** | 前端三页 + 报告 | 工作台三区 + SSE 实时日志 + React Flow 拓扑 + Monaco Diff + 报告 HTML/PDF/MD 导出 | 浏览器里能看到完整链路并导出 PDF |
| **W6** | 打磨与包装 | benchmark 跑分 + 录屏 + README/架构图 + 公网受限 demo + 报告样例 + 单元测试补齐 | 所有硬指标（§1.2）达标 |

**关键路径**：W2（污点分析）和 W3（沙箱）是风险最高的两周。若 W3 卡住，降级方案是先用**本地进程沙箱**（subprocess + 超时 + 白名单）跑通流程，再补远程容器——功能表现一致，架构叙事不变。

---

## 12. 风险与缓解

| # | 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|---|
| 1 | 2 vCPU / 7.3G 跑不动并发扫描 | 高 | 高 | 单 worker 串行；容器硬限 256M/0.5核；**加 2G swap**；必要时临时停 Milvus |
| 2 | 阿里云磁盘剩 19G 被镜像吃满 | 中 | 高 | 只用 `python:3.12-slim`；定期 `docker system prune`；不拉大镜像 |
| 3 | 远程 Docker over SSH 延迟/断连 | 中 | 中 | 3 次重试 + 任务幂等 + 启动时 `reap_orphans` 清残留 |
| 4 | Windows 无 Python | 确定 | 低 | `uv python install 3.12`，已确认 uv 可用 |
| 5 | C 盘仅剩 24G | 高 | 中 | §2.1 的四个缓存环境变量全部指向 D 盘 |
| 6 | LLM 超时/无 key 导致 demo 卡死 | 中 | 高 | 15s 超时 + 全链路降级模板（§7.6 L4），**任何功能不依赖 LLM** |
| 7 | WeasyPrint 在 Windows 需 GTK | 确定 | 中 | 已改用 Playwright/Chromium 打印 PDF |
| 8 | **公网 demo 被滥用为攻击工具** | 中 | **极高** | 三重限制：① 必须登录 ② **只允许扫描内置靶场，Git 地址白名单校验** ③ 全局限流 + 单任务超时。默认不开放公网，仅内网/录屏 |
| 9 | 污点分析误报率高，指标不达标 | 中 | 中 | sanitizer 规则持续补；跨函数只展开一层不虚假精确；用靶场 GROUND_TRUTH 做回归驱动 |
| 10 | 攻击链规则没匹配上 | 中 | 低 | 规则集覆盖到 8 条；无匹配时报告展示单点漏洞，不硬造链 |
| 11 | **LLM 幻觉污染结论**（编造路径/行号/CVE、生成无效补丁、结论随模型抖动） | 中 | **高** | **§7.6 四条铁律**：L1 不参与判定（结论对 LLM 零依赖）+ L2 不引入事实（结构化字段一律代码填充）+ L3 输出必校验（补丁四道校验，含**污点引擎复验**）+ L4 可降级不阻断 |
| 12 | LLM 生成的补丁看似合理但破坏业务逻辑 | 中 | 中 | 补丁**只作为「待人工确认的建议」呈现**，不自动应用（需求 2.5.2 明确由研发人员核对后采纳）；范围校验限制在 ±20 行内，防「顺手重构」 |

---

## 13. 需求覆盖对照表

| 需求条目 | 落实位置 |
|---|---|
| 2.5.1 项目接入与沙箱隔离 | §7.2 沙箱执行器 + §9 项目 API |
| 2.5.1 多智能体协同审计 | §7.5 编排引擎 + 5 个 Agent |
| 2.5.1 漏洞发现与精准验证 | §7.1 污点引擎 + §7.3 无害化验证 |
| 2.5.1 攻击链拓扑与补丁生成 | §7.4 规则引擎 + §7.6 LLM 补丁（含四道校验，补丁有效性由污点引擎复验） |
| 2.5.1 报告交付与实时监控 | §7.6 报告汇编 + §7.5 SSE 推送 |
| 2.5.2 三角色权限 | §6 users.role + §8.1 沙箱配置页 admin 限定 |
| 2.5.2 管理员管理大语言模型推理参数 | §7.6.1 参数固化 + §6 llm_configs + §9 admin LLM 配置 API |
| 2.5.3 项目概览大盘页 | §8.1 ① |
| 2.5.3 安全评估工作台（三区） | §8.1 ② |
| 2.5.3 安全报告中心页 | §8.1 ③ |
| 2.5.3 沙箱与环境配置页 | §8.1 ④ + §6 sandbox_configs |
| 2.5.4 状态与阶段流转 | §6 projects.status / assessment_stages.stage |
| 2.5.4 终止即注销进程但保留数据 | §7.2 + §7.5 编排引擎可中断 |
| 2.5.4 静态污点与动态验证判定 | §7.1 ⑥⑦ + §7.3 + §6 vulns.status 四态 |
| 2.5.4 攻击链路推演规则 | §7.4 规则集 R1-R8 + DAG |
| 2.5.5 五个前端模块 | §8.2 |
| 2.5.6 六个后端模块 | §5 目录 + §7 各引擎 |
| 2.5.7 核心业务流程 | §7.5 编排引擎五阶段 |
| 2.5.8 报告输出格式 | §7.6 + §8.1 ③ |
| 2.5.9 示例业务场景 | §10 两个靶场 |
| 2.5.10 验收标准 | §1.2 硬指标 + §11 里程碑 |

---

## 14. 待办动作项（开发前）

- [ ] 阿里云加 2G swap 并写入 `/etc/fstab`
- [ ] 确认 MySQL/Redis 是否被 `rag_manager_agent` 占用；新建 `security_assessment` 库 + 独立账号 + Redis db=3
- [ ] 生成 SSH 密钥对（用于 Docker over SSH），禁用密码登录
- [ ] 在 `.env` 中填入 `DEEPSEEK_API_KEY`
- [ ] Windows 侧设置 §2.1 的四个缓存环境变量
- [ ] `uv python install 3.12`
- [ ] 确认阿里云安全组放行策略（开发期建议只放行 SSH）

---

## 15. 遗留假设（如有不符请指出）

1. 本项目为**单用户/小团队内部使用**形态，未设计组织、多租户、配额计费。
2. 扫描目标语言**仅支持 Python**（靶场与被扫描工程均为 Python）。Java/JS 的 AST 规则留扩展位但不实现。
3. 阿里云那台 MySQL/Redis 若**不允许新建独立库**，则改为在该机器上用 Docker 起独立的 MySQL/Redis 容器（需重新评估 2 核资源，可能需要停掉 Milvus）。
4. 默认**不部署公网**；若部署，按 §12 风险 8 的三重限制执行，且只向面试官提供演示账号。
5. 界面语言为**简体中文**。
