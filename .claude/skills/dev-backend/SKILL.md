---
name: dev-backend
description: |
  把「模块概要设计 be-0X」变成 `vibecoding_doc/specs/` 下的后端模块 spec。
  当用户要「生成后端 spec」「按 be-0X 开发」「给认证/组织/导入/检索/审计/看板/FAQ/缺口出个 spec」
  「写后端模块 spec」「be-0X 落成 spec」时触发。
  核心动作：读 be-0X → 四份输入对账 → 照后端模块模板出 spec → 自检。
  **只产出 spec，不写业务代码**——实现是评审通过之后的另一个步骤。
---

# 后端模块 spec 生成（dev-backend）

## 定位

上游有三份文档回答不同的问题：PRD 回答「做什么」，字典回答「字段长什么样」，
`模块概要设计/be-0X` 回答「这个模块内部怎么分文件、暴露什么接口、落哪些表」。

**本 skill 只做第四件事**：把 `be-0X` 这份**设计**落成一份**变更 spec**——
某次具体改动怎么做、怎么验。

`模块概要设计/README.md` §6 已经定死了流程，本 skill 是它的可执行版本：

> 1. 从 §2 找到承载该需求的模块 → 打开对应模块文档；
> 2. spec 的「分层落点」抄该文档 §2，「API 契约」抄 §3，「涉及的表」抄 §5；
> 3. spec 若发现模块文档有缺漏或设计不合理，**先改模块文档再写 spec，不要绕过**。

**与 `dev-spec` 的分工**：`dev-spec` 是元流程与门禁（判断该出哪种 spec、生命周期、命名）；
本 skill 是**后端模块**这一类的执行器，管怎么把 be-0X 读透、对账、落成 spec。
前端对应物是 `dev-frontend`。三者不冲突，`dev-spec` 管「要不要做」，本 skill 管「怎么做对」。

**与 `dev-frontend` 的关键差异**：前端有 pencil 原型作为**第三份输入**（原型 ↔ 设计 ↔ 代码三方对账）；
后端**没有原型**，但多一份更硬的东西——**现有代码**。
`backend/` 已有一批真实现（`core/`、`tasks/`、`api/` 壳子），
所以后端的对账是 **be-0X ↔ 字典 ↔ PRD ↔ 代码** 四方对账，
而 be-0X 里每个「📄 已有」都必须到代码里核实（见第 3 步）。

---

## 触发后必须先读

1. `vibecoding_doc/模块概要设计/README.md` —— 模块清单、依赖图、统一模板、写作纪律
2. **承载本次需求的 `vibecoding_doc/模块概要设计/be-0X-*.md`** —— 本 spec 的主要来源
3. `vibecoding_doc/核心数据字典.md` —— 表/字段/枚举/错误码/**权限码**的唯一来源
4. `vibecoding_doc/PRD.md` —— §8 是**接口路径与 DTO 的唯一来源**，不得自创
5. `vibecoding_doc/spec-templates/后端模块spec模板.md` —— 照它出
6. `CLAUDE.md` —— 分层铁律、安全红线、已知坑

**再按需读**（对账要用）：

- 相邻的 `be-0X` 文档 —— 凡出现「归 be-XX」的，去那份文档核对是否真写了
- `backend/` 现有代码 —— 核 `be-0X` 的 📄 标记是否属实
- `vibecoding_doc/specs/` —— 查编号、查是否已有相关 spec

---

## 第 0 步：前置检查

**1. 确认后端现状，别凭记忆。** 每次开工先跑：

```bash
# 哪些是真实现、哪些是壳子
find backend -name "*.py" -size +0 | grep -v __pycache__ | xargs wc -l | sort -n
# 壳子里的 TODO 就是「没实现」的硬证据
grep -rn "TODO" backend/api/
```

当前已知基线（2026-10-14，**开工时重新核**）：

| 位置 | 状态 |
|---|---|
| `backend/core/`（settings / logging / exceptions / response） | ✅ 真实现 |
| `backend/tasks/`（celery_app + import/mining/stats 三个任务模块） | ✅ 真实现 |
| `backend/api/` 三个 router | ⚠️ **TODO 壳子**，只有签名与 docstring |
| `engines/`、`clients/`、`models/`、`schemas/`、`service/`、`faq/` | ❌ 空目录 |

**2. 确认要出哪一份 spec。** 一个后端模块 = 一份 spec（总纲 §2 的粒度）。
P1：be-01…be-05；P2：be-06、be-07；P3：be-08、be-09。

**3. 定编号。** 格式 `{期次}-{NN}-be-{名称}.md`，`NN` **全局唯一、按开发顺序递增**，
不按前后端分段：

```bash
ls vibecoding_doc/specs/ | grep -oE '^[P0-9]+-[0-9]+' | sort -t- -k2 -n | tail -1
```

取现有最大 `NN` + 1。**注意**：`总纲 §2` 的示例 `P1-01-be-auth` 是编号体系落地前写的占位，
别照抄——以 `specs/` 目录实际最大编号为准。（`P1-01` 已被 `fe-login` 占用。）

---

## 第 2 步：从 be-0X 抽结构

9 份 be 文档**骨架完全一致**（都是下面这 10 节），所以可以机械按节取用：

| be-0X 的节 | 进 spec 的哪一节 | 注意 |
|---|---|---|
| 头部引用块（期次/依赖/字段出处/需求出处） | spec 头部 + §1 | **照抄依赖与被依赖**，那是对账的入口 |
| §1 职责与边界（1.1 做什么 / 1.2 明确不做） | spec §1 模块定位 | **1.2 必须进 spec**，它是防职责膨胀的划界 |
| §2 分层落点 | spec §2 | 逐行抄；**状态列要重新核实**（见第 3 步） |
| §3.1 HTTP 接口 | spec §4 API 契约 | 路径与 DTO 再去 PRD §8 复核 |
| §3.2 内部接口（函数签名 + 抛出的异常） | spec §5 或 §8 | 这是**跨模块契约**，必须与对方文档一致 |
| §4.1 类与函数 / §4.2 关键流程 | spec §5 核心逻辑 | mermaid 时序、事务边界、异步边界照搬 |
| §5 数据依赖（MySQL / Milvus / Redis 三小节） | spec §3 涉及的表 | 不要复制字段表，写「见字典 §x.y」 |
| §6 异常与错误码 | spec §6 | 错误码引字典 §5.7，不自造 |
| §7 硬约束落地 | spec §5 的「安全红线」段 | **本模块具体怎么落**，不是「参考 CLAUDE.md」 |
| §8 与其它模块的契约 | spec §8 或单列 | 本模块承诺什么、要求别人保证什么 |
| §9 验收对齐 | spec §8 验收标准 | 对应 PRD 验收编号（A1–A9） |
| §10 待确认 | spec §10 | **编号要接着全局清单往下排**（见第 4 步） |

spec 模板里 §7 异步任务、§9 测试数据两节，be-0X 里没有直接对应——
分别从 §2/§4 的 tasks 落点、PRD §9 的造数场景取。

---

## 第 3 步：对账 —— 本 skill 的核心，别跳

**be 文档单看是自洽的，错都在它和别人的交界处。** 逐条核这七项；
每一项都要给出**证据**（文件路径 + 行号，或章节号），不能凭印象。

### 3.1 接口路径 ↔ PRD §8

PRD §8 未列的路径，去 `backend/api/*.py` 的 docstring 核对（壳子里的签名是既有事实）。
**两处都没有的路径 = 自创，标 ❌ 登记，不要写进 spec 当作已定。**

### 3.2 DTO 字段 ↔ 字典

spec 里出现的每个字段都要能在字典 §2.x / §3 / §4 找到。
**字典没有的字段，标 ❌ 或 🟡 写进待确认，并同时在字典 §9 追加编号**（README 写作纪律 2）。

### 3.3 🔴 ID 类型一律 `string`

字典 §2.1 把 `sys_user.id` / `sys_department.id` / `sys_role.id` 全定为 **VARCHAR**。
这条已经被踩过一次：前端 `types/auth.ts` 把 `depts` 写成 `number[]`、`user_id` 写成 `number`，
两处都错，且**从类型上看完全说得通**，直到对着字典才发现。

→ spec 里凡出现 ID，写 `str`。**看到 `int` 就当错误处理，去字典确认。**

### 3.4 🔴 权限码：不许发明，必须登记

字典 §5.6 **只权威定义了 `org:*`**（以及认证的公开/登录）。
`kb:*` / `faq:*` / `gap:*` / `stats:*` / `audit:*` 全是 🟡 待定（§9 #11/#46/#49/#61）。

**为什么这件事在后端 spec 里比在前端更要命**：权限码是**后端 `sys_permission` 种子**
与**前端 `v-permission` 常量**之间的隐式契约。两边各写各的码名，后果是
**按钮永远不显示、或接口永远 403，而且不报任何错**——前端以为后端没实现，
后端以为前端没接，两边都自洽。

→ spec 里每出现一个权限码：① 能在字典 §5.6 找到就引它；
② 找不到就**明确写「🟡 本 spec 暂定，需进 `sys_permission` 种子」**，
并**同时在字典 §9 追加编号**。两处都要动。

### 3.5 🔴 状态标记（✅/📄/🟡/❌）必须重新核实

be-0X 的状态列是**写文档那一刻**的判断，可能已经过期。逐条核：

- 标 **📄 已有** 的 → 到代码里确认真的存在（`grep` 一下函数名/文件）
- 标 **🟡 拟设计** 的 → 确认确实还没有（别把已经写好的当没写）
- 标 **❌ 未定义** 的 → 确认字典/PRD 里确实没有

已知的一处实例：be-01 §2 标 `main.py` 是「📄 已有但当前只挂了 import / query / data_mining 三个路由」
——**这句话是对的**，但它是写文档时的现状；`auth_router` 挂没挂，每次都要重新看 `main.py`。

### 3.6 跨模块契约：两边都要对得上

be-0X 里凡是写「**归 be-XX**」「由 be-XX 调用」的：

1. 去那份 be-XX 文档，确认它**真的写了**这个函数/契约；
2. 确认**签名一致**（参数、返回类型、抛出的异常类）；
3. 不一致时**两份文档都要改**，并在各自的待确认里留痕。

**为什么这条最值得花时间**：跨模块共用的实现若各写一份，症状是
「登录时算出的 `effective_depts` 与依赖注入时算出的不一样」——
**最难查的越权/漏权 bug**。be-01 §4.1 已经把 `load_user_identity` 明确归到 be-02
并写明了理由，就是为了防这个。你写别的模块时要沿用这个判据：
**同一个语义只准有一份实现，spec 里要指明它归谁。**

### 3.7 错误码 ↔ 字典 §5.7

`1001 / 2001 / 2002 / 3001 / 3002 / 4001` 是既有约定，
由 `backend/core/exceptions.py` 的全局处理器兜底。不自造错误码。

---

## 第 4 步：写 spec

- 路径：`vibecoding_doc/specs/{期次}-{NN}-be-{名称}.md`（第 0 步定好的编号）
- 照 `spec-templates/后端模块spec模板.md`，**所有字段填满，不留空**
- 头部状态从 **草稿** 起步（总纲 §3 的生命周期：草稿 → 评审 → 冻结 → 实现中 → 已实现）
- **待确认编号接着全局清单往下排**：先看字典 §9 现有最大编号和已有 spec 里的 §9-x，
  本 spec 从下一个号开始，**不要每个 spec 都从 9-1 重新数**

**两处都要动**：本 spec 新发现的缺口，除了写进自己的待确认，
还要在 `vibecoding_doc/核心数据字典.md` §9 追加编号（README 写作纪律 2）。
只写一处，下一个人翻字典时看不到。

**发现 be-0X 有缺漏或设计不合理时**：README §6 定的是「**先改模块文档再写 spec，不要绕过**」。
改完在 be-0X 的 §10 也留一条，说明为什么改。

---

## 第 5 步：自检

出完 spec 后逐条核（**这些不依赖跑代码**）：

1. **路径来源**：spec 里每条接口路径，都能指到 PRD §8 或 `backend/api/*.py` 的 docstring。
   有一条指不出来 = 自创。
2. **字段来源**：每个字段能指到字典的章节号。
3. **ID 全 `str`**：`grep -nE "\b(id|_id)\b.*int|: int" spec 文件` 过一遍。
   ⚠️ **这个 grep 有假阳性**：`expires_in: int`（秒数）、`top_k: int`、`total: int` 都不是 ID。
   命中后逐条看**字段名**，别见到 `int` 就改——改错比不改更糟。
4. **权限码**：每个码要么引字典 §5.6，要么标了 🟡 + 已在字典 §9 登记。
   `grep -oE '`[a-z]+:[a-z_:*]+`' spec 文件 | sort -u` 列出来逐个确认。
   ⚠️ **同样有假阳性**：**Redis 键命名空间**（`rag:auth:*` / `rag:faq:*`）长得和权限码一模一样，
   会被一起抓出来。它们在 Redis 小节里，不在权限小节里——按**出现位置**判断，别按形状判断。
5. **状态标记属实**：📄 的到代码里 grep 过，🟡 的确认过确实没有。
6. **跨模块契约双向一致**：引用了别的 be-XX，去那份文档核过签名。
7. **安全红线逐条落地**：CLAUDE.md 八条里与本模块相关的，spec §5 要写**具体怎么做**，
   不是「参考 CLAUDE.md」。八条里通常至少有 1、4、7、8 与本模块相关。
8. **待确认编号不与既有冲突**：和字典 §9、其它 spec 的编号比一遍。
   🔴 **取字典 §9 的最大编号必须用 `awk` 限定区间**，不能直接 grep：

   ```bash
   awk '/^## 9\. 待确认/,/^## 10\./' vibecoding_doc/核心数据字典.md \
     | grep -oE '^\| [0-9]+ \|' | grep -oE '[0-9]+' | sort -n | tail -1
   ```

   直接 `grep -oE '^\| [0-9]+ \|' 整个字典` 会**误抓 §5.7 错误码表**（`| 5000 |` 等，格式完全相同），
   得出「最大编号 5000」这种荒谬结论。本 skill 首跑时踩过。
   另：spec 自身用 `| **79** |` 这种**加粗**编号，所以 `grep '^\| [0-9]+'` **抓不到本 spec 自己的行**——
   验证时要把加粗形式一起纳入，否则会误判成「一条都没写」。

---

## 硬约束速查

### 分层铁律（spec 的「分层落点」逐行核）

- `api/` **禁止**业务逻辑与 SQL —— 只做校验 + 注入 + 转发
- `engines/` **禁止** import FastAPI 的任何东西
- `clients/` **禁止**把第三方异常类型泄漏到上层——统一转 `core/exceptions.py` 的自定义异常
- 跨层传数据一律用 `schemas/` 的 Pydantic 模型，**不传裸 dict**

### 安全红线（八条，spec 里逐条写「本模块怎么落」）

1. 用户身份**从 JWT 解析**，覆盖客户端传参的 `user_context`（越权漏洞，PRD §11.3 R3）
2. LLM 输出与知识正文渲染前过 DOMPurify
3. 密码 `pwdlib[argon2]`；JWT 用 `pyjwt`（禁 `python-jose`）
4. 未授权内容**不返回正文、不返回标题**；`ACL_REVEAL_BLOCKED_TITLES` 默认 false
5. 解 MinerU zip 前做**路径穿越校验**（拒 `..` 与绝对路径）+ 解压体积上限
6. 密钥走环境变量；`.env` 不入库
7. **每个写接口独立校验功能权限**，不得依赖前端隐藏按钮
8. 数据库操作**参数化**（ORM 或 `text()` + 绑定参数），禁 f-string 拼 SQL

### 检索实现要点（be-05 最容易写错）

- 混合检索用 `hybrid_search` + `RRFRanker(k=60)`，两路子检索 `limit = top_k * 3` 再融合
- ACL 过滤表达式：`acl_global == true or array_contains_any(acl_departments, [...]) or ...`
- **前置过滤后仍必须后置兜底**：MySQL 权威权限复核每个候选 `document_id`，
  不一致的剔除 + 告警。这是防越权的硬保证
- 部门权限**向下继承**：有效部门集合 = 自身部门 + 全部祖先
- Milvus `content` 字段要 `enable_analyzer=True` + `analyzer_params={"type":"chinese"}`
- SSE 必须 `fetch` + `ReadableStream`（**不能用 `EventSource`**），Nginx 要 `proxy_buffering off`

### 代码规范

- 全异步：路由、引擎、DB 访问一律 `async def` + `await`；
  **不要在异步函数里调阻塞 IO**（`requests` 等），需要时用 `run_in_threadpool`
- 所有函数写类型注解，包括返回值
- 统一响应 `{code, message, data}`；分页 `{list, total, page, page_size}`
- 配置走 `core/settings.py`，**禁止** `os.getenv`；常量阈值进配置，禁硬编码魔数
- 日志用 `logging`，禁 `print`；中文注释说明「为什么」而不是「做了什么」

---

## 踩过的坑

### 文档与代码的落差

- **be-0X 的状态标记会过期**。它是写文档那一刻的快照，`backend/` 一直在动。
  每次开工重新 `grep`，不要相信文档里的 📄。
- **`总纲 §2` 的命名示例 `P1-01-be-auth` 会误导**——`P1-01` 已经被 `fe-login` 占了。
  `NN` 全局连续，以后端 spec 落地时的实际最大编号 +1 为准。
- **9 份 be 文档骨架一致，但深度不一**。骨架一致只保证「节都在」，
  不保证「节里写全了」——`§3.2 内部接口` 有的模块写得细、有的只给一句。
  节里没写全的，就是对账要补的缺口。

### 类型与字段

- 🔴 **ID 是 VARCHAR 不是数字**。前端已经因此错过两次（`depts: number[]`、`user_id: number`）。
  后端 spec 里写 `int` 之前先去字典 §2.1 确认。
- 🔴 **不发明权限码**。字典 §5.6 只权威定义了 `org:*`，其余全是 🟡。
  自造码名的后果是「按钮不显示 / 接口 403，且不报错」，前后端各自自洽、互不知情。
- **不发明字段**。PRD/字典没有的字段要标 ❌/🟡 并**两处登记**（本 spec + 字典 §9）。

### 跨模块

- 🔴 **同一个语义只准有一份实现**。be-01 把 `load_user_identity` 归给 be-02 并写明理由，
  就是为了防「登录算的部门集合 ≠ 依赖注入算的部门集合」——最难查的越权/漏权 bug。
  写 spec 时遇到跨模块共用的逻辑，**指明它归谁**，不要两边各写一份。
- **跨模块契约要双向核**。be-0X 说「归 be-XX」的，去那份文档确认真的写了、签名一致。
  对不上就两边都改。
- **模块间的回路别写成单向**。README §3 有两条关键回路：
  be-05 ⟷ be-08（问答落 `qa_log` → 挖掘读它；FAQ 发布后检索第一步就命中缓存、不调 LLM）、
  be-05 ⟶ be-09 ⟶ be-04（未命中 → 写缺口 → 一键转建 → 生成 `kb_import_task` → 再导入 → 缺口 `closed`）。
  写其中任一模块的 spec 时，把回路的两头都想到。

### 工具链（CLAUDE.md 已记，spec 里要落到设计）

- 🔴 **Celery 的 `retry_backoff` / `retry_backoff_max` 对手动的 `self.retry()` 不生效**，
  会被静默忽略。用 `bind=True` + `self.retry()` 时一律显式算退避：
  `countdown = min(cap, base * 2 ** self.request.retries)`。
  不给 `countdown` 会退回 `default_retry_delay = 180` 秒。
- **Windows 上 worker 必须 `-P solo`**（或 `-P threads`），默认 prefork 池不可用。
- **`celery_app.py` 的 `include` 列表漏写任务模块 → 报 `Received unregistered task`**，
  **任务不执行且不报错到业务层**，很难查。
- 🔴 **Starlette 1.7 的 `include_router` 不再把子路由摊平进 `app.routes`**，
  而是包成 `_IncludedRouter`。要断言路由注册成功，用 `app.openapi()["paths"]`，
  **不要数 `app.routes`**——会漏报。
- **`pymysql` / `aiomysql` 连 MySQL 8 的默认 `caching_sha2_password` 需要 `cryptography` 包**，
  否则非 SSL 连接直接认证失败。加 `aiomysql` 时一并加 `cryptography`。
- **生产环境配置自检（`settings.py` 的 model_validator）会让缺失密钥的应用启动即失败**，
  这是刻意设计，不要改成 warning。
- **Windows 控制台是 GBK**，`uv run python` 打印中文会乱码。验证脚本**断言布尔值**，
  别靠肉眼读中文输出——这一条在写「验收标准」时会直接影响到你怎么描述验证方式。

### 环境约束（会决定 spec 能不能落地）

- 本机**没有 Docker**，Milvus 单机版依赖 Docker → 本地跑不了真 Milvus，
  开发靠直连云端（`60.205.138.167` 的 Redis 等）。
- 公司 GPU 服务器**只跑 BGE embedding**；MinerU 走官方 API（**有文档出境合规风险**，PRD R1），
  且它是**异步**的，只返回 `full_zip_url`，必须下载解压，不回正文。
- ECS 规格尚未确认（PRD O2），暂按 4C8G 规划；低于此 Milvus 会 OOM。

---

## 反模式（禁止）

- ❌ **跳过 be-0X 直接照 PRD 写 spec**。be-0X 里那些「归 be-XX」「明确不做」
  正是划分职责的地方，绕过它必然写出跨模块重复实现。
- ❌ **发现 be-0X 有缺漏就绕过去、在自己的 spec 里另发明一套结构**。
  README §6 定了：**先改模块文档再写 spec**。
- ❌ **发明接口路径**。PRD §8 是唯一来源；壳子里的 docstring 是次要来源；两处都没有就是不许写。
- ❌ **发明权限码 / 错误码 / 字段**，或发明了只在**一处**登记。
- ❌ **照抄 be-0X 的状态标记而不核实**。
- ❌ **在 spec 里写「参考 CLAUDE.md 安全红线」**——要写**本模块具体怎么落**。
- ❌ **本 skill 里写业务代码**。产出物只有 spec。

---

## 引用文件

| 文件 | 作用 |
|---|---|
| `vibecoding_doc/模块概要设计/README.md` | 模块清单、依赖图、统一模板、写作纪律；**§6 定义本 skill 的流程** |
| `vibecoding_doc/模块概要设计/be-0X-*.md` | 9 份后端模块设计（本 spec 的主要来源） |
| `vibecoding_doc/核心数据字典.md` | 表/字段/枚举/错误码/权限码唯一来源；**§9 是全局待确认清单** |
| `vibecoding_doc/PRD.md` | SSOT；**§8 是接口路径与 DTO 的唯一来源** |
| `vibecoding_doc/开发过程总纲.md` | 元流程、spec 粒度与命名、生命周期、前后端对齐 |
| `vibecoding_doc/spec-templates/后端模块spec模板.md` | 本 skill 的输出模板 |
| `.claude/skills/dev-spec/SKILL.md` | 元流程与门禁（管「要不要做」） |
| `.claude/skills/dev-frontend/SKILL.md` | 前端对应物（本 skill 的结构参照；它的「踩过的坑」对后端同样有借鉴） |
| `backend/` | 现有代码——**核 be-0X 状态标记的唯一依据** |
