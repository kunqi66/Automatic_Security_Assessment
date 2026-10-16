---
name: dev-spec
description: |
  本项目（RAG 知识库管理平台）的「开发规范执行器」。当用户要开发新功能、生成 spec、
  写前端页面或后端模块时触发。触发词：「生成 spec」「开发规范」「开发总纲」「开始开发」
  「实现 XX」「写 XX 页面/模块」「给 XX 出个 spec」「按规范做 XX」。
  核心动作：先把需求落成 spec 文件（前端页面 spec 或后端模块 spec），评审通过后，
  再严格照 spec 写代码，写完回填验收。规则来源：CLAUDE.md + PRD（SSOT）。
---

# 开发规范（dev-spec）

## 定位

本项目的开发必须**先 spec 后代码**。本 skill 把 `CLAUDE.md`（怎么写）与
`PRD.md`（做什么）变成一条可执行流程：**每个功能，先产出一份 spec 文件，
评审通过后再写代码，写完回填验收结果。**

## 触发后必须先读（SSOT）

1. `vibecoding_doc/PRD.md` —— 需求与技术设计的唯一事实来源
2. `CLAUDE.md` —— 编码约定（分层铁律、安全红线、检索要点、已知坑）
3. `vibecoding_doc/开发过程总纲.md` —— 本 skill 遵循的元流程与门禁
4. `vibecoding_doc/核心数据字典.md` —— 表/对象/类/核心字段的统一字典，spec 的「涉及的表」「API 契约字段」从这里取
5. `vibecoding_doc/模块概要设计/README.md` —— 模块级设计的索引与统一模板；再按编号打开承载本次需求的模块文档
6. 对应 spec 模板（见下方「引用文件」）

## 流程（严格按此顺序，禁止跳过 spec 直接写代码）

### 第 1 步：判断 spec 类型

- **前端页面** → 用 `vibecoding_doc/spec-templates/前端页面spec模板.md`
- **后端模块** → 用 `vibecoding_doc/spec-templates/后端模块spec模板.md`
- 一个功能可能同时涉及两者：分别生成，前后端通过「接口映射 / API 契约」字段对齐。

### 第 2 步：生成 spec 文件

- 路径：`vibecoding_doc/specs/{P1|P2|P3}-{NN}-{fe|be}-{名称}.md`（命名规则见总纲 §2）
  ——该目录不存在就创建；spec 与 PRD、概要设计同属设计资产，统一收在 `vibecoding_doc/` 下
- 内容：完整填写模板所有字段，**不准留空**。查不到的字段标「待确认」，
  并把需要用户答复的问题列在 spec 末尾。
- 先检查 `vibecoding_doc/specs/` 是否已有相关 spec，避免重复创建或覆盖既有设计。
- **只生成 spec 时不得写业务代码**；实现必须等用户评审通过后单独开始。
- 硬约束必须落进 spec（见下方「硬约束速查」），不能只写「参考 CLAUDE.md」。

### 第 3 步：评审确认

- 把 spec 要点呈现给用户，确认后进入实现。用户改哪里，回改 spec，再实现。

### 第 4 步：照 spec 写代码

- 严格按 spec 的「分层落点」「API 契约」「验收标准」实现，不越界、不缩水。
- 每完成一条验收标准，在 spec 文件里勾选回填。

### 第 5 步：回填与关闭

- 全部验收通过后，在 spec 头部状态标「✅ 已实现」+ 日期。

## 硬约束速查（写代码时逐条核对，逐条落进 spec）

### 分层铁律

- `api/` 禁止业务逻辑与 SQL；`engines/` 禁止 import FastAPI；
- `clients/` 不泄漏第三方异常类型（统一转 `core/exceptions.py`）；
- 跨层传数据一律用 `schemas/` 的 Pydantic 模型，不传裸 dict。

### 安全红线（违反即严重缺陷）

1. 用户身份从 JWT 解析，**覆盖**客户端 `user_context`（越权漏洞，PRD §11.3 R3）。
2. LLM 输出与知识正文渲染前过 DOMPurify，再 `v-html`。
3. 密码 `pwdlib[argon2]`；JWT 用 `pyjwt`（禁 `python-jose`）。
4. 未授权内容不返回正文、不返回标题；`ACL_REVEAL_BLOCKED_TITLES` 默认 false。
5. 解 MinerU zip 前做路径穿越校验（拒 `..` 与绝对路径）+ 解压体积上限。
6. 密钥走环境变量；`.env` 不入库。
7. 每个写接口独立校验功能权限。
8. 数据库操作参数化，禁止 f-string 拼 SQL。

### 检索要点（search_engine 最容易错）

- 混合检索 `hybrid_search` + `RRFRanker(k=60)`，两路子检索 `limit = top_k * 3`。
- ACL 前置过滤表达式：`acl_global == true or array_contains_any(...) or ...`。
- 前置过滤后仍要 MySQL 权威复核（后置兜底），不一致剔除 + 告警。
- 部门权限向下继承：有效部门集合 = 自身部门 + 全部祖先。
- Milvus `content` 字段 `enable_analyzer=True` + `analyzer_params={"type":"chinese"}`。
- SSE 用 `fetch` + `ReadableStream`（禁 `EventSource`）。

### 代码规范

- 后端：全异步；类型注解全覆盖；统一响应 `{code, message, data}`；
  分页 `{list, total, page, page_size}`；配置走 `settings.py`；常量进配置；日志用 logging。
- 前端：`<script setup lang="ts">` + strict；类型集中 `src/types/`；
  状态用 Pinia；请求走 `src/api/` 封装，不裸 `axios`。

## 引用文件

| 文件 | 作用 |
|---|---|
| `vibecoding_doc/开发过程总纲.md` | 元流程与门禁、spec 命名与生命周期 |
| `vibecoding_doc/核心数据字典.md` | 表/对象/类/核心字段的统一字典（spec 字段唯一引用源） |
| `vibecoding_doc/模块概要设计/README.md` | 模块级设计索引 + 统一模板；含 9 后端 + 6 前端模块文档（spec 的结构唯一引用源） |
| `vibecoding_doc/spec-templates/前端页面spec模板.md` | 前端页面 spec 模板 |
| `vibecoding_doc/spec-templates/后端模块spec模板.md` | 后端模块 spec 模板 |
