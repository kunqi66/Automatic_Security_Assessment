# 自动化安全评估系统 · 前端

React 18 + TypeScript + Vite + Ant Design 5 + Zustand + TanStack Query。

## 启动

```bash
npm install
npm run dev        # http://localhost:5173
```

**默认跑在 Mock 模式**（`.env.development` 里 `VITE_USE_MOCK=true`），不需要后端即可浏览全部页面。
演示账号：`admin` / `admin123`。

后端就绪后，把 `.env.development` 改成 `VITE_USE_MOCK=false` 即可切到真实接口 ——
**业务代码零改动**，因为 Mock 是挂在 axios adapter 上的，不是散落在各处的 `if`。

```bash
npm run build      # 类型检查 + 生产构建
npm run lint
```

## 目录结构

```
src/
├── api/
│   ├── types.ts          # 与后端 DTO 一一对应的类型
│   ├── endpoints.ts      # 全部接口调用（唯一与后端耦合的地方）
│   ├── client.ts         # axios 实例 + JWT 注入 + 401 处理
│   ├── mock.ts           # Mock 适配器：按路由表返回假数据
│   ├── fixtures.ts       # 假数据本体（接后端后可整体删除）
│   └── useLogStream.ts   # 日志流（fetch 版 SSE，支持 Last-Event-ID 重放）
├── modules/              # 需求 2.5.5 的五个功能模块
│   ├── dashboard/        # 概览大盘
│   ├── pipeline/         # 流水线监控（阶段 / 日志 / 资源指标）
│   ├── vuln/             # 漏洞视窗（污点步进 / 补丁 Diff / 四道校验）
│   ├── topology/         # 攻击链拓扑图谱（React Flow + dagre）
│   └── report/           # 报告预览与导出
├── pages/                # 路由页面：Dashboard / Workbench / ReportCenter / SandboxConfig / Login
├── components/
│   ├── AppLayout.tsx     # 侧边栏 + 顶栏布局
│   └── tags.tsx          # 全站状态标签（颜色 + 文字 + 图标三重编码）
├── store/
│   ├── auth.ts           # 登录态
│   └── vulnSelection.ts  # ★ 漏洞视窗 ↔ 拓扑图谱的联动契约
└── constants.ts          # 阶段名、节点类型等展示元数据
```

## 几个值得注意的设计点

**Mock 用 axios adapter 而非条件分支。** `endpoints.ts` 里的调用与真实后端完全一致，
切换只靠一个环境变量。未命中的路由一律 404，避免「以为通了其实没通」。

**日志流不用 `EventSource`。** `EventSource` 无法设置请求头，只能把 JWT 放进 URL 查询串，
而查询串会被 nginx access log、浏览器历史、Referer 记录 —— 等于泄露凭证。
这里用 `fetch` + `ReadableStream` 手动解析 SSE，从而能带 `Authorization` 头，
断线重连时回传 `Last-Event-ID` 让后端从 Redis Stream 对应位置重放。

**状态标签一律三重编码。** 颜色 + 文字 + 图标，不依赖颜色单独表意 ——
色盲用户、黑白打印、截图转灰度都要能读出状态。

**`vulnSelection` store 是两个模块之间的唯一契约。** 漏洞表格与拓扑图谱要双向联动，
但它们互相不 import 对方组件，只通过这个 store 通信。

**UI 上区分「已验证」与「推演」。** 攻击链节点分 `verified`（沙箱内实际执行过）与
`inferred`（规则引擎推演、并未执行）两态，实线/虚线 + 图例 + 顶部统计明确标注，
避免用户把推演结果误读成实测结论。

**补丁区分三种来源。** `llm`（已过四道校验）、`template`（模型不可用时的降级，
结论不变只有措辞变）、`validate_failed`（**没通过第 ④ 道校验，即它并没有真正修好漏洞**，
必须红字告警）。三者绝不能显示成一个样子。
