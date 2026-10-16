---
name: pencil-draw
description: |
  用 Pencil（pen.dev）MCP 画或改前端页面原型图。当用户要「画原型图」「出设计稿」
  「用 pencil 画 XX 页面」「把这个页面改成 XX 样式」「照着 PRD 出前端原型」时触发。
  核心动作：先读 pencil 自带 skill 与项目设计令牌，再定公共组件，最后逐屏 Insert 并
  每屏 TakeScreenshot 自检。附带 pencil execute 脚本的语法坑清单，避免反复试错。
---

# 画原型图（pencil-draw）

## 定位

把「页面需求」变成 `.pen` 画布上可直接评审的高保真原型。本 skill 只解决**怎么画**；
画什么来自 `vibecoding_doc/PRD.md` §4.2（前端模块）与 §9（验收场景）。

配套：`snippets.md`（本目录）——可复制粘贴的通用图元代码（表格卡片、KPI 卡、柱状图、
环形图、状态胶囊、导航高亮）。**动手前先看它，不要从零写。**

## 第 0 步：前置检查（不做这步会白排查一轮）

确认当前会话的工具表里有 `mcp__pencil__*`。

- **没有** → 不要怀疑安装，也不要重装。直接让用户 `Ctrl+Shift+P` → `Developer: Reload Window`。
  pencil MCP 的 Windows 命名管道是**全局固定名** `\\.\pipe\pencil-visual_studio_code`，
  同时开多个 VSCode 窗口会互相抢；工具表在会话启动时就定死，中途连上也不补入。
- `.pen` 文件是**加密**的：只能用 MCP 工具读写，**禁止**用 Read / Grep 打开。

## 第 1 步：读 pencil 自带文档

```
read_skill()            → SKILL.md，execute 的完整语法
read_skill({path:"..."}) → 需要时再读子文档
get_app_state()         → 当前打开的 .pen、选中节点
```

`.pen` 的 schema 与 CSS/HTML **完全不同**：只有 flexbox，没有绝对定位流、没有 grid、
没有 CSS 选择器。先读文档再动手。

## 第 2 步：定设计令牌（只做一次）

画布是空的就先 `SetVariables` 把整套调色板与字体写进去，之后一律用 `$token` 引用，
**不要**在节点上写死十六进制。本项目已定的令牌见下方「设计令牌」。

## 第 3 步：抽公共组件

跨屏复用的一律做成**组件 + ref 实例**（如左侧导航 `NavSidebar`），不要每屏重画。
每屏实例化后用 `descendants` 覆盖高亮项，实现「当前页高亮」：

```js
function navOv(i){return {[navItemIds[i]]:{fill:"$brand"},[navLabelIds[i]]:{fill:"#FFFFFF"},[navIconIds[i]]:{fill:"#FFFFFF"}}}
Insert(screenId,{type:"ref",ref:sidebarCmp,name:"NavSidebar",width:240,height:"fill_container",descendants:navOv(1)})
```

> `navOv` 这类辅助函数**必须写在本条 snippet 里**——函数不跨 `execute` 调用保留。

## 第 4 步：逐屏生成 + 每屏自检

- 建屏时 `placeholder:true`（防止画布重排时误触），全部完成后 `Update(id,{placeholder:false})`。
- **每屏画完立刻 `TakeScreenshot([screenId])`**，看有没有塌陷、溢出、文字截断。
  不要攒到最后一起看——错了要整屏重画。
- 屏幕排布用固定网格，避免互相压盖：

  |  | x=0 | x=1520 | x=3040 |
  |---|---|---|---|
  | **y=1000** | 问答工作台 | 知识维护与导入 | 知识沉淀与运营 |
  | **y=2000** | 运营看板 | 组织架构与系统配置 | 登录页 |

  间距：横向 1520 = 1440 + 80；纵向 1000 = 900 + 100。屏幕统一 1440×900。

## 第 5 步：对齐 PRD 的可见约束

原型要让评审者**一眼看到**关键业务约束，而不只是"长得像后台"。本项目必须画出：

- 权限范围列（globe 图标=全局 / shield 图标=限定部门），体现四维权限；
- 部门树的下钻与「授权部门自动覆盖其子孙部门」提示；
- 问答页的**引用溯源**与未授权内容的「只报数量、不露标题」表现；
- 治理页 FAQ 的「发布后写缓存、不再调生成模型」说明。

## 设计令牌（本项目，直接照抄）

```
SetVariables({
  brand:"#2F6FED", "brand-hover":"#5B8DEF", "brand-soft":"#EAF1FE", "brand-softer":"#F4F8FF",
  "bg-page":"#F5F7FA", "bg-card":"#FFFFFF", "bg-subtle":"#FAFBFC",
  sidebar:"#1D2A3A", "sidebar-hover":"#28374A", "sidebar-text":"#93A3B8", "sidebar-active":"#FFFFFF",
  "text-primary":"#1F2D3D", "text-secondary":"#5E6D82", "text-muted":"#93A0B0", "text-placeholder":"#B4BECC",
  border:"#E4E8EE", "border-soft":"#EEF1F5",
  success:"#10B981", "success-soft":"#E7F7F1",
  warning:"#F59E0B", "warning-soft":"#FEF3E2",
  danger:"#EF4444", "danger-soft":"#FDECEC",
  font:"Noto Sans SC",
})
```

字号梯度：页标题 15/600 · 卡片标题 13/600 · 正文 12.5 · 次要 11.5 · 表头 11.5/600 · 徽标 11。
圆角：卡片 10 · 输入框与按钮 8 · 胶囊 5 · 头像/圆点 全圆。

## 语法坑速查（pencil 的 JS 不是标准 JS）

### 作用域

| 现象 | 规则 |
|---|---|
| `ReferenceError: 'navOv' is not defined` | **函数不跨 execute 调用保留**，每次重新定义 |
| `ReferenceError: 'sContent' is not defined` | `const` 变量跨调用保留**不稳定**（`const kBody` 能留，`const sContent` 留不下）。别纠结，直接用工具返回的**节点 id 字符串** |

### 语法

| 现象 | 原因与写法 |
|---|---|
| `SyntaxError: unexpected token in expression: ''` | ① 箭头函数的**参数解构**（`arr.forEach(([a,b],i)=>{})`）不支持 → 改 `for(let i=0;i<arr.length;i=i+1)` 索引循环；② 也可能只是**漏了一个 `}`** |
| 报错位置指向最后一行 | 解析器会把块级错误报在 snippet 末尾，**先数括号再看别的** |
| `Invalid properties: /italic unexpected property` | text 没有 `italic`，只有 `fontStyle` |

### 属性与布局

- 父 `layout:"fit_content"` + 子 `width:"fill_container"` = **循环依赖**，必须给子节点显式宽度。
- 柱状图不要用绝对定位：父 `layout:"horizontal"` + 子列 `height:"fill_container"` +
  `justifyContent:"end"`，柱高写死像素。
- 透明填充用 `#00000000`（下划线场景常用）。
- icon 优先用**稳定**的 lucide 名（`layout-dashboard` / `info` / `file-text` / `shield-check`）。
  `bar-chart-3`、`circle-help`、`file-type-2` 这类新名会报错。
- 描边只画一边：`strokeWidth:{bottom:1}`（同理 `top`/`left`/`right`）。

### 改错流程

失败时工具给 `editId`：

1. 优先用 `edits` 打补丁（`find` 必须匹配**已打过补丁后**的文本）；
2. `find` 匹配不上时不要死磕——**把整段改好的 snippet 重新塞进 `input`** 是官方认可的退路；
3. 每次失败都会整块回滚，可以安全重试。

### Get 的用法

```js
Get((n,c)=>{if(c.depth===1)t.push(n.name);return undefined})   // ✅ 带 visitor
Get(document,{depth:1})                                        // ❌ 会被拒绝
```

## 引用文件

| 文件 | 作用 |
|---|---|
| `.claude/skills/pencil-draw/snippets.md` | 通用图元代码：导航高亮、表格卡片、KPI 卡、柱状图、环形图、胶囊 |
| `vibecoding_doc/PRD.md` §4.2 / §9 | 前端模块清单与验收场景（画什么的来源） |
| `vibecoding_doc/概要设计总纲.md` §4.2 | 页面与功能的对应表 |
