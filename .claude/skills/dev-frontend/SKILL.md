---
name: dev-frontend
description: |
  把「模块概要设计 fe-0X + pencil 原型」变成 `frontend/` 下的 Vue 3 代码。
  当用户要「生成前端代码」「照原型实现登录页/知识管理页/...」「写这个页面」
  「按 fe-0X 开发前端」时触发。
  核心动作：先读 pencil 原型与 fe-0X 设计 → 三份输入对账 → 出前端 spec 等评审 →
  照 spec 生成代码 → 与原型截图比对自检。**不允许跳过 spec 直接出代码。**
---

# 生成前端代码（dev-frontend）

## 定位

把**设计**变成 `frontend/` 下的代码。本 skill 只解决「怎么把设计落成代码」。

| skill | 干什么 | 产物 |
|---|---|---|
| `pencil-draw` | 需求 → 原型 | `.pen` 画布上的屏 |
| `dev-spec` | 需求 → spec（前后端通用） | `vibecoding_doc/specs/*.md` |
| **`dev-frontend`** | **spec + 原型 → 代码** | `frontend/src/**` |

**与 dev-spec 的关系**：本 skill 是 dev-spec **第 4 步（照 spec 写代码）在前端的落地**，
外加 dev-spec 没写的部分——**原型这一路输入怎么进流程**。它**不替代** dev-spec：
spec 仍然要先出、先评审。**不允许跳过 spec 直接生成代码。**

> pen 官方的代码生成规范（`read_skill({path:"guide/code.md"})`）里有一条
> 「生成代码后不要再写改动说明文档」。这与本项目的 spec 流程**不冲突**：spec 是
> **事前**的治理产物、要评审、存在 `vibecoding_doc/specs/`；而那条规范禁止的是**事后**另写一份
> "我改了什么.md"。两者别混。

---

## 第 0 步：前置检查

1. **工具表里有没有 `mcp__pencil__*`？** 没有 → 让用户 `Ctrl+Shift+P` → `Developer: Reload Window`。
   不要怀疑安装。理由同 `pencil-draw`（全局固定命名管道，多窗口互抢，工具表会话启动时定死）。
2. **读 pen 官方的代码生成规范**：`read_skill({path:"guide/code.md"})`。这是权威方法，
   下面第 2 步的抽取命令都出自它。
3. `.pen` 文件**加密**，只能用 MCP 工具读写，**禁止** Read / Grep。
4. **确认 `frontend/` 现状**：脚手架**已建好**（2026-10-14 登录页那轮，见第 5 步）。
   后续页面**直接复用**，不要重建，更不要各写一份跨页基础设施。

---

## 第 1 步：备齐三份输入

| # | 输入 | 路径 | 提供什么 |
|---|---|---|---|
| 1 | **模块概要设计** | `vibecoding_doc/模块概要设计/fe-0X-*.md` | 结构：§2 分层落点（文件清单）、§4 内部结构（store/props/流程）、§6 错误码分流、§10 待确认 |
| 2 | **pencil 原型** | `.pen` 画布，屏幕节点 id 见 `模块概要设计/README.md` §2.2 | 视觉与文案：布局、尺寸、间距、字号、配色、**静态文案原文** |
| 3 | **数据字典** | `vibecoding_doc/核心数据字典.md` §5.7 错误码 / §8 前端类型映射 | 类型名与错误码要与后端 `schemas/` 对齐 |

后端接口以 **PRD §8** 为准。注意 §8.2/§8.3/§8.4 是**指向代码文件**而非列出端点，
要打开 `backend/api/*.py` 数实际端点，别只看 PRD 表格。

---

## 第 2 步：从 pencil 抽原型结构

```js
Print(Get("<屏幕节点id>", {depth: 3}))          // 先看骨架，确认层级
Print(Get("<子节点id>",   {depth: 5}))          // 再看细节：文案、尺寸、图标名、letterSpacing
Print(Get("<节点id>", {includePathGeometry:true}))  // SVG：取精确 geometry，禁止手描近似
TakeScreenshot(["<屏幕节点id>"])                 // 存视觉基准，第 7 步比对用
```

**抽的时候要抓这四类信息**：

1. **节点名**。画布里的节点名是英文的（`BrandPanel` / `LoginCard` / `Field/用户名`），
   **直接映射为组件名**——登录页原型的 `BrandPanel` 正好就是 fe-01 §2 里的 `BrandPanel.vue`。
   名字对得上就照用，对不上以 fe-01 §2 的文件清单为准。
2. **令牌引用**。`fill:"$brand"` 是**变量引用，不是颜色值**。生成代码时映射成 CSS 变量，
   **禁止**写死十六进制（见下方映射表）。
3. **文案原文**。`content` 里的中文是最终文案，要一字不差地抄进代码，不要改写。
4. **图标名**。`icon:"shield-check"` + `library:"lucide"` —— 图标名要与项目实际用的图标方案对齐。

---

## 第 3 步：对账 —— 本 skill 的核心，别跳

**原型、设计文档、后端接口三者对不上是常态。** 逐屏逐项比对，处理原则：

**以设计为准，不以原型为准。** 原型是视觉稿，不是需求。

| 情形 | 处理 |
|---|---|
| 原型**有**，设计**明确说「不做」** | **不实现**。在 spec §9 记一条「原型有 X，fe-0X §1.2 明确不做，已忽略」 |
| 原型**有**，但**后端接口不存在** | 不实现，或按 fe-0X 给的降级方案做。标 ❌ 并在 spec §9 记明 |
| 设计**有**，原型**没有** | 按设计实现，视觉用原型里已有的图元拼（同字号同间距），spec §9 记一条 |
| 两者**都没有** | **不发明**。进 spec §9 待确认 |

> 登录页实测撞上三处：图形验证码、忘记密码、记住我。逐条处置见
> [`登录页实例.md`](登录页实例.md) —— **动手前先读它**，三处的处理方式是本 skill 的样板。

**为什么不能照抄原型**：`pencil-draw` 画原型时为了「让评审者一眼看到业务约束」，
会刻意画出还没定论的东西（比如验证码框）。原型里出现 ≠ 后端有这个接口。

---

## 第 4 步：先出 spec，评审通过再动代码

用 `vibecoding_doc/spec-templates/前端页面spec模板.md`，落到
`vibecoding_doc/specs/{P1|P2|P3}-{NN}-fe-{名称}.md`（命名见开发过程总纲 §2）。

**该目录不存在就创建**——spec 与 PRD、概要设计、数据字典同属设计资产，
统一收在 `vibecoding_doc/` 下，**不要写到项目根的 `specs/`**（那里已经没有了）。

**模板字段直接从 fe-0X 抄，不要重新发明**：

| spec 模板字段 | 从 fe-0X 的哪节抄 |
|---|---|
| §2 数据流（store / API / 轮询·SSE） | fe-0X §4.1（store 的 state/getters/actions）+ §6（错误码） |
| §3 组件树与布局 | fe-0X §2（分层落点）+ §4.2（props/emits）+ **第 2 步抽出的原型结构** |
| §4 交互与状态 | fe-0X §4.3（关键交互流程） |
| §5 接口映射 | fe-0X §3（对外接口表） |
| §7 安全 | fe-0X §7（硬约束落地） |
| §9 待确认 | fe-0X §10 + **第 3 步对账发现的全部冲突** |

**本步不得写任何代码。** 出完 spec 停下来给用户评审。

---

## 第 5 步：脚手架（**已完成**，后续页面跳过）

> 2026-10-14 生成登录页时已建好。**后面的页面不要重做这一步**——跨页基础设施只有一份，
> 各写一份必然分叉。此节留作记录与重建参考。

```
frontend/
├── index.html
├── package.json        # vue / vue-router / pinia / element-plus / axios / lucide-vue-next / dompurify / marked
├── tsconfig.json       # strict: true（CLAUDE.md 硬要求）
├── vite.config.ts      # Element Plus 按需引入（unplugin-vue-components + unplugin-auto-import）
├── .env.example        # 只有 VITE_API_BASE_URL，非敏感项
└── src/
    ├── main.ts
    ├── App.vue
    ├── styles/tokens.css   # 设计令牌 + Element Plus 主题接入（两者同在这一个文件）
    ├── styles/index.css    # 全局 reset
    ├── api/          http.ts（注入 Bearer、401 单飞刷新、统一拆包）/ auth.ts
    ├── stores/       Pinia，一个域一个文件
    ├── types/        与后端 schemas/ 一一对应
    ├── router/       index.ts + guards.ts
    ├── directives/   permission.ts（v-permission）
    ├── utils/        token.ts（token 唯一读写点）/ markdown.ts（DOMPurify 唯一出口）
    ├── constants/    brand.ts
    ├── components/   跨页面复用组件
    └── views/        一页一个目录，页面私有组件放 views/<页>/components/
```

**这几样跨页基础设施已经在了**：`styles/tokens.css`、`api/http.ts`、`stores/auth.ts`、
`router/guards.ts`，外加 `utils/token.ts`、`directives/permission.ts`。
登录页承载了它们的首次实现，**后面每个页面直接复用**。需要扩展时**加新文件**，
不要改这几样的对外契约（改了要回头验登录页）。

**按需引入**（CLAUDE.md 要求）：Element Plus 组件用 `unplugin-vue-components` 自动引入，
不要在 `main.ts` 里 `app.use(ElementPlus)` 全量注册。

**已知缺口**：`echarts` 尚未安装（fe-05 运营看板要用）。到那一步再 `npm i echarts`，
不要提前装。

---

## 第 6 步：生成代码

**分层纪律**（CLAUDE.md，逐个核对）：

- `<script setup lang="ts">` + Composition API，**不用 Options API**。
- **组件里不直接 `axios`**。调用链单向：组件 → store/composable → `src/api/*.ts` → `http.ts`。
- 状态用 Pinia，**不在组件间用 event bus**。
- 类型集中 `src/types/`，与后端 `schemas/` 同名对应。
- 组件不直接发请求：表单组件只 `emit`，由页面组件编排（见 fe-01 §2 的「为什么这么拆」）。

**安全红线**（CLAUDE.md，前端侧相关四条）：

| 红线 | 前端怎么落 |
|---|---|
| 1 身份从 JWT 解析 | 前端**不构造也不传** `user_context`/`uploaded_by` 之类身份字段。身份只来自 `/me` |
| 2 LLM 输出与知识正文过 DOMPurify | 所有 `v-html` 必须紧跟 `renderSafe()`（`src/utils/markdown.ts` 是**唯一出口**，禁止在别处直接 `import DOMPurify`） |
| 6 密钥走环境变量 | 前端只用 `import.meta.env.VITE_*`，且只放 baseURL 一类非敏感项 |
| 7 写接口独立校验权限 | `v-permission` 只做**显隐**，不是安全边界。代码注释里要写明「后端仍独立校验」 |

**其它**：token 不得写入日志、埋点、URL、错误上报；动态文本一律插值，不塞进 `v-html`。

---

## 第 7 步：自检

**先跑机器能判的**（不用等后端，当场就能核完）：

1. `npx vite build` —— 生成 unplugin 的 d.ts，同时验证打包能不能过
2. `npx vue-tsc --noEmit` —— **是 `vue-tsc` 不是 `tsc`**。`tsc` 不认识 `.vue`，会假装通过
3. 静态 grep 自检：硬编码色值、裸 `axios`、裸 `localStorage`、原型假数据写死

> ⚠️ **多页并行时第 1 条要禁（会互相覆盖 `dist/`、编译到别人在建的文件），
> 但第 2 条 `vue-tsc --noEmit` 不写产物，必须照跑**——详见下文
> 「多页批量生成时」与「禁跑 `vite build` 时怎么自查」。

**再跑需要环境与人眼的**：

4. `TakeScreenshot(["<屏幕节点id>"])` 拿原型基准，与自己渲染的页面对比：
   布局有没有塌陷、文案有没有漏字、字号间距对不对。
5. `npm run dev` 起来，逐个走 fe-0X §4.3 的交互流程。
6. 逐条核对 spec §8 的验收标准，**在 spec 里勾选回填**。
   **要把「已核实」与「待后端」分开写**——后端没就绪的条目显式标注「待 be-xx 落地后才可验证」，
   不要含糊留空，留空看起来像没做。
7. 全部通过后，spec 头部状态改「✅ 已实现」+ 日期。

---

## 设计令牌映射（本项目，直接照抄）

pencil 画布里的 `$token` 与本项目 CSS 变量**一一对应**，命名机械可验：
`$bg-card` → `--kb-bg-card`。

```css
/* src/styles/tokens.css */
:root {
  --kb-brand: #2F6FED;        --kb-brand-hover: #5B8DEF;
  --kb-brand-soft: #EAF1FE;   --kb-brand-softer: #F4F8FF;
  --kb-bg-page: #F5F7FA;      --kb-bg-card: #FFFFFF;      --kb-bg-subtle: #FAFBFC;
  --kb-sidebar: #1D2A3A;      --kb-sidebar-hover: #28374A;
  --kb-sidebar-text: #93A3B8; --kb-sidebar-active: #FFFFFF;
  --kb-text-primary: #1F2D3D; --kb-text-secondary: #5E6D82;
  --kb-text-muted: #93A0B0;   --kb-text-placeholder: #B4BECC;
  --kb-border: #E4E8EE;       --kb-border-soft: #EEF1F5;
  --kb-success: #10B981;      --kb-success-soft: #E7F7F1;
  --kb-warning: #F59E0B;      --kb-warning-soft: #FEF3E2;
  --kb-danger: #EF4444;       --kb-danger-soft: #FDECEC;
  --kb-font: "Noto Sans SC", system-ui, sans-serif;
}
```

**Element Plus 的主题变量必须一并接到设计令牌**，否则页面上会出现两套蓝
（自己的 `var(--kb-brand)` 和 Element 默认的 `#409EFF`）。这组覆盖直接写在
`tokens.css` 末尾即可，不必单开文件：

```css
/* tokens.css 末尾 —— 让 Element Plus 跟随品牌色 */
:root {
  --el-color-primary: var(--kb-brand);
  --el-color-primary-light-3: var(--kb-brand-hover);
  --el-color-primary-light-9: var(--kb-brand-soft);
  --el-text-color-primary: var(--kb-text-primary);
  --el-text-color-regular: var(--kb-text-secondary);
  --el-border-color: var(--kb-border);
  --el-font-family: var(--kb-font);
}
```

**字号与圆角**：**以原型实际给的值为准，不要套全局梯度**。
后台密集页（知识管理/看板）用 页标题 15/600 · 卡片标题 13/600 · 正文 12.5 · 表头 11.5 · 徽标 11；
但**登录页是整页主视觉，量级不同**（`Welcome` 25/600、`Tagline` 15、`InputText` 13.5）。
套错梯度会让主视觉变小。

圆角：卡片 10 · 输入框与按钮 8 · 胶囊 5。图标用 lucide。

---

## 踩过的坑（本项目实测）

> 全部来自 2026-10-14 生成登录页那轮。**动手前先扫一眼**，能省掉大半返工。

### 工具链与依赖

- **`typescript` 必须锁 5.x**。npm 默认装到 7.x（原生新编译器），其包结构里没有 `lib/tsc`，
  vue-tsc 3.x 启动即抛 `ERR_PACKAGE_PATH_NOT_EXPORTED`。而 vue-tsc 的 peer 声明写的是
  `>=5.0.0`，**拦不住**这个组合，npm 给不出任何警告。→ `npm i -D typescript@5`。
- **不要手写版本范围去猜**。先写一个只有 `name` / `scripts` 的最小 `package.json`，
  再 `npm install <pkgs>` 让 npm 自己解析。实测装出来的是 vue-router **5.x**、pinia **4.x**、
  lucide-vue-next **1.0**、vite **8.x**——与凭印象写的差一个大版本，硬写范围会直接装不上。
- **装完立刻核对实际版本**，别信假设：
  `node -e "console.log(require('./node_modules/vue-router/package.json').version)"`
- **`vite preview` 不要放进 `( … & )` 子壳**——Bash 调用一结束就被回收，
  探测得到 `HTTP 000`，看起来像端口没起，其实早起来了。用后台任务起，再单独探。

### Vue SFC 的类型检查

- **`tsc --noEmit` 不认识 `.vue`**，会静默放过所有模板错误。必须用 **`vue-tsc --noEmit`**。
- Element Plus 按需引入靠 `unplugin-vue-components`，它生成的
  `src/types/{components,auto-imports}.d.ts` **要先跑一次 `npx vite build` 才存在**，
  否则 vue-tsc 报「不认识 `<el-button>`」。这两个文件是构建产出，已进 `.gitignore`。
- **正确顺序**：`npx vite build` → `npx vue-tsc --noEmit`。反过来第一次必然失败。

### Element Plus 按需引入的两个坑

- **`ElMessage` 这类函数式 API 不会被 `unplugin-vue-components` 自动引入**（它只管模板标签）。
  要显式 `import { ElMessage } from 'element-plus'`，**并补一行**
  `import 'element-plus/es/components/message/style/css'`——否则弹出来的提示没有样式。
- **主题变量必须接到设计令牌**（见上方映射表），否则同一个页面上会出现两种蓝。

### 图标

- 用 **`lucide-vue-next` + 显式具名导入**，不用 `unplugin-icons` 的 `i-lucide-*` 自动解析：
  后者图标名拼错**只在运行时渲染出一个空白方块**、不报错；前者编译期就报。
- 原型里图标是**字符串**（`icon:"shield-check"`）。显式建映射表
  （`const ICONS = { 'shield-check': ShieldCheck } as const`）配合 `:is="ICONS[f.icon]"`，
  **不要**用 `` :is="`i-lucide-${f.icon}`" `` 拼字符串——拼错了 TS 也拦不住。

### 从原型抄像素时

- **原型画的是「填好状态」，不是空状态**。输入框里的 `chenjing`、密码框的 `••••••••`
  是示意假数据，**既不是 placeholder 也不是默认值**。照抄等于把演示账号写死进代码。
- 密码框上那个 `letterSpacing:2` 是为了把圆点拉开画得好看，**不要**抄到真输入框。
- **`el-form-item` 默认带 `margin-bottom: 18px`**。用 flex `gap` 排版时**必须清零**，
  否则实际间距 = gap + 18px，对着原型调半天都对不上。
- **确认「原型里到底有没有这个东西」时，全画布检索要用带副作用的 visitor**。
  `Print(Get("root", {depth:1}))` 会因「整文档读取」被拒（报错里带 `editId`）；
  返回布尔数组的 visitor **无信息量**（只知道有没有，不知道在哪）。
  可行写法：把命中节点 push 进一个外部数组，再 `Print` 那个数组。
  只有这样才拿得到「`mKWiM` 子树里根本没有 drawer/dialog/modal」这种**可下结论**的否定证据——
  而「原型没画」正是最需要坐实的一类结论。

### 流程纪律

- **spec 与实现分叉了要回改 spec，不要放着**。登录页出过一次：spec 写「提交后立即清空密码」，
  实现时改成「不清」——失败时清空会逼用户重打密码，代价大于收益。当场回改 spec 并注明原因；
  否则下次有人照 spec 复核，会以为是实现漏了。
- **验收跑不通时补最小占位**。登录页要跳 `/chat`，但那是 fe-03 的地盘；没有
  `ChatView.vue` 占位，「登录 → 落 /chat」这条验收根本无从验起。
  占位文件里必须显著标注「**不是 fe-0X 的实现**」，免得被当成正式代码。
- **静态能验的先验掉，别都堆到「等后端」**。登录页 12 条验收里 6 条纯静态可核
  （tsc、无硬编码色、无验证码、无裸 axios…），当场核完再交付。

### 多页批量生成时（2026-10-14，5 页并行那轮）

- **先找公共件，再逐页生成**。动手前先 `get_app_state` 看画布有哪些**顶层节点与复用件**——
  已登录页面的侧栏在原型里是**复用件**（fe-02 里写作 `{"type":"ref","ref":"S5mE0Z"}`），
  这是「存在共享外壳」的直接证据。发现 `ref` 就**必须先建布局层**，
  否则 5 个页面会各画一套侧栏，之后改一处要改五处。
- 🔴 **并行生成时禁跑 `vite build`，但 `vue-tsc --noEmit` 要「允许且必须」跑**。
  本 skill 上一版把两者混为一谈写成「都不许跑」，**这是错的，代价是白多一轮往返**：
  - 禁的是 `vite build`——它会编译到**别人正在写**的文件、得到一堆与自己无关的报错、
    还会互相覆盖 `dist/`。
  - **`vue-tsc --noEmit` 不写任何产物**，多人并发跑也互不干扰，**必须允许**。
    否则像 `DefaultRow` 这类**只在类型检查层暴露**的错误，只能等主控统一构建时才发现，
    而主控只能把错误**发回**给各页——凭空多一轮往返（本轮 20 条错误就是这么绕了一圈）。
  正确顺序：各页自查（**含 `vue-tsc --noEmit`，过滤出自己的文件**）→ 全部写完后
  **由主控再跑一次** `vite build` + `vue-tsc --noEmit` 做最终确认 → 把属于各页的报错发回修。
- **同理不许并行 `npm install`**——同一份 `node_modules` 会撞车。
  缺的包由**主控先一次性装好**再派活（本轮就是先装 `echarts` 才派的 fe-05）。
- **文件归属要显式划到人**。同一目录下有多个页面在写时（如 `views/kb/` 同时有 fe-02 与 fe-06），
  派活时必须写明「哪些文件是你的、哪些绝对不要碰」。
  共享的类型文件（如 `types/org.ts`）只能规定「**只可追加，不可改写**」。
- 🔴 **「只可追加」仍有竞态——`Edit` 是读-改-写**。两个 agent 同时往同一份
  `styles/tokens.css` / `types/org.ts` 追加内容时，**后写的会覆盖先写的**，而且两边都以为自己成功了。
  本轮 fe-02 与 fe-03 都往 `tokens.css` 追加了令牌、fe-04 往 `types/org.ts` 追加了类型，
  侥幸都留下了，但这是**运气不是设计**。
  稳妥做法二选一：① **主控先把所有共享文件的新增项一次性加好**再派活；
  ② 规定并行期间**谁都不许动共享文件**，各页在汇报里列「我需要 X 令牌 / Y 类型」，由主控统一落。
  **合并后必须 grep 复核**每一条声称追加成功的内容是否真在文件里。

### 🔴 页与页之间的「缝」是并行生成最危险的盲区

**没有任何一个 agent 对它负责**——每个 agent 只看得到自己那一页，而跨页跳转天然横跨两页。
本轮 5 页并行，**4 处跳转全部落在空处**，且两边单看都完全自洽、任何单页评审都发现不了：

| 发出方 | 参数 | 接收方 |
|---|---|---|
| fe-06 转建 `GovernanceView` | `?openImport=1` | fe-02 `DocumentCenterView` **从不读 query** |
| fe-05 热门问题下钻 | `?q=` | fe-03 `ChatView` **只 import 了 `useRouter`** |
| fe-05 知识点下钻 | `?document_id=` | 同上 fe-02 |
| fe-03 引用跳转 | `?highlight=` | 同上 fe-02 |

**最坏的性质是它不报错**：跳转成功、页面正常渲染、控制台安静,
只是「什么都没填充」。类型检查抓不到（`query` 是松散的 string 字典），
构建抓不到，只有真在浏览器里点一下才会发现——而本项目恰恰禁跑构建、没有浏览器。

处置：

1. **派活时就把「跨页参数表」写进每份 spec**（谁发、参数名、谁收、收到后做什么）。
   本轮是各页自己在 spec §9 里猜,于是同一个概念被 fe-03 叫 `highlight`、被 fe-05 叫 `document_id`。
   **一个概念只准有一个参数名**,同义别名只作为过渡。
2. **收尾时做一次全局对账**——这是主控的活,单页 agent 做不了：
   ```bash
   # 发出方：所有带 query 的跳转
   grep -rnE "router\.(push|replace)\(\{" --include=*.vue -A6 | grep "query:"
   # 接收方：所有读 query 的地方
   grep -rn "useRoute\|route\.query" --include=*.vue .
   # 两边一对照，落空的一目了然
   ```
   ⚠️ 上面第二条**别写成 `grep -q "useRoute"` 来判断**——
   `useRouter` **包含** `useRoute` 这个子串,会假阳性（本轮我就被它骗过一次,
   误判 `ChatView`「有 useRoute」）。用 `\buseRoute\b` 或 `useRoute(`。
3. 🔴 **接收端绝不允许「静默 no-op」**。参数指向的目标找不到时（分页接口 + 无「按 id 取单篇」接口,
   目标很可能不在当前页），必须给一句明确提示说明为何找不到,
   **不许装作没事发生**。
4. **消费完的 query 要 `router.replace({ query: {} })` 抹掉**。
   它是一次性动作指令,留在 URL 上会让刷新/再次点击**重复触发**。

### 类型口径别凭直觉

- **ID 是字符串，不是数字**。`sys_department.id` / `sys_user.id` / `sys_role.id` 在
  `核心数据字典.md` §2.1 里都是 **VARCHAR**。上一轮登录页顺手写成 `depts: number[]`，是错的。
  **抄类型前先回字典核一眼主键类型。**
- **原型展示得出来 ≠ 接口拿得到**。侧栏底部原型写着「李财务 / 财务部 · 成本组」，
  但 `/api/auth/me` 的 `UserDetail` 只有 `real_name` / `depts`(id) / `roles`，
  **没有部门名字段**。这种「原型有、契约没有」的缺口要写进 spec §9，
  **不要**为了还原版式去编一个字段。

### 路由

- **父路由已是 `path:'/'` 时，不要再写一个顶层 `path:'/'` 做重定向**——路径重复，vue-router 判定冲突。
  正确做法：在子路由数组里放 `{ path: '', redirect: '/chat' }`，父路由本身才能真正匹配到 `/`。
- 侧栏高亮靠 `router-link-active`，因此**导航项的 `name` 必须与路由注册的 `name` 逐字一致**。
  建议把导航配置（label + icon + 路由名）收进 `src/constants/nav.ts` 一处，
  **不要**在侧栏组件里内联一份、路由表里再写一份。

### Element Plus 的具体坑

- **`el-skeleton` 的 `loading` 默认是 `false`**——不传 `:loading="true"` 时它渲染**默认插槽**（空的），
  `#template` 根本不渲染，骨架屏整个消失。症状是「加载态一片空白」，而不报错。必须显式传。
- **`v-permission` 的挂载点要对**。历史实现用 `el.parentNode?.removeChild(el)`，挂在
  **根节点不是单一元素**的组件上（典型是 `el-popconfirm`，根是 Tooltip 的 trigger + popper）
  落点不可预期；且元素被摘出 DOM 后 Vue 的 patch 仍以为它在树里。
  现已改为判 `display` + `mounted`/`updated` 双钩子（`src/directives/permission.ts`）。
  **仍建议挂在 `el-button` 或原生元素上**，别挂在复合组件上。
- **`el-form-item` 默认 `margin-bottom: 18px`**（前文已记）。若自绘弹层不想跟它纠缠，
  就干脆不用 `el-form`/`el-form-item`，改自绘 label + `el-input`——比硬覆盖 18px 干净。
- 🔴 **`el-table` 的 `row-class-name` 传固定函数时，改 prop 不会触发重渲染**。
  Vue 比对的是**函数引用**，不是函数返回值；写 `:row-class-name="rowClass"`（组件内固定的
  那个函数）时，`rowClass` 依赖的 ref 变了但引用没变 → **Vue 认为没变化，高亮永远不出现**。
  → 用 `computed(() => (row) => ...)` 返回**新函数**，靠函数标识变化驱动重算。
- **高亮行要压过 `el-table` 的 hover 规则**。它自带
  `.el-table__body tr:hover > td.el-table__cell`（特异度 **0,3,2**）。
  只写 `.row--focused { background: ... }`（0,1,0）会被 hover 盖掉——
  症状是**鼠标一经过高亮行，高亮就消失**。选择器要写足层级。
  另外高亮底色别和 hover 用同一档令牌（会分不清「选中」与「鼠标停在这」），
  本项目用 `--kb-brand-soft` 压 `--kb-brand-softer`。

### TypeScript 的具体坑

- **`interface` 不能赋给 `Record<string, unknown>`，`type` 别名可以**。
  `src/api/http.ts` 的 `get<T>(url, params?: Record<string, unknown>)` 收的正是后者。
  查询参数类型若写成 `interface`，**所有调用点报「缺少索引签名」，且报错落在 api 层、根因在 types 层**，
  很难顺藤摸瓜。→ 查询参数一律用 `type` 别名。

- 🔴 **`el-table` 插槽给的 `row` 是 `DefaultRow = Record<PropertyKey, any>`，不能直接传给
  形参是具体实体的函数**。读属性完全正常（模板里 `row.title` 看起来毫无问题），
  但 `onEdit(row)` 会报 `DefaultRow is not assignable to KbDocumentVo`；
  传 `emit` 时还会报**重载不匹配**（报错文案完全不同，容易被当成两个问题）。
  本轮这一个根因占了 20 条错误（fe-02 与 fe-06 各一半）。

  → 在该组件里加一个**收窄函数**，只在模板调用点包一层：
  ```ts
  /** el-table 插槽的 row 是 DefaultRow(Record<PropertyKey, any>)，传给形参为具体实体的
   *  函数前必须收窄。用它而不是散落的 `as Xxx`——`as` 写错不报错，这里改一处即全组件生效。 */
  function asDoc(row: unknown): KbDocumentVo {
    return row as KbDocumentVo
  }
  ```
  然后把 `@click="onEdit(row)"` 改成 `@click="onEdit(asDoc(row))"`。
  **不要**在模板里散落 `as`。

  ⚠️ 这类错误**在 `@vue/compiler-sfc` 层查不出来，只在 `vue-tsc` 下暴露**
  （与「漏导出」只在打包器暴露正好互补——两把都得跑，缺一漏一类）。

### ECharts（fe-05 看板）

- **不吃 CSS 变量的不止 `color`。** tooltip 的 `extraCssText` 是**拼给浏览器的 CSS 字符串**，
  同样不吃 `var()`——写成 `rgba(31,45,61,.12)` 就等于把颜色字面量放进 `.ts` 文件，
  破坏「只有 `tokens.css` 有颜色值」的规则。
  → 把整条投影响收编成令牌（如 `--kb-shadow-tooltip`），再用
  `getComputedStyle(document.documentElement).getPropertyValue('--kb-xxx')` 读出传进去。
- **`use([...])` 里不要留「以后可能用得上」的组件。** 注册了没用到的 `LineChart` / `LegendComponent`
  **不会报任何错**，只是静默抵消按需引入的意义。注册清单必须与真实用到的配置逐项对齐。
- **`NonNullable<EChartsOption['tooltip']>` 是联合类型**（对象 | 数组）。拿它当共用样式的返回类型，
  展开进 option 时 TS 按联合分发，后续赋值检查会失败。→ 定义具体的 `TooltipStyle` 接口。
- 容器尺寸变化要 `resize()`，组件卸载要 `dispose()`——**不 dispose 会内存泄漏**，来回切页越积越多。

### 别把原型的数字当契约

- 原型上的数字可能是**自相矛盾**的。fe-05 的延时卡脚注写「8.2% 的提问超过 2s」，
  但它自己画的 5 个桶算出来是 `18/(96+142+88+46+18) = 4.6%`。
  **这条内部矛盾本身就是「原型数字是示意、不是算出来的」的证据**——
  对不上时不要靠抄原型的数去「修正」，要么找接口字段，要么显示 `—`。
- 同理，环比（`+12.4%`）这类若接口没有对应字段，**整行不渲染**，绝不回填原型的数。

### 响应形状未定时先兜底

- 后端契约还没定（P2/P3 页面）时，`props.data.points.length` 这类访问会把**形状不符**
  变成**白屏异常**。→ 在各处加 `Array.isArray` / `?? []` 兜底，
  让形状不符退化成**看得见的空态**，而不是静默空白或崩溃。

### 🔴 注释里写原型节点路径会在 `*/` 处提前闭合块注释

本 skill 鼓励把原型出处写进注释（如 `原型 zUyFC/URow/*/ScopeCell`）——
**但节点路径里的 `*` 紧邻 `/` 时就是块注释的结束符**，注释当场闭合，
后面整段中文被当代码解析。fe-04 撞上时的报错是
`Unexpected character '「'` / `Missing semicolon`，**指向中文注释中间，完全指不到真凶**。

- `/*` 单独出现是安全的（块注释不嵌套）；**只有「星号紧跟斜杠」致命**。
- 通配层级改用文字描述：`zUyFC/URow/<子层>/ScopeCell`，或把注释写成 `//` 行注释。

### 模板与 CSS 的几个隐蔽坑

- **`el-tooltip` 只接受单个子节点，HTML 注释也算一个 vnode**。
  注释写在 `<el-tooltip>` 与子组件之间就会多出一个节点。→ 注释提到 `el-tooltip` 外层。
- **`v-permission` 不宜挂在 `el-tooltip` / `el-popconfirm` 上**（多根：teleport + trigger）。
  挂到内层单根的 `el-button` / `el-switch` / 原生元素上。
- **父组件覆盖子组件根元素样式时，scoped 下特异性会打平**（两边都是 0,2,0，scoped 追加属性选择器）。
  谁生效**取决于两个 SFC 的样式注入顺序**——随构建摇摆。→ 用直接子选择器抬高一级：
  `.user-panel > .user-panel__tree`（0,3,0）。

### Vue 响应式

- **浅 `watch` 一个「值是 store 对象引用」的 prop 永远不会触发**。
  父级改的是该对象的属性、没换引用，`watch(() => props.query, ...)` 的返回值恒等。
  → 逐字段 watch：`watch(() => props.query.keyword, ...)`。

### 布局

- **定高 flex 容器里的子项会被「压扁」而非撑开滚动**。
  `.app-page__body` 是 `flex:1 + overflow:auto` 的定高列容器，子项写 `flex: 1 1 auto` 时
  `flex-shrink` 默认为 1，内容超高就被压缩裁掉。→ 卡片与表格用 `flex: 1 0 auto`（grow 不 shrink）。
- **`el-table` 不给 `height`/`max-height` 就没有内部滚动区**，别指望靠 `flex + min-height:0`
  拿到滚动条——那是让外层容器滚。

### 后端壳子会回 `data: null`

`{code: 0, data: null}` 时 **`page.list ?? []` 仍然会抛** `TypeError: Cannot read properties of null`——
`??` 保护的是 `list`，**不是 `page`**。→ 写 `page?.list ?? []`。
这不是防御性编程，是当前阶段的真实契约。

### `el-tree` / `el-pagination`

- **`el-tree` 的 `default-checked-keys` 只在初次渲染生效，而 `el-dialog` 的 body 是首次打开才挂载的**
  ——`treeRef` 晚一拍可用。权限回显若静默失败，用户看到的是**全未勾选的树，一保存就清空权限**。
  → 在 `visible` 的 watcher 里 `await nextTick()` + 有限次重试。
- **`PAGE_SIZE_OPTIONS` 不要加 `as const`**：`el-pagination` 的 `page-sizes` 要可变 `number[]`，
  只读元组通不过类型检查。
- 给 `el-tree` 的实例 ref 加类型时，`InstanceType<typeof ElTree>` 需要**值导入** `ElTree`，
  会与 `unplugin-vue-components` 在模板里自动注入的同名导入**撞名**。
  → 改用只声明用到方法的结构化 interface（`getCheckedKeys` / `setCheckedKeys` …）。

### SSE / 流式（fe-03 问答）

- 🔴 **中文输入法：Enter 既是「选词上屏」也是「提交」**。部分 IME 在 `compositionend`
  **之后**才派发那个 Enter，此时 `event.isComposing` 已经是 `false`，
  只判它**拦不住**——症状是用户每选一次拼音候选词就误发一条提问。
  判据要两道并用：`if (event.isComposing || event.keyCode === 229) return`（229 = IME 正在处理）。
- **分帧必须留残余缓冲**：对每个 chunk 直接 `split('\n\n')`，会把最后一截**半帧**当完整帧
  `JSON.parse`。→ 把 `split` 剩下的尾巴存回缓冲区，与下一个 chunk 拼接（写成纯函数便于单测）。
- **`TextDecoder` 要传 `{ stream: true }`**，否则**跨包的中文**会被解成 `�`。
- 🔴 **切换会话 / 新建会话后，迟到的 SSE 帧会「串台」**：`abort()` 到 `reader.read()`
  抛错之间仍有窗口，会话 A 的流会继续往会话 B 的气泡里写字。
  → `send()` 记下本次提问对应的**那条气泡引用**，每帧分发前先校验它是否仍是当前气泡
  （`stillCurrent()`），失效即整个循环 `return`。
- **`AbortController` 放进 Pinia state 是安全的，不需要 `markRaw`**：
  `reactive()` 只代理普通对象/数组/Map/Set，取回的是原始实例，`fetch` 能正常消费其 `signal`。
- **不要用模板 ref + `defineExpose` 做跨组件调方法**：`InstanceType<typeof Comp>` 能否拿到
  `defineExpose` 的成员，依赖 Vue ≥3.3 的 SFC 类型推导——是一个**只有类型检查器才知道答案**的假设。
  → 让子组件自己渲染、自己填自己（数据走 props），零隐式跨组件契约。

### 禁跑 `vite build` 时怎么自查

**两把都要跑，缺一漏一类**——本轮实测它们抓的是**完全不相交**的两类错误：

| 手段 | 抓得到 | 抓不到 |
|---|---|---|
| `@vue/compiler-sfc` 的 `parse` + `compileScript` + `compileTemplate` | 模板/脚本**语法**错误（如「注释被 `*/` 提前闭合」） | 类型、漏导出 |
| `npx vue-tsc --noEmit` | **类型**错误（`DefaultRow`、漏 `export`、未使用变量） | — |
| `npx vite build` | **漏导出**（`MISSING_EXPORT`） | 类型 |

要点：

- **`vue-tsc --noEmit` 与 `vite build` 不同，不写 `dist/`、不产生产物，并发跑也互不干扰——
  即使处于「禁 build」阶段也必须跑**（`vite build` 才是要禁的那个）。
- 过滤出自己的文件看：`npx vue-tsc --noEmit 2>&1 | grep "error TS" | grep "<你的目录>"`。
  别人文件的错误**不要动**，也不要因此以为自己没做完。
- **`vue-tsc` 的报错可能来自陈旧的 `src/types/components.d.ts`**（`unplugin-vue-components`
  的生成物）。它会报「未知组件」，症状极易被误判成「代码写错了」。
  跑一次 `npx vite build` 或 `npm run dev` 会重新生成；**别手改那两个 d.ts**（会被覆盖）。
- 🔴 **不要用 `tsc` 代替 `vue-tsc`**——`tsc` 不认 `.vue`，等于没检查。

---

## 反模式（禁止）

- ❌ 跳过 spec 直接生成代码。
- ❌ 用 `tsc` 代替 `vue-tsc` 跑类型检查（等于没检查）。
- ❌ **照抄原型里设计明确说不做的元素**（登录页的「忘记密码？」就是）。原型不是需求。
- ❌ 把原型里有、但后端无接口的元素做成可用控件（登录页的验证码框）——
  留一个永远校验不过的输入框比暂时没有更糟。
- ❌ 在组件里写死 `#2F6FED`。一律走 `var(--kb-*)`。
- ❌ 在组件里直接 `import axios` / 直接 `localStorage.getItem('access_token')`
  （会绕过 `stores/auth` 的内存态，产生两套真相）。
- ❌ 生成代码后再写一份「改动说明.md」（pen 官方 code.md 明令禁止）。
- ❌ 每个页面各写一份 `http.ts` / `stores/auth.ts`。跨页基础设施只有一份。

---

## 引用文件

| 文件 | 作用 |
|---|---|
| `.claude/skills/dev-frontend/登录页实例.md` | **登录页完整实例**：三份输入如何合流、抽出的原型结构、三处冲突的处置、代码骨架 |
| `vibecoding_doc/模块概要设计/fe-01-登录页.md` | 本 skill 贯穿使用的设计文档样板 |
| `vibecoding_doc/spec-templates/前端页面spec模板.md` | 第 4 步要填的模板 |
| `vibecoding_doc/核心数据字典.md` §5.7 / §8 | 错误码、前端类型映射 |
| `.claude/skills/pencil-draw/SKILL.md` | 原型是怎么画出来的（令牌、屏幕网格、节点 id 都在里面） |
| `.claude/skills/dev-spec/SKILL.md` | 上层流程；本 skill 是它第 4 步的前端细化 |
