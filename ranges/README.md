# 靶场（PRD §10）

两个刻意做出来的脆弱应用。它们**不是演示道具**，是基准测试的标的物 ——
`backend/tests/benchmark.py` 拿它们算出召回率，"我的工具还行"这句话因此有了数。

```
ranges/
  ecommerce/    电商订单系统   PRD §10.1   11 个植入漏洞
  usercenter/   微服务用户中心 PRD §10.2    4 个植入漏洞
```

每个靶场根目录有 `GROUND_TRUTH.yaml`：逐条给出漏洞的**确切行号**、
期望命中的探针技术、期望的响应形态。行号取自分析器的实际输出，不是数出来的。

---

## 为什么要两个，而不是一个做大

因为**两类缺陷的检出难度根本不同**，混在一个靶场里就分不清
"召回率低"是因为靶场太难还是因为分析器不行。

| | 靶场一 ecommerce | 靶场二 usercenter |
|---|---|---|
| 缺陷形态 | **写错了** —— 拼接了、没过滤、硬编码了 | **漏写了** —— 少一行归属校验、少一个装饰器 |
| 证据形态 | 有一条看得见的坏语句 | 只能证明"函数体里找不到鉴权痕迹" |
| 典型置信度 | 0.90 ~ 0.99 | **0.55**（IDOR） |
| 对应能力 | 模式匹配 + 污点追踪 | 推断 |

置信度那个差不是拍脑袋填的：靶场一的证据是**在场证明**（这行代码干了坏事），
靶场二的是**缺席证明**（该有的那行不在）。缺席证明天然弱 ——
"我没找到鉴权"与"确实没有鉴权"之间隔着整个调用图，
而引擎按 PRD §7.1 的边界**只做函数内 + 单层跨函数**。
所以 IDOR 报 0.55 而不是 0.9。**报告里的置信度不同，是真实反映。**

---

## 与探针契约的对应关系

B5 的探针表按漏洞类别给出**固定的路由与形态**
（`backend/app/verify/probe.py::PROBE_TEMPLATES`）。靶场必须提供这些端点，
否则那一类探针永远只能落 `unverified`，攻击链也就点不着。
所以两个靶场提供的路由是 **PRD §10 规定的路由 ∪ 探针契约要求的路由**：

| 探针技术 | 路由 | 靶场 | 判据 |
|---|---|---|---|
| `union_extract` | `GET /search?q=` | ecommerce | 响应里出现 nonce |
| `boolean_blind` | `GET /search?q=` | ecommerce | 真假分支长度差，且真分支可重复 |
| `time_blind` | `GET /api/ping?host=` | ecommerce | `sleep 3` 的时延差落在 2.4~3.6s |
| `echo_nonce` | `GET /api/ping?host=` | ecommerce | 响应里出现 nonce |
| `path_traversal_read` | `GET /api/file?path=` | ecommerce | 读到 `root:x:0:0:` |
| `path_traversal_read` | `GET /api/download?file=` | ecommerce | 读到 `/etc/hostname`（12 位十六进制） |
| `upload_marker` | `POST /api/upload` → `/uploads/<n>` | ecommerce | 上传后回读到 nonce |
| `read_config` | `GET /.env` | ecommerce | 出现 `KEY=` 形态 |
| `read_config` | `GET /debug/config` | 两个都有 | 同上 |
| `deser_marker` | `POST /api/deserialize` | ecommerce | nonce 从错误回显里出来 |
| `idor_horizontal` | `POST /api/user/profile` → `/api/user/2/profile` | usercenter | 匿名写入的 nonce 被匿名读回 |
| `unauth_probe` | `GET /api/user/list` | usercenter | 无凭证 200 + 非空 JSON |

---

## 写一个新靶场的硬约束

这几条不是风格建议，是**沙箱起不来或探针打不中**的直接原因。原先它们只写在
最早的 `demo/vulnerable-demo-app/app.py` 的模块注释里 —— 那是唯一一处，
而靶场作者要看的是本文件。

| 约束 | 值 | 违反后果 |
|---|---|---|
| 入口文件名 | **`app.py`**，且在工作区根 | 容器起来后等端口就绪超时，报「目标未就绪」，**看不出是入口点没找对** |
| 监听端口 | **5000** | 同上（探针的 `target` 默认取 5000） |
| 监听地址 | `0.0.0.0` | 容器内回环不通，宿主机侧连不上 |
| 工作目录 | `/workspace` | 相对路径读不到文件 |

前两条在 `backend/app/verify/probe.py::render_mission_script` 里被写死为
`app_entry="app.py"` / `workdir="/workspace"`。**改名或挪位置不会报错，
只会超时** —— 所以这条约束要在这里写清楚，而不是靠踩一次记住。

### ⚠️ 靶场源码是量具，不是文档

**改靶场里的一行代码，等于把量具的刻度磨掉一格。** `GROUND_TRUTH.yaml` 钉的是
**确切行号**，而 `tests/benchmark.py` 在 `LINE_WINDOW = 2` 的窗口里匹配 ——
也就是说**净增 3 行就能让后面所有基准条目失配**。

踩过一次，代价很具体：给 `ranges/ecommerce/app.py` 的 docstring 补了 5 行说明，
召回率从 **11/11 掉到 3/11、误报 8**。代码一行没改，坏的是基准。
（修法是让那次编辑**净增 0 行**，改完行号仍精确落在 88 / 114。）

所以：

- 改靶场源码前先跑一遍 `uv run python tests/benchmark.py` 记下基线；
- docstring 要改就**按原行数改**（换行不换数）；
- 真要增删行，**同一轮里同步更新 `GROUND_TRUTH.yaml` 的行号**，别分两次做；
- 改完再跑一次，召回率与误报数都必须回到基线。

**为什么这条容易漏**：靶场读起来像"示例代码"，改注释像是安全的 ——
它不是，它是这套系统唯一的**外部真值**。

---

## 怎么跑

```bash
# 1. 只跑静态分析，算召回率（不需要 Docker，秒级）
cd backend && uv run python tests/benchmark.py

# 2. 本地起靶场，按探针的真实字节打一遍（验"响应形态对不对"）
uv run --project backend --with flask python backend/tools/range_smoke.py ecommerce

# 3. 走完整流水线（需要 ECS 上的 Docker + 隧道 + API + worker）
uv run --project backend python backend/tools/e2e.py ecommerce
```

后两个是**工具脚本，不是产品代码**，放在 `backend/tools/`（不被 `app/` 引用）。
两条命令都**锚在 `__file__` 上，可以从任意目录跑** —— 不必先 `cd backend`。
它们各自在导入期断言了一次目录布局，挪错位置会立刻报"找不到 ranges/"，
而不是指向一个空目录、然后报"里面什么都没有"。

`range_smoke.py` 是本地快速迭代用的（沙箱一轮要几十秒，而"响应形态对不对"
与本机/容器无关），`e2e.py` 打的是 HTTP API 而不是内部函数 ——
这样验证的是**真正部署起来的那条路径**。

> 上面第 3 条要跑起来，需要四个东西同时活着（隧道 / API / **worker** / 视情况的前端），
> 而缺 worker 的症状是「接口返回 201 启动成功，然后评估永远停在 `created`」——
> 不报错、就是不动。逐条的前置检查、每一步的真实返回、一次完整实测的时间线、
> 以及失败速查表，都在
> [`项目通读/如何评估一个新项目.md`](../项目通读/如何评估一个新项目.md)。
> 那份讲**怎么跑靶场**，本文讲**怎么写靶场**。

---

## 实测数字（诚实版）

```
靶场一 ecommerce    静态召回 11/11 (100.0%)   误报 0
靶场二 usercenter   静态召回  3/5  ( 60.0%)   误报 0
────────────────────────────────────────────────────
合计                             14/16 ( 87.5%)
其中 PRD §10 的 8 条               7/8  ( 87.5%)   ← V8 为半命中
```

**PRD §10.4 的示例输出写的是「召回 7/8 (87.5%)」。现在是 7/8 —— 对上了。**
（补上 V6 那条规则之前是 6/8。补的过程与理由见 `backend/docs/探针路由绑定.md` §7
与本文件下一节。）

剩下两条漏的，原因是具体的，不是"还需要调参"：

| | 漏的原因 |
|---|---|
| **V7** 手机号明文 | 既无规则也无探针。"该脱敏没脱敏"既不是数据流问题，也不是一次请求能证明的问题。**只有人工复核能发现。** |
| **V8** 调试接口（半命中） | 检出的是 `settings.py` 的硬编码密钥，不是 `app.py:175` 那个调试路由本身。没有任何规则指向那一行 —— 它是**借道**密钥 finding 被动态验证掉的。 |

这两条都如实写进了 `GROUND_TRUTH.yaml` 并**计入分母**，而不是从靶场里删掉。
删掉它们，召回率立刻变成 100%，而那个数字除了骗自己没有任何用处。

**关于 `0 误报` 这个数字的可信度**：靶场只有两个、且都是我自己写的，
所以"误报 0"在靶场上证明力有限。更有说服力的一次实测是**自扫本仓库**：
`backend/app/` 130 个文件、23.7k 行的 FastAPI 代码，
`unauth_access` 规则产出 **0 条** finding（真阳性与假阳性都是 0）。
这类"在真实代码上不刷屏"的证据，比在自家靶场上不误报更能说明规则的方向是对的。

---

## 已知的能力边界（写在代码里，不藏着）

1. ~~**V6 是"能验证但发现不了"**~~ —— **已修**。补上了 `detect_unauth_access`
   规则（`backend/app/analysis/patterns.py`）与 `VulnType.UNAUTH_ACCESS`。
   修之前的样子值得留着：`unauth_probe` 探针能打 `/api/user/list`、
   链路规则 R7 也写了、CVSS 表也有 —— 唯独**没有能产出这条 finding 的东西**，
   于是一个系统永远不会去验证它从没发现的漏洞。
   **"能验证"与"能发现"是两件独立的事**，这一条同时暴露过。
   现状：R7 不再是不可达代码，但**两个靶场都没有 `unauth_access + file_upload`
   这对组合**，所以它仍未被任何靶场实际触发过 —— 「不可达」变成了「没被跑到」。
   要证明它工作，得写一条链路规则的单测，而不是指望靶场。
2. ~~**探针的路由来自模板，不来自 finding**~~ —— **已修**（见下一节）。
   原先靶场里三条 SQL 注入 finding（`app.py:88` 的 `/search`、
   `app.py:114` 的 `/api/order/query`、`admin_login.py:43` 的 `/admin/login`）
   **各跑了一遍同一个 `/search?q=` 探针**，因为 sqli 模板的 `url_path` 是写死的。
   现在探针会从 finding 的污点路径**反查它自己的端点**
   （`backend/app/verify/routes.py::bind_route`）。

   **剩下的边界：** 反查不出端点时（`hardcoded_secret` 这类**结构上就没有端点**的
   漏洞），探针仍然走模板路由，而这条命中**不再算作 `verified`** ——
   它落 `potential`，理由是「证的是该类漏洞存在，不是本条被跑通」。
   报告里两种强度的措辞是分开的（`逐点确认` / `仅类别级`）。

   **这一条在 V6 上还多一层，容易被误读成"通了"**：未授权访问的探针
   **命中了**（`assessment #14`：`GET /api/user/list` → `matched=1 http=200`），
   但状态仍是 `potential` —— 因为未鉴权端点**没有输入参数**，
   而绑定的职责是"定出载荷放进哪个参数"，无参可放就绑不上。
   它之所以还能命中，纯粹因为模板里的路由恰好就是 `/api/user/list`
   （规则和靶场是一起写的）——**换个路由名不同的目标就会打空**。
   修法已有（让无载荷的技术允许 `param_name=None` 绑定，顺带把探针
   URL 换成 finding 自己的路由），本轮没做，因为它要动"载荷往哪发"
   那段代码。详见 `backend/docs/探针路由绑定.md` §10.3。

   **另一处边界：** 反查**成功**不等于命中一定算逐点。`idor` 的探针要发两条
   请求，而绑定只描述一个注入点 —— 无差别套上去会把写入侧那条也改掉（实测 404）。
   所以 `idor` 模板不吃绑定，只有它的**读侧** URL 从反查出的路由生成。
   见下一节与 `backend/docs/探针路由绑定.md` §7。

   完整说明见 `backend/docs/探针路由绑定.md`。

3. **`rejected` 是机器结论，不是人工复核** —— 而且它**确实错过**。
   实测第一轮：`admin_login.py:43` 的两条真 SQL 注入被判 `rejected`。
   成因是探针的参数名从污点路径推导（推成 `check_login`），
   却打在只读 `q` 的 `/search` 上 —— 参数被服务端无视，响应与基线逐字节相同，
   布尔差分如实报告"无差异"，runner 如实写下 `rejected`。**每步都对，结论是错的。**
   已修（规范参数名恒进候选 + 非规范参数不得证伪，见
   `tests/test_verify_absence.py`），但**判据只能保证不比原来更容易出错**，
   所以报告里它的口径是「动态未复现（机器判定，待人工确认）」。

4. **上传打不出 RCE**。沙箱 `/workspace` 只读挂载、`/tmp` 是 `noexec` 的 tmpfs，
   落地的文件没有执行路径。这正是链路 R3/R7 标 `outcome_inferred=True` 的原因。

---

## 动态验证实测（ecommerce，完整流水线）

### 修复前：15/15 "已验证"，但只有 5 条是逐点跑出来的

```
15 条 finding → 15 条 verified、0 rejected、0 potential，产出 5 条利用链
```

**15/15 不是"全对"。** 逐条比对 finding 的触发位置与探针的请求路径：

| finding | 自己的端点 | 探针打的端点 | |
|---|---|---|---|
| `app.py:88` SQL 注入 | `/search` | `/search?q=` | 逐点 |
| `app.py:114` SQL 注入 | `/api/order/query` | `/search?q=` | **借道** |
| `admin_login.py:43` ×2 SQL 注入 | `/admin/login`（POST） | `/search?q=` | **借道** |
| `app.py:153` 文件上传 | `/api/upload` | `POST /api/upload` | 逐点 |
| `app.py:165` 路径穿越 | `/uploads/<name>` | `/api/file?path=` | **借道** |
| `app.py:194` 命令注入 | `/api/ping` | `/api/ping?host=` | 逐点 |
| `app.py:220` 路径穿越 | `/api/file` | `/api/file?path=` | 逐点 |
| `app.py:241` 路径穿越 | `/api/download` | `/api/file?path=` | **借道** |
| `app.py:290` 反序列化 | `/api/deserialize` | `POST /api/deserialize` | 逐点 |
| `config.py:26-32`、`admin_login.py:23` ×5 硬编码密钥 | 源码里的常量 | `/.env`、`/debug/config` | **借道** |

逐点 5 条、借道 10 条。借道的那 10 条**不是误报**（它们确实是漏洞，
靶场里也确实是可注入/可穿越的），但它们被"验证"的方式是
**同类漏洞在本目标上成立**，不是**这一行被跑通了**。

### 修复后：借道归零

| | 修复前（`assessment #6`） | 修复后（`assessment #7`） |
|---|---|---|
| 探针命中在本条**自己**的端点上 | 5 | **8** |
| 探针命中在**别的**端点上（借道） | 5 | **0** |
| 结构性无法绑定（`hardcoded_secret`，无端点） | 5 | 5 |
| 状态分布 | verified 15 | **verified 8 / potential 7** |
| 利用链 | 5 条 | **4 条** |

新绑上的 3 条：`app.py:114` → `GET /api/order/query?id=`；
`app.py:165` → `GET /uploads/../../../../etc/passwd`；
`app.py:241` → `GET /api/download?file=`。

最后两条是**路径参数注入** —— 以前 `InjectIn.PATH` 在 `_request()` 里是个空操作，
探针**带着干净 URL** 发出去、必然不命中，然后被记成 `rejected`。

7 条 `potential` 的成分：5 条是结构上就没有端点的 `hardcoded_secret`，
2 条是 `/admin/login` 的字符串语境注入 —— 它们绑定**成功**了，
但能打穿字符串语境所需的载荷形态（`' OR '1'='1' -- `）过不了载荷闸门，
而闸门是**安全边界**，不为覆盖率放宽。

**没有一条是 `rejected`。** 两条 `/admin/login` 的 SQL 注入在靶场里是真实存在的，
静态结论原样保留，只是动态证据不足以支撑"逐点确认" ——
**"没能确认"与"确认不存在"是两件事**，修复前它们在这两个极端之间跳。

### 一个副作用：链条也变短了

5 条链 → 4 条。这是对的：链规则只由 `verified` 节点驱动，
而原先有一条链经过了"硬编码密钥"节点，那个节点的"验证"来自读 `/.env`。
**一条建立在借道证据上的攻击链，被当成了推演的前提。**
现在它不再具备这个资格。链条变短，但每一环都站得住。

逐条的设计说明与取舍见 `backend/docs/探针路由绑定.md`。

### 再补一刀：UNION 载荷的列数改为按目标构造

上面那张表里 `app.py:114` 是"新绑上的"，但绑定只解决了**打哪个端点**，
没解决**载荷长什么样**。`/api/order/query` 的 SELECT 是三列
（`id, product_id, amount`），而 UNION 载荷模板恒为两列，于是：

| 载荷 | 打到 `/api/order/query` |
|---|---|
| `1 UNION SELECT '<nonce>','asa' -- `（模板原值） | **HTTP 500**，nonce 不在响应里 |
| `1 UNION SELECT '<nonce>','asa','asa' -- `（按列数构造） | HTTP 200，nonce 在响应里 |

实测记录（`assessment #11` 的 `poc_attempts`）：
`matched=0 http=500`，`failure_reason` 写着「响应体（HTTP 500）未匹配期望特征」。

**但这一条的最终状态当时仍然是 `verified`** —— 因为同一类别下还有
`boolean_blind` 那条探针（`1 AND 1=1`，与列数无关）命中了。
所以这是**技术覆盖面的**改进，不是状态数的改进：`assessment #11` 与
补上按列数构造之后的 `#13`，15 条 finding 的状态分布**逐条完全相同**
（8 verified / 7 potential）。

这条区分值得写下来，因为「换了个载荷」很容易被讲成「修好了一个漏报」，
而这里**没有漏报被修好** —— 被告席上的是 UNION 这条技术的可用性。
真正被修好的是：三列目标上 UNION 探针从"必然失败且**看起来像没有注入**"
变成了能命中；以及 `SELECT *` 的列数不再被误算成 1
（那会让一次未命中被当成**证伪**，把真注入写成 `rejected` —— 见
`context._column_count` 的注释与 `test_select_星号的列数是不可知而不是_1`）。

### 靶场二 usercenter：IDOR 曾经是绑定的反例

```
修复前（assessment #8）   修复后（assessment #12）
  idor             potential   →   idor             **verified**（medium → high）
  hardcoded_secret potential   →   hardcoded_secret potential
  hardcoded_secret potential   →   hardcoded_secret potential
  hardcoded_secret potential   →   hardcoded_secret potential
  verified 0 / 链 0 条         →   verified 1 / 链 1 条
```

`assessment #8` 里绑定**成功**了（日志写着「已绑定到自己的端点：
`GET /api/user/{payload}/profile`，参数 `user_id`，位置 `path`」），
可 IDOR 还是落 `potential`。原因是"绑定成功就把四个字段一起换掉"这个决定，
在**双请求探针**上是错的：

| | 探针实际发的 | 为什么错 |
|---|---|---|
| ① 写入侧 URL | `POST /api/user/<nonce>/profile` | 该路由只收 GET → 404 |
| ② 写入侧参数名 | `user_id=<nonce>` | 写入接口要的是 `nickname` |
| ③ 读侧 URL | `/api/user/2/profile` | 前两条修好后，这串 URL 仍来自模板，命中只算类别级 |

IDOR 要发**两条打在不同端点上的**请求，而一条绑定只描述**一个**注入点。
所以 `idor` 模板声明 `binds_route=False`（写入侧整条由模板给死），
同时 `aux_resource_id="2"` 让**读侧 URL 从反查出的路由生成** ——
读侧打的正是这条 finding 自己的端点，命中才算逐点。
`hardcoded_secret` 那三条落 `potential` 是结构性的：它们**没有端点**。

`aux_resource_id` 的代价写在文档里：它假定目标至少有 2 号用户。

---

## 靶场本身的安全约束

* 靶场**只监听容器内的 `127.0.0.1`**（沙箱 `network_disabled=True`，无出网）。
* 所有漏洞都是**预置的、静态的**，没有任何"可以被外部触发去攻击别处"的能力。
* 命令注入的载荷由探针闸门限制在时间盲注与 `echo` 两种形态，
  **不含反弹 shell、不含外连、不含删改数据**。
* IDOR 探针的写入是容器内的一次性自造记录，随容器销毁一并消失
  （B5 设计 §7 B5-D10）。
