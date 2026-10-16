"""B5 后半区：攻击链推演。

**本包不 re-export 任何东西**（同 `app/verify/`）：请显式写
`from app.chain.builder import build_chain`。

包内分工：

| 文件 | 职责 |
|---|---|
| `types.py` | 数据契约：`Priv` / `VulnAtom` / `ChainRule` / `ChainNode` / `AttackChain` |
| `atom.py` | `Finding → VulnAtom` 的静态映射表（§4.5） |
| `rules.py` | R1–R8 声明式规则 + 通用匹配器（§4.6） |
| `builder.py` | 状态空间 BFS、选路径、落成链模型（§4.4） |
| `narrative.py` | LLM 用点 ③ + L3 节点集合校验 + 模板降级（§4.8） |

**铁律 L1 的落点**：节点、边、环级 `verification_status` 全部由 `builder.py`
的确定性规则产出；`narrative.py` 只回填 `narrative` 一段文本，
拿掉 LLM 之后链本身一字不变。
"""
