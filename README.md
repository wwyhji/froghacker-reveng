# FrogHacker RevEng 🔍

<div align="center">

**蛙客逆向关联追踪引擎（开源版）** — 关联图建模 · 游标导航 · 非注入 dump

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](./pyproject.toml)
[![零依赖](https://img.shields.io/badge/依赖-纯标准库-important.svg)]()

响应时代号召，开源蛙客网络安全分析自动化平台的**逆向关联追踪引擎**设计与配套工具。

</div>

## 这是什么

蛙客（FrogHacker）是攻·防·取三端共生的安全分析自动化平台。本仓库开源的是其中的**逆向关联追踪引擎**：一套面向「AI 端纯本地」的 APK 逆向找 key 方法论与配套工具链，核心主张——

> **逆向不是「找字符串」，是「追踪业务逻辑的关联链」。**

key 的完整生命周期 `生成 → 存储 → 使用 → 作用于数据` 是一条有向图。引擎主体是**游标在关联图上导航**，弱模型工蚁只做局部四选一判断，判断对错交给**确定性验证**裁决（不靠模型置信度）。

> ⚠️ 本仓库只开源**业界通用的逆向分析能力**。受专利保护的数学检测引擎（同调/因果/范畴/FCA）已剥离，见下方「专利保护与开源边界」。蚁群协作调度底座见独立仓库 [froghacker-ant-swarm](https://github.com/wwyhji/froghacker-ant-swarm)。

## ✨ 特性

- **关联图建模** — 5 类节点（DATA/FUNC/VAR/CONST/EXT）× 5 类关联边（ENCRYPTED_BY/KEY_ARG/SOURCE/CALLED_BY/STORE）
- **游标状态机** — 单调覆盖 + 信息素方向位，只持索引不持正文，上下文与链长解耦
- **弱模型四选一** — 工蚁只做「读一个工具输出 + 答一个四选一」，本地弱模型够用
- **非注入内存 dump** — 只读 `/proc/<pid>/mem`，不 ptrace/hook/注入，绕加固壳反调试
- **确定性兜底** — 降维投票 / 微观验证回溯 / 终局闭环（错误 key 解不出明文）/ 诚实降级
- **零依赖** — `dump_memory.py` 纯标准库，无需 pip install

## 🚀 快速上手

### 非注入内存 dump（逆向引擎「动态降级」工具）

```bash
# 需 root Android 设备 / redroid 容器
python dump_memory.py <package_name> <output_dir>
python dump_memory.py --pid <pid> <output_dir>
# 输出 findings.json：明文候选 + AES key 候选（含证据），供工蚁四选一判断
```

## 🧠 逆向关联追踪引擎（设计）

完整设计见 [`docs/reverse_engine_design.md`](./docs/reverse_engine_design.md)。核心流程：

```
DATA ──①ENCRYPTED_BY──▶ FUNC ──②KEY_ARG──▶ VAR ──③SOURCE──▶ CONST ✅ 收敛（key 到手）
                                                            └─▶ EXT ❌ 死路（动态 key）
        ↓ 静态死路（加固壳 / native 混淆）
   STATIC_DEAD_END → DUMP（dump_memory）→ MEM → CONTAINS → CONST/明文 ✅
```

五（四）层兜底：降维冗余投票 → 微观验证回溯 → 终局闭环 → 诚实降级。准确率不靠模型，靠可验证性。

## 🛡️ 专利保护与开源边界（重要）

本开源包**已剥离**以下受专利保护的技术方案（见 [NOTICE](./NOTICE)、[MANIFEST.md](./MANIFEST.md)），它们**不在**本仓库内：

- 代数拓扑 / 同调论知识库盲区检测（Betti 数）
- 因果推断溯因（贝叶斯反演）
- 形式概念分析（FCA）概念格
- 范畴论结构等价性验证
- 归一化压缩距离（NCD）与 KL/JS 散度、互信息
- Petri 网攻击行为链建模 / 群表示论 / Stone 对偶
- 知识库自充飞轮（AlphaLoop）与统一管线调度

上述方案已申请发明专利（申请日 2026-10-13）。本仓库仅开源业界通用的逆向分析与并发调度能力，**不构成**对上述专利技术方案的实施许可。

## 📁 目录结构

```
froghacker-reveng/
├── LICENSE               Apache-2.0
├── NOTICE                专利保留声明
├── MANIFEST.md           文件清单与剥离说明
├── pyproject.toml        打包配置
├── dump_memory.py        非注入内存 dump（动态降级工具）
└── docs/
    └── reverse_engine_design.md   逆向关联追踪引擎设计（剥离版）
```

## 📄 许可证

Apache License 2.0，© 2026 FrogHacker (wwyhji)。专利保留声明见 [NOTICE](./NOTICE)。
