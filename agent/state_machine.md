# 执行状态机

> standard/deep 模式必读。本文件是所有时序规则、轮次决策、报告门控的**唯一权威来源**。
> ⚠️ Plan 文件（`.claude/plans/*.md`）是设计阶段产物，执行时不得引用。

---

## 状态流转

```
PHASE_1_RECON → ROUND_N_RUNNING → ROUND_N_EVALUATION → REPORT
                      ↑                    │
                      └── NEXT_ROUND ←─────┘（未满足终止条件时）
```

---

## State: PHASE_1_RECON

按 `agent/recon.md` 执行。门控产出（全部满足才可进入下一状态）:

- □ 核心代码目录列表（写入 Agent Contract 的 [搜索路径]）
- □ 排除目录列表
- □ 攻击面地图（从架构、业务、框架、部署、功能五个维度推导）
- □ Agent 切分方案（基于攻击面特征，不是维度编号）
- □ ★ 端点/入口清单（认证授权 Agent 输入）
- □ ★ 业务流程建模（业务逻辑 Agent 输入，Phase 1.5 产出）

### 审计重点判断

不用查表。根据 Phase 1 侦察结果，问自己：
- 这个系统里最值钱的东西是什么？→ 围绕它分配最多精力
- 攻击者最容易进来的地方在哪？→ 优先审计
- 哪些模块是开发者自己写的安全机制？→ 自研安全代码比框架代码更容易出错

---

## State: ROUND_N_RUNNING

Entry: 为每个 Agent 注入 Agent Contract（见 `agent/agent_contract.md`）→ 并行启动。

### Agent 内部执行阶段

每个 Agent 内部按以下阶段执行:

**Phase 2A: 自主审计（主要精力）**
- 基于 Phase 1 攻击面地图，自主选择审计路径和搜索策略
- ⚠️ Phase 2A 不加载 checklist。用自身安全知识和思考能力自由审计
- 核心方法: 理解代码意图 → 找到开发者的认知盲区 → 验证是否可利用
- 发现高价值攻击面时深入挖掘，不要因为"时间分配"而放弃

**Phase 2B: 自检补漏（收尾）**
- Phase 2A 完成后，加载 `references/checklists/coverage_matrix.md` 作为安全网
- 问自己: 有没有明显的攻击面被遗漏了？
- checklist 是安全网，不是方向盘

**Phase 3: 验证**
- 对每个疑似漏洞: 确认输入可控 → 追踪数据流到 Sink → 验证无有效防护 → 构建利用场景 → 评估影响

门控条件:
- ALL Agents 完成 OR 超时标注
- 超时处理: turns_used ≥ max_turns → 标注"该方向审计未完成"（不忽略）
- 禁止: Agent 未全部完成时写最终报告

---

## State: ROUND_N_EVALUATION

### 前置: 截断检测

对每个 Agent 输出:
1. 检查 `=== AGENT_OUTPUT_END ===` 哨兵
   - YES → 完整，正常处理
   - NO → 截断，执行恢复:
     a. HEADER 存活 → 提取 COVERAGE/UNCHECKED/STATS，标记 findings_truncated
     b. HEADER 也丢失 → resume Agent 仅输出 HEADER，或标记 ⚠️ 强制进 R2

### 覆盖缺口评估

对每个审计方向，判断覆盖深度:

- ✅已覆盖 = 核心攻击面已搜索 + 有数据流追踪 + 关键路径已验证
- ⚠️浅覆盖 = 只做了表面搜索，没有深入追踪数据流
- ❌未覆盖 = 完全没有触及

判断标准不是数字（"审计了几个端点"），而是质量:
- Grep 命中了但没 Read 验证 = 浅覆盖
- Read 了但没追踪完整数据流 = 浅覆盖
- 追踪了数据流但没检查防护层 = 浅覆盖
- 完整追踪 + 防护层验证 = 已覆盖

### 跨轮传递结构

```
COVERED:    注入(✅ N个发现), 认证(✅ N个发现), ...
GAPS:       业务逻辑(❌ 未覆盖), 配置安全(⚠️ 仅Grep未深入), ...
CLEAN:      [已搜索确认不存在的攻击面]
HOTSPOTS:   [R1发现但未深入的高风险点, file:line:断点描述]
FILES_READ: [已读文件+关键结论, R2不再重读]
GREP_DONE:  [已执行的Grep patterns, R2不再重复]
```

### 三问法则

Q1: 有没有计划搜索但没搜到的区域？ → YES = NEXT_ROUND
Q2: 发现的入口点是否都追踪到了 Sink？ → NO = NEXT_ROUND
Q3: 高风险发现间是否可能存在跨模块关联？ → YES = NEXT_ROUND

### 自适应轮次决策

**standard 模式（1-2 轮）**:
- R1 后三问全部 NO + 无明显遗漏 → 直接 REPORT
- 否则 → NEXT_ROUND

**deep 模式（2-3 轮）**:
- R2 始终执行 — R2 目的是深度，不是补漏
- R3 仅当 R2 发现跨模块攻击链候选时启动

**通用**: 注入/认证/授权这三个核心方向任一未覆盖 → 不可进入 REPORT

### 收敛保证

- UNCHECKED_CANDIDATES 仅在 R1 产生，R2 消化但不再生
- R2 Agent 禁止输出新的 UNCHECKED_CANDIDATES
- 候选链深度 = 1（R1 产生 → R2 消化 → 终止）

---

## State: NEXT_ROUND

R2 Agent 启动规则:
- 输入: 跨轮传递结构
- 方向 = 缺口方向 + 热点
- prompt 必须包含: 跨轮传递结构 + 禁止重读/重搜规则 + 聚焦缺口和热点
- R2 Agent 数量根据缺口规模灵活决定，不查表

R3 Agent（仅 deep 模式，仅有跨模块候选时）:
- 方向 = 攻击链构建 + 交叉验证

轮次硬上限: standard=2 | deep=3

---

## State: REPORT

前置条件（全部满足才可写最终报告）:
- □ 所有轮次所有 Agent 完成或标注超时
- □ 所有轮次发现已合并去重
- □ 覆盖度检查通过
- □ 严重度校准已完成（见 `agent/report.md`）

最终报告 = 所有轮次合并结果。报告格式见 `agent/report.md`。

---

## Agent 切分

### 切分约束

1. 维度互不重叠 — 每个 Agent 负责独立的安全维度
2. 可完全并行执行 — Agent 之间无依赖关系

### Agent 组合模板（deep 模式参考）

```
Agent 切分原则: 按攻击面特征分组，不是按维度编号分组。
审计者根据 Phase 1 侦察结果自主决定 Agent 数量和方向。

典型分组（参考，非强制）:
- 注入类 Agent: SQL/命令/表达式注入等 Sink 追踪
- 认证授权 Agent: 认证链、权限控制、越权
- 业务逻辑 Agent: 业务流程、状态机、资金逻辑
- 数据处理 Agent: 反序列化、文件操作、SSRF
- 配置安全 Agent: 加密、配置、供应链
- 攻击链 Agent: 跨发现关联，构建端到端攻击路径

如果项目有特殊攻击面（自定义协议、LLM 集成、复杂状态机等），
为其分配专门的 Agent，不要硬塞进上面的分组里。
```

Agent 数量和 turns 不设硬性上限，根据项目攻击面复杂度灵活分配。

### 串行执行策略

当环境不支持并行 Agent 时（如 Claude Code 单线程），按以下顺序串行执行:

```
执行顺序（优先级从高到低）:
1. 认证授权 — 认证绕过放大所有漏洞
2. 注入类 — 最常见高危漏洞
3. 项目特有攻击面 — 自定义协议/特殊机制（如有）
4. 业务逻辑 — 需要前序 Agent 的上下文
5. 数据处理 — 反序列化/文件/SSRF
6. 配置安全 — 加密/配置/供应链
7. 攻击链 — 依赖所有前序 Agent 输出
```

串行优化规则:
- 后续 Agent 消费前序 Agent 的 FILES_READ，避免重复读取同一文件
- 后续 Agent 消费前序 Agent 的 GREP_DONE，避免重复搜索
- 前序 Agent 的 HOTSPOTS 自动注入后续 Agent
- 兼容未来并行支持: 串行策略不改变 Agent Contract 格式

### Agent 数量参考

根据项目攻击面复杂度灵活分配，以下仅为参考:
- 小型项目: 2-4 Agent
- 中型项目: 3-6 Agent
- 大型项目/含自定义协议: 5-7+ Agent

不设 turns 和工具调用次数硬上限。Agent 根据攻击面深度自主决定何时停止。
