# Code Audit Agents

面向 Claude Code 的白盒安全审计 Skill，专注 0day 漏洞挖掘。

不是跑 checklist 的扫描器，而是一套驱动 AI 进行深度安全研究的思维方法论。

## 核心理念

- **思考驱动，不是规则驱动** — 理解代码意图，找到开发者的认知盲区
- **深度优先** — 发现高价值攻击面时深入挖掘，不受时间分配限制
- **攻击链思维** — 单个漏洞不够严重就组合，构建端到端攻击路径
- **零误报原则** — 每个发现必须有完整数据流证据，宁可漏报不误报

## 支持语言

Java · Python · Go · PHP · JavaScript/Node.js · C/C++ · .NET/C# · Ruby · Rust

## 使用方法

### 安装

将本项目克隆到 Claude Code 的 skills 目录：

```bash
git clone https://github.com/wj-wyt/code-audit-agents.git ~/.claude/skills/code-audit
```

### 触发

在 Claude Code 中对目标项目说：

```
深度审计 /path/to/project
```

其他触发词：`安全审计`、`代码审计`、`安全检查`、`漏洞扫描`、`deep audit`、`security audit`

### 审计模式

| 模式 | 触发词 | 说明 |
|------|--------|------|
| standard | 审计、扫描、安全检查 | 1-2 轮，覆盖核心攻击面 |
| deep | 深度审计、全面审计 | 2-3 轮，Multi-Agent 并行，攻击链构建 |

## 项目结构

```
├── SKILL.md                    # 入口，执行路由器
├── agent/
│   ├── core.md                 # 核心思维方法论（4层模型 + 8种方法）
│   ├── recon.md                # Phase 1 侦察 + Phase 1.5 业务理解
│   ├── state_machine.md        # 多轮审计状态机
│   ├── agent_contract.md       # Agent 合约模板（5种审计策略）
│   ├── business_audit.md       # 业务逻辑审计思维链
│   ├── report.md               # 报告格式规范
│   └── quick_diff.md           # 增量审计（针对 diff）
└── references/
    ├── checklists/             # 语言级安全检查清单（安全网，非驱动）
    ├── frameworks/             # 框架特定安全参考
    ├── security/               # 高级攻击技术参考
    └── tools/                  # 工具集成指南
```

## 审计流程

```
Phase 1 侦察 → Phase 1.5 业务理解 → [PLAN] 等待确认
    → Phase 2A 自主审计 → Phase 2B 自检补漏 → Phase 3 验证
    → 轮次评估 → (需要则 R2/R3) → 最终报告
```

## 5 种审计策略

| 策略 | 方法 | 适用场景 |
|------|------|----------|
| sink-driven | Grep 危险函数 → 防护层检查 → Source→Sink 追踪 | 注入类漏洞 |
| control-driven | 端点清单逐个验证权限控制 | 认证授权缺陷 |
| business-driven | 按业务流程逐步提问验证 | 逻辑漏洞、资金安全 |
| config-driven | 理解安全配置意图，找盲区 | 加密、配置、供应链 |
| protocol-driven | 逐消息类型审计身份验证 | 自定义协议 |

## 思维方法论

core.md 定义了 4 层思维模型：

1. **理解系统** — 建立和开发者一样的心智模型
2. **质疑系统** — 对每个安全机制执行"五个为什么"攻击
3. **构建攻击原语** — 把异常行为转化为读/写/执行/绕过/降级原语
4. **验证可利用性** — 确认可达性、可控性、可靠性、影响

以及 8 种具体方法：逆向资产追踪、深度变体分析、信任边界分析、假设攻击、语义差异挖掘、时序并发分析、数学逻辑分析、攻击链构建。

## 可选工具集成

支持 Semgrep / Bandit / Gosec 等静态分析工具作为线索输入，但工具输出不等于发现，必须 Read 代码验证。

## License

MIT
