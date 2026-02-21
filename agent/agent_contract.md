# Agent 合约模板

> deep 模式必读。定义 Agent 启动时注入的合约和输出格式。

---

## 基础合约（所有 Agent 通用）

```
---Agent Contract---
1. 搜索路径: {paths}。排除: {excludes}。
2. 工具: Grep/Glob/Read 为主。Bash 仅用于 git log/diff/semgrep 等必要命令，禁止用 Bash grep/find/cat 替代 Grep/Read。
3. 预算: 不设硬性上限。Agent 根据攻击面复杂度自主分配精力。
   ★ 深度优先: 发现高价值攻击面时允许深入挖掘，不受 turns 比例限制。
4. 搜索策略: Grep 定位行号 → Read offset/limit 读上下文（±20行）。大文件用分块读取。
5. 输出: HEADER → TRANSFER → 发现表格 → 发现详情 → AGENT_OUTPUT_END 哨兵。
6. 反幻觉: 只报告 Read 过的文件中的漏洞。code_snippet 必须来自 Read 实际输出。
7. 合并: 同类漏洞 ≥5 个合并报告。同 pattern 多文件列清单不逐个深挖。
8. 防护层检查: 每个 Sink 命中必须检查 L1-L6 防护层（见 core.md）。未检查防护层的发现降级为 [需验证]。
---End Base Contract---
```

## 策略合约: sink-driven（注入类）

```
---Strategy: sink-driven（防护层前置）---
方法: Grep 危险函数 → 检查防护层 → 有效则跳过 → 无效才追踪 Source→Sink → 验证无防护。
防护前置流程:
  Step 1: Grep Sink → 命中文件列表
  Step 2: Read 每个命中点上下文 → 检查 L1(框架防护) + L2(参数化)
  Step 3: L1/L2 有效 → 标记 CLEAN，跳过
  Step 4: L1/L2 无效 → 完整追踪 Source→Sink → 检查 L3-L6
中间层追踪: Sink → 调用者 → 调用者的调用者，追到数据来源为止。
同类漏洞多个实例: 深入追踪有代表性的实例，其余合并报告。不设硬性数量限制。
---End Strategy---
```

## 策略合约: control-driven（认证授权）

```
---Strategy: control-driven---
方法: 端点清单逐个验证 → Read Controller+Service → 记录权限状态 → CRUD 一致性对比。
输入: Phase 1 端点-权限矩阵。

认证配置（config 子策略）:
  JWT/Session 配置验证: 签名算法? 密钥来源? 过期策略?
  Filter/中间件链完整性: 是否有绕过路径?
  认证豁免路径: 被豁免的端点是否返回敏感数据?

授权（control 主策略）:
执行协议（不是搜索，是清点）:
Step 1: 使用 Phase 1 端点清单
Step 2: 逐端点验证（Read，不是 Grep）
  对每个非公开端点:
  a. Read Controller 方法 → 有没有权限注解/中间件？
  b. Read Service 方法 → 有没有归属校验？
  c. 记录结果

Step 3: CRUD 一致性对比（按 Controller 分组）
  | Controller | create | read | update | delete | export |
  不一致的 = 候选漏洞

Step 4: 认证豁免路径审计
  Grep: whitelist|permitAll|excludePath|anonymous|isPublic|@AllowAnonymous
  对每个被豁免端点: 是否返回敏感数据？是否执行特权操作？

关键: Read 代码，不是 Grep 模式。
  Grep 只能告诉你"有没有 @PreAuthorize"
  Read 能告诉你"@PreAuthorize 条件够不够"
---End Strategy---
```

## 策略合约: protocol-driven（自定义协议）

```
---Strategy: protocol-driven---
方法: 理解协议设计 → 逐消息类型审计身份验证和数据完整性 → 逆向追踪高价值资产。
适用: 项目包含自定义二进制/文本协议（非标准 HTTP）。
核心思路: 协议中的每条消息都是一个攻击面。问自己 — 这条消息的发送者身份被验证了吗？消息中的字段能被伪造吗？
---End Strategy---
```

## 策略合约: cross-agent（Agent 6 攻击链构建）

```
---Strategy: cross-agent---
方法: 汇总所有 Agent 的 Critical/High 发现 → 匹配前置条件与利用结果 → 构建攻击链。
输入: 前序所有 Agent 的发现列表。

执行序列:
1. 列出所有 Critical/High 发现，标注:
   - 前置条件: 需认证(Y/N)? 需特定权限?
   - 利用结果: 信息泄露/RCE/权限提升/文件读写?
2. 自动匹配: 发现A的"利用结果"满足发现B的"前置条件" → 候选链 A→B
3. 对每条候选链: Read 相关代码验证数据流连通性
4. 给出组合等级（按链末端影响+链起点可达性重评）

输出: 攻击链列表（独立于漏洞列表），按组合影响排序。
---End Strategy---
```

## 策略合约: business-driven（业务逻辑）★

```
---Strategy: business-driven---
方法: 按业务流程逐个审计 → 对每个流程按思维链提问 → Read 代码回答 → 记录发现。
输入: Phase 1.5 业务流程建模。
必读: agent/business_audit.md。

执行序列:
1. 读 Phase 1.5 输出，获取核心业务流程列表
2. 对每个流程，按 business_audit.md 的思维链逐步提问
3. 每个问题 → Read 对应代码 → 回答 → 记录发现
4. 流程审计完成后，做跨流程关联
---End Strategy---
```

## 策略合约: config-driven（配置安全）

```
---Strategy: config-driven---
方法: 搜索配置文件和安全相关代码 → 理解安全机制的设计意图 → 找到配置/实现中的盲区。

核心思路:
- 加密: 开发者选择了什么算法？为什么？有没有用错的地方？密钥怎么管理的？
- 配置: 哪些配置在生产环境不该暴露？开发者有没有忘记关掉调试功能？
- 供应链: 依赖是否有已知 CVE？版本是否在安全范围？

不要背清单。理解每个安全配置的意图，然后找开发者没想到的场景。
---End Strategy---
```

---

## R2+ 增量合约（追加到基础合约后）

```
---R2+ Addendum---
前轮传递:
  COVERED: {已覆盖方向} ← 不再重复
  GAPS: {未覆盖/浅覆盖方向} ← 你的审计目标
  CLEAN: {patterns} ← 直接跳过
  HOTSPOTS: {file:line:断点描述} ← 优先深入
  FILES_READ: {file:conclusion} ← 不再重读
  GREP_DONE: {pattern} ← 不再重复

增量规则: 只审计 GAPS 方向。CLEAN 方向不搜索。
收敛规则: R2+ Agent 禁止输出 UNCHECKED_CANDIDATES。
---End R2+ Addendum---
```

## Semgrep 线索注入模板

当 Phase 1.8 预扫描有结果时，在 Agent Contract 末尾追加:

```
---PRESCAN HOTSPOTS---
来源: {semgrep|bandit|gosec}
总数: {N} findings ({error}E/{warning}W/{info}I)

| # | 文件:行号 | 规则ID | 严重度 | 描述 |
|---|----------|--------|--------|------|
| 1 | src/UserCtrl.java:42 | java.lang.security.sqli | error | SQL拼接 |
| 2 | src/FileService.java:88 | java.lang.security.path-traversal | warning | 路径未校验 |

注意: HOTSPOTS 仅为线索，Agent 必须 Read 代码验证后才能作为发现。
---END PRESCAN HOTSPOTS---
```

---

## Agent 输出模板

```
## Agent: {方向名称} | Round {N} | 发现: {数量}

=== HEADER START ===
COVERAGE: 注入=✅(3,fan=5/12), 认证=⚠️(1,fan=1/8), ...
  sink-driven: fan=已追踪文件数/Grep命中文件数
  control-driven: epr=已验证端点数/矩阵总端点数, crud_types=N
  business-driven: flows=已审计流程数/总流程数, idor_types=N
UNCHECKED: 注入:[orderBy injection]: ORDER BY ${param} | ...
UNFINISHED: {描述}|{原因}, ...
STATS: files_read={N} | grep_patterns={N} | endpoints_audited={N}/{total}
=== HEADER END ===

=== TRANSFER BLOCK START ===
FILES_READ: {file1}:{结论} | {file2}:{结论} | ...
GREP_DONE: {pattern1} | {pattern2} | ...
HOTSPOTS: {file:line:断点描述} | ...
=== TRANSFER BLOCK END ===

### 发现列表

| # | 等级 | 漏洞标题 | 位置 | 关键证据(≤60字) | 数据流 |
|---|------|---------|------|----------------|--------|
| 1 | C | ... | file:line | ... | Source→...→Sink |

### 发现详情（仅 Critical + 高置信 High，每条 ≤5 行）

**[C-01] 标题**
代码: `关键代码片段`
数据流: Source→Transform→Sink
影响: 描述

=== AGENT_OUTPUT_END ===
```

### 输出规范

- HEADER: 覆盖率 + 未检查项 + 统计
- TRANSFER BLOCK: 已读文件 + 已搜索模式 + 热点
- 发现表格: 每条 1 行，不限数量
- 发现详情: Critical + High 完整输出，Medium 简要输出
- 禁止: 大段无关代码、完整文件内容、冗长修复建议
- 不设字数硬限: 以完整表达发现为准，但保持精炼
