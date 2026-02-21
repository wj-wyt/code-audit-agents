# Quick-Diff 模式（增量审计）

> 仅 quick-diff 模式加载。适用于 PR Review、CI/CD pipeline 安全门禁。

---

## 触发条件

用户指定 `quick-diff` 模式，或提供 `--diff`/`--pr` 参数。

## 执行流程

### 1. 变更范围获取（hunk 级）

```bash
# 获取变更文件列表
git diff --name-only {base}..{head}

# 获取 hunk 级变更（关键：后续分析基于 hunk，不是整文件）
git diff -U3 {base}..{head} -- {file}
```

如果用户提供了 PR 号: `git diff origin/main...HEAD`

从 diff 输出中提取:
- `added_lines`: 以 `+` 开头的行（新增代码）
- `removed_lines`: 以 `-` 开头的行（删除代码）
- `hunk_context`: 每个 `@@` hunk 的函数/类上下文

### 2. 变更分类

| 类别 | 文件模式 | 安全关注度 |
|------|---------|-----------|
| 源码 | *.java, *.py, *.go, *.php, *.js, *.ts | 高 — 执行完整检查 |
| 配置 | *.yml, *.properties, *.json, *.xml | 高 — 检查安全控制变更 |
| 依赖 | pom.xml, package.json, go.mod, requirements.txt | 高 — 检查 CVE |
| 认证/授权 | *Filter*, *Security*, *Auth*, *Permission* | 最高 — 优先检查 |
| 测试 | test/*, tests/*, *_test.* | 低 — 跳过 |
| 文档 | *.md, docs/* | 跳过 |

### 3. 变更语义分类

对每个 hunk，先判断变更的安全语义（不同语义检查策略不同）:

| 变更语义 | 判定条件 | 安全含义 | 检查策略 |
|---------|---------|---------|---------|
| **新增 Sink** | added_lines 含危险函数调用 | 新攻击面 | → 3a |
| **删除防护** | removed_lines 含校验/过滤/权限检查 | 防护削弱 | → 3b |
| **修改逻辑** | 同一函数内 added+removed 都有 | 逻辑变更可能引入缺陷 | → 3c |
| **新增入口** | added_lines 含路由/端点/Handler 定义 | 新暴露面 | → 3d |
| **参数变更** | 函数签名/参数绑定变化 | 输入面变化 | → 3a+3c |
| **配置变更** | 配置文件的 added/removed | 安全策略变化 | → 3e |

### 3a. 新增 Sink 检测

仅对 added_lines 执行（不是整文件 Grep）:
```
SQL: execute|query|raw|$\{|string\.Format.*sql|拼接.*sql
命令: exec|system|popen|ProcessBuilder|Runtime\.exec|child_process
文件: FileInputStream|open\(|readFile|write|upload|download
SSRF: HttpClient|requests\.get|http\.Get|curl|fetch\(.*url
反序列化: deserialize|readObject|pickle\.load|unserialize|JSON\.parse.*type
模板: render_template_string|Template\(|Velocity|Freemarker
```

命中后: Read 该 hunk 所在函数的完整代码（±30行），追踪参数来源是否用户可控。

### 3b. 删除防护检测

对 removed_lines 检查是否删除了安全控制:
```
认证: @login_required|@authenticated|requireAuth|isAuthenticated|Filter.*auth
授权: @PreAuthorize|@Secured|hasPermission|checkRole|@RequiresPermissions
校验: validate|sanitize|escape|htmlspecialchars|parameterize|prepared
过滤: XssFilter|CsrfFilter|RateLimiter|@Valid|@NotNull|@Size
```

命中后: Read 该函数当前版本，确认删除后是否仍有等效防护。无等效防护 = 高危。

### 3c. 逻辑变更分析

对同一函数内的 added+removed 混合 hunk:
1. Read 变更前后的完整函数（`git show {base}:{file}` vs 当前文件）
2. 对比: 条件分支是否变化？校验逻辑是否放宽？返回值是否改变？
3. 重点关注:
   - `if` 条件从 `&&` 变为 `||`（校验放宽）
   - 异常处理从 `throw` 变为 `catch+continue`（错误吞没）
   - 权限检查条件变化（角色/资源范围扩大）

### 3d. 新增入口检测

对 added_lines 检查是否新增了 API 端点:
```
Java: @RequestMapping|@GetMapping|@PostMapping|@PutMapping|@DeleteMapping
Python: @app.route|@router.get|@api_view|path\(
Go: r.HandleFunc|r.GET|r.POST|gin.Group
PHP: Route::(get|post|put|delete)|->route\(
JS/TS: router\.(get|post|put|delete)|@Get\(|@Post\(
```

命中后: Read 该端点的完整 Handler，检查:
- 有无认证/授权注解？
- 参数是否直接进入 Sink？
- 是否返回敏感数据？

### 3e. 安全配置变更检测

对配置文件的 diff hunk:
```
删除/注释 Filter/中间件 → 认证绕过风险
白名单路径扩大 (permitAll/excludePath 新增条目) → 未授权访问风险
CORS 配置放宽 (allowedOrigins 变为 *) → 跨域攻击风险
DEBUG/开发模式开启 → 信息泄露风险
安全 Header 移除 (CSP/X-Frame-Options) → XSS/Clickjacking 风险
密钥/凭证变更 → 检查是否硬编码、是否降级算法强度
```

### 3f. 依赖变更检测
- 对比变更前后的依赖版本
- 新增依赖: 检查是否有已知 CVE
- 版本降级: 检查降级版本是否有已知漏洞

### 4. 调用链影响分析

对每个变更的函数/类，追踪调用链影响（最多 2 层）:

**Step 4.1: 提取变更符号**
```
从 diff hunk 的 @@ 行和 added_lines 中提取:
- 变更的函数名/方法名
- 变更的类名
- 变更的公共接口（exported/public）
```

**Step 4.2: 向上追溯调用方**
```
Grep 项目代码（排除 test/vendor）:
- 搜索: 变更函数名 → 找到所有调用方文件
- 搜索: 变更类名 + import/require → 找到所有依赖方
```

**Step 4.3: 评估间接影响**

对每个调用方，判断:

| 变更类型 | 调用方影响 | 处理 |
|---------|-----------|------|
| 函数返回值类型/含义变化 | 调用方可能误处理 | Read 调用方相关代码 |
| 函数新增/删除参数 | 调用方可能传错值 | Read 调用方调用点 |
| 共享 Utils/Helper 变更 | 所有调用方受影响 | 列出调用方清单，抽查 ≤5 个 |
| 安全校验函数变更 | 所有依赖该校验的端点受影响 | **必须逐个检查** |
| 数据模型/Entity 字段变更 | 序列化/反序列化/查询受影响 | 检查 Mass Assignment 风险 |
| 中间件/Filter 变更 | 所有经过该中间件的路由受影响 | 检查路由注册，评估影响面 |

**Step 4.4: 跨文件数据流**

如果变更文件是 Service/DAO 层:
1. 向上找 Controller（谁调用了这个 Service？）
2. 向下找 SQL/外部调用（这个 Service 调用了什么 Sink？）
3. 变更是否改变了 Controller→Service→Sink 这条链上的安全属性？

### 5. 报告

仅报告与变更相关的发现，标注:
- `[新增]` — 变更直接引入的漏洞（added_lines 含 Sink + 参数可控）
- `[删除防护]` — 变更删除了安全控制且无等效替代
- `[逻辑变更]` — 变更修改了安全相关逻辑（条件/校验/权限）
- `[新增入口]` — 新端点缺少认证/授权/输入校验
- `[间接影响]` — 变更通过调用链影响了其他文件的安全性
- `[配置削弱]` — 安全配置被削弱
- `[依赖风险]` — 新增/变更依赖引入 CVE

每条发现必须标注:
- 变更 hunk 位置（file:line_range）
- 影响的调用链路径（如有间接影响）
- 变更前后对比（删除防护/逻辑变更类）

## 执行预算

- 不执行 R2，不启动多 Agent
- 单线程 ≤25 turns（含调用链追踪）
- 变更文件 ≤5 个: 每个文件可追踪 2 层调用链
- 变更文件 6-15 个: 仅对高危 hunk 追踪 1 层调用链
- 变更文件 >15 个: 跳过调用链追踪，仅做 hunk 级模式匹配，建议用户切换 standard 模式
- 适合快速反馈，不替代全量审计

## 安全文件变更自动升级建议

当变更文件包含以下安全相关文件时，在报告末尾建议升级为 standard 模式:

| 变更文件模式 | 安全含义 | 建议 |
|------------|---------|------|
| `*Security*`, `*Auth*`, `*Filter*`, `*Guard*` | 认证/授权核心变更 | ⚠️ 建议 standard 模式全量审计认证链 |
| `*Permission*`, `*Role*`, `*Access*` | 权限模型变更 | ⚠️ 建议 standard 模式审计 D3 |
| `*Crypto*`, `*Encrypt*`, `*Key*`, `*Secret*` | 加密/密钥变更 | ⚠️ 建议 standard 模式审计 D7 |
| `application*.yml`, `application*.properties` | 全局配置变更 | ⚠️ 建议 standard 模式审计 D8 |
| `pom.xml`, `package.json`, `go.mod`（大量依赖变更） | 供应链变更 | ⚠️ 建议 standard 模式审计 D10 |
