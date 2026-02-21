# D1-D10 覆盖率矩阵

> Phase 2B 覆盖率验证的唯一权威来源。每个维度定义审计策略、核心检查内容、覆盖判定标准。

---

## D1: 注入漏洞

**审计策略**: sink-driven
**核心 Sink 类别**:

| Sink 类别 | 语言/框架 | 危险模式 | 安全模式 |
|-----------|----------|---------|---------|
| SQL 注入 | Java | `Statement.execute(str+var)`, `${}` in MyBatis | `PreparedStatement`, `#{}` in MyBatis |
| SQL 注入 | Python | `cursor.execute(f"...")`, `.extra()`, `.raw()` | `cursor.execute("...?", params)`, `.filter()` |
| SQL 注入 | Go | `db.Query(fmt.Sprintf(...))` | `db.Query("...?", args)` |
| SQL 注入 | PHP | `mysqli_query($sql.$var)`, `DB::raw()` | PDO prepared, Eloquent ORM |
| SQL 注入 | Node | `connection.query(str+var)`, `sequelize.query()` | 参数化查询, ORM 方法 |
| SQL 注入 | .NET | `SqlCommand(str+var)`, `FromSqlRaw(str+var)` | `SqlParameter`, `FromSqlInterpolated` |
| NoSQL 注入 | Node/Python | `{$where: userInput}`, `{"$gt": ""}` | 类型校验, Schema 验证 |
| 命令注入 | 通用 | `exec(userInput)`, `system(str+var)` | 参数数组, 白名单命令 |
| LDAP 注入 | Java/.NET | `search(filter+var)` | 转义特殊字符 |
| XPath 注入 | 通用 | `evaluate(xpath+var)` | 参数化 XPath |
| 表达式注入 | Java | SpEL `parseExpression(var)`, OGNL, MVEL, EL | 白名单, SimpleEvaluationContext |
| ORDER BY 注入 | 通用 | `ORDER BY ${column}` | 白名单列名映射 |

**覆盖判定**:
- ✅ = 所有 Sink 类别均被搜索 + 有数据流追踪 + 扇出率达到动态阈值
- ⚠️ = Sink 类别有遗漏 / 仅 Grep 未追踪
- ❌ = 未搜索

---

## D2: 认证安全

**审计策略**: config-driven
**核心检查内容**:

| 检查项 | 检查方法 | 风险 |
|--------|---------|------|
| JWT 签名算法 | Read JWT 配置 → alg=none? alg=HS256 用公钥? | 认证绕过 |
| JWT 密钥强度 | Read 密钥配置 → 硬编码? 长度<256bit? | 密钥爆破 |
| JWT 过期策略 | Read token 生成 → exp 字段? 刷新机制? | 永久有效 token |
| Session 配置 | Read session 配置 → HttpOnly? Secure? SameSite? | 会话劫持 |
| 密码存储 | Grep password/hash → bcrypt/scrypt/argon2? MD5/SHA1? | 密码泄露 |
| 密码策略 | Read 注册/改密接口 → 长度/复杂度要求? | 弱口令 |
| MFA 实现 | Read MFA 逻辑 → 可绕过? 备用验证弱? | MFA 绕过 |
| 认证绕过路径 | Read Filter 链 → 白名单路径返回敏感数据? | 未授权访问 |
| 登录限流 | Read 登录接口 → 失败锁定? 验证码? | 暴力破解 |
| 密码重置 | Read 重置逻辑 → token 可预测? 绑定用户? 过期? | 任意密码重置 |

**覆盖判定**:
- ✅ = 核心配置项均已检查 + 认证链完整性验证
- ⚠️ = 仅检查部分配置
- ❌ = 未检查

---

## D3: 授权控制

**审计策略**: control-driven
**核心检查内容**:

| 检查项 | 检查方法 | 风险 |
|--------|---------|------|
| 端点鉴权覆盖 | 端点-权限矩阵 → 无权限注解的非公开端点 | 垂直越权 |
| IDOR/水平越权 | Read Service → findById 后有归属校验? | 水平越权 |
| CRUD 一致性 | 同 Controller 的 CRUD 权限对比 | 权限遗漏 |
| 批量操作 | Read batch 接口 → 逐个校验归属? | 批量越权 |
| 数据导出范围 | Read export 接口 → 查询条件受限于当前用户? | 数据泄露 |
| 多租户隔离 | Read DAO → SQL 强制包含 tenant_id? | 跨租户访问 |
| 角色提权 | Read 角色修改接口 → role 参数可控? | 垂直越权 |
| Mass Assignment | Read 实体绑定 → 敏感字段(role/isAdmin)可绑定? | 提权 |

**覆盖判定**:
- ✅ = 端点审计率 ≥ 50%(deep)/30%(standard) + ≥3 种资源类型 CRUD 一致性对比
- ⚠️ = 仅 Grep pattern 未系统枚举端点
- ❌ = 未执行

---

## D4: 反序列化

**审计策略**: sink-driven
**核心 Sink 类别**:

| 语言 | 危险 Sink | 安全替代 |
|------|----------|---------|
| Java | `ObjectInputStream.readObject()`, `XMLDecoder`, `Hessian`, `Kryo` | 白名单类, JSON 序列化 |
| Java | `enableDefaultTyping()`, `@JsonTypeInfo` | 禁用多态, 白名单 |
| Java | `JNDI lookup()`, `InitialContext` | 禁用远程 codebase |
| Python | `pickle.loads()`, `yaml.load()`, `marshal.loads()` | `json.loads()`, `yaml.safe_load()` |
| PHP | `unserialize()`, `phar://` | `json_decode()`, 签名验证 |
| Node | `node-serialize`, `js-yaml.load()` | `JSON.parse()`, `safeLoad()` |
| .NET | `BinaryFormatter`, `SoapFormatter`, `ObjectStateFormatter` | `JsonSerializer`, 白名单 |

**覆盖判定**:
- ✅ = 对应语言的所有 Sink 类别均被搜索 + 有数据流追踪
- ⚠️ = 部分 Sink 类别遗漏
- ❌ = 未搜索

---

## D5: 文件操作

**审计策略**: sink-driven
**核心 Sink 类别**:

| Sink 类别 | 危险模式 | 检查要点 |
|-----------|---------|---------|
| 文件上传 | 用户可控文件名/扩展名/内容 | 后缀白名单? 内容检测? 存储位置? |
| 文件下载 | 用户可控文件路径 | `../` 过滤? 路径白名单? |
| 文件包含 | `include`/`require` + 用户输入 | LFI/RFI, php://filter |
| 路径穿越 | 用户输入拼接文件路径 | 规范化检查? 根目录限制? |
| Zip Slip | 解压用户上传的压缩包 | 条目路径检查? 符号链接? |
| 文件删除 | 用户可控删除路径 | 归属校验? 路径限制? |

**覆盖判定**: 同 D1

---

## D6: SSRF/外部交互

**审计策略**: sink-driven
**核心 Sink 类别**:

| Sink 类别 | 危险模式 | 检查要点 |
|-----------|---------|---------|
| SSRF | HTTP 客户端 + 用户可控 URL | URL 白名单? 禁止私网? 禁止重定向? |
| XXE | XML 解析 + 外部实体 | 禁用 DTD? 禁用外部实体? |
| SSTI | 模板引擎 + 用户输入进入模板 | 沙箱? 白名单函数? |
| 外部 URL 加载 | 图片/文件预览 + 远程 URL | URL 校验? 协议限制? |

**覆盖判定**: 同 D1

---

## D7: 加密安全

**审计策略**: config-driven
**核心检查内容**:

| 检查项 | 危险模式 | 安全基线 |
|--------|---------|---------|
| 对称加密 | DES, 3DES, RC4, ECB 模式 | AES-128+ GCM/CBC+HMAC |
| 哈希算法 | MD5, SHA1 用于密码/签名 | SHA-256+, bcrypt, argon2 |
| 密钥派生 | PBKDF2 迭代<100K, 无 salt | PBKDF2≥100K, salt≥16B |
| 随机数 | `Math.random()`, `rand()`, 时间戳种子 | `SecureRandom`, `/dev/urandom` |
| 硬编码密钥 | 源码中的 AES key, JWT secret | 环境变量, KMS |
| IV/Nonce | 硬编码 IV, GCM nonce 重用 | 随机 IV, 唯一 nonce |
| 证书校验 | 自定义 TrustManager 返回空, 禁用 hostname 验证 | 系统默认 TrustManager |
| TLS 版本 | TLS 1.0/1.1, SSLv3 | TLS 1.2+ |

**覆盖判定**:
- ✅ = 核心配置项均已检查 + 算法/版本已对比基线
- ⚠️ = 仅检查部分
- ❌ = 未检查

---

## D8: 安全配置

**审计策略**: config-driven
**核心检查内容**:

| 检查项 | 危险模式 | 安全基线 |
|--------|---------|---------|
| DEBUG 模式 | `DEBUG=True`, `devtools` 开启 | 生产环境关闭 |
| 错误泄露 | 堆栈信息返回客户端 | 通用错误消息 |
| CORS | `Access-Control-Allow-Origin: *` + 凭证 | 严格白名单 |
| Actuator/监控 | `/actuator`, `/metrics`, `/debug` 公开 | 内网限制或认证 |
| 安全 Header | 缺少 CSP, X-Frame-Options, HSTS | 完整安全头 |
| 默认凭证 | admin/admin, root/root | 强制修改 |
| 日志泄露 | 日志中含密码/token/密钥 | 脱敏处理 |

**覆盖判定**: 同 D7

---

## D9: 业务逻辑

**审计策略**: business-driven
**核心检查内容**:

| 检查项 | 检查方法 | 风险 |
|--------|---------|------|
| 支付金额篡改 | Read 下单接口 → amount 来源 | 零元购/负数支付 |
| 支付回调验证 | Read 回调接口 → 验签+验金额? | 支付绕过 |
| 退款上限 | Read 退款接口 → refund ≤ paid? | 超额退款 |
| 竞态条件 | Read 扣减逻辑 → 行锁/乐观锁? | 重复扣款/领取 |
| 状态跳变 | Read 状态更新 → 前置条件检查? | 流程绕过 |
| 验证码绕过 | Read 验证码校验 → 后端强制? 过期? 次数? | 验证码绕过 |
| IDOR | Read findById → 归属校验? | 水平越权 |

**覆盖判定**:
- ✅ = ≥3 个核心业务流程完成思维链审计 + IDOR 检查覆盖主要 findById
- ⚠️ = 仅 Grep 搜索 pattern 未按业务流程审计
- ❌ = 未执行

---

## D10: 供应链安全

**审计策略**: config-driven
**核心检查内容**:

| 检查项 | 检查方法 | 风险 |
|--------|---------|------|
| 依赖 CVE | 读取依赖清单 → 对比已知 CVE 数据库 | 已知漏洞利用 |
| 不安全版本 | 检查核心依赖版本 → 是否在安全范围 | 版本漏洞 |
| 不活跃依赖 | 检查最后更新时间 → >2年未更新? | 无人维护 |
| 许可证风险 | 检查依赖许可证 → GPL 传染? | 合规风险 |
| 锁文件 | 检查 lock 文件存在且一致 | 供应链攻击 |

**覆盖判定**: 同 D7

---

## 覆盖率汇总模板

```
COVERAGE MATRIX:
D1  注入漏洞    [✅/⚠️/❌] sink-driven   发现: N  扇出率: X/Y
D2  认证安全    [✅/⚠️/❌] config-driven  发现: N  检查项: X/Y
D3  授权控制    [✅/⚠️/❌] control-driven 发现: N  端点率: X/Y
D4  反序列化    [✅/⚠️/❌] sink-driven   发现: N  扇出率: X/Y
D5  文件操作    [✅/⚠️/❌] sink-driven   发现: N  扇出率: X/Y
D6  SSRF/外部   [✅/⚠️/❌] sink-driven   发现: N  扇出率: X/Y
D7  加密安全    [✅/⚠️/❌] config-driven  发现: N  检查项: X/Y
D8  安全配置    [✅/⚠️/❌] config-driven  发现: N  检查项: X/Y
D9  业务逻辑    [✅/⚠️/❌] business-driven 发现: N  流程数: X/Y
D10 供应链安全  [✅/⚠️/❌] config-driven  发现: N  检查项: X/Y
D11 自定义协议  [✅/⚠️/❌/N/A] protocol-driven 发现: N  消息类型: X/Y
D12 AI/LLM集成  [✅/⚠️/❌/N/A] sink-driven    发现: N  扇出率: X/Y
D13 异常条件    [✅/⚠️/❌] sink-driven   发现: N  扇出率: X/Y
D14 身份管理    [✅/⚠️/❌] control-driven 发现: N  检查项: X/Y
```

---

## D11: 自定义协议安全

**审计策略**: protocol-driven
**核心检查内容**:

| 检查项 | 检查方法 | 风险 |
|--------|---------|------|
| 消息身份验证 | 每种消息类型的 sender 字段是否被验证？ | 消息伪造 |
| 字段完整性 | 关键字段（epoch, secret, config）有无签名/MAC？ | 字段篡改 |
| 敏感数据传输 | 密钥/凭证是否在消息中明文传输？ | 信息泄露 |
| 降级攻击 | 安全参数能否被恶意消息降级？ | 安全降级 |
| 协议认证 | 节点加入是否需要认证？ | 未授权接入 |
| 状态变更保护 | 不可逆状态变更是否需要多数确认？ | 单点篡改 |
| 重放保护 | 消息是否有 nonce/序列号防重放？ | 消息重放 |

**覆盖判定**:
- ✅ = 所有消息类型均被遍历 + 身份验证检查 + 敏感数据路径追踪
- ⚠️ = 部分消息类型遗漏 / 仅检查了主要消息类型
- ❌ = 未执行协议审计
- N/A = 项目无自定义协议

---

## D12: AI/LLM 集成安全

> OWASP LLM Top 10 2025。仅当项目集成了 LLM/AI API 时适用。

**审计策略**: sink-driven
**核心检查内容**:

| 检查项 | 检查方法 | 风险 |
|--------|---------|------|
| Prompt 注入 | 用户输入是否直接拼入 system/user prompt？有无输入过滤？ | 指令劫持、数据泄露 |
| 敏感信息泄露 | LLM 上下文中是否包含 API Key/密码/PII？输出是否过滤？ | 凭证/隐私泄露 |
| 过度代理权限 | LLM Agent 绑定的工具/函数权限范围？能否执行危险操作？ | RCE、数据篡改 |
| 输出处理不当 | LLM 输出是否直接渲染为 HTML/SQL/命令？ | XSS、注入、命令执行 |
| 模型投毒 | 训练数据/微调数据来源是否可信？RAG 数据源是否可控？ | 后门、偏差输出 |
| System Prompt 泄露 | 是否有机制防止用户提取 system prompt 内容？ | 业务逻辑泄露 |
| 不安全插件/工具 | LLM 调用的外部工具是否有输入校验和权限隔离？ | 工具链攻击 |

**覆盖判定**:
- ✅ = 所有 LLM 调用点均被审计 + prompt 构建追踪 + 输出处理验证
- ⚠️ = 仅检查部分调用点 / 未追踪 prompt 数据流
- ❌ = 未执行 LLM 安全审计
- N/A = 项目未集成 LLM/AI

---

## D13: 异常条件处理

> OWASP 2025 新增 A10。覆盖未处理异常导致的安全问题。

**审计策略**: sink-driven
**核心检查内容**:

| 检查项 | 检查方法 | 风险 |
|--------|---------|------|
| 未捕获异常泄露 | 异常堆栈/内部路径是否返回给客户端？ | 信息泄露 |
| panic/crash 路径 | 畸形输入能否触发 panic/segfault/未处理异常？ | DoS |
| 错误恢复不完整 | 异常后资源（锁/文件/连接）是否正确释放？ | 资源泄漏、死锁 |
| 整数溢出后续 | 整数溢出后的代码路径是否安全？(C/C++ 重点) | 堆溢出、逻辑错误 |
| NULL 解引用 | 函数返回 NULL 后是否检查？(malloc/realloc/strdup) | 崩溃、DoS |
| 部分失败状态 | 批量操作中途失败时状态是否一致？ | 数据不一致 |
| 超时/重试逻辑 | 外部调用超时后的降级路径是否安全？ | 竞态、重复操作 |

**语言特定检查**:

| 语言 | 重点检查 |
|------|---------|
| C/C++ | malloc 返回 NULL、整数溢出、信号处理中的非异步安全函数 |
| Java | catch(Exception) 吞异常、finally 中的异常、资源未关闭 |
| Go | 忽略 error 返回值、defer panic recovery 掩盖问题 |
| Python | bare except、异常中的敏感信息、上下文管理器缺失 |
| Rust | unwrap()/expect() 在生产代码中、unsafe 块中的 panic |

**覆盖判定**:
- ✅ = 核心异常路径均被审计 + 资源释放验证 + 错误信息泄露检查
- ⚠️ = 仅检查部分异常路径
- ❌ = 未执行异常条件审计

---

## D14: 身份与访问管理（IAM）

> OWASP 2025 A07 拆分深化。覆盖 OAuth/OIDC/API Key/服务间认证等现代身份管理。

**审计策略**: control-driven
**核心检查内容**:

| 检查项 | 检查方法 | 风险 |
|--------|---------|------|
| OAuth/OIDC 配置 | redirect_uri 严格匹配？state 参数防 CSRF？PKCE 启用？ | 账户接管 |
| API Key 管理 | Key 是否可轮换？是否有作用域限制？泄露后能否撤销？ | 持久化未授权访问 |
| 服务间认证 | 微服务间调用是否有 mTLS/JWT/签名？内网是否裸信任？ | 横向移动 |
| Token 生命周期 | Access Token 过期时间？Refresh Token 轮换？注销时 Token 失效？ | 会话持久化 |
| 权限委托 | OAuth scope 是否最小化？是否有 scope 提升路径？ | 权限膨胀 |
| 多因素认证 | MFA 是否可绕过？备用验证方式是否安全？ | MFA 绕过 |
| 会话绑定 | Session 是否绑定设备/IP？并发会话是否有限制？ | 会话劫持 |

**覆盖判定**:
- ✅ = OAuth/API Key/服务间认证均已检查 + Token 生命周期验证
- ⚠️ = 仅检查部分身份管理机制
- ❌ = 未执行 IAM 审计
