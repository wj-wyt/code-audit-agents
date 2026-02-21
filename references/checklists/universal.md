# 通用安全检查清单

> 适用于所有语言和框架的通用安全检查项。D2/D7/D8/D10 审计时加载。

---

## 认证安全（D2 通用项）

### 密码存储
- [ ] 使用 bcrypt/scrypt/argon2id（不是 MD5/SHA1/SHA256）
- [ ] salt 随机生成且 ≥16 字节
- [ ] bcrypt cost ≥ 10 / argon2 memory ≥ 64MB

### JWT 安全
- [ ] 签名算法不是 none
- [ ] HS256 密钥 ≥ 256 bit
- [ ] RS256 使用 2048+ bit RSA
- [ ] 验证 exp 过期时间
- [ ] 验证 iss/aud 声明
- [ ] 刷新 token 机制安全（单独存储、可撤销）
- [ ] 不在 JWT payload 中存储敏感信息

### Session 安全
- [ ] Cookie 设置 HttpOnly
- [ ] Cookie 设置 Secure（HTTPS）
- [ ] Cookie 设置 SameSite=Lax/Strict
- [ ] Session ID 足够随机（≥128 bit 熵）
- [ ] 登录后重新生成 Session ID
- [ ] 登出时销毁服务端 Session
- [ ] Session 超时合理（≤30min 空闲）

### 登录安全
- [ ] 失败锁定（≥5 次失败后锁定/延迟）
- [ ] 验证码（图形/滑块/短信）
- [ ] 不泄露用户是否存在（统一错误消息）
- [ ] 登录日志记录（IP、时间、结果）

### 密码重置
- [ ] 重置 token 不可预测（UUID v4 / 安全随机）
- [ ] token 绑定用户（不可替换）
- [ ] token 有过期时间（≤30min）
- [ ] token 一次性使用
- [ ] 不在 URL 中泄露 token（Referer 泄露）

---

## 授权控制（D3 通用项）

### RBAC/ABAC
- [ ] 权限检查在服务端执行（不依赖前端隐藏）
- [ ] 每个非公开端点都有权限注解/中间件
- [ ] 权限检查不可被参数篡改绕过
- [ ] 角色层级正确（子角色不超过父角色权限）

### IDOR 防护
- [ ] 资源访问时校验归属关系（userId/tenantId）
- [ ] 不使用可预测的资源 ID（自增 ID → UUID）
- [ ] 批量操作逐个校验归属
- [ ] 数据导出限制范围

### CORS
- [ ] `Access-Control-Allow-Origin` 不是 `*`（带凭证时）
- [ ] Origin 白名单严格匹配（不是 contains/endsWith）
- [ ] 不暴露敏感 Header
- [ ] preflight 缓存合理

### CSRF
- [ ] 状态变更操作使用 CSRF Token
- [ ] Token 绑定 Session
- [ ] SameSite Cookie 作为额外防护
- [ ] 不依赖 Referer 检查作为唯一防护

---

## 加密安全（D7 通用项）

### 对称加密
- [ ] AES-128/256（不是 DES/3DES/RC4）
- [ ] GCM 模式（不是 ECB）
- [ ] CBC 模式配合 HMAC
- [ ] IV 随机生成（不是硬编码/全零）
- [ ] GCM nonce 不重用

### 非对称加密
- [ ] RSA ≥ 2048 bit
- [ ] ECDSA ≥ P-256
- [ ] RSA-OAEP（不是 PKCS1v1.5 加密）
- [ ] RSA-PSS（不是 PKCS1v1.5 签名，推荐）

### 哈希
- [ ] 密码: bcrypt/scrypt/argon2（不是 MD5/SHA）
- [ ] 完整性: SHA-256+（不是 MD5/SHA1）
- [ ] HMAC 用于消息认证

### 随机数
- [ ] 安全随机数生成器（不是 Math.random/rand）
- [ ] Token/密钥/IV/salt 使用安全随机

### 密钥管理
- [ ] 密钥不硬编码在源码中
- [ ] 密钥通过环境变量/KMS/Vault 管理
- [ ] 密钥轮换机制
- [ ] 不同环境使用不同密钥

---

## 安全配置（D8 通用项）

### HTTP 安全头
- [ ] `Content-Security-Policy` 限制脚本来源
- [ ] `X-Frame-Options: DENY/SAMEORIGIN`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `Strict-Transport-Security` (HSTS)
- [ ] `Referrer-Policy: strict-origin-when-cross-origin`

### 错误处理
- [ ] 生产环境不返回堆栈信息
- [ ] 统一错误响应格式
- [ ] 不泄露内部路径/版本/技术栈
- [ ] 数据库错误不直接返回客户端

### 日志安全
- [ ] 不记录密码/token/密钥
- [ ] 敏感数据脱敏（手机号/身份证/银行卡）
- [ ] 日志注入防护（换行符过滤）
- [ ] 日志文件权限限制

### 调试接口
- [ ] 生产环境关闭 DEBUG 模式
- [ ] Actuator/metrics/pprof 需要认证或内网限制
- [ ] Swagger/API 文档不在生产环境暴露
- [ ] 数据库管理工具（phpMyAdmin 等）不公开

### 部署安全
- [ ] HTTPS 强制（HTTP 重定向到 HTTPS）
- [ ] TLS 1.2+（禁用 SSLv3/TLS1.0/1.1）
- [ ] 不使用默认凭证
- [ ] 文件上传目录不可执行
- [ ] 目录列表关闭

---

## 供应链安全（D10 通用项）

### 依赖管理
- [ ] 使用锁文件（package-lock.json/Pipfile.lock/go.sum）
- [ ] 定期检查依赖 CVE（npm audit/pip-audit/govulncheck）
- [ ] 核心依赖版本在安全范围内
- [ ] 不使用已废弃/不维护的依赖

### 构建安全
- [ ] CI/CD 不泄露密钥（日志/环境变量）
- [ ] Docker 镜像使用固定版本（不是 latest）
- [ ] 最小化容器权限（非 root 运行）
- [ ] 依赖来源可信（官方仓库）
