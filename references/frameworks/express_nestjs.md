# Express / NestJS / Koa 安全参考

> 识别到 Express / NestJS / Koa 时加载。

---

## Express 安全审计

### 中间件安全

```javascript
// 必要的安全中间件
const helmet = require('helmet');       // 安全头
const cors = require('cors');           // CORS
const rateLimit = require('express-rate-limit'); // 速率限制
const csrf = require('csurf');          // CSRF（如果使用 Cookie 认证）

app.use(helmet());
app.use(cors({ origin: 'https://example.com', credentials: true }));
app.use(rateLimit({ windowMs: 15*60*1000, max: 100 }));
```

### 常见漏洞模式

| 漏洞 | 危险代码 | 安全替代 |
|------|---------|---------|
| 路径穿越 | `res.sendFile(req.query.file)` | `res.sendFile(file, { root: safeDir })` |
| XSS | `res.send(req.query.name)` | 模板引擎自动转义 |
| 原型污染 | `Object.assign(config, req.body)` | 白名单字段 |
| NoSQL 注入 | `User.find(req.body)` | 类型校验 + Schema |
| SSRF | `axios.get(req.body.url)` | URL 白名单 |
| 开放重定向 | `res.redirect(req.query.next)` | URL 白名单 |

### Express 特有检查
- [ ] `trust proxy` 设置（影响 `req.ip`、速率限制）
- [ ] `express.json({ limit })` 大小限制（默认 100kb）
- [ ] `express.urlencoded({ extended: true })` 嵌套对象（原型污染风险）
- [ ] 错误处理中间件是否泄露堆栈
- [ ] `express.static()` 是否暴露敏感文件
- [ ] `res.jsonp()` JSONP 回调注入

### 认证中间件检查
```javascript
// 检查认证中间件是否覆盖所有路由
app.use('/api/public', publicRouter);     // 无认证
app.use('/api', authMiddleware, apiRouter); // 有认证

// 危险: 路由顺序错误
app.use('/api', apiRouter);               // 先注册 → 无认证!
app.use('/api', authMiddleware);           // 后注册 → 不生效
```

---

## NestJS 安全审计

### Guard 和 Interceptor
```typescript
// 全局 Guard
app.useGlobalGuards(new AuthGuard());

// Controller 级 Guard
@UseGuards(AuthGuard, RolesGuard)
@Controller('admin')
export class AdminController { ... }

// 方法级 Guard
@UseGuards(AuthGuard)
@Get('profile')
getProfile() { ... }

// 检查: 是否有路由缺少 Guard?
// 检查: @Public() 装饰器是否过度使用?
```

### DTO 验证
```typescript
// 安全: 使用 class-validator + class-transformer
@Post('register')
register(@Body(ValidationPipe) dto: CreateUserDto) { ... }

// CreateUserDto 应该:
// 1. 只包含允许的字段（白名单）
// 2. 使用 @IsString() @IsEmail() 等装饰器
// 3. 不包含 role/isAdmin 等敏感字段

// 全局启用白名单模式
app.useGlobalPipes(new ValidationPipe({
    whitelist: true,        // 自动剥离未定义的属性
    forbidNonWhitelisted: true, // 有未定义属性时报错
    transform: true,
}));
```

### NestJS 特有检查
- [ ] `@Public()` / `@SkipAuth()` 装饰器使用范围
- [ ] `ConfigService` 是否泄露敏感配置
- [ ] `TypeORM` 查询是否有拼接
- [ ] `Prisma` 原始查询是否有拼接
- [ ] WebSocket Gateway 是否有认证
- [ ] GraphQL Resolver 是否有授权检查
- [ ] `@Param()` / `@Query()` 类型转换

---

## Koa 安全审计

### 中间件顺序
```javascript
// Koa 中间件是洋葱模型，顺序很重要
app.use(errorHandler);      // 最外层: 错误处理
app.use(helmet());           // 安全头
app.use(cors(corsOptions));  // CORS
app.use(rateLimit(options)); // 速率限制
app.use(bodyParser());       // 请求体解析
app.use(authMiddleware);     // 认证
app.use(router.routes());   // 路由
```

### Koa 特有检查
- [ ] `ctx.body = userInput` 直接输出（XSS）
- [ ] `koa-body` / `koa-bodyparser` 大小限制
- [ ] `koa-static` 配置（是否暴露敏感文件）
- [ ] `ctx.redirect(userInput)` 开放重定向
- [ ] 错误处理是否泄露堆栈信息

---

## 通用 Node.js 安全检查

### 原型污染防护
```javascript
// 危险的对象合并
const merged = { ...defaults, ...userInput };
// 如果 userInput = JSON.parse('{"__proto__":{"isAdmin":true}}')
// 不会污染（展开运算符安全）

// 危险
lodash.merge(target, userInput);      // 深度合并 → 污染
lodash.set(obj, userPath, userValue); // 路径可控 → 污染

// 安全
Object.create(null);                  // 无原型对象
Object.freeze(Object.prototype);      // 冻结原型（可能破坏兼容性）
```

### JWT 安全
```javascript
// 危险: 不指定算法
jwt.verify(token, secret);

// 安全: 明确指定算法
jwt.verify(token, secret, { algorithms: ['HS256'] });

// 危险: RS256 公钥 + HS256 混淆攻击
// 攻击者用公钥作为 HS256 密钥签名
jwt.verify(token, publicKey); // 如果不限制算法 → 绕过
```

### 依赖安全
- [ ] `npm audit` / `yarn audit` 高危漏洞
- [ ] `package-lock.json` 是否提交
- [ ] `postinstall` 脚本是否安全
- [ ] 是否使用已废弃的包（`request`, `crypto`）
- [ ] `node_modules` 是否意外提交
