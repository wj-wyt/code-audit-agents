# JavaScript/Node.js 安全检查清单

> Phase 2B 覆盖率验证时按需加载对应 D 段落。

---

## D1: 注入漏洞

### SQL 注入
- [ ] `connection.query("SELECT ... " + param)` 字符串拼接
- [ ] `sequelize.query("SELECT ... " + param)` 原始查询拼接
- [ ] `knex.raw("SELECT ... " + param)` 拼接
- [ ] Sequelize `.where()` / Prisma 参数化是安全的
- [ ] `knex("table").where("col", val)` 是安全的
- [ ] TypeORM `createQueryBuilder().where("col = " + param)` 拼接

### NoSQL 注入
- [ ] MongoDB `{ $where: userInput }` JavaScript 执行
- [ ] `{ username: { $gt: "" } }` 操作符注入
- [ ] `{ $regex: userInput }` 正则注入（ReDoS）
- [ ] Mongoose `.find(req.body)` 直接传入请求体
- [ ] 类型校验缺失（字符串 vs 对象）

### 命令注入
- [ ] `child_process.exec(cmd + param)`（shell 执行）
- [ ] `child_process.execSync(cmd + param)`
- [ ] `child_process.spawn(cmd, {shell: true})`
- [ ] `child_process.execFile(cmd, [args])` 是相对安全的

### 代码执行
- [ ] `eval(userInput)`
- [ ] `new Function(userInput)()`
- [ ] `vm.runInContext(userInput)` / `vm.runInNewContext(userInput)`
- [ ] `setTimeout(userInput, 0)` / `setInterval(userInput, 0)` 字符串参数
- [ ] `require(userInput)` 动态加载

---

## D4: 原型污染 + 反序列化

### 原型污染
- [ ] `Object.assign(target, userInput)` 含 `__proto__`
- [ ] `lodash.merge(target, userInput)` 深度合并
- [ ] `lodash.set(obj, path, value)` path 可控
- [ ] `JSON.parse(userInput)` 后直接合并到对象
- [ ] `for (key in obj)` 遍历被污染的对象
- [ ] `obj[userInput] = value` 属性名可控

检测模式:
```javascript
// 危险
const merged = { ...defaults, ...userInput };
// 如果 userInput = {"__proto__": {"isAdmin": true}}
```

### 反序列化
- [ ] `node-serialize` 的 `unserialize()` → RCE
- [ ] `js-yaml.load()` 默认不安全（应使用 `safeLoad()`）
- [ ] `serialize-javascript` 的 `deserialize()` 不安全输入

---

## D5: 文件操作

- [ ] `path.join(base, userInput)` 未验证结果在 base 下
- [ ] `fs.readFile(userInput)` 路径可控
- [ ] `res.sendFile(userInput)` 路径可控
- [ ] `express.static()` 配置不当
- [ ] `multer` 上传目标路径/文件名可控
- [ ] `adm-zip` / `unzipper` 解压未检查路径

---

## D6: SSRF

- [ ] `axios.get(userUrl)` / `axios.post(userUrl)`
- [ ] `fetch(userUrl)`（Node 18+ 内置）
- [ ] `http.get(userUrl)` / `https.get(userUrl)`
- [ ] `request(userUrl)`（已废弃但仍广泛使用）
- [ ] `got(userUrl)`
- [ ] URL 解析差异（`new URL()` vs `url.parse()`）

---

## D7: 加密安全

- [ ] `crypto.createHash('md5')` / `crypto.createHash('sha1')` 用于密码
- [ ] `Math.random()` 用于安全场景（应使用 `crypto.randomBytes()`）
- [ ] `crypto.createCipher()` 已废弃（应使用 `createCipheriv()`）
- [ ] 硬编码密钥/JWT Secret
- [ ] `jsonwebtoken` 的 `algorithms` 未限制（算法混淆攻击）
- [ ] JWT `verify()` 未指定 `algorithms` 选项

---

## D8: 安全配置

### Express/NestJS
- [ ] 缺少 `helmet` 中间件（安全头）
- [ ] CORS `origin: '*'` + `credentials: true`
- [ ] 缺少速率限制（`express-rate-limit`）
- [ ] `express.json({ limit: '100mb' })` 过大（DoS）
- [ ] 错误中间件泄露堆栈信息
- [ ] `trust proxy` 配置不当
- [ ] 缺少 CSRF 保护（`csurf` / 自定义）

### 依赖安全
- [ ] `npm audit` 有高危漏洞
- [ ] `package-lock.json` 未提交
- [ ] 使用已废弃的包（`request`, `crypto`）
- [ ] `postinstall` 脚本执行不可信代码

### ReDoS
- [ ] 用户输入进入正则表达式
- [ ] 嵌套量词: `(a+)+`, `(a|a)+`, `(a*)*`
- [ ] 回溯爆炸: `^(a+)+$` 匹配 `aaaaaaaaaaaaaaaaX`
