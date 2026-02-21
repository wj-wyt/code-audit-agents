# Java 安全检查清单

> Phase 2B 覆盖率验证时按需加载对应 D 段落。

---

## D1: 注入漏洞

### SQL 注入
- [ ] MyBatis `${}` 拼接（`#{}` 是安全的）
- [ ] `@Query` 注解中字符串拼接（Spring Data JPA）
- [ ] `Statement.execute(sql + param)`（应使用 PreparedStatement）
- [ ] `JdbcTemplate.query(sql + param)`（应使用 `?` 占位符）
- [ ] Hibernate `createQuery(hql + param)`（应使用 `setParameter`）
- [ ] ORDER BY / GROUP BY 动态拼接（白名单映射）
- [ ] LIKE 查询未转义 `%` `_`

### 命令注入
- [ ] `Runtime.exec(cmd + param)`
- [ ] `ProcessBuilder` 参数拼接
- [ ] `ScriptEngine.eval(userInput)`
- [ ] `GroovyShell.evaluate(userInput)`

### 表达式注入
- [ ] SpEL: `parser.parseExpression(userInput)`
- [ ] OGNL: `Ognl.getValue(userInput, context)`
- [ ] MVEL: `MVEL.eval(userInput)`
- [ ] EL: `${userInput}` 在 JSP/JSF 中

### LDAP 注入
- [ ] `DirContext.search(filter + param)`（应转义特殊字符）

---

## D4: 反序列化

### Java 原生反序列化
- [ ] `ObjectInputStream.readObject()` 接收不可信数据
- [ ] `XMLDecoder.readObject()` 解析不可信 XML
- [ ] 缺少 `ObjectInputFilter` 白名单（Java 9+）
- [ ] `resolveClass` 未重写限制

### JSON 反序列化
- [ ] Jackson `enableDefaultTyping()` / `ObjectMapper.DefaultTyping`
- [ ] Jackson `@JsonTypeInfo(use=CLASS)` 在不可信输入上
- [ ] Fastjson `JSON.parse()` / `JSON.parseObject()` 启用 autoType
- [ ] Fastjson 版本 < 1.2.83（autoType 绕过）
- [ ] Gson 自定义 TypeAdapter 处理不可信类型

### 其他反序列化
- [ ] Hessian/Burlap 反序列化不可信数据
- [ ] Kryo 反序列化无类白名单
- [ ] XStream 反序列化无安全配置
- [ ] JNDI `InitialContext.lookup(userInput)`（JNDI 注入）

---

## D5: 文件操作

- [ ] `MultipartFile.getOriginalFilename()` 直接用于存储路径
- [ ] `new File(basePath + userInput)` 无路径规范化
- [ ] `Files.readAllBytes(Paths.get(userInput))` 无白名单
- [ ] `ZipEntry.getName()` 含 `../`（Zip Slip）
- [ ] 文件上传仅检查 Content-Type（应检查文件内容/扩展名白名单）
- [ ] 上传目录在 Web 根目录下且可执行

---

## D6: SSRF/XXE

### SSRF
- [ ] `HttpURLConnection` / `HttpClient` + 用户可控 URL
- [ ] `RestTemplate.getForObject(userUrl)`
- [ ] `WebClient.create(userUrl)`
- [ ] URL 白名单可被 DNS Rebinding 绕过
- [ ] 未禁止 `file://` / `gopher://` 协议

### XXE
- [ ] `DocumentBuilderFactory` 未禁用外部实体
- [ ] `SAXParserFactory` 未禁用外部实体
- [ ] `XMLInputFactory` 未禁用外部实体
- [ ] `TransformerFactory` 未禁用外部实体
- [ ] `SchemaFactory` 未禁用外部实体

安全配置:
```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

---

## D7: 加密安全

- [ ] `Cipher.getInstance("DES")` / `"DESede"` / `"RC4"`
- [ ] `Cipher.getInstance("AES/ECB/...")` ECB 模式
- [ ] `MessageDigest.getInstance("MD5")` 用于密码/签名
- [ ] `new SecureRandom(seed)` 固定种子
- [ ] `Math.random()` 用于安全场景
- [ ] 硬编码 AES Key / JWT Secret
- [ ] `TrustManager` 返回空（信任所有证书）
- [ ] `HostnameVerifier` 返回 true（禁用主机名验证）
- [ ] PBKDF2 迭代次数 < 100,000

---

## D8: 安全配置

### Spring Boot
- [ ] `spring.profiles.active=dev` 在生产环境
- [ ] Actuator 端点未限制访问（`/actuator/**`）
- [ ] `server.error.include-stacktrace=always`
- [ ] `spring.h2.console.enabled=true`
- [ ] Swagger UI 在生产环境暴露
- [ ] CORS `allowedOrigins("*")` + `allowCredentials(true)`
- [ ] CSRF 保护被全局禁用 `csrf().disable()`
- [ ] `@CrossOrigin` 注解过于宽泛

### 日志
- [ ] 日志中记录密码/token/密钥
- [ ] Log4j 版本 < 2.17.0（Log4Shell）
- [ ] 用户输入直接进入日志格式字符串
