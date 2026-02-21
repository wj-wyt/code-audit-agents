# Spring 全家桶安全参考

> 识别到 Spring Boot / Spring MVC / Spring Security / MyBatis 时加载。

---

## Spring Security 配置审计

### Filter 链分析
```java
// 关键: 检查 SecurityFilterChain 配置
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/public/**").permitAll()  // ← 检查每个 permitAll 路径
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        )
        .csrf(csrf -> csrf.disable())  // ← CSRF 禁用原因?
        .cors(cors -> cors.configurationSource(...))  // ← CORS 配置
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
}
```

### 常见配置漏洞

| 配置 | 风险 | 检查方法 |
|------|------|---------|
| `permitAll()` 路径过多 | 未授权访问 | 逐个 Read 对应 Controller |
| `csrf().disable()` | CSRF 攻击 | 是否纯 API（无 Cookie 认证）? |
| `cors().allowedOrigins("*")` | 跨域攻击 | 是否配合 `allowCredentials(true)`? |
| `antMatchers` 顺序错误 | 权限绕过 | 更具体的规则应在前面 |
| `mvcMatchers` vs `antMatchers` | 路径匹配差异 | Spring MVC 路径标准化差异 |
| `@PreAuthorize` SpEL 注入 | RCE | 表达式中是否包含用户输入? |

### 路径匹配陷阱

```java
// antMatchers 不处理尾部斜杠
.antMatchers("/api/admin").hasRole("ADMIN")
// /api/admin/ 可能绕过!

// mvcMatchers 更安全（处理尾部斜杠、扩展名等）
.mvcMatchers("/api/admin").hasRole("ADMIN")

// Spring Boot 3.x 默认使用 requestMatchers（基于 MVC）
```

### 方法级安全

```java
@PreAuthorize("hasRole('ADMIN')")           // 安全
@PreAuthorize("hasPermission(#id, 'read')") // 安全（如果 PermissionEvaluator 正确）
@PreAuthorize("#user.name == authentication.name") // 检查 SpEL 注入

// 常见遗漏: Controller 有注解但 Service 层无归属校验
@GetMapping("/order/{id}")
@PreAuthorize("isAuthenticated()")  // 只检查了认证，没检查归属!
public Order getOrder(@PathVariable Long id) {
    return orderService.findById(id);  // ← IDOR: 任何认证用户可查任何订单
}
```

---

## MyBatis 审计

### 安全 vs 危险

| 语法 | 安全性 | 说明 |
|------|--------|------|
| `#{param}` | ✅ 安全 | 自动 PreparedStatement 参数化 |
| `${param}` | ❌ 危险 | 直接字符串拼接，SQL 注入 |
| `<if test="">` | ⚠️ 检查 | OGNL 表达式，通常安全 |

### 常见 `${}` 使用场景（需逐个验证）

```xml
<!-- 1. ORDER BY — 最常见的合法 ${} 使用，但需要白名单 -->
<select id="list">
    SELECT * FROM orders ORDER BY ${orderBy}  <!-- 危险: 需要白名单映射 -->
</select>

<!-- 2. 表名/列名动态 — 需要白名单 -->
<select id="query">
    SELECT * FROM ${tableName} WHERE ${column} = #{value}
</select>

<!-- 3. LIKE 查询 — 应使用 CONCAT -->
<!-- 危险 -->
<select>SELECT * FROM t WHERE name LIKE '%${keyword}%'</select>
<!-- 安全 -->
<select>SELECT * FROM t WHERE name LIKE CONCAT('%', #{keyword}, '%')</select>

<!-- 4. IN 查询 — 应使用 foreach -->
<!-- 危险 -->
<select>SELECT * FROM t WHERE id IN (${ids})</select>
<!-- 安全 -->
<select>
    SELECT * FROM t WHERE id IN
    <foreach collection="ids" item="id" open="(" separator="," close=")">
        #{id}
    </foreach>
</select>
```

### MyBatis-Plus 注意点
- [ ] `QueryWrapper.apply("col = " + param)` 拼接
- [ ] `QueryWrapper.last("LIMIT " + param)` 拼接
- [ ] `QueryWrapper.eq("col", val)` 是安全的

---

## Spring Boot Actuator

### 危险端点

| 端点 | 风险 | 默认状态 |
|------|------|---------|
| `/actuator/env` | 泄露环境变量/配置 | 需认证 |
| `/actuator/heapdump` | 泄露内存数据（含密钥） | 需认证 |
| `/actuator/mappings` | 泄露所有 API 路由 | 需认证 |
| `/actuator/beans` | 泄露所有 Bean 信息 | 需认证 |
| `/actuator/configprops` | 泄露配置属性 | 需认证 |
| `/actuator/jolokia` | JMX 操作 → RCE | 需认证 |
| `/actuator/gateway/routes` | Spring Cloud Gateway 路由 | 需认证 |
| `/actuator/health` | 健康检查 | 公开 |
| `/actuator/info` | 应用信息 | 公开 |

### 检查配置
```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: health,info  # 只暴露必要端点
  endpoint:
    health:
      show-details: never  # 不泄露详细信息
```

---

## Spring Data JPA 审计

### 安全 vs 危险

| 方法 | 安全性 |
|------|--------|
| `findById(id)` | ✅ 安全（参数化） |
| `findByUsername(name)` | ✅ 安全（方法名查询） |
| `@Query("SELECT u FROM User u WHERE u.name = :name")` | ✅ 安全（命名参数） |
| `@Query("SELECT u FROM User u WHERE u.name = " + name)` | ❌ 编译错误（注解不支持拼接） |
| `@Query(value = "...", nativeQuery = true)` | ⚠️ 检查原生 SQL |
| `entityManager.createQuery(hql + param)` | ❌ 危险 |
| `entityManager.createNativeQuery(sql + param)` | ❌ 危险 |
| `JpaSpecificationExecutor` | ✅ 安全（Criteria API） |

---

## Spring MVC 参数绑定

### Mass Assignment
```java
// 危险: 直接绑定 Entity
@PostMapping("/user/update")
public void update(@RequestBody User user) {
    userService.save(user);  // user.role 可被篡改!
}

// 安全: 使用 DTO
@PostMapping("/user/update")
public void update(@RequestBody UserUpdateDTO dto) {
    // DTO 只包含允许修改的字段
}
```

### 参数校验
```java
// 检查 @Valid 是否存在
@PostMapping("/register")
public void register(@Valid @RequestBody RegisterDTO dto) { ... }

// 检查 DTO 上的校验注解
public class RegisterDTO {
    @NotBlank @Size(min=3, max=50) private String username;
    @NotBlank @Size(min=8) private String password;
    @Email private String email;
    // 没有 role 字段 → 防止 Mass Assignment
}
```

---

## 常见 Spring 漏洞模式

| 模式 | 漏洞 | 检查 |
|------|------|------|
| `@PathVariable` 直接进入 SQL | SQL 注入 | 检查 Service/DAO 层 |
| `@RequestParam` 进入 `redirect:` | 开放重定向 | 检查重定向 URL 校验 |
| `@RequestBody` 绑定 Entity | Mass Assignment | 检查是否使用 DTO |
| `MultipartFile` 存储路径可控 | 路径穿越 | 检查文件名处理 |
| `RestTemplate` URL 拼接 | SSRF | 检查 URL 来源 |
| `@Cacheable` key 拼接 | 缓存投毒 | 检查 key 生成逻辑 |
