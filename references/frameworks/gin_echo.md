# Gin / Echo / Fiber 安全参考

> 识别到 Gin / Echo / Fiber 时加载。

---

## Gin 安全审计

### 路由与中间件

```go
// 中间件顺序
r := gin.Default() // 包含 Logger + Recovery
r.Use(cors.Default())
r.Use(authMiddleware())
r.Use(rateLimiter())

// 路由组
public := r.Group("/api/public")
{
    public.POST("/login", loginHandler)
    public.POST("/register", registerHandler)
}

auth := r.Group("/api", authMiddleware())
{
    auth.GET("/profile", profileHandler)
    auth.PUT("/profile", updateProfileHandler)
}

admin := r.Group("/api/admin", authMiddleware(), adminMiddleware())
{
    admin.GET("/users", listUsersHandler)
}
```

### 常见漏洞模式

| 漏洞 | 危险代码 | 安全替代 |
|------|---------|---------|
| SQL 注入 | `db.Where(fmt.Sprintf("name='%s'", name))` | `db.Where("name = ?", name)` |
| 路径穿越 | `c.File(c.Query("path"))` | `filepath.Join` + 前缀检查 |
| XSS | `c.Writer.WriteString(userInput)` | `c.HTML()` 模板渲染 |
| SSRF | `http.Get(c.Query("url"))` | URL 白名单 |
| 信息泄露 | `c.JSON(500, gin.H{"error": err.Error()})` | 通用错误消息 |

### Gin 特有检查
- [ ] `gin.SetMode(gin.ReleaseMode)` 生产环境
- [ ] `c.ShouldBindJSON(&obj)` 绑定到含敏感字段的结构体（Mass Assignment）
- [ ] `c.SaveUploadedFile()` 文件名可控
- [ ] `c.Redirect()` 目标 URL 可控
- [ ] `trusted proxies` 配置（`r.SetTrustedProxies()`）
- [ ] `c.ClientIP()` 在无 trusted proxy 时可伪造

### GORM 安全

```go
// 安全
db.Where("name = ?", name).Find(&users)
db.Where(&User{Name: name}).Find(&users)
db.First(&user, id)

// 危险
db.Where(fmt.Sprintf("name = '%s'", name)).Find(&users)
db.Raw("SELECT * FROM users WHERE name = '" + name + "'").Scan(&users)
db.Order(userInput).Find(&users)  // ORDER BY 注入

// GORM 注意点
// db.Where(map[string]interface{}{...}) 是安全的
// db.Where("name = ? AND age > ?", name, age) 是安全的
// db.Exec(sql + param) 是危险的
```

---

## Echo 安全审计

### 中间件配置

```go
e := echo.New()
e.Use(middleware.Logger())
e.Use(middleware.Recover())
e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
    AllowOrigins: []string{"https://example.com"},
    AllowCredentials: true,
}))
e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20)))
e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
    XSSProtection:         "1; mode=block",
    ContentTypeNosniff:    "nosniff",
    XFrameOptions:         "DENY",
    HSTSMaxAge:            31536000,
    ContentSecurityPolicy: "default-src 'self'",
}))
```

### Echo 特有检查
- [ ] `e.Debug = true` 生产环境
- [ ] `middleware.CORS()` 默认允许所有来源
- [ ] `c.Bind(&obj)` 绑定到含敏感字段的结构体
- [ ] `c.File(path)` / `c.Attachment(path)` 路径可控
- [ ] `c.Redirect()` 目标可控
- [ ] JWT 中间件配置（`middleware.JWT()`）
- [ ] `c.RealIP()` 在无 proxy 配置时可伪造

---

## Fiber 安全审计

### 中间件配置

```go
app := fiber.New(fiber.Config{
    ErrorHandler: customErrorHandler, // 自定义错误处理
    BodyLimit:    4 * 1024 * 1024,    // 请求体大小限制
})

app.Use(cors.New(cors.Config{
    AllowOrigins:     "https://example.com",
    AllowCredentials: true,
}))
app.Use(limiter.New(limiter.Config{
    Max:        20,
    Expiration: 30 * time.Second,
}))
app.Use(helmet.New())
app.Use(csrf.New())
```

### Fiber 特有检查
- [ ] `c.BodyParser(&obj)` 绑定安全
- [ ] `c.SendFile(path)` 路径可控
- [ ] `c.Redirect(url)` 目标可控
- [ ] `c.IP()` / `c.IPs()` 可伪造
- [ ] `app.Static()` 配置
- [ ] WebSocket 升级无认证

---

## 通用 Go Web 安全检查

### SQL 注入防护
```go
// 安全: 使用占位符
db.Query("SELECT * FROM users WHERE id = ?", id)
db.Exec("INSERT INTO users (name) VALUES (?)", name)

// 危险: 字符串拼接
db.Query("SELECT * FROM users WHERE id = " + id)
db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))

// 安全: sqlx 命名参数
db.NamedExec("INSERT INTO users (name) VALUES (:name)", map[string]interface{}{"name": name})
```

### 路径穿越防护
```go
// 正确的路径校验
func safePath(basePath, userInput string) (string, error) {
    // 1. 拼接路径
    fullPath := filepath.Join(basePath, userInput)
    // 2. 规范化
    fullPath = filepath.Clean(fullPath)
    // 3. 检查前缀
    if !strings.HasPrefix(fullPath, filepath.Clean(basePath)+string(os.PathSeparator)) {
        return "", fmt.Errorf("path traversal attempt")
    }
    return fullPath, nil
}
```

### 竞态条件
```go
// 检查共享状态是否有锁保护
// go run -race ./... 检测竞态

// 危险: 无锁的共享 map
var cache = make(map[string]interface{})
func handler(c *gin.Context) {
    cache[key] = value  // 并发写 → panic
}

// 安全: sync.RWMutex 或 sync.Map
var cache sync.Map
```

### 模板安全
```go
// html/template 自动转义（安全）
tmpl := template.Must(template.ParseFiles("page.html"))

// text/template 不转义（危险用于 HTML）
tmpl := text_template.Must(text_template.ParseFiles("page.html"))

// 危险: template.HTML() 标记为安全
template.HTML(userInput)  // 绕过转义 → XSS
```
