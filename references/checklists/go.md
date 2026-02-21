# Go 安全检查清单

> Phase 2B 覆盖率验证时按需加载对应 D 段落。

---

## D1: 注入漏洞

### SQL 注入
- [ ] `db.Query(fmt.Sprintf("SELECT ... %s", param))` 字符串拼接
- [ ] `db.Exec("DELETE FROM t WHERE id=" + param)`
- [ ] `db.Query("SELECT ... ?", param)` 是安全的（占位符）
- [ ] GORM `.Where(fmt.Sprintf(...))` 拼接（`.Where("id = ?", id)` 安全）
- [ ] GORM `.Raw(sql + param)` 拼接
- [ ] sqlx `.Select(&result, sql+param)`
- [ ] ORDER BY / LIMIT 动态拼接

### 命令注入
- [ ] `exec.Command("sh", "-c", userInput)`（shell 执行用户输入）
- [ ] `exec.Command(userInput)`（命令名可控）
- [ ] `exec.Command("cmd", "/c", userInput)`（Windows）
- [ ] `exec.Command("ls", "-la", userInput)` 参数注入

### 模板注入
- [ ] `template.HTML(userInput)` 标记为安全 HTML（绕过转义）
- [ ] `template.JS(userInput)` 标记为安全 JS
- [ ] `template.URL(userInput)` 标记为安全 URL
- [ ] `text/template` 无自动转义（应使用 `html/template`）

---

## D4: 反序列化

- [ ] `encoding/gob` 解码不可信数据
- [ ] `encoding/xml` 未限制实体扩展
- [ ] 自定义 `UnmarshalJSON` 中的不安全操作
- [ ] `json.Unmarshal` 到 `interface{}` 后不安全类型断言

---

## D5: 文件操作

- [ ] `filepath.Join(base, userInput)` 未检查结果是否在 base 下
- [ ] `os.Open(userInput)` 无路径白名单
- [ ] `http.ServeFile(w, r, userInput)` 路径可控
- [ ] `io.Copy(file, request.Body)` 无大小限制
- [ ] `archive/zip` 解压未检查条目路径
- [ ] `archive/tar` 解压未检查条目路径和符号链接

正确的路径校验:
```go
absPath := filepath.Join(baseDir, userInput)
if !strings.HasPrefix(absPath, filepath.Clean(baseDir)+string(os.PathSeparator)) {
    return errors.New("path traversal")
}
```

---

## D6: SSRF

- [ ] `http.Get(userUrl)` / `http.Post(userUrl, ...)`
- [ ] `http.NewRequest("GET", userUrl, nil)`
- [ ] 未禁止私网地址（127.0.0.1, 10.x, 172.16-31.x, 192.168.x）
- [ ] 未禁止重定向到私网
- [ ] 未限制协议（`file://`）

---

## D7: 加密安全

- [ ] `crypto/des` 使用 DES 算法
- [ ] `crypto/rc4` 使用 RC4
- [ ] `crypto/md5` / `crypto/sha1` 用于密码/签名
- [ ] `math/rand` 用于安全场景（应使用 `crypto/rand`）
- [ ] 硬编码密钥/IV
- [ ] `tls.Config{InsecureSkipVerify: true}`

---

## D8: 安全配置

### Gin/Echo/Fiber
- [ ] `gin.SetMode(gin.DebugMode)` 在生产环境
- [ ] CORS `AllowAllOrigins: true` + `AllowCredentials: true`
- [ ] 缺少速率限制中间件
- [ ] pprof 端点公开（`/debug/pprof/`）
- [ ] 错误信息直接返回客户端（`c.JSON(500, err.Error())`）
- [ ] 缺少 CSRF 保护

### 内存安全
- [ ] `unsafe.Pointer` 使用不当
- [ ] `reflect.SliceHeader` / `reflect.StringHeader` 不安全转换
- [ ] CGO 中的缓冲区溢出
- [ ] 竞态条件（`go run -race` 检测）
