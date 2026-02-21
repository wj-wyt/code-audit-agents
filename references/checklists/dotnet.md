# .NET/C# 安全检查清单

> Phase 2B 覆盖率验证时按需加载对应 D 段落。

---

## D1: 注入漏洞

### SQL 注入
- [ ] `SqlCommand(sql + param)` 字符串拼接
- [ ] `String.Format(sql, param)` 格式化拼接
- [ ] `$"SELECT ... {param}"` 插值字符串
- [ ] `FromSqlRaw(sql + param)` EF Core 原始查询拼接
- [ ] `ExecuteSqlRaw(sql + param)` EF Core
- [ ] `FromSqlInterpolated($"...")` 是安全的（自动参数化）
- [ ] EF Core LINQ `.Where(x => x.Id == id)` 是安全的
- [ ] Dapper `Query(sql + param)` 拼接（`Query(sql, new { id })` 安全）

### 命令注入
- [ ] `Process.Start(new ProcessStartInfo { FileName = userInput })`
- [ ] `Process.Start("cmd", "/c " + userInput)`
- [ ] `PowerShell.Create().AddScript(userInput)`

### 代码执行
- [ ] `CSharpScript.EvaluateAsync(userInput)` Roslyn 脚本
- [ ] `Assembly.Load(userInput)` 动态加载
- [ ] `Activator.CreateInstance(Type.GetType(userInput))`

### XSS
- [ ] `@Html.Raw(userInput)` 不转义输出
- [ ] `HttpUtility.HtmlDecode()` 后输出
- [ ] Razor `@variable` 是安全的（自动编码）
- [ ] `Content(userInput)` 返回未编码内容

---

## D4: 反序列化

- [ ] `BinaryFormatter.Deserialize(stream)` → RCE
- [ ] `SoapFormatter.Deserialize(stream)` → RCE
- [ ] `ObjectStateFormatter.Deserialize(data)` → RCE（ViewState）
- [ ] `NetDataContractSerializer.ReadObject(reader)` → RCE
- [ ] `LosFormatter.Deserialize(data)` → RCE
- [ ] `XmlSerializer` 类型可控时危险
- [ ] `JavaScriptSerializer.Deserialize()` + TypeResolver
- [ ] `Json.NET` `TypeNameHandling != None` + 不可信输入
- [ ] ViewState 未加密/签名（`__VIEWSTATE` 参数）

安全替代:
```csharp
// 使用 System.Text.Json（默认安全）
JsonSerializer.Deserialize<MyType>(json);
// Json.NET 安全配置
JsonConvert.DeserializeObject<MyType>(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None
});
```

---

## D5: 文件操作

- [ ] `Path.Combine(basePath, userInput)` 未验证结果
- [ ] `File.ReadAllText(userInput)` 路径可控
- [ ] `FileStream(userInput, FileMode.Open)` 路径可控
- [ ] `IFormFile.FileName` 直接用于存储（应重命名）
- [ ] 上传目录在 wwwroot 下且可执行
- [ ] `ZipFile.ExtractToDirectory()` 未检查条目路径

正确的路径校验:
```csharp
var fullPath = Path.GetFullPath(Path.Combine(basePath, userInput));
if (!fullPath.StartsWith(Path.GetFullPath(basePath)))
    throw new SecurityException("Path traversal");
```

---

## D6: SSRF

- [ ] `HttpClient.GetAsync(userUrl)`
- [ ] `WebClient.DownloadString(userUrl)`
- [ ] `HttpWebRequest.Create(userUrl)`
- [ ] `RestClient(userUrl)`（RestSharp）
- [ ] 未禁止私网地址和重定向

---

## D7: 加密安全

- [ ] `DESCryptoServiceProvider` / `TripleDESCryptoServiceProvider`
- [ ] `RC2CryptoServiceProvider`
- [ ] `MD5.Create()` / `SHA1.Create()` 用于密码
- [ ] `RNGCryptoServiceProvider` 已废弃（应使用 `RandomNumberGenerator`）
- [ ] `Random()` 用于安全场景
- [ ] 硬编码密钥在 `appsettings.json` 或源码中
- [ ] `ServicePointManager.ServerCertificateValidationCallback = (s,c,ch,e) => true`

---

## D8: 安全配置

### ASP.NET Core
- [ ] `app.UseDeveloperExceptionPage()` 在生产环境
- [ ] `ASPNETCORE_ENVIRONMENT=Development` 在生产环境
- [ ] CORS `AllowAnyOrigin()` + `AllowCredentials()`
- [ ] 缺少 `app.UseHsts()` / `app.UseHttpsRedirection()`
- [ ] 缺少 `[Authorize]` 全局过滤器
- [ ] `[AllowAnonymous]` 过度使用
- [ ] Swagger 在生产环境暴露
- [ ] Kestrel 直接暴露公网（应使用反向代理）

### 配置泄露
- [ ] `appsettings.json` 含数据库连接字符串（应使用 User Secrets/环境变量）
- [ ] `web.config` 含敏感信息
- [ ] `launchSettings.json` 提交到仓库
