# Rust 安全检查清单

> Phase 2B 覆盖率验证时按需加载对应 D 段落。

---

## D1: 注入漏洞

### SQL 注入
- [ ] `format!("SELECT ... {}", param)` 拼接 SQL
- [ ] `query(&format!("SELECT ... {}", param))` 拼接
- [ ] `sqlx::query("SELECT ... ?").bind(param)` 是安全的（参数化）
- [ ] `diesel` ORM 查询是安全的（编译期检查）
- [ ] `sea-orm` 参数化查询是安全的
- [ ] `rusqlite` `execute(sql, params![val])` 是安全的

### 命令注入
- [ ] `Command::new("sh").arg("-c").arg(user_input)` shell 执行用户输入
- [ ] `Command::new(user_input)` 命令名可控
- [ ] `Command::new("cmd").args(["/c", &user_input])` Windows
- [ ] `Command::new("ls").arg(user_input)` 参数注入

### 模板注入
- [ ] `tera` 模板引擎用户输入作为模板内容
- [ ] `askama` 编译期模板（安全）
- [ ] `handlebars` 用户输入作为模板

---

## D4: 反序列化

- [ ] `serde_json::from_str::<Value>(user_input)` 到 `Value` 后不安全类型转换
- [ ] `bincode::deserialize(user_input)` 不可信二进制数据
- [ ] `serde_yaml::from_str(user_input)` YAML 解析
- [ ] `rmp-serde` MessagePack 反序列化不可信数据
- [ ] 自定义 `Deserialize` 实现中的不安全操作
- [ ] `serde` 默认是安全的（无多态类型），但自定义 `#[serde(tag)]` 需检查

---

## D5: 文件操作

- [ ] `std::fs::read_to_string(user_input)` 路径可控
- [ ] `std::fs::File::open(user_input)` 路径可控
- [ ] `Path::new(base).join(user_input)` 未验证结果在 base 下
- [ ] `std::fs::remove_file(user_input)` 删除路径可控
- [ ] `zip` crate 解压未检查条目路径（Zip Slip）
- [ ] `tar` crate 解压未检查条目路径和符号链接

正确的路径校验:
```rust
let full_path = base_dir.join(user_input).canonicalize()?;
if !full_path.starts_with(base_dir.canonicalize()?) {
    return Err("path traversal");
}
```

---

## D6: SSRF

- [ ] `reqwest::get(user_url)` URL 可控
- [ ] `hyper::Client::get(user_url)` URL 可控
- [ ] `ureq::get(user_url)` URL 可控
- [ ] 未禁止私网地址和 `file://` 协议
- [ ] 未禁止重定向到私网

---

## D7: 加密安全

- [ ] `rand::thread_rng()` 是安全的（CSPRNG）
- [ ] `rand::rngs::SmallRng` 不安全（非密码学）
- [ ] 硬编码密钥/IV 在源码中
- [ ] `ring` / `rustls` 是推荐的加密库
- [ ] `openssl` crate 配置不当
- [ ] `md-5` / `sha-1` crate 用于密码/签名

---

## D8: 安全配置

### Actix-web
- [ ] CORS `Cors::permissive()` 允许所有来源
- [ ] 缺少速率限制中间件
- [ ] 错误信息直接返回（`HttpResponse::InternalServerError().body(err.to_string())`）
- [ ] `actix-files` 静态文件服务配置

### Axum
- [ ] CORS `CorsLayer::permissive()` 允许所有来源
- [ ] `tower-http` 安全中间件是否配置
- [ ] 缺少 `TraceLayer` 日志
- [ ] `ServeDir` 静态文件配置

### 内存安全
- [ ] `unsafe` 块中的操作:
  - `std::ptr::read` / `std::ptr::write` 未对齐/越界
  - `std::mem::transmute` 类型转换
  - `from_raw_parts` / `from_raw_parts_mut` 长度/对齐
  - `Box::from_raw` / `Arc::from_raw` 所有权
- [ ] FFI 边界的不安全操作
- [ ] `std::mem::forget` 导致资源泄漏
- [ ] `Send` / `Sync` 不正确的手动实现
