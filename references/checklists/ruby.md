# Ruby 安全检查清单

> Phase 2B 覆盖率验证时按需加载对应 D 段落。

---

## D1: 注入漏洞

### SQL 注入
- [ ] `where("name = '#{params[:name]}'")` 字符串插值
- [ ] `where("name = " + params[:name])` 字符串拼接
- [ ] `find_by_sql("SELECT ... #{param}")` 原始 SQL 插值
- [ ] `connection.execute("SELECT ... #{param}")` 直接执行
- [ ] `where(name: params[:name])` 是安全的（参数化）
- [ ] `where("name = ?", params[:name])` 是安全的（占位符）
- [ ] `order(params[:sort])` 排序注入（应白名单）
- [ ] `pluck(params[:column])` 列名注入

### 命令注入
- [ ] `system("cmd #{user_input}")`
- [ ] `exec("cmd #{user_input}")`
- [ ] `` `cmd #{user_input}` `` 反引号
- [ ] `%x(cmd #{user_input})` 百分号语法
- [ ] `IO.popen("cmd #{user_input}")`
- [ ] `Open3.capture3("cmd #{user_input}")`
- [ ] `Kernel.open("| cmd #{user_input}")` 管道前缀

### 代码执行
- [ ] `eval(user_input)`
- [ ] `send(user_input, args)` / `public_send(user_input, args)` 动态方法调用
- [ ] `constantize` 动态类加载（`params[:class].constantize`）
- [ ] `instance_variable_set("@#{user_input}", value)` 动态属性
- [ ] `class_eval(user_input)` / `module_eval(user_input)`
- [ ] `method(user_input).call` 动态方法

### SSTI
- [ ] `ERB.new(user_input).result` 用户输入作为模板
- [ ] `render inline: user_input` Rails 内联渲染
- [ ] `render template: user_input` 模板路径可控
- [ ] `Slim::Template.new { user_input }.render` Slim 模板
- [ ] `Haml::Engine.new(user_input).render` Haml 模板

---

## D4: 反序列化

- [ ] `Marshal.load(user_input)` → RCE
- [ ] `Marshal.restore(user_input)` → RCE
- [ ] `YAML.load(user_input)` → RCE（Ruby < 3.1 默认不安全）
- [ ] `YAML.unsafe_load(user_input)` → RCE（Ruby ≥ 3.1）
- [ ] `YAML.safe_load(user_input)` 是安全的
- [ ] `Oj.load(user_input, mode: :object)` → 对象实例化
- [ ] `JSON.parse(user_input)` 是安全的（无对象实例化）
- [ ] `Psych.load(user_input)` 同 YAML.load

### Rails 特有
- [ ] `ActiveSupport::JSON.decode` 旧版本可能不安全
- [ ] Cookie 序列化使用 Marshal（`Rails.application.config.action_dispatch.cookies_serializer = :marshal`）
- [ ] Session 存储使用 Marshal
- [ ] `GlobalID::Locator.locate(user_input)` 对象定位

---

## D5: 文件操作

- [ ] `File.read(user_input)` 路径可控
- [ ] `File.open(user_input)` 路径可控
- [ ] `send_file(user_input)` 路径可控
- [ ] `send_data(File.read(user_input))` 路径可控
- [ ] `Kernel.open(user_input)` 支持管道（`| cmd`）→ 命令注入
- [ ] `IO.read(user_input)` 路径可控
- [ ] `Pathname.new(user_input).read` 路径可控
- [ ] `Rack::Utils.clean_path_info` 路径清理不充分
- [ ] 文件上传 `original_filename` 直接用于存储

---

## D6: SSRF

- [ ] `Net::HTTP.get(URI(user_url))`
- [ ] `open-uri` 的 `URI.open(user_url)` / `open(user_url)`
- [ ] `HTTParty.get(user_url)`
- [ ] `Faraday.get(user_url)`
- [ ] `RestClient.get(user_url)`
- [ ] `Typhoeus::Request.new(user_url)`
- [ ] `Kernel.open(user_url)` 支持 HTTP（open-uri）

---

## D7: 加密安全

- [ ] `Digest::MD5.hexdigest(password)` 用于密码
- [ ] `Digest::SHA1.hexdigest(password)` 用于密码
- [ ] `BCrypt::Password.create(password)` 是安全的
- [ ] `SecureRandom.hex` / `SecureRandom.uuid` 是安全的
- [ ] `rand()` / `Random.new` 用于安全场景（不安全）
- [ ] 硬编码 `secret_key_base`
- [ ] `OpenSSL::Cipher` 使用 DES/ECB

---

## D8: 安全配置

### Rails
- [ ] `config.consider_all_requests_local = true` 生产环境
- [ ] `config.force_ssl = false` 未强制 HTTPS
- [ ] `config.action_dispatch.cookies_serializer = :marshal` 不安全序列化
- [ ] `protect_from_forgery` 未启用或 `with: :null_session` 不当
- [ ] `config.action_controller.allow_forgery_protection = false`
- [ ] `secret_key_base` 硬编码或泄露
- [ ] `config.hosts` 未限制（Host Header 攻击）
- [ ] `config.middleware.delete ActionDispatch::RemoteIp` 删除安全中间件

### Strong Parameters
```ruby
# 安全: 白名单参数
params.require(:user).permit(:name, :email)

# 危险: permit!
params.require(:user).permit!  # 允许所有参数 → Mass Assignment
```

### 路由安全
- [ ] `match` 路由未限制 HTTP 方法（`via: [:get, :post]`）
- [ ] 管理路由缺少认证约束
- [ ] `constraints` 正则不严格
