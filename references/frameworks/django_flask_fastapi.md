# Django / Flask / FastAPI 安全参考

> 识别到 Django / Flask / FastAPI 时加载。

---

## Django 安全审计

### ORM 安全 vs 危险

| 方法 | 安全性 | 说明 |
|------|--------|------|
| `.filter(name=val)` | ✅ 安全 | 自动参数化 |
| `.exclude(name=val)` | ✅ 安全 | 自动参数化 |
| `.get(pk=val)` | ✅ 安全 | 自动参数化 |
| `.extra(where=["col=%s"], params=[val])` | ⚠️ 检查 | 参数化但容易误用 |
| `.extra(where=["col=" + val])` | ❌ 危险 | 字符串拼接 |
| `.raw("SELECT ... %s" % val)` | ❌ 危险 | 字符串拼接 |
| `.raw("SELECT ... %s", [val])` | ✅ 安全 | 参数化 |
| `RawSQL("col = %s" % val)` | ❌ 危险 | 字符串拼接 |
| `connection.cursor().execute(sql + val)` | ❌ 危险 | 直接拼接 |

### Django 特有漏洞

| 漏洞 | 检查点 |
|------|--------|
| Q 对象 `_connector` 注入 | `Q(**user_dict)` 键名可控 → `__gt`/`__lt` 操作符注入 |
| JSONField 查询注入 | `.filter(data__key=val)` 键名可控 |
| `Func`/`Value` 拼接 | 自定义数据库函数中的拼接 |
| 模板注入 | `Template(user_input).render()` |
| 管理后台暴露 | `/admin/` 弱口令或公网可访问 |

### Django 安全配置

```python
# settings.py 检查清单
DEBUG = False                          # 生产环境必须 False
ALLOWED_HOSTS = ['example.com']        # 不能是 ['*']
SECRET_KEY = os.environ['SECRET_KEY']  # 不能硬编码
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_TYPE_NOSNIFF = True
```

### Django REST Framework
- [ ] `DEFAULT_PERMISSION_CLASSES` 是否设置（默认 `AllowAny`!）
- [ ] `DEFAULT_AUTHENTICATION_CLASSES` 配置
- [ ] `DEFAULT_THROTTLE_RATES` 速率限制
- [ ] Serializer 字段白名单（`fields` vs `exclude`）
- [ ] `ModelSerializer` 是否暴露敏感字段
- [ ] `ViewSet` 的 `get_queryset()` 是否过滤当前用户数据

---

## Flask 安全审计

### 常见漏洞

| 漏洞 | 危险代码 | 安全替代 |
|------|---------|---------|
| SSTI | `render_template_string(user_input)` | `render_template("file.html")` |
| XSS | `Markup(user_input)` / `{{ x \| safe }}` | `{{ x }}`（自动转义） |
| 路径穿越 | `send_file(user_input)` | `send_from_directory(safe_dir, filename)` |
| Session 伪造 | 弱 `SECRET_KEY` | 强随机密钥 |
| 调试 RCE | `app.debug = True` 生产环境 | Werkzeug debugger PIN |

### Flask 安全配置
```python
app.config['SECRET_KEY'] = os.urandom(32)  # 强随机密钥
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

### Flask-Login 检查
- [ ] `@login_required` 是否覆盖所有需要认证的路由
- [ ] `current_user` 是否用于数据归属校验
- [ ] `remember_me` cookie 安全性

---

## FastAPI 安全审计

### 依赖注入安全
```python
# 检查 Depends() 链是否完整
@app.get("/admin/users")
async def list_users(
    current_user: User = Depends(get_current_user),  # 认证
    _: bool = Depends(require_admin),                  # 授权
):
    ...

# 危险: 缺少认证/授权依赖
@app.get("/admin/users")
async def list_users():  # 无认证!
    return await User.all()
```

### Pydantic 模型安全
```python
# 安全: 明确字段白名单
class UserUpdate(BaseModel):
    name: str
    email: str
    # 没有 role/is_admin 字段

# 危险: 使用 ORM 模型直接接收
@app.put("/user/{id}")
async def update_user(id: int, user: UserORM):  # 可能包含 role 字段
    ...
```

### FastAPI 特有检查
- [ ] CORS 配置: `allow_origins=["*"]` + `allow_credentials=True`
- [ ] `/docs` `/redoc` 在生产环境暴露
- [ ] `Response` 直接返回未转义内容
- [ ] `BackgroundTasks` 中的异常处理
- [ ] WebSocket 端点缺少认证
- [ ] 文件上传 `UploadFile` 大小限制

---

## 通用 Python Web 检查

### Pickle 反序列化
```python
# 危险场景
session_data = pickle.loads(cookie_value)  # Cookie 中的 pickle
cache_data = pickle.loads(redis.get(key))  # 缓存中的 pickle
task_args = pickle.loads(message.body)     # 消息队列中的 pickle
```

### YAML 反序列化
```python
# 危险
data = yaml.load(user_input)              # 默认 FullLoader
# 安全
data = yaml.safe_load(user_input)         # SafeLoader
```

### 依赖安全
- [ ] `pip-audit` 检查已知 CVE
- [ ] `safety check` 检查依赖漏洞
- [ ] `requirements.txt` 是否固定版本（`==` 而非 `>=`）
- [ ] `Pipfile.lock` / `poetry.lock` 是否提交
