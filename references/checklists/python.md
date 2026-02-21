# Python 安全检查清单

> Phase 2B 覆盖率验证时按需加载对应 D 段落。

---

## D1: 注入漏洞

### SQL 注入
- [ ] `cursor.execute(f"SELECT ... {param}")` 字符串拼接
- [ ] `cursor.execute("SELECT ... %s" % param)` 格式化拼接
- [ ] Django `.extra(where=[...])` / `.raw(sql)` / `RawSQL()`
- [ ] SQLAlchemy `text(f"...")` / `execute(f"...")`
- [ ] `.filter()` / `.exclude()` 是安全的（ORM 参数化）
- [ ] ORDER BY 动态拼接

### 命令注入
- [ ] `os.system(cmd + param)`
- [ ] `os.popen(cmd + param)`
- [ ] `subprocess.call(cmd + param, shell=True)`（shell=True 是关键）
- [ ] `subprocess.Popen(cmd, shell=True)`
- [ ] `subprocess.run([cmd, arg])` 数组形式是安全的（shell=False）

### 代码执行
- [ ] `eval(userInput)`
- [ ] `exec(userInput)`
- [ ] `compile(userInput, ...)`
- [ ] `__import__(userInput)`
- [ ] `getattr(obj, userInput)()`（动态方法调用）

### SSTI（模板注入）
- [ ] Flask `render_template_string(userInput)`
- [ ] Jinja2 `Template(userInput).render()`
- [ ] `render_template("template.html")` 是安全的（文件模板）
- [ ] Jinja2 `{{ x }}` 默认转义，`{{ x | safe }}` / `Markup()` 不转义

---

## D4: 反序列化

- [ ] `pickle.loads(userInput)` / `pickle.load(file)`
- [ ] `yaml.load(data)` 无 Loader（应使用 `yaml.safe_load()`）
- [ ] `yaml.load(data, Loader=yaml.FullLoader)` 仍有风险
- [ ] `marshal.loads(data)`
- [ ] `shelve.open(userControlledPath)`
- [ ] `jsonpickle.decode(data)`
- [ ] `dill.loads(data)`

---

## D5: 文件操作

- [ ] `open(userInput)` 无路径校验
- [ ] `os.path.join(base, userInput)` 未检查 `../`
- [ ] `send_file(userInput)` / `send_from_directory()` 路径可控
- [ ] `shutil.copy(src, dst)` 路径可控
- [ ] `zipfile.extractall()` 未检查条目路径（Zip Slip）
- [ ] `tarfile.extractall()` 未检查条目路径
- [ ] 文件上传仅检查扩展名（应检查 MIME + magic bytes）

---

## D6: SSRF/XXE

### SSRF
- [ ] `requests.get(userUrl)` / `requests.post(userUrl)`
- [ ] `urllib.request.urlopen(userUrl)`
- [ ] `httpx.get(userUrl)`
- [ ] `aiohttp.ClientSession().get(userUrl)`
- [ ] URL 校验可被 `@` / `#` / 重定向绕过

### XXE
- [ ] `xml.etree.ElementTree.parse()` 默认安全（Python 3.8+）
- [ ] `lxml.etree.parse()` 需要 `resolve_entities=False`
- [ ] `xml.sax` 需要禁用外部实体
- [ ] `defusedxml` 库是安全替代

---

## D7: 加密安全

- [ ] `hashlib.md5(password)` / `hashlib.sha1(password)` 用于密码
- [ ] `random.random()` / `random.randint()` 用于安全场景（应使用 `secrets`）
- [ ] 硬编码 SECRET_KEY / JWT_SECRET
- [ ] `DES` / `Blowfish` 弱加密算法
- [ ] PyCrypto（已废弃）→ 应使用 PyCryptodome 或 cryptography

---

## D8: 安全配置

### Django
- [ ] `DEBUG = True` 在生产环境
- [ ] `ALLOWED_HOSTS = ['*']`
- [ ] `SECRET_KEY` 硬编码或弱密钥
- [ ] `CSRF_COOKIE_SECURE = False`
- [ ] `SESSION_COOKIE_SECURE = False`
- [ ] `SECURE_SSL_REDIRECT = False`
- [ ] `X_FRAME_OPTIONS` 未设置

### Flask
- [ ] `app.debug = True` 在生产环境
- [ ] `app.secret_key` 硬编码或弱密钥
- [ ] Werkzeug debugger 在生产环境开启（RCE 风险）

### FastAPI
- [ ] CORS `allow_origins=["*"]` + `allow_credentials=True`
- [ ] 缺少速率限制
- [ ] `/docs` `/redoc` 在生产环境暴露
