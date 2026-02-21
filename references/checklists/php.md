# PHP 安全检查清单

> Phase 2B 覆盖率验证时按需加载对应 D 段落。

---

## D1: 注入漏洞

### SQL 注入
- [ ] `mysqli_query($conn, "SELECT ... $var")` 字符串拼接
- [ ] `$pdo->query("SELECT ... $var")` 拼接
- [ ] `DB::raw("SELECT ... $var")` Laravel 原始查询拼接
- [ ] `->whereRaw("col = $var")` Laravel 原始条件拼接
- [ ] `->orderByRaw($userInput)` 排序注入
- [ ] Eloquent `.where('col', $val)` 是安全的（参数化）
- [ ] PDO `prepare()` + `execute()` 是安全的

### 命令注入
- [ ] `system($cmd . $param)`
- [ ] `exec($cmd . $param)`
- [ ] `passthru($cmd . $param)`
- [ ] `shell_exec($cmd . $param)` / 反引号 `` `$cmd` ``
- [ ] `popen($cmd . $param, 'r')`
- [ ] `proc_open()` 参数可控
- [ ] `escapeshellarg()` / `escapeshellcmd()` 可被绕过（多字节字符）

### 代码执行
- [ ] `eval($userInput)`
- [ ] `assert($userInput)`（PHP 7 前可执行代码）
- [ ] `preg_replace('/.*/e', $userInput, ...)` e 修饰符（PHP 7 已移除）
- [ ] `create_function('', $userInput)`（PHP 7.2 已废弃）
- [ ] `$$var` 变量覆盖
- [ ] `extract($_POST)` / `extract($_GET)` 变量覆盖

### 文件包含
- [ ] `include($userInput)` / `require($userInput)`
- [ ] `include("pages/" . $userInput . ".php")` 可用 `../` 和 `%00` 绕过
- [ ] `php://filter/convert.base64-encode/resource=` 读取源码
- [ ] `php://input` 远程代码执行
- [ ] `data://text/plain;base64,` 代码执行
- [ ] `allow_url_include=On` 启用远程包含

---

## D4: 反序列化

- [ ] `unserialize($userInput)` 无类白名单
- [ ] `unserialize($data, ['allowed_classes' => true])` 允许所有类
- [ ] `phar://` 协议触发反序列化（文件操作函数）
- [ ] `__wakeup()` / `__destruct()` 中的危险操作
- [ ] 已知 gadget chain（Monolog、Guzzle、Laravel 等）

触发 phar 反序列化的函数:
```
file_exists / is_dir / is_file / file_get_contents / fopen
copy / rename / unlink / stat / fileatime / filesize
```

---

## D5: 文件操作

- [ ] `move_uploaded_file()` 目标路径可控
- [ ] 仅检查 `$_FILES['file']['type']`（客户端可伪造）
- [ ] 未检查文件内容（magic bytes）
- [ ] 上传目录在 Web 根目录下
- [ ] `.htaccess` 可被上传覆盖
- [ ] `.user.ini` 可被上传（`auto_prepend_file`）
- [ ] `file_get_contents($userUrl)` SSRF + 文件读取
- [ ] `readfile($userPath)` 路径穿越

### 危险扩展名
```
.php .php3 .php4 .php5 .phtml .phar .inc
.htaccess .user.ini
```

---

## D6: SSRF/XXE

### SSRF
- [ ] `file_get_contents($userUrl)`
- [ ] `curl_exec()` + `CURLOPT_URL` 可控
- [ ] `fopen($userUrl)` + `allow_url_fopen=On`
- [ ] `SoapClient($userUrl)`
- [ ] `simplexml_load_file($userUrl)`

### XXE
- [ ] `simplexml_load_string($xml)` 未禁用外部实体
- [ ] `DOMDocument->loadXML($xml)` 未禁用外部实体
- [ ] `XMLReader->xml($xml)` 未禁用外部实体

安全配置:
```php
libxml_disable_entity_loader(true); // PHP < 8.0
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD); // 仍不安全
// 正确: 不加载 DTD
```

---

## D7: 加密安全

- [ ] `md5($password)` / `sha1($password)` 用于密码
- [ ] `password_hash()` 未使用（应使用 `PASSWORD_BCRYPT` / `PASSWORD_ARGON2ID`）
- [ ] `rand()` / `mt_rand()` 用于安全场景（应使用 `random_bytes()` / `random_int()`）
- [ ] `mcrypt_*` 函数（已废弃）
- [ ] 硬编码密钥/IV
- [ ] `openssl_encrypt()` 使用 ECB 模式

---

## D8: 安全配置

### PHP 配置
- [ ] `display_errors = On` 在生产环境
- [ ] `expose_php = On`
- [ ] `allow_url_include = On`
- [ ] `allow_url_fopen = On`（SSRF 风险）
- [ ] `open_basedir` 未设置
- [ ] `disable_functions` 未限制危险函数
- [ ] `session.cookie_httponly = 0`
- [ ] `session.cookie_secure = 0`

### Laravel
- [ ] `APP_DEBUG=true` 在生产环境
- [ ] `APP_KEY` 泄露（可伪造加密数据）
- [ ] `.env` 文件可公网访问
- [ ] `CORS` 配置过宽
- [ ] 路由缓存未启用（性能 + 安全）

### 类型杂耍
- [ ] `==` 松散比较（`"0" == false`, `"0e123" == "0e456"`）
- [ ] `in_array($val, $arr)` 无 strict 参数
- [ ] `switch($val)` 松散比较
- [ ] `strcmp()` 传入数组返回 NULL
