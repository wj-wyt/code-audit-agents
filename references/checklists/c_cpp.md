# C/C++ 安全检查清单

> Phase 2B 覆盖率验证时按需加载对应 D 段落。

---

## D1: 注入漏洞

### 命令注入
- [ ] `system(user_input)` 直接执行
- [ ] `popen(user_input, "r")` 管道执行
- [ ] `execvp(user_input, args)` 命令名可控
- [ ] `sprintf(cmd, "ls %s", user_input)` + `system(cmd)` 拼接
- [ ] `snprintf` 拼接后传入 `system/popen/exec`

### 格式化字符串
- [ ] `printf(user_input)` 用户输入作为格式字符串
- [ ] `fprintf(fp, user_input)` 同上
- [ ] `sprintf(buf, user_input)` 同上
- [ ] `syslog(LOG_ERR, user_input)` 同上
- [ ] 正确: `printf("%s", user_input)` 固定格式字符串

### SQL 注入（嵌入式数据库）
- [ ] `sqlite3_exec(db, sql_with_user_input, ...)` 拼接
- [ ] `mysql_query(conn, sql_with_user_input)` 拼接
- [ ] `sqlite3_prepare_v2` + `sqlite3_bind_*` 是安全的（参数化）
- [ ] `mysql_stmt_prepare` + `mysql_stmt_bind_param` 是安全的

---

## D4: 反序列化 / 数据解析

- [ ] 自定义二进制协议解析未校验长度/边界
- [ ] `protobuf` 解析超大消息（DoS）
- [ ] `XML` 解析未禁用外部实体（libxml2 `XML_PARSE_NOENT`）
- [ ] `JSON` 解析库（cJSON/jansson）整数溢出
- [ ] ASN.1/DER 解析（OpenSSL）已知漏洞

---

## D5: 文件操作

- [ ] `fopen(user_input, "r")` 路径可控
- [ ] `open(user_input, O_RDONLY)` 路径可控
- [ ] `realpath()` 后未检查前缀（TOCTOU）
- [ ] `symlink` 跟随（检查 `lstat` vs `stat`）
- [ ] `mktemp()` 不安全（应使用 `mkstemp()`）
- [ ] 临时文件竞态条件

---

## D6: SSRF

- [ ] `libcurl` `curl_easy_setopt(curl, CURLOPT_URL, user_url)` URL 可控
- [ ] 未设置 `CURLOPT_PROTOCOLS` 限制协议
- [ ] 未禁止 `file://` / `gopher://` 协议
- [ ] 未检查目标是否为私网地址

---

## D7: 加密安全

- [ ] `DES_ecb_encrypt` / `DES_cbc_encrypt` 使用 DES
- [ ] `RC4` / `RC2` 弱加密
- [ ] `MD5_Init/Update/Final` 用于密码/签名
- [ ] `SHA1` 用于密码/签名
- [ ] `rand()` / `srand(time(NULL))` 用于安全场景（应使用 `/dev/urandom` 或 `getrandom()`）
- [ ] 硬编码密钥/IV
- [ ] OpenSSL `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL)` 禁用证书验证

---

## 内存安全（C/C++ 特有，高优先级）

### 缓冲区溢出
- [ ] `strcpy(dst, src)` 无长度检查（应使用 `strncpy` / `strlcpy`）
- [ ] `strcat(dst, src)` 无长度检查（应使用 `strncat` / `strlcat`）
- [ ] `sprintf(buf, fmt, ...)` 无长度检查（应使用 `snprintf`）
- [ ] `gets(buf)` 已废弃，永远不安全（应使用 `fgets`）
- [ ] `scanf("%s", buf)` 无宽度限制（应使用 `%Ns`）
- [ ] `memcpy(dst, src, user_len)` 长度可控
- [ ] `read(fd, buf, user_len)` 长度可控
- [ ] 栈缓冲区 `char buf[256]` 接收不定长输入

### 整数溢出
- [ ] `malloc(user_size)` 大小可控（整数溢出 → 小分配 → 堆溢出）
- [ ] `size_t len = a * b` 乘法溢出
- [ ] `int` 到 `size_t` 隐式转换（负数 → 巨大正数）
- [ ] 长度计算 `len1 + len2` 溢出后传入 `malloc/memcpy`

### Use-After-Free
- [ ] `free(ptr)` 后继续使用 `ptr`
- [ ] 双重 `free(ptr)`
- [ ] 返回栈上局部变量的指针
- [ ] 回调函数中引用已释放的上下文

### 其他内存问题
- [ ] 未初始化变量使用（信息泄露）
- [ ] `alloca(user_size)` 栈溢出
- [ ] 空指针解引用
- [ ] 类型混淆（C++ `dynamic_cast` 失败后使用）
- [ ] `realloc` 返回 NULL 后原指针泄漏

### 安全编译选项
- [ ] `-fstack-protector-strong` 栈保护
- [ ] `-D_FORTIFY_SOURCE=2` 缓冲区检查
- [ ] `-fPIE -pie` 地址随机化
- [ ] `-Wformat -Wformat-security` 格式字符串警告
- [ ] `-z relro -z now` GOT 保护
- [ ] AddressSanitizer (`-fsanitize=address`) 用于测试

---

## D8: 安全配置

- [ ] 编译时未启用安全选项（见上方）
- [ ] `setuid` 程序未正确降权
- [ ] `chroot` 后未 `chdir("/")`
- [ ] 信号处理函数中调用非异步安全函数
- [ ] `umask` 设置过于宽松
- [ ] 环境变量 `PATH` / `LD_PRELOAD` 未清理（setuid 程序）
- [ ] `/tmp` 文件竞态（应使用 `mkstemp`）
