# 反序列化安全专题

> D4 审计时加载。覆盖 Java/Python/PHP/Node/.NET 反序列化攻击与防护。

---

## Java 反序列化

### 攻击面

| 入口 | 协议/格式 | 常见场景 |
|------|----------|---------|
| `ObjectInputStream.readObject()` | Java 原生序列化 | RMI, JMX, 自定义协议 |
| `XMLDecoder.readObject()` | XML | 配置文件, Web Service |
| `Hessian.readObject()` | Hessian 协议 | Dubbo, 微服务 RPC |
| `Kryo.readObject()` | Kryo 二进制 | Spark, Storm |
| `XStream.fromXML()` | XML | 配置, API |
| `Fastjson JSON.parse()` | JSON + autoType | REST API |
| `Jackson ObjectMapper` | JSON + 多态 | REST API |
| `SnakeYAML yaml.load()` | YAML | 配置文件 |
| `JNDI lookup()` | JNDI | Log4j, 配置注入 |

### 常见 Gadget Chain

| Chain | 依赖 | 效果 |
|-------|------|------|
| CommonsCollections1-7 | commons-collections 3.x/4.x | RCE |
| CommonsBeanutils1 | commons-beanutils | RCE |
| Spring1/2 | spring-core + spring-beans | RCE |
| JDK7u21 | JDK 7u21 | RCE |
| Hibernate1 | hibernate-core | RCE |
| URLDNS | JDK 内置 | DNS 探测（无 RCE） |
| C3P0 | c3p0 | RCE（JNDI） |

### 检测方法

```
1. Grep 入口:
   ObjectInputStream|XMLDecoder|readObject|readExternal|
   Hessian2Input|readUnshared|XStream|fromXML

2. 检查数据来源:
   - 网络输入（Socket, HTTP Body, RMI）→ 高危
   - 文件输入（用户上传）→ 高危
   - 数据库/缓存 → 中危（需要先污染存储）
   - 硬编码/内部 → 低危

3. 检查防护:
   - ObjectInputFilter（Java 9+）
   - 自定义 resolveClass 白名单
   - SerialKiller / NotSoSerial 库
   - 依赖版本是否有已知 gadget
```

### Fastjson 专项

```
版本风险:
- < 1.2.25: autoType 默认开启
- 1.2.25-1.2.41: 黑名单绕过
- 1.2.42-1.2.47: 缓存绕过
- 1.2.48-1.2.68: expectClass 绕过
- 1.2.69-1.2.82: safeMode 可选
- ≥ 1.2.83: safeMode 默认开启

检查:
- ParserConfig.getGlobalInstance().setAutoTypeSupport(true) → 危险
- JSON.parseObject(input, Feature.SupportAutoType) → 危险
- @type 字段在 JSON 输入中 → 检查版本
```

### Jackson 专项

```
危险配置:
- ObjectMapper.enableDefaultTyping() → 全局多态
- ObjectMapper.activateDefaultTyping() → 全局多态
- @JsonTypeInfo(use = Id.CLASS) → 类级多态
- @JsonTypeInfo(use = Id.MINIMAL_CLASS) → 类级多态

安全配置:
- 不启用 defaultTyping
- @JsonTypeInfo(use = Id.NAME) + @JsonSubTypes 白名单
- PolymorphicTypeValidator 白名单（Jackson 2.10+）
```

---

## Python 反序列化

### Pickle

```python
# 危险: 任何 pickle.loads 接收不可信数据都是 RCE
import pickle
data = pickle.loads(user_input)  # RCE!

# 常见场景:
# - Cookie/Session 中的 pickle 数据
# - Redis/Memcached 缓存的 pickle 对象
# - Celery 任务参数（默认 pickle 序列化）
# - 机器学习模型文件（.pkl）

# PoC:
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
payload = pickle.dumps(Exploit())
```

### YAML

```python
# 危险
yaml.load(data)                    # 默认 FullLoader（Python 3.9 前）
yaml.load(data, Loader=yaml.Loader) # 不安全 Loader

# 安全
yaml.safe_load(data)               # SafeLoader
yaml.load(data, Loader=yaml.SafeLoader)
```

### 其他
- `marshal.loads()` — 不安全，可执行代码
- `shelve.open()` — 底层使用 pickle
- `jsonpickle.decode()` — 可实例化任意类
- `dill.loads()` — pickle 的超集，更危险

---

## PHP 反序列化

### unserialize

```php
// 危险
$obj = unserialize($user_input);

// 安全: 类白名单（PHP 7.0+）
$obj = unserialize($data, ['allowed_classes' => ['SafeClass']]);

// 安全: 禁止所有类
$obj = unserialize($data, ['allowed_classes' => false]);
```

### Phar 反序列化

```php
// 以下函数处理 phar:// 协议时会触发反序列化:
file_exists('phar://user_upload.jpg')
is_dir / is_file / fileatime / filesize / stat
file_get_contents / fopen / copy / rename / unlink
getimagesize / exif_read_data

// 攻击: 上传伪装为图片的 phar 文件 → 触发反序列化
```

### 常见 Gadget Chain

| Chain | 框架/库 | 效果 |
|-------|--------|------|
| Monolog/RCE1-3 | monolog | RCE |
| Guzzle/RCE1 | guzzle | RCE |
| Laravel/RCE1-8 | laravel | RCE |
| Symfony/RCE1-4 | symfony | RCE |
| ThinkPHP/RCE1-3 | thinkphp | RCE |
| Yii/RCE1 | yii2 | RCE |

工具: `phpggc` — PHP Generic Gadget Chains

---

## Node.js 反序列化

### node-serialize

```javascript
// 极度危险: node-serialize 的 unserialize 可执行函数
var serialize = require('node-serialize');
var payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}';
serialize.unserialize(payload);  // RCE!
```

### js-yaml

```javascript
// 危险（旧版本）
yaml.load(data);  // 默认 DEFAULT_FULL_SCHEMA → 可实例化对象

// 安全
yaml.load(data, { schema: yaml.SAFE_SCHEMA });
yaml.safeLoad(data);  // 已废弃但安全
```

### 原型污染 → RCE

```javascript
// 原型污染可以间接导致 RCE:
// 1. 污染 Object.prototype
// 2. 影响 child_process.spawn 的 env/shell 选项
// 3. 或影响模板引擎的编译选项

// 例: Handlebars + 原型污染 → RCE
// 污染: Object.prototype.type = 'Program'
// 触发: Handlebars.compile(template)(data)
```

---

## .NET 反序列化

### 高危类

| 类 | 风险 | 替代 |
|----|------|------|
| `BinaryFormatter` | RCE | `System.Text.Json` |
| `SoapFormatter` | RCE | `System.Text.Json` |
| `ObjectStateFormatter` | RCE（ViewState） | 加密+签名 ViewState |
| `NetDataContractSerializer` | RCE | `DataContractSerializer` |
| `LosFormatter` | RCE | 避免使用 |

### Json.NET (Newtonsoft.Json)

```csharp
// 危险
JsonConvert.DeserializeObject(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // 或 Auto/Objects/Arrays
});

// 安全
JsonConvert.DeserializeObject<MyType>(json); // 无 TypeNameHandling
// 或
new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None,
    SerializationBinder = new SafeBinder()  // 白名单
};
```

### ViewState
```
检查:
- __VIEWSTATE 参数是否加密
- machineKey 是否硬编码/泄露
- enableViewStateMac 是否为 true
- 泄露 machineKey → 伪造 ViewState → RCE
```

---

## 防护总结

| 语言 | 推荐方案 |
|------|---------|
| Java | ObjectInputFilter 白名单 + 禁用 defaultTyping + 升级依赖 |
| Python | 禁用 pickle 接收不可信数据 + yaml.safe_load |
| PHP | unserialize 类白名单 + 禁止 phar:// 用户输入 |
| Node | 禁用 node-serialize + yaml.safeLoad + 防原型污染 |
| .NET | 禁用 BinaryFormatter + TypeNameHandling.None |
