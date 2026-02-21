# Laravel / Symfony 安全参考

> 识别到 Laravel / Symfony 时加载。

---

## Laravel 安全审计

### Eloquent ORM 安全 vs 危险

| 方法 | 安全性 | 说明 |
|------|--------|------|
| `User::find($id)` | ✅ 安全 | 参数化 |
| `User::where('name', $val)->get()` | ✅ 安全 | 参数化 |
| `User::whereIn('id', $ids)->get()` | ✅ 安全 | 参数化 |
| `DB::raw("col = $val")` | ❌ 危险 | 字符串拼接 |
| `->whereRaw("col = $val")` | ❌ 危险 | 字符串拼接 |
| `->whereRaw("col = ?", [$val])` | ✅ 安全 | 参数化 |
| `->orderByRaw($userInput)` | ❌ 危险 | 排序注入 |
| `->selectRaw("$userInput")` | ❌ 危险 | 列名注入 |
| `DB::statement($sql . $var)` | ❌ 危险 | 直接拼接 |

### Mass Assignment

```php
// 危险: 无 $fillable/$guarded
class User extends Model {
    // 所有字段可批量赋值!
}

// 安全: 白名单
class User extends Model {
    protected $fillable = ['name', 'email'];
    // role, is_admin 不在白名单中
}

// 安全: 黑名单
class User extends Model {
    protected $guarded = ['id', 'role', 'is_admin'];
}

// 危险: $guarded = [] (空数组 = 无保护)
class User extends Model {
    protected $guarded = [];  // 所有字段可批量赋值!
}
```

### 检查 Mass Assignment 的方法
```php
// 搜索直接使用请求数据创建/更新的代码
User::create($request->all());           // 危险
User::create($request->validated());     // 安全（经过 FormRequest 验证）
User::create($request->only(['name']));  // 安全（白名单）
$user->update($request->all());          // 危险
$user->fill($request->all())->save();    // 危险
```

### Laravel 认证与授权

```php
// Gate 定义
Gate::define('update-post', function ($user, $post) {
    return $user->id === $post->user_id;  // 归属校验
});

// Policy
class PostPolicy {
    public function update(User $user, Post $post) {
        return $user->id === $post->user_id;
    }
}

// Controller 中使用
$this->authorize('update', $post);  // 安全
// 或
Gate::authorize('update-post', $post);

// 危险: 缺少授权检查
public function update(Request $request, $id) {
    $post = Post::find($id);  // 无归属校验 → IDOR
    $post->update($request->all());
}
```

### Laravel 特有漏洞

| 漏洞 | 检查点 |
|------|--------|
| APP_KEY 泄露 | `.env` 文件可访问 → 伪造加密数据/Session |
| Debug 模式 | `APP_DEBUG=true` → Ignition 页面泄露源码/环境变量 |
| 路由缓存 | `php artisan route:cache` 后新路由不生效 |
| CSRF 豁免 | `VerifyCsrfToken::$except` 过多 |
| 文件上传 | `$request->file()->store()` 路径可控 |
| 队列反序列化 | Job 类的 `unserialize` → 已知 gadget chain |
| Blade XSS | `{!! $var !!}` 不转义（`{{ $var }}` 安全） |

### Laravel 安全配置

```php
// .env 检查
APP_DEBUG=false
APP_KEY=base64:...  // 不能泄露
SESSION_SECURE_COOKIE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax

// config/cors.php
'allowed_origins' => ['https://example.com'],  // 不能是 ['*']
'supports_credentials' => true,
```

---

## Symfony 安全审计

### 安全组件

```yaml
# security.yaml 检查
security:
    firewalls:
        main:
            pattern: ^/
            anonymous: true  # 检查匿名访问范围
    access_control:
        - { path: ^/admin, roles: ROLE_ADMIN }
        - { path: ^/api, roles: ROLE_USER }
        # 检查: 是否有遗漏的路径?
```

### Symfony 特有检查
- [ ] `Voter` 授权逻辑是否正确
- [ ] `ParamConverter` 是否有注入风险
- [ ] `Twig` 模板: `{{ var|raw }}` 不转义
- [ ] `Process` 组件命令注入
- [ ] `Serializer` 反序列化不可信数据
- [ ] `EventSubscriber` 中的权限检查
- [ ] `Form` 组件的 CSRF 保护是否启用

### Doctrine ORM
```php
// 安全
$qb->where('u.name = :name')->setParameter('name', $val);

// 危险
$qb->where("u.name = '$val'");  // 字符串拼接
$em->createQuery("SELECT u FROM User u WHERE u.name = '$val'");  // DQL 拼接
```
