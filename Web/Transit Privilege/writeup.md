# Transit Privilege 官方题解

## 题目整体思路

这题前半段是黑盒，后半段才转成白盒。

选手一开始拿到的不是服务端源码，而是一个客户端附件 `edge-agent-client-0.1.0.jar`。这个附件把 `/proxy` 这一层通信协议暴露了出来，所以起手重点不是去猜后台接口，而是先把客户端协议吃透。  

整个利用链可以概括成下面几步：

1. 从附件里恢复 `/proxy` WebSocket 协议和签名方式；
2. 通过 `cap.sync` 创建一个可以登录后台的 `OPERATOR` 用户；
3. 登录后台后，顺着 workspace 这一套流程，把自己提到 `ADMIN`；
4. 拿管理员权限访问 backup 功能，下载服务端 jar；
5. 从服务端源码里确认 maintenance import 的反序列化链和最后的文件读取问题；
6. 构造 payload，读出 `/flag`。

这题真正考的是几段能力的串联，不是哪一个点单独有多深。

---

## 一、黑盒阶段：先确认题目真正的入口

题目网页表面上只是一个普通登录页。最先能看到的接口信息很少，像：

- `/login`
- `/admin/me`
- `/api/status`

访问 `/api/status`，返回内容比较普通：

```json
{
  "name": "Transit Privilege",
  "login": "POST /login",
  "dashboard": "GET /admin/me",
  "notice": "database-backed auth is enabled"
}
```

单靠这里很难直接往下打。  

真正有价值的是附件 jar。反编译后很快能看出来，这个客户端不是去访问普通的 REST 接口，而是会把目标地址转成：

```text
ws://host/proxy
```

也就是说，第一段真正的通信入口是：

```text
/proxy
```

从客户端逻辑里还能顺着看到它的大致流程：

```text
HELLO -> AUTH -> DESCRIBE -> CALL
```

同时，签名所需的固定材料也都在客户端里，尤其是那串硬编码的 key：

```text
6Ziy5ZCb5a2Q5LiN5aao5bCP5Lq6ISEh
```

以及 `AUTH`、`CALL` 的拼接格式和 HMAC 计算方式。

---

## 二、为什么会盯上 `cap.sync`

把 `HELLO` 和 `AUTH` 跑通以后，再去看 `DESCRIBE` 返回的能力列表。  

这里最值得注意的是 `cap.sync`。原因很简单：它不是普通的一次性调用，而是一个明显的协商流程。通常这种接口的副作用都不会小，要么是在做初始化，要么是在做身份绑定。

当时并不是只凭字段名下判断，而是先拿远程服务做了几轮测试。`cap.sync` 这边有三个比较醒目的字段：

- `identity`
- `principal`
- `secret`

一开始只看名字，其实还不够。但继续发包会发现，`secret` 这个字段不是随便传都收。故意传一个太短或者过弱的值时，服务端会直接在回包里把密码规则打出来，例如：

```json
{
  "ok": false,
  "operation": "cap.sync",
  "profile": "edge-v3",
  "state": "rejected",
  "reason": "password must be at least 8 characters and include letters and digits"
}
```

看到这种报错，基本就能判断：`secret` 在这里更像是口令，而不是普通配置项。再结合 `principal` 这个字段名，思路自然就会往“创建用户”或者“绑定一组可登录凭据”上走。

---

## 三、走通 `cap.sync`，拿到后台账号

### 1. HELLO

建立 WebSocket 到 `/proxy`，先发：

```json
{"type":"HELLO"}
```

服务端返回：

```json
{
  "ok": true,
  "type": "HELLO_ACK",
  "nonce": "22cc0466020d482e96cc6b1e902bc0d5",
  "profile": "edge-v3",
  "routeEpoch": "rt-a82a95ad0bab",
  "challenge": "b3de52e9e149245f"
}
```

这里后面要用到的是：

- `nonce`
- `profile`
- `routeEpoch`

### 2. AUTH

按客户端里的规则，用 `source=Transit` 做签名后发 `AUTH`。成功回包大致是：

```json
{
  "ok": true,
  "type": "AUTH_ACK",
  "source": "Transit"
}
```

说明这条会话已经进入可调用状态。

### 3. DESCRIBE

接着发：

```json
{
  "type": "DESCRIBE",
  "source": "Transit",
  "scope": "edge.capability"
}
```

返回里能看到：

```json
{
  "scope": "edge.capability",
  "operations": [
    {
      "name": "cap.sync",
      "routeId": 1724737265,
      "required": ["identity", "principal", "secret"],
      "mode": "negotiated-bind"
    }
  ]
}
```

### 4. 第一阶段绑定

先提交一组候选身份，例如：

```json
{
  "identity": "edge-a1b2c3d4",
  "principal": "ua3e351ca84",
  "secret": "Aa910334b81f0614"
}
```

服务端不会直接绑定成功，而是返回：

```json
{
  "ok": true,
  "operation": "cap.sync",
  "profile": "edge-v3",
  "state": "proof_required",
  "ticket": "1e14737afe79853cdb",
  "resumeScope": "edge.capability.ticket",
  "missing": ["ticket", "proof"]
}
```

这个回包已经把后面的方向说得很明白了：  

- 当前流程没失败；
- 服务端发了 `ticket`；
- 还缺 `proof`；
- 下一步要切到 `edge.capability.ticket` 继续。

### 5. 第二阶段绑定

再去看 `edge.capability.ticket` 这一层，服务端会把 proof 所需的上下文提示得比较完整。按客户端里的逻辑把 proof 算出来，再带着：

- `identity`
- `principal`
- `secret`
- `ticket`
- `proof`

发第二次 `cap.sync`。

成功回包：

```json
{
  "ok": true,
  "operation": "cap.sync",
  "profile": "edge-v3",
  "state": "linked",
  "scope": "operator-console",
  "bindingId": "bind-942851708",
  "principal": "ua3e351ca84"
}
```

真正关键的是：

```json
"scope": "operator-console"
```

这就说明这组身份已经不是内部协商对象，而是被挂到了后台控制台这条身份域上。

拿这组 `principal/secret` 去登录后台，可以验证这个判断。

---

## 四、后台提权：顺着 workspace 继续走

登录进去以后，不会直接看到很露骨的后台管理入口。  

比较有价值的是：

```text
GET /api/workspace/bootstrap
```

这个接口会返回一组当前会话可用的 actionId，例如：

```json
{
  "workflow": {
    "draftActionId": "12aa370d-365f-44ed-9c28-31db1cda29c2",
    "previewActionId": "0a7e788c-68da-4050-a390-1bfba909638d",
    "submitActionId": "4bdd3e48-4bb6-4859-96a4-bc0785b168c8",
    "advanceActionId": "16a4b417-bda6-429e-b207-6cd850183685"
  }
}
```

这一步很关键，因为它说明前端真正用的是一套 facade：

```text
POST /api/workspace/action
```

所以后面应该顺着这一套工作流去试，而不是回头乱猜其他旧接口。

### 1. draft

先发起一个 draft。第一次回包不是直接完成，而是：

```json
{
  "ok": true,
  "state": "ROUTING_REQUIRED",
  "draftRef": "wf-7d4996a260cd"
}
```

这就说明后续的 reviewer 或 lane 不是固定死的，还要继续走 routing。

### 2. preview

再做 preview，能拿到一组比较模糊但足够用的提示：

```json
{
  "ok": true,
  "state": "ROUTING_REQUIRED",
  "schema": {
    "fields": ["policyRef", "routing"],
    "profiles": ["desk", "delegate"]
  },
  "note": "handoff remains policy-scoped",
  "compat": "retained resolver aliases may still bind"
}
```

这时候虽然还看不到完整后台逻辑，但几个关键词已经够用了：

- `policyRef`
- `routing`
- `handoff`
- `retained`

这里的思路其实不复杂：既然 reviewer 是通过 routing 决出来的，那就试试看能不能把这一步回收给自己。

### 3. submit

真正起作用的是这样一组 routing 元数据：

```json
{
  "draftRef": "wf-7d4996a260cd",
  "policyRef": "desk-default",
  "routing": {
    "mode": "retain",
    "handoff": "owner"
  }
}
```

提交之后，队列里能看到一条新记录，lane 会落到 `retain`。

### 4. advance

最后再用 `advanceActionId` 去推进它，把状态推到 `APPROVED`。  

推进成功以后，再看：

```text
GET /admin/me
```

回包已经变成：

```json
{
  "username": "ua3e351ca84",
  "role": "ADMIN"
}
```

也就是说，这一步确实完成了自提权。

---

## 五、为什么拿到 ADMIN 后要先看 backup

到了这里，前半段的目标已经完成，剩下的是找最后的读旗点。  

这时候最自然的思路不是继续无头苍蝇一样扫接口，而是看后台有没有把更多实现信息暴露出来。这个题恰好把“黑盒转白盒”的入口放在 backup 功能里。

访问：

```text
GET /api/backup/list
```

可以看到一条很有价值的记录：

```json
[
  {
    "name": "support-source",
    "state": "ready",
    "profile": "server-source",
    "note": "Server support snapshot with packaged service jar."
  }
]
```

这条说明已经非常直接了：  

- profile 是 `server-source`
- note 里明确说了里面是 packaged service jar

接下来走：

```text
POST /api/backup/create
GET /api/backup/fetch
```

可以拿到 `server-source.zip`。  

这个压缩包里只有一个服务端 jar：

```text
ops-console-demo-0.1.0.jar
```

从这一步开始，题目才正式进入后半段源码分析。

---

## 六、拿到源码后，定位最终链

拿到服务端 jar 以后，后半段就清楚很多了。  

最值得先看的几个关键词是：

- `reconcile`
- `ObjectInputStream`
- `readObject`

很快能定位到：

```text
/admin/maintenance/reconcile
```

这里会接收一个 Base64 的 zip，解包后找：

- `manifest.json`
- `inventory.dat`

然后对 `inventory.dat` 做原生 Java 反序列化。

顺着往下看，最关键的类是：

```text
ctf.sctf.ops.maintenance.InventoryCursorEntry
```

它的 `readObject()` 在反序列化时会直接继续调用：

```text
ProbeSandbox.renderSnapshot(name, profile, cursor)
```

同时，这一步的输出还会被写进 maintenance report。  

这就同时满足了两件事：

1. 反序列化时能触发逻辑；
2. 结果还能从 report 里拿回来。

所以它就是后半段最合适的入口。

---

## 七、真正的问题出在“检查的字符串”和“实际用的字符串”不是一回事

继续看 `ProbeSandbox`，会发现 `profile=merge` 这条分支最终会把 `cursor` 带进文件读取链。  

单看过滤逻辑，好像是在拦路径穿越，比如会检查：

- `../`
- `./`
- `%2e%2e`
- `..%2f`
- `%u002e`

但关键问题不是“有没有黑名单”，而是它检查的是**可见字符串**，后面真正参与路径解析的却是另一个被重新物化过的值。

中间有一步很关键的转换，大意就是把每个 Java `char` 强制截成一个 `byte`。  

这就带来一个后果：

- 过滤时看见的字符，不一定是最后参与拼路径的字符；
- 只要某个 Unicode 字符的低 8 位刚好等于目标 ASCII 值，后面就会被还原成真正的 `.`、`/` 之类的字符。

比如：

- `售` 的低 8 位是 `0x2e`，最后会变成 `.`
- `启` 的低 8 位是 `0x2f`，最后会变成 `/`
- `书`、`公`、`卡`、`剧` 的低字节分别能对应 `f`、`l`、`a`、`g`

所以看起来像普通汉字的一串内容：

```text
售售启售售启售售启书公卡剧
```

最后会被物化成：

```text
../../../flag
```

再结合 report 目录去做 `resolve().normalize()`，最终就能走到：

```text
/flag
```

---

## 八、最后一步：把读取结果从 report 拿回来

构造好 `InventoryCursorEntry` 对象以后，把它放进导入 zip 的 `inventory.dat`，再配一份合法的 `manifest.json`，整体 Base64 后提交到：

```text
POST /admin/maintenance/reconcile
```

服务端返回一个 `importId`，然后去访问：

```text
GET /admin/maintenance/reports?importId=<importId>
```

就能在 report 中看到最终输出。  

实际拿到的 flag 是：

```text
SCTF{Tr4ns1t_Pr0b3_4107_M@sTer}
```

---

## 总结

这题真正有意思的地方，在于几段能力都是“半露不露”的：

- 前半段不是直接给后台接口，而是给了一个看起来像边缘客户端的 jar；
- 提权也不是明牌的管理审批，而是藏在 workspace 这套 facade 里；
- 后半段不是一上来就把源码给选手，而是要求先拿管理员，再自己从 backup 里把服务端 jar 取出来；
- 最终读旗点也不是直白的路径穿越，而是落在一次表示层不一致上。

如果只拆开看单个点，这题都不算特别复杂；真正的难点在于要把整条链自己接起来。
