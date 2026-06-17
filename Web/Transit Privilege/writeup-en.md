# Transit Privilege Writeup

## Overview

This challenge is split into two parts.  

At the beginning, the player does not have the server source code. The only attachment is a client JAR, `edge-agent-client-0.1.0.jar`. That JAR exposes the `/proxy` protocol, so the first half of the challenge is about recovering the protocol and turning it into a usable foothold.  

After that, the route to the flag is not a direct admin endpoint. The player has to use the workspace workflow to become `ADMIN`, then use the backup feature to obtain the server JAR, and only then analyze the deserialization and file-read chain in the second half.

The intended path is:

```text
analyze the player JAR
-> recover the /proxy WebSocket protocol
-> finish cap.sync and create an OPERATOR account
-> log into the console
-> use the workspace flow to become ADMIN
-> download the server JAR from the backup feature
-> analyze the maintenance import chain
-> abuse the char -> byte truncation issue
-> read /flag
```

What makes the challenge interesting is not any single step on its own, but the way these steps have to be connected.

---

## 1. The real entry point is not the login page

The public web page looks like a normal login portal. At first glance, the only obvious endpoints are things like:

- `/login`
- `/admin/me`
- `/api/status`

The status response is intentionally plain:

```json
{
  "name": "Transit Privilege",
  "login": "POST /login",
  "dashboard": "GET /admin/me",
  "notice": "database-backed auth is enabled"
}
```

That is not enough to move very far. The useful starting point is the attachment JAR.

After reversing the client, it becomes clear that it does not speak to a normal REST backend first. It upgrades the target into:

```text
ws://host/proxy
```

So the first meaningful surface is:

```text
/proxy
```

The client flow is also visible there:

```text
HELLO -> AUTH -> DESCRIBE -> CALL
```

The signing material is hardcoded as well, including the fixed key string:

```text
6Ziy5ZCb5a2Q5LiN5aao5bCP5Lq6ISEh
```

At this point, the challenge stops being “guess the web app” and turns into “rebuild the client protocol.”

---

## 2. Why `cap.sync` stands out

Once `HELLO` and `AUTH` are working, the next step is to inspect the capability scope with `DESCRIBE`.  

Among the returned operations, `cap.sync` is the one that deserves attention. It is clearly not a one-shot helper call. It is a negotiated flow with a ticket and a proof stage, which usually means it has some persistent side effect.

The field names are already suggestive:

- `identity`
- `principal`
- `secret`

But the stronger hint comes from live interaction rather than from names alone.

If `secret` is intentionally weak, the server rejects it with a password-style validation message:

```json
{
  "ok": false,
  "operation": "cap.sync",
  "profile": "edge-v3",
  "state": "rejected",
  "reason": "password must be at least 8 characters and include letters and digits"
}
```

That is not the kind of response you would expect from a harmless configuration field. It is much more consistent with a login credential. Together with `principal`, it points toward account creation or credential binding.

---

## 3. Turning `cap.sync` into a console account

The first `HELLO` response looks like this:

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

The values that matter afterward are:

- `nonce`
- `profile`
- `routeEpoch`

After `AUTH`, querying `edge.capability` reveals `cap.sync`:

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

That reply is enough to understand the rest of the flow:

- the request is accepted so far,
- the server issues a `ticket`,
- a second step with `proof` is required,
- the flow continues under `edge.capability.ticket`.

After computing the proof exactly as the client does and submitting the second-stage request, the server returns:

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

The important field here is:

```json
"scope": "operator-console"
```

This is the point where the earlier guess becomes easy to verify: the returned `principal/secret` pair can now be used to log into the web console, and the resulting role is `OPERATOR`.

---

## 4. The privilege escalation is hidden inside workspace

After logging in, the application still does not expose an obvious “become admin” route. The useful surface is:

```text
GET /api/workspace/bootstrap
```

This returns a per-session set of action IDs, for example:

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

This makes it clear that the workflow is exposed through a facade:

```text
POST /api/workspace/action
```

The first draft request does not go straight into an approval queue. Instead, it returns:

```json
{
  "ok": true,
  "state": "ROUTING_REQUIRED",
  "draftRef": "wf-7d4996a260cd"
}
```

So the next question is obvious: who decides the reviewer and the lane?

The preview step provides enough hints to keep following that path:

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

Even without the source code, the interesting words are already there:

- `policyRef`
- `routing`
- `handoff`
- `retained`

That is enough to start testing whether the routing metadata can be used to make the request come back to the owner.

The intended payload is:

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

After submitting it, the request lands in the `retain` lane. Pushing it forward with `advanceActionId` and setting the state to `APPROVED` upgrades the account. A later call to `/admin/me` returns:

```json
{
  "username": "ua3e351ca84",
  "role": "ADMIN"
}
```

At that point, the first half of the challenge is done.

---

## 5. The backup feature is the intended transition to white-box analysis

Once `ADMIN` is reached, the most valuable next step is not blind endpoint hunting. It is to check whether the application itself exposes more implementation detail.

The backup feature does exactly that.

Listing available bundles reveals:

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

That response is already explicit:

- the profile is `server-source`,
- the note states that it contains the packaged service JAR.

After creating a ticket and fetching the bundle, the archive contains:

```text
ops-console-demo-0.1.0.jar
```

Only now does the challenge become a proper white-box problem.

---

## 6. What the server code confirms

With the server JAR in hand, the second half becomes much easier to map out.

The first useful keywords are:

- `reconcile`
- `ObjectInputStream`
- `readObject`

They quickly lead to:

```text
/admin/maintenance/reconcile
```

This route accepts a Base64-encoded ZIP, extracts:

- `manifest.json`
- `inventory.dat`

and then deserializes `inventory.dat` with Java native deserialization.

The most useful class on that path is:

```text
ctf.sctf.ops.maintenance.InventoryCursorEntry
```

Its `readObject()` method calls:

```text
ProbeSandbox.renderSnapshot(name, profile, cursor)
```

and the output is later written into the maintenance report.

That makes it ideal for the final stage:

1. deserialization triggers behavior immediately,
2. the output can be recovered from the report endpoint.

---

## 7. The bug is a mismatch between what is filtered and what is used

Inside `ProbeSandbox`, the `merge` profile eventually sends `cursor` into the file-backed path.

At first glance, the filtering logic looks as if it is blocking traversal markers such as:

- `../`
- `./`
- `%2e%2e`
- `..%2f`
- `%u002e`

The real issue is not that the blacklist is incomplete in a trivial way. The real issue is that the string being checked is not the same string that is later used for path resolution.

In the middle of the process, each Java `char` is truncated into a single `byte`. That creates a representation gap:

- the filter looks at the visible Unicode string,
- the path logic later works on the low-byte materialized form.

As a result, a character that does not visibly look like `.` or `/` can still become `.` or `/` after truncation if its low byte matches.

For example:

- `售` becomes `.`
- `启` becomes `/`
- `书`, `公`, `卡`, `剧` can become `f`, `l`, `a`, `g`

So the visible string:

```text
售售启售售启售售启书公卡剧
```

materializes into:

```text
../../../flag
```

After `resolve().normalize()`, the final target becomes:

```text
/flag
```

---

## 8. Getting the flag back from the report

At that point, the remaining work is straightforward:

- build an `InventoryCursorEntry`,
- place it into `inventory.dat`,
- include a valid `manifest.json`,
- submit the bundle to `/admin/maintenance/reconcile`.

The server returns an `importId`.  

Querying:

```text
GET /admin/maintenance/reports?importId=<importId>
```

returns the final output, which includes:

```text
SCTF{Tr4ns1t_Pr0b3_4107_M@sTer}
```

---

## Final notes

This challenge is built out of several half-hidden layers:

- the first half is exposed through a client JAR rather than through obvious admin routes,
- the privilege escalation is buried inside a workflow facade,
- the source code is not given away at the start but becomes available through the backup feature,
- the final file-read issue is not a plain traversal string but a representation mismatch.

Taken separately, none of these steps is especially large. The real difficulty lies in noticing how they fit together.
