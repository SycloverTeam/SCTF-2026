from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone
from typing import Any


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
