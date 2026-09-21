#!/usr/bin/env python3
"""Display the current Isolation Bytes daily administrator credentials.

This utility intentionally derives the same rotating credentials used by the
cloud authentication endpoint. It does not store the generated password.
"""

from __future__ import annotations

import hashlib
import os
from datetime import date, timedelta


def _admin_base() -> str:
    value = (
        os.environ.get("CLOUD_ADMIN_USERNAME")
        or os.environ.get("ADMIN_USERNAME")
        or ""
    ).strip()
    return value or "soluzka"


def daily_username(base: str, today: date) -> str:
    prefix = base.split("_", 1)[0] if "_" in base else base
    day = today.strftime("%Y%m%d")
    suffix = hashlib.sha256(f"{day}:{base}".encode()).hexdigest()[:8]
    return f"{prefix}_adm_{day}_{suffix}"


def daily_password(base: str, today: date) -> str:
    day = today.strftime("%Y%m%d")
    suffix = hashlib.sha256(f"pw:{day}:{base}".encode()).hexdigest()[:12]
    return f"IB{day}-{suffix}"


def main() -> int:
    base = _admin_base()
    today = date.today()
    print("=" * 60)
    print("  Isolation Bytes — Daily Admin Credentials")
    print("=" * 60)
    print(f"Username : {daily_username(base, today)}")
    print(f"Password : {daily_password(base, today)}")
    print(f"Expires  : {(today + timedelta(days=1)).isoformat()} 00:00")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
