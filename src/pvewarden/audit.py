"""Append-only JSON Lines audit log."""

import json
from datetime import UTC, datetime
from pathlib import Path


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, action: str, **fields) -> None:
        entry = {"ts": datetime.now(UTC).isoformat(timespec="seconds"), "action": action, **fields}
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
