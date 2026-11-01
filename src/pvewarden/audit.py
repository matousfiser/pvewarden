"""Append-only JSON Lines audit log.

Every tool call gets a call id, a 'tool_call' record before it runs and a 'tool_result' record with
its outcome and duration; the records an operation writes in between (snapshot, apply_updates, ...)
carry the same id. Refused HTTP requests are summarised per address (DeniedLog), so a flood of them
cannot fill the disk.
"""

import contextvars
import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger(__name__)
CALL_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar("pvewarden_call_id", default=None)


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, action: str, *, must: bool = False, **fields) -> None:
        """must=True: raise OSError if the record cannot be written (a change must not start without
        it). Otherwise a failure goes to the server log: once a change is done, failing would only
        hide its result."""
        entry = {"ts": datetime.now(UTC).isoformat(timespec="seconds"), "action": action}
        if (call := CALL_ID.get()) is not None:
            entry["call"] = call
        entry |= fields
        try:
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError as e:
            if must:
                raise
            log.error("audit log %s not writable, lost record %s: %s", self.path, json.dumps(entry, default=str), e)


class DeniedLog:
    """Refused requests: the first from an address is written at once, the rest of that minute as one
    summary (first, last, count). At most `max_sources` addresses are tracked, plus one entry the rest share."""

    def __init__(self, audit: AuditLog, window: float = 60, max_sources: int = 256, clock=time.monotonic):
        self.audit, self.window, self.max_sources, self.clock = audit, window, max_sources, clock
        self.sources: dict[str, dict] = {}

    def denied(self, ip: str, path: str) -> None:
        now = self.clock()
        self.flush(now)
        key = ip if ip in self.sources or len(self.sources) < self.max_sources else "*"
        s = self.sources.get(key)
        if s is None:
            self.sources[key] = {"start": now, "first": _ts(), "last": _ts(), "count": 1, "path": path}
            self._write("http_denied", ip=key, path=path)
        else:
            s["count"] += 1
            s["last"] = _ts()

    def flush(self, now: float | None = None, force: bool = False) -> None:
        """Write the summaries of windows that have ended (all of them with force)."""
        now = self.clock() if now is None else now
        for key, s in list(self.sources.items()):
            if force or now - s["start"] >= self.window:
                if s["count"] > 1:
                    self._write("http_denied_summary", ip=key, first=s["first"], last=s["last"], count=s["count"])
                del self.sources[key]

    def _write(self, action: str, **fields) -> None:
        self.audit.write(action, **fields)


def _ts() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
