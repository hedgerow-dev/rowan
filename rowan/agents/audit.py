"""Append-only audit trail for what Hunt sends off the machine.

`record()` writes one JSON object per line to the `rowan.audit` logger. The
logger has no handler unless `rowan hunt --audit-log PATH` opens one, so by
default nothing is written. Records describe a request (endpoint, sizes,
hashes, outcome), never its content.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

_LOGGER = logging.getLogger("rowan.audit")
_LOGGER.setLevel(logging.INFO)
_LOGGER.propagate = False


def record(event: str, **fields: object) -> None:
    if not _LOGGER.handlers:
        return
    entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "event": event, **fields}
    _LOGGER.info(json.dumps(entry, sort_keys=True))


def open_audit_log(path: Path) -> logging.Handler:
    """Start appending audit records to `path`, created owner-read/write only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))
    handler = logging.FileHandler(path, mode="a", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    _LOGGER.addHandler(handler)
    return handler


def close_audit_log(handler: logging.Handler) -> None:
    _LOGGER.removeHandler(handler)
    handler.close()
