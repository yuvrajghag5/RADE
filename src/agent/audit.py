"""
Tamper-evident audit ledger.

Every agent decision and tool result is appended as one JSON line, hash-chained:
each record's `hash = sha256(prev_hash + canonical(record))`. Changing or
deleting any past record breaks the chain, which `verify()` detects. This is the
accountability control — a separate, append-only record of what the agent
actually did, distinct from any user-facing report.

The chain continues across runs (the ledger is a single growing file), so the
whole history of the agent is verifiable end to end.
"""
from __future__ import annotations
import hashlib
import json
import time
from pathlib import Path

GENESIS = "0" * 64


def _canonical(record: dict) -> str:
    # deterministic serialisation so the hash is reproducible
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.prev = self._last_hash()
        self.seq = self._last_seq()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = None
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = line
        return json.loads(last)["hash"] if last else GENESIS

    def _last_seq(self) -> int:
        if not self.path.exists():
            return 0
        n = 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                n = json.loads(line)["seq"]
        return n

    def record(self, event: str, data: dict) -> dict:
        self.seq += 1
        rec = {
            "seq": self.seq,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "event": event,
            "data": data,
            "prev": self.prev,
        }
        rec["hash"] = hashlib.sha256((self.prev + _canonical(rec)).encode()).hexdigest()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        self.prev = rec["hash"]
        return rec

    @staticmethod
    def verify(path: Path) -> tuple[bool, str]:
        """Re-walk the chain; return (ok, message)."""
        path = Path(path)
        if not path.exists():
            return True, "no ledger yet"
        prev = GENESIS
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            claimed = rec.pop("hash")
            if rec["prev"] != prev:
                return False, f"broken link at seq {rec['seq']} (line {i})"
            recomputed = hashlib.sha256((prev + _canonical(rec)).encode()).hexdigest()
            if recomputed != claimed:
                return False, f"tampered record at seq {rec['seq']} (line {i})"
            prev = claimed
        return True, "chain intact"
