"""Append-only, hash-chained audit log.

Each entry stores sha256(prev_hash + canonical entry). Editing or deleting any
row in the database breaks the chain, which `verify` detects.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

GENESIS = "0" * 64
FIELDS = ("ts", "actor", "action", "entity", "record_id", "details")


def init(conn) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
        "actor TEXT NOT NULL, action TEXT NOT NULL, entity TEXT, record_id TEXT, details TEXT NOT NULL, "
        "prev_hash TEXT NOT NULL, hash TEXT NOT NULL)"
    )


def _digest(prev_hash: str, entry: dict) -> str:
    payload = json.dumps({k: entry[k] for k in FIELDS}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + payload).encode()).hexdigest()


def record(conn, actor: str, action: str, entity: str | None = None, record_id=None, details: dict | None = None) -> None:
    row = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = row[0] if row else GENESIS
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "actor": actor, "action": action, "entity": entity,
        "record_id": None if record_id is None else str(record_id),
        "details": json.dumps(details or {}, sort_keys=True, default=str),
    }
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, entity, record_id, details, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)",
        (*[entry[k] for k in FIELDS], prev, _digest(prev, entry)),
    )
    conn.commit()


def query(conn, *, entity=None, actor=None, action=None, limit=200) -> list[dict]:
    sql, args = "SELECT * FROM audit_log WHERE 1=1", []
    for col, val in (("entity", entity), ("actor", actor), ("action", action)):
        if val:
            sql += f" AND {col} = ?"
            args.append(val)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    return [dict(r) | {"details": json.loads(r["details"])} for r in conn.execute(sql, args)]


def verify(conn) -> dict:
    prev = GENESIS
    count = 0
    for r in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        entry = dict(r)
        if entry["prev_hash"] != prev or _digest(prev, entry) != entry["hash"]:
            return {"ok": False, "entries": count, "broken_at": entry["id"]}
        prev = entry["hash"]
        count += 1
    return {"ok": True, "entries": count, "head": prev}
