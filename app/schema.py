"""Schema registry: YAML table definitions -> governed SQLite tables.

This is the Dataverse "table/column" equivalent. Every table automatically gets
system columns used by the governance engine (ownership, team, timestamps).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

SQL_TYPES = {
    "string": "TEXT", "text": "TEXT", "date": "TEXT", "choice": "TEXT", "user": "TEXT",
    "integer": "INTEGER", "boolean": "INTEGER", "decimal": "REAL",
}
CLASSIFICATIONS = ("internal", "pii", "financial", "restricted")
SYSTEM_COLUMNS = ("id", "owner_id", "team", "created_by", "created_at", "updated_at")
IDENT = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


class ValidationError(ValueError):
    pass


@dataclass
class Column:
    name: str
    type: str
    classification: str = "internal"
    required: bool = False
    choices: list[str] | None = None
    default: Any = None
    min: float | None = None
    max: float | None = None

    @property
    def sensitive(self) -> bool:
        return self.classification != "internal"

    @property
    def system_stamped(self) -> bool:
        # `user` columns are written only by the engine (e.g. approved_by), never by clients.
        return self.type == "user"


@dataclass
class Table:
    name: str
    label: str
    description: str = ""
    display_field: str | None = None
    columns: list[Column] = field(default_factory=list)
    rules: list[dict] = field(default_factory=list)

    def column(self, name: str) -> Column | None:
        return next((c for c in self.columns if c.name == name), None)

    def to_dict(self) -> dict:
        return {
            "name": self.name, "label": self.label, "description": self.description,
            "display_field": self.display_field, "rules": self.rules,
            "columns": [c.__dict__ | {"sensitive": c.sensitive} for c in self.columns],
        }


def parse_table(raw: dict) -> Table:
    name = raw["name"]
    if not IDENT.match(name):
        raise ValueError(f"invalid table name {name!r}")
    cols = []
    for c in raw.get("columns", []):
        col = Column(**c)
        if not IDENT.match(col.name) or col.name in SYSTEM_COLUMNS:
            raise ValueError(f"{name}: invalid column name {col.name!r}")
        if col.type not in SQL_TYPES:
            raise ValueError(f"{name}.{col.name}: unknown type {col.type!r}")
        if col.classification not in CLASSIFICATIONS:
            raise ValueError(f"{name}.{col.name}: unknown classification {col.classification!r}")
        if col.type == "choice" and not col.choices:
            raise ValueError(f"{name}.{col.name}: choice column needs choices")
        cols.append(col)
    for rule in raw.get("rules", []):
        need = {"four_eyes": {"when", "stamp"}, "approval_threshold": {"when", "field", "threshold", "approver_role"}}
        if rule.get("type") not in need or not need[rule["type"]] <= rule.keys():
            raise ValueError(f"{name}: invalid rule {rule}")
    return Table(name=name, label=raw.get("label", name), description=raw.get("description", ""),
                 display_field=raw.get("display_field"), columns=cols, rules=raw.get("rules", []))


def check_compatible(old: Table | None, new: Table) -> list[str]:
    """Only additive changes are allowed: a column can be added, never removed or retyped."""
    if old is None:
        return [c.name for c in new.columns]
    for c in old.columns:
        n = new.column(c.name)
        if n is None:
            raise ValidationError(f"column {c.name!r} cannot be removed (existing data would be lost)")
        if n.type != c.type:
            raise ValidationError(f"column {c.name!r} cannot change type {c.type} -> {n.type}")
    return [c.name for c in new.columns if old.column(c.name) is None]


def load_schemas(directory: Path) -> dict[str, Table]:
    tables = {}
    for path in sorted(directory.glob("*.yaml")):
        t = parse_table(yaml.safe_load(path.read_text()))
        tables[t.name] = t
    return tables


def ensure_tables(conn, tables: dict[str, Table]) -> None:
    """Create tables and apply additive migrations (new columns). Never drops data."""
    for t in tables.values():
        conn.execute(
            f'CREATE TABLE IF NOT EXISTS "{t.name}" ('
            "id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id TEXT NOT NULL, team TEXT NOT NULL, "
            "created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        existing = {r[1] for r in conn.execute(f'PRAGMA table_info("{t.name}")')}
        for c in t.columns:
            if c.name not in existing:
                conn.execute(f'ALTER TABLE "{t.name}" ADD COLUMN "{c.name}" {SQL_TYPES[c.type]}')
    conn.commit()


def coerce(col: Column, value: Any) -> Any:
    if value is None or value == "":
        return None
    try:
        if col.type == "integer":
            v = int(value)
        elif col.type == "decimal":
            v = round(float(value), 2)
        elif col.type == "boolean":
            v = 1 if value in (True, 1, "1", "true", "True", "on") else 0
        elif col.type == "date":
            v = date.fromisoformat(str(value)).isoformat()
        else:
            v = str(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{col.name}: expected {col.type}")
    if col.type == "choice" and v not in col.choices:
        raise ValidationError(f"{col.name}: must be one of {col.choices}")
    if col.min is not None and v < col.min:
        raise ValidationError(f"{col.name}: must be >= {col.min}")
    if col.max is not None and v > col.max:
        raise ValidationError(f"{col.name}: must be <= {col.max}")
    return v


def validate(table: Table, values: dict, *, creating: bool) -> dict:
    out = {}
    for key, value in values.items():
        col = table.column(key)
        if col is None:
            raise ValidationError(f"unknown column {key!r}")
        if col.system_stamped:
            raise ValidationError(f"{key} is set by the system and cannot be written directly")
        out[key] = coerce(col, value)
    if creating:
        for col in table.columns:
            if col.name not in out and col.default is not None:
                out[col.name] = coerce(col, col.default)
            if col.required and out.get(col.name) is None:
                raise ValidationError(f"{col.name} is required")
    else:
        for key, v in out.items():
            if table.column(key).required and v is None:
                raise ValidationError(f"{key} is required")
    return out
