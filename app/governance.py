"""Governance engine: roles, row-level scopes, field-level security, business rules.

Model (mirrors Dataverse security roles, simplified):
  * A role grants each table a scope per privilege: none < own < team < all.
  * Columns carry a data classification. Sensitive columns default to masked
    (pii/financial) or hidden (restricted) unless a role explicitly grants more.
  * A user with several roles gets the union (most permissive) of them.
  * Every write, denial and sensitive read goes to the audit log.
All data access goes through `DataService`, so no caller can bypass policy.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import audit
from .schema import SYSTEM_COLUMNS, Table, ValidationError, check_compatible, ensure_tables, parse_table, validate

SCOPES = ("none", "own", "team", "all")
PRIVILEGES = ("create", "read", "update", "delete")
FIELD_LEVELS = ("hidden", "masked", "read", "write")
CAPABILITIES = ("manage_roles", "view_audit", "manage_schema")
DEFAULT_FIELD_LEVEL = {"internal": "write", "pii": "masked", "financial": "masked", "restricted": "hidden"}


class Forbidden(PermissionError):
    pass


class NotFound(LookupError):
    pass


@dataclass
class User:
    id: str
    name: str
    team: str
    roles: list[str]
    email: str = ""


@dataclass
class Effective:
    """A user's merged permissions across all their roles."""
    tables: dict[str, dict[str, str]] = field(default_factory=dict)
    fields: dict[str, str] = field(default_factory=dict)
    capabilities: set[str] = field(default_factory=set)
    roles: set[str] = field(default_factory=set)

    def scope(self, table: str, privilege: str) -> str:
        return self.tables.get(table, {}).get(privilege, "none")

    def field_level(self, table: Table, column: str) -> str:
        default = DEFAULT_FIELD_LEVEL[table.column(column).classification]
        return self.fields.get(f"{table.name}.{column}", default)

    def to_dict(self, tables: dict[str, Table]) -> dict:
        return {
            "roles": sorted(self.roles),
            "capabilities": sorted(self.capabilities),
            "tables": {t: {p: self.scope(t, p) for p in PRIVILEGES} for t in tables},
            "fields": {f"{t.name}.{c.name}": self.field_level(t, c.name) for t in tables.values() for c in t.columns},
        }


log = logging.getLogger("governance")
if not log.handlers:  # uvicorn only configures its own loggers; make denials visible in the server log
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(levelname)s:  [%(name)s] %(message)s"))
    log.addHandler(_h)
    log.setLevel(logging.INFO)


def _max(order, a, b):
    return a if order.index(a) >= order.index(b) else b


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def mask(value):
    if value is None:
        return None
    s = str(value)
    if "@" in s:
        local, _, domain = s.partition("@")
        return f"{local[:1]}•••@{domain}"
    return "•" * min(max(len(s), 4), 8)


def validate_role(role: dict, tables: dict[str, Table]) -> dict:
    perms = role.get("permissions") or {}
    tperms = {}
    for tname, privs in (perms.get("tables") or {}).items():
        if tname not in tables:
            raise ValidationError(f"unknown table {tname!r}")
        for p, s in privs.items():
            if p not in PRIVILEGES or s not in SCOPES:
                raise ValidationError(f"invalid privilege {tname}.{p}={s}")
        tperms[tname] = {p: privs.get(p, "none") for p in PRIVILEGES}
    fperms = {}
    for key, level in (perms.get("fields") or {}).items():
        tname, _, cname = key.partition(".")
        if tname not in tables or tables[tname].column(cname) is None:
            raise ValidationError(f"unknown field {key!r}")
        if level not in FIELD_LEVELS:
            raise ValidationError(f"invalid field level {key}={level}")
        fperms[key] = level
    caps = role.get("capabilities") or []
    if any(c not in CAPABILITIES for c in caps):
        raise ValidationError(f"capabilities must be within {CAPABILITIES}")
    if not role.get("id") or not str(role["id"]).replace("_", "").isalnum():
        raise ValidationError("role id must be alphanumeric/underscore")
    return {"id": role["id"], "name": role.get("name") or role["id"], "description": role.get("description", ""),
            "permissions": {"tables": tperms, "fields": fperms}, "capabilities": sorted(caps)}


class DataService:
    def __init__(self, conn, tables: dict[str, Table]):
        self.conn = conn
        self.tables = tables

    # ---------- identity & roles ----------
    def init_meta(self) -> None:
        self.conn.execute("CREATE TABLE IF NOT EXISTS roles (id TEXT PRIMARY KEY, name TEXT, description TEXT, "
                          "permissions TEXT NOT NULL, capabilities TEXT NOT NULL)")
        self.conn.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT, email TEXT, "
                          "team TEXT NOT NULL, roles TEXT NOT NULL)")
        audit.init(self.conn)
        self.conn.commit()

    def get_user(self, user_id: str) -> User:
        r = self.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not r:
            raise Forbidden("unknown user")
        return User(id=r["id"], name=r["name"], team=r["team"], roles=json.loads(r["roles"]), email=r["email"])

    def list_users(self) -> list[dict]:
        return [dict(r) | {"roles": json.loads(r["roles"])} for r in self.conn.execute("SELECT * FROM users ORDER BY id")]

    def list_roles(self) -> list[dict]:
        return [dict(r) | {"permissions": json.loads(r["permissions"]), "capabilities": json.loads(r["capabilities"])}
                for r in self.conn.execute("SELECT * FROM roles ORDER BY id")]

    def effective(self, user: User) -> Effective:
        eff = Effective()
        roles = {r["id"]: r for r in self.list_roles()}
        for rid in user.roles:
            role = roles.get(rid)
            if not role:
                continue
            eff.roles.add(rid)
            eff.capabilities.update(role["capabilities"])
            for t, privs in role["permissions"].get("tables", {}).items():
                cur = eff.tables.setdefault(t, {})
                for p, s in privs.items():
                    cur[p] = _max(SCOPES, cur.get(p, "none"), s)
            # Per role, an ungranted column falls back to its classification default; across roles, most permissive wins.
            grants = role["permissions"].get("fields", {})
            for t in self.tables.values():
                for c in t.columns:
                    key = f"{t.name}.{c.name}"
                    lvl = grants.get(key, DEFAULT_FIELD_LEVEL[c.classification])
                    eff.fields[key] = _max(FIELD_LEVELS, eff.fields.get(key, "hidden"), lvl)
        return eff

    def _require_cap(self, user: User, cap: str) -> None:
        if cap not in self.effective(user).capabilities:
            self._deny(user, f"missing capability {cap}")

    def save_role(self, user: User, role: dict, *, actor_override: str | None = None) -> dict:
        if actor_override is None:
            self._require_cap(user, "manage_roles")
        clean = validate_role(role, self.tables)
        before = next((r for r in self.list_roles() if r["id"] == clean["id"]), None)
        self.conn.execute("INSERT OR REPLACE INTO roles VALUES (?,?,?,?,?)",
                          (clean["id"], clean["name"], clean["description"],
                           json.dumps(clean["permissions"]), json.dumps(clean["capabilities"])))
        audit.record(self.conn, actor_override or user.id, "role_update" if before else "role_create", "roles",
                     clean["id"], {"before": before and {k: before[k] for k in ("permissions", "capabilities")},
                                   "after": {k: clean[k] for k in ("permissions", "capabilities")}})
        return clean

    def delete_role(self, user: User, role_id: str) -> None:
        self._require_cap(user, "manage_roles")
        if any(role_id in u["roles"] for u in self.list_users()):
            raise ValidationError("role is still assigned to users")
        self.conn.execute("DELETE FROM roles WHERE id = ?", (role_id,))
        audit.record(self.conn, user.id, "role_delete", "roles", role_id)

    def set_user_roles(self, user: User, target_id: str, roles: list[str]) -> None:
        self._require_cap(user, "manage_roles")
        target = self.get_user(target_id)
        known = {r["id"] for r in self.list_roles()}
        if any(r not in known for r in roles):
            raise ValidationError("unknown role")
        if target_id == user.id and "manage_roles" in self.effective(user).capabilities:
            # Prevent an admin from silently escalating their own data access.
            if set(roles) - set(target.roles):
                self._deny(user, "cannot grant roles to yourself")
        self.conn.execute("UPDATE users SET roles = ? WHERE id = ?", (json.dumps(sorted(roles)), target_id))
        audit.record(self.conn, user.id, "user_roles_update", "users", target_id,
                     {"before": target.roles, "after": sorted(roles)})

    # ---------- schema administration ----------
    def preview_schema(self, user: User, yaml_text: str) -> dict:
        self._require_cap(user, "manage_schema")
        table = self._parse_yaml(yaml_text)
        added = check_compatible(self.tables.get(table.name), table)
        return table.to_dict() | {"is_new": table.name not in self.tables, "added_columns": added}

    def save_schema(self, user: User, name: str, yaml_text: str, schema_dir) -> dict:
        self._require_cap(user, "manage_schema")
        table = self._parse_yaml(yaml_text)
        if table.name != name:
            raise ValidationError(f"schema name {table.name!r} does not match {name!r}")
        is_new = name not in self.tables
        added = check_compatible(self.tables.get(name), table)
        (schema_dir / f"{name}.yaml").write_text(yaml_text if yaml_text.endswith("\n") else yaml_text + "\n")
        ensure_tables(self.conn, {name: table})
        self.tables[name] = table  # hot reload: shared dict, so the API and UI see it on the next request
        audit.record(self.conn, user.id, "schema_create" if is_new else "schema_update", name, None,
                     {"added_columns": added, "columns": [c.name for c in table.columns]})
        return table.to_dict() | {"is_new": is_new, "added_columns": added}

    @staticmethod
    def _parse_yaml(yaml_text: str) -> Table:
        import yaml
        try:
            raw = yaml.safe_load(yaml_text)
        except yaml.YAMLError as e:
            raise ValidationError(f"YAML syntax: {e}")
        if not isinstance(raw, dict):
            raise ValidationError("schema must be a YAML mapping with name/label/columns")
        try:
            return parse_table(raw)
        except (ValueError, TypeError) as e:
            raise ValidationError(str(e))

    # ---------- data access ----------
    def _table(self, name: str) -> Table:
        if name not in self.tables:
            raise NotFound(f"no table {name}")
        return self.tables[name]

    def _deny(self, user: User, reason: str, table: str | None = None, record_id=None):
        audit.record(self.conn, user.id, "denied", table, record_id, {"reason": reason})
        where = f"{table}#{record_id}" if record_id is not None else (table or "-")
        log.warning("DENIED actor=%s roles=%s target=%s reason=%r (audited)", user.id, ",".join(user.roles), where, reason)
        raise Forbidden(reason)

    @staticmethod
    def _scope_sql(scope: str, user: User) -> tuple[str, list]:
        if scope == "all":
            return "1=1", []
        if scope == "team":
            return "team = ?", [user.team]
        if scope == "own":
            return "owner_id = ?", [user.id]
        return "1=0", []

    @staticmethod
    def _in_scope(scope: str, user: User, row: dict) -> bool:
        return scope == "all" or (scope == "team" and row["team"] == user.team) or \
            (scope == "own" and row["owner_id"] == user.id)

    def _project(self, table: Table, eff: Effective, row: dict) -> dict:
        out = {k: row[k] for k in SYSTEM_COLUMNS}
        for col in table.columns:
            level = eff.field_level(table, col.name)
            if level == "hidden":
                continue
            out[col.name] = mask(row[col.name]) if level == "masked" else row[col.name]
        return out

    def _revealed_sensitive(self, table: Table, eff: Effective) -> list[str]:
        return [c.name for c in table.columns if c.sensitive and eff.field_level(table, c.name) in ("read", "write")]

    def _fetch(self, table: Table, record_id: int) -> dict:
        r = self.conn.execute(f'SELECT * FROM "{table.name}" WHERE id = ?', (record_id,)).fetchone()
        if not r:
            raise NotFound("record not found")
        return dict(r)

    def list(self, user: User, table_name: str, filters: dict | None = None) -> list[dict]:
        table, eff = self._table(table_name), self.effective(user)
        scope = eff.scope(table.name, "read")
        if scope == "none":
            self._deny(user, f"no read access to {table.name}", table.name)
        where, args = self._scope_sql(scope, user)
        for key, val in (filters or {}).items():
            if table.column(key) is None:
                raise ValidationError(f"unknown column {key!r}")
            if eff.field_level(table, key) not in ("read", "write"):
                # Filtering on a masked column would let users infer its value.
                self._deny(user, f"cannot filter on protected field {key}", table.name)
            where += f' AND "{key}" = ?'
            args.append(val)
        rows = [dict(r) for r in self.conn.execute(f'SELECT * FROM "{table.name}" WHERE {where} ORDER BY id DESC', args)]
        revealed = self._revealed_sensitive(table, eff)
        if rows and revealed:
            audit.record(self.conn, user.id, "read_sensitive", table.name, None,
                         {"fields": revealed, "records": [r["id"] for r in rows]})
        return [self._project(table, eff, r) for r in rows]

    def get(self, user: User, table_name: str, record_id: int) -> dict:
        table, eff = self._table(table_name), self.effective(user)
        row = self._fetch(table, record_id)
        if not self._in_scope(eff.scope(table.name, "read"), user, row):
            self._deny(user, f"no read access to {table.name}#{record_id}", table.name, record_id)
        revealed = self._revealed_sensitive(table, eff)
        if revealed:
            audit.record(self.conn, user.id, "read_sensitive", table.name, record_id, {"fields": revealed})
        return self._project(table, eff, row)

    def _check_keys(self, user: User, table: Table, values: dict, record_id=None):
        """Reject mass assignment: system columns are never client-writable, unknown columns are a 422."""
        for key in values:
            if key in SYSTEM_COLUMNS:
                self._deny(user, f"cannot write system column {key}", table.name, record_id)
            if table.column(key) is None:
                raise ValidationError(f"unknown column {key!r}")

    def _check_field_writes(self, user: User, table: Table, eff: Effective, values: dict, record_id=None):
        for key in values:
            if eff.field_level(table, key) != "write":
                self._deny(user, f"no write access to field {key}", table.name, record_id)

    def _apply_rules(self, user: User, table: Table, eff: Effective, before: dict, values: dict, record_id=None):
        merged = {**before, **values}
        for rule in table.rules:
            when = rule.get("when", {})
            triggered = all(values.get(k) == v and before.get(k) != v for k, v in when.items())
            if not triggered:
                continue
            if rule["type"] == "four_eyes":
                if before.get("created_by") == user.id:
                    self._deny(user, "four-eyes rule: you cannot approve a record you created", table.name, record_id)
                values[rule["stamp"]] = user.id
            elif rule["type"] == "approval_threshold":
                amount = merged.get(rule["field"]) or 0
                if amount > rule["threshold"] and rule["approver_role"] not in eff.roles:
                    self._deny(user, f"{rule['field']} above {rule['threshold']} requires role "
                                     f"{rule['approver_role']}", table.name, record_id)

    def create(self, user: User, table_name: str, values: dict) -> dict:
        table, eff = self._table(table_name), self.effective(user)
        if eff.scope(table.name, "create") == "none":
            self._deny(user, f"no create access to {table.name}", table.name)
        self._check_keys(user, table, values)
        self._check_field_writes(user, table, eff, values)
        clean = validate(table, values, creating=True)
        self._apply_rules(user, table, eff, {"created_by": user.id}, clean)
        ts = now()
        row = {**clean, "owner_id": user.id, "team": user.team, "created_by": user.id, "created_at": ts, "updated_at": ts}
        cols = ", ".join(f'"{k}"' for k in row)
        cur = self.conn.execute(f'INSERT INTO "{table.name}" ({cols}) VALUES ({", ".join("?" * len(row))})',
                                list(row.values()))
        audit.record(self.conn, user.id, "create", table.name, cur.lastrowid, {"after": self._redact(table, clean)})
        return self._project(table, eff, self._fetch(table, cur.lastrowid))

    def update(self, user: User, table_name: str, record_id: int, values: dict) -> dict:
        table, eff = self._table(table_name), self.effective(user)
        before = self._fetch(table, record_id)
        if not self._in_scope(eff.scope(table.name, "update"), user, before):
            self._deny(user, f"no update access to {table.name}#{record_id}", table.name, record_id)
        self._check_keys(user, table, values, record_id)
        clean = validate(table, values, creating=False)
        clean = {k: v for k, v in clean.items() if before.get(k) != v}
        self._check_field_writes(user, table, eff, clean, record_id)
        if not clean:
            return self._project(table, eff, before)
        self._apply_rules(user, table, eff, before, clean, record_id)
        sets = ", ".join(f'"{k}" = ?' for k in clean)
        self.conn.execute(f'UPDATE "{table.name}" SET {sets}, updated_at = ? WHERE id = ?',
                          [*clean.values(), now(), record_id])
        audit.record(self.conn, user.id, "update", table.name, record_id, {
            "before": self._redact(table, {k: before.get(k) for k in clean}),
            "after": self._redact(table, clean)})
        return self._project(table, eff, self._fetch(table, record_id))

    def delete(self, user: User, table_name: str, record_id: int) -> None:
        table, eff = self._table(table_name), self.effective(user)
        before = self._fetch(table, record_id)
        if not self._in_scope(eff.scope(table.name, "delete"), user, before):
            self._deny(user, f"no delete access to {table.name}#{record_id}", table.name, record_id)
        self.conn.execute(f'DELETE FROM "{table.name}" WHERE id = ?', (record_id,))
        audit.record(self.conn, user.id, "delete", table.name, record_id,
                     {"before": self._redact(table, {c.name: before[c.name] for c in table.columns})})

    def import_rows(self, actor: str, table_name: str, owner: User, rows: list[dict]) -> list[int]:
        """Bulk load (e.g. migration from Power Apps / Dataverse). System-only; not exposed over HTTP."""
        table, ids, ts = self._table(table_name), [], now()
        for values in rows:
            clean = {k: v for k, v in validate(table, values, creating=True).items()}
            row = {**clean, "owner_id": owner.id, "team": owner.team, "created_by": owner.id,
                   "created_at": ts, "updated_at": ts}
            cols = ", ".join(f'"{k}"' for k in row)
            cur = self.conn.execute(f'INSERT INTO "{table.name}" ({cols}) VALUES ({", ".join("?" * len(row))})',
                                    list(row.values()))
            ids.append(cur.lastrowid)
        audit.record(self.conn, actor, "import", table.name, None, {"count": len(ids), "owner": owner.id})
        return ids

    @staticmethod
    def _redact(table: Table, values: dict) -> dict:
        # The audit log must not become a second copy of restricted data.
        return {k: ("[restricted]" if (c := table.column(k)) and c.classification == "restricted" and v is not None else v)
                for k, v in values.items()}

    # ---------- governance views ----------
    def access_matrix(self, user: User) -> dict:
        self._require_cap(user, "view_audit")
        users = [self.get_user(u["id"]) for u in self.list_users()]
        effs = {u.id: self.effective(u) for u in users}
        tables = {t: {u.id: {p: effs[u.id].scope(t, p) for p in PRIVILEGES} for u in users} for t in self.tables}
        fields = {
            f"{t.name}.{c.name}": {"classification": c.classification,
                                   "users": {u.id: effs[u.id].field_level(t, c.name)
                                             if effs[u.id].scope(t.name, "read") != "none" else "no_access"
                                             for u in users}}
            for t in self.tables.values() for c in t.columns if c.sensitive
        }
        return {"users": [u.__dict__ for u in users], "tables": tables, "fields": fields}
