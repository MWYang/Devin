"""HTTP API + static dashboard. Identity comes from the X-User-Id header (stand-in for SSO/OIDC)."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from fastapi import Body, Depends, FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import audit
from .governance import (CAPABILITIES, DEFAULT_FIELD_LEVEL, FIELD_LEVELS, PRIVILEGES, SCOPES, DataService,
                         Forbidden, NotFound, User)
from .schema import ValidationError, ensure_tables, load_schemas
from .seed import seed

ROOT = Path(__file__).resolve().parent.parent


def create_app(db_path: str | None = None, schema_dir: Path | None = None, with_seed: bool = True) -> FastAPI:
    conn = sqlite3.connect(db_path or os.environ.get("DATAGOV_DB", str(ROOT / "data.db")), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    tables = load_schemas(schema_dir or ROOT / "schema")
    ensure_tables(conn, tables)
    svc = DataService(conn, tables)
    svc.init_meta()
    if with_seed:
        seed(svc)

    app = FastAPI(title="Governed Data Layer")
    app.state.svc = svc

    for exc, code in ((Forbidden, 403), (NotFound, 404), (ValidationError, 422)):
        app.add_exception_handler(exc, lambda _r, e, code=code: JSONResponse({"detail": str(e)}, status_code=code))

    def current_user(x_user_id: str = Header(...)) -> User:
        return svc.get_user(x_user_id)

    # All endpoints are `async def` so requests are serialized on one thread (single SQLite connection).
    @app.get("/api/me")
    async def me(user: User = Depends(current_user)):
        return user.__dict__ | {"effective": svc.effective(user).to_dict(tables)}

    @app.get("/api/users")
    async def users():
        # Public only for the demo user switcher; in production this comes from the IdP.
        return svc.list_users()

    @app.get("/api/tables")
    async def list_tables(user: User = Depends(current_user)):
        return [t.to_dict() for t in tables.values()]

    @app.get("/api/meta")
    async def meta():
        return {"scopes": SCOPES, "privileges": PRIVILEGES, "field_levels": FIELD_LEVELS,
                "capabilities": CAPABILITIES, "default_field_level": DEFAULT_FIELD_LEVEL}

    @app.get("/api/data/{table}")
    async def list_rows(table: str, request: Request, user: User = Depends(current_user)):
        return svc.list(user, table, dict(request.query_params))

    @app.get("/api/data/{table}/{record_id}")
    async def get_row(table: str, record_id: int, user: User = Depends(current_user)):
        return svc.get(user, table, record_id)

    @app.post("/api/data/{table}", status_code=201)
    async def create_row(table: str, values: dict = Body(...), user: User = Depends(current_user)):
        return svc.create(user, table, values)

    @app.patch("/api/data/{table}/{record_id}")
    async def update_row(table: str, record_id: int, values: dict = Body(...), user: User = Depends(current_user)):
        return svc.update(user, table, record_id, values)

    @app.delete("/api/data/{table}/{record_id}", status_code=204)
    async def delete_row(table: str, record_id: int, user: User = Depends(current_user)):
        svc.delete(user, table, record_id)

    @app.get("/api/roles")
    async def roles(user: User = Depends(current_user)):
        caps = svc.effective(user).capabilities
        if not caps & {"manage_roles", "view_audit"}:
            raise Forbidden("missing capability manage_roles or view_audit")
        return svc.list_roles()

    @app.put("/api/roles/{role_id}")
    async def put_role(role_id: str, role: dict = Body(...), user: User = Depends(current_user)):
        return svc.save_role(user, role | {"id": role_id})

    @app.delete("/api/roles/{role_id}", status_code=204)
    async def delete_role(role_id: str, user: User = Depends(current_user)):
        svc.delete_role(user, role_id)

    @app.put("/api/users/{user_id}/roles")
    async def put_user_roles(user_id: str, roles: list[str] = Body(...), user: User = Depends(current_user)):
        svc.set_user_roles(user, user_id, roles)
        return svc.get_user(user_id).__dict__

    @app.get("/api/governance/matrix")
    async def matrix(user: User = Depends(current_user)):
        return svc.access_matrix(user)

    @app.get("/api/audit")
    async def audit_log(entity: str | None = None, actor: str | None = None, action: str | None = None,
                        user: User = Depends(current_user)):
        svc._require_cap(user, "view_audit")
        return audit.query(conn, entity=entity, actor=actor, action=action)

    @app.get("/api/audit/verify")
    async def audit_verify(user: User = Depends(current_user)):
        svc._require_cap(user, "view_audit")
        return audit.verify(conn)

    app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

    @app.get("/")
    async def index():
        return FileResponse(ROOT / "static" / "index.html")

    return app

