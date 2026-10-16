"""Executable spec for the governance layer: each test is a policy the client cares about."""
import sqlite3

from fastapi.testclient import TestClient

from app.main import create_app


def rows(as_user, user, table, **params):
    r = as_user(user, "GET", f"/api/data/{table}", params=params)
    assert r.status_code == 200, r.text
    return r.json()


# ---------- row-level security ----------
def test_team_scope_limits_rows(as_user):
    names = {r["customer_name"] for r in rows(as_user, "alice", "kyc_cases")}
    assert "Sophie Martin" not in names  # owned by the EU compliance team
    assert "Maria Gonzalez" in names
    assert len(rows(as_user, "carol", "kyc_cases")) == 5  # manager: org-wide


def test_own_scope_blocks_updating_colleagues_records(as_user):
    ivys = [r for r in rows(as_user, "dave", "refunds") if r["owner_id"] == "ivy"]
    assert ivys, "team read scope lets dave see ivy's refunds"
    r = as_user("dave", "PATCH", f"/api/data/refunds/{ivys[0]['id']}", json={"reason": "fraud"})
    assert r.status_code == 403


def test_no_table_grant_means_no_access(as_user):
    assert as_user("frank", "GET", "/api/data/kyc_cases").status_code == 403
    assert as_user("grace", "GET", "/api/data/refunds").status_code == 403  # admins don't get data by default


# ---------- field-level security ----------
def test_sensitive_fields_masked_or_hidden_by_default(as_user):
    case = next(r for r in rows(as_user, "dave", "kyc_cases") if r["customer_name"] == "Maria Gonzalez")
    assert case["email"] == "m•••@example.com"
    assert case["date_of_birth"] == "••••••••"
    assert "ssn_last4" not in case  # restricted -> hidden unless granted


def test_explicit_grants_reveal_fields(as_user):
    analyst = next(r for r in rows(as_user, "alice", "kyc_cases") if r["customer_name"] == "Maria Gonzalez")
    manager = next(r for r in rows(as_user, "carol", "kyc_cases") if r["customer_name"] == "Maria Gonzalez")
    assert analyst["email"] == "maria.g@example.com" and analyst["ssn_last4"] == "••••"
    assert manager["ssn_last4"] == "4821"


def test_cannot_write_field_without_write_grant(as_user):
    r = as_user("alice", "PATCH", "/api/data/kyc_cases/2", json={"ssn_last4": "0000"})
    assert r.status_code == 403
    r = as_user("henry", "PATCH", "/api/data/refunds/1", json={"amount_usd": 1})
    assert r.status_code == 403


def test_cannot_filter_on_masked_field(as_user):
    r = as_user("dave", "GET", "/api/data/kyc_cases", params={"email": "maria.g@example.com"})
    assert r.status_code == 403
    assert len(rows(as_user, "alice", "kyc_cases", status="escalated")) == 1


# ---------- business rules ----------
def test_four_eyes_blocks_self_approval_and_stamps_approver(as_user):
    created = as_user("alice", "POST", "/api/data/kyc_cases",
                      json={"customer_name": "Test Person", "country": "US", "risk_score": 10})
    assert created.status_code == 201, created.text
    cid = created.json()["id"]
    assert as_user("alice", "PATCH", f"/api/data/kyc_cases/{cid}", json={"status": "approved"}).status_code == 403
    ok = as_user("bob", "PATCH", f"/api/data/kyc_cases/{cid}", json={"status": "approved"})
    assert ok.status_code == 200 and ok.json()["approved_by"] == "bob"


def test_approval_threshold_requires_role(as_user):
    big = as_user("dave", "POST", "/api/data/refunds",
                  json={"order_id": "ORD-1", "amount_usd": 900, "reason": "fraud"}).json()
    assert as_user("henry", "PATCH", f"/api/data/refunds/{big['id']}", json={"status": "approved"}).status_code == 403
    assert as_user("erin", "PATCH", f"/api/data/refunds/{big['id']}", json={"status": "approved"}).status_code == 200
    small = as_user("dave", "POST", "/api/data/refunds", json={"order_id": "ORD-2", "amount_usd": 20}).json()
    assert as_user("henry", "PATCH", f"/api/data/refunds/{small['id']}", json={"status": "approved"}).status_code == 200


def test_validation_and_system_stamped_columns(as_user):
    bad = [{"order_id": "X", "amount_usd": -5}, {"order_id": "X", "amount_usd": 5, "reason": "bored"},
           {"amount_usd": 5}, {"order_id": "X", "amount_usd": 5, "approved_by": "dave"}]
    for body in bad:
        assert as_user("dave", "POST", "/api/data/refunds", json=body).status_code == 422, body


# ---------- role administration ----------
def test_role_change_takes_effect_immediately_and_is_audited(as_user):
    role = next(r for r in as_user("grace", "GET", "/api/roles").json() if r["id"] == "support_agent")
    role["permissions"]["fields"]["kyc_cases.ssn_last4"] = "read"
    assert as_user("grace", "PUT", "/api/roles/support_agent", json=role).status_code == 200
    case = next(r for r in rows(as_user, "dave", "kyc_cases") if r["customer_name"] == "Maria Gonzalez")
    assert case["ssn_last4"] == "4821"
    log = as_user("grace", "GET", "/api/audit", params={"action": "role_update"}).json()
    assert log[0]["record_id"] == "support_agent" and log[0]["actor"] == "grace"


def test_only_role_managers_can_edit_roles(as_user):
    assert as_user("carol", "PUT", "/api/roles/x", json={"permissions": {}}).status_code == 403
    assert as_user("alice", "GET", "/api/roles").status_code == 403


def test_admin_cannot_self_grant_roles(as_user):
    r = as_user("grace", "PUT", "/api/users/grace/roles", json=["governance_admin", "compliance_manager"])
    assert r.status_code == 403
    assert as_user("grace", "PUT", "/api/users/dave/roles", json=["support_agent", "finance_lead"]).status_code == 200


def test_role_validation_rejects_unknown_tables_and_levels(as_user):
    for perms in ({"tables": {"nope": {"read": "all"}}}, {"tables": {"refunds": {"read": "everyone"}}},
                  {"fields": {"refunds.card_last4": "peek"}}):
        assert as_user("grace", "PUT", "/api/roles/bad", json={"permissions": perms}).status_code == 422


# ---------- audit ----------
def test_writes_denials_and_sensitive_reads_are_audited(as_user):
    as_user("alice", "PATCH", "/api/data/kyc_cases/2", json={"ssn_last4": "0000"})
    rows(as_user, "carol", "kyc_cases")
    log = as_user("carol", "GET", "/api/audit").json()
    actions = {(e["actor"], e["action"]) for e in log}
    assert ("alice", "denied") in actions
    assert ("carol", "read_sensitive") in actions
    assert ("bob", "update") in actions  # from seed


def test_restricted_values_never_written_to_audit(as_user):
    role = next(r for r in as_user("grace", "GET", "/api/roles").json() if r["id"] == "compliance_manager")
    role["permissions"]["fields"]["kyc_cases.ssn_last4"] = "write"
    as_user("grace", "PUT", "/api/roles/compliance_manager", json=role)
    assert as_user("carol", "PATCH", "/api/data/kyc_cases/2", json={"ssn_last4": "9999"}).status_code == 200
    entry = as_user("carol", "GET", "/api/audit", params={"action": "update", "entity": "kyc_cases"}).json()[0]
    assert entry["details"]["after"]["ssn_last4"] == "[restricted]"


def test_audit_chain_detects_tampering(app, as_user):
    assert as_user("grace", "GET", "/api/audit/verify").json()["ok"] is True
    app.state.svc.conn.execute("UPDATE audit_log SET actor = 'mallory' WHERE id = 2")
    result = as_user("grace", "GET", "/api/audit/verify").json()
    assert result == {"ok": False, "entries": 1, "broken_at": 2}


# ---------- extensibility ----------
def test_new_schema_file_becomes_governed_table_with_default_deny(tmp_path, schema_dir):
    db = str(tmp_path / "ext.db")
    create_app(db, schema_dir)
    (schema_dir / "vendor_payments.yaml").write_text(
        "name: vendor_payments\nlabel: Vendor Payments\ncolumns:\n"
        "  - {name: vendor, type: string, required: true}\n"
        "  - {name: iban, type: string, classification: restricted}\n")
    app = create_app(db, schema_dir)  # restart picks up the new table, existing data untouched
    c = TestClient(app)
    h = lambda u: {"X-User-Id": u}
    assert "vendor_payments" in [t["name"] for t in c.get("/api/tables", headers=h("carol")).json()]
    assert c.get("/api/data/vendor_payments", headers=h("carol")).status_code == 403
    assert len(c.get("/api/data/kyc_cases", headers=h("carol")).json()) == 5

    # Additive migration: a new column on an existing table is added in place.
    p = schema_dir / "refunds.yaml"
    p.write_text(p.read_text().replace("columns:\n", "columns:\n  - {name: ticket_url, type: string}\n", 1))
    c = TestClient(create_app(db, schema_dir))
    assert "ticket_url" in c.get("/api/data/refunds", headers=h("erin")).json()[0]
    cols = {r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(refunds)")}
    assert "ticket_url" in cols


# ---------- schema editor ----------
NEW_APP = """name: vendor_payments
label: Vendor Payments
columns:
  - {name: vendor, type: string, required: true}
  - {name: iban, type: string, classification: restricted}
  - {name: status, type: choice, choices: [draft, approved], default: draft}
  - {name: approved_by, type: user}
rules:
  - {type: four_eyes, when: {status: approved}, stamp: approved_by}
"""


def test_schema_editor_creates_live_app_with_default_deny(as_user, schema_dir):
    assert as_user("carol", "PUT", "/api/schema/vendor_payments", json={"yaml": NEW_APP}).status_code == 403
    r = as_user("grace", "PUT", "/api/schema/vendor_payments", json={"yaml": NEW_APP})
    assert r.status_code == 200 and r.json()["is_new"] and (schema_dir / "vendor_payments.yaml").exists()
    assert "vendor_payments" in [t["name"] for t in as_user("alice", "GET", "/api/tables").json()]
    assert as_user("grace", "GET", "/api/data/vendor_payments").status_code == 403  # creator gets nothing for free
    as_user("grace", "PUT", "/api/roles/vendor_clerk", json={"permissions": {"tables": {"vendor_payments": {"create": "team", "read": "team", "update": "team"}}}})
    as_user("grace", "PUT", "/api/users/henry/roles", json=["finance_analyst", "vendor_clerk"])
    assert as_user("henry", "POST", "/api/data/vendor_payments", json={"vendor": "Acme", "iban": "DE89"}).status_code == 403  # restricted
    created = as_user("henry", "POST", "/api/data/vendor_payments", json={"vendor": "Acme Paper"})
    assert created.status_code == 201 and "iban" not in created.json()  # restricted -> hidden by default
    assert as_user("henry", "PATCH", f"/api/data/vendor_payments/{created.json()['id']}", json={"status": "approved"}).status_code == 403
    assert as_user("grace", "GET", "/api/audit", params={"action": "schema_create"}).json()[0]["record_id"] is None


def test_schema_edits_are_additive_only(as_user):
    yaml_text = as_user("grace", "GET", "/api/schema/feature_flags").json()["yaml"]
    plus = yaml_text.replace("columns:\n", "columns:\n  - {name: owner_team, type: string}\n")
    r = as_user("grace", "POST", "/api/schema/validate", json={"yaml": plus})
    assert r.status_code == 200 and r.json()["added_columns"] == ["owner_team"]
    assert as_user("grace", "PUT", "/api/schema/feature_flags", json={"yaml": plus}).status_code == 200
    assert "owner_team" in as_user("frank", "GET", "/api/data/feature_flags").json()[0]
    minus = yaml_text.replace("  - {name: description, type: text}\n", "")
    assert as_user("grace", "PUT", "/api/schema/feature_flags", json={"yaml": minus}).status_code == 422
    retyped = yaml_text.replace("{name: rollout_percent, type: integer", "{name: rollout_percent, type: string")
    assert as_user("grace", "PUT", "/api/schema/feature_flags", json={"yaml": retyped}).status_code == 422
    assert as_user("grace", "PUT", "/api/schema/feature_flags", json={"yaml": "name: [broken"}).status_code == 422
    assert as_user("grace", "PUT", "/api/schema/other_name", json={"yaml": yaml_text}).status_code == 422
