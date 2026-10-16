"""Red-team tests: call the API directly, bypassing the UI, and check the server refuses.

Mirrors scripts/attack.sh so each probe is pinned as a regression test.
"""
import sqlite3

J = {"content-type": "application/json"}


def denied(as_user, actor):
    return [e["details"]["reason"] for e in as_user("grace", "GET", "/api/audit", params={"action": "denied", "actor": actor}).json()]


def test_idor_other_team_record_by_id_is_denied_and_logged(as_user):
    r = as_user("alice", "GET", "/api/data/kyc_cases/5")  # team compliance_eu
    assert r.status_code == 403 and "no read access to kyc_cases#5" in r.json()["detail"]
    assert "no read access to kyc_cases#5" in denied(as_user, "alice")


def test_cannot_infer_hidden_or_masked_values_via_filters(as_user):
    assert as_user("dave", "GET", "/api/data/kyc_cases", params={"ssn_last4": "4821"}).status_code == 403
    assert as_user("dave", "GET", "/api/data/kyc_cases", params={"email": "maria.g@example.com"}).status_code == 403
    assert as_user("alice", "GET", "/api/data/kyc_cases", params={"team": "compliance_eu"}).status_code == 422  # not a column
    assert "cannot filter on protected field ssn_last4" in denied(as_user, "dave")


def test_mass_assignment_of_system_columns_is_denied_not_crashed(as_user):
    before = len(as_user("carol", "GET", "/api/data/kyc_cases").json())
    for payload in ({"customer_name": "P", "country": "US", "team": "finance"},
                    {"customer_name": "P", "country": "US", "created_by": "carol"},
                    {"customer_name": "P", "country": "US", "id": 999}):
        r = as_user("alice", "POST", "/api/data/kyc_cases", json=payload)
        assert r.status_code == 403, r.text
    assert as_user("alice", "PATCH", "/api/data/kyc_cases/1", json={"team": "support"}).status_code == 403
    assert as_user("alice", "PATCH", "/api/data/kyc_cases/1", json={"owner_id": "alice"}).status_code == 403
    assert as_user("alice", "POST", "/api/data/kyc_cases", json={"customer_name": "P", "country": "US", "is_admin": True}).status_code == 422
    assert len(as_user("carol", "GET", "/api/data/kyc_cases").json()) == before
    assert as_user("carol", "GET", "/api/data/kyc_cases/1").json()["team"] == "compliance"
    assert any(r.startswith("cannot write system column") for r in denied(as_user, "alice"))


def test_sql_injection_in_filters_and_identifiers_is_inert(as_user):
    assert as_user("alice", "GET", "/api/data/kyc_cases", params={"country": "US' OR 1=1--"}).json() == []
    assert as_user("alice", "GET", "/api/data/kyc_cases", params={'country" OR 1=1--': "US"}).status_code == 422
    assert as_user("alice", "GET", "/api/data/audit_log").status_code == 404
    assert as_user("alice", "GET", "/api/data/kyc_cases/1 OR 1=1").status_code == 422
    evil = 'name: evil\nlabel: x\ncolumns:\n  - {name: "a\\" TEXT); DROP TABLE kyc_cases;--", type: string}'
    assert as_user("grace", "POST", "/api/schema/validate", json={"yaml": evil}).status_code == 422


def test_privilege_escalation_paths_are_closed(as_user):
    assert as_user("alice", "PUT", "/api/users/alice/roles", json=["kyc_analyst", "compliance_manager"]).status_code == 403
    assert as_user("alice", "PUT", "/api/roles/kyc_analyst", json={"permissions": {"tables": {"kyc_cases": {"read": "all"}}}}).status_code == 403
    assert as_user("alice", "PUT", "/api/schema/kyc_cases", json={"yaml": "name: kyc_cases\nlabel: x\ncolumns: []"}).status_code == 403
    assert as_user("alice", "GET", "/api/data/kyc_cases/5").status_code == 403  # still no access afterwards


def test_identity_is_required_and_cannot_be_passed_in_the_query(client):
    assert client.get("/api/data/kyc_cases").status_code == 422
    assert client.get("/api/data/kyc_cases", params={"as": "carol"}).status_code == 422
    assert client.get("/api/data/kyc_cases", headers={"X-User-Id": "mallory"}).status_code == 403
    assert client.get("/api/data/kyc_cases", headers={"X-User-Id": "Carol"}).status_code == 403


def test_audit_log_has_no_write_api_and_direct_edits_are_detected(as_user, client):
    assert as_user("grace", "DELETE", "/api/audit/1").status_code == 404
    assert as_user("grace", "PATCH", "/api/audit/1", json={"actor": "nobody"}).status_code == 404
    assert as_user("alice", "GET", "/api/audit").status_code == 403
    assert as_user("grace", "GET", "/api/audit/verify").json()["ok"] is True
    conn = client.app.state.svc.conn
    conn.execute("UPDATE audit_log SET actor = 'nobody' WHERE action = 'denied'")
    conn.commit()
    assert as_user("grace", "GET", "/api/audit/verify").json()["ok"] is False
