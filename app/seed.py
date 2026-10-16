"""Demo roles, users and records for the three existing Power Apps."""
import json

USERS = [
    ("alice", "Alice Chen", "compliance", ["kyc_analyst"]),
    ("bob", "Bob Okafor", "compliance", ["kyc_analyst"]),
    ("carol", "Carol Diaz", "compliance", ["compliance_manager"]),
    ("dave", "Dave Kim", "support", ["support_agent"]),
    ("ivy", "Ivy Novak", "support", ["support_agent"]),
    ("henry", "Henry Ito", "finance", ["finance_analyst"]),
    ("erin", "Erin Patel", "finance", ["finance_lead"]),
    ("frank", "Frank Muller", "platform", ["platform_engineer"]),
    ("grace", "Grace Lee", "security", ["governance_admin"]),
]

ALL = {"create": "all", "read": "all", "update": "all", "delete": "all"}
ROLES = [
    {"id": "kyc_analyst", "name": "KYC Analyst", "description": "Works the KYC queue for their team.",
     "permissions": {"tables": {"kyc_cases": {"create": "team", "read": "team", "update": "team", "delete": "none"}},
                     "fields": {"kyc_cases.email": "write", "kyc_cases.date_of_birth": "write",
                                "kyc_cases.ssn_last4": "masked"}}},
    {"id": "compliance_manager", "name": "Compliance Manager", "description": "Full KYC access incl. restricted fields; can view audit.",
     "permissions": {"tables": {"kyc_cases": ALL},
                     "fields": {"kyc_cases.email": "write", "kyc_cases.date_of_birth": "write",
                                "kyc_cases.ssn_last4": "read"}},
     "capabilities": ["view_audit"]},
    {"id": "support_agent", "name": "Support Agent", "description": "Files refunds; read-only, masked view of KYC status.",
     "permissions": {"tables": {"refunds": {"create": "team", "read": "team", "update": "own", "delete": "none"},
                                "kyc_cases": {"create": "none", "read": "all", "update": "none", "delete": "none"}},
                     "fields": {"refunds.customer_email": "write", "refunds.amount_usd": "write",
                                "refunds.card_last4": "masked"}}},
    {"id": "finance_analyst", "name": "Finance Analyst", "description": "Reviews and approves refunds up to the threshold.",
     "permissions": {"tables": {"refunds": {"create": "none", "read": "all", "update": "all", "delete": "none"}},
                     "fields": {"refunds.customer_email": "read", "refunds.amount_usd": "read",
                                "refunds.card_last4": "masked"}}},
    {"id": "finance_lead", "name": "Finance Lead", "description": "Approves refunds of any size.",
     "permissions": {"tables": {"refunds": {"create": "none", "read": "all", "update": "all", "delete": "none"}},
                     "fields": {"refunds.customer_email": "read", "refunds.amount_usd": "read",
                                "refunds.card_last4": "read"}}},
    {"id": "platform_engineer", "name": "Platform Engineer", "description": "Manages feature flags.",
     "permissions": {"tables": {"feature_flags": ALL}}},
    {"id": "governance_admin", "name": "Governance Admin", "description": "Manages roles and reviews audit. No data access by default.",
     "permissions": {"tables": {}}, "capabilities": ["manage_roles", "view_audit"]},
]

KYC = [
    ("onboard", "compliance", {"customer_name": "Maria Gonzalez", "email": "maria.g@example.com", "date_of_birth": "1988-04-12", "ssn_last4": "4821", "country": "US", "risk_score": 22}),
    ("onboard", "compliance", {"customer_name": "Liam O'Brien", "email": "liam.ob@example.com", "date_of_birth": "1992-11-03", "ssn_last4": "1177", "country": "IE", "risk_score": 67, "status": "in_review"}),
    ("onboard", "compliance", {"customer_name": "Yuki Tanaka", "email": "yuki.t@example.com", "date_of_birth": "1979-06-30", "ssn_last4": "9034", "country": "JP", "risk_score": 88, "status": "escalated", "reviewer_notes": "Name match on sanctions list; needs manager review."}),
    ("onboard", "compliance", {"customer_name": "Ahmed Hassan", "email": "ahmed.h@example.com", "date_of_birth": "1995-01-21", "ssn_last4": "5560", "country": "AE", "risk_score": 41}),
    ("onboard_eu", "compliance_eu", {"customer_name": "Sophie Martin", "email": "sophie.m@example.com", "date_of_birth": "1990-08-14", "ssn_last4": "3302", "country": "FR", "risk_score": 15}),
]
REFUNDS = [
    ("dave", {"order_id": "ORD-10421", "customer_email": "j.smith@example.com", "amount_usd": 49.99, "reason": "damaged", "card_last4": "4242"}),
    ("dave", {"order_id": "ORD-10433", "customer_email": "p.wong@example.com", "amount_usd": 1250.00, "reason": "duplicate_charge", "card_last4": "1881"}),
    ("ivy", {"order_id": "ORD-10457", "customer_email": "r.ali@example.com", "amount_usd": 320.00, "reason": "not_received", "card_last4": "0005"}),
    ("ivy", {"order_id": "ORD-10460", "customer_email": "k.brown@example.com", "amount_usd": 75.50, "reason": "other", "card_last4": "7310"}),
]
FLAGS = [
    {"key": "new_onboarding_flow", "description": "Redesigned signup", "environment": "staging", "enabled": True, "rollout_percent": 100},
    {"key": "new_onboarding_flow", "description": "Redesigned signup", "environment": "production", "enabled": True, "rollout_percent": 10},
    {"key": "instant_payouts", "description": "Same-day payouts for merchants", "environment": "production", "enabled": False, "rollout_percent": 0},
]


def seed(svc) -> None:
    conn = svc.conn
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        return
    for uid, name, team, roles in USERS:
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?)", (uid, name, f"{uid}@acme-fintech.com", team, json.dumps(roles)))
    conn.commit()
    for role in ROLES:
        svc.save_role(None, role, actor_override="system")
    from .governance import User
    for (owner, team, row) in KYC:
        svc.import_rows("system", "kyc_cases", User(id=owner, name=owner, team=team, roles=[]), [row])
    for owner, row in REFUNDS:
        svc.import_rows("system", "refunds", svc.get_user(owner), [row])
    svc.import_rows("system", "feature_flags", svc.get_user("frank"), FLAGS)
    # A little governed activity so the audit log has history on first run.
    svc.update(svc.get_user("bob"), "kyc_cases", 1, {"status": "approved", "reviewer_notes": "Docs verified."})
    svc.update(svc.get_user("erin"), "refunds", 2, {"status": "approved"})
