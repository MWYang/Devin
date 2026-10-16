# Governed Data Layer — a Dataverse-style prototype

A ~2-hour proof of concept, built with Devin, for the question *"can our team replace Power Apps with internal tools we build ourselves?"*

It focuses on the part of Power Apps that is hardest to replace: **Dataverse**, the data and governance layer
underneath every app. Pages and forms are cheap to build with Devin. What's expensive is making the 13th internal tool
follow the same access rules, PII handling and audit trail as the first. So this prototype is one governed data layer
that any number of internal apps can run on, plus a thin dashboard to show it working.

The client's three existing Power Apps (KYC review queue, refunds dashboard, feature-flag admin) are each defined as a single YAML file.

## What it does

| Power Apps / Dataverse concept | Here |
|---|---|
| Tables & columns | One YAML file per table in [`schema/`](schema/). Tables are created automatically, and new columns are added in place without touching existing data. |
| Security roles (User / Business Unit / Org access levels) | Roles give each table a scope per privilege (create/read/update/delete): `none < own < team < all`. |
| Column-level security | Every column has a classification: `internal`, `pii`, `financial` or `restricted`. Sensitive columns are **masked or hidden by default**. A role has to grant `read` or `write` explicitly. |
| Business rules / approvals | Declarative rules in the schema: **four-eyes** (the creator can't approve their own record; the approver is recorded automatically) and **approval thresholds** (e.g. refunds over $500 need `finance_lead`). |
| Auditing | Every write, every **denied attempt** and every **read of unmasked sensitive data** is logged. The log is hash-chained, so editing a past entry is detectable, and restricted values are redacted from it. |
| Admin center | A **role editor** (scopes, column access, user assignment) and a **data governance** page (who can see each sensitive column, row access, audit log with integrity check, data catalog). |
| Model-driven apps | Each table's grid and form are **generated from its schema** and the current user's permissions. |
| Maker / table designer | An **app schema editor** page (capability `manage_schema`) edits or creates the YAML in the browser with validation and a column preview. Saving applies additive migrations live, with no restart, and is audited. Removing or retyping columns is rejected. |

All data access goes through one class, `DataService` ([`app/governance.py`](app/governance.py)). The HTTP API and the UI
can't get around it, and the UI only displays what the server already decided.

## Run it

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn --factory app.main:create_app --reload --port 8000
# open http://localhost:8000
```

Or `docker build -t govdata . && docker run -p 8000:8000 govdata`.

The first run seeds demo users, roles and records into `data.db`. Delete that file to reset.

Tests (27 executable policy and adversarial checks): `.venv/bin/python -m pytest -q`

## 5-minute demo script

Use the **Acting as** dropdown in the top bar to switch users. It stands in for SSO.

1. **Alice (KYC analyst)** → KYC Review Queue. She sees her team's 4 cases, but not the EU team's case. She can see PII; the SSN column is masked.
2. **Dave (support)** → same table. He sees all 5 cases (read-only), with email and DOB masked. The SSN column isn't shown to him at all.
3. **Alice** creates a case, then tries to set it to `approved` → *Denied: four-eyes rule*. **Bob** approves it → `approved_by = bob` is filled in automatically.
4. **Henry (finance analyst)** tries to approve the $1,250 refund → *Denied: requires finance_lead*. **Erin** can approve it.
5. **Grace (governance admin)** → Role editor. She grants *Support Agent* `read` on `kyc_cases.ssn_last4`. Switch to Dave and the SSN column now appears. Grace herself still has **no data access**, and she can't give herself new roles.
6. **Grace** → App schema editor. Pick *Refunds Dashboard*, add `- {name: ticket_url, type: string}` under `columns`, save. Open the refunds app: the column is there. Choose **+ New app**, save the vendor-payments template: a new app appears in the nav, and nobody can read it until a role is granted.
7. **Grace** → Data governance. The "who can see" matrix reflects the change. The audit log shows the role change, Alice's denied attempt and Dave's sensitive read. **Verify integrity** confirms the chain is intact.

## Adding a new internal app

```yaml
# schema/vendor_payments.yaml
name: vendor_payments
label: Vendor Payments
columns:
  - {name: vendor, type: string, required: true}
  - {name: amount_usd, type: decimal, classification: financial}
  - {name: iban, type: string, classification: restricted}
  - {name: status, type: choice, choices: [draft, approved, sent], default: draft}
  - {name: approved_by, type: user}
rules:
  - {type: four_eyes, when: {status: approved}, stamp: approved_by}
```

Save this in the **App schema editor** (or drop the file in `schema/` and restart). The table, API and UI now exist, and **nobody has access** until a role grants it in the role editor.
A custom UI (React, Retool, anything else) can be built on top of `/api/data/vendor_payments` and gets the same governance.
In practice this is a good unit of work to hand to Devin: *"add a vendor payments app, finance can create, finance_lead approves over $10k."*

## Red-team check: is RBAC enforced on the server?

The UI hides what you can't see, but the test that matters is calling the API directly. `scripts/attack.sh` fires ~30
attacks at a running server (IDOR by record id, filtering on masked columns to infer values, mass assignment of
`team`/`owner_id`/`created_by`, SQL in filters and column names, self-granting roles, rewriting schemas, reading or
editing the audit log, identity spoofing) and expects each one to be refused:

```bash
scripts/attack.sh            # against http://localhost:8000; prints BLOCKED/HOLE per attempt and the audit entries
```

Every refusal is also a `denied` entry in the hash-chained audit log and a `DENIED actor=... reason=...` line in the
server log, so attempts are visible, not silent. `tests/test_adversarial.py` pins each probe as a regression test.

**What the first red-team pass found.** The first version of this prototype handled a POST containing a system column
(`{"team": "finance", ...}`) with a 500 error: the insert never happened, but the attempt wasn't logged as a denial,
and PATCH silently dropped `team`/`owner_id` instead of refusing. Both now return 403 and are audited
(`cannot write system column team`). The recorded run then found a second gap: a request with an unknown
`X-User-Id` was refused (403) but left no `denied` audit entry and no server-log warning, so credential-guessing
would have been invisible. Unknown identities are now audited under the identity presented. Everything else held.

**Known gaps, by design of the demo, not fixed.** Identity is the `X-User-Id` header, so anyone who can reach the API
can be anyone; in production this header comes from the SSO gateway and the app must only trust it from there.
`/api/users` is unauthenticated (it feeds the demo user switcher). The audit log is append-only because nothing in the
app writes to it except `audit.record`, and tampering is detected by `verify`, not prevented; a production deployment
would ship entries to WORM storage.

## Write-ups

- [`docs/key_decisions.md`](docs/key_decisions.md): key decisions one-pager (scope, architecture, tradeoffs).
- [`docs/presentation.html`](docs/presentation.html): the 5-minute build-vs-buy deck. It is a single offline HTML file; download it and open it in a browser (arrow keys to navigate, F for full screen).

## Layout

```
app/schema.py      YAML → tables, types, validation, additive migrations
app/governance.py  roles, scopes, column security, rules, DataService (the only data path)
app/audit.py       append-only hash-chained audit log
app/main.py        FastAPI routes; identity from X-User-Id header
app/seed.py        demo users / roles / records
static/            dashboard (plain JS, no build step)
schema/            one YAML file per governed table
tests/             policy tests
docs/              key decisions one-pager and presentation
```

## What this prototype deliberately does not do

These are the gaps between this prototype and production. They are the real cost of building instead of buying:

- **Identity**: `X-User-Id` is a demo stand-in. Production needs OIDC/SAML with Entra ID or Okta, with groups mapped to roles.
- **Storage**: SQLite with a single connection. Production would use Postgres, ideally with row-level security as a second layer of enforcement, plus backups and point-in-time recovery.
- **Audit storage**: hash-chaining detects tampering but doesn't prevent it. Production should also ship the log to WORM storage or a SIEM.
- **Workflow / connectors**: no equivalent of Power Automate. There are no email or Teams notifications, scheduled jobs or 1,000+ connectors.
- **Schema changes are additive only**: no renames, type changes or drops. There are no environments (dev/test/prod) and no promotion flow between them.
- **Low-code authoring**: business users can't build apps here. New apps are YAML plus code changes, made by engineers or Devin.
- No pagination, record-level sharing, field-level history UI, or encryption at rest.
