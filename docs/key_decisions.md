# Key decisions

**The problem.** At Power Apps Premium list price (~$240/user/year), $250K buys ~1,040 seats, far more than a ~60-engineer company has staff. My working assumption is that most seats are outsourced KYC and support reviewers. They use apps rather than build them, so the low-code builder is worth little. The license is really buying control over who sees customer PII and an audit trail an examiner accepts. That is Dataverse's security model.

**Scope: the governance layer, not the apps.** CRUD screens are the easiest thing for Devin to rebuild, so rebuilding them proves little. The risk with 13+ tools is that tool #13 drifts from tool #1's access rules. I built one data layer for every app to run on, then generated the KYC, refunds and feature-flag apps on it.

**Architecture**
- **Metadata-driven.** One YAML file per table (columns, types, classification, rules) produces the table, a generic REST API and the UI. A generic API is less flexible than hand-written endpoints, but custom UIs can still inherit its policy.
- **One enforcement path.** Every read and write goes through `DataService`. The UI only renders what the server returns.
- **Fail closed.** `pii`/`financial` columns are masked, `restricted` columns are hidden, and new tables deny everyone by default. A forgotten permission doesn't leak data.
- **Simplified scopes.** `none/own/team/all` per privilege replaces Dataverse's business-unit hierarchy.
- **Admins see no data** and can't grant themselves roles.
- **Two rule types, no workflow engine.** `four_eyes` and `approval_threshold` are the controls auditors ask about first.
- **Audit.** The log records writes, denials and sensitive reads, redacts restricted values and is hash-chained. Tampering is detectable, not prevented.
- **Additive-only schema edits.** Removing or retyping a column is rejected.

**Stack: FastAPI, SQLite, plain JS.** One command to run, no build step. Production needs Postgres with row-level security, OIDC instead of the `X-User-Id` header, and write-once audit storage.

**Proving it, not demoing it.** Hiding things in the UI proves nothing, so I had Devin attack its own API with ~30 probes (cross-team IDs, filters on masked columns, system-column writes, SQL in filters, self-granted roles). It found two holes: system columns in a POST caused an unlogged 500, and unknown identities weren't audited. Both are fixed and covered by tests (27 total). That loop is how the client should use Devin.

**What I cut.** Workflow and connectors, SSO, dev/test/prod environments, destructive migrations, authoring for non-engineers, and pagination. Parallel page loads also produced a 500 on the single SQLite connection. Each is easy; together they are the ongoing cost of ownership. That is why my cost model includes half an engineer (~$100K/year), far more than Devin itself (~$12K/year).

**Recommendation.** Build with Devin if users are mostly contractors and the data lives in the company's own database, which is likely for a Series C startup. Stay on Power Apps if the data is in Dataverse or the tools depend on Power Automate. Devin still helps there by writing code components. A two-week audit of seats and data decides which.
