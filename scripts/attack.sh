#!/usr/bin/env bash
# Red-team script: hit the API directly (bypassing the UI) and check the server says no.
# Usage: scripts/attack.sh [http://localhost:8000]
H=${1:-http://localhost:8000}; pass=0; fail=0
try() { # try "<expected status>" "<description>" curl-args...
  local want=$1 desc=$2; shift 2
  local got; got=$(curl -s -o /tmp/attack_body -w "%{http_code}" "$@")
  local body; body=$(head -c 110 /tmp/attack_body | tr -d '\n')
  if [ "$got" = "$want" ]; then pass=$((pass+1)); printf "  \e[32mBLOCKED %s\e[0m  %s\n      %s\n" "$got" "$desc" "$body"
  else fail=$((fail+1)); printf "  \e[31mHOLE    %s (expected %s)\e[0m  %s\n      %s\n" "$got" "$want" "$desc" "$body"; fi
}
J='content-type: application/json'
echo "== 1. Row-level security: Alice (KYC analyst, team=compliance) goes after other teams' cases"
try 403 "IDOR: fetch EU team's case by id"           -H 'X-User-Id: alice' "$H/api/data/kyc_cases/5"
try 403 "read a table her role never mentions"       -H 'X-User-Id: alice' "$H/api/data/refunds"
try 403 "fetch a refund by id"                       -H 'X-User-Id: alice' "$H/api/data/refunds/1"
try 403 "delete a case (no delete scope)"            -H 'X-User-Id: alice' -X DELETE "$H/api/data/kyc_cases/1"
echo "== 2. Field-level security: Dave (support, sees KYC masked) tries to get an unmasked SSN"
try 403 "filter on hidden column to infer SSN"       -H 'X-User-Id: dave' "$H/api/data/kyc_cases?ssn_last4=4821"
try 403 "filter on masked email to infer it"         -H 'X-User-Id: dave' "$H/api/data/kyc_cases?email=maria.g@example.com"
try 403 "Alice writes SSN she can only see masked"   -H 'X-User-Id: alice' -X PATCH -H "$J" -d '{"ssn_last4":"0000"}' "$H/api/data/kyc_cases/1"
echo "== 3. Mass assignment / tampering with system columns"
try 403 "create a record owned by another team"      -H 'X-User-Id: alice' -X POST  -H "$J" -d '{"customer_name":"Planted","country":"US","team":"finance"}' "$H/api/data/kyc_cases"
try 403 "forge created_by to dodge four-eyes"        -H 'X-User-Id: alice' -X POST  -H "$J" -d '{"customer_name":"Planted","country":"US","created_by":"carol"}' "$H/api/data/kyc_cases"
try 403 "move an existing case to another team"      -H 'X-User-Id: alice' -X PATCH -H "$J" -d '{"team":"support"}' "$H/api/data/kyc_cases/1"
try 422 "stamp approved_by directly"                 -H 'X-User-Id: alice' -X PATCH -H "$J" -d '{"approved_by":"carol"}' "$H/api/data/kyc_cases/1"
try 422 "write a column that does not exist"         -H 'X-User-Id: alice' -X POST  -H "$J" -d '{"customer_name":"P","country":"US","is_admin":true}' "$H/api/data/kyc_cases"
echo "== 4. Injection"
try 200 "SQL in a filter value is just a value"      -H 'X-User-Id: alice' "$H/api/data/kyc_cases?country=US'%20OR%201=1--"
try 422 "SQL in a filter key"                        -H 'X-User-Id: alice' "$H/api/data/kyc_cases?country%22%20OR%201=1--=US"
try 404 "read the audit table through the data API"  -H 'X-User-Id: alice' "$H/api/data/audit_log"
try 422 "SQL in a column name via the schema editor" -H 'X-User-Id: grace' -X POST -H "$J" -d '{"yaml":"name: evil\nlabel: x\ncolumns:\n  - {name: \"a\\\" TEXT); DROP TABLE kyc_cases;--\", type: string}"}' "$H/api/schema/validate"
echo "== 5. Privilege escalation"
try 403 "Alice grants herself compliance_manager"    -H 'X-User-Id: alice' -X PUT -H "$J" -d '["kyc_analyst","compliance_manager"]' "$H/api/users/alice/roles"
try 403 "Alice widens her own role to read=all"      -H 'X-User-Id: alice' -X PUT -H "$J" -d '{"permissions":{"tables":{"kyc_cases":{"read":"all"}}}}' "$H/api/roles/kyc_analyst"
try 403 "Alice rewrites the KYC schema"              -H 'X-User-Id: alice' -X PUT -H "$J" -d '{"yaml":"name: kyc_cases\nlabel: x\ncolumns: []"}' "$H/api/schema/kyc_cases"
try 403 "Grace (admin) grants herself a data role"   -H 'X-User-Id: grace' -X PUT -H "$J" -d '["governance_admin","compliance_manager"]' "$H/api/users/grace/roles"
try 403 "Grace (admin) reads KYC data"               -H 'X-User-Id: grace' "$H/api/data/kyc_cases"
echo "== 6. Audit log"
try 403 "Alice reads the audit log"                  -H 'X-User-Id: alice' "$H/api/audit"
try 404 "delete an audit entry (no such endpoint)"   -H 'X-User-Id: grace' -X DELETE "$H/api/audit/1"
try 404 "rewrite an audit entry (no such endpoint)"  -H 'X-User-Id: grace' -X PATCH -H "$J" -d '{"actor":"nobody"}' "$H/api/audit/1"
echo "== 7. Identity"
try 422 "no identity header"                         "$H/api/data/kyc_cases"
try 403 "unknown user"                               -H 'X-User-Id: mallory' "$H/api/data/kyc_cases"
try 422 "?as= query param does not work on the API"  "$H/api/data/kyc_cases?as=carol"
echo
echo "== Did the server notice? Denials recorded in the tamper-evident audit log (as Grace):"
curl -s -H 'X-User-Id: grace' "$H/api/audit?action=denied" | python3 -c "
import json,sys; rows=json.load(sys.stdin)
print(f'  {len(rows)} denied entries total; latest:')
for r in rows[:8]: print(f\"  {r['ts'][11:19]}  {r['actor']:6} {str(r['entity'] or '-'):14} {r['details']['reason']}\")"
echo
echo "Result: $pass blocked, $fail holes"; [ "$fail" = 0 ]
