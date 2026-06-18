#!/usr/bin/env bash
#
# Live cross-stack RDFC interop harness for ZCAP-LD capability DELEGATION proofs.
#
# Proves, end-to-end and at runtime, that zcap-dotnet's RDFC-1.0 path is wire-
# compatible with the @digitalbazaar/zcap v9 reference implementation:
#
#   1. OUTBOUND  dotnet signs (RDFC) -> @digitalbazaar/zcap verifies        (must PASS)
#   2. INBOUND   @digitalbazaar/zcap signs -> dotnet verifies (RDFC)        (must PASS)
#   3. NEG out   tamper dotnet zcap -> @digitalbazaar/zcap rejects          (must FAIL)
#   4. NEG in    tamper db zcap -> dotnet rejects                           (must FAIL)
#
# Scope: delegation proofs only (the canonicalization interop path). Invocation
# interop is a separate envelope concern, out of scope. See
# docs/ZCAP-LD-INTEROP-COMPATIBILITY-ANALYSIS.md.
#
# Usage:  interop/run-interop.sh
# Exit:   0 if every expectation held; 1 otherwise.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # interop/
VEC="$HERE/vectors"
JS="$HERE/js"
PROJ="$HERE/ZcapLd.Interop"
DLL="$PROJ/bin/Release/net10.0/ZcapLd.Interop.dll"
mkdir -p "$VEC"

cyan() { printf '\033[36m%s\033[0m\n' "$1"; }
red()  { printf '\033[31m%s\033[0m\n' "$1"; }
grn()  { printf '\033[32m%s\033[0m\n' "$1"; }

PASS_COUNT=0
FAIL_COUNT=0

# expect <label> <expected:PASS|FAIL> <actual_exit_code>
# (verify commands exit 0 on PASS, non-zero on FAIL)
expect() {
  local label="$1" want="$2" code="$3" got
  if [[ "$code" -eq 0 ]]; then got="PASS"; else got="FAIL"; fi
  if [[ "$got" == "$want" ]]; then
    grn "  OK   $label  (got $got, expected $want)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    red "  FAIL $label  (got $got, expected $want)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

dotnet_cli() { dotnet "$DLL" "$@"; }
js_verify()  { ( cd "$JS" && node verify.mjs "$@" ); }

cyan "== Setup =="
echo "-- building .NET harness (Release) --"
dotnet build "$PROJ" -c Release -v quiet -nologo || { red "dotnet build failed"; exit 1; }

if [[ ! -d "$JS/node_modules" ]]; then
  echo "-- installing JS deps (npm ci) --"
  ( cd "$JS" && npm ci ) || { red "npm ci failed"; exit 1; }
fi

cyan "== Generate fresh vectors (both stacks) =="
dotnet_cli gen "$VEC/dotnet-root.json" "$VEC/dotnet-delegated.json" || { red "dotnet gen failed"; exit 1; }
dotnet_cli gen-multi "$VEC/dotnet-multi-root.json" "$VEC/dotnet-multi-l1.json" "$VEC/dotnet-multi-l2.json" \
  || { red "dotnet gen-multi failed"; exit 1; }
( cd "$JS" && node gen.mjs ) >/dev/null || { red "js gen failed"; exit 1; }
( cd "$JS" && node gen-multi.mjs ) >/dev/null || { red "js gen-multi failed"; exit 1; }
echo "  wrote single- and multi-level dotnet-*.json and js-*.json under interop/vectors/"

cyan "== 1. OUTBOUND: @digitalbazaar/zcap verifies the dotnet RDFC capability =="
js_verify "$VEC/dotnet-delegated.json" "$VEC/dotnet-root.json"
expect "dotnet -> db   (delegation verifies upstream)" PASS $?

cyan "== 2. INBOUND: zcap-dotnet verifies the @digitalbazaar/zcap capability =="
dotnet_cli verify "$VEC/js-delegated.json" "$VEC/js-root.json"
expect "db -> dotnet   (delegation verifies locally)" PASS $?

cyan "== 3. NEGATIVE (outbound): tampered dotnet capability must be rejected by db =="
jq '.allowedAction=["read","write"]' "$VEC/dotnet-delegated.json" > "$VEC/dotnet-delegated.tampered.json"
js_verify "$VEC/dotnet-delegated.tampered.json" "$VEC/dotnet-root.json"
expect "dotnet(tampered) -> db   (rejected)" FAIL $?

cyan "== 4. NEGATIVE (inbound): tampered db capability must be rejected by dotnet =="
jq '.allowedAction=["read","write"]' "$VEC/js-delegated.json" > "$VEC/js-delegated.tampered.json"
dotnet_cli verify "$VEC/js-delegated.tampered.json" "$VEC/js-root.json"
expect "db(tampered) -> dotnet   (rejected)" FAIL $?

cyan "== 5. MULTI-LEVEL outbound: db verifies the dotnet 2-level chain [rootId, {parent}] =="
js_verify "$VEC/dotnet-multi-l2.json" "$VEC/dotnet-multi-root.json"
expect "dotnet -> db   (depth-2 chain verifies upstream)" PASS $?

cyan "== 6. MULTI-LEVEL inbound: zcap-dotnet verifies the db 2-level chain =="
dotnet_cli verify "$VEC/js-multi-l2.json" "$VEC/js-multi-root.json"
expect "db -> dotnet   (depth-2 chain verifies locally)" PASS $?

rm -f "$VEC/dotnet-delegated.tampered.json" "$VEC/js-delegated.tampered.json"

echo
if [[ "$FAIL_COUNT" -eq 0 ]]; then
  grn "ALL $PASS_COUNT CHECKS PASSED — RDFC delegation interop with @digitalbazaar/zcap proven end-to-end."
  exit 0
else
  red "$FAIL_COUNT check(s) failed, $PASS_COUNT passed."
  exit 1
fi
