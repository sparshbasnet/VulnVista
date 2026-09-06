#!/usr/bin/env bash
#
# ZAP-driven OS command-injection active scan against the DVWA lab target.
#
# Drives the OWASP ZAP daemon from tools/docker-compose.yml to run *only* ZAP's
# "Remote OS Command Injection" scan rule (plugin id 90020) against DVWA's exec
# exercise, and prints the resulting alerts.
#
# ZAP has no published host port. Run this helper inside its container so the
# API and DVWA are reachable through their vulnvista_net service names.
#
# Prereqs (from repo root):
#   docker network create vulnvista_net 2>/dev/null || true
#   docker compose --env-file .env -f lab/docker-compose.yml   up -d dvwa
#   docker compose --env-file .env -f tools/docker-compose.yml up -d zap
#
# Usage (Bash): docker exec -i vulnvista_zap bash -s < tools/zap-command-injection.sh
set -euo pipefail

PROXY="${ZAP_PROXY:-http://zap:8080}"         # Internal Docker network only
ZAPI="${ZAP_API_BASE:-http://zap:8080}"       # ZAP's own address, as seen via the proxy
KEY="${ZAP_API_KEY:-vulnvista-dev-key}"
TARGET="${TARGET:-http://dvwa}"               # DVWA via vulnvista_net DNS (port 80)
EXEC="$TARGET/vulnerabilities/exec/"
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT

# ZAP API call routed through the proxy. Args: <path> [extra curl -G data...]
api() { local p="$1"; shift; curl -s -x "$PROXY" -G "$@" \
  --data-urlencode "apikey=$KEY" "$ZAPI$p"; }
jget()   { python3 -c 'import sys,json;print(json.load(sys.stdin)["'"$1"'"])'; }
token()  { sed -n "s/.*name='user_token'[^>]*value='\([a-f0-9]*\)'.*/\1/p" | head -1; }
# Target request routed through the proxy so it lands in ZAP's site tree.
via()    { curl -s -x "$PROXY" "$@"; }

echo "==> Waiting for ZAP daemon ..."
for i in $(seq 1 45); do
  [ "$(api /JSON/core/view/version/ | jget version 2>/dev/null || true)" ] && break
  sleep 2
done
echo "    ZAP $(api /JSON/core/view/version/ | jget version)"

echo "==> Authenticating to DVWA through ZAP (seeds session + site tree)"
T1="$(via -c "$JAR" "$TARGET/login.php" | token)"
via -b "$JAR" -c "$JAR" \
  --data-urlencode "username=admin" --data-urlencode "password=password" \
  --data-urlencode "Login=Login"    --data-urlencode "user_token=$T1" \
  "$TARGET/login.php" >/dev/null
T2="$(via -b "$JAR" "$TARGET/security.php" | token)"
via -b "$JAR" -c "$JAR" \
  --data-urlencode "security=low" --data-urlencode "seclev_submit=Submit" \
  --data-urlencode "user_token=$T2" "$TARGET/security.php" >/dev/null

echo "==> Submitting the injectable exec form once so ZAP learns the 'ip' param"
via -b "$JAR" --data-urlencode "ip=127.0.0.1" --data-urlencode "Submit=Submit" \
  "$EXEC" >/dev/null

echo "==> Scoping active scanner to rule 90020 (Remote OS Command Injection)"
api /JSON/ascan/action/disableAllScanners/ >/dev/null
api /JSON/ascan/action/enableScanners/ --data-urlencode "ids=90020" >/dev/null

echo "==> Launching active scan against $EXEC"
SID="$(api /JSON/ascan/action/scan/ \
  --data-urlencode "url=$EXEC" --data-urlencode "recurse=true" \
  --data-urlencode "inScopeOnly=false" | jget scan)"
while :; do
  ST="$(api /JSON/ascan/view/status/ --data-urlencode "scanId=$SID" | jget status)"
  printf '\r    progress: %s%%   ' "$ST"; [ "$ST" = "100" ] && break; sleep 2
done; echo

echo "==> Command-injection alerts:"
api /JSON/core/view/alerts/ --data-urlencode "baseurl=$EXEC" \
  | python3 -c 'import sys,json
a=json.load(sys.stdin)["alerts"]
c=[x for x in a if x.get("pluginId")=="90020" or "command" in x["alert"].lower()]
print(json.dumps([{k:x[k] for k in ("alert","risk","param","attack","evidence","url")} for x in c], indent=2)
      if c else "  (no OS command-injection alert raised)")'
