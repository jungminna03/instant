#!/bin/bash
# EPL fork: add or update a password-login workspace for the dashboard.
#
#   ./epl/add-workspace.sh <name> <email>
#
# Logs in as <email> (creating the dashboard account if needed) by reading the
# magic code from the server logs, then stores the account's master token and
# the scrypt hash of the password in password-workspaces.json. Re-running with
# an existing <name> replaces its password and revokes its old master token.
# The password is prompted for (or taken from WS_PASSWORD).
set -euo pipefail

cd "$(dirname "$0")/.."
NAME=${1:?usage: add-workspace.sh <name> <email>}
EMAIL=${2:?usage: add-workspace.sh <name> <email>}
API=${API:-http://127.0.0.1:8888}
FILE=${PASSWORD_WORKSPACES_HOST_FILE:-./epl-config/password-workspaces.json}
DC=./dc.sh

PASSWORD=${WS_PASSWORD:-}
if [ -z "$PASSWORD" ]; then
  read -rsp "Password for workspace '$NAME': " PASSWORD; echo
  read -rsp "Repeat password: " PASSWORD2; echo
  [ "$PASSWORD" = "$PASSWORD2" ] || { echo "Passwords do not match" >&2; exit 1; }
fi
[ -n "$PASSWORD" ] || { echo "Empty password" >&2; exit 1; }

since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
curl -fsS -X POST "$API/dash/auth/send_magic_code" \
  -H 'content-type: application/json' \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"email": sys.argv[1]}))' "$EMAIL")" >/dev/null

code=""
for _ in $(seq 1 10); do
  sleep 1
  code=$($DC logs --since "$since" server 2>/dev/null | python3 -c '
import re, sys
email = sys.argv[1].lower()
lines = [re.sub(r"\x1b\[[0-9;]*m", "", l) for l in sys.stdin]
found = ""
for i, l in enumerate(lines):
    if "INSTANT DASHBOARD LOGIN CODE" not in l:
        continue
    code = next((m.group(1) for x in lines[i:i+6] for m in [re.search(r"\|\s+(\d{6})\s*$", x)] if m), None)
    to = next((x for x in lines[i:i+80] if "to= <" in x), "")
    if code and f"<{email}>" in to.lower():
        found = code
print(found)' "$EMAIL")
  [ -n "$code" ] && break
done
[ -n "$code" ] || { echo "Could not find the login code in the server logs" >&2; exit 1; }

TOKEN=$(curl -fsS -X POST "$API/dash/auth/verify_magic_code" \
  -H 'content-type: application/json' \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"email": sys.argv[1], "code": sys.argv[2]}))' "$EMAIL" "$code")" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
sudo touch "$FILE"
sudo cat "$FILE" | WS_PASSWORD="$PASSWORD" WS_TOKEN="$TOKEN" python3 -c '
import base64, hashlib, json, os, sys
name, out = sys.argv[1], sys.argv[2]
raw = sys.stdin.read().strip()
entries = json.loads(raw) if raw else []
salt = os.urandom(16)
h = hashlib.scrypt(os.environ["WS_PASSWORD"].encode(), salt=salt,
                   n=16384, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=64)
entry = {
    "name": name,
    "passwordHash": "scrypt$16384$8$1$%s$%s" % (base64.b64encode(salt).decode(), base64.b64encode(h).decode()),
    "masterToken": os.environ["WS_TOKEN"],
}
old = [e for e in entries if e.get("name") == name]
entries = [e for e in entries if e.get("name") != name] + [entry]
json.dump(entries, open(out, "w"), indent=2)
for e in old:
    print(e["masterToken"])
' "$NAME" "$tmp" > "$tmp.old"

# Revoke replaced master tokens so they cannot be reused.
while read -r old_token; do
  [ -n "$old_token" ] && curl -fsS -X POST "$API/dash/signout" \
    -H 'content-type: application/json' -H "authorization: Bearer $old_token" -d '{}' >/dev/null || true
done < "$tmp.old"
rm -f "$tmp.old"

# The dashboard container runs as uid 1001 (nextjs) and reads this file per request.
# The directory (not the file) is bind-mounted, so replacing the file is picked up.
sudo install -o 1001 -g 1001 -m 600 "$tmp" "$FILE"
echo "Workspace '$NAME' -> $EMAIL saved to $FILE"
