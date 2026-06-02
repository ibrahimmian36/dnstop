#!/usr/bin/env bash
# simulate_dns_threats.sh
#
# Generates DGA-like and DNS-tunnel-like query traffic so you can
# verify dnstop's detection on your own box. All queries go to your
# system resolver and resolve to NXDOMAIN (the names are made up), so
# nothing actually connects anywhere.
#
# Run dnstop first:
#     yeet run main.js
# or audit:
#     yeet run main.js -- --audit --duration 30
# Then run this. Within a few seconds:
#   - a DGA alert for this script's process (many high-entropy domains)
#   - a tunnel alert for "tunnel-demo.example" (many long-label subdomains)
#
# Ctrl-C to stop.

set -uo pipefail

# Pick a DNS query tool. dig is ideal (lets us do TXT); fall back to
# Python's resolver (A records only, still trips detection).
have_dig=0
if command -v dig >/dev/null 2>&1; then have_dig=1; fi

query() {
  # $1 = name, $2 = type (optional, default A)
  local name="$1" type="${2:-A}"
  if [ "$have_dig" = "1" ]; then
    dig +short +tries=1 +time=1 "$type" "$name" >/dev/null 2>&1 || true
  else
    python3 -c "import socket,sys
try: socket.getaddrinfo(sys.argv[1], None)
except Exception: pass" "$name" >/dev/null 2>&1 || true
  fi
}

cleanup() { echo "" >&2; echo "simulate_dns_threats.sh: done." >&2; exit 0; }
trap cleanup INT TERM

echo "simulate_dns_threats.sh" >&2
echo "  DNS tool: $([ "$have_dig" = 1 ] && echo dig || echo 'python3 getaddrinfo')" >&2
echo "  generating DGA-like + tunnel-like queries against the system resolver" >&2
echo "  (all NXDOMAIN, nothing connects). Ctrl-C to stop." >&2
echo "" >&2

# --- DGA pattern: ONE process, many high-entropy unique domains ------
# Real DGA malware is a single long-lived process cycling through
# generated domains. We use one python3 invocation in a loop (not one
# `dig` per name, which would spawn a process per query and spread the
# signal across PIDs). dnstop's per-process detector keys on this.
echo "  [dga]    one process querying random high-entropy domains..." >&2
dga_round() {
  python3 -c "
import socket, random, string
tlds = ['com','net','org','info','biz','xyz']
for _ in range(40):
    lbl = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    name = lbl + '.' + random.choice(tlds)
    try: socket.getaddrinfo(name, None)
    except Exception: pass
" 2>/dev/null || true
}

# --- tunnel pattern: many long-label subdomains under one domain ------
echo "  [tunnel] querying long-label subdomains under tunnel-demo.example..." >&2
tunnel_round() {
  for _ in $(seq 1 25); do
    # 50+ char label simulating base32-encoded exfil data
    local data
    data="$(LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c 55)"
    query "${data}.tunnel-demo.example" TXT
  done
}

# Run a few rounds so the dashboard has time to cross thresholds.
for round in 1 2 3; do
  echo "  round $round/3..." >&2
  dga_round
  tunnel_round
  sleep 1
done

echo "" >&2
echo "  done. check dnstop for DGA + tunnel alerts." >&2
echo "  (if running --audit, wait for the scan window to close.)" >&2
