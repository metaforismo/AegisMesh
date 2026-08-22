#!/usr/bin/env sh
# demo.sh — end-to-end local demo: scaffold, run, poke decoys, show evidence.
#
# Binds loopback only, uses unprivileged ports, cleans up after itself.
# Requires: go (>= 1.25), curl.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
work="${TMPDIR:-/tmp}/aegismesh-demo.$$"
mkdir -p "$work"
log="$work/aegismesh.log"

cleanup() {
  if [ -f "$work/pid" ] && kill -0 "$(cat "$work/pid")" 2>/dev/null; then
    kill "$(cat "$work/pid")" 2>/dev/null || true
    wait "$(cat "$work/pid")" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "==> building"
make -C "$root" build >/dev/null
bin="$root/bin/aegismesh"

echo "==> scaffolding workspace in $work"
"$bin" init --dir "$work" >/dev/null

# The init scaffold ships an HTTP admin decoy on 127.0.0.1:8081 and a TCP
# decoy on 127.0.0.1:6399; add nothing — just verify and run.
echo "==> validating config"
"$bin" validate --config "$work/mesh.yaml"

echo "==> starting aegismesh"
"$bin" run --config "$work/mesh.yaml" >"$log" 2>&1 &
pid=$!
echo $pid > "$work/pid"

# Wait for readiness through the admin endpoint instead of a fixed sleep.
i=0
until curl -fsS --max-time 1 http://127.0.0.1:9110/readyz >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -gt 50 ] && { echo "aegismesh did not become ready; log:" >&2; cat "$log" >&2; exit 1; }
  sleep 0.1
done
echo "==> ready (admin on http://127.0.0.1:9110)"

echo "==> poking the HTTP admin decoy"
curl -fsS --max-time 3 http://127.0.0.1:8081/admin/login >/dev/null && echo "HTTP decoy responded"

echo "==> poking the TCP build-cache decoy"
printf 'PING\n' | nc -w 2 127.0.0.1 6399 || true

echo "==> calling the MCP canary tool"
curl -fsS --max-time 3 -X POST http://127.0.0.1:8090/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"canary:prod-db-export","arguments":{"database":"prod"}}}' \
  | head -c 200; echo

echo "==> metrics spot-check (interactions observed)"
curl -fsS --max-time 3 http://127.0.0.1:9110/metrics | grep -E '^aegismesh_sensor_.*_total'

echo "==> graceful shutdown (SIGTERM)"
kill -TERM $pid
wait $pid

echo "==> recorded evidence (integrity-verified):"
"$bin" inspect list --data-dir "$work/data" --verify

echo "==> done."
if [ "${AEGISMESH_DEMO_KEEP:-}" != "1" ]; then
  trap - EXIT INT TERM
  rm -rf "$work"
else
  echo "workspace kept at $work"
fi
