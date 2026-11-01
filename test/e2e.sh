#!/usr/bin/env bash
# End to end harness: mock upstream (DSH look-alike) behind two dsh-seal
# instances (offer and passthrough), then the Node interop suite against them.
# Ports 3190-3192 on loopback; state in a throwaway directory.
set -euo pipefail
cd "$(dirname "$0")/.."
export TMPDIR=${TMPDIR:-/var/tmp}
W=$(mktemp -d "$TMPDIR/seal-e2e.XXXXXX")
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup EXIT

bin/mockupstream 127.0.0.1:3190 127.0.0.1:3193 "$W/remote-ca.pem" & pids+=($!)
for i in $(seq 50); do [ -s "$W/remote-ca.pem" ] && break; sleep 0.1; done
cat > "$W/offer.conf" <<EOF
listen=127.0.0.1:3191
upstream=127.0.0.1:3190
mode=offer
state_dir=$W/offer
seal_anonymous=true
identities=alice@example.com
# sealed egress against the TLS mock on 3193 ("the internet" on loopback)
egress=on
egress_ports=3193
egress_unsafe_allow_nets=127.0.0.1/32
egress_ca_file=$W/remote-ca.pem
EOF
sed -e 's/3191/3192/' -e 's/mode=offer/mode=passthrough/' -e "s#$W/offer#$W/pass#" "$W/offer.conf" > "$W/pass.conf"
"${SEAL_BIN:-bin/dsh-seal}" -config "$W/offer.conf" 2>"$W/offer.log" & pids+=($!)
"${SEAL_BIN:-bin/dsh-seal}" -config "$W/pass.conf" 2>"$W/pass.log" & pids+=($!)
for port in 3190 3191 3192; do
  for i in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$port/" && break; sleep 0.1; done
done
node test/interop/interop.mjs
