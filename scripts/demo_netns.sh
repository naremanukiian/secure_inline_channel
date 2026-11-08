#!/usr/bin/env bash
# End-to-end lab on one Linux machine using network namespaces:
#
#   pc1 --(10.0.1.0/24)-- dev1 --(10.0.12.0/24)-- dev2 --(10.0.2.0/24)-- pc2
#
#   sudo scripts/demo_netns.sh up      # build topology, start both devices
#   sudo scripts/demo_netns.sh test    # transfer data PC1<->PC2 and sniff the Device1-Device2 link
#   sudo scripts/demo_netns.sh down    # tear everything down
#
# Requires: iproute2, iptables (NFQUEUE, TCPMSS, CT), ethtool, python3, python3-netfilterqueue, python3-cryptography
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUN=/tmp/secure-inline-demo
PORT=${PORT:-5001}
MARKER="SECRET-MARKER-0123456789"
PY=${PYTHON:-python3}

nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

up() {
  [[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
  down quiet || true
  mkdir -p "$RUN"
  $PY -c 'import os;print(os.urandom(32).hex())' > "$RUN/psk"; chmod 600 "$RUN/psk"
  for ns in pc1 dev1 dev2 pc2; do ip netns add $ns; nsx $ns ip link set lo up; done
  ip link add v-pc1 type veth peer name v-d1l
  ip link set v-pc1 netns pc1  name eth0
  ip link set v-d1l netns dev1 name lan0
  ip link add v-d1w type veth peer name v-d2w
  ip link set v-d1w netns dev1 name wan0
  ip link set v-d2w netns dev2 name wan0
  ip link add v-d2l type veth peer name v-pc2
  ip link set v-d2l netns dev2 name lan0
  ip link set v-pc2 netns pc2  name eth0
  nsx pc1  ip addr add 10.0.1.2/24  dev eth0
  nsx dev1 ip addr add 10.0.1.1/24  dev lan0
  nsx dev1 ip addr add 10.0.12.1/24 dev wan0
  nsx dev2 ip addr add 10.0.12.2/24 dev wan0
  nsx dev2 ip addr add 10.0.2.1/24  dev lan0
  nsx pc2  ip addr add 10.0.2.2/24  dev eth0
  for p in "pc1 eth0" "dev1 lan0" "dev1 wan0" "dev2 wan0" "dev2 lan0" "pc2 eth0"; do
    set -- $p; nsx "$1" ip link set "$2" up
    for f in tx rx tso gso gro sg; do nsx "$1" ethtool -K "$2" $f off >/dev/null 2>&1 || true; done
  done
  nsx pc1  ip route add default via 10.0.1.1
  nsx pc2  ip route add default via 10.0.2.1
  nsx dev1 ip route add 10.0.2.0/24 via 10.0.12.2
  nsx dev2 ip route add 10.0.1.0/24 via 10.0.12.1
  nsx dev1 sysctl -qw net.ipv4.ip_forward=1
  nsx dev2 sysctl -qw net.ipv4.ip_forward=1

  nsx dev1 "$ROOT/scripts/setup_device.sh" up lan0 wan0 "$PORT"
  nsx dev2 "$ROOT/scripts/setup_device.sh" up lan0 wan0 "$PORT"

  nsx dev2 env PYTHONPATH="$ROOT" $PY -m secure_inline.device --role responder --listen 10.0.12.2 \
      --psk-file "$RUN/psk" --port "$PORT" > "$RUN/dev2.log" 2>&1 &
  echo $! > "$RUN/dev2.pid"
  sleep 1
  nsx dev1 env PYTHONPATH="$ROOT" $PY -m secure_inline.device --role initiator --peer 10.0.12.2 \
      --psk-file "$RUN/psk" --port "$PORT" > "$RUN/dev1.log" 2>&1 &
  echo $! > "$RUN/dev1.pid"
  for _ in $(seq 50); do
    grep -q "established" "$RUN/dev1.log" 2>/dev/null && grep -q "established" "$RUN/dev2.log" 2>/dev/null && break
    sleep 0.2
  done
  grep -h "established" "$RUN"/dev*.log || { echo "handshake did not complete, see $RUN/*.log"; exit 1; }
  echo "topology up. logs in $RUN"
}

test_run() {
  nsx pc2 $PY "$ROOT/scripts/demo_app.py" server --bind 10.0.2.2 --port "$PORT" --marker "$MARKER" &
  local srv=$!
  nsx dev1 $PY "$ROOT/scripts/sniff.py" --iface wan0 --marker "$MARKER" --port "$PORT" --seconds 10 > "$RUN/sniff.out" 2>&1 &
  local snf=$!
  sleep 1.5
  local rc=0
  nsx pc1 $PY "$ROOT/scripts/demo_app.py" client --host 10.0.2.2 --port "$PORT" --marker "$MARKER" || rc=$?
  wait $srv || true
  wait $snf || true
  cat "$RUN/sniff.out"
  echo "--- device stats"; grep -h "stats" "$RUN"/dev1.log | tail -1; grep -h "stats" "$RUN"/dev2.log | tail -1
  if [[ $rc -eq 0 ]] && grep -q "segments_containing_marker=0" "$RUN/sniff.out"; then
    echo "PASS: data intact end-to-end, no plaintext visible between the devices"
  else
    echo "FAIL"; exit 1
  fi
}

down() {
  for f in "$RUN"/dev1.pid "$RUN"/dev2.pid; do [[ -f $f ]] && kill "$(cat "$f")" 2>/dev/null || true; done
  for ns in pc1 dev1 dev2 pc2; do ip netns del $ns 2>/dev/null || true; done
  rm -f "$RUN"/*.pid
  [[ ${1:-} == quiet ]] || echo "torn down"
}

case "${1:-}" in
  up) up ;; test) test_run ;; down) down ;;
  *) sed -n '2,10p' "$0"; exit 1 ;;
esac
