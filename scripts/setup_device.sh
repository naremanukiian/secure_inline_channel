#!/usr/bin/env bash
# Install / remove the netfilter plumbing on a device (run as root).
#
#   setup_device.sh up   <plain_if> <secure_if> <ports|all> [mtu=1500]
#   setup_device.sh down <plain_if> <secure_if> <ports|all> [mtu=1500]
#
#   plain_if  : interface towards the host (PC1 on Device1, PC2 on Device2)
#   secure_if : interface towards the peer device
#   ports     : iptables multiport syntax, e.g. 5001 or 5001,5002 or 8000:8010, or "all"
#
# Env: ENC_Q (default 0), DEC_Q (default 1) must match --enc-queue / --dec-queue.
set -euo pipefail

ACTION=${1:-}; PLAIN=${2:-}; SECURE=${3:-}; PORTS=${4:-}; MTU=${5:-1500}
ENC_Q=${ENC_Q:-0}; DEC_Q=${DEC_Q:-1}
[[ $ACTION =~ ^(up|down)$ && -n $PLAIN && -n $SECURE && -n $PORTS ]] || { sed -n '2,12p' "$0"; exit 1; }

MSS=$((MTU - 40 - 16))          # leave room for the 16-byte GCM tag
PM=(); [[ $PORTS == all ]] || PM=(-m multiport --ports "$PORTS")

if [[ $ACTION == up ]]; then
  sysctl -qw net.ipv4.ip_forward=1
  for ifc in "$PLAIN" "$SECURE"; do
    # Segmentation/receive offloads must be off: the kernel would otherwise merge or
    # re-split packets and break the 1 packet == 1 AES-GCM record mapping.
    for f in gro lro gso tso sg rx tx; do ethtool -K "$ifc" "$f" off >/dev/null 2>&1 || true; done
  done
  OP=(-I); POS=(1)
else
  OP=(-D); POS=()
fi

ipt() { iptables "$@"; }
# Order matters: with -I ... 1 the LAST inserted rule ends up first.
# Final chain order (mangle/FORWARD): 1) drop IP fragments  2) clamp MSS  3) enc queue  4) dec queue
if [[ $ACTION == up ]]; then
  ipt -t mangle "${OP[@]}" FORWARD "${POS[@]}" -i "$SECURE" -p tcp "${PM[@]}" -j NFQUEUE --queue-num "$DEC_Q"
  ipt -t mangle "${OP[@]}" FORWARD "${POS[@]}" -i "$PLAIN"  -p tcp "${PM[@]}" -j NFQUEUE --queue-num "$ENC_Q"
  ipt -t mangle "${OP[@]}" FORWARD "${POS[@]}" -p tcp --tcp-flags SYN,RST SYN "${PM[@]}" -j TCPMSS --set-mss "$MSS"
  ipt -t mangle "${OP[@]}" FORWARD "${POS[@]}" -p tcp -f -j DROP   # later fragments carry no TCP header: never forward in clear
  # Keep conntrack away from payload-resized packets (and from reassembling fragments).
  ipt -t raw "${OP[@]}" PREROUTING "${POS[@]}" -p tcp "${PM[@]}" -j CT --notrack
else
  ipt -t mangle "${OP[@]}" FORWARD -i "$SECURE" -p tcp "${PM[@]}" -j NFQUEUE --queue-num "$DEC_Q" || true
  ipt -t mangle "${OP[@]}" FORWARD -i "$PLAIN"  -p tcp "${PM[@]}" -j NFQUEUE --queue-num "$ENC_Q" || true
  ipt -t mangle "${OP[@]}" FORWARD -p tcp --tcp-flags SYN,RST SYN "${PM[@]}" -j TCPMSS --set-mss "$MSS" || true
  ipt -t mangle "${OP[@]}" FORWARD -p tcp -f -j DROP || true
  ipt -t raw "${OP[@]}" PREROUTING -p tcp "${PM[@]}" -j CT --notrack || true
fi
echo "secure-inline netfilter rules: $ACTION (plain=$PLAIN secure=$SECURE ports=$PORTS mss=$MSS)"
