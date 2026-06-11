#!/usr/bin/env bash
# run.sh - Start the FRITZ!Box live capture. Login data comes from .env.
#
# Usage:
#   ./run.sh                 Capture LAN + Wi-Fi 5 GHz + Wi-Fi 2.4 GHz
#   ./run.sh test            Check login + list interfaces (no capture)
#   ./run.sh wireshark 2-1   Live into Wireshark, interface 2-1
#   ./run.sh ntopng 1-0      Live into ntopng
#   ./run.sh file 2-1        Write to dump_<date>.pcap
#   ./run.sh raw 2-1         Raw pcap to stdout (e.g. | your SIEM tool)
#   ./run.sh home            Capture LAN + Wi-Fi 5 GHz + Wi-Fi 2.4 GHz
#
# Set FRITZ_REDACT=true (in .env or the environment) to strip packet payloads
# and record only headers (addresses, ports, sizes) -- no message contents.

set -euo pipefail
cd "$(dirname "$0")"
umask 077

PY="$(command -v python3 || command -v python || echo "python3")"

MODE="${1:-home}"
IFACE="${2:-}"
PROJECT_DIR="$(pwd -P)"
EXPECTED_DUMP_ROOT="$PROJECT_DIR/dumps"
DUMP_ROOT="${DUMP_ROOT:-$EXPECTED_DUMP_ROOT}"

# Abort with a helpful hint if no interface was given. $1 is an example ID.
require_iface() {
  if [[ -z "$IFACE" ]]; then
    echo "Interface missing, e.g.: ./run.sh $MODE ${1:-2-1}" >&2
    exit 1
  fi
}

# Abort if an external tool we want to pipe into is not installed.
require_tool() {
  command -v "$1" >/dev/null || { echo "$1 not installed" >&2; exit 1; }
}

prepare_dump_root() {
  if [[ -z "$DUMP_ROOT" || "$DUMP_ROOT" == "/" || "$DUMP_ROOT" == "." ]]; then
    echo "ERROR: refusing unsafe DUMP_ROOT: ${DUMP_ROOT:-<empty>}" >&2
    exit 1
  fi
  if [[ ! -d "$DUMP_ROOT" ]]; then
    mkdir -m 700 "$DUMP_ROOT" || { echo "ERROR: Could not create DUMP_ROOT" >&2; exit 1; }
  fi
  if [[ -L "$DUMP_ROOT" ]]; then
    echo "ERROR: DUMP_ROOT is a symlink: $DUMP_ROOT" >&2
    exit 1
  fi
  DUMP_ROOT="$(cd "$DUMP_ROOT" && pwd -P)"
  if [[ "$DUMP_ROOT" != "$EXPECTED_DUMP_ROOT" ]]; then
    echo "ERROR: dumps must be written to $EXPECTED_DUMP_ROOT" >&2
    exit 1
  fi
  chmod 700 "$DUMP_ROOT" 2>/dev/null || true
}

remove_old_dumps() {
  local path base
  shopt -s nullglob
  for path in "$DUMP_ROOT"/dump_*; do
    base="$(basename "$path")"
    if [[ "$base" =~ ^dump_[0-9]{8}_[0-9]{6}(_[A-Za-z0-9]{6})?(\.pcap)?$ ]]; then
      rm -rf -- "$path"
    fi
  done
  shopt -u nullglob
}

capture_group() {
  local stamp outdir
  stamp="$(date +%Y%m%d_%H%M%S)"
  prepare_dump_root

  echo "[*] Removing old dumps ..."
  remove_old_dumps

  outdir="$(mktemp -d -p "$DUMP_ROOT" "dump_${stamp}_XXXXXX")"
  chmod go-rwx "$outdir"

  # Interface IDs as listed by the FRITZ!OS capture page (run `./run.sh test`).
  # They vary by box/firmware, so the whole set is overridable via the
  # FRITZ_HOME_IFACES env var: a space-separated list of name:iface pairs, e.g.
  #   FRITZ_HOME_IFACES="lan:1-lan wifi_5ghz:4-133 wifi_24ghz:1-ath0"
  #
  # Defaults for this box: 1-lan = LAN bridge, 4-133 = AP 5 GHz (ath1). For
  # 2.4 GHz we use the RAW radio interface 1-ath0, NOT the logical AP 4-135:
  # on this firmware 4-135 accepts the capture but streams ZERO packets, while
  # the actual 2.4 GHz client traffic (e.g. phones that only roam onto 2.4 GHz)
  # shows up on 1-ath0. Capturing 4-135 silently lost every 2.4 GHz-only device.
  local -a names=() ifaces=() pids=()
  local default_ifaces="lan:1-lan wifi_5ghz:4-133 wifi_24ghz:1-ath0"
  local pair
  for pair in ${FRITZ_HOME_IFACES:-$default_ifaces}; do
    names+=("${pair%%:*}")    # text before the ':' is the file-name label
    ifaces+=("${pair#*:}")    # text after the ':' is the FRITZ!OS interface ID
  done

  echo "[*] Capturing LAN + Wi-Fi 5 GHz + Wi-Fi 2.4 GHz into $outdir/"
  echo "[*] Stop with Ctrl-C."

  cleanup() {
    trap - INT TERM EXIT
    echo
    echo "[*] Stopping captures ..."
    for pid in "${pids[@]}"; do
      kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
  }
  trap cleanup INT TERM EXIT

  for i in "${!ifaces[@]}"; do
    local outfile="$outdir/${names[$i]}_${ifaces[$i]}.pcap"
    echo "    ${ifaces[$i]} -> $outfile"
    "$PY" fritzdump.py --iface "${ifaces[$i]}" --to "$outfile" &
    pids+=("$!")
  done

  wait
}

if [[ ! -f .env ]]; then
  echo "ERROR: .env missing. Copy .env.example -> .env and set the password." >&2
  exit 1
fi
chmod go-rwx .env

case "$MODE" in
  test)
    echo "[*] Testing login and listing interfaces ..."
    exec "$PY" fritzdump.py --list
    ;;
  wireshark)
    require_iface 2-1
    require_tool wireshark
    exec "$PY" fritzdump.py --iface "$IFACE" --to wireshark
    ;;
  ntopng)
    require_iface 1-0
    require_tool ntopng
    exec "$PY" fritzdump.py --iface "$IFACE" --to ntopng
    ;;
  file)
    require_iface 2-1
    prepare_dump_root
    OUT="$(mktemp -p "$DUMP_ROOT" "dump_$(date +%Y%m%d_%H%M%S)_XXXXXX.pcap")"
    echo "[*] Writing to $OUT (Ctrl-C stops) ..."
    exec "$PY" fritzdump.py --iface "$IFACE" --to "$OUT"
    ;;
  home)
    capture_group
    ;;
  raw)
    require_iface 2-1
    exec "$PY" fritzdump.py --iface "$IFACE" --to -
    ;;
  *)
    echo "Unknown mode: $MODE  (allowed: test | wireshark | ntopng | file | home | raw)" >&2
    exit 1
    ;;
esac
