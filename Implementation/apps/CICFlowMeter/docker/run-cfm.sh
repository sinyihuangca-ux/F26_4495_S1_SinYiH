#!/bin/sh
# Entrypoint of cicflowmeter-worker:  run-cfm.sh <capture file> <output dir>
#
# CICFlowMeter only reads classic microsecond pcap. pcapng (Wireshark's default) and
# nanosecond pcap are first converted with editcap into <output dir>/.convert/, keeping
# the original file name so the CSV is still <output dir>/<original name>_Flow.csv.
# The output dir is used (not /tmp) because /tmp is a small tmpfs in the worker.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <capture file> <output dir>" >&2
    exit 1
fi
in="$1"
out="$2"

if [ ! -f "$in" ]; then
    echo "input file not found: $in" >&2
    exit 1
fi

magic="$(head -c 4 "$in" | od -An -tx1 | tr -d ' \n')"
case "$magic" in
    0a0d0d0a) kind="pcapng" ;;
    a1b23c4d|4d3cb2a1) kind="nanosecond pcap" ;;
    a1b2c3d4|d4c3b2a1) kind="" ;;
    *)
        echo "not a pcap/pcapng file (magic: ${magic:-empty}): $in" >&2
        exit 1
        ;;
esac

if [ -n "$kind" ]; then
    convert_dir="$out/.convert"
    mkdir -p "$convert_dir"
    converted="$convert_dir/$(basename "$in")"
    echo "Converting $kind to pcap: $in"
    # Fails (non-zero) e.g. for pcapng files mixing link-layer types, which pcap cannot hold.
    editcap -F pcap "$in" "$converted"
    in="$converted"
fi

exec "${CFM_BIN:-/opt/cicflowmeter/bin/cfm}" "$in" "$out"
