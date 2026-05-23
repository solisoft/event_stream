#!/usr/bin/env bash
# End-to-end demo of the basic event-streaming broker.
#
# Spins up the broker on 127.0.0.1:9000 with a tiny --segment-bytes so segment
# rolls are visible on disk, produces 200 records into a 2-partition topic,
# consumes through a group with a mid-stream restart, then prints DEMO OK.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DATA_DIR="$ROOT/data"
PORT="${ES_PORT:-9876}"
BROKER_URL="http://127.0.0.1:${PORT}"
BROKER_BIN="$ROOT/target/release/es-broker"
CLI_BIN="$ROOT/target/release/es"
SEGMENT_BYTES="${ES_SEGMENT_BYTES:-1024}"

BROKER_PID=""
cleanup() {
    if [[ -n "$BROKER_PID" ]] && kill -0 "$BROKER_PID" 2>/dev/null; then
        kill "$BROKER_PID" 2>/dev/null || true
        wait "$BROKER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

start_broker() {
    "$BROKER_BIN" \
        --data-dir "$DATA_DIR" \
        --bind "127.0.0.1:${PORT}" \
        --segment-bytes "$SEGMENT_BYTES" \
        --retention-check-interval 500ms \
        --compaction-check-interval 500ms \
        --segment-delete-grace 200ms \
        > "$ROOT/data/broker.log" 2>&1 &
    BROKER_PID=$!
    for _ in $(seq 1 50); do
        if curl -fsS "$BROKER_URL/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    echo "broker failed to start (see data/broker.log)" >&2
    return 1
}

stop_broker() {
    if [[ -n "$BROKER_PID" ]] && kill -0 "$BROKER_PID" 2>/dev/null; then
        kill "$BROKER_PID"
        wait "$BROKER_PID" 2>/dev/null || true
        BROKER_PID=""
    fi
}

echo "== reset data dir"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "== ensure release build"
cargo build --release --quiet

export ES_BROKER="$BROKER_URL"

echo "== start broker on $BROKER_URL"
start_broker

echo "== create topic 'orders' with 2 partitions"
"$CLI_BIN" topic create --name orders --partitions 2
"$CLI_BIN" topic list

echo "== produce 200 records"
for i in $(seq 0 199); do
    "$CLI_BIN" produce --topic orders --key "k$i" --value "v$i" >/dev/null
done

echo "== describe topic (segment rolls should be visible)"
"$CLI_BIN" topic describe --name orders

echo "== consume + commit halfway through partition 0 as group 'analytics'"
RESP=$("$CLI_BIN" consume --topic orders --partition 0 --group analytics --max 5)
echo "$RESP"
"$CLI_BIN" commit --group analytics --topic orders --partition 0 --offset 5
"$CLI_BIN" group show --name analytics

echo "== restart broker and resume"
stop_broker
start_broker
"$CLI_BIN" group show --name analytics

NEXT=$("$CLI_BIN" consume --topic orders --partition 0 --group analytics --max 3 | tail -1)
echo "after restart, group consume said: $NEXT"

echo
echo "== retention: create 'retain' with retention_ms=1500, produce, watch segments shrink"
"$CLI_BIN" topic create --name retain --partitions 1 \
  --retention-ms 1500 --cleanup-policy delete --segment-bytes 256 >/dev/null
for i in $(seq 0 40); do
    "$CLI_BIN" produce --topic retain --value "v$i" --partition 0 >/dev/null
done
echo "  segments before retention kicks in:"
"$CLI_BIN" topic describe --name retain | grep "partition 0"
sleep 3
echo "  segments after retention pass:"
"$CLI_BIN" topic describe --name retain | grep "partition 0"

echo
echo "== compaction: create 'compact-me' with cleanup-policy=compact, produce dupes"
"$CLI_BIN" topic create --name compact-me --partitions 1 \
  --cleanup-policy compact --segment-bytes 256 >/dev/null
for v in 0 1 2 3 4 5; do
    for k in 0 1 2 3 4; do
        "$CLI_BIN" produce --topic compact-me --key "k$k" --value "k${k}-v${v}" --partition 0 >/dev/null
    done
done
echo "  segments before compaction:"
"$CLI_BIN" topic describe --name compact-me | grep "partition 0"
sleep 3
echo "  segments after compaction:"
"$CLI_BIN" topic describe --name compact-me | grep "partition 0"
echo "  latest values seen by a fresh consumer:"
"$CLI_BIN" consume --topic compact-me --partition 0 --offset 0 --max 100 | grep "^p=" | awk '{print $4, $5}'

echo
echo "DEMO OK"
