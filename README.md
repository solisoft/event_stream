# es

A small Kafka-shaped event log, written from scratch in Rust. Single-node, single-binary
broker; sibling CLI; HTTP and binary wire protocols. **No Kafka libraries, no ZooKeeper.**

Built to be read in an afternoon, not to scale a production stream.

## Quick start

```bash
make demo
```

Builds the workspace in release mode, boots the broker, creates topics, produces
through HTTP, demonstrates segment rolls, retention deletion, log compaction, and
group offset persistence across a broker restart. Ends with `DEMO OK`.

Drive it yourself in two terminals:

```bash
# terminal 1
cargo build --release
./target/release/es-broker --data-dir ./data --bind 127.0.0.1:9000

# terminal 2
export ES_BROKER=http://127.0.0.1:9000
./target/release/es topic create  --name orders --partitions 2
./target/release/es produce       --topic orders --key k1 --value hello
./target/release/es consume       --topic orders --partition 0 --offset 0
```

## Docs

A Soli MVP app under `www/` hosts the documentation site:

```bash
cd www && soli serve . --dev
# open http://127.0.0.1:5011/docs
```

It covers the HTTP API, the binary protocol, the CLI, on-disk storage, retention &
compaction, and bench numbers.

## Workspace

```
crates/
├── es-protocol/   # serde DTOs + binary wire format
├── es-broker/     # broker: storage, HTTP, binary, auth, retention, compaction
└── es-cli/        # `es` binary
scripts/demo.sh    # one-command end-to-end exercise
Makefile           # build · run-broker · demo · test · clean
```

## What's shipped

The broker grew through five hardening phases on top of the original "basic" build:

- **Phase 1** — per-topic config; log retention (time & size); log compaction with tombstones.
- **Phase 2** — Prometheus `/metrics` with 14 series; synchronous `/admin/run-{retention,compaction}` triggers.
- **Phase 3** — TLS (rustls), bearer-token auth, ACL grammar (read/write/admin × topic-prefix), per-key byte-rate quotas (`governor`).
- **Phase 4** — idempotent producer with replay-dedup; admin API for producer state and offset resets.
- **Phase 5** — length-prefixed binary protocol on a second TCP listener; native `Vec<u8>` payloads; gzip negotiated at handshake; pipelined client; `--flush-every-records` policy.

**Test totals: 38 passing** — 7 unit + 29 integration + 2 protocol unit, plus an ignored
throughput bench (`cargo test --release --test bench -- --ignored --nocapture`).

## What's not here

In rough order of cost:

- **Replication via Raft** — closes the single-point-of-failure gap. Multi-month build.
- **Consumer-group coordination** — Kafka-style member assignment + rebalances. We track offsets, we don't coordinate workers.
- **`sendfile(2)` consume** — zero-copy from page cache to socket. Awkward in the current wire format.

See `.claude/plans/i-want-a-basic-rippling-glade.md` for the full build log, including the bench surprises (fsync was the original ceiling worth ~100×; pipelining didn't help on loopback with a single partition).

## Common commands

```bash
make build         # cargo build --release
make demo          # end-to-end smoke (`DEMO OK` on success)
make test          # full test suite
make run-broker    # release broker on :9000

cargo test --release --test bench -- --ignored --nocapture  # throughput bench
```

## License

MIT.
