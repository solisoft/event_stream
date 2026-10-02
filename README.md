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
├── es-cli/        # `es` binary
└── es-tools/      # offline dump/restore tools
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

Since then: Raft replication across brokers, consumer-group coordination, schema
registry, tiered storage, and a security and performance audit (see below).

**Test totals: 158 passing** across the workspace, plus an ignored throughput bench
(`cargo test --release --test bench -- --ignored --nocapture`).

## Defaults worth knowing

- **Durable by default.** Nothing is acknowledged before it is fsynced, one fsync per
  request (shared between concurrent requests through group commit), not per record.
- **Auth is off by default — and then only loopback.** With `--auth disabled` every caller
  is an admin, so the broker refuses a non-loopback bind unless
  `--allow-remote-unauthenticated` is passed, and answers only requests whose `Host` names
  this machine (DNS-rebinding guard). No CORS headers unless `--cors-origin` lists origins.
- **TLS covers both listeners.** `--tls-cert`/`--tls-key` apply to HTTP and the binary
  protocol; giving only one of them is an error.
- **Tenants are isolated.** ACL prefixes match at name boundaries (`orders` covers
  `orders.eu`, not `ordersecret`); consumer groups and idempotent producer ids belong to the
  key that first used them; `/metrics` needs a key and shows only what it can read.
- **Limits.** Records up to 8 MiB on both protocols, consume responses up to 8 MiB /
  10,000 records, produce and consume byte-rate quotas per key.
- **Raft peers authenticate each other** (HMAC challenge-response, MAC on every frame).
  Replication traffic is not encrypted: keep `--raft-bind` on a private network.

## What's not here

In rough order of cost:

- **Leader routing** — a produce sent to a Raft follower fails with a leader hint; the client retries.
- **Safe membership changes and linearizable reads** in Raft.
- **`sendfile(2)` consume** — zero-copy from page cache to socket. Awkward in the current wire format.

See `.claude/plans/i-want-a-basic-rippling-glade.md` for the full build log, including the bench surprises (fsync was the original ceiling worth ~100×; pipelining didn't help on loopback with a single partition).

## Common commands

```bash
make build         # cargo build --release
make demo          # end-to-end smoke (`DEMO OK` on success)
make test          # full test suite
make run-broker    # release broker on :9000

cargo test --release --test bench -- --ignored --nocapture  # throughput bench

# Backup & restore
./target/release/es-tools dump --data-dir ./data --output backup.tar.gz
./target/release/es-tools restore --input backup.tar.gz --data-dir ./new-data
```

## License

MIT.
