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
├── es-client/     # blocking binary-protocol client (std::net, no tokio)
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
- **Tenants are isolated.** ACL prefixes match at `.` boundaries only (`orders` covers
  `orders.eu`, not `ordersecret`, `orders-archive` or `orders_old`; spell `orders-` to mean
  every name starting with it). Schema subjects `<topic>-value` / `<topic>-key` are
  authorized against `<topic>`. Consumer groups and idempotent producer ids belong to the
  key that first used them, and a key may only claim names under its own ACL prefixes
  (`orders.billing-service`, not `billing-service`); a group or id you may not use is
  refused the same way whether or not it exists. `/metrics` needs a key and shows only
  what it can read.
- **Limits.** Records up to 8 MiB on both protocols, consume responses up to 8 MiB /
  10,000 records, produce and consume byte-rate quotas per key.
- **Raft peers share one secret, and can each have their own certificate.** The secret
  (HMAC challenge-response, the dialer proving itself first, a MAC on every frame) keeps
  outsiders out: without it nothing can join the cluster or forge, alter or replay a frame.
  On its own it does not tell members apart: any node holding it can claim to be any other
  member. With `--raft-tls-cert`, `--raft-tls-key` and `--raft-tls-ca`, every Raft
  connection is mutual TLS 1.3: each broker's certificate names it (`DNS:es-node-<id>`),
  the listener takes the peer's id from the certificate, and frames are encrypted. The
  secret must be at least 32 bytes (`openssl rand -hex 32`); pass it through
  `ES_RAFT_SHARED_SECRET` or `--raft-shared-secret-file` (mode 600) rather than on the
  command line. The raft port accepts connections only from the peers' addresses, and closes
  one that has been silent for 15 seconds (keepalives every 5). Without mTLS, replication
  traffic is not encrypted: keep `--raft-bind` on a private network. Upgrading from 0.2.1
  one broker at a time needs `--raft-legacy-handshake` until every member runs 0.3.

## What's not here yet

The [roadmap](https://es.solisoft.net/docs/roadmap) plans each of these, release by release:

- **0.3**: leader routing (today a produce sent to a Raft follower fails with a leader hint and
  the client retries), safe membership changes and opt-in linearizable reads. (Per-broker
  identity in Raft, the other 0.3 item, is in: see `--raft-tls-*` above.)
- **0.4**: record format v2, with record headers, compression on disk and `sendfile(2)` consume.
- **0.5**: object-store tiering.
- **0.6**: transactions across partitions.

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
# API keys come back only on request, whatever the archive claims
./target/release/es-tools restore --input backup.tar.gz --data-dir ./new-data --with-keys
```

## License

MIT.
