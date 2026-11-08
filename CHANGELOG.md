# Changelog

What changed in each release of `es`, newest first. The same notes are on the docs site at
`/docs/changelog`.

## Unreleased (0.3)

A cluster you can operate. See the roadmap for what remains in 0.3.

### Upgrading: what can break

- **The Raft handshake is now version 3**, where the dialing broker proves itself first. A 0.3
  broker refuses 0.2 brokers unless it runs with `--raft-legacy-handshake`. Set the flag on
  each upgraded broker until every member runs 0.3, then remove it. It goes away in 0.4. Do
  not change membership in the middle of the upgrade.
- **"Not leader" is now `503` with `Retry-After`**, instead of `400`.
- **After a membership change, a broker's membership comes from each partition's log and
  snapshot**, not from `--raft-peer`, which only gives the starting membership.

### Added

- **Leader routing.** A produce sent to a follower is forwarded once to the partition's leader,
  on HTTP and on the binary protocol, and the leader's offsets come back. Give each peer's API
  address with `--raft-peer-api id=https://host:port`. The leader checks the caller's own key
  again, so keys must match on every broker.
- **Membership changes without a restart.** `GET`, `POST` and `DELETE` on
  `/admin/raft/members` add or remove one broker at a time (single-server changes), and the
  Raft transport follows: an added broker is accepted, and a removed one is disconnected and
  refused. A new broker starts with `--raft-join` and waits to be added. Send each change to
  every broker, since each partition's leader applies it.
- **Per-broker identity.** With `--raft-tls-cert`, `--raft-tls-key` and `--raft-tls-ca`, every
  Raft connection is mutual TLS 1.3. Each certificate names its broker (`DNS:es-node-<id>`),
  so one broker cannot act as another, and replication traffic is encrypted. Raft connections
  send keepalives and close after 15 s of silence.
- **Linearizable reads, as an opt-in.** `consistency=linearizable` on HTTP consumes, or a flag
  on the binary consume, which is negotiated at the handshake so old clients are unaffected.
  The leader confirms its leadership with a majority before serving the read. A follower
  answers "not leader".

### Fixed

- Deleting a topic removes it from consumer-group subscriptions and rebalances the affected
  groups.

## 0.2.1 — 2026-11-08

A security release: it fixes every finding of a second audit, and is the first release to ship
everything merged since 0.2.0.

### Upgrading: what can break

- **Group names and producer ids must sit under the key's own ACL prefixes.** A key granted
  `orders` can claim `orders.billing` but no longer `billing`. Admin keys and `--auth disabled`
  are unrestricted, and a key keeps the names it already owns.
- **ACL prefixes match at `.` only.** A grant on `acme` no longer covers `acme-corp` or `acme_eu`.
  Grant `acme-` (or `acme_`) explicitly if that was intended. Schema subjects `<topic>-value` and
  `<topic>-key` are still authorized against `<topic>`.
- **A Raft shared secret must be at least 32 bytes**, or the broker refuses to start. Generate one
  with `openssl rand -hex 32`, and prefer the new `--raft-shared-secret-file` (mode 0600) to the
  command line.
- **`es-tools restore` restores API keys only with `--with-keys`**, whatever the archive's
  manifest says.
- **Consume quotas are enforced strictly.** A rate-limited consumer that used to overdraw now gets
  `429` with `Retry-After`.
- **The Docker image runs as an unprivileged user** (`es`, uid 10001, home `/var/lib/es`). Mount
  data volumes writable by that user.
- **`es-client`:** encoding a request whose topic or key is too long for its length field returns
  the new `Error::Invalid` (the connection stays usable) instead of truncating the field.

### Security

High:
- The DNS-rebinding guard accepted any `Host` starting with `127.`, so with auth disabled (the
  default) a web page could act as admin. The host must now be a loopback address, the bind
  address, `localhost` or an `--allowed-host`, exactly. A request with no host is refused.
- Binary protocol: gzip frames could deadlock the global memory budget, and a frame's length
  prefix alone reserved budget until its body arrived. One reservation now covers a frame and
  what it can inflate to, slow bodies draw on a per-source share, and they must keep up a
  minimum rate.
- Binary protocol: consume responses now count against the memory budget until written, so
  unread responses can no longer exhaust memory.
- Binary protocol: a per-connection table of produce topics grew without limit. It is now pruned.

Medium:
- `rustls` 0.23.46, `rustls-webpki` 0.103.16, `webpki-roots` 1.0.11, `tokio` 1.54.1
  (RUSTSEC-2026-0346 to 0349, 0381, 0382, 0386). CI now checks advisories.
- Retention could delete a segment that compaction had just rebuilt, losing data. It now drops
  only the exact segments it planned.
- Consume quotas are reserved before the read instead of charged after, so concurrent reads can
  no longer overdraw them.
- Consumer group names and idempotent producer ids can no longer be squatted by another tenant,
  and a refusal no longer reveals whether the name exists.
- `es-tools restore` no longer trusts the archive for its size limits (new `--max-bytes`,
  `--max-entries`), for restoring keys, or for `topic.json` contents.
- Raft: weak shared secrets are refused, and the secret no longer appears in `--help` or debug
  output. Inbound connections are accepted only from configured peers, with per-IP handshake
  limits and one connection per peer. Leader messages and snapshot chunks are validated before
  they take effect, and offsets use checked arithmetic.
- Binary listener: the per-IP connection cap treats an IPv6 /64 as one source. TLS and the
  protocol handshake share one deadline, and unauthenticated connections have their own cap.
- The docs now state exactly what the Raft shared secret guarantees: outsiders cannot join or
  forge frames, but any node holding the secret can act as any member.

Low:
- Group names that differ only in case are refused.
- API key changes are persisted before they take effect.
- Deleting a topic purges its group offsets, producer windows and cold-tier data.
- Produce requests with too many records are refused before decoding.
- `es-tools dump` always writes a fresh 0600 file. The restore staging directory can no longer be
  redirected through a symlink.
- Wire encoders refuse over-long fields instead of truncating them. The pipelined client no
  longer hangs after its connection fails.
- The `es` CLI warns when a token would be sent over plain `http://` or read from a file other
  users can read.
- CI workflows are read-only by default. The Docker image runs as a non-root user.

### Also since 0.2.0

- Fixes from the first security and performance audit:
  - With auth disabled, the broker binds loopback only and checks `Host`. There are no CORS
    headers unless `--cors-origin` is set.
  - TLS covers the binary listener as well.
  - Tenants are isolated by ACL prefix.
  - Group commit gives one fsync per request.
  - Snapshots are streamed.
  - Compaction is crash-safe.
- Raft clustering is configurable from the command line, and `GET /raft` reports replication
  status.
- `es-client`: a blocking Rust client for the binary protocol, without tokio or the broker.
- Release binaries for Linux (amd64, arm64) and macOS (arm64, amd64), each with a `.sha256`, and a
  multi-arch Docker image on GHCR.
- A redesigned documentation site at es.solisoft.net.

## 0.2.0 — 2026-07-05

Security hardening and backup/restore.

- Raft transport authenticated with a pre-shared secret; state machine hardened against
  crafted messages.
- `es-tools` backup and restore, with path-traversal-safe extraction.
- Bounded allocations on the wire and in Raft, capped gzip decompression, validated identifiers.
- Authorization on schema reads, group offsets and coordinator calls.
- Connection limits and timeouts on the binary listener; `--auth-file` for the CLI.

## 0.1.x

The first releases: a single-node broker with segments, retention, compaction, metrics, TLS,
token auth with ACLs, quotas, idempotent producers and the binary protocol.
