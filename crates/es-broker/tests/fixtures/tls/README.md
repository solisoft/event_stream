Test-only TLS material for the broker's integration tests: a throwaway CA
(`ca.pem`) and a `localhost` / `127.0.0.1` leaf it signed (`cert.pem`, `key.pem`).
The CA key was discarded after signing. Never use these outside tests.
