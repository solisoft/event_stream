Test-only mTLS material for the Raft transport: a throwaway CA (`ca.pem`) and one
leaf per broker, `node<N>.pem` / `node<N>.key`, each naming its broker the way
`--raft-tls-cert` requires — subjectAltName `DNS:es-node-<N>`, extended key usage
serverAuth and clientAuth. The CA key was discarded after signing. Never use these
outside tests.
