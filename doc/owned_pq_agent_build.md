# Building the agent with the owned strict-PQ SDK

The reviewed SDK at `ed8c14cf82c5850eabb36fbc00e73da2b11c8fc0` deliberately
returns opaque `*tlsconfig.Config` values, not mutable `*crypto/tls.Config`.
It also wraps gRPC authentication information. SPIRE's older agent callers
therefore required an API migration, not a compiler-version downgrade.

## Migrated agent callers

- Prometheus SPIFFE/server-SVID and Web-PKI-server/SPIFFE-client modes snapshot
  preferences with `WithBaseTLSConfig`, then serve over the owned listener.
  They never assign an owned configuration to `http.Server.TLSConfig` or call
  legacy certificate-only authentication callbacks. Explicit non-SPIFFE
  file-certificate TLS remains a separate existing mode, not a fallback.
- Authenticated agent-to-server gRPC connections use owned TLS credentials during
  bootstrap and owned mutual credentials once the agent SVID is available. The
  expected server SPIFFE ID, live bundle/certificate getters, xDS handling and
  load-balancing configuration remain intact.
- Broker gRPC listeners use owned mutual credentials and their identity allowlist.
  Broker API authorization reads `grpccredentials.PeerIDFromContext`, not a
  bare `credentials.TLSInfo.SPIFFEID`. Missing/unwrapped identities fail closed;
  reference-type authorization and mandatory security headers remain unchanged.

The authenticated agent uses an opaque `crypto.Signer` from its key-manager
plugin, not an exported `*mldsa.PrivateKey`. The SDK admits this handle only
when its native ML-DSA-65 public key matches the signed leaf DER, then requires
actual ML-DSA proof of possession in TLS CertificateVerify. The client regression
suite exercises the real plugin facade, including a lost/unavailable signing
key. No private-key export or native-TLS fallback is used.

TLS preferences are applied before snapshotting. The owned SDK controls protocol,
KEM, certificate algorithms and session policy. Classical preferences cannot
weaken the profile. Source failures, bad credentials, unauthorized identities and
configuration conflicts do not trigger stock TLS or plaintext fallback.

The pre-existing explicit insecure-bootstrap transport is not used by the
strict agent; `strict_pq` configuration continues to reject `insecure_bootstrap`.

## Reproducible local artifact

From a clean committed SPIRE checkout, with clean sibling `go-spiffe` and
`spire-plugin-sdk` repositories:

```sh
./scripts/build-owned-agent.sh /absolute/new-output-directory
```

The recipe checks the reviewed SDK/plugin-SDK commits, archives all three
committed sources into a private output directory, creates an isolated Go
workspace, and builds with `GOTOOLCHAIN=go1.27.3` and `CGO_ENABLED=0`. It writes
`bin/spire-agent`, `manifest.json`, `go-build-info.txt` and `build.log`. The
manifest records the exact commits and binary SHA256. It refuses dirty source
or replacement of an existing output directory. It does not modify the sibling
checkouts, read bootstrap keys, generate credentials, use sudo or start services.

Tests can be reproduced against those exact archived sources:

```sh
export GOTOOLCHAIN=go1.27.3 GOWORK=/absolute/new-output-directory/source/go.work
cd /absolute/new-output-directory/source/spire
go test -race ./pkg/agent/client ./pkg/agent/broker/... \
  ./pkg/common/telemetry ./pkg/common/tlspolicy
go vet ./pkg/agent/client ./pkg/agent/broker/... \
  ./pkg/common/telemetry ./test/pqca
go test ./cmd/spire-agent/cli/run -run TestStrictPQAgentConfiguration
```

Regression tests use synthetic native ML-DSA-65 CAs and real owned TLS/gRPC
handshakes. They check bootstrap/mutual clients, federated broker/metrics
allowlists, identity extraction, source loss/recovery, SVID rotation, session
non-resumption and rejection of classical KEMs/keys and unauthenticated peers.
A forged SPIFFE URL in bare authentication information is not a verified peer.

## Scope

This recipe builds **spire-agent**, not `spire-server`. It does not migrate or
claim compatibility for all remaining mutable-TLS integrations in the SPIRE
server source. Do not replace the owned SDK with upstream or weaken the profile
to compile another target. A server migration requires its own treatment of
bootstrap versus authenticated RPCs and authorization context.

A successful build is not node admission. Installing/starting this artifact still
requires explicit local privileges, an administrator-approved x509pop bootstrap
certificate and an independently trusted server bundle. Workload registration,
Desk installation binding and fresh owner/key proof remain separate steps.
