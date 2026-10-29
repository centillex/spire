# Server plugin: KeyManager "pqsql"

The `pqsql` key manager stores ML-DSA-65 private keys encrypted in PostgreSQL so
that multiple SPIRE servers can share the same issuer keys. It is intended for
post-quantum HA deployments that cannot use a PQ-capable KMS/HSM yet.

Only ML-DSA-65 keys are accepted. A stored classical key, a wrong key-encryption
key (KEK), or a missing/over-permissive KEK file makes configuration fail; the
plugin never falls back to plaintext or classical keys.

## Configuration

| Configuration | Description |
|---|---|
| `connection_string` | Required. PostgreSQL connection string, e.g. `postgres://user:pass@host:5432/spire?sslmode=verify-full`. |
| `encryption_key_path` | Required. Path to a 32-byte KEK. The file must not be accessible by group or others. |
| `refresh_interval` | Optional. How often to check for keys written by another server. Default `2s`. |
| `max_open_conns` | Optional. Connection pool size. Default `4`. |

```hcl
KeyManager "pqsql" {
    plugin_data {
        connection_string    = "postgres://spire:secret@db.example:5432/spire?sslmode=verify-full"
        encryption_key_path  = "/run/secrets/pq-keymanager-kek"
        refresh_interval     = "2s"
        max_open_conns       = 10
    }
}
```

## Storage

Two tables are created on first configure:

- `pq_keymanager_keys`: key ID, type, PKIX public key, AES-256-GCM encrypted
  PKCS#8 private key, fingerprint, update time. The key ID is used as additional
  authenticated data so ciphertext cannot be moved between slots.
- `pq_keymanager_meta`: a monotonic revision used to detect writes by other
  servers.

Writes are upsert-only and run in one transaction under a PostgreSQL advisory
lock. Rows are never deleted on write: SPIRE does not remove key slots during
normal rotation, and deleting rows would let one server remove a key another
server just created.

## HA behaviour

- Every server uses the same database and KEK.
- A server checks the revision before generating or fetching keys and reloads
  when another server has written (bounded by `refresh_interval`).
- Signing uses the key as loaded. Rotation becomes visible through key lookups,
  which the CA manager performs when the shared CA journal assigns a slot. This
  keeps the fingerprint returned by the plugin consistent with the fingerprint
  the facade recorded when the key was fetched.
- CA rotation is coordinated by SPIRE's CA journal, not a leader election; the
  plugin only provides shared, durable key custody.

## Security notes

- The KEK is the root of key confidentiality. Supply it from a secrets manager
  or encrypted volume, not from the SPIRE configuration or the database.
- A host or process that can read the KEK and the database can sign with the
  issuer keys. Host isolation, database access control and backups are deployment
  responsibilities.
- This is software custody. Deployments that require non-exportable keys need a
  PQ-capable HSM/KMS (tracked as PAR-21 in the workspace gap register).
- KEK rotation/re-wrap tooling is not implemented; rotating a KEK currently
  requires re-encrypting the key rows.
