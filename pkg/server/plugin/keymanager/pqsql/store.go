package pqsql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver
)

// keyRecord is the persisted representation of one key slot.
type keyRecord struct {
	ID          string
	KeyType     int32
	PKIXData    []byte
	SealedKey   []byte
	Fingerprint string
}

// store is the persistence interface. It is intentionally small so tests can
// exercise sharing semantics without a live PostgreSQL instance.
type store interface {
	Migrate(ctx context.Context) error
	Load(ctx context.Context) ([]keyRecord, error)
	Upsert(ctx context.Context, records []keyRecord) (int64, error)
	Revision(ctx context.Context) (int64, error)
	Close() error
}

type postgresStore struct {
	db *sql.DB
}

func newPostgresStore(ctx context.Context, connString string, maxOpenConns int) (*postgresStore, error) {
	db, err := sql.Open("pgx", connString)
	if err != nil {
		return nil, err
	}
	if maxOpenConns <= 0 {
		maxOpenConns = 4
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &postgresStore{db: db}, nil
}

func (s *postgresStore) Migrate(ctx context.Context) error {
	stmts := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			revision BIGINT NOT NULL DEFAULT 0
		)`, metadataTableName),
		fmt.Sprintf(`INSERT INTO %s (id, revision) VALUES ('global', 0) ON CONFLICT (id) DO NOTHING`, metadataTableName),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			key_type INTEGER NOT NULL,
			pkix_data BYTEA NOT NULL,
			sealed_key BYTEA NOT NULL,
			fingerprint TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`, keysTableName),
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *postgresStore) Load(ctx context.Context) ([]keyRecord, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(
		`SELECT id, key_type, pkix_data, sealed_key, fingerprint FROM %s ORDER BY id`, keysTableName))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []keyRecord
	for rows.Next() {
		var record keyRecord
		if err := rows.Scan(&record.ID, &record.KeyType, &record.PKIXData, &record.SealedKey, &record.Fingerprint); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// Upsert writes records and bumps the global revision in one transaction. Rows
// are never deleted: SPIRE does not remove key slots during rotation, and a
// delete here could remove a key another server just created.
func (s *postgresStore) Upsert(ctx context.Context, records []keyRecord) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	// Serialize concurrent writers across servers.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('qspiffe-pqsql-keymanager'))`); err != nil {
		return 0, err
	}

	for _, record := range records {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (id, key_type, pkix_data, sealed_key, fingerprint, updated_at)
			VALUES ($1, $2, $3, $4, $5, now())
			ON CONFLICT (id) DO UPDATE SET
				key_type = EXCLUDED.key_type,
				pkix_data = EXCLUDED.pkix_data,
				sealed_key = EXCLUDED.sealed_key,
				fingerprint = EXCLUDED.fingerprint,
				updated_at = now()`, keysTableName),
			record.ID, record.KeyType, record.PKIXData, record.SealedKey, record.Fingerprint); err != nil {
			return 0, err
		}
	}

	var revision int64
	if err := tx.QueryRowContext(ctx, fmt.Sprintf(
		`UPDATE %s SET revision = revision + 1 WHERE id = 'global' RETURNING revision`, metadataTableName)).Scan(&revision); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return revision, nil
}

func (s *postgresStore) Revision(ctx context.Context) (int64, error) {
	var revision int64
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT revision FROM %s WHERE id = 'global'`, metadataTableName)).Scan(&revision); err != nil {
		return 0, err
	}
	return revision, nil
}

func (s *postgresStore) Close() error {
	return s.db.Close()
}
