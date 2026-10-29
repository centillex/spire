// Package pqsql implements a shared, encrypted, ML-DSA-65 key manager backed by
// PostgreSQL. It exists so multiple SPIRE servers can share issuer and agent
// signing keys for HA without a PQ-capable KMS/HSM.
//
// Keys are stored as AES-256-GCM encrypted PKCS#8 with a key-encryption key
// (KEK) supplied out of band. The plugin deliberately only accepts ML-DSA-65
// keys: it is a post-quantum key manager, not a general classical one.
//
// Writes are upsert-only. SPIRE never deletes key slots during normal rotation,
// and deleting rows on write would let one server remove keys another server
// just created. Concurrent writers are serialized with a PostgreSQL advisory
// transaction lock.
package pqsql

import (
	"context"
	"crypto/x509"
	"sync"
	"time"

	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName        = "pqsql"
	defaultRefresh    = 2 * time.Second
	keyTypeMLDSA65    = int32(keymanagerv1.KeyType_ML_DSA_65)
	metadataTableName = "pq_keymanager_meta"
	keysTableName     = "pq_keymanager_keys"
)

func BuiltIn() catalog.BuiltIn {
	return asBuiltIn(newPlugin())
}

func asBuiltIn(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		keymanagerv1.KeyManagerPluginServer(p),
		configv1.ConfigServiceServer(p))
}

type configuration struct {
	ConnectionString  string `hcl:"connection_string"`
	EncryptionKeyPath string `hcl:"encryption_key_path"`
	RefreshInterval   string `hcl:"refresh_interval"`
	MaxOpenConns      int    `hcl:"max_open_conns"`
}

func buildConfig(_ catalog.CoreConfig, hclText string, status *pluginconf.Status) *configuration {
	newConfig := new(configuration)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}
	if newConfig.ConnectionString == "" {
		status.ReportError("connection_string is required")
	}
	if newConfig.EncryptionKeyPath == "" {
		status.ReportError("encryption_key_path is required")
	}
	return newConfig
}

// Plugin implements the KeyManager plugin service.
type Plugin struct {
	*keymanagerbase.Base
	configv1.UnimplementedConfigServer

	mu              sync.Mutex
	store           store
	kek             []byte
	refreshInterval time.Duration
	lastCheck       time.Time
	revision        int64
	configured      bool
}

func newPlugin() *Plugin {
	p := &Plugin{}
	p.Base = keymanagerbase.New(keymanagerbase.Config{
		WriteEntries: p.writeEntries,
	})
	return p
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	refresh := defaultRefresh
	if newConfig.RefreshInterval != "" {
		refresh, err = time.ParseDuration(newConfig.RefreshInterval)
		if err != nil || refresh <= 0 {
			return nil, status.Errorf(codes.InvalidArgument, "invalid refresh_interval %q", newConfig.RefreshInterval)
		}
	}

	kek, err := loadKEK(newConfig.EncryptionKeyPath)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to load encryption key: %v", err)
	}

	st, err := newPostgresStore(ctx, newConfig.ConnectionString, newConfig.MaxOpenConns)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "unable to initialize key store: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		_ = st.Close()
		return nil, status.Errorf(codes.Unavailable, "unable to migrate key store: %v", err)
	}

	entries, revision, err := loadEntries(ctx, st, kek)
	if err != nil {
		_ = st.Close()
		return nil, status.Errorf(codes.Internal, "unable to load stored keys: %v", err)
	}
	p.Base.SetEntries(entries)

	p.mu.Lock()
	if p.store != nil {
		_ = p.store.Close()
	}
	p.store = st
	p.kek = kek
	p.refreshInterval = refresh
	p.revision = revision
	p.lastCheck = time.Now()
	p.configured = true
	p.mu.Unlock()

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

// GenerateKey generates a key and persists it before returning it.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyType != keymanagerv1.KeyType_ML_DSA_65 {
		return nil, status.Error(codes.InvalidArgument, "pqsql only supports ML-DSA-65 keys")
	}
	if err := p.refresh(ctx); err != nil {
		return nil, err
	}
	return p.Base.GenerateKey(ctx, req)
}

// GetPublicKey refreshes from the shared store before answering so keys created
// by another server become visible.
func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if err := p.refresh(ctx); err != nil {
		return nil, err
	}
	return p.Base.GetPublicKey(ctx, req)
}

// GetPublicKeys refreshes from the shared store before answering.
func (p *Plugin) GetPublicKeys(ctx context.Context, req *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	if err := p.refresh(ctx); err != nil {
		return nil, err
	}
	return p.Base.GetPublicKeys(ctx, req)
}

// SignData signs with the key as loaded. It deliberately does NOT refresh
// underneath an active key: the facade checks the fingerprint returned by the
// plugin against the fingerprint it saw when the key was fetched, so swapping
// the key mid-call would look like key mismanagement. Rotation becomes visible
// through GetPublicKey/GetPublicKeys, which the CA manager consults when the
// shared journal assigns a new slot.
func (p *Plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	return p.Base.SignData(ctx, req)
}

func (p *Plugin) writeEntries(ctx context.Context, entries []*keymanagerbase.KeyEntry) error {
	p.mu.Lock()
	st := p.store
	kek := p.kek
	refresh := p.refreshInterval
	p.mu.Unlock()

	if st == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	records := make([]keyRecord, 0, len(entries))
	for _, entry := range entries {
		if entry == nil || entry.PrivateKey == nil || entry.PublicKey == nil {
			return status.Error(codes.Internal, "nil key entry")
		}
		if entry.PublicKey.Type != keymanagerv1.KeyType_ML_DSA_65 {
			return status.Errorf(codes.Internal, "key %q is not ML-DSA-65", entry.Id)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(entry.PrivateKey)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to marshal key %q: %v", entry.Id, err)
		}
		sealed, err := sealKey(kek, entry.Id, pkcs8)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to encrypt key %q: %v", entry.Id, err)
		}
		records = append(records, keyRecord{
			ID:          entry.Id,
			KeyType:     int32(entry.PublicKey.Type),
			PKIXData:    entry.PublicKey.PkixData,
			SealedKey:   sealed,
			Fingerprint: entry.PublicKey.Fingerprint,
		})
	}

	revision, err := st.Upsert(ctx, records)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to persist keys: %v", err)
	}

	p.mu.Lock()
	p.revision = revision
	p.lastCheck = time.Now()
	p.mu.Unlock()
	_ = refresh
	return nil
}

// refresh reloads keys when another server has written since the last check.
func (p *Plugin) refresh(ctx context.Context) error {
	p.mu.Lock()
	st := p.store
	kek := p.kek
	refresh := p.refreshInterval
	lastCheck := p.lastCheck
	revision := p.revision
	configured := p.configured
	p.mu.Unlock()

	if !configured || st == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}
	if time.Since(lastCheck) < refresh {
		return nil
	}

	current, err := st.Revision(ctx)
	if err != nil {
		return status.Errorf(codes.Unavailable, "unable to read key store revision: %v", err)
	}

	p.mu.Lock()
	p.lastCheck = time.Now()
	p.mu.Unlock()
	if current == revision {
		return nil
	}

	entries, loadedRevision, err := loadEntries(ctx, st, kek)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to reload keys: %v", err)
	}
	p.Base.SetEntries(entries)

	p.mu.Lock()
	p.revision = loadedRevision
	p.mu.Unlock()
	return nil
}

func loadEntries(ctx context.Context, st store, kek []byte) ([]*keymanagerbase.KeyEntry, int64, error) {
	revision, err := st.Revision(ctx)
	if err != nil {
		return nil, 0, err
	}
	records, err := st.Load(ctx)
	if err != nil {
		return nil, 0, err
	}
	entries := make([]*keymanagerbase.KeyEntry, 0, len(records))
	for _, record := range records {
		if record.KeyType != keyTypeMLDSA65 {
			return nil, 0, status.Errorf(codes.Internal, "stored key %q is not ML-DSA-65", record.ID)
		}
		pkcs8, err := openKey(kek, record.ID, record.SealedKey)
		if err != nil {
			return nil, 0, status.Errorf(codes.Internal, "unable to decrypt key %q (wrong KEK?): %v", record.ID, err)
		}
		key, err := x509.ParsePKCS8PrivateKey(pkcs8)
		if err != nil {
			return nil, 0, status.Errorf(codes.Internal, "unable to parse key %q: %v", record.ID, err)
		}
		entry, err := keymanagerbase.MakeKeyEntryFromKey(record.ID, key)
		if err != nil {
			return nil, 0, status.Errorf(codes.Internal, "unable to build entry %q: %v", record.ID, err)
		}
		entries = append(entries, entry)
	}
	return entries, revision, nil
}
