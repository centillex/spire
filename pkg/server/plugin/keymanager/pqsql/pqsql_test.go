package pqsql

import (
	"context"
	"crypto/mldsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"github.com/stretchr/testify/require"
)

// memoryStore implements the persistence interface for tests, including the
// sharing semantics of the PostgreSQL store.
type memoryStore struct {
	mu       sync.Mutex
	revision int64
	records  map[string]keyRecord
}

func newMemoryStore() *memoryStore {
	return &memoryStore{records: make(map[string]keyRecord)}
}

func (s *memoryStore) Migrate(context.Context) error { return nil }

func (s *memoryStore) Load(context.Context) ([]keyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]keyRecord, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, record)
	}
	return records, nil
}

func (s *memoryStore) Upsert(_ context.Context, records []keyRecord) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range records {
		s.records[record.ID] = record
	}
	s.revision++
	return s.revision, nil
}

func (s *memoryStore) Revision(context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revision, nil
}

func (s *memoryStore) Close() error { return nil }

func writeKEK(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kek")
	kek := make([]byte, kekSize)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	require.NoError(t, os.WriteFile(path, kek, 0600))
	return path
}

func configurePlugin(t *testing.T, st store, kekPath string) *Plugin {
	t.Helper()
	p := newPlugin()
	p.mu.Lock()
	p.store = st
	kek, err := loadKEK(kekPath)
	require.NoError(t, err)
	p.kek = kek
	p.refreshInterval = time.Millisecond
	p.lastCheck = time.Time{}
	p.configured = true
	p.mu.Unlock()

	entries, revision, err := loadEntries(context.Background(), st, kek)
	require.NoError(t, err)
	p.Base.SetEntries(entries)
	p.mu.Lock()
	p.revision = revision
	p.mu.Unlock()
	return p
}

func generateKey(t *testing.T, p *Plugin, id string) *keymanagerv1.PublicKey {
	t.Helper()
	resp, err := p.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyId:   id,
		KeyType: keymanagerv1.KeyType_ML_DSA_65,
	})
	require.NoError(t, err)
	require.NotNil(t, resp.PublicKey)
	return resp.PublicKey
}

func sign(t *testing.T, p *Plugin, id string, message []byte) ([]byte, *keymanagerv1.PublicKey) {
	t.Helper()
	resp, err := p.SignData(context.Background(), &keymanagerv1.SignDataRequest{
		KeyId: id,
		Data:  message,
		SignerOpts: &keymanagerv1.SignDataRequest_MldsaOptions{
			MldsaOptions: &keymanagerv1.SignDataRequest_MLDSAOptions{},
		},
	})
	require.NoError(t, err)
	pub, err := p.GetPublicKey(context.Background(), &keymanagerv1.GetPublicKeyRequest{KeyId: id})
	require.NoError(t, err)
	return resp.Signature, pub.PublicKey
}

func parsePublicKey(t *testing.T, pkix []byte) *mldsa.PublicKey {
	t.Helper()
	key, err := x509.ParsePKIXPublicKey(pkix)
	require.NoError(t, err)
	pub, ok := key.(*mldsa.PublicKey)
	require.True(t, ok)
	return pub
}

// TestSharedKeysAcrossServers models two SPIRE servers using the same store and
// KEK: a key generated on one becomes usable on the other after refresh.
func TestSharedKeysAcrossServers(t *testing.T) {
	st := newMemoryStore()
	kekPath := writeKEK(t)

	serverA := configurePlugin(t, st, kekPath)
	serverB := configurePlugin(t, st, kekPath)

	// A generates the key; B has not refreshed yet.
	generateKey(t, serverA, "X509-CA-A")
	serverB.mu.Lock()
	serverB.lastCheck = time.Time{}
	serverB.mu.Unlock()

	message := []byte("shared-key signing")
	sig, pub := sign(t, serverB, "X509-CA-A", message)
	require.NoError(t, mldsa.Verify(parsePublicKey(t, pub.PkixData), message, sig, nil))

	// A signature from B verifies against the public key A reports.
	sigA, pubA := sign(t, serverA, "X509-CA-A", message)
	require.Equal(t, pub.PkixData, pubA.PkixData)
	require.NoError(t, mldsa.Verify(parsePublicKey(t, pubA.PkixData), message, sigA, nil))
}

// TestRefreshPicksUpRotation models a rotation on one server becoming visible on
// the other without a restart.
func TestRefreshPicksUpRotation(t *testing.T) {
	st := newMemoryStore()
	kekPath := writeKEK(t)
	serverA := configurePlugin(t, st, kekPath)
	serverB := configurePlugin(t, st, kekPath)

	first := generateKey(t, serverA, "X509-CA-A")
	serverB.mu.Lock()
	serverB.lastCheck = time.Time{}
	serverB.mu.Unlock()
	_, onB := sign(t, serverB, "X509-CA-A", []byte("before"))
	require.Equal(t, first.PkixData, onB.PkixData)

	// Rotation happens on A. B must use the new key after its refresh interval.
	rotated := generateKey(t, serverA, "X509-CA-A")
	require.NotEqual(t, first.PkixData, rotated.PkixData)
	time.Sleep(2 * time.Millisecond)
	_, onB = sign(t, serverB, "X509-CA-A", []byte("after"))
	require.Equal(t, rotated.PkixData, onB.PkixData)
}

func TestWrongKEKCannotReadKeys(t *testing.T) {
	st := newMemoryStore()
	good := writeKEK(t)
	serverA := configurePlugin(t, st, good)
	generateKey(t, serverA, "X509-CA-A")

	badPath := filepath.Join(t.TempDir(), "bad-kek")
	badKEKFile := make([]byte, kekSize)
	for i := range badKEKFile {
		badKEKFile[i] = 0xff
	}
	require.NoError(t, os.WriteFile(badPath, badKEKFile, 0600))
	p := newPlugin()
	badKEK, err := loadKEK(badPath)
	require.NoError(t, err)
	p.mu.Lock()
	p.store = st
	p.kek = badKEK
	p.configured = true
	p.mu.Unlock()

	_, _, err = loadEntries(context.Background(), st, badKEK)
	require.ErrorContains(t, err, "wrong KEK")
}

func TestRejectsNonMLDSAKeys(t *testing.T) {
	st := newMemoryStore()
	p := configurePlugin(t, st, writeKEK(t))

	_, err := p.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyId:   "classical",
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	require.ErrorContains(t, err, "only supports ML-DSA-65")
	require.Empty(t, st.records)
}

func TestWritesAreUpsertOnly(t *testing.T) {
	st := newMemoryStore()
	kekPath := writeKEK(t)
	p := configurePlugin(t, st, kekPath)

	generateKey(t, p, "existing")
	require.Len(t, st.records, 1)

	// A second server that only knows about a different slot must not delete
	// the existing record when it writes.
	other := configurePlugin(t, newMemoryStore(), kekPath)
	generateKey(t, other, "other-slot")

	entry, err := keymanagerbase.MakeKeyEntryFromKey("other-slot", mustGenerate(t))
	require.NoError(t, err)
	require.NoError(t, p.writeEntries(context.Background(), []*keymanagerbase.KeyEntry{entry}))
	require.Contains(t, st.records, "existing")
	require.Contains(t, st.records, "other-slot")
}

func TestEncryptionBindsKeyID(t *testing.T) {
	kek, err := loadKEK(writeKEK(t))
	require.NoError(t, err)

	sealed, err := sealKey(kek, "slot-a", []byte("secret material"))
	require.NoError(t, err)
	_, err = openKey(kek, "slot-b", sealed)
	require.Error(t, err)
	plain, err := openKey(kek, "slot-a", sealed)
	require.NoError(t, err)
	require.Equal(t, []byte("secret material"), plain)
}

func TestKEKValidation(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short")
	require.NoError(t, os.WriteFile(short, make([]byte, 16), 0600))
	_, err := loadKEK(short)
	require.ErrorContains(t, err, "exactly 32 bytes")

	permissive := filepath.Join(dir, "permissive")
	require.NoError(t, os.WriteFile(permissive, make([]byte, kekSize), 0644))
	_, err = loadKEK(permissive)
	require.ErrorContains(t, err, "must not be accessible")
}

func mustGenerate(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	return key
}

var _ store = (*memoryStore)(nil)
