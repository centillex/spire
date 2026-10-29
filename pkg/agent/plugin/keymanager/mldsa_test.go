package keymanager_test

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	keymanagerbase "github.com/spiffe/spire/pkg/agent/plugin/keymanager/base"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/stretchr/testify/require"
)

func loadMLDSAPlugin(t *testing.T, base *keymanagerbase.Base) keymanager.KeyManager {
	km := new(keymanager.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("test", keymanagerv1.KeyManagerPluginServer(base)), km)
	return km
}

func TestMLDSA65PluginSigning(t *testing.T) {
	base := keymanagerbase.New(keymanagerbase.Config{})
	km := loadMLDSAPlugin(t, base)
	key, err := km.GenerateKey(context.Background(), "pq", keymanager.MLDSA65)
	require.NoError(t, err)
	pub, ok := key.Public().(*mldsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, mldsa.MLDSA65(), pub.Parameters())
	message := []byte("component signing control")
	sig, err := key.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	require.NoError(t, mldsa.Verify(pub, message, sig, nil))
	require.Error(t, mldsa.Verify(pub, []byte("different message"), sig, nil))
	opts := &mldsa.Options{Context: "component-context"}
	sig, err = key.Sign(rand.Reader, message, opts)
	require.NoError(t, err)
	require.NoError(t, mldsa.Verify(pub, message, sig, opts))
	require.Error(t, mldsa.Verify(pub, message, sig, nil))
	for _, opts := range []crypto.SignerOpts{nil, crypto.SHA256, crypto.MLDSAMu, (*mldsa.Options)(nil), &mldsa.Options{Context: strings.Repeat("x", 256)}} {
		_, err = key.Sign(rand.Reader, message, opts)
		require.Error(t, err)
	}
	// Exercise native certificate and CSR issuance through the actual plugin facade.
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "component test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.Equal(t, x509.MLDSA65, cert.SignatureAlgorithm)
	require.NoError(t, cert.CheckSignatureFrom(cert))
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "component request"}}, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature())
	require.Equal(t, x509.MLDSA65, csr.SignatureAlgorithm)
	// Explicit options cannot be substituted across algorithm families.
	_, err = base.SignData(context.Background(), &keymanagerv1.SignDataRequest{KeyId: "pq", Data: message, SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256}})
	require.Error(t, err)
	_, err = base.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{KeyId: "ec", KeyType: keymanagerv1.KeyType_EC_P256})
	require.NoError(t, err)
	_, err = base.SignData(context.Background(), &keymanagerv1.SignDataRequest{KeyId: "ec", Data: message, SignerOpts: &keymanagerv1.SignDataRequest_MldsaOptions{MldsaOptions: &keymanagerv1.SignDataRequest_MLDSAOptions{}}})
	require.Error(t, err)
}

func TestMLDSA65KeyRestoration(t *testing.T) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		key, err := mldsa.GenerateKey(params)
		require.NoError(t, err)
		// Persistence serialization stays in memory; artifacts contain no private keys.
		der, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		restored, err := x509.ParsePKCS8PrivateKey(der)
		require.NoError(t, err)
		entry, err := keymanagerbase.MakeKeyEntryFromKey("restored", restored)
		if params != mldsa.MLDSA65() {
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, keymanagerv1.KeyType_ML_DSA_65, entry.Type)
		base := keymanagerbase.New(keymanagerbase.Config{})
		base.SetEntries([]*keymanagerbase.KeyEntry{entry})
		km := loadMLDSAPlugin(t, base)
		got, err := km.GetKey(context.Background(), "restored")
		require.NoError(t, err)
		sig, err := got.Sign(nil, []byte("restored"), crypto.Hash(0))
		require.NoError(t, err)
		require.NoError(t, mldsa.Verify(key.PublicKey(), []byte("restored"), sig, nil))
	}
	_, err := keymanagerbase.MakeKeyEntryFromKey("nil", (*mldsa.PrivateKey)(nil))
	require.Error(t, err)
	_, err = keymanagerbase.MakeKeyEntryFromKey("zero", new(mldsa.PrivateKey))
	require.Error(t, err)
}
