package bundleutil

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func mldsaAuthority(t *testing.T, td spiffeid.TrustDomain) *x509.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ML-DSA test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		URIs:                  []*url.URL{td.ID().URL()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestPQBundlesMarshalAndUnmarshal(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	cert := mldsaAuthority(t, td)
	bundle := spiffebundle.FromX509Authorities(td, []*x509.Certificate{cert})
	bundle.SetSequenceNumber(7)
	bundle.SetRefreshHint(42 * time.Second)

	data, err := Marshal(bundle)
	require.NoError(t, err)

	var doc struct {
		Keys []struct {
			Kty  string   `json:"kty"`
			Alg  string   `json:"alg"`
			Use  string   `json:"use"`
			X5c  []string `json:"x5c"`
			Pub  string   `json:"pub"`
			Kid  string   `json:"kid"`
			Priv string   `json:"priv"`
		} `json:"keys"`
		Sequence    uint64 `json:"spiffe_sequence"`
		RefreshHint int    `json:"spiffe_refresh_hint"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	require.Len(t, doc.Keys, 1)
	entry := doc.Keys[0]
	require.Equal(t, "AKP", entry.Kty)
	require.Equal(t, "ML-DSA-65", entry.Alg)
	require.Equal(t, "x509-svid", entry.Use)
	require.Len(t, entry.X5c, 1)
	require.NotEmpty(t, entry.Pub)
	require.Empty(t, entry.Kid)
	require.Empty(t, entry.Priv)
	require.Equal(t, uint64(7), doc.Sequence)
	require.Equal(t, 42, doc.RefreshHint)

	parsed, err := Unmarshal(td, data)
	require.NoError(t, err)
	require.Equal(t, td, parsed.TrustDomain())
	require.True(t, bundle.Equal(parsed))
	require.Equal(t, cert.Raw, parsed.X509Authorities()[0].Raw)
}

func TestPQBundlesRejectMalformedEntries(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	cert := mldsaAuthority(t, td)
	bundle := spiffebundle.FromX509Authorities(td, []*x509.Certificate{cert})
	data, err := Marshal(bundle)
	require.NoError(t, err)

	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &doc))

	for _, mutate := range []func(map[string]any){
		func(m map[string]any) { m["priv"] = "private" },
		func(m map[string]any) { m["alg"] = "ML-DSA-44" },
		func(m map[string]any) { m["use"] = "jwt-svid" },
		func(m map[string]any) { m["x5c"] = []string{} },
	} {
		keys := doc["keys"]
		var raw []map[string]any
		require.NoError(t, json.Unmarshal(keys, &raw))
		entry := raw[0]
		mutate(entry)
		badKeys, err := json.Marshal([]any{entry})
		require.NoError(t, err)
		bad := map[string]json.RawMessage{"keys": badKeys}
		badData, err := json.Marshal(bad)
		require.NoError(t, err)
		_, err = Unmarshal(td, badData)
		require.Error(t, err)
	}
}
