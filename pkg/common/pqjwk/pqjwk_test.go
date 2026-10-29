package pqjwk

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

	"github.com/stretchr/testify/require"
)

// This exercises the SPIRE-side copy of the go-spiffe AKP codec so divergence
// between the copies is caught. It is not a substitute for the SDK's fuller
// malformed-input and fuzz coverage.
func TestCertificateEntryRoundTrip(t *testing.T) {
	td, err := url.Parse("spiffe://pq.example")
	require.NoError(t, err)
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ML-DSA CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		URIs:                  []*url.URL{td},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	encoded, err := MarshalX509Authority(cert)
	require.NoError(t, err)
	parsed, err := ParseX509Authority(encoded)
	require.NoError(t, err)
	require.Equal(t, cert.Raw, parsed.Raw)

	// The entry must not contain private or competing key material.
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &fields))
	for _, forbidden := range []string{"priv", "kid", "d", "crv", "x", "n"} {
		require.NotContains(t, fields, forbidden)
	}

	// A different algorithm identifier is rejected.
	fields["alg"] = json.RawMessage(`"ML-DSA-44"`)
	mutated, err := json.Marshal(fields)
	require.NoError(t, err)
	_, err = ParseX509Authority(mutated)
	require.Error(t, err)
}
