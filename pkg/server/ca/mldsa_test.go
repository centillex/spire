package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/pqjose"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakehealthchecker"
	"github.com/stretchr/testify/require"
)

// TestMLDSA65X509Issuance exercises the real server CA, credential template
// builder, and credential validator with ML-DSA-65. It is a component test,
// not deployment evidence.
func TestMLDSA65X509Issuance(t *testing.T) {
	for _, tt := range []struct {
		name          string
		params        mldsa.Parameters
		expectFailure bool
	}{
		{name: "ML-DSA-65", params: mldsa.MLDSA65()},
		{name: "ML-DSA-44 rejected", params: mldsa.MLDSA44(), expectFailure: true},
		{name: "ML-DSA-87 rejected", params: mldsa.MLDSA87(), expectFailure: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testMLDSA65X509Issuance(t, tt.params, tt.expectFailure)
		})
	}
}

func testMLDSA65X509Issuance(t *testing.T, params mldsa.Parameters, expectFailure bool) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	mockClock := clock.NewMock(t)
	mockClock.Set(time.Now().Truncate(time.Second).UTC())

	builder, err := credtemplate.NewBuilder(credtemplate.Config{
		TrustDomain:   td,
		Clock:         mockClock,
		X509CASubject: pkix.Name{CommonName: "ML-DSA TEST CA"},
		X509CATTL:     10 * time.Minute,
		X509SVIDTTL:   time.Minute,
	})
	require.NoError(t, err)
	validator, err := credvalidator.New(credvalidator.Config{TrustDomain: td, Clock: mockClock})
	require.NoError(t, err)

	caKey, err := mldsa.GenerateKey(params)
	require.NoError(t, err)
	caTemplate, err := builder.BuildSelfSignedX509CATemplate(t.Context(), credtemplate.SelfSignedX509CAParams{PublicKey: caKey.Public()})
	require.NoError(t, err)
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	require.NoError(t, validator.ValidateX509CA(caCert))

	serverCA := NewCA(Config{
		Clock:         mockClock,
		Metrics:       telemetry.Blackhole{},
		TrustDomain:   td,
		CredBuilder:   builder,
		CredValidator: validator,
		HealthChecker: fakehealthchecker.New(),
		StrictPQ:      true,
	})
	serverCA.SetX509CA(&X509CA{Signer: caKey, Certificate: caCert})

	leafKey, err := mldsa.GenerateKey(params)
	require.NoError(t, err)
	chain, err := serverCA.SignWorkloadX509SVID(t.Context(), WorkloadX509SVIDParams{
		SPIFFEID:  spiffeid.RequireFromPath(td, "/workload"),
		PublicKey: leafKey.Public(),
		TTL:       time.Minute,
	})
	if expectFailure {
		// Strict policy must reject non-profile parameter sets.
		require.ErrorContains(t, err, "strict PQ policy")
		return
	}
	require.NoError(t, err)
	require.Len(t, chain, 1) // self-signed CA has no upstream chain
	leaf := chain[0]
	require.Equal(t, x509.MLDSA65, leaf.SignatureAlgorithm)
	require.Equal(t, x509.MLDSA, leaf.PublicKeyAlgorithm)
	require.NoError(t, leaf.CheckSignatureFrom(caCert))
	require.NoError(t, validator.ValidateX509SVID(leaf, spiffeid.RequireFromPath(td, "/workload")))

	// Signed DER, not exported fields, is what a verifier must consume.
	reparsedLeaf, err := x509.ParseCertificate(leaf.Raw)
	require.NoError(t, err)
	pub, ok := reparsedLeaf.PublicKey.(*mldsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, mldsa.MLDSA65(), pub.Parameters())
	// A classical request is rejected rather than downgraded.
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = serverCA.SignWorkloadX509SVID(t.Context(), WorkloadX509SVIDParams{SPIFFEID: spiffeid.RequireFromPath(td, "/classical"), PublicKey: classicalKey.Public(), TTL: time.Minute})
	require.ErrorContains(t, err, "strict PQ policy")
	// A classical signer cannot impersonate the PQ CA.
	classicalCA := NewCA(Config{
		Clock:         mockClock,
		Metrics:       telemetry.Blackhole{},
		TrustDomain:   td,
		CredBuilder:   builder,
		CredValidator: validator,
		HealthChecker: fakehealthchecker.New(),
		StrictPQ:      true,
	})
	classicalCA.SetX509CA(&X509CA{Signer: classicalKey, Certificate: caCert})
	_, err = classicalCA.SignWorkloadX509SVID(t.Context(), WorkloadX509SVIDParams{SPIFFEID: spiffeid.RequireFromPath(td, "/workload"), PublicKey: leafKey.Public(), TTL: time.Minute})
	require.ErrorContains(t, err, "strict PQ policy")
	require.NoError(t, caCert.CheckSignature(reparsedLeaf.SignatureAlgorithm, reparsedLeaf.RawTBSCertificate, reparsedLeaf.Signature))
}

// TestMLDSA65JWTSVIDIssuance exercises the ML-DSA-65 JWT-SVID signing path and
// the shared credential validator. It is a component test, not deployment
// evidence.
func TestMLDSA65JWTSVIDIssuance(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	id := spiffeid.RequireFromPath(td, "/workload")
	mockClock := clock.NewMock(t)
	mockClock.Set(time.Now().Truncate(time.Second).UTC())

	builder, err := credtemplate.NewBuilder(credtemplate.Config{
		TrustDomain:   td,
		Clock:         mockClock,
		X509CASubject: pkix.Name{CommonName: "ML-DSA TEST CA"},
		X509CATTL:     10 * time.Minute,
		X509SVIDTTL:   time.Minute,
	})
	require.NoError(t, err)
	validator, err := credvalidator.New(credvalidator.Config{TrustDomain: td, Clock: mockClock})
	require.NoError(t, err)
	serverCA := NewCA(Config{
		Clock:         mockClock,
		Metrics:       telemetry.Blackhole{},
		TrustDomain:   td,
		CredBuilder:   builder,
		CredValidator: validator,
		HealthChecker: fakehealthchecker.New(),
		StrictPQ:      true,
	})

	jwtKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	serverCA.SetJWTKey(&JWTKey{
		Signer:   jwtKey,
		Kid:      "jwt-key-1",
		NotAfter: mockClock.Now().Add(time.Hour),
	})

	token, err := serverCA.SignWorkloadJWTSVID(t.Context(), WorkloadJWTSVIDParams{
		SPIFFEID: id,
		TTL:      time.Minute,
		Audience: []string{"audience.test"},
	})
	require.NoError(t, err)

	parsed, err := pqjose.ParseJWT(token)
	require.NoError(t, err)
	require.Equal(t, "ML-DSA-65", parsed.Header().Algorithm)
	require.Equal(t, "jwt-key-1", parsed.Header().KeyID)
	require.NoError(t, parsed.Verify(jwtKey.PublicKey()))

	var claims struct {
		Subject  string   `json:"sub"`
		Audience []string `json:"aud"`
		Expiry   int64    `json:"exp"`
	}
	require.NoError(t, json.Unmarshal(parsed.Claims(), &claims))
	require.Equal(t, id.String(), claims.Subject)
	require.Equal(t, []string{"audience.test"}, claims.Audience)
	require.Greater(t, claims.Expiry, mockClock.Now().Unix())

	require.NoError(t, validator.ValidateWorkloadJWTSVID(token, id))

	// A modified signature must not validate.
	tampered := []byte(token)
	if tampered[len(tampered)-1] == 'A' {
		tampered[len(tampered)-1] = 'B'
	} else {
		tampered[len(tampered)-1] = 'A'
	}
	tamperedParsed, err := pqjose.ParseJWT(string(tampered))
	require.NoError(t, err)
	require.Error(t, tamperedParsed.Verify(jwtKey.PublicKey()))

	// Strict PQ refuses a classical JWT signer rather than falling back.
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serverCA.SetJWTKey(&JWTKey{Signer: classicalKey, Kid: "classical", NotAfter: mockClock.Now().Add(time.Hour)})
	_, err = serverCA.SignWorkloadJWTSVID(t.Context(), WorkloadJWTSVIDParams{SPIFFEID: id, TTL: time.Minute, Audience: []string{"audience.test"}})
	require.ErrorContains(t, err, "strict PQ policy")
}
