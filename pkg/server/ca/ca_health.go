package ca

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/pemutil"
)

var (
	caHealthKey, _ = pemutil.ParsePublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzLY1/SRlsMJExTnuvzBO292RjGjU
3L8jFRtmQl0CjBeHdxUlGK1OkNLDYh0b6AW4siWt+y+DcbUAWNb14e5zWg==
-----END PUBLIC KEY-----`))
)

// healthMLDSAKey is generated once and reused so strict PQ health checks do not
// pay ML-DSA key generation cost on every probe. It is a public/private test key
// used only for issuing an ephemeral health-check certificate.
var healthMLDSAKey = sync.OnceValues(func() (crypto.Signer, error) {
	return mldsa.GenerateKey(mldsa.MLDSA65())
})

type caHealth struct {
	ca ServerCA
	td spiffeid.TrustDomain
	// strictPQ selects an ML-DSA health key so the probe exercises the same
	// issuance path the profile enforces.
	strictPQ bool
}

func (h *caHealth) CheckHealth() health.State {
	// Prevent a problem with signing the SVID from blocking the health check
	// indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	ctx = health.CheckContext(ctx)

	var publicKey crypto.PublicKey = caHealthKey
	var err error
	if h.strictPQ {
		var signer crypto.Signer
		signer, err = healthMLDSAKey()
		if err == nil {
			publicKey = signer.Public()
		}
	}

	spiffeID, idErr := spiffeid.FromPath(h.td, "/for/health/check/only")
	if err == nil {
		err = idErr
	}
	if err == nil {
		_, err = h.ca.SignWorkloadX509SVID(ctx, WorkloadX509SVIDParams{
			SPIFFEID:  spiffeID,
			PublicKey: publicKey,
		})
	}

	// Both liveness and readiness are determined by whether the
	// x509 CA was successfully signed.
	ready := err == nil
	live := err == nil

	return health.State{
		Live:  live,
		Ready: ready,
		ReadyDetails: caHealthDetails{
			SignX509SVIDErr: errString(err),
		},
		LiveDetails: caHealthDetails{
			SignX509SVIDErr: errString(err),
		},
	}
}

type caHealthDetails struct {
	SignX509SVIDErr string `json:"sign_x509_svid_err,omitempty"`
}

func errString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
