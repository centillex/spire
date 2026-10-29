package util

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func MakeCSR(privateKey any, spiffeID spiffeid.ID) ([]byte, error) {
	return makeCSR(privateKey, &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIRE"},
		},
		URIs: []*url.URL{spiffeID.URL()},
	})
}

func MakeCSRWithoutURISAN(privateKey any) ([]byte, error) {
	// Do not pin a signature algorithm: crypto/x509 selects the scheme that
	// matches the key type, including ML-DSA. Pinning ECDSAWithSHA256 would
	// reject non-ECDSA agent/workload keys.
	return makeCSR(privateKey, &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIRE"},
		},
	})
}

func makeCSR(privateKey any, template *x509.CertificateRequest) ([]byte, error) {
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, err
	}
	return csr, nil
}
