// Package pqca provides synthetic ML-DSA-65 credentials for transport tests.
package pqca

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
)

type CA struct {
	Root        *x509.Certificate
	Key         *mldsa.PrivateKey
	TrustDomain spiffeid.TrustDomain
}

func New(t testing.TB, domain string) *CA {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "synthetic PQ test root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &CA{cert, key, spiffeid.RequireTrustDomainFromString(domain)}
}
func (ca *CA) SVID(t testing.TB, path string, keys ...crypto.Signer) *x509svid.SVID {
	return ca.issue(t, path, true, keys...)
}

// Web creates a Web PKI fixture without a SPIFFE URI SAN. A supplied signer is
// useful for isolating algorithm rejection from chain or hostname rejection.
func (ca *CA) Web(t testing.TB, keys ...crypto.Signer) *x509svid.SVID {
	return ca.issue(t, "/web", false, keys...)
}
func (ca *CA) issue(t testing.TB, path string, spiffe bool, keys ...crypto.Signer) *x509svid.SVID {
	t.Helper()
	generated, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	var key crypto.Signer = generated
	if len(keys) > 0 {
		key = keys[0]
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	id := spiffeid.RequireFromPath(ca.TrustDomain, path)
	template := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if spiffe {
		template.URIs = []*url.URL{id.URL()}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Root, key.Public(), ca.Key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{cert}, PrivateKey: key}
}
func (ca *CA) Bundle() *x509bundle.Bundle {
	return x509bundle.FromX509Authorities(ca.TrustDomain, []*x509.Certificate{ca.Root})
}

// PeerAuthInfo performs a real owned mutual handshake. Tests must not fake an
// SDK-authenticated peer by putting a SPIFFE URL in a bare credentials.TLSInfo.
func PeerAuthInfo(t testing.TB, caller spiffeid.ID) credentials.AuthInfo {
	t.Helper()
	ca := New(t, caller.TrustDomain().String())
	server := ca.SVID(t, "/test/server")
	client := ca.SVID(t, caller.Path())
	sc := grpccredentials.MTLSServerCredentials(server, ca.Bundle(), tlsconfig.AuthorizeID(caller))
	cc := grpccredentials.MTLSClientCredentials(client, ca.Bundle(), tlsconfig.AuthorizeID(server.ID))
	left, right := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	left.SetDeadline(deadline)
	right.SetDeadline(deadline)
	defer left.Close()
	defer right.Close()
	type result struct {
		conn net.Conn
		auth credentials.AuthInfo
		err  error
	}
	done := make(chan result, 1)
	go func() { conn, auth, err := sc.ServerHandshake(left); done <- result{conn, auth, err} }()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	conn, _, err := cc.ClientHandshake(ctx, "localhost", right)
	r := <-done
	left.Close()
	right.Close()
	if conn != nil {
		conn.Close()
	}
	if r.conn != nil {
		r.conn.Close()
	}
	require.NoError(t, err)
	require.NoError(t, r.err)
	return r.auth
}
