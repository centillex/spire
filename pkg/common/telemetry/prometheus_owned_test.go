package telemetry

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/test/pqca"
	"github.com/stretchr/testify/require"
)

type prometheusPQCA struct {
	ca   *pqca.CA
	cert *x509.Certificate
	td   spiffeid.TrustDomain
}

func newPrometheusPQCA(t *testing.T, domain string) *prometheusPQCA {
	t.Helper()
	ca := pqca.New(t, domain)
	return &prometheusPQCA{ca, ca.Root, ca.TrustDomain}
}
func (ca *prometheusPQCA) svid(t *testing.T, path string, keys ...crypto.Signer) *x509svid.SVID {
	t.Helper()
	if path == "/web" {
		return ca.ca.Web(t, keys...)
	}
	return ca.ca.SVID(t, path, keys...)
}
func (ca *prometheusPQCA) bundle() *x509bundle.Bundle { return ca.ca.Bundle() }
func writePrometheusPQWeb(t *testing.T, svid *x509svid.SVID) (string, string) {
	t.Helper()
	key, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
	require.NoError(t, err)
	return createTempFile(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: svid.Certificates[0].Raw})), createTempFile(t, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}
func servePrometheusTest(t *testing.T, p *prometheusRunner) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p.server.ErrorLog = log.New(io.Discard, "", 0)
	done := make(chan error, 1)
	go func() { done <- p.serve(listener) }()
	t.Cleanup(func() {
		require.NoError(t, p.server.Close())
		select {
		case err := <-done:
			require.ErrorIs(t, err, http.ErrServerClosed)
		case <-time.After(5 * time.Second):
			t.Error("Prometheus listener did not stop")
		}
	})
	return listener.Addr().String()
}
func prometheusOwnedRequest(cfg *tlsconfig.Config, addr string) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := cfg.DialContext(ctx, "tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	state := conn.(*tlsconfig.Conn).ConnectionState()
	req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/metrics", nil)
	req.Close = true
	if err = req.Write(conn); err != nil {
		return state, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return state, err
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, response.Body)
	if response.StatusCode != 200 {
		return state, errors.New("metrics response was not successful")
	}
	return state, err
}

// These exercise the actual serving path, not legacy certificate callbacks.
func TestPrometheusSPIFFETLSConfig(t *testing.T) {
	serverCA := newPrometheusPQCA(t, "example.org")
	clientCA := newPrometheusPQCA(t, "foreign.example.org")
	server := serverCA.svid(t, "/spire/server")
	web := serverCA.svid(t, "/web")
	allowed := clientCA.svid(t, "/prometheus")
	denied := clientCA.svid(t, "/other")
	untrusted := newPrometheusPQCA(t, "foreign.example.org").svid(t, "/prometheus")
	for _, mode := range []string{"svid", "svid_mtls", "web_mtls"} {
		t.Run(mode, func(t *testing.T) {
			config := testPrometheusConfig()
			config.FileConfig.Prometheus.TLS = &TLSConfig{UseSPIRESVID: mode != "web_mtls"}
			config.GetX509SVID = func() (*x509svid.SVID, error) { return server, nil }
			config.GetX509BundleAuthorities = func(td spiffeid.TrustDomain) ([]*x509.Certificate, error) {
				if td == clientCA.td {
					return []*x509.Certificate{clientCA.cert}, nil
				}
				return nil, errors.New("unknown domain")
			}
			if mode != "svid" {
				config.FileConfig.Prometheus.TLS.AuthorizedSPIFFEIDs = []string{allowed.ID.String()}
			}
			if mode == "web_mtls" {
				config.FileConfig.Prometheus.TLS.CertFile, config.FileConfig.Prometheus.TLS.KeyFile = writePrometheusPQWeb(t, web)
			}
			// Even explicitly weak preferences cannot override the SDK profile.
			var err error
			config.TLSPolicy, err = tlspolicy.NewPolicy(false, &tlspolicy.TLSConfig{MinTLSVersion: "VersionTLS12", CurvePreferences: []string{"X25519"}}, nil)
			require.NoError(t, err)
			runner, err := newTestPrometheusRunner(config)
			require.NoError(t, err)
			p := runner.(*prometheusRunner)
			require.NotNil(t, p.ownedTLS)
			require.Nil(t, p.server.TLSConfig)
			var requests atomic.Int32
			original := p.server.Handler
			p.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); original.ServeHTTP(w, r) })
			addr := servePrometheusTest(t, p)
			client := func(svid *x509svid.SVID) *tlsconfig.Config {
				opts := []tlsconfig.Option{tlsconfig.WithBaseTLSConfig(&tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(1)})}
				if mode == "web_mtls" {
					roots := x509.NewCertPool()
					roots.AddCert(serverCA.cert)
					return tlsconfig.MTLSWebClientConfig(svid, roots, opts...)
				}
				if mode == "svid" || svid == nil {
					return tlsconfig.TLSClientConfig(serverCA.bundle(), tlsconfig.AuthorizeID(server.ID), opts...)
				}
				return tlsconfig.MTLSClientConfig(svid, serverCA.bundle(), tlsconfig.AuthorizeID(server.ID), opts...)
			}
			good := client(allowed)
			for n := 0; n < 2; n++ {
				state, err := prometheusOwnedRequest(good, addr)
				require.NoError(t, err)
				require.Equal(t, uint16(tls.VersionTLS13), state.Version)
				require.Contains(t, []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}, state.CurveID)
				require.False(t, state.DidResume)
				require.Equal(t, x509.MLDSA65, state.PeerCertificates[0].SignatureAlgorithm)
			}
			if mode != "svid" {
				for _, svid := range []*x509svid.SVID{denied, untrusted} {
					_, err := prometheusOwnedRequest(client(svid), addr)
					require.Error(t, err)
				}
				noCert := tlsconfig.TLSClientConfig(serverCA.bundle(), tlsconfig.AuthorizeID(server.ID))
				if mode == "web_mtls" {
					roots := x509.NewCertPool()
					roots.AddCert(serverCA.cert)
					noCert = tlsconfig.WebClientConfig(roots)
				}
				_, err = prometheusOwnedRequest(noCert, addr)
				require.Error(t, err)
			} else {
				_, err = prometheusOwnedRequest(client(nil), addr)
				require.NoError(t, err)
			}
			before := requests.Load()
			roots := x509.NewCertPool()
			roots.AddCert(serverCA.cert)
			// Valid server trust, but only a classical key exchange: no HTTP access.
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, Certificates: []tls.Certificate{{Certificate: [][]byte{allowed.Certificates[0].Raw}, PrivateKey: allowed.PrivateKey}}}}
			ordinary := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			response, err := ordinary.Get("https://" + addr + "/metrics")
			if response != nil {
				response.Body.Close()
			}
			require.Error(t, err)
			transport.CloseIdleConnections()
			if mode != "svid" {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				classic := clientCA.svid(t, "/prometheus", key)
				legacy := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, Certificates: []tls.Certificate{{Certificate: [][]byte{classic.Certificates[0].Raw}, PrivateKey: classic.PrivateKey}}}}
				response, err := (&http.Client{Transport: legacy, Timeout: 3 * time.Second}).Get("https://" + addr + "/metrics")
				if response != nil {
					response.Body.Close()
				}
				legacy.CloseIdleConnections()
				require.Error(t, err)
			}
			plain := &http.Client{Timeout: 3 * time.Second}
			response, err = plain.Get("http://" + addr + "/metrics")
			if response != nil {
				response.Body.Close()
			}
			require.Error(t, err)
			require.Equal(t, before, requests.Load(), "a rejected handshake reached the metrics handler")
		})
	}
}

func TestPrometheusOwnedFailuresNeverFallback(t *testing.T) {
	ca := newPrometheusPQCA(t, "example.org")
	svid := ca.svid(t, "/spire/server")
	classicKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for _, failure := range []string{"svid_source", "nil_svid", "bundle_source", "classical_server", "classical_web_server"} {
		t.Run(failure, func(t *testing.T) {
			config := testPrometheusConfig()
			config.FileConfig.Prometheus.TLS = &TLSConfig{UseSPIRESVID: true}
			config.GetX509SVID = func() (*x509svid.SVID, error) { return svid, nil }
			client := tlsconfig.TLSClientConfig(ca.bundle(), tlsconfig.AuthorizeID(svid.ID))
			switch failure {
			case "svid_source":
				config.GetX509SVID = func() (*x509svid.SVID, error) { return nil, errors.New("source unavailable") }
			case "nil_svid":
				config.GetX509SVID = func() (*x509svid.SVID, error) { return nil, nil }
			case "classical_server":
				classic := ca.svid(t, "/spire/server", classicKey)
				config.GetX509SVID = func() (*x509svid.SVID, error) { return classic, nil }
			case "bundle_source":
				config.FileConfig.Prometheus.TLS.AuthorizedSPIFFEIDs = []string{svid.ID.String()}
				config.GetX509BundleAuthorities = func(spiffeid.TrustDomain) ([]*x509.Certificate, error) { return nil, errors.New("source unavailable") }
				client = tlsconfig.MTLSClientConfig(svid, ca.bundle(), tlsconfig.AuthorizeID(svid.ID))
			case "classical_web_server":
				config.FileConfig.Prometheus.TLS = &TLSConfig{AuthorizedSPIFFEIDs: []string{svid.ID.String()}}
				config.FileConfig.Prometheus.TLS.CertFile, config.FileConfig.Prometheus.TLS.KeyFile = writePrometheusPQWeb(t, ca.svid(t, "/web", classicKey))
				config.GetX509BundleAuthorities = func(spiffeid.TrustDomain) ([]*x509.Certificate, error) { return []*x509.Certificate{ca.cert}, nil }
			}
			runner, err := newTestPrometheusRunner(config)
			require.NoError(t, err)
			p := runner.(*prometheusRunner)
			require.Nil(t, p.server.TLSConfig)
			require.NotNil(t, p.ownedTLS)
			var calls atomic.Int32
			p.server.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) })
			addr := servePrometheusTest(t, p)
			_, err = prometheusOwnedRequest(client, addr)
			require.Error(t, err)
			// A conventional client trusts this CA, accepts ECDSA certificates and uses
			// an allowed hybrid KEM. The server must still reject its own classic key.
			roots := x509.NewCertPool()
			roots.AddCert(ca.cert)
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, Certificates: []tls.Certificate{{Certificate: [][]byte{svid.Certificates[0].Raw}, PrivateKey: svid.PrivateKey}}}}
			response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get("https://" + addr + "/metrics")
			if response != nil {
				response.Body.Close()
			}
			transport.CloseIdleConnections()
			require.Error(t, err)
			require.Zero(t, calls.Load())
		})
	}
}

func TestPrometheusOwnedSVIDRotationAndRecovery(t *testing.T) {
	ca := newPrometheusPQCA(t, "example.org")
	first := ca.svid(t, "/spire/server")
	second := ca.svid(t, "/spire/server")
	var current atomic.Pointer[x509svid.SVID]
	current.Store(first)
	config := testPrometheusConfig()
	config.FileConfig.Prometheus.TLS = &TLSConfig{UseSPIRESVID: true}
	config.GetX509SVID = func() (*x509svid.SVID, error) {
		s := current.Load()
		if s == nil {
			return nil, errors.New("temporarily unavailable")
		}
		return s, nil
	}
	runner, err := newTestPrometheusRunner(config)
	require.NoError(t, err)
	addr := servePrometheusTest(t, runner.(*prometheusRunner))
	client := tlsconfig.TLSClientConfig(ca.bundle(), tlsconfig.AuthorizeID(first.ID))
	state, err := prometheusOwnedRequest(client, addr)
	require.NoError(t, err)
	require.Equal(t, first.Certificates[0].Raw, state.PeerCertificates[0].Raw)
	current.Store(second)
	state, err = prometheusOwnedRequest(client, addr)
	require.NoError(t, err)
	require.Equal(t, second.Certificates[0].Raw, state.PeerCertificates[0].Raw)
	current.Store(nil)
	_, err = prometheusOwnedRequest(client, addr)
	require.Error(t, err)
	current.Store(second)
	_, err = prometheusOwnedRequest(client, addr)
	require.NoError(t, err)
}

func TestPrometheusInvalidOwnedConfigClosesListener(t *testing.T) {
	for _, mutable := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid_owned", true: "mutable_config_conflict"}[mutable], func(t *testing.T) {
			runner, err := newTestPrometheusRunner(testPrometheusConfig())
			require.NoError(t, err)
			p := runner.(*prometheusRunner)
			p.ownedTLS = &tlsconfig.Config{}
			if mutable {
				p.server.TLSConfig = &tls.Config{}
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			require.Error(t, p.serve(listener))
			conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if conn != nil {
				conn.Close()
			}
			require.Error(t, err)
		})
	}
}
