package client

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

var (
	trustDomain = spiffeid.RequireTrustDomainFromString("domain.test")
	serverID    = spiffeid.RequireFromString("spiffe://domain.test/spiffe-bundle-endpoint-server")
)

// TestClientRejectsRedirect ensures a federation fetch cannot be bounced to a
// different (possibly weaker or unrelated) endpoint.
func TestClientRejectsRedirect(t *testing.T) {
	fetched := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		fetched = true
	}))
	defer target.Close()

	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	transport := source.Client().Transport.(*http.Transport)
	client, err := NewClient(ClientConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("domain.test"),
		EndpointURL: source.URL,
		mutateTransportHook: func(t *http.Transport) {
			t.TLSClientConfig = transport.TLSClientConfig
		},
	})
	require.NoError(t, err)
	_, err = client.FetchBundle(context.Background())
	require.ErrorContains(t, err, "redirect")
	require.False(t, fetched, "redirect target must not be contacted")
}

func TestClient(t *testing.T) {
	testCases := []struct {
		name           string
		expectedID     spiffeid.ID
		serverID       spiffeid.ID
		status         int
		body           string
		newClientErr   string
		fetchBundleErr string
		useWebAuth     bool
		mutateConfig   func(*ClientConfig)
	}{
		{
			name:   "success",
			status: http.StatusOK,
			// We don't need a really elaborate body here. this test just
			// makes sure we unmarshal the body. The unmarshal tests will
			// provide the coverage for unmarshalling code.
			body:       `{"spiffe_refresh_hint": 10}`,
			serverID:   serverID,
			expectedID: serverID,
		},
		{
			name:         "no SPIFFE ID",
			status:       http.StatusOK,
			body:         `{"spiffe_refresh_hint": 10}`,
			serverID:     serverID,
			newClientErr: `no SPIFFE ID specified for federation with "domain.test"`,
		},
		{
			name:           "SPIFFE ID override",
			serverID:       spiffeid.RequireFromString("spiffe://domain.test/my-spiffe-bundle-endpoint-server"),
			expectedID:     spiffeid.RequireFromString("spiffe://domain.test/authorized"),
			fetchBundleErr: fmt.Sprintf(`unexpected ID %q`, spiffeid.RequireFromString("spiffe://domain.test/my-spiffe-bundle-endpoint-server")),
		},
		{
			name:           "redirect rejected",
			status:         http.StatusTemporaryRedirect,
			body:           "",
			serverID:       serverID,
			expectedID:     serverID,
			fetchBundleErr: "bundle endpoint redirect (status 307)",
		},
		{
			name:           "non-200 status",
			status:         http.StatusServiceUnavailable,
			body:           "tHe SYsTEm iS DowN",
			serverID:       serverID,
			expectedID:     serverID,
			fetchBundleErr: "unexpected status 503 fetching bundle: tHe SYsTEm iS DowN",
		},
		{
			name:           "invalid bundle content",
			status:         http.StatusOK,
			body:           "NOT JSON",
			serverID:       serverID,
			expectedID:     serverID,
			fetchBundleErr: "failed to decode bundle",
		},
		{
			name:           "hostname validation fails",
			status:         http.StatusOK,
			body:           "NOT JSON",
			serverID:       serverID,
			expectedID:     serverID,
			fetchBundleErr: "failed to authenticate bundle endpoint using web authentication but the server certificate contains SPIFFE ID \"spiffe://domain.test/spiffe-bundle-endpoint-server\": maybe use https_spiffe instead of https_web:",
			useWebAuth:     true,
			mutateConfig: func(c *ClientConfig) {
				c.SPIFFEAuth = nil
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			serverCert, serverKey := createServerCertificate(t, testCase.serverID)

			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(testCase.status)
				_, _ = w.Write([]byte(testCase.body))
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{
				Certificates: []tls.Certificate{
					{
						Certificate: [][]byte{serverCert.Raw},
						PrivateKey:  serverKey,
					},
				},
				MinVersion: tls.VersionTLS12,
			}
			server.StartTLS()
			defer server.Close()

			var mutateTransportHook func(*http.Transport)
			if testCase.useWebAuth {
				mutateTransportHook = func(transport *http.Transport) {
					rootCAs := x509.NewCertPool()
					rootCAs.AddCert(serverCert)
					transport.TLSClientConfig = &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}
				}
			}

			config := ClientConfig{
				TrustDomain: trustDomain,
				EndpointURL: server.URL,
				SPIFFEAuth: &SPIFFEAuthConfig{
					EndpointSpiffeID: testCase.expectedID,
					RootCAs:          []*x509.Certificate{serverCert},
				},
				mutateTransportHook: mutateTransportHook,
			}

			if testCase.mutateConfig != nil {
				testCase.mutateConfig(&config)
			}

			client, err := NewClient(config)
			if testCase.newClientErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.newClientErr)
				return
			}
			require.NoError(t, err)

			bundle, err := client.FetchBundle(context.Background())
			if testCase.fetchBundleErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.fetchBundleErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, bundle)
			require.Equal(t, trustDomain.IDString(), bundle.TrustDomain().IDString())
			refreshHint, ok := bundle.RefreshHint()
			require.True(t, ok)
			require.Equal(t, 10*time.Second, refreshHint)
		})
	}
}

func createServerCertificate(t *testing.T, serverID spiffeid.ID) (*x509.Certificate, crypto.Signer) {
	return spiretest.SelfSignCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{serverID.URL()},
	})
}
