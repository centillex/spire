package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	keymanagerbase "github.com/spiffe/spire/pkg/agent/plugin/keymanager/base"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/pqca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestOwnedServerGRPCClient(t *testing.T) {
	ca := pqca.New(t, "example.org")
	server := ca.SVID(t, "/spire/server")
	agent := ca.SVID(t, "/spire/agent/x509pop/test")
	classicKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for _, mutual := range []bool{false, true} {
		for _, scenario := range []string{"valid", "wrong_server_id", "untrusted_server", "classical_server", "classical_kem", "unavailable_agent", "classical_agent", "plugin_agent", "unavailable_plugin_agent"} {
			if !mutual && (scenario == "unavailable_agent" || scenario == "classical_agent" || scenario == "plugin_agent" || scenario == "unavailable_plugin_agent") {
				continue
			}
			prefix := "bootstrap/"
			if mutual {
				prefix = "attested/"
			}
			t.Run(prefix+scenario, func(t *testing.T) {
				serverSVID := server
				if scenario == "wrong_server_id" {
					serverSVID = ca.SVID(t, "/not-the-spire-server")
				}
				if scenario == "untrusted_server" {
					serverSVID = pqca.New(t, "example.org").SVID(t, "/spire/server")
				}
				if scenario == "classical_server" {
					serverSVID = ca.SVID(t, "/spire/server", classicKey)
				}
				var transport credentials.TransportCredentials
				if mutual {
					transport = grpccredentials.MTLSServerCredentials(serverSVID, ca.Bundle(), tlsconfig.AuthorizeID(agent.ID))
				} else {
					transport = grpccredentials.TLSServerCredentials(serverSVID)
				}
				if scenario == "classical_kem" || scenario == "classical_server" {
					// A deliberately non-owned peer, with otherwise valid server trust/ID.
					// The production client must reject it for KEM or key-policy violations.
					base := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{serverSVID.Certificates[0].Raw}, PrivateKey: serverSVID.PrivateKey}}, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
					if scenario == "classical_kem" {
						base.CurvePreferences = []tls.CurveID{tls.X25519}
					}
					if mutual {
						base.ClientAuth = tls.RequireAnyClientCert
					}
					transport = credentials.NewTLS(base)
				}
				var calls atomic.Int32
				rpc := grpc.NewServer(grpc.Creds(transport), grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
					if mutual {
						id, ok := grpccredentials.PeerIDFromContext(ctx)
						if !ok || id != agent.ID {
							return nil, status.Error(codes.Unauthenticated, "unexpected agent")
						}
					}
					calls.Add(1)
					return handler(ctx, req)
				}))
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				healthpb.RegisterHealthServer(rpc, health.NewServer())
				done := make(chan error, 1)
				go func() { done <- rpc.Serve(listener) }()
				t.Cleanup(func() {
					rpc.Stop()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("RPC server did not stop")
					}
				})
				config := ServerClientConfig{Address: listener.Addr().String(), TrustDomain: ca.TrustDomain, GetBundle: func() []*x509.Certificate { return []*x509.Certificate{ca.Root} }}
				if mutual {
					cert := agent
					if scenario == "classical_agent" {
						cert = ca.SVID(t, "/spire/agent/x509pop/test", classicKey)
					}
					if scenario == "plugin_agent" || scenario == "unavailable_plugin_agent" {
						// Use the actual opaque plugin facade, not a native private
						// key fixture. This is the production agent SVID key path.
						base := keymanagerbase.New(keymanagerbase.Config{})
						km := new(keymanager.V1)
						plugintest.Load(t, catalog.MakeBuiltIn("test", keymanagerv1.KeyManagerPluginServer(base)), km)
						key, err := km.GenerateKey(context.Background(), "agent-svid-A", keymanager.MLDSA65)
						require.NoError(t, err)
						cert = ca.SVID(t, "/spire/agent/x509pop/test", key)
						if scenario == "unavailable_plugin_agent" {
							base.SetEntries(nil)
						}
					}
					config.GetAgentCertificate = func() *tls.Certificate {
						if scenario == "unavailable_agent" {
							return nil
						}
						return &tls.Certificate{Certificate: [][]byte{cert.Certificates[0].Raw}, PrivateKey: cert.PrivateKey}
					}
				}
				conn, err := NewServerGRPCClient(config)
				require.NoError(t, err)
				defer conn.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				var remote peer.Peer
				response, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}, grpc.Peer(&remote))
				if scenario != "valid" && scenario != "plugin_agent" {
					require.Error(t, err)
					require.Zero(t, calls.Load())
					return
				}
				require.NoError(t, err)
				require.Equal(t, healthpb.HealthCheckResponse_SERVING, response.Status)
				id, ok := grpccredentials.PeerIDFromPeer(&remote)
				require.True(t, ok)
				require.Equal(t, server.ID, id)
				require.Equal(t, int32(1), calls.Load())
			})
		}
	}
}

func TestAgentSVIDSourceRejectsMissingChain(t *testing.T) {
	for _, cert := range []*tls.Certificate{nil, {}} {
		source := newX509SVIDSource(func() *tls.Certificate { return cert })
		svid, err := source.GetX509SVID()
		require.ErrorContains(t, err, "unavailable")
		require.Nil(t, svid)
	}
}
