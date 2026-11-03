package broker

import (
	"context"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/test/pqca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrokerOwnedListenerPolicies(t *testing.T) {
	ca := pqca.New(t, "example.org")
	foreign := pqca.New(t, "foreign.example.org")
	server := ca.SVID(t, "/agent")
	allowed := foreign.SVID(t, "/broker")
	denied := foreign.SVID(t, "/other")
	for _, weak := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "weak_preferences"}[weak], func(t *testing.T) {
			var policy tlspolicy.Policy
			if weak {
				var err error
				policy, err = tlspolicy.NewPolicy(false, &tlspolicy.TLSConfig{MinTLSVersion: "VersionTLS12", CurvePreferences: []string{"X25519"}}, nil)
				require.NoError(t, err)
			}
			transport, err := buildListenerCredentials(&Config{SVIDSource: server, BundleSource: x509bundle.NewSet(ca.Bundle(), foreign.Bundle()), Brokers: []Broker{{ID: allowed.ID.String()}}, TLSPolicy: policy})
			require.NoError(t, err)
			require.Equal(t, "1.3", transport.Info().SecurityVersion)
			var calls atomic.Int32
			rpc := grpc.NewServer(grpc.Creds(transport), grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				id, ok := grpccredentials.PeerIDFromContext(ctx)
				if !ok || id != allowed.ID {
					return nil, status.Error(codes.Unauthenticated, "missing owned peer identity")
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
					t.Error("broker did not stop")
				}
			})
			check := func(cred credentials.TransportCredentials) error {
				conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(cred))
				if err != nil {
					return err
				}
				defer conn.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				ctx = metadata.AppendToOutgoingContext(ctx, "x-spiffe-id", "spiffe://forged.example/identity")
				_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
				return err
			}
			require.NoError(t, check(grpccredentials.MTLSClientCredentials(allowed, ca.Bundle(), tlsconfig.AuthorizeID(server.ID))))
			require.Equal(t, int32(1), calls.Load())
			require.Error(t, check(grpccredentials.MTLSClientCredentials(denied, ca.Bundle(), tlsconfig.AuthorizeID(server.ID))))
			require.Error(t, check(grpccredentials.TLSClientCredentials(ca.Bundle(), tlsconfig.AuthorizeID(server.ID))))
			require.Equal(t, int32(1), calls.Load(), "unauthorized peer reached RPC handler")
			// A malformed allowlist remains a construction failure, not authorize-any.
			_, err = buildListenerCredentials(&Config{Brokers: []Broker{{ID: "not-spiffe"}}})
			require.Error(t, err)
			// Confirm SDK auth info cannot be fabricated from an arbitrary SPIFFE URL.
			_, ok := grpccredentials.PeerIDFromContext(context.Background())
			require.False(t, ok)
		})
	}
}
