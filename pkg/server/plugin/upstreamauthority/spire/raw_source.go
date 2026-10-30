package spireplugin

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// workloadSource fetches the server SVID and X.509 bundles directly from the
// Workload API. It constructs x509svid.SVID values from DER so ML-DSA private
// keys do not pass through the upstream SDK's key validation.
type workloadSource struct {
	conn   *grpc.ClientConn
	client workload.SpiffeWorkloadAPIClient
	cancel context.CancelFunc

	mtx     sync.RWMutex
	svid    *x509svid.SVID
	bundles map[spiffeid.TrustDomain]*x509bundle.Bundle
}

func newWorkloadSource(ctx context.Context, addr net.Addr) (*workloadSource, error) {
	target := addr.String()
	if addr.Network() == "unix" {
		target = "unix://" + target
		if _, err := url.Parse(target); err != nil {
			return nil, fmt.Errorf("workload endpoint socket is not a valid URI: %w", err)
		}
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	source := &workloadSource{
		conn:    conn,
		client:  workload.NewSpiffeWorkloadAPIClient(conn),
		bundles: make(map[spiffeid.TrustDomain]*x509bundle.Bundle),
	}
	refreshCtx, cancel := context.WithCancel(context.Background())
	source.cancel = cancel
	var refreshErr error
	for range 30 {
		if refreshErr = source.refresh(ctx); refreshErr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if refreshErr != nil {
		cancel()
		conn.Close()
		return nil, refreshErr
	}
	go source.refreshLoop(refreshCtx)
	return source, nil
}

func (s *workloadSource) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.refresh(ctx)
		}
	}
}

func (s *workloadSource) refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(withWorkloadHeader(ctx), 10*time.Second)
	defer cancel()

	stream, err := s.client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return err
	}
	resp, err := stream.Recv()
	if err != nil {
		return err
	}
	if len(resp.Svids) == 0 {
		return errors.New("no SVIDs in Workload API response")
	}
	svid := resp.Svids[0]
	certificates, err := x509.ParseCertificates(svid.X509Svid)
	if err != nil {
		return fmt.Errorf("parse SVID certificates: %w", err)
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(svid.X509SvidKey)
	if err != nil {
		return fmt.Errorf("parse SVID private key: %w", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return errors.New("workload private key is not a signer")
	}
	id, err := x509svid.IDFromCert(certificates[0])
	if err != nil {
		return err
	}
	s.setSVID(&x509svid.SVID{ID: id, Certificates: certificates, PrivateKey: signer})
	bundles := make(map[spiffeid.TrustDomain]*x509bundle.Bundle)
	if len(svid.Bundle) > 0 {
		certs, err := x509.ParseCertificates(svid.Bundle)
		if err != nil {
			return fmt.Errorf("parse SVID bundle: %w", err)
		}
		td := parsedSVIDID(certificates).TrustDomain()
		bundles[td] = x509bundle.FromX509Authorities(td, certs)
	}
	for tdID, der := range resp.FederatedBundles {
		td, err := spiffeid.TrustDomainFromString(tdID)
		if err != nil {
			return err
		}
		certs, err := x509.ParseCertificates(der)
		if err != nil {
			return fmt.Errorf("parse federated bundle: %w", err)
		}
		bundles[td] = x509bundle.FromX509Authorities(td, certs)
	}
	s.mtx.Lock()
	s.bundles = bundles
	s.mtx.Unlock()
	return nil
}

func parsedSVIDID(certificates []*x509.Certificate) spiffeid.ID {
	id, err := x509svid.IDFromCert(certificates[0])
	if err != nil {
		return spiffeid.ID{}
	}
	return id
}

func (s *workloadSource) setSVID(svid *x509svid.SVID) {
	s.mtx.Lock()
	s.svid = svid
	s.mtx.Unlock()
}

func (s *workloadSource) GetX509SVID() (*x509svid.SVID, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	if s.svid == nil {
		return nil, errors.New("no SVID available")
	}
	return s.svid, nil
}

func (s *workloadSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	bundle, ok := s.bundles[td]
	if !ok {
		return nil, fmt.Errorf("no X.509 bundle for trust domain %q", td)
	}
	return bundle, nil
}

func (s *workloadSource) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	return s.conn.Close()
}

func withWorkloadHeader(ctx context.Context) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("workload.spiffe.io", "true"))
}
