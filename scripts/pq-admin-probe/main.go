// pq-admin-probe calls the SPIRE Server API with a caller SVID and reports
// whether the server authorized the request. It is used to test admin_ids and
// audit logging under strict PQ.
package main

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type report struct {
	Allowed bool   `json:"allowed"`
	Caller  string `json:"caller"`
	Error   string `json:"error,omitempty"`
}

func run() error {
	addr := flag.String("addr", "", "server address")
	bundlePath := flag.String("bundle", "", "server trust bundle PEM")
	certPath := flag.String("cert", "", "caller certificate chain PEM")
	keyPath := flag.String("key", "", "caller private key PEM")
	serverID := flag.String("server-id", "", "server SPIFFE ID")
	timeout := flag.Duration("timeout", 10*time.Second, "call timeout")
	flag.Parse()
	if *addr == "" || *bundlePath == "" || *certPath == "" || *keyPath == "" || *serverID == "" {
		return errors.New("-addr, -bundle, -cert, -key and -server-id are required")
	}

	certs, err := pemutil.ParseCertificates(readFile(*certPath))
	if err != nil {
		return fmt.Errorf("parse caller certificate: %w", err)
	}
	key, err := pemutil.ParsePrivateKey(readFile(*keyPath))
	if err != nil {
		return fmt.Errorf("parse caller key: %w", err)
	}
	roots, err := pemutil.ParseCertificates(readFile(*bundlePath))
	if err != nil {
		return fmt.Errorf("parse server bundle: %w", err)
	}
	callerID, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		return err
	}
	td := callerID.TrustDomain()
	bundle := x509bundle.FromX509Authorities(td, roots)
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("caller key is not a signer")
	}
	svid := &x509svid.SVID{ID: callerID, Certificates: certs, PrivateKey: signer}
	server, err := spiffeid.FromString(*serverID)
	if err != nil {
		return err
	}
	tlsConfig := tlsconfig.MTLSClientConfig(svid, bundle, tlsconfig.AuthorizeID(server))

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = bundlev1.NewBundleClient(conn).GetBundle(ctx, &bundlev1.GetBundleRequest{})
	result := report{Allowed: err == nil, Caller: callerID.String()}
	if err != nil {
		result.Error = err.Error()
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func readFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return data
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
