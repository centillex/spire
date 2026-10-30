// pq-sds-probe fetches the default X509-SVID and ROOTCA validation context
// from the agent's Envoy SDS API and reports whether the delivered material is
// native ML-DSA-65.
package main

import (
	"context"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type report struct {
	TLSCertificate    bool     `json:"tls_certificate"`
	ValidationContext bool     `json:"validation_context"`
	MLDSA             bool     `json:"ml_dsa"`
	Identities        []string `json:"identities,omitempty"`
	AuthorityCount    int      `json:"authority_count"`
}

func run() error {
	socket := flag.String("socket", "", "agent SDS/workload API unix socket")
	timeout := flag.Duration("timeout", 10*time.Second, "request timeout")
	flag.Parse()
	if *socket == "" {
		return errors.New("-socket is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := grpc.NewClient("unix://"+*socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := secret_v3.NewSecretDiscoveryServiceClient(conn)
	resp, err := client.FetchSecrets(ctx, &discovery_v3.DiscoveryRequest{
		Node:          &core_v3.Node{Id: "pq-sds-probe", Cluster: "pq-sds-probe"},
		ResourceNames: nil,
	})
	if err != nil {
		return fmt.Errorf("FetchSecrets: %w", err)
	}

	result := report{}
	for _, resource := range resp.Resources {
		secret := new(tls_v3.Secret)
		if err := resource.UnmarshalTo(secret); err != nil {
			return fmt.Errorf("unmarshal secret: %w", err)
		}
		switch typed := secret.Type.(type) {
		case *tls_v3.Secret_TlsCertificate:
			result.TLSCertificate = true
			certs, err := parsePEM(typed.TlsCertificate.GetCertificateChain().GetInlineBytes())
			if err != nil {
				return err
			}
			for _, cert := range certs {
				if _, ok := cert.PublicKey.(*mldsa.PublicKey); ok {
					result.MLDSA = true
				}
				if id, err := spiffeIDFromCert(cert); err == nil {
					result.Identities = append(result.Identities, id)
				}
			}
		case *tls_v3.Secret_ValidationContext:
			result.ValidationContext = true
			certs, err := parsePEM(typed.ValidationContext.GetTrustedCa().GetInlineBytes())
			if err != nil {
				return err
			}
			result.AuthorityCount = len(certs)
			for _, cert := range certs {
				if _, ok := cert.PublicKey.(*mldsa.PublicKey); ok {
					result.MLDSA = true
				}
			}
		}
	}
	if !result.TLSCertificate || !result.ValidationContext || !result.MLDSA {
		return errors.New("SDS did not deliver ML-DSA certificate and validation context")
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func parsePEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	block, rest := pem.Decode(data)
	for block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		block, rest = pem.Decode(rest)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates")
	}
	return certs, nil
}

func spiffeIDFromCert(cert *x509.Certificate) (string, error) {
	if len(cert.URIs) != 1 {
		return "", errors.New("no SPIFFE URI")
	}
	return cert.URIs[0].String(), nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
