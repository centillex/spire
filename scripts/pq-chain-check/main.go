// pq-chain-check verifies an ML-DSA certificate chain against a root bundle.
package main

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
)

type report struct {
	ChainLength int    `json:"chain_length"`
	MLDSA       bool   `json:"ml_dsa"`
	RootSubject string `json:"root_subject"`
	LeafSubject string `json:"leaf_subject"`
}

func run() error {
	chainPath := flag.String("chain", "", "PEM certificate chain")
	rootPath := flag.String("root", "", "PEM root bundle")
	flag.Parse()
	if *chainPath == "" || *rootPath == "" {
		return errors.New("-chain and -root are required")
	}
	chain, err := parse(*chainPath)
	if err != nil {
		return err
	}
	roots, err := parse(*rootPath)
	if err != nil {
		return err
	}
	if len(chain) < 2 || len(roots) == 0 {
		return errors.New("chain must contain a leaf and intermediate")
	}
	for i := range len(chain) - 1 {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return fmt.Errorf("chain link %d: %w", i, err)
		}
	}
	rootSig := false
	for _, root := range roots {
		if err := chain[len(chain)-1].CheckSignatureFrom(root); err == nil {
			rootSig = true
		}
	}
	if !rootSig {
		return errors.New("chain does not terminate at the supplied root")
	}
	result := report{ChainLength: len(chain), LeafSubject: chain[0].Subject.String(), RootSubject: chain[len(chain)-1].Subject.String()}
	for _, cert := range append(chain, roots...) {
		if _, ok := cert.PublicKey.(*mldsa.PublicKey); ok {
			result.MLDSA = true
		}
	}
	if !result.MLDSA {
		return errors.New("chain does not contain ML-DSA keys")
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func parse(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
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

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
