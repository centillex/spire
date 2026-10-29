package bundleutil

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/pqjose"
	"github.com/spiffe/spire/pkg/common/pqjwk"
)

func Decode(trustDomain spiffeid.TrustDomain, r io.Reader) (*spiffebundle.Bundle, error) {
	doc := new(rawBundleDoc)
	if err := json.NewDecoder(r).Decode(doc); err != nil {
		return nil, fmt.Errorf("failed to decode bundle: %w", err)
	}
	return unmarshal(trustDomain, doc)
}

func Unmarshal(trustDomain spiffeid.TrustDomain, data []byte) (*spiffebundle.Bundle, error) {
	doc := new(rawBundleDoc)
	if err := json.Unmarshal(data, doc); err != nil {
		return nil, err
	}
	return unmarshal(trustDomain, doc)
}

func unmarshal(trustDomain spiffeid.TrustDomain, doc *rawBundleDoc) (*spiffebundle.Bundle, error) {
	bundle := spiffebundle.New(trustDomain)
	bundle.SetRefreshHint(time.Second * time.Duration(doc.RefreshHint))
	if doc.Sequence != 0 {
		bundle.SetSequenceNumber(doc.Sequence)
	}

	for i, raw := range doc.Keys {
		use, keyType := rawEntryUse(raw)
		if use == x509SVIDUse && keyType == "AKP" {
			// RFC 9964 AKP authority. The codec validates the ML-DSA-65 key,
			// CA shape, and public key/certificate binding from copied DER.
			cert, err := pqjwk.ParseX509Authority(raw)
			if err != nil {
				return nil, fmt.Errorf("failed to parse x509-svid entry %d: %w", i, err)
			}
			bundle.AddX509Authority(cert)
			continue
		}
		if use == jwtSVIDUse && keyType == "AKP" {
			keyID, publicKey, err := pqjose.ParsePublicJWK(raw)
			if err != nil {
				return nil, fmt.Errorf("failed to parse jwt-svid entry %d: %w", i, err)
			}
			if err := bundle.AddJWTAuthority(keyID, publicKey); err != nil {
				return nil, fmt.Errorf("failed to add jwt-svid entry %d: %w", i, err)
			}
			continue
		}

		key := new(jose.JSONWebKey)
		if err := json.Unmarshal(raw, key); err != nil {
			return nil, fmt.Errorf("failed to decode key entry %d: %w", i, err)
		}

		switch use {
		case x509SVIDUse:
			if len(key.Certificates) != 1 {
				return nil, fmt.Errorf("expected a single certificate in x509-svid entry %d; got %d", i, len(key.Certificates))
			}
			bundle.AddX509Authority(key.Certificates[0])
		case jwtSVIDUse:
			if key.KeyID == "" {
				return nil, fmt.Errorf("missing key ID in jwt-svid entry %d", i)
			}
			if err := bundle.AddJWTAuthority(key.KeyID, key.Key); err != nil {
				return nil, fmt.Errorf("failed to add jwt-svid entry %d: %w", i, err)
			}
		case witSVIDUse:
			if key.KeyID == "" {
				return nil, fmt.Errorf("missing key ID in wit-svid entry %d", i)
			}
			if err := bundle.AddWITAuthority(key.KeyID, key.Key); err != nil {
				return nil, fmt.Errorf("failed to add wit-svid entry %d: %w", i, err)
			}
		case "":
			return nil, fmt.Errorf("missing use for key entry %d", i)
		default:
			return nil, fmt.Errorf("unrecognized use %q for key entry %d", use, i)
		}
	}

	return bundle, nil
}
