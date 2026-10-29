package bundleutil

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/spire/pkg/common/pqjose"
)

type marshalConfig struct {
	refreshHint    time.Duration
	sequenceNumber uint64
	noX509SVIDKeys bool
	noJWTSVIDKeys  bool
	noWITSVIDKeys  bool
	standardJWKS   bool
}

type MarshalOption interface {
	configure(*marshalConfig) error
}

type marshalOption func(c *marshalConfig) error

func (o marshalOption) configure(c *marshalConfig) error {
	return o(c)
}

// OverrideRefreshHint overrides the refresh hint in the bundle
func OverrideRefreshHint(value time.Duration) MarshalOption {
	return marshalOption(func(c *marshalConfig) error {
		c.refreshHint = value
		return nil
	})
}

// OverrideSequenceNumber overrides the sequence number in the bundle
func OverrideSequenceNumber(value uint64) MarshalOption {
	return marshalOption(func(c *marshalConfig) error {
		c.sequenceNumber = value
		return nil
	})
}

// NoX509SVIDKeys skips marshalling X509 SVID keys
func NoX509SVIDKeys() MarshalOption {
	return marshalOption(func(c *marshalConfig) error {
		c.noX509SVIDKeys = true
		return nil
	})
}

// NoJWTSVIDKeys skips marshalling JWT SVID keys
func NoJWTSVIDKeys() MarshalOption {
	return marshalOption(func(c *marshalConfig) error {
		c.noJWTSVIDKeys = true
		return nil
	})
}

// NoWITSVIDKeys skips marshalling WIT SVID keys
func NoWITSVIDKeys() MarshalOption {
	return marshalOption(func(c *marshalConfig) error {
		c.noWITSVIDKeys = true
		return nil
	})
}

// StandardJWKS omits SPIFFE-specific parameters from the marshaled bundle
func StandardJWKS() MarshalOption {
	return marshalOption(func(c *marshalConfig) error {
		c.standardJWKS = true
		return nil
	})
}

func MarshalX509SVIDBundle(bundle *spiffebundle.Bundle, opts ...MarshalOption) ([]byte, error) {
	allOpts := append([]MarshalOption{NoJWTSVIDKeys(), NoWITSVIDKeys()}, opts...)
	return Marshal(bundle, allOpts...)
}

func MarshalJWTSVIDBundle(bundle *spiffebundle.Bundle, opts ...MarshalOption) ([]byte, error) {
	allOpts := append([]MarshalOption{NoX509SVIDKeys(), NoWITSVIDKeys()}, opts...)
	return Marshal(bundle, allOpts...)
}

func MarshalWITSVIDBundle(bundle *spiffebundle.Bundle, opts ...MarshalOption) (string, error) {
	allOpts := append([]MarshalOption{NoX509SVIDKeys(), NoJWTSVIDKeys()}, opts...)
	marshaledBundle, err := Marshal(bundle, allOpts...)
	if err != nil {
		return "", err
	}
	return string(marshaledBundle), nil
}

func Marshal(bundle *spiffebundle.Bundle, opts ...MarshalOption) ([]byte, error) {
	refreshHint, ok := bundle.RefreshHint()
	if !ok {
		refreshHint = 0
	}

	sequenceNumber, ok := bundle.SequenceNumber()
	if !ok {
		sequenceNumber = 0
	}

	c := &marshalConfig{
		refreshHint:    refreshHint,
		sequenceNumber: sequenceNumber,
	}
	for _, opt := range opts {
		if err := opt.configure(c); err != nil {
			return nil, err
		}
	}

	// Entries are heterogeneous: classical keys serialize through go-jose, while
	// recognized ML-DSA X509-SVID authorities use the RFC 9964 AKP codec because
	// go-jose cannot marshal *mldsa.PublicKey.
	keys := make([]any, 0)

	maybeUse := func(use string) string {
		if !c.standardJWKS {
			return use
		}
		return ""
	}

	if !c.noX509SVIDKeys {
		for _, rootCA := range bundle.X509Authorities() {
			if isMLDSA(rootCA) {
				if c.standardJWKS {
					return nil, errors.New("standard JWKS output cannot represent an ML-DSA AKP x509-svid entry")
				}
				keys = append(keys, pqX509Entry{cert: rootCA})
				continue
			}
			keys = append(keys, jose.JSONWebKey{
				Key:          rootCA.PublicKey,
				Certificates: []*x509.Certificate{rootCA},
				Use:          maybeUse(x509SVIDUse),
			})
		}
	}

	if !c.noJWTSVIDKeys {
		for keyID, jwtSigningKey := range bundle.JWTAuthorities() {
			if publicKey, ok := jwtSigningKey.(*mldsa.PublicKey); ok {
				encoded, err := pqjose.MarshalPublicJWKWithUse(keyID, maybeUse(jwtSVIDUse), publicKey)
				if err != nil {
					return nil, err
				}
				keys = append(keys, json.RawMessage(encoded))
				continue
			}
			keys = append(keys, jose.JSONWebKey{
				Key:   jwtSigningKey,
				KeyID: keyID,
				Use:   maybeUse(jwtSVIDUse),
			})
		}
	}

	if !c.noWITSVIDKeys {
		for keyID, witSigningKey := range bundle.WITAuthorities() {
			keys = append(keys, jose.JSONWebKey{
				Key:   witSigningKey,
				KeyID: keyID,
				Use:   maybeUse(witSVIDUse),
			})
		}
	}

	type document struct {
		Keys        []any  `json:"keys"`
		Sequence    uint64 `json:"spiffe_sequence,omitempty"`
		RefreshHint int    `json:"spiffe_refresh_hint,omitempty"`
	}
	out := document{Keys: keys}
	if !c.standardJWKS {
		out.Sequence = c.sequenceNumber
		out.RefreshHint = int(c.refreshHint / time.Second)
	}

	return json.MarshalIndent(out, "", "    ")
}
