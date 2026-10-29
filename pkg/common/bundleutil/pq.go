package bundleutil

import (
	"bytes"
	"crypto/x509"
	"encoding/json"

	"github.com/spiffe/spire/pkg/common/pqjwk"
)

// pqX509Entry emits an RFC 9964 AKP X509-SVID entry for ML-DSA authorities.
// go-jose cannot serialize *mldsa.PublicKey, so recognized ML-DSA entries are
// written by the qspiffe codec instead. Classical entries keep using go-jose.
type pqX509Entry struct {
	cert *x509.Certificate
}

func (e pqX509Entry) MarshalJSON() ([]byte, error) {
	return pqjwk.MarshalX509Authority(e.cert)
}

// isMLDSA reports whether the authority key requires AKP serialization. Mutable
// parsed fields are not trusted: the key is re-derived from signed DER.
func isMLDSA(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	reparsed, err := x509.ParseCertificate(bytes.Clone(cert.Raw))
	if err != nil {
		return false
	}
	return reparsed.SignatureAlgorithm == x509.MLDSA65
}

// rawEntryUse inspects just enough of an entry to route decoding.
func rawEntryUse(raw json.RawMessage) (use, keyType string) {
	var probe struct {
		Use string `json:"use"`
		Kty string `json:"kty"`
	}
	_ = json.Unmarshal(raw, &probe)
	return probe.Use, probe.Kty
}

type rawBundleDoc struct {
	Keys        []json.RawMessage `json:"keys"`
	Sequence    uint64            `json:"spiffe_sequence,omitempty"`
	RefreshHint int               `json:"spiffe_refresh_hint,omitempty"`
}
