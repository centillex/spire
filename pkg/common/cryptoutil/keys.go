package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rsa"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

func PublicKeyEqual(a, b crypto.PublicKey) (bool, error) {
	switch a := a.(type) {
	case *mldsa.PublicKey:
		b, ok := b.(*mldsa.PublicKey)
		return ok && validMLDSA65(a) && validMLDSA65(b) && a.Equal(b), nil
	case *rsa.PublicKey:
		return a.Equal(b), nil
	case *ecdsa.PublicKey:
		return a.Equal(b), nil
	default:
		return false, fmt.Errorf("unsupported public key type %T", a)
	}
}

func KeyMatches(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) (bool, error) {
	switch privateKey := privateKey.(type) {
	case *mldsa.PrivateKey:
		if privateKey == nil {
			return false, fmt.Errorf("nil ML-DSA key")
		}
		return PublicKeyEqual(privateKey.PublicKey(), publicKey)
	case *rsa.PrivateKey:
		return privateKey.PublicKey.Equal(publicKey), nil
	case *ecdsa.PrivateKey:
		return privateKey.PublicKey.Equal(publicKey), nil
	default:
		return false, fmt.Errorf("unsupported private key type %T", privateKey)
	}
}

func validMLDSA65(key *mldsa.PublicKey) bool {
	return key != nil && len(key.Bytes()) == mldsa.MLDSA65().PublicKeySize() && key.Parameters() == mldsa.MLDSA65()
}

func JoseAlgFromPublicKey(publicKey any) (jose.SignatureAlgorithm, error) {
	var alg jose.SignatureAlgorithm
	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		// Prevent the use of keys smaller than 2048 bits
		if publicKey.Size() < 256 {
			return "", fmt.Errorf("unsupported RSA key size: %d", publicKey.Size())
		}
		alg = jose.RS256
	case *ecdsa.PublicKey:
		params := publicKey.Params()
		switch params.BitSize {
		case 256:
			alg = jose.ES256
		case 384:
			alg = jose.ES384
		default:
			return "", fmt.Errorf("unable to determine signature algorithm for EC public key size %d", params.BitSize)
		}
	default:
		return "", fmt.Errorf("unable to determine signature algorithm for public key type %T", publicKey)
	}
	return alg, nil
}
