package pqsql

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

const (
	kekSize    = 32
	sealFormat = 1
)

// loadKEK reads a 32-byte key-encryption key. The file must not be world
// readable; the plugin refuses anything that is not exactly 32 bytes so a
// truncated or text key cannot be used silently.
func loadKEK(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("encryption key %s must not be accessible by group or others", path)
	}
	kek, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(kek) != kekSize {
		return nil, fmt.Errorf("encryption key must be exactly %d bytes, got %d", kekSize, len(kek))
	}
	return kek, nil
}

// sealKey encrypts a PKCS#8 private key with AES-256-GCM. The key ID is used as
// additional authenticated data so ciphertexts cannot be moved between slots.
func sealKey(kek []byte, keyID string, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, []byte(keyID))
	out := make([]byte, 0, 1+len(nonce)+len(sealed))
	out = append(out, sealFormat)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

func openKey(kek []byte, keyID string, sealed []byte) ([]byte, error) {
	if len(sealed) < 1 {
		return nil, errors.New("empty sealed key")
	}
	if sealed[0] != sealFormat {
		return nil, fmt.Errorf("unsupported sealed key format %d", sealed[0])
	}
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(sealed) < 1+nonceSize {
		return nil, errors.New("truncated sealed key")
	}
	nonce := sealed[1 : 1+nonceSize]
	ciphertext := sealed[1+nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, []byte(keyID))
}

func newGCM(kek []byte) (cipher.AEAD, error) {
	if len(kek) != kekSize {
		return nil, fmt.Errorf("key-encryption key must be %d bytes", kekSize)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
