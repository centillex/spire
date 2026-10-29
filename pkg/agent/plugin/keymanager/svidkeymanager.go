package keymanager

import (
	"context"
)

// SVIDKeyManager is a wrapper around the key manager specifically used for
// managing the agent SVID.
type SVIDKeyManager interface {
	// GenerateKey generates a new key. The current key is passed, if available
	// so the key manager can determine which which "slot" to occupy (i.e.
	// which key ID to use for the new key).
	GenerateKey(ctx context.Context, currentKey Key) (Key, error)

	// GetKeys returns all keys managed by the KeyManager.
	GetKeys(ctx context.Context) ([]Key, error)
}

// Returns an SVIDKeyManager over the given KeyManager. If no key type is
// supplied the historical EC P-256 default is used.
func ForSVID(km KeyManager, keyType ...KeyType) SVIDKeyManager {
	kt := ECP256
	if len(keyType) > 0 && keyType[0] != KeyTypeUnset {
		kt = keyType[0]
	}
	return svidKeyManager{km: km, keyType: kt}
}

type svidKeyManager struct {
	km      KeyManager
	keyType KeyType
}

func (s svidKeyManager) GenerateKey(ctx context.Context, currentKey Key) (Key, error) {
	keyID := "agent-svid-A"
	if currentKey != nil && currentKey.ID() == keyID {
		keyID = "agent-svid-B"
	}
	return s.km.GenerateKey(ctx, keyID, s.keyType)
}

func (s svidKeyManager) GetKeys(ctx context.Context) ([]Key, error) {
	return s.km.GetKeys(ctx)
}
