package store

import (
	"context"
	"keysafe/internal/crypto"
	"sync"

	"github.com/palantir/stacktrace"
)

type InMemoryKeyStore struct {
	masterKey crypto.Key

	// We are storing all keys and protecting with a single mutex.
	// A possible improvement would be to have a KeyEntry where each key has a mutex
	keyStore map[string]crypto.Key

	mutex sync.RWMutex

	maxNumberKeys int
}

func NewInMemoryKeyStore(ctx context.Context, masterKey crypto.Key, maxNumberKeys int) (*InMemoryKeyStore, error) {
	return &InMemoryKeyStore{
		masterKey:     masterKey,
		keyStore:      make(map[string]crypto.Key),
		maxNumberKeys: maxNumberKeys,
	}, nil
}

// getSealedKeyCopy is a private function that looks up a given key and performs a key object clone
func (m *InMemoryKeyStore) getSealedKeyCopy(id string) (crypto.Key, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	key, ok := m.keyStore[id]
	if !ok {
		return nil, false
	}

	return key.Clone(), true
}

// SaveKey stores a key in memory storage. Caller key is not modified.
func (m *InMemoryKeyStore) SaveKey(ctx context.Context, id string, key []byte) error {
	// Quick read-lock to check for duplicates and current capacity. Seal can be expensive.
	// Off course this can be done because UUIDs are unique. Let's keep out of scope UUID generation collision for simplicity.
	m.mutex.RLock()
	_, ok := m.keyStore[id]
	keyStorageSize := len(m.keyStore)
	m.mutex.RUnlock()
	if ok {
		return stacktrace.NewError("Key %s already exists in key store", id)
	}

	// Lets verify if we allow more keys to be added
	if m.maxNumberKeys > 0 && keyStorageSize >= m.maxNumberKeys {
		return stacktrace.NewError("Key storage is full")
	}

	// Unfortunately we need to realize. We would need to change the interface to generalize
	// and pass directly the object
	keyImport := &crypto.AES256GCMKey{
		Key:      append([]byte(nil), key...), // Lets explicit copy so that we don't change the state of the caller. Caller might want to operate over the key material
		IsSealed: false,
	}

	if err := keyImport.Seal(ctx, m.masterKey); err != nil {
		return stacktrace.Propagate(err, "")
	}

	m.mutex.Lock()
	m.keyStore[id] = keyImport
	m.mutex.Unlock()

	return nil
}

// GetKey returns a copy of the raw key. It's up to the caller to wipe it
func (m *InMemoryKeyStore) GetKey(ctx context.Context, id string) ([]byte, error) {
	keyCopyObj, ok := m.getSealedKeyCopy(id)
	if !ok {
		return nil, stacktrace.NewError("key not found in keystore")
	}
	// We are wiping a copy of the key stored in keystore so it short leaves on memory
	defer func() {
		keyCopyObj.Wipe()
	}()

	if err := keyCopyObj.Unseal(ctx, m.masterKey); err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	// Export provides a copy of the raw Key
	rawKey, err := keyCopyObj.Export(ctx)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	// No need to seal, since the key object was a copy and will be wiped out in the end of this scope

	return rawKey, nil
}

// ListKeys list all keys UUIDs
func (m *InMemoryKeyStore) ListKeys(ctx context.Context) ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	uuids := make([]string, 0, len(m.keyStore))

	for id := range m.keyStore {
		uuids = append(uuids, id)
	}

	return uuids, nil
}
