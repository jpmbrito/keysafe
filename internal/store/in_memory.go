package store

import (
	"context"
	"keysafe/internal/crypto"
	"sync"

	"github.com/palantir/stacktrace"
)

type InMemoryKeyStore struct {
	masterKey crypto.Key
	keyStore  map[string]crypto.Key

	mutex sync.RWMutex
}

func NewInMemoryKeyStore(ctx context.Context, masterKey crypto.Key) *InMemoryKeyStore {
	return &InMemoryKeyStore{
		masterKey: masterKey,
		keyStore:  make(map[string]crypto.Key),
	}
}

func (m *InMemoryKeyStore) SaveKey(ctx context.Context, id string, key []byte) error {
	// Unfortunately we need to use a realization. We would need to change the interface to generalize
	// and pass directly the object
	keyImport := &crypto.AES256GCMKey{
		Key:      key,
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

func (m *InMemoryKeyStore) GetKey(ctx context.Context, id string) ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	exportKey, ok := m.keyStore[id]
	if !ok {
		return nil, nil
	}

	if err := exportKey.Unseal(ctx, m.masterKey); err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	rawKey, err := exportKey.Export(ctx)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	return rawKey, nil
}

func (m *InMemoryKeyStore) ListKeys(ctx context.Context) ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	uuids := make([]string, 0, len(m.keyStore))

	for id := range m.keyStore {
		uuids = append(uuids, id)
	}

	return uuids, nil
}
