package store

import (
	"context"
	"keysafe/internal/crypto"

	"github.com/palantir/stacktrace"
)

type InMemoryKeyStore struct {
	masterKey crypto.Key
	keyStore  map[string]crypto.Key
}

func NewInMemoryKeyStore(ctx context.Context, masterKey crypto.Key) *InMemoryKeyStore {
	return &InMemoryKeyStore{
		masterKey: masterKey,
		keyStore:  make(map[string]crypto.Key),
	}
}

func (m *InMemoryKeyStore) SaveKey(ctx context.Context, id string, key []byte) error {
	keyImport := &crypto.AES256GCMKey{
		Key:      key,
		IsSealed: false,
	}

	if err := keyImport.Seal(ctx, m.masterKey); err != nil {
		return stacktrace.Propagate(err, "")
	}

	m.keyStore[id] = keyImport
	return nil
}

func (m *InMemoryKeyStore) GetKey(ctx context.Context, id string) ([]byte, error) {
	exportKey, ok := m.keyStore[id]
	if !ok {
		return nil, nil
	}

	if err := exportKey.Unseal(ctx, m.masterKey); err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	// Pretty sensitive. Lets admite that this code runs on a secure enclave
	rawKey, err := exportKey.Export(ctx)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	return rawKey, nil
}

func (m *InMemoryKeyStore) ListKeys(ctx context.Context) ([]string, error) {
	uuids := make([]string, 0, len(m.keyStore))

	for id := range m.keyStore {
		uuids = append(uuids, id)
	}

	return uuids, nil
}
