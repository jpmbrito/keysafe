package service

import (
	"context"
	"keysafe/internal/crypto"
	"keysafe/internal/store"

	"github.com/google/uuid"
	"github.com/palantir/stacktrace"
)

type Keysafe struct {
	keyStore store.KeyStore
}

func NewKeysafe(keyStore store.KeyStore) (*Keysafe, error) {
	return &Keysafe{
		keyStore: keyStore,
	}, nil
}

// CreateKey service handler
func (k *Keysafe) CreateKey(ctx context.Context) (string, error) {
	// Idealy this service could be "generalized" so that the keytype is also a parameter. Probably using reflection or generics.
	// However for the sake of simplicity I am going to realize here AES 256 GCM KEY as defined on the challenge document
	keyObj, err := crypto.NewAES256GCMKey(ctx)
	if err != nil {
		return "", stacktrace.Propagate(err, "")
	}
	defer func() {
		keyObj.Wipe()
	}()

	rawKey, err := keyObj.Export(ctx)
	if err != nil {
		return "", stacktrace.Propagate(err, "")
	}

	uuid := uuid.New().String()

	err = k.keyStore.SaveKey(ctx, uuid, rawKey)
	if err != nil {
		return "", stacktrace.Propagate(err, "")
	}

	return uuid, nil
}

// ListKeys service handler
func (k *Keysafe) ListKeys(ctx context.Context) ([]string, error) {
	return k.keyStore.ListKeys(ctx)
}

// Encrypt service handler
func (k *Keysafe) Encrypt(ctx context.Context, keyId string, data []byte) ([]byte, error) {
	rawKey, err := k.keyStore.GetKey(ctx, keyId)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	keyObj := &crypto.AES256GCMKey{
		Key:      rawKey,
		IsSealed: false,
	}
	// We are wiping a copy of the keystore so it short leaves on memory
	defer func() {
		keyObj.Wipe()
	}()

	encryptedData, err := keyObj.Encrypt(ctx, data)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	return encryptedData, nil
}

// Decrypt service handler
func (k *Keysafe) Decrypt(ctx context.Context, keyId string, data []byte) ([]byte, error) {
	rawKey, err := k.keyStore.GetKey(ctx, keyId)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	keyObj := &crypto.AES256GCMKey{
		Key:      rawKey,
		IsSealed: false,
	}
	// We are wiping a copy of the keystore so it short leaves on memory
	defer func() {
		keyObj.Wipe()
	}()

	encryptedData, err := keyObj.Decrypt(ctx, data)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	return encryptedData, nil
}
