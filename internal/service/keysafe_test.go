package service

import (
	"context"
	"keysafe/internal/crypto"
	"keysafe/internal/store"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupTest(t *testing.T, ctx context.Context) *Keysafe {
	masterKey, err := crypto.NewAES256GCMKey(ctx)
	assert.NoError(t, err)

	store, err := store.NewInMemoryKeyStore(ctx, masterKey, 0)
	assert.NoError(t, err)

	keySafe, err := NewKeysafe(store)
	assert.NoError(t, err)

	return keySafe
}

func TestKeySafe_KeyCreation(t *testing.T) {
	ctx := context.Background()
	keySafe := setupTest(t, ctx)

	key1Id, err := keySafe.CreateKey(ctx)
	assert.NoError(t, err)

	keySafeKeyIds, err := keySafe.ListKeys(ctx)
	assert.NoError(t, err)
	assert.Equal(t, len(keySafeKeyIds), 1)
	assert.Contains(t, keySafeKeyIds, key1Id)

	key2Id, err := keySafe.CreateKey(ctx)
	assert.NoError(t, err)

	keySafeKeyIds, err = keySafe.ListKeys(ctx)
	assert.NoError(t, err)
	assert.Equal(t, len(keySafeKeyIds), 2)
	assert.Contains(t, keySafeKeyIds, key1Id)
	assert.Contains(t, keySafeKeyIds, key2Id)

	for range 10 {
		_, err := keySafe.CreateKey(ctx)
		assert.NoError(t, err)
	}
	keySafeKeyIds, err = keySafe.ListKeys(ctx)
	assert.NoError(t, err)
	assert.Equal(t, len(keySafeKeyIds), 12)

	// Concurrency test:
	var wg sync.WaitGroup
	workers := make([]struct{}, 10000)
	wg.Add(len(workers))
	for range workers {
		go func() {
			defer wg.Done()

			keyId, err := keySafe.CreateKey(ctx)
			assert.NoError(t, err)

			keySafeKeyIds, err := keySafe.ListKeys(ctx)
			assert.NoError(t, err)
			assert.Contains(t, keySafeKeyIds, keyId)
		}()
	}
	wg.Wait()

	keySafeKeyIds, err = keySafe.ListKeys(ctx)
	assert.NoError(t, err)
	assert.Equal(t, len(keySafeKeyIds), 12+len(workers))
}

func TestKeySafe_EncryptionDecryption(t *testing.T) {
	ctx := context.Background()
	keySafe := setupTest(t, ctx)

	key1Id, err := keySafe.CreateKey(ctx)
	assert.NoError(t, err)

	plainTextData := []byte("Test plaintext")
	encryptedData, err := keySafe.Encrypt(ctx, key1Id, plainTextData)
	assert.NoError(t, err)

	assert.NotEqual(t, plainTextData, encryptedData)

	decryptedData, err := keySafe.Decrypt(ctx, key1Id, encryptedData)
	assert.NoError(t, err)

	assert.NotEqual(t, encryptedData, decryptedData)
	assert.Equal(t, plainTextData, decryptedData)

	// Concurrency test:
	var wg sync.WaitGroup
	workers := make([]struct{}, 10000)
	wg.Add(len(workers))

	for range workers {
		go func(t *testing.T, keySafe *Keysafe, keyID string, plainTextData []byte) {
			defer wg.Done()

			encryptedDataRoutine, err := keySafe.Encrypt(ctx, keyID, plainTextData)
			assert.NoError(t, err)

			concurrentDecrypted, err := keySafe.Decrypt(ctx, keyID, encryptedDataRoutine)
			assert.NoError(t, err)
			assert.Equal(t, concurrentDecrypted, plainTextData)
		}(t, keySafe, key1Id, plainTextData)
	}

	wg.Wait()
}
