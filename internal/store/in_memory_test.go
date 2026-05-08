package store

import (
	"context"
	"keysafe/internal/crypto"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryKeyStore(t *testing.T) {
	ctx := context.Background()

	masterKey, err := crypto.NewAES256GCMKey(ctx)
	assert.NoError(t, err)

	keyStore, err := NewInMemoryKeyStore(ctx, masterKey, 0)
	require.NoError(t, err)

	key1, err := crypto.NewAES256GCMKey(ctx)
	require.NoError(t, err)
	require.False(t, key1.IsSealed)

	assert.NoError(t, keyStore.SaveKey(ctx, "key1", key1.Key))

	// If we double register same keyid we get an error
	assert.Error(t, keyStore.SaveKey(ctx, "key1", key1.Key))

	ksKey1, err := keyStore.GetKey(ctx, "key1")
	require.NoError(t, err)
	require.Equal(t, key1.Key, ksKey1)

	// If I get the same key again it shall work. Means that seal and unseal always happens in GetKey
	ksKey1_copy, err := keyStore.GetKey(ctx, "key1")
	require.NoError(t, err)
	require.Equal(t, ksKey1_copy, ksKey1)

	// Lets make sure the keys don't share same raw bit slice
	key1.Wipe()
	require.NotEqual(t, key1.Key, ksKey1)

	ksKeys, err := keyStore.ListKeys(ctx)
	require.NoError(t, err)
	require.Contains(t, ksKeys, "key1")

	key2, err := crypto.NewAES256GCMKey(ctx)
	require.NoError(t, err)
	assert.NoError(t, keyStore.SaveKey(ctx, "key2", key2.Key))

	ksKeys, err = keyStore.ListKeys(ctx)
	require.NoError(t, err)
	require.Contains(t, ksKeys, "key1")
	require.Contains(t, ksKeys, "key2")
}

func TestInMemoryKeyStore_Capacity(t *testing.T) {
	ctx := context.Background()

	masterKey, err := crypto.NewAES256GCMKey(ctx)
	assert.NoError(t, err)

	keyStore, err := NewInMemoryKeyStore(ctx, masterKey, 2)
	require.NoError(t, err)

	key1, err := crypto.NewAES256GCMKey(ctx)
	require.NoError(t, err)

	assert.NoError(t, keyStore.SaveKey(ctx, "key1", key1.Key))
	assert.NoError(t, keyStore.SaveKey(ctx, "key2", key1.Key))
	assert.Error(t, keyStore.SaveKey(ctx, "key3", key1.Key))
}
