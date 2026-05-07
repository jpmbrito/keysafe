package store

import (
	"context"
	"keysafe/internal/crypto"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryKeyStore_HappyPath(t *testing.T) {
	ctx := context.Background()

	masterKey, err := crypto.NewAES256GCMKey(ctx)
	assert.NoError(t, err)

	keyStore := NewInMemoryKeyStore(ctx, masterKey)

	key1, err := crypto.NewAES256GCMKey(ctx)
	require.NoError(t, err)
	require.False(t, key1.IsSealed)

	assert.NoError(t, keyStore.SaveKey(ctx, "key1", key1.Key))

	ksKey1, err := keyStore.GetKey(ctx, "key1")
	require.NoError(t, err)
	require.Equal(t, key1.Key, ksKey1)

	ksKeys, err := keyStore.ListKeys(ctx)
	require.NoError(t, err)
	require.Equal(t, ksKeys, []string{"key1"})

	key2, err := crypto.NewAES256GCMKey(ctx)
	require.NoError(t, err)
	assert.NoError(t, keyStore.SaveKey(ctx, "key2", key2.Key))

	ksKeys, err = keyStore.ListKeys(ctx)
	require.NoError(t, err)
	require.Equal(t, ksKeys, []string{"key1", "key2"})
}
