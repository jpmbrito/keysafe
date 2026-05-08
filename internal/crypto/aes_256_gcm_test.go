package crypto

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAES256GCMKey_EncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	plaintext := []byte("Some test!")

	c, err := NewAES256GCMKey(ctx)
	assert.NoError(t, err)

	ciphertext, err := c.Encrypt(ctx, plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, ciphertext, plaintext)

	decrypted, err := c.Decrypt(ctx, ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, decrypted, plaintext)
}

func TestAES256GCMKey_SealAndUnseal(t *testing.T) {
	ctx := context.Background()
	originalData := []byte("Some Test!")

	key, err := NewAES256GCMKey(ctx)
	require.NoError(t, err)

	masterKey, err := NewAES256GCMKey(ctx)
	require.NoError(t, err)

	ciphertext, err := key.Encrypt(ctx, originalData)
	require.NoError(t, err)

	err = key.Seal(ctx, masterKey)
	assert.NoError(t, err)

	_, err = key.Decrypt(ctx, ciphertext)
	assert.Error(t, err)

	err = key.Unseal(ctx, masterKey)
	assert.NoError(t, err)

	decrypted, err := key.Decrypt(ctx, ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, originalData, decrypted)
}

func TestAES256GCMKey_TamperProof(t *testing.T) {
	ctx := context.Background()
	c, err := NewAES256GCMKey(ctx)
	require.NoError(t, err)

	plaintext := []byte("Some test!")
	ciphertext, err := c.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	ciphertext[len(ciphertext)-1] += 1

	_, err = c.Decrypt(ctx, ciphertext)
	assert.Error(t, err)
}

func TestAES256GCMKey_ShortCiphertext(t *testing.T) {
	ctx := context.Background()
	c, err := NewAES256GCMKey(ctx)
	require.NoError(t, err)

	_, err = c.Decrypt(ctx, []byte("too-short"))
	assert.Error(t, err)
}
