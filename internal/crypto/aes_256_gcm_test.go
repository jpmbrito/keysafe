package crypto

import (
	"context"
	"runtime"
	"runtime/secret"
	"testing"

	"keysafe/internal/testutil"

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

// The aim of this test is to validate the memory hygiene capabilities of the AES-256-GCM module.
func TestAES256GCMKey_EncryptDecryptMemoryHygiene(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procfs memory scanning requires Linux")
	}

	ctx := context.Background()

	var secretEnabled bool
	secret.Do(func() {
		secretEnabled = secret.Enabled()
	})
	assert.True(t, secretEnabled)

	// 1. Generate key
	key, err := NewAES256GCMKey(ctx)
	require.NoError(t, err)

	countAfterCreate, _ := testutil.ScanProcessMemoryForPattern(t, key.Key)
	t.Logf("After NewAES256GCMKey: %d occurrence(s)", countAfterCreate)
	assert.GreaterOrEqual(t, countAfterCreate, 1, "key should be in memory after creation")

	//  2: Export
	rawKey, err := key.Export(ctx)
	require.NoError(t, err)

	countAfterExport, _ := testutil.ScanProcessMemoryForPattern(t, rawKey)
	t.Logf("After Export: %d occurrence(s)", countAfterExport)

	// 3. Encrypt (3x) — with secret.Do, occurrences stay bounded (≤ 6)
	plaintext := []byte("sensitive data for memory lifecycle test")
	for i := range 3 {
		ciphertext, err := key.Encrypt(ctx, plaintext)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)

		count, _ := testutil.ScanProcessMemoryForPattern(t, rawKey)
		t.Logf("After Encrypt #%d: %d occurrence(s)", i+1, count)
		assert.LessOrEqual(t, count, 6)
	}

	// 4. Decrypt (3x)
	ciphertext, err := key.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	for i := range 3 {
		decrypted, err := key.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)

		count, _ := testutil.ScanProcessMemoryForPattern(t, rawKey)
		t.Logf("After Decrypt #%d: %d occurrence(s)", i+1, count)
		assert.LessOrEqual(t, count, 6)
	}

	// 5. Seal/Unseal (3x)
	masterKey, err := NewAES256GCMKey(ctx)
	require.NoError(t, err)

	for i := range 3 {
		err = key.Seal(ctx, masterKey)
		require.NoError(t, err)

		count, _ := testutil.ScanProcessMemoryForPattern(t, rawKey)
		t.Logf("After Seal #%d: %d occurrence(s)", i+1, count)
		assert.Equal(t, 1, count)

		err = key.Unseal(ctx, masterKey)
		require.NoError(t, err)

		count, _ = testutil.ScanProcessMemoryForPattern(t, rawKey)
		t.Logf("After Unseal #%d: %d occurrence(s)", i+1, count)
		assert.Equal(t, 2, count)
	}

	// Step 6. Wipe
	scanPattern := make([]byte, len(key.Key))
	copy(scanPattern, key.Key)
	key.Wipe()
	clear(rawKey)

	countAfterWipe, regions := testutil.ScanProcessMemoryForPattern(t, scanPattern)
	t.Logf("After Wipe: %d occurrence(s) in regions: %v", countAfterWipe, regions)
	assert.LessOrEqual(t, countAfterWipe, 3) // after wipe, only scanPattern + scanner buffer copies should remain
}
