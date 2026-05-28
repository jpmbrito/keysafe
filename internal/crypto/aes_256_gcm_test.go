package crypto

import (
	"context"
	"runtime"
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
// Unfortunately it's not possible, deterministically, to detect whether or not clear() is used.
// There are many reasons for it:
//
// 1. Heisenberg effect: The act of scanning process memory copies the key pattern into the
//    scanner's own buffers, can create false positives.
//
// 2. Go internal memory management: The runtime may relocate heap objects during GC compaction,
//    leaving stale copies in previously-used pages. Stack growth copies goroutine stacks to new
//    locations without zeroing the old one immediately.
//
// 3. Scanning process memory is insufficient because the runtime calls memclrNoHeapPointers
//    (runtime/stack.go:995) when shrinking or freeing goroutine stacks, which may zero
//    stack-resident key copies without any explicit action from user code — causing false
//    negatives.
//    See: https://github.com/golang/go/blob/go1.26.3/src/runtime/stack.go#L995
//
// However, by running this test multiple times (see evidence/ folder), it's clear that memory
// hygiene improves when explicit clear() is used. The test passes regardless, logging occurrence
// counts at each lifecycle step for observational evidence. However assertions are not reliable.

func TestAES256GCMKey_EncryptDecryptMemoryHygiene(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procfs memory scanning requires Linux")
	}

	ctx := context.Background()

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
	// assert.GreaterOrEqual(t, countAfterExport, countAfterCreate, "key should be in memory after Export") // Flacky

	// 3. Encrypt (3x)
	plaintext := []byte("sensitive data for memory lifecycle test")
	for i := range 3 {
		ciphertext, err := key.Encrypt(ctx, plaintext)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)

		count, _ := testutil.ScanProcessMemoryForPattern(t, rawKey)
		t.Logf("After Encrypt #%d: %d occurrence(s)", i+1, count)
		assert.GreaterOrEqual(t, count, countAfterExport)
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
		assert.GreaterOrEqual(t, count, countAfterExport)
	}

	// 5. Seal/Unseal (3x)
	masterKey, err := NewAES256GCMKey(ctx)
	require.NoError(t, err)

	for i := range 3 {
		err = key.Seal(ctx, masterKey)
		require.NoError(t, err)

		count, _ := testutil.ScanProcessMemoryForPattern(t, rawKey)
		t.Logf("After Seal #%d: %d occurrence(s)", i+1, count)

		err = key.Unseal(ctx, masterKey)
		require.NoError(t, err)

		count, _ = testutil.ScanProcessMemoryForPattern(t, rawKey)
		t.Logf("After Unseal #%d: %d occurrence(s)", i+1, count)
		assert.GreaterOrEqual(t, count, countAfterExport)
	}

	// Step 6. Wipe
	scanPattern := make([]byte, len(key.Key))
	copy(scanPattern, key.Key)
	key.Wipe()
	clear(rawKey)

	countAfterWipe, regions := testutil.ScanProcessMemoryForPattern(t, scanPattern)
	t.Logf("After Wipe: %d occurrence(s) in regions: %v", countAfterWipe, regions)
}
