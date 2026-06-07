//go:build linux

package testutil

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScannerFindsKnownPattern(t *testing.T) {
	pattern := make([]byte, 64)
	_, err := rand.Read(pattern)
	require.NoError(t, err)

	count, regions := ScanProcessMemoryForPattern(t, pattern)

	// We are dealing with the Heisenberg uncertainty principle here. There is a fraction
	// of a percentage chance that the pattern randomly already exists on memory (garbage).
	t.Logf("Pattern (hex): %s", hex.EncodeToString(pattern))
	t.Logf("Found %d occurrence(s) in regions: %v", count, regions)

	assert.GreaterOrEqual(t, count, 1, "scanner should find random pattern in heap memory")
}
