package testutil

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/require"
)

// parseMemoryMaps reads /proc/self/maps using prometheus/procfs and returns all readable memory regions
func parseMemoryMaps(t *testing.T) []*procfs.ProcMap {
	t.Helper()

	proc, err := procfs.Self()
	require.NoError(t, err, "requires Linux with procfs: cannot access /proc/self")

	maps, err := proc.ProcMaps()
	require.NoError(t, err, "requires Linux with procfs: cannot read /proc/self/maps")

	var regions []*procfs.ProcMap
	for _, m := range maps {
		if m.Perms == nil || !m.Perms.Read {
			continue
		}
		if strings.Contains(m.Pathname, "vdso") || strings.Contains(m.Pathname, "vsyscall") {
			continue
		}
		regions = append(regions, m)
	}

	return regions
}

// countOccurrences counts non-overlapping occurrences of a pattern in a memory segment.
func countOccurrences(data, pattern []byte) int {
	count := 0
	for {
		idx := bytes.Index(data, pattern)
		if idx == -1 {
			break
		}
		count++
		data = data[idx+len(pattern):]
	}
	return count
}

// ScanProcessMemoryForPattern opens /proc/self/mem and scans all readable memory
// regions for non-overlapping occurrences of pattern.
func ScanProcessMemoryForPattern(t *testing.T, pattern []byte) (int, []string) {
	t.Helper()

	regions := parseMemoryMaps(t)

	f, err := os.Open("/proc/self/mem")
	require.NoError(t, err, "cannot open /proc/self/mem: requires Linux with procfs")
	defer f.Close()

	const chunkSize = 4 * 1024 * 1024
	overlap := len(pattern) - 1
	buf := make([]byte, chunkSize)

	totalCount := 0
	var matchingRegions []string

	for _, m := range regions {
		regionStart := int64(m.StartAddr)
		regionEnd := int64(m.EndAddr)
		regionMatches := 0

		offset := regionStart
		for offset < regionEnd {
			readSize := chunkSize
			if offset+int64(readSize) > regionEnd {
				readSize = int(regionEnd - offset)
			}

			n, err := f.ReadAt(buf[:readSize], offset)
			if err != nil || n == 0 {
				break
			}

			regionMatches += countOccurrences(buf[:n], pattern)

			offset += int64(n - overlap)
			if n < chunkSize {
				break
			}
		}

		if regionMatches > 0 {
			totalCount += regionMatches
			desc := fmt.Sprintf("%s [%x-%x]", m.Pathname, m.StartAddr, m.EndAddr)
			matchingRegions = append(matchingRegions, desc)
		}
	}

	return totalCount, matchingRegions
}
