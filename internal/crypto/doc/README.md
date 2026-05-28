# Memory Hygiene Evidence

This folder contains test output logs from `TestAES256GCMKey_EncryptDecryptMemoryHygiene`, run 30 times each with and without explicit `clear()` calls in the crypto module.

## Files

- `memory_hygiene_with_clean.txt` — Output with `clear(a.Key)` in Seal/Unseal and `defer wipeBlock(block)` in Encrypt/Decrypt
- `memory_hygiene_without_clean.txt` — Output without any explicit memory clearing

## How they were generated

```bash
# With clean (production code as-is)
for i in $(seq 1 30); do echo "=== Run $i ==="; go test -v -count=1 -run TestAES256GCMKey_EncryptDecryptMemoryHygiene ./internal/crypto/; done > internal/crypto/doc/memory_hygiene_with_clean.txt

# Without clean (clear/wipeBlock removed from aes_256_gcm.go)
# Manually comment out:
# (1) All `defer wipeBlock(block)`
# (2) clear and runtime.GC() from Wipe()
for i in $(seq 1 30); do echo "=== Run $i ==="; go test -v -count=1 -run TestAES256GCMKey_EncryptDecryptMemoryHygiene ./internal/crypto/; done > internal/crypto/doc/memory_hygiene_without_clean.txt
```

## Conclusion

The results show that explicit clearing reduces key material occurrences in process memory, but due to Go runtime non-determinism (GC timing, stack relocation, scanner self-pollution), a single-run assertion cannot reliably distinguish the two. The evidence is statistical across multiple runs. Which was totally expected.
