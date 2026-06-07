//go:build goexperiment.runtimesecret

package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"runtime"
	"runtime/secret"

	"github.com/palantir/stacktrace"
)

type AES256GCMKey struct {
	Key      []byte
	IsSealed bool
	isWiped  bool
}

// NewAES256GCMKey creates a AES256GCMKey
func NewAES256GCMKey(ctx context.Context) (*AES256GCMKey, error) {
	Key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, Key); err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	return &AES256GCMKey{
		Key:      Key,
		IsSealed: false,
	}, nil
}

// Seal encrypts the Key with master Key
func (a *AES256GCMKey) Seal(ctx context.Context, masterKey Key) error {
	if a.isWiped {
		return stacktrace.NewError("Key is wiped")
	}

	if a.IsSealed {
		return stacktrace.NewError("Key is sealed")
	}

	var sealedKey []byte
	var err error

	secret.Do(func() {
		sealedKey, err = masterKey.Encrypt(ctx, a.Key)
	})

	if err != nil {
		return stacktrace.Propagate(err, "")
	}

	clear(a.Key)
	a.Key = sealedKey
	a.IsSealed = true

	return nil
}

// Unseal decrypts the Key with master key
func (a *AES256GCMKey) Unseal(ctx context.Context, masterKey Key) error {
	if a.isWiped {
		return stacktrace.NewError("Key is wiped")
	}

	if !a.IsSealed {
		return stacktrace.NewError("Key is unsealed")
	}

	var unsealedKey []byte
	var err error

	secret.Do(func() {
		unsealedKey, err = masterKey.Decrypt(ctx, a.Key)
	})

	if err != nil {
		return stacktrace.Propagate(err, "")
	}

	clear(a.Key)
	a.Key = unsealedKey
	a.IsSealed = false

	return nil
}

// Export duplicates the raw Key to a byte slice
func (a *AES256GCMKey) Export(ctx context.Context) ([]byte, error) {
	if a.isWiped {
		return nil, stacktrace.NewError("Key is wiped")
	}

	if a.IsSealed {
		return nil, stacktrace.NewError("Key is sealed")
	}

	// Export provides a copy of the raw key. It's up to the caller to wipe it.
	return append([]byte(nil), a.Key...), nil
}

// Encrypt encrypts a data blob
func (a *AES256GCMKey) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	if a.isWiped {
		return nil, stacktrace.NewError("Key is wiped")
	}

	if a.IsSealed {
		return nil, stacktrace.NewError("Key is sealed")
	}

	var result []byte
	var err error

	secret.Do(func() {
		var block cipher.Block
		block, err = aes.NewCipher(a.Key)
		if err != nil {
			return
		}

		var aesgcm cipher.AEAD
		aesgcm, err = cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return
		}

		result = aesgcm.Seal(nil, nil, data, nil)
	})

	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	return result, nil
}

// Decrypt decrypts a data blob
func (a *AES256GCMKey) Decrypt(ctx context.Context, data []byte) ([]byte, error) {
	if a.isWiped {
		return nil, stacktrace.NewError("Key is wiped")
	}

	if a.IsSealed {
		return nil, stacktrace.NewError("Key is sealed")
	}

	var result []byte
	var err error

	secret.Do(func() {
		var block cipher.Block
		block, err = aes.NewCipher(a.Key)
		if err != nil {
			return
		}

		var aesgcm cipher.AEAD
		aesgcm, err = cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return
		}

		result, err = aesgcm.Open(nil, nil, data, nil)
	})

	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	return result, nil
}

// Attempt to zero plain text material from RAM
// same as I mentioned in wipeBlock. Best effort. Calling GC, by experience, improves a bit.
// I will keep it as part of this exercice. There is a runtime penalty, but it's ok for this.
func (a *AES256GCMKey) Wipe() {
	clear(a.Key)
	runtime.GC()
	a.isWiped = true
}

// Clone clones the key object
func (k *AES256GCMKey) Clone() Key {
	return &AES256GCMKey{
		Key:      append([]byte(nil), k.Key...),
		IsSealed: k.IsSealed,
		isWiped:  k.isWiped,
	}
}
