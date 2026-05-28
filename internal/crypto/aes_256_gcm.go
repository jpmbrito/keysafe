package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"reflect"
	"runtime"
	"unsafe"

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
	var err error

	if a.isWiped {
		return stacktrace.NewError("Key is wiped")
	}

	if a.IsSealed {
		return stacktrace.NewError("Key is sealed")
	}

	sealedKey, err := masterKey.Encrypt(ctx, a.Key)
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
	var err error

	if a.isWiped {
		return stacktrace.NewError("Key is wiped")
	}

	if !a.IsSealed {
		return stacktrace.NewError("Key is unsealed")
	}

	unsealedKey, err := masterKey.Decrypt(ctx, a.Key)
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

// wipeBlock zeroes the internal expanded key schedule of a cipher.Block returned by aes.NewCipher.
//
// This is a best-effort memory hygiene practice. It does not guarantee that all copies
// are cleared due to Go runtime stack growth, GC relocation, and compiler optimizations—making
// it a bit of a futile exercise in reality.
//
// Nevertheless, I believe memory hygiene is important, and it is a practice I have maintained
// throughout the years. It serves as a defensive best practice; in the event that a device
// is compromised or jailbroken, we at least make the attacker's life a little more miserable.
//
// While this level of control can be easily achieved using C++ smart pointers or Rust. Golang with
// all its beauty, was simply not designed for it and I do off course understand. Just use a TEE and you are fine.
func wipeBlock(block cipher.Block) {
	v := reflect.ValueOf(block)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	size := v.Type().Size()
	ptr := unsafe.Pointer(v.UnsafeAddr())
	mem := unsafe.Slice((*byte)(ptr), size)
	clear(mem)
	runtime.GC()
}

// Encrypt encrypts a data blob
func (a *AES256GCMKey) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	if a.isWiped {
		return nil, stacktrace.NewError("Key is wiped")
	}

	if a.IsSealed {
		return nil, stacktrace.NewError("Key is sealed")
	}

	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}
	defer wipeBlock(block)

	aesgcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	return aesgcm.Seal(nil, nil, data, nil), nil
}

// Decrypt decryps a data blob
func (a *AES256GCMKey) Decrypt(ctx context.Context, data []byte) ([]byte, error) {
	if a.isWiped {
		return nil, stacktrace.NewError("Key is wiped")
	}

	if a.IsSealed {
		return nil, stacktrace.NewError("Key is sealed")
	}

	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}
	defer wipeBlock(block)

	aesgcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	plaintext, err := aesgcm.Open(nil, nil, data, nil)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	return plaintext, nil
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
