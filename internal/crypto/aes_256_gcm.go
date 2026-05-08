package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/palantir/stacktrace"
)

type AES256GCMKey struct {
	Key      []byte
	IsSealed bool
	isWiped  bool
}

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

	a.Key = sealedKey
	a.IsSealed = true

	return nil
}

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

	a.Key = unsealedKey
	a.IsSealed = false

	return nil
}

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
	aesgcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	return aesgcm.Seal(nonce, nonce, data, nil), nil
}

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

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	nonceSize := aesgcm.NonceSize()
	if len(data) < nonceSize {
		return nil, stacktrace.NewError("ciphertext too short")
	}

	// remove the nonce
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, stacktrace.Propagate(err, "")
	}

	return plaintext, nil
}

func (a *AES256GCMKey) Wipe() {
	clear(a.Key)
	a.isWiped = true
}

func (k *AES256GCMKey) Clone() Key {
	return &AES256GCMKey{
		Key:      append([]byte(nil), k.Key...),
		IsSealed: k.IsSealed,
		isWiped:  k.isWiped,
	}
}
