package crypto

import "context"

type Key interface {
	Seal(ctx context.Context, masterKey Key) error
	Unseal(ctx context.Context, masterKey Key) error

	Encrypt(ctx context.Context, data []byte) ([]byte, error)
	Decrypt(ctx context.Context, data []byte) ([]byte, error)

	Export(ctx context.Context) ([]byte, error)
}
