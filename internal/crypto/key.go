package crypto

import "context"

type Key interface {
	Seal(ctx context.Context, masterKey Key) error
	Unseal(ctx context.Context, masterKey Key) error

	Export(ctx context.Context) ([]byte, error)
}
