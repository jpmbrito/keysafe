package store

import "context"

// KeyStore defines the interface for cryptographic key storage.
type KeyStore interface {
	SaveKey(ctx context.Context, id string, key []byte) error
	GetKey(ctx context.Context, id string) ([]byte, error)
	ListKeys(ctx context.Context) ([]string, error)
}
