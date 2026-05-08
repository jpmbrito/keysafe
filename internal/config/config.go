package config

import (
	"fmt"

	"github.com/caarlos0/env/v6"
	"github.com/creasty/defaults"
)

type Config struct {
	KeyStorageType string `env:"KEY_STORAGE" json:"KEY_STORAGE" default:"in-memory"`
	MaxKeyStorage  int    `env:"MAX_KEY_STORAGE" json:"MAX_KEY_STORAGE" default:"0"` // 0 unlimited
	ListenAddress  string `env:"LISTEN_ADDRESS" json:"LISTEN_ADDRESS" default:"127.0.0.1:8000"`
}

func UnmarshalConfig(cfg any) error {
	if err := defaults.Set(cfg); err != nil {
		return fmt.Errorf("unable to set config defaults: %w", err)
	}

	if err := env.Parse(cfg); err != nil {
		return fmt.Errorf("unable to parse environment variables: %w", err)
	}

	return nil
}
