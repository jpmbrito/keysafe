package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"keysafe/internal/audit"
	"keysafe/internal/config"
	"keysafe/internal/crypto"
	"keysafe/internal/service"
	"keysafe/internal/store"
	keysafehttp "keysafe/internal/transport/http"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Parse configuration
	envFilePath := flag.String("env", ".env", "path to the .env file")
	flag.Parse()

	_ = godotenv.Load(*envFilePath)
	appConfig := config.Config{}
	if err := config.UnmarshalConfig(&appConfig); err != nil {
		panic(err)
	}

	b, err := json.MarshalIndent(appConfig, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("Error identing configuration: %s", err.Error()))
	}
	fmt.Printf("Configuration:\n%s\n", string(b))

	if appConfig.KeyStorageType != "in-memory" {
		panic(fmt.Sprintf("'%s' key storage is not supported", appConfig.KeyStorageType))
	}

	fmt.Printf("Setting up '%s' Keystorage\n", appConfig.KeyStorageType)

	// This is the most critical crypto material. The master key seals and unseals the storage
	// In in-memory mode, we generate it internally. Off course it's not secure.
	masterKey, err := crypto.NewAES256GCMKey(ctx)
	if err != nil {
		panic(fmt.Sprintf("Error generating Master key: %s", err.Error()))
	}

	fmt.Printf("Master key installed. Vault unsealed.\n")

	// Initialize the key store
	keyStore, err := store.NewInMemoryKeyStore(ctx, masterKey, 0)
	if err != nil {
		panic(fmt.Sprintf("Error initializing key store: %s", err.Error()))
	}

	fmt.Printf("Key store initialized\n")

	// Initialize the key safe Service
	keySafe, err := service.NewKeysafe(keyStore)
	if err != nil {
		panic(fmt.Sprintf("Error initializing key Safe service: %s", err.Error()))
	}

	fmt.Printf("KeySafe Service initialized\n")

	// Initialize logger. For this demo is stdout. But can be easily changed
	logger := audit.NewJsonAuditLogger(os.Stdout)

	fmt.Printf("Audit Logger initialized\n")

	// Initialize HTTP server
	handler, err := keysafehttp.NewHandler(ctx, *keySafe, logger)
	if err != nil {
		panic(fmt.Sprintf("Error initializing key Safe service: %s", err.Error()))
	}

	// Initialize router
	router := keysafehttp.InitRouter(handler)

	// Start server
	server := &http.Server{
		Addr:    appConfig.ListenAddress,
		Handler: router,
	}

	fmt.Printf("HTTP Server started at %s\n", appConfig.ListenAddress)

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("HTTP server error: %s", err.Error()))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	// Graceful shutdown
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		fmt.Printf("HTTP server shutdown error: %s\n", err.Error())
	}
}
