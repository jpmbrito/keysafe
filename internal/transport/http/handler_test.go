package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"keysafe/internal/audit"
	"keysafe/internal/crypto"
	"keysafe/internal/service"
	"keysafe/internal/store"
	"keysafe/internal/transport/http/dto"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// setupTest initializes the full crypto stack for each test case
func setupTest(t *testing.T, ctx context.Context) *http.ServeMux {
	masterKey, err := crypto.NewAES256GCMKey(ctx)
	assert.NoError(t, err)

	kStore, err := store.NewInMemoryKeyStore(ctx, masterKey, 0)
	assert.NoError(t, err)

	keySafe, err := service.NewKeysafe(kStore)
	assert.NoError(t, err)

	handler, err := NewHandler(ctx, *keySafe, audit.NewJsonAuditLogger(os.Stdout))
	assert.NoError(t, err)

	return InitRouter(handler)
}

func TestHandler_CreateKey(t *testing.T) {
	ctx := context.Background()
	router := setupTest(t, ctx)

	k1 := createKey(t, router)
	k2 := createKey(t, router)
	assert.NotEqual(t, k1, k2)

	keyIds := listKeys(t, router)
	assert.Contains(t, keyIds, k1)
	assert.Contains(t, keyIds, k2)
	assert.Equal(t, len(keyIds), 2)
}

func TestHandler_EncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	router := setupTest(t, ctx)

	k1 := createKey(t, router)
	k2 := createKey(t, router)

	plainText := []byte("test")

	cypherTextb64 := encrypt(t, router, k1, plainText)
	decypheredText := decrypt(t, router, k1, cypherTextb64)
	assert.Equal(t, decypheredText, plainText)

	cypherText2b64 := encrypt(t, router, k2, plainText)
	assert.NotEqual(t, cypherTextb64, cypherText2b64)
	decypheredText2 := decrypt(t, router, k1, cypherTextb64)
	assert.Equal(t, decypheredText2, plainText)

	// Concurrency tests
	var wg1 sync.WaitGroup
	workers1 := make([]struct{}, 10000)
	wg1.Add(len(workers1))
	for range workers1 {
		go func(t *testing.T, k1 string, plainText []byte) {
			defer wg1.Done()

			cypherTextb64 := encrypt(t, router, k1, plainText)
			decypheredText := decrypt(t, router, k1, cypherTextb64)
			assert.Equal(t, decypheredText, plainText)

		}(t, k1, plainText)
	}

	var wg2 sync.WaitGroup
	workers2 := make([]struct{}, 10000)
	wg1.Add(len(workers2))
	for range workers2 {
		go func(t *testing.T, plainText []byte) {
			defer wg1.Done()

			k1 := createKey(t, router)

			cypherTextb64 := encrypt(t, router, k1, plainText)
			decypheredText := decrypt(t, router, k1, cypherTextb64)
			assert.Equal(t, decypheredText, plainText)

		}(t, plainText)
	}

	wg1.Wait()
	wg2.Wait()
}

func TestHandler_EncryptDecryptNegativeTests(t *testing.T) {
	ctx := context.Background()
	router := setupTest(t, ctx)

	// Invalid key ids
	encryptNegativeCall(t, router, "INVALID", []byte("123"), http.StatusBadRequest, "key not found in keystore")
	encryptNegativeCall(t, router, "", []byte("123"), http.StatusBadRequest, "key not found in keystore")
	decryptNegativeCall(t, router, "", base64.StdEncoding.EncodeToString([]byte("123")), http.StatusBadRequest, "key not found in keystore")

	// Invalid encrypted payload
	decryptNegativeCall(t, router, "INVALID", "123", http.StatusBadRequest, "Error decoding cyphertext from base64: illegal base64 data at input byte 0")

	// Invalid plaintext field
	k1 := createKey(t, router)
	encryptNegativeCall(t, router, "INVALID", nil, http.StatusBadRequest, "plaintext field is empty")
	encryptNegativeCall(t, router, k1, nil, http.StatusBadRequest, "plaintext field is empty")
	encryptNegativeCall(t, router, k1, nil, http.StatusBadRequest, "plaintext field is empty")

	// Decrypt payload from different key
	k2 := createKey(t, router)

	plainText := []byte("test")
	cypherTextb64 := encrypt(t, router, k1, plainText)
	decryptNegativeCall(t, router, k2, cypherTextb64, http.StatusBadRequest, "Error during decryption: cipher: message authentication failed")
}

func createKey(t *testing.T, router *http.ServeMux) string {
	req := httptest.NewRequest("POST", "/keys", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp dto.CreateKeyResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.KeyID, "Handler should return a valid KeyID")

	return resp.KeyID
}

func listKeys(t *testing.T, router *http.ServeMux) []string {
	req := httptest.NewRequest("GET", "/keys", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp dto.ListKeysResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)

	return resp.Keys
}

func encrypt(t *testing.T, router *http.ServeMux, keyID string, data []byte) string {
	b64Plaintext := base64.StdEncoding.EncodeToString(data)

	reqBody, _ := json.Marshal(dto.EncryptRequest{
		KeyID:     keyID,
		Plaintext: b64Plaintext,
	})

	req := httptest.NewRequest("POST", "/encrypt", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp dto.EncryptResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)

	return resp.Ciphertext
}

func encryptNegativeCall(t *testing.T, router *http.ServeMux, keyID string, data []byte, httpErrorCode int, errorMessage string) {
	b64Plaintext := base64.StdEncoding.EncodeToString(data)

	reqBody, _ := json.Marshal(dto.EncryptRequest{
		KeyID:     keyID,
		Plaintext: b64Plaintext,
	})

	req := httptest.NewRequest("POST", "/encrypt", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, httpErrorCode, w.Code)

	var resp dto.ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Contains(t, resp.Error, errorMessage)
}

func decrypt(t *testing.T, router *http.ServeMux, keyID string, b64Ciphertext string) []byte {
	reqBody, _ := json.Marshal(dto.DecryptRequest{
		KeyID:      keyID,
		Ciphertext: b64Ciphertext,
	})

	req := httptest.NewRequest("POST", "/decrypt", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp dto.DecryptResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.Plaintext)

	decoded, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	assert.NoError(t, err)

	return decoded
}

func decryptNegativeCall(t *testing.T, router *http.ServeMux, keyID string, b64Ciphertext string, httpErrorCode int, errorMessage string) {
	reqBody, _ := json.Marshal(dto.DecryptRequest{
		KeyID:      keyID,
		Ciphertext: b64Ciphertext,
	})

	req := httptest.NewRequest("POST", "/decrypt", bytes.NewBuffer(reqBody))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, httpErrorCode, w.Code)

	var resp dto.ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Contains(t, resp.Error, errorMessage)
}
