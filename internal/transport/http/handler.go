package http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"keysafe/internal/audit"
	"keysafe/internal/service"
	"keysafe/internal/transport/http/dto"

	"net/http"

	"github.com/palantir/stacktrace"
)

type Handler struct {
	ctx     context.Context
	keysafe service.Keysafe
	logger  audit.JsonAudit
}

func NewHandler(ctx context.Context, keysafe service.Keysafe, logger audit.JsonAudit) (*Handler, error) {
	return &Handler{
		ctx:     ctx,
		keysafe: keysafe,
		logger:  logger,
	}, nil
}

func httpError(w http.ResponseWriter, httpStatus int, msg string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(dto.ErrorResponse{Error: fmt.Sprintf("%s: %v", msg, stacktrace.RootCause(err))})
}

func httpOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(v)
}

// CreateKey HTTP Handler
func (s *Handler) CreateKey(w http.ResponseWriter, r *http.Request) {
	// Create key has no request dto

	keyID, err := s.keysafe.CreateKey(s.ctx)
	if err != nil {
		s.logger.Log("POST /keys", "", err)
		httpError(w, http.StatusInternalServerError, "Error during key creation", err)
	}

	s.logger.Log("POST /keys", keyID, nil)
	httpOK(w, dto.CreateKeyResponse{
		KeyID: keyID,
	})
}

// ListKeys HTTP Handler
func (s *Handler) ListKeys(w http.ResponseWriter, r *http.Request) {
	// List keys have no request dto

	keyIDs, err := s.keysafe.ListKeys(s.ctx)
	if err != nil {
		s.logger.Log("GET /keys", "", err)
		httpError(w, http.StatusInternalServerError, "Error listing keys", err)
	}

	s.logger.Log("GET /keys", "", nil)
	httpOK(w, dto.ListKeysResponse{
		Keys: keyIDs,
	})
}

// Encrypt HTTP Handler
func (s *Handler) Encrypt(w http.ResponseWriter, r *http.Request) {
	var req dto.EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Log("POST /encrypt", "", err)
		httpError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if len(req.Plaintext) == 0 {
		err := stacktrace.NewError("plaintext field is empty")
		s.logger.Log("POST /encrypt", "", err)
		httpError(w, http.StatusBadRequest, "empty field", err)
		return
	}

	plainText, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		s.logger.Log("POST /encrypt", "", err)
		httpError(w, http.StatusBadRequest, "Error decoding plaintext from base64", err)
		return
	}

	cipherBytes, err := s.keysafe.Encrypt(s.ctx, req.KeyID, []byte(plainText))
	if err != nil {
		s.logger.Log("POST /encrypt", "", err)
		httpError(w, http.StatusBadRequest, "Error during encryption", err)
		return
	}

	s.logger.Log("POST /encrypt", "", nil)
	httpOK(w, dto.EncryptResponse{
		Ciphertext: base64.StdEncoding.EncodeToString(cipherBytes),
	})
}

// Decrypt HTTP Handler
func (s *Handler) Decrypt(w http.ResponseWriter, r *http.Request) {
	var req dto.DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Log("POST /decrypt", "", err)
		httpError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if len(req.Ciphertext) == 0 {
		err := stacktrace.NewError("cyphertext field is empty")
		s.logger.Log("POST /decrypt", "", err)
		httpError(w, http.StatusBadRequest, "empty field", err)
		return
	}

	cipherText, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		s.logger.Log("POST /decrypt", "", err)
		httpError(w, http.StatusBadRequest, "Error decoding cyphertext from base64", err)
		return
	}

	plainText, err := s.keysafe.Decrypt(s.ctx, req.KeyID, []byte(cipherText))
	if err != nil {
		s.logger.Log("POST /decrypt", "", err)
		httpError(w, http.StatusBadRequest, "Error during decryption", err)
		return
	}

	s.logger.Log("POST /decrypt", "", nil)
	httpOK(w, dto.DecryptResponse{
		Plaintext: base64.StdEncoding.EncodeToString(plainText),
	})
}
