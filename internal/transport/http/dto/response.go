package dto

type CreateKeyResponse struct {
	KeyID string `json:"key_id"`
}

type ListKeysResponse struct {
	Keys []string `json:"keys"`
}

type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"`
}

type DecryptResponse struct {
	Plaintext string `json:"plaintext"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
