package http

import "net/http"

func InitRouter(handler *Handler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /keys", handler.CreateKey)
	mux.HandleFunc("GET /keys", handler.ListKeys)
	mux.HandleFunc("POST /encrypt", handler.Encrypt)
	mux.HandleFunc("POST /decrypt", handler.Decrypt)

	return mux
}
