package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type JsonAuditLogger struct {
	writer *json.Encoder
	mu     sync.Mutex
}

func NewJsonAuditLogger(w io.Writer) *JsonAuditLogger {
	return &JsonAuditLogger{
		writer: json.NewEncoder(w),
	}
}

func (l *JsonAuditLogger) Log(operation string, keyID string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err != nil {
		l.writer.Encode(map[string]string{
			"timestamp": time.Now().Format(time.RFC3339Nano),
			"operation": operation,
			"key_id":    keyID,
			"status":    "failure",
			"error":     err.Error(),
		})
		return
	}

	l.writer.Encode(map[string]string{
		"timestamp": time.Now().Format(time.RFC3339Nano),
		"operation": operation,
		"key_id":    keyID,
		"status":    "success",
	})
}
