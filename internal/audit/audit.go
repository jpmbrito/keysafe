package audit

type JsonAudit interface {
	Log(operation string, keyID string, err error)
}
