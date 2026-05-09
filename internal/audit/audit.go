package audit

// JsonAudit interface enables the creation of json loggers
type JsonAudit interface {
	Log(operation string, keyID string, err error)
}
