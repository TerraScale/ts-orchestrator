package observability

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

const (
	maxLogBody       = 16 * 1024
	maxLogAttributes = 32
	maxLogValue      = 512
)

var (
	bearerSecretPattern   = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`)
	keyValueSecretPattern = regexp.MustCompile(`(?i)\b(token|password|passwd|secret|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+`)
)

// LogRecord is the bounded structured log shape sent to an OTLP logs
// encoder. Body and attributes are sanitized before they cross the boundary.
type LogRecord struct {
	Timestamp  time.Time
	Body       string
	Attributes map[string]string
}

// RedactLog returns a bounded defensive copy with credentials removed from
// both structured fields and free-form body text.
func RedactLog(record LogRecord) (LogRecord, error) {
	if len(record.Body) > maxLogBody {
		return LogRecord{}, errors.New("log body exceeds 16 KiB")
	}
	if len(record.Attributes) > maxLogAttributes {
		return LogRecord{}, errors.New("log attributes exceed 32 fields")
	}
	result := LogRecord{Timestamp: record.Timestamp, Body: RedactText(record.Body)}
	if record.Attributes != nil {
		result.Attributes = make(map[string]string, len(record.Attributes))
	}
	for key, value := range record.Attributes {
		if len(key) == 0 || len(key) > 63 || strings.ContainsAny(key, "\r\n\x00") {
			return LogRecord{}, errors.New("log attribute key is invalid")
		}
		if len(value) > maxLogValue {
			return LogRecord{}, errors.New("log attribute value exceeds 512 bytes")
		}
		if sensitiveKey(key) {
			result.Attributes[key] = "[redacted]"
		} else {
			result.Attributes[key] = RedactText(value)
		}
	}
	return result, nil
}

// RedactText removes common bearer/basic credentials and secret-bearing
// key/value fields without returning the original token in diagnostics.
func RedactText(value string) string {
	value = bearerSecretPattern.ReplaceAllString(value, "$1 [redacted]")
	return keyValueSecretPattern.ReplaceAllString(value, "$1=[redacted]")
}

func sensitiveKey(key string) bool {
	switch strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), ".", "_")) {
	case "token", "password", "passwd", "secret", "api_key", "authorization", "cookie", "credential", "credentials":
		return true
	default:
		return false
	}
}
