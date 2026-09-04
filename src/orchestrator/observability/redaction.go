package observability

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
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
	if !utf8.ValidString(record.Body) {
		return LogRecord{}, errors.New("log body must contain valid UTF-8")
	}
	if containsLogControl(record.Body) {
		return LogRecord{}, errors.New("log body must be control-free")
	}
	if len(record.Attributes) > maxLogAttributes {
		return LogRecord{}, errors.New("log attributes exceed 32 fields")
	}
	result := LogRecord{Timestamp: record.Timestamp, Body: RedactText(record.Body)}
	if record.Attributes != nil {
		result.Attributes = make(map[string]string, len(record.Attributes))
	}
	for key, value := range record.Attributes {
		if err := validateLabelKey(key); err != nil {
			return LogRecord{}, errors.New("log attribute key is invalid")
		}
		if isCustomerDimension(key) {
			return LogRecord{}, fmt.Errorf("customer dimension %q is not permitted in logs", key)
		}
		if len(value) > maxLogValue {
			return LogRecord{}, errors.New("log attribute value exceeds 512 bytes")
		}
		if !utf8.ValidString(value) || containsLogControl(value) {
			return LogRecord{}, errors.New("log attribute value must be valid UTF-8 and control-free")
		}
		if sensitiveKey(key) {
			result.Attributes[key] = "[redacted]"
		} else {
			result.Attributes[key] = RedactText(value)
		}
	}
	return result, nil
}

func containsLogControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f || (character >= 0x80 && character <= 0x9f) {
			return true
		}
	}
	return false
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
