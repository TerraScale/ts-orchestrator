package logs

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

var (
	uuid    = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	ulid    = regexp.MustCompile(`\b[0-7][0-9A-HJKMNP-TV-Z]{25}\b`)
	address = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b`)
	number  = regexp.MustCompile(`\b[0-9a-fA-F]*[0-9][0-9a-fA-F]*\b|\d+`)
)

// Normalize turns a message into its class: credentials are redacted, then
// identifiers, addresses and numbers become N, so one cause counts as one class.
func Normalize(message string) string {
	// The whole message is redacted before the cut: a cut first could leave half a credential.
	s := strings.TrimSpace(observability.RedactText(message, len(message)))
	for _, pattern := range []*regexp.Regexp{uuid, ulid, address, number} {
		s = pattern.ReplaceAllString(s, "N")
	}
	return cut(s, 160)
}

// example is the raw message a class keeps once, with its credentials redacted.
func example(message string) string {
	return observability.RedactText(strings.TrimSpace(message), 512)
}

// cut keeps at most n bytes of s without splitting a UTF-8 sequence.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
