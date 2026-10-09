package observability

import (
	"errors"
	"testing"
)

func TestLogRedactionURLFragmentCredentials(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"json", "logfmt"} {
		t.Run(format, func(t *testing.T) {
			logger, output, bus := redactionLogger(t, format)
			for _, raw := range []string{
				"https://example.test/callback#access_token=fragmentFixture123&mode=normal",
				"https://example.test/callback#access%5Ftoken=encodedFragmentFixture123&mode=normal",
			} {
				logger.Warn(raw, "error", errors.New(raw))
			}
			assertNoLogSecrets(t, output, bus, "fragmentFixture123", "encodedFragmentFixture123")
		})
	}
}
