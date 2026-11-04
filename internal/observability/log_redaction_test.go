package observability

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"
)

func redactionLogger(t *testing.T, format string, attrs ...slog.Attr) (*slog.Logger, *logOutput, *EventBus) {
	t.Helper()
	output := newLogOutput(t)
	bus := NewEventBus(256)
	logger, err := NewLogger(output, LogConfig{Format: format}, bus, attrs...)
	if err != nil {
		t.Fatal(err)
	}
	return logger, output, bus
}

func assertNoLogSecrets(t *testing.T, output *logOutput, bus *EventBus, secrets ...string) {
	t.Helper()
	events, err := json.Marshal(bus.Recent(0))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(output.String(), secret) || bytes.Contains(events, []byte(secret)) {
			t.Fatalf("credential %q escaped redaction: output=%s events=%s", secret, output.String(), events)
		}
	}
	if !utf8.Valid(output.Bytes()) || !utf8.Valid(events) {
		t.Fatal("invalid UTF8 in a sink")
	}
}

func TestLogRedactionCredentialsBothSinks(t *testing.T) {
	t.Parallel()
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsb2dUZXN0In0.signatureSecret123"
	spacedJWT := base64.RawURLEncoding.EncodeToString([]byte("{\n \"alg\":\"HS256\"}")) + ".eyJzdWIiOiJsb2dUZXN0In0.spacedJWTSecret123"
	seed := "SU" + strings.Repeat("A", 56)
	pem := "-----BEGIN PRIVATE KEY-----\npemPayloadSecret123\n-----END PRIVATE KEY-----"
	freeText := "request Bearer bearerSecret123 jwt=" + jwt + " spaced=" + spacedJWT + " seed=" + seed + " key=" + pem +
		" url=https://urlUserSecret:urlPasswordSecret@example.test/path?access_token=querySecret123&mode=normal"
	for _, format := range []string{"json", "logfmt"} {
		t.Run(format, func(t *testing.T) {
			logger, output, bus := redactionLogger(t, format, slog.String("cell", "gru"), slog.String("AUTHORIZATION", "staticSecret123"))
			logger = logger.With("component", "placement", "Cookie", "scopedSecret123").WithGroup("request")
			logger.Warn(freeText,
				"error", errors.New(freeText),
				"details", freeText,
				"pAsS_wOrD", "passwordSecret123", "access-key", "accessKeySecret123",
				"client_credential", "credentialSecret123", "Session-ID", "sessionSecret123",
				"nested", slog.GroupValue(slog.String("private-key", "privateKeySecret123")),
			)
			logger.WithGroup("client-secrets").Warn("sensitive group", "innocent", "groupSecret123")
			logger.Warn("nested sensitive group", slog.Group("auth_token", "innocent", "nestedGroupSecret123"))
			assertNoLogSecrets(t, output, bus, "bearerSecret123", jwt, "signatureSecret123", spacedJWT, "spacedJWTSecret123", seed, "pemPayloadSecret123",
				"urlUserSecret", "urlPasswordSecret", "querySecret123", "staticSecret123", "scopedSecret123",
				"passwordSecret123", "accessKeySecret123", "credentialSecret123", "sessionSecret123",
				"privateKeySecret123", "groupSecret123", "nestedGroupSecret123")
			if len(bus.Recent(0)) != 3 || !strings.Contains(output.String(), "mode=normal") {
				t.Fatalf("normal URL data or events lost: %s %+v", output, bus.Recent(0))
			}
			if strings.Contains(output.String(), logTruncatedKey) {
				t.Fatalf("redaction alone should not claim truncation: %s", output)
			}
		})
	}
}
