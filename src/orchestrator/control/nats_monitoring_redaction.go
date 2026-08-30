// Port of src/TerraScale.Orchestrator/Messaging/NatsMonitoringRedaction.cs.
package control

import (
	"errors"
	"regexp"
)

// NatsMonitoringCorrelation mirrors the C# record: redacted correlation
// metadata for NATS monitoring logs and traces.
type NatsMonitoringCorrelation struct {
	CorrelationToken string
	RedactedSummary  string
}

// NewNatsMonitoringCorrelation mirrors the C# constructor.
func NewNatsMonitoringCorrelation(correlationToken, redactedSummary string) (*NatsMonitoringCorrelation, error) {
	if err := natsMonitoringValidateToken(correlationToken); err != nil {
		return nil, err
	}

	return &NatsMonitoringCorrelation{
		CorrelationToken: correlationToken,
		RedactedSummary:  NatsMonitoringRedaction.Sanitize(redactedSummary),
	}, nil
}

func natsMonitoringValidateToken(token string) error {
	if len(token) < 8 || len(token) > 64 {
		return errors.New("The correlation token must be a bounded lowercase alphanumeric token.")
	}

	for index := 0; index < len(token); index++ {
		character := token[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}

		return errors.New("The correlation token must be a bounded lowercase alphanumeric token.")
	}

	return nil
}

// NatsMonitoringRedactionRedactedPlaceholder mirrors the C# constant: the
// bounded replacement for any detected secret-bearing span.
const NatsMonitoringRedactionRedactedPlaceholder = "[redacted]"

// natsMonitoringMaximumSummaryLength mirrors the C# private bound.
const natsMonitoringMaximumSummaryLength = 256

var (
	natsMonitoringPemBlockRegex = regexp.MustCompile(
		`-----BEGIN [A-Z ]*KEY-----[\s\S]*?-----END [A-Z ]*KEY-----`)
	natsMonitoringJwtRegex = regexp.MustCompile(
		`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{16,}`)
	natsMonitoringNkeySeedRegex = regexp.MustCompile(`\bS[UAOPSC][A-Z2-7]{40,}\b`)
	natsMonitoringBearerRegex   = regexp.MustCompile(
		`(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	natsMonitoringCredentialAssignmentRegex = regexp.MustCompile(
		`(?i)(?:password|secret|token|apikey|api_key|nkey|seed)["']?\s*[:=]\s*["']?[^\s,"'}]{4,}`)
)

// NatsMonitoringRedaction mirrors the C# static class: the single redaction
// boundary for NATS monitoring output.
var NatsMonitoringRedaction natsMonitoringRedaction

type natsMonitoringRedaction struct{}

// Sanitize mirrors the C# Sanitize: removes secret-bearing spans and bounds
// the length. If a span cannot be proven clean it is replaced, never passed
// through.
func (natsMonitoringRedaction) Sanitize(value string) string {
	sanitized := natsMonitoringPemBlockRegex.ReplaceAllString(
		value, NatsMonitoringRedactionRedactedPlaceholder)
	sanitized = natsMonitoringJwtRegex.ReplaceAllString(
		sanitized, NatsMonitoringRedactionRedactedPlaceholder)
	sanitized = natsMonitoringNkeySeedRegex.ReplaceAllString(
		sanitized, NatsMonitoringRedactionRedactedPlaceholder)
	sanitized = natsMonitoringBearerRegex.ReplaceAllString(
		sanitized, NatsMonitoringRedactionRedactedPlaceholder)
	sanitized = natsMonitoringCredentialAssignmentRegex.ReplaceAllString(
		sanitized, NatsMonitoringRedactionRedactedPlaceholder)

	if len(sanitized) <= natsMonitoringMaximumSummaryLength {
		return sanitized
	}

	return sanitized[:natsMonitoringMaximumSummaryLength]
}

// ContainsSecretMaterial mirrors the C# ContainsSecretMaterial: true when the
// value contains material the monitoring contract must never emit.
func (natsMonitoringRedaction) ContainsSecretMaterial(value string) bool {
	if value == "" {
		return false
	}

	return natsMonitoringPemBlockRegex.MatchString(value) ||
		natsMonitoringJwtRegex.MatchString(value) ||
		natsMonitoringNkeySeedRegex.MatchString(value) ||
		natsMonitoringBearerRegex.MatchString(value) ||
		natsMonitoringCredentialAssignmentRegex.MatchString(value)
}
