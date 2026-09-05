package hostmanifest

import (
	"regexp"
	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

var tokenPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

const (
	maximumTokenLength = 63
)

// RequireToken enforces the bounded canonical token vocabulary
// shared by node identifiers and command identifiers.
func RequireToken(value, param, message string) (string, error) {
	if len(value) < 1 || len(value) > maximumTokenLength ||
		!tokenPattern.MatchString(value) {
		return "", &errs.Argument{Param: param, Message: message}
	}
	return value, nil
}
