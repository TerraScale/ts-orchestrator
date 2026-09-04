package control

import (
	"fmt"
	"net/url"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
)

// resolveCiRunnerNatsIdentityForOptions resolves and verifies the controller's
// CI runner account signer during option parsing. It retains no key bytes. The
// signer is opened by runtime composition when it is ready to issue a lease.
func resolveCiRunnerNatsIdentityForOptions(signingKeyFile, accountPublicKey string) (*CiRunnerNatsIdentityConfiguration, error) {
	identity, err := CiRunnerNatsIdentityConfigurationResolve(signingKeyFile, accountPublicKey)
	if err != nil {
		return nil, fmt.Errorf("CI runner NATS identity is invalid: %w", err)
	}
	if identity == nil {
		return nil, nil
	}

	path, err := NatsCredentialFile.Resolve(identity.SigningKeyFile, "TS_ORCH_CI_RUNNER_NATS_ACCOUNT_SIGNING_KEY_FILE")
	if err != nil {
		return nil, fmt.Errorf("CI runner NATS identity is invalid: %w", err)
	}
	issuer, err := NatsCredentialFile.PublicKey(path)
	if err != nil || !isAccountPublicKey(issuer) {
		return nil, fmt.Errorf("CI runner NATS identity is invalid: signing key must be an account NKey")
	}
	if identity.AccountPublicKey != nil && !isAccountPublicKey(*identity.AccountPublicKey) {
		return nil, fmt.Errorf("CI runner NATS identity is invalid: account public key is not an account NKey")
	}
	identity.SigningKeyFile = path
	return identity, nil
}

func isAccountPublicKey(value string) bool {
	return shared.NatsRequireAccountPublicKey(strings.TrimSpace(value), "") == nil
}

// String intentionally omits both the private path and public identity. The
// latter is not secret, but keeping the complete identity out of diagnostics
// makes accidental credential disclosure less likely and keeps this type's
// redaction contract stable.
func (c *CiRunnerNatsIdentityConfiguration) String() string {
	if c == nil {
		return "<nil>"
	}
	return "<ci-runner-nats-identity>"
}

// String provides a bounded, credential-free diagnostic projection. In
// particular, it does not delegate to fmt's struct formatting, which would
// expose configured paths and make adding a secret field unsafe by default.
func (o *OrchestratorOptions) String() string {
	if o == nil {
		return "<nil>"
	}
	return fmt.Sprintf("OrchestratorOptions{command=%s, cell=%q, nats_url=%q, replicas=%d, instance=%q, ci_runner_identity=%t, command_identity=%t}",
		o.Command.String(), o.Cell, redactedNatsURL(o.NatsURL), o.Replicas, o.Instance,
		o.CiRunnerNatsIdentity != nil, o.CommandIdentity != nil)
}

func redactedNatsURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err == nil && parsed.User != nil {
		parsed.User = url.User(parsed.User.Username())
		return parsed.String()
	}
	return raw
}
