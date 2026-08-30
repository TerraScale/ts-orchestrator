package security

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
)

// CommandIdentityConfiguration is the credential-reference seam for control
// runtime composition. It retains paths only; no key material is loaded until
// Open is called.
type CommandIdentityConfiguration struct {
	SigningKeyFile string
	TrustKeyFiles  []string
}

// CommandIdentityConfigurationResolve captures bounded path configuration.
// The trust list uses the platform path-list separator and accepts one to four
// entries. An entirely empty configuration resolves to nil.
func CommandIdentityConfigurationResolve(signingKeyFile, trustKeyFiles string) (*CommandIdentityConfiguration, error) {
	signing := strings.TrimSpace(signingKeyFile)
	trust := strings.TrimSpace(trustKeyFiles)
	if signing == "" && trust == "" {
		return nil, nil
	}
	var paths []string
	if trust != "" {
		parts := strings.Split(trust, string(filepath.ListSeparator))
		if len(parts) < 1 || len(parts) > maximumCommandTrustKeys {
			return nil, errors.New("command trust key configuration must contain one to four paths")
		}
		seen := make(map[string]struct{}, len(parts))
		for _, part := range parts {
			if strings.TrimSpace(part) == "" {
				return nil, errors.New("command trust key configuration contains an empty path")
			}
			absolute, err := filepath.Abs(strings.TrimSpace(part))
			if err != nil {
				return nil, errors.New("command trust key path is invalid")
			}
			if _, exists := seen[absolute]; exists {
				return nil, errors.New("command trust key configuration contains duplicate paths")
			}
			seen[absolute] = struct{}{}
			paths = append(paths, absolute)
		}
	}
	absSigning := ""
	if signing != "" {
		var err error
		absSigning, err = filepath.Abs(signing)
		if err != nil {
			return nil, errors.New("command signing credential path is invalid")
		}
	}
	return &CommandIdentityConfiguration{SigningKeyFile: absSigning, TrustKeyFiles: paths}, nil
}

func (c *CommandIdentityConfiguration) String() string {
	if c == nil {
		return "<nil>"
	}
	return "<command-identity-configuration>"
}

// Open loads the configured identities and creates a process-local replay
// boundary. It is intentionally suitable only for single-process tools and
// tests. Multi-instance production composition must call OpenWithReplay with
// an explicitly durable CAS-backed implementation.
func (c *CommandIdentityConfiguration) Open() (*CommandIdentityRuntime, error) {
	replay, err := NewMemoryCommandReplayStore(maximumCommandReplayEntries)
	if err != nil {
		return nil, err
	}
	return c.OpenWithReplay(replay)
}

// OpenWithReplay loads identities while retaining the caller-owned replay
// implementation. The store is never replaced with memory, which prevents a
// production process from accidentally losing replay protection at restart.
func (c *CommandIdentityConfiguration) OpenWithReplay(replay CommandReplayStore) (*CommandIdentityRuntime, error) {
	if c == nil {
		return nil, errors.New("command identity configuration is required")
	}
	if replay == nil {
		return nil, errors.New("command replay store is required")
	}
	var signer *CommandSignatureSigner
	var verifier *CommandSignatureVerifier
	var err error
	if c.SigningKeyFile != "" {
		signer, err = LoadCommandSignatureSignerPEM(c.SigningKeyFile)
		if err != nil {
			return nil, err
		}
	}
	if len(c.TrustKeyFiles) > 0 {
		verifier, err = LoadCommandSignatureVerifierPEM(c.TrustKeyFiles)
		if err != nil {
			_ = signer.Close()
			return nil, err
		}
	}
	return &CommandIdentityRuntime{Signer: signer, Verifier: verifier, Replay: replay}, nil
}

// OpenForMultiInstanceProduction is the fail-closed composition entry point.
// In particular, passing a MemoryCommandReplayStore returns an error before
// credentials are loaded or any subscriber can be started.
func (c *CommandIdentityConfiguration) OpenForMultiInstanceProduction(replay CommandReplayStore) (*CommandIdentityRuntime, error) {
	if err := RequireDurableCommandReplayStore(replay); err != nil {
		return nil, err
	}
	return c.OpenWithReplay(replay)
}

// CommandIdentityRuntime owns loaded cryptographic identities for one process
// lifetime. It does not execute commands or establish transport connections.
type CommandIdentityRuntime struct {
	Signer   *CommandSignatureSigner
	Verifier *CommandSignatureVerifier
	Replay   CommandReplayStore
	close    sync.Once
}

func (r *CommandIdentityRuntime) String() string {
	if r == nil {
		return "<nil>"
	}
	return "<command-identity-runtime>"
}

func (r *CommandIdentityRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.close.Do(func() {
		if r.Signer != nil {
			_ = r.Signer.Close()
		}
	})
	return nil
}

func (r *CommandIdentityRuntime) Dispose() error { return r.Close() }
