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
// boundary. A future multi-instance runtime should replace Replay with a
// durable CAS-backed implementation before admitting commands.
func (c *CommandIdentityConfiguration) Open() (*CommandIdentityRuntime, error) {
	if c == nil {
		return nil, errors.New("command identity configuration is required")
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
	replay, err := NewMemoryCommandReplayStore(maximumCommandReplayEntries)
	if err != nil {
		_ = signer.Close()
		return nil, err
	}
	return &CommandIdentityRuntime{Signer: signer, Verifier: verifier, Replay: replay}, nil
}

// CommandIdentityRuntime owns loaded cryptographic identities for one process
// lifetime. It does not execute commands or establish transport connections.
type CommandIdentityRuntime struct {
	Signer   *CommandSignatureSigner
	Verifier *CommandSignatureVerifier
	Replay   *MemoryCommandReplayStore
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
