// Package functions runs one admitted tenant/function revision per worker process.
// SwarmKit owns worker processes; this package owns only bounded invocations.
package functions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

const (
	ABI               = release.FunctionABI
	RuntimeVersion    = "wazero-v1.12.0"
	MaxModuleBytes    = release.MaxFunctionModuleBytes
	MaxPayloadBytes   = 1 << 20
	MaxOutputBytes    = 1 << 20
	MaxMemoryPages    = 256
	MaxConcurrent     = 4
	InvocationTimeout = 2 * time.Second
)

var (
	ErrInvalid        = errors.New("invalid function invocation")
	ErrScope          = errors.New("function tenant or revision scope mismatch")
	ErrBusy           = errors.New("function worker concurrency exhausted")
	ErrOutputLimit    = errors.New("function output limit exceeded")
	ErrClosed         = errors.New("function worker closed")
	namePattern       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	invocationPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
)

// Manifest must arrive through signed release admission, never through a guest request.
// No production host capabilities are admitted by this first ABI.
type Manifest struct {
	ABI          string   `json:"abi"`
	TenantID     string   `json:"tenant_id"`
	FunctionID   string   `json:"function_id"`
	Revision     string   `json:"revision"`
	Digest       string   `json:"digest"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type Artifact struct {
	Manifest Manifest
	Module   []byte
}

// Invocation is encoded on guest stdin as JSON. Payload is base64 in that envelope;
// stdout is returned verbatim. Stderr is bounded and never included in results.
type Invocation struct {
	TenantID   string `json:"tenant_id"`
	FunctionID string `json:"function_id"`
	Revision   string `json:"revision"`
	ID         string `json:"id"`
	Trigger    string `json:"trigger"`
	Payload    []byte `json:"payload"`
}

type Result struct {
	InvocationID string `json:"invocation_id"`
	Revision     string `json:"revision"`
	Output       []byte `json:"output"`
}

// Invoker lets HTTP/queue boundaries consume the worker without owning its lifetime.
type Invoker interface {
	Manifest() Manifest
	Invoke(context.Context, Invocation) (Result, error)
}

func (m Manifest) Validate() error {
	digest, err := hex.DecodeString(m.Digest)
	if m.ABI != ABI || !entityid.Valid(m.TenantID) || !namePattern.MatchString(m.FunctionID) || !namePattern.MatchString(m.Revision) || err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != m.Digest {
		return fmt.Errorf("%w: ABI, identity or SHA-256 digest", ErrInvalid)
	}
	if len(m.Capabilities) != 0 {
		return fmt.Errorf("%w: unsupported host capabilities", ErrInvalid)
	}
	return nil
}

func (a Artifact) Validate() error {
	if err := a.Manifest.Validate(); err != nil {
		return err
	}
	if len(a.Module) == 0 || len(a.Module) > MaxModuleBytes {
		return fmt.Errorf("%w: module size", ErrInvalid)
	}
	sum := sha256.Sum256(a.Module)
	if hex.EncodeToString(sum[:]) != a.Manifest.Digest {
		return fmt.Errorf("%w: module digest mismatch", ErrInvalid)
	}
	return nil
}

func (in Invocation) Validate(m Manifest) error {
	if in.TenantID != m.TenantID || in.FunctionID != m.FunctionID || in.Revision != m.Revision {
		return ErrScope
	}
	if !invocationPattern.MatchString(in.ID) || (in.Trigger != "http" && in.Trigger != "queue") || len(in.Payload) > MaxPayloadBytes {
		return fmt.Errorf("%w: id, trigger or payload size", ErrInvalid)
	}
	return nil
}
