package security

import (
	"context"
	"errors"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

const (
	maximumCommandReplayEntries = 64 * 1024
)

// CommandReplayKey is a content identity, not a signature identity. It is the
// SHA-256 hash of the canonical signed material, so a re-signing of the same
// command cannot bypass replay protection. Its bytes are never rendered.
type CommandReplayKey [32]byte

func (CommandReplayKey) String() string { return "<command-replay-key>" }

// CommandReplayKeyFor derives the replay identity from protocol-owned bytes.
func CommandReplayKeyFor(material protocol.CommandSignedMaterial) (CommandReplayKey, error) {
	digest, err := protocol.CommandSignedMaterialCodec.Hash(&material)
	if err != nil {
		return CommandReplayKey{}, err
	}
	return CommandReplayKey(digest), nil
}

// CommandReplayConsumeResult describes an atomic consume operation.
type CommandReplayConsumeResult int

const (
	CommandReplayConsumeRejected CommandReplayConsumeResult = iota
	CommandReplayConsumeConsumed
	CommandReplayConsumeAlreadyConsumed
)

func (r CommandReplayConsumeResult) String() string {
	switch r {
	case CommandReplayConsumeConsumed:
		return "Consumed"
	case CommandReplayConsumeAlreadyConsumed:
		return "AlreadyConsumed"
	case CommandReplayConsumeRejected:
		return "Rejected"
	default:
		return "Unknown"
	}
}

// CommandReplayStore is the durable boundary future runtimes can implement
// with a transactional KV/CAS operation. TryConsume must atomically claim key
// until expiresAt and must never retain it beyond its expiry.
type CommandReplayStore interface {
	TryConsume(key CommandReplayKey, expiresAt time.Time) (CommandReplayConsumeResult, error)
}

// MemoryCommandReplayStore is a bounded process-local replay store. It is
// suitable for one process lifetime and tests; a multi-instance runtime should
// supply a durable implementation of CommandReplayStore.
type MemoryCommandReplayStore struct {
	mu      sync.Mutex
	entries map[CommandReplayKey]time.Time
	maximum int
	now     func() time.Time
}

// NewMemoryCommandReplayStore constructs a bounded store using the system
// clock. Capacity is deliberately capped to prevent configuration accidents.
func NewMemoryCommandReplayStore(capacity int) (*MemoryCommandReplayStore, error) {
	return newMemoryCommandReplayStore(capacity, time.Now)
}

// NewMemoryCommandReplayStoreWithClock is deterministic and is useful to
// callers that own a test clock; production code should normally use the
// system-clock constructor.
func NewMemoryCommandReplayStoreWithClock(capacity int, now func() time.Time) (*MemoryCommandReplayStore, error) {
	return newMemoryCommandReplayStore(capacity, now)
}

func newMemoryCommandReplayStore(capacity int, now func() time.Time) (*MemoryCommandReplayStore, error) {
	if capacity < 1 || capacity > maximumCommandReplayEntries {
		return nil, errors.New("command replay capacity must be between one and 65536 entries")
	}
	if now == nil {
		return nil, errors.New("command replay clock is required")
	}
	return &MemoryCommandReplayStore{entries: make(map[CommandReplayKey]time.Time, capacity), maximum: capacity, now: now}, nil
}

// TryConsume atomically checks and inserts one command identity. An expired
// claim is rejected; cleanup occurs before capacity is evaluated.
func (s *MemoryCommandReplayStore) TryConsume(key CommandReplayKey, expiresAt time.Time) (CommandReplayConsumeResult, error) {
	if s == nil {
		return CommandReplayConsumeRejected, errors.New("command replay store is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	for existing, expiry := range s.entries {
		if !now.Before(expiry) {
			delete(s.entries, existing)
		}
	}
	if !expiresAt.After(now) {
		return CommandReplayConsumeRejected, errors.New("command replay expiry is invalid")
	}
	if _, found := s.entries[key]; found {
		return CommandReplayConsumeAlreadyConsumed, nil
	}
	if len(s.entries) >= s.maximum {
		return CommandReplayConsumeRejected, errors.New("command replay store capacity is exhausted")
	}
	s.entries[key] = expiresAt.UTC()
	return CommandReplayConsumeConsumed, nil
}

// Len is a bounded diagnostic useful to health checks. It returns no command
// identities or signatures.
func (s *MemoryCommandReplayStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	for key, expiry := range s.entries {
		if !now.Before(expiry) {
			delete(s.entries, key)
		}
	}
	return len(s.entries)
}

// CommandSecurityOutcome is the result of authentication plus the replay
// boundary. Denials are ordinary outcomes; infrastructure failures are errors.
type CommandSecurityOutcome int

const (
	CommandSecurityInvalidMaterial CommandSecurityOutcome = iota
	CommandSecurityNotYetValid
	CommandSecurityExpired
	CommandSecurityInvalidSignature
	CommandSecurityAccepted
	CommandSecurityReplayDetected
)

func (o CommandSecurityOutcome) String() string {
	switch o {
	case CommandSecurityInvalidMaterial:
		return "InvalidMaterial"
	case CommandSecurityNotYetValid:
		return "NotYetValid"
	case CommandSecurityExpired:
		return "Expired"
	case CommandSecurityInvalidSignature:
		return "InvalidSignature"
	case CommandSecurityAccepted:
		return "Accepted"
	case CommandSecurityReplayDetected:
		return "ReplayDetected"
	default:
		return "Unknown"
	}
}

// CommandSecurityBoundary composes the protocol signature verifier with an
// atomic replay store. It performs no command execution or side effects beyond
// claiming the replay key after successful authentication.
type CommandSecurityBoundary struct {
	verifier protocol.ICommandSignatureVerifier
	replay   CommandReplayStore
	skew     time.Duration
}

// NewCommandSecurityBoundary returns a future-runtime integration seam. The
// caller supplies the protocol verifier and durable replay implementation.
func NewCommandSecurityBoundary(verifier protocol.ICommandSignatureVerifier, replay CommandReplayStore, allowedClockSkew time.Duration) (*CommandSecurityBoundary, error) {
	if verifier == nil || replay == nil || allowedClockSkew < 0 {
		return nil, errors.New("command security boundary configuration is invalid")
	}
	return &CommandSecurityBoundary{verifier: verifier, replay: replay, skew: allowedClockSkew}, nil
}

// VerifyAndConsume applies validity-window checks, cryptographic verification,
// then the atomic replay claim in that order. Signature failures never consume
// replay capacity.
func (b *CommandSecurityBoundary) VerifyAndConsume(material protocol.CommandSignedMaterial, signature protocol.OpaqueSignature, now time.Time) (CommandSecurityOutcome, error) {
	return b.verifyAndConsume(context.Background(), material, signature, now)
}

// VerifyAndConsumeContext is the cancellation-aware form used by runtimes
// whose admission request has a bounded lifecycle. Cancellation is checked
// before cryptographic work and again before the replay claim.
func (b *CommandSecurityBoundary) VerifyAndConsumeContext(ctx context.Context, material protocol.CommandSignedMaterial, signature protocol.OpaqueSignature, now time.Time) (CommandSecurityOutcome, error) {
	if ctx == nil {
		return CommandSecurityInvalidMaterial, errors.New("command security context is required")
	}
	return b.verifyAndConsume(ctx, material, signature, now)
}

func (b *CommandSecurityBoundary) verifyAndConsume(ctx context.Context, material protocol.CommandSignedMaterial, signature protocol.OpaqueSignature, now time.Time) (CommandSecurityOutcome, error) {
	if b == nil || b.verifier == nil || b.replay == nil {
		return CommandSecurityInvalidMaterial, errors.New("command security boundary is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return CommandSecurityInvalidMaterial, err
	}
	if _, err := protocol.CommandSignedMaterialCodec.Hash(&material); err != nil {
		return CommandSecurityInvalidMaterial, nil
	}
	if material.ExpiresAt.Before(material.IssuedAt) {
		return CommandSecurityInvalidMaterial, nil
	}
	if material.IssuedAt.Sub(now) > b.skew {
		return CommandSecurityNotYetValid, nil
	}
	if now.Sub(material.ExpiresAt) > b.skew {
		return CommandSecurityExpired, nil
	}
	if timed, ok := b.verifier.(interface {
		VerifyAt(protocol.CommandSignedMaterial, protocol.OpaqueSignature, time.Time) protocol.VerificationOutcome
	}); ok {
		if timed.VerifyAt(material, signature, now) != protocol.VerificationOutcomeValid {
			return CommandSecurityInvalidSignature, nil
		}
	} else if b.verifier.Verify(material, signature) != protocol.VerificationOutcomeValid {
		return CommandSecurityInvalidSignature, nil
	}
	if err := ctx.Err(); err != nil {
		return CommandSecurityInvalidMaterial, err
	}
	key, err := CommandReplayKeyFor(material)
	if err != nil {
		return CommandSecurityInvalidMaterial, nil
	}
	claimed, err := b.replay.TryConsume(key, material.ExpiresAt)
	if err != nil {
		return CommandSecurityInvalidMaterial, err
	}
	switch claimed {
	case CommandReplayConsumeConsumed:
		return CommandSecurityAccepted, nil
	case CommandReplayConsumeAlreadyConsumed:
		return CommandSecurityReplayDetected, nil
	default:
		return CommandSecurityInvalidMaterial, errors.New("command replay claim was rejected")
	}
}

func (b *CommandSecurityBoundary) String() string {
	if b == nil {
		return "<nil>"
	}
	return "<command-security-boundary>"
}
