package rollout

import (
	"context"
	"errors"
	"time"
)

// Class tells a rollout driver what an error permits.
type Class int

const (
	// ClassTerminal stops automation until a human reviews the rollout. It is
	// the default for any unclassified error.
	ClassTerminal Class = iota
	// ClassTransient may be retried against the same pinned candidate.
	ClassTransient
)

type classified struct {
	err   error
	class Class
}

func (c classified) Error() string { return c.err.Error() }
func (c classified) Unwrap() error { return c.err }

// Transient marks err as safe to retry with the same candidate: transport
// failures, a controller leader change, a peer that is briefly not serving,
// or an outcome wait that ended while the seat was still prepared.
func Transient(err error) error {
	if err == nil {
		return nil
	}
	return classified{err: err, class: ClassTransient}
}

// Terminal marks err as requiring human review: a held candidate or
// rollback, an admission rejection, a digest mismatch, a known-bad or
// incompatible candidate.
func Terminal(err error) error {
	if err == nil {
		return nil
	}
	return classified{err: err, class: ClassTerminal}
}

// Classify returns the outermost explicit class of err. Unclassified errors
// are terminal so that automation fails closed.
func Classify(err error) Class {
	var marked classified
	if errors.As(err, &marked) {
		return marked.class
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ClassTransient
	}
	return ClassTerminal
}

// IsTransient reports whether err may be retried.
func IsTransient(err error) bool { return err != nil && Classify(err) == ClassTransient }

// Backoff is a bounded exponential retry schedule.
type Backoff struct {
	Initial  time.Duration
	Max      time.Duration
	Attempts int
}

// Delay returns the wait before retry attempt (1-based) and whether that
// attempt is still allowed.
func (b Backoff) Delay(attempt int) (time.Duration, bool) {
	if attempt < 1 || attempt > b.Attempts || b.Initial <= 0 {
		return 0, false
	}
	delay := b.Initial
	for range attempt - 1 {
		delay *= 2
		if b.Max > 0 && delay >= b.Max {
			return b.Max, true
		}
	}
	if b.Max > 0 && delay > b.Max {
		delay = b.Max
	}
	return delay, true
}
