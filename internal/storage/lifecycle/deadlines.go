package lifecycle

import (
	"errors"
	"time"
)

// Deadlines bound every transitional phase. Zero fields use the defaults.
type Deadlines struct {
	Creating   time.Duration `json:"creating,omitzero"`
	Attaching  time.Duration `json:"attaching,omitzero"`
	Formatting time.Duration `json:"formatting,omitzero"`
	Resizing   time.Duration `json:"resizing,omitzero"`
	Detaching  time.Duration `json:"detaching,omitzero"`
	Deleting   time.Duration `json:"deleting,omitzero"`
	// MaxAttachRetries bounds same-host attach retries before the remediation
	// escalates to host replacement.
	MaxAttachRetries uint32 `json:"max_attach_retries,omitzero"`
}

// DefaultDeadlines are conservative OCI service-level bounds: an OCI
// paravirtualized attach normally settles in well under two minutes, so ten
// minutes in ATTACHING is a real stall rather than a slow API.
func DefaultDeadlines() Deadlines {
	return Deadlines{
		Creating:         15 * time.Minute,
		Attaching:        10 * time.Minute,
		Formatting:       30 * time.Minute,
		Resizing:         30 * time.Minute,
		Detaching:        10 * time.Minute,
		Deleting:         30 * time.Minute,
		MaxAttachRetries: 2,
	}
}

const maxDeadline = 24 * time.Hour

// WithDefaults fills zero fields from DefaultDeadlines.
func (deadlines Deadlines) WithDefaults() Deadlines {
	defaults := DefaultDeadlines()
	fill := func(value *time.Duration, fallback time.Duration) {
		if *value == 0 {
			*value = fallback
		}
	}
	fill(&deadlines.Creating, defaults.Creating)
	fill(&deadlines.Attaching, defaults.Attaching)
	fill(&deadlines.Formatting, defaults.Formatting)
	fill(&deadlines.Resizing, defaults.Resizing)
	fill(&deadlines.Detaching, defaults.Detaching)
	fill(&deadlines.Deleting, defaults.Deleting)
	if deadlines.MaxAttachRetries == 0 {
		deadlines.MaxAttachRetries = defaults.MaxAttachRetries
	}
	return deadlines
}

// Validate rejects negative or unbounded deadlines.
func (deadlines Deadlines) Validate() error {
	for _, value := range []time.Duration{
		deadlines.Creating, deadlines.Attaching, deadlines.Formatting,
		deadlines.Resizing, deadlines.Detaching, deadlines.Deleting,
	} {
		if value < 0 || value > maxDeadline {
			return errors.New("retained volume lifecycle deadlines must be between zero and 24h")
		}
	}
	if deadlines.MaxAttachRetries > 10 {
		return errors.New("retained volume attach retries must not exceed 10")
	}
	return nil
}

// For returns the deadline of phase, or zero for non-transitional phases.
func (deadlines Deadlines) For(phase Phase) time.Duration {
	deadlines = deadlines.WithDefaults()
	switch phase {
	case Creating:
		return deadlines.Creating
	case Attaching:
		return deadlines.Attaching
	case Formatting:
		return deadlines.Formatting
	case Resizing:
		return deadlines.Resizing
	case Detaching:
		return deadlines.Detaching
	case Deleting:
		return deadlines.Deleting
	default:
		return 0
	}
}

// Expired reports whether a transitional state has outlived its deadline. A
// zero Since or a Since in the future is treated as expired so a corrupt or
// clock-skewed record cannot wait forever.
func (deadlines Deadlines) Expired(state State, now time.Time) bool {
	limit := deadlines.For(state.Phase)
	if limit == 0 {
		return false
	}
	if state.Since.IsZero() || state.Since.After(now.Add(time.Minute)) {
		return true
	}
	return now.Sub(state.Since) >= limit
}

const ()
