package rollout

import (
	"errors"
	"fmt"
	"time"
)

// DefaultSoak is how long a promoted seat must keep serving the candidate,
// without restarting, before the next seat is updated.
const DefaultSoak = 5 * time.Minute

// SoakSample is one observation of the seat that already runs the candidate.
type SoakSample struct {
	At             time.Time
	ArtifactDigest string
	OperationID    string
	Phase          string
	Serving        bool
	// ProcessPID is zero when the controller reports no live host process.
	ProcessPID int
}

// ErrSoakFailed marks a candidate that regressed after its serving proof.
var ErrSoakFailed = errors.New("candidate failed its soak")

// Soak gates the next seat on one promoted seat staying healthy for the
// whole window: same candidate and operation, still serving, and the same
// process as when the soak began. A failed soak is terminal; the caller
// treats the candidate as known bad.
type Soak struct {
	Window   time.Duration
	Digest   string
	Promoted string // the update phase that proves the canary served
	first    *SoakSample
	last     time.Time
}

// Observe records one sample. It returns done once the window has elapsed
// with every sample healthy, or a terminal ErrSoakFailed error.
func (s *Soak) Observe(sample SoakSample) (bool, error) {
	if sample.ArtifactDigest != s.Digest || sample.Phase != s.Promoted || !sample.Serving {
		return false, Terminal(fmt.Errorf("%w: seat left %s serving (artifact %s, phase %s, serving %t)",
			ErrSoakFailed, s.Digest, sample.ArtifactDigest, sample.Phase, sample.Serving))
	}
	if s.first == nil {
		first := sample
		s.first, s.last = &first, sample.At
		return s.Window <= 0, nil
	}
	if sample.OperationID != s.first.OperationID {
		return false, Terminal(fmt.Errorf("%w: seat operation changed from %s to %s",
			ErrSoakFailed, s.first.OperationID, sample.OperationID))
	}
	if s.first.ProcessPID != 0 && sample.ProcessPID != s.first.ProcessPID {
		return false, Terminal(fmt.Errorf("%w: seat process restarted (pid %d -> %d)",
			ErrSoakFailed, s.first.ProcessPID, sample.ProcessPID))
	}
	if sample.At.Before(s.last) {
		return false, errors.New("soak samples went back in time")
	}
	s.last = sample.At
	return !sample.At.Before(s.first.At.Add(s.Window)), nil
}

// Remaining is how long the soak still needs after its first sample.
func (s *Soak) Remaining(now time.Time) time.Duration {
	if s.first == nil {
		return s.Window
	}
	return max(0, s.first.At.Add(s.Window).Sub(now))
}
