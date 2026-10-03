package rollout

import (
	"errors"
	"fmt"
	"time"
)

// DefaultSoak is how long a promoted seat must keep serving the candidate,
// without restarting, before the next seat is updated.
const DefaultSoak = 5 * time.Minute

// minSoakGap is the shortest host-report gap a soak tolerates, so a short
// window does not turn one missed host report into a failure.
const minSoakGap = time.Minute

// SoakSample is one observation of the seat that already runs the candidate.
type SoakSample struct {
	At             time.Time
	ArtifactDigest string
	OperationID    string
	Phase          string
	// Serving holds when the controller keeps the seat serving and, unless
	// the sample is a Gap, the host's current report proves it serves.
	Serving bool
	// ProcessPID is zero when the controller reports no live host process.
	ProcessPID int
	// Gap marks a sample without a current host report: the controller
	// fields are checked, but the process and its serving proof are unknown.
	Gap bool
}

// ErrSoakFailed marks a candidate that regressed after its serving proof.
var ErrSoakFailed = errors.New("candidate failed its soak")

// Soak gates the next seat on one promoted seat staying healthy for the
// whole window: same candidate and operation, still serving, and the same
// process as when the soak began. A failed soak is terminal; the caller
// treats the candidate as known bad. A gap in host reports is not a failure,
// but the window only completes on a reported sample, and a gap longer than
// the window (at least a minute) ends the soak with a transient error.
type Soak struct {
	Window   time.Duration
	Digest   string
	Promoted string // the update phase that proves the canary served
	first    *SoakSample
	last     time.Time
	// lastPID is the last nonzero process ID; zero means none seen yet.
	lastPID int
	// reported is when the last sample with a host report was taken, or
	// when the soak's gap began if none has been.
	reported time.Time
}

// Observe records one sample. It returns done once the window has elapsed
// with every sample healthy, or a terminal ErrSoakFailed error.
func (s *Soak) Observe(sample SoakSample) (bool, error) {
	if sample.ArtifactDigest != s.Digest || sample.Phase != s.Promoted || !sample.Serving {
		return false, Terminal(fmt.Errorf("%w: seat left %s serving (artifact %s, phase %s, serving %t)",
			ErrSoakFailed, s.Digest, sample.ArtifactDigest, sample.Phase, sample.Serving))
	}
	if s.first != nil && sample.OperationID != s.first.OperationID {
		return false, Terminal(fmt.Errorf("%w: seat operation changed from %s to %s",
			ErrSoakFailed, s.first.OperationID, sample.OperationID))
	}
	if !s.last.IsZero() && sample.At.Before(s.last) {
		return false, errors.New("soak samples went back in time")
	}
	s.last = sample.At
	if sample.Gap {
		if s.Window <= 0 {
			// A disabled soak checks only the controller's own fields.
			return true, nil
		}
		if s.reported.IsZero() {
			s.reported = sample.At
		}
		if gap := sample.At.Sub(s.reported); gap > max(s.Window, minSoakGap) {
			return false, Transient(fmt.Errorf("seat has had no current host report for %s during its soak", gap))
		}
		return false, nil
	}
	s.reported = sample.At
	// Zero is "no live process reported", not a process: it neither sets
	// nor breaks the baseline, so a reporting gap cannot hide a later
	// restart or fake one.
	if sample.ProcessPID != 0 {
		if s.lastPID != 0 && sample.ProcessPID != s.lastPID {
			return false, Terminal(fmt.Errorf("%w: seat process restarted (pid %d -> %d)",
				ErrSoakFailed, s.lastPID, sample.ProcessPID))
		}
		s.lastPID = sample.ProcessPID
	}
	if s.first == nil {
		first := sample
		s.first = &first
		return s.Window <= 0, nil
	}
	return !sample.At.Before(s.first.At.Add(s.Window)), nil
}

// Remaining is how long the soak still needs after its first sample.
func (s *Soak) Remaining(now time.Time) time.Duration {
	if s.first == nil {
		return s.Window
	}
	return max(0, s.first.At.Add(s.Window).Sub(now))
}
