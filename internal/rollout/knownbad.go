package rollout

import (
	"errors"
	"fmt"
	"time"
)

// KnownBad durably records a candidate that failed on a seat. A known-bad
// digest is never a prepare target again, neither as a new rollout nor as
// the "previous" artifact of a rollback, until a human removes the record.
type KnownBad struct {
	Digest      string    `json:"digest"`
	SeatID      string    `json:"seat_id"`
	OperationID string    `json:"operation_id"`
	Reason      string    `json:"reason"`
	RecordedAt  time.Time `json:"recorded_at"`
}

// Validate checks the record's identity fields.
func (k KnownBad) Validate() error {
	if !digestRE.MatchString(k.Digest) || k.SeatID == "" || k.Reason == "" || k.RecordedAt.IsZero() {
		return errors.New("known-bad record is incomplete")
	}
	return nil
}

// KnownBadSet answers membership for one deployment.
type KnownBadSet map[string]KnownBad

// Refuse returns a terminal error when digest is known bad.
func (set KnownBadSet) Refuse(digest string) error {
	if record, bad := set[digest]; bad {
		return Terminal(fmt.Errorf("%w: %s failed on seat %s (%s)", ErrKnownBad, digest, record.SeatID, record.Reason))
	}
	return nil
}
