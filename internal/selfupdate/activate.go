package selfupdate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	ActivationSchema = "terrascale.selfupdate.activation.v1"
	// MinProofWindow and MaxProofWindow bound the activation deadline: long
	// enough for a restart and cluster rejoin, short enough that a silent
	// bad build does not linger.
	MinProofWindow = 30 * time.Second
	MaxProofWindow = time.Hour
	maxKnownBad    = 256
)

// errUnreadableActivation marks an owned activation record that does not
// decode or validate, for example one written by a newer binary.
var errUnreadableActivation = errors.New("self-update activation record is unreadable")

var (
	unitRE         = regexp.MustCompile(`^[a-z0-9][a-z0-9@_.-]{0,127}\.service$`)
	activationIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Activation is the durable record of one pending A/B switch. It is written
// before the current link moves, so a crash between the two steps leaves a
// record the watchdog can always resolve.
type Activation struct {
	Schema       string    `json:"schema"`
	ActivationID string    `json:"activation_id"`
	Unit         string    `json:"unit"`
	Target       string    `json:"target"`
	Previous     string    `json:"previous"`
	ActivatedAt  time.Time `json:"activated_at"`
	Deadline     time.Time `json:"deadline"`
}

func (activation Activation) validate() error {
	if activation.Schema != ActivationSchema || !digestRE.MatchString(activation.Target) ||
		!digestRE.MatchString(activation.Previous) || activation.Target == activation.Previous ||
		!activationIDRE.MatchString(activation.ActivationID) || !unitRE.MatchString(activation.Unit) ||
		activation.ActivatedAt.IsZero() || !activation.Deadline.After(activation.ActivatedAt) ||
		activation.Deadline.Sub(activation.ActivatedAt) > MaxProofWindow {
		return fmt.Errorf("%w: activation record", ErrInvalid)
	}
	return nil
}

// Pending returns the pending activation, if any.
func (layout Layout) Pending() (Activation, bool, error) {
	data, exists, err := layout.pendingRecord()
	if err != nil || !exists {
		return Activation{}, false, err
	}
	activation, err := decodeActivation(data)
	if err != nil {
		return Activation{}, false, err
	}
	return activation, true, nil
}

// pendingRecord reads the owned activation record without decoding it.
func (layout Layout) pendingRecord() ([]byte, bool, error) {
	if err := layout.checkOwned(layout.activationPath(), false); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	data, err := readBounded(layout.activationPath(), maxStateBytes)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func decodeActivation(data []byte) (Activation, error) {
	var activation Activation
	if err := protocol.DecodeStrict(data, &activation, maxStateBytes); err != nil {
		return Activation{}, fmt.Errorf("%w: activation record: %w", errUnreadableActivation, err)
	}
	if err := activation.validate(); err != nil {
		return Activation{}, fmt.Errorf("%w: %w", errUnreadableActivation, err)
	}
	return activation, nil
}

// Activate records a pending activation of a staged release and flips the
// current link to it. The caller restarts unit afterwards. A second
// activation is refused while one is pending, unless it is the same target.
// The caller holds Layout.Lock.
func Activate(layout Layout, digest, unit string, now time.Time, window time.Duration) (Activation, error) {
	if window < MinProofWindow || window > MaxProofWindow || !unitRE.MatchString(unit) || now.IsZero() {
		return Activation{}, fmt.Errorf("%w: activation unit or proof window", ErrInvalid)
	}
	if pending, exists, err := layout.Pending(); err != nil {
		return Activation{}, err
	} else if exists {
		if pending.Target == digest && pending.Unit == unit {
			// A retry passes the same gates as a fresh activation: a crash
			// after a rollback marked the target known bad must not
			// re-activate it, and unverified bytes never become current.
			if !now.Before(pending.Deadline) {
				return Activation{}, fmt.Errorf("%w: activation %s passed its deadline; the watchdog resolves it", ErrInvalid, pending.ActivationID)
			}
			if knownBad, err := layout.KnownBad(); err != nil {
				return Activation{}, err
			} else if knownBad[digest] {
				return Activation{}, ErrKnownBad
			}
			if err := layout.VerifyRelease(digest); err != nil {
				return Activation{}, err
			}
			return pending, layout.flipCurrent(digest)
		}
		return Activation{}, fmt.Errorf("%w: activation %s is still pending", ErrInvalid, pending.ActivationID)
	}
	if knownBad, err := layout.KnownBad(); err != nil {
		return Activation{}, err
	} else if knownBad[digest] {
		return Activation{}, ErrKnownBad
	}
	previous, err := layout.Current()
	if err != nil {
		return Activation{}, err
	}
	if previous == "" {
		return Activation{}, fmt.Errorf("%w: seed the baked release before activating another", ErrInvalid)
	}
	if previous == digest {
		return Activation{}, fmt.Errorf("%w: release is already current", ErrInvalid)
	}
	for _, release := range []string{previous, digest} {
		if err := layout.VerifyRelease(release); err != nil {
			return Activation{}, err
		}
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return Activation{}, err
	}
	activation := Activation{
		Schema: ActivationSchema, ActivationID: hex.EncodeToString(id), Unit: unit,
		Target: digest, Previous: previous, ActivatedAt: now.UTC(), Deadline: now.UTC().Add(window),
	}
	encoded, err := protocol.EncodeJSON(activation)
	if err != nil {
		return Activation{}, err
	}
	if err := writeFileAtomic(layout.activationPath(), encoded, 0o644); err != nil {
		return Activation{}, err
	}
	if err := layout.flipCurrent(digest); err != nil {
		return activation, err
	}
	recordActivation(activation)
	return activation, nil
}

type knownBadState struct {
	Digests []string `json:"digests"`
}

// KnownBad returns the node-local set of releases that were rolled back.
// Stage and Activate refuse them, so a rejected build never returns.
func (layout Layout) KnownBad() (map[string]bool, error) {
	data, err := readBounded(layout.knownBadPath(), maxStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	var state knownBadState
	if err := protocol.DecodeStrict(data, &state, maxStateBytes); err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(state.Digests))
	for _, digest := range state.Digests {
		if !digestRE.MatchString(digest) {
			return nil, fmt.Errorf("%w: known-bad digest", ErrInvalid)
		}
		known[digest] = true
	}
	return known, nil
}

func (layout Layout) markKnownBad(digest string) error {
	data, err := readBounded(layout.knownBadPath(), maxStateBytes)
	var state knownBadState
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	default:
		if err := protocol.DecodeStrict(data, &state, maxStateBytes); err != nil {
			return err
		}
	}
	if slices.Contains(state.Digests, digest) {
		return nil
	}
	state.Digests = append(state.Digests, digest)
	if len(state.Digests) > maxKnownBad {
		state.Digests = state.Digests[len(state.Digests)-maxKnownBad:]
	}
	encoded, err := protocol.EncodeJSON(state)
	if err != nil {
		return err
	}
	return writeFileAtomic(layout.knownBadPath(), encoded, 0o644)
}
