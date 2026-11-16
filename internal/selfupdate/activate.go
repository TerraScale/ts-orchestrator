package selfupdate

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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

// ErrUnreadableActivation marks an owned activation record that does not
// decode or validate, for example one written by a newer binary.
var ErrUnreadableActivation = errors.New("self-update activation record is unreadable")

var (
	unitRE = regexp.MustCompile(`^[a-z0-9][a-z0-9@_.-]{0,127}\.service$`)
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
		!entityid.Valid(activation.ActivationID) || !unitRE.MatchString(activation.Unit) ||
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

// RecoveryActivation reads only rollback destinations from an owned unreadable
// record. The caller must authenticate the predecessor before any root effect.
func (layout Layout) RecoveryActivation() (Activation, error) {
	data, exists, err := layout.pendingRecord()
	if err != nil || !exists {
		return Activation{}, errors.Join(ErrInvalid, err)
	}
	if _, err := decodeActivation(data); !errors.Is(err, ErrUnreadableActivation) {
		return Activation{}, ErrInvalid
	}
	var pins struct {
		Target   string `json:"target"`
		Previous string `json:"previous"`
		Unit     string `json:"unit"`
	}
	if err := json.Unmarshal(data, &pins); err != nil ||
		!digestRE.MatchString(pins.Target) || !digestRE.MatchString(pins.Previous) ||
		pins.Target == pins.Previous || !unitRE.MatchString(pins.Unit) {
		return Activation{}, errors.Join(ErrUnreadableActivation, err)
	}
	return Activation{Target: pins.Target, Previous: pins.Previous, Unit: pins.Unit}, nil
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
		return Activation{}, fmt.Errorf("%w: activation record: %w", ErrUnreadableActivation, err)
	}
	if err := activation.validate(); err != nil {
		return Activation{}, fmt.Errorf("%w: %w", ErrUnreadableActivation, err)
	}
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
