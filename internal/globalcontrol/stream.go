package globalcontrol

import (
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// StreamName is the global stream in the home region and its mirror name.
	StreamName = protocol.GlobalControlStream
	contract   = "global-control-v1"
	apiTimeout = 5 * time.Second
	// mirrorHeartbeat is the only heartbeat the flow-control ack policy
	// accepts; a mirror treats a longer silence as a stalled source.
	mirrorHeartbeat = time.Second
	// mirrorMaxAckPending bounds unacknowledged records in flight to a peer.
	mirrorMaxAckPending = 1024
	// mirrorConsumerPrefix names every peer's durable mirror consumer.
	mirrorConsumerPrefix = "global-mirror-"
)

func verifyHome(actual jetstream.StreamConfig, replicas int) error {
	if actual.Name != StreamName || !slices.Equal(actual.Subjects, []string{protocol.GlobalStateStreamSubject()}) ||
		actual.Mirror != nil || len(actual.Sources) != 0 || actual.Replicas != replicas ||
		// A transform would store records outside the subjects reads use.
		actual.SubjectTransform != nil ||
		actual.Storage != jetstream.FileStorage || actual.Retention != jetstream.LimitsPolicy ||
		!actual.DenyDelete || !actual.DenyPurge || actual.AllowDirect || actual.AllowRollup ||
		actual.MaxMsgs != -1 || actual.MaxBytes != -1 || actual.MaxMsgsPerSubject != -1 || actual.MaxAge != 0 ||
		actual.Metadata["terrascale-contract"] != contract || actual.Metadata["terrascale-role"] != "home" {
		return errors.New("global control stream is not the durable leader-read home stream")
	}
	return nil
}
