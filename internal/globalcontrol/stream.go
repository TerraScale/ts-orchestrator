package globalcontrol

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
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

// HomeStreamConfig is the writable global stream in the home region. Like the
// regional control log it is durable, append-only and leader-read.
func HomeStreamConfig(replicas int) jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:              StreamName,
		Description:       "Fenced global region roster and database directory",
		Subjects:          []string{protocol.GlobalStateStreamSubject()},
		Retention:         jetstream.LimitsPolicy,
		MaxConsumers:      -1,
		MaxMsgs:           -1,
		MaxBytes:          -1,
		MaxMsgsPerSubject: -1,
		MaxMsgSize:        maxMessageBytes,
		Storage:           jetstream.FileStorage,
		Replicas:          replicas,
		DenyDelete:        true,
		DenyPurge:         true,
		AllowDirect:       false,
		Metadata:          map[string]string{"terrascale-contract": contract, "terrascale-role": "home"},
	}
}

// MirrorStreamConfig is cell's read-only mirror of the home region's stream.
// It sources through the durable consumer the home region created for cell
// (MirrorConsumerConfig), so the mirror only ever resets that one consumer
// through the link API prefix and receives on its fixed delivery subject. It
// never asks the home region to create a consumer or pick a delivery subject.
func MirrorStreamConfig(home, cell string, replicas int) jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:         StreamName,
		Description:  "Read-only mirror of the home region's global control stream",
		Retention:    jetstream.LimitsPolicy,
		MaxConsumers: -1, MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1,
		Storage:     jetstream.FileStorage,
		Replicas:    replicas,
		DenyDelete:  true,
		DenyPurge:   true,
		AllowDirect: false,
		Mirror: &jetstream.StreamSource{
			Name:     StreamName,
			External: &jetstream.ExternalStream{APIPrefix: protocol.InterRegionJSAPIPrefix(home)},
			Consumer: &jetstream.StreamConsumerSource{
				Name:           protocol.GlobalMirrorConsumer(cell),
				DeliverSubject: protocol.InterRegionGlobalDeliverSubject(cell),
			},
		},
		Metadata: map[string]string{"terrascale-contract": contract, "terrascale-role": "mirror", "terrascale-home": home},
	}
}

// MirrorConsumerConfig is the durable push consumer the home region creates
// on its global stream for one peer's mirror. The home region alone chooses
// its delivery subject, the peer's fixed contract subject; acknowledgements
// ride on flow-control replies, so the peer needs no ack subject either.
func MirrorConsumerConfig(peer string, replicas int) jetstream.ConsumerConfig {
	return jetstream.ConsumerConfig{
		Durable:        protocol.GlobalMirrorConsumer(peer),
		Description:    "Durable source of a peer region's read-only global mirror",
		DeliverSubject: protocol.InterRegionGlobalDeliverSubject(peer),
		DeliverPolicy:  jetstream.DeliverAllPolicy,
		AckPolicy:      jetstream.AckFlowControlPolicy,
		FlowControl:    true,
		IdleHeartbeat:  mirrorHeartbeat,
		MaxAckPending:  mirrorMaxAckPending,
		Replicas:       replicas,
		Metadata:       map[string]string{"terrascale-contract": contract, "terrascale-role": "mirror-source", "terrascale-peer": peer},
	}
}

func verifyMirrorConsumer(actual jetstream.ConsumerConfig, peer string, replicas int) error {
	expected := MirrorConsumerConfig(peer, replicas)
	if actual.Durable != expected.Durable || actual.DeliverSubject != expected.DeliverSubject ||
		actual.DeliverGroup != "" || actual.DeliverPolicy != expected.DeliverPolicy ||
		actual.AckPolicy != expected.AckPolicy || !actual.FlowControl ||
		actual.FilterSubject != "" || len(actual.FilterSubjects) != 0 || actual.Replicas != replicas ||
		actual.Metadata["terrascale-contract"] != contract || actual.Metadata["terrascale-role"] != "mirror-source" ||
		actual.Metadata["terrascale-peer"] != peer {
		return fmt.Errorf("global mirror consumer for %q is not the home-created contract consumer", peer)
	}
	return nil
}

// ensureMirrorConsumers creates or verifies the durable mirror consumer of
// every peer. A consumer whose delivery subject or policy drifted is an error,
// never silently rewritten, because it would deliver outside the contract.
func ensureMirrorConsumers(ctx context.Context, stream jetstream.Stream, peers []string, replicas int) error {
	for _, peer := range peers {
		config := MirrorConsumerConfig(peer, replicas)
		createCtx, cancel := context.WithTimeout(ctx, apiTimeout)
		consumer, err := stream.CreatePushConsumer(createCtx, config)
		cancel()
		if errors.Is(err, jetstream.ErrConsumerExists) {
			lookupCtx, lookupCancel := context.WithTimeout(ctx, apiTimeout)
			consumer, err = stream.PushConsumer(lookupCtx, config.Durable)
			lookupCancel()
		}
		if err != nil {
			return fmt.Errorf("create global mirror consumer for %q: %w", peer, err)
		}
		if err := verifyMirrorConsumer(consumer.CachedInfo().Config, peer, replicas); err != nil {
			return err
		}
	}
	return nil
}

// removeStaleMirrorConsumers deletes every global mirror consumer whose peer
// is no longer in peers, so a removed region's durable consumer neither keeps
// delivering home records to its contract subject nor pins resources. Only
// consumers named like a mirror source are touched.
func removeStaleMirrorConsumers(ctx context.Context, stream jetstream.Stream, peers []string) error {
	keep := make(map[string]bool, len(peers))
	for _, peer := range peers {
		keep[protocol.GlobalMirrorConsumer(peer)] = true
	}
	listCtx, cancel := context.WithTimeout(ctx, apiTimeout)
	lister := stream.ConsumerNames(listCtx)
	var stale []string
	for name := range lister.Name() {
		if strings.HasPrefix(name, mirrorConsumerPrefix) && !keep[name] {
			stale = append(stale, name)
		}
	}
	err := lister.Err()
	cancel()
	if err != nil {
		return fmt.Errorf("list global mirror consumers: %w", err)
	}
	for _, name := range stale {
		deleteCtx, deleteCancel := context.WithTimeout(ctx, apiTimeout)
		err := stream.DeleteConsumer(deleteCtx, name)
		deleteCancel()
		if err != nil && !errors.Is(err, jetstream.ErrConsumerNotFound) {
			return fmt.Errorf("delete stale global mirror consumer %q: %w", name, err)
		}
	}
	return nil
}

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

func verifyMirror(actual jetstream.StreamConfig, home, cell string, replicas int) error {
	expected := MirrorStreamConfig(home, cell, replicas)
	if actual.Name != StreamName || len(actual.Subjects) != 0 || len(actual.Sources) != 0 ||
		actual.Mirror == nil || actual.Mirror.Name != StreamName || actual.Mirror.External == nil ||
		actual.Mirror.External.APIPrefix != expected.Mirror.External.APIPrefix ||
		actual.Mirror.External.DeliverPrefix != "" || actual.Mirror.Consumer == nil ||
		*actual.Mirror.Consumer != *expected.Mirror.Consumer ||
		actual.Mirror.FilterSubject != "" || len(actual.Mirror.SubjectTransforms) != 0 ||
		// A mirror starting past the first record never copies the ones
		// before its start.
		actual.Mirror.OptStartSeq != 0 || actual.Mirror.OptStartTime != nil ||
		actual.Replicas != replicas || actual.Storage != jetstream.FileStorage ||
		!actual.DenyDelete || !actual.DenyPurge || actual.AllowDirect || actual.AllowRollup || actual.MaxAge != 0 ||
		// Finite limits would let the mirror discard home records.
		actual.MaxMsgs != -1 || actual.MaxBytes != -1 || actual.MaxMsgsPerSubject != -1 ||
		actual.Metadata["terrascale-contract"] != contract || actual.Metadata["terrascale-role"] != "mirror" ||
		actual.Metadata["terrascale-home"] != home {
		return errors.New("global control mirror is not the read-only mirror of the home stream")
	}
	return nil
}

func openStream(ctx context.Context, js jetstream.JetStream, config jetstream.StreamConfig,
	verify func(jetstream.StreamConfig) error,
) (jetstream.Stream, error) {
	if js == nil {
		return nil, errors.New("JetStream is required")
	}
	createCtx, cancel := context.WithTimeout(ctx, apiTimeout)
	stream, err := js.CreateStream(createCtx, config)
	cancel()
	created := err == nil
	if err != nil {
		if !errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
			return nil, fmt.Errorf("create global control stream: %w", err)
		}
		lookupCtx, lookupCancel := context.WithTimeout(ctx, apiTimeout)
		stream, err = js.Stream(lookupCtx, StreamName)
		lookupCancel()
		if err != nil {
			return nil, fmt.Errorf("lookup global control stream: %w", err)
		}
	}
	info, err := inspectStream(ctx, stream, created)
	if err != nil {
		return nil, fmt.Errorf("inspect global control stream: %w", err)
	}
	if err := verify(info.Config); err != nil {
		return nil, err
	}
	// A home stream created before relayed documents bounded messages at
	// 64 KiB; the bound is raised in place.
	if limit := info.Config.MaxMsgSize; limit > 0 && limit < config.MaxMsgSize {
		raised := info.Config
		raised.MaxMsgSize = config.MaxMsgSize
		updateCtx, cancel := context.WithTimeout(ctx, apiTimeout)
		stream, err = js.UpdateStream(updateCtx, raised)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("raise the global control message bound: %w", err)
		}
	}
	return stream, nil
}

// createdStreamConvergence bounds how long a just-created stream may answer
// Info with stream-not-found while its metadata leader converges.
var createdStreamConvergence = 10 * time.Second

// inspectStream reads the stream's info. A new replicated stream can be
// visible to CreateStream before its metadata leader serves Info, which then
// answers stream-not-found for a moment; only for a stream this call created
// is that retried, briefly and cancelably, as authority's control stream
// opener does.
func inspectStream(ctx context.Context, stream jetstream.Stream, created bool) (*jetstream.StreamInfo, error) {
	window, cancel := context.WithTimeout(ctx, createdStreamConvergence)
	defer cancel()
	for {
		infoCtx, infoCancel := context.WithTimeout(window, apiTimeout)
		info, err := stream.Info(infoCtx)
		infoCancel()
		if err == nil || !created || !errors.Is(err, jetstream.ErrStreamNotFound) {
			return info, err
		}
		select {
		case <-window.Done():
			return nil, err
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// OpenMirror creates or verifies cell's read-only mirror of home's stream and
// returns a Reader over it. It never creates a writable stream.
func OpenMirror(ctx context.Context, js jetstream.JetStream, home, cell string, replicas int) (*Reader, error) {
	if !cellToken.MatchString(home) || !cellToken.MatchString(cell) || home == cell {
		return nil, errors.New("global mirror needs distinct home and regional cells")
	}
	stream, err := openStream(ctx, js, MirrorStreamConfig(home, cell, replicas), func(actual jetstream.StreamConfig) error {
		return verifyMirror(actual, home, cell, replicas)
	})
	if err != nil {
		return nil, err
	}
	return &Reader{stream: stream, mirror: true}, nil
}
