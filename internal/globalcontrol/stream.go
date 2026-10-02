package globalcontrol

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// StreamName is the global stream in the home region and its mirror name.
	StreamName = protocol.GlobalControlStream
	contract   = "global-control-v1"
	apiTimeout = 5 * time.Second
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
		MaxMsgSize:        maxRecordBytes,
		Storage:           jetstream.FileStorage,
		Replicas:          replicas,
		DenyDelete:        true,
		DenyPurge:         true,
		AllowDirect:       false,
		Metadata:          map[string]string{"terrascale-contract": contract, "terrascale-role": "home"},
	}
}

// MirrorStreamConfig is cell's read-only mirror of the home region's stream.
// It reaches the home region only through the interregion contract subjects:
// the linked consumer-create prefix and the cell's own delivery prefix.
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
		Mirror: &jetstream.StreamSource{Name: StreamName, External: &jetstream.ExternalStream{
			APIPrefix:     protocol.InterRegionJSAPIPrefix(home),
			DeliverPrefix: protocol.InterRegionGlobalDeliverPrefix(cell),
		}},
		Metadata: map[string]string{"terrascale-contract": contract, "terrascale-role": "mirror", "terrascale-home": home},
	}
}

func verifyHome(actual jetstream.StreamConfig, replicas int) error {
	if actual.Name != StreamName || !slices.Equal(actual.Subjects, []string{protocol.GlobalStateStreamSubject()}) ||
		actual.Mirror != nil || len(actual.Sources) != 0 || actual.Replicas != replicas ||
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
		actual.Mirror.External.DeliverPrefix != expected.Mirror.External.DeliverPrefix ||
		actual.Mirror.FilterSubject != "" || len(actual.Mirror.SubjectTransforms) != 0 ||
		actual.Replicas != replicas || actual.Storage != jetstream.FileStorage ||
		!actual.DenyDelete || !actual.DenyPurge || actual.AllowDirect || actual.AllowRollup || actual.MaxAge != 0 ||
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
	infoCtx, infoCancel := context.WithTimeout(ctx, apiTimeout)
	info, err := stream.Info(infoCtx)
	infoCancel()
	if err != nil {
		return nil, fmt.Errorf("inspect global control stream: %w", err)
	}
	if err := verify(info.Config); err != nil {
		return nil, err
	}
	return stream, nil
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
	return &Reader{stream: stream}, nil
}
