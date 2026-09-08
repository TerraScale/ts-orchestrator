package restoredrill

import (
	"context"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
)

// FinalSnapshotEvidence records the source and restored identities separately.
// It is emitted only after complete state readback and exact current R3 peers.
type FinalSnapshotEvidence struct {
	Snapshot        SnapshotRestoreEvidence `json:"snapshot"`
	RestoredCreated time.Time               `json:"restoredCreated"`
	Servers         []string                `json:"servers"`
	Cluster         string                  `json:"cluster"`
}

// RestoreFinalSnapshot executes only the storage effects declared by a finite
// verified plan. The caller must authenticate the final capture and predecessor
// receipts and supply a connection to its isolated destination account.
// Existing streams are verified in place; a retry never deletes one.
func RestoreFinalSnapshot(ctx context.Context, nc *nats.Conn, verified controltransition.VerifiedPlan, role, stream string, envelope []byte) (FinalSnapshotEvidence, error) {
	fail := func(err error) (FinalSnapshotEvidence, error) { return FinalSnapshotEvidence{}, err }
	if ctx == nil || nc == nil || nc.IsClosed() {
		return fail(ErrSnapshotVerification)
	}
	plan, err := verified.Plan()
	if err != nil {
		return fail(err)
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return verified.Check(time.Now().UTC())
	}
	if err := check(); err != nil {
		return fail(err)
	}
	var admitted *controltransition.Stream
	for _, account := range plan.Accounts {
		if account.Role == role {
			for _, item := range account.Streams {
				if item.Name == stream {
					admitted = new(item)
				}
			}
		}
	}
	if admitted == nil {
		return fail(ErrSnapshotVerification)
	}
	manifest, archive, err := decodeJetStreamSnapshotEnvelope(envelope, stream, plan.Limits.MaxSnapshotBytes)
	if err != nil {
		return fail(err)
	}
	canonical, err := canonicalSnapshotJSON(manifest.Config)
	if err != nil || controltransition.Digest(canonical) != admitted.SourceConfigSHA256 {
		return fail(fmt.Errorf("%w: source stream config differs from plan", ErrSnapshotVerification))
	}
	var source jetstream.StreamConfig
	if json.Unmarshal(manifest.Config, &source, jsonv1.DefaultOptionsV1()) != nil || source.Replicas != 1 || source.Storage != jetstream.FileStorage || source.Mirror != nil || len(source.Sources) != 0 {
		return fail(ErrSnapshotVerification)
	}
	final := source
	final.Replicas = 3
	final.Placement = nil
	finalRaw, err := json.Marshal(final, jsonv1.DefaultOptionsV1())
	if err != nil {
		return fail(err)
	}
	finalCanonical, err := canonicalSnapshotJSON(finalRaw)
	if err != nil || controltransition.Digest(finalCanonical) != admitted.FinalConfigSHA256 {
		return fail(fmt.Errorf("%w: final stream config differs from plan", ErrSnapshotVerification))
	}
	if len(manifest.Consumers) != len(admitted.Consumers) {
		return fail(ErrSnapshotVerification)
	}
	for i, consumer := range manifest.Consumers {
		declared := admitted.Consumers[i]
		if consumer.Name != declared.Name || consumer.MemoryStorage || consumer.Checkpoint == nil || (consumer.Durable != "") != declared.Durable || consumer.Checkpoint.ConfigSHA256 != declared.SourceConfigSHA256 {
			return fail(ErrSnapshotVerification)
		}
	}
	temporary := source
	temporary.Placement = &jetstream.Placement{Cluster: plan.ClusterName, Tags: []string{"ts-control-node:" + plan.Destinations[0].NodeID}}
	js, err := jetstream.New(nc)
	if err != nil {
		return fail(err)
	}
	target, err := js.Stream(ctx, stream)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		restored := manifest
		restored.Config, err = json.Marshal(temporary, jsonv1.DefaultOptionsV1())
		if err != nil {
			return fail(err)
		}
		if err := check(); err != nil {
			return fail(err)
		}
		if err := restoreSnapshotArchive(ctx, nc, restored, archive); err != nil {
			return fail(err)
		}
		target, err = js.Stream(ctx, stream)
	}
	if err != nil {
		return fail(err)
	}
	before, err := target.Info(ctx)
	if err != nil {
		return fail(err)
	}
	if !sameRestoredConfig(before.Config, temporary) && !sameRestoredConfig(before.Config, source) && !sameRestoredConfig(before.Config, final) {
		return fail(fmt.Errorf("%w: existing destination config conflicts", ErrSnapshotVerification))
	}
	// Validate records and every checkpoint before any promotion, including retry
	// states where an earlier call already promoted a subset of consumers.
	observedManifest := manifest
	observedManifest.Config, err = json.Marshal(before.Config, jsonv1.DefaultOptionsV1())
	if err != nil {
		return fail(err)
	}
	observedManifest.Consumers = slices.Clone(manifest.Consumers)
	for i, consumer := range manifest.Consumers {
		object, err := target.Consumer(ctx, consumer.Name)
		if err != nil {
			return fail(err)
		}
		info, err := object.Info(ctx)
		if err != nil {
			return fail(err)
		}
		if info.Config.Replicas != 1 && info.Config.Replicas != 3 && info.Config.Replicas != 0 {
			return fail(ErrSnapshotVerification)
		}
		checkpoint, err := snapshotConsumerEvidence(*info)
		if err != nil {
			return fail(err)
		}
		expectedHash := admitted.Consumers[i].SourceConfigSHA256
		if info.Config.Replicas == 3 {
			expectedHash = admitted.Consumers[i].FinalConfigSHA256
		}
		if checkpoint.ConfigSHA256 != expectedHash {
			return fail(ErrSnapshotVerification)
		}
		expected := *consumer.Checkpoint
		expected.ConfigSHA256 = expectedHash
		observedManifest.Consumers[i].Checkpoint = &expected
	}
	if _, err := observeRestoredSnapshot(ctx, nc, target, observedManifest, plan.Limits.MaxSnapshotBytes); err != nil {
		return fail(err)
	}
	servers := make([]string, 0, 3)
	for _, destination := range plan.Destinations {
		servers = append(servers, destination.ServerName)
	}
	slices.Sort(servers)
	if before.Config.Replicas != 3 {
		if !finalClusterPeers(before.Cluster, plan.ClusterName, []string{plan.Destinations[0].ServerName}) {
			return fail(fmt.Errorf("%w: temporary restore is not placed on GRU", ErrSnapshotVerification))
		}
		if err := check(); err != nil {
			return fail(err)
		}
		if _, err := js.UpdateStream(ctx, final); err != nil {
			return fail(err)
		}
	}
	if err := waitFinalStream(ctx, target, plan.ClusterName, servers, check); err != nil {
		return fail(err)
	}
	for i, consumer := range manifest.Consumers {
		object, err := target.Consumer(ctx, consumer.Name)
		if err != nil {
			return fail(err)
		}
		info, err := object.Info(ctx)
		if err != nil {
			return fail(err)
		}
		config := info.Config
		config.Replicas = 3
		candidate := *info
		candidate.Config = config
		checkpoint, err := snapshotConsumerEvidence(candidate)
		if err != nil {
			return fail(err)
		}
		if checkpoint.ConfigSHA256 != admitted.Consumers[i].FinalConfigSHA256 {
			return fail(ErrSnapshotVerification)
		}
		if info.Config.Replicas != 3 {
			if err := check(); err != nil {
				return fail(err)
			}
			if _, err := target.UpdateConsumer(ctx, config); err != nil {
				return fail(err)
			}
		}
		if err := waitFinalConsumer(ctx, object, plan.ClusterName, servers, consumer.Created, check); err != nil {
			return fail(err)
		}
		expected := *consumer.Checkpoint
		expected.ConfigSHA256 = admitted.Consumers[i].FinalConfigSHA256
		observedManifest.Consumers[i].Checkpoint = &expected
	}
	observedManifest.Config = finalRaw
	evidence, err := observeRestoredSnapshot(ctx, nc, target, observedManifest, plan.Limits.MaxSnapshotBytes)
	if err != nil {
		return fail(err)
	}
	if err := waitFinalStream(ctx, target, plan.ClusterName, servers, check); err != nil {
		return fail(err)
	}
	after, err := target.Info(ctx)
	if err != nil {
		return fail(err)
	}
	if !after.Created.Equal(before.Created) {
		return fail(ErrSnapshotVerification)
	}
	return FinalSnapshotEvidence{Snapshot: evidence, RestoredCreated: after.Created, Servers: servers, Cluster: plan.ClusterName}, nil
}

func finalClusterPeers(cluster *jetstream.ClusterInfo, name string, servers []string) bool {
	if cluster == nil || cluster.Name != name || cluster.Leader == "" || len(cluster.Replicas)+1 != len(servers) {
		return false
	}
	actual := []string{cluster.Leader}
	for _, peer := range cluster.Replicas {
		if peer == nil || !peer.Current || peer.Offline || peer.Lag != 0 {
			return false
		}
		actual = append(actual, peer.Name)
	}
	slices.Sort(actual)
	return slices.Equal(actual, servers)
}
func waitFinalStream(ctx context.Context, stream jetstream.Stream, cluster string, servers []string, check func() error) error {
	for {
		if err := check(); err != nil {
			return err
		}
		info, err := stream.Info(ctx)
		if err != nil {
			return err
		}
		if info.Config.Replicas == 3 && finalClusterPeers(info.Cluster, cluster, servers) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}
func waitFinalConsumer(ctx context.Context, consumer jetstream.Consumer, cluster string, servers []string, created time.Time, check func() error) error {
	for {
		if err := check(); err != nil {
			return err
		}
		info, err := consumer.Info(ctx)
		if err != nil {
			return err
		}
		if !info.Created.Equal(created) {
			return fmt.Errorf("%w: consumer creation identity changed", ErrSnapshotVerification)
		}
		if info.Config.Replicas == 3 && finalClusterPeers(info.Cluster, cluster, servers) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}
