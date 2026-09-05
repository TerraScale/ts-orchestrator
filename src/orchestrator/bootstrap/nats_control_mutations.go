package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/control/journal"
)

// Mutation identity comes from the admitted action declaration, not a first
// process-local observation. It therefore remains exact across journal retries
// and runtime reconstruction. Stream administration has no lease CAS: these
// checks cannot revoke an administration request already accepted by NATS.
type controlMutationPin struct {
	store string
	check ControlStoreCheck
}

func (r *NATSControlRuntime) controlMutationPins(plan ControlRuntimeActionPlan) ([]controlMutationPin, error) {
	targets := map[string]bool{}
	for _, m := range plan.MirrorUpdates {
		targets[m.Store] = true
	}
	for _, u := range plan.ReplicaUpdates {
		targets[u.Store] = true
	}
	if len(targets) == 0 {
		return nil, nil
	}
	pins := []controlMutationPin{}
	covered := map[string]bool{}
	for _, check := range plan.Checks {
		if !targets[check.Store] {
			continue
		}
		if check.AuthorityTerm == 0 || check.AuthorityCandidateID == "" || check.AuthorityLeaseID == "" {
			return nil, ErrControlProviderInvalid
		}
		if !r.admittedControlAuthority(check, check.AuthorityCandidateID) {
			return nil, ErrControlProviderInvalid
		}
		pins = append(pins, controlMutationPin{check.Store, check})
		covered[check.Store] = true
	}
	if len(covered) != len(targets) {
		return nil, ErrControlProviderInvalid
	}
	return pins, nil
}
func verifyControlMutationLease(ctx context.Context, js jetstream.JetStream, check ControlStoreCheck) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if check.AuthorityCandidateID == "" || check.AuthorityLeaseID == "" {
		return ErrControlRuntimeUnavailable
	}
	entry, err := readControlLeaseFromLeader(ctx, js.Conn(), check.LeaseKey)
	if err != nil {
		return err
	}
	var lease authority.RegionalAuthorityLeaseDocument
	now := time.Now().UTC()
	if json.Unmarshal(entry.Data, &lease) != nil || lease.Validate() != nil || lease.AuthorityId != check.AuthorityID || lease.Epoch <= 0 || uint64(lease.Epoch) != check.AuthorityTerm || lease.CandidateId != check.AuthorityCandidateID || lease.LeaseId != check.AuthorityLeaseID || now.Before(lease.IssuedAt) || !now.Before(lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond)) {
		return ErrControlRuntimeUnavailable
	}
	return nil
}
func checkControlMutation(ctx context.Context, js jetstream.JetStream, store string, pins []controlMutationPin) error {
	found := false
	for _, pin := range pins {
		if pin.store == store {
			found = true
			if err := verifyControlMutationLease(ctx, js, pin.check); err != nil {
				return err
			}
		}
	}
	if !found {
		return ErrControlRuntimeUnavailable
	}
	return nil
}
func (r *NATSControlRuntime) updateControlReplicas(ctx context.Context, update ControlReplicaPlan, pins []controlMutationPin) error {
	connection, err := openControlNATS(ctx, r.config.Stores[update.Store])
	if err != nil {
		return err
	}
	defer connection.Close()
	js, err := jetstream.New(connection)
	if err != nil {
		return err
	}
	return updateControlReplicaStreams(ctx, js, update, pins)
}
func updateControlReplicaStreams(ctx context.Context, js jetstream.JetStream, update ControlReplicaPlan, pins []controlMutationPin) error {
	if err := validateControlConsumerReplicas(update); err != nil {
		return err
	}
	if err := preflightControlConsumers(ctx, js, update, pins); err != nil {
		return fmt.Errorf("control consumer preflight: %w", err)
	}
	for _, name := range update.Streams {
		stream, err := js.Stream(ctx, name)
		if err != nil {
			return err
		}
		info, err := stream.Info(ctx)
		if err != nil {
			return err
		}
		if info.Config.Storage != jetstream.FileStorage || info.Config.Mirror != nil || len(info.Config.Sources) != 0 || (info.Config.Replicas != 1 && info.Config.Replicas != update.Replicas) {
			return ErrControlRuntimeUnavailable
		}
		if err := checkControlMutation(ctx, js, update.Store, pins); err != nil {
			return err
		}
		if info.Config.Replicas == update.Replicas {
			continue
		}
		config := info.Config
		config.Replicas = update.Replicas
		if _, err := js.UpdateStream(ctx, config); err != nil {
			return err
		}
		if err := checkControlMutation(ctx, js, update.Store, pins); err != nil {
			return err
		}
	}
	for _, consumer := range update.Consumers {
		if err := promoteControlConsumer(ctx, js, update, consumer, pins); err != nil {
			return fmt.Errorf("control consumer promotion %s/%s: %w", consumer.Stream, consumer.Config.Name, err)
		}
	}
	return nil
}

// Mirror capacity and retention are inherited from the actual retained source
// profile. Refuse unbounded or derived sources; never silently tighten capacity
// and claim that a truncated mirror represents the authoritative inventory.
func controlMirrorConfig(plan ControlMirrorPlan, source jetstream.StreamConfig) (jetstream.StreamConfig, error) {
	if source.Name != plan.SourceStream || source.Storage != jetstream.FileStorage || source.MaxBytes <= 0 || source.Mirror != nil || len(source.Sources) != 0 || source.Retention != jetstream.LimitsPolicy {
		return jetstream.StreamConfig{}, ErrControlRuntimeUnavailable
	}
	mirror := &jetstream.StreamSource{Name: plan.SourceStream}
	if plan.ExternalAPIPrefix != "" {
		mirror.External = &jetstream.ExternalStream{APIPrefix: plan.ExternalAPIPrefix}
	}
	return jetstream.StreamConfig{Name: plan.Name, Storage: jetstream.FileStorage, Replicas: 1, Mirror: mirror, MaxBytes: source.MaxBytes, MaxMsgs: source.MaxMsgs, MaxMsgsPerSubject: source.MaxMsgsPerSubject, MaxMsgSize: source.MaxMsgSize, MaxAge: source.MaxAge, Discard: source.Discard, DiscardNewPerSubject: source.DiscardNewPerSubject}, nil
}
func matchesControlMirror(config jetstream.StreamConfig, plan ControlMirrorPlan, source jetstream.StreamConfig) bool {
	wanted, err := controlMirrorConfig(plan, source)
	if err != nil || config.Name != wanted.Name || config.Storage != wanted.Storage || config.Replicas != 1 || config.Mirror == nil || config.Mirror.Name != plan.SourceStream || len(config.Sources) != 0 || config.Retention != jetstream.LimitsPolicy || config.MaxBytes != wanted.MaxBytes || config.MaxMsgs != wanted.MaxMsgs || config.MaxMsgsPerSubject != wanted.MaxMsgsPerSubject || config.MaxMsgSize != wanted.MaxMsgSize || config.MaxAge != wanted.MaxAge || config.Discard != wanted.Discard {
		return false
	}
	// Compare the complete source declaration. A matching watermark cannot
	// reveal omitted history, filtering, transformed subjects or redirection.
	if !reflect.DeepEqual(config.Mirror, wanted.Mirror) {
		return false
	}
	if len(config.Subjects) != 0 || config.SubjectTransform != nil || config.RePublish != nil || config.FirstSeq != 0 || config.Sealed || config.Template != "" || config.AllowRollup || config.AllowMsgTTL || config.SubjectDeleteMarkerTTL != 0 || config.AllowMsgCounter || config.AllowMsgSchedules || config.AllowAtomicPublish || config.AllowBatchPublish || config.NoAck || config.MirrorDirect || config.PersistMode != jetstream.DefaultPersistMode || config.DiscardNewPerSubject != wanted.DiscardNewPerSubject {
		return false
	}
	return true
}
func (r *NATSControlRuntime) createMirror(ctx context.Context, plan ControlMirrorPlan, pins []controlMutationPin) error {
	sourceConn, err := openControlNATS(ctx, r.config.Stores[plan.SourceStore])
	if err != nil {
		return err
	}
	defer sourceConn.Close()
	sourceJS, err := jetstream.New(sourceConn)
	if err != nil {
		return err
	}
	source, err := sourceJS.Stream(ctx, plan.SourceStream)
	if err != nil {
		return err
	}
	profile, err := source.Info(ctx)
	if err != nil {
		return err
	}
	wanted, err := controlMirrorConfig(plan, profile.Config)
	if err != nil {
		return err
	}
	connection, err := openControlNATS(ctx, r.config.Stores[plan.Store])
	if err != nil {
		return err
	}
	defer connection.Close()
	js, err := jetstream.New(connection)
	if err != nil {
		return err
	}
	stream, err := js.Stream(ctx, plan.Name)
	if err == nil {
		info, err := stream.Info(ctx)
		if err != nil {
			return err
		}
		if !matchesControlMirror(info.Config, plan, profile.Config) {
			return errors.New("bootstrap: existing candidate mirror has a different source or retention budget")
		}
		return checkControlMutation(ctx, js, plan.Store, pins)
	}
	if !errors.Is(err, jetstream.ErrStreamNotFound) {
		return err
	}
	if err := checkControlMutation(ctx, js, plan.Store, pins); err != nil {
		return err
	}
	stream, err = js.CreateStream(ctx, wanted)
	if err != nil {
		return err
	}
	if err := checkControlMutation(ctx, js, plan.Store, pins); err != nil {
		return err
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return err
	}
	if !matchesControlMirror(info.Config, plan, profile.Config) {
		return ErrControlRuntimeUnavailable
	}
	return nil
}

// Storage placement grants no application authority outside GRU.
func (r *NATSControlRuntime) admittedControlAuthority(check ControlStoreCheck, candidateID string) bool {
	for _, member := range r.members {
		candidate := member.Region + "-controller-" + member.Instance
		if check.AuthorityID == "global" {
			if member.Region != "gru" {
				continue
			}
			candidate = "global-controller-gru-" + member.Instance
		} else if member.Region != check.Region || member.Store != check.Store {
			continue
		}
		if candidate != candidateID {
			continue
		}
		for _, stream := range check.Streams {
			for _, server := range stream.Servers {
				if server == member.ServerName {
					return true
				}
			}
		}
	}
	return false
}

func validateControlConsumerReplicas(update ControlReplicaPlan) error {
	if len(update.Consumers) > 64 || len(update.Streams) > 64 {
		return ErrControlProviderInvalid
	}
	streams := map[string]bool{}
	for _, name := range update.Streams {
		streams[name] = true
	}
	seen := map[string]bool{}
	covered := map[string]bool{}
	for _, consumer := range update.Consumers {
		c := consumer.Config
		key := consumer.Stream + "/" + c.Name
		if !streams[consumer.Stream] || seen[key] || c.Name == "" || len(c.Name) > 255 || strings.ContainsAny(c.Name, ".*> /\\\t\r\n") || c.Durable != c.Name || c.Replicas != update.Replicas || c.FilterSubject == "" || c.DeliverSubject != "" || c.DeliverGroup != "" || c.AckPolicy != jetstream.AckExplicitPolicy || c.InactiveThreshold != 0 || c.MemoryStorage {
			return ErrControlProviderInvalid
		}
		seen[key] = true
		covered[consumer.Stream] = true
	}
	for _, name := range []string{"GLOBAL_SPEC", "CELL_SPEC", "CELL_EVENTS"} {
		if streams[name] && !covered[name] {
			return ErrControlProviderInvalid
		}
	}
	return nil
}

func promoteControlConsumer(ctx context.Context, js jetstream.JetStream, update ControlReplicaPlan, plan ControlConsumerReplicaPlan, pins []controlMutationPin) error {
	// The stream update response can precede its R3 election and catch-up.
	// Consumer assignment uses those peers, so require the complete admitted
	// stream placement before any consumer update, including a resumed action.
	if err := waitControlConsumerStream(ctx, js, update.Store, plan.Stream, pins); err != nil {
		return err
	}
	if err := checkControlMutation(ctx, js, update.Store, pins); err != nil {
		return err
	}
	consumer, err := js.Consumer(ctx, plan.Stream, plan.Config.Name)
	if err != nil {
		return fmt.Errorf("read predecessor consumer: %w", err)
	}
	before, err := consumer.Info(ctx)
	if err != nil {
		return fmt.Errorf("read predecessor consumer info: %w", err)
	}
	expected := plan.Config
	expected.Replicas = before.Config.Replicas
	if (expected.Replicas != 1 && expected.Replicas != update.Replicas) || !journal.NatsConsumerProfileMatches(before, expected, plan.Stream) {
		return fmt.Errorf("%w: predecessor consumer profile differs, replicas=%d", ErrControlRuntimeUnavailable, before.Config.Replicas)
	}
	if err := checkControlMutation(ctx, js, update.Store, pins); err != nil {
		return err
	}
	if before.Config.Replicas != update.Replicas {
		config := before.Config
		config.Replicas = update.Replicas
		consumer, err = js.UpdateConsumer(ctx, plan.Stream, config)
		if err != nil {
			return fmt.Errorf("update consumer replicas: %w", err)
		}
		if err := checkControlMutation(ctx, js, update.Store, pins); err != nil {
			return err
		}
	}
	// Even an already-applied retry must prove the durable replica quorum.
	for {
		if err := checkControlMutation(ctx, js, update.Store, pins); err != nil {
			return err
		}
		info, err := consumer.Info(ctx)
		if err != nil {
			return fmt.Errorf("read promoted consumer info: %w", err)
		}
		profileMatches := journal.NatsConsumerProfileMatches(info, plan.Config, plan.Stream)
		createdMatches := info.Created.Equal(before.Created)
		checkpointPreserved := info.AckFloor.Consumer >= before.AckFloor.Consumer && info.AckFloor.Stream >= before.AckFloor.Stream && info.Delivered.Consumer >= before.Delivered.Consumer && info.Delivered.Stream >= before.Delivered.Stream
		if !profileMatches || !createdMatches || !checkpointPreserved {
			return fmt.Errorf("%w: promoted consumer observation differs, profile=%t replicas=%d created=%t checkpoint=%t", ErrControlRuntimeUnavailable, profileMatches, info.Config.Replicas, createdMatches, checkpointPreserved)
		}
		servers, err := controlConsumerTargetServers(update.Store, plan.Stream, pins)
		if err != nil {
			return err
		}
		ready := controlConsumerReplicaAssignment(info.Cluster, servers)
		if ready {
			return checkControlMutation(ctx, js, update.Store, pins)
		}
		select {
		case <-ctx.Done():
			cluster, _ := json.Marshal(info.Cluster)
			return fmt.Errorf("%w: waiting for current consumer replicas, cluster=%s", ctx.Err(), cluster)
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func waitControlConsumerStream(ctx context.Context, js jetstream.JetStream, store, name string, pins []controlMutationPin) error {
	servers, err := controlConsumerTargetServers(store, name, pins)
	if err != nil {
		return err
	}
	wanted := ControlStreamAssignment{Name: name, Replicas: 3, Servers: servers}
	stream, err := js.Stream(ctx, name)
	if err != nil {
		return fmt.Errorf("open consumer source stream: %w", err)
	}
	for {
		if err := checkControlMutation(ctx, js, store, pins); err != nil {
			return err
		}
		info, err := stream.Info(ctx)
		if err != nil {
			return fmt.Errorf("read consumer source stream: %w", err)
		}
		if verifyControlStreamAssignmentMode(info, wanted, false) == nil {
			return checkControlMutation(ctx, js, store, pins)
		}
		select {
		case <-ctx.Done():
			cluster, _ := json.Marshal(info.Cluster)
			return fmt.Errorf("%w: waiting for current stream replicas before consumer promotion, replicas=%d cluster=%s", ctx.Err(), info.Config.Replicas, cluster)
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// Listing verifies the admitted set only; mutations always use declared names.
func preflightControlConsumers(ctx context.Context, js jetstream.JetStream, update ControlReplicaPlan, pins []controlMutationPin) error {
	for _, name := range update.Streams {
		if err := checkControlMutation(ctx, js, update.Store, pins); err != nil {
			return err
		}
		expected := map[string]jetstream.ConsumerConfig{}
		for _, c := range update.Consumers {
			if c.Stream == name {
				expected[c.Config.Name] = c.Config
			}
		}
		if len(expected) > 0 {
			if _, err := controlConsumerTargetServers(update.Store, name, pins); err != nil {
				return err
			}
		}
		stream, err := js.Stream(ctx, name)
		if err != nil {
			return err
		}
		listing, cancel := context.WithCancel(ctx)
		consumers := stream.ListConsumers(listing)
		seen := map[string]bool{}
		for observed := range consumers.Info() {
			wanted, ok := expected[observed.Name]
			if len(seen) >= len(expected) || !ok || seen[observed.Name] {
				cancel()
				return ErrControlRuntimeUnavailable
			}
			wanted.Replicas = observed.Config.Replicas
			if (wanted.Replicas != 1 && wanted.Replicas != update.Replicas) || !journal.NatsConsumerProfileMatches(observed, wanted, name) {
				cancel()
				return ErrControlRuntimeUnavailable
			}
			seen[observed.Name] = true
		}
		err = consumers.Err()
		cancel()
		if err != nil {
			return err
		}
		if len(seen) != len(expected) {
			return ErrControlRuntimeUnavailable
		}
		if err := checkControlMutation(ctx, js, update.Store, pins); err != nil {
			return err
		}
	}
	return nil
}

func controlConsumerTargetServers(store, stream string, pins []controlMutationPin) ([]string, error) {
	var result []string
	for _, pin := range pins {
		if pin.store == store {
			for _, assignment := range pin.check.Streams {
				if assignment.Name == stream {
					if assignment.Replicas != 3 || len(assignment.Servers) != 3 {
						return nil, ErrControlProviderInvalid
					}
					if result != nil && !reflect.DeepEqual(result, assignment.Servers) {
						return nil, ErrControlProviderInvalid
					}
					result = assignment.Servers
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, name := range result {
		if name == "" || seen[name] {
			return nil, ErrControlProviderInvalid
		}
		seen[name] = true
	}
	if len(result) != 3 {
		return nil, ErrControlProviderInvalid
	}
	return result, nil
}

func controlConsumerReplicaAssignment(cluster *jetstream.ClusterInfo, servers []string) bool {
	if cluster == nil || len(servers) != 3 || len(cluster.Replicas) != 2 {
		return false
	}
	expected := map[string]bool{}
	for _, name := range servers {
		if name == "" || expected[name] {
			return false
		}
		expected[name] = true
	}
	if !expected[cluster.Leader] {
		return false
	}
	delete(expected, cluster.Leader)
	for _, replica := range cluster.Replicas {
		if replica == nil || !expected[replica.Name] || !replica.Current || replica.Offline {
			return false
		}
		delete(expected, replica.Name)
	}
	return len(expected) == 0
}
