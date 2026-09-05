package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
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
	for _, name := range update.Streams {
		stream, err := js.Stream(ctx, name)
		if err != nil {
			return err
		}
		info, err := stream.Info(ctx)
		if err != nil {
			return err
		}
		if info.Config.Storage != jetstream.FileStorage || (info.Config.Replicas != 1 && info.Config.Replicas != update.Replicas) {
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
