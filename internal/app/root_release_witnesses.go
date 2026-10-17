package app

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutexec"
	"github.com/TerraScale/ts-orchestrator/internal/rootrelease"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

// Every discovered expiry cancels the original operation and all SDK attempts.
func (o *rootReleaseObservation) capDeadline(values ...time.Time) {
	deadline := o.deadline
	for _, value := range values {
		deadline = earlierRootRelease(deadline, value)
	}
	if !deadline.Before(o.deadline) {
		return
	}
	o.deadline = deadline
	if o.deadlineTimer == nil {
		o.deadlineTimer = time.AfterFunc(time.Until(deadline), o.cancel)
	} else {
		o.deadlineTimer.Reset(time.Until(deadline))
	}
	if !time.Now().Before(deadline) {
		o.cancel()
	}
}

type rootReleaseRecord struct {
	kv       jetstream.KeyValue
	key      string
	revision uint64
	wire     []byte
}

type rootReleaseProof struct {
	proof rolloutexec.HealthProof
	wire  []byte
}

type rootReleaseWitnesses struct {
	err     error
	values  map[string][]byte
	records map[string]rootReleaseRecord
	proofs  map[string]rootReleaseProof
}

func (o *rootReleaseObservation) pinValue(key string, value any) error {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err == nil {
		if old, ok := o.witnesses.values[key]; ok && !bytes.Equal(old, wire) {
			err = rootrelease.ErrPending
		}
	}
	if err != nil {
		o.witnesses.err = err
		return err
	}
	if o.witnesses.values == nil {
		o.witnesses.values = map[string][]byte{}
	}
	o.witnesses.values[key] = wire
	return nil
}

func (o *rootReleaseObservation) ListHosts(ctx context.Context) ([]host.HostStatus, error) {
	hosts, err := o.b.sources.Hosts.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(hosts, func(a, b host.HostStatus) int {
		return cmp.Compare(a.Registration.Node, b.Registration.Node)
	})
	return hosts, o.pinValue("hosts", hosts)
}

func (o *rootReleaseObservation) ListDesired(ctx context.Context, role string) ([]host.Desired, error) {
	desired, err := o.b.sources.Hosts.ListDesired(ctx, role)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(desired, func(a, b host.Desired) int { return cmp.Compare(a.Node, b.Node) })
	return desired, o.pinValue("desired/"+role, desired)
}

func (o *rootReleaseObservation) pinnedKV(kv jetstream.KeyValue) rootReleaseKV {
	return rootReleaseKV{KeyValue: kv, js: o.b.js, guard: o.guard, pin: func(key string, entry jetstream.KeyValueEntry, err error) error {
		if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil
		}
		record := rootReleaseRecord{kv: kv, key: key}
		if err == nil {
			record.revision, record.wire = entry.Revision(), bytes.Clone(entry.Value())
		}
		id := kv.Bucket() + "/" + key
		if previous, exists := o.witnesses.records[id]; exists && (previous.revision != record.revision || !bytes.Equal(previous.wire, record.wire)) {
			o.witnesses.err = rootrelease.ErrPending
			return o.witnesses.err
		}
		if o.witnesses.records == nil {
			o.witnesses.records = map[string]rootReleaseRecord{}
		}
		o.witnesses.records[id] = record
		return nil
	}}
}

func (o *rootReleaseObservation) pinProof(ctx context.Context, unit string, proof rolloutexec.HealthProof, wire []byte) error {
	if previous, exists := o.witnesses.proofs[unit]; exists && (previous.proof != proof || !bytes.Equal(previous.wire, wire)) {
		o.witnesses.err = rootrelease.ErrPending
		return o.witnesses.err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return err
	}
	o.capDeadline(envelope.ExpiresAt, proof.ReceivedAt.Add(rolloutexec.DefaultProofFreshness))
	if !slices.ContainsFunc(o.b.controllers, func(controller rollout.Unit) bool { return controller.ID == unit }) {
		if _, err := o.pinnedKV(o.b.board).Get(ctx, rollout.HostMembershipKey(unit)); err != nil {
			return err
		}
		hosts, err := o.ListHosts(ctx)
		if err != nil {
			return err
		}
		found := false
		for _, status := range hosts {
			if status.Registration.Node == unit && status.Verified && !status.Retired {
				o.capDeadline(status.SessionExpiresAt)
				found = true
			}
		}
		if !found {
			return rootrelease.ErrPending
		}
	}
	if o.witnesses.proofs == nil {
		o.witnesses.proofs = map[string]rootReleaseProof{}
	}
	o.witnesses.proofs[unit] = rootReleaseProof{proof: proof, wire: bytes.Clone(wire)}
	return o.guard(ctx)
}

func (o *rootReleaseObservation) validateWitnesses(ctx context.Context) error {
	if err := o.guard(ctx); err != nil {
		return err
	}
	for _, record := range o.witnesses.records {
		entry, err := (rootReleaseKV{KeyValue: record.kv, js: o.b.js}).Get(ctx, record.key)
		if errors.Is(err, jetstream.ErrKeyNotFound) && record.revision == 0 {
			continue
		}
		if err != nil || entry.Revision() != record.revision || !bytes.Equal(entry.Value(), record.wire) {
			return errors.Join(rootrelease.ErrPending, err)
		}
	}
	for key := range o.witnesses.values {
		if key == "hosts" {
			if _, err := o.ListHosts(ctx); err != nil {
				return err
			}
		} else if role, ok := strings.CutPrefix(key, "desired/"); ok {
			if _, err := o.ListDesired(ctx, role); err != nil {
				return err
			}
		}
	}
	for unit, pinned := range o.witnesses.proofs {
		current, ok := (rootChannelProofs{b: o.b, ctx: ctx}).Latest(unit)
		o.b.mu.Lock()
		wire := bytes.Clone(o.b.proofWires[unit])
		o.b.mu.Unlock()
		if !ok || current != pinned.proof || !bytes.Equal(wire, pinned.wire) {
			return rootrelease.ErrPending
		}
	}
	if ctx.Err() != nil || o.scopeCtx.Err() != nil || !time.Now().Before(o.deadline) || o.witnesses.err != nil {
		return rootrelease.ErrPending
	}
	return nil
}
