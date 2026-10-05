package app

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/serviceset"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	serviceSetBucket    = "TS_SERVICE_SET"
	serviceSetKey       = "current"
	serviceSetListKind  = "service.set.list"
	serviceSetApplyKind = "service.set.apply"
)

// serviceRegistry holds the cell's service set. The signed controller config
// is generation 0; the authority leader admits later generations into a
// replicated KV record, and every controller re-verifies that record before
// it uses it.
type serviceRegistry struct {
	cell     string
	identity serviceset.Identity
	// roots is nil when the controller cannot verify sets (a lab without
	// service_trust): it then refuses every amendment.
	roots trust.Keyring
	// reserved roles are owned by placement and keep their signed config
	// profiles in fixed; a set never holds them.
	reserved      []string
	fixed         map[string]WorkloadProfile
	hostTelemetry bool
	kv            jetstream.KeyValue
	// changed receives every newly adopted set's profiles and reconciled
	// specs, under the registry lock so updates arrive in order.
	changed func(map[string]WorkloadProfile, []workload.ServiceSpec)

	mu       sync.Mutex
	current  serviceset.Set
	revision uint64
}

// serviceSetBakedInputs reads the image roots; tests of production-mode
// controllers replace it.
var serviceSetBakedInputs = bootstrapstart.LoadBakedInputs

type serviceSetReply struct {
	Set    serviceset.Set `json:"set"`
	Status string         `json:"status,omitempty"`
	Error  string         `json:"error,omitempty"`
}

func newServiceRegistry(cfg Config, memberRole string) (*serviceRegistry, error) {
	r := &serviceRegistry{cell: cfg.NATS.Cell, reserved: []string{terrabase.Role}, fixed: map[string]WorkloadProfile{}}
	if memberRole != "" {
		r.reserved = append(r.reserved, memberRole)
	}
	autoscaleConfig := cfg.Controller.Autoscale
	if autoscaleConfig != nil {
		r.hostTelemetry = autoscaleConfig.HostTelemetry
	}
	if err := r.loadTrust(cfg); err != nil {
		return nil, err
	}
	// Generation 0 is the signed config's generic workloads.
	r.current = serviceset.Set{Schema: serviceset.Schema, Identity: r.identity}
	for _, role := range slices.Sorted(maps.Keys(cfg.Controller.Workloads)) {
		profile := cfg.Controller.Workloads[role]
		if slices.Contains(r.reserved, role) {
			r.fixed[role] = profile
			continue
		}
		service := serviceset.Service{Role: role, Profile: profile}
		// Generation 0 reconciles exactly what the signed config already
		// reconciled.
		if autoscaleConfig != nil && autoscaleConfig.Enabled {
			for _, spec := range autoscaleConfig.Services {
				if spec.Role == role {
					service.Spec = &spec
				}
			}
		}
		r.current.Services = append(r.current.Services, service)
	}
	return r, nil
}

// loadTrust takes the roots and deployment identity from the image, or for a
// lab controller from its service_trust setting.
func (r *serviceRegistry) loadTrust(cfg Config) error {
	if settings := cfg.Controller.ServiceTrust; settings != nil {
		if !cfg.NATS.Lab {
			return errors.New("controller service_trust is a lab setting; production uses the image trust roots")
		}
		data, err := readBoundedConfigFile(settings.RootPublicKeyFile)
		if err != nil {
			return fmt.Errorf("service set root key: %w", err)
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "PUBLIC KEY" {
			return errors.New("service set root key must be an Ed25519 PKIX PEM")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		public, ok := parsed.(ed25519.PublicKey)
		if err != nil || !ok {
			return errors.New("service set root key must be an Ed25519 PKIX PEM")
		}
		if r.roots, err = trust.ParseKeyring(public); err != nil {
			return err
		}
		r.identity = serviceset.Identity{DeploymentID: settings.DeploymentID, Cell: cfg.NATS.Cell,
			Environment: settings.Environment}
		return r.identity.Validate()
	}
	if cfg.NATS.Lab {
		return nil
	}
	baked, err := serviceSetBakedInputs()
	if err != nil {
		return fmt.Errorf("load image trust roots for service sets: %w", err)
	}
	identity := serviceset.Identity{DeploymentID: baked.Identity.DeploymentID,
		Cell: strings.ToLower(string(baked.Identity.Cell)), Environment: baked.Identity.Environment}
	if identity.Cell != cfg.NATS.Cell {
		return errors.New("image trust cell differs from the controller cell")
	}
	r.roots, r.identity = baked.Roots, identity
	return identity.Validate()
}

// open creates the replicated record and adopts the stored set, so the
// reconciler and planner start from it.
func (r *serviceRegistry) open(ctx context.Context, js jetstream.JetStream, replicas int) error {
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: serviceSetBucket, History: 4,
		MaxValueSize: serviceset.MaxSignedBytes, Storage: jetstream.FileStorage, Replicas: replicas})
	if err != nil {
		return fmt.Errorf("open service set: %w", err)
	}
	r.kv = kv
	entry, err := kv.Get(ctx, serviceSetKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read service set: %w", err)
	}
	r.load(entry)
	return nil
}

// Run adopts every set another controller stores.
func (r *serviceRegistry) Run(ctx context.Context) error {
	watcher, err := r.kv.Watch(ctx, serviceSetKey)
	if err != nil {
		return fmt.Errorf("watch service set: %w", err)
	}
	defer watcher.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case entry, ok := <-watcher.Updates():
			if !ok {
				return errors.New("service set watch ended")
			}
			if entry != nil {
				r.load(entry)
			}
		}
	}
}

// load re-verifies a stored set without expiry and adopts it. A record that
// fails is logged and ignored: the controller keeps the set it had, and the
// leader amends that set, replacing the bad record.
func (r *serviceRegistry) load(entry jetstream.KeyValueEntry) {
	if entry.Operation() != jetstream.KeyValuePut {
		slog.Error("service set record was removed; keeping the current set", observability.ComponentKey, "services")
		return
	}
	set, err := r.verify(entry.Value(), nil)
	if err != nil {
		slog.Error("stored service set rejected; keeping the current set", observability.ComponentKey, "services",
			"revision", entry.Revision(), "error", err)
		return
	}
	r.adopt(set, entry.Revision())
}

func (r *serviceRegistry) adopt(set serviceset.Set, revision uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if revision <= r.revision {
		return
	}
	// A stored record only moves forward; an older signed set written into
	// the record is a rollback, whatever its revision.
	if set.Generation < r.current.Generation || set.Generation == r.current.Generation && !sameServiceSet(set, r.current) {
		slog.Error("stored service set would roll back the current set; keeping it", observability.ComponentKey, "services",
			"generation", set.Generation, "current", r.current.Generation, "revision", revision)
		return
	}
	r.current, r.revision = set, revision
	slog.Info("service set adopted", observability.ComponentKey, "services", "generation", set.Generation,
		"revision", revision, "roles", len(set.Services))
	if r.changed != nil {
		profiles, specs := r.effectiveLocked()
		r.changed(profiles, specs)
	}
}

// verify checks the signatures (current when now is set, else historical)
// and the cell's own rules for every profile and spec.
func (r *serviceRegistry) verify(wire []byte, now *time.Time) (serviceset.Set, error) {
	if r.roots == nil {
		return serviceset.Set{}, errors.New("this controller has no service set trust roots")
	}
	var set serviceset.Set
	var err error
	if now != nil {
		set, err = serviceset.VerifyCurrent(wire, r.roots, r.identity, *now)
	} else {
		set, err = serviceset.VerifyHistorical(wire, r.roots, r.identity)
	}
	if err != nil {
		return serviceset.Set{}, err
	}
	return set, r.validate(set)
}

// validate applies the signed controller config's rules to the set.
func (r *serviceRegistry) validate(set serviceset.Set) error {
	profiles := maps.Clone(r.fixed)
	var specs []workload.ServiceSpec
	for _, service := range set.Services {
		if slices.Contains(r.reserved, service.Role) {
			return fmt.Errorf("role %q is owned by placement and stays in the signed controller config", service.Role)
		}
		profiles[service.Role] = service.Profile
		if service.Spec != nil {
			specs = append(specs, *service.Spec)
		}
	}
	if err := validateWorkloadProfiles(r.cell, profiles); err != nil {
		return err
	}
	return validateAutoscaleConfig(&AutoscaleConfig{HostTelemetry: r.hostTelemetry, Services: specs}, profiles)
}

func (r *serviceRegistry) effectiveLocked() (map[string]WorkloadProfile, []workload.ServiceSpec) {
	profiles := maps.Clone(r.fixed)
	var specs []workload.ServiceSpec
	for _, service := range r.current.Services {
		profiles[service.Role] = service.Profile
		if service.Spec != nil {
			specs = append(specs, *service.Spec)
		}
	}
	return profiles, specs
}

// effective returns every delivery profile and the reconciled specs.
func (r *serviceRegistry) effective() (map[string]WorkloadProfile, []workload.ServiceSpec) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.effectiveLocked()
}

func (r *serviceRegistry) profiles() map[string]WorkloadProfile {
	profiles, _ := r.effective()
	return profiles
}

// apply admits a signed set on the authority leader. A set equal to the
// stored one is a no-op; otherwise its generation must follow the stored
// one, which refuses replays, rollbacks and sets built on a stale view.
func (r *serviceRegistry) apply(ctx context.Context, wire []byte, epoch uint64, fencer authority.Fencer,
	hosts *host.Controller,
) (serviceSetReply, error) {
	now := time.Now()
	set, err := r.verify(wire, &now)
	if err != nil {
		return serviceSetReply{}, err
	}
	// Amend the newer of the adopted set and the stored record, so a lost,
	// older or corrupt record neither blocks changes nor rolls them back.
	r.mu.Lock()
	current := r.current
	r.mu.Unlock()
	revision, stored := uint64(0), false
	entry, err := r.kv.Get(ctx, serviceSetKey)
	switch {
	case err == nil:
		revision = entry.Revision()
		verified, err := r.verify(entry.Value(), nil)
		if err != nil {
			slog.Error("stored service set is invalid; amending the adopted set", observability.ComponentKey, "services",
				"revision", revision, "error", err)
		} else if verified.Generation > current.Generation || sameServiceSet(verified, current) {
			current, stored = verified, true
		}
	case !errors.Is(err, jetstream.ErrKeyNotFound):
		return serviceSetReply{}, fmt.Errorf("read service set: %w", err)
	}
	if stored && sameServiceSet(current, set) {
		r.adopt(current, revision)
		return serviceSetReply{Set: current, Status: "unchanged"}, nil
	}
	if set.Generation != current.Generation+1 {
		return serviceSetReply{}, fmt.Errorf("service set generation %d does not follow the current generation %d",
			set.Generation, current.Generation)
	}
	// Removing a role stops managing it, so its replicas must be gone first.
	for _, service := range current.Services {
		if _, kept := set.Find(service.Role); kept {
			continue
		}
		desired, err := hosts.ListDesired(ctx, service.Role)
		if err != nil {
			return serviceSetReply{}, err
		}
		for _, allocation := range desired {
			if !allocation.Withdrawn {
				return serviceSetReply{}, fmt.Errorf("service %q still has a replica on %s; scale it to zero before removing it",
					service.Role, allocation.Node)
			}
		}
	}
	if err := fencer.Guard(ctx, epoch); err != nil {
		return serviceSetReply{}, err
	}
	if revision == 0 {
		revision, err = r.kv.Create(ctx, serviceSetKey, wire)
	} else {
		revision, err = r.kv.Update(ctx, serviceSetKey, wire, revision)
	}
	if err != nil {
		return serviceSetReply{}, fmt.Errorf("store service set: %w", err)
	}
	r.adopt(set, revision)
	slog.Info("service set applied", observability.ComponentKey, "services", "generation", set.Generation,
		"epoch", epoch)
	return serviceSetReply{Set: set, Status: "applied"}, nil
}

// serve answers a signed operator request on the host registration subject,
// which every issued operator credential may already publish to.
func (r *serviceRegistry) serve(ctx context.Context, wire []byte, policy signerPolicy, fencer authority.Fencer,
	hosts *host.Controller,
) (serviceSetReply, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxRegistrationWireBytes); err != nil {
		return serviceSetReply{}, err
	}
	trusted, ok := policy.codec.Trusted[envelope.KeyID]
	if !ok || trusted.Actor != envelope.Actor {
		return serviceSetReply{}, errors.New("service set request signer is untrusted")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{Region: r.cell, Kind: envelope.Kind,
		Actor: trusted.Actor, OperationID: envelope.OperationID, Generation: envelope.Generation, Epoch: envelope.Epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return serviceSetReply{}, err
	}
	if envelope.Epoch == 0 || fencer.Current().Epoch != envelope.Epoch {
		return serviceSetReply{}, authority.ErrFenced
	}
	if envelope.Kind == serviceSetListKind {
		r.mu.Lock()
		defer r.mu.Unlock()
		return serviceSetReply{Set: r.current}, nil
	}
	reply, err := r.apply(ctx, envelope.Payload, envelope.Epoch, fencer, hosts)
	if err == nil {
		slog.Info("service set request", observability.ComponentKey, "services", "actor", trusted.Actor,
			"generation", reply.Set.Generation, "status", reply.Status)
	}
	return reply, err
}

func sameServiceSet(a, b serviceset.Set) bool {
	left, leftErr := serviceset.Digest(a)
	right, rightErr := serviceset.Digest(b)
	return leftErr == nil && rightErr == nil && left == right
}
