package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/bucket"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/nlb"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/nsg"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/routetable"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/seclist"
	"github.com/TerraScale/ts-orchestrator/internal/rootfoundation"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// rootOCIResources is the concrete APP-owned amendment domain. Its constructor
// admits the installed config; broker credentials open lazily under a root Call.
type rootOCIResources struct {
	cfg        Config
	foundation *rootfoundation.Backend
}

func newRootOCIResources(cfg Config, foundation *rootfoundation.Backend) (rootoci.Foundation, error) {
	if os.Geteuid() != 0 || foundation == nil {
		return nil, errors.New("OCI resource reconciliation requires the concrete root foundation backend")
	}
	if _, _, _, err := loadSignedManagedControllerConfig(cfg); err != nil {
		return nil, err
	}
	return &rootOCIResources{cfg: cfg, foundation: foundation}, nil
}

func (b *rootOCIResources) EnsureSource(ctx context.Context, call rootoci.Call, request rootoci.SourceRequest) (rootoci.SourceReceipt, error) {
	return b.foundation.EnsureSource(ctx, call, request)
}

type rootResourceSnapshot struct {
	services                   *specRegistry
	managed                    managedControllerConfig
	configDigest               string
	rootWire, specWire         []byte
	rootRevision, specRevision uint64
	specExpiresAt              time.Time
}

// The legacy API's GetLastMsg always goes through the stream leader. Direct
// replica reads cannot establish current signed mutation authority.
func rootResourceKV(ctx context.Context, js jetstream.JetStream, bucket, key string) (*nats.RawStreamMsg, error) {
	options := js.Options()
	var opts []nats.JSOpt
	if options.Domain != "" {
		opts = append(opts, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		opts = append(opts, nats.APIPrefix(options.APIPrefix))
	}
	reader, err := js.Conn().JetStream(opts...)
	if err != nil {
		return nil, err
	}
	subject := "$KV." + bucket + "." + key
	entry, err := reader.GetLastMsg("KV_"+bucket, subject, nats.Context(ctx))
	if err != nil {
		return nil, err
	}
	if entry == nil || entry.Subject != subject || entry.Sequence == 0 || entry.Header.Get("KV-Operation") != "" || entry.Header.Get(jetstream.MarkerReasonHeader) != "" || len(entry.Data) == 0 || len(entry.Data) > cellspec.MaxSignedBytes {
		return nil, errors.New("root OCI source is deleted, corrupt or outside its exact subject")
	}
	return entry, nil
}

func readRootResourceSnapshot(ctx context.Context, cfg Config, js jetstream.JetStream) (rootResourceSnapshot, error) {
	intent, region, placement, err := loadSignedManagedControllerConfig(cfg)
	if err != nil {
		return rootResourceSnapshot{}, err
	}
	services, err := newSpecRegistry(cfg, placement.MemberRole)
	if err != nil {
		return rootResourceSnapshot{}, err
	}
	services.ociRegion = &region
	// Root only verifies this snapshot; the ordinary root-chain writer owns
	// persistence and rotation. Do not rewrite its accepted file here.
	services.roots.path = ""
	wire, err := cfg.signedWire()
	if err != nil {
		return rootResourceSnapshot{}, err
	}
	snapshot := rootResourceSnapshot{services: services, managed: managedControllerConfig{intent: intent, region: region, placement: placement}, configDigest: controllerSHA256(wire)}
	root, err := rootResourceKV(ctx, js, rootChainBucket, rootChainKey)
	if err != nil {
		return rootResourceSnapshot{}, err
	}
	chain, err := trust.DecodeRootChain(root.Data)
	if err != nil {
		return rootResourceSnapshot{}, err
	}
	if err := services.roots.adopt(chain); err != nil {
		return rootResourceSnapshot{}, err
	}
	snapshot.rootWire, snapshot.rootRevision = bytes.Clone(root.Data), root.Sequence
	spec, err := rootResourceKV(ctx, js, cellSpecBucket, cellSpecKey)
	if err != nil {
		return rootResourceSnapshot{}, err
	}
	now := time.Now().UTC()
	verified, err := services.verify(spec.Data, &now)
	if err != nil {
		return rootResourceSnapshot{}, err
	}
	if !verified.RootSigned {
		return rootResourceSnapshot{}, errors.New("OCI amendment authority requires the current root-signed service spec; unsigned prior admission cannot widen it")
	}
	services.current, services.revision = verified.Spec, spec.Sequence
	snapshot.specWire, snapshot.specRevision = bytes.Clone(spec.Data), spec.Sequence
	var signed cellspec.Signed
	if err := json.Unmarshal(spec.Data, &signed, json.RejectUnknownMembers(true)); err != nil {
		return rootResourceSnapshot{}, err
	}
	envelope, err := trust.DecodeEnvelope(signed.Spec)
	if err != nil {
		return rootResourceSnapshot{}, err
	}
	snapshot.specExpiresAt = envelope.ExpiresAt
	return snapshot, nil
}

func (s rootResourceSnapshot) same(next rootResourceSnapshot) bool {
	return s.configDigest == next.configDigest && s.rootRevision == next.rootRevision && s.specRevision == next.specRevision &&
		bytes.Equal(s.rootWire, next.rootWire) && bytes.Equal(s.specWire, next.specWire)
}

type rootResourceFencer struct {
	call        rootoci.Call
	epoch       uint64
	observed    authority.Snapshot
	js          jetstream.JetStream
	guard       func(context.Context) error
	deadline    time.Time
	credentials *rootsecret.ControllerReader
}

// Current retains Observe's Leader=false: only the sealed root Call admits
// this operation; the independently observed lease can only narrow it.
func (f rootResourceFencer) Current() authority.Snapshot { return f.observed }
func (f rootResourceFencer) Guard(ctx context.Context, epoch uint64) error {
	if epoch != f.epoch || f.deadline.IsZero() || !time.Now().Before(f.deadline) || f.call.RuntimeID() == "" || f.call.RuntimeID() != f.observed.CandidateID {
		return ociresource.ErrFenced
	}
	if err := f.call.Guard(ctx); err != nil {
		return err
	}
	if f.credentials == nil || f.credentials.Guard(ctx) != nil {
		return rootoci.ErrUnauthorized
	}
	current, err := authority.Observe(ctx, f.js, f.observed.Scope)
	if err != nil || !current.Ready || current.DeploymentID != f.observed.DeploymentID || current.CandidateID != f.observed.CandidateID ||
		current.OwnerID != f.observed.OwnerID || current.Epoch != f.observed.Epoch || current.Revision < f.observed.Revision || !time.Now().Before(current.ExpiresAt) {
		return errors.Join(ociresource.ErrFenced, err)
	}
	if err := f.guard(ctx); err != nil {
		return err
	}
	if !time.Now().Before(f.deadline) {
		return ociresource.ErrFenced
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ociclient.LimitAdmission(ctx, f.deadline); err != nil {
		return err
	}
	if err := f.call.Guard(ctx); err != nil {
		return err
	}
	return f.credentials.Guard(ctx)
}

func (b *rootOCIResources) ReconcileFoundation(ctx context.Context, call rootoci.Call, request rootoci.ReconcileFoundationRequest) (rootoci.FoundationReceipt, error) {
	if os.Geteuid() != 0 || request.Cell == "" {
		return rootoci.FoundationReceipt{}, rootoci.ErrUnauthorized
	}
	if err := call.Guard(ctx); err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	defer cancel()
	receipt, err := b.foundation.ReconcileFoundation(ctx, call, request)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	credentials, err := rootsecret.OpenControllerReader(ctx)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	conn, credentialContext := credentials.Conn(), credentials.Context()
	if conn == nil || credentialContext == nil || credentialContext.Done() == nil || credentialContext.Err() != nil {
		if conn != nil {
			conn.Close()
		}
		return rootoci.FoundationReceipt{}, rootoci.ErrUnauthorized
	}
	defer conn.Close()
	credentialDeadline, ok := credentialContext.Deadline()
	if !ok || !time.Now().Before(credentialDeadline) {
		return rootoci.FoundationReceipt{}, rootoci.ErrUnauthorized
	}
	ctx, cancelCredentials := context.WithDeadline(ctx, credentialDeadline)
	stopCredentialCancellation := context.AfterFunc(credentialContext, cancelCredentials)
	defer stopCredentialCancellation()
	defer cancelCredentials()
	guardCredentials := func(ctx context.Context) error {
		if err := call.Guard(ctx); err != nil {
			return err
		}
		if err := credentials.Guard(ctx); err != nil {
			return err
		}
		return call.Guard(ctx)
	}
	ctx = ociclient.WithRequestGuard(ctx, guardCredentials)
	if err := guardCredentials(ctx); err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	js, err := jetstream.New(conn)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	snapshot, err := readRootResourceSnapshot(ctx, b.cfg, js)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	cell := string(snapshot.managed.region.Region)
	if cell != request.Cell || receipt.Cell != cell {
		return rootoci.FoundationReceipt{}, rootfoundation.ErrScope
	}
	if err := ociresource.RejectLegacyDesired(ctx, js, cell); err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	observed, err := authority.Observe(ctx, js, b.cfg.NATS.Cell)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	if observed.DeploymentID != snapshot.services.identity.DeploymentID || observed.Scope != b.cfg.NATS.Cell || !observed.Ready {
		return rootoci.FoundationReceipt{}, ociresource.ErrFenced
	}
	deadline := minResourceDeadline(call.Deadline(), observed.ExpiresAt, snapshot.specExpiresAt, credentialDeadline)
	if deadline.IsZero() || !time.Now().Before(deadline) {
		return rootoci.FoundationReceipt{}, ociresource.ErrFenced
	}
	ctx, cancelEffects := context.WithDeadline(ctx, deadline)
	defer cancelEffects()
	regionName, err := snapshot.managed.region.Region.OCIRegion()
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	factory, err := ociclient.InstancePrincipal(regionName)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	source := ociresource.ResourceSource{ControllerConfigSHA256: snapshot.configDigest, GrantSHA256: receipt.GrantDigest}
	if len(snapshot.specWire) != 0 {
		source.CellSpecSHA256, source.CellSpecGeneration = controllerSHA256(snapshot.specWire), snapshot.services.current.Generation
	}
	authorized := rootfoundation.ResourceAuthority{Source: source, Specs: map[string]string{}, PruneKinds: map[string]bool{}}
	var sets []ociDesiredSet
	pruneDelay := defaultOciPruneDelay
	if desired := snapshot.services.ociDesired(); desired != nil {
		sets, pruneDelay, err = desiredSets(*desired, cell, snapshot.managed.region)
		if err != nil {
			return rootoci.FoundationReceipt{}, err
		}
		for _, set := range sets {
			authorized.PruneKinds[set.kind] = desired.Prune
		}
	}
	config := b.cfg.Controller.OciReconcile
	var seats *seatrollout.Reader
	var drained map[string]bool
	var fleet oci.FleetObserver
	var instances []oci.Instance
	if config != nil && config.PublicLB != nil {
		seats, err = seatrollout.OpenReader(ctx, js)
		if err != nil {
			return rootoci.FoundationReceipt{}, err
		}
		drained, err = seats.Drained(ctx)
		if err != nil {
			return rootoci.FoundationReceipt{}, err
		}
		spec, err := config.PublicLB.spec(snapshot.services.profiles(), drained)
		if err != nil {
			return rootoci.FoundationReceipt{}, err
		}
		sets = append(sets, ociDesiredSet{kind: lb.Kind, entries: []ociresource.Entry{{Name: lb.PublicTerraBase, Policy: ociresource.PolicyEnforce, Spec: spec}}})
	}
	if config != nil && config.PublicNLB != nil {
		journal, err := oci.OpenJournalReader(ctx, js, b.cfg.NATS.Replicas)
		if err != nil {
			return rootoci.FoundationReceipt{}, err
		}
		images, err := managedImageVerifierFor(b.cfg.Controller, snapshot.services.hostImageSnapshot, snapshot.services.holdLaunch)(ctx, snapshot.managed.region)
		if err != nil {
			return rootoci.FoundationReceipt{}, err
		}
		fleet, err = oci.NewFleetObserver(snapshot.managed.region, snapshot.managed.intent, factory, journal, images)
		if err != nil {
			return rootoci.FoundationReceipt{}, err
		}
		instances, err = fleet.Observe(ociclient.WithRequestGuard(ctx, guardCredentials))
		if err != nil {
			return rootoci.FoundationReceipt{}, err
		}
		public := config.PublicNLB
		spec := nlb.FromPlacement(public.NLBID, public.BackendSet, public.Port, instances)
		if err := spec.Validate(); err != nil {
			return rootoci.FoundationReceipt{}, err
		}
		sets = append(sets, ociDesiredSet{kind: nlb.Kind, entries: []ociresource.Entry{{Name: public.Name, Policy: ociresource.PolicyEnforce, Spec: spec}}})
	}
	for _, set := range sets {
		for _, entry := range set.entries {
			desired, err := ociresource.NewDesired(ociresource.Key{Region: cell, Kind: set.kind, Name: entry.Name}, 1, entry.Policy, entry.Spec)
			if err != nil {
				return rootoci.FoundationReceipt{}, err
			}
			authorized.Specs[desired.Key.String()] = desired.SpecDigest
		}
	}
	guard := func(ctx context.Context) error {
		if err := guardCredentials(ctx); err != nil {
			return err
		}
		if conn.IsClosed() {
			return errors.New("root OCI source connection ended")
		}
		current, err := readRootResourceSnapshot(ctx, b.cfg, js)
		if err != nil || !snapshot.same(current) {
			return errors.Join(errors.New("current signed OCI source changed"), err)
		}
		if err := ociresource.RejectLegacyDesired(ctx, js, cell); err != nil {
			return err
		}
		if seats != nil {
			current, err := seats.Drained(ctx)
			if err != nil || !reflect.DeepEqual(current, drained) {
				return errors.Join(errors.New("current TerraBase drain authority changed"), err)
			}
		}
		if fleet != nil {
			current, err := fleet.Observe(ociclient.WithRequestGuard(ctx, guardCredentials))
			public := config.PublicNLB
			if err != nil || !reflect.DeepEqual(nlb.FromPlacement(public.NLBID, public.BackendSet, public.Port, current), nlb.FromPlacement(public.NLBID, public.BackendSet, public.Port, instances)) {
				return errors.Join(errors.New("current NLB placement authority changed"), err)
			}
		}
		return guardCredentials(ctx)
	}
	fencer := rootResourceFencer{call: call, epoch: receipt.Epoch, observed: observed, js: js, guard: guard, deadline: deadline, credentials: credentials}
	guardCurrent := func(ctx context.Context) error { return fencer.Guard(ctx, receipt.Epoch) }
	if err := guardCurrent(ctx); err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	ctx = ociclient.WithRequestGuard(ctx, guardCurrent)
	ctx = ociclient.WithAdmission(ctx, func(ctx context.Context) (func(), error) {
		if err := guardCurrent(ctx); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
	observations, err := ociresource.OpenObservationStore(ctx, js, b.cfg.NATS.Replicas)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	store, err := b.foundation.OpenResourceStore(ctx, call, receipt, authorized, observations)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	// A changed spec cannot replace unfinished original history. Retain the
	// publication error while protected reconcilers observe that old outcome.
	pendingErr := desiredPass(cell, store, fencer, sets, false, pruneDelay).Run(ctx, receipt.Epoch)
	if errors.Is(pendingErr, ociresource.ErrFenced) || ctx.Err() != nil {
		return rootoci.FoundationReceipt{}, errors.Join(pendingErr, ctx.Err())
	}
	for _, set := range sets {
		if authorized.PruneKinds[set.kind] {
			if err := desiredPass(cell, store, fencer, []ociDesiredSet{set}, true, pruneDelay).Run(ctx, receipt.Epoch); err != nil {
				if errors.Is(err, ociresource.ErrFenced) || ctx.Err() != nil {
					return rootoci.FoundationReceipt{}, errors.Join(err, ctx.Err())
				}
				pendingErr = errors.Join(pendingErr, err)
			}
		}
	}
	passes, lbAPI, err := rootResourcePasses(cell, factory, store, fencer, snapshot.managed.region.Owner)
	if err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	for _, pass := range passes {
		if err := guardCurrent(ctx); err != nil {
			return rootoci.FoundationReceipt{}, err
		}
		if err := pass.Run(ctx, receipt.Epoch); err != nil {
			if errors.Is(err, ociresource.ErrFenced) || ctx.Err() != nil {
				return rootoci.FoundationReceipt{}, errors.Join(err, ctx.Err())
			}
			pendingErr = errors.Join(pendingErr, fmt.Errorf("root OCI %s: %w", pass.Name, err))
		}
	}
	if pendingErr != nil {
		return rootoci.FoundationReceipt{}, pendingErr
	}
	if config != nil && config.PublicLB != nil {
		receipt.SeatBackends, err = rootPublicSeatBackends(ctx, lbAPI, *config.PublicLB, snapshot.services.profiles(), cell, snapshot.managed.region.Owner)
		if err != nil {
			return rootoci.FoundationReceipt{}, err
		}
	}
	if err := guardCurrent(ctx); err != nil {
		return rootoci.FoundationReceipt{}, err
	}
	return receipt, nil
}

func rootResourcePasses(cell string, factory *ociclient.Factory, store *rootfoundation.ResourceStore,
	fencer rootResourceFencer, owner string,
) ([]ociresource.Pass, lb.API, error) {
	ownership := ociresource.Ownership{Owner: owner}
	if err := ownership.Validate(); err != nil {
		return nil, nil, err
	}
	nsgAPI, err := nsg.NewSDKAPI(factory)
	if err != nil {
		return nil, nil, err
	}
	listAPI, err := seclist.NewSDKAPI(factory)
	if err != nil {
		return nil, nil, err
	}
	tableAPI, err := routetable.NewSDKAPI(factory)
	if err != nil {
		return nil, nil, err
	}
	bucketAPI, err := bucket.NewSDKAPI(factory)
	if err != nil {
		return nil, nil, err
	}
	passes := []ociresource.Pass{
		ociresource.ControllerPass(&ociresource.Controller[nsg.Spec, nsg.Observed]{Region: cell, Resource: nsg.Reconciler{API: nsgAPI}, Store: store, Ownership: ownership, Authority: fencer}),
		ociresource.ControllerPass(&ociresource.Controller[seclist.Spec, seclist.List]{Region: cell, Resource: seclist.Reconciler{API: listAPI}, Store: store, Ownership: ownership, Authority: fencer}),
		ociresource.ControllerPass(&ociresource.Controller[routetable.Spec, routetable.Table]{Region: cell, Resource: routetable.Reconciler{API: tableAPI}, Store: store, Ownership: ownership, Authority: fencer}),
		ociresource.ControllerPass(&ociresource.Controller[bucket.Spec, bucket.Observed]{Region: cell, Resource: rootBucketResource{Reconciler: bucket.Reconciler{API: bucketAPI}}, Store: store, Ownership: ownership, Authority: fencer}),
	}
	// Protected prior operations still need observation after configuration
	// stops naming these amendment kinds; the Store denies revoked effects.
	nlbAPI, err := nlb.NewSDKAPI(factory)
	if err != nil {
		return nil, nil, err
	}
	passes = append(passes, ociresource.ControllerPass(&ociresource.Controller[nlb.Spec, nlb.Observed]{Region: cell, Resource: nlb.Reconciler{API: nlbAPI}, Store: store, Ownership: ownership, Authority: fencer}))
	api, err := lb.NewSDKAPI(factory)
	if err != nil {
		return nil, nil, err
	}
	passes = append(passes, ociresource.ControllerPass(&ociresource.Controller[lb.Spec, lb.Observed]{Region: cell, Resource: lb.Reconciler{API: api}, Store: store, Ownership: ownership, Authority: fencer}))
	return passes, api, nil
}

// Bucket protection can incur storage spend; signed desired state alone
// cannot supply the missing protected CAP property reservation.
type rootBucketResource struct{ bucket.Reconciler }

func (rootBucketResource) Apply(context.Context, ociresource.Target[bucket.Spec], bucket.Observed, bool, ociresource.Plan) error {
	return errors.New("bucket property mutation requires protected CAP admission; integration is open")
}

func rootPublicSeatBackends(ctx context.Context, api lb.API, public OciReconcileLBConfig, profiles map[string]WorkloadProfile, cell, owner string) (map[string]rootoci.FoundationBackend, error) {
	expected, err := public.spec(profiles, nil)
	if err != nil {
		return nil, err
	}
	balancer, err := api.GetLoadBalancer(ctx, public.LoadBalancerID)
	if err != nil {
		return nil, err
	}
	key, err := public.key(cell)
	if err != nil || balancer.ID != public.LoadBalancerID || !(ociresource.Ownership{Owner: owner}).Owns(key, balancer.Tags) {
		return nil, errors.Join(errors.New("root public backend observation lacks the exact owned load balancer"), err)
	}
	backends, err := api.ListBackends(ctx, public.LoadBalancerID, public.BackendSet)
	if err != nil {
		return nil, err
	}
	if len(backends) > 64 {
		return nil, errors.New("root public backend observation exceeds its bound")
	}
	unhealthy, err := api.UnhealthyBackends(ctx, public.LoadBalancerID, public.BackendSet)
	if err != nil {
		return nil, err
	}
	if len(unhealthy) > 64 {
		return nil, errors.New("root public backend health exceeds its bound")
	}
	allowed := map[string]bool{}
	for _, backend := range expected.Backends {
		allowed[backend.IP+":"+strconv.Itoa(backend.Port)] = true
	}
	result := make(map[string]rootoci.FoundationBackend, len(backends))
	names := make(map[string]bool, len(backends))
	for _, backend := range backends {
		key := backend.IP + ":" + strconv.Itoa(backend.Port)
		if !allowed[key] || len(key) > 64 {
			return nil, errors.New("root public backend is outside signed TerraBase membership")
		}
		if _, duplicate := result[key]; duplicate {
			return nil, errors.New("root public backend observation repeats a member")
		}
		result[key] = rootoci.FoundationBackend{Drained: backend.Drain, Healthy: !unhealthy[backend.Name()]}
		names[backend.Name()] = true
	}
	for name := range unhealthy {
		if !names[name] || len(name) > 256 {
			return nil, errors.New("root public health row is outside the exact observed backends")
		}
	}
	return result, nil
}

var _ rootoci.Foundation = (*rootOCIResources)(nil)

func minResourceDeadline(call, lease time.Time, caps ...time.Time) time.Time {
	if call.IsZero() || lease.IsZero() {
		return time.Time{}
	}
	if lease.Before(call) {
		call = lease
	}
	for _, cap := range caps {
		if !cap.IsZero() && cap.Before(call) {
			call = cap
		}
	}
	return call
}
