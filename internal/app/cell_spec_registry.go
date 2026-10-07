package app

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/atlas"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostpool"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	cellSpecBucket    = "TS_SERVICE_SET"
	cellSpecKey       = "current"
	cellSpecGetKind   = "cell.spec.get"
	cellSpecDiffKind  = "cell.spec.diff"
	cellSpecApplyKind = "cell.spec.apply"
)

// specRegistry holds the cell spec. The signed controller config is
// generation 0; the authority leader admits later generations into a
// replicated KV record, and every controller re-verifies that record before
// it uses it.
type specRegistry struct {
	cell     string
	identity cellspec.Identity
	// roots is the cell's root chain; nil when the controller cannot verify
	// specs (a lab without spec_trust): it then refuses every amendment.
	roots *rootRegistry
	// reserved roles are owned by placement and keep their signed config
	// profiles in fixed; a spec never holds them. TerraBase's signed profile
	// is in fixed too: a spec entry for it replaces it, and only a root may
	// change what binds its membership (cellspec.AuthorityChanges).
	reserved []string
	fixed    map[string]WorkloadProfile
	// signers are the signed config's trusted signers, sorted by actor; a
	// spec's signers section replaces them.
	signers       []TrustedSignerConfig
	hostTelemetry bool
	kv            jetstream.KeyValue
	// changed receives every newly adopted spec's profiles and reconciled
	// specs, under the registry lock so updates arrive in order.
	changed func(map[string]WorkloadProfile, []workload.ServiceSpec)
	// replaceSigners receives every newly adopted spec's trusted signers,
	// under the registry lock; the controller's signer policy swaps them in.
	replaceSigners func([]TrustedSignerConfig) error
	// pools are the signed config's node pools; a budget needs each priced.
	pools []hostpool.NodePool
	// snapshots is whether the signed config sets a kv_snapshot location,
	// which a kv_snapshot schedule needs.
	snapshots bool
	// terraBaseCA is whether the signed config holds the TerraBase member
	// CA, without which no member gets a certificate: a terrabase entry
	// needs it. A signed TerraBase profile implies it, since signing
	// refuses one without the CA.
	terraBaseCA bool
	// rolloutExecutor is whether this controller runs orchestrator
	// rollouts, which a rollout policy needs; signedPolicy is then the
	// signed config's policy, or the default.
	rolloutExecutor bool
	signedPolicy    *rollout.Policy
	// signedDesired is the signed config's desired OCI resources when OCI
	// reconcile is on; ociRegion, set once the signed region config is
	// loaded, admits an oci_desired section's entries.
	ociReconcile  bool
	signedDesired *cellspec.OCIDesired
	// publicLB is the backend set oci_reconcile.public_lb owns; a release
	// fence may not name it.
	publicLB  *OciReconcileLBConfig
	ociRegion *oci.RegionConfig
	// signedArtifactStore is the signed config's artifact store quota, or
	// the default; artifactStoreLimit is the most this controller's
	// embedded NATS store holds beside control state.
	signedArtifactStore int64
	artifactStoreLimit  int64

	// launches fences host image changes against launches: a launch holds
	// it for reading from its final image check through the provider launch,
	// and adopting a spec or root set holds it for writing, so a change takes
	// effect only between launches. It is taken before mu.
	launches sync.RWMutex
	mu       sync.Mutex
	current  cellspec.Spec
	revision uint64
}

// specBakedInputs reads the image roots; tests of production-mode
// controllers replace it.
var specBakedInputs = bootstrapstart.LoadBakedInputs

type specReply struct {
	Spec   cellspec.Spec  `json:"spec"`
	Plan   *cellspec.Plan `json:"plan,omitempty"`
	Status string         `json:"status,omitempty"`
	Error  string         `json:"error,omitempty"`
}

func newSpecRegistry(cfg Config, memberRole string) (*specRegistry, error) {
	r := &specRegistry{cell: cfg.NATS.Cell, fixed: map[string]WorkloadProfile{},
		signers: slices.SortedFunc(slices.Values(cfg.Controller.TrustedSigners), func(a, b TrustedSignerConfig) int {
			return strings.Compare(a.Actor, b.Actor)
		}), snapshots: cfg.Controller.KVSnapshot.Enabled, terraBaseCA: cfg.Controller.TerraBaseCACertFile != "",
		rolloutExecutor:     cfg.Controller.Rollouts != nil && cfg.Controller.Rollouts.Executor,
		signedArtifactStore: cmp.Or(cfg.Controller.ArtifactStoreMaxBytes, delivery.DefaultArtifactStoreMaxBytes)}
	if cfg.NATS.Embedded != nil {
		r.artifactStoreLimit = cfg.NATS.Embedded.StoreLimitBytes() - controlStoreHeadroomBytes
	}
	if _, signed := cfg.Controller.Workloads[terrabase.Role]; signed {
		r.terraBaseCA = true
	}
	if r.rolloutExecutor {
		policy := rollout.DefaultPolicy()
		if cfg.Controller.Rollouts.Policy != nil {
			policy = *cfg.Controller.Rollouts.Policy
		}
		r.signedPolicy = &policy
	}
	if reconcile := cfg.Controller.OciReconcile; reconcile != nil && reconcile.Enabled {
		r.ociReconcile, r.signedDesired, r.publicLB = true, reconcile.Desired, reconcile.PublicLB
	}
	if memberRole != "" {
		r.reserved = append(r.reserved, memberRole)
	}
	autoscaleConfig := cfg.Controller.Autoscale
	if autoscaleConfig != nil {
		r.hostTelemetry = autoscaleConfig.HostTelemetry
		if autoscaleConfig.Enabled {
			r.pools = autoscaleConfig.NodePools
		}
	}
	if err := r.loadTrust(cfg); err != nil {
		return nil, err
	}
	// Generation 0 is the signed config's generic workloads.
	r.current = cellspec.Spec{Schema: cellspec.Schema, Identity: r.identity, RequiresBinary: 1}
	for _, role := range slices.Sorted(maps.Keys(cfg.Controller.Workloads)) {
		profile := cfg.Controller.Workloads[role]
		if slices.Contains(r.reserved, role) || role == terrabase.Role {
			r.fixed[role] = profile
			continue
		}
		service := cellspec.Service{Role: role, Profile: profile}
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
	r.current.RequiresBinary = r.current.Level()
	return r, nil
}

// loadTrust takes the roots and deployment identity from the image, or for a
// lab controller from its spec_trust setting.
func (r *specRegistry) loadTrust(cfg Config) error {
	if settings := cfg.Controller.SpecTrust; settings != nil {
		if !cfg.NATS.Lab {
			return errors.New("controller spec_trust is a lab setting; production uses the image trust roots")
		}
		data, err := readBoundedConfigFile(settings.RootPublicKeyFile)
		if err != nil {
			return fmt.Errorf("cell spec root key: %w", err)
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "PUBLIC KEY" {
			return errors.New("cell spec root key must be an Ed25519 PKIX PEM")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		public, ok := parsed.(ed25519.PublicKey)
		if err != nil || !ok {
			return errors.New("cell spec root key must be an Ed25519 PKIX PEM")
		}
		genesis, err := trust.ParseKeyring(public)
		if err != nil {
			return err
		}
		r.identity = cellspec.Identity{DeploymentID: settings.DeploymentID, Cell: cfg.NATS.Cell,
			Environment: settings.Environment}
		if err := r.identity.Validate(); err != nil {
			return err
		}
		return r.openRoots(genesis, trust.RootChain{}, "")
	}
	if cfg.NATS.Lab {
		return nil
	}
	baked, err := specBakedInputs()
	if err != nil {
		return fmt.Errorf("load image trust roots for cell specs: %w", err)
	}
	identity := cellspec.Identity{DeploymentID: baked.Identity.DeploymentID,
		Cell: strings.ToLower(string(baked.Identity.Cell)), Environment: baked.Identity.Environment}
	if identity.Cell != cfg.NATS.Cell {
		return errors.New("image trust cell differs from the controller cell")
	}
	if err := identity.Validate(); err != nil {
		return err
	}
	r.identity = identity
	return r.openRoots(baked.Genesis, baked.Chain, bootstrapstart.RootChainFile)
}

// openRoots builds the cell's root chain from genesis and the adopted chain.
func (r *specRegistry) openRoots(genesis trust.Keyring, chain trust.RootChain, path string) error {
	roots, err := newRootRegistry(genesis, trust.ChainIdentity{DeploymentID: r.identity.DeploymentID,
		Cell: r.identity.Cell, Environment: r.identity.Environment}, chain, path)
	if err != nil {
		return err
	}
	roots.keeps = r.keepsStoredSpec
	roots.fence = &r.launches
	r.roots = roots
	return nil
}

// reverify reads the stored spec again after the roots change: a follower
// may have refused a spec signed under a root it had not yet adopted.
func (r *specRegistry) reverify(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	entry, err := r.kv.Get(ctx, cellSpecKey)
	if err != nil {
		if !errors.Is(err, jetstream.ErrKeyNotFound) {
			slog.Error("reread cell spec after a root rotation", observability.ComponentKey, "cellspec", "error", err)
		}
		return
	}
	r.load(entry)
}

// keepsStoredSpec refuses a root rotation that would leave the stored spec
// signed under a removed root. Rotate make-before-break instead: add the new
// root, apply the next generation signed under it, then remove the old root.
func (r *specRegistry) keepsStoredSpec(ctx context.Context, roots trust.Keyring) error {
	if r.kv == nil {
		return nil
	}
	entry, err := r.kv.Get(ctx, cellSpecKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read cell spec: %w", err)
	}
	// A spec that needs a newer binary still passed its signature check.
	signed := func(roots trust.Keyring) bool {
		_, err := cellspec.VerifyHistorical(entry.Value(), roots, r.identity)
		return err == nil || errors.As(err, new(*cellspec.NewerBinaryError))
	}
	// A record the current roots already refuse is replaced by the next
	// applied generation; the rotation does not change that.
	if signed(r.roots.current()) && !signed(roots) {
		return errors.New("the stored cell spec is signed under a root this rotation removes: keep that root, " +
			"apply the next spec generation signed under a new root, then rotate again")
	}
	return nil
}

// open creates the replicated record and adopts the stored spec, so the
// reconciler and planner start from it.
func (r *specRegistry) open(ctx context.Context, js jetstream.JetStream, replicas int) error {
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: cellSpecBucket, History: 4,
		MaxValueSize: cellspec.MaxSignedBytes, Storage: jetstream.FileStorage, Replicas: replicas})
	if err != nil {
		return fmt.Errorf("open cell spec: %w", err)
	}
	r.kv = kv
	entry, err := kv.Get(ctx, cellSpecKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read cell spec: %w", err)
	}
	r.load(entry)
	return nil
}

// Run adopts every spec another controller stores.
func (r *specRegistry) Run(ctx context.Context) error {
	watcher, err := r.kv.Watch(ctx, cellSpecKey)
	if err != nil {
		return fmt.Errorf("watch cell spec: %w", err)
	}
	defer watcher.Stop()
	var rootsChanged <-chan struct{}
	if r.roots != nil {
		rootsChanged = r.roots.changed
	}
	// Rereads run beside the watch; adopt keeps revision order.
	var rereads sync.WaitGroup
	defer rereads.Wait()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case entry, ok := <-watcher.Updates():
			if !ok {
				return errors.New("cell spec watch ended")
			}
			if entry != nil {
				r.load(entry)
			}
		case <-rootsChanged:
			rereads.Go(func() { r.reverify(ctx) })
		}
	}
}

// load re-verifies a stored spec without expiry and adopts it. A record that
// fails is logged and ignored: the controller keeps the spec it had. An
// amendment for a newer binary waits for this controller's binary update;
// any other bad record is replaced by the leader's next amendment.
func (r *specRegistry) load(entry jetstream.KeyValueEntry) {
	if entry.Operation() != jetstream.KeyValuePut {
		slog.Error("cell spec record was removed; keeping the current spec", observability.ComponentKey, "cellspec")
		return
	}
	verified, err := r.verify(entry.Value(), nil)
	if newer := (*cellspec.NewerBinaryError)(nil); errors.As(err, &newer) {
		slog.Warn("stored cell spec needs a newer binary; keeping the current spec", observability.ComponentKey, "cellspec",
			"revision", entry.Revision(), "generation", newer.Generation, "requires_binary", newer.RequiresBinary,
			"binary_level", cellspec.BinaryLevel)
		return
	}
	if err != nil {
		slog.Error("stored cell spec rejected; keeping the current spec", observability.ComponentKey, "cellspec",
			"revision", entry.Revision(), "error", err)
		return
	}
	r.adopt(verified.Spec, entry.Revision())
}

func (r *specRegistry) adopt(spec cellspec.Spec, revision uint64) {
	r.launches.Lock()
	defer r.launches.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if revision <= r.revision {
		return
	}
	// A stored record only moves forward; an older signed spec written into
	// the record is a rollback, whatever its revision.
	if spec.Generation < r.current.Generation || spec.Generation == r.current.Generation && !sameSpec(spec, r.current) {
		slog.Error("stored cell spec would roll back the current spec; keeping it", observability.ComponentKey, "cellspec",
			"generation", spec.Generation, "current", r.current.Generation, "revision", revision)
		return
	}
	// The signers change first, and a spec whose signers are refused is not
	// adopted at all, so no consumer sees one generation's spec with
	// another's signers.
	if r.replaceSigners != nil {
		if err := r.replaceSigners(r.effectiveSigners(spec)); err != nil {
			slog.Error("stored cell spec signers refused; keeping the current spec", observability.ComponentKey, "cellspec",
				"generation", spec.Generation, "revision", revision, "error", err)
			return
		}
	}
	r.current, r.revision = spec, revision
	slog.Info("cell spec adopted", observability.ComponentKey, "cellspec", "generation", spec.Generation,
		"revision", revision, "roles", len(spec.Services))
	if r.changed != nil {
		profiles, specs := r.effectiveLocked()
		r.changed(profiles, specs)
	}
}

// effectiveSigners are spec's trusted signers, or the signed config's when
// it has none.
func (r *specRegistry) effectiveSigners(spec cellspec.Spec) []TrustedSignerConfig {
	if len(spec.Signers) != 0 {
		return spec.Signers
	}
	return r.signers
}

// verify checks the signatures (current when now is set, else historical)
// and the cell's own rules for every profile and service spec.
func (r *specRegistry) verify(wire []byte, now *time.Time) (cellspec.Verified, error) {
	if r.roots == nil {
		return cellspec.Verified{}, errors.New("this controller has no cell spec trust roots")
	}
	var verified cellspec.Verified
	var err error
	// Stored records verify with the current roots too, so a replaced root
	// cannot write a spec; keepsStoredSpec keeps the stored spec valid.
	if now != nil {
		verified, err = cellspec.VerifyCurrent(wire, r.roots.current(), r.identity, *now)
	} else {
		verified, err = cellspec.VerifyHistorical(wire, r.roots.current(), r.identity)
	}
	if err != nil {
		return cellspec.Verified{}, err
	}
	// Host image receipts verify with every root the chain named, so a
	// rotation does not strand the images a replaced root qualified; the
	// leader admits new ones only under the current roots.
	if err := cellspec.VerifyHostImages(cellspec.Spec{}, verified.Spec, r.roots.historical(), nil); err != nil {
		return cellspec.Verified{}, err
	}
	return verified, r.validate(verified.Spec)
}

// validate applies the signed controller config's rules to the spec. Who may
// sign which change is the leader's admission check, not a rule of the spec.
func (r *specRegistry) validate(spec cellspec.Spec) error {
	if len(spec.Signers) != 0 {
		if _, err := newSignerSet(spec.Signers); err != nil {
			return fmt.Errorf("cell spec signers: %w", err)
		}
	}
	profiles := maps.Clone(r.fixed)
	var specs []workload.ServiceSpec
	for _, service := range spec.Services {
		if slices.Contains(r.reserved, service.Role) {
			return fmt.Errorf("role %q is owned by placement and stays in the signed controller config", service.Role)
		}
		if service.Role == terrabase.Role && (!r.terraBaseCA || service.Spec != nil) {
			return fmt.Errorf("service %q needs the signed TerraBase member CA and is never reconciled", service.Role)
		}
		for _, actor := range service.Releasers {
			if !slices.ContainsFunc(r.effectiveSigners(spec), func(signer TrustedSignerConfig) bool { return signer.Actor == actor }) {
				return fmt.Errorf("service %q releaser %q is not a trusted signer", service.Role, actor)
			}
		}
		profiles[service.Role] = service.Profile
		if service.Spec != nil {
			specs = append(specs, *service.Spec)
		}
	}
	if err := validateWorkloadProfiles(r.cell, profiles); err != nil {
		return err
	}
	if err := r.validateHostGrants(spec.HostGrants, profiles); err != nil {
		return err
	}
	if spec.KVSnapshot != nil && !r.snapshots {
		return errors.New("a kv_snapshot schedule needs the signed controller config's kv_snapshot location")
	}
	if desired := spec.OCIDesired; desired != nil {
		if !r.ociReconcile || r.ociRegion == nil {
			return errors.New("desired OCI resources need OCI reconcile and the signed region config (controller.oci_reconcile)")
		}
		if _, _, err := desiredSets(*desired, string(r.ociRegion.Region), *r.ociRegion); err != nil {
			return err
		}
	}
	if fence, public := spec.ReleaseFence, r.publicLB; fence != nil && public != nil && fence.LoadBalancerID == public.LoadBalancerID {
		for _, set := range fence.BackendSets {
			if set.Name == public.BackendSet {
				// The reconciler would return a fenced backend to rotation.
				return fmt.Errorf("release_fence names backend set %q, which oci_reconcile.public_lb owns", set.Name)
			}
		}
	}
	if store := spec.ArtifactStore; store != nil && store.MaxBytes > r.artifactStoreLimit {
		return fmt.Errorf("artifact_store max_bytes %d exceeds this controller's %d: its embedded NATS store_max_bytes less %d bytes for control state",
			store.MaxBytes, max(r.artifactStoreLimit, 0), controlStoreHeadroomBytes)
	}
	if spec.RolloutPolicy != nil && !r.rolloutExecutor {
		return errors.New("a rollout policy needs the controllers' rollout executor (controller.rollouts.executor)")
	}
	for _, pool := range r.pools {
		if pool.HostMonthlyCents == 0 && spec.Budget != nil {
			return fmt.Errorf("node pool %q has no host_monthly_cents, so a budget would hold all its launches", pool.Name)
		}
	}
	return validateAutoscaleConfig(&AutoscaleConfig{HostTelemetry: r.hostTelemetry, Services: specs}, profiles)
}

// validateHostGrants admits a grant only for roles the cell delivers and
// placement does not own. It lists role terrabase exactly when the spec's
// effective TerraBase profile lists its node, at the grant's address: a
// controller VM then runs a member beside its other roles (TS-578).
func (r *specRegistry) validateHostGrants(grants []cellspec.HostGrant, profiles map[string]WorkloadProfile) error {
	var members terrabase.Profile
	if effective, ok := profiles[terrabase.Role]; ok && len(effective.Env) != 0 {
		members, _ = terrabase.ParseProfile(effective.Env)
	}
	for _, grant := range grants {
		peer, member := members.Peer(grant.Node)
		if member != slices.Contains(grant.Roles, terrabase.Role) || member && peer.Address.Addr().String() != grant.PrivateIP {
			return fmt.Errorf("host grant %q lists role %q exactly when %s lists the node at the grant's address",
				grant.Node, terrabase.Role, terrabase.EnvPeers)
		}
		for _, role := range grant.Roles {
			if _, ok := profiles[role]; !ok || slices.Contains(r.reserved, role) {
				return fmt.Errorf("host grant %q role %q has no service profile or belongs to placement", grant.Node, role)
			}
		}
	}
	return nil
}

// hostGrant returns the adopted spec's grant for node and the capacity of
// one replica of each of its roles.
func (r *specRegistry) hostGrant(node string) (cellspec.HostGrant, host.Capacity, bool) {
	if r == nil {
		return cellspec.HostGrant{}, host.Capacity{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	grant, ok := r.current.Grant(node)
	if !ok {
		return cellspec.HostGrant{}, host.Capacity{}, false
	}
	profiles, _ := r.effectiveLocked()
	var capacity host.Capacity
	for _, role := range grant.Roles {
		resources := profiles[role].Resources
		capacity.CPU += resources.CPU
		capacity.MemoryBytes += resources.MemoryBytes
		capacity.DiskBytes += resources.DiskBytes
	}
	return grant, capacity, true
}

// hostImageSnapshot is the adopted cell spec's host images and launch
// image, with the roots that may qualify a launch from them now. version
// names the spec generation and root set it was read from.
type hostImageSnapshot struct {
	images  []cellspec.HostImage
	launch  string
	roots   trust.Keyring
	version string
}

func (s hostImageSnapshot) ids() []string {
	ids := make([]string, 0, len(s.images))
	for _, image := range s.images {
		ids = append(ids, image.ImageID)
	}
	return ids
}

// hostImages returns the image IDs the adopted spec allows managed hosts to
// run besides the signed fleet image.
func (r *specRegistry) hostImages() []string {
	return r.hostImageSnapshot().ids()
}

// holdLaunch holds the launch fence for reading until the returned release.
func (r *specRegistry) holdLaunch() func() {
	r.launches.RLock()
	return r.launches.RUnlock
}

func (r *specRegistry) hostImageSnapshot() hostImageSnapshot {
	if r == nil {
		return hostImageSnapshot{}
	}
	// The roots are read under the spec lock, so the snapshot pairs the
	// adopted spec with the roots of the same instant. The root registry
	// never takes the spec lock, so the order cannot deadlock.
	r.mu.Lock()
	defer r.mu.Unlock()
	roots := r.roots.current()
	return hostImageSnapshot{images: slices.Clone(r.current.HostImages), launch: r.current.LaunchImage, roots: roots,
		version: fmt.Sprintf("%d/%s", r.current.Generation, strings.Join(slices.Sorted(maps.Keys(roots)), ","))}
}

// releaser reports whether the adopted spec lets actor release role and
// register its hosts in environment.
func (r *specRegistry) releaser(actor, role, environment string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	service, ok := r.current.Find(role)
	return ok && environment == r.identity.Environment && slices.Contains(service.Releasers, actor)
}

func (r *specRegistry) effectiveLocked() (map[string]WorkloadProfile, []workload.ServiceSpec) {
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
func (r *specRegistry) effective() (map[string]WorkloadProfile, []workload.ServiceSpec) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.effectiveLocked()
}

// budget is a copy of the current spec's budget; the pool scaler reads it
// every tick.
func (r *specRegistry) budget() *hostpool.Budget {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current.Budget == nil {
		return nil
	}
	budget := *r.current.Budget
	return &budget
}

// kvSnapshot is the current spec's snapshot interval, or signed when the
// spec sets none, and whether a root paused the uploads.
func (r *specRegistry) kvSnapshot(signed time.Duration) (time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	schedule := r.current.KVSnapshot
	if schedule == nil {
		return signed, false
	}
	if schedule.IntervalSeconds != 0 {
		signed = time.Duration(schedule.IntervalSeconds) * time.Second
	}
	return signed, schedule.Paused
}

// rolloutPolicy is the current spec's rollout policy, or signed when the
// spec sets none.
// ociDesired is the current spec's desired OCI resources, or the signed
// config's when the spec lists none; nil lists none.
func (r *specRegistry) ociDesired() *cellspec.OCIDesired {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current.OCIDesired != nil {
		return r.current.OCIDesired
	}
	return r.signedDesired
}

// releaseFence is the current spec's release fence, or nil, and the private
// address of each granted node.
func (r *specRegistry) releaseFence() (*cellspec.ReleaseFence, map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	addresses := make(map[string]string, len(r.current.HostGrants))
	for _, grant := range r.current.HostGrants {
		addresses[grant.Node] = grant.PrivateIP
	}
	return r.current.ReleaseFence, addresses
}

// machinesAPI is the current spec's Machines API, or nil.
func (r *specRegistry) machinesAPI() *cellspec.MachinesAPI {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current.MachinesAPI
}

// atlasConfig is the current spec's Atlas publisher, or nil.
func (r *specRegistry) atlasConfig() *atlas.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current.Atlas
}

// withSigned fills the sections generation 0 holds in the signed config, so
// plans and the root rule compare what is in force: restating the signed
// setting changes nothing, and dropping a section returns to it.
func (r *specRegistry) withSigned(spec cellspec.Spec) cellspec.Spec {
	if spec.OCIDesired == nil {
		spec.OCIDesired = r.signedDesired
	}
	if spec.RolloutPolicy == nil {
		spec.RolloutPolicy = r.signedPolicy
	}
	spec.Signers = r.effectiveSigners(spec)
	if spec.KVSnapshot == nil && r.snapshots {
		spec.KVSnapshot = &cellspec.KVSnapshot{}
	}
	if spec.ArtifactStore == nil {
		spec.ArtifactStore = &cellspec.ArtifactStore{MaxBytes: r.signedArtifactStore}
	}
	return spec
}

// artifactStoreMaxBytes is the current spec's artifact store quota, or the
// signed config's when the spec sets none.
func (r *specRegistry) artifactStoreMaxBytes() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current.ArtifactStore != nil {
		return r.current.ArtifactStore.MaxBytes
	}
	return r.signedArtifactStore
}

func (r *specRegistry) rolloutPolicy(signed rollout.Policy) rollout.Policy {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current.RolloutPolicy != nil {
		return *r.current.RolloutPolicy
	}
	return signed
}

func (r *specRegistry) profiles() map[string]WorkloadProfile {
	profiles, _ := r.effective()
	return profiles
}

// amended returns the spec an amendment must follow: the newer of the
// adopted spec and the stored record, so a lost, older or corrupt record
// neither blocks changes nor rolls them back. A record that needs a newer
// binary is refused with a NewerBinaryError and its revision instead:
// amending the older spec would drop its sections.
func (r *specRegistry) amended(ctx context.Context) (current cellspec.Spec, revision uint64, stored bool, err error) {
	r.mu.Lock()
	current = r.current
	r.mu.Unlock()
	entry, err := r.kv.Get(ctx, cellSpecKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return current, 0, false, nil
	}
	if err != nil {
		return cellspec.Spec{}, 0, false, fmt.Errorf("read cell spec: %w", err)
	}
	verified, err := r.verify(entry.Value(), nil)
	if newer := (*cellspec.NewerBinaryError)(nil); errors.As(err, &newer) {
		return current, entry.Revision(), false, fmt.Errorf("the stored %w; update this controller's binary first", newer)
	}
	if err != nil {
		slog.Error("stored cell spec is invalid; amending the adopted spec", observability.ComponentKey, "cellspec",
			"revision", entry.Revision(), "error", err)
		return current, entry.Revision(), false, nil
	}
	if verified.Generation > current.Generation || sameSpec(verified.Spec, current) {
		return verified.Spec, entry.Revision(), true, nil
	}
	return current, entry.Revision(), false, nil
}

// diff plans a candidate against the spec it amends, with the cell's rules
// and the authority it widens, without changing anything.
func (r *specRegistry) diff(ctx context.Context, payload []byte) (specReply, error) {
	candidate, err := cellspec.Decode(payload)
	if err != nil {
		return specReply{}, err
	}
	if candidate.Identity != r.identity {
		return specReply{}, errors.New("cell spec names another deployment, cell or environment")
	}
	if err := r.validate(candidate); err != nil {
		return specReply{}, err
	}
	current, _, _, err := r.amended(ctx)
	if err != nil {
		return specReply{}, err
	}
	now := time.Now()
	if err := cellspec.VerifyHostImages(current, candidate, r.roots.current(), &now); err != nil {
		return specReply{}, err
	}
	plan, err := cellspec.Diff(r.withSigned(current), r.withSigned(candidate), r.fixed)
	if err != nil {
		return specReply{}, err
	}
	status := "planned"
	switch {
	case sameSpec(current, candidate):
		status = "unchanged"
	case candidate.Generation != current.Generation+1:
		status = "stale"
	}
	return specReply{Spec: candidate, Plan: &plan, Status: status}, nil
}

// apply admits a signed spec on the authority leader. A spec equal to the
// stored one is a no-op; otherwise its generation must follow the stored
// one, which refuses replays, rollbacks and specs built on a stale view, and
// an amendment that widens authority must be signed by a root.
func (r *specRegistry) apply(ctx context.Context, wire []byte, keyID string, epoch uint64, fencer authority.Fencer,
	hosts *host.Controller,
) (specReply, error) {
	now := time.Now()
	verified, err := r.verify(wire, &now)
	if err != nil {
		return specReply{}, err
	}
	spec := verified.Spec
	current, revision, stored, err := r.amended(ctx)
	// After a binary rollback no controller may read the stored record. The
	// root may replace it with the generation that follows it.
	newer := (*cellspec.NewerBinaryError)(nil)
	replacing := errors.As(err, &newer) && verified.RootSigned && spec.Generation == newer.Generation+1
	if err != nil && !replacing {
		return specReply{}, err
	}
	if stored && sameSpec(current, spec) {
		r.adopt(current, revision)
		return specReply{Spec: current, Status: "unchanged"}, nil
	}
	if !replacing && spec.Generation != current.Generation+1 {
		return specReply{}, fmt.Errorf("cell spec generation %d does not follow the current generation %d",
			spec.Generation, current.Generation)
	}
	// An accepted image stays allowed after its receipt expires; one the
	// amendment adds or changes must be qualified now, by a current root.
	if err := cellspec.VerifyHostImages(current, spec, r.roots.current(), &now); err != nil {
		return specReply{}, err
	}
	if changes := cellspec.AuthorityChanges(r.withSigned(current), r.withSigned(spec), r.fixed); len(changes) > 0 && !verified.RootSigned {
		return specReply{}, fmt.Errorf("cell spec generation %d widens authority (%s); a root must sign it",
			spec.Generation, strings.Join(changes, ", "))
	}
	// A spec that stops trusting the key that applies it could leave no
	// operator able to apply the next one: add the new signer first.
	if !reflect.DeepEqual(r.withSigned(current).Signers, r.withSigned(spec).Signers) {
		set, err := newSignerSet(r.effectiveSigners(spec))
		if err != nil {
			return specReply{}, fmt.Errorf("cell spec signers: %w", err)
		}
		if _, kept := set.trusted[keyID]; !kept {
			return specReply{}, errors.New("cell spec would no longer trust the key that applies it; " +
				"apply a spec that adds the new signer first, then remove this one")
		}
	}
	// Removing a role stops managing it, so its replicas must be gone first.
	// A role of the signed config keeps its signed profile instead.
	for _, service := range current.Services {
		_, kept := spec.Find(service.Role)
		if _, signed := r.fixed[service.Role]; kept || signed {
			continue
		}
		desired, err := hosts.ListDesired(ctx, service.Role)
		if err != nil {
			return specReply{}, err
		}
		for _, allocation := range desired {
			if !allocation.Withdrawn {
				return specReply{}, fmt.Errorf("service %q still has a replica on %s; scale it to zero before removing it",
					service.Role, allocation.Node)
			}
		}
	}
	if err := fencer.Guard(ctx, epoch); err != nil {
		return specReply{}, err
	}
	if revision == 0 {
		revision, err = r.kv.Create(ctx, cellSpecKey, wire)
	} else {
		revision, err = r.kv.Update(ctx, cellSpecKey, wire, revision)
	}
	if err != nil {
		return specReply{}, fmt.Errorf("store cell spec: %w", err)
	}
	r.adopt(spec, revision)
	signer := map[bool]string{true: "root", false: "release leaf"}[verified.RootSigned]
	decisionlog.Record(ctx, decisionlog.Decision{Region: r.cell, Actor: decisionlog.Actor{Slice: "cellspec"},
		Kind: "cell_spec_applied", Subject: decisionlog.Subject{Kind: "region", ID: r.cell, Name: "cell spec"},
		Summary: fmt.Sprintf("Applied cell spec generation %d", spec.Generation),
		Reason:  fmt.Sprintf("Signed by the %s; it follows generation %d.", signer, current.Generation),
		Rule:    "cellspec.apply", Status: decisionlog.StatusSucceeded, Epoch: epoch,
		Attrs: map[string]string{"generation": strconv.FormatUint(spec.Generation, 10),
			"requires_binary": strconv.FormatUint(spec.RequiresBinary, 10), "signer": signer}})
	return specReply{Spec: spec, Status: "applied"}, nil
}

// serve answers a signed operator request on the host registration subject,
// which every issued operator credential may already publish to.
func (r *specRegistry) serve(ctx context.Context, wire []byte, policy signerPolicy, fencer authority.Fencer,
	hosts *host.Controller,
) (specReply, error) {
	envelope, actor, err := verifyCellRequest(wire, policy, fencer)
	if err != nil {
		return specReply{}, err
	}
	switch envelope.Kind {
	case cellSpecGetKind:
		r.mu.Lock()
		defer r.mu.Unlock()
		return specReply{Spec: r.current}, nil
	case cellSpecDiffKind:
		return r.diff(ctx, envelope.Payload)
	}
	reply, err := r.apply(ctx, envelope.Payload, envelope.KeyID, envelope.Epoch, fencer, hosts)
	if err == nil {
		slog.Info("cell spec request", observability.ComponentKey, "cellspec", "actor", actor,
			"generation", reply.Spec.Generation, "status", reply.Status)
	}
	return reply, err
}

// verifyCellRequest verifies a trusted operator's signed request to the
// current authority term and returns it with the signer's actor.
func verifyCellRequest(wire []byte, policy signerPolicy, fencer authority.Fencer) (protocol.Envelope, string, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxRegistrationWireBytes); err != nil {
		return protocol.Envelope{}, "", err
	}
	trusted, ok := policy.trusted(envelope.KeyID)
	if !ok || trusted.Actor != envelope.Actor {
		return protocol.Envelope{}, "", errors.New("operator request signer is untrusted")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{Region: policy.cell, Kind: envelope.Kind,
		Actor: trusted.Actor, OperationID: envelope.OperationID, Generation: envelope.Generation, Epoch: envelope.Epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return protocol.Envelope{}, "", err
	}
	if envelope.Epoch == 0 || fencer.Current().Epoch != envelope.Epoch {
		return protocol.Envelope{}, "", authority.ErrFenced
	}
	return envelope, trusted.Actor, nil
}

func sameSpec(a, b cellspec.Spec) bool {
	left, leftErr := cellspec.Digest(a)
	right, rightErr := cellspec.Digest(b)
	return leftErr == nil && rightErr == nil && left == right
}
