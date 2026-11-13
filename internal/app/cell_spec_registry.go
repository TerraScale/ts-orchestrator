package app

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
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
	nativeHistory *nativeHistory
	removalReady  func(context.Context, string) error
	cell          string
	identity      cellspec.Identity
	// roots is the cell's accepted root chain.
	roots *rootRegistry
	// reserved roles are owned by placement and keep their signed config
	// profiles in fixed; a spec never holds them. TerraBase's signed profile
	// is in fixed too: a spec entry for it replaces it, and only a root may
	// change what binds its membership (cellspec.AuthorityChanges).
	reserved []string
	fixed    map[string]WorkloadProfile
	// signers are the signed config's trusted signers, sorted by actor; a
	// spec's signers section replaces them.
	signers []TrustedSignerConfig
	kv      jetstream.KeyValue
	// changed receives every newly adopted spec's profiles and reconciled
	// specs, under the registry lock so updates arrive in order.
	changed func(map[string]WorkloadProfile, []workload.ServiceSpec)
	// replaceSigners receives every newly adopted spec's trusted signers,
	// under the registry lock; the controller's signer policy swaps them in.
	replaceSigners func([]TrustedSignerConfig) error
	// terraBaseCA is whether the signed config holds the TerraBase member
	// CA, without which no member gets a certificate: a terrabase entry
	// needs it. A signed TerraBase profile implies it, since signing
	// refuses one without the CA.
	terraBaseCA bool
	// signedDesired is the signed config's resource amendments. ociRegion,
	// set once the signed region config is loaded, admits desired entries.
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

// specAcceptedInputs loads the accepted installation and its fixed trust tree.
var specAcceptedInputs = func() (bootstrapstart.AcceptedIdentity, bootstrapstart.TrustInputs, error) {
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return bootstrapstart.AcceptedIdentity{}, bootstrapstart.TrustInputs{}, err
	}
	if err := bootstrapstart.CheckIdentityRekeyPrestart(accepted); err != nil {
		return bootstrapstart.AcceptedIdentity{}, bootstrapstart.TrustInputs{}, err
	}
	inputs, err := bootstrapstart.LoadTrustInputs(accepted)
	return accepted, inputs, err
}

func newSpecRegistry(cfg Config, memberRole string) (*specRegistry, error) {
	r := &specRegistry{cell: cfg.NATS.Cell, fixed: map[string]WorkloadProfile{},
		signers: slices.SortedFunc(slices.Values(cfg.Controller.TrustedSigners), func(a, b TrustedSignerConfig) int {
			return strings.Compare(a.Actor, b.Actor)
		}), terraBaseCA: cfg.Controller.TerraBaseCACertFile != "",
		signedArtifactStore: cmp.Or(cfg.Controller.ArtifactStoreMaxBytes, delivery.DefaultArtifactStoreMaxBytes)}
	if cfg.NATS.Embedded != nil {
		r.artifactStoreLimit = cfg.NATS.Embedded.StoreLimitBytes() - specStoreHeadroomBytes
	}
	if _, signed := cfg.Controller.Workloads[terrabase.Role]; signed {
		r.terraBaseCA = true
	}
	if reconcile := cfg.Controller.OciReconcile; reconcile != nil {
		r.signedDesired, r.publicLB = reconcile.Desired, reconcile.PublicLB
	}
	if memberRole != "" {
		r.reserved = append(r.reserved, memberRole)
	}
	autoscaleConfig := cfg.Controller.Autoscale
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
		if autoscaleConfig != nil {
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

// loadTrust takes the roots and deployment identity from the accepted image.
func (r *specRegistry) loadTrust(cfg Config) error {
	if cfg.Controller.SpecTrust != nil {
		return errors.New("production controller uses the image trust roots")
	}
	accepted, inputs, err := specAcceptedInputs()
	if err != nil {
		return fmt.Errorf("load accepted trust roots for cell specs: %w", err)
	}
	identity := cellspec.Identity{DeploymentID: accepted.DeploymentID,
		Cell: strings.ToLower(accepted.Cell), Environment: accepted.Environment}
	if identity.Cell != cfg.NATS.Cell {
		return errors.New("accepted trust cell differs from the controller cell")
	}
	if err := identity.Validate(); err != nil {
		return err
	}
	r.identity = identity
	return r.openRoots(inputs.Genesis, inputs.Chain, bootstrapstart.RootChainFile)
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
			slog.ErrorContext(ctx, "reread cell spec after a root rotation", observability.ComponentKey, "cellspec", "error", err)
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
// fails is logged; startup refuses it, and a running controller keeps its spec. An
// amendment for a newer binary waits for this controller's binary update;
// any other bad record is replaced by the leader's next amendment.
func (r *specRegistry) load(entry jetstream.KeyValueEntry) error {
	if entry.Operation() != jetstream.KeyValuePut {
		slog.Error("cell spec record was removed; keeping the current spec", observability.ComponentKey, "cellspec")
		return errors.New("stored cell spec was removed")
	}
	verified, err := r.verify(entry.Value(), nil)
	if newer := (*cellspec.NewerBinaryError)(nil); errors.As(err, &newer) {
		slog.Warn("stored cell spec needs a newer binary; keeping the current spec", observability.ComponentKey, "cellspec",
			"revision", entry.Revision(), "generation", newer.Generation, "requires_binary", newer.RequiresBinary,
			"binary_level", cellspec.BinaryLevel)
		return err
	}
	if err != nil {
		slog.Error("stored cell spec rejected; keeping the current spec", observability.ComponentKey, "cellspec",
			"revision", entry.Revision(), "error", err)
		return fmt.Errorf("stored cell spec rejected: %w", err)
	}
	r.adopt(verified.Spec, entry.Revision())
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revision < entry.Revision() {
		return errors.New("stored cell spec could not be adopted")
	}
	return nil
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
	if profiles == nil {
		profiles = make(map[string]WorkloadProfile)
	}
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
	if desired := spec.OCIDesired; desired != nil {
		if r.ociRegion == nil {
			return errors.New("desired OCI resources need the signed region config")
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
	limit, headroom := r.artifactStoreLimit, specStoreHeadroomBytes
	if spec.MachinesAPI != nil {
		limit, headroom = limit-machinesAPIStoreBytes, headroom+machinesAPIStoreBytes
	}
	if store := spec.ArtifactStore; store != nil && store.MaxBytes > limit {
		return fmt.Errorf("artifact_store max_bytes %d exceeds this controller's %d: its embedded NATS store_max_bytes less %d bytes for control state",
			store.MaxBytes, max(limit, 0), headroom)
	}
	return validateAutoscaleConfig(&AutoscaleConfig{Services: specs}, profiles)
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
		peer, member := members.Member(grant.Node, grant.PrivateIP)
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
	if profiles == nil {
		profiles = make(map[string]WorkloadProfile)
	}
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

// hostGrants is a copy of the current spec's host grants.
func (r *specRegistry) hostGrants() []cellspec.HostGrant {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.current.HostGrants)
}

// controllerNode returns the node whose VM runs controller slot of cell: the
// host grant that names the slot, else the slot's NATS server name.
func (r *specRegistry) controllerNode(cell, slot string) string {
	if r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, grant := range r.current.HostGrants {
			if grant.Controller == slot {
				return grant.Node
			}
		}
	}
	return naming.NATSServer(cell, slot)
}

func (r *specRegistry) profiles() map[string]WorkloadProfile {
	profiles, _ := r.effective()
	return profiles
}

func sameSpec(a, b cellspec.Spec) bool {
	left, leftErr := cellspec.Digest(a)
	right, rightErr := cellspec.Digest(b)
	return leftErr == nil && rightErr == nil && left == right
}
