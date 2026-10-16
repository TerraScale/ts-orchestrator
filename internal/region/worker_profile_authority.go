package region

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type VerifiedWorkerProfile struct {
	profile     WorkerProfile
	image       release.VerifiedImage
	grantDigest string
	generation  uint64
	expires     time.Time
	reader      *SignedFootprint
	bindings    foundationbinding.VerifiedBindings
}

func (p VerifiedWorkerProfile) IsVerified() bool {
	return p.reader != nil && p.grantDigest != "" && p.image.IsVerified()
}
func (p VerifiedWorkerProfile) Profile() WorkerProfile { return cloneWorkerProfile(p.profile) }
func (p VerifiedWorkerProfile) GrantDigest() string    { return p.grantDigest }
func (p VerifiedWorkerProfile) Generation() uint64     { return p.generation }
func (p VerifiedWorkerProfile) ExpiresAt() time.Time   { return p.expires }

// WorkerProfiles loads authorization independently of the candidate requester.
func (r FoundationResolver) WorkerProfiles(ctx context.Context, cell, role string) ([]VerifiedWorkerProfile, error) {
	reader, ok := r.Footprint.(*SignedFootprint)
	if !ok {
		return nil, errors.New("worker profiles require the independent signed foundation reader")
	}
	return reader.WorkerProfiles(ctx, cell, role)
}

func (s *SignedFootprint) WorkerProfiles(ctx context.Context, cell, role string) ([]VerifiedWorkerProfile, error) {
	wire, err := s.readGrant(ctx)
	if err != nil {
		return nil, err
	}
	_, expires, err := s.verifyGrant(wire)
	if err != nil {
		return nil, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return nil, err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	if grant.InfrastructureSpend == nil || grant.InfrastructureSpend.MonthlyLimitMinor <= 0 || len(grant.WorkerProfiles) > 512 {
		return nil, errors.New("worker authority lacks explicit bounded fleet spending")
	}
	var result []VerifiedWorkerProfile
	seen := map[string]bool{}
	images := map[string]releasechannel.CurrentImage{}
	var bindings foundationbinding.VerifiedBindings
	for _, profile := range grant.WorkerProfiles {
		if err := ValidateWorkerProfile(grant, profile); err != nil {
			return nil, err
		}
		identity := profile.Cell + "/" + profile.Role + "/" + profile.Architecture + "/" + profile.Shape
		if seen[identity] {
			return nil, errors.New("ambiguous root-signed worker profile")
		}
		seen[identity] = true
		if profile.Cell != cell || profile.Role != role {
			continue
		}
		if s.factory == nil || profile.ImageSource.Namespace != s.storage.Namespace {
			return nil, errors.New("worker current image requires the independently authenticated OCI source")
		}
		current, checked := images[profile.Architecture]
		if !checked {
			var found bool
			current, found, err = releasechannel.ReadCurrentImageSDK(ctx, s.factory, profile.ImageSource.Namespace, s.roots,
				releasechannel.CurrentImageExpectation{Cell: cell, Environment: profile.Environment, Architecture: profile.Architecture, Role: role}, time.Now())
			if err != nil {
				return nil, err
			}
			if !found {
				current = releasechannel.CurrentImage{}
			}
			images[profile.Architecture] = current
		}
		if !current.Image.IsVerified() {
			continue
		}
		image := current.Image
		if bindings.GrantSHA256() == "" {
			bindings, err = s.resourceBindingsFor(ctx, cell, wire, "control_compartment", "workload_compartment", "subnet", "workload_network_security_group", "vault", "key")
			if err != nil {
				return nil, err
			}
		}
		if bindings.GrantSHA256() != s.home.GrantSHA256 || bindings.Generation() != grant.Generation {
			return nil, errors.New("worker bindings differ from the same root grant")
		}
		deadline := expires
		if bindings.ExpiresAt().Before(deadline) {
			deadline = bindings.ExpiresAt()
		}
		if image.ExpiresAt().Before(deadline) {
			deadline = image.ExpiresAt()
		}
		for _, wire := range [][]byte{current.QualificationWire, current.QualificationDelegationWire} {
			if len(wire) == 0 {
				continue
			}
			envelope, err := trust.DecodeEnvelope(wire)
			if err != nil {
				return nil, err
			}
			if envelope.ExpiresAt.Before(deadline) {
				deadline = envelope.ExpiresAt
			}
		}
		result = append(result, VerifiedWorkerProfile{profile: cloneWorkerProfile(profile), image: image, grantDigest: s.home.GrantSHA256,
			generation: grant.Generation, expires: deadline, reader: s, bindings: bindings})
	}
	if len(result) == 0 {
		return nil, errors.New("root grant has no matching worker authority")
	}
	return result, nil
}

// ValidateWorkerProfile is shared by the unsigned producer and signed consumer.
func ValidateWorkerProfile(grant FoundationGrant, p WorkerProfile) error {
	if p.Cell == "" || p.Environment != "production" || p.Role != "container" && p.Role != "wasm" ||
		p.Architecture != "arm64" && p.Architecture != "amd64" || p.Shape == "" || len(p.Shape) > 128 ||
		p.OCPUs != 2 || p.MemoryGB != 12 || p.BootGB != 50 || len(p.AvailabilityDomains) == 0 ||
		len(p.AvailabilityDomains) > 4 || p.Bootstrap.Derivation != WorkerBootstrapDerivationV1 ||
		p.Bootstrap.RecipientPermission != "SECRET_BUNDLE_READ" || len(p.ImageReceipt) > 1<<20 || len(p.ImageDelegation) > 1<<20 || p.Runtime != release.ProductionRuntime ||
		(len(p.ImageReceipt) == 0) != (len(p.ImageDelegation) == 0) || p.RuntimeSHA256 != "" && !workerDigest(p.RuntimeSHA256) {
		return errors.New("invalid fixed production worker profile")
	}
	entry, known := catalog.Lookup(p.Cell)
	bucket, bucketErr := releasechannel.BucketName(p.Cell)
	if !known || bucketErr != nil || p.ImageSource.OCIRegion != entry.OCIRegion || p.ImageSource.Namespace == "" ||
		p.ImageSource.Bucket != bucket || p.ImageSource.CurrentObject != releasechannel.CurrentImageObject(p.Role, p.Architecture, p.Environment) ||
		p.ImageSource.ImageDomain != release.ImageDomain || p.ImageSource.QualificationDomain != release.ProductionQualificationDomain {
		return errors.New("worker image source is outside the fixed qualified release channel")
	}
	seenAD := map[string]bool{}
	for _, ad := range p.AvailabilityDomains {
		if ad == "" || len(ad) > 255 || strings.ContainsAny(ad, "\r\n") || seenAD[ad] {
			return errors.New("invalid worker availability domain")
		}
		seenAD[ad] = true
	}
	for _, pair := range [][2]string{{p.CompartmentRef, "workload_compartment"}, {p.SubnetRef, "subnet"}, {p.NSGRef, "workload_network_security_group"}, {p.Bootstrap.VaultRef, "vault"}, {p.Bootstrap.KMSKeyRef, "key"}} {
		expected, err := FoundationResourceReference(p.Cell, pair[1])
		if err != nil || pair[0] != expected {
			return errors.New("worker authority is outside its signed logical foundation role")
		}
	}
	for _, region := range grant.Regions {
		if region.Plan["cell"] == p.Cell && region.BootstrapMaterial != nil && region.BootstrapMaterial.PlanSHA256 == p.Bootstrap.MaterialPlanSHA256 &&
			region.BootstrapMaterial.Config.Environment == p.Environment && region.BootstrapMaterial.SourceRegistration != nil &&
			region.BootstrapMaterial.SourceRegistration.StorageDomain.Namespace == p.ImageSource.Namespace {
			return nil
		}
	}
	return errors.New("worker bootstrap source is outside the same signed regional generation")
}

// VerifiedWorkerRecipe binds root policy, protected OCI provenance and the
// authenticated generated source. A recipe alone cannot manufacture this proof.
type VerifiedWorkerRecipe struct {
	profile VerifiedWorkerProfile
	source  bootstrap.VerifiedRegionalSource
	recipe  WorkerRecipe
}

func (p VerifiedWorkerProfile) Bind(ctx context.Context, source bootstrap.VerifiedRegionalSource, caWire []byte) (VerifiedWorkerRecipe, error) {
	if !p.IsVerified() || !time.Now().Before(p.expires) || !source.IsVerified() ||
		source.Template().GrantDigest() != p.grantDigest || source.Template().Generation() != p.generation ||
		source.Template().PlanDigest() != p.profile.Bootstrap.MaterialPlanSHA256 {
		return VerifiedWorkerRecipe{}, errors.New("worker source differs from exact signed profile")
	}
	if err := source.VerifyCurrent(ctx, time.Now()); err != nil {
		return VerifiedWorkerRecipe{}, err
	}
	var record bootstrapmaterial.Record
	if err := json.Unmarshal(source.MaterialRecord(), &record, json.RejectUnknownMembers(true)); err != nil {
		return VerifiedWorkerRecipe{}, err
	}
	bundle, err := workerPublicBundle(record, caWire, p.profile)
	if err != nil {
		return VerifiedWorkerRecipe{}, err
	}
	publicWire, err := json.Marshal(bundle, json.Deterministic(true))
	if err != nil {
		return VerifiedWorkerRecipe{}, err
	}
	compartment, err := p.bindings.Resolve(p.profile.CompartmentRef)
	if err != nil {
		return VerifiedWorkerRecipe{}, err
	}
	subnet, err := p.bindings.Resolve(p.profile.SubnetRef)
	if err != nil {
		return VerifiedWorkerRecipe{}, err
	}
	nsg, err := p.bindings.Resolve(p.profile.NSGRef)
	if err != nil {
		return VerifiedWorkerRecipe{}, err
	}
	recipe := WorkerRecipe{Cell: strings.ToLower(p.profile.Cell), Environment: p.profile.Environment, Role: p.profile.Role,
		Architecture: p.profile.Architecture, ImageID: p.image.Receipt().OCIImageOCID, CompartmentID: compartment, SubnetID: subnet,
		NSGIDs: []string{nsg}, AvailabilityDomains: slices.Clone(p.profile.AvailabilityDomains), Shape: p.profile.Shape,
		OCPUs: p.profile.OCPUs, MemoryGB: p.profile.MemoryGB, BootGB: p.profile.BootGB,
		Metadata: map[string]string{hostboot.NodePoolMetadataKey: `{"schemaVersion":1}`, hostboot.EnrollmentMetadataKey: string(publicWire)}}
	return VerifiedWorkerRecipe{profile: p, source: source, recipe: recipe}, nil
}

func (v VerifiedWorkerRecipe) IsVerified() bool {
	return v.profile.IsVerified() && v.source.IsVerified() && v.recipe.ImageID != "" && time.Now().Before(v.profile.expires) && time.Now().Before(v.source.ExpiresAt())
}
func (v VerifiedWorkerRecipe) Recipe() WorkerRecipe {
	r := v.recipe
	r.NSGIDs = slices.Clone(r.NSGIDs)
	r.AvailabilityDomains = slices.Clone(r.AvailabilityDomains)
	r.Metadata = maps.Clone(r.Metadata)
	return r
}
func (v VerifiedWorkerRecipe) Profile() VerifiedWorkerProfile { return v.profile }
func (v VerifiedWorkerRecipe) SourceSHA256() string {
	if !v.source.IsVerified() {
		return ""
	}
	envelope, err := trust.DecodeEnvelope(v.source.Inventory())
	if err != nil {
		return ""
	}
	var inventory bootstrap.RegionalSourceInventory
	if err := json.Unmarshal(envelope.Payload, &inventory, json.RejectUnknownMembers(true)); err != nil {
		return ""
	}
	return inventory.SourceSHA256
}
func (v VerifiedWorkerRecipe) InventorySHA256() string {
	if !v.source.IsVerified() {
		return ""
	}
	return workerSHA256(v.source.Inventory())
}

func (v VerifiedWorkerRecipe) Match(candidate WorkerRecipe) error {
	if !v.IsVerified() {
		return errors.New("worker recipe has no independent authority")
	}
	expected := v.Recipe()
	// A launch may select a subset of the root-authorized placement domains.
	if len(candidate.AvailabilityDomains) == 0 {
		return errors.New("worker placement is absent")
	}
	seenAD := map[string]bool{}
	for _, ad := range candidate.AvailabilityDomains {
		if !slices.Contains(expected.AvailabilityDomains, ad) || seenAD[ad] {
			return errors.New("worker placement is outside signed authority")
		}
		seenAD[ad] = true
	}
	expected.AvailabilityDomains = slices.Clone(candidate.AvailabilityDomains)
	expected.NSGIDs = slices.Sorted(slices.Values(expected.NSGIDs))
	candidate.NSGIDs = slices.Sorted(slices.Values(candidate.NSGIDs))
	left, err := json.Marshal(expected, json.Deterministic(true))
	if err != nil {
		return err
	}
	right, err := json.Marshal(candidate, json.Deterministic(true))
	if err != nil {
		return err
	}
	if !bytes.Equal(left, right) {
		return errors.New("worker recipe differs from independently derived root authority")
	}
	return nil
}

func (v VerifiedWorkerRecipe) Revalidate(ctx context.Context) error {
	if !v.IsVerified() || !time.Now().Before(v.profile.expires) {
		return errors.New("worker authority expired")
	}
	if err := v.profile.bindings.Revalidate(ctx); err != nil {
		return err
	}
	if err := v.source.VerifyCurrent(ctx, time.Now()); err != nil {
		return err
	}
	profiles, err := v.profile.reader.WorkerProfiles(ctx, v.profile.profile.Cell, v.profile.profile.Role)
	if err != nil {
		return err
	}
	want, _ := json.Marshal(v.profile.profile, json.Deterministic(true))
	for _, profile := range profiles {
		actual, _ := json.Marshal(profile.profile, json.Deterministic(true))
		if profile.grantDigest == v.profile.grantDigest && profile.image.EnvelopeSHA256() == v.profile.image.EnvelopeSHA256() && bytes.Equal(actual, want) {
			return nil
		}
	}
	return errors.New("worker policy changed since recipe derivation")
}

func workerPublicBundle(record bootstrapmaterial.Record, caWire []byte, p WorkerProfile) (hostenroll.PublicBundle, error) {
	if record.SchemaVersion != 1 || record.Config.Validate() != nil || record.Config.Cell != strings.ToLower(p.Cell) || record.Config.Environment != p.Environment || !time.Now().Before(record.ExpiresAt) {
		return hostenroll.PublicBundle{}, errors.New("worker material record differs from signed source")
	}
	found := false
	for _, file := range record.Files {
		if file.Name == "ca.pem" {
			if found || file.Purpose != bootstrap.SecretRegionalShared || file.Slot != "" || file.MaxBytes != int64(len(caWire)) || file.SHA256 != workerSHA256(caWire) {
				return hostenroll.PublicBundle{}, errors.New("worker public CA differs from authenticated source")
			}
			found = true
		}
	}
	if !found {
		return hostenroll.PublicBundle{}, errors.New("worker source contains no public CA")
	}
	bundle := hostenroll.PublicBundle{SchemaVersion: 1, Cell: record.Config.Cell, Region: p.Cell, Environment: p.Environment, CAPEM: string(caWire), ControllerResponsePublicKey: record.Public.ControllerResponsePublicKey, CellAccountNKey: record.Public.CellAccountNKey,
		InstallRoot: hostenroll.ImageInstallRoot, StateRoot: hostenroll.ImageStateRoot, ManagedRuntimeRoot: hostenroll.ImageManagedRuntimeRoot, WorkloadUID: hostenroll.ImageWorkloadUID, WorkloadGID: hostenroll.ImageWorkloadGID}
	for i, slot := range record.Config.Slots {
		if slot.Name != fmt.Sprintf("controller-%c", 'a'+i) {
			return hostenroll.PublicBundle{}, errors.New("worker source controller order differs")
		}
		bundle.ControllerEndpoints = append(bundle.ControllerEndpoints, slot.PrivateIP+":8443")
		bundle.NATSURLs = append(bundle.NATSURLs, "tls://"+slot.PrivateIP+":4222")
	}
	return bundle, bundle.Validate()
}

func cloneWorkerProfile(p WorkerProfile) WorkerProfile {
	p.AvailabilityDomains = slices.Clone(p.AvailabilityDomains)
	p.ImageReceipt = bytes.Clone(p.ImageReceipt)
	p.ImageDelegation = bytes.Clone(p.ImageDelegation)
	return p
}
func workerSHA256(wire []byte) string { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }
func workerDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

// ValidateWorkerProfiles validates the explicit entire role/architecture policy
// before signing. Missing qualified images leave runtime capacity pending.
func ValidateWorkerProfiles(grant FoundationGrant, profiles []WorkerProfile, roots trust.Keyring, now time.Time) error {
	if grant.InfrastructureSpend == nil || grant.InfrastructureSpend.MonthlyLimitMinor <= 0 || len(profiles) > 512 {
		return errors.New("worker authority lacks explicit bounded fleet spending")
	}
	seen := map[string]bool{}
	coverage := map[string]bool{}
	for _, p := range profiles {
		if err := ValidateWorkerProfile(grant, p); err != nil {
			return err
		}
		id := p.Cell + "/" + p.Role + "/" + p.Architecture + "/" + p.Shape
		if seen[id] {
			return errors.New("duplicate signed worker geometry")
		}
		seen[id] = true
		coverage[p.Cell+"/"+p.Role+"/"+p.Architecture] = true
		if len(p.ImageReceipt) == 0 {
			if p.RuntimeSHA256 != "" {
				return errors.New("worker seed digest has no seed receipt")
			}
			continue
		}
		image, err := release.VerifyImageCurrent(p.ImageReceipt, p.ImageDelegation, roots, release.ImageExpectation{Environment: p.Environment, LogicalRegion: p.Cell, Architecture: p.Architecture}, now)
		if err != nil {
			return err
		}
		receipt := image.Receipt()
		if p.RuntimeSHA256 != receipt.ImageSHA256 || receipt.Production == nil {
			return errors.New("worker seed evidence differs from signed image")
		}
		proof, ok := receipt.HostProduction[p.Role]
		if !ok {
			return errors.New("worker seed lacks exact role qualification")
		}
		candidate := release.ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256, QualificationSHA256: receipt.QualificationSHA256, Cell: p.Cell, Environment: p.Environment, Runtime: p.Runtime, Architecture: p.Architecture, Role: p.Role}
		if _, err := release.VerifyProductionCurrent(proof.Qualification, proof.Delegation, roots, candidate, now); err != nil {
			return err
		}
	}
	for _, region := range grant.Regions {
		cell, _ := region.Plan["cell"].(string)
		for _, role := range []string{"container", "wasm"} {
			for _, arch := range []string{"arm64", "amd64"} {
				if !coverage[cell+"/"+role+"/"+arch] {
					return errors.New("signed worker policy omits an approved role or architecture")
				}
			}
		}
	}
	return nil
}

// AuthorizeWorkerRecipe is the concrete home-side consumer. Request metadata
// contributes only public CA bytes whose hash the independent source pins.
func (r FoundationResolver) AuthorizeWorkerRecipe(ctx context.Context, candidate WorkerRecipe) (VerifiedWorkerRecipe, error) {
	profiles, err := r.WorkerProfiles(ctx, strings.ToUpper(candidate.Cell), candidate.Role)
	if err != nil {
		return VerifiedWorkerRecipe{}, err
	}
	bundle, err := hostenroll.ParsePublicBundle([]byte(candidate.Metadata[hostboot.EnrollmentMetadataKey]))
	if err != nil {
		return VerifiedWorkerRecipe{}, err
	}
	for _, profile := range profiles {
		if profile.profile.Architecture != candidate.Architecture || profile.profile.Shape != candidate.Shape {
			continue
		}
		source, err := profile.reader.workerSource(ctx, profile.profile.Cell)
		if err != nil {
			return VerifiedWorkerRecipe{}, err
		}
		recipe, err := profile.Bind(ctx, source, []byte(bundle.CAPEM))
		if err != nil {
			return VerifiedWorkerRecipe{}, err
		}
		if err := recipe.Match(candidate); err != nil {
			return VerifiedWorkerRecipe{}, err
		}
		if err := recipe.Revalidate(ctx); err != nil {
			return VerifiedWorkerRecipe{}, err
		}
		return recipe, nil
	}
	return VerifiedWorkerRecipe{}, errors.New("worker candidate has no exact signed role/architecture/shape policy")
}

// WorkerRecipes supplies launch bases from independent authority instead of the
// controller's own shape, subnet, NSGs, SSH keys or other instance metadata.
func (r FoundationResolver) WorkerRecipes(ctx context.Context, cell, role string, caWire []byte) ([]VerifiedWorkerRecipe, error) {
	profiles, err := r.WorkerProfiles(ctx, cell, role)
	if err != nil {
		return nil, err
	}
	source, err := profiles[0].reader.workerSource(ctx, cell)
	if err != nil {
		return nil, err
	}
	recipes := make([]VerifiedWorkerRecipe, 0, len(profiles))
	for _, profile := range profiles {
		recipe, err := profile.Bind(ctx, source, caWire)
		if err != nil {
			return nil, err
		}
		recipes = append(recipes, recipe)
	}
	return recipes, nil
}

func (s *SignedFootprint) workerSource(ctx context.Context, cell string) (bootstrap.VerifiedRegionalSource, error) {
	if !s.bootstrapAnchor.IsVerified() {
		return bootstrap.VerifiedRegionalSource{}, errors.New("worker source requires the original independently verified bootstrap anchor")
	}
	wire, err := s.readGrant(ctx)
	if err != nil {
		return bootstrap.VerifiedRegionalSource{}, err
	}
	template, err := bootstrap.VerifyRegionalStartupTemplate(wire, s.roots, s.bootstrapAnchor, oci.Region(cell), time.Now())
	if err != nil {
		return bootstrap.VerifiedRegionalSource{}, err
	}
	return bootstrap.LoadRegionalSource(ctx, template, s.client, time.Now())
}

// WorkerVaultTarget is the exact owned Vault for a separately authenticated
// instance-recipient grant. It confers no permission to read controller secrets.
func (v VerifiedWorkerRecipe) WorkerVaultTarget() (bootstrapmaterial.VaultTarget, error) {
	if !v.IsVerified() {
		return bootstrapmaterial.VaultTarget{}, errors.New("worker Vault target lacks recipe authority")
	}
	control, _ := FoundationResourceReference(v.profile.profile.Cell, "control_compartment")
	compartment, err := v.profile.bindings.Resolve(control)
	if err != nil {
		return bootstrapmaterial.VaultTarget{}, err
	}
	vault, err := v.profile.bindings.Resolve(v.profile.profile.Bootstrap.VaultRef)
	if err != nil {
		return bootstrapmaterial.VaultTarget{}, err
	}
	key, err := v.profile.bindings.Resolve(v.profile.profile.Bootstrap.KMSKeyRef)
	if err != nil {
		return bootstrapmaterial.VaultTarget{}, err
	}
	return bootstrapmaterial.VaultTarget{CompartmentOCID: compartment, VaultOCID: vault, KMSKeyOCID: key}, nil
}
