package bootstrap

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// FounderPlanAuthority retains the original root or source-derived proof while
// sharing the exact managed-peer intent, launch and recovery checks.
type FounderPlanAuthority interface {
	IsVerified() bool
	Plan() FounderPlan
	Digest() string
	ControllerFailureDomains() (map[string]ControllerFailureDomain, error)
	InitialManagedPeerIntent(string, time.Time) (Intent, error)
	ReplacementManagedPeerIntent(string, SlotState, []byte, time.Time) (Intent, error)
	VerifyFounderPlanCurrent(context.Context, trust.Keyring, time.Time, trust.Policy) error
	AuthorizeFounderPeer(context.Context, string, LaunchAuthorization, trust.Keyring, time.Time, trust.Policy) (VerifiedFounderPeer, error)
	AuthorizeFounderPeerRecovery(context.Context, string, ManagedPeerRecoveryAuthorization, trust.Keyring, time.Time, time.Time, trust.Policy) (VerifiedFounderPeer, error)
	sealedFounderPlanAuthority()
}

// FounderPlanContinuation carries only the identity of already completed peers.
// It grants no new launch, observation or repair authority.
type FounderPlanContinuation interface {
	IsVerified() bool
	Digest() string
	ControllerFailureDomains() (map[string]ControllerFailureDomain, error)
	SeedSlot() string
	PeerRow(string) (FounderPeerRow, bool)
	StoredCompletionBeforeLaunchDeadline(time.Time, time.Time) bool
	sealedFounderPlanContinuation()
}

type founderPlanSnapshot struct {
	plan                       FounderPlan
	digest                     string
	anchor                     BootstrapAnchor
	manifests                  map[string]StartupAuthority
	manifestWires              map[string][]byte
	expiresAt, anchorExpiresAt time.Time
}

func (verified VerifiedFounderPlan) snapshot() founderPlanSnapshot {
	manifests := make(map[string]StartupAuthority, len(verified.manifests))
	for slot, manifest := range verified.manifests {
		manifests[slot] = manifest
	}
	return founderPlanSnapshot{plan: verified.plan, digest: verified.digest, anchor: verified.anchor.Anchor(),
		manifests: manifests, manifestWires: verified.manifestWires,
		expiresAt: verified.envelope.ExpiresAt, anchorExpiresAt: verified.anchor.ExpiresAt()}
}

func (VerifiedFounderPlan) sealedFounderPlanAuthority()             {}
func (VerifiedCompletedFounderPlan) sealedFounderPlanContinuation() {}

func (verified VerifiedFounderPlan) VerifyFounderPlanCurrent(ctx context.Context, roots trust.Keyring, now time.Time, policy trust.Policy) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !verified.IsVerified() {
		return ErrFounderPlanAuthorization
	}
	_, err := VerifyFounderPlan(verified.wire, roots, verified.anchorWire, verified.manifestWires, now, policy)
	return err
}

func (verified VerifiedFounderPlan) AuthorizeFounderPeer(ctx context.Context, slot string, launch LaunchAuthorization, roots trust.Keyring, now time.Time, policy trust.Policy) (VerifiedFounderPeer, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedFounderPeer{}, err
	}
	return verified.AuthorizePeer(slot, launch, roots, now, policy)
}

func (verified VerifiedFounderPlan) AuthorizeFounderPeerRecovery(ctx context.Context, slot string, recovery ManagedPeerRecoveryAuthorization, roots trust.Keyring, now, selectorExpiresAt time.Time, policy trust.Policy) (VerifiedFounderPeer, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedFounderPeer{}, err
	}
	return verified.AuthorizePeerRecovery(slot, recovery, roots, now, selectorExpiresAt, policy)
}

// DerivedFounderPlan is a finite rendering of the signed startup recipe and
// all three immutable source-CAS proofs. It is never a root-signed plan.
type DerivedFounderPlan struct {
	snapshotValue founderPlanSnapshot
	authorities   map[string]DerivedStartupAuthority
	seed          DerivedStartupAuthority
}

// LoadSeedStartupAuthority lets any admitted slot recover the seed's genuine
// proof using only its retained signed recipe and original source reader.
func LoadSeedStartupAuthority(ctx context.Context, authority DerivedStartupAuthority, now time.Time) (DerivedStartupAuthority, error) {
	if !validFounderNow(now) || !authority.IsVerified() {
		return DerivedStartupAuthority{}, ErrFounderPlanAuthorization
	}
	if err := authority.VerifyCurrent(ctx, now); err != nil {
		return DerivedStartupAuthority{}, err
	}
	seed, err := LoadDerivedStartupAuthority(ctx, authority.template, authority.client, authority.template.template.SeedSlot, now)
	if err != nil {
		return DerivedStartupAuthority{}, err
	}
	if seed.SourceSHA256() != authority.SourceSHA256() || seed.MaterialSHA256() != authority.MaterialSHA256() {
		return DerivedStartupAuthority{}, ErrFounderPlanAuthorization
	}
	return seed, nil
}

// NewDerivedFounderPlan loads every slot from the seed's original source CAS.
// A passed launch deadline still permits completed-peer continuation; every
// effect-authorizing method independently enforces that deadline.
func NewDerivedFounderPlan(ctx context.Context, seed DerivedStartupAuthority, now time.Time) (DerivedFounderPlan, error) {
	if !validFounderNow(now) || !seed.IsVerified() || seed.Manifest().Slot != seed.template.template.SeedSlot {
		return DerivedFounderPlan{}, ErrFounderPlanAuthorization
	}
	if err := seed.VerifyCurrent(ctx, now); err != nil {
		return DerivedFounderPlan{}, fmt.Errorf("%w: current seed proof: %v", ErrFounderPlanAuthorization, err)
	}
	template := seed.template
	identity := template.startupIdentity()
	resources := template.template.FounderResources
	if resources == nil || resources.Validate(identity.ControllerSlots) != nil ||
		!resources.LaunchDeadline.After(seed.IssuedAt()) || resources.LaunchDeadline.After(seed.IssuedAt().Add(maxRetryAge)) ||
		resources.LaunchDeadline.After(seed.ExpiresAt()) || resources.LaunchDeadline.After(template.ExpiresAt()) ||
		!resources.LaunchDeadline.Before(template.anchor.ExpiresAt()) {
		return DerivedFounderPlan{}, ErrFounderPlanInvalid
	}
	authorities := make(map[string]DerivedStartupAuthority, len(identity.ControllerSlots))
	manifests := make(map[string]StartupAuthority, len(identity.ControllerSlots))
	wires := make(map[string][]byte, len(identity.ControllerSlots))
	ips := make(map[string]string, len(identity.ControllerSlots))
	for _, slot := range identity.ControllerSlots {
		authority, err := LoadDerivedStartupAuthority(ctx, template, seed.client, slot, now)
		if err != nil {
			return DerivedFounderPlan{}, fmt.Errorf("%w: slot %q source proof: %v", ErrFounderPlanAuthorization, slot, err)
		}
		if authority.TemplateDigest() != seed.TemplateDigest() || authority.SourceSHA256() != seed.SourceSHA256() ||
			authority.MaterialSHA256() != seed.MaterialSHA256() || authority.binding.GrantSHA256 != seed.binding.GrantSHA256 ||
			!authority.IssuedAt().Equal(seed.IssuedAt()) || !authority.ExpiresAt().Equal(seed.ExpiresAt()) ||
			slot == template.template.SeedSlot && authority.Digest() != seed.Digest() {
			return DerivedFounderPlan{}, fmt.Errorf("%w: source proof changed for slot %q", ErrFounderPlanAuthorization, slot)
		}
		ip, err := template.SlotPrivateIP(slot)
		if err != nil {
			return DerivedFounderPlan{}, err
		}
		authorities[slot], manifests[slot], wires[slot], ips[slot] = authority, authority, authority.Wire(), ip
	}
	plan := FounderPlan{SchemaVersion: FounderPlanSchemaVersion, DeploymentID: identity.DeploymentID,
		Cell: identity.Cell, Environment: identity.Environment, SeedSlot: template.template.SeedSlot,
		AnchorSHA256: seed.AnchorDigest(), ControllerSlots: slices.Clone(identity.ControllerSlots),
		SeedManifestSHA256: seed.Digest(), SeedPrivateIP: ips[template.template.SeedSlot], LaunchDeadline: resources.LaunchDeadline}
	for _, resource := range resources.Slots {
		if resource.Slot == plan.SeedSlot {
			continue
		}
		authority := authorities[resource.Slot]
		profile, ok := authority.Profile(resource.Slot)
		if !ok {
			return DerivedFounderPlan{}, ErrFounderPlanInvalid
		}
		tls, err := derivedFounderTLS(authority)
		if err != nil {
			return DerivedFounderPlan{}, err
		}
		row := FounderPeerRow{Slot: resource.Slot, ManifestSHA256: authority.Digest(), ImageOCID: authority.Manifest().ImageOCID,
			ImageCompartmentOCID: resource.ImageCompartmentOCID, CompartmentOCID: profile.CompartmentOCID,
			AvailabilityDomain: profile.AvailabilityDomain, FaultDomain: profile.FaultDomain, SubnetOCID: profile.SubnetOCID,
			NetworkSecurityGroupOCIDs: slices.Clone(profile.NetworkSecurityGroupOCIDs), Shape: profile.Shape,
			WholeOCPUs: resource.WholeOCPUs, MemoryInGB: resource.MemoryInGB, BootVolumeGB: resource.BootVolumeGB,
			BootVolumeTier: resource.BootVolumeTier, PrivateIP: ips[resource.Slot], TLSMaterial: tls,
			ClientEndpoints: []FounderEndpoint{{Slot: resource.Slot, PrivateIP: ips[resource.Slot], Port: 4222}}}
		for _, slot := range identity.ControllerSlots {
			if slot != resource.Slot {
				row.RouteEndpoints = append(row.RouteEndpoints, FounderEndpoint{Slot: slot, PrivateIP: ips[slot], Port: 6222})
			}
		}
		var cpuOK, memoryOK, bootOK bool
		plan.Budget.WholeOCPUs, cpuOK = addFounderBudget(plan.Budget.WholeOCPUs, row.WholeOCPUs)
		plan.Budget.MemoryInGB, memoryOK = addFounderBudget(plan.Budget.MemoryInGB, row.MemoryInGB)
		plan.Budget.BootVolumeGB, bootOK = addFounderBudget(plan.Budget.BootVolumeGB, row.BootVolumeGB)
		if !cpuOK || !memoryOK || !bootOK {
			return DerivedFounderPlan{}, ErrFounderPlanInvalid
		}
		plan.Peers = append(plan.Peers, row)
	}
	if err := plan.Validate(); err != nil {
		return DerivedFounderPlan{}, err
	}
	// Wire hashes are ordered by the signed slot list; mutable source ETags do
	// not change the immutable plan identity when seed progress is persisted.
	proof := struct {
		Plan                              FounderPlan `json:"plan"`
		Grant, Template, Source, Material string
		Slots                             []string
	}{Plan: plan, Grant: template.GrantDigest(), Template: template.TemplateDigest(), Source: seed.SourceSHA256(), Material: seed.MaterialSHA256()}
	for _, slot := range identity.ControllerSlots {
		proof.Slots = append(proof.Slots, authorities[slot].Digest())
	}
	wire, err := json.Marshal(proof, json.Deterministic(true))
	if err != nil {
		return DerivedFounderPlan{}, err
	}
	return DerivedFounderPlan{snapshotValue: founderPlanSnapshot{plan: plan, digest: digestBytes(wire), anchor: identity,
		manifests: manifests, manifestWires: wires, expiresAt: earlierTime(seed.ExpiresAt(), template.ExpiresAt()),
		anchorExpiresAt: template.anchor.ExpiresAt()}, authorities: authorities, seed: seed}, nil
}

func derivedFounderTLS(authority DerivedStartupAuthority) (FounderTLSMaterialDigests, error) {
	slot := authority.Manifest().Slot
	var digests [3]string
	for index, name := range []string{"ca.pem", slot + "-tls-cert.pem", slot + "-tls-key.pem"} {
		for _, ref := range authority.Manifest().Secrets {
			if ref.TargetFile == name && (index == 0 && ref.Purpose == SecretRegionalShared || index > 0 && ref.Purpose == SecretController && ref.Slot == slot) {
				digests[index] = ref.SHA256
			}
		}
		if !validDigest(digests[index]) {
			return FounderTLSMaterialDigests{}, ErrFounderPlanInvalid
		}
	}
	return FounderTLSMaterialDigests{ClientCA: digests[0], ClientCertificate: digests[1], ClientPrivateKey: digests[2],
		RouteCA: digests[0], RouteCertificate: digests[1], RoutePrivateKey: digests[2]}, nil
}

func (DerivedFounderPlan) sealedFounderPlanAuthority() {}
func (verified DerivedFounderPlan) IsVerified() bool {
	return verified.seed.IsVerified() && validDigest(verified.snapshotValue.digest) && len(verified.authorities) == 3
}
func (verified DerivedFounderPlan) Plan() FounderPlan {
	return cloneFounderPlan(verified.snapshotValue.plan)
}
func (verified DerivedFounderPlan) Digest() string          { return verified.snapshotValue.digest }
func (verified DerivedFounderPlan) SelectionDigest() string { return verified.Digest() }
func (verified DerivedFounderPlan) SelectionGeneration() uint64 {
	return verified.seed.template.Generation()
}
func (verified DerivedFounderPlan) SeedAuthority() DerivedStartupAuthority { return verified.seed }
func (verified DerivedFounderPlan) Authority(slot string) (DerivedStartupAuthority, bool) {
	authority, ok := verified.authorities[slot]
	return authority, verified.IsVerified() && ok
}

func (verified DerivedFounderPlan) current(ctx context.Context, roots trust.Keyring, now time.Time) (DerivedFounderPlan, error) {
	if !verified.IsVerified() || !validFounderNow(now) || len(roots) == 0 {
		return DerivedFounderPlan{}, ErrFounderPlanAuthorization
	}
	seed := verified.seed
	home := seed.template.anchor.Anchor()
	envelope, err := trust.DecodeEnvelope(seed.template.anchor.Wire())
	if err != nil {
		return DerivedFounderPlan{}, err
	}
	anchor, err := VerifyBootstrapAnchor(envelope, roots, BootstrapAnchorExpectation{DeploymentID: home.DeploymentID, Environment: home.Environment, Cell: home.Cell}, now, BootstrapAnchorTrustPolicy())
	if err != nil {
		return DerivedFounderPlan{}, err
	}
	if seed.template.bindings != nil {
		if err := seed.template.bindings.Revalidate(ctx); err != nil {
			return DerivedFounderPlan{}, err
		}
	}
	template, err := verifyStartupTemplateForIdentityBindings(seed.GrantWire(), roots, anchor, seed.template.startupIdentity(), seed.template.bindings, now)
	if err != nil {
		return DerivedFounderPlan{}, err
	}
	seed, err = VerifyDerivedStartupAuthority(ctx, template, seed.client, seed.wire, now)
	if err != nil {
		return DerivedFounderPlan{}, err
	}
	current, err := NewDerivedFounderPlan(ctx, seed, now)
	if err != nil {
		return DerivedFounderPlan{}, err
	}
	if current.Digest() != verified.Digest() {
		return DerivedFounderPlan{}, ErrFounderPlanAuthorization
	}
	return current, nil
}

// RevalidateCurrent refreshes the original proof under the caller's current
// roots. It preserves completed-peer admission after the launch deadline.
func (verified DerivedFounderPlan) RevalidateCurrent(ctx context.Context, roots trust.Keyring, now time.Time) (DerivedFounderPlan, error) {
	return verified.current(ctx, roots, now)
}

func (verified DerivedFounderPlan) VerifyFounderPlanCurrent(ctx context.Context, roots trust.Keyring, now time.Time, policy trust.Policy) error {
	current, err := verified.current(ctx, roots, now)
	if err != nil {
		return err
	}
	if !now.Before(current.snapshotValue.plan.LaunchDeadline) {
		return ErrFounderPlanExpired
	}
	return nil
}

func (verified DerivedFounderPlan) InitialManagedPeerIntent(slot string, createdAt time.Time) (Intent, error) {
	if !verified.IsVerified() || !validFounderNow(createdAt) {
		return Intent{}, ErrFounderPeerAuthorization
	}
	return initialManagedPeerIntent(verified.snapshotValue, slot, createdAt)
}

func (verified DerivedFounderPlan) ReplacementManagedPeerIntent(slot string, previous SlotState, retirementWire []byte, createdAt time.Time) (Intent, error) {
	return replacementManagedPeerIntent(verified, slot, previous, retirementWire, createdAt)
}

func (verified DerivedFounderPlan) AuthorizeFounderPeer(ctx context.Context, slot string, launch LaunchAuthorization, roots trust.Keyring, now time.Time, policy trust.Policy) (VerifiedFounderPeer, error) {
	current, err := verified.current(ctx, roots, now)
	if err != nil {
		return VerifiedFounderPeer{}, err
	}
	return authorizeFounderPeer(current.snapshotValue, slot, launch, now)
}

func (verified DerivedFounderPlan) AuthorizeFounderPeerRecovery(ctx context.Context, slot string, recovery ManagedPeerRecoveryAuthorization, roots trust.Keyring, now, selectorExpiresAt time.Time, policy trust.Policy) (VerifiedFounderPeer, error) {
	if !recovery.verified || !validFounderNow(now) || !validFounderNow(selectorExpiresAt) {
		return VerifiedFounderPeer{}, ErrFounderPeerAuthorization
	}
	serverDate, authorizationTime := recovery.ServerDate(), recovery.AuthorizationTime()
	if serverDate.IsZero() || authorizationTime.IsZero() {
		return VerifiedFounderPeer{}, ErrFounderPeerAuthorization
	}
	if now.After(authorizationTime) {
		authorizationTime = now
	}
	if !selectorExpiresAt.After(authorizationTime) {
		return VerifiedFounderPeer{}, ErrFounderPlanExpired
	}
	if _, err := verified.current(ctx, roots, serverDate); err != nil {
		return VerifiedFounderPeer{}, err
	}
	current, err := verified.current(ctx, roots, authorizationTime)
	if err != nil {
		return VerifiedFounderPeer{}, err
	}
	return authorizeFounderPeerRecovery(current.snapshotValue, slot, recovery, authorizationTime, selectorExpiresAt)
}

// DerivedCompletedFounderPlan keeps derived provenance distinct after launch
// authority ends. All original signatures and source proofs must remain current.
type DerivedCompletedFounderPlan struct {
	plan           FounderPlan
	digest         string
	seed           DerivedStartupAuthority
	failureDomains map[string]ControllerFailureDomain
}

func (verified DerivedFounderPlan) ForCompletedPeerContinuation(ctx context.Context, now time.Time) (DerivedCompletedFounderPlan, error) {
	current, err := verified.current(ctx, verified.seed.template.roots, now)
	if err != nil {
		return DerivedCompletedFounderPlan{}, err
	}
	// Historical continuation stays readable; execution separately requires this projection.
	domains, _ := current.ControllerFailureDomains()
	return DerivedCompletedFounderPlan{plan: current.Plan(), digest: current.Digest(), seed: current.seed, failureDomains: domains}, nil
}

func (DerivedCompletedFounderPlan) sealedFounderPlanContinuation() {}
func (verified DerivedCompletedFounderPlan) IsVerified() bool {
	return verified.seed.IsVerified() && validDigest(verified.digest)
}
func (verified DerivedCompletedFounderPlan) Digest() string   { return verified.digest }
func (verified DerivedCompletedFounderPlan) SeedSlot() string { return verified.plan.SeedSlot }
func (verified DerivedCompletedFounderPlan) PeerRow(slot string) (FounderPeerRow, bool) {
	if verified.IsVerified() {
		for _, row := range verified.plan.Peers {
			if row.Slot == slot {
				return cloneFounderPeerRow(row), true
			}
		}
	}
	return FounderPeerRow{}, false
}
func (verified DerivedCompletedFounderPlan) StoredCompletionBeforeLaunchDeadline(resultStored, headStored time.Time) bool {
	return verified.IsVerified() && !resultStored.IsZero() && !headStored.IsZero() &&
		resultStored.Location() == time.UTC && headStored.Location() == time.UTC &&
		!resultStored.Add(time.Second).After(verified.plan.LaunchDeadline) &&
		!headStored.Add(time.Second).After(verified.plan.LaunchDeadline)
}

var (
	_ FounderPlanAuthority    = VerifiedFounderPlan{}
	_ FounderPlanAuthority    = DerivedFounderPlan{}
	_ FounderPlanContinuation = VerifiedCompletedFounderPlan{}
	_ FounderPlanContinuation = DerivedCompletedFounderPlan{}
)
