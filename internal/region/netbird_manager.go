package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/networkplan"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const NetBirdManagerRole = "netbird-manager"
const NetBirdManagerRuntime = "netbird-containerd"

// NetBirdManagerProfile names one dedicated host. Subnet and NSG identities are
// compiled from its own foundation checkpoints, never from discovery or tags.
// It conveys no regional controller, worker or customer serving authority.
type NetBirdManagerProfile struct {
	AvailabilityDomain string  `json:"availabilityDomain"`
	FaultDomain        string  `json:"faultDomain"`
	PrivateIP          string  `json:"privateIp"`
	NetworkCIDR        string  `json:"networkCidr"`
	Shape              string  `json:"shape"`
	OCPUs              float32 `json:"ocpus"`
	MemoryGB           float32 `json:"memoryGb"`
	BootVolumeGB       int64   `json:"bootVolumeGb"`
}

// NetBirdManagerIntent extends the same root-signed foundation footprint. Image
// and runtime qualification are independent of permission to buy this slot.
type NetBirdManagerIntent struct {
	Role                        string                `json:"role"`
	StoreOrigin                 string                `json:"storeOrigin"`
	Profile                     NetBirdManagerProfile `json:"profile"`
	ImageOCID                   string                `json:"imageOcid"`
	Architecture                string                `json:"architecture"`
	ImageReceiptWire            []byte                `json:"imageReceiptWire"`
	ImageDelegationWire         []byte                `json:"imageDelegationWire"`
	QualificationWire           []byte                `json:"qualificationWire"`
	QualificationDelegationWire []byte                `json:"qualificationDelegationWire"`
}

// NetBirdManagerLaunch is an immutable singleton reservation in the existing
// foundation journal. New grant generations cannot reset a pending launch.
type NetBirdManagerLaunch struct {
	SlotID        string    `json:"slotId"`
	OperationID   string    `json:"operationId"`
	ProfileSHA256 string    `json:"profileSha256"`
	RecipeSHA256  string    `json:"recipeSha256"`
	RequestDigest string    `json:"requestDigest"`
	RetryToken    string    `json:"retryToken"`
	StartedAt     time.Time `json:"startedAt"`
	InstanceID    string    `json:"instanceId,omitempty"`
	BootVolumeID  string    `json:"bootVolumeId,omitempty"`
	StoreState    string    `json:"storeState"`
}

type verifiedNetBirdIntent struct {
	intent                      NetBirdManagerIntent
	installationID              string
	generation                  uint64
	expires                     time.Time
	image                       release.VerifiedImage
	profileDigest, recipeDigest string
}

func (i NetBirdManagerIntent) validate() error {
	p := i.Profile
	address, err := netip.ParseAddr(p.PrivateIP)
	network, networkErr := netip.ParsePrefix(p.NetworkCIDR)
	if i.Role != NetBirdManagerRole || i.Architecture != "arm64" || p.Shape != "VM.Standard.A1.Flex" ||
		p.AvailabilityDomain == "" || len(p.AvailabilityDomain) > 255 ||
		!slices.Contains([]string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"}, p.FaultDomain) ||
		err != nil || !address.Is4() || !address.IsPrivate() || address.String() != p.PrivateIP ||
		networkErr != nil || !network.Addr().Is4() || !network.Addr().IsPrivate() || network.Bits() != 24 || network.Masked().String() != p.NetworkCIDR ||
		networkplan.ValidateRegion("GRU", p.NetworkCIDR) != nil ||
		!network.Contains(address) || address == network.Addr() || address == network.Addr().Next() || !network.Contains(address.Next()) ||
		(i.StoreOrigin != "new" && i.StoreOrigin != "restore") ||
		!(p.OCPUs > 0) || !(p.MemoryGB > 0) || math.IsInf(float64(p.OCPUs), 0) || math.IsInf(float64(p.MemoryGB), 0) ||
		p.BootVolumeGB < 50 || p.BootVolumeGB > 32768 || !strings.HasPrefix(i.ImageOCID, "ocid1.image.oc1.sa-saopaulo-1.") ||
		len(i.ImageReceiptWire) == 0 || len(i.ImageReceiptWire) > bootstrap.MaxManifestBytes || len(i.ImageDelegationWire) > bootstrap.MaxManifestBytes ||
		len(i.QualificationWire) == 0 || len(i.QualificationWire) > bootstrap.MaxManifestBytes || len(i.QualificationDelegationWire) > bootstrap.MaxManifestBytes {
		return errors.New("dedicated NetBird manager intent lacks exact role, native image, profile or qualification")
	}
	return nil
}

func (s *SignedFootprint) authorizedNetBirdManager(ctx context.Context) (verifiedNetBirdIntent, error) {
	wire, err := s.readGrant(ctx)
	if err != nil {
		return verifiedNetBirdIntent{}, err
	}
	footprint, expires, err := s.verifyGrant(wire)
	if err != nil {
		return verifiedNetBirdIntent{}, err
	}
	for _, region := range footprint.Regions {
		if region.Plan["cell"] != "GRU" || region.NetBirdManager == nil {
			continue
		}
		intent := *region.NetBirdManager
		if err := intent.validate(); err != nil {
			return verifiedNetBirdIntent{}, err
		}
		image, err := release.VerifyNetBirdImageCurrent(intent.ImageReceiptWire, intent.ImageDelegationWire, s.roots,
			release.ImageExpectation{Environment: s.scope.Environment, LogicalRegion: "GRU", OCIImageOCID: intent.ImageOCID, Architecture: intent.Architecture}, time.Now())
		if err != nil {
			return verifiedNetBirdIntent{}, err
		}
		receipt := image.Receipt()
		proof := release.ProductionProof{Qualification: intent.QualificationWire, Delegation: intent.QualificationDelegationWire}
		deadline, err := release.VerifyRetainedProductionCurrent(ctx, proof, s.roots, release.ProductionExpectation{
			SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256, QualificationSHA256: receipt.QualificationSHA256,
			Cell: "GRU", Environment: s.scope.Environment, Runtime: release.NetBirdProductionRuntime, Architecture: "arm64", Role: NetBirdManagerRole,
		}, s.openNetBirdEvidence, time.Now())
		if err != nil {
			return verifiedNetBirdIntent{}, err
		}
		if deadline.Before(expires) {
			expires = deadline
		}
		profileDigest, err := NetBirdManagerProfileDigest(intent.Profile)
		if err != nil {
			return verifiedNetBirdIntent{}, err
		}
		recipeDigest, err := NetBirdManagerRecipeDigest(intent, image.Receipt().ImageSHA256)
		if err != nil {
			return verifiedNetBirdIntent{}, err
		}
		if image.ExpiresAt().Before(expires) {
			expires = image.ExpiresAt()
		}
		return verifiedNetBirdIntent{intent: intent, installationID: s.home.InstallationID, generation: region.Generation, expires: expires,
			image: image, profileDigest: profileDigest, recipeDigest: recipeDigest}, nil
	}
	return verifiedNetBirdIntent{}, errors.New("same signed footprint has no dedicated NetBird manager role")
}

func (s *SignedFootprint) openNetBirdEvidence(ctx context.Context, digest string) (io.ReadCloser, error) {
	return releasechannel.OpenImageProductionEvidence(ctx, releasechannel.Location{Client: s.client, Namespace: s.storage.Namespace, Bucket: s.storage.HeadBucket}, digest)
}

// VerifiedNetBirdManager is held only by the independently observed dedicated
// instance. No caller-supplied role or resource name can construct this proof.
type VerifiedNetBirdManager struct {
	target          vaultsecret.Target
	storeGeneration string
	check           func(context.Context) error
	recovery        bool
	transition      func(context.Context, bool) error
}

func (v VerifiedNetBirdManager) VaultTarget() vaultsecret.Target { return v.target }
func (v VerifiedNetBirdManager) StoreGeneration() string         { return v.storeGeneration }
func (v VerifiedNetBirdManager) RecoveryRequired() bool          { return v.recovery }
func (v VerifiedNetBirdManager) ClaimGenesis(ctx context.Context) error {
	if v.transition == nil {
		return errors.New("dedicated manager store authority is absent")
	}
	return v.transition(ctx, false)
}
func (v VerifiedNetBirdManager) MarkStoreReady(ctx context.Context) error {
	if v.transition == nil {
		return errors.New("dedicated manager store authority is absent")
	}
	return v.transition(ctx, true)
}
func (v VerifiedNetBirdManager) Check(ctx context.Context) error {
	if v.check == nil || v.storeGeneration == "" {
		return errors.New("dedicated NetBird manager admission is absent")
	}
	return v.check(ctx)
}

// AdmitNetBirdManager works before the overlay, NATS and SwarmKit. OCI instance
// identity selects an observation; the signed role and exact checkpoint admit it.
func AdmitNetBirdManager(ctx context.Context, factory *ociclient.Factory, resolver FoundationResolver, instanceID string) (VerifiedNetBirdManager, error) {
	if factory == nil || factory.Region() != foundationHomeRegion || !strings.HasPrefix(instanceID, "ocid1.instance.oc1.sa-saopaulo-1.") {
		return VerifiedNetBirdManager{}, errors.New("NetBird manager requires independently observed GRU instance identity")
	}
	local, err := bootstrapstart.NewIMDSClient().FetchInstanceID(ctx)
	if err != nil || local != instanceID {
		return VerifiedNetBirdManager{}, errors.Join(errors.New("dedicated NetBird manager must be the exact local OCI instance"), err)
	}
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok {
		return VerifiedNetBirdManager{}, errors.New("NetBird manager requires the current root-signed foundation producer")
	}
	observer, err := bootstrapstart.NewOCIInstanceObserver(oci.RegionGRU, factory.Provider())
	if err != nil {
		return VerifiedNetBirdManager{}, err
	}
	return admitNetBirdManager(ctx, resolver, reader, netBirdObservedInstance{factory: factory, resolver: resolver, reader: reader, observer: observer},
		instanceID, bootstrapstart.VerifyCurrentRunningBinary)
}

func admitNetBirdManager(ctx context.Context, resolver FoundationResolver, reader *SignedFootprint, observer bootstrapstart.InstanceObserver,
	instanceID string, verifyBinary func(release.VerifiedImage) (bootstrapstart.RunningBinary, error),
) (VerifiedNetBirdManager, error) {
	current := func(ctx context.Context) (vaultsecret.Target, string, error) {
		intent, err := reader.authorizedNetBirdManager(ctx)
		if err != nil {
			return vaultsecret.Target{}, "", err
		}
		record, err := resolver.Resolve(ctx, "GRU")
		if err != nil {
			return vaultsecret.Target{}, "", err
		}
		launch := record.NetBirdManager
		if launch == nil || launch.InstanceID != instanceID || launch.RecipeSHA256 != intent.recipeDigest || launch.ProfileSHA256 != intent.profileDigest {
			return vaultsecret.Target{}, "", errors.New("dedicated manager instance has no exact immutable foundation checkpoint")
		}
		observed, err := observer.ObserveInstance(ctx, instanceID)
		if err != nil {
			return vaultsecret.Target{}, "", err
		}
		profile, err := managerLaunchProfile(intent.intent.Profile, record)
		if err != nil {
			return vaultsecret.Target{}, "", err
		}
		if observed.InstanceOCID != instanceID || observed.ImageOCID != intent.intent.ImageOCID || observed.CompartmentOCID != profile.CompartmentOCID ||
			observed.AvailabilityDomain != profile.AvailabilityDomain || observed.FaultDomain != profile.FaultDomain || observed.Shape != profile.Shape ||
			observed.SubnetOCID != profile.SubnetOCID || !slices.Equal(slices.Sorted(slices.Values(observed.NSGOCIDs)), slices.Sorted(slices.Values(profile.NetworkSecurityGroupOCIDs))) ||
			!observed.PrimaryVNIC || observed.PrimaryPrivateIP != intent.intent.Profile.PrivateIP || observed.LifecycleState != "RUNNING" {
			return vaultsecret.Target{}, "", errors.New("observed NetBird manager differs from its exact signed profile and image")
		}
		if _, err := verifyBinary(intent.image); err != nil {
			return vaultsecret.Target{}, "", err
		}
		target, err := record.VaultTarget()
		if err != nil {
			return vaultsecret.Target{}, "", err
		}
		store := entityid.Derive("netbird-foundation-store", intent.installationID) + ":1"
		return target, store, nil
	}
	target, store, err := current(ctx)
	if err != nil {
		return VerifiedNetBirdManager{}, err
	}
	check := func(ctx context.Context) error {
		nextTarget, nextStore, err := current(ctx)
		if err != nil {
			return err
		}
		if nextTarget != target || nextStore != store {
			return errors.New("dedicated manager store or Vault target changed")
		}
		return nil
	}
	record, err := resolver.Resolve(ctx, "GRU")
	if err != nil {
		return VerifiedNetBirdManager{}, err
	}
	intent, err := reader.authorizedNetBirdManager(ctx)
	if err != nil {
		return VerifiedNetBirdManager{}, err
	}
	transition := func(ctx context.Context, ready bool) error {
		if err := check(ctx); err != nil {
			return err
		}
		latest, etag, err := resolver.Store.Load(ctx, "GRU")
		if err != nil {
			return err
		}
		if latest.Stage != "reconciled" || latest.LeaseID != "" || latest.Generation != record.Generation || latest.IntentDigest != record.IntentDigest ||
			latest.NetBirdManager == nil || latest.NetBirdManager.InstanceID != instanceID || latest.NetBirdManager.RecipeSHA256 != intent.recipeDigest {
			return ErrFoundationFenced
		}
		launch := *latest.NetBirdManager
		if ready {
			if launch.StoreState != "initializing" && !(intent.intent.StoreOrigin == "restore" && launch.StoreState == "empty") && launch.StoreState != "ready" {
				return errors.New("NetBird store has no consumed genesis or restore authority")
			}
			launch.StoreState = "ready"
		} else {
			if intent.intent.StoreOrigin != "new" || launch.StoreState != "empty" {
				return errors.New("NetBird store genesis authorization was absent or already consumed; restore is required")
			}
			launch.StoreState = "initializing"
		}
		latest.NetBirdManager, latest.UpdatedAt = &launch, time.Now().UTC()
		if err := check(ctx); err != nil {
			return err
		}
		_, err = resolver.Store.CompareAndSwap(ctx, latest, etag)
		return err
	}
	return VerifiedNetBirdManager{target: target, storeGeneration: store, check: check, transition: transition,
		recovery: intent.intent.StoreOrigin == "restore" || record.NetBirdManager.StoreState != "empty"}, nil
}

func managerLaunchProfile(profile NetBirdManagerProfile, record FoundationRecord) (bootstrap.LaunchProfile, error) {
	compartment := record.ResourceIDs["control_compartment"]
	subnet, nsg := record.AuxiliaryIDs["netbird_manager_subnet"], record.AuxiliaryIDs["netbird_manager_nsg"]
	if compartment == "" || subnet == "" || nsg == "" {
		return bootstrap.LaunchProfile{}, errors.New("dedicated NetBird manager network is not checkpointed")
	}
	return bootstrap.LaunchProfile{Slot: NetBirdManagerRole, CompartmentOCID: compartment, AvailabilityDomain: profile.AvailabilityDomain,
		FaultDomain: profile.FaultDomain, SubnetOCID: subnet, NetworkSecurityGroupOCIDs: []string{nsg}, Shape: profile.Shape}, nil
}

// NetBirdManagerProfileDigest lets the same root-grant producer bind the finite
// bootstrap slot to the exact logical profile before OCI allocates any OCID.
func NetBirdManagerProfileDigest(profile NetBirdManagerProfile) (string, error) {
	wire, err := json.Marshal(profile, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

// NetBirdManagerRecipeDigest shares the exact logical recipe with the offline
// signer; no discovered resource or caller-supplied role enters this digest.
func NetBirdManagerRecipeDigest(intent NetBirdManagerIntent, imageSHA256 string) (string, error) {
	if err := intent.validate(); err != nil {
		return "", err
	}
	if !bootstrapSHA256.MatchString(imageSHA256) {
		return "", errors.New("NetBird manager recipe requires a qualified image digest")
	}
	wire, err := json.Marshal(struct {
		Role        string                `json:"role"`
		StoreOrigin string                `json:"storeOrigin"`
		Profile     NetBirdManagerProfile `json:"profile"`
		ImageOCID   string                `json:"imageOcid"`
		ImageSHA256 string                `json:"imageSha256"`
		Runtime     string                `json:"runtime"`
	}{NetBirdManagerRole, intent.StoreOrigin, intent.Profile, intent.ImageOCID, imageSHA256, NetBirdManagerRuntime}, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

func (l NetBirdManagerLaunch) validate() error {
	if !entityid.Valid(l.SlotID) || !entityid.Valid(l.OperationID) || l.StartedAt.IsZero() {
		return errors.New("NetBird manager checkpoint lacks immutable slot identity")
	}
	if !slices.Contains([]string{"empty", "initializing", "ready"}, l.StoreState) || l.StoreState != "empty" && l.InstanceID == "" {
		return errors.New("NetBird manager checkpoint has invalid durable store state")
	}
	for _, value := range []string{l.ProfileSHA256, l.RecipeSHA256, l.RequestDigest, l.RetryToken} {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != sha256.Size || hex.EncodeToString(b) != value {
			return errors.New("NetBird manager checkpoint has invalid recipe or request digest")
		}
	}
	if l.InstanceID != "" && !strings.HasPrefix(l.InstanceID, "ocid1.instance.oc1.sa-saopaulo-1.") ||
		l.BootVolumeID != "" && !strings.HasPrefix(l.BootVolumeID, "ocid1.bootvolume.oc1.sa-saopaulo-1.") {
		return fmt.Errorf("NetBird manager checkpoint contains an out-of-region instance or volume")
	}
	return nil
}
