package bootstrapstart

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

var ErrAdmission = errors.New("controller bootstrap admission failed")
var ErrAdmissionPending = errors.New("managed controller peer is awaiting its signed positive bootstrap result")

// InstanceObservation is assembled only from OCI GetInstance and the attached
// primary VNIC. The IMDS identity merely selects which instance to observe.
type InstanceObservation struct {
	InstanceOCID       string
	BootstrapCreateKey string
	CompartmentOCID    string
	ImageOCID          string
	ETag               string
	AvailabilityDomain string
	FaultDomain        string
	Shape              string
	SubnetOCID         string
	NSGOCIDs           []string
	PrimaryVNICOCID    string
	PrimaryPrivateIP   string
	PrimaryVNIC        bool
	LifecycleState     string
	// Filled by Gate from signed anchor and intent fields after OCI comparison.
	Facts bootstrap.InstanceFacts
}

type DescriptorSource interface {
	FetchDescriptor(context.Context) (Descriptor, error)
	FetchInstanceID(context.Context) (string, error)
}

type InstanceObserver interface {
	ObserveInstance(context.Context, string) (InstanceObservation, error)
}

type SlotReader interface {
	ReadSlot(context.Context, bootstrap.BootstrapScope) (bootstrap.SlotState, error)
}

// AdmissionLedger reads current formation proofs and exports exact accepted bytes.
type AdmissionLedger interface {
	SlotReader
	PublishAcceptedInstall(context.Context, bootstrap.BootstrapScope, []byte) error
}

type LedgerOpener interface {
	OpenCurrentLedger(context.Context, bootstrap.VerifiedBootstrapAnchor, trust.Keyring) (AdmissionLedger, error)
}

type BinaryChecker interface {
	VerifyCurrent(release.VerifiedImage) (RunningBinary, error)
	VerifyAccepted(identityrekey.BinaryPin) (RunningBinary, error)
	VerifySelfUpdated(selfupdate.Layout, trust.Keyring, release.UpdateExpectation) (RunningBinary, error)
}

type MaterialChecker interface {
	PrepareInitial(context.Context, bootstrap.StartupAuthority, bootstrap.VerifiedReceipt, map[string]string, CurrentProofVerifier) error
	// RestartPins reads the install's adopted material generation, if any,
	// and returns what its credential directory must hold (TS-568).
	RestartPins(AcceptedIdentity, trust.Keyring) (MaterialPins, error)
	VerifyRestart(context.Context, AcceptedIdentity, MaterialPins) error
}

// CurrentProofVerifier rechecks the root anchor, its ledger grant, manifest,
// release image, and exact-instance receipt at an effect boundary.
type CurrentProofVerifier func(time.Time) error

type LiveCredentialChecker interface {
	VerifyInitialLiveCredentials(context.Context, MaterialPins, bootstrap.StartupAuthority) error
	VerifyLiveCredentials(context.Context, MaterialPins, AcceptedIdentity) error
}

// Gate admits fresh formation from current image proofs, and accepted restarts
// from the independently loaded root-owned installation and fixed trust roots.
type Gate struct {
	derivedStartup               *bootstrap.DerivedStartupAuthority
	Roots                        trust.Keyring
	AnchorWire                   []byte
	Expected                     bootstrap.BootstrapAnchorExpectation
	LoadedControllerConfigSHA256 string
	Descriptor                   DescriptorSource
	Instances                    InstanceObserver
	Ledgers                      LedgerOpener
	Binary                       BinaryChecker
	Material                     MaterialChecker
	Credentials                  LiveCredentialChecker
	ObserveIdentity              IdentityObservation
	InitialIdentity              func(bootstrap.Manifest) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error)
	Markers                      MarkerStore
	ClockCheck                   func() error
	Now                          func() time.Time
	InitialFounderFloor          func(context.Context, AcceptedInstall, time.Time) error
	InitialPeerFloor             func(context.Context, AcceptedInstall, bootstrap.SlotState, time.Time) error
	// SelfUpdate is the root-owned self-update release root. Restart
	// admission also accepts its current release under a binary-update
	// receipt; the zero value accepts only the accepted binary baseline.
	SelfUpdate selfupdate.Layout
	// LoadedControllerConfig is the loaded config's exact bytes. An adopted
	// generation pins them in place of the accepted baseline (TS-668).
	LoadedControllerConfig []byte
	// Tests inject the fixed trust-tree seam; production always loads fixed paths.
	trustStore *bakedStore
}

type executableBinaryChecker struct{}

func (executableBinaryChecker) VerifyCurrent(image release.VerifiedImage) (RunningBinary, error) {
	return VerifyCurrentRunningBinary(image)
}

func (executableBinaryChecker) VerifyAccepted(pin identityrekey.BinaryPin) (RunningBinary, error) {
	return VerifyAcceptedRunningBinary(pin)
}

func (executableBinaryChecker) VerifySelfUpdated(layout selfupdate.Layout, roots trust.Keyring,
	expected release.UpdateExpectation,
) (RunningBinary, error) {
	return verifySelfUpdatedBinary("/proc/self/exe", layout, roots, expected)
}

func (gate Gate) binaryChecker() BinaryChecker {
	if gate.Binary != nil {
		return gate.Binary
	}
	return executableBinaryChecker{}
}

// verifyRestartBinary pins the running executable to the accepted baseline.
// Only an executable that differs from it may
// instead be the self-update current release.
func (gate Gate) verifyRestartBinary(accepted AcceptedIdentity, roots trust.Keyring) error {
	binary, err := gate.binaryChecker().VerifyAccepted(accepted.Binary)
	if err == nil && binary.SHA256 == accepted.Binary.SHA256 && binary.Bytes == accepted.Binary.Size &&
		binary.Architecture == accepted.Binary.Architecture {
		return nil
	}
	if err == nil {
		err = ErrRunningBinaryMismatch
	}
	if errors.Is(err, ErrRunningBinaryMismatch) && gate.SelfUpdate.Root != "" {
		_, err = gate.binaryChecker().VerifySelfUpdated(gate.SelfUpdate, roots, release.UpdateExpectation{
			Environment: accepted.Environment, Cell: accepted.Cell, Architecture: accepted.Binary.Architecture,
		})
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: installed executable differs: %v", ErrAdmission, err)
}

func (gate Gate) observe(ctx context.Context, instanceID string, state bootstrap.SlotState,
	anchor bootstrap.BootstrapAnchor,
) (InstanceObservation, error) {
	observed, err := gate.Instances.ObserveInstance(ctx, instanceID)
	if err != nil {
		return InstanceObservation{}, fmt.Errorf("observe exact OCI instance and primary VNIC: %w", err)
	}
	if state.Result == nil || state.ResultRecord == nil || state.Head.ResultDigest == "" ||
		state.Head.ResultDigest != state.ResultRecord.SHA256 ||
		observed.InstanceOCID != instanceID || state.Result.InstanceOCID != instanceID ||
		observed.ImageOCID != state.Intent.ImageOCID || observed.ImageOCID != state.Result.ImageOCID ||
		observed.CompartmentOCID != state.Intent.CompartmentOCID ||
		observed.CompartmentOCID != state.Result.CompartmentOCID ||
		observed.AvailabilityDomain != state.Intent.AvailabilityDomain ||
		observed.FaultDomain != state.Intent.FaultDomain ||
		observed.Shape != state.Intent.Shape || observed.Shape != state.Result.Shape ||
		observed.SubnetOCID != state.Intent.SubnetOCID ||
		!sameOCIDSet(observed.NSGOCIDs, state.Intent.NetworkSecurityGroupIDs) ||
		state.Intent.DeploymentID != anchor.DeploymentID || state.Intent.Environment != anchor.Environment ||
		state.Intent.Cell != string(anchor.Cell) || state.Intent.OCIRegion != anchor.OCIRegion ||
		state.Result.CreateKey != state.Intent.CreateKey ||
		observed.LifecycleState != "RUNNING" || !observed.PrimaryVNIC ||
		!strings.HasPrefix(observed.PrimaryVNICOCID, "ocid1.vnic.") ||
		!validPrivateIPv4(observed.PrimaryPrivateIP) {
		return InstanceObservation{}, fmt.Errorf("%w: local instance, OCI observation, and signed slot result differ", ErrAdmission)
	}
	observed.Facts = bootstrap.InstanceFacts{
		DeploymentID: anchor.DeploymentID, Environment: anchor.Environment, ClusterID: anchor.ClusterID,
		Cell: anchor.Cell, OCIRegion: anchor.OCIRegion, Role: state.Intent.Role, Slot: state.Intent.Slot,
		InstanceOCID: observed.InstanceOCID, CompartmentOCID: observed.CompartmentOCID,
		ImageOCID: observed.ImageOCID, CreateKey: state.Intent.CreateKey,
		IntentSHA256: state.IntentRecord.SHA256,
		Profile: bootstrap.LaunchProfile{
			Slot: state.Intent.Slot, CompartmentOCID: observed.CompartmentOCID,
			AvailabilityDomain: observed.AvailabilityDomain, FaultDomain: observed.FaultDomain,
			SubnetOCID: observed.SubnetOCID,
			// OCI reports NSG membership without a stable order. The exact set
			// was checked above; keep the signed order for receipt verification.
			NetworkSecurityGroupOCIDs: slices.Clone(state.Intent.NetworkSecurityGroupIDs),
			Shape:                     observed.Shape,
		},
	}
	return observed, nil
}

func sameOCIDSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	left, right = slices.Clone(left), slices.Clone(right)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

func digest(body []byte) string {
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

func coveredAt(issuedAt, expiresAt, acceptedAt time.Time) bool {
	return !acceptedAt.Before(issuedAt) && acceptedAt.Before(expiresAt)
}
