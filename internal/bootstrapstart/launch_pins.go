package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

const (
	OperatorSSHKeyFilename             = operatorSSHKeyFilename
	ManagedHostImageReceiptFilename    = "managed-host-image-receipt.json"
	ManagedHostImageDelegationFilename = "managed-host-image-delegation.json"
)

var acceptedLaunchNames = [...]string{HostEnrollmentFilename, OperatorSSHKeyFilename,
	ManagedHostImageReceiptFilename, ManagedHostImageDelegationFilename}

// LoadAcceptedHostLaunchMaterial reads only the two accepted public host inputs.
func LoadAcceptedHostLaunchMaterial(accepted AcceptedIdentity) (LaunchMaterial, error) {
	store := bakedStore{directory: BakedDirectory, chainFile: RootChainFile}
	return store.loadAcceptedHostLaunchMaterial(accepted, NewMarkerStore())
}

func LoadAcceptedHostLaunchMaterialContext(ctx context.Context, accepted AcceptedIdentity) (LaunchMaterial, error) {
	return (bakedStore{directory: BakedDirectory, chainFile: RootChainFile}).loadAcceptedHostLaunchMaterialContext(ctx, accepted, NewMarkerStore())
}

func (store bakedStore) loadAcceptedHostLaunchMaterial(accepted AcceptedIdentity, markers MarkerStore) (LaunchMaterial, error) {
	if _, original := accepted.LaunchMaterialSHA256[OriginalStartupOriginFilename]; original {
		return LaunchMaterial{}, ErrOriginalStartup
	}
	return store.loadAcceptedHostLaunchMaterialContext(context.Background(), accepted, markers)
}

func (store bakedStore) loadAcceptedHostLaunchMaterialContext(ctx context.Context, accepted AcceptedIdentity, markers MarkerStore) (LaunchMaterial, error) {
	names, err := AcceptedLaunchFileNames(accepted)
	if err != nil {
		return LaunchMaterial{}, err
	}
	wires, err := store.loadAcceptedLaunchFilesContext(ctx, accepted, markers, names[:2])
	if err != nil {
		return LaunchMaterial{}, err
	}
	if _, original := accepted.LaunchMaterialSHA256[OriginalStartupOriginFilename]; original {
		if err := validateHostEnrollment(wires[HostEnrollmentFilename], accepted.Cell, accepted.Environment); err != nil {
			return LaunchMaterial{}, err
		}
		return LaunchMaterial{HostEnrollment: wires[HostEnrollmentFilename], OriginalOrigin: wires[OriginalStartupOriginFilename]}, nil
	}
	if err := validateHostLaunchInputs(wires[HostEnrollmentFilename], wires[OperatorSSHKeyFilename], accepted.Cell, accepted.Environment); err != nil {
		return LaunchMaterial{}, err
	}
	return LaunchMaterial{HostEnrollment: wires[HostEnrollmentFilename], OperatorSSHKey: wires[OperatorSSHKeyFilename]}, nil
}

// LoadAcceptedManagedImageMaterial checks installed pins; the launcher must
// independently verify CURRENT release qualification against its configured image.
func LoadAcceptedManagedImageMaterial(accepted AcceptedIdentity) (receipt, delegation []byte, err error) {
	store := bakedStore{directory: BakedDirectory, chainFile: RootChainFile}
	return store.loadAcceptedManagedImageMaterial(accepted, NewMarkerStore())
}

func LoadAcceptedManagedImageMaterialContext(ctx context.Context, accepted AcceptedIdentity) ([]byte, []byte, error) {
	return (bakedStore{directory: BakedDirectory, chainFile: RootChainFile}).loadAcceptedManagedImageMaterialContext(ctx, accepted, NewMarkerStore())
}

func (store bakedStore) loadAcceptedManagedImageMaterial(accepted AcceptedIdentity, markers MarkerStore) ([]byte, []byte, error) {
	if _, original := accepted.LaunchMaterialSHA256[OriginalStartupOriginFilename]; original {
		return nil, nil, ErrOriginalStartup
	}
	return store.loadAcceptedManagedImageMaterialContext(context.Background(), accepted, markers)
}

func (store bakedStore) loadAcceptedManagedImageMaterialContext(ctx context.Context, accepted AcceptedIdentity, markers MarkerStore) ([]byte, []byte, error) {
	wires, err := store.loadAcceptedLaunchFilesContext(ctx, accepted, markers, acceptedLaunchNames[2:])
	if err != nil {
		return nil, nil, err
	}
	return wires[ManagedHostImageReceiptFilename], wires[ManagedHostImageDelegationFilename], nil
}

func (store bakedStore) loadAcceptedLaunchFiles(accepted AcceptedIdentity, markers MarkerStore, names []string) (map[string][]byte, error) {
	if _, original := accepted.LaunchMaterialSHA256[OriginalStartupOriginFilename]; original {
		return nil, ErrOriginalStartup
	}
	return store.loadAcceptedLaunchFilesContext(context.Background(), accepted, markers, names)
}

func (store bakedStore) loadAcceptedLaunchFilesContext(ctx context.Context, accepted AcceptedIdentity, markers MarkerStore, names []string) (map[string][]byte, error) {
	if err := accepted.Validate(); err != nil {
		return nil, err
	}
	installed, err := markers.ReadIdentity()
	if err != nil {
		return nil, err
	}
	want, err := EncodeAcceptedIdentity(accepted)
	if err != nil {
		return nil, err
	}
	actual, err := EncodeAcceptedIdentity(installed)
	if err != nil || !bytes.Equal(want, actual) {
		return nil, ErrLaunchMaterial
	}
	inputs, err := store.loadTrustInputs(accepted)
	if err != nil {
		return nil, err
	}
	if _, err := markers.verifiedIdentityRekey(accepted, inputs); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	wires, err := store.readLaunchFiles(names)
	if err != nil {
		return nil, err
	}
	for name, wire := range wires {
		if digest(wire) != accepted.LaunchMaterialSHA256[name] {
			return nil, fmt.Errorf("%w: accepted launch input %s differs", ErrLaunchMaterial, name)
		}
	}
	if _, original := accepted.LaunchMaterialSHA256[OriginalStartupOriginFilename]; original {
		originWire := wires[OriginalStartupOriginFilename]
		if len(originWire) == 0 {
			originFiles, err := store.readLaunchFiles([]string{OriginalStartupOriginFilename})
			if err != nil {
				return nil, err
			}
			originWire = originFiles[OriginalStartupOriginFilename]
		}
		if err := verifyAcceptedOriginalOrigin(ctx, accepted, originWire, time.Now().UTC()); err != nil {
			return nil, err
		}
		dir, err := store.openDirectory(store.directory)
		if err != nil {
			return nil, err
		}
		err = rejectOriginalSSH(dir)
		unix.Close(dir)
		if err != nil {
			return nil, err
		}
	}
	if err := (Gate{Markers: markers, trustStore: &store}).checkAcceptedUnchanged(accepted); err != nil {
		return nil, err
	}
	return wires, nil
}

func (store bakedStore) readLaunchFiles(names []string) (map[string][]byte, error) {
	dir, err := store.openDirectory(store.directory)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	wires := make(map[string][]byte, len(names))
	for _, name := range names {
		maximum := int64(trust.MaxEnvelopeBytes)
		switch name {
		case HostEnrollmentFilename:
			maximum = hostenroll.MaxPublicBundleBytes
		case OperatorSSHKeyFilename:
			maximum = maxOperatorSSHKey
		case OriginalStartupOriginFilename:
			maximum = maxOriginalStartupOriginBytes
		case ManagedHostImageReceiptFilename, ManagedHostImageDelegationFilename:
		default:
			return nil, ErrLaunchMaterial
		}
		wire, err := store.readFile(dir, name, maximum)
		if err != nil {
			return nil, fmt.Errorf("read root-owned public launch input %s: %w", name, err)
		}
		wires[name] = wire
	}
	return wires, nil
}

func validateHostLaunchInputs(enrollment, ssh []byte, cell, environment string) error {
	if err := validateHostEnrollment(enrollment, cell, environment); err != nil {
		return err
	}
	return validateOperatorSSHKey(ssh)
}

func validateHostEnrollment(enrollment []byte, cell, environment string) error {
	bundle, err := hostenroll.ParsePublicBundle(enrollment)
	if err != nil {
		return err
	}
	if err := bundle.MatchesImageLayout(); err != nil {
		return err
	}
	if bundle.Cell != strings.ToLower(cell) || bundle.Region != cell || bundle.Environment != environment {
		return ErrLaunchMaterial
	}
	return nil
}

func (store bakedStore) measureInitialLaunchMaterial(manifest bootstrap.StartupAuthority, roots trust.Keyring, now time.Time) (map[string]string, error) {
	if derived, ok := manifest.(bootstrap.DerivedStartupAuthority); ok {
		if _, err := derived.Template().OriginalLaunch(); err == nil {
			return nil, ErrOriginalStartup
		}
	}
	return store.measureInitialLaunchMaterialContext(context.Background(), manifest, roots, now)
}

func (store bakedStore) measureInitialLaunchMaterialContext(ctx context.Context, manifest bootstrap.StartupAuthority, roots trust.Keyring, now time.Time) (map[string]string, error) {
	if manifest.Digest() == "" {
		return nil, ErrLaunchMaterial
	}
	payload := manifest.Manifest()
	var regionWire []byte
	for _, file := range payload.ControllerFiles {
		if file.Name == "oci-region.json" {
			if digest(file.Bytes) != file.SHA256 {
				return nil, ErrLaunchMaterial
			}
			regionWire = file.Bytes
		}
	}
	expected, err := managedLaunchExpectation(regionWire, string(payload.Cell), payload.Environment)
	if err != nil {
		return nil, err
	}
	names := acceptedLaunchNames[:]
	derived, isDerived := manifest.(bootstrap.DerivedStartupAuthority)
	original := false
	if isDerived {
		_, err := derived.OriginalLaunch()
		original = err == nil
		if original {
			names = originalAcceptedLaunchNames()
		}
	}
	wires, err := store.readLaunchFiles(names)
	if err != nil {
		return nil, err
	}
	if original {
		origin, err := originalOriginWire(derived)
		if err != nil || !bytes.Equal(origin, wires[OriginalStartupOriginFilename]) || derived.VerifyCurrent(ctx, now) != nil {
			return nil, ErrOriginalStartup
		}
		if err := validateHostEnrollment(wires[HostEnrollmentFilename], string(payload.Cell), payload.Environment); err != nil {
			return nil, err
		}
		dir, err := store.openDirectory(store.directory)
		if err != nil {
			return nil, err
		}
		err = rejectOriginalSSH(dir)
		unix.Close(dir)
		if err != nil {
			return nil, err
		}
		roots = derived.Template().Roots()
	} else if err := validateHostLaunchInputs(wires[HostEnrollmentFilename], wires[OperatorSSHKeyFilename], string(payload.Cell), payload.Environment); err != nil {
		return nil, err
	}
	if _, err := release.VerifyImageCurrent(wires[ManagedHostImageReceiptFilename], wires[ManagedHostImageDelegationFilename], roots,
		expected, now); err != nil {
		return nil, err
	}
	pins := make(map[string]string, len(wires))
	for name, wire := range wires {
		pins[name] = digest(wire)
	}
	return pins, nil
}

func managedLaunchExpectation(regionWire []byte, cell, environment string) (release.ImageExpectation, error) {
	region, err := oci.ParseRegionConfig(regionWire)
	if err != nil || string(region.Region) != cell {
		return release.ImageExpectation{}, ErrLaunchMaterial
	}
	// Offline installation checks the signed image identity; launch observes its processor through OCI.
	return release.ImageExpectation{Environment: environment, LogicalRegion: cell, OCIImageOCID: region.ImageID}, nil
}

func originalAcceptedLaunchNames() []string {
	return []string{HostEnrollmentFilename, OriginalStartupOriginFilename, ManagedHostImageReceiptFilename, ManagedHostImageDelegationFilename}
}

// AcceptedLaunchFileNames selects an exact inventory from accepted pins. The
// caller must verify the accepted record and companion before installation.
func AcceptedLaunchFileNames(accepted AcceptedIdentity) ([]string, error) {
	if err := accepted.Validate(); err != nil {
		return nil, err
	}
	return acceptedLaunchFileNames(accepted.LaunchMaterialSHA256)
}

func acceptedLaunchFileNames(pins map[string]string) ([]string, error) {
	if err := identityrekey.ValidateLaunchMaterialPins(pins); err != nil {
		return nil, err
	}
	if _, present := pins[OriginalStartupOriginFilename]; present {
		return originalAcceptedLaunchNames(), nil
	}
	return append([]string(nil), acceptedLaunchNames[:]...), nil
}
