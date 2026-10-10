package bootstrapstart

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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

func (store bakedStore) loadAcceptedHostLaunchMaterial(accepted AcceptedIdentity, markers MarkerStore) (LaunchMaterial, error) {
	wires, err := store.loadAcceptedLaunchFiles(accepted, markers, acceptedLaunchNames[:2])
	if err != nil {
		return LaunchMaterial{}, err
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

func (store bakedStore) loadAcceptedManagedImageMaterial(accepted AcceptedIdentity, markers MarkerStore) ([]byte, []byte, error) {
	wires, err := store.loadAcceptedLaunchFiles(accepted, markers, acceptedLaunchNames[2:])
	if err != nil {
		return nil, nil, err
	}
	return wires[ManagedHostImageReceiptFilename], wires[ManagedHostImageDelegationFilename], nil
}

func (store bakedStore) loadAcceptedLaunchFiles(accepted AcceptedIdentity, markers MarkerStore, names []string) (map[string][]byte, error) {
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
	return validateOperatorSSHKey(ssh)
}

func (store bakedStore) measureInitialLaunchMaterial(manifest bootstrap.VerifiedManifest, roots trust.Keyring, now time.Time) (map[string]string, error) {
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
	wires, err := store.readLaunchFiles(acceptedLaunchNames[:])
	if err != nil {
		return nil, err
	}
	if err := validateHostLaunchInputs(wires[HostEnrollmentFilename], wires[OperatorSSHKeyFilename], string(payload.Cell), payload.Environment); err != nil {
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
	architecture := ""
	switch {
	case region.Shape == "VM.Standard.A1.Flex":
		architecture = "arm64"
	case strings.HasPrefix(region.Shape, "VM.Standard.E4."), strings.HasPrefix(region.Shape, "VM.Standard.E5."):
		architecture = "amd64"
	default:
		return release.ImageExpectation{}, ErrLaunchMaterial
	}
	return release.ImageExpectation{Environment: environment, LogicalRegion: cell, OCIImageOCID: region.ImageID, Architecture: architecture}, nil
}
