package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

// ControllerClientGate admits an ordinary client without opening broker secrets.
// Its concrete verifiers are private so a caller cannot replace custody checks.
type ControllerClientGate struct {
	proof       Gate
	material    MaterialStore
	credentials LiveCredentials
}

func NewControllerClientGate(proof Gate) (ControllerClientGate, error) {
	material, materialOK := proof.Material.(MaterialStore)
	credentials, credentialsOK := proof.Credentials.(LiveCredentials)
	if !materialOK || !credentialsOK || material.serviceUID == 0 || material.serviceGID == 0 ||
		material.serviceUID != credentials.ServiceUID || material.serviceGID != credentials.ServiceGID ||
		material.installedDirectory != credentials.directory || proof.Descriptor == nil ||
		proof.ObserveIdentity == nil || proof.Markers.directory == "" ||
		!markerDigestRE.MatchString(proof.LoadedControllerConfigSHA256) {
		return ControllerClientGate{}, ErrAdmission
	}
	proof.Material, proof.Credentials = nil, nil
	proof.LoadedControllerConfig = bytes.Clone(proof.LoadedControllerConfig)
	return ControllerClientGate{proof: proof, material: material, credentials: credentials}, nil
}

func (gate ControllerClientGate) AdmitRestartLocal(ctx context.Context) (AcceptedIdentity, error) {
	return gate.admitLocal(ctx, gate.proof.verifyRestartBinary)
}

func (gate ControllerClientGate) AdmitIdentityRekeyCompletion(ctx context.Context) (AcceptedIdentity, error) {
	return gate.admitLocal(ctx, func(accepted AcceptedIdentity, roots trust.Keyring) error {
		if err := gate.proof.verifyRestartBinary(accepted, roots); err == nil {
			return nil
		}
		_, err := verifyRecoveryPredecessor("/proc/self/exe", gate.proof.SelfUpdate, roots, accepted)
		return err
	})
}

// AdmitRestart adds the fixed local instance observation to ordinary admission.
func (gate ControllerClientGate) AdmitRestart(ctx context.Context, observer InstanceObserver) (AcceptedIdentity, error) {
	if observer == nil {
		return AcceptedIdentity{}, ErrAdmission
	}
	if _, err := gate.proof.checkedNow(); err != nil {
		return AcceptedIdentity{}, err
	}
	accepted, err := gate.AdmitRestartLocal(ctx)
	if err != nil {
		return AcceptedIdentity{}, err
	}
	observed, err := observer.ObserveInstance(ctx, accepted.InstanceOCID)
	if err != nil {
		return AcceptedIdentity{}, fmt.Errorf("observe accepted OCI instance: %w", err)
	}
	if observed.InstanceOCID != accepted.InstanceOCID || observed.ImageOCID != accepted.ImageOCID ||
		observed.PrimaryVNICOCID != accepted.PrimaryVNICOCID || observed.PrimaryPrivateIP != accepted.PrimaryPrivateIP ||
		!observed.PrimaryVNIC || observed.LifecycleState != "RUNNING" {
		return AcceptedIdentity{}, ErrAdmission
	}
	if _, err := gate.proof.checkedNow(); err != nil {
		return AcceptedIdentity{}, err
	}
	// Repeat public admission after the remote wait, including the durable floor.
	current, err := gate.AdmitRestartLocal(ctx)
	if err != nil {
		return AcceptedIdentity{}, err
	}
	before, err := EncodeAcceptedIdentity(accepted)
	if err != nil {
		return AcceptedIdentity{}, err
	}
	after, err := EncodeAcceptedIdentity(current)
	if err != nil || !bytes.Equal(before, after) {
		return AcceptedIdentity{}, ErrAdmission
	}
	return current, nil
}

func (gate ControllerClientGate) admitLocal(ctx context.Context, verifyBinary func(AcceptedIdentity, trust.Keyring) error) (AcceptedIdentity, error) {
	if ctx == nil || ctx.Err() != nil || gate.material.serviceUID == 0 ||
		os.Geteuid() != int(gate.material.serviceUID) || os.Getegid() != int(gate.material.serviceGID) {
		return AcceptedIdentity{}, ErrAdmission
	}
	proof := gate.proof
	accepted, err := proof.Markers.ReadIdentity()
	if err != nil {
		return AcceptedIdentity{}, err
	}
	inputs, err := proof.acceptedTrustInputs(accepted)
	if err != nil {
		return AcceptedIdentity{}, err
	}
	if err := proof.checkRestartJournal(accepted, inputs); err != nil {
		return AcceptedIdentity{}, err
	}
	descriptor, err := proof.Descriptor.FetchDescriptor(ctx)
	if err != nil {
		return AcceptedIdentity{}, err
	}
	instance, err := proof.Descriptor.FetchInstanceID(ctx)
	if err != nil || descriptor.SchemaVersion != 1 || descriptor.Slot != accepted.Slot || instance != accepted.InstanceOCID {
		return AcceptedIdentity{}, ErrAdmission
	}
	if err := verifyBinary(accepted, inputs.Roots.Historical); err != nil {
		return AcceptedIdentity{}, err
	}
	if err := VerifyAcceptedLocalIdentity(accepted, proof.ObserveIdentity); err != nil {
		return AcceptedIdentity{}, err
	}
	pins, floor, err := gate.clientPins(accepted, inputs.Roots.Historical)
	if err != nil {
		return AcceptedIdentity{}, err
	}
	if err := proof.restartConfig(&pins, accepted); err != nil {
		return AcceptedIdentity{}, err
	}
	if err := gate.credentials.verifyControllerClient(ctx, pins, accepted); err != nil {
		return AcceptedIdentity{}, err
	}
	currentFloor, err := gate.proof.Markers.readClientGenerationFloor()
	if err != nil || !bytes.Equal(floor, currentFloor) {
		return AcceptedIdentity{}, ErrMaterial
	}
	if pins.Generation != nil && !time.Now().Before(pins.Generation.ExpiresAt()) {
		return AcceptedIdentity{}, ErrMaterial
	}
	if err := proof.checkAcceptedUnchanged(accepted); err != nil {
		return AcceptedIdentity{}, err
	}
	if err := verifyBinary(accepted, inputs.Roots.Historical); err != nil {
		return AcceptedIdentity{}, err
	}
	if err := ctx.Err(); err != nil {
		return AcceptedIdentity{}, err
	}
	return accepted, nil
}

func (gate ControllerClientGate) clientPins(accepted AcceptedIdentity, roots trust.Keyring) (MaterialPins, []byte, error) {
	wire, err := gate.proof.Markers.readClientGenerationFloor()
	if err != nil {
		return MaterialPins{}, nil, err
	}
	target, err := generationTarget(accepted)
	if err != nil {
		return MaterialPins{}, nil, err
	}
	if len(wire) == 0 {
		if accepted.MaterialGenerationSHA256 != "" {
			return MaterialPins{}, nil, ErrMaterial
		}
		acceptedWire, err := EncodeAcceptedIdentity(accepted)
		if err != nil {
			return MaterialPins{}, nil, err
		}
		return MaterialPins{Digests: acceptedMaterialDigests(accepted), slot: accepted.Slot,
			acceptance: target.AcceptanceSHA256, acceptedSHA256: digest(acceptedWire), references: accepted.MaterialReferences}, nil, nil
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
	if err != nil {
		return MaterialPins{}, nil, err
	}
	verified, err := target.VerifyAdoptedChain(chain, roots)
	if err != nil {
		return MaterialPins{}, nil, err
	}
	newest := verified[len(verified)-1]
	if !time.Now().Before(newest.ExpiresAt()) {
		return MaterialPins{}, nil, ErrMaterial
	}
	pins, err := pinsFromGeneration(accepted, newest, wire)
	return pins, wire, err
}

// Only root can advance the durable public chain; ordinary installed files do
// not select a generation or lower its floor.
func (store MarkerStore) readClientGenerationFloor() ([]byte, error) {
	directory, err := store.openDirectory()
	if err != nil {
		return nil, err
	}
	defer unix.Close(directory)
	fd, err := unix.Openat(directory, MaterialGenerationsFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), MaterialGenerationsFile)
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != store.ownerUID || store.ownerUID == 0 && stat.Gid != 0 ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o644 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxGenerationChainBytes {
		return nil, ErrMaterial
	}
	return readLimited(file, MaterialGenerationsFile, maxGenerationChainBytes)
}

func (check LiveCredentials) verifyControllerClient(ctx context.Context, pins MaterialPins, accepted AcceptedIdentity) error {
	if !pins.matchesAccepted(accepted) || check.Config.Embedded == nil || check.ValidateControllerKeys == nil {
		return ErrLiveCredentials
	}
	if err := check.verifyPaths(pins, accepted.Slot, accepted.SeedSlot, accepted.MaterialReferences); err != nil {
		return err
	}
	directory, err := openMaterialDirectory(check.directory, check.ServiceUID, check.ServiceGID, 0o700, check.allowUnsafeAncestors)
	if err != nil {
		return err
	}
	defer unix.Close(directory)
	e := check.Config.Embedded
	// TLS private keys, issuer seeds and privileged users never enter this list.
	paths := []string{e.OperatorJWTFile, e.SystemJWTFile, e.CellJWTFile, e.TicketPublicKeyFile,
		check.Config.CredentialsFile, check.ResponseKeyFile, check.BrokerTicketKeyFile}
	if e.InterRegion != nil {
		paths = append(paths, e.InterRegion.AccountJWTFile)
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := filepath.Base(path)
		if path != filepath.Join(check.directory, name) || !pins.known(name) {
			return ErrLiveCredentials
		}
		var content []byte
		if want := pins.Digests[name]; want != "" {
			content, err = readMaterial(directory, name, check.ServiceUID, check.ServiceGID, want, bootstrap.MaxSecretBytes)
		} else if path == check.Config.CredentialsFile && pins.Generation != nil {
			content, err = readUnpinned(directory, name, check.ServiceUID, check.ServiceGID, bootstrap.MaxSecretBytes)
			if err == nil && digest(content) != pins.Issued[name] {
				err = bootstrapmaterial.CheckIssuedCredentials(pins.Generation.Generation(), content, time.Now())
			}
		} else {
			err = ErrLiveCredentials
		}
		clear(content)
		if err != nil {
			return fmt.Errorf("ordinary controller material %s: %w", name, err)
		}
	}
	if err := natscell.ValidateProductionControllerCredentials(check.Config); err != nil {
		return err
	}
	return check.ValidateControllerKeys()
}
