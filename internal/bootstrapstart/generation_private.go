package bootstrapstart

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

const (
	// GenerationPrivateSpoolDirectory holds every raw generation file; its
	// parent is root-owned, so the service cannot replace or unlink the stage.
	GenerationPrivateSpoolDirectory = StagingDirectory + "/material-generation"
	GenerationDeliveryFile          = "delivery.json"
	maxGenerationDeliveryBytes      = 16 << 10
)

// prepareDirectoryCustody removes the service's directory mutation rights
// before any raw temporary inode is created in the installed memory mount.
func (store MaterialStore) prepareDirectoryCustody() error {
	if store.installedDirectory != MaterialDirectory {
		return nil
	}
	if os.Geteuid() != 0 {
		return ErrMaterial
	}
	parent, err := openMaterialDirectory(filepath.Dir(MaterialDirectory), 0, 0, 0o755, false)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	name := filepath.Base(MaterialDirectory)
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var held, current unix.Stat_t
	if unix.Fstat(fd, &held) != nil ||
		(held.Uid != 0 || held.Gid != 0 || held.Mode&0o7777 != 0o755) &&
			(held.Uid != store.serviceUID || held.Gid != store.serviceGID || held.Mode&0o7777 != 0o700) {
		return ErrMaterial
	}
	if unix.Fstatat(parent, name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || held.Dev != current.Dev || held.Ino != current.Ino || held.Mode != current.Mode {
		return ErrMaterial
	}
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, 0o755); err != nil {
		return err
	}
	if unix.Fstatat(parent, name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || held.Dev != current.Dev || held.Ino != current.Ino || current.Uid != 0 || current.Gid != 0 || current.Mode&0o7777 != 0o755 {
		return ErrMaterial
	}
	return unix.Fsync(fd)
}

// GenerationDeliveryLifetime is root's immutable delivery record, never an
// authority supplied by the service. Activation also verifies the current
// accepted identity, signed chain, rollback floor and complete private files.
type GenerationDeliveryLifetime struct {
	AcceptanceSHA256 string    `json:"acceptance_sha256"`
	ChainSHA256      string    `json:"chain_sha256"`
	GenerationSHA256 string    `json:"generation_sha256"`
	ExpiresAt        time.Time `json:"expires_at"`
	admit            func() error
	chain            []trust.Envelope
}

func verifyCurrentGenerationAdmission(target GenerationTarget, chain []trust.Envelope) error {
	return verifyGenerationAdmission(target, chain, true)
}

func verifyGenerationAdmission(target GenerationTarget, chain []trust.Envelope, currentAction bool) error {
	accepted, err := NewMarkerStore().ReadIdentity()
	if err != nil {
		return err
	}
	current, err := generationTarget(accepted)
	if err != nil || current.AcceptanceSHA256 != target.AcceptanceSHA256 {
		return ErrMaterial
	}
	inputs, err := LoadTrustInputs(accepted)
	if err != nil {
		return err
	}
	var generationExpiry time.Time
	if len(chain) != 0 {
		var verified []bootstrap.VerifiedMaterialGeneration
		if currentAction {
			verified, err = current.VerifyChain(chain, inputs.Roots.Current, time.Now())
		} else {
			verified, err = current.VerifyAdoptedChain(chain, inputs.Roots.Historical)
		}
		if err != nil {
			return err
		}
		generationExpiry = verified[len(verified)-1].ExpiresAt()
		if !time.Now().Before(generationExpiry) {
			return ErrMaterial
		}
	} else if current.MaterialGenerationSHA256 != "" {
		return ErrMaterial
	}
	wire, err := readCurrentGenerationFloor()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		held, err := bootstrap.DecodeMaterialGenerationChain(wire)
		if err != nil {
			return err
		}
		if _, err := current.VerifyAdoptedChain(held, inputs.Roots.Historical); err != nil {
			return err
		}
		if !chainIs(chain, wire) && !bootstrap.ExtendsMaterialGenerationChain(chain, held) {
			return ErrMaterial
		}
		if !currentAction && !chainIs(chain, wire) {
			if _, err := current.VerifyChain(chain, inputs.Roots.Current, time.Now()); err != nil {
				return err
			}
		}
	} else if !currentAction && len(chain) != 0 {
		newest, err := trust.Fingerprint(chain[len(chain)-1])
		if err != nil {
			return err
		}
		if newest != current.MaterialGenerationSHA256 {
			if _, err := current.VerifyChain(chain, inputs.Roots.Current, time.Now()); err != nil {
				return err
			}
		}
	}
	latest, err := NewMarkerStore().ReadIdentity()
	if err != nil {
		return err
	}
	latestTarget, err := generationTarget(latest)
	if err != nil || latestTarget.AcceptanceSHA256 != current.AcceptanceSHA256 {
		return ErrMaterial
	}
	latestInputs, err := LoadTrustInputs(latest)
	if err != nil {
		return err
	}
	if latestInputs.Roots.Sequence != inputs.Roots.Sequence || latestInputs.Roots.Head != inputs.Roots.Head ||
		trust.RootSetDigest(latestInputs.Genesis) != trust.RootSetDigest(inputs.Genesis) {
		return ErrMaterial
	}
	if !generationExpiry.IsZero() && !time.Now().Before(generationExpiry) {
		return ErrMaterial
	}
	return nil
}

func readCurrentGenerationFloor() ([]byte, error) {
	dir, err := NewMarkerStore().openDirectory()
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, MaterialGenerationsFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), MaterialGenerationsFile)
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o022 != 0 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxGenerationChainBytes {
		return nil, ErrMaterial
	}
	return readLimited(file, MaterialGenerationsFile, maxGenerationChainBytes)
}

func (store MaterialStore) bindGenerationAdmission(delivery *GenerationDeliveryLifetime, target GenerationTarget, chain []trust.Envelope) {
	if delivery != nil {
		delivery.chain = chain
		if store.admitGeneration != nil {
			delivery.admit = func() error { return store.admitGeneration(target, chain) }
		}
	}
}

// PrepareGenerationPrivateSpool creates only the fixed root-only memory stage.
// Existing ownership is checked before creating children; it is never repaired.
func PrepareGenerationPrivateSpool() error {
	if os.Geteuid() != 0 || requireSwapOff() != nil {
		return ErrMaterial
	}
	run, err := openMaterialDirectory("/run", 0, 0, 0o755, false)
	if err != nil {
		return err
	}
	defer unix.Close(run)
	if !memoryFilesystem(run) {
		return ErrMaterial
	}
	if err := unix.Mkdirat(run, filepath.Base(StagingDirectory), 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	parent, err := openMaterialDirectory(StagingDirectory, 0, 0, 0o700, false)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	if !memoryFilesystem(parent) {
		return ErrMaterial
	}
	if err := unix.Mkdirat(parent, filepath.Base(GenerationPrivateSpoolDirectory), 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	stage, err := openMaterialDirectory(GenerationPrivateSpoolDirectory, 0, 0, 0o700, false)
	if err != nil {
		return err
	}
	defer unix.Close(stage)
	if !memoryFilesystem(stage) {
		return ErrMaterial
	}
	return nil
}

func (installer generationInstaller) readPrivateGeneration(wire []byte, newest bootstrap.VerifiedMaterialGeneration, now time.Time) (map[string][]byte, *GenerationDeliveryLifetime, error) {
	directory, err := openMaterialDirectory(installer.privateSpool, 0, 0, 0o700, installer.store.allowUnsafeAncestors)
	if err != nil {
		return nil, nil, err
	}
	defer unix.Close(directory)
	if !installer.store.allowUnsafeAncestors && (!memoryFilesystem(directory) || requireSwapOff() != nil) {
		return nil, nil, ErrMaterial
	}
	delivery, metadata, err := readGenerationDelivery(directory, installer.target, wire, newest, now)
	if err != nil {
		return nil, nil, err
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
	if err != nil {
		return nil, nil, err
	}
	installer.store.bindGenerationAdmission(&delivery, installer.target, chain)
	if err := deliveryLive(&delivery); err != nil {
		return nil, nil, err
	}
	files := map[string][]byte{}
	for _, reference := range newest.Generation().Secrets {
		if reference.Slot != "" && reference.Slot != installer.target.Slot {
			continue
		}
		value, err := readMaterial(directory, reference.TargetFile, 0, 0, reference.SHA256, reference.MaxBytes)
		if err != nil {
			clearContents(files)
			return nil, nil, err
		}
		files[reference.TargetFile] = value
	}
	current, err := readUnpinned(directory, GenerationDeliveryFile, 0, 0, maxGenerationDeliveryBytes)
	if err != nil || digest(current) != digest(metadata) || !time.Now().Before(delivery.ExpiresAt) {
		clearContents(files)
		return nil, nil, ErrMaterial
	}
	if err := deliveryLive(&delivery); err != nil {
		clearContents(files)
		return nil, nil, err
	}
	return files, &delivery, nil
}

func readGenerationDelivery(directory int, target GenerationTarget, wire []byte, newest bootstrap.VerifiedMaterialGeneration, now time.Time) (GenerationDeliveryLifetime, []byte, error) {
	metadata, err := readUnpinned(directory, GenerationDeliveryFile, 0, 0, maxGenerationDeliveryBytes)
	if err != nil {
		return GenerationDeliveryLifetime{}, nil, err
	}
	var delivery GenerationDeliveryLifetime
	if protocol.DecodeStrict(metadata, &delivery, maxGenerationDeliveryBytes) != nil ||
		delivery.AcceptanceSHA256 != target.AcceptanceSHA256 || delivery.ChainSHA256 != digest(wire) ||
		delivery.GenerationSHA256 != newest.Fingerprint() || delivery.ExpiresAt.IsZero() ||
		!now.Before(delivery.ExpiresAt) || !time.Now().Before(delivery.ExpiresAt) ||
		delivery.ExpiresAt.After(newest.ExpiresAt()) {
		return GenerationDeliveryLifetime{}, nil, ErrMaterial
	}
	return delivery, metadata, nil
}

func deliveryLive(delivery *GenerationDeliveryLifetime) error {
	if delivery != nil && (delivery.ExpiresAt.IsZero() || !time.Now().Before(delivery.ExpiresAt)) {
		return ErrMaterial
	}
	if delivery != nil && delivery.admit != nil {
		if err := delivery.admit(); err != nil {
			return err
		}
		if !time.Now().Before(delivery.ExpiresAt) {
			return ErrMaterial
		}
	}
	return nil
}

func (store MaterialStore) publicationLive(delivery *GenerationDeliveryLifetime) error {
	if err := deliveryLive(delivery); err != nil {
		return err
	}
	if store.restoreCurrent != nil {
		chain := store.restoreChain
		if delivery != nil {
			chain = delivery.chain
		}
		if err := store.restoreCurrent(chain); err != nil {
			return err
		}
	}
	if err := deliveryLive(delivery); err != nil {
		return err
	}
	if store.restoreSeal != nil {
		return store.restoreSeal()
	}
	return nil
}

// requireDeliveredStage refuses untagged committed stages in the generation
// activation path. Identity rekey retains its independently admitted path.
func (installer generationInstaller) requireDeliveredStage(now time.Time) error {
	dir, err := openMaterialDirectory(installer.store.installedDirectory, installer.store.serviceUID, installer.store.serviceGID, 0o700, installer.store.allowUnsafeAncestors)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	stage, err := installer.store.openStaging(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(stage)
	wire, err := installer.store.readStaged(stage, MaterialGenerationsFile, "", maxGenerationChainBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
	if err != nil {
		return err
	}
	verified, err := installer.target.VerifyChain(chain, installer.roots, now)
	if err != nil {
		return err
	}
	_, _, err = readGenerationDelivery(stage, installer.target, wire, verified[len(verified)-1], now)
	return err
}
