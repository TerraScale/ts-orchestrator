package bootstrapstart

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// A controller installs a published material generation (TS-668) in two
// halves. Its unprivileged process stages the chain, its slot's config and
// the files its slot holds in GenerationSpoolDirectory, and writes
// GenerationArmedFile there while the cell arms the slot. selfupdate prepare,
// root before every start of the controller unit, installs an armed stage.
// It trusts only root-signed content and the digests it pins, never the
// spool's owner.
const (
	// GenerationSpoolDirectory is the stager's directory, inside the
	// controller's state directory. selfupdate prepare mounts it in memory:
	// the staged files are secrets (TS-745).
	GenerationSpoolDirectory = "/var/lib/terrascale-orchestrator-controller/material-generation"
	// GenerationArmedFile holds the fingerprint of the spooled generation
	// the cell armed this slot for.
	GenerationArmedFile = "armed"
	// ControllerManifestFile is the accepted install's signed manifest.
	ControllerManifestFile = "/etc/terrascale-orchestrator/controller-manifest.json"
	controllerConfigFile   = "/etc/terrascale-orchestrator/controller.json"
	// pendingControllerConfig is the next controller.json, written before
	// the chain commits, so a crash after the commit converges next start.
	pendingControllerConfig = ".controller.json.generation"
	maxGenerationChainBytes = bootstrap.MaxMaterialGenerations * (bootstrap.MaxMaterialGenerationBytes + 16<<10)
	controllerServiceUser   = "terrascale-orchestrator"
)

// GenerationConfigFile names slot's controller config beside a generation.
func GenerationConfigFile(slot string) string { return "controller-" + slot + ".json" }

// GenerationTarget is what a material generation must match on this
// controller: its accepted slot, the slot's manifest and the deployment.
type GenerationTarget struct {
	Slot           string
	ManifestSHA256 string
	Expected       bootstrap.MaterialGenerationExpectation
}

// AcceptedGenerationTarget reads the target from the root-owned
// accepted-install marker and the signed manifest it pins.
func AcceptedGenerationTarget() (GenerationTarget, error) {
	marker, err := NewMarkerStore().Read()
	if err != nil {
		return GenerationTarget{}, fmt.Errorf("read accepted-install marker: %w", err)
	}
	return generationTarget(marker, ControllerManifestFile)
}

func generationTarget(marker AcceptedInstall, manifestPath string) (GenerationTarget, error) {
	wire, err := readBoundedFile(manifestPath, MaxControllerManifestMetadataBytes)
	if err != nil {
		return GenerationTarget{}, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil || digestWire(wire) != marker.ManifestSHA256 {
		return GenerationTarget{}, fmt.Errorf("%w: %s is not the accepted manifest", ErrMaterial, manifestPath)
	}
	manifest, err := bootstrap.ManifestPayload(envelope.Payload)
	if err != nil || manifest.Slot != marker.Slot {
		return GenerationTarget{}, fmt.Errorf("%w: accepted manifest is not this slot's", ErrMaterial)
	}
	return GenerationTarget{Slot: manifest.Slot, ManifestSHA256: marker.ManifestSHA256,
		Expected: bootstrap.MaterialGenerationExpectation{DeploymentID: manifest.DeploymentID,
			Environment: manifest.Environment, ClusterID: manifest.ClusterID, Cell: manifest.Cell,
			ControllerSlots: slices.Clone(manifest.ControllerSlots)}}, nil
}

// InstallGeneration is selfupdate prepare's material step for the
// controller unit. It completes or drops an install a crash interrupted,
// points controller.json at the installed generation's config for the slot,
// then installs an armed stage. It reports what it did, and fails only while
// the credential directory may hold a partial install: a refused stage never
// stops the controller's start.
func InstallGeneration(now time.Time) (string, error) {
	present, err := BakedInputsPresent()
	if err != nil || !present {
		return "", err
	}
	marker, err := NewMarkerStore().Read()
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	account, err := user.Lookup(controllerServiceUser)
	if err != nil {
		return "", fmt.Errorf("look up the controller service account: %w", err)
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil {
		return "", errors.New("controller service UID/GID is invalid")
	}
	store, err := NewMaterialStore(nil, uint32(uid), uint32(gid))
	if err != nil {
		return "", err
	}
	if err := store.FinishMaterialAdoption(); err != nil {
		return "", fmt.Errorf("finish an interrupted material generation install: %w", err)
	}
	target, err := generationTarget(marker, ControllerManifestFile)
	if err != nil {
		return "refused: " + err.Error(), nil
	}
	baked, err := LoadBakedInputs()
	if err != nil {
		return "refused: " + err.Error(), nil
	}
	roots, err := trust.VerifyRootChain(baked.Genesis, baked.Identity.ChainIdentity(), baked.Chain)
	if err != nil {
		return "refused: " + err.Error(), nil
	}
	return generationInstaller{store: store, target: target, roots: roots.Current, spool: GenerationSpoolDirectory,
		config: controllerConfigFile}.install(now)
}

type generationInstaller struct {
	store  MaterialStore
	target GenerationTarget
	roots  trust.Keyring
	spool  string
	// config is controller.json; its directory holds the pending copy.
	config string
}

// install runs after FinishMaterialAdoption. The chain's rename is the
// commit point: before it the installed set is unchanged and a refusal
// leaves it so; after it every start converges controller.json from the
// pending copy written before the commit.
func (installer generationInstaller) install(now time.Time) (string, error) {
	held, err := installer.store.installedGenerations()
	if err != nil {
		return "refused: read the installed generations: " + err.Error(), nil
	}
	note := installer.convergeConfig(held)
	wire, chain, files, config, err := installer.armedStage(held, now)
	if err != nil {
		return note + "refused: " + err.Error(), nil
	}
	if wire == nil {
		return note + "none", nil
	}
	if config != nil {
		if err := writeSynced(filepath.Join(filepath.Dir(installer.config), pendingControllerConfig), config); err != nil {
			return note + "refused: write the pending controller config: " + err.Error(), nil
		}
	}
	if err := installer.store.AdoptGeneration(installer.target.Slot, wire, files); err != nil {
		// Roll a committed stage forward, or drop an uncommitted one, now.
		if finishErr := installer.store.FinishMaterialAdoption(); finishErr != nil {
			return "", errors.Join(err, finishErr)
		}
		if held, readErr := installer.store.installedGenerations(); readErr != nil || !chainIs(held, wire) {
			return note + "refused: " + err.Error(), nil
		}
	}
	return installer.convergeConfig(chain) + fmt.Sprintf("installed generation %d", len(chain)), nil
}

// convergeConfig replaces controller.json with the newest installed
// generation's config for the slot when it differs, from the pending copy.
func (installer generationInstaller) convergeConfig(chain []trust.Envelope) string {
	if len(chain) == 0 {
		return ""
	}
	generation, err := bootstrap.MaterialGenerationPayload(chain[len(chain)-1])
	if err != nil {
		return "controller config: " + err.Error() + "; "
	}
	index := slices.IndexFunc(generation.ControllerConfigs, func(pin bootstrap.GenerationControllerConfig) bool {
		return pin.Slot == installer.target.Slot
	})
	if index < 0 {
		return ""
	}
	pin := generation.ControllerConfigs[index]
	matches := func(data []byte) bool { return int64(len(data)) == pin.Size && digest(data) == pin.SHA256 }
	pending := filepath.Join(filepath.Dir(installer.config), pendingControllerConfig)
	if current, err := readBoundedFile(installer.config, bootstrap.MaxControllerConfigBytes); err == nil && matches(current) {
		_ = os.Remove(pending)
		return ""
	}
	data, err := readBoundedFile(pending, bootstrap.MaxControllerConfigBytes)
	if err != nil || !matches(data) {
		return "controller.json differs from the installed generation's config and no pending copy matches; "
	}
	if err := os.Rename(pending, installer.config); err != nil {
		return "controller config: " + err.Error() + "; "
	}
	if err := syncDirectory(filepath.Dir(installer.config)); err != nil {
		return "controller config: " + err.Error() + "; "
	}
	return ""
}

// armedStage reads the spool's armed stage and verifies all of it again: a
// chain that extends the installed one under the current roots, armed for
// its newest generation, the slot's config for its accepted manifest, and
// every file the slot holds by pin and by CheckGenerationFiles. It returns
// no wire when nothing is armed or the stage is already installed.
func (installer generationInstaller) armedStage(held []trust.Envelope, now time.Time,
) ([]byte, []trust.Envelope, map[string][]byte, []byte, error) {
	spool, err := os.OpenRoot(installer.spool)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer spool.Close()
	armed, err := readSpooled(spool, GenerationArmedFile, 128)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, nil, err
	}
	wire, err := readSpooled(spool, MaterialGenerationsFile, maxGenerationChainBytes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	verified, err := bootstrap.VerifyMaterialGenerationChain(chain, installer.roots, installer.target.Expected, now)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	newest := verified[len(verified)-1]
	if strings.TrimSpace(string(armed)) != newest.Fingerprint() {
		return nil, nil, nil, nil, errors.New("the slot is armed for another generation")
	}
	if chainIs(held, wire) {
		return nil, nil, nil, nil, nil
	}
	if !bootstrap.ExtendsMaterialGenerationChain(chain, held) {
		return nil, nil, nil, nil, errors.New("the staged chain does not extend the installed generations")
	}
	slot := installer.target.Slot
	generation := newest.Generation()
	files := map[string][]byte{}
	for _, secret := range generation.Secrets {
		if secret.Slot != "" && secret.Slot != slot {
			continue
		}
		if files[secret.TargetFile], err = readSpooled(spool, secret.TargetFile, secret.MaxBytes); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	var config []byte
	if index := slices.IndexFunc(generation.ControllerConfigs, func(pin bootstrap.GenerationControllerConfig) bool {
		return pin.Slot == slot
	}); index >= 0 {
		if generation.ControllerConfigs[index].ManifestSHA256 != installer.target.ManifestSHA256 {
			return nil, nil, nil, nil, errors.New("the generation's config is for another manifest of this slot")
		}
		if config, err = readSpooled(spool, GenerationConfigFile(slot), bootstrap.MaxControllerConfigBytes); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, func(name string) ([]byte, error) {
		if data, ok := files[name]; ok {
			return data, nil
		}
		if config != nil && name == GenerationConfigFile(slot) {
			return config, nil
		}
		return nil, fs.ErrNotExist
	}, now); err != nil {
		return nil, nil, nil, nil, err
	}
	return wire, chain, files, config, nil
}

func chainIs(chain []trust.Envelope, wire []byte) bool {
	encoded, err := bootstrap.EncodeMaterialGenerationChain(chain)
	return err == nil && string(encoded) == string(wire)
}

// installedGenerations reads the adopted chain; nil without one.
func (store MaterialStore) installedGenerations() ([]trust.Envelope, error) {
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700,
		store.allowUnsafeAncestors)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	wire, err := readUnpinned(dir, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return bootstrap.DecodeMaterialGenerationChain(wire)
}

// readSpooled reads a regular file beneath the unprivileged spool. The root
// keeps a link from leading elsewhere; O_NONBLOCK keeps a FIFO from
// stalling the start.
func readSpooled(spool *os.Root, name string, limit int64) ([]byte, error) {
	file, err := spool.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: spooled %s is not a regular file", ErrMaterial, name)
	}
	return readLimited(file, name, limit)
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readLimited(file, path, limit)
}

func readLimited(reader io.Reader, name string, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err == nil && (len(data) == 0 || int64(len(data)) > limit) {
		err = fmt.Errorf("%w: %s is empty or too large", ErrMaterial, name)
	}
	return data, err
}

// writeSynced replaces path with data (mode 0644, the writer's owner)
// through a synced temporary file in its directory, then syncs the directory.
func writeSynced(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".generation-config-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(0o644); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
