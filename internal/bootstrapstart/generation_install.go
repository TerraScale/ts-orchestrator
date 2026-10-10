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
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/identityrekey"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/jwt/v2"
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
	GenerationArmedFile  = "armed"
	controllerConfigFile = "/etc/terrascale-orchestrator/controller.json"
	// pendingControllerConfig is the next controller.json, written before
	// the chain commits, so a crash after the commit converges next start.
	pendingControllerConfig = ".controller.json.generation"
	maxGenerationChainBytes = bootstrap.MaxMaterialGenerations * (bootstrap.MaxMaterialGenerationBytes + 16<<10)
	controllerServiceUser   = "terrascale-orchestrator"
)

// GenerationConfigFile names slot's controller config beside a generation.
func GenerationConfigFile(slot string) string { return "controller-" + slot + ".json" }

// GenerationTarget is what a material generation must match on this
// controller: its accepted slot, material baseline, broker and deployment.
type GenerationTarget struct {
	Slot                     string
	AcceptanceSHA256         string
	Expected                 bootstrap.MaterialGenerationExpectation
	Broker                   identityrekey.BrokerIdentity
	MaterialGenerationSHA256 string
	ControllerConfigSHA256   string
}

// AcceptedGenerationTarget reads the target from the root-owned
// accepted-install record.
func AcceptedGenerationTarget() (GenerationTarget, error) {
	accepted, err := NewMarkerStore().ReadIdentity()
	if err != nil {
		return GenerationTarget{}, fmt.Errorf("read accepted installation: %w", err)
	}
	return generationTarget(accepted)
}

// GenerationTargetFromAccepted derives the slot's acyclic acceptance binding.
func GenerationTargetFromAccepted(accepted AcceptedIdentity) (GenerationTarget, error) {
	return generationTarget(accepted)
}

func generationTarget(accepted AcceptedIdentity) (GenerationTarget, error) {
	acceptance, err := accepted.AcceptanceSHA256()
	if err != nil {
		return GenerationTarget{}, err
	}
	return GenerationTarget{Slot: accepted.Slot, AcceptanceSHA256: acceptance, Broker: accepted.Broker,
		MaterialGenerationSHA256: accepted.MaterialGenerationSHA256, ControllerConfigSHA256: accepted.ConfigSHA256["controller.json"],
		Expected: bootstrap.MaterialGenerationExpectation{DeploymentID: accepted.DeploymentID,
			Environment: accepted.Environment, ClusterID: accepted.ClusterID, Cell: oci.Region(accepted.Cell),
			ControllerSlots: slices.Clone(accepted.ControllerSlots)}}, nil
}

// VerifyChain admits a new or interrupted generation under the current roots.
func (target GenerationTarget) VerifyChain(chain []trust.Envelope, roots trust.Keyring, now time.Time) ([]bootstrap.VerifiedMaterialGeneration, error) {
	verified, err := bootstrap.VerifyMaterialGenerationChain(chain, roots, target.Expected, now)
	if err != nil {
		return nil, err
	}
	return target.bindChain(verified)
}

// VerifyAdoptedChain verifies a previously installed chain's signatures and acceptance.
func (target GenerationTarget) VerifyAdoptedChain(chain []trust.Envelope, roots trust.Keyring) ([]bootstrap.VerifiedMaterialGeneration, error) {
	verified, err := bootstrap.VerifyAdoptedMaterialGenerationChain(chain, roots, target.Expected)
	if err != nil {
		return nil, err
	}
	return target.bindChain(verified)
}

func (target GenerationTarget) bindChain(verified []bootstrap.VerifiedMaterialGeneration) ([]bootstrap.VerifiedMaterialGeneration, error) {
	if !slices.Contains(target.Expected.ControllerSlots, target.Slot) || !markerDigestRE.MatchString(target.AcceptanceSHA256) ||
		validateAcceptedBroker(target.Broker) != nil || len(verified) == 0 {
		return nil, ErrMaterial
	}
	baseline := target.MaterialGenerationSHA256 == ""
	for _, item := range verified {
		generation := item.Generation()
		if generation.Operator != target.Broker.Operator || generation.SystemAccount != target.Broker.SystemAccount ||
			generation.CellAccount != target.Broker.CellAccount || generation.HostSigner != target.Broker.HostSigner ||
			generation.RoleSigner != target.Broker.RoleSigner {
			return nil, fmt.Errorf("%w: generation changes the accepted broker identity", ErrMaterial)
		}
		if item.Fingerprint() == target.MaterialGenerationSHA256 {
			baseline = true
			if generation.AccountSigner != target.Broker.AccountSigner {
				return nil, fmt.Errorf("%w: accepted generation changes the account signer", ErrMaterial)
			}
		}
	}
	if !baseline {
		return nil, fmt.Errorf("%w: chain omits the accepted material generation", ErrMaterial)
	}
	for _, pin := range verified[len(verified)-1].Generation().ControllerConfigs {
		if pin.Slot == target.Slot && pin.AcceptanceSHA256 != target.AcceptanceSHA256 {
			return nil, fmt.Errorf("%w: generation config is bound to another acceptance", ErrMaterial)
		}
	}
	return verified, nil
}

// VerifyFiles checks every local file and config, plus their material semantics.
func (target GenerationTarget) VerifyFiles(generation bootstrap.MaterialGeneration, read func(string) ([]byte, error), now time.Time) error {
	for _, secret := range generation.Secrets {
		if secret.Slot == "" || secret.Slot == target.Slot {
			if _, err := read(secret.TargetFile); err != nil {
				return err
			}
		}
	}
	for _, pin := range generation.ControllerConfigs {
		if pin.Slot == target.Slot {
			if pin.AcceptanceSHA256 != target.AcceptanceSHA256 {
				return fmt.Errorf("%w: controller config is bound to another acceptance", ErrMaterial)
			}
			if _, err := read(GenerationConfigFile(target.Slot)); err != nil {
				return err
			}
		}
	}
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, read, now); err != nil {
		return err
	}
	if target.Broker.InterRegionAccount != "" {
		wire, err := read("interregion.jwt")
		if err != nil {
			return err
		}
		claim, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(wire)))
		if err != nil || claim.Subject != target.Broker.InterRegionAccount {
			return fmt.Errorf("%w: interregion account differs from accepted broker", ErrMaterial)
		}
	}
	return nil
}

// InstallGeneration is selfupdate prepare's material step for the
// controller unit. It completes or drops an install a crash interrupted,
// points controller.json at the installed generation's config for the slot,
// then installs an armed stage. It reports what it did, and fails only while
// the credential directory may hold a partial install: a refused stage never
// stops the controller's start.
func InstallGeneration(now time.Time) (string, error) {
	accepted, err := NewMarkerStore().ReadIdentity()
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if err := CheckIdentityRekeyPrestart(accepted); err != nil {
		return "", err
	}
	target, err := generationTarget(accepted)
	if err != nil {
		return "", err
	}
	inputs, err := LoadTrustInputs(accepted)
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
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, false)
	if err != nil {
		return "", err
	}
	inMemory := memoryFilesystem(dir)
	unix.Close(dir)
	if !inMemory {
		return "", fmt.Errorf("%w: restore controller credentials into memory before generation adoption", ErrMaterial)
	}
	return generationInstaller{store: store, target: target, roots: inputs.Roots.Current, historicalRoots: inputs.Roots.Historical, spool: GenerationSpoolDirectory,
		config: controllerConfigFile}.install(now)
}

type generationInstaller struct {
	store           MaterialStore
	target          GenerationTarget
	roots           trust.Keyring
	historicalRoots trust.Keyring
	spool           string
	// config is controller.json; its directory holds the pending copy.
	config string
}

func (installer generationInstaller) heldGenerations() ([]trust.Envelope, error) {
	held, err := installer.store.installedGenerations()
	if err != nil {
		return nil, fmt.Errorf("read installed generations: %w", err)
	}
	// A reboot can empty the credential directory, never the durable rollback floor.
	durableWire, err := readBoundedFile(installer.store.chainCopy, maxGenerationChainBytes)
	if err == nil {
		durable, err := bootstrap.DecodeMaterialGenerationChain(durableWire)
		if err != nil {
			return nil, err
		}
		if len(held) == 0 || bootstrap.ExtendsMaterialGenerationChain(durable, held) {
			held = durable
		} else if !chainIs(held, durableWire) && !bootstrap.ExtendsMaterialGenerationChain(held, durable) {
			return nil, fmt.Errorf("%w: installed chain differs from durable chain", ErrMaterial)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	staged, err := installer.stagedGenerations()
	if err != nil {
		return nil, err
	}
	if len(staged) != 0 {
		if len(held) == 0 || bootstrap.ExtendsMaterialGenerationChain(staged, held) {
			held = staged
		} else {
			wire, err := bootstrap.EncodeMaterialGenerationChain(staged)
			if err != nil || !chainIs(held, wire) {
				return nil, fmt.Errorf("%w: committed stage differs from held chain", ErrMaterial)
			}
		}
	}
	if len(held) != 0 {
		if _, err := installer.target.VerifyAdoptedChain(held, installer.historicalRoots); err != nil {
			return nil, err
		}
	}
	return held, nil
}

func (installer generationInstaller) stagedGenerations() ([]trust.Envelope, error) {
	dir, err := openMaterialDirectory(installer.store.installedDirectory, installer.store.serviceUID,
		installer.store.serviceGID, 0o700, installer.store.allowUnsafeAncestors)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	staging, err := installer.store.openStaging(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer unix.Close(staging)
	wire, err := installer.store.readStaged(staging, MaterialGenerationsFile, "", maxGenerationChainBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return bootstrap.DecodeMaterialGenerationChain(wire)
}

func (installer generationInstaller) finishAdoption(now time.Time) error {
	original := installer.store.FinishMaterialAdoption(installer.target, installer.roots, installer.config, now)
	if original == nil {
		return nil
	}
	held, err := installer.heldGenerations()
	if err != nil {
		return errors.Join(original, err)
	}
	wire, chain, files, _, err := installer.armedStage(held, now)
	if err != nil || wire == nil {
		return errors.Join(original, err)
	}
	defer clearContents(files)
	replacement, err := installer.target.VerifyChain(chain, installer.roots, now)
	if err != nil {
		return err
	}
	dir, err := openMaterialDirectory(installer.store.installedDirectory, installer.store.serviceUID,
		installer.store.serviceGID, 0o700, installer.store.allowUnsafeAncestors)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	return installer.store.finish(dir, installer.target, installer.historicalRoots, installer.config, now, nil, replacement)
}

// install completes interrupted adoption first. The chain's rename is the
// commit point: before it the installed set is unchanged and a refusal
// leaves it so; after it every start converges controller.json from the
// pending copy written before the commit.
func (installer generationInstaller) install(now time.Time) (string, error) {
	if err := installer.finishAdoption(now); err != nil {
		return "", err
	}
	held, err := installer.heldGenerations()
	if err != nil {
		return "", err
	}
	wire, chain, files, config, err := installer.armedStage(held, now)
	if err != nil {
		if heldErr := installer.convergeConfig(held, now); heldErr != nil {
			return "", errors.Join(err, heldErr)
		}
		return "refused: " + err.Error(), nil
	}
	if wire == nil {
		if err := installer.convergeConfig(held, now); err != nil {
			return "", err
		}
		return "none", nil
	}
	return installer.installArmed(held, wire, chain, files, config, now)
}

func (installer generationInstaller) installArmed(held []trust.Envelope, wire []byte, chain []trust.Envelope,
	files map[string][]byte, config []byte, now time.Time,
) (string, error) {
	defer clearContents(files)
	// Preserve the committed config before its pending copy becomes the successor's.
	// Adopted signature checks permit an expired predecessor to be replaced.
	if err := installer.preserveConfig(held); err != nil {
		return "", err
	}
	if config != nil {
		if err := writeSynced(filepath.Join(filepath.Dir(installer.config), pendingControllerConfig), config); err != nil {
			return "", fmt.Errorf("write pending controller config: %w", err)
		}
	}
	if err := installer.store.AdoptGeneration(installer.target, installer.roots, wire, files, config, now); err != nil {
		if finishErr := installer.store.FinishMaterialAdoption(installer.target, installer.roots, installer.config, now); finishErr != nil {
			return "", errors.Join(err, finishErr)
		}
		if installed, readErr := installer.store.installedGenerations(); readErr != nil || !chainIs(installed, wire) {
			return "", err
		}
	}
	if err := installer.convergeConfig(chain, now); err != nil {
		return "", err
	}
	return fmt.Sprintf("installed generation %d", len(chain)), nil
}

func (installer generationInstaller) preserveConfig(held []trust.Envelope) error {
	if len(held) != 0 {
		verified, err := installer.target.VerifyAdoptedChain(held, installer.historicalRoots)
		if err != nil {
			return err
		}
		_, pending, err := generationConfig(installer.target, verified[len(verified)-1].Generation(), installer.config)
		if err != nil {
			return err
		}
		if pending {
			if err := os.Rename(filepath.Join(filepath.Dir(installer.config), pendingControllerConfig), installer.config); err != nil {
				return err
			}
			if err := syncDirectory(filepath.Dir(installer.config)); err != nil {
				return err
			}
		}
	}
	return nil
}

// convergeConfig verifies installed material and both config candidates before
// replacing controller.json or removing its exact matching pending copy.
func (installer generationInstaller) convergeConfig(chain []trust.Envelope, now time.Time) error {
	if len(chain) == 0 {
		if installer.target.MaterialGenerationSHA256 != "" {
			return fmt.Errorf("%w: accepted generation chain is missing", ErrMaterial)
		}
		current, err := readBoundedFile(installer.config, bootstrap.MaxControllerConfigBytes)
		if err != nil || digest(current) != installer.target.ControllerConfigSHA256 {
			return fmt.Errorf("%w: controller config differs from accepted baseline", ErrMaterial)
		}
		return nil
	}
	verified, err := installer.target.VerifyAdoptedChain(chain, installer.historicalRoots)
	if err != nil {
		return err
	}
	newest := verified[len(verified)-1]
	if !now.Before(newest.ExpiresAt()) {
		return fmt.Errorf("%w: installed material generation expired", ErrMaterial)
	}
	generation := newest.Generation()
	config, usePending, err := generationConfig(installer.target, generation, installer.config)
	if err != nil {
		return err
	}
	dir, err := openMaterialDirectory(installer.store.installedDirectory, installer.store.serviceUID, installer.store.serviceGID, 0o700, installer.store.allowUnsafeAncestors)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	files, err := installer.store.generationFiles(dir, -1, installer.target, generation, config)
	if err != nil {
		return err
	}
	defer clearContents(files)
	if err := installer.target.VerifyFiles(generation, materialReader(files), now); err != nil {
		return err
	}
	if !usePending {
		return nil
	}
	if err := os.Rename(filepath.Join(filepath.Dir(installer.config), pendingControllerConfig), installer.config); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(installer.config))
}

func generationConfig(target GenerationTarget, generation bootstrap.MaterialGeneration, configPath string) ([]byte, bool, error) {
	for _, pin := range generation.ControllerConfigs {
		if pin.Slot != target.Slot {
			continue
		}
		if pin.AcceptanceSHA256 != target.AcceptanceSHA256 {
			return nil, false, ErrMaterial
		}
		matches := func(wire []byte) bool { return int64(len(wire)) == pin.Size && digest(wire) == pin.SHA256 }
		if current, err := readBoundedFile(configPath, bootstrap.MaxControllerConfigBytes); err == nil && matches(current) {
			return current, false, nil
		}
		pending, err := readBoundedFile(filepath.Join(filepath.Dir(configPath), pendingControllerConfig), bootstrap.MaxControllerConfigBytes)
		if err != nil || !matches(pending) {
			return nil, false, fmt.Errorf("%w: controller config differs and no pending copy matches", ErrMaterial)
		}
		return pending, true, nil
	}
	current, err := readBoundedFile(configPath, bootstrap.MaxControllerConfigBytes)
	if err != nil || digest(current) != target.ControllerConfigSHA256 {
		return nil, false, fmt.Errorf("%w: controller config differs from accepted baseline", ErrMaterial)
	}
	return nil, false, nil
}

func materialReader(files map[string][]byte) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		if wire, ok := files[name]; ok {
			return wire, nil
		}
		return nil, fs.ErrNotExist
	}
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
	verified, err := installer.target.VerifyChain(chain, installer.roots, now)
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
		if generation.ControllerConfigs[index].AcceptanceSHA256 != installer.target.AcceptanceSHA256 {
			return nil, nil, nil, nil, errors.New("the generation's config is for another acceptance of this slot")
		}
		if config, err = readSpooled(spool, GenerationConfigFile(slot), bootstrap.MaxControllerConfigBytes); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	if err := installer.target.VerifyFiles(generation, func(name string) ([]byte, error) {
		if data, ok := files[name]; ok {
			return data, nil
		}
		if config != nil && name == GenerationConfigFile(slot) {
			return config, nil
		}
		return nil, fs.ErrNotExist
	}, now); err != nil {
		clearContents(files)
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
