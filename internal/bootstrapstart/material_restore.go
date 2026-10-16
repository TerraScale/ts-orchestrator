package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// GenerationChainCopy is the durable copy of the adopted generation chain.
// The chain is root-signed public metadata (secret OCIDs, versions and
// digests), so it stays on disk; the credential directory itself is memory
// only and is rebuilt at every boot from Vault (TS-745).
const GenerationChainCopy = MarkerDirectory + "/" + MaterialGenerationsFile

// SecretReader reads one exact Vault version and returns its bytes once they
// match the reference's digest and size.
type SecretReader func(context.Context, bootstrap.SecretReference) ([]byte, error)

// ReadIdentityRekeyMaterial reads the full proposed Vault inventory and refuses
// replacement of existing baseline files outside the signed generation, except
// the controller response key rotated by the root-signed host handoff. The
// installer must verify generation/config semantics together before effects.
func (store MaterialStore) ReadIdentityRekeyMaterial(ctx context.Context, accepted AcceptedIdentity, generationChain []byte, roots trust.Keyring, read SecretReader, now time.Time) (map[string][]byte, error) {
	target, err := generationTarget(accepted)
	if err != nil {
		return nil, err
	}
	var newest *bootstrap.VerifiedMaterialGeneration
	if len(generationChain) != 0 {
		chain, err := bootstrap.DecodeMaterialGenerationChain(generationChain)
		if err != nil {
			return nil, err
		}
		verified, err := target.VerifyChain(chain, roots, now)
		if err != nil {
			return nil, err
		}
		newest = &verified[len(verified)-1]
		if newest.Fingerprint() != accepted.MaterialGenerationSHA256 {
			return nil, fmt.Errorf("%w: proposed chain differs from accepted baseline", ErrMaterial)
		}
	} else if accepted.MaterialGenerationSHA256 != "" {
		return nil, fmt.Errorf("%w: proposed generation chain is missing", ErrMaterial)
	}
	refs := materialReferences(accepted, newest)
	baseline := materialReferences(accepted, nil)
	immutable := acceptedMaterialDigests(accepted)
	delete(immutable, accepted.Slot+"-response.key")
	if newest != nil {
		for _, ref := range newest.Generation().Secrets {
			if ref.Slot == "" || ref.Slot == accepted.Slot {
				if baseline[ref.TargetFile] != ref {
					return nil, fmt.Errorf("%w: proposed generation reference %s differs from accepted baseline", ErrMaterial, ref.TargetFile)
				}
				delete(immutable, ref.TargetFile)
			}
		}
	}
	installed, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return nil, err
	}
	defer unix.Close(installed)
	if err := store.verifyInstalled(ctx, installed, immutable); err != nil {
		return nil, fmt.Errorf("identity rekey must preserve existing baseline material: %w", err)
	}
	return readReferences(ctx, refs, read)
}

// RestoreMaterial mounts the controller credential directory in memory and
// fills it with the exact Vault versions the accepted baseline and the newest
// adopted generation pin. Root runs it before bootstrap admission. Restart
// admission verifies the result exactly as it verified the files on disk.
//
// A directory that is already in memory keeps its files; only missing pins
// are read. Before the first mount, removeDiskCopies deletes the old on-disk
// files once each equals its Vault copy; without it they stay hidden beneath
// the mount. check reads and compares every pin and changes nothing.
func RestoreMaterial(ctx context.Context, read SecretReader, removeDiskCopies, check bool) (string, error) {
	if !check {
		unlock, err := selfupdate.NewLayout(selfupdate.DefaultRoot).Lock()
		if err != nil {
			return "", err
		}
		defer unlock()
	}
	accepted, err := NewMarkerStore().ReadIdentity()
	initial := errors.Is(err, os.ErrNotExist)
	if err != nil && !initial {
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
	if initial {
		if present, err := IdentityRekeyJournalPresent(); err != nil {
			return "", err
		} else if present {
			return "", ErrIdentityRekeyLocalPending
		}
		if check {
			return "no accepted controller installation", nil
		}
		if err := requireSwapOff(); err != nil {
			return "", err
		}
		if err := store.prepareInitialMemory(); err != nil {
			return "", err
		}
		return "prepared initial controller credential directory in memory", nil
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
	installer := generationInstaller{store: store, target: target, roots: inputs.Roots.Current,
		historicalRoots: inputs.Roots.Historical, spool: GenerationSpoolDirectory, config: controllerConfigFile}
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, false)
	if err != nil {
		return "", fmt.Errorf("open service-owned credential directory: %w", err)
	}
	inMemory := memoryFilesystem(dir)
	unix.Close(dir)
	if !check {
		if err := requireSwapOff(); err != nil {
			return "", err
		}
		if !inMemory {
			return installer.restoreDisk(ctx, accepted, read, removeDiskCopies, time.Now())
		}
		if err := installer.finishAdoption(time.Now()); err != nil {
			return "", fmt.Errorf("finish an interrupted material generation install: %w", err)
		}
		if err := installer.restoreArmedGeneration(time.Now()); err != nil {
			return "", err
		}
	}
	dir, err = openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, false)
	if err != nil {
		return "", fmt.Errorf("open service-owned credential directory: %w", err)
	}
	refs, chain, err := store.restorePlan(dir, accepted, inputs.Roots.Historical, time.Now())
	unix.Close(dir)
	if err != nil {
		return "", err
	}
	if check {
		return store.checkRestore(ctx, refs, chain, read)
	}
	if removeDiskCopies {
		return "", fmt.Errorf("%w: the credential directory is already in memory; disk copies beneath the mount can only be removed before the first mount", ErrMaterial)
	}
	pins := MaterialPins{}
	if chain != nil {
		decoded, err := bootstrap.DecodeMaterialGenerationChain(chain)
		if err != nil {
			return "", err
		}
		verified, err := target.VerifyAdoptedChain(decoded, inputs.Roots.Historical)
		if err != nil {
			return "", err
		}
		pins, err = pinsFromGeneration(accepted, verified[len(verified)-1], chain)
		if err != nil {
			return "", err
		}
	}
	missing, err := store.missing(refs, pins.Issued)
	if err != nil {
		return "", err
	}
	contents, err := store.readRestoreReferences(ctx, refs, missing, read)
	if err != nil {
		return "", err
	}
	defer clearContents(contents)
	if err := pins.verifyIssuedFiles(contents, time.Now()); err != nil {
		return "", err
	}
	if err := verifyRestoreContents(target, inputs.Roots.Historical, chain, contents, controllerConfigFile, time.Now()); err != nil {
		return "", err
	}
	if chain != nil {
		if err := writeSynced(store.chainCopy, chain); err != nil {
			return "", err
		}
		if err := convergeRestoredConfig(store, target, inputs.Roots.Historical, chain, controllerConfigFile, time.Now(), contents); err != nil {
			return "", err
		}
	}
	for name := range contents {
		if _, ok := missing[name]; !ok {
			clear(contents[name])
			delete(contents, name)
		}
	}
	if err := store.fill(contents, chain); err != nil {
		return "", err
	}
	return fmt.Sprintf("credential directory is in memory; restored %d missing files from Vault", len(missing)), nil
}

// Restoration precedes prepare: install a verified armed successor before
// checking the freshness of the adopted Vault inventory.
func (installer generationInstaller) restoreDisk(ctx context.Context, accepted AcceptedIdentity, read SecretReader, removeDiskCopies bool, now time.Time) (string, error) {
	started := time.Now()
	store := installer.store
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return "", err
	}
	defer unix.Close(dir)
	if memoryFilesystem(dir) {
		return "", fmt.Errorf("%w: credential directory is already in memory", ErrMaterial)
	}
	staging, err := store.openStaging(dir)
	if err == nil {
		unix.Close(staging)
		return "", fmt.Errorf("%w: refuse to hide an existing disk-backed material stage", ErrMaterial)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	held, err := installer.heldGenerations()
	if err != nil {
		return "", err
	}
	wire, chain, staged, config, _ := installer.armedStage(held, now)
	defer clearContents(staged)
	successor := wire != nil
	if !successor {
		chain = held
		if len(chain) != 0 {
			wire, err = bootstrap.EncodeMaterialGenerationChain(chain)
			if err != nil {
				return "", err
			}
		}
	}
	var newest *bootstrap.VerifiedMaterialGeneration
	if len(chain) != 0 {
		verified, err := installer.target.VerifyAdoptedChain(chain, installer.historicalRoots)
		if err != nil {
			return "", err
		}
		newest = &verified[len(verified)-1]
		if !now.Before(newest.ExpiresAt()) {
			return "", fmt.Errorf("%w: adopted material generation expired", ErrMaterial)
		}
	} else if installer.target.MaterialGenerationSHA256 != "" {
		return "", fmt.Errorf("%w: accepted material generation is missing", ErrMaterial)
	}
	refs := materialReferences(accepted, newest)
	contents, err := readReferences(ctx, refs, read)
	if err != nil {
		return "", err
	}
	defer clearContents(contents)
	var diskContents map[string][]byte
	var diskChain []byte
	if removeDiskCopies {
		diskRefs, wire, err := installer.diskRemovalPlan(dir, accepted, held)
		if err != nil {
			return "", err
		}
		diskChain = wire
		diskContents, err = readReferences(ctx, diskRefs, read)
		if err != nil {
			return "", err
		}
		defer clearContents(diskContents)
		if _, err := store.checkRestore(ctx, diskRefs, diskChain, func(_ context.Context, ref bootstrap.SecretReference) ([]byte, error) {
			return bytes.Clone(diskContents[ref.TargetFile]), nil
		}); err != nil {
			return "", err
		}
	}
	if successor {
		checked := maps.Clone(contents)
		if config != nil {
			checked[GenerationConfigFile(installer.target.Slot)] = config
		}
		if _, err := installer.target.VerifyChain(chain, installer.roots, now.Add(time.Since(started))); err != nil {
			return "", err
		}
		if err := installer.target.VerifyFiles(newest.Generation(), materialReader(checked), now.Add(time.Since(started))); err != nil {
			return "", err
		}
		if err := installer.preserveConfig(held); err != nil {
			return "", err
		}
		if config != nil {
			if err := writeSynced(filepath.Join(filepath.Dir(installer.config), pendingControllerConfig), config); err != nil {
				return "", err
			}
		}
	}
	if err := verifyRestoreContents(installer.target, installer.historicalRoots, wire, contents, installer.config, now.Add(time.Since(started))); err != nil {
		return "", err
	}
	if wire != nil {
		if err := writeSynced(store.chainCopy, wire); err != nil {
			return "", err
		}
		if err := convergeRestoredConfig(store, installer.target, installer.historicalRoots, wire, installer.config, now.Add(time.Since(started)), contents); err != nil {
			return "", err
		}
	}
	removed := 0
	if removeDiskCopies {
		if removed, err = store.removeDiskCopies(diskContents, diskChain); err != nil {
			return "", err
		}
	}
	if err := mountMemory(store.installedDirectory, store.serviceUID, store.serviceGID); err != nil {
		return "", fmt.Errorf("mount the credential directory in memory: %w", err)
	}
	if err := verifyRestoreContents(installer.target, installer.historicalRoots, wire, contents, installer.config, now.Add(time.Since(started))); err != nil {
		return "", err
	}
	if err := store.fill(contents, wire); err != nil {
		return "", err
	}
	return fmt.Sprintf("restored %d files from Vault into memory; removed %d disk copies", len(refs), removed), nil
}

// Disk cleanup uses the exact installed prefix, even after a successor's durable commit.
func (installer generationInstaller) diskRemovalPlan(dir int, accepted AcceptedIdentity, held []trust.Envelope) (map[string]bootstrap.SecretReference, []byte, error) {
	wire, err := readUnpinned(dir, MaterialGenerationsFile, installer.store.serviceUID, installer.store.serviceGID, maxGenerationChainBytes)
	var newest *bootstrap.VerifiedMaterialGeneration
	if err == nil {
		chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
		if err != nil {
			return nil, nil, err
		}
		if !chainIs(held, wire) && !bootstrap.ExtendsMaterialGenerationChain(held, chain) {
			return nil, nil, fmt.Errorf("%w: disk cleanup chain differs from held chain", ErrMaterial)
		}
		verified, err := installer.target.VerifyAdoptedChain(chain, installer.historicalRoots)
		if err != nil {
			return nil, nil, err
		}
		newest = &verified[len(verified)-1]
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	refs := materialReferences(accepted, newest)
	names, err := stagedNames(dir)
	if err != nil {
		return nil, nil, err
	}
	present := map[string]bootstrap.SecretReference{}
	for _, name := range names {
		if name == MaterialGenerationsFile && wire != nil {
			continue
		}
		ref, ok := refs[name]
		if !ok {
			return nil, nil, fmt.Errorf("%w: %s has no verified disk reference", ErrMaterial, name)
		}
		present[name] = ref
	}
	return present, wire, nil
}

func (installer generationInstaller) restoreArmedGeneration(now time.Time) error {
	held, err := installer.heldGenerations()
	if err != nil {
		return err
	}
	wire, chain, files, config, err := installer.armedStage(held, now)
	if err != nil || wire == nil {
		// Vault restoration validates the held inventory after filling missing files.
		return nil
	}
	_, err = installer.installArmed(held, wire, chain, files, config, now)
	return err
}

// restorePlan returns the exact references the slot's credential directory
// holds and the adopted chain, if any. Without an accepted install nothing is
// pinned yet: initial admission fills the empty memory directory. The chain
// comes from its durable copy, or once, before the first mount, from the
// directory, which then seeds the copy unless keep is false.
func (store MaterialStore) restorePlan(dir int, accepted AcceptedIdentity, roots trust.Keyring, now time.Time) (map[string]bootstrap.SecretReference, []byte, error) {
	target, err := generationTarget(accepted)
	if err != nil {
		return nil, nil, err
	}
	chain, err := readBoundedFile(store.chainCopy, maxGenerationChainBytes)
	if errors.Is(err, os.ErrNotExist) {
		chain, err = readUnpinned(dir, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
	} else if err == nil {
		installed, readErr := readUnpinned(dir, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
		if readErr == nil {
			if newer, ok := newerChain(chain, installed); ok {
				chain = newer
			} else if _, extends := newerChain(installed, chain); !extends && !bytes.Equal(chain, installed) {
				return nil, nil, fmt.Errorf("%w: installed chain differs from durable chain", ErrMaterial)
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return nil, nil, readErr
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		if target.MaterialGenerationSHA256 != "" {
			return nil, nil, fmt.Errorf("%w: accepted material generation is missing", ErrMaterial)
		}
		return materialReferences(accepted, nil), nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read adopted generation chain: %w", err)
	}
	decoded, err := bootstrap.DecodeMaterialGenerationChain(chain)
	if err != nil {
		return nil, nil, err
	}
	verified, err := target.VerifyAdoptedChain(decoded, roots)
	if err != nil {
		return nil, nil, fmt.Errorf("verify adopted material generations: %w", err)
	}
	if !now.Before(verified[len(verified)-1].ExpiresAt()) {
		return nil, nil, fmt.Errorf("%w: adopted material generation expired", ErrMaterial)
	}
	return materialReferences(accepted, &verified[len(verified)-1]), chain, nil
}

// newerChain returns installed, and true, when it extends the durable chain:
// a release older than the durable copy adopts a generation without updating
// it. Either way the caller verifies the chain it keeps.
func newerChain(durable, installed []byte) ([]byte, bool) {
	held, heldErr := bootstrap.DecodeMaterialGenerationChain(durable)
	newer, newerErr := bootstrap.DecodeMaterialGenerationChain(installed)
	if heldErr != nil || newerErr != nil || !bootstrap.ExtendsMaterialGenerationChain(newer, held) {
		return durable, false
	}
	return installed, true
}

// materialReferences is what restartPins pins, by reference: the slot's
// accepted references, replaced by the newest generation's for the files it pins.
// An issued file keeps its accepted version, which restart admission accepts
// until the slot's first renewal.
// Recovery of issued renewal requires a root-signed generation pin in Vault.
func materialReferences(accepted AcceptedIdentity, newest *bootstrap.VerifiedMaterialGeneration) map[string]bootstrap.SecretReference {
	refs := map[string]bootstrap.SecretReference{}
	for _, reference := range accepted.MaterialReferences {
		refs[reference.TargetFile] = reference
	}
	if newest != nil {
		for _, secret := range newest.Generation().Secrets {
			if secret.Slot == "" || secret.Slot == accepted.Slot {
				refs[secret.TargetFile] = secret
			}
		}
	}
	return refs
}

func readReferences(ctx context.Context, refs map[string]bootstrap.SecretReference, read SecretReader) (map[string][]byte, error) {
	if read == nil && len(refs) != 0 {
		return nil, ErrMaterial
	}
	contents := map[string][]byte{}
	for _, name := range slices.Sorted(maps.Keys(refs)) {
		reference := refs[name]
		if !markerNameRE.MatchString(name) {
			clearContents(contents)
			return nil, ErrMaterial
		}
		content, err := read(ctx, reference)
		if err == nil && (len(content) == 0 || int64(len(content)) > reference.MaxBytes || digest(content) != reference.SHA256) {
			clear(content)
			err = bootstrap.ErrVaultSecretMismatch
		}
		if err != nil {
			clearContents(contents)
			return nil, fmt.Errorf("read %s from Vault: %w", name, err)
		}
		contents[name] = content
	}
	return contents, nil
}

func clearContents(contents map[string][]byte) {
	for _, content := range contents {
		clear(content)
	}
}

// checkRestore reads every pin from Vault and compares it with the installed
// file, which may still be on disk. It writes nothing.
func (store MaterialStore) checkRestore(ctx context.Context, refs map[string]bootstrap.SecretReference, chain []byte,
	read SecretReader,
) (string, error) {
	contents, err := readReferences(ctx, refs, read)
	if err != nil {
		return "", err
	}
	defer clearContents(contents)
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return "", err
	}
	defer unix.Close(dir)
	for name, content := range contents {
		installed, err := readMaterial(dir, name, store.serviceUID, store.serviceGID, digest(content), bootstrap.MaxSecretBytes)
		clear(installed)
		if err != nil {
			return "", fmt.Errorf("installed %s differs from its Vault version: %w", name, err)
		}
	}
	if chain != nil {
		installed, err := readUnpinned(dir, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
		if err != nil || !bytes.Equal(installed, chain) {
			return "", fmt.Errorf("%w: installed generation chain differs from its durable copy", ErrMaterial)
		}
	}
	return fmt.Sprintf("all %d files equal their Vault versions", len(contents)), nil
}

// removeDiskCopies deletes the on-disk directory's files after each one is
// shown to equal its Vault copy (or the chain's durable copy). Anything else
// in the directory refuses the removal, so nothing unrecovered is lost.
func (store MaterialStore) removeDiskCopies(contents map[string][]byte, chain []byte) (int, error) {
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return 0, err
	}
	defer unix.Close(dir)
	names, err := stagedNames(dir)
	if err != nil {
		return 0, err
	}
	for _, name := range names {
		var installed []byte
		if want, ok := contents[name]; ok {
			installed, err = readMaterial(dir, name, store.serviceUID, store.serviceGID, digest(want), bootstrap.MaxSecretBytes)
		} else if name == MaterialGenerationsFile && chain != nil {
			installed, err = readUnpinned(dir, name, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
			if err == nil && !bytes.Equal(installed, chain) {
				err = ErrMaterial
			}
		} else {
			err = fmt.Errorf("%w: %s has no Vault copy", ErrMaterial, name)
		}
		clear(installed)
		if err != nil {
			return 0, fmt.Errorf("keep the disk copies: %s: %w", name, err)
		}
	}
	// Keep the predecessor chain until its last secret is gone so cleanup can retry.
	if index := slices.Index(names, MaterialGenerationsFile); index >= 0 {
		names = append(slices.Delete(names, index, index+1), MaterialGenerationsFile)
	}
	for _, name := range names {
		if err := unix.Unlinkat(dir, name, 0); err != nil {
			return 0, fmt.Errorf("remove disk copy %s: %w", name, err)
		}
	}
	return len(names), unix.Fsync(dir)
}

// missing returns the references whose files the directory lacks; a file that
// is present but differs fails, as restart admission would.
func (store MaterialStore) missing(refs map[string]bootstrap.SecretReference, issued map[string]string) (map[string]bootstrap.SecretReference, error) {
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	missing := map[string]bootstrap.SecretReference{}
	for name, reference := range refs {
		content, err := readMaterial(dir, name, store.serviceUID, store.serviceGID, reference.SHA256, reference.MaxBytes)
		if issued[name] != "" {
			clear(content)
			content, err = readUnpinned(dir, name, store.serviceUID, store.serviceGID, reference.MaxBytes)
		}
		clear(content)
		if errors.Is(err, os.ErrNotExist) {
			missing[name] = reference
		} else if err != nil {
			return nil, fmt.Errorf("installed %s: %w", name, err)
		}
	}
	return missing, nil
}

// fill installs contents and, when the directory has none, the chain; a chain
// it has must be the durable copy.
func (store MaterialStore) fill(contents map[string][]byte, chain []byte) error {
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	for _, name := range slices.Sorted(maps.Keys(contents)) {
		if err := store.installMaterial(dir, name, contents[name], digest(contents[name]), bootstrap.MaxSecretBytes); err != nil {
			return fmt.Errorf("install %s: %w", name, err)
		}
	}
	if chain == nil {
		return nil
	}
	installed, err := readUnpinned(dir, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
	if errors.Is(err, os.ErrNotExist) {
		return store.writeStaged(dir, MaterialGenerationsFile, chain)
	}
	if err == nil && !bytes.Equal(installed, chain) {
		err = fmt.Errorf("%w: installed generation chain differs from its durable copy", ErrMaterial)
	}
	return err
}

// keepChain writes the durable copy of a staged chain before it commits.
func (store MaterialStore) keepChain(staging int) error {
	if store.chainCopy == "" {
		return nil
	}
	chain, err := readUnpinned(staging, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
	if err != nil {
		return err
	}
	return writeSynced(store.chainCopy, chain)
}

func memoryFilesystem(fd int) bool {
	var fs unix.Statfs_t
	return unix.Fstatfs(fd, &fs) == nil && fs.Type == unix.TMPFS_MAGIC
}

// requireSwapOff refuses to put credentials in memory that could be paged to
// disk, also into a tmpfs mounted earlier.
func requireSwapOff() error {
	if !vaultsecret.SwapOff() {
		return errors.New("controller credentials need swap disabled")
	}
	return nil
}

// mountMemory mounts an owner-only tmpfs at path. It keeps tmpfs's default
// cap, half the RAM: a legal manifest and generation may pin hundreds of
// files of up to bootstrap.MaxSecretBytes, and an adoption stages a whole set
// beside them, so a smaller fixed cap could fail a restore after its disk
// copies are gone. tmpfs holds only what is written.
func mountMemory(path string, uid, gid uint32) error {
	if filepath.Clean(path) != path {
		return ErrMaterial
	}
	return unix.Mount("tmpfs", path, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC,
		fmt.Sprintf("mode=0700,uid=%d,gid=%d", uid, gid))
}

// convergeRestoredConfig puts the pending controller config in place when the
// adopted chain pins it, as prepare does after an adoption. Admission reads
// controller.json before the controller's prepare can run, so a reboot
// between the chain's commit and that rename would otherwise refuse the
// controller its own new config.
func verifyRestoreContents(target GenerationTarget, roots trust.Keyring, chainWire []byte, contents map[string][]byte, configPath string, now time.Time) error {
	if chainWire == nil {
		config, err := readBoundedFile(configPath, bootstrap.MaxControllerConfigBytes)
		if err != nil || digest(config) != target.ControllerConfigSHA256 {
			return fmt.Errorf("%w: controller config differs from accepted baseline", ErrMaterial)
		}
		return nil
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(chainWire)
	if err != nil {
		return err
	}
	verified, err := target.VerifyAdoptedChain(chain, roots)
	if err != nil {
		return err
	}
	newest := verified[len(verified)-1]
	if !now.Before(newest.ExpiresAt()) {
		return fmt.Errorf("%w: adopted material generation expired", ErrMaterial)
	}
	config, _, err := generationConfig(target, newest.Generation(), configPath)
	if err != nil {
		return err
	}
	files := maps.Clone(contents)
	if config != nil {
		files[GenerationConfigFile(target.Slot)] = config
	}
	return target.VerifyFiles(newest.Generation(), materialReader(files), now)
}

func convergeRestoredConfig(store MaterialStore, target GenerationTarget, roots trust.Keyring, chainWire []byte, configPath string, now time.Time, contents map[string][]byte) error {
	if err := verifyRestoreContents(target, roots, chainWire, contents, configPath, now); err != nil {
		return err
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(chainWire)
	if err != nil {
		return err
	}
	generation, err := bootstrap.MaterialGenerationPayload(chain[len(chain)-1])
	if err != nil {
		return err
	}
	_, pending, err := generationConfig(target, generation, configPath)
	if err != nil || !pending {
		return err
	}
	if err := os.Rename(filepath.Join(filepath.Dir(configPath), pendingControllerConfig), configPath); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(configPath))
}

func (store MaterialStore) prepareInitialMemory() error {
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	if memoryFilesystem(dir) {
		return nil
	}
	copy, err := unix.Dup(dir)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(copy), store.installedDirectory)
	names, err := file.Readdirnames(-1)
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if len(names) != 0 {
		return fmt.Errorf("%w: initial disk credential directory must be empty", ErrMaterial)
	}
	return mountMemory(store.installedDirectory, store.serviceUID, store.serviceGID)
}

func (store MaterialStore) readRestoreReferences(ctx context.Context, refs, missing map[string]bootstrap.SecretReference, read SecretReader) (map[string][]byte, error) {
	contents, err := readReferences(ctx, missing, read)
	if err != nil {
		return nil, err
	}
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		clearContents(contents)
		return nil, err
	}
	defer unix.Close(dir)
	for name, ref := range refs {
		if _, absent := missing[name]; absent {
			continue
		}
		wire, err := readUnpinned(dir, name, store.serviceUID, store.serviceGID, ref.MaxBytes)
		if err != nil {
			clearContents(contents)
			return nil, err
		}
		contents[name] = wire
	}
	return contents, nil
}
