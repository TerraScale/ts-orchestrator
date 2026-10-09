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
	"strings"

	"golang.org/x/sys/unix"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// GenerationChainCopy is the durable copy of the adopted generation chain.
// The chain is root-signed public metadata (secret OCIDs, versions and
// digests), so it stays on disk; the credential directory itself is memory
// only and is rebuilt at every boot from Vault (TS-745).
const GenerationChainCopy = MarkerDirectory + "/" + MaterialGenerationsFile

// SecretReader reads one exact Vault version and returns its bytes once they
// match the reference's digest and size.
type SecretReader func(context.Context, bootstrap.SecretReference) ([]byte, error)

// RestoreMaterial mounts the controller credential directory in memory and
// fills it with the exact Vault versions the accepted manifest and the newest
// adopted generation pin. Root runs it before bootstrap admission. Restart
// admission verifies the result exactly as it verified the files on disk.
//
// A directory that is already in memory keeps its files; only missing pins
// are read. Before the first mount, removeDiskCopies deletes the old on-disk
// files once each equals its Vault copy; without it they stay hidden beneath
// the mount. check reads and compares every pin and changes nothing.
func RestoreMaterial(ctx context.Context, read SecretReader, removeDiskCopies, check bool) (string, error) {
	if present, err := BakedInputsPresent(); err != nil || !present {
		return "no baked controller inputs", err
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
	if !check {
		if err := requireSwapOff(); err != nil {
			return "", err
		}
		// An adoption interrupted after its commit is completed first, so the
		// installed chain, its durable copy and the files agree.
		if err := store.FinishMaterialAdoption(); err != nil {
			return "", fmt.Errorf("finish an interrupted material generation install: %w", err)
		}
	}
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, false)
	if err != nil {
		return "", fmt.Errorf("open service-owned credential directory: %w", err)
	}
	inMemory := memoryFilesystem(dir)
	refs, chain, err := store.restorePlan(dir, inMemory, !check)
	unix.Close(dir)
	if err != nil {
		return "", err
	}
	if check {
		return store.checkRestore(ctx, refs, chain, read)
	}
	if chain != nil {
		target, err := AcceptedGenerationTarget()
		if err != nil {
			return "", err
		}
		if err := convergeRestoredConfig(store, target, chain, controllerConfigFile); err != nil {
			return "", err
		}
	}
	if !inMemory {
		contents, err := readReferences(ctx, refs, read)
		if err != nil {
			return "", err
		}
		defer clearContents(contents)
		removed := 0
		if removeDiskCopies {
			if removed, err = store.removeDiskCopies(contents, chain); err != nil {
				return "", err
			}
		}
		if err := mountMemory(store.installedDirectory, store.serviceUID, store.serviceGID); err != nil {
			return "", fmt.Errorf("mount the credential directory in memory: %w", err)
		}
		if err := store.fill(contents, chain); err != nil {
			return "", err
		}
		return fmt.Sprintf("restored %d files from Vault into memory; removed %d disk copies", len(refs), removed), nil
	}
	if removeDiskCopies {
		return "", fmt.Errorf("%w: the credential directory is already in memory; disk copies beneath the mount can only be removed before the first mount", ErrMaterial)
	}
	missing, err := store.missing(refs)
	if err != nil {
		return "", err
	}
	contents, err := readReferences(ctx, missing, read)
	if err != nil {
		return "", err
	}
	defer clearContents(contents)
	if err := store.fill(contents, chain); err != nil {
		return "", err
	}
	return fmt.Sprintf("credential directory is in memory; restored %d missing files from Vault", len(missing)), nil
}

// restorePlan returns the exact references the slot's credential directory
// holds and the adopted chain, if any. Without an accepted install nothing is
// pinned yet: initial admission fills the empty memory directory. The chain
// comes from its durable copy, or once, before the first mount, from the
// directory, which then seeds the copy unless keep is false.
func (store MaterialStore) restorePlan(dir int, inMemory, keep bool) (map[string]bootstrap.SecretReference, []byte, error) {
	marker, err := NewMarkerStore().Read()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read accepted-install marker: %w", err)
	}
	wire, err := readBoundedFile(ControllerManifestFile, MaxControllerManifestMetadataBytes)
	if err != nil {
		return nil, nil, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil || digestWire(wire) != marker.ManifestSHA256 {
		return nil, nil, fmt.Errorf("%w: %s is not the accepted manifest", ErrMaterial, ControllerManifestFile)
	}
	manifest, err := bootstrap.ManifestPayload(envelope.Payload)
	if err != nil || manifest.Slot != marker.Slot {
		return nil, nil, fmt.Errorf("%w: accepted manifest is not this slot's", ErrMaterial)
	}
	baked, err := LoadBakedInputs()
	if err != nil {
		return nil, nil, err
	}
	chain, err := readBoundedFile(store.chainCopy, maxGenerationChainBytes)
	seed := false
	if errors.Is(err, os.ErrNotExist) && !inMemory {
		chain, err = readUnpinned(dir, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
		seed = err == nil && keep
	} else if err == nil {
		installed, readErr := readUnpinned(dir, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
		if newer, ok := newerChain(chain, installed); readErr == nil && ok {
			chain, seed = newer, keep
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		return materialReferences(manifest, nil), nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read the adopted generation chain: %w", err)
	}
	decoded, err := bootstrap.DecodeMaterialGenerationChain(chain)
	if err != nil {
		return nil, nil, err
	}
	verified, err := bootstrap.VerifyAdoptedMaterialGenerationChain(decoded, baked.Roots, bootstrap.MaterialGenerationExpectation{
		DeploymentID: manifest.DeploymentID, Environment: manifest.Environment, ClusterID: manifest.ClusterID,
		Cell: manifest.Cell, ControllerSlots: manifest.ControllerSlots})
	if err != nil {
		return nil, nil, fmt.Errorf("verify adopted material generations: %w", err)
	}
	if seed {
		if err := writeSynced(store.chainCopy, chain); err != nil {
			return nil, nil, fmt.Errorf("keep the adopted generation chain: %w", err)
		}
	}
	return materialReferences(manifest, &verified[len(verified)-1]), chain, nil
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
// manifest secrets, replaced by the newest generation's for the files it pins.
// An issued file keeps its manifest version, which restart admission accepts
// until the slot's first renewal.
// ponytail: no controller renews its issued files yet; a renewal must publish
// its new version to Vault before restart recovery can restore it.
func materialReferences(manifest bootstrap.Manifest, newest *bootstrap.VerifiedMaterialGeneration) map[string]bootstrap.SecretReference {
	refs := map[string]bootstrap.SecretReference{}
	for _, reference := range slotReferences(manifest, manifest.Slot) {
		refs[reference.TargetFile] = reference
	}
	if newest != nil {
		for _, secret := range newest.Generation().Secrets {
			if secret.Slot == "" || secret.Slot == manifest.Slot {
				refs[secret.TargetFile] = secret
			}
		}
	}
	return refs
}

func readReferences(ctx context.Context, refs map[string]bootstrap.SecretReference, read SecretReader) (map[string][]byte, error) {
	contents := map[string][]byte{}
	for _, name := range slices.Sorted(maps.Keys(refs)) {
		reference := refs[name]
		if !markerNameRE.MatchString(name) {
			clearContents(contents)
			return nil, ErrMaterial
		}
		content, err := read(ctx, reference)
		if err == nil && digest(content) != reference.SHA256 {
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
	for _, name := range names {
		if err := unix.Unlinkat(dir, name, 0); err != nil {
			return 0, fmt.Errorf("remove disk copy %s: %w", name, err)
		}
	}
	return len(names), unix.Fsync(dir)
}

// missing returns the references whose files the directory lacks; a file that
// is present but differs fails, as restart admission would.
func (store MaterialStore) missing(refs map[string]bootstrap.SecretReference) (map[string]bootstrap.SecretReference, error) {
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	missing := map[string]bootstrap.SecretReference{}
	for name, reference := range refs {
		content, err := readMaterial(dir, name, store.serviceUID, store.serviceGID, reference.SHA256, bootstrap.MaxSecretBytes)
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
func convergeRestoredConfig(store MaterialStore, target GenerationTarget, chainWire []byte, config string) error {
	chain, err := bootstrap.DecodeMaterialGenerationChain(chainWire)
	if err != nil {
		return err
	}
	if note := (generationInstaller{store: store, target: target, config: config}).convergeConfig(chain); note != "" {
		return fmt.Errorf("%w: %s", ErrMaterial, strings.TrimSuffix(note, "; "))
	}
	return nil
}
