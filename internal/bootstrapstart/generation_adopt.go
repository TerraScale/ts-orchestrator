package bootstrapstart

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"

	"golang.org/x/sys/unix"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// generationStaging is the credential directory's staging subdirectory for
// a material generation being installed. Restart admission never sees it:
// FinishMaterialAdoption runs first.
const generationStaging = ".generation-staging"

// AdoptGeneration installs a material generation the caller verified (chain
// under the current roots, files with bootstrapmaterial.CheckGenerationFiles)
// into slot's credential directory, crash-safely: exactly the files the slot
// holds, every unbound pin and the slot's own. The files are written to a
// staging subdirectory and synced, then the chain, which is the commit
// record; then every file is renamed over its installed name and the chain
// last. A crash before the chain is staged leaves the installed set as it
// was; after, FinishMaterialAdoption completes the install. The running
// processes see each renamed file as soon as it is in place. Root runs it
// (selfupdate prepare): everything it writes belongs to the service user.
func (store MaterialStore) AdoptGeneration(slot string, chainWire []byte, files map[string][]byte) error {
	chain, err := bootstrap.DecodeMaterialGenerationChain(chainWire)
	if err != nil {
		return err
	}
	if err := stagedFilesMatch(chain, slot, files); err != nil {
		return err
	}
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return fmt.Errorf("open service-owned credential directory: %w", err)
	}
	defer unix.Close(dir)
	// A leftover stage is never mixed with this one.
	if err := store.finish(dir); err != nil {
		return err
	}
	if err := unix.Mkdirat(dir, generationStaging, 0o700); err != nil {
		return fmt.Errorf("create generation staging: %w", err)
	}
	if err := unix.Fchownat(dir, generationStaging, int(store.serviceUID), int(store.serviceGID),
		unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("own generation staging: %w", err)
	}
	staging, err := store.openStaging(dir)
	if err != nil {
		return err
	}
	defer unix.Close(staging)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if err := store.writeStaged(staging, name, files[name]); err != nil {
			return fmt.Errorf("stage %s: %w", name, err)
		}
	}
	if err := store.writeStaged(staging, MaterialGenerationsFile, chainWire); err != nil {
		return fmt.Errorf("commit staged generation: %w", err)
	}
	return store.rollForward(dir, staging)
}

// FinishMaterialAdoption completes a generation install interrupted after
// its commit, or discards one interrupted before it (or one whose staged
// files no longer match its chain). It runs before restart admission.
func (store MaterialStore) FinishMaterialAdoption() error {
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return fmt.Errorf("open service-owned credential directory: %w", err)
	}
	defer unix.Close(dir)
	return store.finish(dir)
}

func (store MaterialStore) finish(dir int) error {
	staging, err := store.openStaging(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(staging)
	names, err := stagedNames(staging)
	if err != nil {
		return err
	}
	if slices.Contains(names, MaterialGenerationsFile) {
		chainWire, err := readUnpinned(staging, MaterialGenerationsFile, store.serviceUID, store.serviceGID,
			bootstrap.MaxMaterialGenerations*(bootstrap.MaxMaterialGenerationBytes+16<<10))
		if err == nil {
			var chain []trust.Envelope
			if chain, err = bootstrap.DecodeMaterialGenerationChain(chainWire); err == nil {
				err = store.stagedDigestsMatch(staging, chain, names)
			}
		}
		if err == nil {
			return store.rollForward(dir, staging)
		}
	}
	// Uncommitted or inconsistent: the installed set is untouched; drop it.
	for _, name := range names {
		if err := unix.Unlinkat(staging, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return removeStaging(dir)
}

// rollForward renames every staged file over its installed name, the chain
// last, then removes the staging directory.
func (store MaterialStore) rollForward(dir, staging int) error {
	names, err := stagedNames(staging)
	if err != nil {
		return err
	}
	for _, name := range names {
		if name == MaterialGenerationsFile {
			continue
		}
		if err := unix.Renameat(staging, name, dir, name); err != nil {
			return fmt.Errorf("install %s: %w", name, err)
		}
	}
	if slices.Contains(names, MaterialGenerationsFile) {
		if err := unix.Fsync(dir); err != nil {
			return err
		}
		// The durable copy is what restart recovery restores from (TS-745).
		if err := store.keepChain(staging); err != nil {
			return fmt.Errorf("keep %s: %w", MaterialGenerationsFile, err)
		}
		if err := unix.Renameat(staging, MaterialGenerationsFile, dir, MaterialGenerationsFile); err != nil {
			return fmt.Errorf("install %s: %w", MaterialGenerationsFile, err)
		}
	}
	if err := unix.Fsync(dir); err != nil {
		return err
	}
	return removeStaging(dir)
}

func (store MaterialStore) openStaging(dir int) (int, error) {
	fd, err := unix.Openat(dir, generationStaging, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, os.ErrNotExist
	}
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != store.serviceUID || stat.Gid != store.serviceGID ||
		stat.Mode&0o777 != 0o700 {
		unix.Close(fd)
		return -1, fmt.Errorf("%w: generation staging is not the service's own directory", ErrMaterial)
	}
	return fd, nil
}

func (store MaterialStore) writeStaged(staging int, name string, content []byte) error {
	if !markerNameRE.MatchString(name) || len(content) == 0 || int64(len(content)) > bootstrap.MaxSecretBytes &&
		name != MaterialGenerationsFile {
		return ErrMaterial
	}
	fd, err := unix.Openat(staging, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	if err := unix.Fchown(fd, int(store.serviceUID), int(store.serviceGID)); err != nil {
		_ = file.Close()
		return err
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = file.Close()
		return err
	}
	if n, err := file.Write(content); err != nil || n != len(content) {
		_ = file.Close()
		return errors.Join(err, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return unix.Fsync(staging)
}

// stagedDigestsMatch checks every staged file against the newest
// generation's pins; a file already renamed into place is not staged.
func (store MaterialStore) stagedDigestsMatch(staging int, chain []trust.Envelope, names []string) error {
	pins, err := newestPins(chain)
	if err != nil {
		return err
	}
	for _, name := range names {
		if name == MaterialGenerationsFile {
			continue
		}
		want := pins[name]
		if want == "" {
			return fmt.Errorf("%w: staged %s is not pinned by the staged generation", ErrMaterial, name)
		}
		content, err := readMaterial(staging, name, store.serviceUID, store.serviceGID, want, bootstrap.MaxSecretBytes)
		if err != nil {
			return fmt.Errorf("staged %s: %w", name, err)
		}
		clear(content)
	}
	return nil
}

// stagedFilesMatch requires exactly the newest generation's files slot
// holds: every unbound pin and the slot's own, never another slot's.
func stagedFilesMatch(chain []trust.Envelope, slot string, files map[string][]byte) error {
	if len(chain) == 0 {
		return ErrMaterial
	}
	generation, err := bootstrap.MaterialGenerationPayload(chain[len(chain)-1])
	if err != nil {
		return err
	}
	held := 0
	for _, secret := range generation.Secrets {
		if secret.Slot != "" && secret.Slot != slot {
			continue
		}
		held++
		if content, ok := files[secret.TargetFile]; !ok || digest(content) != secret.SHA256 {
			return fmt.Errorf("%w: %s differs from its pin", ErrMaterial, secret.TargetFile)
		}
	}
	if len(files) != held {
		return fmt.Errorf("%w: a generation installs exactly the pinned files its slot holds", ErrMaterial)
	}
	return nil
}

// newestPins reads the newest generation's pins without verifying the
// chain's signatures: restart admission does that.
func newestPins(chain []trust.Envelope) (map[string]string, error) {
	if len(chain) == 0 {
		return nil, ErrMaterial
	}
	generation, err := bootstrap.MaterialGenerationPayload(chain[len(chain)-1])
	if err != nil {
		return nil, err
	}
	pins := map[string]string{}
	for _, secret := range generation.Secrets {
		pins[secret.TargetFile] = secret.SHA256
	}
	return pins, nil
}

// stagedNames lists the staging directory through a fresh descriptor: a
// dup shares the directory offset, so a second listing would come back empty.
func stagedNames(staging int) ([]string, error) {
	fd, err := unix.Openat(staging, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), generationStaging)
	defer file.Close()
	names, err := file.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	return names, nil
}

func removeStaging(dir int) error {
	if err := unix.Unlinkat(dir, generationStaging, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove generation staging: %w", err)
	}
	return unix.Fsync(dir)
}
