package bootstrapstart

import (
	"errors"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// generationStaging is the credential directory's staging subdirectory for
// a material generation being installed. Restart admission never sees it:
// FinishMaterialAdoption runs first.
const generationStaging = ".generation-staging"
const generationChainTemporary = ".material-generations.writing"

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
func (store MaterialStore) AdoptGeneration(target GenerationTarget, roots trust.Keyring, chainWire []byte, files map[string][]byte, config []byte, now time.Time) error {
	return store.adoptGeneration(target, roots, chainWire, files, config, now, nil)
}

func (store MaterialStore) adoptGeneration(target GenerationTarget, roots trust.Keyring, chainWire []byte, files map[string][]byte, config []byte,
	now time.Time, previous *identityMaterialPredecessors,
) error {
	chain, err := bootstrap.DecodeMaterialGenerationChain(chainWire)
	if err != nil {
		return err
	}
	verified, err := target.VerifyChain(chain, roots, now)
	if err != nil {
		return err
	}
	if err := stagedFilesMatch(chain, target.Slot, files); err != nil {
		return err
	}
	checked := maps.Clone(files)
	if config != nil {
		checked[GenerationConfigFile(target.Slot)] = config
	}
	if err := target.VerifyFiles(verified[len(verified)-1].Generation(), materialReader(checked), now); err != nil {
		return err
	}
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return fmt.Errorf("open service-owned credential directory: %w", err)
	}
	defer unix.Close(dir)
	if previous != nil {
		if err := store.verifyIdentityMaterialPredecessors(dir, chainWire, *previous); err != nil {
			return err
		}
	}
	installed, err := readUnpinned(dir, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
	if err == nil {
		if err := verifyInstalledGenerationChain(installed, chainWire, chain, previous); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
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
	if err := store.writeStaged(staging, generationChainTemporary, chainWire); err != nil {
		return fmt.Errorf("commit staged generation: %w", err)
	}
	if err := unix.Renameat2(staging, generationChainTemporary, staging, MaterialGenerationsFile, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err := unix.Fsync(staging); err != nil {
		return err
	}
	snapshot := maps.Clone(files)
	snapshot[MaterialGenerationsFile] = chainWire
	return store.rollForward(dir, staging, append(slices.Sorted(maps.Keys(files)), MaterialGenerationsFile), snapshot, previous)
}

// FinishMaterialAdoption completes a generation install interrupted after
// its commit, or discards an observed local stage interrupted before it.
// A committed invalid stage fails closed before any effect.
func (store MaterialStore) FinishMaterialAdoption(target GenerationTarget, roots trust.Keyring, configPath string, now time.Time) error {
	if !slices.Contains(target.Expected.ControllerSlots, target.Slot) || !markerDigestRE.MatchString(target.AcceptanceSHA256) ||
		validateAcceptedBroker(target.Broker) != nil || len(roots) == 0 {
		return ErrMaterial
	}
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return fmt.Errorf("open service-owned credential directory: %w", err)
	}
	defer unix.Close(dir)
	return store.finish(dir, target, roots, configPath, now, nil, nil)
}

func (store MaterialStore) finish(dir int, target GenerationTarget, roots trust.Keyring, configPath string, now time.Time,
	previous *identityMaterialPredecessors, replacement []bootstrap.VerifiedMaterialGeneration,
) error {
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
	if slices.Contains(names, verifiedMaterialTemporary) {
		var stat unix.Stat_t
		if err := unix.Fstatat(staging, verifiedMaterialTemporary, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 {
			return ErrMaterial
		}
		if !slices.Contains(names, MaterialGenerationsFile) {
			return ErrMaterial
		}
		names = slices.DeleteFunc(names, func(name string) bool { return name == verifiedMaterialTemporary })
	}
	if slices.Contains(names, MaterialGenerationsFile) {
		chainWire, err := store.readStaged(staging, MaterialGenerationsFile, "", maxGenerationChainBytes)
		if err != nil {
			return err
		}
		chain, err := bootstrap.DecodeMaterialGenerationChain(chainWire)
		if err != nil {
			return err
		}
		var verified []bootstrap.VerifiedMaterialGeneration
		if replacement == nil {
			verified, err = target.VerifyChain(chain, roots, now)
		} else {
			verified, err = target.VerifyAdoptedChain(chain, roots)
			if err == nil && (len(replacement) <= len(verified) || replacement[len(verified)-1].Fingerprint() != verified[len(verified)-1].Fingerprint()) {
				err = ErrMaterial
			}
		}
		if err != nil {
			return fmt.Errorf("verify committed generation stage: %w", err)
		}
		generation := verified[len(verified)-1].Generation()
		installed, err := readUnpinned(dir, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
		if err == nil {
			if err := verifyInstalledGenerationChain(installed, chainWire, chain, previous); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := store.stagedDigestsMatch(staging, generation, target.Slot, names); err != nil {
			return err
		}
		config, _, err := generationConfig(target, generation, configPath)
		if err != nil {
			return err
		}
		files, err := store.generationFiles(dir, staging, target, generation, config)
		if err != nil {
			return err
		}
		defer clearContents(files)
		// A fully verified current successor authorizes preserving this exact
		// predecessor floor; expired predecessor material never passes startup.
		if replacement == nil {
			if err := target.VerifyFiles(generation, materialReader(files), now); err != nil {
				return err
			}
		}
		files[MaterialGenerationsFile] = chainWire
		return store.rollForward(dir, staging, names, files, previous)
	}
	// Only exact observed local material names may be removed before commitment.
	allowed := bootstrap.MaterialGenerationFiles()
	cert, key := bootstrap.InterRegionTLSFiles(target.Slot)
	for _, name := range names {
		_, known := allowed[name]
		known = known || name == generationChainTemporary
		known = known || name == "interregion.jwt" || name == "interregion-ca.pem" || name == cert || name == key || name == target.Slot+".creds" ||
			name == bootstrap.LinkCredentialsFile
		if strings.HasPrefix(name, "leaf-") && strings.HasSuffix(name, ".creds") {
			peer := strings.TrimSuffix(strings.TrimPrefix(name, "leaf-"), ".creds")
			known = catalog.IsCell(strings.ToUpper(peer)) && peer == strings.ToLower(peer)
		}
		if !known {
			return fmt.Errorf("%w: uncommitted stage contains unrelated file %s", ErrMaterial, name)
		}
	}
	for _, name := range names {
		if err := unix.Unlinkat(staging, name, 0); err != nil {
			return err
		}
	}
	return removeStaging(dir)
}

// generationFiles reads a complete local set, using installed bytes for files
// already moved by an interrupted adoption. Other slots are never read.
func (store MaterialStore) generationFiles(dir, staging int, target GenerationTarget, generation bootstrap.MaterialGeneration, config []byte) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, ref := range generation.Secrets {
		if ref.Slot != "" && ref.Slot != target.Slot {
			continue
		}
		var wire []byte
		var err error
		if staging >= 0 {
			wire, err = store.readStaged(staging, ref.TargetFile, ref.SHA256, ref.MaxBytes)
		} else {
			err = os.ErrNotExist
		}
		if errors.Is(err, os.ErrNotExist) {
			wire, err = readMaterial(dir, ref.TargetFile, store.serviceUID, store.serviceGID, ref.SHA256, ref.MaxBytes)
		}
		if err != nil {
			clearContents(files)
			return nil, err
		}
		files[ref.TargetFile] = wire
	}
	if config != nil {
		files[GenerationConfigFile(target.Slot)] = config
	}
	return files, nil
}

// rollForward renames every staged file over its installed name, the chain
// last, then removes the staging directory.
const verifiedMaterialTemporary = ".verified-material"

func (store MaterialStore) rollForward(dir, staging int, names []string, snapshot map[string][]byte, previous *identityMaterialPredecessors) error {
	if previous != nil {
		if err := store.verifyIdentityMaterialPredecessors(dir, snapshot[MaterialGenerationsFile], *previous); err != nil {
			return err
		}
	}
	// New inodes inside a root-only directory prevent the spool owner from
	// changing verified bytes between validation and their privileged rename.
	if err := unix.Fchown(staging, os.Geteuid(), os.Getegid()); err != nil {
		return err
	}
	if err := unix.Fsync(staging); err != nil {
		return err
	}
	for _, name := range names {
		if name == MaterialGenerationsFile {
			continue
		}
		if err := store.replaceStaged(staging, name, snapshot[name]); err != nil {
			return err
		}
		if err := unix.Renameat(staging, name, dir, name); err != nil {
			return fmt.Errorf("install %s: %w", name, err)
		}
	}
	if slices.Contains(names, MaterialGenerationsFile) {
		if err := unix.Fsync(dir); err != nil {
			return err
		}
		if err := store.replaceStaged(staging, MaterialGenerationsFile, snapshot[MaterialGenerationsFile]); err != nil {
			return err
		}
		if err := store.keepChain(staging); err != nil {
			return fmt.Errorf("keep %s: %w", MaterialGenerationsFile, err)
		}
		if err := unix.Renameat(staging, MaterialGenerationsFile, dir, MaterialGenerationsFile); err != nil {
			return err
		}
	}
	if err := unix.Fsync(dir); err != nil {
		return err
	}
	return removeStaging(dir)
}

func (store MaterialStore) replaceStaged(staging int, name string, wire []byte) error {
	if len(wire) == 0 {
		return ErrMaterial
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(staging, verifiedMaterialTemporary, &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 {
			return ErrMaterial
		}
		if err := unix.Unlinkat(staging, verifiedMaterialTemporary, 0); err != nil {
			return err
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	fd, err := unix.Openat(staging, verifiedMaterialTemporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), verifiedMaterialTemporary)
	defer file.Close()
	if count, err := file.Write(wire); err != nil || count != len(wire) {
		return errors.Join(err, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := unix.Renameat(staging, verifiedMaterialTemporary, staging, name); err != nil {
		return err
	}
	if err := unix.Fchown(fd, int(store.serviceUID), int(store.serviceGID)); err != nil {
		return err
	}
	return unix.Fsync(staging)
}

func (store MaterialStore) readStaged(staging int, name, want string, maximum int64) ([]byte, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(staging, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	uid, gid := store.serviceUID, store.serviceGID
	if stat.Uid == uint32(os.Geteuid()) && stat.Gid == uint32(os.Getegid()) {
		uid, gid = stat.Uid, stat.Gid
	}
	if want == "" {
		return readUnpinned(staging, name, uid, gid, maximum)
	}
	return readMaterial(staging, name, uid, gid, want, maximum)
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
	if err := unix.Fstat(fd, &stat); err != nil || (stat.Uid != store.serviceUID || stat.Gid != store.serviceGID) && (stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid())) ||
		stat.Mode&0o7777 != 0o700 {
		unix.Close(fd)
		return -1, fmt.Errorf("%w: generation staging is not the service's own directory", ErrMaterial)
	}
	return fd, nil
}

func (store MaterialStore) writeStaged(staging int, name string, content []byte) error {
	if !markerNameRE.MatchString(name) && name != generationChainTemporary || len(content) == 0 ||
		int64(len(content)) > bootstrap.MaxSecretBytes && name != MaterialGenerationsFile && name != generationChainTemporary {
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
func (store MaterialStore) stagedDigestsMatch(staging int, generation bootstrap.MaterialGeneration, slot string, names []string) error {
	pins := map[string]string{}
	for _, ref := range generation.Secrets {
		if ref.Slot == "" || ref.Slot == slot {
			pins[ref.TargetFile] = ref.SHA256
		}
	}
	for _, name := range names {
		if name == MaterialGenerationsFile {
			continue
		}
		if pins[name] == "" {
			return fmt.Errorf("%w: staged %s is not pinned for this slot", ErrMaterial, name)
		}
		content, err := store.readStaged(staging, name, pins[name], bootstrap.MaxSecretBytes)
		clear(content)
		if err != nil {
			return err
		}
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
