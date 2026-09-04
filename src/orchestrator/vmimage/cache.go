package vmimage

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Cache stores complete image pairs under digest-derived directories. A
// directory is made visible only after both files and manifest.json have been
// fsynced and verified; an existing directory is never overwritten.
type Cache struct {
	Root        string
	Client      *http.Client
	Downloader  Downloader
	QEMUImgPath string
	Runner      CommandRunner

	RootFSPreparer RootFSPreparer
	DebugFSPath    string
	E2FSCKPath     string
	OutputRunner   OutputCommandRunner
}

// CommandRunner is the typed process boundary used only for qemu-img QCOW2
// conversion. Implementations receive an executable and argv, never a shell
// command string.
type CommandRunner interface {
	Run(context.Context, string, ...string) error
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, executable string, args ...string) error {
	return exec.CommandContext(ctx, executable, args...).Run()
}

// InstalledImage identifies one immutable cache entry.
type InstalledImage struct {
	Manifest GuestImageManifest
	Dir      string
	Kernel   string
	RootFS   string
	Receipt  string
}

// NewCache creates a cache handle. It does not create or mutate the root;
// Install performs that operation after manifest validation.
func NewCache(root string) (*Cache, error) {
	if root == "" || filepath.IsAbs(root) == false || strings.ContainsRune(root, 0) {
		return nil, errors.New("vmimage: cache root must be an absolute path")
	}
	return &Cache{Root: filepath.Clean(root)}, nil
}

// Install validates and atomically caches an image pair from local paths or
// bounded HTTP(S) responses. HTTP redirects are rejected so a verified source
// cannot silently change origin. Context cancellation removes staging bytes.
func (cache *Cache) Install(ctx context.Context, manifest GuestImageManifest) (InstalledImage, error) {
	if cache == nil {
		return InstalledImage{}, errors.New("vmimage: cache is nil")
	}
	if ctx == nil {
		return InstalledImage{}, errors.New("vmimage: context is nil")
	}
	canonical, err := NewPinnedManifest(manifest)
	if err != nil {
		return InstalledImage{}, err
	}
	pairDigest, err := canonical.Digest()
	if err != nil {
		return InstalledImage{}, err
	}
	entry := filepath.Join(cache.Root, string(canonical.Architecture), canonical.Version, pairDigest)
	if installed, ok := cache.existing(entry, canonical); ok {
		return installed, nil
	}
	if err := ensurePrivateTree(cache.Root, filepath.Dir(entry)); err != nil {
		return InstalledImage{}, fmt.Errorf("vmimage: create cache: %w", err)
	}
	stage, err := createStaging(filepath.Dir(entry))
	if err != nil {
		return InstalledImage{}, err
	}
	defer os.RemoveAll(stage)

	kernelPath := filepath.Join(stage, canonical.Kernel.Name)
	rootfsPath := filepath.Join(stage, canonical.RootFS.Name)
	if err := cache.fetch(ctx, canonical.Kernel, kernelPath, canonical.UbuntuRelease); err != nil {
		return InstalledImage{}, fmt.Errorf("vmimage: cache kernel: %w", err)
	}
	if err := cache.fetch(ctx, canonical.RootFS, rootfsPath, canonical.UbuntuRelease); err != nil {
		return InstalledImage{}, fmt.Errorf("vmimage: cache rootfs: %w", err)
	}
	preparer := cache.RootFSPreparer
	if preparer == nil {
		preparer = Ext4Preparer{DebugFSPath: cache.DebugFSPath, E2FSCKPath: cache.E2FSCKPath, Runner: cache.OutputRunner}
	}
	inspection, err := preparer.Prepare(ctx, rootfsPath, canonical.UbuntuRelease)
	if err != nil {
		return InstalledImage{}, fmt.Errorf("vmimage: prepare extracted Ubuntu rootfs: %w", err)
	}
	if err := VerifyFile(kernelPath, canonical.Kernel); err != nil {
		return InstalledImage{}, fmt.Errorf("vmimage: cached kernel: %w", err)
	}
	if err := VerifyFile(rootfsPath, canonical.RootFS); err != nil {
		return InstalledImage{}, fmt.Errorf("vmimage: cached rootfs: %w", err)
	}
	receipt, err := NewPreparationReceipt(canonical, inspection)
	if err != nil {
		return InstalledImage{}, err
	}
	receiptBytes, err := receipt.CanonicalJSON(canonical)
	if err != nil {
		return InstalledImage{}, err
	}
	if err := writePrivate(filepath.Join(stage, "image-receipt.json"), receiptBytes); err != nil {
		return InstalledImage{}, err
	}
	if err := syncFile(filepath.Join(stage, "image-receipt.json")); err != nil {
		return InstalledImage{}, err
	}
	manifestPath := filepath.Join(stage, "manifest.json")
	manifestBytes, err := canonical.CanonicalJSON()
	if err != nil {
		return InstalledImage{}, err
	}
	if err := writePrivate(manifestPath, manifestBytes); err != nil {
		return InstalledImage{}, err
	}
	if err := syncFile(manifestPath); err != nil {
		return InstalledImage{}, err
	}
	if err := syncDir(stage); err != nil {
		return InstalledImage{}, err
	}
	plan, err := NewBuildPlan(canonical, cache.Root)
	if err != nil {
		return InstalledImage{}, err
	}
	planBytes, err := plan.CanonicalJSON()
	if err != nil {
		return InstalledImage{}, err
	}
	if err := writePrivate(filepath.Join(stage, "build-plan.json"), planBytes); err != nil {
		return InstalledImage{}, err
	}
	if err := syncFile(filepath.Join(stage, "build-plan.json")); err != nil {
		return InstalledImage{}, err
	}
	if err := syncDir(stage); err != nil {
		return InstalledImage{}, err
	}
	if err := os.Chmod(stage, 0o700); err != nil {
		return InstalledImage{}, err
	}
	if err := ctx.Err(); err != nil {
		return InstalledImage{}, err
	}
	if err := publishDirectory(stage, entry); err != nil {
		// Another installer may have won the compare-and-create race. Only
		// accept it when the immutable entry verifies completely.
		if installed, ok := cache.existing(entry, canonical); ok {
			return installed, nil
		}
		return InstalledImage{}, fmt.Errorf("vmimage: publish cache entry: %w", err)
	}
	if err := syncDir(filepath.Dir(entry)); err != nil {
		return InstalledImage{}, fmt.Errorf("vmimage: sync cache parent: %w", err)
	}
	return InstalledImage{Manifest: canonical, Dir: entry, Kernel: filepath.Join(entry, canonical.Kernel.Name), RootFS: filepath.Join(entry, canonical.RootFS.Name), Receipt: filepath.Join(entry, "image-receipt.json")}, nil
}

// Install is a package-level convenience for callers that do not need a
// reusable cache client.
func Install(ctx context.Context, root string, manifest GuestImageManifest) (InstalledImage, error) {
	cache, err := NewCache(root)
	if err != nil {
		return InstalledImage{}, err
	}
	return cache.Install(ctx, manifest)
}

// Plan returns the exact deterministic work description without creating the
// cache root or reading either artifact. It is useful for CI dry runs and for
// showing what vm-image will verify before privileged qualification begins.
func (cache *Cache) Plan(manifest GuestImageManifest) (BuildPlan, error) {
	if cache == nil {
		return BuildPlan{}, errors.New("vmimage: cache is nil")
	}
	return NewBuildPlan(manifest, cache.Root)
}

// VerifyInstalled checks every file and the on-disk manifest in one cache
// entry. It is useful after a process restart and before giving a path to a
// VMM.
func (cache *Cache) VerifyInstalled(image InstalledImage) error {
	if cache == nil {
		return errors.New("vmimage: cache is nil")
	}
	canonical, err := NewPinnedManifest(image.Manifest)
	if err != nil {
		return err
	}
	plan, err := NewBuildPlan(canonical, cache.Root)
	if err != nil {
		return err
	}
	expectedKernel := filepath.Join(plan.CacheEntry, canonical.Kernel.Name)
	expectedRootFS := filepath.Join(plan.CacheEntry, canonical.RootFS.Name)
	expectedReceipt := filepath.Join(plan.CacheEntry, "image-receipt.json")
	if image.Dir != plan.CacheEntry || image.Kernel != expectedKernel || image.RootFS != expectedRootFS || image.Receipt != expectedReceipt {
		return errors.New("vmimage: installed image paths do not match their derived cache location")
	}
	if err := rejectSymlinkAncestors(image.Dir); err != nil {
		return err
	}
	if err := verifyDirectory(image.Dir); err != nil {
		return err
	}
	if err := verifyExactDirectoryEntries(image.Dir, canonical.Kernel.Name, canonical.RootFS.Name, "manifest.json", "build-plan.json", "image-receipt.json"); err != nil {
		return err
	}
	data, err := readRegularFile(filepath.Join(image.Dir, "manifest.json"), 0o600, maxManifestBytes)
	if err != nil {
		return fmt.Errorf("vmimage: read cached manifest: %w", err)
	}
	cached, err := DecodeManifest(data)
	if err != nil {
		return err
	}
	left, _ := canonical.CanonicalJSON()
	right, _ := cached.CanonicalJSON()
	if string(left) != string(right) {
		return errors.New("vmimage: cached manifest differs from requested manifest")
	}
	planData, err := readRegularFile(filepath.Join(image.Dir, "build-plan.json"), 0o600, maxBuildPlanBytes)
	if err != nil {
		return fmt.Errorf("vmimage: read cached build plan: %w", err)
	}
	cachedPlan, err := DecodeBuildPlan(planData)
	if err != nil {
		return err
	}
	expectedBytes, err := plan.CanonicalJSON()
	if err != nil {
		return err
	}
	cachedBytes, err := cachedPlan.CanonicalJSON()
	if err != nil || string(expectedBytes) != string(cachedBytes) {
		return errors.New("vmimage: cached build plan differs from requested manifest")
	}
	if err := VerifyFile(filepath.Join(image.Dir, canonical.Kernel.Name), canonical.Kernel); err != nil {
		return err
	}
	if err := VerifyFile(filepath.Join(image.Dir, canonical.RootFS.Name), canonical.RootFS); err != nil {
		return err
	}
	receiptData, err := readRegularFile(expectedReceipt, 0o600, maxPreparationReceiptBytes)
	if err != nil {
		return fmt.Errorf("vmimage: read preparation receipt: %w", err)
	}
	_, err = DecodePreparationReceipt(receiptData, canonical)
	return err
}

func (cache *Cache) existing(entry string, manifest GuestImageManifest) (InstalledImage, bool) {
	if _, err := os.Stat(entry); err != nil {
		return InstalledImage{}, false
	}
	image := InstalledImage{Manifest: manifest, Dir: entry, Kernel: filepath.Join(entry, manifest.Kernel.Name), RootFS: filepath.Join(entry, manifest.RootFS.Name), Receipt: filepath.Join(entry, "image-receipt.json")}
	if err := cache.VerifyInstalled(image); err != nil {
		return InstalledImage{}, false
	}
	return image, true
}

func (cache *Cache) fetch(ctx context.Context, artifact ArtifactManifest, target, ubuntuRelease string) error {
	if artifact.Transform != nil {
		return cache.transform(ctx, artifact, target, ubuntuRelease)
	}
	return cache.fetchDirect(ctx, artifact, target)
}

func (cache *Cache) fetchDirect(ctx context.Context, artifact ArtifactManifest, target string) error {
	downloader := cache.Downloader
	if downloader == nil {
		downloader = httpDownloader{client: cache.Client}
	}
	return downloadPinned(ctx, downloader, artifact.Source, target, artifact.digest(), artifact.Size, os.FileMode(artifact.expectedMode()))
}

func (cache *Cache) transform(ctx context.Context, artifact ArtifactManifest, target, ubuntuRelease string) error {
	input := artifact
	input.Name += ".input"
	input.SHA256 = artifact.InputSHA256
	input.Size = artifact.InputSize
	input.Mode = 0o600
	input.InputSHA256 = ""
	input.InputSize = 0
	input.Transform = nil
	inputPath := target + ".input"
	rawPath := target + ".raw"
	defer os.Remove(inputPath)
	defer os.Remove(rawPath)
	if err := cache.fetchDirect(ctx, input, inputPath); err != nil {
		return fmt.Errorf("fetch transformation input: %w", err)
	}
	if err := VerifyFile(inputPath, input); err != nil {
		return fmt.Errorf("verify transformation input: %w", err)
	}
	qemuImg, err := resolveExecutable(cache.QEMUImgPath, "qemu-img")
	if err != nil {
		return err
	}
	runner := cache.Runner
	if runner == nil {
		runner = execRunner{}
	}
	if err := runner.Run(ctx, qemuImg, "convert", "-f", "qcow2", "-O", "raw", inputPath, rawPath); err != nil {
		return fmt.Errorf("convert pinned QCOW2 input: %w", err)
	}
	if err := verifyRegular(rawPath); err != nil {
		return fmt.Errorf("verify converted raw disk: %w", err)
	}
	if err := os.Chmod(rawPath, 0o600); err != nil {
		return fmt.Errorf("secure converted raw disk: %w", err)
	}
	if err := VerifyFile(inputPath, input); err != nil {
		return fmt.Errorf("reverify transformation input: %w", err)
	}
	transform := artifact.Transform
	if transform.StartSector > (1<<63-1)/transform.SectorSize {
		return errors.New("root partition offset overflows")
	}
	offset := transform.StartSector * transform.SectorSize
	if offset < 0 || offset > maxArtifactSize || offset > (1<<63-1)-artifact.Size {
		return errors.New("root partition offset overflows")
	}
	if err := copySparseSection(ctx, rawPath, target, offset, artifact.Size, os.FileMode(artifact.expectedMode())); err != nil {
		return fmt.Errorf("extract root partition: %w", err)
	}
	return nil
}

func verifyRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a regular non-symlink file")
	}
	return nil
}

func copySparseSection(ctx context.Context, source, target string, offset, size int64, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if offset < 0 || size <= 0 || offset > info.Size() || size > info.Size()-offset {
		return errors.New("root partition lies outside converted raw disk")
	}
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(target)
		}
	}()
	if err := output.Chmod(mode.Perm()); err != nil {
		return err
	}
	section := io.NewSectionReader(input, offset, size)
	buffer := make([]byte, 1<<20)
	var copied int64
	for copied < size {
		if err := ctx.Err(); err != nil {
			return err
		}
		want := int64(len(buffer))
		if remaining := size - copied; remaining < want {
			want = remaining
		}
		chunk := buffer[:int(want)]
		if _, err := io.ReadFull(section, chunk); err != nil {
			return err
		}
		if allZero(chunk) {
			if _, err := output.Seek(want, io.SeekCurrent); err != nil {
				return err
			}
		} else if _, err := output.Write(chunk); err != nil {
			return err
		}
		copied += want
	}
	if err := output.Truncate(size); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(p []byte) (int, error) {
	select {
	case <-reader.ctx.Done():
		return 0, reader.ctx.Err()
	default:
		return reader.reader.Read(p)
	}
}

func createStaging(parent string) (string, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	name := fmt.Sprintf(".staging-%x", random)
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func writePrivate(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func syncFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func syncDir(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func verifyDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("vmimage: cache entry must be a non-symlink directory")
	}
	if info.Mode().Perm() != 0o700 {
		return errors.New("vmimage: cache entry directory has unsafe mode")
	}
	return nil
}

func pathWithin(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
