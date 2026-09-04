package vmimage

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Cache stores complete image pairs under digest-derived directories. A
// directory is made visible only after both files and manifest.json have been
// fsynced and verified; an existing directory is never overwritten.
type Cache struct {
	Root        string
	Client      *http.Client
	QEMUImgPath string
	Runner      CommandRunner
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
	canonical, err := NewManifest(manifest)
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
	if err := os.MkdirAll(filepath.Dir(entry), 0o700); err != nil {
		return InstalledImage{}, fmt.Errorf("vmimage: create cache: %w", err)
	}
	if err := chmodDirectory(cache.Root, 0o700); err != nil {
		return InstalledImage{}, err
	}
	stage, err := createStaging(filepath.Dir(entry))
	if err != nil {
		return InstalledImage{}, err
	}
	defer os.RemoveAll(stage)

	kernelPath := filepath.Join(stage, canonical.Kernel.Name)
	rootfsPath := filepath.Join(stage, canonical.RootFS.Name)
	if err := cache.fetch(ctx, canonical.Kernel, kernelPath); err != nil {
		return InstalledImage{}, fmt.Errorf("vmimage: cache kernel: %w", err)
	}
	if err := cache.fetch(ctx, canonical.RootFS, rootfsPath); err != nil {
		return InstalledImage{}, fmt.Errorf("vmimage: cache rootfs: %w", err)
	}
	if err := VerifyFile(kernelPath, canonical.Kernel); err != nil {
		return InstalledImage{}, fmt.Errorf("vmimage: cached kernel: %w", err)
	}
	if err := VerifyFile(rootfsPath, canonical.RootFS); err != nil {
		return InstalledImage{}, fmt.Errorf("vmimage: cached rootfs: %w", err)
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
	if err := os.Rename(stage, entry); err != nil {
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
	return InstalledImage{Manifest: canonical, Dir: entry, Kernel: filepath.Join(entry, canonical.Kernel.Name), RootFS: filepath.Join(entry, canonical.RootFS.Name)}, nil
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
	canonical, err := NewManifest(image.Manifest)
	if err != nil {
		return err
	}
	if image.Dir == "" || !pathWithin(cache.Root, image.Dir) {
		return errors.New("vmimage: installed image directory is outside cache")
	}
	if err := verifyDirectory(image.Dir); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(image.Dir, "manifest.json"))
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
	if planData, planErr := os.ReadFile(filepath.Join(image.Dir, "build-plan.json")); planErr == nil {
		plan, decodeErr := DecodeBuildPlan(planData)
		if decodeErr != nil {
			return decodeErr
		}
		expectedPlan, planErr := NewBuildPlan(canonical, cache.Root)
		if planErr != nil {
			return planErr
		}
		expectedBytes, planErr := expectedPlan.CanonicalJSON()
		cachedBytes, cachedPlanErr := plan.CanonicalJSON()
		if planErr != nil || cachedPlanErr != nil || string(expectedBytes) != string(cachedBytes) {
			return errors.New("vmimage: cached build plan differs from requested manifest")
		}
	} else if !errors.Is(planErr, os.ErrNotExist) {
		return fmt.Errorf("vmimage: read cached build plan: %w", planErr)
	}
	if err := VerifyFile(filepath.Join(image.Dir, canonical.Kernel.Name), canonical.Kernel); err != nil {
		return err
	}
	return VerifyFile(filepath.Join(image.Dir, canonical.RootFS.Name), canonical.RootFS)
}

func (cache *Cache) existing(entry string, manifest GuestImageManifest) (InstalledImage, bool) {
	if _, err := os.Stat(entry); err != nil {
		return InstalledImage{}, false
	}
	image := InstalledImage{Manifest: manifest, Dir: entry, Kernel: filepath.Join(entry, manifest.Kernel.Name), RootFS: filepath.Join(entry, manifest.RootFS.Name)}
	if err := cache.VerifyInstalled(image); err != nil {
		return InstalledImage{}, false
	}
	return image, true
}

func (cache *Cache) fetch(ctx context.Context, artifact ArtifactManifest, target string) error {
	if artifact.Transform != nil {
		return cache.transform(ctx, artifact, target)
	}
	return cache.fetchDirect(ctx, artifact, target)
}

func (cache *Cache) fetchDirect(ctx context.Context, artifact ArtifactManifest, target string) error {
	parsed, err := url.Parse(artifact.Source)
	if err != nil {
		return errors.New("source is not a valid URL or path")
	}
	if parsed.Scheme == "" {
		return copyLocal(ctx, artifact.Source, target, artifact)
	}
	if parsed.Scheme == "file" {
		return copyLocal(ctx, parsed.Path, target, artifact)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("source URL scheme is not supported")
	}
	client := cache.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	} else {
		clone := *client
		client = &clone
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("source redirects are not allowed")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.Source, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("source answered HTTP %d", response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != artifact.Size {
		return errors.New("source content length does not match manifest")
	}
	return copyStream(ctx, response.Body, target, artifact)
}

func (cache *Cache) transform(ctx context.Context, artifact ArtifactManifest, target string) error {
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
	qemuImg := cache.QEMUImgPath
	if qemuImg == "" {
		var err error
		qemuImg, err = exec.LookPath("qemu-img")
		if err != nil {
			return errors.New("qemu-img is required to convert the pinned QCOW2 image")
		}
	}
	if !filepath.IsAbs(qemuImg) {
		return errors.New("qemu-img path must be absolute")
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
	if err := VerifyFile(target, artifact); err != nil {
		return fmt.Errorf("verify transformed rootfs: %w", err)
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

func copyLocal(ctx context.Context, source, target string, artifact ArtifactManifest) error {
	if source == "" {
		return errors.New("local source path is empty")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("local source must be a regular non-symlink file")
	}
	if uint32(info.Mode().Perm()) != artifact.expectedMode() {
		return fmt.Errorf("local source mode %04o does not match manifest mode %04o", info.Mode().Perm(), artifact.expectedMode())
	}
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()
	return copyStream(ctx, file, target, artifact)
}

func copyStream(ctx context.Context, reader io.Reader, target string, artifact ArtifactManifest) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(artifact.expectedMode()))
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(target)
		}
	}()
	limited := io.LimitReader(reader, artifact.Size+1)
	written, err := io.Copy(file, contextReader{ctx: ctx, reader: limited})
	if err != nil {
		return err
	}
	if written != artifact.Size {
		return fmt.Errorf("source size %d does not match manifest size %d", written, artifact.Size)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
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
	return path, nil
}

func writePrivate(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
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

func chmodDirectory(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("vmimage: chmod cache: %w", err)
	}
	return nil
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
