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
	"path/filepath"
	"strings"
	"time"
)

// Cache stores complete image pairs under digest-derived directories. A
// directory is made visible only after both files and manifest.json have been
// fsynced and verified; an existing directory is never overwritten.
type Cache struct {
	Root   string
	Client *http.Client
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
