package bootstrapstart

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

const (
	MaterialDirectory = "/var/lib/terrascale-orchestrator-secrets"
	StagingDirectory  = "/run/terrascale-orchestrator-bootstrap"
)

var ErrMaterial = errors.New("controller credential material is invalid")

type SecretMaterializer interface {
	MaterializeCurrent(context.Context, bootstrap.VerifiedManifest, bootstrap.VerifiedReceipt,
		bootstrap.SecretReference, string, func(time.Time) error) error
}

// MaterialStore transfers Vault-verified material from a root-only staging
// directory into one fixed service-owned credential directory. The configured
// service UID/GID must be resolved from the dedicated system user by the caller.
// No file is made group- or world-readable.
type MaterialStore struct {
	vault                SecretMaterializer
	installedDirectory   string
	stagingDirectory     string
	serviceUID           uint32
	serviceGID           uint32
	allowUnsafeAncestors bool
}

func NewMaterialStore(vault SecretMaterializer, serviceUID, serviceGID uint32) (MaterialStore, error) {
	if serviceUID == 0 || serviceGID == 0 {
		return MaterialStore{}, ErrMaterial
	}
	return MaterialStore{
		vault: vault, installedDirectory: MaterialDirectory, stagingDirectory: StagingDirectory,
		serviceUID: serviceUID, serviceGID: serviceGID,
	}, nil
}

func (store MaterialStore) PrepareInitial(ctx context.Context, manifest bootstrap.VerifiedManifest,
	receipt bootstrap.VerifiedReceipt, expected map[string]string, verifyCurrent CurrentProofVerifier,
) error {
	if store.vault == nil || verifyCurrent == nil ||
		!sameMaterials(expectedMaterials(manifest.Manifest(), receipt.Slot()), expected) {
		return ErrMaterial
	}
	staging, err := openMaterialDirectory(store.stagingDirectory, 0, 0, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return fmt.Errorf("open root-only credential staging: %w", err)
	}
	defer unix.Close(staging)
	installed, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return fmt.Errorf("open service-owned credential directory: %w", err)
	}
	defer unix.Close(installed)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	child := ".bootstrap-" + hex.EncodeToString(nonce[:])
	if err := unix.Mkdirat(staging, child, 0o700); err != nil {
		return fmt.Errorf("create root-only staging child: %w", err)
	}
	stagePath := filepath.Join(store.stagingDirectory, child)
	defer os.RemoveAll(stagePath)
	stageFD, err := unix.Openat(staging, child, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(stageFD)
	for _, reference := range manifest.Manifest().Secrets {
		want, selected := expected[reference.TargetFile]
		if !selected {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyCurrent(time.Now()); err != nil {
			return fmt.Errorf("verify current proof before Vault read: %w", err)
		}
		if err := store.vault.MaterializeCurrent(ctx, manifest, receipt, reference, stagePath, verifyCurrent); err != nil {
			return fmt.Errorf("materialize exact Vault secret %s: %w", reference.TargetFile, err)
		}
		content, err := readMaterial(stageFD, reference.TargetFile, 0, 0, want, reference.MaxBytes)
		if err != nil {
			return fmt.Errorf("verify staged secret %s: %w", reference.TargetFile, err)
		}
		if err := verifyCurrent(time.Now()); err != nil {
			clear(content)
			return fmt.Errorf("verify current proof before service install: %w", err)
		}
		if err := store.installMaterial(installed, reference.TargetFile, content, want, reference.MaxBytes); err != nil {
			clear(content)
			return fmt.Errorf("install service-owned secret %s: %w", reference.TargetFile, err)
		}
		clear(content)
	}
	return store.verifyInstalled(ctx, installed, expected)
}

// RestartPins reads the install's adopted material generation, if any, from
// the credential directory and returns what the directory must hold.
func (store MaterialStore) RestartPins(manifest bootstrap.HistoricalManifest, roots trust.Keyring, privateIP string,
) (MaterialPins, error) {
	installed, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return MaterialPins{}, fmt.Errorf("open service-owned credential directory: %w", err)
	}
	defer unix.Close(installed)
	return restartPins(installed, store.serviceUID, store.serviceGID, manifest.Manifest(), roots, privateIP)
}

func (store MaterialStore) VerifyRestart(ctx context.Context, manifest bootstrap.HistoricalManifest,
	pins MaterialPins,
) error {
	if pins.Generation == nil && !sameMaterials(expectedMaterials(manifest.Manifest(), manifest.Manifest().Slot), pins.Digests) {
		return ErrMaterial
	}
	installed, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return fmt.Errorf("open service-owned credential directory: %w", err)
	}
	defer unix.Close(installed)
	if err := store.verifyInstalled(ctx, installed, pins.Digests); err != nil {
		return err
	}
	return pins.verifyGeneration(installed, store.serviceUID, store.serviceGID, time.Now())
}

func (store MaterialStore) verifyInstalled(ctx context.Context, dir int, expected map[string]string) error {
	for name, want := range expected {
		if err := ctx.Err(); err != nil {
			return err
		}
		content, err := readMaterial(dir, name, store.serviceUID, store.serviceGID, want, bootstrap.MaxSecretBytes)
		if err != nil {
			return fmt.Errorf("verify installed secret %s: %w", name, err)
		}
		clear(content)
	}
	return nil
}

func sameMaterials(left, right map[string]string) bool {
	if len(left) == 0 || len(left) != len(right) {
		return false
	}
	for name, digest := range left {
		if right[name] != digest {
			return false
		}
	}
	return true
}

func (store MaterialStore) installMaterial(dir int, name string, content []byte, want string, maximum int64) error {
	if existing, err := readMaterial(dir, name, store.serviceUID, store.serviceGID, want, maximum); err == nil {
		clear(existing)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := ".secret-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(dir, temporary, 0)
	file := os.NewFile(uintptr(fd), temporary)
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = file.Close()
		return err
	}
	if err := unix.Fchown(fd, int(store.serviceUID), int(store.serviceGID)); err != nil {
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
	if err := unix.Renameat2(dir, temporary, dir, name, unix.RENAME_NOREPLACE); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
	}
	if err := unix.Fsync(dir); err != nil {
		return err
	}
	verified, err := readMaterial(dir, name, store.serviceUID, store.serviceGID, want, maximum)
	clear(verified)
	return err
}

func readMaterial(dir int, name string, uid, gid uint32, want string, maximum int64) ([]byte, error) {
	if !markerNameRE.MatchString(name) || !markerDigestRE.MatchString(want) || maximum <= 0 || maximum > bootstrap.MaxSecretBytes {
		return nil, ErrMaterial
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != uid || stat.Gid != gid || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 ||
		stat.Size <= 0 || stat.Size > maximum {
		return nil, ErrMaterial
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(content) == 0 || int64(len(content)) > maximum || digest(content) != want {
		clear(content)
		return nil, ErrMaterial
	}
	return content, nil
}

func openMaterialDirectory(path string, uid, gid uint32, mode uint32, allowUnsafeAncestors bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, ErrMaterial
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			unix.Close(fd)
			return -1, ErrMaterial
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil ||
			index < len(components)-1 && !allowUnsafeAncestors && (stat.Uid != 0 || stat.Mode&0o022 != 0) {
			unix.Close(fd)
			return -1, ErrMaterial
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o777 != mode {
		unix.Close(fd)
		return -1, ErrMaterial
	}
	return fd, nil
}

var _ MaterialChecker = MaterialStore{}
