package bootstrapstart

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"golang.org/x/sys/unix"
)

const (
	MaterialDirectory = bootstrap.MaterialDirectory
	StagingDirectory  = "/run/terrascale-orchestrator-bootstrap"
)

var ErrMaterial = errors.New("controller credential material is invalid")

type SecretMaterializer interface {
	MaterializeCurrent(context.Context, bootstrap.StartupAuthority, bootstrap.VerifiedReceipt,
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
	// chainCopy is where an adopted chain is kept durably (GenerationChainCopy).
	chainCopy string
}

func NewMaterialStore(vault SecretMaterializer, serviceUID, serviceGID uint32) (MaterialStore, error) {
	if serviceUID == 0 || serviceGID == 0 {
		return MaterialStore{}, ErrMaterial
	}
	return MaterialStore{
		vault: vault, installedDirectory: MaterialDirectory, stagingDirectory: StagingDirectory,
		serviceUID: serviceUID, serviceGID: serviceGID, chainCopy: GenerationChainCopy,
	}, nil
}

func readMaterial(dir int, name string, uid, gid uint32, want string, maximum int64) ([]byte, error) {
	if !markerNameRE.MatchString(name) || !markerDigestRE.MatchString(want) || maximum <= 0 || maximum > bootstrap.MaxSecretBytes {
		return nil, ErrMaterial
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
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
