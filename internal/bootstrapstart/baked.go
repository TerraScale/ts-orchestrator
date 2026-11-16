package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

const (
	BakedDirectory = "/etc/terrascale-orchestrator/bootstrap"
	// RootChainFile is the root chain this controller adopted from the
	// cell's replicated record. The baked roots are only its genesis.
	RootChainFile = "/var/lib/terrascale-orchestrator-controller/trust/root-chain.json"
	// MaxRootFiles, MaxRootBytes, and MaxRootsTotal bound the baked trust-root
	// inventory shared with the offline anchor verifier.
	MaxRootFiles  = 16
	MaxRootBytes  = 16 << 10
	MaxRootsTotal = 64 << 10
	maxIdentity   = 4096
)

var (
	ErrBakedInputs = errors.New("baked bootstrap inputs are invalid")
)

// BakedIdentity is root-owned image content. It is an independent local
// deployment expectation, never filled from IMDS or instance tags.
type BakedIdentity struct {
	SchemaVersion int        `json:"schemaVersion"`
	DeploymentID  string     `json:"deploymentId"`
	Environment   string     `json:"environment"`
	Cell          oci.Region `json:"cell"`
}

// ChainIdentity binds the cell's root chain to this deployment.
func (identity BakedIdentity) ChainIdentity() trust.ChainIdentity {
	return trust.ChainIdentity{DeploymentID: identity.DeploymentID,
		Cell: strings.ToLower(string(identity.Cell)), Environment: identity.Environment}
}

func (identity BakedIdentity) AnchorExpectation() bootstrap.BootstrapAnchorExpectation {
	return bootstrap.BootstrapAnchorExpectation{
		DeploymentID: identity.DeploymentID, Environment: identity.Environment, Cell: identity.Cell,
	}
}

// BakedInputs contains exact canonical public proof bytes and the root sets.
// Genesis is the image's baked set. Chain is the root chain the controller
// adopted, verified from Genesis, and Roots is every set on it (genesis and
// each rotated set), so records signed before and after a rotation verify
// without a rebuild. Removing a genesis root from the image still removes
// its authority; no stale key is recovered from a marker or manifest.
type BakedInputs struct {
	Identity       BakedIdentity
	Genesis        trust.Keyring
	Chain          trust.RootChain
	Roots          trust.Keyring
	AnchorWire     []byte
	originalOrigin []byte
	originRoots    trust.Keyring
}

type bakedStore struct {
	directory            string
	chainFile            string
	ownerUID             uint32
	ownerGID             uint32
	allowUnsafeAncestors bool
}

func (store bakedStore) openDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, ErrBakedInputs
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			unix.Close(fd)
			return -1, ErrBakedInputs
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil ||
			!store.allowUnsafeAncestors && (stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o755) {
			unix.Close(fd)
			return -1, ErrBakedInputs
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		stat.Uid != store.ownerUID || stat.Gid != store.ownerGID || stat.Mode&0o777 != 0o755 {
		unix.Close(fd)
		return -1, ErrBakedInputs
	}
	return fd, nil
}

func (store bakedStore) readFile(dir int, name string, maximum int64) ([]byte, error) {
	if strings.Contains(name, "/") || name == "" || maximum <= 0 {
		return nil, ErrBakedInputs
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != store.ownerUID || stat.Gid != store.ownerGID ||
		stat.Mode&0o7777 != 0o444 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maximum {
		return nil, ErrBakedInputs
	}
	wire, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(wire) == 0 || int64(len(wire)) > maximum {
		return nil, ErrBakedInputs
	}
	return wire, nil
}

// OriginRoots returns an independent copy of HOME current roots for an original
// installation; ordinary installations retain their regional trust lineage.
func (baked BakedInputs) OriginRoots() trust.Keyring {
	if len(baked.originalOrigin) != 0 {
		return cloneOriginRoots(baked.originRoots)
	}
	return cloneOriginRoots(baked.Roots)
}

func (baked BakedInputs) VerifyOriginAnchor(ctx context.Context, now time.Time) (bootstrap.VerifiedBootstrapAnchor, error) {
	if len(baked.originalOrigin) != 0 {
		authority, err := baked.originalAuthority(ctx, now)
		if err != nil {
			return bootstrap.VerifiedBootstrapAnchor{}, err
		}
		return authority.Template().OriginAnchor(), nil
	}
	envelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return bootstrap.VerifiedBootstrapAnchor{}, err
	}
	return bootstrap.VerifyBootstrapAnchor(envelope, baked.Roots, baked.Identity.AnchorExpectation(), now, bootstrap.BootstrapAnchorTrustPolicy())
}

func (baked BakedInputs) originalAuthority(ctx context.Context, now time.Time) (bootstrap.DerivedStartupAuthority, error) {
	origin, err := parseOriginalStartupOrigin(baked.originalOrigin)
	if err != nil || origin.Cell != baked.Identity.Cell || !bytes.Equal(origin.AnchorWire, baked.AnchorWire) {
		return bootstrap.DerivedStartupAuthority{}, ErrOriginalStartup
	}
	// The fixed production loader independently verifies the actual HOME
	// grant and exact signed regional registration, not local JSON claims.
	authority, err := LoadOriginalStartupAuthority(ctx, now)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	manifest := authority.Manifest()
	if manifest.DeploymentID != baked.Identity.DeploymentID || manifest.Cell != baked.Identity.Cell || manifest.Environment != baked.Identity.Environment ||
		!bytes.Equal(authority.Wire(), origin.AuthorityWire) || !bytes.Equal(authority.GrantWire(), origin.GrantWire) ||
		!bytes.Equal(authority.Template().OriginAnchor().Wire(), origin.AnchorWire) {
		return bootstrap.DerivedStartupAuthority{}, ErrOriginalStartup
	}
	return authority, nil
}
