package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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
	rootFilenameRE = regexp.MustCompile(`^[0-9]{3}\.pem$`)
	identityNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
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

// LoadBakedInputs reads only the fixed production paths. Tests use the private
// bakedStore seam to exercise modes and symlink handling in temporary trees.
func LoadBakedInputs() (BakedInputs, error) {
	return bakedStore{directory: BakedDirectory, chainFile: RootChainFile, ownerUID: 0, ownerGID: 0}.load()
}

// LoadImageRoots reads only the existing fixed root-owned image root inventory.
// Finite qualification verifies its own signed purpose without a production identity.
func LoadImageRoots() (trust.Keyring, error) {
	return bakedStore{directory: BakedDirectory, ownerUID: 0, ownerGID: 0}.loadRoots()
}

// BakedInputsPresent is a routing check, not validation. Any object at the
// fixed path, including an invalid file or symlink, requires production
// admission and therefore fails through LoadBakedInputs. Only an absent path
// permits an explicitly configured lab runtime.
func BakedInputsPresent() (bool, error) {
	_, err := os.Lstat(BakedDirectory)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

type bakedStore struct {
	directory            string
	chainFile            string
	ownerUID             uint32
	ownerGID             uint32
	allowUnsafeAncestors bool
}

func (store bakedStore) load() (BakedInputs, error) {
	dir, err := store.openDirectory(store.directory)
	if err != nil {
		return BakedInputs{}, fmt.Errorf("open baked bootstrap directory: %w", err)
	}
	defer unix.Close(dir)
	identityWire, err := store.readFile(dir, identityFilename, maxIdentity)
	if err != nil {
		return BakedInputs{}, fmt.Errorf("read baked identity: %w", err)
	}
	identity, err := parseBakedIdentity(identityWire)
	if err != nil {
		return BakedInputs{}, err
	}
	anchorWire, err := store.readFile(dir, anchorFilename, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return BakedInputs{}, fmt.Errorf("read baked anchor: %w", err)
	}
	if _, err := trust.DecodeEnvelope(anchorWire); err != nil {
		return BakedInputs{}, fmt.Errorf("decode baked anchor: %w", err)
	}
	genesis, err := store.loadRoots()
	if err != nil {
		return BakedInputs{}, err
	}
	chain, err := readRootChain(store.chainFile)
	if err != nil {
		return BakedInputs{}, err
	}
	verified, err := trust.VerifyRootChain(genesis, identity.ChainIdentity(), chain)
	if err != nil {
		return BakedInputs{}, fmt.Errorf("verify adopted root chain: %w", err)
	}
	inputs := BakedInputs{Identity: identity, Genesis: genesis, Chain: chain, Roots: verified.Historical, AnchorWire: anchorWire}
	originWire, err := store.readFile(dir, OriginalStartupOriginFilename, maxOriginalStartupOriginBytes)
	if errors.Is(err, unix.ENOENT) {
		return inputs, nil
	}
	if err != nil {
		return BakedInputs{}, err
	}
	origin, err := parseOriginalStartupOrigin(originWire)
	if err != nil || !bytes.Equal(origin.AnchorWire, anchorWire) {
		return BakedInputs{}, ErrOriginalStartup
	}
	discoveryGenesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return BakedInputs{}, err
	}
	_, originRoots, err := origin.verifyAnchor(discoveryGenesis, time.Now().UTC())
	if err != nil {
		return BakedInputs{}, err
	}
	inputs.originalOrigin, inputs.originRoots = bytes.Clone(originWire), cloneOriginRoots(originRoots)
	return inputs, nil
}

// readRootChain reads the adopted chain; a controller that never adopted
// one has no file. The chain verifies from the baked genesis, so the file
// needs no ownership pin, but a damaged file fails closed rather than
// falling back to the genesis roots.
func readRootChain(path string) (trust.RootChain, error) {
	if path == "" {
		return trust.RootChain{Version: 1}, nil
	}
	// O_NONBLOCK keeps a FIFO from hanging the open; it is refused below.
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return trust.RootChain{Version: 1}, nil
	}
	if err != nil {
		return trust.RootChain{}, fmt.Errorf("open adopted root chain: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return trust.RootChain{}, fmt.Errorf("stat adopted root chain %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return trust.RootChain{}, fmt.Errorf("adopted root chain %s is not a regular file", path)
	}
	wire, err := io.ReadAll(io.LimitReader(file, trust.MaxRootChainBytes+1))
	if err != nil {
		return trust.RootChain{}, fmt.Errorf("read adopted root chain: %w", err)
	}
	return trust.DecodeRootChain(wire)
}

// parseBakedIdentity accepts only the canonical encoding, so the installed
// bytes and every digest over them stay unambiguous.
func parseBakedIdentity(wire []byte) (BakedIdentity, error) {
	var identity BakedIdentity
	if err := protocol.DecodeStrict(wire, &identity, maxIdentity); err != nil ||
		identity.SchemaVersion != 1 || !entityid.Valid(identity.DeploymentID) ||
		identity.Environment != "production" && identity.Environment != "canary" {
		return BakedIdentity{}, ErrBakedInputs
	}
	if _, err := identity.Cell.OCIRegion(); err != nil {
		return BakedIdentity{}, ErrBakedInputs
	}
	canonical, err := protocol.EncodeJSON(identity)
	if err != nil || !bytes.Equal(wire, canonical) {
		return BakedIdentity{}, ErrBakedInputs
	}
	return identity, nil
}

// loadRoots reads the image's trust roots, the only bootstrap authority the
// image itself carries.
func (store bakedStore) loadRoots() (trust.Keyring, error) {
	rootsDir, err := store.openDirectory(filepath.Join(store.directory, "trust-roots"))
	if err != nil {
		return nil, fmt.Errorf("open baked trust roots: %w", err)
	}
	file := os.NewFile(uintptr(rootsDir), "trust-roots")
	defer file.Close()
	names, err := file.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("read baked root entries: %w", err)
	}
	if len(names) == 0 || len(names) > MaxRootFiles {
		return nil, ErrBakedInputs
	}
	sort.Strings(names)
	keys := make([]ed25519.PublicKey, 0, len(names))
	total := 0
	for _, name := range names {
		if !rootFilenameRE.MatchString(name) || name == "000.pem" {
			return nil, ErrBakedInputs
		}
		wire, err := store.readFile(rootsDir, name, MaxRootBytes)
		if err != nil {
			return nil, fmt.Errorf("read baked root %s: %w", name, err)
		}
		total += len(wire)
		if total > MaxRootsTotal {
			return nil, ErrBakedInputs
		}
		block, rest := pem.Decode(wire)
		if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrBakedInputs
		}
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		key, ok := publicKey.(ed25519.PublicKey)
		if err != nil || !ok || len(key) != ed25519.PublicKeySize {
			return nil, ErrBakedInputs
		}
		keys = append(keys, key)
	}
	roots, err := trust.ParseKeyring(keys...)
	if err != nil {
		return nil, fmt.Errorf("assemble unambiguous root key IDs: %w", err)
	}
	return roots, nil
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

func (baked BakedInputs) verifyHistoricalOriginAnchor(ctx context.Context, acceptedAt time.Time) (bootstrap.HistoricalBootstrapAnchor, error) {
	if len(baked.originalOrigin) != 0 {
		if _, err := baked.originalAuthority(ctx, time.Now().UTC()); err != nil {
			return bootstrap.HistoricalBootstrapAnchor{}, err
		}
		origin, err := parseOriginalStartupOrigin(baked.originalOrigin)
		if err != nil {
			return bootstrap.HistoricalBootstrapAnchor{}, err
		}
		genesis, err := trust.DiscoveryGenesis()
		if err != nil {
			return bootstrap.HistoricalBootstrapAnchor{}, err
		}
		envelope, expected, roots, err := origin.anchorInputs(genesis)
		if err != nil {
			return bootstrap.HistoricalBootstrapAnchor{}, err
		}
		return bootstrap.VerifyHistoricalBootstrapAnchor(envelope, roots.Historical, expected, acceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
	}
	envelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return bootstrap.HistoricalBootstrapAnchor{}, err
	}
	return bootstrap.VerifyHistoricalBootstrapAnchor(envelope, baked.Roots, baked.Identity.AnchorExpectation(), acceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
}
