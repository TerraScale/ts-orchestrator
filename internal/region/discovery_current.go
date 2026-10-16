package region

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const foundationFloorLimit = 2*trust.MaxRootChainBytes + 4096

// DiscoverCurrentFoundation discovers current authority from the independently
// embedded genesis and durably adopts its lineage before exposing a resolver.
func DiscoverCurrentFoundation(ctx context.Context, factory *ociclient.Factory) (FoundationResolver, error) {
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return FoundationResolver{}, err
	}
	client, tenancy, err := foundationHomeClient(factory)
	if err != nil {
		return FoundationResolver{}, err
	}
	return discoverCurrentFoundation(ctx, client, tenancy, genesis)
}

type foundationFloor struct {
	Version        int    `json:"version"`
	TenancyID      string `json:"tenancyId"`
	InstallationID string `json:"installationId"`
	DeploymentID   string `json:"deploymentId"`
	ClusterID      string `json:"clusterId"`
	ChainWire      []byte `json:"chainWire"`
	Generation     uint64 `json:"generation"`
	GrantSHA256    string `json:"grantSha256"`
	AnchorSHA256   string `json:"anchorSha256"`
}

func discoverCurrentFoundation(ctx context.Context, client foundationDiscoveryObjects, tenancy string, genesis trust.Keyring) (FoundationResolver, error) {
	if len(genesis) == 0 || tenancy == "" {
		return FoundationResolver{}, errors.New("current foundation requires independent genesis and authenticated tenancy")
	}
	directory, err := openFoundationFloorDirectory()
	if err != nil {
		return FoundationResolver{}, fmt.Errorf("open foundation trust floor: %w", err)
	}
	defer directory.Close()
	digest := sha256.Sum256([]byte(tenancy))
	name := hex.EncodeToString(digest[:]) + ".json"
	lock, err := openFoundationFloorFile(int(directory.Fd()), name+".lock", unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return FoundationResolver{}, err
	}
	defer lock.Close()
	for {
		if err := ctx.Err(); err != nil {
			return FoundationResolver{}, err
		}
		err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return FoundationResolver{}, err
		}
		select {
		case <-ctx.Done():
			return FoundationResolver{}, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	previous, found, err := readFoundationFloor(int(directory.Fd()), name, tenancy, genesis)
	if err != nil {
		return FoundationResolver{}, err
	}
	namespace, err := discoveryNamespace(ctx, client, tenancy)
	if err != nil {
		return FoundationResolver{}, errors.Join(err, ctx.Err())
	}
	anchorWire, err := readDiscoveryObject(ctx, client, namespace, foundationDiscoveryObject, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return FoundationResolver{}, fmt.Errorf("%w: read current home anchor: %w", ErrFoundationDiscoveryPending, err)
	}
	envelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		return FoundationResolver{}, err
	}
	// The unverified deployment selects only the cryptographic scope. Every
	// identity and location is checked after verification with current roots.
	identity := foundationChainIdentity(envelope.Scope.DeploymentID)
	chainWire, err := readDiscoveryObject(ctx, client, namespace, foundationRootChainObject, trust.MaxRootChainBytes)
	if err != nil {
		return FoundationResolver{}, fmt.Errorf("%w: read current root chain: %w", ErrFoundationDiscoveryPending, err)
	}
	chain, err := trust.DecodeRootChain(chainWire)
	if err != nil {
		return FoundationResolver{}, err
	}
	verified, err := trust.VerifyRootChain(genesis, identity, chain)
	if err != nil {
		return FoundationResolver{}, err
	}
	adopted := trust.RootChain{Version: 1}
	if found {
		adopted, err = trust.DecodeRootChain(previous.ChainWire)
		if err != nil {
			return FoundationResolver{}, err
		}
		if identity.DeploymentID != previous.DeploymentID || !chain.Extends(adopted) {
			return FoundationResolver{}, errors.New("current foundation root chain forks or rolls back adopted deployment")
		}
	}
	// Historical transitions remain valid for an offline or fresh client;
	// current authority must be signed by the terminal roots below.
	anchor, err := verifyDiscoveryAnchor(anchorWire, verified.Current, tenancy, namespace)
	if err != nil {
		return FoundationResolver{}, err
	}
	reader, err := NewSignedFootprint(client, anchor, verified.Current, tenancy)
	if err != nil {
		return FoundationResolver{}, err
	}
	grantWire, err := reader.readGrant(ctx)
	if err != nil {
		return FoundationResolver{}, err
	}
	if _, _, err := reader.verifyGrant(grantWire); err != nil {
		return FoundationResolver{}, err
	}
	home := reader.home
	grantDigest := sha256.Sum256(grantWire)
	anchorDigest := sha256.Sum256(envelope.Payload)
	next := foundationFloor{Version: 1, TenancyID: tenancy, InstallationID: home.InstallationID, DeploymentID: home.DeploymentID,
		ClusterID: home.ClusterID, ChainWire: chainWire, Generation: home.GrantGeneration, GrantSHA256: hex.EncodeToString(grantDigest[:]), AnchorSHA256: hex.EncodeToString(anchorDigest[:])}
	if found && (next.InstallationID != previous.InstallationID || next.DeploymentID != previous.DeploymentID || next.ClusterID != previous.ClusterID ||
		next.Generation < previous.Generation || next.Generation == previous.Generation && (next.GrantSHA256 != previous.GrantSHA256 ||
		len(chain.Rotations) == len(adopted.Rotations) && next.AnchorSHA256 != previous.AnchorSHA256)) {
		return FoundationResolver{}, errors.New("current foundation switches identity, rolls back grant or changes an adopted generation")
	}
	store, err := NewObjectFoundationStore(client, namespace, foundationDiscoveryBucket)
	if err != nil {
		return FoundationResolver{}, err
	}
	if err := ctx.Err(); err != nil {
		return FoundationResolver{}, err
	}
	if err := writeFoundationFloor(directory, name, next); err != nil {
		return FoundationResolver{}, fmt.Errorf("persist foundation trust floor: %w", err)
	}
	return FoundationResolver{Footprint: reader, Store: store}, nil
}

func foundationChainIdentity(deployment string) trust.ChainIdentity {
	return trust.ChainIdentity{DeploymentID: deployment, Cell: "gru", Environment: "production"}
}

// Every path component is opened relative to its held parent; a renamed path
// or symlink cannot redirect the floor or its lock to another inode.
func openFoundationFloorDirectory() (*os.File, error) {
	config, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(config) || filepath.Clean(config) != config {
		return nil, errors.New("foundation user config directory must be absolute and clean")
	}
	path := filepath.Join(config, "terrascale-orchestrator", "foundation")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, component := range parts {
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if openErr = unix.Mkdirat(fd, component, 0700); openErr == nil || errors.Is(openErr, unix.EEXIST) {
				openErr = unix.Fsync(fd)
				if openErr == nil {
					next, openErr = unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				}
			}
		}
		unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			unix.Close(fd)
			return nil, err
		}
		owner := stat.Uid == uint32(os.Geteuid())
		// Root-owned sticky ancestors such as /tmp are safe for private test
		// homes; only the user may own either application directory.
		stickyRoot := stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0
		if (!owner && stat.Uid != 0) || stat.Mode&0022 != 0 && !stickyRoot ||
			index >= len(parts)-2 && (!owner || stat.Mode&07777 != 0700) {
			unix.Close(fd)
			return nil, errors.New("unsafe foundation floor directory owner or permissions")
		}
	}
	return os.NewFile(uintptr(fd), "foundation floor directory"), nil
}

func openFoundationFloorFile(directory int, name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(directory, name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		file.Close()
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Mode&07777 != 0600 || stat.Size > foundationFloorLimit {
		file.Close()
		return nil, errors.New("unsafe foundation floor file owner, links, mode or length")
	}
	return file, nil
}

func readFoundationFloor(directory int, name, tenancy string, genesis trust.Keyring) (foundationFloor, bool, error) {
	file, err := openFoundationFloorFile(directory, name, unix.O_RDONLY)
	if errors.Is(err, unix.ENOENT) {
		return foundationFloor{}, false, nil
	}
	if err != nil {
		return foundationFloor{}, false, err
	}
	defer file.Close()
	wire, err := io.ReadAll(io.LimitReader(file, foundationFloorLimit+1))
	if err != nil {
		return foundationFloor{}, false, err
	}
	var floor foundationFloor
	if err := protocol.DecodeStrict(wire, &floor, foundationFloorLimit); err != nil {
		return foundationFloor{}, false, err
	}
	if floor.Version != 1 || floor.TenancyID != tenancy || !entityid.Valid(floor.InstallationID) || !entityid.Valid(floor.DeploymentID) || !entityid.Valid(floor.ClusterID) || floor.Generation == 0 {
		return foundationFloor{}, false, errors.New("invalid adopted foundation floor identity or grant")
	}
	for _, value := range []string{floor.GrantSHA256, floor.AnchorSHA256} {
		if digest, err := hex.DecodeString(value); err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != value {
			return foundationFloor{}, false, errors.New("invalid adopted foundation digest")
		}
	}
	chain, err := trust.DecodeRootChain(floor.ChainWire)
	if err == nil {
		_, err = trust.VerifyRootChain(genesis, foundationChainIdentity(floor.DeploymentID), chain)
	}
	return floor, true, err
}

func writeFoundationFloor(directory *os.File, name string, floor foundationFloor) error {
	wire, err := json.Marshal(floor, json.Deterministic(true))
	if err != nil {
		return err
	}
	if len(wire) > foundationFloorLimit {
		return errors.New("foundation floor exceeds size bound")
	}
	temporary := ".foundation-" + rand.Text()
	fd := int(directory.Fd())
	file, err := openFoundationFloorFile(fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(fd, temporary, 0)
	if _, err = file.Write(wire); err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err != nil {
		return err
	}
	if err := unix.Renameat(fd, temporary, fd, name); err != nil {
		return err
	}
	return directory.Sync()
}
