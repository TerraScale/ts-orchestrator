package bootstrapstart

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

// TrustInputs is independently verified image genesis and its adopted lineage.
// Durable rollback floors belong to the installer/adoption journal.
type TrustInputs struct {
	ChainIdentity trust.ChainIdentity
	Genesis       trust.Keyring
	Chain         trust.RootChain
	Roots         trust.VerifiedRoots
}

// LoadTrustInputs reads fixed trust paths without reopening retired bootstrap
// identity, anchor or manifest files. A rotated chain must bind this deployment.
func LoadTrustInputs(accepted AcceptedIdentity) (TrustInputs, error) {
	return bakedStore{directory: BakedDirectory, chainFile: RootChainFile, ownerUID: 0, ownerGID: 0}.loadTrustInputs(accepted)
}

func (store bakedStore) loadTrustInputs(accepted AcceptedIdentity) (TrustInputs, error) {
	if err := accepted.Validate(); err != nil {
		return TrustInputs{}, err
	}
	genesis, err := store.loadRoots()
	if err != nil {
		return TrustInputs{}, err
	}
	chain, err := readAcceptedRootChain(store.chainFile)
	if err != nil {
		return TrustInputs{}, err
	}
	identity := trust.ChainIdentity{DeploymentID: accepted.DeploymentID, Environment: accepted.Environment,
		Cell: strings.ToLower(accepted.Cell)}
	roots, err := trust.VerifyRootChain(genesis, identity, chain)
	if err != nil {
		return TrustInputs{}, fmt.Errorf("verify accepted deployment root lineage: %w", err)
	}
	return TrustInputs{ChainIdentity: identity, Genesis: genesis, Chain: chain, Roots: roots}, nil
}

// The adopted chain is service-owned signed public state. It has no root-owner
// requirement, but indirect or damaged state cannot become a genesis fallback.
func readAcceptedRootChain(path string) (trust.RootChain, error) {
	if path == "" {
		return trust.RootChain{Version: 1}, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return trust.RootChain{}, ErrBakedInputs
	}
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return trust.RootChain{}, err
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if component == "" {
			continue
		}
		next, err := unix.Openat(dir, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return trust.RootChain{Version: 1}, nil
			}
			return trust.RootChain{}, err
		}
		dir = next
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return trust.RootChain{Version: 1}, nil
	}
	if err != nil {
		return trust.RootChain{}, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 ||
		stat.Mode&0o7777 != 0o600 && stat.Mode&0o7777 != 0o644 || stat.Size <= 0 || stat.Size > trust.MaxRootChainBytes {
		return trust.RootChain{}, ErrBakedInputs
	}
	wire, err := io.ReadAll(io.LimitReader(file, trust.MaxRootChainBytes+1))
	if err != nil {
		return trust.RootChain{}, err
	}
	return trust.DecodeRootChain(wire)
}
