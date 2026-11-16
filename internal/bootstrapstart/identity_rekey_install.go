package bootstrapstart

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

type identityMaterialPredecessors struct {
	installed, durable string
}

func verifyInstalledGenerationChain(installed, chainWire []byte, chain []trust.Envelope, previous *identityMaterialPredecessors) error {
	if previous != nil {
		if bytes.Equal(installed, chainWire) || digest(installed) == previous.installed {
			return nil
		}
		return ErrMaterial
	}
	held, err := bootstrap.DecodeMaterialGenerationChain(installed)
	if err != nil || !chainIs(held, chainWire) && !bootstrap.ExtendsMaterialGenerationChain(chain, held) {
		return ErrMaterial
	}
	return nil
}

func (store MaterialStore) verifyIdentityMaterialPredecessors(dir int, chainWire []byte, previous identityMaterialPredecessors) error {
	if !markerDigestRE.MatchString(previous.installed) || !markerDigestRE.MatchString(previous.durable) || len(chainWire) == 0 || store.chainCopy == "" {
		return ErrMaterial
	}
	installed, err := readUnpinned(dir, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
	if err != nil || !bytes.Equal(installed, chainWire) && digest(installed) != previous.installed {
		return errors.Join(ErrMaterial, err)
	}
	copyDir, err := openMaterialDirectory(filepath.Dir(store.chainCopy), uint32(os.Geteuid()), uint32(os.Getegid()), 0o755, store.allowUnsafeAncestors)
	if err != nil {
		return err
	}
	defer unix.Close(copyDir)
	fd, err := unix.Openat(copyDir, filepath.Base(store.chainCopy), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), store.chainCopy)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o644 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxGenerationChainBytes {
		return ErrMaterial
	}
	wire, err := io.ReadAll(io.LimitReader(file, maxGenerationChainBytes+1))
	if err != nil || int64(len(wire)) != stat.Size || !bytes.Equal(wire, chainWire) && digest(wire) != previous.durable {
		return errors.Join(ErrMaterial, err)
	}
	return nil
}
