package membership

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"golang.org/x/sys/unix"
)

// maxEvidenceBytes bounds one retirement envelope file.
const maxEvidenceBytes = 64 << 10

// EvidenceFileSuffix names an operator-placed retirement envelope file.
const EvidenceFileSuffix = ".retirement"

// FileEvidence reads <dir>/<slot>.retirement for every topology slot. Files
// must be regular, owner-only and not symbolic links. The payload is decoded
// only to route the envelope; the ledger verifies the root signature.
type FileEvidence struct {
	Dir   string
	Slots []string
}

func (source FileEvidence) Evidence(ctx context.Context) (map[string]Evidence, error) {
	evidence := make(map[string]Evidence, len(source.Slots))
	if source.Dir == "" {
		return evidence, nil
	}
	for _, slot := range source.Slots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		wire, err := readEvidenceFile(filepath.Join(source.Dir, slot+EvidenceFileSuffix))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s retirement evidence: %w", slot, err)
		}
		decoded, err := bootstrap.DecodeSlotRetirementCandidate(wire)
		if err != nil || decoded.Slot != slot {
			// A malformed or misplaced file is ignored rather than trusted.
			continue
		}
		sum := sha256.Sum256(wire)
		evidence[slot] = Evidence{Slot: slot, PreviousAttempt: decoded.PreviousAttempt,
			PriorInstanceOCID: decoded.PriorInstanceOCID, Digest: hex.EncodeToString(sum[:]), Wire: wire}
	}
	return evidence, nil
}

func readEvidenceFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Uid != uint32(os.Geteuid()) &&
		stat.Uid != 0 || stat.Size <= 0 || stat.Size > maxEvidenceBytes {
		return nil, errors.New("retirement evidence must be a bounded owner-only regular file")
	}
	wire, err := io.ReadAll(io.LimitReader(file, maxEvidenceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(wire) > maxEvidenceBytes || int64(len(wire)) != stat.Size {
		return nil, errors.New("retirement evidence changed while reading")
	}
	return wire, nil
}
