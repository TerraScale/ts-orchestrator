package bootstrapstart

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"golang.org/x/sys/unix"
)

const (
	founderPeersCompleteName = "founder-peers-complete.json"
	founderPeersCompleteMax  = 1024
)

// founderPeersComplete is the seed's local record that every planned peer
// reached a verified managed result for this exact accepted install. It lets
// a seed restart skip the historical OCI ledger read.
//
// The fact can only suppress founder work; it never authorizes an OCI effect
// or admission. A forged or stale fact therefore costs liveness (no peer is
// launched), never safety, and it binds the accepted instance and anchor so a
// replacement seed or a re-anchored install falls back to the ledger read.
type founderPeersCompleteFact struct {
	SchemaVersion  int    `json:"schemaVersion"`
	DeploymentID   string `json:"deploymentId"`
	Cell           string `json:"cell"`
	SeedSlot       string `json:"seedSlot"`
	InstanceOCID   string `json:"instanceOcid"`
	AnchorSHA256   string `json:"anchorSha256"`
	ManifestSHA256 string `json:"manifestSha256"`
}

func newFounderPeersCompleteFact(accepted AcceptedInstall) founderPeersCompleteFact {
	return founderPeersCompleteFact{SchemaVersion: 1, DeploymentID: accepted.DeploymentID,
		Cell: accepted.Cell, SeedSlot: accepted.SeedSlot, InstanceOCID: accepted.InstanceOCID,
		AnchorSHA256: accepted.AnchorSHA256, ManifestSHA256: accepted.ManifestSHA256}
}

// PeersComplete reports whether a canonical completion fact for this exact
// accepted seed install is durable. Any absent, malformed, foreign, or
// mismatched fact reads as incomplete so the caller repeats the ledger read.
func (store *FounderSelectionFloorStore) PeersComplete(accepted AcceptedInstall) bool {
	if accepted.Slot != accepted.SeedSlot {
		return false
	}
	dir, err := store.openDirectory()
	if err != nil {
		return false
	}
	defer unix.Close(dir)
	complete := false
	_ = store.withLock(dir, func() error {
		fd, err := unix.Openat(dir, founderPeersCompleteName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), founderPeersCompleteName)
		defer file.Close()
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
			stat.Mode&0o777 != 0o600 || stat.Uid != store.ownerUID || stat.Nlink != 1 ||
			stat.Size < 1 || stat.Size > founderPeersCompleteMax {
			return ErrFounderSelectionFloor
		}
		wire, err := io.ReadAll(io.LimitReader(file, founderPeersCompleteMax+1))
		if err != nil || len(wire) != int(stat.Size) {
			return ErrFounderSelectionFloor
		}
		var fact founderPeersCompleteFact
		if protocol.DecodeStrict(wire, &fact, founderPeersCompleteMax) != nil {
			return ErrFounderSelectionFloor
		}
		canonical, err := protocol.EncodeJSON(fact)
		if err != nil || !bytes.Equal(canonical, wire) {
			return ErrFounderSelectionFloor
		}
		complete = fact == newFounderPeersCompleteFact(accepted)
		return nil
	})
	return complete
}

// MarkPeersComplete durably records completion after a verified result for
// every planned peer. It replaces any older fact atomically.
func (store *FounderSelectionFloorStore) MarkPeersComplete(accepted AcceptedInstall) error {
	if accepted.validate() != nil || accepted.Slot != accepted.SeedSlot {
		return ErrFounderRuntime
	}
	wire, err := protocol.EncodeJSON(newFounderPeersCompleteFact(accepted))
	if err != nil || len(wire) > founderPeersCompleteMax {
		return ErrFounderSelectionFloor
	}
	dir, err := store.openDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	return store.withLock(dir, func() error {
		var nonce [12]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		temporary := ".founder-peers-complete." + hex.EncodeToString(nonce[:])
		fd, err := unix.Openat(dir, temporary,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		remove := true
		defer func() {
			if remove {
				_ = unix.Unlinkat(dir, temporary, 0)
			}
		}()
		file := os.NewFile(uintptr(fd), temporary)
		written, writeErr := file.Write(wire)
		if written != len(wire) && writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return err
		}
		if err := unix.Renameat(dir, temporary, dir, founderPeersCompleteName); err != nil {
			return err
		}
		remove = false
		return unix.Fsync(dir)
	})
}
