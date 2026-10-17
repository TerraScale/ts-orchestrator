package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"golang.org/x/sys/unix"
)

// CompletedTargetView is a readonly worker checkpoint, not membership authority.
// Its caller independently authenticates the current signed target and daemon.
type CompletedTargetView struct {
	Generation, Epoch                                  uint64
	Transaction, ActionID, Action                      string
	TargetHash, InstalledTargetHash, AppliedTargetHash string
}

// ReadCompletedTarget reads only the fixed private worker ledger for an accepted
// cell and node. It neither creates state nor repairs the managed installation.
func ReadCompletedTarget(cell, node string) (CompletedTargetView, error) {
	if os.Geteuid() != 0 || cell != strings.ToLower(cell) || !catalog.IsCell(strings.ToUpper(cell)) || naming.Validate(node) != nil {
		return CompletedTargetView{}, errors.New("invalid NetBird completed-target reader identity")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return CompletedTargetView{}, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Join(StateRoot, cell, node), "/"), "/") {
		if err := checkCompletedTargetDirectory(fd, false); err != nil {
			unix.Close(fd)
			return CompletedTargetView{}, err
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return CompletedTargetView{}, err
		}
		fd = next
	}
	directory := os.NewFile(uintptr(fd), "NetBird completed-target directory")
	defer directory.Close()
	return readCompletedTarget(directory)
}

func checkCompletedTargetDirectory(fd int, private bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0022 != 0 || private && stat.Mode&07777 != 0700 {
		return errors.New("unsafe NetBird completed-target directory")
	}
	return nil
}

func readCompletedTarget(directory *os.File) (CompletedTargetView, error) {
	if err := checkCompletedTargetDirectory(int(directory.Fd()), true); err != nil {
		return CompletedTargetView{}, err
	}
	last, err := loadLedger(fmt.Sprintf("/proc/self/fd/%d", directory.Fd()))
	if err != nil {
		return CompletedTargetView{}, err
	}
	return completedTarget(last)
}

func completedTarget(last ledger) (CompletedTargetView, error) {
	// Action is persisted before the effect; only its completed command ID and
	// matching applied/installed target establish a successful confirmation.
	if last.Generation == 0 || last.Epoch == 0 || !entityid.Valid(last.Transaction) || last.Action != "confirm" ||
		last.ActionID != network.CommandID(last.Transaction, "confirm") || last.Error != "" ||
		!client.SHA256Pattern.MatchString(last.TargetHash) || last.TargetHash != last.InstalledTargetHash || last.TargetHash != last.AppliedTargetHash {
		return CompletedTargetView{}, errors.New("NetBird worker target is not confirmed")
	}
	return CompletedTargetView{Generation: last.Generation, Epoch: last.Epoch, Transaction: last.Transaction, ActionID: last.ActionID, Action: last.Action,
		TargetHash: last.TargetHash, InstalledTargetHash: last.InstalledTargetHash, AppliedTargetHash: last.AppliedTargetHash}, nil
}
