package swarmruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/moby/swarmkit/v2/agent"
	"github.com/moby/swarmkit/v2/api"
	bolt "go.etcd.io/bbolt"

	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
)

// OfflineExitProcess is the only process identity an offline-armed job may
// retain. Linux PIDs are always below pid_max, whose ceiling is 1<<22, so this
// identity never exists after the worker boots: Exited reduces to the physical
// proof that the boot volume was detached from a STOPPED instance.
var OfflineExitProcess = rolloutmaintenance.Process{PID: 1 << 22, Start: 1}

// offlineAgentDB is the old Swarm agent's local task database below --state.
const offlineAgentDB = "swarm/worker/tasks.db"

// OfflinePins reads the single assigned regional TerraBase task from a stopped
// host's mounted Swarm agent database. The operator compares it with the
// manager's task list; it cannot invent a pin for arm-offline.
func OfflinePins(root, state string) (rolloutmaintenance.Pin, error) {
	db, err := bolt.Open(filepath.Join(root, state, offlineAgentDB), 0o600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return rolloutmaintenance.Pin{}, err
	}
	defer db.Close()
	var found []rolloutmaintenance.Pin
	err = db.View(func(tx *bolt.Tx) error {
		return agent.WalkTasks(tx, func(task *api.Task) error {
			// Retained SHUTDOWN history stays assigned; only the desired-running task is the source.
			if !agent.TaskAssigned(tx, task.ID) || task.DesiredState != api.TaskStateRunning || task.ServiceAnnotations.Labels[LabelServiceSpec] != "terrabase" {
				return nil
			}
			spec, err := DecodeContainer(task)
			if err != nil || !slices.ContainsFunc(spec.Env, func(v string) bool { return strings.HasPrefix(v, "TS_REGION=") }) {
				return nil
			}
			found = append(found, rolloutmaintenance.Pin{Node: task.NodeID, Service: task.ServiceID, Task: task.ID, Fingerprint: taskFingerprint(task), Image: spec.Image})
			return nil
		})
	})
	if err == nil && len(found) != 1 {
		err = errors.New("offline agent state must hold exactly one assigned regional TerraBase task")
	}
	if err != nil {
		return rolloutmaintenance.Pin{}, err
	}
	return found[0], nil
}

// ArmOfflineColdBootstrap arms a stopped worker's boot volume while it is
// mounted read-write on its region's founder. It never runs against the live
// root. The manifest's source pin must equal the volume's own agent state.
// After the fence is durable, the old agent database moves aside, so its
// worker.Init cannot restart any assigned task before the manager reassigns.
func ArmOfflineColdBootstrap(ctx context.Context, root, state string, input ColdBootstrap) error {
	if os.Geteuid() != 0 {
		return errors.New("offline cold bootstrap arming requires root")
	}
	if err := offlineMountedRoot(root); err != nil {
		return err
	}
	return armOffline(ctx, root, state, input)
}

func armOffline(ctx context.Context, root, state string, input ColdBootstrap) error {
	if !filepath.IsAbs(state) || filepath.Clean(state) != state {
		return errors.New("offline state must be an absolute clean path inside the mounted root")
	}
	name, err := os.ReadFile(filepath.Join(root, "etc", "hostname"))
	if err != nil {
		return err
	}
	self, err := os.Hostname()
	if err != nil {
		return err
	}
	if member := strings.TrimSpace(string(name)); member != input.Local.Member || member == self {
		return errors.New("offline cold bootstrap manifest does not name the mounted host")
	}
	if input.Local.Process != OfflineExitProcess {
		return errors.New("offline cold bootstrap requires the unreachable exit identity")
	}
	retained := filepath.Join(root, state, "zdt-retained", "tasks.db."+input.Local.ID)
	database := filepath.Join(root, state, offlineAgentDB)
	if _, err := os.Stat(database); errors.Is(err, os.ErrNotExist) {
		// Resume only an exact interrupted arm: its retained agent state remains.
		if _, err := os.Stat(retained); err != nil {
			return errors.New("offline agent state is missing")
		}
		return retainColdBootstrap(ctx, filepath.Join(root, state), input)
	}
	pin, err := OfflinePins(root, state)
	if err != nil {
		return err
	}
	if pin != input.Local.Source {
		return errors.New("offline agent task differs from the manifest source pin")
	}
	if err := retainColdBootstrap(ctx, filepath.Join(root, state), input); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(retained), 0o700); err != nil {
		return err
	}
	if err := os.Rename(database, retained); err != nil {
		return err
	}
	return errors.Join(syncPath(filepath.Dir(database)), syncPath(filepath.Dir(retained)))
}

// offlineMountedRoot accepts only a separate mounted filesystem, never "/".
func offlineMountedRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return errors.New("offline root must be an absolute mounted path other than /")
	}
	var mounted, parent, live syscall.Stat_t
	if err := syscall.Lstat(root, &mounted); err != nil {
		return err
	}
	if err := syscall.Stat(filepath.Dir(root), &parent); err != nil {
		return err
	}
	if err := syscall.Stat("/", &live); err != nil {
		return err
	}
	if mounted.Mode&syscall.S_IFMT != syscall.S_IFDIR || mounted.Dev == parent.Dev || mounted.Dev == live.Dev {
		return errors.New("offline root is not a separately mounted filesystem")
	}
	return nil
}

func syncPath(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
