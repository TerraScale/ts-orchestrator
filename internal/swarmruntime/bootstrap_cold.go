package swarmruntime

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"

	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
)

// ColdBootstrap contains captured runtime pins, never a synthesized task spec.
// Every host retains its region's owner ingress hold, including when the owner
// is a worker and the edge is on the founder.
type ColdBootstrap struct {
	Local rolloutmaintenance.Job `json:"local"`
	Owner rolloutmaintenance.Job `json:"owner"`
}

// ArmColdBootstrap is an offline operation, before starting the new daemon.
// The operator must first prove all six old processes gone. This host additionally
// checks its retained PID identity and that the fixed production runtime socket
// cannot accept work. The journal never expires into automatic rollout permission.
func ArmColdBootstrap(ctx context.Context, state string, input ColdBootstrap) error {
	if os.Geteuid() != 0 {
		return errors.New("cold bootstrap arming requires root")
	}
	member, err := os.Hostname()
	if err != nil {
		return err
	}
	if input.Local.Member != member {
		return errors.New("cold bootstrap manifest does not name this host")
	}
	if err := coldProcessExited(input.Local.Process); err != nil {
		return err
	}
	if err := coldRuntimeStopped(ctx, HostContainerdSocket); err != nil {
		return err
	}
	return retainColdBootstrap(ctx, state, input)
}

func coldProcessExited(retained rolloutmaintenance.Process) error {
	current, err := processIdentity(retained.PID)
	if err == nil && current == retained {
		return errors.New("retained TerraBase process is still alive")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func coldRuntimeStopped(ctx context.Context, socket string) error {
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err == nil {
		connection.Close()
		return errors.New("containerd must be stopped before cold bootstrap arming")
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ECONNREFUSED) {
		return err
	}
	return nil
}

func retainColdBootstrap(ctx context.Context, state string, input ColdBootstrap) error {
	local, owner := input.Local, input.Owner
	if local.Phase != "held" || owner.Phase != "held" || !local.Deadline.IsZero() || !owner.Deadline.IsZero() ||
		local.Target.Task != "" || owner.Target.Task != "" || local.Target.Fingerprint != "" || owner.Target.Fingerprint != "" ||
		owner.Member != local.Owner || owner.Owner != local.Owner || owner.Epoch != local.Epoch || owner.Target.Image != local.Target.Image {
		return errors.New("cold bootstrap requires matching initial owner and local pins")
	}
	store, err := rolloutmaintenance.Open(state)
	if err != nil {
		return err
	}
	if err := store.Arm(ctx, local); err != nil {
		return err
	}
	// This remains held until the selected owner's replacement verifies. The
	// fleet-wide maintenance gate is independent and stays until final checks.
	return store.HoldIngress(ctx, owner)
}
