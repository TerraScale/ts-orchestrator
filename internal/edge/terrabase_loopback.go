package edge

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

// TerraBaseInternalPort is TerraBase's private listener, bound only on this
// host's NetBird address; ts-auth and ts-dashboard reach it as
// http://127.0.0.1:8081, which this edge serves.
const TerraBaseInternalPort = 8081

var terrabaseLoopback = net.JoinHostPort("127.0.0.1", strconv.Itoa(TerraBaseInternalPort))

// terrabaseInternal is the address TerraBase's private listener binds.
func terrabaseInternal() (string, error) {
	ip, err := mesh.NetBirdAddress()
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip, strconv.Itoa(TerraBaseInternalPort)), nil
}

// terrabaseBindError names the host shortcut that held 127.0.0.1:8081 before
// ts-orch served it, so the operator knows what to remove.
func terrabaseBindError(err error) error {
	if !errors.Is(err, syscall.EADDRINUSE) {
		return err
	}
	return fmt.Errorf("%w: another process holds %s; if it is the fr1-terrabase-loopback host shortcut, run "+
		"`systemctl disable --now fr1-terrabase-loopback.socket fr1-terrabase-loopback.service` and delete both units; "+
		"ts-orch binds the port within 5 s", err, terrabaseLoopback)
}
