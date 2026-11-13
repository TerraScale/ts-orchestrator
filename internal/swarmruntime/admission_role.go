package swarmruntime

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"

	"github.com/moby/swarmkit/v2/ca"
	"github.com/moby/swarmkit/v2/manager"
)

func reconcileAdmissionRole(ctx context.Context, state string, identity *admittedIdentity) error {
	if identity.Role != "manager" && identity.Role != "container" && identity.Role != "wasm" {
		return errors.New("invalid stored SwarmKit admission role")
	}
	paths := ca.NewConfigPaths(filepath.Join(state, "certificates"))
	if _, err := os.Stat(paths.Node.Cert); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	root, err := ca.GetLocalRootCA(paths.RootCA)
	if err != nil {
		return err
	}
	security, cleanup, err := ca.LoadSecurityConfig(ctx, root, ca.NewKeyReadWriter(paths.Node, nil, &manager.RaftDEKData{}), false)
	if err != nil {
		return err
	}
	role := security.ClientTLSCreds.Role()
	if err := cleanup(); err != nil {
		return err
	}
	updated := *identity
	switch {
	case role == ca.ManagerRole && identity.Role == "container":
		updated.Role = "manager"
	case role == ca.WorkerRole && identity.Role == "manager":
		updated.Role = "container"
	case role == ca.ManagerRole && identity.Role == "manager", role == ca.WorkerRole && (identity.Role == "container" || identity.Role == "wasm"):
		return nil
	default:
		return errors.New("SwarmKit certificate role does not match admitted host role")
	}
	data, err := json.Marshal(updated)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(state, ".admission-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(state, "admission.json")); err != nil {
		return err
	}
	*identity = updated
	return nil
}
