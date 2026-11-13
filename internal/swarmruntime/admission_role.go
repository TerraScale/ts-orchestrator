package swarmruntime

import (
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"

	"github.com/moby/swarmkit/v2/ca"
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
	certificate, err := nodeCertificate(ctx, state)
	if err != nil {
		return err
	}
	role := certificate.Subject.OrganizationalUnit[0]
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

func nodeCertificate(ctx context.Context, state string) (*x509.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	paths := ca.NewConfigPaths(filepath.Join(state, "certificates"))
	root, err := ca.GetLocalRootCA(paths.RootCA)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(paths.Node.Cert)
	if err != nil {
		return nil, err
	}
	certificates, _, err := ca.ValidateCertChain(root.Pool, data, false)
	if err != nil {
		return nil, err
	}
	certificate := certificates[0]
	identity := certificate.Subject
	if identity.CommonName == "" || len(identity.Organization) != 1 || len(identity.OrganizationalUnit) != 1 ||
		identity.OrganizationalUnit[0] != ca.ManagerRole && identity.OrganizationalUnit[0] != ca.WorkerRole {
		return nil, errors.New("invalid SwarmKit node certificate identity")
	}
	return certificate, nil
}
