package swarmruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/oracle/oci-go-sdk/v65/secrets"

	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
)

// WorkerBundleClient reads only the exact secret/version pinned by enrollment.
type WorkerBundleClient interface {
	GetSecretBundle(context.Context, secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error)
}

type workerJoinMaterial struct {
	Version                                                 uint8
	DeploymentID, ClusterID, Environment, Region, FounderID string
	RegistrationID, InstanceID, Role, Architecture          string
	SwarmID, CAPEM, ManagerAddress, WorkerToken             string
}

func workerMaterialMatches(material workerJoinMaterial, signed hostenroll.SwarmWorker) bool {
	return material.Version == 1 && material.DeploymentID == signed.DeploymentID && material.ClusterID == signed.ClusterID &&
		material.Environment == signed.Environment && strings.EqualFold(material.Region, signed.Region) && material.FounderID == signed.FounderID &&
		material.RegistrationID == signed.RegistrationID && material.InstanceID == signed.InstanceID && material.Role == signed.Role &&
		material.Architecture == signed.Architecture && material.SwarmID == signed.SwarmID && material.CAPEM == signed.CAPEM && material.ManagerAddress == signed.ManagerAddress
}

func persistWorkerEnrollment(directory string, accepted hostenroll.VerifiedSwarmWorker) error {
	path := filepath.Join(directory, "enrollment.json")
	next := accepted.Worker()
	if wire, err := os.ReadFile(path); err == nil {
		var stored struct {
			Worker    hostenroll.SwarmWorker
			Transport []byte
		}
		if json.Unmarshal(wire, &stored, json.RejectUnknownMembers(true)) != nil {
			return errors.New("invalid persistent worker admission floor")
		}
		previous := stored.Worker
		if previous.DeploymentID != next.DeploymentID || previous.ClusterID != next.ClusterID || previous.Environment != next.Environment || previous.Cell != next.Cell || previous.Region != next.Region || previous.OCIRegion != next.OCIRegion ||
			previous.FounderID != next.FounderID || previous.RegistrationID != next.RegistrationID || previous.InstanceID != next.InstanceID || previous.PrivateIP != next.PrivateIP || previous.Role != next.Role || previous.Architecture != next.Architecture ||
			previous.SwarmID != next.SwarmID || previous.CAPEM != next.CAPEM || next.Generation < previous.Generation || next.Revision < previous.Revision {
			return errors.New("worker signed scope changed or enrollment generation rolled back")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if _, err := os.Stat(filepath.Join(directory, "node")); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("worker state is missing its signed enrollment floor")
	}
	wire, err := json.Marshal(struct {
		Worker    hostenroll.SwarmWorker
		Transport []byte
	}{next, accepted.Wire()})
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".enrollment-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(wire)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

// RefreshWorkerEnrollment advances the signed admission floor without restarting
// the agent or its tasks. The upstream node certificate has its own lifetime.
func (n *Node) RefreshWorkerEnrollment(accepted hostenroll.VerifiedSwarmWorker) error {
	worker := accepted.Worker()
	if n == nil || n.workerDirectory == "" || n.role == "manager" || n.role != worker.Role || worker.Architecture != runtime.GOARCH || worker.Validate(time.Now().UTC()) != nil {
		return errors.New("worker refresh requires current signed native worker admission")
	}
	lock := flock.New(filepath.Join(n.workerDirectory, "bootstrap.lock"))
	locked, err := lock.TryLock()
	if err != nil || !locked {
		return errors.New("worker enrollment floor is already in use")
	}
	defer lock.Unlock()
	admissionWire, err := os.ReadFile(filepath.Join(n.stateDir, "admission.json"))
	var admission admittedIdentity
	if err != nil || json.Unmarshal(admissionWire, &admission) != nil || admission.HostID != worker.RegistrationID || admission.InstanceID != worker.InstanceID || admission.Region != worker.Region || admission.FounderID != worker.FounderID {
		return errors.New("worker refresh differs from persistent admission")
	}
	certificateWire, certErr := os.ReadFile(filepath.Join(n.stateDir, "certificates", "swarm-node.crt"))
	rootWire, rootErr := os.ReadFile(filepath.Join(n.stateDir, "certificates", "swarm-root-ca.crt"))
	block, _ := pem.Decode(certificateWire)
	if certErr != nil || rootErr != nil || block == nil || string(rootWire) != worker.CAPEM {
		return errors.New("worker refresh differs from current certificate authority")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || certificate.Subject.CommonName != n.ID() || len(certificate.Subject.Organization) != 1 || certificate.Subject.Organization[0] != worker.SwarmID ||
		len(certificate.Subject.OrganizationalUnit) != 1 || certificate.Subject.OrganizationalUnit[0] != "swarm-worker" {
		return errors.New("worker refresh differs from current upstream identity")
	}
	return persistWorkerEnrollment(n.workerDirectory, accepted)
}

// WorkerBinding signs the post-join mapping without exporting the Swarm key.
func (n *Node) WorkerBinding(accepted hostenroll.VerifiedSwarmWorker, hostKey ed25519.PrivateKey) (hostenroll.SwarmNodeBinding, error) {
	if err := n.RefreshWorkerEnrollment(accepted); err != nil {
		return hostenroll.SwarmNodeBinding{}, err
	}
	key, _, err := n.nodeSigningKey()
	if err != nil {
		return hostenroll.SwarmNodeBinding{}, err
	}
	return hostenroll.SignWorkerBinding(accepted, n.ID(), hostKey, key, time.Now().UTC())
}
