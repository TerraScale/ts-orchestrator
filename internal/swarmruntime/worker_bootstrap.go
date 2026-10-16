package swarmruntime

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/ca"
	"github.com/oracle/oci-go-sdk/v65/secrets"

	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
)

const workerStateDirectory = "/var/lib/terrascale-orchestrator-host/swarm-worker"

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

// StartAcceptedWorker consumes the existing signed recipient enrollment. The
// worker token's pinned version cannot grant manager or founder authority.
func StartAcceptedWorker(ctx context.Context, accepted hostenroll.VerifiedSwarmWorker, bundles WorkerBundleClient, executor exec.Executor) (*Node, error) {
	return startAcceptedWorkerAt(ctx, workerStateDirectory, accepted, bundles, executor)
}

func startAcceptedWorkerAt(ctx context.Context, directory string, accepted hostenroll.VerifiedSwarmWorker, bundles WorkerBundleClient, executor exec.Executor) (*Node, error) {
	signed := accepted.Worker()
	if err := signed.Validate(time.Now().UTC()); err != nil {
		return nil, err
	}
	if signed.Architecture != runtime.GOARCH || len(accepted.Wire()) == 0 || bundles == nil || executor == nil {
		return nil, errors.New("worker requires signed native architecture, Vault and executor")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	lock := flock.New(filepath.Join(directory, "bootstrap.lock"))
	locked, err := lock.TryLock()
	if err != nil || !locked {
		return nil, errors.New("worker bootstrap state is already in use")
	}
	defer lock.Unlock()
	if err := persistWorkerEnrollment(directory, accepted); err != nil {
		return nil, err
	}
	response, err := bundles.GetSecretBundle(ctx, secrets.GetSecretBundleRequest{SecretId: new(signed.SecretID), VersionNumber: new(signed.SecretVersion)})
	if err != nil {
		return nil, errors.New("read exact admitted worker Vault material failed")
	}
	content, ok := response.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	if !ok || content.Content == nil || response.SecretId == nil || *response.SecretId != signed.SecretID || response.VersionNumber == nil || *response.VersionNumber != signed.SecretVersion {
		return nil, errors.New("worker Vault bundle differs from signed version")
	}
	wire, err := base64.StdEncoding.DecodeString(*content.Content)
	if err != nil || len(wire) == 0 || len(wire) > 16384 {
		return nil, errors.New("invalid worker Vault material")
	}
	defer clear(wire)
	digest := sha256.Sum256(wire)
	if hex.EncodeToString(digest[:]) != signed.SecretSHA256 {
		return nil, errors.New("worker Vault bytes differ from signed digest")
	}
	var material workerJoinMaterial
	if json.Unmarshal(wire, &material, json.RejectUnknownMembers(true)) != nil || !workerMaterialMatches(material, signed) {
		return nil, errors.New("worker Vault material differs from signed recipient scope")
	}
	if _, err := ca.ParseJoinToken(material.WorkerToken); err != nil {
		return nil, errors.New("invalid upstream worker token")
	}
	nodeDirectory := filepath.Join(directory, "node")
	n, err := StartNode(ctx, NodeConfig{StateDir: nodeDirectory, ListenAddress: net.JoinHostPort(signed.PrivateIP, swarmManagerPort), AdvertiseAddress: net.JoinHostPort(signed.PrivateIP, swarmManagerPort),
		Admission: Admission{Region: signed.Region, HostID: signed.RegistrationID, InstanceID: signed.InstanceID, FounderID: signed.FounderID, Role: signed.Role, ManagerAddress: signed.ManagerAddress, JoinToken: material.WorkerToken}}, executor)
	if err != nil {
		return nil, err
	}
	certWire, err := os.ReadFile(filepath.Join(nodeDirectory, "certificates", "swarm-node.crt"))
	rootWire, rootErr := os.ReadFile(filepath.Join(nodeDirectory, "certificates", "swarm-root-ca.crt"))
	block, _ := pem.Decode(certWire)
	if err == nil && block != nil {
		cert, certErr := x509.ParseCertificate(block.Bytes)
		if certErr == nil && rootErr == nil && string(rootWire) == signed.CAPEM && len(cert.Subject.Organization) == 1 && cert.Subject.Organization[0] == signed.SwarmID && signed.Validate(time.Now().UTC()) == nil {
			return n, nil
		}
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = n.Stop(stopCtx)
	return nil, errors.New("joined worker certificate differs from signed upstream cluster")
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

// WorkerBinding signs the post-join mapping without exporting the Swarm key.
func (n *Node) WorkerBinding(accepted hostenroll.VerifiedSwarmWorker, hostKey ed25519.PrivateKey) (hostenroll.SwarmNodeBinding, error) {
	worker := accepted.Worker()
	if n.role == "manager" || n.role != worker.Role {
		return hostenroll.SwarmNodeBinding{}, errors.New("worker binding requires the admitted worker role")
	}
	admissionWire, err := os.ReadFile(filepath.Join(n.stateDir, "admission.json"))
	var admission admittedIdentity
	if err != nil || json.Unmarshal(admissionWire, &admission) != nil || admission.HostID != worker.RegistrationID || admission.InstanceID != worker.InstanceID || admission.Region != worker.Region || admission.FounderID != worker.FounderID {
		return hostenroll.SwarmNodeBinding{}, errors.New("worker binding differs from persistent admission")
	}
	wire, err := os.ReadFile(filepath.Join(n.stateDir, "certificates", "swarm-node.key"))
	if err != nil {
		return hostenroll.SwarmNodeBinding{}, err
	}
	defer clear(wire)
	block, _ := pem.Decode(wire)
	if block == nil {
		return hostenroll.SwarmNodeBinding{}, errors.New("upstream worker private key unavailable")
	}
	var key crypto.Signer
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, _ = parsed.(crypto.Signer)
	}
	if key == nil {
		if parsed, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			key = parsed
		}
	}
	if key == nil {
		return hostenroll.SwarmNodeBinding{}, errors.New("unsupported upstream worker private key")
	}
	return hostenroll.SignWorkerBinding(accepted, n.ID(), hostKey, key, time.Now().UTC())
}
