package hostenroll

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// SwarmWorker is covered by the ordinary canonical enrollment response signature.
// Its Vault reference contains only an upstream worker token, never a manager token.
type SwarmWorker struct {
	Version        uint8     `json:"version"`
	DeploymentID   string    `json:"deployment_id"`
	ClusterID      string    `json:"cluster_id"`
	Environment    string    `json:"environment"`
	Cell           string    `json:"cell"`
	Region         string    `json:"region"`
	OCIRegion      string    `json:"oci_region"`
	FounderID      string    `json:"founder_id"`
	RegistrationID string    `json:"registration_id"`
	Generation     uint64    `json:"generation"`
	Revision       uint64    `json:"revision"`
	InstanceID     string    `json:"instance_id"`
	PrivateIP      string    `json:"private_ip"`
	Architecture   string    `json:"architecture"`
	Role           string    `json:"role"`
	ManagerAddress string    `json:"manager_address"`
	SwarmID        string    `json:"swarm_id"`
	CAPEM          string    `json:"ca_pem"`
	SecretID       string    `json:"secret_id"`
	SecretVersion  int64     `json:"secret_version"`
	SecretSHA256   string    `json:"secret_sha256"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (worker SwarmWorker) Validate(now time.Time) error {
	region, known := catalog.CellForOCIRegion(worker.Region)
	address, _, addressErr := net.SplitHostPort(worker.ManagerAddress)
	managerIP, managerErr := netip.ParseAddr(address)
	privateIP, privateErr := netip.ParseAddr(worker.PrivateIP)
	if !known || worker.Version != 1 || !entityid.Valid(worker.DeploymentID) || !entityid.Valid(worker.ClusterID) ||
		!entityid.Valid(worker.RegistrationID) || worker.Environment != "production" && worker.Environment != "canary" ||
		worker.Cell == "" || worker.OCIRegion != region.OCIRegion || worker.FounderID == "" || worker.InstanceID == "" ||
		worker.Role != "container" && worker.Role != "wasm" || worker.Architecture != "amd64" && worker.Architecture != "arm64" ||
		worker.Generation == 0 || worker.Revision == 0 || worker.SwarmID == "" || worker.CAPEM == "" ||
		!secretReferenceValid(worker) || addressErr != nil || managerErr != nil || privateErr != nil ||
		managerIP.IsUnspecified() || managerIP.IsMulticast() || privateIP.IsUnspecified() || privateIP.IsMulticast() ||
		worker.IssuedAt.IsZero() || worker.IssuedAt.After(now.Add(30*time.Second)) || !now.Before(worker.ExpiresAt) ||
		!worker.IssuedAt.Before(worker.ExpiresAt) || worker.ExpiresAt.Sub(worker.IssuedAt) > 10*time.Minute {
		return errors.New("invalid or expired signed SwarmKit worker projection")
	}
	return nil
}

func secretReferenceValid(worker SwarmWorker) bool {
	if !strings.HasPrefix(worker.SecretID, "ocid1.vaultsecret.oc1."+worker.OCIRegion+".") || worker.SecretVersion < 1 || len(worker.SecretSHA256) != 64 {
		return false
	}
	for _, c := range worker.SecretSHA256 {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// WorkerTransport survives the enrollment child and reboot without secret values.
type WorkerTransport struct {
	Request  []byte `json:"request"`
	Response []byte `json:"response"`
}

// VerifiedSwarmWorker can only be constructed from the existing pinned response
// authority and exact recipient request. It grants no manager or founder role.
type VerifiedSwarmWorker struct {
	worker    SwarmWorker
	transport []byte
}

func (verified VerifiedSwarmWorker) Worker() SwarmWorker { return verified.worker }
func (verified VerifiedSwarmWorker) Wire() []byte        { return bytes.Clone(verified.transport) }

func VerifyWorkerTransport(wire []byte, public ed25519.PublicKey, metadata InstanceMetadata,
	architecture string, now time.Time,
) (VerifiedSwarmWorker, error) {
	return verifyWorkerTransportAt(wire, public, metadata, architecture, now, time.Now())
}

func verifyWorkerTransportAt(wire []byte, public ed25519.PublicKey, metadata InstanceMetadata,
	architecture string, now, responseTime time.Time,
) (VerifiedSwarmWorker, error) {
	if len(wire) == 0 || len(wire) > 2*(MaxRequestBytes+MaxResponseBytes) {
		return VerifiedSwarmWorker{}, errors.New("worker enrollment transport is missing or oversized")
	}
	var transport WorkerTransport
	if err := json.Unmarshal(wire, &transport, json.RejectUnknownMembers(true)); err != nil {
		return VerifiedSwarmWorker{}, err
	}
	request, descriptor, err := ParseRetainedWorkerRequest(transport.Request, now)
	if err != nil {
		return VerifiedSwarmWorker{}, err
	}
	response, err := verifyResponseAt(transport.Response, public, request, transport.Request, descriptor, responseTime)
	if err != nil {
		return VerifiedSwarmWorker{}, err
	}
	if response.Swarm == nil || response.Swarm.Validate(now) != nil {
		return VerifiedSwarmWorker{}, errors.New("enrollment has no current signed worker projection")
	}
	worker := *response.Swarm
	if metadata.InstanceID != request.InstanceID || metadata.Descriptor != descriptor ||
		worker.InstanceID != request.InstanceID || worker.RegistrationID != entityid.Derive("host", descriptor.Cell, descriptor.Node) ||
		worker.Cell != descriptor.Cell || !strings.EqualFold(descriptor.Region, catalog.CellOf(worker.Region, "")) || worker.Architecture != architecture ||
		worker.Generation != response.RegistrationReceipt.Generation || worker.Revision != response.RegistrationReceipt.Revision ||
		worker.ExpiresAt.After(response.ExpiresAt) {
		return VerifiedSwarmWorker{}, errors.New("signed worker projection differs from admitted recipient, registration or architecture")
	}
	canonical, err := protocol.EncodeJSON(transport)
	if err != nil || !bytes.Equal(canonical, wire) {
		return VerifiedSwarmWorker{}, errors.New("worker enrollment transport is not canonical")
	}
	return VerifiedSwarmWorker{worker: worker, transport: bytes.Clone(wire)}, nil
}

// SwarmNodeBinding proves possession of both identities after real TLS join.
type SwarmNodeBinding struct {
	NodeID          string    `json:"node_id"`
	RegistrationID  string    `json:"registration_id"`
	ClusterID       string    `json:"cluster_id"`
	FounderID       string    `json:"founder_id"`
	Generation      uint64    `json:"generation"`
	Revision        uint64    `json:"revision"`
	TransportSHA256 string    `json:"transport_sha256"`
	Nonce           string    `json:"nonce"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	HostSignature   string    `json:"host_signature"`
	NodeSignature   string    `json:"node_signature"`
}

func (binding SwarmNodeBinding) signingWire() ([]byte, error) {
	binding.HostSignature, binding.NodeSignature = "", ""
	wire, err := protocol.EncodeJSON(binding)
	return append([]byte("TS-SWARM-WORKER-BINDING-V1\x00"), wire...), err
}

func SignWorkerBinding(accepted VerifiedSwarmWorker, nodeID string, hostKey ed25519.PrivateKey, nodeKey crypto.Signer, now time.Time) (SwarmNodeBinding, error) {
	worker := accepted.Worker()
	if err := worker.Validate(now); err != nil {
		return SwarmNodeBinding{}, err
	}
	if len(hostKey) != ed25519.PrivateKeySize || nodeKey == nil || nodeID == "" {
		return SwarmNodeBinding{}, errors.New("worker binding requires both identity keys")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return SwarmNodeBinding{}, err
	}
	digest := sha256.Sum256(accepted.Wire())
	binding := SwarmNodeBinding{NodeID: nodeID, RegistrationID: worker.RegistrationID, ClusterID: worker.ClusterID, FounderID: worker.FounderID,
		Generation: worker.Generation, Revision: worker.Revision, TransportSHA256: hex.EncodeToString(digest[:]), Nonce: base64.StdEncoding.EncodeToString(nonce), IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)}
	if binding.ExpiresAt.After(worker.ExpiresAt) {
		binding.ExpiresAt = worker.ExpiresAt
	}
	wire, err := binding.signingWire()
	if err != nil {
		return SwarmNodeBinding{}, err
	}
	binding.HostSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(hostKey, wire))
	nodeDigest := sha256.Sum256(wire)
	signature, err := nodeKey.Sign(rand.Reader, nodeDigest[:], crypto.SHA256)
	if err != nil {
		return SwarmNodeBinding{}, err
	}
	binding.NodeSignature = base64.StdEncoding.EncodeToString(signature)
	return binding, nil
}

func VerifyWorkerBinding(binding SwarmNodeBinding, accepted VerifiedSwarmWorker, hostPublic ed25519.PublicKey, nodeCertificate []byte, now time.Time) error {
	worker := accepted.Worker()
	digest := sha256.Sum256(accepted.Wire())
	nonce, nonceErr := base64.StdEncoding.DecodeString(binding.Nonce)
	if worker.Validate(now) != nil || binding.NodeID == "" || binding.RegistrationID != worker.RegistrationID || binding.ClusterID != worker.ClusterID || binding.FounderID != worker.FounderID ||
		binding.Generation != worker.Generation || binding.Revision != worker.Revision || binding.TransportSHA256 != hex.EncodeToString(digest[:]) ||
		binding.IssuedAt.IsZero() || binding.IssuedAt.After(now.Add(5*time.Second)) || !now.Before(binding.ExpiresAt) || binding.ExpiresAt.After(worker.ExpiresAt) ||
		!binding.IssuedAt.Before(binding.ExpiresAt) || binding.ExpiresAt.Sub(binding.IssuedAt) > 30*time.Second || nonceErr != nil || len(nonce) != 32 {
		return errors.New("worker binding differs from current signed recipient scope")
	}
	block, _ := pem.Decode(nodeCertificate)
	if block == nil {
		return errors.New("upstream node certificate missing")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || certificate.Subject.CommonName != binding.NodeID || len(certificate.Subject.Organization) != 1 || certificate.Subject.Organization[0] != worker.SwarmID ||
		len(certificate.Subject.OrganizationalUnit) != 1 || certificate.Subject.OrganizationalUnit[0] != "swarm-worker" || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return errors.New("worker binding differs from actual upstream certificate")
	}
	nodePublic, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("unsupported upstream worker identity key")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(worker.CAPEM)) {
		return errors.New("invalid signed upstream worker root")
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return errors.New("worker certificate differs from signed upstream root")
	}
	wire, err := binding.signingWire()
	hostSignature, hostErr := base64.StdEncoding.DecodeString(binding.HostSignature)
	nodeSignature, nodeErr := base64.StdEncoding.DecodeString(binding.NodeSignature)
	nodeDigest := sha256.Sum256(wire)
	if err != nil || hostErr != nil || nodeErr != nil || len(hostPublic) != ed25519.PublicKeySize || !ed25519.Verify(hostPublic, wire, hostSignature) || !ecdsa.VerifyASN1(nodePublic, nodeDigest[:], nodeSignature) {
		return errors.New("worker binding requires possession of both enrolled host and Swarm node keys")
	}
	return nil
}
