package host

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/nats-io/nkeys"
)

// ManagerRuntimeBinding is inert until the actual current native manager,
// original host session and regional lease independently verify it.
type ManagerRuntimeBinding struct {
	Version                uint8     `json:"version"`
	DeploymentID           string    `json:"deployment_id"`
	ClusterID              string    `json:"cluster_id"`
	SwarmClusterID         string    `json:"swarm_cluster_id"`
	Environment            string    `json:"environment"`
	Cell                   string    `json:"cell"`
	OCIRegion              string    `json:"oci_region"`
	NodeID                 string    `json:"node_id"`
	InstanceID             string    `json:"instance_id"`
	HostID                 string    `json:"host_id"`
	HostNode               string    `json:"host_node"`
	HostSessionID          string    `json:"host_session_id"`
	HostSessionEpoch       uint64    `json:"host_session_epoch"`
	RegistrationGeneration uint64    `json:"registration_generation"`
	RegistrationRevision   uint64    `json:"registration_revision"`
	SourceRevision         uint64    `json:"source_revision"`
	HostPublicKey          string    `json:"host_public_key"`
	NATSUserPublicKey      string    `json:"nats_user_public_key"`
	RuntimeCandidateID     string    `json:"runtime_candidate_id"`
	AcceptanceSHA256       string    `json:"acceptance_sha256"`
	AnchorSHA256           string    `json:"anchor_sha256"`
	SourceSHA256           string    `json:"source_sha256"`
	ClusterCASHA256        string    `json:"cluster_ca_sha256"`
	CertificateSHA256      string    `json:"certificate_sha256"`
	IssuedAt               time.Time `json:"issued_at"`
	ExpiresAt              time.Time `json:"expires_at"`
}

type SignedManagerRuntimeBinding struct {
	Binding          ManagerRuntimeBinding `json:"binding"`
	CertificateChain [][]byte              `json:"certificate_chain"`
	Signature        []byte                `json:"signature"`
}

func (binding ManagerRuntimeBinding) Validate() error {
	entry, ok := catalog.CellForOCIRegion(binding.OCIRegion)
	if binding.Version != 1 || !ok || !strings.EqualFold(entry.Cell, binding.Cell) ||
		validateToken(binding.Cell, "cell") != nil || binding.Environment != "production" ||
		!entityid.Valid(binding.DeploymentID) || !entityid.Valid(binding.ClusterID) ||
		!managerNativeID(binding.SwarmClusterID) || !managerNativeID(binding.NodeID) ||
		binding.HostID != entityid.Derive("host", binding.Cell, binding.HostNode) ||
		validateToken(binding.HostNode, "host node") != nil || !entityid.Valid(binding.HostSessionID) ||
		!entityid.Valid(binding.RuntimeCandidateID) || binding.HostSessionEpoch == 0 ||
		binding.RegistrationGeneration == 0 || binding.RegistrationRevision == 0 || binding.SourceRevision == 0 ||
		!strings.HasPrefix(binding.InstanceID, "ocid1.instance.") || len(binding.InstanceID) > 512 ||
		strings.ContainsAny(binding.InstanceID, " \t\r\n") || binding.IssuedAt.IsZero() ||
		!binding.ExpiresAt.After(binding.IssuedAt) || binding.ExpiresAt.Sub(binding.IssuedAt) > sessionTTL {
		return errors.New("manager runtime binding has incomplete finite scope")
	}
	for _, digest := range []string{binding.AcceptanceSHA256, binding.AnchorSHA256, binding.SourceSHA256, binding.ClusterCASHA256, binding.CertificateSHA256} {
		if validateDigest(digest) != nil {
			return errors.New("manager runtime binding has invalid source pins")
		}
	}
	if _, err := decodePublicKey(binding.HostPublicKey); err != nil {
		return err
	}
	if !nkeys.IsValidPublicUserKey(binding.NATSUserPublicKey) {
		return errors.New("manager runtime binding has invalid host NATS identity")
	}
	return nil
}

func managerNativeID(value string) bool {
	return len(value) == 25 && strings.Trim(value, "abcdefghijklmnopqrstuvwxyz0123456789") == ""
}

func ManagerRuntimeSigningBytes(binding ManagerRuntimeBinding) ([]byte, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(binding, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	return append([]byte("terrascale.manager-runtime-binding.v1\x00"), wire...), nil
}

func (signed SignedManagerRuntimeBinding) Clone() SignedManagerRuntimeBinding {
	signed.Signature = slices.Clone(signed.Signature)
	signed.CertificateChain = slices.Clone(signed.CertificateChain)
	for index := range signed.CertificateChain {
		signed.CertificateChain[index] = slices.Clone(signed.CertificateChain[index])
	}
	return signed
}

// VerifySignedManagerRuntimeBinding authenticates only against the independently
// read exact current manager certificate and actual native cluster authority.
func VerifySignedManagerRuntimeBinding(signed SignedManagerRuntimeBinding, managerCertPEM, clusterCAPEM []byte, clusterID string, now time.Time) error {
	wire, err := ManagerRuntimeSigningBytes(signed.Binding)
	if err != nil {
		return err
	}
	binding := signed.Binding
	caDigest := sha256.Sum256(clusterCAPEM)
	if binding.ClusterCASHA256 != hex.EncodeToString(caDigest[:]) || binding.SwarmClusterID != clusterID || binding.IssuedAt.After(now) || !now.Before(binding.ExpiresAt) ||
		len(signed.CertificateChain) == 0 || len(signed.CertificateChain) > 8 ||
		len(signed.Signature) == 0 || len(signed.Signature) > 1024 {
		return errors.New("manager runtime binding has no current native identity")
	}
	block, _ := pem.Decode(managerCertPEM)
	if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, signed.CertificateChain[0]) {
		return errors.New("manager runtime binding certificate was replaced")
	}
	leaf, err := x509.ParseCertificate(signed.CertificateChain[0])
	if err != nil {
		return err
	}
	digest := sha256.Sum256(leaf.Raw)
	if hex.EncodeToString(digest[:]) != binding.CertificateSHA256 || leaf.Subject.CommonName != binding.NodeID ||
		len(leaf.Subject.OrganizationalUnit) != 1 || leaf.Subject.OrganizationalUnit[0] != "swarm-manager" ||
		len(leaf.Subject.Organization) != 1 || leaf.Subject.Organization[0] != clusterID ||
		binding.ExpiresAt.After(leaf.NotAfter) {
		return errors.New("manager runtime binding differs from its exact native manager")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	if !roots.AppendCertsFromPEM(clusterCAPEM) {
		return errors.New("manager runtime binding has no current cluster authority")
	}
	total := 0
	for index, raw := range signed.CertificateChain {
		total += len(raw)
		if total > 64<<10 {
			return errors.New("manager runtime certificate chain exceeds bound")
		}
		if index > 0 {
			certificate, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			intermediates.AddCert(certificate)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return err
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	signatureDigest := sha256.Sum256(wire)
	if !ok || !ecdsa.VerifyASN1(public, signatureDigest[:], signed.Signature) {
		return errors.New("manager runtime binding signature is invalid")
	}
	return nil
}
