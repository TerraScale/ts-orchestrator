package host

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nkeys"
)

func managerBindingFixture(t *testing.T) (SignedManagerRuntimeBinding, []byte, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	clusterID, nodeID := strings.Repeat("a", 25), strings.Repeat("b", 25)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "native cluster"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: nodeID, Organization: []string{clusterID}, OrganizationalUnit: []string{"swarm-manager"}}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	hostKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	natsKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	natsPublic, err := natsKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	certHash, caHash := sha256.Sum256(der), sha256.Sum256(caPEM)
	b := ManagerRuntimeBinding{Version: 1, DeploymentID: entityid.New(), ClusterID: entityid.New(), SwarmClusterID: clusterID,
		Environment: "production", Cell: "gru", OCIRegion: "sa-saopaulo-1", NodeID: nodeID, InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.manager",
		HostID: entityid.Derive("host", "gru", "controller-a"), HostNode: "controller-a", HostSessionID: entityid.New(), HostSessionEpoch: 1,
		RegistrationGeneration: 1, RegistrationRevision: 3, SourceRevision: 7, HostPublicKey: base64.StdEncoding.EncodeToString(hostKey), NATSUserPublicKey: natsPublic,
		RuntimeCandidateID: entityid.New(), BinarySHA256: strings.Repeat("a", 64), AcceptanceSHA256: strings.Repeat("1", 64), AnchorSHA256: strings.Repeat("2", 64), SourceSHA256: strings.Repeat("3", 64),
		CertificateSHA256: hex.EncodeToString(certHash[:]), ClusterCASHA256: hex.EncodeToString(caHash[:]), IssuedAt: now, ExpiresAt: now.Add(20 * time.Second)}
	signed := SignedManagerRuntimeBinding{Binding: b, CertificateChain: [][]byte{der, caDER}}
	signManagerBindingFixture(t, &signed, key)
	return signed, certPEM, caPEM, key
}

func signManagerBindingFixture(t *testing.T, signed *SignedManagerRuntimeBinding, key *ecdsa.PrivateKey) {
	t.Helper()
	wire, err := ManagerRuntimeSigningBytes(signed.Binding)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	signed.Signature, err = ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
}

func TestManagerRuntimeBindingRequiresActualNativeSignatureAndOriginalExpiry(t *testing.T) {
	signed, cert, ca, _ := managerBindingFixture(t)
	if err := VerifySignedManagerRuntimeBinding(signed, cert, ca, signed.Binding.SwarmClusterID, time.Now()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*SignedManagerRuntimeBinding){
		"candidate":  func(s *SignedManagerRuntimeBinding) { s.Binding.RuntimeCandidateID = entityid.New() },
		"binary":     func(s *SignedManagerRuntimeBinding) { s.Binding.BinarySHA256 = strings.Repeat("b", 64) },
		"session":    func(s *SignedManagerRuntimeBinding) { s.Binding.HostSessionID = entityid.New() },
		"expiry":     func(s *SignedManagerRuntimeBinding) { s.Binding.ExpiresAt = s.Binding.ExpiresAt.Add(time.Second) },
		"signature":  func(s *SignedManagerRuntimeBinding) { s.Signature[0] ^= 1 },
		"cluster CA": func(s *SignedManagerRuntimeBinding) { s.Binding.ClusterCASHA256 = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := signed.Clone()
			change(&changed)
			if VerifySignedManagerRuntimeBinding(changed, cert, ca, signed.Binding.SwarmClusterID, time.Now()) == nil {
				t.Fatal("accepted replaced signed binding")
			}
		})
	}
	if VerifySignedManagerRuntimeBinding(signed, cert, ca, signed.Binding.SwarmClusterID, signed.Binding.ExpiresAt) == nil {
		t.Fatal("revived original expired binding")
	}
	_, otherCert, _, _ := managerBindingFixture(t)
	if VerifySignedManagerRuntimeBinding(signed, otherCert, ca, signed.Binding.SwarmClusterID, time.Now()) == nil {
		t.Fatal("accepted replacement current certificate")
	}
}

func TestManagerRuntimeBindingRequiresCanonicalBinaryDigest(t *testing.T) {
	signed, _, _, _ := managerBindingFixture(t)
	for _, digest := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		binding := signed.Binding
		binding.BinarySHA256 = digest
		if _, err := ManagerRuntimeSigningBytes(binding); err == nil {
			t.Fatalf("accepted invalid executable digest %q", digest)
		}
	}
}
