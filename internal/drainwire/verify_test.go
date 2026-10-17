package drainwire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestGenericExecutionHoldAndStoppedProofBindOriginalAuthority(t *testing.T) {
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "drain-test-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leaf := func(serial int64, role, name string) (*ecdsa.PrivateKey, []byte, []byte) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name, Organization: []string{"cluster"}, OrganizationalUnit: []string{role}},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return key, der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	managerKey, managerDER, managerPEM := leaf(2, "swarm-manager", "manager")
	workerKey, workerDER, workerPEM := leaf(3, "swarm-worker", "worker")
	h := ExecutionHold{HostSession: HostSession{Cell: "gru", HostNode: "host-a", RegistrationID: entityid.New(), InstanceID: "ocid1.instance.original", HostSessionID: entityid.New(),
		RegistrationGeneration: 1, HostEpoch: 41, ExpiresAt: now.Add(time.Minute)}, OriginalEpoch: 3, NodeID: "worker", TaskID: "task", ServiceID: "service",
		TaskSHA256: strings.Repeat("a", 64), ExecutionSHA256: strings.Repeat("b", 64), ExecutionSessionID: entityid.New(), IssuedAt: now.Add(-time.Second)}
	wire, err := HoldSigningBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	signature, err := ecdsa.SignASN1(rand.Reader, managerKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	hold := SignedHold{Hold: h, CertificateChain: [][]byte{managerDER}, Signature: signature}
	if err := VerifySignedHold(hold, managerPEM, caPEM, "cluster", now); err != nil {
		t.Fatal(err)
	}
	changed := hold
	changed.Hold.ExecutionSessionID = entityid.New()
	if err := VerifySignedHold(changed, managerPEM, caPEM, "cluster", now); err == nil {
		t.Fatal("substituted execution session retained manager authority")
	}
	if err := VerifySignedHold(hold, workerPEM, caPEM, "cluster", now); err == nil {
		t.Fatal("another actual node certificate accepted original manager hold")
	}
	c := DrainStopChallenge{Cell: h.Cell, HostNode: h.HostNode, RemovalOperationID: entityid.New(), BirthOperationID: entityid.New(), InstanceID: h.InstanceID,
		NodeID: h.NodeID, RegistrationID: h.RegistrationID, HostSessionID: h.HostSessionID, RegistrationGeneration: h.RegistrationGeneration, Epoch: 4,
		HostEpoch: h.HostEpoch, OriginalEpoch: h.OriginalEpoch, ExecutionSessionID: h.ExecutionSessionID, TaskID: h.TaskID, ServiceID: h.ServiceID,
		TaskSHA256: h.TaskSHA256, ExecutionSHA256: h.ExecutionSHA256, Nonce: strings.Repeat("c", 64), IssuedAt: now.Add(-time.Second), Deadline: now.Add(time.Minute)}
	if !c.Matches(h) || c.Validate(now) != nil {
		t.Fatal("independent original, host and drain counters were conflated")
	}
	p := StopPayload{Challenge: c, ObservedAt: now, ContainerID: "ts-task", KernelStart: "123", Cgroup: "0::/terrascale/ts-task\n", HostPID: 1234, PIDNamespace: 1, MountNamespace: 2}
	wire, err = StopSigningBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	digest = sha256.Sum256(wire)
	signature, err = ecdsa.SignASN1(rand.Reader, workerKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	proof := SignedStop{StopPayload: p, CertificateChain: [][]byte{workerDER}, Signature: signature}
	if err := VerifySignedStop(proof, c, workerPEM, caPEM, "cluster", now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SignedStop){
		"task":               func(s *SignedStop) { s.Challenge.TaskID = "other" },
		"host session":       func(s *SignedStop) { s.Challenge.HostSessionID = entityid.New() },
		"host epoch":         func(s *SignedStop) { s.Challenge.HostEpoch++ },
		"original epoch":     func(s *SignedStop) { s.Challenge.OriginalEpoch++ },
		"kernel process":     func(s *SignedStop) { s.KernelStart = "124" },
		"populated identity": func(s *SignedStop) { s.Cgroup = "0::/terrascale/foreign\n" },
		"stale observation":  func(s *SignedStop) { s.ObservedAt = now.Add(-11 * time.Second) },
		"missing process":    func(s *SignedStop) { s.HostPID = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proof
			mutate(&changed)
			if err := VerifySignedStop(changed, c, workerPEM, caPEM, "cluster", now); err == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
	if err := VerifySignedStop(proof, c, managerPEM, caPEM, "cluster", now); err == nil {
		t.Fatal("manager certificate substituted for original worker")
	}
}
