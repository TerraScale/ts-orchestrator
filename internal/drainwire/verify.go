package drainwire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strconv"
	"time"
)

// VerifySignedHold authenticates the retained manager identity, not task safety.
func VerifySignedHold(s SignedHold, managerCertPEM, clusterCAPEM []byte, clusterID string, now time.Time) error {
	if s.Hold.Validate() != nil || s.Hold.IssuedAt.After(now) {
		return errors.New("invalid retained generic execution hold")
	}
	wire, err := HoldSigningBytes(s.Hold)
	if err != nil {
		return err
	}
	return verifySignature(wire, s.CertificateChain, s.Signature, managerCertPEM, clusterCAPEM, clusterID, "swarm-manager", "", now)
}

// VerifySignedStop requires the exact protected capture and original worker key.
// ROOT additionally proves retained task termination and absence of uncaptured work.
func VerifySignedStop(s SignedStop, exact DrainStopChallenge, workerCertPEM, clusterCAPEM []byte, clusterID string, now time.Time) error {
	start, err := strconv.ParseUint(s.KernelStart, 10, 64)
	if s.Challenge != exact || exact.Validate(now) != nil || s.ObservedAt.Before(exact.IssuedAt) ||
		s.ObservedAt.After(now.Add(time.Second)) || now.Sub(s.ObservedAt) > 10*time.Second || s.ContainerID != "ts-"+exact.TaskID ||
		s.HostPID < 2 || err != nil || start == 0 || s.Cgroup != "0::/terrascale/"+s.ContainerID+"\n" || s.PIDNamespace == 0 || s.MountNamespace == 0 {
		return errors.New("stopped proof differs from exact fresh captured execution")
	}
	wire, err := StopSigningBytes(s.StopPayload)
	if err != nil {
		return err
	}
	return verifySignature(wire, s.CertificateChain, s.Signature, workerCertPEM, clusterCAPEM, clusterID, "swarm-worker", exact.NodeID, now)
}

func verifySignature(wire []byte, chain [][]byte, signature, currentCertPEM, clusterCAPEM []byte, clusterID, role, nodeID string, now time.Time) error {
	if len(chain) == 0 || len(chain) > 8 || len(signature) == 0 || len(signature) > 1024 || clusterID == "" {
		return errors.New("execution proof signing identity is unavailable")
	}
	block, _ := pem.Decode(currentCertPEM)
	if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, chain[0]) {
		return errors.New("execution proof certificate differs from retained actual node certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return err
	}
	if leaf.Subject.CommonName == "" || nodeID != "" && leaf.Subject.CommonName != nodeID ||
		len(leaf.Subject.OrganizationalUnit) != 1 || leaf.Subject.OrganizationalUnit[0] != role ||
		len(leaf.Subject.Organization) != 1 || leaf.Subject.Organization[0] != clusterID {
		return errors.New("execution proof certificate has no exact cluster role")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	if !roots.AppendCertsFromPEM(clusterCAPEM) {
		return errors.New("execution proof cluster CA unavailable")
	}
	total := 0
	for i, raw := range chain {
		total += len(raw)
		if total > 64<<10 {
			return errors.New("execution proof certificate chain exceeds bound")
		}
		if i > 0 {
			certificate, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			intermediates.AddCert(certificate)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return err
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	digest := sha256.Sum256(wire)
	if !ok || !ecdsa.VerifyASN1(public, digest[:], signature) {
		return errors.New("execution proof signature is invalid")
	}
	return nil
}
