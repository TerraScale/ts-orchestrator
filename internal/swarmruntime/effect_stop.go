package swarmruntime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/moby/swarmkit/v2/api"
)

func (s *EffectSessions) verifyRuntimeStop(ctx context.Context, epoch uint64, effect authority.RuntimeEffect, challenge runtimeStopChallenge, proof executionwire.SignedRuntimeStop) error {
	now := time.Now().UTC()
	payload := proof.Payload
	retained, err := json.Marshal(challenge.effect, json.Deterministic(true))
	if err != nil {
		return err
	}
	current, err := json.Marshal(effect, json.Deterministic(true))
	if err != nil {
		return err
	}
	kernelStart, parseErr := strconv.ParseUint(payload.KernelStart, 10, 64)
	if !bytes.Equal(retained, current) || challenge.effect.Sequence != effect.Sequence || challenge.epoch != epoch ||
		challenge.nonce == "" || challenge.nonce != payload.Challenge || !challenge.issued.After(effect.ExpiresAt) ||
		now.Sub(challenge.issued) > 10*time.Second || challenge.issued.After(now) ||
		effect.Phase != authority.RuntimeEffectClosing || now.Before(effect.ExpiresAt) ||
		payload.EffectID != effect.EffectID || payload.TaskSHA256 != effect.TaskSHA256 || payload.InstanceID != effect.InstanceID || payload.NodeID != effect.NodeID ||
		payload.Epoch != effect.Epoch || payload.Revision != effect.Sequence || !payload.Deadline.Equal(effect.ExpiresAt) ||
		payload.ContainerID != "ts-"+effect.TaskID || payload.HostPID < 2 || parseErr != nil || kernelStart == 0 ||
		payload.Cgroup != "0::/terrascale/"+payload.ContainerID+"\n" || payload.PIDNamespace == 0 || payload.MountNamespace == 0 ||
		payload.ObservedAt.Before(challenge.issued) || payload.ObservedAt.After(now.Add(time.Second)) || now.Sub(payload.ObservedAt) > 10*time.Second ||
		len(proof.CertificateChain) == 0 || len(proof.CertificateChain) > 8 || len(proof.Signature) == 0 || len(proof.Signature) > 1024 {
		return errors.New("runtime stopped proof differs from fresh exact closing challenge")
	}
	material, err := runtimeMaterial(effect)
	if err != nil {
		return err
	}
	var registration host.Registration
	if err := json.Unmarshal(material.Registration, &registration, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	node, err := s.admittedNode(ctx, registration, effect.NodeID)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(node.Certificate.Certificate)
	if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, proof.CertificateChain[0]) {
		return errors.New("runtime stopped proof did not use the manager's current worker certificate")
	}
	leaf, err := x509.ParseCertificate(proof.CertificateChain[0])
	if err != nil {
		return err
	}
	if leaf.Subject.CommonName != effect.NodeID || len(leaf.Subject.OrganizationalUnit) != 1 || leaf.Subject.OrganizationalUnit[0] != "swarm-worker" || len(leaf.Subject.Organization) != 1 {
		return errors.New("runtime stopped proof certificate has no exact worker identity")
	}
	clusters, err := s.control.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil {
		return err
	}
	if clusters == nil || len(clusters.Clusters) != 1 || clusters.Clusters[0] == nil || leaf.Subject.Organization[0] != clusters.Clusters[0].ID {
		return errors.New("runtime stopped proof certificate differs from the current manager cluster")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(clusters.Clusters[0].RootCA.CACert) {
		return errors.New("manager cluster CA is unavailable")
	}
	intermediates := x509.NewCertPool()
	total := len(proof.CertificateChain[0])
	for _, wire := range proof.CertificateChain[1:] {
		total += len(wire)
		if total > 64<<10 {
			return errors.New("runtime stopped proof certificate chain is oversized")
		}
		certificate, err := x509.ParseCertificate(wire)
		if err != nil {
			return err
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return err
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("runtime stopped proof worker key is unsupported")
	}
	wire, err := json.Marshal(payload, json.Deterministic(true))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append([]byte("TS-RUNTIME-STOP-V1\x00"), wire...))
	if !ecdsa.VerifyASN1(key, digest[:], proof.Signature) {
		return errors.New("runtime stopped proof worker signature is invalid")
	}
	return s.authority.Guard(ctx, epoch)
}
