package swarmruntime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/moby/swarmkit/v2/api"
)

func (s *EffectSessions) verifyRuntimeStop(ctx context.Context, epoch uint64, effect authority.RuntimeEffect, challenge runtimeStopChallenge, proof executionwire.SignedRuntimeStop, settlementDeadline time.Time) error {
	deadline, err := runtimeStopDeadline(challenge, proof)
	if err != nil {
		return err
	}
	if settlementDeadline.IsZero() || settlementDeadline.After(deadline) {
		return errors.New("runtime stopped proof settlement exceeds its original lifetime")
	}
	ctx, cancel := context.WithDeadline(ctx, settlementDeadline)
	defer cancel()
	if err := checkRuntimeStopContext(ctx); err != nil {
		return err
	}
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
	if err := verifyRuntimeStopGrant(effect, challenge, proof); err != nil {
		return err
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
	if err := checkRuntimeStopContext(ctx); err != nil {
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
	if err := checkRuntimeStopContext(ctx); err != nil {
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
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: time.Now().UTC(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return err
	}
	chainCoversSettlement := false
	for _, chain := range chains {
		covers := true
		for _, certificate := range chain {
			if certificate.NotAfter.Before(settlementDeadline) {
				covers = false
				break
			}
		}
		if covers {
			chainCoversSettlement = true
			break
		}
	}
	if !chainCoversSettlement {
		return errors.New("runtime stopped proof verified certificate chain expires before its outer settlement deadline")
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("runtime stopped proof worker key is unsupported")
	}
	wire, err := json.Marshal(payload, json.Deterministic(true))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append([]byte("TS-RUNTIME-STOP-V2\x00"), wire...))
	if !ecdsa.VerifyASN1(key, digest[:], proof.Signature) {
		return errors.New("runtime stopped proof worker signature is invalid")
	}
	if err := s.authority.Guard(ctx, epoch); err != nil {
		return err
	}
	return checkRuntimeStopContext(ctx)
}

func runtimeStopDeadline(challenge runtimeStopChallenge, proof executionwire.SignedRuntimeStop) (time.Time, error) {
	if len(proof.CertificateChain) == 0 {
		return time.Time{}, errors.New("runtime stopped proof worker certificate unavailable")
	}
	leaf, err := x509.ParseCertificate(proof.CertificateChain[0])
	if err != nil {
		return time.Time{}, err
	}
	deadline := challenge.issued.Add(10 * time.Second)
	for _, limit := range []time.Time{proof.ClosingGrant.ExpiresAt, leaf.NotAfter} {
		if limit.Before(deadline) {
			deadline = limit
		}
	}
	return deadline, nil
}

func checkRuntimeStopContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// The worker verified this original envelope before observing the stop. Its
// signed digest binds those bytes; root consumers must verify the manager key.
func verifyRuntimeStopGrant(effect authority.RuntimeEffect, challenge runtimeStopChallenge, proof executionwire.SignedRuntimeStop) error {
	wire, err := json.Marshal(proof.ClosingGrant, json.Deterministic(true))
	if err != nil {
		return err
	}
	if proof.Payload.ClosingGrantSHA256 != fmt.Sprintf("%x", sha256.Sum256(wire)) {
		return errors.New("runtime stopped proof differs from its original closing grant digest")
	}
	var response struct {
		Nonce     string         `json:"nonce"`
		Node      string         `json:"node"`
		SessionID string         `json:"session_id"`
		Epoch     uint64         `json:"epoch"`
		Operation string         `json:"operation"`
		Error     string         `json:"error,omitempty"`
		Retryable bool           `json:"retryable,omitzero"`
		Payload   jsontext.Value `json:"payload,omitempty"`
	}
	if err := protocol.DecodeStrict(proof.ClosingGrant.Payload, &response, 512<<10); err != nil {
		return err
	}
	var grant executionwire.WorkerGrantPayload
	if err := protocol.DecodeStrict(response.Payload, &grant, 512<<10); err != nil {
		return err
	}
	expected, err := runtimePayload(effect, grant.Nonce, effect.IssuedAt)
	if err != nil {
		return err
	}
	expected.LeaderEpoch, expected.StopChallenge = challenge.epoch, challenge.nonce
	want, err := json.Marshal(expected, json.Deterministic(true))
	if err != nil {
		return err
	}
	got, err := json.Marshal(grant, json.Deterministic(true))
	if err != nil {
		return err
	}
	region, err := protocol.CanonicalRegion(expected.Identity.Cell)
	envelope := proof.ClosingGrant
	if err != nil || !bytes.Equal(want, got) || response.Operation != "runtime-effect" || response.Error != "" || response.Retryable ||
		response.Node != expected.Identity.HostNode || !entityid.Valid(response.SessionID) || response.Epoch == 0 || len(response.Nonce) != 32 ||
		envelope.SchemaVersion != protocol.EnvelopeSchemaVersion || envelope.Region != region || envelope.Kind != "host.response.runtime-effect" ||
		envelope.Actor != "controller" || envelope.Generation != 0 || envelope.Epoch != response.Epoch ||
		envelope.OperationID != entityid.Derive("host-request", response.Nonce) || envelope.KeyID == "" || envelope.Signature == "" ||
		envelope.IssuedAt.Before(challenge.issued) || envelope.IssuedAt.After(proof.Payload.ObservedAt) ||
		!envelope.ExpiresAt.After(envelope.IssuedAt) || envelope.ExpiresAt.Sub(envelope.IssuedAt) > 10*time.Second ||
		!time.Now().Before(envelope.ExpiresAt) {
		return errors.New("runtime stopped proof closing grant differs from its exact retained challenge and material")
	}
	return nil
}
