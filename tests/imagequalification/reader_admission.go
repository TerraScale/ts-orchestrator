package imagequalification

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/qualification/hostadmission"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
)

// readerProofs refines only this private confined lifecycle's actual SDK results.
// It cannot adopt caller-built host registration or supply production identity.
func (c *cloud) readerProofs(ctx context.Context, j journal, confined confinement.Verified, signer ed25519.PrivateKey) (map[string][]byte, error) {
	p := c.prepared
	if err := c.check(ctx, false); err != nil {
		return nil, err
	}
	if p.approval.Purpose != qualification.RootCredentialBoundaryPurpose || len(p.principalWire) == 0 || len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("original purpose-specific principal and qualifier required")
	}
	if _, err := validatedConfinement(ctx, p, j, confined); err != nil {
		return nil, err
	}
	original, err := trust.DecodeEnvelope(p.approvalWire)
	if err != nil {
		return nil, err
	}
	signerID, err := trust.KeyID(signer.Public().(ed25519.PublicKey))
	if err != nil || signerID != original.KeyID {
		return nil, errors.New("host read attenuation requires the original qualifier")
	}
	if _, err := c.image(ctx, j.ImageID); err != nil {
		return nil, err
	}
	var hosts []hostadmission.BoundHost
	for _, spec := range p.approval.Hosts {
		observed, err := c.observeHost(ctx, j, spec)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, hostadmission.BoundHost{Name: observed.Name, InstanceID: observed.InstanceID, ImageID: observed.ImageID, PrivateIP: observed.PrivateIP})
	}
	// Every attenuation shares the original one-hour run cap; re-signing cannot renew it.
	expires := original.IssuedAt.Add(time.Hour)
	if p.expires.Before(expires) {
		expires = p.expires
	}
	now := c.now().UTC()
	if !now.Before(expires) {
		return nil, errors.New("finite original startup reader interval expired")
	}
	result := make(map[string][]byte, len(hosts))
	for _, host := range hosts {
		binding := hostadmission.Binding{Schema: hostadmission.BindingSchema, Purpose: p.approval.Purpose, RunID: p.approval.RunID,
			PreparationSHA256: hashBytes(p.principalWire), ApprovalSHA256: p.approvalSHA256, HostName: host.Name, Hosts: hosts}
		payload, err := json.Marshal(binding, json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		envelope, err := trust.Sign(payload, ApprovalScope(p.approval.RunID, p.approval.Candidate), now, expires, signer)
		if err != nil {
			return nil, err
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			return nil, err
		}
		proof := hostadmission.Proof{Schema: hostadmission.ProofSchema, Preparation: p.principalWire, Approval: p.approvalWire, Delegation: p.delegationWire, Binding: wire}
		encoded, err := json.Marshal(proof, json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		if len(encoded) > hostadmission.MaxProofBytes {
			return nil, errors.New("finite reader proof exceeds installed input bound")
		}
		result[host.InstanceID] = encoded
	}
	return result, nil
}
