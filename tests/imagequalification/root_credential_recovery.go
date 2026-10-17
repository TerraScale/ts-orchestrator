package imagequalification

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/principal"
)

// recoverRootCredentialBoundary performs cleanup only. It needs no signing key,
// local disk archives, create replay or new authority after the original expiry.
func recoverRootCredentialBoundary(ctx context.Context, v principal.VerifiedPreparation, preparationWire, delegationWire []byte, roots trust.Keyring, issuer *ociclient.Factory, paths rootCredentialPaths) (bool, error) {
	if _, err := os.Stat(paths.Journal); errors.Is(err, os.ErrNotExist) {
		if _, approvalErr := os.Stat(paths.Approval); errors.Is(approvalErr, os.ErrNotExist) {
			return false, nil
		} else if approvalErr != nil {
			return true, approvalErr
		}
		return true, err
	} else if err != nil {
		return true, err
	}
	wire, err := os.ReadFile(paths.Approval)
	if err != nil {
		return true, err
	}
	p, err := cleanupApproval(v, preparationWire, delegationWire, wire, roots, time.Now().UTC())
	if err != nil {
		return true, err
	}
	if _, err := (&cloud{prepared: p}).loadExisting(paths.Journal); err != nil {
		return true, err
	}
	cleanup, cancel := context.WithDeadline(context.Background(), p.approval.CleanupUntil)
	defer cancel()
	producer := principal.New(issuer)
	issuer, err = producer.CleanupObserver(cleanup, v, paths.PrincipalDirectory)
	if err != nil {
		return true, err
	}
	producer = principal.New(issuer)
	if err := producer.CleanupReaders(cleanup, v, paths.PrincipalDirectory); err != nil {
		return true, err
	}
	result, err := producer.ResumeForCleanup(cleanup, v, paths.PrincipalDirectory)
	if errors.Is(err, principal.ErrCleanupPrincipalUnavailable) {
		observer, observeErr := issuer.ForRegion(p.approval.OCIRegion)
		if observeErr != nil {
			return true, observeErr
		}
		if err := verifyCompletedCleanup(cleanup, p, observer, paths.Journal); err != nil {
			return true, err
		}
		_, err = producer.Cleanup(cleanup, v, paths.PrincipalDirectory)
		return true, err
	}
	if err != nil {
		return true, err
	}
	if result.Receipt().Principal != p.approval.Principal || result.Receipt().Group != p.approval.Group || result.Receipt().PolicyID != p.approval.PolicyID {
		return true, errors.New("cleanup principal differs from exact original signed host approval")
	}
	scope, err := p.ConfinementScope(paths.Journal)
	if err != nil {
		return true, err
	}
	verified, err := confinement.Observe(cleanup, issuer, result.CandidateFactory(), scope)
	if err != nil {
		return true, err
	}
	c, err := newConfinedCloud(cleanup, p, verified, paths.Journal)
	if err != nil {
		return true, err
	}
	observer, err := issuer.ForRegion(p.approval.OCIRegion)
	if err != nil {
		return true, err
	}
	if err := c.superviseRetainedImage(ctx, paths.Journal, observer); err != nil {
		return true, err
	}
	_, err = producer.Cleanup(cleanup, v, paths.PrincipalDirectory)
	return true, err
}

func cleanupApproval(v principal.VerifiedPreparation, preparationWire, delegationWire, wire []byte, roots trust.Keyring, now time.Time) (Prepared, error) {
	var empty Prepared
	e, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return empty, err
	}
	original, err := trust.DecodeEnvelope(preparationWire)
	if err != nil {
		return empty, err
	}
	prep := v.Preparation()
	if !now.Before(prep.CleanupUntil) {
		return empty, errors.New("original cleanup authority expired")
	}
	if v.SHA256() != hashBytes(preparationWire) || e.KeyID != original.KeyID || e.IssuedAt.Before(original.IssuedAt) || e.ExpiresAt.After(prep.ExpiresAt) {
		return empty, errors.New("cleanup approval changes original signer or create interval")
	}
	policy := trust.Policy{MaxLifetime: maxRunLifetime}
	var payload []byte
	var issued, expires = e.IssuedAt, e.ExpiresAt
	if len(delegationWire) == 0 {
		payload, err = trust.VerifyCurrent(e, ApprovalScope(prep.RunID, prep.Candidate), roots, e.IssuedAt, policy)
	} else {
		de, decodeErr := trust.DecodeEnvelope(delegationWire)
		if decodeErr != nil {
			return empty, decodeErr
		}
		delegation, verifyErr := trust.VerifyDelegationCurrent(de, roots, e.IssuedAt, policy)
		if verifyErr != nil {
			return empty, verifyErr
		}
		payload, err = trust.VerifyDelegatedCurrent(e, ApprovalScope(prep.RunID, prep.Candidate), delegation, e.IssuedAt, policy)
		if de.IssuedAt.After(issued) {
			issued = de.IssuedAt
		}
		if de.ExpiresAt.Before(expires) {
			expires = de.ExpiresAt
		}
	}
	if err != nil {
		return empty, err
	}
	var a Approval
	if err := protocol.DecodeStrict(payload, &a, trust.MaxPayloadBytes); err != nil {
		return empty, err
	}
	if err := a.validate(); err != nil {
		return empty, err
	}
	statements := confinement.RequiredStatements(confinement.Scope{RunID: prep.RunID, Group: a.Group, Compartment: prep.Compartment, Bucket: prep.Bucket, Object: prep.Object, ExpiresAt: prep.ExpiresAt, CleanupUntil: prep.CleanupUntil})
	want, err := json.Marshal(approvalFromPrincipal(prep, principal.Receipt{Principal: a.Principal, Group: a.Group, PolicyID: a.PolicyID, PolicyStatements: statements}), json.Deterministic(true))
	if err != nil {
		return empty, err
	}
	got, err := json.Marshal(a, json.Deterministic(true))
	if err != nil || !bytes.Equal(want, got) {
		return empty, errors.New("cleanup approval differs from original preparation and canonical finite policy")
	}
	cloned := maps.Clone(roots)
	for id, key := range cloned {
		cloned[id] = slices.Clone(key)
	}
	return Prepared{approval: a, issuedAt: issued, expires: expires, approvalSHA256: hashBytes(wire), approvalWire: bytes.Clone(wire), principalWire: bytes.Clone(preparationWire), delegationWire: bytes.Clone(delegationWire), roots: cloned}, nil
}
