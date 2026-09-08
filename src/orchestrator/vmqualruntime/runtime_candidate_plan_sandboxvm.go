//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/vmcandidateseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

// prepareCandidate is called before Create allocates or stages a remote guest.
// It observes the original GRU store, then signs the immutable finite candidate
// intent using the persisted issuer. Bootstrap remains an offline consumer.
func (services *qualificationRuntimeServices) prepareCandidate(ctx context.Context, guest vmqual.Guest) error {
	bad := errors.New("vmqual: candidate preparation requires admitted live original GRU source")
	if ctx == nil {
		return bad
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	services.mu.Lock()
	admission, issuer := services.controlAdmission, services.bootstrapIssuer
	closed := services.closed
	services.mu.Unlock()
	if closed || admission == nil || issuer == nil {
		return bad
	}
	admission.prepareMu.Lock()
	defer admission.prepareMu.Unlock()
	sourceHost := ""
	if admission.candidatePlan != nil {
		sourceHost = admission.candidatePlan.SourceNodeID
		found := false
		for _, entry := range admission.candidatePlan.Candidates {
			found = found || entry.Config.NodeID == guest.ID
		}
		// Additional ordinary members require a separate explicit run admission;
		// this planner cannot synthesize a third preparation peer.
		if !found {
			return nil
		}
	} else {
		material, ok := admission.candidates[guest.ID]
		if !ok {
			return nil
		}
		grant, err := transitiongrant.VerifyGrant(material.PublicKeyPEM, material.PreparationGrant)
		if err != nil {
			return err
		}
		sourceHost = grant.Grant.Source.NodeID
	}
	observation, err := services.observeInitialCandidateSource(ctx, sourceHost)
	if err != nil {
		return err
	}
	source, err := issuer.AdmittedGrant(sourceHost)
	if err != nil || !bytes.Equal(source.PublicKeyPEM, admission.ownerPublic) {
		return bad
	}
	proof, err := initialgrant.VerifyProof(sourceHost, source.PublicKeyPEM, source.SignedGrant)
	if err != nil || proof == nil || proof.Config().Role != "seed" {
		return bad
	}
	now := time.Now().UTC()
	lease := observation.Lease
	identity := admission.memberships[sourceHost]
	if identity == nil || observation.HostID != sourceHost || observation.Instance != sourceHost || lease.AuthorityId != "gru-regional" || lease.CandidateId != "gru-controller-"+sourceHost || lease.Validate() != nil || now.Before(lease.IssuedAt) || !now.Before(lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond)) || observation.LeaseRevision == 0 || !observation.Membership.VerifySignedIdentity() || observation.Membership.IdentityPublicKey != identity.PublicKey || observation.Membership.Instance != sourceHost || observation.Membership.AuthorityEpoch != lease.Epoch || !observation.Membership.IsAuthorityLeader {
		return bad
	}
	bundle := admission.candidateBundle
	if admission.candidatePlan != nil {
		bundle, err = issuer.PrepareCandidates(ctx, *admission.candidatePlan)
	} else {
		bundle, err = issuer.AdmitCandidates(ctx, sourceHost, bundle)
	}
	if err != nil {
		return err
	}
	after, err := services.observeInitialCandidateSource(ctx, sourceHost)
	if err != nil {
		return err
	}
	if after.Lease.Epoch != lease.Epoch || after.Lease.CandidateId != lease.CandidateId || after.Lease.LeaseId != lease.LeaseId {
		return bad
	}
	if admission.candidatePlan == nil {
		return nil
	}
	var document struct {
		PublicKeyPEM     string         `json:"publicKeyPem"`
		PreparationGrant jsontext.Value `json:"preparationGrant"`
		Candidates       []struct {
			NodeID         string         `json:"nodeId"`
			Manifest       jsontext.Value `json:"manifest"`
			BootstrapGrant jsontext.Value `json:"bootstrapGrant"`
		} `json:"candidates"`
	}
	if json.Unmarshal(bundle, &document, json.RejectUnknownMembers(true)) != nil || len(document.Candidates) != 2 {
		return bad
	}
	artifacts := map[string]vmimage.GuestArtifact{}
	for _, artifact := range services.artifacts {
		artifacts[artifact.manifest.Component] = artifact.manifest
	}
	materials := map[string]vmcandidateseed.Material{}
	retained := false
	defer func() {
		if !retained {
			for _, material := range materials {
				material.Clear()
			}
		}
	}()
	manifests := map[string][]byte{}
	for _, candidate := range document.Candidates {
		material, err := vmcandidateseed.Load(admission.candidatePlan.PrivateMaterialDirectory, candidate.NodeID, bundle)
		if err != nil {
			return err
		}
		materials[candidate.NodeID] = material
		manifest, err := hostmanifest.ParseHostManifest(candidate.Manifest)
		if err != nil || validateQualificationManifestArtifacts(manifest, artifacts) != nil || !strings.HasPrefix(candidate.NodeID, material.Config.Region+"-") {
			return bad
		}
		manifests[candidate.NodeID] = bytes.Clone(candidate.Manifest)
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if services.closed || services.controlAdmission != admission {
		return bad
	}
	for host, material := range admission.candidates {
		material.Clear()
		delete(admission.candidates, host)
	}
	admission.candidates, admission.candidateManifests, admission.candidateBundle = materials, manifests, bytes.Clone(bundle)
	retained = true
	return nil
}
