package vmqualbootstrap

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/candidateplan"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"time"
)

// PrepareCandidates keeps the persisted owner signer encapsulated. The source
// must already have an issued grant; the caller must observe its actual initial
// runtime before invoking this method. Returned peer grants are registered with
// the same finite command issuer used for GRU activation, never a regional lease.
func (i *Issuer) PrepareCandidates(ctx context.Context, plan candidateplan.Plan) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("vmqual: candidate context missing")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	source, ok := i.grants[plan.SourceNodeID]
	if i.signer == nil || i.persistent == nil || !ok || plan.PrivateMaterialDirectory == "" {
		return nil, errors.New("vmqual: persisted issued source required for candidate planning")
	}
	bundle, err := candidateplan.Prepare(ctx, plan, i.public, source.SignedGrant, i.signer)
	if err != nil {
		return nil, err
	}
	return i.admitCandidates(plan.SourceNodeID, bundle)
}

// AdmitCandidates registers an already signed preparation bundle only against
// this issuer's exact existing initial source grant. It grants only the finite
// commands that the candidate's original bootstrap grant permits.
func (i *Issuer) AdmitCandidates(ctx context.Context, sourceHost string, bundle []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("vmqual: candidate context missing")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.admitCandidates(sourceHost, bundle)
}
func (i *Issuer) admitCandidates(sourceHost string, bundle []byte) ([]byte, error) {
	source, ok := i.grants[sourceHost]
	if i.signer == nil || i.persistent == nil || !ok || len(bundle) > 2<<20 {
		return nil, errors.New("vmqual: persisted candidate source missing")
	}
	proof, err := initialgrant.VerifyProof(sourceHost, i.public, source.SignedGrant)
	if err != nil || proof == nil || proof.Config().Role != "seed" {
		return nil, errors.New("vmqual: initial candidate source proof invalid")
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
	if json.Unmarshal(bundle, &document, json.RejectUnknownMembers(true)) != nil || len(document.Candidates) != 2 || !bytes.Equal([]byte(document.PublicKeyPEM), i.public) {
		return nil, errors.New("vmqual: candidate bundle differs from owner")
	}
	prepared, err := transitiongrant.VerifyGrant(i.public, document.PreparationGrant)
	if err != nil {
		return nil, err
	}
	identity := proof.Identity()
	expected := prepared.Grant.Source
	if expected.NodeID != sourceHost || expected.InitialGrantSHA256 != identity.GrantSHA256 || expected.StoreScopeSHA256 != identity.StoreScopeSHA256 || expected.ServerName != proof.Config().Broker.ServerName {
		return nil, errors.New("vmqual: candidate preparation source differs from issued initial grant")
	}
	seen := map[string]bool{}
	for _, candidate := range document.Candidates {
		manifest, err := hostmanifest.ParseHostManifest(candidate.Manifest)
		if err != nil {
			return nil, err
		}
		var candidateConfig transitiongrant.Config
		found := false
		for _, component := range manifest.Components {
			config, isCandidate, err := transitiongrant.ComponentConfig(component)
			if err != nil {
				return nil, err
			}
			if isCandidate {
				if found {
					return nil, errors.New("vmqual: duplicate candidate role")
				}
				found = true
				candidateConfig = config
			}
		}
		if !found || seen[candidateConfig.Region] {
			return nil, errors.New("vmqual: duplicate or missing candidate Region")
		}
		seen[candidateConfig.Region] = true
		peer, err := bootstrap.PlanControlCandidatePeer(candidateConfig, i.public, candidate.BootstrapGrant)
		if err != nil {
			return nil, err
		}
		if err := prepared.CheckCandidate(time.Now().UTC(), candidateConfig, peer.BootstrapGrantSHA256, peer.PreparedManifestSHA256); err != nil {
			return nil, err
		}
		material := Material{PublicKeyPEM: bytes.Clone(i.public), SignedGrant: bytes.Clone(candidate.BootstrapGrant)}
		if prior, ok := i.grants[candidate.NodeID]; ok && !bytes.Equal(prior.SignedGrant, material.SignedGrant) {
			return nil, errors.New("vmqual: existing finite candidate grant cannot be replaced")
		}
		retained, err := i.persistent.saveGrant(candidate.NodeID, manifest, material)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(retained.SignedGrant, material.SignedGrant) {
			return nil, errors.New("vmqual: original candidate signature differs from persisted bundle")
		}
		i.grants[candidate.NodeID] = retained
	}
	return bytes.Clone(bundle), nil
}
