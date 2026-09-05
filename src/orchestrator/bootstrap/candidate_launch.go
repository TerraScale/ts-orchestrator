package bootstrap

import (
	"encoding/json"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

// PlanControlCandidateManifest binds an explicit SFO/FRA preparation identity
// and grant file references before the owner signs initial host admission.
// Grant bytes and their digest stay outside the manifest to avoid a hash cycle.
// This preparation launch grants neither a regional lease nor serving readiness.
func PlanControlCandidateManifest(input hostmanifest.HostManifest, config transitiongrant.Config) (hostmanifest.HostManifest, error) {
	if err := config.Validate(); err != nil {
		return hostmanifest.HostManifest{}, err
	}
	raw, err := hostmanifest.CanonicalHostManifestJSON(input)
	if err != nil {
		return hostmanifest.HostManifest{}, err
	}
	planned, err := hostmanifest.ParseHostManifest(raw)
	if err != nil {
		return hostmanifest.HostManifest{}, err
	}
	settings, err := json.Marshal(config)
	if err != nil {
		return hostmanifest.HostManifest{}, err
	}
	found := false
	for i := range planned.Components {
		component := &planned.Components[i]
		if component.Name != "orchestrator" {
			continue
		}
		if found {
			return hostmanifest.HostManifest{}, errors.New("bootstrap: repeated candidate orchestrator")
		}
		found = true
		component.Arguments = transitiongrant.Arguments
		component.Configuration = string(settings)
		if _, _, err := transitiongrant.ComponentConfig(*component); err != nil {
			return hostmanifest.HostManifest{}, err
		}
	}
	if !found {
		return hostmanifest.HostManifest{}, errors.New("bootstrap: candidate orchestrator component missing")
	}
	return PlanControlLaunchManifest(planned)
}

// PlanControlCandidatePeer derives the exact grant bindings after the owner has
// signed the prepared host manifest. It verifies the original bootstrap grant;
// caller-provided digest strings cannot substitute for that signed admission.
func PlanControlCandidatePeer(config transitiongrant.Config, bootstrapPublicPEM, signedBootstrapGrant []byte) (transitiongrant.Peer, error) {
	if err := config.Validate(); err != nil {
		return transitiongrant.Peer{}, err
	}
	authority, err := nodebootstrap.NewBootstrapAuthority(config.NodeID, bootstrapPublicPEM, signedBootstrapGrant)
	if err != nil {
		return transitiongrant.Peer{}, err
	}
	manifest, err := hostmanifest.ParseHostManifest(authority.Grant().Manifest)
	if err != nil {
		return transitiongrant.Peer{}, err
	}
	found := false
	for _, component := range manifest.Components {
		actual, candidate, err := transitiongrant.ComponentConfig(component)
		if err != nil {
			return transitiongrant.Peer{}, err
		}
		if !candidate {
			continue
		}
		if found || actual != config {
			return transitiongrant.Peer{}, errors.New("bootstrap: signed candidate configuration differs from preparation identity")
		}
		found = true
	}
	if !found {
		return transitiongrant.Peer{}, errors.New("bootstrap: signed bootstrap grant contains no candidate preparation")
	}
	digest, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil {
		return transitiongrant.Peer{}, err
	}
	return transitiongrant.Peer{Region: config.Region, NodeID: config.NodeID, ServerName: config.ServerName, BootstrapGrantSHA256: authority.Digest(), PreparedManifestSHA256: digest}, nil
}
