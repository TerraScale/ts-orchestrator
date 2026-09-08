//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/vmcandidateseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

// bootstrapCandidate runs with the service lock held. Preparation is admitted
// only for the exact two signed transition peers, never an unadmitted second
// member or the reserved fourth Region.
func (services *qualificationRuntimeServices) bootstrapCandidate(guest vmqual.Guest) (vmimage.TSNodeBootstrap, []vmimage.GuestArtifact, error) {
	bad := errors.New("vmqual: candidate bootstrap requires exact owner-signed preparation and engine admission")
	if services.controlAdmission == nil || services.natsAuthority == nil {
		return vmimage.TSNodeBootstrap{}, nil, bad
	}
	material, ok := services.controlAdmission.candidates[guest.ID]
	manifest := services.controlAdmission.candidateManifests[guest.ID]
	if !ok {
		return services.bootstrapOrdinaryRun(guest)
	}
	if material.Config.Region != strings.ToLower(string(guest.Region)) || material.ValidateManifest(manifest) != nil {
		return vmimage.TSNodeBootstrap{}, nil, bad
	}
	preparation, err := transitiongrant.VerifyGrant(material.PublicKeyPEM, material.PreparationGrant)
	if err != nil || services.bootstrapIssuer == nil || !services.controlReady[preparation.Grant.Source.NodeID] {
		return vmimage.TSNodeBootstrap{}, nil, bad
	}
	source, err := services.bootstrapIssuer.AdmittedGrant(preparation.Grant.Source.NodeID)
	if err != nil || !bytes.Equal(source.PublicKeyPEM, material.PublicKeyPEM) {
		return vmimage.TSNodeBootstrap{}, nil, bad
	}
	proof, err := initialgrant.VerifyProof(preparation.Grant.Source.NodeID, source.PublicKeyPEM, source.SignedGrant)
	if err != nil || proof == nil {
		return vmimage.TSNodeBootstrap{}, nil, bad
	}
	sourceIdentity := proof.Identity()
	expected := preparation.Grant.Source
	if proof.Config().Role != "seed" || proof.Config().Broker.ServerName != expected.ServerName || sourceIdentity.GrantSHA256 != expected.InitialGrantSHA256 || sourceIdentity.StoreScopeSHA256 != expected.StoreScopeSHA256 {
		return vmimage.TSNodeBootstrap{}, nil, bad
	}
	identity := services.natsAuthority.guests[guest.ID]
	membership := services.natsAuthority.memberships[guest.ID]
	natsEndpoint, natsOK := services.plan.Endpoint(guest.Region, "nats")
	artifactEndpoint, artifactOK := services.plan.Endpoint(guest.Region, "artifacts")
	if identity == nil || membership == nil || !natsOK || !artifactOK {
		return vmimage.TSNodeBootstrap{}, nil, bad
	}
	run, err := services.prepareRemoteRun(guest, manifest, material.Files)
	if err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	engine := services.engineSeeds[guest.ID]
	if engine != nil {
		desired, err := hostmanifest.ParseHostManifest(manifest)
		if err != nil {
			return vmimage.TSNodeBootstrap{}, nil, err
		}
		if run != nil {
			err = engine.ValidateStagedManifest(guest.ID, engine.Address(), desired, run.Manifest)
		} else {
			err = engine.ValidateManifest(guest.ID, engine.Address(), desired)
		}
		if err != nil {
			return vmimage.TSNodeBootstrap{}, nil, err
		}
	}
	trust, err := services.natsAuthority.commandTrust(services.plan, guest.Region)
	if err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	pins := map[string]string{}
	for host, admission := range services.controlAdmission.memberships {
		pins[host] = admission.PublicKey
	}
	var tsNode guestArtifactInput
	artifacts := make([]vmimage.GuestArtifact, 0, len(services.artifacts))
	for _, artifact := range services.artifacts {
		artifacts = append(artifacts, artifact.manifest)
		if artifact.manifest.Component == "ts-node" {
			tsNode = artifact
		}
	}
	if len(tsNode.binary) == 0 || len(tsNode.signature) != ed25519.SignatureSize {
		return vmimage.TSNodeBootstrap{}, nil, bad
	}
	copied, err := cloneQualificationCandidate(material)
	if err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	return vmimage.TSNodeBootstrap{
		Engine: engine.Clone(), Candidate: copied, ControllerRun: run.Clone(),
		InitialGrant:                 &vmimage.TSNodeInitialGrant{PublicKeyPEM: bytes.Clone(material.PublicKeyPEM), SignedGrant: bytes.Clone(material.BootstrapGrant)},
		MembershipIdentityPrivateKey: bytes.Clone(membership.PrivatePEM), MembershipPins: pins,
		Version: tsNode.manifest.Version, Binary: bytes.Clone(tsNode.binary), SHA256: tsNode.manifest.SHA256, Signature: bytes.Clone(tsNode.signature), ReleasePublicKey: bytes.Clone(services.publicKey),
		Config:              vmimage.TSNodeConfig{AuthorityReader: material.Reader, AuthorityBucket: "ORCH_LEADERS", CommandTrustKeys: trust, NodeID: guest.ID, NATSURL: "tls://" + net.JoinHostPort(natsEndpoint.GuestAddress, strconv.Itoa(int(natsEndpoint.GuestPort))), HeartbeatInterval: 10 * time.Second, ReconcileInterval: 30 * time.Second},
		DesiredHostManifest: bytes.Clone(manifest), ArtifactCACertificate: bytes.Clone(services.caCertificate), ArtifactHostAddress: artifactEndpoint.GuestAddress,
		NATSIdentity: &vmimage.TSNodeNATSIdentity{NKeySeed: bytes.Clone(identity.seed), TLSCA: bytes.Clone(services.natsAuthority.ca), TLSCertificate: bytes.Clone(identity.certificate), TLSPrivateKey: bytes.Clone(identity.privateKey)},
	}, artifacts, nil
}
func cloneQualificationCandidate(material vmcandidateseed.Material) (*vmcandidateseed.Material, error) {
	// Config has nested pointer fields; canonical roundtrip avoids handing callers
	// mutable aliases to the owner-pinned admission retained by the service.
	raw, err := json.Marshal(material)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var copy vmcandidateseed.Material
	if err := json.Unmarshal(raw, &copy); err != nil {
		return nil, err
	}
	return &copy, nil
}
