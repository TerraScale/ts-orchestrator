//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

// Ordinary members start only after the promoted store is available. They do
// not participate in the finite two-peer preparation or fabricate a GRU seed.
func (services *qualificationRuntimeServices) prepareOrdinaryRun(ctx context.Context, guest vmqual.Guest) error {
	bad := errors.New("vmqual: ordinary member requires admitted live R3 authority")
	if ctx == nil {
		return bad
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	services.mu.Lock()
	defer services.mu.Unlock()
	admission := services.controlAdmission
	if services.closed || admission == nil || admission.source == nil {
		return bad
	}
	if _, candidate := admission.candidates[guest.ID]; candidate {
		return nil
	}
	delete(services.ordinaryPrepared, guest.ID)
	run, ok := services.runAdmissions[guest.ID]
	reader, hasReader := admission.authorityReaders[guest.ID]
	if !ok || !hasReader || run.Global != nil || run.Regional.Endpoint != reader.Reader.Endpoint || run.Regional.Account != reader.Reader.Account || run.Regional.ServerName != reader.Reader.ServerName || run.Regional.Connection.PublicNKey == reader.Reader.PublicNKey || run.Regional.Connection.TLS.CertificateSHA256 == reader.Reader.CertificateSHA256 || !admission.source.admissionLive() {
		return bad
	}
	region := strings.ToLower(string(guest.Region))
	store := ""
	for _, member := range admission.source.config.Members {
		if member.HostID == guest.ID && member.Region == region {
			store = member.Store
		}
	}
	if store == "" {
		return bad
	}
	connection, err := admission.source.connect(ctx, store)
	if err != nil {
		return err
	}
	defer connection.Close()
	js, err := connection.JetStream()
	if err != nil {
		return err
	}
	info, err := js.StreamInfo("KV_ORCH_LEADERS", nats.Context(ctx))
	if err != nil || !ordinaryAuthorityR3(info) {
		return errors.Join(bad, err)
	}
	// Exercise the exact identity installed in ts-node, rather than inferring
	// authority-read access from the more capable qualification observer.
	configured, release, err := loadQualificationControlStore(reader)
	if err != nil {
		return err
	}
	defer release()
	source := *admission.source
	source.config.Stores = map[string]bootstrap.ControlNATSStore{store: configured}
	if _, err := source.readLease(ctx, store, region, "authority.regional"); err != nil {
		return err
	}
	if services.ordinaryPrepared == nil {
		services.ordinaryPrepared = map[string]bool{}
	}
	services.ordinaryPrepared[guest.ID] = true
	return nil
}

func ordinaryAuthorityR3(info *nats.StreamInfo) bool {
	if info == nil || info.Config.Replicas != 3 || info.Config.Storage != nats.FileStorage || info.Cluster == nil || info.Cluster.Leader == "" || len(info.Cluster.Replicas) != 2 {
		return false
	}
	seen := map[string]bool{info.Cluster.Leader: true}
	for _, replica := range info.Cluster.Replicas {
		if replica == nil || replica.Name == "" || seen[replica.Name] || !replica.Current || replica.Offline || replica.Lag != 0 {
			return false
		}
		seen[replica.Name] = true
	}
	return true
}

// Called with services.mu held. The finite grant binds the complete production
// manifest; production startup still verifies its real R3 runtime dependencies.
func (services *qualificationRuntimeServices) bootstrapOrdinaryRun(guest vmqual.Guest) (vmimage.TSNodeBootstrap, []vmimage.GuestArtifact, error) {
	bad := errors.New("vmqual: ordinary bootstrap lacks admitted production configuration")
	admission := services.controlAdmission
	if admission == nil || admission.source == nil || !admission.source.admissionLive() || !services.ordinaryPrepared[guest.ID] || services.bootstrapIssuer == nil || services.natsAuthority == nil {
		return vmimage.TSNodeBootstrap{}, nil, bad
	}
	reader, ok := admission.authorityReaders[guest.ID]
	identity := services.natsAuthority.guests[guest.ID]
	membership := services.natsAuthority.memberships[guest.ID]
	engine := services.engineSeeds[guest.ID]
	natsEndpoint, natsOK := services.plan.Endpoint(guest.Region, "nats")
	artifactEndpoint, artifactOK := services.plan.Endpoint(guest.Region, "artifacts")
	if !ok || identity == nil || membership == nil || engine == nil || !natsOK || !artifactOK {
		return vmimage.TSNodeBootstrap{}, nil, bad
	}
	authority, err := services.ordinaryAuthority(guest.ID)
	if err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	run, err := services.prepareRemoteRun(guest, nil, authority.Files)
	if err != nil || run == nil {
		return vmimage.TSNodeBootstrap{}, nil, errors.Join(bad, err)
	}
	if err := engine.ValidateManifest(guest.ID, engine.Address(), run.Manifest); err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	manifest, err := hostmanifest.CanonicalHostManifestJSON(run.Manifest)
	if err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	grant, err := services.bootstrapIssuer.Grant(guest.ID, run.Manifest)
	if err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	trust, err := services.natsAuthority.commandTrust(services.plan, guest.Region)
	if err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	pins := map[string]string{}
	for host, member := range admission.memberships {
		pins[host] = member.PublicKey
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
	return vmimage.TSNodeBootstrap{
		Engine: engine.Clone(), ControllerRun: run.Clone(), OrdinaryAuthority: authority.Clone(),
		InitialGrant:                 &vmimage.TSNodeInitialGrant{PublicKeyPEM: grant.PublicKeyPEM, SignedGrant: grant.SignedGrant},
		MembershipIdentityPrivateKey: bytes.Clone(membership.PrivatePEM), MembershipPins: pins,
		Version: tsNode.manifest.Version, Binary: bytes.Clone(tsNode.binary), SHA256: tsNode.manifest.SHA256, Signature: bytes.Clone(tsNode.signature), ReleasePublicKey: bytes.Clone(services.publicKey),
		Config:              vmimage.TSNodeConfig{AuthorityReader: reader.Reader, AuthorityBucket: "ORCH_LEADERS", CommandTrustKeys: trust, NodeID: guest.ID, NATSURL: "tls://" + net.JoinHostPort(natsEndpoint.GuestAddress, strconv.Itoa(int(natsEndpoint.GuestPort))), HeartbeatInterval: 10 * time.Second, ReconcileInterval: 30 * time.Second},
		DesiredHostManifest: manifest, ArtifactCACertificate: bytes.Clone(services.caCertificate), ArtifactHostAddress: artifactEndpoint.GuestAddress,
		NATSIdentity: &vmimage.TSNodeNATSIdentity{NKeySeed: bytes.Clone(identity.seed), TLSCA: bytes.Clone(services.natsAuthority.ca), TLSCertificate: bytes.Clone(identity.certificate), TLSPrivateKey: bytes.Clone(identity.privateKey)},
	}, artifacts, nil
}
