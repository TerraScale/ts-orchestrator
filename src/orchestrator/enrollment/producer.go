package enrollment

import (
	"context"
	"time"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/keyrotation"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type CredentialPublisher interface {
	PublishEnrollmentCredential(context.Context, keyrotation.EnrollmentCredentialRequest) (hostsecrets.Entry, error)
}

type Issuer interface {
	Issue(context.Context, security.IdentityRequest) (security.IdentityMaterial, error)
}

type Producer struct { Issuer Issuer; Vault CredentialPublisher; Journal *Journal; Signer *security.CommandSignatureSigner }

// Enroll reserves the slot before issuing provider material. Only Vault
// references and the signed public bootstrap leave this method.
func (p *Producer) Enroll(ctx context.Context, record Record, manifestHostManifest hostmanifest.HostManifest, now time.Time) (Record, PublicBootstrap, error) {
	if p == nil || p.Issuer == nil || p.Vault == nil || p.Journal == nil || p.Signer == nil { return Record{}, PublicBootstrap{}, ErrInvalid }
	reserved, err := p.Journal.Reserve(ctx, record); if err != nil { return Record{}, PublicBootstrap{}, err }
	identity, err := p.Issuer.Issue(ctx, security.IdentityRequest{OperationID: record.OperationID, Generation: record.Generation, NotBefore: record.IssuedAt, ExpiresAt: record.ExpiresAt, IdempotencyKey: "enrollment/" + record.OperationID}); if err != nil { return Record{}, PublicBootstrap{}, err }
	defer clear(identity.WorkloadTLS); defer clear(identity.ControlTLS); defer clear(identity.TrustBundle)
	reserved.IdentityReference = identity.Reference
	for _, item := range []struct{ path string }{{"/etc/terrascale/placement/host.nkey"}, {"/etc/terrascale/terrabase/transition/receipt-signer.key"}} {
		key, e := nkeys.CreateUser(); if e != nil { return Record{}, PublicBootstrap{}, e }
		seed, e := key.Seed(); if e != nil { key.Wipe(); return Record{}, PublicBootstrap{}, e }
		entry, e := p.Vault.PublishEnrollmentCredential(ctx, keyrotation.EnrollmentCredentialRequest{OperationID: record.OperationID, Destination: item.path, Content: []byte(seed)}); key.Wipe(); clear(seed)
		if e != nil { return Record{}, PublicBootstrap{}, e }
		reserved.ManifestReference += entry.SecretID + ":" + entry.SHA256
	}
	public, err := SignPublicBootstrap(p.Signer, reserved, manifestHostManifest, now); if err != nil { return Record{}, PublicBootstrap{}, err }
	reserved.Grant = public.Grant
	_, err = p.Journal.Reserve(ctx, reserved); if err != nil { return Record{}, PublicBootstrap{}, err }
	return reserved, public, nil
}
