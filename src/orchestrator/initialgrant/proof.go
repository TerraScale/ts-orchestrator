package initialgrant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
)

// Proof retains the original owner signature and canonical signed component.
// It cannot authorize a runtime without the fixed root-owned publication and
// the separate durable initial-R1 admission record.
type Proof struct {
	node           string
	public, signed []byte
	config         Config
	component      hostmanifest.ComponentSpec
	identity       nodeauthority.InitialR1Identity
}

func digest(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }

// VerifyProof reuses the nodebootstrap verifier. A valid grant without an
// explicit initial-R1 component returns nil,nil for ordinary host startup.
func VerifyProof(node string, public, signed []byte) (*Proof, error) {
	a, err := nodebootstrap.NewBootstrapAuthority(node, public, signed)
	if err != nil {
		return nil, err
	}
	g := a.Grant()
	manifest, err := hostmanifest.ParseHostManifest(g.Manifest)
	if err != nil {
		return nil, err
	}
	canonical, err := hostmanifest.CanonicalHostManifestJSON(manifest)
	if err != nil || !bytes.Equal(canonical, g.Manifest) {
		return nil, errors.New("initialgrant: original manifest is not canonical")
	}
	for _, spec := range manifest.Components {
		c, initial, err := ComponentConfig(spec)
		if err != nil {
			return nil, err
		}
		if !initial {
			continue
		}
		if c.NodeID != node || spec.User != "terrascale-orchestrator" {
			return nil, errors.New("initialgrant: signed host or service identity differs")
		}
		launch, err := hostmanifest.CanonicalHostManifestJSON(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}})
		if err != nil {
			return nil, err
		}
		scope, _ := json.Marshal(struct {
			Seed, Server, Endpoint, Store, Regional, Profile string
			Budget                                           int64
		}{c.SeedInstance, c.Broker.ServerName, c.Broker.Endpoint, c.Broker.StoreDir, c.Regional.Account, c.ProfileSHA256, c.Broker.StorageBudgetBytes})
		candidate := "global-controller-gru-" + c.Instance
		if c.Role == "participant" {
			candidate = "gru-controller-" + c.Instance
		}
		i := nodeauthority.InitialR1Identity{Role: c.Role, NodeID: node, GrantSHA256: a.Digest(), ManifestSHA256: digest(canonical), LaunchSHA256: digest(launch), CandidateID: candidate, StoreScopeSHA256: digest(scope), IssuedAt: g.IssuedAt, ExpiresAt: g.ExpiresAt}
		return &Proof{node: node, public: append([]byte(nil), public...), signed: append([]byte(nil), signed...), config: c, component: spec, identity: i}, nil
	}
	return nil, nil
}
func (p *Proof) Identity() nodeauthority.InitialR1Identity {
	if p == nil {
		return nodeauthority.InitialR1Identity{}
	}
	return p.identity
}
func (p *Proof) Config() Config {
	if p == nil {
		return Config{}
	}
	return cloneConfig(p.config)
}
func (p *Proof) Component() hostmanifest.ComponentSpec {
	if p == nil {
		return hostmanifest.ComponentSpec{}
	}
	return p.component
}
func cloneConfig(c Config) Config {
	raw, _ := json.Marshal(c)
	var copy Config
	_ = json.Unmarshal(raw, &copy)
	return copy
}

// Publish is called by the existing verified host bootstrap before unit effects.
// The EpochStore callback verifies the pinned grant before publishing its proof.
// Original proof bytes are immutable; publication never introduces a signer.
func Publish(ctx context.Context, epochs *nodeauthority.EpochStore, p *Proof) error {
	if ctx == nil || epochs == nil || p == nil || os.Geteuid() != 0 {
		return errors.New("initialgrant: trusted host proof publication required")
	}
	now := time.Now()
	if now.Before(p.identity.IssuedAt) || !now.Before(p.identity.ExpiresAt) {
		return errors.New("initialgrant: initial grant expired")
	}
	return epochs.AdmitInitialR1WithPublication(ctx, nodeauthority.InitialR1AdmissionDirectory, p.identity, func() error {
		return publishProof(p)
	})
}

type Admission struct {
	proof *Proof
	guard *nodeauthority.InitialR1Guard
}

func (a *Admission) Config() Config {
	if a == nil {
		return Config{}
	}
	return a.proof.Config()
}
func (a *Admission) ExpiresAt() time.Time {
	if a == nil {
		return time.Time{}
	}
	return a.proof.identity.ExpiresAt
}
func (a *Admission) Check(ctx context.Context) error {
	if a == nil || a.guard == nil {
		return errors.New("initialgrant: admitted launch required")
	}
	return a.guard.Check(ctx)
}
func (a *Admission) WithinMutation(ctx context.Context, fn func(context.Context) error) error {
	if a == nil || a.guard == nil {
		return errors.New("initialgrant: admitted launch required")
	}
	return a.guard.WithinMutation(ctx, fn)
}

func admission(ctx context.Context, p *Proof) (*Admission, error) {
	g, err := nodeauthority.NewInitialR1Guard(nodeauthority.InitialR1AdmissionDirectory, p.identity)
	if err != nil {
		return nil, err
	}
	if err = g.Check(ctx); err != nil {
		return nil, err
	}
	return &Admission{proof: p, guard: g}, nil
}

// VerifyMaterial is separate from host launch admission: initial host handoff
// may provision runtime credentials after verifying the signed launch. The
// runtime must call this before starting listeners or opening control stores.
func (a *Admission) VerifyMaterial() error {
	if a == nil || a.proof == nil {
		return errors.New("initialgrant: admitted launch required")
	}
	return verifyMaterial(a.proof.config)
}

// AdmitConfiguration is the actual command entrypoint's admission. Caller data
// supplies no trusted key path: the original signature is read from one fixed
// host-owned publication, then the exact signed configuration is compared.
func AdmitConfiguration(ctx context.Context, raw []byte) (*Admission, error) {
	if _, err := ParseConfig(raw); err != nil {
		return nil, err
	}
	p, err := ReadPublishedProof()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, []byte(p.component.Configuration)) {
		return nil, errors.New("initialgrant: launch configuration differs from original signed component")
	}
	a, err := admission(ctx, p)
	if err != nil {
		return nil, err
	}
	if err = a.VerifyMaterial(); err != nil {
		return nil, err
	}
	if err = a.Check(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

// AdmitComponent protects actual installed releases as well as desired input.
// An ordinary component returns nil,nil. Attempted malformed initial launches
// are rejected rather than silently classified as ordinary.
func AdmitComponent(ctx context.Context, spec hostmanifest.ComponentSpec) (*Admission, error) {
	_, initial, err := ComponentConfig(spec)
	if err != nil {
		return nil, err
	}
	if !initial {
		return nil, nil
	}
	p, err := ReadPublishedProof()
	if err != nil {
		return nil, err
	}
	raw, err := hostmanifest.CanonicalHostManifestJSON(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}})
	if err != nil {
		return nil, err
	}
	if digest(raw) != p.identity.LaunchSHA256 {
		return nil, errors.New("initialgrant: installed launch differs from original signed component")
	}
	return admission(ctx, p)
}

// RetireForReplacement is invoked only inside the existing verified manifest
// handler. It preserves ordinary hosts without a bootstrap proof, requires the
// proof for every initial launch, and delegates exact command binding to the
// existing EpochStore writer. Retirement precedes replacement manifest effects.
func RetireForReplacement(ctx context.Context, epochs *nodeauthority.EpochStore, authorization nodeauthority.CommandAuthorization, command hostmanifest.ApplyManifestCommand, current hostmanifest.HostManifest) error {
	currentInitial := false
	for _, spec := range current.Components {
		_, initial, err := ComponentConfig(spec)
		if err != nil {
			return err
		}
		currentInitial = currentInitial || initial
	}
	nextInitial := false
	for _, spec := range command.Manifest.Components {
		_, initial, err := ComponentConfig(spec)
		if err != nil {
			return err
		}
		if !initial {
			continue
		}
		nextInitial = true
		if _, err = AdmitComponent(ctx, spec); err != nil {
			return err
		}
	}
	if nextInitial {
		return nil
	}
	p, err := ReadPublishedProof()
	if err != nil {
		if !currentInitial && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if p.node != authorization.NodeID {
		if !currentInitial {
			return nil
		}
		return errors.New("initialgrant: retirement host differs")
	}
	if !currentInitial && command.ExpectedManifestSha256 != p.identity.ManifestSHA256 {
		return nil
	}
	if p.config.StorageTransition != (controltransition.Delivery{}) {
		return controltransition.ErrPreparationMissing
	}
	replacement, err := hostmanifest.HostManifestSha256(command.Manifest)
	if err != nil {
		return err
	}
	return epochs.RetireInitialR1(ctx, nodeauthority.InitialR1AdmissionDirectory, p.identity, authorization, command.CommandId, command.ExpectedManifestSha256, replacement)
}
