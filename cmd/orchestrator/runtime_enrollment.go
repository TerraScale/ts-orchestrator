package main

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/brokeradmission"
	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/keyrotation"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type productionEnrollmentFile struct {
	BrokerIDs     []string                       `json:"broker_ids"`
	SignerFile    string                         `json:"signer_file"`
	PublicKeyFile string                         `json:"public_key_file"`
	Templates     map[string]enrollment.Template `json:"templates"`
}
type computeProjection func(context.Context, estate.Region) (ocireconcile.ComputeDeclared, error)
type computeTargetProjection func(context.Context, estate.Region) (uint16, error)
type productionEnrollmentProjection struct {
	publishGrants func(context.Context) error
	journal       interface {
		Read(context.Context) (enrollment.State, error)
		Retire(context.Context, string, int, hostremoval.Operation) error
	}
	removals interface {
		Load(context.Context, string) (hostremoval.Operation, error)
	}
	gateways             map[string]ocireconcile.ComputeGateway
	mu                   sync.Mutex
	producer             *enrollment.Producer
	templates            map[string]enrollment.Template
	compute              productionGlobalComputeFile
	environment, cluster string
	generation           uint64
	targets              func(context.Context) (map[string]autoscale.Target, error)
	now                  func() time.Time
}

func newProductionEnrollmentProjection(ctx context.Context, session globalWorkerSession, global *productionGlobalFile, environment, cluster string) (*productionEnrollmentProjection, func() error, error) {
	config := global.Compute.Enrollment
	if config == nil || config.SignerFile == "" || config.PublicKeyFile == "" || len(config.Templates) == 0 || len(config.BrokerIDs) == 0 {
		return nil, nil, errors.New("runtime enrollment: signed bootstrap templates and delegated signer are required")
	}
	signer, err := security.LoadCommandSignatureSignerPEM(config.SignerFile)
	if err != nil {
		return nil, nil, err
	}
	fail := func(e error) (*productionEnrollmentProjection, func() error, error) {
		_ = signer.Close()
		return nil, nil, e
	}
	public, err := bootstrapcredentials.ReadFile(config.PublicKeyFile, false, 32<<10)
	if err != nil {
		return fail(err)
	}
	authority := authorityjournal.Config{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId}
	journal, err := enrollment.NewJournal(authority)
	if err != nil {
		return fail(err)
	}
	verifier, err := brokeradmission.NewVerifier(public, signer.PublicKeyID())
	if err != nil {
		return fail(err)
	}
	seenBrokers := map[string]bool{}
	for _, id := range config.BrokerIDs {
		if _, _, err := brokeradmission.ReaderPermissions(id); err != nil || seenBrokers[id] {
			return fail(brokeradmission.ErrInvalid)
		}
		seenBrokers[id] = true
	}
	grants, err := brokeradmission.NewPublisher(authority, signer, verifier, environment, cluster)
	if err != nil {
		return fail(err)
	}
	authority.StateKey = "host-removal"
	removals, err := hostremoval.New(authority)
	if err != nil {
		return fail(err)
	}
	authority.StateKey = "autoscale"
	targets, err := authorityjournal.New(authority, func() map[string]autoscale.Target { return map[string]autoscale.Target{} }, func(map[string]autoscale.Target) error { return nil })
	if err != nil {
		return fail(err)
	}
	vaultConfig := global.Rotation.Vault
	credentials, err := hostsecrets.NewInstanceConfiguration(ctx, vaultConfig.Region)
	if err != nil {
		return fail(err)
	}
	vault, err := keyrotation.NewOCICapabilityVault(keyrotation.OCICapabilityVaultConfig{Provider: credentials, Region: vaultConfig.Region, CompartmentID: vaultConfig.CompartmentID, VaultID: vaultConfig.VaultID, KeyID: vaultConfig.KeyID, Authority: session.CheckEffectAuthority})
	if err != nil {
		return fail(err)
	}
	issuerConfig := global.Rotation.Issuer
	issuerCredentials := credentials
	if issuerConfig.Region != vaultConfig.Region {
		issuerCredentials, err = hostsecrets.NewInstanceConfiguration(ctx, issuerConfig.Region)
		if err != nil {
			return fail(err)
		}
	}
	producer := &enrollment.Producer{Journal: journal, Vault: vault, Signer: signer, Check: session.CheckEffectAuthority}
	producer.Issuer = func(record enrollment.Record) (enrollment.Issuer, error) {
		principals := make([]keyrotation.OCIIdentityPrincipal, 0, len(enrollment.TLSRoles))
		for _, role := range enrollment.TLSRoles {
			principals = append(principals, keyrotation.OCIIdentityPrincipal{ID: role.Name, SPIFFEID: enrollment.Identity(record, role.Name)})
		}
		return keyrotation.NewOCIIdentityIssuer(keyrotation.OCIIdentityIssuerConfig{Provider: issuerCredentials, Region: issuerConfig.Region, CompartmentID: issuerConfig.CompartmentID, CertificateAuthorityID: issuerConfig.CertificateAuthorityID, Principals: principals, KeyVault: vault, Authority: session.CheckEffectAuthority})
	}
	templates := map[string]enrollment.Template{}
	for region, template := range config.Templates {
		files := map[string]string{}
		for path, content := range template.Files {
			files[path] = content
		}
		files["/etc/terrascale/ts-node-bootstrap/owner.pub"] = string(public)
		template.Files = files
		templates[region] = template
	}
	projection := &productionEnrollmentProjection{journal: journal, removals: removals, producer: producer, templates: templates, compute: global.Compute, environment: environment, cluster: cluster, generation: uint64(session.Lease.Epoch), targets: targets.Read, now: time.Now}
	brokers := slices.Clone(config.BrokerIDs)
	projection.publishGrants = func(ctx context.Context) error {
		state, err := journal.Read(ctx)
		if err != nil {
			return err
		}
		wire, err := grants.Publish(ctx, state)
		if err != nil {
			return err
		}
		if err := session.CheckEffectAuthority(ctx); err != nil {
			return err
		}
		if err := brokeradmission.Acknowledged(ctx, session.Connection, brokers, wire, verifier); err != nil {
			return errors.Join(errBrokerGrantsPending, err)
		}
		return session.CheckEffectAuthority(ctx)
	}
	return projection, signer.Close, nil
}
func (p *productionEnrollmentProjection) Declared(ctx context.Context, region estate.Region) (ocireconcile.ComputeDeclared, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := ocireconcile.ComputeDeclared{}
	if p.producer == nil || p.targets == nil || p.now == nil {
		return result, enrollment.ErrInvalid
	}
	targets, err := p.targets(ctx)
	if err != nil {
		return result, err
	}
	if target, ok := targets[region.Code]; ok {
		if target.Region != region.Code || target.Members < 2 || target.Members > 1024 {
			return result, enrollment.ErrInvalid
		}
		region.Members.Count = uint16(target.Members)
	}
	template, ok := p.templates[region.Code]
	if !ok {
		return result, errors.New("runtime enrollment: Region template missing")
	}
	result = ocireconcile.ComputeDeclared{Region: region, ImageID: p.compute.ImageID, FallbackImageID: p.compute.FallbackImageID, CloudInitByMember: map[int]string{}, MemberBindings: map[int]ocireconcile.MemberBinding{}, CandidatesByMember: map[int][]ocireconcile.MemberLaunchCandidate{}}
	for slot := 1; slot <= int(region.Members.Count); slot++ {
		now := p.now().UTC().Truncate(time.Second)
		if completed, ok := targets[region.Code].CompletedRemovals[slot]; ok {
			if err := p.prepareReenrollment(ctx, region.Code, slot, completed); err != nil {
				return ocireconcile.ComputeDeclared{}, err
			}
		}
		record, public, err := p.producer.Enroll(ctx, enrollment.Record{Environment: p.environment, Cluster: p.cluster, Region: region.Code, Slot: slot, Generation: p.generation, IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour)}, template)
		if err != nil {
			return ocireconcile.ComputeDeclared{}, err
		}
		result.MemberBindings[slot] = ocireconcile.MemberBinding{ServerIdentity: enrollment.Identity(record, "member"), Environment: record.Environment, Cluster: record.Cluster, MemberID: record.MemberID, CellID: record.Region, Generation: record.Generation}
		byArch := map[string]string{}
		for _, arch := range []string{"arm64", "amd64"} {
			artifact, ok := p.compute.Artifacts[arch]
			if !ok {
				return ocireconcile.ComputeDeclared{}, enrollment.ErrInvalid
			}
			files := make([]ocireconcile.BootstrapHostFile, 0, len(public.ArchitectureFiles[arch]))
			for path, content := range public.ArchitectureFiles[arch] {
				files = append(files, ocireconcile.BootstrapHostFile{Path: path, Content: slices.Clone(content)})
			}
			seed, e := ocireconcile.TSNodeCloudInit(artifact.Version, artifact.SHA256, artifact.URL, artifact.URL+".sig", artifact.PublicKey, files)
			if e != nil {
				return ocireconcile.ComputeDeclared{}, e
			}
			byArch[arch] = seed
		}
		result.CloudInitByMember[slot] = byArch["arm64"]
		for _, candidate := range region.Members.Candidates {
			image := result.ImageID
			if candidate.Architecture == "amd64" {
				image = result.FallbackImageID
			}
			result.CandidatesByMember[slot] = append(result.CandidatesByMember[slot], ocireconcile.MemberLaunchCandidate{Shape: candidate.Shape, ImageID: image, Architecture: candidate.Architecture, QualificationRef: candidate.QualificationRef, CostRef: candidate.CostRef, CloudInitBase64: byArch[candidate.Architecture]})
		}
	}
	result.Candidates = slices.Clone(result.CandidatesByMember[1])
	if p.publishGrants != nil {
		if err := p.publishGrants(ctx); err != nil {
			return ocireconcile.ComputeDeclared{}, err
		}
	}
	return result, nil
}

var errBrokerGrantsPending = errors.New("runtime enrollment: broker grant acknowledgements pending")

func (p *productionEnrollmentProjection) retireCompleted(ctx context.Context, operation string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	removal, err := p.removals.Load(ctx, operation)
	if err != nil {
		return err
	}
	if removal.Stage != hostremoval.StageComplete {
		return enrollment.ErrInvalid
	}
	state, err := p.journal.Read(ctx)
	if err != nil {
		return err
	}
	for _, record := range state.Records {
		if enrollment.Identity(record, "member") != removal.MemberIdentity || record.Generation != removal.Generation {
			continue
		}
		if err := p.prepareReenrollment(ctx, record.Region, record.Slot, autoscale.CompletedRemoval{OperationID: operation, ResourceID: removal.ResourceID}); err != nil {
			return err
		}
		return p.publishGrants(ctx)
	}
	if _, ok := state.Retired[operation]; ok {
		return p.publishGrants(ctx)
	}
	return enrollment.ErrInvalid
}

// TargetCount reads the durable target without enrolling slots or constructing
// provider credentials. Typed compute reconciliation continues to use Declared
// for real launches.
func (p *productionEnrollmentProjection) TargetCount(ctx context.Context, region estate.Region) (uint16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.targets == nil {
		return 0, errors.New("runtime enrollment: durable target source is unavailable")
	}
	targets, err := p.targets(ctx)
	if err != nil {
		return 0, err
	}
	target, ok := targets[region.Code]
	if !ok {
		return region.Members.Count, nil
	}
	if target.Region != region.Code || target.Members < 2 || target.Members > 1024 {
		return 0, enrollment.ErrInvalid
	}
	return uint16(target.Members), nil
}

// prepareReenrollment only retires an incarnation which the durable removal
// owner completed and the exact provider still reports terminal. Completed
// references remain harmless on retries after a successor reservation exists.
func (p *productionEnrollmentProjection) prepareReenrollment(ctx context.Context, region string, slot int, completed autoscale.CompletedRemoval) error {
	if p.journal == nil || p.removals == nil || completed.OperationID == "" || completed.ResourceID == "" {
		return enrollment.ErrInvalid
	}
	state, err := p.journal.Read(ctx)
	if err != nil {
		return err
	}
	if archived, ok := state.Retired[completed.OperationID]; ok {
		if archived.Region != region || archived.Slot != slot || archived.Retirement == nil || archived.Retirement.ResourceID != completed.ResourceID {
			return enrollment.ErrInvalid
		}
		return nil
	}
	removal, err := p.removals.Load(ctx, completed.OperationID)
	if err != nil {
		return err
	}
	if removal.Stage != hostremoval.StageComplete || removal.OperationID != completed.OperationID || removal.ResourceID != completed.ResourceID {
		return enrollment.ErrInvalid
	}
	observer, ok := p.gateways[region].(exactOCIMemberObserver)
	if !ok {
		return enrollment.ErrInvalid
	}
	current, err := observer.ObserveMember(ctx, completed.ResourceID)
	if !errors.Is(err, ocireconcile.ErrMemberTerminated) || current.ID != completed.ResourceID || current.LifecycleState != "TERMINATED" || current.ETag == "" {
		if err != nil {
			return err
		}
		return enrollment.ErrInvalid
	}
	return p.journal.Retire(ctx, region, slot, removal)
}
