package main

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/reaper"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/restoresnapshot"
)

// Recovery configuration carries file references and exact bucket ownership
// identities. Admission reads credentials but never contacts a provider.
type productionRecoveryMailFile struct {
	OCIRegion         string `json:"oci_region"`
	Endpoint          string `json:"endpoint"`
	CompartmentID     string `json:"compartment_id"`
	Sender            string `json:"sender"`
	OperatorRecipient string `json:"operator_recipient"`
	SigningKeyIDFile  string `json:"signing_key_id_file"`
	SigningKeyPEMFile string `json:"signing_key_pem_file"`
}
type productionRecoverySnapshotRegionFile struct {
	productionDeliveryObjectRegionFile
	BucketResourceID    string `json:"bucket_resource_id"`
	OwnershipGeneration uint64 `json:"ownership_generation"`
}
type productionRecoveryFile struct {
	PolicyEndpoint         string                                 `json:"policy_endpoint"`
	PolicyServiceKeyFile   string                                 `json:"policy_service_key_file"`
	Environment            string                                 `json:"environment"`
	Mail                   productionRecoveryMailFile             `json:"mail"`
	SnapshotRegions        []productionRecoverySnapshotRegionFile `json:"snapshot_regions"`
	SourceRegion           string                                 `json:"source_region"`
	SnapshotStream         string                                 `json:"snapshot_stream"`
	SnapshotPrefix         string                                 `json:"snapshot_prefix"`
	SnapshotMaxBytes       int64                                  `json:"snapshot_max_bytes"`
	SnapshotTimeoutSeconds int64                                  `json:"snapshot_timeout_seconds"`
	ControlPlaneID         string                                 `json:"control_plane_id"`
	SampleSize             int                                    `json:"sample_size"`
	Seed                   int64                                  `json:"seed"`
}

// This bundle deliberately excludes database and branch authorities: the root
// must assemble those concrete producers before constructing either worker.
type productionRecoverySupport struct {
	Policy          *reaper.LifecyclePolicyClient
	environment     string
	Mail            *reaper.OCIMailAdapter
	Pager           *restoredrill.OCIEmailPager
	Journal         *restoredrill.NATSJournal
	Snapshotter     *restoredrill.NATSJetStreamSnapshotter
	SnapshotMirror  *restoresnapshot.Store
	SnapshotRegions []string
	Drill           restoredrill.Config
	ReaperState     reaper.NATSStateStoreConfig
}

func (f productionRecoveryMailFile) adapter(check func(context.Context) error) (*reaper.OCIMailAdapter, error) {
	if !filepath.IsAbs(f.SigningKeyIDFile) || !filepath.IsAbs(f.SigningKeyPEMFile) || f.Endpoint != "https://cell0.submit.email."+f.OCIRegion+".oci.oraclecloud.com" {
		return nil, errors.New("recovery email requires exact regional OCI endpoint and absolute credential references")
	}
	// Reuse strict RSA file parsing without making an Object Storage request.
	credentials, err := (productionDeliveryObjectRegionFile{OCIRegion: f.OCIRegion, Endpoint: "https://objectstorage." + f.OCIRegion + ".oraclecloud.com", SigningKeyIDFile: f.SigningKeyIDFile, SigningKeyPEMFile: f.SigningKeyPEMFile}).transport()
	if err != nil {
		return nil, err
	}
	signer, ok := credentials.Signer.(*provider.InstancePrincipalSigner)
	if !ok {
		return nil, errors.New("recovery signing identity is unavailable")
	}
	return reaper.NewOCIMailAdapter(reaper.OCIMailConfig{Endpoint: f.Endpoint, CompartmentID: f.CompartmentID, Sender: f.Sender, KeyID: signer.KeyID, PrivateKey: signer.Key, CheckEffectAuthority: check})
}
func (f productionRecoveryFile) policy(check func(context.Context) error) (*reaper.LifecyclePolicyClient, error) {
	if !filepath.IsAbs(f.PolicyServiceKeyFile) || !regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(f.Environment) {
		return nil, errors.New("recovery requires an environment and absolute policy credential reference")
	}
	raw, err := bootstrapcredentials.ReadFile(f.PolicyServiceKeyFile, true, 4096)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return reaper.NewLifecyclePolicyClient(reaper.LifecyclePolicyClientConfig{Endpoint: f.PolicyEndpoint, ServiceKey: strings.TrimSpace(string(raw)), CheckEffectAuthority: check})
}
func (s productionRecoverySupport) ConstructCatalog(journal *databaseadmission.NATSJournal) (*reaper.LifecycleCatalog, error) {
	return reaper.NewLifecycleCatalog(journal, s.Policy, s.environment)
}
func (f productionRecoveryFile) Admit() error {
	if _, err := f.policy(func(context.Context) error { return errors.New("static admission cannot authorize policy access") }); err != nil {
		return err
	}

	if !deliveryScopePart(f.ControlPlaneID) || f.SampleSize < 1 || f.SampleSize > 10000 || !deliveryScopePart(f.SnapshotStream) || strings.ContainsAny(f.SnapshotStream, ".*>") || f.SourceRegion != "gru" || f.SnapshotMaxBytes < 1024 || f.SnapshotMaxBytes > 1<<30 || f.SnapshotTimeoutSeconds < 1 || f.SnapshotTimeoutSeconds > 600 {
		return errors.New("recovery requires bounded drill and GRU snapshot configuration")
	}
	if !strings.HasSuffix(f.SnapshotPrefix, "/") || path.Clean(f.SnapshotPrefix)+"/" != f.SnapshotPrefix || strings.HasPrefix(f.SnapshotPrefix, "/") || strings.Contains(f.SnapshotPrefix, "..") {
		return errors.New("invalid recovery snapshot prefix")
	}
	for part := range strings.SplitSeq(strings.TrimSuffix(f.SnapshotPrefix, "/"), "/") {
		if !deliveryScopePart(part) {
			return errors.New("invalid recovery snapshot prefix component")
		}
	}
	seen := map[string]bool{}
	for _, r := range f.SnapshotRegions {
		if seen[r.Region] || !deliveryScopePart(r.Region) || !deliveryScopePart(r.Bucket) || !deliveryScopePart(r.Namespace) || !deliveryScopePart(r.CompartmentID) || !deliveryScopePart(r.BucketResourceID) || r.OwnershipGeneration == 0 || !filepath.IsAbs(r.SigningKeyIDFile) || !filepath.IsAbs(r.SigningKeyPEMFile) {
			return errors.New("invalid recovery snapshot regional ownership scope")
		}
		if _, err := r.transport(); err != nil {
			return fmt.Errorf("recovery snapshot %s: %w", r.Region, err)
		}
		seen[r.Region] = true
	}
	if !seen[f.SourceRegion] {
		return errors.New("recovery snapshot source is missing")
	}
	mail, err := f.Mail.adapter(func(context.Context) error { return errors.New("static admission cannot authorize effects") })
	if err != nil {
		return err
	}
	_, err = restoredrill.NewOCIEmailPager(mail, f.Mail.OperatorRecipient)
	return err
}

func (f productionRecoveryFile) Construct(ctx context.Context, session globalWorkerSession, shared provider.DeliveryRegionStoreConfig, ownership *provider.DurableOwnershipJournal) (productionRecoverySupport, error) {
	var result productionRecoverySupport
	if err := f.Admit(); err != nil {
		return result, err
	}
	if err := session.CheckEffectAuthority(ctx); err != nil {
		return result, err
	}
	if shared.Journal == nil || !shared.Journal.AuthoritativeDurable() || ownership == nil || !ownership.AuthoritativeDurable() {
		return result, errors.New("recovery requires shared durable mutation and ownership journals")
	}
	cfg := restoresnapshot.Config{Regions: map[string]restoresnapshot.Region{}, SourceRegion: f.SourceRegion, Prefix: f.SnapshotPrefix, MaxBytes: f.SnapshotMaxBytes, Journal: shared.Journal, Ownership: ownership}
	for _, r := range f.SnapshotRegions {
		receipt, found, err := ownership.Lookup(ctx, provider.ProviderResourceId{Value: r.BucketResourceID})
		if err != nil {
			return result, err
		}
		if !found || receipt.CellId.Value != r.Region || receipt.CompartmentId.Value != r.CompartmentID || receipt.Generation.Value != r.OwnershipGeneration {
			return result, errors.New("recovery snapshot bucket ownership is absent or changed")
		}
		transport, err := r.transport()
		if err != nil {
			return result, err
		}
		observed, found, err := provider.ObserveOCIBucket(ctx, transport, r.Namespace, r.Bucket)
		if err != nil {
			return result, err
		}
		if !found || observed.ID != r.BucketResourceID || observed.CompartmentID != r.CompartmentID || observed.Namespace != r.Namespace || observed.Name != r.Bucket || !provider.HasOCIOwnershipTags(observed.FreeformTags, "bucket", r.Region) {
			return result, errors.New("recovery snapshot OCI ownership does not match admitted scope")
		}
		cfg.Regions[r.Region] = restoresnapshot.Region{Transport: transport, OCIRegion: r.OCIRegion, Namespace: r.Namespace, Bucket: r.Bucket, BucketResourceID: r.BucketResourceID, CompartmentID: r.CompartmentID, OwnershipGeneration: r.OwnershipGeneration}
		result.SnapshotRegions = append(result.SnapshotRegions, r.Region)
	}
	cfg.Authorize = func(ctx context.Context, region string, epoch uint64) error {
		if _, ok := cfg.Regions[region]; !ok || epoch != uint64(session.Lease.Epoch) {
			return errors.New("recovery upload exceeds session scope")
		}
		return session.CheckEffectAuthority(ctx)
	}
	var err error
	result.Policy, err = f.policy(session.CheckEffectAuthority)
	if err != nil {
		return productionRecoverySupport{}, err
	}
	result.environment = f.Environment
	result.SnapshotMirror, err = restoresnapshot.New(cfg)
	if err != nil {
		return productionRecoverySupport{}, err
	}
	result.Mail, err = f.Mail.adapter(session.CheckEffectAuthority)
	if err != nil {
		return productionRecoverySupport{}, err
	}
	result.Pager, err = restoredrill.NewOCIEmailPager(result.Mail, f.Mail.OperatorRecipient)
	if err != nil {
		return productionRecoverySupport{}, err
	}
	result.Journal, err = restoredrill.NewNATSJournal(restoredrill.NATSJournalConfig{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId})
	if err != nil {
		return productionRecoverySupport{}, err
	}
	result.Snapshotter, err = restoredrill.NewNATSJetStreamSnapshotter(restoredrill.NATSJetStreamSnapshotterConfig{Connection: session.Connection, Stream: f.SnapshotStream, Store: result.SnapshotMirror, Region: f.SourceRegion, Bucket: cfg.Regions[f.SourceRegion].Bucket, MaxBytes: f.SnapshotMaxBytes, Timeout: time.Duration(f.SnapshotTimeoutSeconds) * time.Second})
	if err != nil {
		return productionRecoverySupport{}, err
	}
	result.Drill = restoredrill.Config{ControlPlaneID: f.ControlPlaneID, SampleSize: f.SampleSize, Seed: f.Seed, SnapshotPrefix: f.SnapshotPrefix, AcceptedControlEpoch: uint64(session.Lease.Epoch), SnapshotRegions: slices.Clone(result.SnapshotRegions)}
	result.ReaperState = reaper.NATSStateStoreConfig{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId}
	if err := session.CheckEffectAuthority(ctx); err != nil {
		return productionRecoverySupport{}, err
	}
	return result, nil
}
