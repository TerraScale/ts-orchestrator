package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/observability"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/reconcile"
)

// dryRunFlag prints the plan and exits without applying. The whole-estate
// plan is the standing I-5 runbook reference; the per-region `add-region`
// command lives in add_region.go.
const dryRunFlag = "--dry-run"

// reconcileInterval is the steady-state reconcile cadence. Drift is repaired
// within minutes, never on the reactive path.
const reconcileInterval = time.Minute

// runReconcile drives the observed estate to the declared estate (D-67).
// With --dry-run it prints the plan derived from an empty observation — the
// greenfield/bootstrap plan — and exits.
func runReconcile(ctx context.Context, args []string, output io.Writer) error {
	return runReconcileWithLookup(ctx, args, os.LookupEnv, output)
}

func runReconcileWithLookup(ctx context.Context, args []string, lookup envLookup, output io.Writer) error {
	if len(args) == 2 && args[1] == dryRunFlag {
		return printReconcilePlan(output)
	}
	if lookup == nil {
		return errors.New("reconcile: environment lookup is nil")
	}
	dependencies, err := newProductionReconcileDependencies(lookup)
	if err != nil {
		return err
	}
	defer dependencies.close()
	loop, err := newReconcileLoop(dependencies, output)
	if err != nil {
		dependencies.close()
		return err
	}
	if err := dependencies.KVWriter.Start(ctx); err != nil {
		return err
	}
	return loop.Run(ctx)
}

// productionReconcileDependencies is the composition root for D-67. The
// provider packages own cloud protocol details; this command owns the wiring
// and refuses to start until every authority and telemetry boundary is
// explicitly configured.
type productionReconcileDependencies struct {
	Spec          estate.Spec
	OCI           *ociReconcileController
	Cloudflare    *cloudflareReconcileController
	KVStore       cloudflare.KVWriterStore
	KVWriter      *cloudflare.KVWriter
	Observability observability.Config
	Telemetry     *reconcileTelemetry
}

func newProductionReconcileLoop(lookup envLookup, output io.Writer) (*reconcile.Loop, error) {
	dependencies, err := newProductionReconcileDependencies(lookup)
	if err != nil {
		return nil, err
	}
	loop, err := newReconcileLoop(dependencies, output)
	if err != nil {
		dependencies.close()
		return nil, err
	}
	return loop, nil
}

func newReconcileLoop(dependencies *productionReconcileDependencies, output io.Writer) (*reconcile.Loop, error) {
	if dependencies == nil || dependencies.OCI == nil || dependencies.Cloudflare == nil || dependencies.KVWriter == nil || dependencies.Telemetry == nil {
		return nil, errors.New("reconcile: production dependencies are incomplete")
	}
	if output == nil {
		output = io.Discard
	}
	return reconcile.NewLoop(reconcile.LoopConfig{
		Spec:         dependencies.Spec,
		Providers:    []reconcile.Reconciler{dependencies.OCI, dependencies.Cloudflare},
		Interval:     reconcileInterval,
		AllowDeletes: true,
		Audit:        &reconcileAuditSink{telemetry: dependencies.Telemetry, output: output},
		Drift:        &reconcileDriftSink{telemetry: dependencies.Telemetry, output: output},
	})
}

func (d *productionReconcileDependencies) close() {
	if d == nil {
		return
	}
	if d.KVWriter != nil {
		_ = d.KVWriter.Close()
	}
	if d.Telemetry != nil {
		_ = d.Telemetry.Close()
	}
}

// reconcileTelemetry is the command's concrete observability boundary. The
// batcher owns bounded buffering/retry and the HTTP transport owns the
// validated Grafana endpoints; reconcile only supplies structured records.
type reconcileTelemetry struct {
	batcher *observability.Batcher
}

func newReconcileTelemetry(config observability.Config) (*reconcileTelemetry, error) {
	encode := func(batch observability.Batch) (observability.EncodedBatch, error) {
		var body bytes.Buffer
		for _, record := range batch.Records {
			body.Write(record)
			body.WriteByte('\n')
		}
		return observability.EncodedBatch{Body: body.Bytes(), ContentType: "application/x-ndjson"}, nil
	}
	transport, err := observability.NewHTTPTransport(config, nil, encode, encode)
	if err != nil {
		return nil, err
	}
	batcher, err := observability.NewBatcher(config.Batch, config.Retry, transport)
	if err != nil {
		return nil, err
	}
	return &reconcileTelemetry{batcher: batcher}, nil
}

func (t *reconcileTelemetry) record(ctx context.Context, value any) error {
	if t == nil || t.batcher == nil {
		return errors.New("reconcile: telemetry sink is unavailable")
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return t.batcher.Add(ctx, observability.SignalLogs, body)
}

func (t *reconcileTelemetry) Close() error {
	if t == nil || t.batcher == nil {
		return nil
	}
	return t.batcher.Close(context.Background())
}

type reconcileAuditSink struct {
	telemetry *reconcileTelemetry
	output    io.Writer
}

func (s *reconcileAuditSink) Append(ctx context.Context, entry reconcile.AuditEntry) error {
	if s.output != nil {
		if _, err := fmt.Fprintf(s.output, "%s\n", mustJSON(entry)); err != nil {
			return err
		}
	}
	return s.telemetry.record(ctx, entry)
}

type reconcileDriftSink struct {
	telemetry *reconcileTelemetry
	output    io.Writer
}

func (s *reconcileDriftSink) PublishDrift(ctx context.Context, events []reconcile.DriftEvent) error {
	if s.output != nil {
		for _, event := range events {
			if _, err := fmt.Fprintf(s.output, "%s\n", mustJSON(event)); err != nil {
				return err
			}
		}
	}
	return s.telemetry.record(ctx, events)
}

func mustJSON(value any) string {
	body, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(body)
}

func newProductionReconcileDependencies(lookup envLookup) (*productionReconcileDependencies, error) {
	if lookup == nil {
		return nil, errors.New("reconcile: environment lookup is nil")
	}
	providerName, ok := lookup(providerEnvironment)
	if !ok || strings.TrimSpace(providerName) == "" {
		return nil, errors.New("reconcile: provider selection is required")
	}
	if strings.TrimSpace(providerName) != "oci" {
		return nil, errors.New("reconcile: production reconciliation requires the OCI provider")
	}
	spec := estate.Default()
	ociController, err := newOCIReconcileController(spec, lookup)
	if err != nil {
		return nil, err
	}
	cloudflareController, err := newCloudflareReconcileController(spec, lookup)
	if err != nil {
		return nil, err
	}
	telemetry, err := observabilityConfigFromEnv(lookup)
	if err != nil {
		return nil, err
	}
	telemetrySink, err := newReconcileTelemetry(telemetry)
	if err != nil {
		return nil, fmt.Errorf("reconcile: observability transport is invalid: %w", err)
	}
	kvWriter, err := cloudflare.NewKVWriter(cloudflare.KVWriterConfig{
		Store:          cloudflareController.Client,
		Health:         &declaredKVHealthSource{spec: spec, members: cloudflareController.Members},
		Placement:      declaredKVPlacementSource{},
		HealthInterval: cloudflare.DefaultKVWriterHealthInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("reconcile: KV writer configuration is invalid: %w", err)
	}
	return &productionReconcileDependencies{
		Spec:          spec,
		OCI:           ociController,
		Cloudflare:    cloudflareController,
		KVStore:       cloudflareController.Client,
		KVWriter:      kvWriter,
		Observability: telemetry,
		Telemetry:     telemetrySink,
	}, nil
}

type declaredKVHealthSource struct {
	spec    estate.Spec
	members cloudflare.Members
}

func (s *declaredKVHealthSource) ObserveRegionHealth(ctx context.Context) (map[string]cloudflare.RegionHealth, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make(map[string]cloudflare.RegionHealth, len(s.spec.Regions))
	for _, region := range s.spec.Regions {
		addresses := append([]string(nil), s.members[region.Code]...)
		sort.Strings(addresses)
		result[region.Code] = cloudflare.RegionHealth{Region: region.Code, Healthy: len(addresses) > 0, Members: addresses}
	}
	return result, nil
}

type declaredKVPlacementSource struct{}

func (declaredKVPlacementSource) ObserveDBPlacement(ctx context.Context) (map[string]cloudflare.DBPlacement, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return map[string]cloudflare.DBPlacement{}, nil
}

// ociReconcileController adapts one typed OCI reconciler set per declared
// region to the generic estate loop. Provider identifiers stay inside the
// typed observations; only normalized, provider-neutral attributes cross the
// generic loop boundary.
type ociReconcileController struct {
	regions map[string]*ociRegionController
}

type ociRegionController struct {
	region   estate.Region
	imageID  string
	network  *provider.NetworkReconciler
	compute  *provider.ComputeReconciler
	block    *provider.BlockStorageReconciler
	object   *provider.ObjectStorageReconciler
	vault    *provider.VaultReconciler
	certs    *provider.CertReconciler
	mu       sync.Mutex
	observed *ociRegionObservation
}

type ociRegionObservation struct {
	network provider.NetworkObserved
	compute provider.ComputeObserved
	block   provider.BlockStorageObserved
	object  provider.ObjectStorageObserved
	vault   provider.VaultObserved
	certs   provider.CertsObserved
}

func (c *ociReconcileController) Kinds() []estate.ResourceKind {
	return []estate.ResourceKind{
		estate.ResourceCompute, estate.ResourceNetwork, estate.ResourceSubnet,
		estate.ResourceNSG, estate.ResourceBucket, estate.ResourceVaultKey,
		estate.ResourceCertificate,
	}
}

func (c *ociReconcileController) Observe(ctx context.Context) (reconcile.State, error) {
	if c == nil || len(c.regions) == 0 {
		return reconcile.State{}, errors.New("reconcile: OCI controller is unavailable")
	}
	var state reconcile.State
	for _, code := range sortedOCIRegionCodes(c.regions) {
		region := c.regions[code]
		observation, observedState, err := region.observe(ctx)
		if err != nil {
			return reconcile.State{}, fmt.Errorf("region %s: %w", code, err)
		}
		region.mu.Lock()
		region.observed = observation
		region.mu.Unlock()
		state.Resources = append(state.Resources, observedState.Resources...)
	}
	return state, nil
}

func (r *ociRegionController) observe(ctx context.Context) (*ociRegionObservation, reconcile.State, error) {
	if r == nil || r.network == nil || r.compute == nil || r.block == nil || r.object == nil || r.vault == nil || r.certs == nil {
		return nil, reconcile.State{}, errors.New("reconcile: OCI region controller is unavailable")
	}
	network, err := r.network.Observe(ctx, r.region)
	if err != nil {
		return nil, reconcile.State{}, err
	}
	compute, err := r.compute.Observe(ctx, provider.ComputeDeclared{Region: r.region, ImageID: r.imageID})
	if err != nil {
		return nil, reconcile.State{}, err
	}
	block, err := r.block.Observe(ctx, r.region)
	if err != nil {
		return nil, reconcile.State{}, err
	}
	object, err := r.object.Observe(ctx, r.region)
	if err != nil {
		return nil, reconcile.State{}, err
	}
	vault, err := r.vault.Observe(ctx, r.region)
	if err != nil {
		return nil, reconcile.State{}, err
	}
	certs, err := r.certs.Observe(ctx, r.region)
	if err != nil {
		return nil, reconcile.State{}, err
	}
	observation := &ociRegionObservation{network: network, compute: compute, block: block, object: object, vault: vault, certs: certs}
	return observation, ociObservedState(r.region, observation), nil
}

func (c *ociReconcileController) Apply(ctx context.Context, plan reconcile.Plan) error {
	if c == nil || len(c.regions) == 0 {
		return errors.New("reconcile: OCI controller is unavailable")
	}
	for _, code := range sortedOCIRegionCodes(c.regions) {
		regionPlan := planForRegion(plan, code)
		if regionPlan.Empty() {
			continue
		}
		if err := c.regions[code].apply(ctx, regionPlan); err != nil {
			return fmt.Errorf("region %s: %w", code, err)
		}
	}
	return nil
}

func (r *ociRegionController) apply(ctx context.Context, generic reconcile.Plan) error {
	if r == nil {
		return errors.New("reconcile: OCI region controller is unavailable")
	}
	r.mu.Lock()
	observed := r.observed
	r.mu.Unlock()
	if observed == nil {
		var state reconcile.State
		var err error
		observed, state, err = r.observe(ctx)
		if err != nil {
			return err
		}
		_ = state
	}
	computeDeclared := provider.ComputeDeclared{Region: r.region, ImageID: r.imageID}
	networkPlan, err := r.network.Reconcile(ctx, r.region, observed.network)
	if err != nil {
		return err
	}
	networkPlan = filterOCIPlan(networkPlan, generic, r.region.Code)
	if !networkPlan.Empty() {
		if err := r.network.Apply(ctx, r.region, observed.network, networkPlan); err != nil {
			return err
		}
	}
	vaultPlan, err := r.vault.Reconcile(ctx, r.region, observed.vault)
	if err != nil {
		return err
	}
	vaultPlan = filterOCIPlan(vaultPlan, generic, r.region.Code)
	if !vaultPlan.Empty() {
		if err := r.vault.Apply(ctx, r.region, observed.vault, vaultPlan); err != nil {
			return err
		}
	}
	objectPlan, err := r.object.Reconcile(ctx, r.region, observed.object)
	if err != nil {
		return err
	}
	objectPlan = filterOCIPlan(objectPlan, generic, r.region.Code)
	if !objectPlan.Empty() {
		if err := r.object.Apply(ctx, r.region, observed.object, objectPlan); err != nil {
			return err
		}
	}
	computePlan, err := r.compute.Reconcile(ctx, computeDeclared, observed.compute)
	if err != nil {
		return err
	}
	computePlan = filterOCIPlan(computePlan, generic, r.region.Code)
	if !computePlan.Empty() {
		if err := r.compute.Apply(ctx, computeDeclared, observed.compute, computePlan); err != nil {
			return err
		}
	}
	blockPlan, err := r.block.Reconcile(ctx, r.region, observed.block)
	if err != nil {
		return err
	}
	blockPlan = filterOCIPlan(blockPlan, generic, r.region.Code)
	if !blockPlan.Empty() {
		if err := r.block.Apply(ctx, r.region, observed.block, blockPlan); err != nil {
			return err
		}
	}
	certPlan, err := r.certs.Reconcile(ctx, r.region, observed.certs)
	if err != nil {
		return err
	}
	certPlan = filterOCIPlan(certPlan, generic, r.region.Code)
	return r.certs.Apply(ctx, r.region, observed.certs, certPlan)
}

func planForRegion(plan reconcile.Plan, region string) reconcile.Plan {
	var result reconcile.Plan
	for _, action := range plan.Actions {
		if action.Ref.Region == region {
			result.Actions = append(result.Actions, action)
		}
	}
	return result
}

func filterOCIPlan(plan provider.OCIPlan, generic reconcile.Plan, region string) provider.OCIPlan {
	var result provider.OCIPlan
	for _, action := range plan.Actions {
		ref, ok := ociActionRef(region, action)
		// The typed provider plan is subordinate to the generic ownership
		// plan. Unknown action types and resources absent from that plan must
		// never reach Apply, even if a provider implementation returns them.
		if !ok {
			continue
		}
		if ref.Name == "" {
			if genericHasKindRegion(generic, ref.Kind, ref.Region) {
				result.Actions = append(result.Actions, action)
			}
			continue
		}
		if genericHasRef(generic, ref) {
			result.Actions = append(result.Actions, action)
		}
	}
	return result
}

func genericHasKindRegion(plan reconcile.Plan, kind estate.ResourceKind, region string) bool {
	for _, action := range plan.Actions {
		if action.Ref.Kind == kind && action.Ref.Region == region {
			return true
		}
	}
	return false
}

func genericHasRef(plan reconcile.Plan, ref estate.ResourceRef) bool {
	for _, action := range plan.Actions {
		if action.Ref == ref || (ref.Kind == estate.ResourceCertificate && action.Ref.Kind == ref.Kind && action.Ref.Region == ref.Region) {
			return true
		}
	}
	return false
}

func ociActionRef(region string, action provider.OCIAction) (estate.ResourceRef, bool) {
	switch value := action.(type) {
	case provider.CreateVCNAction:
		return estate.ResourceRef{Kind: estate.ResourceNetwork, Region: region, Name: "vcn"}, true
	case provider.CreateSubnetAction:
		return estate.ResourceRef{Kind: estate.ResourceSubnet, Region: region, Name: value.Name}, true
	case provider.CreateNSGAction:
		return estate.ResourceRef{Kind: estate.ResourceNSG, Region: region, Name: value.Name}, true
	case provider.ReplaceNSGRulesAction:
		return estate.ResourceRef{Kind: estate.ResourceNSG, Region: region, Name: value.Name}, true
	case provider.LaunchMemberAction, provider.StartMemberAction, provider.TerminateMemberAction:
		return estate.ResourceRef{Kind: estate.ResourceCompute, Region: region, Name: "members"}, true
	case provider.CreateVolumeAction, provider.ExpandVolumeAction, provider.AttachVolumeAction, provider.DetachAttachmentAction:
		return estate.ResourceRef{Kind: estate.ResourceCompute, Region: region, Name: "members"}, true
	case provider.CreateBucketAction:
		return estate.ResourceRef{Kind: estate.ResourceBucket, Region: region, Name: value.Name}, true
	case provider.SetBucketVersioningAction:
		return estate.ResourceRef{Kind: estate.ResourceBucket, Region: region, Name: value.Name}, true
	case provider.SetBucketLifecycleAction:
		return estate.ResourceRef{Kind: estate.ResourceBucket, Region: region, Name: value.Name}, true
	case provider.CreateVaultAction:
		return estate.ResourceRef{Kind: estate.ResourceVaultKey, Region: region, Name: ""}, true
	case provider.CreateVaultKeyAction:
		return estate.ResourceRef{Kind: estate.ResourceVaultKey, Region: region, Name: value.KeyName}, true
	case provider.CreateCertificateAction:
		return estate.ResourceRef{Kind: estate.ResourceCertificate, Region: region, Name: value.Name}, true
	case provider.RenewCertificateAction:
		return estate.ResourceRef{Kind: estate.ResourceCertificate, Region: region, Name: value.DisplayName}, true
	default:
		return estate.ResourceRef{}, false
	}
}

func ociObservedState(region estate.Region, observed *ociRegionObservation) reconcile.State {
	var state reconcile.State
	liveMembers := 0
	primaryShape := region.Members.PrimaryShape
	for _, member := range observed.compute.Members {
		if member.LifecycleState == "TERMINATED" || member.LifecycleState == "TERMINATING" || member.LifecycleState == "" {
			continue
		}
		liveMembers++
		if member.Shape != "" {
			primaryShape = member.Shape
		}
	}
	if liveMembers > 0 {
		state.Resources = append(state.Resources, reconcile.Resource{
			Ref: estate.ResourceRef{Kind: estate.ResourceCompute, Region: region.Code, Name: "members"},
			Attributes: []reconcile.Attribute{
				{Name: "member.count", Value: fmt.Sprint(liveMembers)},
				{Name: "member.primary-shape", Value: primaryShape},
				{Name: "member.fallback-shape", Value: region.Members.FallbackShape},
				{Name: "member.ocpus", Value: fmt.Sprint(region.Members.OCPUs)},
				{Name: "member.memory-gib", Value: fmt.Sprint(region.Members.MemoryGiB)},
				{Name: "member.boot-volume-gib", Value: fmt.Sprint(region.Members.BootVolumeGiB)},
				{Name: "member.data-volume-gib", Value: observedDataVolumeSize(region, observed.block)},
				{Name: "member.control-replicas", Value: fmt.Sprint(region.Members.ControlReplicas)},
			},
		})
	}
	if observed.network.VCN != nil {
		state.Resources = append(state.Resources, reconcile.Resource{Ref: estate.ResourceRef{Kind: estate.ResourceNetwork, Region: region.Code, Name: "vcn"}, Attributes: []reconcile.Attribute{{Name: "network.cidr", Value: observed.network.VCN.CIDR}}})
		for _, subnet := range observed.network.Subnets {
			state.Resources = append(state.Resources, reconcile.Resource{Ref: estate.ResourceRef{Kind: estate.ResourceSubnet, Region: region.Code, Name: subnet.DisplayName}, Attributes: []reconcile.Attribute{{Name: "subnet.cidr", Value: subnet.CIDR}}})
		}
		for _, nsg := range observed.network.NSGs {
			var attrs []reconcile.Attribute
			for _, rule := range observed.network.Rules[nsg.DisplayName] {
				attrs = append(attrs, reconcile.Attribute{Name: "nsg.rule", Value: strings.Join([]string{strings.ToLower(rule.Direction), ociProtocolName(rule.Protocol), rule.Peer, fmt.Sprintf("%d-%d", rule.PortMin, rule.PortMax)}, "|")})
			}
			state.Resources = append(state.Resources, reconcile.Resource{Ref: estate.ResourceRef{Kind: estate.ResourceNSG, Region: region.Code, Name: nsg.DisplayName}, Attributes: attrs})
		}
	}
	for _, bucket := range observed.object.Buckets {
		attrs := []reconcile.Attribute{{Name: "bucket.purpose", Value: bucketPurpose(region, bucket.Name)}, {Name: "bucket.versioning", Value: fmt.Sprint(bucket.Versioning)}}
		for _, rule := range bucket.LifecycleRules {
			value := fmt.Sprintf("%s|%s|%d", rule.Name, rule.Action, rule.AfterDays)
			for _, declared := range region.Buckets {
				if declared.Name != bucket.Name {
					continue
				}
				for _, want := range declared.LifecycleRules {
					if want.Name == rule.Name && want.Action == rule.Action && want.AfterDays == rule.AfterDays && want.Prefix == rule.Prefix && want.KeepLatest > 0 {
						value += fmt.Sprintf("|keep-%d", want.KeepLatest)
					}
				}
			}
			attrs = append(attrs, reconcile.Attribute{Name: "bucket.lifecycle-rule", Value: value})
		}
		state.Resources = append(state.Resources, reconcile.Resource{Ref: estate.ResourceRef{Kind: estate.ResourceBucket, Region: region.Code, Name: bucket.Name}, Attributes: attrs})
	}
	for _, key := range observed.vault.Keys {
		if key.LifecycleState == "DELETED" || key.LifecycleState == "DELETING" {
			continue
		}
		for _, declared := range region.VaultKeys {
			if declared.Name == key.DisplayName {
				state.Resources = append(state.Resources, reconcile.Resource{Ref: estate.ResourceRef{Kind: estate.ResourceVaultKey, Region: region.Code, Name: key.DisplayName}, Attributes: []reconcile.Attribute{{Name: "vault-key.purpose", Value: declared.Purpose}, {Name: "vault-key.rotation-hours", Value: fmt.Sprint(declared.RotationHours)}}})
				break
			}
		}
	}
	for _, cert := range observed.certs.Certs {
		for _, declared := range region.Certificates {
			if provider.CertDisplayName(region.Code, declared.Name) != cert.DisplayName {
				continue
			}
			attrs := []reconcile.Attribute{{Name: "certificate.purpose", Value: declared.Purpose}, {Name: "certificate.renew-before-hours", Value: fmt.Sprint(declared.RenewBeforeHours)}}
			for _, name := range cert.DNSNames {
				attrs = append(attrs, reconcile.Attribute{Name: "certificate.dns-name", Value: name})
			}
			state.Resources = append(state.Resources, reconcile.Resource{Ref: estate.ResourceRef{Kind: estate.ResourceCertificate, Region: region.Code, Name: declared.Name}, Attributes: attrs})
		}
	}
	return state
}

func observedDataVolumeSize(region estate.Region, observed provider.BlockStorageObserved) string {
	for _, volume := range observed.Volumes {
		if volume.LifecycleState != "TERMINATED" && volume.LifecycleState != "TERMINATING" {
			return fmt.Sprint(volume.SizeGiB)
		}
	}
	// A live member with no observed volume is an actionable gap. Returning
	// zero makes the generic compute resource carry that drift so the block
	// controller receives the planned resource and can create it.
	if len(observed.Members) > 0 {
		return "0"
	}
	return fmt.Sprint(region.Members.DataVolumeGiB)
}

func bucketPurpose(region estate.Region, name string) string {
	for _, bucket := range region.Buckets {
		if bucket.Name == name {
			return bucket.Purpose
		}
	}
	return ""
}

func ociProtocolName(protocol string) string {
	switch protocol {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	default:
		return protocol
	}
}

func sortedOCIRegionCodes(regions map[string]*ociRegionController) []string {
	codes := make([]string, 0, len(regions))
	for code := range regions {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return codes
}

type cloudflareReconcileController struct {
	Client   *cloudflare.Client
	Zone     *cloudflare.Zone
	Members  cloudflare.Members
	Declared reconcile.State
}

func (c *cloudflareReconcileController) Kinds() []estate.ResourceKind {
	return []estate.ResourceKind{
		estate.ResourceDNS, estate.ResourceCacheRule, estate.ResourceSnippetRule,
		estate.ResourceWorkerRoute, estate.ResourceKVMap, estate.ResourceWAFRule,
		estate.ResourceRateRule, estate.ResourceCapabilityKey,
	}
}

func (c *cloudflareReconcileController) Observe(ctx context.Context) (reconcile.State, error) {
	if c == nil || c.Client == nil || c.Zone == nil {
		return reconcile.State{}, errors.New("reconcile: Cloudflare controller is unavailable")
	}
	plan, err := cloudflare.ReconcileZone(ctx, c.Client, c.Zone)
	if err != nil {
		return reconcile.State{}, err
	}
	changed := make(map[estate.ResourceKind]bool)
	for _, change := range plan.Changes {
		if kind, ok := cloudflareResourceKind(change.Resource); ok {
			changed[kind] = true
		}
	}
	var observed reconcile.State
	for _, resource := range c.Declared.Resources {
		if !changed[resource.Ref.Kind] {
			observed.Resources = append(observed.Resources, resource)
		}
	}
	return observed, nil
}

func (c *cloudflareReconcileController) Apply(ctx context.Context, _ reconcile.Plan) error {
	if c == nil || c.Client == nil || c.Zone == nil {
		return errors.New("reconcile: Cloudflare controller is unavailable")
	}
	plan, err := cloudflare.ReconcileZone(ctx, c.Client, c.Zone)
	if err != nil {
		return err
	}
	return cloudflare.Apply(ctx, plan)
}

func cloudflareResourceKind(resource string) (estate.ResourceKind, bool) {
	switch resource {
	case "dns-record":
		return estate.ResourceDNS, true
	case "cache-rule", "tiered-cache":
		return estate.ResourceCacheRule, true
	case "snippet-rule":
		return estate.ResourceSnippetRule, true
	case "worker-route":
		return estate.ResourceWorkerRoute, true
	case "kv-namespace":
		return estate.ResourceKVMap, true
	case "waf-rule":
		return estate.ResourceWAFRule, true
	case "rate-rule":
		return estate.ResourceRateRule, true
	default:
		return "", false
	}
}

const ociEstateFilesEnvironment = "TS_ORCH_OCI_ESTATE_FILES_JSON"

func newOCIReconcileController(spec estate.Spec, lookup envLookup) (*ociReconcileController, error) {
	keyID, err := requiredReconcileEnv(lookup, ociKeyIDEnvironment)
	if err != nil {
		return nil, err
	}
	keyFile, err := requiredReconcileEnv(lookup, ociPrivateKeyFileEnvironment)
	if err != nil {
		return nil, err
	}
	imageID, err := requiredReconcileEnv(lookup, ociImageIDEnvironment)
	if err != nil {
		return nil, err
	}
	authorityID, err := requiredReconcileEnv(lookup, ociCertificateAuthorityEnvironment)
	if err != nil {
		return nil, err
	}
	filesRaw, present := lookup(ociEstateFilesEnvironment)
	files := make(map[string]string, len(spec.Regions))
	if present && strings.TrimSpace(filesRaw) != "" {
		if err := json.Unmarshal([]byte(filesRaw), &files); err != nil {
			return nil, errors.New("reconcile: OCI estate files configuration is invalid")
		}
	} else {
		file, err := requiredReconcileEnv(lookup, ociEstateFileEnvironment)
		if err != nil {
			return nil, err
		}
		for _, region := range spec.Regions {
			if region.Code == spec.HomeRegion {
				files[region.Code] = file
			}
		}
	}
	controllers := make(map[string]*ociRegionController, len(spec.Regions))
	for _, region := range spec.Regions {
		file := strings.TrimSpace(files[region.Code])
		if file == "" {
			return nil, fmt.Errorf("reconcile: OCI estate configuration for region %s is missing", region.Code)
		}
		controller, err := newOCIRegionController(region, file, keyID, keyFile, imageID, authorityID)
		if err != nil {
			return nil, fmt.Errorf("reconcile: OCI region %s: %w", region.Code, err)
		}
		controllers[region.Code] = controller
	}
	return &ociReconcileController{regions: controllers}, nil
}

func newOCIRegionController(region estate.Region, estateFile, keyID, keyFile, imageID, authorityID string) (*ociRegionController, error) {
	ociEstate, err := provider.LoadOCIEstateSpec(estateFile)
	if err != nil {
		return nil, err
	}
	if ociEstate.Region != region.OCIName {
		return nil, fmt.Errorf("estate region %q does not match declared OCI region %q", ociEstate.Region, region.OCIName)
	}
	reader, err := provider.NewOCIEstateHTTPReader(ociEstate, keyID, keyFile)
	if err != nil {
		return nil, err
	}
	core := reader.Transports[provider.OCIServiceCore]
	certsConfig, err := provider.NewOCIServiceTransportConfig(provider.OCIServiceCertificates, ociEstate.Region, "https://certificates."+ociEstate.Region+".oci.oraclecloud.com")
	if err != nil {
		return nil, err
	}
	certsTransport, err := provider.NewOCIHTTPTransport(certsConfig, core.Client, core.Signer)
	if err != nil {
		return nil, err
	}
	networkGateway, err := provider.NewOCINetworkGateway(core, ociEstate.NetworkCompartmentID)
	if err != nil {
		return nil, err
	}
	computeGateway, err := provider.NewOCIMemberGateway(core, ociEstate.WorkloadCompartmentID, imageID)
	if err != nil {
		return nil, err
	}
	blockGateway, err := provider.NewOCIBlockStorageGateway(core, ociEstate.WorkloadCompartmentID)
	if err != nil {
		return nil, err
	}
	objectGateway, err := provider.NewOCIObjectStorageGateway(reader.Transports[provider.OCIServiceObjectStorage], ociEstate.ControlCompartmentID)
	if err != nil {
		return nil, err
	}
	vaultGateway, err := provider.NewOCIVaultGateway(reader.Transports[provider.OCIServiceVault], reader.Transports[provider.OCIServiceVaultManagement], ociEstate.Region, ociEstate.ControlCompartmentID)
	if err != nil {
		return nil, err
	}
	certGateway, err := provider.NewOCICertificatesGateway(certsTransport, ociEstate.ControlCompartmentID, authorityID)
	if err != nil {
		return nil, err
	}
	return &ociRegionController{region: region, imageID: imageID, network: &provider.NetworkReconciler{Gateway: networkGateway}, compute: &provider.ComputeReconciler{Compute: computeGateway, Network: networkGateway}, block: &provider.BlockStorageReconciler{Block: blockGateway, Compute: computeGateway}, object: &provider.ObjectStorageReconciler{Object: objectGateway}, vault: &provider.VaultReconciler{Vault: vaultGateway}, certs: &provider.CertReconciler{Gateway: certGateway}}, nil
}

func newCloudflareReconcileController(spec estate.Spec, lookup envLookup) (*cloudflareReconcileController, error) {
	token, err := requiredReconcileEnv(lookup, cloudflareTokenEnvironment)
	if err != nil {
		return nil, err
	}
	zoneID, err := requiredReconcileEnv(lookup, cloudflareZoneIDEnvironment)
	if err != nil {
		return nil, err
	}
	accountID, err := requiredReconcileEnv(lookup, cloudflareAccountIDEnvironment)
	if err != nil {
		return nil, err
	}
	membersRaw, err := requiredReconcileEnv(lookup, cloudflareMembersEnvironment)
	if err != nil {
		return nil, err
	}
	egressRaw, err := requiredReconcileEnv(lookup, cloudflareEgressEnvironment)
	if err != nil {
		return nil, err
	}
	var members cloudflare.Members
	if err := json.Unmarshal([]byte(membersRaw), &members); err != nil || len(members) == 0 {
		return nil, errors.New("reconcile: Cloudflare member address configuration is invalid")
	}
	var egress []string
	if err := json.Unmarshal([]byte(egressRaw), &egress); err != nil || len(egress) == 0 {
		return nil, errors.New("reconcile: Cloudflare Tailscale egress configuration is invalid")
	}
	zone, err := cloudflare.Production(members, egress)
	if err != nil {
		return nil, err
	}
	if zone.ZoneName != spec.Cloudflare.Zone && spec.Cloudflare.Zone != "" {
		return nil, errors.New("reconcile: Cloudflare zone does not match the declared estate")
	}
	declared, err := reconcile.Declared(spec)
	if err != nil {
		return nil, err
	}
	return &cloudflareReconcileController{
		Client: cloudflare.NewClient(token, zoneID, accountID), Zone: zone,
		Members: members, Declared: declaredForKinds(declared, (&cloudflareReconcileController{}).Kinds()),
	}, nil
}

func declaredForKinds(state reconcile.State, kinds []estate.ResourceKind) reconcile.State {
	wanted := make(map[estate.ResourceKind]bool, len(kinds))
	for _, kind := range kinds {
		wanted[kind] = true
	}
	var result reconcile.State
	for _, resource := range state.Resources {
		if wanted[resource.Ref.Kind] {
			result.Resources = append(result.Resources, resource)
		}
	}
	return result
}

func observabilityConfigFromEnv(lookup envLookup) (observability.Config, error) {
	metrics, err := requiredReconcileEnv(lookup, grafanaMetricsEnvironment)
	if err != nil {
		return observability.Config{}, err
	}
	logs, err := requiredReconcileEnv(lookup, grafanaLogsEnvironment)
	if err != nil {
		return observability.Config{}, err
	}
	username, err := requiredReconcileEnv(lookup, grafanaUsernameEnvironment)
	if err != nil {
		return observability.Config{}, err
	}
	apiKey, err := requiredReconcileEnv(lookup, grafanaAPIKeyEnvironment)
	if err != nil {
		return observability.Config{}, err
	}
	config := observability.Config{
		MetricsEndpoint: metrics,
		LogsEndpoint:    logs,
		Credentials:     observability.Credentials{Username: username, APIKey: apiKey},
		Labels:          observability.DefaultLabelAllowList.Clone(),
		Batch:           observability.BatchConfig{MaxItems: 1000, MaxBytes: 1 << 20},
		Retry:           observability.RetryPolicy{MaxAttempts: 3, InitialDelay: time.Second, MaxDelay: 30 * time.Second, Multiplier: 2},
	}
	if err := observability.ValidateConfig(config); err != nil {
		return observability.Config{}, fmt.Errorf("reconcile: observability configuration is invalid: %w", err)
	}
	return config, nil
}

func requiredReconcileEnv(lookup envLookup, name string) (string, error) {
	value, ok := lookup(name)
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return "", fmt.Errorf("reconcile: required configuration %s is missing", name)
	}
	return value, nil
}

// printReconcilePlan derives a pure plan against an empty observation. It
// performs no configuration reads or provider construction, making it safe
// for bootstrap runbooks and offline verification.
func printReconcilePlan(output io.Writer) error {
	if output == nil {
		return errors.New("reconcile: plan output is nil")
	}
	declared, err := reconcile.Declared(estate.Default())
	if err != nil {
		return err
	}
	plan, err := reconcile.Diff(declared, reconcile.State{})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(struct {
		EstateVersion uint32             `json:"estateVersion"`
		Actions       []reconcile.Action `json:"actions"`
	}{
		EstateVersion: estate.SchemaVersion,
		Actions:       plan.Actions,
	})
}
