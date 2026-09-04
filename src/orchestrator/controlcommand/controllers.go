package controlcommand

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/reconcile"
)

// OCIRegionControllerConfig binds the production typed reconcilers for one
// declared Region. Gateway implementations own transport authentication,
// mutation journals, and durable ownership evidence.
type OCIRegionControllerConfig struct {
	Region       estate.Region
	ImageID      string
	Gateways     provider.BootstrapGateways
	Certificates provider.CertGateway
	BlockPolicy  provider.BlockStoragePolicy
}

type OCIRegionControllerSource interface {
	OCIRegionController(context.Context, estate.Region) (OCIRegionControllerConfig, error)
}

type OCIRegionControllerSourceFunc func(context.Context, estate.Region) (OCIRegionControllerConfig, error)

func (f OCIRegionControllerSourceFunc) OCIRegionController(ctx context.Context, region estate.Region) (OCIRegionControllerConfig, error) {
	if f == nil {
		return OCIRegionControllerConfig{}, ErrInvalidConfiguration
	}
	return f(ctx, region)
}

type CloudflareControllerConfig struct {
	Client *cloudflare.Client
	Zone   *cloudflare.Zone
}

type CloudflareControllerSource interface {
	CloudflareController(context.Context, estate.Spec) (CloudflareControllerConfig, error)
}

type CloudflareControllerSourceFunc func(context.Context, estate.Spec) (CloudflareControllerConfig, error)

func (f CloudflareControllerSourceFunc) CloudflareController(ctx context.Context, desired estate.Spec) (CloudflareControllerConfig, error) {
	if f == nil {
		return CloudflareControllerConfig{}, ErrInvalidConfiguration
	}
	return f(ctx, desired)
}

// ProviderReconcilerSource builds the shared production OCI and Cloudflare
// controllers for each desired estate.
type ProviderReconcilerSource struct {
	OCI        OCIRegionControllerSource
	Cloudflare CloudflareControllerSource
	OnChange   func()
}

func (s *ProviderReconcilerSource) Reconcilers(ctx context.Context, desired estate.Spec) ([]reconcile.Reconciler, error) {
	if s == nil || s.OCI == nil || s.Cloudflare == nil || ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := desired.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	regions := make(map[string]*ociRegionController, len(desired.Regions))
	for _, declared := range desired.Regions {
		config, err := s.OCI.OCIRegionController(ctx, declared)
		if err != nil {
			return nil, fmt.Errorf("controlcommand: OCI Region %s: %w", declared.Code, err)
		}
		controller, err := newOCIRegionController(declared, config)
		if err != nil {
			return nil, fmt.Errorf("controlcommand: OCI Region %s: %w", declared.Code, err)
		}
		regions[declared.Code] = controller
	}
	edgeConfig, err := s.Cloudflare.CloudflareController(ctx, desired)
	if err != nil {
		return nil, fmt.Errorf("controlcommand: Cloudflare: %w", err)
	}
	cloudflareController, err := newCloudflareReconcileController(desired, edgeConfig, s.OnChange)
	if err != nil {
		return nil, err
	}
	return []reconcile.Reconciler{
		&OCIReconcileController{regions: regions, onChange: s.OnChange},
		cloudflareController,
	}, nil
}

// OCIReconcileController adapts the typed OCI reconcilers to the estate loop.
type OCIReconcileController struct {
	regions  map[string]*ociRegionController
	onChange func()
}

type ociRegionController struct {
	region  estate.Region
	imageID string
	network *provider.NetworkReconciler
	compute *provider.ComputeReconciler
	block   *provider.BlockStorageReconciler
	object  *provider.ObjectStorageReconciler
	vault   *provider.VaultReconciler
	certs   *provider.CertReconciler

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

func newOCIRegionController(declared estate.Region, config OCIRegionControllerConfig) (*ociRegionController, error) {
	if config.Region.Code != declared.Code || config.Region.OCIName != declared.OCIName || strings.TrimSpace(config.ImageID) == "" ||
		config.Gateways.Network == nil || config.Gateways.Compute == nil || config.Gateways.Block == nil ||
		config.Gateways.Object == nil || config.Gateways.Vault == nil || config.Certificates == nil {
		return nil, ErrInvalidConfiguration
	}
	return &ociRegionController{
		region: declared, imageID: config.ImageID,
		network: &provider.NetworkReconciler{Gateway: config.Gateways.Network},
		compute: &provider.ComputeReconciler{Compute: config.Gateways.Compute, Network: config.Gateways.Network},
		block:   &provider.BlockStorageReconciler{Block: config.Gateways.Block, Compute: config.Gateways.Compute, Policy: config.BlockPolicy},
		object:  &provider.ObjectStorageReconciler{Object: config.Gateways.Object},
		vault:   &provider.VaultReconciler{Vault: config.Gateways.Vault},
		certs:   &provider.CertReconciler{Gateway: config.Certificates},
	}, nil
}

func (c *OCIReconcileController) Kinds() []estate.ResourceKind {
	return []estate.ResourceKind{
		estate.ResourceCompute, estate.ResourceNetwork, estate.ResourceSubnet,
		estate.ResourceNSG, estate.ResourceBucket, estate.ResourceVaultKey,
		estate.ResourceCertificate,
	}
}

func (c *OCIReconcileController) Observe(ctx context.Context) (reconcile.State, error) {
	if c == nil || len(c.regions) == 0 {
		return reconcile.State{}, ErrInvalidConfiguration
	}
	var state reconcile.State
	for _, code := range sortedRegionCodes(c.regions) {
		region := c.regions[code]
		observation, observed, err := region.observe(ctx)
		if err != nil {
			return reconcile.State{}, fmt.Errorf("controlcommand: observe OCI Region %s: %w", code, err)
		}
		region.mu.Lock()
		region.observed = observation
		region.mu.Unlock()
		state.Resources = append(state.Resources, observed.Resources...)
	}
	return state, nil
}

func (r *ociRegionController) observe(ctx context.Context) (*ociRegionObservation, reconcile.State, error) {
	if r == nil {
		return nil, reconcile.State{}, ErrInvalidConfiguration
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
	return observation, observedOCIState(r.region, observation), nil
}

func (c *OCIReconcileController) Apply(ctx context.Context, plan reconcile.Plan) error {
	if c == nil || len(c.regions) == 0 {
		return ErrInvalidConfiguration
	}
	changed := false
	for _, code := range sortedRegionCodes(c.regions) {
		regionPlan := planForRegion(plan, code)
		if regionPlan.Empty() {
			continue
		}
		if err := c.regions[code].apply(ctx, regionPlan); err != nil {
			return fmt.Errorf("controlcommand: apply OCI Region %s: %w", code, err)
		}
		changed = true
	}
	if changed && c.onChange != nil {
		c.onChange()
	}
	return nil
}

func (r *ociRegionController) apply(ctx context.Context, generic reconcile.Plan) error {
	r.mu.Lock()
	observed := r.observed
	r.mu.Unlock()
	if observed == nil {
		var err error
		observed, _, err = r.observe(ctx)
		if err != nil {
			return err
		}
	}
	computeDeclared := provider.ComputeDeclared{Region: r.region, ImageID: r.imageID}
	steps := []func() error{
		func() error {
			plan, err := r.network.Reconcile(ctx, r.region, observed.network)
			if err != nil {
				return err
			}
			plan = filterOCIPlan(plan, generic, r.region.Code)
			if plan.Empty() {
				return nil
			}
			return r.network.Apply(ctx, r.region, observed.network, plan)
		},
		func() error {
			plan, err := r.vault.Reconcile(ctx, r.region, observed.vault)
			if err != nil {
				return err
			}
			plan = filterOCIPlan(plan, generic, r.region.Code)
			if plan.Empty() {
				return nil
			}
			return r.vault.Apply(ctx, r.region, observed.vault, plan)
		},
		func() error {
			plan, err := r.object.Reconcile(ctx, r.region, observed.object)
			if err != nil {
				return err
			}
			plan = filterOCIPlan(plan, generic, r.region.Code)
			if plan.Empty() {
				return nil
			}
			return r.object.Apply(ctx, r.region, observed.object, plan)
		},
		func() error {
			plan, err := r.compute.Reconcile(ctx, computeDeclared, observed.compute)
			if err != nil {
				return err
			}
			plan = filterOCIPlan(plan, generic, r.region.Code)
			if plan.Empty() {
				return nil
			}
			return r.compute.Apply(ctx, computeDeclared, observed.compute, plan)
		},
		func() error {
			plan, err := r.block.Reconcile(ctx, r.region, observed.block)
			if err != nil {
				return err
			}
			plan = filterOCIPlan(plan, generic, r.region.Code)
			if plan.Empty() {
				return nil
			}
			return r.block.Apply(ctx, r.region, observed.block, plan)
		},
		func() error {
			plan, err := r.certs.Reconcile(ctx, r.region, observed.certs)
			if err != nil {
				return err
			}
			plan = filterOCIPlan(plan, generic, r.region.Code)
			if plan.Empty() {
				return nil
			}
			return r.certs.Apply(ctx, r.region, observed.certs, plan)
		},
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

type CloudflareReconcileController struct {
	client   *cloudflare.Client
	zone     *cloudflare.Zone
	declared reconcile.State
	onChange func()
}

func newCloudflareReconcileController(desired estate.Spec, config CloudflareControllerConfig, onChange func()) (*CloudflareReconcileController, error) {
	if config.Client == nil || config.Zone == nil || config.Zone.ZoneName != desired.Cloudflare.Zone {
		return nil, ErrInvalidConfiguration
	}
	declared, err := reconcile.Declared(desired)
	if err != nil {
		return nil, err
	}
	controller := &CloudflareReconcileController{client: config.Client, zone: config.Zone, onChange: onChange}
	controller.declared = declaredForKinds(declared, controller.Kinds())
	return controller, nil
}

func (c *CloudflareReconcileController) Kinds() []estate.ResourceKind {
	return []estate.ResourceKind{
		estate.ResourceDNS, estate.ResourceCacheRule, estate.ResourceSnippetRule,
		estate.ResourceWorkerRoute, estate.ResourceKVMap, estate.ResourceWAFRule,
		estate.ResourceRateRule, estate.ResourceCapabilityKey,
	}
}

func (c *CloudflareReconcileController) Observe(ctx context.Context) (reconcile.State, error) {
	if c == nil || c.client == nil || c.zone == nil {
		return reconcile.State{}, ErrInvalidConfiguration
	}
	plan, err := cloudflare.ReconcileZone(ctx, c.client, c.zone)
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
	for _, resource := range c.declared.Resources {
		if !changed[resource.Ref.Kind] {
			observed.Resources = append(observed.Resources, resource)
		}
	}
	return observed, nil
}

func (c *CloudflareReconcileController) Apply(ctx context.Context, _ reconcile.Plan) error {
	if c == nil || c.client == nil || c.zone == nil {
		return ErrInvalidConfiguration
	}
	plan, err := cloudflare.ReconcileZone(ctx, c.client, c.zone)
	if err != nil {
		return err
	}
	if err := cloudflare.Apply(ctx, plan); err != nil {
		return err
	}
	if len(plan.Changes) > 0 && c.onChange != nil {
		c.onChange()
	}
	return nil
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
		if action.Ref == ref || ref.Kind == estate.ResourceCertificate && action.Ref.Kind == ref.Kind && action.Ref.Region == ref.Region {
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
	case provider.LaunchMemberAction, provider.StartMemberAction, provider.TerminateMemberAction,
		provider.CreateVolumeAction, provider.ExpandVolumeAction, provider.AttachVolumeAction, provider.DetachAttachmentAction:
		return estate.ResourceRef{Kind: estate.ResourceCompute, Region: region, Name: "members"}, true
	case provider.CreateBucketAction:
		return estate.ResourceRef{Kind: estate.ResourceBucket, Region: region, Name: value.Name}, true
	case provider.SetBucketVersioningAction:
		return estate.ResourceRef{Kind: estate.ResourceBucket, Region: region, Name: value.Name}, true
	case provider.SetBucketLifecycleAction:
		return estate.ResourceRef{Kind: estate.ResourceBucket, Region: region, Name: value.Name}, true
	case provider.CreateVaultAction:
		return estate.ResourceRef{Kind: estate.ResourceVaultKey, Region: region}, true
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

func observedOCIState(region estate.Region, observed *ociRegionObservation) reconcile.State {
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
			var attributes []reconcile.Attribute
			for _, rule := range observed.network.Rules[nsg.DisplayName] {
				attributes = append(attributes, reconcile.Attribute{Name: "nsg.rule", Value: strings.Join([]string{strings.ToLower(rule.Direction), ociProtocolName(rule.Protocol), rule.Peer, fmt.Sprintf("%d-%d", rule.PortMin, rule.PortMax)}, "|")})
			}
			state.Resources = append(state.Resources, reconcile.Resource{Ref: estate.ResourceRef{Kind: estate.ResourceNSG, Region: region.Code, Name: nsg.DisplayName}, Attributes: attributes})
		}
	}
	for _, bucket := range observed.object.Buckets {
		attributes := []reconcile.Attribute{{Name: "bucket.purpose", Value: bucketPurpose(region, bucket.Name)}, {Name: "bucket.versioning", Value: fmt.Sprint(bucket.Versioning)}}
		for _, rule := range bucket.LifecycleRules {
			value := fmt.Sprintf("%s|%s|%d", rule.Name, rule.Action, rule.AfterDays)
			for _, declared := range region.Buckets {
				if declared.Name != bucket.Name {
					continue
				}
				for _, wanted := range declared.LifecycleRules {
					if wanted.Name == rule.Name && wanted.Action == rule.Action && wanted.AfterDays == rule.AfterDays && wanted.Prefix == rule.Prefix && wanted.KeepLatest > 0 {
						value += fmt.Sprintf("|keep-%d", wanted.KeepLatest)
					}
				}
			}
			attributes = append(attributes, reconcile.Attribute{Name: "bucket.lifecycle-rule", Value: value})
		}
		state.Resources = append(state.Resources, reconcile.Resource{Ref: estate.ResourceRef{Kind: estate.ResourceBucket, Region: region.Code, Name: bucket.Name}, Attributes: attributes})
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
	for _, certificate := range observed.certs.Certs {
		for _, declared := range region.Certificates {
			if provider.CertDisplayName(region.Code, declared.Name) != certificate.DisplayName {
				continue
			}
			attributes := []reconcile.Attribute{{Name: "certificate.purpose", Value: declared.Purpose}, {Name: "certificate.renew-before-hours", Value: fmt.Sprint(declared.RenewBeforeHours)}}
			for _, name := range certificate.DNSNames {
				attributes = append(attributes, reconcile.Attribute{Name: "certificate.dns-name", Value: name})
			}
			state.Resources = append(state.Resources, reconcile.Resource{Ref: estate.ResourceRef{Kind: estate.ResourceCertificate, Region: region.Code, Name: declared.Name}, Attributes: attributes})
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

func sortedRegionCodes(regions map[string]*ociRegionController) []string {
	codes := make([]string, 0, len(regions))
	for code := range regions {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return codes
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
	case "secrets-store", "secret-reference":
		return estate.ResourceCapabilityKey, true
	default:
		return "", false
	}
}

var (
	_ ReconcilerSource     = (*ProviderReconcilerSource)(nil)
	_ reconcile.Reconciler = (*OCIReconcileController)(nil)
	_ reconcile.Reconciler = (*CloudflareReconcileController)(nil)
	_                      = errors.Is
)
