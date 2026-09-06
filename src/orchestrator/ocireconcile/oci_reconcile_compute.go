package ocireconcile

import "terrascale.tech/orchestrator/src/orchestrator/provider"

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/tsnodebootstrap"
)

// The compute reconciler launches and repairs the Region's member hosts
// (D-65/D-67): Ampere A1 primary shape, the declared flex shape as the
// automatic fallback when A1 capacity is unavailable (D-69), a cloud-init
// that installs ONLY ts-node, and no credentials anywhere on the host — the
// hosts authenticate to OCI with instance principals and fetch everything
// else from the orchestrator. Shape and image architectures must agree
// (D-69): A1 hosts are arm64, the x86 flex shapes are amd64, and every
// launch boots the image declared for its shape's architecture.

// MemberIndexTag is the freeform tag carrying the member's stable slot.
const MemberIndexTag = "terrascale-member-index"

// ManagedMemberTagValue marks instances this reconciler owns.
const ManagedMemberTagValue = "member"

// MemberDisplayName derives the deterministic display name for a member slot.
func MemberDisplayName(regionCode string, index int) string {
	return "terrascale-" + regionCode + "-" + strconv.Itoa(index)
}

type ObservedMember struct {
	ID                 string
	DisplayName        string
	Index              int
	Shape              string
	LifecycleState     string
	AvailabilityDomain string
	CompartmentID      string
	FreeformTags       map[string]string
}

// MemberLaunchSpec is one member launch request. FallbackShape is tried
// automatically when the primary shape is out of capacity. ImageID boots
// Shape and FallbackImageID boots FallbackShape: a cross-architecture
// fallback (A1 arm64 → E5 amd64) refuses to launch without its own image,
// a same-architecture fallback may reuse ImageID.
type MemberLaunchSpec struct {
	DisplayName        string
	Index              int
	Shape              string
	FallbackShape      string
	ImageID            string
	FallbackImageID    string
	OCPUs, MemoryGiB   float64
	SubnetID           string
	NSGIDs             []string
	AvailabilityDomain string
	CloudInitBase64    string
	Candidates         []MemberLaunchCandidate
}

// MemberLaunchCandidate is an ordered, independently qualified OCI launch
// option. Capacity errors may advance to the next option; unknown outcomes
// and quota errors must stop so a possibly accepted mutation is never
// replaced by another request.
type MemberLaunchCandidate struct {
	Shape            string
	ImageID          string
	Architecture     string
	QualificationRef string
	CostRef          string
}

type ComputeDeclared struct {
	Region estate.Region
	// ImageID boots the primary shape; FallbackImageID boots the fallback
	// shape whenever the two shapes span architectures (D-69).
	ImageID           string
	FallbackImageID   string
	Candidates        []MemberLaunchCandidate
	CloudInitByMember map[int]string
}

type ComputeObserved struct {
	Members             []ObservedMember
	AvailabilityDomains []string
	Subnets             []ObservedSubnet
	NSGs                []ObservedNSG
}

// ComputeGateway is the OCI core-service seam for member-host
// reconciliation.
type ComputeGateway interface {
	ListAvailabilityDomains(ctx context.Context) ([]string, error)
	ListMembers(ctx context.Context) ([]ObservedMember, error)
	LaunchMember(ctx context.Context, spec MemberLaunchSpec) (ObservedMember, error)
	StartMember(ctx context.Context, instanceID string) error
	TerminateMember(ctx context.Context, instanceID string) error
}

// MemberRemovalOwner performs the durable removal choreography before OCI
// termination. It owns the GRU intent CAS, TBEP drain/readiness receipts,
// RF2/control quorum and retained-backup/headroom proofs. A compute gateway
// alone is never sufficient authority to remove an admitted member.
type MemberRemovalOwner interface {
	RemoveMember(context.Context, string, ObservedMember, []ObservedMember) error
}

type LaunchMemberAction struct {
	Region estate.Region
	Spec   MemberLaunchSpec
}

func (a LaunchMemberAction) Kind() OCIActionKind { return OCIActionLaunchMember }
func (a LaunchMemberAction) Summary() string {
	return "launch member " + a.Spec.DisplayName + " on " + a.Spec.Shape + " (fallback " + a.Spec.FallbackShape + ")"
}

type StartMemberAction struct{ InstanceID string }

func (a StartMemberAction) Kind() OCIActionKind { return OCIActionStartMember }
func (a StartMemberAction) Summary() string     { return "start member " + a.InstanceID }

type TerminateMemberAction struct{ InstanceID string }

func (a TerminateMemberAction) Kind() OCIActionKind { return OCIActionTerminateMember }
func (a TerminateMemberAction) Summary() string     { return "terminate member " + a.InstanceID }

// ComputeReconciler converges one Region's member hosts toward the declared
// member pool.
type ComputeReconciler struct {
	Compute ComputeGateway
	Network NetworkGateway
	// RemovalOwner is the lease-owned durable removal choreography. A compute
	// gateway must never terminate an admitted member without this proof owner.
	RemovalOwner MemberRemovalOwner
}

func computeScopeCompartment(gateway ComputeGateway) string {
	if concrete, ok := gateway.(*ociMemberGateway); ok && concrete != nil {
		return concrete.CompartmentID
	}
	return ""
}

var _ OCIReconciler[ComputeDeclared, ComputeObserved] = (*ComputeReconciler)(nil)

func memberIsLive(state string) bool {
	return state != "TERMINATED" && state != "TERMINATING" && state != "" && state != "FAILED" && state != "ERROR"
}

// Member CPU architectures (D-69). A launch must boot an image built for
// its shape's architecture; mixing them strands a host in cloud-init.
const (
	MemberArchArm64 = "arm64"
	MemberArchAMD64 = "amd64"
)

// ShapeArch classifies an OCI VM shape's CPU architecture. An unrecognized
// shape is never guessed: the reconciler refuses to plan or launch it.
func ShapeArch(shape string) (string, bool) {
	if strings.HasPrefix(shape, "VM.Standard.A1.") {
		return MemberArchArm64, true
	}
	if rest, ok := strings.CutPrefix(shape, "VM.Standard.E"); ok && rest != "" && rest[0] >= '0' && rest[0] <= '9' {
		return MemberArchAMD64, true
	}
	return "", false
}

func (r *ComputeReconciler) Observe(ctx context.Context, declared ComputeDeclared) (ComputeObserved, error) {
	if r == nil || r.Compute == nil || r.Network == nil {
		return ComputeObserved{}, &provider.InvalidOperationError{Message: "compute reconciler is unavailable"}
	}
	if ctx == nil {
		return ComputeObserved{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return ComputeObserved{}, err
	}
	observed := ComputeObserved{}
	var err error
	if observed.AvailabilityDomains, err = r.Compute.ListAvailabilityDomains(ctx); err != nil {
		return ComputeObserved{}, err
	}
	if observed.Members, err = r.Compute.ListMembers(ctx); err != nil {
		return ComputeObserved{}, err
	}
	network, err := (&NetworkReconciler{Gateway: r.Network}).Observe(ctx, declared.Region)
	if err != nil {
		return ComputeObserved{}, err
	}
	if network.VCN != nil {
		observed.Subnets = network.Subnets
		observed.NSGs = network.NSGs
	}
	return observed, nil
}

// memberSubnetAndNSGs resolves launch networking from observed state. The
// launch estate declares one members subnet and member NSGs per Region
// (D-65), so the first declared subnet and every declared NSG apply.
func (r *ComputeReconciler) memberSubnetAndNSGs(declared estate.Region, observed ComputeObserved) (string, []string, error) {
	if len(declared.Network.Subnets) == 0 || len(observed.Subnets) == 0 {
		return "", nil, &provider.InvalidDataError{Message: "member launch requires an observed subnet"}
	}
	declaredSubnet := declared.Network.Subnets[0].Name
	var subnetID string
	for _, subnet := range observed.Subnets {
		if subnet.DisplayName == declaredSubnet && networkSubnetOwned(subnet, declared.Code) && memberIsLive(subnet.LifecycleState) {
			subnetID = subnet.ID
			break
		}
	}
	if !provider.IsOCID(subnetID, "subnet") {
		return "", nil, &provider.InvalidDataError{Message: "member launch requires a live observed subnet"}
	}
	nsgIDs := make([]string, 0, len(observed.NSGs))
	for _, declaredGroup := range declared.Network.SecurityGroups {
		for _, group := range observed.NSGs {
			if group.DisplayName == declaredGroup.Name && networkNSGOwned(group, declared.Code) && memberIsLive(group.LifecycleState) && provider.IsOCID(group.ID, "networksecuritygroup") {
				nsgIDs = append(nsgIDs, group.ID)
			}
		}
	}
	sort.Strings(nsgIDs)
	return subnetID, nsgIDs, nil
}

func (r *ComputeReconciler) Reconcile(ctx context.Context, declared ComputeDeclared, observed ComputeObserved) (OCIPlan, error) {
	if ctx == nil {
		return OCIPlan{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return OCIPlan{}, err
	}
	pool := declared.Region.Members
	if pool.Count < provider.PlacementMinimumMemberHosts {
		return OCIPlan{}, &errs.Argument{Message: "declared member pool is below the placement host floor"}
	}
	if len(declared.Candidates) > 0 {
		if len(declared.Candidates) < 2 {
			return OCIPlan{}, &provider.InvalidDataError{Message: "declared member candidates are incomplete"}
		}
		for _, candidate := range declared.Candidates {
			architecture, ok := ShapeArch(candidate.Shape)
			if !ok || candidate.Architecture != architecture || !provider.IsOCID(candidate.ImageID, "image") || candidate.QualificationRef == "" || candidate.CostRef == "" {
				return OCIPlan{}, &provider.InvalidDataError{Message: "declared member candidate is unqualified or has an invalid architecture/image"}
			}
		}
	} else {
		if _, ok := ShapeArch(pool.PrimaryShape); !ok {
			return OCIPlan{}, &provider.InvalidDataError{Message: "declared primary shape " + pool.PrimaryShape + " has an unrecognized architecture"}
		}
		if _, ok := ShapeArch(pool.FallbackShape); !ok {
			return OCIPlan{}, &provider.InvalidDataError{Message: "declared fallback shape " + pool.FallbackShape + " has an unrecognized architecture"}
		}
	}
	live := make(map[int]ObservedMember, len(observed.Members))
	plan := OCIPlan{}
	for _, member := range observed.Members {
		owned := memberOwnedInRegion(member, declared.Region.Code) && (computeScopeCompartment(r.Compute) == "" || member.CompartmentID == computeScopeCompartment(r.Compute))
		if !owned {
			// Unknown/unmarked instances are drift evidence, never termination
			// authority. They remain untouched even when they resemble a member;
			// in particular, a foreign instance cannot be adopted into a declared
			// slot merely because its display name happens to match.
			continue
		}
		if member.Index < 1 || member.Index > 1024 || member.DisplayName != MemberDisplayName(declared.Region.Code, member.Index) {
			if !owned {
				continue
			}
			return OCIPlan{}, &provider.InvalidDataError{Message: "owned member is outside the declared member namespace"}
		}
		state := observedMemberState(member.LifecycleState)
		if state == memberStateFailed {
			return OCIPlan{}, &provider.InvalidDataError{Message: "observed member " + member.DisplayName + " failed and cannot be used"}
		}
		if state == memberStateUnknown {
			return OCIPlan{}, &provider.InvalidDataError{Message: "observed member " + member.DisplayName + " has an unusable lifecycle state"}
		}
		if state == memberStateAbsent {
			continue
		}
		if member.Index >= 1 && member.Index <= int(pool.Count) {
			if _, duplicate := live[member.Index]; duplicate {
				return OCIPlan{}, &provider.InvalidDataError{Message: "multiple instances occupy declared member slot " + strconv.Itoa(member.Index)}
			}
			live[member.Index] = member
			continue
		}
		// Members outside the declared slots (scale-in or stray) terminate.
		plan.Actions = append(plan.Actions, TerminateMemberAction{InstanceID: member.ID})
	}
	if len(observed.Subnets) == 0 {
		// Launches need the network first; bootstrap ordering guarantees it,
		// and the reconcile loop simply replans on the next pass.
		for index := 1; index <= int(pool.Count); index++ {
			if _, exists := live[index]; !exists {
				return OCIPlan{}, &provider.InvalidDataError{Message: "member launch requires the network to exist first"}
			}
		}
		return plan, nil
	}
	subnetID, nsgIDs, err := r.memberSubnetAndNSGs(declared.Region, observed)
	if err != nil {
		return OCIPlan{}, err
	}
	for index := 1; index <= int(pool.Count); index++ {
		member, exists := live[index]
		if !exists {
			plan.Actions = append(plan.Actions, r.launchAction(declared, index, subnetID, nsgIDs, observed))
			continue
		}
		if observedMemberState(member.LifecycleState) == memberStatePending {
			// OCI is still provisioning/updating this slot. Adopt it and wait;
			// launching a second instance would violate the stable slot identity.
			continue
		}
		if member.Shape != pool.PrimaryShape && member.Shape != pool.FallbackShape {
			if !memberOwnedInRegion(member, declared.Region.Code) || (computeScopeCompartment(r.Compute) != "" && member.CompartmentID != computeScopeCompartment(r.Compute)) {
				continue
			}
			plan.Actions = append(plan.Actions, TerminateMemberAction{InstanceID: member.ID})
			plan.Actions = append(plan.Actions, r.launchAction(declared, index, subnetID, nsgIDs, observed))
			continue
		}
		if member.LifecycleState == "STOPPED" {
			if memberOwnedInRegion(member, declared.Region.Code) && (computeScopeCompartment(r.Compute) == "" || member.CompartmentID == computeScopeCompartment(r.Compute)) {
				plan.Actions = append(plan.Actions, StartMemberAction{InstanceID: member.ID})
			}
		}
	}
	for _, action := range plan.Actions {
		if _, launch := action.(LaunchMemberAction); launch {
			if err := validateBootstrapHostCloudInit(declared.CloudInitByMember, int(pool.Count)); err != nil {
				return OCIPlan{}, err
			}
			break
		}
	}
	return plan, nil
}

type memberLifecycleState uint8

const (
	memberStateAbsent memberLifecycleState = iota
	memberStatePending
	memberStateActive
	memberStateStopped
	memberStateFailed
	memberStateUnknown
)

func observedMemberState(state string) memberLifecycleState {
	switch state {
	case "RUNNING":
		return memberStateActive
	case "STOPPED":
		return memberStateStopped
	case "PROVISIONING", "STARTING", "STOPPING", "UPDATING", "REBOOTING":
		return memberStatePending
	case "TERMINATED", "TERMINATING", "":
		return memberStateAbsent
	case "FAILED", "ERROR":
		return memberStateFailed
	default:
		return memberStateUnknown
	}
}

func (r *ComputeReconciler) bootstrapConverged(value, declaration any) (bool, error) {
	observed, ok := value.(ComputeObserved)
	if !ok {
		return false, &provider.InvalidDataError{Message: "compute convergence observation has the wrong type"}
	}
	declared, ok := declaration.(ComputeDeclared)
	if !ok {
		return false, &provider.InvalidDataError{Message: "compute convergence declaration has the wrong type"}
	}
	slots := make(map[int]ObservedMember, len(observed.Members))
	for _, member := range observed.Members {
		if !memberOwnedInRegion(member, declared.Region.Code) {
			continue
		}
		switch observedMemberState(member.LifecycleState) {
		case memberStateFailed:
			return false, &provider.InvalidDataError{Message: "observed member " + member.DisplayName + " failed and cannot be used"}
		case memberStatePending, memberStateStopped, memberStateAbsent:
			return false, nil
		case memberStateUnknown:
			return false, &provider.InvalidDataError{Message: "observed member " + member.DisplayName + " has an unusable lifecycle state"}
		}
		if member.Index >= 1 && member.Index <= int(declared.Region.Members.Count) {
			if _, duplicate := slots[member.Index]; duplicate {
				return false, &provider.InvalidDataError{Message: "multiple instances occupy declared member slot " + strconv.Itoa(member.Index)}
			}
			slots[member.Index] = member
		}
	}
	for index := 1; index <= int(declared.Region.Members.Count); index++ {
		member, exists := slots[index]
		if !exists || observedMemberState(member.LifecycleState) != memberStateActive {
			return false, nil
		}
		if member.Shape != declared.Region.Members.PrimaryShape && member.Shape != declared.Region.Members.FallbackShape {
			return false, nil
		}
	}
	return true, nil
}

func (r *ComputeReconciler) launchAction(declared ComputeDeclared, index int, subnetID string, nsgIDs []string, observed ComputeObserved) LaunchMemberAction {
	pool := declared.Region.Members
	domain := ""
	if len(observed.AvailabilityDomains) > 0 {
		domain = observed.AvailabilityDomains[(index-1)%len(observed.AvailabilityDomains)]
	}
	cloudInit := declared.CloudInitByMember[index]
	candidates := make([]MemberLaunchCandidate, len(declared.Candidates))
	copy(candidates, declared.Candidates)
	return LaunchMemberAction{Region: declared.Region, Spec: MemberLaunchSpec{
		DisplayName:        MemberDisplayName(declared.Region.Code, index),
		Index:              index,
		Shape:              pool.PrimaryShape,
		FallbackShape:      pool.FallbackShape,
		ImageID:            declared.ImageID,
		FallbackImageID:    declared.FallbackImageID,
		Candidates:         candidates,
		OCPUs:              float64(pool.OCPUs),
		MemoryGiB:          float64(pool.MemoryGiB),
		SubnetID:           subnetID,
		NSGIDs:             nsgIDs,
		AvailabilityDomain: domain,
		CloudInitBase64:    cloudInit,
	}}
}

func (r *ComputeReconciler) Apply(ctx context.Context, declared ComputeDeclared, observed ComputeObserved, plan OCIPlan) error {
	if r == nil || r.Compute == nil {
		return &provider.InvalidOperationError{Message: "compute reconciler is unavailable"}
	}
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, action := range plan.Actions {
		switch a := action.(type) {
		case LaunchMemberAction:
			if err := r.launchWithFallback(ctx, a.Spec); err != nil {
				return err
			}
		case StartMemberAction:
			if err := r.Compute.StartMember(ctx, a.InstanceID); err != nil {
				return err
			}
		case TerminateMemberAction:
			if err := r.terminateOwnedMember(ctx, declared.Region.Code, observed, a.InstanceID); err != nil {
				return err
			}
		default:
			return &provider.InvalidOperationError{Message: "compute reconciler received a foreign action"}
		}
	}
	return nil
}

func memberOwnedInRegion(member ObservedMember, region string) bool {
	return provider.IsOCID(member.ID, "instance") && provider.HasOCIOwnershipTags(member.FreeformTags, ManagedMemberTagValue, region) &&
		member.DisplayName == MemberDisplayName(region, member.Index)
}

func sameObservedMember(a, b ObservedMember) bool {
	return a.ID == b.ID && a.DisplayName == b.DisplayName && a.Index == b.Index && a.Shape == b.Shape &&
		a.LifecycleState == b.LifecycleState && a.AvailabilityDomain == b.AvailabilityDomain &&
		a.CompartmentID == b.CompartmentID && sameStringMap(a.FreeformTags, b.FreeformTags)
}

func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func (r *ComputeReconciler) terminateOwnedMember(ctx context.Context, region string, observed ComputeObserved, id string) error {
	var expected ObservedMember
	found := false
	for _, member := range observed.Members {
		if member.ID == id {
			expected, found = member, true
			break
		}
	}
	if !found || !memberOwnedInRegion(expected, region) || (computeScopeCompartment(r.Compute) != "" && expected.CompartmentID != computeScopeCompartment(r.Compute)) {
		return &provider.InvalidOperationError{Message: "member termination requires positively owned observed instance"}
	}
	if observedMemberState(expected.LifecycleState) == memberStateUnknown {
		return &provider.InvalidDataError{Message: "refusing termination of member with an unusable lifecycle state"}
	}
	current, err := r.Compute.ListMembers(ctx)
	if err != nil {
		return err
	}
	for _, member := range current {
		if member.ID != id {
			continue
		}
		if !memberOwnedInRegion(member, region) || (computeScopeCompartment(r.Compute) != "" && member.CompartmentID != computeScopeCompartment(r.Compute)) {
			return &provider.InvalidOperationError{Message: "refusing stale or ownership-changed member termination"}
		}
		if observedMemberState(member.LifecycleState) == memberStateUnknown {
			return &provider.InvalidDataError{Message: "refusing termination of member with an unusable lifecycle state"}
		}
		if !sameObservedMember(member, expected) {
			return &provider.InvalidOperationError{Message: "refusing stale or ownership-changed member termination"}
		}
		owner := r.RemovalOwner
		if owner == nil {
			var ok bool
			owner, ok = r.Compute.(MemberRemovalOwner)
			if !ok {
				return &provider.InvalidOperationError{Message: "member termination requires a durable removal owner with placement drain/readiness proof"}
			}
		}
		survivors := make([]ObservedMember, 0, len(current)-1)
		for _, candidate := range current {
			if candidate.ID != id && memberOwnedInRegion(candidate, region) {
				survivors = append(survivors, candidate)
			}
		}
		return owner.RemoveMember(ctx, region, member, survivors)
	}
	return nil // already terminated/absent
}

// launchWithFallback implements the D-69 capacity rule: an out-of-capacity
// rejection on the primary shape (Ampere A1 exhaustion is routine) retries
// once on the declared fallback shape, booting the image declared for that
// shape's architecture — A1 hosts are arm64, the x86 flex shapes are amd64,
// and a cross-architecture fallback without its own image fails closed
// instead of launching an unbootable host. Quota errors are never retried
// on another shape: they need an owner decision.
func (r *ComputeReconciler) launchWithFallback(ctx context.Context, spec MemberLaunchSpec) error {
	if len(spec.Candidates) > 0 {
		return r.launchCandidates(ctx, spec)
	}
	_, err := r.Compute.LaunchMember(ctx, spec)
	if err == nil {
		return nil
	}
	var capacity *OCIShapeCapacityError
	if !errors.As(err, &capacity) || spec.FallbackShape == "" || spec.FallbackShape == spec.Shape {
		return err
	}
	primaryArch, primaryOK := ShapeArch(spec.Shape)
	fallbackArch, fallbackOK := ShapeArch(spec.FallbackShape)
	if !primaryOK || !fallbackOK {
		return err
	}
	image := spec.FallbackImageID
	if !provider.IsOCID(image, "image") {
		if fallbackArch != primaryArch {
			return &provider.InvalidDataError{Message: "fallback shape " + spec.FallbackShape + " is " + fallbackArch + " while the primary is " + primaryArch + "; the declaration names no " + fallbackArch + " boot image"}
		}
		image = spec.ImageID
	}
	fallback := spec
	fallback.Shape = spec.FallbackShape
	fallback.ImageID = image
	_, err = r.Compute.LaunchMember(ctx, fallback)
	return err
}

func (r *ComputeReconciler) launchCandidates(ctx context.Context, spec MemberLaunchSpec) error {
	var lastCapacity error
	for index, candidate := range spec.Candidates {
		if candidate.Shape == "" || candidate.ImageID == "" || candidate.QualificationRef == "" || candidate.CostRef == "" {
			return &provider.InvalidDataError{Message: "qualified member launch candidate is incomplete"}
		}
		architecture, ok := ShapeArch(candidate.Shape)
		if !ok || candidate.Architecture != architecture {
			return &provider.InvalidDataError{Message: "qualified member launch candidate architecture does not match its shape"}
		}
		attempt := spec
		attempt.Shape = candidate.Shape
		attempt.ImageID = candidate.ImageID
		attempt.FallbackShape = ""
		attempt.FallbackImageID = ""
		attempt.Candidates = nil
		_, err := r.Compute.LaunchMember(ctx, attempt)
		if err == nil {
			return nil
		}
		var capacity *OCIShapeCapacityError
		if !errors.As(err, &capacity) {
			return err
		}
		lastCapacity = err
		if index == len(spec.Candidates)-1 {
			break
		}
	}
	return lastCapacity
}

const (
	tsNodeUser         = "terrascale-node"
	tsNodeTrustKeyPath = "/etc/terrascale/ts-node.pub"
	tsNodeDataVolume   = "/var/lib/terrascale/ts-node"
)

// TSNodeCloudInit renders the D-67 bootstrap cloud-config and returns its
// base64 OCI user_data value. It installs ONLY ts-node: download the release
// binary and its detached signature, verify both the SHA-256 and Ed25519
// signature, expose it through the current symlink, and run one hardened
// system unit as a dedicated account. The optional arguments are the
// signature URL and pinned public-key material (hex, base64, or Ed25519 PKIX
// PEM). With no optional arguments the signature URL is artifactURL + ".sig"
// and the image-provisioned key at tsNodeTrustKeyPath is used. No credentials
// are written to the host or emitted in cloud-init command output.
func renderTSNodeCloudInit(version, sha256Hex, artifactURL, signatureURL, publicKey string) (string, error) {
	if len(version) < 1 || len(version) > 32 || !provider.ValidToken(version) {
		return "", &errs.Argument{Message: "ts-node release version is invalid"}
	}
	if len(sha256Hex) != 64 || strings.ToLower(sha256Hex) != sha256Hex {
		return "", &errs.Argument{Message: "ts-node release digest must be canonical SHA-256"}
	}
	if _, err := hex.DecodeString(sha256Hex); err != nil {
		return "", &errs.Argument{Message: "ts-node release digest must be canonical SHA-256"}
	}
	if err := validateTSNodeReleaseURL(artifactURL); err != nil {
		return "", &errs.Argument{Message: "ts-node release URL is invalid"}
	}
	if err := validateTSNodeReleaseURL(signatureURL); err != nil {
		return "", err
	}
	publicKeyPath := tsNodeTrustKeyPath
	publicKeyPEM, err := canonicalTSNodePublicKey(publicKey)
	if err != nil {
		return "", err
	}
	artifactPath := "/opt/terrascale/ts-node/" + version + "/ts-node"
	artifactTempPath := artifactPath + ".download"
	signatureTempPath := artifactPath + ".sig.download"
	var b strings.Builder
	b.WriteString("#cloud-config\n")
	b.WriteString("write_files:\n")
	if publicKeyPEM != "" {
		b.WriteString("  - path: " + publicKeyPath + "\n")
		b.WriteString("    owner: root:root\n")
		b.WriteString("    permissions: '0644'\n")
		b.WriteString("    content: |\n")
		for _, line := range strings.Split(strings.TrimSuffix(publicKeyPEM, "\n"), "\n") {
			b.WriteString("      " + line + "\n")
		}
	}
	b.WriteString("  - path: /etc/systemd/system/terrascale-ts-node.service\n")
	b.WriteString("    owner: root:root\n")
	b.WriteString("    permissions: '0644'\n")
	b.WriteString("    content: |\n")
	unit, err := tsnodebootstrap.RenderSystemdUnit(tsnodebootstrap.ProductionConfig())
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSuffix(unit, "\n"), "\n") {
		b.WriteString("      " + line + "\n")
	}
	b.WriteString("runcmd:\n")
	// These are the only host executables used by this seed. Fail before
	// downloading anything when the selected OCI image cannot run bootstrap.
	for _, executable := range []string{"/usr/bin/install", "/usr/bin/curl", "/usr/bin/sha256sum", "/usr/bin/openssl", "/usr/bin/systemctl"} {
		b.WriteString("  - [/usr/bin/test, -x, " + executable + "]\n")
	}
	b.WriteString("  - [/usr/bin/install, -d, -o, root, -g, root, -m, 0755, /opt/terrascale/ts-node/" + version + "]\n")
	b.WriteString("  - [/usr/bin/install, -d, -o, root, -g, root, -m, 0700, " + tsNodeDataVolume + "]\n")
	b.WriteString("  - [/usr/bin/test, -s, " + publicKeyPath + "]\n")
	b.WriteString("  - [/usr/bin/rm, -f, " + artifactTempPath + ", " + signatureTempPath + "]\n")
	b.WriteString("  - [/usr/bin/curl, --fail, --silent, --show-error, --location, --proto, '=https', --tlsv1.2, --max-redirs, 3, --connect-timeout, 10, --max-time, 300, --max-filesize, 67108864, --output, " + artifactTempPath + ", " + tsNodeShellQuote(artifactURL) + "]\n")
	b.WriteString("  - [/usr/bin/curl, --fail, --silent, --show-error, --location, --proto, '=https', --tlsv1.2, --max-redirs, 3, --connect-timeout, 10, --max-time, 300, --max-filesize, 128, --output, " + signatureTempPath + ", " + tsNodeShellQuote(signatureURL) + "]\n")
	b.WriteString("  - [/bin/sh, -c, \"printf '%s  %s\\\\n' " + sha256Hex + " " + artifactTempPath + " | /usr/bin/sha256sum -c --strict\"]\n")
	b.WriteString("  - [/usr/bin/openssl, pkeyutl, -verify, -pubin, -inkey, " + publicKeyPath + ", -in, " + artifactTempPath + ", -sigfile, " + signatureTempPath + "]\n")
	b.WriteString("  - [/usr/bin/install, -o, root, -g, root, -m, 0755, " + artifactTempPath + ", " + artifactPath + "]\n")
	b.WriteString("  - [/usr/bin/rm, -f, " + artifactTempPath + ", " + signatureTempPath + "]\n")
	b.WriteString("  - [/usr/bin/ln, -sfn, /opt/terrascale/ts-node/" + version + ", /opt/terrascale/ts-node/current]\n")
	b.WriteString("  - [/usr/bin/systemctl, daemon-reload]\n")
	b.WriteString("  - [/usr/bin/systemctl, enable, --now, terrascale-ts-node.service]\n")
	return base64.StdEncoding.EncodeToString([]byte(b.String())), nil
}

func validateTSNodeReleaseURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(value, "\r\n\x00") || len(value) > 2048 {
		return errors.New("invalid release URL")
	}
	return nil
}

func canonicalTSNodePublicKey(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > 4096 || strings.ContainsRune(trimmed, '\x00') {
		return "", errors.New("empty trust key")
	}
	var publicKey ed25519.PublicKey
	if block, rest := pem.Decode([]byte(trimmed)); block != nil && strings.TrimSpace(string(rest)) == "" {
		if block.Type != "PUBLIC KEY" {
			return "", errors.New("trust key is not an Ed25519 PKIX key")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return "", err
		}
		var ok bool
		publicKey, ok = parsed.(ed25519.PublicKey)
		if !ok {
			return "", errors.New("trust key is not Ed25519")
		}
	} else {
		decoded, err := hex.DecodeString(trimmed)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			decoded, err = base64.StdEncoding.DecodeString(trimmed)
			if err != nil || len(decoded) != ed25519.PublicKeySize {
				decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
			}
		}
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return "", errors.New("trust key is not 32 Ed25519 bytes")
		}
		publicKey = ed25519.PublicKey(decoded)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func tsNodeShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

// ociMemberGateway is the real compute gateway over the signed core-service
// transport. Instances are launched with no SSH keys and no metadata beyond
// the cloud-init user_data: hosts use instance principals, never files.
type ociMemberGateway struct {
	Core          *provider.OCIHTTPTransport
	CompartmentID string
	ImageID       string
	Adapter       *provider.OCIComputeAdapter
	Epoch         provider.ProviderEpoch
}

// NewOCIMemberGateway validates the compartment and launch image scope.
// NewDurableOCIMemberGateway binds member launches to the lease-owned durable
// provider journal. Production composition must use this constructor.
func NewDurableOCIMemberGateway(core *provider.OCIHTTPTransport, adapter *provider.OCIComputeAdapter, compartmentID, imageID string, epoch provider.ProviderEpoch) (ComputeGateway, error) {
	if adapter == nil || epoch.Value == 0 {
		return nil, &errs.Argument{Message: "durable member gateway requires a provider adapter and epoch"}
	}
	gateway, err := NewOCIMemberGateway(core, compartmentID, imageID)
	if err != nil {
		return nil, err
	}
	result := gateway.(*ociMemberGateway)
	result.Adapter, result.Epoch = adapter, epoch
	return result, nil
}

func NewOCIMemberGateway(core *provider.OCIHTTPTransport, compartmentID, imageID string) (ComputeGateway, error) {
	if core == nil || core.Config.Service != provider.OCIServiceCore {
		return nil, &errs.Argument{Message: "member gateway requires the OCI core transport"}
	}
	if !provider.IsOCID(compartmentID, "compartment") || !provider.IsOCID(imageID, "image") {
		return nil, &errs.Argument{Message: "member gateway requires a compartment and image identity"}
	}
	return &ociMemberGateway{Core: core, CompartmentID: compartmentID, ImageID: imageID}, nil
}

var _ ComputeGateway = (*ociMemberGateway)(nil)

type ociMemberDocument struct {
	ID                 string            `json:"id"`
	CompartmentID      string            `json:"compartmentId"`
	DisplayName        string            `json:"displayName"`
	LifecycleState     string            `json:"lifecycleState"`
	Shape              string            `json:"shape"`
	AvailabilityDomain string            `json:"availabilityDomain"`
	FreeformTags       map[string]string `json:"freeformTags"`
}

func (g *ociMemberGateway) ListAvailabilityDomains(ctx context.Context) ([]string, error) {
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	type domain struct {
		Name string `json:"name"`
	}
	items, err := provider.ReadOCICollection[domain](ctx, g.Core, "/20160918/availabilityDomains", query)
	if err != nil {
		return nil, err
	}
	domains := make([]string, 0, len(items))
	for _, item := range items {
		if len(item.Name) == 0 || len(item.Name) > 128 {
			return nil, &provider.InvalidDataError{Message: "OCI availability domain response is invalid"}
		}
		domains = append(domains, item.Name)
	}
	return domains, nil
}

func (g *ociMemberGateway) ListMembers(ctx context.Context) ([]ObservedMember, error) {
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	items, err := provider.ReadOCICollection[ociMemberDocument](ctx, g.Core, "/20160918/instances", query)
	if err != nil {
		return nil, err
	}
	members := make([]ObservedMember, 0, len(items))
	for _, item := range items {
		if !provider.IsOCID(item.ID, "instance") {
			return nil, &provider.InvalidDataError{Message: "OCI member instance response has an invalid identity"}
		}
		index := 0
		if item.FreeformTags[provider.OCIManagedTag] == ManagedMemberTagValue {
			parsed, err := strconv.Atoi(item.FreeformTags[MemberIndexTag])
			if err != nil || parsed < 1 || parsed > 1024 {
				return nil, &provider.InvalidDataError{Message: "OCI member instance has an invalid member index"}
			}
			index = parsed
		}
		members = append(members, ObservedMember{ID: item.ID, DisplayName: item.DisplayName, Index: index, Shape: item.Shape, LifecycleState: item.LifecycleState, AvailabilityDomain: item.AvailabilityDomain, CompartmentID: item.CompartmentID, FreeformTags: provider.CopyOCITags(item.FreeformTags)})
	}
	return members, nil
}

func (g *ociMemberGateway) LaunchMember(ctx context.Context, spec MemberLaunchSpec) (ObservedMember, error) {
	if g.Adapter != nil {
		return g.launchMemberDurable(ctx, spec)
	}

	if !validEstateName(strings.TrimPrefix(spec.DisplayName, "terrascale-")) || spec.Index < 1 || spec.Index > 1024 ||
		len(spec.Shape) == 0 || len(spec.Shape) > 96 || spec.OCPUs <= 0 || spec.OCPUs > 192 || spec.MemoryGiB <= 0 || spec.MemoryGiB > 2048 ||
		!provider.IsOCID(spec.SubnetID, "subnet") || len(spec.CloudInitBase64) == 0 || len(spec.CloudInitBase64) > 48*1024 {
		return ObservedMember{}, &errs.Argument{Message: "member launch request is invalid"}
	}
	for _, nsg := range spec.NSGIDs {
		if !provider.IsOCID(nsg, "networksecuritygroup") {
			return ObservedMember{}, &errs.Argument{Message: "member launch request has an invalid network security group"}
		}
	}
	if err := validateBootstrapHostCloudInit(map[int]string{1: spec.CloudInitBase64}, 1); err != nil {
		return ObservedMember{}, err
	}
	// Boot the image carried by the spec — the reconciler resolves one per
	// shape architecture (D-69) — falling back to the gateway's image when
	// the spec names none.
	imageID := g.ImageID
	if spec.ImageID != "" {
		imageID = spec.ImageID
	}
	if !provider.IsOCID(imageID, "image") || (spec.FallbackImageID != "" && !provider.IsOCID(spec.FallbackImageID, "image")) {
		return ObservedMember{}, &errs.Argument{Message: "member launch request has an invalid boot image"}
	}
	payload := struct {
		CompartmentID string `json:"compartmentId"`
		DisplayName   string `json:"displayName"`
		Availability  string `json:"availabilityDomain,omitempty"`
		Shape         string `json:"shape"`
		ShapeConfig   struct {
			OCPUs       float64 `json:"ocpus"`
			MemoryInGBs float64 `json:"memoryInGBs"`
		} `json:"shapeConfig"`
		CreateVnicDetails struct {
			SubnetID                string   `json:"subnetId"`
			AssignPublicIP          bool     `json:"assignPublicIp"`
			NetworkSecurityGroupIDs []string `json:"nsgIds,omitempty"`
		} `json:"createVnicDetails"`
		SourceDetails struct {
			SourceType string `json:"sourceType"`
			ImageID    string `json:"imageId"`
		} `json:"sourceDetails"`
		Metadata     map[string]string `json:"metadata"`
		FreeformTags map[string]string `json:"freeformTags"`
	}{
		CompartmentID: g.CompartmentID,
		DisplayName:   spec.DisplayName,
		Availability:  spec.AvailabilityDomain,
		Shape:         spec.Shape,
		ShapeConfig: struct {
			OCPUs       float64 `json:"ocpus"`
			MemoryInGBs float64 `json:"memoryInGBs"`
		}{OCPUs: spec.OCPUs, MemoryInGBs: spec.MemoryGiB},
		CreateVnicDetails: struct {
			SubnetID                string   `json:"subnetId"`
			AssignPublicIP          bool     `json:"assignPublicIp"`
			NetworkSecurityGroupIDs []string `json:"nsgIds,omitempty"`
		}{SubnetID: spec.SubnetID, AssignPublicIP: false, NetworkSecurityGroupIDs: spec.NSGIDs},
		SourceDetails: struct {
			SourceType string `json:"sourceType"`
			ImageID    string `json:"imageId"`
		}{SourceType: "image", ImageID: imageID},
		Metadata:     map[string]string{"user_data": spec.CloudInitBase64},
		FreeformTags: map[string]string{provider.OCIManagedTag: ManagedMemberTagValue, provider.OCIScopeTag: strings.TrimSuffix(strings.TrimPrefix(spec.DisplayName, "terrascale-"), "-"+strconv.Itoa(spec.Index)), MemberIndexTag: strconv.Itoa(spec.Index)},
	}
	var document ociMemberDocument
	retryToken := spec.DisplayName
	if err := doOCIJSON(ctx, g.Core, http.MethodPost, "/20160918/instances", payload, map[string]string{"opc-retry-token": retryToken}, &document); err != nil {
		return ObservedMember{}, err
	}
	if !provider.IsOCID(document.ID, "instance") {
		return ObservedMember{}, &provider.InvalidDataError{Message: "OCI member launch response is invalid"}
	}
	return ObservedMember{ID: document.ID, DisplayName: document.DisplayName, Index: spec.Index, Shape: document.Shape, LifecycleState: document.LifecycleState, AvailabilityDomain: document.AvailabilityDomain}, nil
}

func (g *ociMemberGateway) launchMemberDurable(ctx context.Context, spec MemberLaunchSpec) (ObservedMember, error) {
	candidates := make([]provider.ComputeCapacityCandidate, 0, len(spec.Candidates))
	for _, candidate := range spec.Candidates {
		candidates = append(candidates, provider.ComputeCapacityCandidate{
			AvailabilityDomain: spec.AvailabilityDomain, SubnetID: spec.SubnetID,
			Shape: candidate.Shape, Architecture: candidate.Architecture, ImageID: candidate.ImageID,
			OCPUs: spec.OCPUs, MemoryGiB: spec.MemoryGiB,
		})
	}
	if len(candidates) == 0 {
		return ObservedMember{}, &errs.Argument{Message: "durable member launch requires qualified capacity candidates"}
	}
	opID, err := provider.NewProviderOperationId("member-" + spec.DisplayName)
	if err != nil {
		return ObservedMember{}, err
	}
	intent := provider.ProviderMutationIntent{
		OperationID: opID,
		Scope:       provider.ProviderMutationScope("compute", g.CompartmentID, spec.DisplayName),
		Action:      "compute.launch", Epoch: g.Epoch,
		IdempotencyKey: provider.ProviderIdempotencyKey{Value: provider.ProviderMutationFingerprint("compute.launch", g.CompartmentID, spec.DisplayName)},
	}
	request := provider.ComputeLaunchRequest{Mutation: intent, CompartmentID: g.CompartmentID, DisplayName: spec.DisplayName,
		NSGIDs: append([]string(nil), spec.NSGIDs...), BootstrapBase64: spec.CloudInitBase64, Candidates: candidates,
		Tags: map[string]string{}}
	request.Mutation.Fingerprint = provider.ComputeLaunchMutationFingerprint(request)
	instance, err := g.Adapter.LaunchInstance(ctx, request)
	if err != nil {
		return ObservedMember{}, err
	}
	return ObservedMember{ID: instance.ID, DisplayName: spec.DisplayName, Index: spec.Index, Shape: instance.Shape,
		LifecycleState: instance.LifecycleState, AvailabilityDomain: instance.AvailabilityDomain, CompartmentID: g.CompartmentID}, nil
}

func (g *ociMemberGateway) StartMember(ctx context.Context, instanceID string) error {
	if !provider.IsOCID(instanceID, "instance") {
		return &errs.Argument{Message: "member start requires an instance identity"}
	}
	return doOCIJSON[struct{}](ctx, g.Core, http.MethodPost, "/20160918/instances/"+url.PathEscape(instanceID)+"/actions/start", struct{}{}, nil, nil)
}

func (g *ociMemberGateway) TerminateMember(ctx context.Context, instanceID string) error {
	if !provider.IsOCID(instanceID, "instance") {
		return &errs.Argument{Message: "member terminate requires an instance identity"}
	}
	return doOCIJSON[struct{}](ctx, g.Core, http.MethodDelete, "/20160918/instances/"+url.PathEscape(instanceID), nil, nil, nil)
}
