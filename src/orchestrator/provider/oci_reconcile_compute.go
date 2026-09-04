package provider

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// The compute reconciler launches and repairs the Region's member hosts
// (D-65/D-67): Ampere A1 primary shape, the declared flex shape as the
// automatic fallback when A1 capacity is unavailable (D-69), a cloud-init
// that installs ONLY ts-node, and no credentials anywhere on the host — the
// hosts authenticate to OCI with instance principals and fetch everything
// else from the orchestrator.

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
}

// MemberLaunchSpec is one member launch request. FallbackShape is tried
// automatically when the primary shape is out of capacity.
type MemberLaunchSpec struct {
	DisplayName        string
	Index              int
	Shape              string
	FallbackShape      string
	OCPUs, MemoryGiB   float64
	SubnetID           string
	NSGIDs             []string
	AvailabilityDomain string
	CloudInitBase64    string
}

type ComputeDeclared struct {
	Region          estate.Region
	ImageID         string
	CloudInitBase64 string
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
}

var _ OCIReconciler[ComputeDeclared, ComputeObserved] = (*ComputeReconciler)(nil)

func memberIsLive(state string) bool {
	return state != "TERMINATED" && state != "TERMINATING" && state != ""
}

func (r *ComputeReconciler) Observe(ctx context.Context, declared ComputeDeclared) (ComputeObserved, error) {
	if r == nil || r.Compute == nil || r.Network == nil {
		return ComputeObserved{}, &InvalidOperationError{Message: "compute reconciler is unavailable"}
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
		return "", nil, &InvalidDataError{Message: "member launch requires an observed subnet"}
	}
	declaredSubnet := declared.Network.Subnets[0].Name
	var subnetID string
	for _, subnet := range observed.Subnets {
		if subnet.DisplayName == declaredSubnet && memberIsLive(subnet.LifecycleState) {
			subnetID = subnet.ID
			break
		}
	}
	if !isOCID(subnetID, "subnet") {
		return "", nil, &InvalidDataError{Message: "member launch requires a live observed subnet"}
	}
	nsgIDs := make([]string, 0, len(observed.NSGs))
	for _, declaredGroup := range declared.Network.SecurityGroups {
		for _, group := range observed.NSGs {
			if group.DisplayName == declaredGroup.Name && memberIsLive(group.LifecycleState) && isOCID(group.ID, "networksecuritygroup") {
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
	if pool.Count < PlacementMinimumMemberHosts {
		return OCIPlan{}, &errs.Argument{Message: "declared member pool is below the placement host floor"}
	}
	live := make(map[int]ObservedMember, len(observed.Members))
	plan := OCIPlan{}
	for _, member := range observed.Members {
		if !memberIsLive(member.LifecycleState) {
			continue
		}
		if member.Index >= 1 && member.Index <= int(pool.Count) {
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
				return OCIPlan{}, &InvalidDataError{Message: "member launch requires the network to exist first"}
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
		if member.Shape != pool.PrimaryShape && member.Shape != pool.FallbackShape {
			plan.Actions = append(plan.Actions, TerminateMemberAction{InstanceID: member.ID})
			plan.Actions = append(plan.Actions, r.launchAction(declared, index, subnetID, nsgIDs, observed))
			continue
		}
		if member.LifecycleState == "STOPPED" {
			plan.Actions = append(plan.Actions, StartMemberAction{InstanceID: member.ID})
		}
	}
	return plan, nil
}

func (r *ComputeReconciler) launchAction(declared ComputeDeclared, index int, subnetID string, nsgIDs []string, observed ComputeObserved) LaunchMemberAction {
	pool := declared.Region.Members
	domain := ""
	if len(observed.AvailabilityDomains) > 0 {
		domain = observed.AvailabilityDomains[(index-1)%len(observed.AvailabilityDomains)]
	}
	return LaunchMemberAction{Region: declared.Region, Spec: MemberLaunchSpec{
		DisplayName:        MemberDisplayName(declared.Region.Code, index),
		Index:              index,
		Shape:              pool.PrimaryShape,
		FallbackShape:      pool.FallbackShape,
		OCPUs:              float64(pool.OCPUs),
		MemoryGiB:          float64(pool.MemoryGiB),
		SubnetID:           subnetID,
		NSGIDs:             nsgIDs,
		AvailabilityDomain: domain,
		CloudInitBase64:    declared.CloudInitBase64,
	}}
}

func (r *ComputeReconciler) Apply(ctx context.Context, declared ComputeDeclared, observed ComputeObserved, plan OCIPlan) error {
	if r == nil || r.Compute == nil {
		return &InvalidOperationError{Message: "compute reconciler is unavailable"}
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
			if err := r.Compute.TerminateMember(ctx, a.InstanceID); err != nil {
				return err
			}
		default:
			return &InvalidOperationError{Message: "compute reconciler received a foreign action"}
		}
	}
	return nil
}

// launchWithFallback implements the D-69 capacity rule: an out-of-capacity
// rejection on the primary shape (Ampere A1 exhaustion is routine) retries
// once on the declared fallback shape. Quota errors are never retried on
// another shape: they need an owner decision.
func (r *ComputeReconciler) launchWithFallback(ctx context.Context, spec MemberLaunchSpec) error {
	_, err := r.Compute.LaunchMember(ctx, spec)
	if err == nil {
		return nil
	}
	var capacity *OCIShapeCapacityError
	if !errors.As(err, &capacity) || spec.FallbackShape == "" || spec.FallbackShape == spec.Shape {
		return err
	}
	fallback := spec
	fallback.Shape = spec.FallbackShape
	_, err = r.Compute.LaunchMember(ctx, fallback)
	return err
}

// TSNodeCloudInit renders the D-67 bootstrap cloud-config and returns its
// base64 OCI user_data value. It installs ONLY ts-node: download the signed
// release binary, verify its SHA-256, expose it through the `current`
// symlink, and run one minimal system unit. Hosts carry no credentials.
func TSNodeCloudInit(version, sha256Hex, artifactURL string) (string, error) {
	if len(version) < 1 || len(version) > 32 || !tokenPattern.MatchString(version) {
		return "", &errs.Argument{Message: "ts-node release version is invalid"}
	}
	if len(sha256Hex) != 64 || strings.ToLower(sha256Hex) != sha256Hex {
		return "", &errs.Argument{Message: "ts-node release digest must be canonical SHA-256"}
	}
	if _, err := hex.DecodeString(sha256Hex); err != nil {
		return "", &errs.Argument{Message: "ts-node release digest must be canonical SHA-256"}
	}
	parsed, err := url.Parse(artifactURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || strings.ContainsAny(artifactURL, "\r\n\x00") || len(artifactURL) > 2048 {
		return "", &errs.Argument{Message: "ts-node release URL is invalid"}
	}
	var b strings.Builder
	b.WriteString("#cloud-config\n")
	b.WriteString("write_files:\n")
	b.WriteString("  - path: /etc/systemd/system/terrascale-ts-node.service\n")
	b.WriteString("    content: |\n")
	b.WriteString("      [Unit]\n")
	b.WriteString("      Description=TerraScale ts-node host agent\n")
	b.WriteString("      After=network-online.target\n")
	b.WriteString("      Wants=network-online.target\n")
	b.WriteString("      [Service]\n")
	b.WriteString("      ExecStart=/opt/terrascale/ts-node/current/ts-node\n")
	b.WriteString("      Restart=always\n")
	b.WriteString("      RestartSec=2\n")
	b.WriteString("      [Install]\n")
	b.WriteString("      WantedBy=multi-user.target\n")
	b.WriteString("runcmd:\n")
	b.WriteString("  - [mkdir, -p, /opt/terrascale/ts-node/" + version + "]\n")
	b.WriteString("  - [curl, -fsSL, -o, /opt/terrascale/ts-node/" + version + "/ts-node, " + artifactURL + "]\n")
	b.WriteString("  - [sh, -c, \"echo '" + sha256Hex + "  /opt/terrascale/ts-node/" + version + "/ts-node' | sha256sum -c -\"]\n")
	b.WriteString("  - [chmod, 0755, /opt/terrascale/ts-node/" + version + "/ts-node]\n")
	b.WriteString("  - [ln, -sfn, /opt/terrascale/ts-node/" + version + ", /opt/terrascale/ts-node/current]\n")
	b.WriteString("  - [systemctl, daemon-reload]\n")
	b.WriteString("  - [systemctl, enable, --now, terrascale-ts-node]\n")
	return base64.StdEncoding.EncodeToString([]byte(b.String())), nil
}

// ociMemberGateway is the real compute gateway over the signed core-service
// transport. Instances are launched with no SSH keys and no metadata beyond
// the cloud-init user_data: hosts use instance principals, never files.
type ociMemberGateway struct {
	Core          *OCIHTTPTransport
	CompartmentID string
	ImageID       string
}

// NewOCIMemberGateway validates the compartment and launch image scope.
func NewOCIMemberGateway(core *OCIHTTPTransport, compartmentID, imageID string) (ComputeGateway, error) {
	if core == nil || core.Config.Service != OCIServiceCore {
		return nil, &errs.Argument{Message: "member gateway requires the OCI core transport"}
	}
	if !isOCID(compartmentID, "compartment") || !isOCID(imageID, "image") {
		return nil, &errs.Argument{Message: "member gateway requires a compartment and image identity"}
	}
	return &ociMemberGateway{Core: core, CompartmentID: compartmentID, ImageID: imageID}, nil
}

var _ ComputeGateway = (*ociMemberGateway)(nil)

type ociMemberDocument struct {
	ID                 string            `json:"id"`
	DisplayName        string            `json:"displayName"`
	LifecycleState     string            `json:"lifecycleState"`
	Shape              string            `json:"shape"`
	AvailabilityDomain string            `json:"availabilityDomain"`
	FreeformTags       map[string]string `json:"freeformTags"`
}

func (g *ociMemberGateway) ListAvailabilityDomains(ctx context.Context) ([]string, error) {
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	var list struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Core, http.MethodGet, "/20160918/availabilityDomains?"+query.Encode(), nil, nil, &list); err != nil {
		return nil, err
	}
	domains := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		if len(item.Name) == 0 || len(item.Name) > 128 {
			return nil, &InvalidDataError{Message: "OCI availability domain response is invalid"}
		}
		domains = append(domains, item.Name)
	}
	return domains, nil
}

func (g *ociMemberGateway) ListMembers(ctx context.Context) ([]ObservedMember, error) {
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	var list struct {
		Items []ociMemberDocument `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Core, http.MethodGet, "/20160918/instances?"+query.Encode(), nil, nil, &list); err != nil {
		return nil, err
	}
	members := make([]ObservedMember, 0, len(list.Items))
	for _, item := range list.Items {
		if item.FreeformTags["terrascale-managed"] != ManagedMemberTagValue || !isOCID(item.ID, "instance") {
			continue
		}
		index, err := strconv.Atoi(item.FreeformTags[MemberIndexTag])
		if err != nil || index < 1 || index > 1024 {
			return nil, &InvalidDataError{Message: "OCI member instance has an invalid member index"}
		}
		members = append(members, ObservedMember{ID: item.ID, DisplayName: item.DisplayName, Index: index, Shape: item.Shape, LifecycleState: item.LifecycleState, AvailabilityDomain: item.AvailabilityDomain})
	}
	return members, nil
}

func (g *ociMemberGateway) LaunchMember(ctx context.Context, spec MemberLaunchSpec) (ObservedMember, error) {
	if !validEstateName(strings.TrimPrefix(spec.DisplayName, "terrascale-")) || spec.Index < 1 || spec.Index > 1024 ||
		len(spec.Shape) == 0 || len(spec.Shape) > 96 || spec.OCPUs <= 0 || spec.OCPUs > 192 || spec.MemoryGiB <= 0 || spec.MemoryGiB > 2048 ||
		!isOCID(spec.SubnetID, "subnet") || len(spec.CloudInitBase64) == 0 || len(spec.CloudInitBase64) > 48*1024 {
		return ObservedMember{}, &errs.Argument{Message: "member launch request is invalid"}
	}
	for _, nsg := range spec.NSGIDs {
		if !isOCID(nsg, "networksecuritygroup") {
			return ObservedMember{}, &errs.Argument{Message: "member launch request has an invalid network security group"}
		}
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
		}{SourceType: "image", ImageID: g.ImageID},
		Metadata:     map[string]string{"user_data": spec.CloudInitBase64},
		FreeformTags: map[string]string{"terrascale-managed": ManagedMemberTagValue, MemberIndexTag: strconv.Itoa(spec.Index)},
	}
	var document ociMemberDocument
	retryToken := spec.DisplayName
	if err := doOCIJSON(ctx, g.Core, http.MethodPost, "/20160918/instances", payload, map[string]string{"opc-retry-token": retryToken}, &document); err != nil {
		return ObservedMember{}, err
	}
	if !isOCID(document.ID, "instance") {
		return ObservedMember{}, &InvalidDataError{Message: "OCI member launch response is invalid"}
	}
	return ObservedMember{ID: document.ID, DisplayName: document.DisplayName, Index: spec.Index, Shape: document.Shape, LifecycleState: document.LifecycleState, AvailabilityDomain: document.AvailabilityDomain}, nil
}

func (g *ociMemberGateway) StartMember(ctx context.Context, instanceID string) error {
	if !isOCID(instanceID, "instance") {
		return &errs.Argument{Message: "member start requires an instance identity"}
	}
	return doOCIJSON[struct{}](ctx, g.Core, http.MethodPost, "/20160918/instances/"+url.PathEscape(instanceID)+"/actions/start", struct{}{}, nil, nil)
}

func (g *ociMemberGateway) TerminateMember(ctx context.Context, instanceID string) error {
	if !isOCID(instanceID, "instance") {
		return &errs.Argument{Message: "member terminate requires an instance identity"}
	}
	return doOCIJSON[struct{}](ctx, g.Core, http.MethodDelete, "/20160918/instances/"+url.PathEscape(instanceID), nil, nil, nil)
}
