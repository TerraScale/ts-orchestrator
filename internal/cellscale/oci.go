package cellscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/limits"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	tagCell        = "ts-cell"
	tagRole        = "ts-role"
	tagLaunchToken = "ts-launch-token"
	roleDB         = "db"
)

var subnetDNSLabelRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,14}$`)

// Template is the launch template of a cell's db instances.
type Template struct {
	// Region is the OCI region id, for example sa-saopaulo-1.
	Region             string `json:"region"`
	CompartmentID      string `json:"compartment_id"`
	AvailabilityDomain string `json:"availability_domain"`
	SubnetID           string `json:"subnet_id"`
	ImageID            string `json:"image_id"`
	// Shape is a flex shape such as VM.Standard.A1.Flex.
	Shape string `json:"shape"`
	// BootVolumeGB is the boot volume size; 0 keeps the image default.
	BootVolumeGB int64 `json:"boot_volume_gb,omitempty"`
	// UserData is the base64 cloud-init payload.
	UserData string `json:"user_data,omitempty"`
}

// Validate rejects a template OCI cannot launch or resize.
func (t Template) Validate() error {
	for name, value := range map[string]string{
		"compartment_id": t.CompartmentID, "availability_domain": t.AvailabilityDomain,
		"subnet_id": t.SubnetID, "image_id": t.ImageID,
	} {
		if value == "" {
			return fmt.Errorf("template %s is required", name)
		}
	}
	if !catalog.IsOCIRegion(t.Region) {
		return fmt.Errorf("template region %q is not in the region catalog", t.Region)
	}
	if !strings.HasSuffix(t.Shape, ".Flex") {
		return fmt.Errorf("template shape %q must be a .Flex shape so it can be resized", t.Shape)
	}
	if t.BootVolumeGB != 0 && (t.BootVolumeGB < 50 || t.BootVolumeGB > 32768) {
		return fmt.Errorf("template boot_volume_gb %d must be 0 or 50..32768", t.BootVolumeGB)
	}
	return nil
}

// computeAPI is the slice of core.ComputeClient the autoscaler uses.
type computeAPI interface {
	ListInstances(ctx context.Context, request core.ListInstancesRequest) (core.ListInstancesResponse, error)
	GetInstance(ctx context.Context, request core.GetInstanceRequest) (core.GetInstanceResponse, error)
	LaunchInstance(ctx context.Context, request core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error)
	UpdateInstance(ctx context.Context, request core.UpdateInstanceRequest) (core.UpdateInstanceResponse, error)
	TerminateInstance(ctx context.Context, request core.TerminateInstanceRequest) (core.TerminateInstanceResponse, error)
	ListShapes(ctx context.Context, request core.ListShapesRequest) (core.ListShapesResponse, error)
	GetImage(ctx context.Context, request core.GetImageRequest) (core.GetImageResponse, error)
}

// readAPI is the read-only rest of OCI that Preflight consults.
type readAPI interface {
	GetSubnet(ctx context.Context, request core.GetSubnetRequest) (core.GetSubnetResponse, error)
	GetResourceAvailability(ctx context.Context, request limits.GetResourceAvailabilityRequest) (limits.GetResourceAvailabilityResponse, error)
}

// sdkReads joins the network and limits clients into one readAPI.
type sdkReads struct {
	core.VirtualNetworkClient
	limits.LimitsClient
}

// OCICloud is the Cloud of one cell over the OCI Compute API. It finds its
// instances by the ts-cell and ts-role freeform tags it sets at launch.
type OCICloud struct {
	cell     string
	template Template
	compute  computeAPI
	reads    readAPI
	// ponytail: serialize launch reconciliation for this single-cell controller;
	// use per-name locks only if concurrent launches become necessary.
	launchMu                 sync.Mutex
	launches                 map[string]*OCILaunchState
	saveLaunches             func([]OCILaunchState) error
	requireLaunchPersistence bool
	launchPersistenceError   error
}

// OCILaunchState is one generation's durable intent. Request freezes the exact
// OCI payload; retrying after restart must not rebuild it from current policy.
// Observed existing instances can have only Name and InstanceID populated.
type OCILaunchState struct {
	Name       string                     `json:"name"`
	Template   Template                   `json:"template"`
	Shape      Shape                      `json:"shape"`
	RetryToken string                     `json:"retry_token"`
	Request    core.LaunchInstanceDetails `json:"request"`
	StartedAt  time.Time                  `json:"started_at"`
	InstanceID string                     `json:"instance_id"`
}

// OCI tokens expire after 24 hours. Stop replaying an uncertain POST an hour
// earlier, and bound SDK retries by that deadline; expiration never proves
// that the original launch failed.
const launchReplayWindow = 23 * time.Hour

// NewOCICloud builds the Cloud of cell using the operator's OCI credentials.
func NewOCICloud(cell string, template Template) (*OCICloud, error) {
	if err := ValidateCell(cell); err != nil {
		return nil, err
	}
	if err := template.Validate(); err != nil {
		return nil, err
	}
	factory, err := ociclient.OperatorConfig(template.Region)
	if err != nil {
		return nil, err
	}
	compute, err := factory.Compute()
	if err != nil {
		return nil, err
	}
	network, err := factory.Network()
	if err != nil {
		return nil, err
	}
	quota, err := factory.Limits()
	if err != nil {
		return nil, err
	}
	cloud, err := newOCICloud(cell, template, compute, sdkReads{network, quota})
	if err == nil {
		cloud.requireLaunchPersistence = true
	}
	return cloud, err
}

func newOCICloud(cell string, template Template, compute computeAPI, reads readAPI) (*OCICloud, error) {
	if err := ValidateCell(cell); err != nil {
		return nil, err
	}
	if err := template.Validate(); err != nil {
		return nil, err
	}
	return &OCICloud{cell: cell, template: template, compute: compute, reads: reads, launches: map[string]*OCILaunchState{}}, nil
}

// RestoreLaunchState installs an existing journal before the controller starts.
// save must atomically persist and fsync the whole snapshot before returning;
// it must not modify the supplied state. Missing/unreadable journals must be
// rejected by the caller, never silently treated as an empty initial state.
func (c *OCICloud) RestoreLaunchState(states []OCILaunchState, save func([]OCILaunchState) error) error {
	c.launchMu.Lock()
	defer c.launchMu.Unlock()
	if save == nil || len(c.launches) != 0 || c.saveLaunches != nil {
		return errors.New("launch persistence requires a save callback and an unused OCICloud")
	}
	if len(states) > maxOrdinal {
		return errors.New("launch journal exceeds the cell's name bound")
	}
	launches := map[string]*OCILaunchState{}
	for _, state := range states {
		if _, ok := Ordinal(c.cell, state.Name); !ok || launches[state.Name] != nil {
			return fmt.Errorf("launch journal has an invalid or duplicate node %q", state.Name)
		}
		if state.RetryToken == "" {
			if state.InstanceID == "" || !state.StartedAt.IsZero() {
				return fmt.Errorf("launch journal node %s has no token or observed instance", state.Name)
			}
		} else {
			if state.StartedAt.IsZero() || state.StartedAt.After(time.Now()) || state.Template.Region != c.template.Region {
				return fmt.Errorf("launch journal node %s has an invalid start time or region", state.Name)
			}
			if err := state.Template.Validate(); err != nil {
				return fmt.Errorf("launch journal node %s: %w", state.Name, err)
			}
			if err := checkShape(state.Shape); err != nil {
				return fmt.Errorf("launch journal node %s: %w", state.Name, err)
			}
			// SDK polymorphic source details may decode as pointers. Compare
			// their JSON rather than their Go representation.
			want, err := json.Marshal(c.launchDetails(state.Name, state.Shape, state.Template, state.RetryToken))
			got, gotErr := json.Marshal(state.Request)
			if err != nil || gotErr != nil || !bytes.Equal(want, got) {
				return fmt.Errorf("launch journal node %s has inconsistent frozen payload", state.Name)
			}
		}
		launches[state.Name] = &state
	}
	c.launches, c.saveLaunches = launches, save
	return nil
}

func (c *OCICloud) persistLaunchState() error {
	if c.launchPersistenceError != nil {
		return c.launchPersistenceError
	}
	if c.saveLaunches == nil {
		if c.requireLaunchPersistence {
			return errors.New("launch persistence is not configured")
		}
		return nil // Injected offline clouds may deliberately use process-local state.
	}
	states := make([]OCILaunchState, 0, len(c.launches))
	for _, state := range c.launches {
		states = append(states, *state)
	}
	slices.SortFunc(states, func(a, b OCILaunchState) int { return strings.Compare(a.Name, b.Name) })
	if err := c.saveLaunches(states); err != nil {
		c.launchPersistenceError = fmt.Errorf("persist launch journal (restart after reconciling the journal): %w", err)
		return c.launchPersistenceError
	}
	return nil
}

func (c *OCICloud) tags() map[string]string {
	return map[string]string{tagCell: c.cell, tagRole: roleDB}
}

// List discovers occupied cell names across the compartment's availability
// domains and returns them ordered by ordinal. The template AD only binds launches.
// Duplicate live names and unsupported owned shapes fail the whole listing
// before launch state is reconciled.
func (c *OCICloud) List(ctx context.Context) ([]Instance, error) {
	c.launchMu.Lock()
	defer c.launchMu.Unlock()
	return c.list(ctx)
}

func (c *OCICloud) list(ctx context.Context) ([]Instance, error) {
	if c.launchPersistenceError != nil {
		return nil, c.launchPersistenceError
	}
	changed := false
	type ordered struct {
		ordinal     int
		instance    Instance
		launchToken string
	}
	var found []ordered
	var terminated []core.Instance
	var occupied [maxOrdinal + 1]bool
	var page *string
	for {
		response, err := c.compute.ListInstances(ctx, core.ListInstancesRequest{
			CompartmentId: common.String(c.template.CompartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, fmt.Errorf("list instances of cell %s: %w", c.cell, err)
		}
		for _, item := range response.Items {
			// A terminating instance still holds its name and hostname.
			if item.LifecycleState == core.InstanceLifecycleStateTerminated {
				if c.launches[deref(item.DisplayName)] != nil {
					terminated = append(terminated, item)
				}
				continue
			}
			if n, ok := Ordinal(c.cell, deref(item.DisplayName)); ok {
				if occupied[n] {
					return nil, fmt.Errorf("list instances of cell %s: duplicate live node name %q", c.cell, deref(item.DisplayName))
				}
				occupied[n] = true
				instance := instanceOf(item)
				instance.Foreign = item.FreeformTags[tagCell] != c.cell || item.FreeformTags[tagRole] != roleDB
				found = append(found, ordered{n, instance, item.FreeformTags[tagLaunchToken]})
			}
		}
		if response.OpcNextPage == nil {
			break
		}
		page = response.OpcNextPage
	}
	for _, f := range found {
		if !f.instance.Foreign {
			if err := c.checkInstanceShape(f.instance); err != nil {
				return nil, err
			}
		}
	}
	// Stage reconciliation so a failed listing cannot partially change the
	// launch journal, including releasing a generation through a tombstone.
	launches := make(map[string]*OCILaunchState, len(c.launches))
	for name, launch := range c.launches {
		state := *launch
		launches[name] = &state
	}
	for _, item := range terminated {
		name := deref(item.DisplayName)
		if launch := launches[name]; launch != nil && deref(item.Id) != "" && item.FreeformTags[tagCell] == c.cell && item.FreeformTags[tagRole] == roleDB {
			// Historical tombstones cannot release a newer generation. The
			// token tag also identifies a launch whose response was lost.
			if launch.InstanceID != "" && launch.InstanceID == deref(item.Id) || launch.InstanceID == "" &&
				launch.RetryToken != "" && item.FreeformTags[tagLaunchToken] == launch.RetryToken {
				delete(launches, name)
				changed = true
			}
		}
	}
	slices.SortFunc(found, func(a, b ordered) int { return a.ordinal - b.ordinal })
	instances := make([]Instance, len(found))
	for i, f := range found {
		instances[i] = f.instance
		if !f.instance.Foreign && f.instance.ID != "" {
			launch := launches[f.instance.Name]
			if launch == nil {
				launch = &OCILaunchState{Name: f.instance.Name}
				launches[f.instance.Name] = launch
			}
			if launch.InstanceID != "" && launch.InstanceID != f.instance.ID || launch.InstanceID == "" &&
				launch.RetryToken != "" && launch.RetryToken != f.launchToken {
				return nil, fmt.Errorf("reconcile launch %s: listed instance belongs to a different generation", f.instance.Name)
			}
			if launch.InstanceID == "" {
				launch.InstanceID = f.instance.ID
				changed = true
			}
		}
	}
	if changed {
		c.launches = launches
	}
	if changed && c.saveLaunches != nil {
		if err := c.persistLaunchState(); err != nil {
			return nil, err
		}
	}
	return instances, nil
}

// Launch retains a token and its exact payload across uncertain calls. A new
// generation requires confirmed rejection of every attempt in its initial call
// or positively observing the previous ID as TERMINATED, never just an empty
// List or a successful asynchronous Terminate call.
// NewOCICloud requires RestoreLaunchState before any launch mutation. Injected
// offline clouds without a save callback retain only process-local state.
func (c *OCICloud) Launch(ctx context.Context, name string, shape Shape) (Instance, error) {
	if _, ok := Ordinal(c.cell, name); !ok {
		return Instance{}, fmt.Errorf("launch %s: not a node of cell %s", name, c.cell)
	}
	if err := checkShape(shape); err != nil {
		return Instance{}, fmt.Errorf("launch %s: %w", name, err)
	}
	c.launchMu.Lock()
	defer c.launchMu.Unlock()
	existing, err := c.list(ctx)
	if err != nil {
		return Instance{}, err
	}
	for _, instance := range existing {
		if instance.Name == name && instance.Foreign {
			return Instance{}, fmt.Errorf("launch %s: the name is held by an instance the autoscaler does not own", name)
		}
		if instance.Name == name && instance.State == string(core.InstanceLifecycleStateTerminating) {
			return Instance{}, fmt.Errorf("launch %s: the previous instance is still terminating", name)
		}
		if instance.Name == name {
			return instance, nil
		}
	}
	launch := c.launches[name]
	if launch != nil && launch.InstanceID != "" {
		response, err := c.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: common.String(launch.InstanceID)})
		if err != nil {
			// A 404 also means not authorized/not visible, not confirmed termination.
			return Instance{}, fmt.Errorf("reconcile launch %s (%s): %w", name, launch.InstanceID, err)
		}
		if deref(response.Id) != launch.InstanceID || deref(response.DisplayName) != name {
			return Instance{}, fmt.Errorf("reconcile launch %s: instance identity is unconfirmed", name)
		}
		switch response.LifecycleState {
		case core.InstanceLifecycleStateTerminated:
			delete(c.launches, name)
			launch = nil
		case core.InstanceLifecycleStateTerminating:
			return Instance{}, fmt.Errorf("launch %s: the previous instance is still terminating", name)
		default:
			if response.FreeformTags[tagCell] != c.cell || response.FreeformTags[tagRole] != roleDB {
				return Instance{}, fmt.Errorf("reconcile launch %s: instance ownership is unconfirmed", name)
			}
			instance := instanceOf(response.Instance)
			if err := c.checkInstanceShape(instance); err != nil {
				return Instance{}, err
			}
			return instance, nil
		}
	}
	if launch != nil {
		if launch.Template != c.template || launch.Shape != shape {
			return Instance{}, fmt.Errorf("launch %s: previous launch is uncertain; cannot change its payload", name)
		}
		if !time.Now().Before(launch.StartedAt.Add(launchReplayWindow)) {
			return Instance{}, fmt.Errorf("launch %s: retry token replay window expired; reconcile the uncertain instance before relaunching", name)
		}
		return c.launch(ctx, name, launch, false)
	}
	token := common.RetryToken()
	launch = &OCILaunchState{
		Name: name, RetryToken: token, Request: c.launchDetails(name, shape, c.template, token),
		Template: c.template, Shape: shape, StartedAt: time.Now().UTC(),
	}
	c.launches[name] = launch // Save intent before any POST, including uncertain failures.
	return c.launch(ctx, name, launch, true)
}

func (c *OCICloud) launchDetails(name string, shape Shape, template Template, token string) core.LaunchInstanceDetails {
	source := core.InstanceSourceViaImageDetails{ImageId: common.String(template.ImageID)}
	if template.BootVolumeGB > 0 {
		source.BootVolumeSizeInGBs = common.Int64(template.BootVolumeGB)
	}
	details := core.LaunchInstanceDetails{
		DisplayName:        common.String(name),
		CompartmentId:      common.String(template.CompartmentID),
		AvailabilityDomain: common.String(template.AvailabilityDomain),
		Shape:              common.String(template.Shape),
		ShapeConfig: &core.LaunchInstanceShapeConfigDetails{
			Ocpus:       common.Float32(float32(shape.OCPUs)),
			MemoryInGBs: common.Float32(float32(shape.MemoryGB)),
		},
		SourceDetails: source,
		CreateVnicDetails: &core.CreateVnicDetails{
			SubnetId:       common.String(template.SubnetID),
			HostnameLabel:  common.String(name),
			AssignPublicIp: common.Bool(false),
		},
		FreeformTags: c.tags(),
		// SDK decoding makes nil polymorphic slices empty. Start empty so a
		// journal JSON roundtrip preserves the exact retry-token payload.
		LaunchVolumeAttachments: []core.LaunchAttachVolumeDetails{},
		LicensingConfigs:        []core.LaunchInstanceLicensingConfig{},
	}
	if template.UserData != "" {
		details.Metadata = map[string]string{"user_data": template.UserData}
	}
	details.FreeformTags[tagLaunchToken] = token
	return details
}

func (c *OCICloud) launch(ctx context.Context, name string, launch *OCILaunchState, fresh bool) (Instance, error) {
	if err := c.persistLaunchState(); err != nil {
		return Instance{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, launch.StartedAt.Add(launchReplayWindow))
	defer cancel()
	request := core.LaunchInstanceRequest{LaunchInstanceDetails: launch.Request, OpcRetryToken: common.String(launch.RetryToken)}
	var ambiguous, observed atomic.Bool // SDK retry callbacks can outlive a cancelled call.
	observeRetries := false
	if fresh {
		policy := ociclient.RetryPolicy(ociclient.RetryOptions{})
		var configured *common.RetryPolicy
		switch compute := c.compute.(type) {
		case core.ComputeClient:
			observeRetries = true
			policy, configured = common.NoRetryPolicy(), compute.RetryPolicy()
		case *core.ComputeClient:
			observeRetries = true
			policy, configured = common.NoRetryPolicy(), compute.RetryPolicy()
		}
		if configured != nil {
			policy = *configured
		}
		shouldRetry := policy.ShouldRetryOperation
		policy.ShouldRetryOperation = func(attempt common.OCIOperationResponse) bool {
			response, ok := attempt.Response.(core.LaunchInstanceResponse)
			if !ok || response.Id != nil || !ociMutationRejected(attempt.Error, response.RawResponse) {
				ambiguous.Store(true)
			}
			observed.Store(true)
			return shouldRetry(attempt)
		}
		request.RequestMetadata.RetryPolicy = &policy
	}
	response, err := c.compute.LaunchInstance(ctx, request)
	if id := deref(response.Id); id != "" {
		launch.InstanceID = id
		if saveErr := c.persistLaunchState(); saveErr != nil {
			return Instance{}, errors.Join(err, saveErr)
		}
	}
	if err != nil {
		// A restored/replayed intent has no proof its earlier POST failed.
		// Only a fresh generation whose every SDK attempt was rejected may
		// release its fence, and the deletion must be durable before reuse.
		if fresh && !ambiguous.Load() && (!observeRetries || observed.Load()) &&
			response.Id == nil && ociMutationRejected(err, response.RawResponse) {
			delete(c.launches, name)
			if saveErr := c.persistLaunchState(); saveErr != nil {
				c.launches[name] = launch
				return Instance{}, errors.Join(err, saveErr)
			}
		}
		return Instance{}, fmt.Errorf("launch %s: %w", name, err)
	}
	if launch.InstanceID == "" {
		return Instance{}, fmt.Errorf("launch %s: OCI returned no instance ID; launch outcome is uncertain", name)
	}
	instance := instanceOf(response.Instance)
	if err := c.checkInstanceShape(instance); err != nil {
		return Instance{}, err
	}
	return instance, nil
}

// Resize changes the instance's OCPUs and memory; OCI restarts it.
func (c *OCICloud) Resize(ctx context.Context, id string, shape Shape) error {
	c.launchMu.Lock()
	defer c.launchMu.Unlock()
	if c.launchPersistenceError != nil {
		return c.launchPersistenceError
	}
	if c.requireLaunchPersistence && c.saveLaunches == nil {
		return errors.New("launch persistence is not configured")
	}
	if err := checkShape(shape); err != nil {
		return fmt.Errorf("resize %s: %w: %w", id, ErrResizeRejected, err)
	}
	response, err := c.compute.UpdateInstance(ctx, core.UpdateInstanceRequest{
		InstanceId: common.String(id),
		UpdateInstanceDetails: core.UpdateInstanceDetails{
			ShapeConfig: &core.UpdateInstanceShapeConfigDetails{
				Ocpus:       common.Float32(float32(shape.OCPUs)),
				MemoryInGBs: common.Float32(float32(shape.MemoryGB)),
			},
		},
	})
	if err != nil {
		// The shared factory retries PUT only on 429, never after an ambiguous
		// attempt. Only documented rejection codes without success evidence
		// confirm this call did not mutate; unknown errors remain fenced.
		if response.Id == nil && ociMutationRejected(err, response.RawResponse) {
			err = errors.Join(ErrResizeRejected, err)
		}
		return fmt.Errorf("resize %s: %w", id, err)
	}
	return nil
}

// ociMutationRejected recognizes documented no-effect errors without a
// conflicting HTTP response. Callers must also exclude accepted instance IDs
// and any earlier ambiguous attempts before treating a generation as rejected.
func ociMutationRejected(err error, raw *http.Response) bool {
	failure, ok := common.IsServiceError(err)
	if !ok || raw != nil && raw.StatusCode != failure.GetHTTPStatusCode() {
		return false
	}
	switch failure.GetHTTPStatusCode() {
	case http.StatusBadRequest:
		switch failure.GetCode() {
		case "CannotParseRequest", "InvalidParameter", "MissingParameter", "LimitExceeded", "QuotaExceeded":
			return true
		}
	case http.StatusUnauthorized:
		return failure.GetCode() == "NotAuthenticated"
	case http.StatusForbidden:
		return failure.GetCode() == "NotAuthorized"
	case http.StatusNotFound:
		return failure.GetCode() == "NotAuthorizedOrNotFound" || failure.GetCode() == "InvalidParameter"
	case http.StatusConflict:
		return failure.GetCode() == "IncorrectState"
	case http.StatusTooManyRequests:
		return failure.GetCode() == "TooManyRequests"
	}
	return false
}

// Terminate deletes the instance and its boot volume.
func (c *OCICloud) Terminate(ctx context.Context, id string) error {
	c.launchMu.Lock()
	defer c.launchMu.Unlock()
	if c.launchPersistenceError != nil {
		return c.launchPersistenceError
	}
	if c.requireLaunchPersistence && c.saveLaunches == nil {
		return errors.New("launch persistence is not configured")
	}
	_, err := c.compute.TerminateInstance(ctx, core.TerminateInstanceRequest{
		InstanceId:         common.String(id),
		PreserveBootVolume: common.Bool(false),
	})
	if err != nil {
		return fmt.Errorf("terminate %s: %w", id, err)
	}
	return nil
}

func checkShape(s Shape) error {
	if s.OCPUs <= 0 || s.MemoryGB <= 0 {
		return errors.New("shape must have positive OCPUs and memory")
	}
	return nil
}

func (c *OCICloud) checkInstanceShape(instance Instance) error {
	if instance.ShapeName != c.template.Shape {
		return fmt.Errorf("instance %s: shape %q does not match template shape %q", instance.ID, instance.ShapeName, c.template.Shape)
	}
	return nil
}

func instanceOf(i core.Instance) Instance {
	out := Instance{ID: deref(i.Id), Name: deref(i.DisplayName), State: string(i.LifecycleState), ShapeName: deref(i.Shape), AvailabilityDomain: deref(i.AvailabilityDomain)}
	if cfg := i.ShapeConfig; cfg != nil {
		if cfg.Ocpus != nil {
			out.Shape.OCPUs = float64(*cfg.Ocpus)
		}
		if cfg.MemoryInGBs != nil {
			out.Shape.MemoryGB = float64(*cfg.MemoryInGBs)
		}
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Preflight is a read-only check of a cell's template and policy against
// OCI. Problems are what would make a live autoscaler fail or overspend;
// an error means OCI could not be asked.
type Preflight struct {
	Nodes int `json:"nodes"`
	// Available is the minimum headroom of any checked scope. Needed sums
	// growth across all domains; Quotas records each scoped comparison.
	CoresAvailable    float64          `json:"cores_available"`
	MemoryGBAvailable float64          `json:"memory_gb_available"`
	CoresNeeded       float64          `json:"cores_needed"`
	MemoryGBNeeded    float64          `json:"memory_gb_needed"`
	Problems          []string         `json:"problems,omitempty"`
	Quotas            []PreflightQuota `json:"quotas,omitempty"`
}

// PreflightQuota records one core or memory quota; an empty domain is regional.
type PreflightQuota struct {
	Quota              string  `json:"quota"`
	AvailabilityDomain string  `json:"availability_domain,omitempty"`
	Available          float64 `json:"available"`
	Needed             float64 `json:"needed"`
}

// Preflight lists the cell, then reads the template's image, subnet, shape
// options and quota headroom in each occupied domain and the template domain
// for growing to max_nodes at max_ocpus. Image compatibility applies to launches.
// It never changes anything.
func (c *OCICloud) Preflight(ctx context.Context, policy Policy) (Preflight, error) {
	var report Preflight
	problem := func(format string, values ...any) {
		report.Problems = append(report.Problems, fmt.Sprintf(format, values...))
	}
	instances, err := c.List(ctx)
	if err != nil {
		return report, err
	}
	t := c.template
	bounds := policy.Shape
	neededByDomain := map[string]Shape{t.AvailabilityDomain: {}}
	for _, instance := range instances {
		if instance.Foreign {
			continue
		}
		if strings.TrimSpace(instance.AvailabilityDomain) == "" {
			return report, fmt.Errorf("instance %s: availability domain is missing; cannot check resize quota", instance.ID)
		}
		report.Nodes++
		needed := neededByDomain[instance.AvailabilityDomain]
		// Shrinking oversized nodes cannot fund growth in another domain or
		// earlier in a rolling resize. Only positive growth needs quota.
		needed.OCPUs += math.Max(0, bounds.MaxOCPUs-instance.Shape.OCPUs)
		needed.MemoryGB += math.Max(0, bounds.MaxOCPUs*bounds.MemoryGBPerOCPU-instance.Shape.MemoryGB)
		neededByDomain[instance.AvailabilityDomain] = needed
	}
	launches := float64(max(0, policy.Nodes.Max-report.Nodes))
	needed := neededByDomain[t.AvailabilityDomain]
	needed.OCPUs += launches * bounds.MaxOCPUs
	needed.MemoryGB += launches * bounds.MaxOCPUs * bounds.MemoryGBPerOCPU
	neededByDomain[t.AvailabilityDomain] = needed
	var domains []string
	for domain, needed := range neededByDomain {
		domains = append(domains, domain)
		report.CoresNeeded += needed.OCPUs
		report.MemoryGBNeeded += needed.MemoryGB
	}
	slices.Sort(domains)
	var launchImage *string
	image, err := c.compute.GetImage(ctx, core.GetImageRequest{ImageId: common.String(t.ImageID)})
	switch {
	case notFound(err):
		problem("image %s does not exist or is not visible", t.ImageID)
	case err != nil:
		return report, fmt.Errorf("get image: %w", err)
	case image.LifecycleState != core.ImageLifecycleStateAvailable:
		problem("image %s is %s", t.ImageID, image.LifecycleState)
	default:
		// Only shapes the image can boot on are listed.
		launchImage = common.String(t.ImageID)
	}
	subnet, err := c.reads.GetSubnet(ctx, core.GetSubnetRequest{SubnetId: common.String(t.SubnetID)})
	switch {
	case notFound(err):
		problem("subnet %s does not exist or is not visible", t.SubnetID)
	case err != nil:
		return report, fmt.Errorf("get subnet: %w", err)
	case subnet.LifecycleState != core.SubnetLifecycleStateAvailable:
		problem("subnet %s is %s", t.SubnetID, subnet.LifecycleState)
	case deref(subnet.AvailabilityDomain) != "" && deref(subnet.AvailabilityDomain) != t.AvailabilityDomain:
		problem("subnet %s is in %s, template requires %s", t.SubnetID, *subnet.AvailabilityDomain, t.AvailabilityDomain)
	// Launch always sets HostnameLabel. OCI permits a subnet DNS label only if
	// its VCN has one (core.CreateSubnetDetails.DnsLabel), so no VCN read is needed.
	case !subnetDNSLabelRE.MatchString(deref(subnet.DnsLabel)):
		problem("subnet %s requires a DNS label of 1..15 alphanumeric characters starting with a letter for instance hostname labels", t.SubnetID)
	}

	var shape *core.Shape
	for _, domain := range domains {
		shapes := core.ListShapesRequest{CompartmentId: common.String(t.CompartmentID), AvailabilityDomain: common.String(domain)}
		if domain == t.AvailabilityDomain {
			shapes.ImageId = launchImage
		}
		var offered *core.Shape
		for {
			response, err := c.compute.ListShapes(ctx, shapes)
			if err != nil {
				return report, fmt.Errorf("list shapes in %s: %w", domain, err)
			}
			if index := slices.IndexFunc(response.Items, func(s core.Shape) bool { return deref(s.Shape) == t.Shape }); index >= 0 {
				offered = &response.Items[index]
				break
			}
			if response.OpcNextPage == nil {
				break
			}
			shapes.Page = response.OpcNextPage
		}
		if offered == nil {
			problem("shape %s is not offered in %s", t.Shape, domain)
			continue
		}
		ocpus, memory := offered.OcpuOptions, offered.MemoryOptions
		if offered.IsFlexible == nil || !*offered.IsFlexible || ocpus == nil || memory == nil {
			problem("shape %s is not flexible in %s", t.Shape, domain)
			continue
		}
		if bounds.MinOCPUs < value(ocpus.Min) || bounds.MaxOCPUs > value(ocpus.Max) {
			problem("shape %s in %s allows %g..%g OCPUs, policy asks %g..%g", t.Shape, domain, value(ocpus.Min), value(ocpus.Max), bounds.MinOCPUs, bounds.MaxOCPUs)
		}
		if bounds.MemoryGBPerOCPU < value(memory.MinPerOcpuInGBs) || bounds.MemoryGBPerOCPU > value(memory.MaxPerOcpuInGBs) ||
			bounds.MaxOCPUs*bounds.MemoryGBPerOCPU > value(memory.MaxInGBs) || bounds.MinOCPUs*bounds.MemoryGBPerOCPU < value(memory.MinInGBs) {
			problem("shape %s in %s allows %g..%g GB per OCPU and %g..%g GB, policy asks %g GB per OCPU",
				t.Shape, domain, value(memory.MinPerOcpuInGBs), value(memory.MaxPerOcpuInGBs), value(memory.MinInGBs), value(memory.MaxInGBs), bounds.MemoryGBPerOCPU)
		}
		if domain == t.AvailabilityDomain {
			shape = offered
		}
	}
	if shape == nil {
		return report, nil
	}
	// Regional quotas cover all growth; AD quotas cover local resizes plus
	// new-node demand only in the template AD.
	var coresChecked, memoryChecked bool
	quotasChecked := map[string]bool{}
	for _, quota := range shape.QuotaNames {
		if quotasChecked[quota] {
			continue
		}
		quotasChecked[quota] = true
		available := &report.CoresAvailable
		needed := report.CoresNeeded
		checked := &coresChecked
		resource := strings.Replace(quota, "-regional-", "-", 1)
		switch {
		case strings.HasSuffix(resource, "-memory-count"):
			available, needed = &report.MemoryGBAvailable, report.MemoryGBNeeded
			checked = &memoryChecked
		case !strings.HasSuffix(resource, "-core-count"):
			continue
		}
		scopes := domains
		if strings.Contains(quota, "-regional-") {
			scopes = []string{""}
		}
		for _, domain := range scopes {
			request := limits.GetResourceAvailabilityRequest{ServiceName: common.String("compute"),
				LimitName: common.String(quota), CompartmentId: common.String(t.CompartmentID)}
			if domain != "" {
				request.AvailabilityDomain = common.String(domain)
				needed = neededByDomain[domain].OCPUs
				if checked == &memoryChecked {
					needed = neededByDomain[domain].MemoryGB
				}
			}
			response, err := c.reads.GetResourceAvailability(ctx, request)
			if err != nil {
				return report, fmt.Errorf("quota %s (availability domain %q): %w", quota, domain, err)
			}
			remaining := value(response.FractionalAvailability)
			if response.FractionalAvailability == nil {
				if response.Available == nil {
					return report, fmt.Errorf("quota %s (availability domain %q): availability is missing", quota, domain)
				}
				remaining = float64(*response.Available)
			}
			if !*checked || remaining < *available {
				*available = remaining
			}
			*checked = true
			report.Quotas = append(report.Quotas, PreflightQuota{Quota: quota, AvailabilityDomain: domain, Available: remaining, Needed: needed})
			if remaining < needed {
				problem("quota %s has %g left; growing to max_nodes at max_ocpus needs %g (availability domain %q)", quota, remaining, needed, domain)
			}
		}
	}
	if !coresChecked || !memoryChecked {
		return report, fmt.Errorf("shape %s: quota coverage is unchecked (cores checked=%t, memory checked=%t)", t.Shape, coresChecked, memoryChecked)
	}
	return report, nil
}

func notFound(err error) bool {
	failure, ok := common.IsServiceError(err)
	return ok && failure.GetHTTPStatusCode() == http.StatusNotFound
}

func value(pointer *float32) float64 {
	if pointer == nil {
		return 0
	}
	return float64(*pointer)
}
