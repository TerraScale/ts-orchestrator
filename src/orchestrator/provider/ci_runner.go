package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

type TrustZone int

const (
	TrustUntrustedProduct TrustZone = iota + 1
	TrustTrustedBuild
)

type OciCiRunnerNodeState int

const (
	RunnerLaunching OciCiRunnerNodeState = iota
	RunnerRunning
	RunnerStopped
	RunnerTerminating
	RunnerTerminated
)

type OciCiRunnerDemand struct {
	Runner                                                      string
	Zone                                                        TrustZone
	Sequence                                                    int64
	BootstrapCloudInitBase64, BootstrapSha256, IdempotencyToken string
}

func NewOciCiRunnerDemand(runner string, zone TrustZone, sequence int64, bootstrapBase64, bootstrapSHA string) (OciCiRunnerDemand, error) {
	if runner == "" || zone < TrustUntrustedProduct || zone > TrustTrustedBuild || sequence <= 0 {
		return OciCiRunnerDemand{}, &errs.Argument{Message: "CI runner demand identity is invalid"}
	}
	if len(runner) > 256 || strings.ContainsAny(runner, "\r\n") {
		return OciCiRunnerDemand{}, &errs.Argument{Message: "CI runner demand identity is invalid"}
	}
	raw, err := base64.StdEncoding.DecodeString(bootstrapBase64)
	if err != nil || len(raw) < 1 || len(raw) > 32*1024 {
		return OciCiRunnerDemand{}, &errs.Argument{Message: "CI runner bootstrap is invalid"}
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != bootstrapSHA {
		return OciCiRunnerDemand{}, &errs.Argument{Message: "CI runner bootstrap digest does not match"}
	}
	h := sha256.Sum256([]byte(runner + ":" + strconv.FormatInt(sequence, 10) + ":" + bootstrapSHA))
	return OciCiRunnerDemand{runner, zone, sequence, bootstrapBase64, bootstrapSHA, "ci-" + hex.EncodeToString(h[:])[:48]}, nil
}

type OciCiRunnerNodeObservation struct {
	InstanceId, ETag, Runner        string
	Sequence                        int64
	State                           OciCiRunnerNodeState
	ActiveJob                       bool
	LastActivity                    time.Time
	Preemptible, PreserveBootVolume bool
	FreeformTags                    map[string]string
}
type OciCiRunnerLaunchTemplate struct {
	CompartmentId, AvailabilityDomain, FaultDomain, SubnetId, ImageId string
	NetworkSecurityGroupIds                                           []string
	Generation                                                        int64
}

func NewOciCiRunnerLaunchTemplate(compartment, availability, fault, subnet string, nsg []string, image string, generation int64) (OciCiRunnerLaunchTemplate, error) {
	for _, x := range []struct{ v, k string }{{compartment, "compartment"}, {subnet, "subnet"}, {image, "image"}} {
		if !isOCID(x.v, x.k) {
			return OciCiRunnerLaunchTemplate{}, &errs.Argument{Message: "OCI CI runner OCID is invalid"}
		}
	}
	if availability == "" || len(availability) > 128 || strings.IndexFunc(availability, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 || generation <= 0 || len(nsg) < 1 || len(nsg) > 5 {
		return OciCiRunnerLaunchTemplate{}, &errs.Argument{Message: "OCI CI runner launch template is invalid"}
	}
	seen := map[string]bool{}
	for _, x := range nsg {
		if !isOCID(x, "networksecuritygroup") || seen[x] {
			return OciCiRunnerLaunchTemplate{}, &errs.Argument{Message: "OCI CI runner NSGs must be distinct OCIDs"}
		}
		seen[x] = true
	}
	if fault != "" && (len(fault) > 64 || strings.IndexFunc(fault, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0) {
		return OciCiRunnerLaunchTemplate{}, &errs.Argument{Message: "OCI fault domain is invalid"}
	}
	return OciCiRunnerLaunchTemplate{compartment, availability, fault, subnet, image, append([]string(nil), nsg...), generation}, nil
}

type OciCiRunnerCapacityRequest struct {
	Now                time.Time
	IdleTimeout        time.Duration
	MaximumNodes       int
	LaunchTemplate     OciCiRunnerLaunchTemplate
	Permitted, Desired []OciCiRunnerDemand
	Observed           []OciCiRunnerNodeObservation
	// OwnershipRecords are authoritative journal facts. Provider tags are
	// inventory only and are never sufficient to classify a resource as ours.
	OwnershipRecords []ProviderOwnershipRecord
}

func NewOciCiRunnerCapacityRequest(now time.Time, idle time.Duration, max int, template OciCiRunnerLaunchTemplate, permitted, desired []OciCiRunnerDemand, observed []OciCiRunnerNodeObservation) (OciCiRunnerCapacityRequest, error) {
	if now.UnixMilli() <= 0 || idle < 30*time.Second || idle > 15*time.Minute || max < 1 || max > 256 || len(permitted) == 0 || len(permitted) > max || len(desired) > max || len(observed) > 512 || !validRunnerLaunchTemplate(template) {
		return OciCiRunnerCapacityRequest{}, &errs.Argument{Message: "CI runner capacity request is outside its bounds"}
	}
	p := map[string]OciCiRunnerDemand{}
	for _, x := range permitted {
		if !validRunnerDemand(x) {
			return OciCiRunnerCapacityRequest{}, &errs.Argument{Message: "invalid permitted runner demand"}
		}
		k := x.Runner + ":" + strconv.FormatInt(x.Sequence, 10)
		if _, ok := p[k]; ok {
			return OciCiRunnerCapacityRequest{}, &errs.Argument{Message: "duplicate permitted runner identity"}
		}
		p[k] = x
	}
	seen := map[string]bool{}
	for _, x := range desired {
		if !validRunnerDemand(x) {
			return OciCiRunnerCapacityRequest{}, &errs.Argument{Message: "invalid desired runner demand"}
		}
		k := x.Runner + ":" + strconv.FormatInt(x.Sequence, 10)
		if seen[k] {
			return OciCiRunnerCapacityRequest{}, &errs.Argument{Message: "duplicate desired runner identity"}
		}
		seen[k] = true
		y, ok := p[k]
		if !ok || y.Zone != x.Zone || y.BootstrapSha256 != x.BootstrapSha256 {
			return OciCiRunnerCapacityRequest{}, &errs.Argument{Message: "desired runner is not permitted"}
		}
	}
	inst := map[string]bool{}
	for _, x := range observed {
		if x.InstanceId == "" || inst[x.InstanceId] || x.LastActivity.After(now) || x.State < RunnerLaunching || x.State > RunnerTerminated || len(x.FreeformTags) > 32 {
			return OciCiRunnerCapacityRequest{}, &errs.Argument{Message: "invalid CI runner observation"}
		}
		if x.Runner != "" && x.Sequence <= 0 {
			return OciCiRunnerCapacityRequest{}, &errs.Argument{Message: "invalid CI runner observation identity"}
		}
		inst[x.InstanceId] = true
	}
	return OciCiRunnerCapacityRequest{Now: now, IdleTimeout: idle, MaximumNodes: max, LaunchTemplate: template, Permitted: append([]OciCiRunnerDemand(nil), permitted...), Desired: append([]OciCiRunnerDemand(nil), desired...), Observed: append([]OciCiRunnerNodeObservation(nil), observed...)}, nil
}

type OciCiRunnerCapacityAction interface{ capacityAction() }
type LaunchOciCiRunnerAction struct {
	Demand   OciCiRunnerDemand
	Template OciCiRunnerLaunchTemplate
}

func (LaunchOciCiRunnerAction) capacityAction() {}

type TerminateOciCiRunnerAction struct{ InstanceId, ETag string }

func (TerminateOciCiRunnerAction) capacityAction() {}

const (
	runnerOwnerTag           = "terrascale-owner"
	runnerRoleTag            = "terrascale-role"
	runnerIdentityTag        = "terrascale-runner"
	runnerSequenceTag        = "terrascale-runner-sequence"
	runnerZoneTag            = "terrascale-zone"
	runnerGenerationTag      = "terrascale-generation"
	runnerBootstrapDigestTag = "terrascale-bootstrap-sha256"
	runnerPreemptibleTag     = "terrascale-preemptible"
	runnerPreserveVolumeTag  = "terrascale-preserve-boot-volume"
)

func RunnerTags(d OciCiRunnerDemand, generation int64) map[string]string {
	zone := "trusted-build"
	if d.Zone == TrustUntrustedProduct {
		zone = "untrusted-product"
	}
	return map[string]string{
		runnerOwnerTag:           "orchestrator",
		runnerRoleTag:            "ci-runner",
		runnerIdentityTag:        d.Runner,
		runnerSequenceTag:        strconv.FormatInt(d.Sequence, 10),
		runnerZoneTag:            zone,
		runnerGenerationTag:      strconv.FormatInt(generation, 10),
		runnerBootstrapDigestTag: d.BootstrapSha256,
		// These are immutable ownership invariants, not authorization. They
		// make an observation of an instance explicit and auditable.
		runnerPreemptibleTag:    "true",
		runnerPreserveVolumeTag: "false",
	}
}

// parseRunnerTags returns an identity only when the complete runner tag set
// is present and valid. Partial or malformed provider tags are not silently
// interpreted as a runner; callers must quarantine that observation.
func parseRunnerTags(tags map[string]string) (runner string, sequence int64, generation int64, bootstrap string, preemptible, preserve bool, tagged, valid bool) {
	keys := []string{runnerOwnerTag, runnerRoleTag, runnerIdentityTag, runnerSequenceTag, runnerZoneTag, runnerGenerationTag, runnerBootstrapDigestTag, runnerPreemptibleTag, runnerPreserveVolumeTag}
	for _, key := range keys {
		if _, ok := tags[key]; ok {
			tagged = true
		}
	}
	if !tagged {
		return "", 0, 0, "", false, false, false, true
	}
	for _, key := range keys {
		if strings.TrimSpace(tags[key]) == "" {
			return "", 0, 0, "", false, false, true, false
		}
	}
	if tags[runnerOwnerTag] != "orchestrator" || tags[runnerRoleTag] != "ci-runner" || (tags[runnerZoneTag] != "untrusted-product" && tags[runnerZoneTag] != "trusted-build") || tags[runnerPreemptibleTag] != "true" || tags[runnerPreserveVolumeTag] != "false" {
		return "", 0, 0, "", false, false, true, false
	}
	sequence, err := strconv.ParseInt(tags[runnerSequenceTag], 10, 64)
	if err != nil || sequence <= 0 {
		return "", 0, 0, "", false, false, true, false
	}
	generation, err = strconv.ParseInt(tags[runnerGenerationTag], 10, 64)
	if err != nil || generation <= 0 {
		return "", 0, 0, "", false, false, true, false
	}
	if len(tags[runnerIdentityTag]) == 0 || len(tags[runnerIdentityTag]) > 256 || strings.ContainsAny(tags[runnerIdentityTag], "\r\n") || len(tags[runnerBootstrapDigestTag]) != 64 || strings.ToLower(tags[runnerBootstrapDigestTag]) != tags[runnerBootstrapDigestTag] || !isLowerHex(tags[runnerBootstrapDigestTag]) {
		return "", 0, 0, "", false, false, true, false
	}
	return tags[runnerIdentityTag], sequence, generation, tags[runnerBootstrapDigestTag], true, false, true, true
}

func RunnerOwned(n OciCiRunnerNodeObservation) bool {
	runner, sequence, _, _, preemptible, preserve, tagged, valid := parseRunnerTags(n.FreeformTags)
	return tagged && valid && preemptible && !preserve && runner == n.Runner && sequence == n.Sequence
}
func RunnerMatches(n OciCiRunnerNodeObservation, d OciCiRunnerDemand, t OciCiRunnerLaunchTemplate) bool {
	zone := "trusted-build"
	if d.Zone == TrustUntrustedProduct {
		zone = "untrusted-product"
	}
	return RunnerOwned(n) && n.FreeformTags[runnerZoneTag] == zone && n.FreeformTags[runnerGenerationTag] == strconv.FormatInt(t.Generation, 10) && n.FreeformTags[runnerBootstrapDigestTag] == d.BootstrapSha256
}

func runnerOwnership(n OciCiRunnerNodeObservation, template OciCiRunnerLaunchTemplate, records []ProviderOwnershipRecord) bool {
	if !RunnerOwned(n) || len(records) == 0 {
		return false
	}
	for _, record := range records {
		if record.ResourceId.Value == n.InstanceId && record.CompartmentId.Value == template.CompartmentId && record.Generation.Value == uint64(template.Generation) {
			return true
		}
	}
	return false
}

func validRunnerDemand(d OciCiRunnerDemand) bool {
	if d.Runner == "" || len(d.Runner) > 256 || strings.ContainsAny(d.Runner, "\r\n") || d.Zone < TrustUntrustedProduct || d.Zone > TrustTrustedBuild || d.Sequence <= 0 || len(d.BootstrapSha256) != 64 || strings.ToLower(d.BootstrapSha256) != d.BootstrapSha256 || !isLowerHex(d.BootstrapSha256) || d.IdempotencyToken == "" {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(d.BootstrapCloudInitBase64)
	if err != nil || len(raw) == 0 || len(raw) > 32*1024 {
		return false
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != d.BootstrapSha256 {
		return false
	}
	h := sha256.Sum256([]byte(d.Runner + ":" + strconv.FormatInt(d.Sequence, 10) + ":" + d.BootstrapSha256))
	return d.IdempotencyToken == "ci-"+hex.EncodeToString(h[:])[:48]
}

func validRunnerLaunchTemplate(t OciCiRunnerLaunchTemplate) bool {
	if !isOCID(t.CompartmentId, "compartment") || !isOCID(t.SubnetId, "subnet") || !isOCID(t.ImageId, "image") || t.AvailabilityDomain == "" || t.Generation <= 0 || len(t.NetworkSecurityGroupIds) < 1 || len(t.NetworkSecurityGroupIds) > 5 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range t.NetworkSecurityGroupIds {
		if !isOCID(id, "networksecuritygroup") || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func validRunnerOwnershipRecords(r OciCiRunnerCapacityRequest) bool {
	seen := map[string]bool{}
	for _, record := range r.OwnershipRecords {
		if !isOCID(record.ResourceId.Value, "instance") || !isOCID(record.CompartmentId.Value, "compartment") || record.CompartmentId.Value != r.LaunchTemplate.CompartmentId || record.Generation.Value != uint64(r.LaunchTemplate.Generation) || seen[record.ResourceId.Value] {
			return false
		}
		if _, err := canonicalToken(record.CellId.Value, "cellId"); err != nil {
			return false
		}
		seen[record.ResourceId.Value] = true
	}
	return true
}
func DecideRunnerCapacity(r OciCiRunnerCapacityRequest) ([]OciCiRunnerCapacityAction, error) {
	if !validRunnerLaunchTemplate(r.LaunchTemplate) || !validRunnerOwnershipRecords(r) {
		return nil, &InvalidDataError{Message: "CI runner capacity request lacks valid authoritative scope"}
	}
	for _, demand := range append(append([]OciCiRunnerDemand(nil), r.Permitted...), r.Desired...) {
		if !validRunnerDemand(demand) {
			return nil, &InvalidDataError{Message: "CI runner capacity request contains invalid demand"}
		}
	}
	desired := map[string]bool{}
	for _, x := range r.Desired {
		desired[x.Runner+":"+strconv.FormatInt(x.Sequence, 10)] = true
	}
	live := []OciCiRunnerNodeObservation{}
	for _, x := range r.Observed {
		if x.State != RunnerTerminated {
			live = append(live, x)
		}
	}
	managed := []OciCiRunnerNodeObservation{}
	for _, n := range live {
		for _, d := range r.Permitted {
			if d.Runner == n.Runner && d.Sequence == n.Sequence && RunnerMatches(n, d, r.LaunchTemplate) && runnerOwnership(n, r.LaunchTemplate, r.OwnershipRecords) {
				managed = append(managed, n)
				break
			}
		}
	}
	for _, d := range r.Desired {
		coll := 0
		for _, n := range live {
			if n.Runner == d.Runner && n.Sequence == d.Sequence {
				coll++
				if !RunnerMatches(n, d, r.LaunchTemplate) || !runnerOwnership(n, r.LaunchTemplate, r.OwnershipRecords) {
					return nil, &InvalidDataError{Message: "CI runner identity has ambiguous provider ownership"}
				}
			}
		}
		if coll > 1 {
			return nil, &InvalidDataError{Message: "CI runner identity has ambiguous provider ownership"}
		}
	}
	sort.Slice(managed, func(i, j int) bool { return managed[i].InstanceId < managed[j].InstanceId })
	out := []OciCiRunnerCapacityAction{}
	for _, n := range managed {
		stopped := n.State == RunnerStopped
		if !runnerOwnership(n, r.LaunchTemplate, r.OwnershipRecords) || (!stopped && (n.State != RunnerRunning)) || (!stopped && (n.ActiveJob || desired[n.Runner+":"+strconv.FormatInt(n.Sequence, 10)] || r.Now.Sub(n.LastActivity) < r.IdleTimeout)) {
			continue
		}
		if n.ETag == "" {
			return nil, &InvalidDataError{Message: "idle runner has no exact ETag fence"}
		}
		out = append(out, TerminateOciCiRunnerAction{n.InstanceId, n.ETag})
	}
	available := r.MaximumNodes - len(managed)
	if available < 0 {
		available = 0
	}
	missing := []OciCiRunnerDemand{}
	for _, d := range r.Desired {
		found := false
		for _, n := range managed {
			if n.Runner == d.Runner && n.Sequence == d.Sequence {
				found = true
			}
		}
		if !found {
			missing = append(missing, d)
		}
	}
	sort.Slice(missing, func(i, j int) bool {
		if missing[i].Runner != missing[j].Runner {
			return missing[i].Runner < missing[j].Runner
		}
		return missing[i].Sequence < missing[j].Sequence
	})
	for i, d := range missing {
		if i >= available {
			break
		}
		out = append(out, LaunchOciCiRunnerAction{d, r.LaunchTemplate})
	}
	return out, nil
}

type RunnerLaunchRequest struct {
	RetryToken, DisplayName, HostnameLabel, Shape, CompartmentId, AvailabilityDomain, FaultDomain, SubnetId, ImageId string
	Ocpus, MemoryGB                                                                                                  float64
	NsgIds                                                                                                           []string
	BootstrapBase64                                                                                                  string
	Tags                                                                                                             map[string]string
}

func CompileRunnerLaunch(a LaunchOciCiRunnerAction) RunnerLaunchRequest {
	h := sha256.Sum256([]byte(a.Demand.Runner))
	id := hex.EncodeToString(h[:])[:16]
	return RunnerLaunchRequest{a.Demand.IdempotencyToken, "ci-runner-" + id, "ci-" + id, "VM.Standard.A1.Flex", a.Template.CompartmentId, a.Template.AvailabilityDomain, a.Template.FaultDomain, a.Template.SubnetId, a.Template.ImageId, 4, 24, append([]string(nil), a.Template.NetworkSecurityGroupIds...), a.Demand.BootstrapCloudInitBase64, RunnerTags(a.Demand, a.Template.Generation)}
}

type RunnerTerminateRequest struct {
	InstanceId, IfMatch                                    string
	PreserveBootVolume, PreserveDataVolumesCreatedAtLaunch bool
}

func CompileRunnerTerminate(a TerminateOciCiRunnerAction) RunnerTerminateRequest {
	return RunnerTerminateRequest{a.InstanceId, a.ETag, false, false}
}

type OciCiRunnerMutationReceipt struct{ InstanceId, ETag, OpcRequestId, OpcWorkRequestId string }

type OciCiRunnerPoolSlot struct{ Demand OciCiRunnerDemand }
type OciCiRunnerPoolConfiguration struct {
	Endpoint                  string
	Template                  OciCiRunnerLaunchTemplate
	IdleTimeout, PollInterval time.Duration
	Slots                     []OciCiRunnerPoolSlot
}

func LoadOciCiRunnerPoolConfiguration(path string) (*OciCiRunnerPoolConfiguration, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 256*1024 {
		return nil, &errs.Argument{Message: "CI runner pool configuration must be a bounded regular file"}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d struct {
		SchemaVersion                                                               int `json:"schemaVersion"`
		Endpoint, CompartmentId, AvailabilityDomain, FaultDomain, SubnetId, ImageId string
		NetworkSecurityGroupIds                                                     []string `json:"networkSecurityGroupIds"`
		Generation                                                                  int64
		IdleSeconds, PollSeconds                                                    int
		Runners                                                                     []struct {
			Runner, Zone, BootstrapFile string
			Sequence                    int64
		} `json:"runners"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || d.SchemaVersion != 1 || len(d.Runners) < 1 || len(d.Runners) > 32 {
		return nil, &InvalidDataError{Message: "CI runner pool configuration has unsupported shape"}
	}
	eu, eerr := url.Parse(strings.TrimSpace(d.Endpoint))
	if eerr != nil || eu.Scheme != "https" || eu.User != nil || (eu.Path != "" && eu.Path != "/") || eu.RawQuery != "" || eu.Fragment != "" || !strings.HasPrefix(eu.Host, "iaas.") || !strings.HasSuffix(eu.Host, ".oraclecloud.com") || !regionPattern.MatchString(strings.TrimSuffix(strings.TrimPrefix(eu.Host, "iaas."), ".oraclecloud.com")) {
		return nil, &InvalidDataError{Message: "CI runner pool endpoint is invalid"}
	}
	if d.IdleSeconds < 30 || d.IdleSeconds > 900 || d.PollSeconds < 1 || d.PollSeconds > 30 {
		return nil, &InvalidDataError{Message: "CI runner pool timing is outside its bound"}
	}
	t, err := NewOciCiRunnerLaunchTemplate(d.CompartmentId, d.AvailabilityDomain, d.FaultDomain, d.SubnetId, d.NetworkSecurityGroupIds, d.ImageId, d.Generation)
	if err != nil {
		return nil, err
	}
	slots := make([]OciCiRunnerPoolSlot, 0, len(d.Runners))
	seen := map[string]bool{}
	for _, x := range d.Runners {
		if x.Runner == "" || seen[x.Runner] {
			return nil, &InvalidDataError{Message: "CI runner identities must be unique"}
		}
		seen[x.Runner] = true
		z := TrustZone(0)
		if x.Zone == "untrusted-product" {
			z = TrustUntrustedProduct
		} else if x.Zone == "trusted-build" {
			z = TrustTrustedBuild
		} else {
			return nil, &InvalidDataError{Message: "unsupported CI runner trust zone"}
		}
		bp := x.BootstrapFile
		if !filepath.IsAbs(bp) {
			bp = filepath.Join(filepath.Dir(path), bp)
		}
		bsInfo, bErr := os.Lstat(bp)
		if bErr != nil || !bsInfo.Mode().IsRegular() || bsInfo.Size() < 1 || bsInfo.Size() > 32*1024 {
			return nil, &InvalidDataError{Message: "runner bootstrap file is invalid"}
		}
		bs, bErr := os.ReadFile(bp)
		if bErr != nil || len(bs) < 1 || len(bs) > 32*1024 {
			return nil, &InvalidDataError{Message: "runner bootstrap file is invalid"}
		}
		txt := string(bs)
		if !strings.HasPrefix(txt, "#cloud-config") && !strings.HasPrefix(txt, "#!") || strings.Contains(strings.ToUpper(txt), "PRIVATE KEY-----") || strings.Contains(strings.ToUpper(txt), "BEGIN NATS USER JWT") || strings.Contains(strings.ToUpper(txt), "BEGIN USER NKEY SEED") {
			return nil, &InvalidDataError{Message: "runner bootstrap contains invalid content"}
		}
		sum := sha256.Sum256(bs)
		dd, e := NewOciCiRunnerDemand(x.Runner, z, x.Sequence, base64.StdEncoding.EncodeToString(bs), hex.EncodeToString(sum[:]))
		if e != nil {
			return nil, e
		}
		slots = append(slots, OciCiRunnerPoolSlot{dd})
	}
	return &OciCiRunnerPoolConfiguration{d.Endpoint, t, time.Duration(d.IdleSeconds) * time.Second, time.Duration(d.PollSeconds) * time.Second, slots}, nil
}

type RunnerCapacityAdapter interface {
	Observe(context.Context, OciCiRunnerLaunchTemplate) ([]OciCiRunnerNodeObservation, error)
	Execute(context.Context, OciCiRunnerCapacityAction) (OciCiRunnerMutationReceipt, error)
}

type OciCiRunnerCapacityEngine struct{}

func (OciCiRunnerCapacityEngine) Decide(r OciCiRunnerCapacityRequest) ([]OciCiRunnerCapacityAction, error) {
	return DecideRunnerCapacity(r)
}

type OciCiRunnerRequestCompiler struct{}

func (OciCiRunnerRequestCompiler) Launch(a LaunchOciCiRunnerAction) RunnerLaunchRequest {
	return CompileRunnerLaunch(a)
}
func (OciCiRunnerRequestCompiler) Terminate(a TerminateOciCiRunnerAction) RunnerTerminateRequest {
	return CompileRunnerTerminate(a)
}
