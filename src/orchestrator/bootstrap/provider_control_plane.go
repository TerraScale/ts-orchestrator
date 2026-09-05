package bootstrap

// This file binds the control transition state machine to the provider APIs
// used by production. OCI member tags are the durable intent and observation
// boundary. Cloudflare receives only the derived Region health document used
// by the edge router; it never stores control state or carries control traffic.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

const (
	controlTagRole             = "terrascale-control-role"
	controlTagEpoch            = "terrascale-control-epoch"
	controlTagPendingEpoch     = "terrascale-control-pending-epoch"
	controlTagActive           = "terrascale-control-active"
	controlTagAuthority        = "terrascale-control-authority"
	controlTagActionKey        = "terrascale-control-action-key"
	controlTagActionKind       = "terrascale-control-action-kind"
	controlTagPlan             = "terrascale-control-plan"
	controlTagSequence         = "terrascale-control-sequence"
	controlTagQuorumVerified   = "terrascale-control-quorum-verified"
	controlTagPromotionSeq     = "terrascale-control-promotion-sequence"
	controlTagRemoteMembers    = "terrascale-control-remote-members"
	controlCandidateTagPrefix  = "terrascale-control-candidate-"
	controlCandidateIdentity   = "-identity"
	controlCandidateStorage    = "-storage"
	controlCandidateHealth     = "-health"
	controlCandidateState      = "-state"
	controlCandidateStartSeq   = "-start-sequence"
	controlCandidateSyncSeq    = "-sync-sequence"
	controlCandidateVerifySeq  = "-verify-sequence"
	controlCandidateStarted    = "started"
	controlCandidateSynced     = "synchronized"
	controlAuthorityBootstrap  = "bootstrap"
	controlAuthorityPermanent  = "permanent"
	controlAuthorityRegional   = "regional"
	controlRoleTemporaryStart  = "temporary-starting"
	controlRoleTemporary       = "temporary-r1"
	controlRoleCandidate       = "candidate-r1"
	controlRoleGlobal          = "global-r3"
	controlRoleRemote          = "remote-managed"
	controlRoleRegional        = "regional-r3"
	controlProviderBodyLimit   = int64(1 << 20)
	controlProviderMaxAttempts = 4
)

var (
	ErrControlProviderInvalid     = errors.New("control provider configuration or response is invalid")
	ErrControlProviderUnavailable = errors.New("control provider is unavailable")
)

// ControlRegionBinding binds a declared Region to the member identities that
// may receive control metadata. MemberIDs must be the exact instances created
// by the OCI member reconciler. The first member co-hosts a launch replica;
// regional R3 uses the first three members.
type ControlRegionBinding struct {
	Code          string
	OCIRegion     string
	CompartmentID string
	MemberIDs     []string
	Latitude      float64
	Longitude     float64
}

// ProductionControlPlaneProviderConfig accepts only repository OCI transports
// and the canonical Cloudflare client. OCI transports must be signed, bound to
// the Region's canonical HTTPS authority, and use the core service.
type ProductionControlPlaneProviderConfig struct {
	Runtime    ControlRuntime
	Regions    []ControlRegionBinding
	OCI        map[string]*provider.OCIHTTPTransport
	Cloudflare *cloudflare.Client
}

// LocalControlPlaneProviderConfig is the only constructor that admits custom
// provider URLs. Every URL must be an absolute loopback HTTP(S) URL with an
// explicit port and no path, query, userinfo, or fragment.
type LocalControlPlaneProviderConfig struct {
	Runtime             ControlRuntime
	Regions             []ControlRegionBinding
	OCIBaseURLs         map[string]string
	CloudflareBaseURL   string
	CloudflareZoneID    string
	CloudflareAccountID string
	HTTPClient          *http.Client
}

// ControlReplica is one expected co-hosted control process as observed through
// OCI. Missing and stopped expected members remain in the result with Active
// false, which lets quorum checks describe an actual provider-side loss.
type ControlReplica struct {
	Region             string `json:"region"`
	MemberID           string `json:"memberId"`
	Role               string `json:"role"`
	Epoch              uint64 `json:"epoch"`
	LifecycleState     string `json:"lifecycleState"`
	Active             bool   `json:"active"`
	LastActionSequence uint64 `json:"lastActionSequence,omitempty"`
	LastAction         string `json:"lastAction,omitempty"`
	ReceiptID          string `json:"receiptId,omitempty"`
}

// ControlCandidateObservation includes the provider evidence and ordering
// needed to prove that candidate synchronization preceded R3 promotion.
type ControlCandidateObservation struct {
	Evidence       CandidateEvidence `json:"evidence"`
	StartSequence  uint64            `json:"startSequence,omitempty"`
	SyncSequence   uint64            `json:"syncSequence,omitempty"`
	VerifySequence uint64            `json:"verifySequence,omitempty"`
}

// ControlObservation is a detached view derived from provider reads. Edge
// health consistency is descriptive: stale Cloudflare health never changes the
// accepted control epoch or quorum derived from OCI members.
type ControlObservation struct {
	State                ControlPlaneState             `json:"state"`
	Replicas             []ControlReplica              `json:"replicas,omitempty"`
	Candidates           []ControlCandidateObservation `json:"candidates,omitempty"`
	RemoteRegions        []string                      `json:"remoteRegions,omitempty"`
	RemoteHealth         map[string]bool               `json:"remoteHealth,omitempty"`
	BootstrapAuthorized  bool                          `json:"bootstrapAuthorized"`
	QuorumAvailable      bool                          `json:"quorumAvailable"`
	LastSequence         uint64                        `json:"lastSequence,omitempty"`
	PromotionSequence    uint64                        `json:"promotionSequence,omitempty"`
	EdgeHealth           map[string]bool               `json:"edgeHealth,omitempty"`
	EdgeHealthConsistent bool                          `json:"edgeHealthConsistent"`
}

// Validate rejects internally contradictory observations. It intentionally
// permits stale edge health because Cloudflare is not a control authority.
func (o ControlObservation) Validate() error {
	if err := o.State.Validate(); err != nil || o.BootstrapAuthorized != o.State.BootstrapAuthorized {
		return ErrControlProviderInvalid
	}
	seenMembers := make(map[string]struct{}, len(o.Replicas))
	active := 0
	for _, replica := range o.Replicas {
		if !validControlRegion(replica.Region) || !validProviderIdentity(replica.MemberID, "instance") || replica.Role == "" {
			return ErrControlProviderInvalid
		}
		if _, exists := seenMembers[replica.MemberID]; exists {
			return ErrControlProviderInvalid
		}
		seenMembers[replica.MemberID] = struct{}{}
		if replica.Active {
			active++
		}
		if replica.Epoch > o.State.Epoch || replica.LastActionSequence > o.LastSequence {
			return ErrControlProviderInvalid
		}
	}
	seenCandidates := make(map[string]struct{}, len(o.Candidates))
	for _, candidate := range o.Candidates {
		if !candidate.Evidence.Ready() || candidate.SyncSequence == 0 || candidate.SyncSequence > o.LastSequence ||
			(candidate.VerifySequence != 0 && candidate.VerifySequence < candidate.SyncSequence) {
			return ErrControlProviderInvalid
		}
		if _, exists := seenCandidates[candidate.Evidence.Region]; exists {
			return ErrControlProviderInvalid
		}
		seenCandidates[candidate.Evidence.Region] = struct{}{}
		if o.PromotionSequence != 0 && candidate.SyncSequence >= o.PromotionSequence {
			return ErrControlProviderInvalid
		}
	}
	seenRemote := make(map[string]struct{}, len(o.RemoteRegions))
	for _, region := range o.RemoteRegions {
		if !validControlRegion(region) {
			return ErrControlProviderInvalid
		}
		if _, exists := seenRemote[region]; exists {
			return ErrControlProviderInvalid
		}
		seenRemote[region] = struct{}{}
		if _, exists := o.RemoteHealth[region]; !exists {
			return ErrControlProviderInvalid
		}
	}
	quorum := false
	switch o.State.Topology {
	case ControlTopologyGlobalR3, ControlTopologyRegionalR3:
		quorum = active >= 2
	case ControlTopologyTemporaryR1:
		quorum = active == 1
	}
	if quorum != o.QuorumAvailable {
		return ErrControlProviderInvalid
	}
	return nil
}

type controlOCIClient struct {
	transport *provider.OCIHTTPTransport
	baseURL   string
	http      *http.Client
	local     bool
}

type controlRegion struct {
	binding ControlRegionBinding
	oci     controlOCIClient
}

// ProviderControlPlane implements the bootstrap provider against OCI and
// Cloudflare HTTP clients. Calls are serialized within the process; OCI ETags
// fence concurrent writers outside it.
type ProviderControlPlane struct {
	runtime    ControlRuntime
	mu         sync.Mutex
	regions    map[string]controlRegion
	cloudflare *cloudflare.Client
	now        func() time.Time
}

var _ ControlPlaneProvider = (*ProviderControlPlane)(nil)

// NewProductionControlPlaneProvider builds a provider that cannot be pointed
// at non-canonical authorities. Local qualification must use the separate
// local constructor below.
func NewProductionControlPlaneProvider(config ProductionControlPlaneProviderConfig) (*ProviderControlPlane, error) {
	if config.Runtime == nil || !validProductionCloudflareClient(config.Cloudflare) {
		return nil, ErrControlProviderInvalid
	}
	regions, err := normalizeControlRegions(config.Regions)
	if err != nil || len(config.OCI) != len(regions) {
		return nil, ErrControlProviderInvalid
	}
	bound := make(map[string]controlRegion, len(regions))
	for code, binding := range regions {
		transport := config.OCI[code]
		if !validProductionOCITransport(transport, binding.OCIRegion) {
			return nil, ErrControlProviderInvalid
		}
		client := &http.Client{Transport: transport.Client.Transport, Timeout: transport.Client.Timeout,
			CheckRedirect: rejectControlRedirects}
		cloned, cloneErr := provider.NewOCIHTTPTransport(transport.Config, client, transport.Signer)
		if cloneErr != nil {
			return nil, ErrControlProviderInvalid
		}
		bound[code] = controlRegion{binding: binding, oci: controlOCIClient{transport: cloned}}
	}
	cf := cloudflare.NewClient(config.Cloudflare.Token, config.Cloudflare.ZoneID, config.Cloudflare.AccountID)
	cf.HTTP = config.Cloudflare.HTTP
	return &ProviderControlPlane{runtime: config.Runtime, regions: bound, cloudflare: cf, now: time.Now}, nil
}

// NewLocalControlPlaneProvider builds a provider for the loopback HTTP
// contracts used by VM qualification. It rejects non-loopback and path-bearing
// URLs even if the supplied HTTP client could reach them.
func NewLocalControlPlaneProvider(config LocalControlPlaneProviderConfig) (*ProviderControlPlane, error) {
	regions, err := normalizeControlRegions(config.Regions)
	if config.Runtime == nil || err != nil || len(config.OCIBaseURLs) != len(regions) || config.HTTPClient == nil || config.HTTPClient.Timeout <= 0 ||
		strings.TrimSpace(config.CloudflareZoneID) == "" || strings.TrimSpace(config.CloudflareAccountID) == "" {
		return nil, ErrControlProviderInvalid
	}
	cfBase, err := validateLocalProviderURL(config.CloudflareBaseURL)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: config.HTTPClient.Transport, Timeout: config.HTTPClient.Timeout,
		CheckRedirect: rejectControlRedirects}
	bound := make(map[string]controlRegion, len(regions))
	for code, binding := range regions {
		base, parseErr := validateLocalProviderURL(config.OCIBaseURLs[code])
		if parseErr != nil {
			return nil, parseErr
		}
		bound[code] = controlRegion{binding: binding, oci: controlOCIClient{baseURL: base, http: client, local: true}}
	}
	cf := cloudflare.NewClient("local-qualification", config.CloudflareZoneID, config.CloudflareAccountID)
	cf.BaseURL = cfBase
	if client.Transport != nil {
		cf.HTTP = client.Transport
	}
	return &ProviderControlPlane{runtime: config.Runtime, regions: bound, cloudflare: cf, now: time.Now}, nil
}

func validProductionCloudflareClient(client *cloudflare.Client) bool {
	return client != nil && strings.TrimSpace(client.Token) != "" && strings.TrimSpace(client.ZoneID) != "" &&
		strings.TrimSpace(client.AccountID) != "" && client.BaseURL == cloudflare.DefaultBaseURL && client.HTTP != nil
}

func validProductionOCITransport(transport *provider.OCIHTTPTransport, region string) bool {
	if transport == nil || transport.Signer == nil || transport.Client == nil || transport.Config.Endpoint == nil ||
		transport.Client.Timeout <= 0 || transport.Config.Service != provider.OCIServiceCore || transport.Config.Region != region {
		return false
	}
	want := "https://iaas." + region + ".oraclecloud.com/"
	return transport.Config.Endpoint.String() == want
}

func normalizeControlRegions(input []ControlRegionBinding) (map[string]ControlRegionBinding, error) {
	if len(input) == 0 || len(input) > 20 {
		return nil, ErrControlProviderInvalid
	}
	result := make(map[string]ControlRegionBinding, len(input))
	seenMembers := make(map[string]struct{})
	for _, raw := range input {
		binding := raw
		binding.Code = strings.TrimSpace(binding.Code)
		binding.OCIRegion = strings.TrimSpace(binding.OCIRegion)
		binding.CompartmentID = strings.TrimSpace(binding.CompartmentID)
		binding.MemberIDs = append([]string(nil), binding.MemberIDs...)
		if !validControlRegion(binding.Code) || !validOCIRegionName(binding.OCIRegion) ||
			!validProviderIdentity(binding.CompartmentID, "compartment") || len(binding.MemberIDs) < 1 || len(binding.MemberIDs) > 16 ||
			binding.Latitude < -90 || binding.Latitude > 90 || binding.Longitude < -180 || binding.Longitude > 180 {
			return nil, ErrControlProviderInvalid
		}
		if _, exists := result[binding.Code]; exists {
			return nil, ErrControlProviderInvalid
		}
		for index, memberID := range binding.MemberIDs {
			memberID = strings.TrimSpace(memberID)
			if !validProviderIdentity(memberID, "instance") {
				return nil, ErrControlProviderInvalid
			}
			if _, exists := seenMembers[memberID]; exists {
				return nil, ErrControlProviderInvalid
			}
			seenMembers[memberID] = struct{}{}
			binding.MemberIDs[index] = memberID
		}
		result[binding.Code] = binding
	}
	return result, nil
}

func validOCIRegionName(value string) bool {
	if value == "" || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func validProviderIdentity(value, kind string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 5 || parts[0] != "ocid1" || parts[1] != kind {
		return false
	}
	for _, char := range value {
		if char <= 0x20 || char == 0x7f || strings.ContainsRune("/\\?&#%", char) {
			return false
		}
	}
	return true
}

func validateLocalProviderURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil ||
		parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.Port() == "" {
		return "", ErrControlProviderInvalid
	}
	host := strings.ToLower(parsed.Hostname())
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", ErrControlProviderInvalid
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 {
		return "", ErrControlProviderInvalid
	}
	parsed.Path = ""
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func rejectControlRedirects(_ *http.Request, _ []*http.Request) error {
	return errors.New("control provider redirects are not allowed")
}

func (c controlOCIClient) do(ctx context.Context, method, path string, body []byte, headers map[string]string) (*http.Response, error) {
	if ctx == nil || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") {
		return nil, ErrControlProviderInvalid
	}
	if c.transport != nil {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		return c.transport.DoWithHeaders(ctx, method, path, reader, headers)
	}
	if c.http == nil || c.baseURL == "" {
		return nil, ErrControlProviderUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, ErrControlProviderInvalid
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		if name == "" || strings.ContainsAny(name+value, "\r\n") {
			return nil, ErrControlProviderInvalid
		}
		request.Header.Set(name, value)
	}
	return c.http.Do(request)
}

type controlInstance struct {
	ID             string            `json:"id"`
	CompartmentID  string            `json:"compartmentId"`
	DisplayName    string            `json:"displayName"`
	LifecycleState string            `json:"lifecycleState"`
	ETag           string            `json:"etag"`
	FreeformTags   map[string]string `json:"freeformTags"`
	missing        bool
	local          bool
	region         string
	memberIndex    int
	runtimeActive  bool
}

func (p *ProviderControlPlane) readInstance(ctx context.Context, region controlRegion, memberID string, index int) (controlInstance, error) {
	response, err := region.oci.do(ctx, http.MethodGet, "/20160918/instances/"+url.PathEscape(memberID), nil, nil)
	if err != nil {
		return controlInstance{}, err
	}
	if response.StatusCode == http.StatusNotFound {
		_, _ = readControlBody(response, 64<<10)
		return controlInstance{ID: memberID, CompartmentID: region.binding.CompartmentID, LifecycleState: "TERMINATED", missing: true, local: region.oci.local, region: region.binding.Code, memberIndex: index}, nil
	}
	body, err := readControlBody(response, controlProviderBodyLimit)
	if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return controlInstance{}, ErrControlProviderUnavailable
	}
	var instance controlInstance
	if json.Unmarshal(body, &instance) != nil {
		return controlInstance{}, ErrControlProviderInvalid
	}
	if instance.ETag == "" {
		instance.ETag = response.Header.Get("ETag")
	}
	if instance.ID != memberID || instance.CompartmentID != region.binding.CompartmentID ||
		instance.ETag == "" || len(instance.ETag) > 256 || strings.ContainsAny(instance.ETag, "\r\n") ||
		instance.FreeformTags[provider.OCIManagedTag] != ocireconcile.ManagedMemberTagValue ||
		instance.FreeformTags[provider.OCIScopeTag] != region.binding.Code ||
		instance.FreeformTags[ocireconcile.MemberIndexTag] != strconv.Itoa(index+1) {
		return controlInstance{}, ErrControlProviderInvalid
	}
	instance.local, instance.region, instance.memberIndex = region.oci.local, region.binding.Code, index
	return instance, nil
}

func readControlBody(response *http.Response, limit int64) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, ErrControlProviderUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, ErrControlProviderUnavailable
	}
	return body, nil
}

func (p *ProviderControlPlane) readAllLocked(ctx context.Context) ([]controlInstance, error) {
	if p.runtime == nil {
		return nil, ErrControlRuntimeUnavailable
	}
	live, err := p.runtime.Observe(ctx)
	if err != nil {
		return nil, err
	}
	codes := p.regionCodes()
	instances := make([]controlInstance, 0)
	for _, code := range codes {
		region := p.regions[code]
		for index, memberID := range region.binding.MemberIDs {
			instance, err := p.readInstance(ctx, region, memberID, index)
			if err != nil {
				return nil, err
			}
			instance.runtimeActive = live[memberID]
			instances = append(instances, instance)
		}
	}
	return instances, nil
}

func (p *ProviderControlPlane) regionCodes() []string {
	codes := make([]string, 0, len(p.regions))
	for code := range p.regions {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return codes
}

func activeMemberLifecycle(instance controlInstance) bool {
	return instance.runtimeActive && (instance.LifecycleState == "RUNNING" || (instance.local && instance.LifecycleState == "AVAILABLE"))
}

func parseUintTag(tags map[string]string, name string) (uint64, error) {
	value := tags[name]
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, ErrControlProviderInvalid
	}
	return parsed, nil
}

func controlCandidateTag(region, suffix string) string {
	return controlCandidateTagPrefix + region + suffix
}

func candidateFromTags(tags map[string]string, region string) (ControlCandidateObservation, bool, error) {
	state := tags[controlCandidateTag(region, controlCandidateState)]
	if state == "" {
		return ControlCandidateObservation{}, false, nil
	}
	start, err := parseUintTag(tags, controlCandidateTag(region, controlCandidateStartSeq))
	if err != nil {
		return ControlCandidateObservation{}, false, err
	}
	syncSequence, err := parseUintTag(tags, controlCandidateTag(region, controlCandidateSyncSeq))
	if err != nil {
		return ControlCandidateObservation{}, false, err
	}
	verify, err := parseUintTag(tags, controlCandidateTag(region, controlCandidateVerifySeq))
	if err != nil {
		return ControlCandidateObservation{}, false, err
	}
	observation := ControlCandidateObservation{
		Evidence: CandidateEvidence{
			Region:         region,
			IdentityDigest: tags[controlCandidateTag(region, controlCandidateIdentity)],
			StorageDigest:  tags[controlCandidateTag(region, controlCandidateStorage)],
			HealthDigest:   tags[controlCandidateTag(region, controlCandidateHealth)],
			CaughtUp:       state == controlCandidateSynced,
			IdentityReady:  tags[controlCandidateTag(region, controlCandidateIdentity)] != "",
			StorageReady:   tags[controlCandidateTag(region, controlCandidateStorage)] != "",
			HealthReady:    tags[controlCandidateTag(region, controlCandidateHealth)] != "",
		},
		StartSequence: start, SyncSequence: syncSequence, VerifySequence: verify,
	}
	if state != controlCandidateStarted && state != controlCandidateSynced {
		return ControlCandidateObservation{}, false, ErrControlProviderInvalid
	}
	if state == controlCandidateSynced && !observation.Evidence.Ready() {
		return ControlCandidateObservation{}, false, ErrControlProviderInvalid
	}
	return observation, true, nil
}

func mergeCandidateObservation(values map[string]ControlCandidateObservation, candidate ControlCandidateObservation) error {
	prior, exists := values[candidate.Evidence.Region]
	if !exists {
		values[candidate.Evidence.Region] = candidate
		return nil
	}
	if prior != candidate {
		return ErrControlProviderInvalid
	}
	return nil
}

func (p *ProviderControlPlane) observationFromInstances(instances []controlInstance) (ControlObservation, error) {
	observation := ControlObservation{EdgeHealthConsistent: true, RemoteHealth: make(map[string]bool)}
	candidates := make(map[string]ControlCandidateObservation)
	remote := make(map[string]struct{})
	remoteActive := make(map[string]int)
	globalEpoch := uint64(0)
	regionalEpoch := uint64(0)
	temporaryEpoch := uint64(0)
	globalBootstrap := 0
	globalPermanent := 0
	globalRoles := 0
	regionalRoles := 0
	temporaryRoles := 0

	for _, instance := range instances {
		if instance.missing {
			continue
		}
		epoch, err := parseUintTag(instance.FreeformTags, controlTagEpoch)
		if err != nil {
			return ControlObservation{}, err
		}
		sequence, err := parseUintTag(instance.FreeformTags, controlTagSequence)
		if err != nil {
			return ControlObservation{}, err
		}
		promotion, err := parseUintTag(instance.FreeformTags, controlTagPromotionSeq)
		if err != nil {
			return ControlObservation{}, err
		}
		observation.LastSequence = maxUint64(observation.LastSequence, sequence)
		observation.PromotionSequence = maxUint64(observation.PromotionSequence, promotion)
		for _, region := range []string{"sfo", "fra"} {
			candidate, exists, candidateErr := candidateFromTags(instance.FreeformTags, region)
			if candidateErr != nil {
				return ControlObservation{}, candidateErr
			}
			if exists && candidate.Evidence.Ready() {
				if err := mergeCandidateObservation(candidates, candidate); err != nil {
					return ControlObservation{}, err
				}
			}
		}
		role := instance.FreeformTags[controlTagRole]
		switch role {
		case "":
			continue
		case controlRoleRemote:
			remote[instance.region] = struct{}{}
			if activeMemberLifecycle(instance) {
				remoteActive[instance.region]++
			}
			continue
		case controlRoleTemporaryStart:
			continue
		case controlRoleTemporary:
			temporaryRoles++
			temporaryEpoch = maxUint64(temporaryEpoch, epoch)
		case controlRoleCandidate:
			// Candidates are not voting replicas until promotion.
			continue
		case controlRoleGlobal:
			globalRoles++
			globalEpoch = maxUint64(globalEpoch, epoch)
		case controlRoleRegional:
			regionalRoles++
			regionalEpoch = maxUint64(regionalEpoch, epoch)
		default:
			return ControlObservation{}, ErrControlProviderInvalid
		}
		authority := instance.FreeformTags[controlTagAuthority]
		if role == controlRoleGlobal {
			switch authority {
			case controlAuthorityBootstrap:
				globalBootstrap++
			case controlAuthorityPermanent:
				globalPermanent++
			default:
				return ControlObservation{}, ErrControlProviderInvalid
			}
		}
		active := instance.FreeformTags[controlTagActive] == "true" && activeMemberLifecycle(instance)
		observation.Replicas = append(observation.Replicas, ControlReplica{
			Region: instance.region, MemberID: instance.ID, Role: role, Epoch: epoch,
			LifecycleState: instance.LifecycleState, Active: active,
			LastActionSequence: sequence, LastAction: instance.FreeformTags[controlTagActionKind], ReceiptID: instance.FreeformTags[controlTagActionKey],
		})
	}

	for _, candidate := range candidates {
		observation.Candidates = append(observation.Candidates, candidate)
	}
	sort.Slice(observation.Candidates, func(i, j int) bool {
		return observation.Candidates[i].Evidence.Region < observation.Candidates[j].Evidence.Region
	})
	for region := range remote {
		observation.RemoteRegions = append(observation.RemoteRegions, region)
		observation.RemoteHealth[region] = remoteActive[region] >= 2
	}
	sort.Strings(observation.RemoteRegions)

	switch {
	case globalRoles > 0:
		if globalEpoch == 0 || globalBootstrap+globalPermanent != globalRoles {
			return ControlObservation{}, ErrControlProviderInvalid
		}
		stateCandidates := make([]CandidateEvidence, 0, len(observation.Candidates))
		for _, candidate := range observation.Candidates {
			stateCandidates = append(stateCandidates, candidate.Evidence)
		}
		observation.BootstrapAuthorized = globalBootstrap > 0
		observation.State = ControlPlaneState{Topology: ControlTopologyGlobalR3, Phase: ControlPhaseR3, Epoch: globalEpoch,
			BootstrapAuthorized: observation.BootstrapAuthorized, MemberHosts: 2,
			ControlRegions: []string{"gru", "sfo", "fra"}, Candidates: stateCandidates}.normalize()
		p.addMissingGlobalReplicas(&observation, instances, globalEpoch)
	case regionalRoles > 0:
		if regionalEpoch == 0 {
			return ControlObservation{}, ErrControlProviderInvalid
		}
		regions := uniqueReplicaRegions(observation.Replicas, controlRoleRegional)
		observation.State = ControlPlaneState{Topology: ControlTopologyRegionalR3, Phase: ControlPhaseRegionalR3,
			Epoch: regionalEpoch, MemberHosts: regionalRoles, ControlRegions: regions}.normalize()
	case temporaryRoles > 0:
		if temporaryRoles != 1 || temporaryEpoch == 0 {
			return ControlObservation{}, ErrControlProviderInvalid
		}
		stateCandidates := make([]CandidateEvidence, 0, len(observation.Candidates))
		for _, candidate := range observation.Candidates {
			stateCandidates = append(stateCandidates, candidate.Evidence)
		}
		observation.BootstrapAuthorized = true
		observation.State = ControlPlaneState{Topology: ControlTopologyTemporaryR1, Phase: ControlPhaseR1, Epoch: temporaryEpoch,
			BootstrapAuthorized: true, MemberHosts: 2, ControlRegions: []string{"gru"}, Candidates: stateCandidates}.normalize()
	default:
		observation.State = ControlPlaneState{}.normalize()
	}
	for index := range observation.Replicas {
		if observation.Replicas[index].Epoch != observation.State.Epoch {
			observation.Replicas[index].Active = false
		}
	}
	active := 0
	for _, replica := range observation.Replicas {
		if replica.Active {
			active++
		}
	}
	switch observation.State.Topology {
	case ControlTopologyGlobalR3, ControlTopologyRegionalR3:
		observation.QuorumAvailable = active >= 2
	case ControlTopologyTemporaryR1:
		observation.QuorumAvailable = active == 1
	}
	if err := observation.Validate(); err != nil {
		return ControlObservation{}, err
	}
	return observation, nil
}

func uniqueReplicaRegions(replicas []ControlReplica, role string) []string {
	set := make(map[string]struct{})
	for _, replica := range replicas {
		if replica.Role == role {
			set[replica.Region] = struct{}{}
		}
	}
	regions := make([]string, 0, len(set))
	for region := range set {
		regions = append(regions, region)
	}
	sort.Strings(regions)
	return regions
}

func (p *ProviderControlPlane) addMissingGlobalReplicas(observation *ControlObservation, instances []controlInstance, epoch uint64) {
	present := make(map[string]bool)
	for _, replica := range observation.Replicas {
		if replica.Role == controlRoleGlobal {
			present[replica.Region] = true
		}
	}
	for _, instance := range instances {
		if !instance.missing || instance.memberIndex != 0 || present[instance.region] ||
			(instance.region != "gru" && instance.region != "sfo" && instance.region != "fra") {
			continue
		}
		observation.Replicas = append(observation.Replicas, ControlReplica{Region: instance.region, MemberID: instance.ID,
			Role: controlRoleGlobal, Epoch: epoch, LifecycleState: instance.LifecycleState, Active: false})
	}
	sort.Slice(observation.Replicas, func(i, j int) bool {
		if observation.Replicas[i].Region != observation.Replicas[j].Region {
			return observation.Replicas[i].Region < observation.Replicas[j].Region
		}
		return observation.Replicas[i].MemberID < observation.Replicas[j].MemberID
	})
}

// ObserveControl reads every configured expected member and the Cloudflare
// Worker-health document. Runtime readback, not OCI lifecycle tags, proves
// that an expected control process is active.
func (p *ProviderControlPlane) ObserveControl(ctx context.Context) (ControlObservation, error) {
	if p == nil || ctx == nil {
		return ControlObservation{}, ErrControlProviderUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ControlObservation{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	instances, err := p.readAllLocked(ctx)
	if err != nil {
		return ControlObservation{}, err
	}
	observation, err := p.observationFromInstances(instances)
	if err != nil {
		return ControlObservation{}, err
	}
	p.readEdgeHealthLocked(ctx, &observation)
	return observation, nil
}

// ReplicaStatus returns the exact expected member observation for one Region.
func (p *ProviderControlPlane) ReplicaStatus(ctx context.Context, region string) (ControlReplica, error) {
	observation, err := p.ObserveControl(ctx)
	if err != nil {
		return ControlReplica{}, err
	}
	for _, replica := range observation.Replicas {
		if replica.Region == region {
			return replica, nil
		}
	}
	return ControlReplica{}, ErrControlProviderUnavailable
}

func (p *ProviderControlPlane) readEdgeHealthLocked(ctx context.Context, observation *ControlObservation) {
	namespaces, err := p.cloudflare.ListKVNamespaces(ctx)
	if err != nil {
		observation.EdgeHealthConsistent = false
		return
	}
	found := false
	for _, namespace := range namespaces {
		if namespace.Title == cloudflare.RegionHealthNamespace {
			found = true
			break
		}
	}
	if !found {
		observation.EdgeHealthConsistent = observation.State.Phase == ControlPhaseEmpty
		return
	}
	document, err := p.cloudflare.WorkerHealth(ctx)
	if err != nil {
		observation.EdgeHealthConsistent = false
		return
	}
	observation.EdgeHealth = make(map[string]bool, len(document.Regions))
	for region, health := range document.Regions {
		observation.EdgeHealth[strings.ToLower(region)] = health.OK
	}
	want := p.derivedRegionHealth(*observation)
	for region, healthy := range want {
		if observation.EdgeHealth[region] != healthy {
			observation.EdgeHealthConsistent = false
		}
	}
}

func (p *ProviderControlPlane) derivedRegionHealth(observation ControlObservation) map[string]bool {
	health := make(map[string]bool, len(p.regions))
	for code := range p.regions {
		health[code] = false
	}
	for _, replica := range observation.Replicas {
		health[replica.Region] = health[replica.Region] || replica.Active
	}
	for _, region := range observation.RemoteRegions {
		health[region] = observation.RemoteHealth[region]
	}
	return health
}

func (p *ProviderControlPlane) ensureHealthNamespaceLocked(ctx context.Context) error {
	namespaces, err := p.cloudflare.ListKVNamespaces(ctx)
	if err != nil {
		return err
	}
	for _, namespace := range namespaces {
		if namespace.Title == cloudflare.RegionHealthNamespace {
			return nil
		}
	}
	if err := p.cloudflare.CreateKVNamespace(ctx, cloudflare.RegionHealthNamespace); err != nil {
		// A competing reconciler may have created it after our list.
		namespaces, listErr := p.cloudflare.ListKVNamespaces(ctx)
		if listErr != nil {
			return err
		}
		for _, namespace := range namespaces {
			if namespace.Title == cloudflare.RegionHealthNamespace {
				return nil
			}
		}
		return err
	}
	return nil
}

func (p *ProviderControlPlane) publishHealthLocked(ctx context.Context) error {
	if err := p.ensureHealthNamespaceLocked(ctx); err != nil {
		return err
	}
	instances, err := p.readAllLocked(ctx)
	if err != nil {
		return err
	}
	observation, err := p.observationFromInstances(instances)
	if err != nil {
		return err
	}
	derived := p.derivedRegionHealth(observation)
	entries := make(map[string]cloudflare.WorkerRegionHealth, len(p.regions))
	for code, region := range p.regions {
		entries[code] = cloudflare.WorkerRegionHealth{OK: derived[code], LagMS: 0,
			Lat: region.binding.Latitude, Lon: region.binding.Longitude}
	}
	now := p.now
	if now == nil {
		now = time.Now
	}
	return p.cloudflare.SetWorkerHealth(ctx, cloudflare.WorkerHealthDoc{Updated: now().UTC().Unix(), Regions: entries})
}

func validateProviderAction(ctx context.Context, request ControlActionRequest, kind ControlActionKind) error {
	if ctx == nil || request.Action.Kind != kind || request.Action.ID == "" || request.Action.IdempotencyKey == "" ||
		request.PlanFingerprint == "" || len(request.PlanFingerprint) != sha256.Size*2 || request.Action.ExpectedEpoch > request.Action.TargetEpoch {
		return ErrControlProviderInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := request.State.Validate(); err != nil {
		return err
	}
	if _, err := hex.DecodeString(request.PlanFingerprint); err != nil {
		return ErrControlProviderInvalid
	}
	return nil
}

func (p *ProviderControlPlane) actionTargets(kind ControlActionKind, region string) ([]struct {
	region string
	index  int
}, error) {
	makeTarget := func(code string, count int) ([]struct {
		region string
		index  int
	}, error) {
		binding, exists := p.regions[code]
		if !exists || len(binding.binding.MemberIDs) < count {
			return nil, ErrControlProviderInvalid
		}
		result := make([]struct {
			region string
			index  int
		}, count)
		for index := 0; index < count; index++ {
			result[index] = struct {
				region string
				index  int
			}{code, index}
		}
		return result, nil
	}
	switch kind {
	case ControlActionStartTemporaryR1, ControlActionFenceR1:
		if region != "gru" {
			return nil, ErrControlProviderInvalid
		}
		return makeTarget("gru", 1)
	case ControlActionStartCandidate, ControlActionSyncCandidate, ControlActionVerifyCandidate:
		if region != "sfo" && region != "fra" {
			return nil, ErrControlProviderInvalid
		}
		return makeTarget(region, 1)
	case ControlActionPromoteR3, ControlActionVerifyQuorum, ControlActionRevokeBootstrap:
		var targets []struct {
			region string
			index  int
		}
		for _, code := range []string{"gru", "sfo", "fra"} {
			part, err := makeTarget(code, 1)
			if err != nil {
				return nil, err
			}
			targets = append(targets, part...)
		}
		return targets, nil
	case ControlActionRemoteManage:
		return makeTarget(region, 2)
	case ControlActionStartRegionalR3:
		return makeTarget(region, 3)
	default:
		return nil, ErrControlProviderInvalid
	}
}

type tagMutation func(map[string]string, controlInstance, uint64, []controlInstance, ControlRuntimeEvidence) error

func (p *ProviderControlPlane) mutate(ctx context.Context, request ControlActionRequest, kind ControlActionKind, change tagMutation) (ControlReceipt, error) {
	if p == nil {
		return ControlReceipt{}, ErrControlProviderUnavailable
	}
	if err := validateProviderAction(ctx, request, kind); err != nil {
		return ControlReceipt{}, err
	}
	if p.runtime == nil {
		return ControlReceipt{}, ErrControlRuntimeUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	targets, err := p.actionTargets(kind, request.Action.Region)
	if err != nil {
		return ControlReceipt{}, err
	}
	var evidence ControlRuntimeEvidence
	runtimeExecuted := false
	for attempt := 0; attempt < controlProviderMaxAttempts; attempt++ {
		instances, readErr := p.readAllLocked(ctx)
		if readErr != nil {
			return ControlReceipt{}, readErr
		}
		maxEpoch, maxSequence := uint64(0), uint64(0)
		byMember := make(map[string]controlInstance, len(instances))
		for _, instance := range instances {
			byMember[instance.ID] = instance
			if !instance.missing {
				epoch, parseErr := parseUintTag(instance.FreeformTags, controlTagEpoch)
				if parseErr != nil {
					return ControlReceipt{}, parseErr
				}
				sequence, parseErr := parseUintTag(instance.FreeformTags, controlTagSequence)
				if parseErr != nil {
					return ControlReceipt{}, parseErr
				}
				maxEpoch, maxSequence = maxUint64(maxEpoch, epoch), maxUint64(maxSequence, sequence)
			}
		}
		if request.Action.TargetEpoch < maxEpoch {
			return ControlReceipt{}, ErrControlEpochRegression
		}
		for _, target := range targets {
			instance := byMember[p.regions[target.region].binding.MemberIDs[target.index]]
			if instance.missing {
				return ControlReceipt{}, ErrControlProviderUnavailable
			}
			if instance.FreeformTags[controlTagActionKey] == request.Action.IdempotencyKey && (instance.FreeformTags[controlTagActionKind] != string(kind) || instance.FreeformTags[controlTagPlan] != request.PlanFingerprint) {
				return ControlReceipt{}, ErrControlProviderInvalid
			}
		}
		if !runtimeExecuted {
			evidence, err = p.runtime.Execute(ctx, request)
			if err != nil {
				return ControlReceipt{}, err
			}
			if err := evidence.validate(time.Now().UTC()); err != nil {
				return ControlReceipt{}, err
			}
			runtimeExecuted = true
			// Execution can start or replace processes. Re-read actual liveness
			// before evaluating the transition's postconditions and recording it.
			continue
		}
		if err := evidence.validate(time.Now().UTC()); err != nil {
			return ControlReceipt{}, err
		}
		sequence := maxSequence + 1
		complete := true
		for _, target := range targets {
			region := p.regions[target.region]
			instance := byMember[region.binding.MemberIDs[target.index]]
			if instance.missing {
				return ControlReceipt{}, ErrControlProviderUnavailable
			}
			if instance.FreeformTags[controlTagActionKey] == request.Action.IdempotencyKey {
				if instance.FreeformTags[controlTagActionKind] != string(kind) || instance.FreeformTags[controlTagPlan] != request.PlanFingerprint {
					return ControlReceipt{}, ErrControlProviderInvalid
				}
				continue
			}
			complete = false
			tags := cloneControlTags(instance.FreeformTags)
			if err := change(tags, instance, sequence, instances, evidence); err != nil {
				return ControlReceipt{}, err
			}
			tags[controlTagActionKey] = request.Action.IdempotencyKey
			tags[controlTagActionKind] = string(kind)
			tags[controlTagPlan] = request.PlanFingerprint
			tags[controlTagSequence] = strconv.FormatUint(sequence, 10)
			if len(tags) > 32 {
				return ControlReceipt{}, ErrControlProviderInvalid
			}
			if err := p.updateInstance(ctx, region, instance, tags); err != nil {
				if errors.Is(err, errControlETagConflict) {
					complete = false
					break
				}
				return ControlReceipt{}, err
			}
		}
		if complete {
			if err := p.publishHealthLocked(ctx); err != nil {
				return ControlReceipt{}, err
			}
			return ControlReceipt{ID: request.Action.IdempotencyKey}, nil
		}
		// Re-observe even after a partially completed multi-Region action. The
		// stable action key makes the next pass update only the missing targets.
		if attempt+1 == controlProviderMaxAttempts {
			return ControlReceipt{}, ErrControlProviderUnavailable
		}
	}
	return ControlReceipt{}, ErrControlProviderUnavailable
}

var errControlETagConflict = errors.New("control provider ETag conflict")

func cloneControlTags(input map[string]string) map[string]string {
	result := make(map[string]string, len(input)+16)
	for key, value := range input {
		result[key] = value
	}
	return result
}

func (p *ProviderControlPlane) updateInstance(ctx context.Context, region controlRegion, instance controlInstance, tags map[string]string) error {
	body, err := json.Marshal(struct {
		FreeformTags map[string]string `json:"freeformTags"`
	}{FreeformTags: tags})
	if err != nil {
		return ErrControlProviderInvalid
	}
	response, err := region.oci.do(ctx, http.MethodPut, "/20160918/instances/"+url.PathEscape(instance.ID), body,
		map[string]string{"If-Match": instance.ETag, "opc-retry-token": tags[controlTagActionKey]})
	if err != nil {
		return err
	}
	responseBody, readErr := readControlBody(response, controlProviderBodyLimit)
	if response.StatusCode == http.StatusPreconditionFailed || response.StatusCode == http.StatusConflict {
		return errControlETagConflict
	}
	if readErr != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrControlProviderUnavailable
	}
	var updated controlInstance
	if len(responseBody) != 0 && (json.Unmarshal(responseBody, &updated) != nil || updated.ID != instance.ID) {
		return ErrControlProviderInvalid
	}
	return nil
}

func setControlBase(tags map[string]string, role, authority string, epoch uint64, active bool) {
	tags[controlTagRole] = role
	tags[controlTagEpoch] = strconv.FormatUint(epoch, 10)
	tags[controlTagActive] = strconv.FormatBool(active)
	tags[controlTagAuthority] = authority
	delete(tags, controlTagPendingEpoch)
}

func copyCandidateTags(target map[string]string, source map[string]string, region string) error {
	for _, suffix := range []string{controlCandidateIdentity, controlCandidateStorage, controlCandidateHealth, controlCandidateState,
		controlCandidateStartSeq, controlCandidateSyncSeq, controlCandidateVerifySeq} {
		key := controlCandidateTag(region, suffix)
		if source[key] == "" {
			return ErrControlPromotionNotReady
		}
		target[key] = source[key]
	}
	return nil
}

func candidateSource(instances []controlInstance, region string) (controlInstance, error) {
	for _, instance := range instances {
		if instance.region == region && instance.memberIndex == 0 && !instance.missing {
			candidate, exists, err := candidateFromTags(instance.FreeformTags, region)
			if err != nil {
				return controlInstance{}, err
			}
			if exists && candidate.Evidence.Ready() {
				return instance, nil
			}
		}
	}
	return controlInstance{}, ErrControlPromotionNotReady
}

func (p *ProviderControlPlane) StartTemporaryR1(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.mutate(ctx, request, ControlActionStartTemporaryR1, func(tags map[string]string, instance controlInstance, _ uint64, _ []controlInstance, evidence ControlRuntimeEvidence) error {
		if request.State.normalize().Phase != ControlPhaseEmpty || request.Action.TargetEpoch != 1 || tags[controlTagRole] != "" {
			return ErrControlInvalid
		}
		setControlBase(tags, controlRoleTemporaryStart, controlAuthorityBootstrap, 0, false)
		tags[controlTagPendingEpoch] = "1"
		return nil
	})
}

func (p *ProviderControlPlane) FenceTemporaryR1(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.mutate(ctx, request, ControlActionFenceR1, func(tags map[string]string, _ controlInstance, _ uint64, _ []controlInstance, evidence ControlRuntimeEvidence) error {
		if tags[controlTagRole] != controlRoleTemporaryStart || tags[controlTagPendingEpoch] != "1" || request.Action.TargetEpoch != 1 {
			return ErrControlInvalid
		}
		setControlBase(tags, controlRoleTemporary, controlAuthorityBootstrap, 1, true)
		return nil
	})
}

func (p *ProviderControlPlane) StartCandidate(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.mutate(ctx, request, ControlActionStartCandidate, func(tags map[string]string, instance controlInstance, sequence uint64, instances []controlInstance, evidence ControlRuntimeEvidence) error {
		phase := request.State.normalize().Phase
		if phase != ControlPhaseR1 && phase != ControlPhasePromoting {
			return ErrControlInvalid
		}
		if !providerHasTemporaryR1(instances, request.Action.ExpectedEpoch) {
			return ErrControlInvalid
		}
		setControlBase(tags, controlRoleCandidate, controlAuthorityBootstrap, request.Action.ExpectedEpoch, false)
		region := request.Action.Region
		tags[controlCandidateTag(region, controlCandidateIdentity)] = evidence.IdentityDigest
		tags[controlCandidateTag(region, controlCandidateState)] = controlCandidateStarted
		tags[controlCandidateTag(region, controlCandidateStartSeq)] = strconv.FormatUint(sequence, 10)
		return nil
	})
}

func providerHasTemporaryR1(instances []controlInstance, epoch uint64) bool {
	for _, instance := range instances {
		if instance.region != "gru" || instance.memberIndex != 0 || instance.missing || !activeMemberLifecycle(instance) ||
			instance.FreeformTags[controlTagRole] != controlRoleTemporary || instance.FreeformTags[controlTagAuthority] != controlAuthorityBootstrap {
			continue
		}
		observed, err := parseUintTag(instance.FreeformTags, controlTagEpoch)
		return err == nil && observed == epoch
	}
	return false
}

func (p *ProviderControlPlane) SyncCandidate(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.mutate(ctx, request, ControlActionSyncCandidate, func(tags map[string]string, instance controlInstance, sequence uint64, _ []controlInstance, evidence ControlRuntimeEvidence) error {
		region := request.Action.Region
		if tags[controlTagRole] != controlRoleCandidate || tags[controlCandidateTag(region, controlCandidateState)] != controlCandidateStarted ||
			tags[controlCandidateTag(region, controlCandidateIdentity)] == "" || !activeMemberLifecycle(instance) {
			return ErrControlInvalid
		}
		tags[controlCandidateTag(region, controlCandidateStorage)] = evidence.StorageDigest
		tags[controlCandidateTag(region, controlCandidateHealth)] = evidence.HealthDigest
		tags[controlCandidateTag(region, controlCandidateState)] = controlCandidateSynced
		tags[controlCandidateTag(region, controlCandidateSyncSeq)] = strconv.FormatUint(sequence, 10)
		return nil
	})
}

func (p *ProviderControlPlane) VerifyCandidate(ctx context.Context, request ControlActionRequest) (CandidateEvidence, error) {
	receipt, err := p.mutate(ctx, request, ControlActionVerifyCandidate, func(tags map[string]string, _ controlInstance, sequence uint64, _ []controlInstance, evidence ControlRuntimeEvidence) error {
		candidate, exists, parseErr := candidateFromTags(tags, request.Action.Region)
		if parseErr != nil || !exists || !candidate.Evidence.Ready() {
			return ErrControlPromotionNotReady
		}
		tags[controlCandidateTag(request.Action.Region, controlCandidateVerifySeq)] = strconv.FormatUint(sequence, 10)
		return nil
	})
	if err != nil || receipt.ID == "" {
		return CandidateEvidence{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	region := p.regions[request.Action.Region]
	instance, err := p.readInstance(ctx, region, region.binding.MemberIDs[0], 0)
	if err != nil {
		return CandidateEvidence{}, err
	}
	candidate, exists, err := candidateFromTags(instance.FreeformTags, request.Action.Region)
	if err != nil || !exists || !candidate.Evidence.Ready() {
		return CandidateEvidence{}, ErrControlPromotionNotReady
	}
	return candidate.Evidence, nil
}

func (p *ProviderControlPlane) PromoteGlobalR3(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.mutate(ctx, request, ControlActionPromoteR3, func(tags map[string]string, _ controlInstance, sequence uint64, instances []controlInstance, evidence ControlRuntimeEvidence) error {
		if request.Action.TargetEpoch != request.Action.ExpectedEpoch+1 {
			return ErrControlInvalid
		}
		for _, region := range []string{"sfo", "fra"} {
			source, err := candidateSource(instances, region)
			if err != nil {
				return err
			}
			if err := copyCandidateTags(tags, source.FreeformTags, region); err != nil {
				return err
			}
		}
		setControlBase(tags, controlRoleGlobal, controlAuthorityBootstrap, request.Action.TargetEpoch, true)
		tags[controlTagPromotionSeq] = strconv.FormatUint(sequence, 10)
		return nil
	})
}

func (p *ProviderControlPlane) VerifyGlobalR3(ctx context.Context, request ControlActionRequest) error {
	_, err := p.mutate(ctx, request, ControlActionVerifyQuorum, func(tags map[string]string, _ controlInstance, _ uint64, instances []controlInstance, evidence ControlRuntimeEvidence) error {
		active := 0
		for _, instance := range instances {
			if instance.memberIndex != 0 || instance.missing || instance.FreeformTags[controlTagRole] != controlRoleGlobal ||
				!activeMemberLifecycle(instance) || instance.FreeformTags[controlTagActive] != "true" {
				continue
			}
			epoch, parseErr := parseUintTag(instance.FreeformTags, controlTagEpoch)
			if parseErr != nil {
				return parseErr
			}
			if epoch == request.Action.TargetEpoch {
				active++
			}
		}
		if active < 2 {
			return ErrControlQuorumNotVerified
		}
		tags[controlTagQuorumVerified] = "true"
		return nil
	})
	return err
}

func (p *ProviderControlPlane) RevokeBootstrapAuthority(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.mutate(ctx, request, ControlActionRevokeBootstrap, func(tags map[string]string, _ controlInstance, _ uint64, instances []controlInstance, evidence ControlRuntimeEvidence) error {
		verified := 0
		for _, instance := range instances {
			if instance.memberIndex == 0 && !instance.missing && instance.FreeformTags[controlTagRole] == controlRoleGlobal &&
				instance.FreeformTags[controlTagQuorumVerified] == "true" {
				verified++
			}
		}
		if verified < 2 || tags[controlTagAuthority] != controlAuthorityBootstrap {
			return ErrControlQuorumNotVerified
		}
		tags[controlTagAuthority] = controlAuthorityPermanent
		return nil
	})
}

func (p *ProviderControlPlane) RemoteManageRegion(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.mutate(ctx, request, ControlActionRemoteManage, func(tags map[string]string, _ controlInstance, _ uint64, instances []controlInstance, evidence ControlRuntimeEvidence) error {
		if !providerHasPermanentQuorum(instances, request.Action.ExpectedEpoch) {
			return ErrControlQuorumNotVerified
		}
		setControlBase(tags, controlRoleRemote, controlAuthorityPermanent, request.Action.ExpectedEpoch, false)
		tags[controlTagRemoteMembers] = "2"
		return nil
	})
}

func providerHasPermanentQuorum(instances []controlInstance, epoch uint64) bool {
	active := 0
	for _, instance := range instances {
		if instance.memberIndex != 0 || instance.missing || instance.FreeformTags[controlTagRole] != controlRoleGlobal ||
			instance.FreeformTags[controlTagAuthority] != controlAuthorityPermanent || instance.FreeformTags[controlTagActive] != "true" ||
			!activeMemberLifecycle(instance) {
			continue
		}
		observed, err := parseUintTag(instance.FreeformTags, controlTagEpoch)
		if err == nil && observed == epoch {
			active++
		}
	}
	return active >= 2
}

func (p *ProviderControlPlane) StartRegionalR3(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.mutate(ctx, request, ControlActionStartRegionalR3, func(tags map[string]string, instance controlInstance, _ uint64, _ []controlInstance, evidence ControlRuntimeEvidence) error {
		if !activeMemberLifecycle(instance) || request.Action.TargetEpoch <= request.Action.ExpectedEpoch {
			return ErrControlInvalid
		}
		setControlBase(tags, controlRoleRegional, controlAuthorityRegional, request.Action.TargetEpoch, true)
		return nil
	})
}
