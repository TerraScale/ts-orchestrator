package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	productioncf "terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	localcf "terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/cloudflare"
	localoci "terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/oci"
)

type controlProviderHarness struct {
	t        *testing.T
	ctx      context.Context
	client   *http.Client
	oci      *httptest.Server
	cf       *httptest.Server
	provider *ProviderControlPlane
	bindings map[string]ControlRegionBinding
}

func newControlProviderHarness(t *testing.T) *controlProviderHarness {
	t.Helper()
	ociHandler := localoci.New(localoci.Config{WorkRequestPolls: 1})
	cfHandler := localcf.New(localcf.Config{ZoneID: "zone-local", AccountID: "account-local"})
	h := &controlProviderHarness{
		t: t, ctx: context.Background(), client: &http.Client{Timeout: 3 * time.Second},
		oci: httptest.NewServer(ociHandler), cf: httptest.NewServer(cfHandler),
		bindings: make(map[string]ControlRegionBinding),
	}
	t.Cleanup(h.oci.Close)
	t.Cleanup(h.cf.Close)
	regions := []struct {
		code, oci string
		members   int
	}{
		{"gru", "sa-saopaulo-1", 2},
		{"sfo", "us-sanjose-1", 2},
		{"fra", "eu-frankfurt-1", 2},
		{"lhr", "uk-london-1", 2},
	}
	bindings := make([]ControlRegionBinding, 0, len(regions))
	urls := make(map[string]string, len(regions))
	for _, declared := range regions {
		binding := ControlRegionBinding{Code: declared.code, OCIRegion: declared.oci,
			CompartmentID: "ocid1.compartment.oc1.local.control"}
		for index := 1; index <= declared.members; index++ {
			binding.MemberIDs = append(binding.MemberIDs, h.createMember(declared.code, index))
		}
		h.bindings[declared.code] = binding
		bindings = append(bindings, binding)
		urls[declared.code] = h.oci.URL
	}
	var err error
	h.provider, err = NewLocalControlPlaneProvider(LocalControlPlaneProviderConfig{
		Runtime: &unitControlRuntime{bindings: bindings},
		Regions: bindings, OCIBaseURLs: urls, CloudflareBaseURL: h.cf.URL,
		CloudflareZoneID: "zone-local", CloudflareAccountID: "account-local", HTTPClient: h.client,
	})
	if err != nil {
		t.Fatalf("create local control provider: %v", err)
	}
	return h
}

func (h *controlProviderHarness) createMember(region string, index int) string {
	h.t.Helper()
	payload, err := json.Marshal(map[string]any{
		"compartmentId":      "ocid1.compartment.oc1.local.control",
		"displayName":        fmt.Sprintf("terrascale-%s-%d", region, index),
		"shape":              "VM.Standard.A1.Flex",
		"availabilityDomain": "AD-1",
		"freeformTags": map[string]string{
			provider.OCIManagedTag:      ocireconcile.ManagedMemberTagValue,
			provider.OCIScopeTag:        region,
			ocireconcile.MemberIndexTag: strconv.Itoa(index),
		},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(h.ctx, http.MethodPost, h.oci.URL+"/20160918/instances", bytes.NewReader(payload))
	if err != nil {
		h.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("opc-retry-token", fmt.Sprintf("member-%s-%d", region, index))
	response, err := h.client.Do(request)
	if err != nil {
		h.t.Fatalf("create %s member %d: %v", region, index, err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusAccepted {
		h.t.Fatalf("create %s member %d: status=%d body=%s err=%v", region, index, response.StatusCode, body, err)
	}
	var instance struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(body, &instance) != nil || instance.ID == "" {
		h.t.Fatalf("create %s member %d returned invalid body %s", region, index, body)
	}
	workID := response.Header.Get("opc-work-request-id")
	workResponse := h.do(http.MethodGet, h.oci.URL+"/20160918/workRequests/"+workID, nil, nil)
	if workResponse.StatusCode != http.StatusOK {
		workResponse.Body.Close()
		h.t.Fatalf("activate %s member %d: %s", region, index, workResponse.Status)
	}
	workResponse.Body.Close()
	return instance.ID
}

func (h *controlProviderHarness) do(method, target string, body []byte, headers map[string]string) *http.Response {
	h.t.Helper()
	request, err := http.NewRequestWithContext(h.ctx, method, target, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := h.client.Do(request)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, target, err)
	}
	return response
}

func controlTestRequest(kind ControlActionKind, region string, expected, target uint64, state ControlPlaneState) ControlActionRequest {
	label := string(kind) + "/" + region + "/" + strconv.FormatUint(expected, 10) + "/" + strconv.FormatUint(target, 10)
	plan := sha256.Sum256([]byte("plan/" + label))
	key := sha256.Sum256([]byte("action/" + label))
	return ControlActionRequest{
		Action: ControlAction{ID: string(kind) + "-test", Kind: kind, Region: region, ExpectedEpoch: expected,
			TargetEpoch: target, IdempotencyKey: "control-" + hex.EncodeToString(key[:])[:48]},
		State: state, PlanFingerprint: hex.EncodeToString(plan[:]),
	}
}

func (h *controlProviderHarness) bootstrapAndPromote() (ControlPlaneState, ControlActionRequest) {
	h.t.Helper()
	empty := ControlPlaneState{}
	start := controlTestRequest(ControlActionStartTemporaryR1, "gru", 0, 1, empty)
	if receipt, err := h.provider.StartTemporaryR1(h.ctx, start); err != nil || receipt.ID != start.Action.IdempotencyKey {
		h.t.Fatalf("start temporary R1: receipt=%+v err=%v", receipt, err)
	}
	fence := controlTestRequest(ControlActionFenceR1, "gru", 0, 1, empty)
	if _, err := h.provider.FenceTemporaryR1(h.ctx, fence); err != nil {
		h.t.Fatalf("fence temporary R1: %v", err)
	}
	observation, err := h.provider.ObserveControl(h.ctx)
	if err != nil {
		h.t.Fatalf("observe R1: %v", err)
	}
	if observation.State.Topology != ControlTopologyTemporaryR1 || !observation.BootstrapAuthorized || !observation.QuorumAvailable {
		h.t.Fatalf("R1 observation = %+v", observation)
	}
	state := observation.State
	for _, region := range []string{"sfo", "fra"} {
		startCandidate := controlTestRequest(ControlActionStartCandidate, region, 1, 1, state)
		if _, err := h.provider.StartCandidate(h.ctx, startCandidate); err != nil {
			h.t.Fatalf("start %s candidate: %v", region, err)
		}
		syncCandidate := controlTestRequest(ControlActionSyncCandidate, region, 1, 1, state)
		if _, err := h.provider.SyncCandidate(h.ctx, syncCandidate); err != nil {
			h.t.Fatalf("sync %s candidate: %v", region, err)
		}
		verifyCandidate := controlTestRequest(ControlActionVerifyCandidate, region, 1, 1, state)
		evidence, err := h.provider.VerifyCandidate(h.ctx, verifyCandidate)
		if err != nil || !evidence.Ready() || evidence.Region != region {
			h.t.Fatalf("verify %s candidate: evidence=%+v err=%v", region, evidence, err)
		}
		observation, err = h.provider.ObserveControl(h.ctx)
		if err != nil {
			h.t.Fatalf("observe %s candidate: %v", region, err)
		}
		state = observation.State
	}
	promote := controlTestRequest(ControlActionPromoteR3, "", 1, 2, state)
	if _, err := h.provider.PromoteGlobalR3(h.ctx, promote); err != nil {
		h.t.Fatalf("promote R3: %v", err)
	}
	verify := controlTestRequest(ControlActionVerifyQuorum, "", 1, 2, state)
	if err := h.provider.VerifyGlobalR3(h.ctx, verify); err != nil {
		h.t.Fatalf("verify R3: %v", err)
	}
	revoke := controlTestRequest(ControlActionRevokeBootstrap, "gru", 1, 2, state)
	if _, err := h.provider.RevokeBootstrapAuthority(h.ctx, revoke); err != nil {
		h.t.Fatalf("revoke bootstrap authority: %v", err)
	}
	observation, err = h.provider.ObserveControl(h.ctx)
	if err != nil {
		h.t.Fatalf("observe R3: %v", err)
	}
	return observation.State, promote
}

func TestLocalControlPlaneProviderDrivesProviderContracts(t *testing.T) {
	h := newControlProviderHarness(t)
	state, _ := h.bootstrapAndPromote()
	observation, err := h.provider.ObserveControl(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := observation.Validate(); err != nil {
		t.Fatalf("validate R3 observation: %v", err)
	}
	if state.Topology != ControlTopologyGlobalR3 || state.Epoch != 2 || state.BootstrapAuthorized ||
		len(observation.Replicas) != 3 || len(observation.Candidates) != 2 || !observation.QuorumAvailable ||
		observation.PromotionSequence == 0 || !observation.EdgeHealthConsistent {
		t.Fatalf("R3 observation = %+v", observation)
	}
	for _, candidate := range observation.Candidates {
		if candidate.SyncSequence >= observation.PromotionSequence || candidate.VerifySequence >= observation.PromotionSequence {
			t.Fatalf("candidate was not verified before promotion: candidate=%+v promotion=%d", candidate, observation.PromotionSequence)
		}
	}

	remote := controlTestRequest(ControlActionRemoteManage, "lhr", 2, 2, state)
	if _, err := h.provider.RemoteManageRegion(h.ctx, remote); err != nil {
		t.Fatalf("remote-manage lhr: %v", err)
	}
	observation, err = h.provider.ObserveControl(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.RemoteRegions) != 1 || observation.RemoteRegions[0] != "lhr" || !observation.EdgeHealth["lhr"] || !observation.EdgeHealthConsistent {
		t.Fatalf("fourth-Region observation = %+v", observation)
	}

	fra := h.bindings["fra"].MemberIDs[0]
	read := h.do(http.MethodGet, h.oci.URL+"/20160918/instances/"+fra, nil, nil)
	body, _ := io.ReadAll(read.Body)
	read.Body.Close()
	var instance struct {
		ETag string `json:"etag"`
	}
	if json.Unmarshal(body, &instance) != nil || instance.ETag == "" {
		t.Fatalf("read FRA replica before loss: %s", body)
	}
	deleted := h.do(http.MethodDelete, h.oci.URL+"/20160918/instances/"+fra, nil, map[string]string{"If-Match": instance.ETag})
	deleted.Body.Close()
	if deleted.StatusCode != http.StatusNoContent {
		t.Fatalf("delete FRA replica: %s", deleted.Status)
	}
	observation, err = h.provider.ObserveControl(h.ctx)
	if err != nil {
		t.Fatalf("observe one-replica loss: %v", err)
	}
	status, err := h.provider.ReplicaStatus(h.ctx, "fra")
	if err != nil {
		t.Fatalf("FRA replica status: %v", err)
	}
	if status.Active || status.LifecycleState != "TERMINATED" || !observation.QuorumAvailable || observation.EdgeHealthConsistent {
		t.Fatalf("degraded observation=%+v FRA=%+v", observation, status)
	}
}

func TestLocalControlPlaneProviderIsIdempotentAndRaceSafe(t *testing.T) {
	h := newControlProviderHarness(t)
	state, _ := h.bootstrapAndPromote()
	request := controlTestRequest(ControlActionRemoteManage, "lhr", 2, 2, state)

	const workers = 20
	start := make(chan struct{})
	errorsSeen := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			if index%2 == 0 {
				receipt, err := h.provider.RemoteManageRegion(h.ctx, request)
				if err == nil && receipt.ID != request.Action.IdempotencyKey {
					err = fmt.Errorf("receipt %q", receipt.ID)
				}
				errorsSeen <- err
				return
			}
			observation, err := h.provider.ObserveControl(h.ctx)
			if err == nil {
				err = observation.Validate()
			}
			errorsSeen <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent provider call: %v", err)
		}
	}
	observation, err := h.provider.ObserveControl(h.ctx)
	if err != nil || len(observation.RemoteRegions) != 1 || observation.RemoteRegions[0] != "lhr" {
		t.Fatalf("final observation=%+v err=%v", observation, err)
	}
}

func TestControlPlaneProviderSeparatesProductionAndLocalAuthorities(t *testing.T) {
	cf := productioncf.NewClient("token", "zone", "account")
	cf.BaseURL = "http://127.0.0.1:8080"
	if _, err := NewProductionControlPlaneProvider(ProductionControlPlaneProviderConfig{Cloudflare: cf}); !errors.Is(err, ErrControlProviderInvalid) {
		t.Fatalf("production constructor accepted local Cloudflare URL: %v", err)
	}
	client := &http.Client{Timeout: time.Second}
	binding := ControlRegionBinding{Code: "gru", OCIRegion: "sa-saopaulo-1", CompartmentID: "ocid1.compartment.oc1.local.control",
		MemberIDs: []string{"ocid1.instance.oc1.local.1"}}
	for _, rawURL := range []string{"https://api.cloudflare.com:443", "http://127.0.0.1", "http://127.0.0.1:8080/path", "http://user@127.0.0.1:8080"} {
		_, err := NewLocalControlPlaneProvider(LocalControlPlaneProviderConfig{Runtime: &unitControlRuntime{}, Regions: []ControlRegionBinding{binding},
			OCIBaseURLs: map[string]string{"gru": "http://127.0.0.1:8080"}, CloudflareBaseURL: rawURL,
			CloudflareZoneID: "zone", CloudflareAccountID: "account", HTTPClient: client})
		if !errors.Is(err, ErrControlProviderInvalid) {
			t.Errorf("local constructor accepted %q: %v", rawURL, err)
		}
	}
}

// unitControlRuntime is deliberately test-owned. Provider HTTP tests exercise
// OCI intent recording only; they are not evidence of a live control runtime.
type unitControlRuntime struct {
	bindings []ControlRegionBinding
	failure  error
	calls    int
}

func (r *unitControlRuntime) Execute(_ context.Context, request ControlActionRequest) (ControlRuntimeEvidence, error) {
	r.calls++
	if r.failure != nil {
		return ControlRuntimeEvidence{}, r.failure
	}
	digest := sha256.Sum256([]byte("unit-runtime:" + request.Action.IdempotencyKey))
	value := hex.EncodeToString(digest[:])
	return ControlRuntimeEvidence{IdentityDigest: value, StorageDigest: value, HealthDigest: value, ObservedAt: time.Now().UTC()}, nil
}
func (r *unitControlRuntime) Observe(context.Context) (map[string]bool, error) {
	result := map[string]bool{}
	for _, binding := range r.bindings {
		for _, member := range binding.MemberIDs {
			result[member] = true
		}
	}
	return result, nil
}

func TestControlProviderCannotRecordRuntimeFailure(t *testing.T) {
	h := newControlProviderHarness(t)
	runtime := h.provider.runtime.(*unitControlRuntime)
	runtime.failure = ErrControlRuntimeUnavailable
	request := controlTestRequest(ControlActionStartTemporaryR1, "gru", 0, 1, ControlPlaneState{})
	if _, err := h.provider.StartTemporaryR1(h.ctx, request); !errors.Is(err, ErrControlRuntimeUnavailable) {
		t.Fatalf("runtime error lost: %v", err)
	}
	observation, err := h.provider.ObserveControl(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if observation.State.Epoch != 0 {
		t.Fatalf("runtime failure mutated topology: %+v", observation)
	}
}

func TestControlProviderRejectsEpochRegressionBeforeRuntimeExecution(t *testing.T) {
	h := newControlProviderHarness(t)
	h.bootstrapAndPromote()
	runtime := h.provider.runtime.(*unitControlRuntime)
	calls := runtime.calls
	request := controlTestRequest(ControlActionStartTemporaryR1, "gru", 0, 1, ControlPlaneState{})
	if _, err := h.provider.StartTemporaryR1(h.ctx, request); !errors.Is(err, ErrControlEpochRegression) {
		t.Fatalf("regression not refused: %v", err)
	}
	if runtime.calls != calls {
		t.Fatal("runtime handoff ran before epoch regression validation")
	}
}

func TestLocalControlProviderRequiresExplicitRuntime(t *testing.T) {
	h := newControlProviderHarness(t)
	binding := h.bindings["gru"]
	_, err := NewLocalControlPlaneProvider(LocalControlPlaneProviderConfig{Regions: []ControlRegionBinding{binding}, OCIBaseURLs: map[string]string{"gru": h.oci.URL}, CloudflareBaseURL: h.cf.URL, CloudflareZoneID: "zone-local", CloudflareAccountID: "account-local", HTTPClient: h.client})
	if !errors.Is(err, ErrControlProviderInvalid) {
		t.Fatalf("constructor silently supplied runtime: %v", err)
	}
}
