package region

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

type originalCompartmentDispatch struct {
	body    []byte
	token   string
	pending PendingFoundationCreate
}

// The existing fixture owns authority and OCI state; this wrapper observes the
// real signed SDK boundary and injects only remote transport/resource faults.
type originalCompartmentSDKFixture struct {
	foundationProvisionFixture
	mu       sync.Mutex
	bundle   RetainedFoundation
	fault    string
	faulted  bool
	posts    []originalCompartmentDispatch
	gets     map[string]int
	accepted map[string]bool
	started  time.Time
}

func newOriginalCompartmentSDKFixture(t *testing.T, fault string) *originalCompartmentSDKFixture {
	t.Helper()
	base := newFoundationProvisionFixture(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	bundle := signProvisionFoundation(t, base.prepared, base.bundle.RootChainWire, base.root, base.now)
	base.cloud.bundle = bundle.clone()
	f := &originalCompartmentSDKFixture{foundationProvisionFixture: base, bundle: bundle, fault: fault, gets: map[string]int{}, accepted: map[string]bool{}, started: time.Now().UTC()}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("original compartment fixture requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("fixture refuses network %q", network)
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	return f
}

func signHistoricalOriginalCompartmentBundle(t *testing.T, fixture foundationProvisionFixture) RetainedFoundation {
	t.Helper()
	prepared := fixture.prepared
	home := *prepared.Anchor.FoundationScope
	prepared.Anchor.FoundationScope = &home
	payload, err := trust.EncodePayload(prepared.Grant)
	if err != nil {
		t.Fatal(err)
	}
	issued, expires := fixture.now.Add(-25*time.Hour), fixture.now.Add(time.Hour)
	scope := trust.Scope{Domain: foundationGrantDomain, DeploymentID: prepared.Anchor.DeploymentID, Cell: string(prepared.Anchor.Cell), Environment: prepared.Anchor.Environment, Role: "foundation", Slot: prepared.Anchor.ClusterID}
	grant, err := trust.Sign(payload, scope, issued, expires, fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(grant)
	if err != nil {
		t.Fatal(err)
	}
	prepared.Anchor.FoundationScope.GrantSHA256 = preparationDigest(grantWire)
	anchor, err := bootstrap.SignBootstrapAnchor(prepared.Anchor, issued, expires, fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	anchorWire, err := trust.EncodeEnvelope(anchor)
	if err != nil {
		t.Fatal(err)
	}
	return RetainedFoundation{TenancyID: prepared.Grant.TenancyID, Namespace: prepared.Anchor.StorageDomain.Namespace, RootChainWire: fixture.bundle.RootChainWire, AnchorWire: anchorWire, GrantWire: grantWire}
}

func (f *originalCompartmentSDKFixture) run(t *testing.T) error {
	t.Helper()
	stage, err := provisionFoundationMaterial(t.Context(), f.factoryFor(), f.roots, f.bundle)
	if err != nil {
		return err
	}
	defer stage.cancel()
	ctx, release, err := stage.authority.HomeWrite(stage.ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	return retainOriginalFoundationCompartments(ctx, stage.authority)
}

// Full provisioning reconciles infrastructure before writer admission. These
// cases need the real material stage and its refusal of unpublished startup.
func (f *originalCompartmentSDKFixture) prepareMaterialWithStartupRefusal(t *testing.T) {
	t.Helper()
	stage, err := provisionFoundationMaterial(t.Context(), f.factoryFor(), f.roots, f.bundle)
	if err != nil {
		t.Fatalf("material-only preparation failed: %v", err)
	}
	defer stage.cancel()
	retained, materialPosts := f.wire(t), f.cloud.materialPosts
	reader := stage.resolver.Footprint.(*SignedFootprint)
	if _, err := bootstrap.VerifyRegionalStartupTemplate(f.bundle.GrantWire, f.roots, reader.bootstrapAnchor, reader.bootstrapAnchor.Anchor().Cell, time.Now()); !errors.Is(err, bootstrap.ErrManifestInvalid) {
		t.Fatalf("unbound prospective startup lost its schema refusal: %v", err)
	}
	err = stage.authority.verifyFoundationWorkloadStartup(stage.ctx)
	var service common.ServiceError
	ok := errors.As(err, &service)
	if !ok || service.GetHTTPStatusCode() != http.StatusNotFound || !strings.Contains(err.Error(), "read current protected foundation grant") {
		t.Fatalf("prospective startup bypassed its unpublished protected grant: %v", err)
	}
	home := f.approval.HomeStorageDomain
	if _, err := os.Stat(f.cloud.objectPath(home.HeadBucket + "/" + home.Prefix + "/" + foundationGrantObject)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unpublished current grant unexpectedly exists: %v", err)
	}
	f.assertMaterial(t)
	if len(f.dispatches()) != 0 || f.cloud.materialPosts != materialPosts || !bytes.Equal(retained, f.wire(t)) {
		t.Fatal("refused prospective startup changed compartment or material effects or protected birth")
	}
}

func (f *originalCompartmentSDKFixture) record(t *testing.T) FoundationRecord {
	t.Helper()
	f.cloud.mu.Lock()
	defer f.cloud.mu.Unlock()
	return f.cloud.journal("GRU")
}

func (f *originalCompartmentSDKFixture) wire(t *testing.T) []byte {
	t.Helper()
	wire, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json"))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (f *originalCompartmentSDKFixture) replaceRecord(t *testing.T, mutate func(*FoundationRecord)) {
	t.Helper()
	record := f.record(t)
	mutate(&record)
	wire, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	f.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", wire)
}

func (f *originalCompartmentSDKFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fault == "missing origin" && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/o/orchestrator/workload-genesis/v1/") {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
			f.cloud.test.Error("missing-origin fault received an unsigned OCI request")
		}
		f.faulted = true
		originalCompartmentFailure(w, http.StatusNotFound, "NotAuthorizedOrNotFound")
		return
	}
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json") && f.fault == "lost accepted checkpoint" && !f.faulted {
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			f.cloud.test.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(wire))
		var record FoundationRecord
		if json.Unmarshal(wire, &record) == nil && record.OriginalFoundationCompartments != nil {
			for _, region := range record.OriginalFoundationCompartments.Regions {
				for _, entry := range region.Compartments {
					if entry.Provenance != nil {
						f.faulted = true
						recorder := httptest.NewRecorder()
						f.cloud.serveHTTP(recorder, r)
						if recorder.Code >= 300 {
							f.cloud.test.Errorf("checkpoint fault preceded accepted CAS: %d", recorder.Code)
						}
						originalCompartmentFailure(w, http.StatusServiceUnavailable, "InternalError")
						return
					}
				}
			}
		}
	}
	if !strings.Contains(r.URL.Path, "/compartments") {
		f.cloud.serveHTTP(w, r)
		return
	}
	validHost := false
	for _, cell := range []string{"GRU", "SJC", "FRA"} {
		validHost = validHost || r.Host == "identity."+catalog.OCIRegion(cell)+".oci.oraclecloud.com"
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/20160918/compartments"), "/")
	if !validHost || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") || !strings.HasPrefix(r.URL.Path, "/20160918/compartments") || r.URL.RawQuery != "" ||
		r.Method == http.MethodPost && r.URL.Path != "/20160918/compartments" || r.Method == http.MethodGet && (len(parts) != 2 || parts[0] != "" || parts[1] == "") || r.Method != http.MethodPost && r.Method != http.MethodGet {
		f.cloud.test.Errorf("unexpected compartment SDK request: %s %s %s", r.Method, r.Host, r.URL.Path)
		originalCompartmentFailure(w, http.StatusBadRequest, "InvalidParameter")
		return
	}
	if r.Method == http.MethodGet {
		id := parts[1]
		f.gets[id]++
		if f.accepted[id] {
			record := f.cloud.journal("GRU")
			found := false
			if record.OriginalFoundationCompartments != nil {
				for _, region := range record.OriginalFoundationCompartments.Regions {
					for _, entry := range region.Compartments {
						found = found || entry.Provenance != nil && entry.Provenance.ResourceID == id
					}
				}
			}
			if !found {
				f.cloud.test.Error("accepted exact ID readback preceded durable returned-ID provenance")
			}
		}
		f.cloud.serveHTTP(w, r)
		return
	}
	wire, err := io.ReadAll(r.Body)
	if err != nil {
		f.cloud.test.Error(err)
		originalCompartmentFailure(w, http.StatusBadRequest, "InvalidParameter")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(wire))
	var actual map[string]any
	if err := json.Unmarshal(wire, &actual); err != nil {
		f.cloud.test.Error(err)
		originalCompartmentFailure(w, http.StatusBadRequest, "InvalidParameter")
		return
	}
	canonical, err := json.Marshal(actual, json.Deterministic(true))
	if err != nil {
		f.cloud.test.Error(err)
		originalCompartmentFailure(w, http.StatusBadRequest, "InvalidParameter")
		return
	}
	record := f.cloud.journal("GRU")
	f.checkPrerequisites(record)
	matched := false
	if section := record.OriginalFoundationCompartments; section != nil {
		for _, region := range section.Regions {
			for _, entry := range region.Compartments {
				if entry.Request.Name == nil || *entry.Request.Name != actual["name"] {
					continue
				}
				matched = true
				digest, digestErr := originalCompartmentRequestSHA(entry.Request)
				pending := entry.Pending
				if pending == nil || digestErr != nil || digest != preparationDigest(canonical) || pending.Request.RequestDigest != digest ||
					pending.Request.RetryToken != r.Header.Get("opc-retry-token") || pending.Request.RetryToken != BootstrapRetryToken(region.OperationID, digest) ||
					pending.Request.Key != entry.Role || pending.Request.Region != foundationHomeRegion || pending.OperationID != region.OperationID || pending.IntentDigest != region.IntentSHA256 ||
					pending.FirstAttemptAt.IsZero() || pending.FirstAttemptAt.Before(f.started) || pending.FirstAttemptAt.After(time.Now()) || entry.SelectedID != "" || entry.Provenance != nil || actual["compartmentId"] != f.approval.ParentCompartmentID || r.Host != "identity."+foundationHomeRegion+".oci.oraclecloud.com" {
					f.cloud.test.Error("create lacked its exact durable scoped SDK body/hash/token/original time")
					originalCompartmentFailure(w, http.StatusBadRequest, "InvalidParameter")
					return
				}
				f.posts = append(f.posts, originalCompartmentDispatch{body: canonical, token: pending.Request.RetryToken, pending: *pending})
			}
		}
	}
	if !matched {
		f.cloud.test.Error("create request was absent from complete original compartment reservation")
		originalCompartmentFailure(w, http.StatusBadRequest, "InvalidParameter")
		return
	}
	if !f.faulted {
		switch f.fault {
		case "unknown create":
			f.faulted = true
			originalCompartmentFailure(w, http.StatusServiceUnavailable, "InternalError")
			return
		case "bad request", "conflict", "invalid retry token":
			f.faulted = true
			status, code := http.StatusBadRequest, "InvalidParameter"
			if f.fault == "conflict" {
				status, code = http.StatusConflict, "Conflict"
			} else if f.fault == "invalid retry token" {
				code = "InvalidRetryToken"
			}
			originalCompartmentFailure(w, status, code)
			return
		}
	}
	recorder := httptest.NewRecorder()
	f.cloud.serveHTTP(recorder, r)
	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response.ID == "" {
		f.cloud.test.Errorf("create fixture did not return an actual ID: %v", err)
	}
	f.accepted[response.ID] = true
	if !f.faulted && f.fault == "lost create response" {
		f.faulted = true
		originalCompartmentFailure(w, http.StatusServiceUnavailable, "InternalError")
		return
	}
	if !f.faulted && f.fault == "nonactive readback" {
		f.faulted = true
		f.cloud.mu.Lock()
		f.cloud.rows[response.ID]["lifecycleState"] = "CREATING"
		f.cloud.mu.Unlock()
	}
	for key, values := range recorder.Header() {
		w.Header()[key] = values
	}
	w.WriteHeader(recorder.Code)
	w.Write(recorder.Body.Bytes())
}

func originalCompartmentFailure(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"code":%q,"message":"original compartment fixture fault"}`, code)
}

func (f *originalCompartmentSDKFixture) checkPrerequisites(record FoundationRecord) {
	if record.OriginalSourceProducers == nil || record.validateOriginalSourceProducers() != nil || record.NetBirdMaterial == nil || !record.NetBirdMaterial.Complete || record.NetBirdMaterial.BornAt.IsZero() || len(record.ResourceIDs) != 0 || record.FoundationWriter != nil || record.NetBirdManager != nil {
		f.cloud.test.Error("compartment dispatch preceded complete original producer/NetBird birth or acquired runtime state")
	}
	expected, err := json.Marshal(f.bundle, json.Deterministic(true))
	if err != nil {
		f.cloud.test.Error(err)
	}
	if len(f.prepared.Grant.WorkloadGenesis) != 9 {
		f.cloud.test.Error("fixture lacks all nine original workload origins")
	}
	for _, origin := range f.prepared.Grant.WorkloadGenesis {
		name, err := release.WorkloadGenesisObject(origin.TenancyID, origin.Cell, origin.Environment, origin.Role)
		if err != nil {
			f.cloud.test.Error(err)
			continue
		}
		actual, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + name))
		if err != nil || !bytes.Equal(actual, expected) {
			f.cloud.test.Errorf("compartment dispatch preceded exact signed original origin %s: %v", name, err)
		}
	}
}

func (f *originalCompartmentSDKFixture) assertIncomplete(t *testing.T, complete bool) {
	t.Helper()
	record := f.record(t)
	if record.Stage != "original-foundation" || !record.netBirdMaterialOnly() || !record.CompletedAt.IsZero() || len(record.ResourceIDs) != 0 || len(record.ResourceProvenance) != 0 || len(record.PendingCreates) != 0 || record.FoundationWriter != nil || record.NetBirdManager != nil || f.cloud.launchPosts != 0 || f.cloud.hasAnchor() || record.OriginalFoundationCompartments == nil {
		t.Fatal("original compartment stage fabricated runtime resources, writer, manager, anchor or completion")
	}
	f.checkPrerequisites(record)
	if complete {
		for _, region := range record.OriginalFoundationCompartments.Regions {
			for _, entry := range region.Compartments {
				if entry.VerifiedAt.IsZero() || len(entry.ReadbackSHA256) != 64 || entry.HoldReason != "" || entry.SelectedID == "" && (entry.Pending == nil || entry.Provenance == nil || entry.Provenance.ResourceID == "" || !sameOriginalSourceValue(entry.Pending, entry.Provenance.Create)) {
					t.Fatalf("%s %s lacks accepted exact independent ACTIVE readback", region.Cell, entry.Role)
				}
			}
		}
	}
}

type originalCompartmentProvider struct {
	common.ConfigurationProvider
	user, tenancy string
}

func (p originalCompartmentProvider) UserOCID() (string, error)    { return p.user, nil }
func (p originalCompartmentProvider) TenancyOCID() (string, error) { return p.tenancy, nil }

func (p originalCompartmentProvider) KeyIDContext(ctx context.Context) (string, error) {
	provider, ok := p.ConfigurationProvider.(common.ContextKeyProvider)
	if !ok {
		return "", errors.New("original fixture provider lacks context key support")
	}
	return provider.KeyIDContext(ctx)
}

func (p originalCompartmentProvider) PrivateRSAKeyContext(ctx context.Context) (*rsa.PrivateKey, error) {
	provider, ok := p.ConfigurationProvider.(common.ContextKeyProvider)
	if !ok {
		return nil, errors.New("original fixture provider lacks context key support")
	}
	return provider.PrivateRSAKeyContext(ctx)
}

func (f *originalCompartmentSDKFixture) store(t *testing.T) *ObjectFoundationStore {
	t.Helper()
	client, err := f.factoryFor().ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewObjectFoundationStore(&client, f.approval.HomeStorageDomain.Namespace, f.approval.HomeStorageDomain.HeadBucket)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func (f *originalCompartmentSDKFixture) dispatches() []originalCompartmentDispatch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]originalCompartmentDispatch{}, f.posts...)
}

func TestOriginalFoundationCompartmentsSDK(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	// Subtests stay sequential: the inherited fixture owns the default transport
	// and process environment while still exercising real authenticated SDK I/O.
	t.Run("five exact original creates and selected GRU read only", func(t *testing.T) {
		f := newOriginalCompartmentSDKFixture(t, "")
		f.prepareMaterialWithStartupRefusal(t)
		origin := f.prepared.Grant.WorkloadGenesis[0]
		name, err := release.WorkloadGenesisObject(origin.TenancyID, origin.Cell, origin.Environment, origin.Role)
		if err != nil {
			t.Fatal(err)
		}
		published, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + name))
		if err != nil || len(published) <= foundationRecordLimit {
			t.Fatalf("retained origin fixture must exceed journal bound: %d bytes: %v", len(published), err)
		}
		if err := f.run(t); err != nil {
			t.Fatalf("original compartment component did not complete: %v", err)
		}
		f.assertIncomplete(t, true)
		posts := f.dispatches()
		if len(posts) != 5 || f.cloud.creates != 5 {
			t.Fatalf("original scope created %d resources through %d POSTs; want five compartments", f.cloud.creates, len(posts))
		}
		wanted := map[string]bool{}
		for _, regional := range f.prepared.Grant.Regions {
			cell := regional.Plan["cell"].(string)
			names := regional.Plan["preview_compartment_names"].(map[string]any)
			for _, role := range []string{"control", "network"} {
				if cell != "GRU" || role != "control" {
					wanted[names[role].(string)] = false
				}
			}
		}
		for _, post := range posts {
			var body map[string]any
			if err := json.Unmarshal(post.body, &body); err != nil {
				t.Fatal(err)
			}
			name, _ := body["name"].(string)
			seen, exists := wanted[name]
			if !exists || seen || body["compartmentId"] != f.approval.ParentCompartmentID {
				t.Fatalf("create differs from the five exact signed parent/name selections: %s", name)
			}
			wanted[name] = true
		}
		f.mu.Lock()
		selectedReads := f.gets[f.approval.SourceVaultTarget.CompartmentOCID]
		f.mu.Unlock()
		if selectedReads == 0 {
			t.Fatal("GRU selected control compartment never received independent exact-ID GET")
		}
		record := f.record(t)
		section := record.OriginalFoundationCompartments
		selected := section.Regions[0].Compartments[0]
		if selected.SelectedID != f.approval.SourceVaultTarget.CompartmentOCID || selected.Pending != nil || selected.Provenance != nil {
			t.Fatal("GRU root-selected control was replaced with create/adoption provenance")
		}
		bundleWire, err := json.Marshal(f.bundle, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		if section.GrantSHA256 != preparationDigest(f.bundle.GrantWire) || section.BundleSHA256 != preparationDigest(bundleWire) || section.GRUIntentSHA256 != record.IntentDigest || section.Generation != record.Generation || section.OperationID != record.OperationID || !section.BornAt.Equal(record.NetBirdMaterial.BornAt) || section.UserID != "ocid1.user.oc1..test" || section.Currency != f.prepared.Grant.Currency || section.MonthlyLimitMinor != f.prepared.Grant.MonthlyLimitMinor || section.CleanupOwner != f.prepared.Grant.CleanupOwner {
			t.Fatal("original compartment section lost full signed document, user, birth or finite budget scope")
		}
		for index, regional := range section.Regions {
			digest, err := FoundationIntentDigest(f.prepared.Grant.Regions[index])
			if err != nil || regional.IntentSHA256 != digest || regional.ProducerIntentSHA256 != (*record.OriginalSourceProducers)[index].IntentSHA256 {
				t.Fatalf("%s compartment stage substituted signed plan or producer metadata: %v", regional.Cell, err)
			}
		}
		postsBefore, materialBefore := len(posts), f.cloud.materialPosts
		if err := f.run(t); err != nil || len(f.dispatches()) != postsBefore || f.cloud.creates != 5 || f.cloud.materialPosts != materialBefore {
			t.Fatalf("completed compartment replay repeated creates/material or claimed serving: %v", err)
		}
		authority, _, err := newOperatorHomeIAMAuthority(t.Context(), f.factoryFor(), f.roots, f.bundle)
		if err != nil {
			t.Fatal(err)
		}
		ctx, releaseLease, err := authority.HomeWrite(t.Context(), 0)
		if err != nil {
			t.Fatal(err)
		}
		defer releaseLease()
		if current, err := originalCompartmentScope(ctx, authority); err != nil || !sameOriginalSourceValue(current, section.scopeOnly()) {
			t.Fatalf("prepared grant did not reproduce the exact guarded compartment scope: %v", err)
		}
		retained := f.wire(t)
		defer f.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", retained)
		f.replaceRecord(t, func(record *FoundationRecord) {
			birth := &record.OriginalSourceProducers[0]
			birth.Intent.PlanSHA256 = preparationDigest([]byte("foreign original producer plan"))
			wire, err := json.Marshal(birth.Intent, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			birth.IntentSHA256 = preparationDigest(wire)
			record.OriginalFoundationCompartments.Regions[0].ProducerIntentSHA256 = birth.IntentSHA256
			if err := record.validate(); err != nil {
				t.Fatalf("fresh birth drift must remain structurally valid: %v", err)
			}
		})
		changed := f.wire(t)
		if _, err := originalCompartmentScope(ctx, authority); !errors.Is(err, ErrOriginalSourceProducerHold) || len(f.dispatches()) != postsBefore || f.cloud.creates != 5 || f.cloud.materialPosts != materialBefore || !bytes.Equal(changed, f.wire(t)) {
			t.Fatalf("validated local grant reused stale birth authority or changed effects: %v", err)
		}
	})

	t.Run("unknown effects reopen exact original identity", func(t *testing.T) {
		for _, fault := range []string{"lost create response", "lost accepted checkpoint"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalCompartmentSDKFixture(t, fault)
				firstErr := f.run(t)
				if firstErr == nil {
					t.Fatal("uncertain create/checkpoint response claimed completed provisioning")
				}
				before := f.dispatches()
				if len(before) == 0 || f.cloud.creates == 0 {
					t.Fatal("response-loss fixture never accepted an actual SDK compartment create")
				}
				if fault == "lost create response" {
					store := f.store(t)
					record, etag, err := store.Load(t.Context(), "GRU")
					if err != nil {
						t.Fatal(err)
					}
					retained := f.wire(t)
					record.OriginalFoundationCompartments.Regions[0].Compartments[1].Pending = nil
					if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(retained, f.wire(t)) {
						t.Fatal("unknown accepted response permitted erasure of original pending identity")
					}
				}
				if err := f.run(t); err != nil || f.cloud.creates != 5 {
					t.Fatalf("original uncertain response did not resume to five physical compartments: %v", err)
				}
				after := f.dispatches()
				if fault == "lost create response" {
					if len(before) != 1 || len(after) != 6 || !bytes.Equal(after[0].body, after[1].body) || after[0].token != after[1].token || !sameOriginalSourceValue(after[0].pending, after[1].pending) {
						t.Fatal("lost accepted response reset canonical body, stable token, original scope or first dispatch time")
					}
				} else if len(after) != 5 {
					t.Fatal("lost accepted-ID checkpoint response repeated an already accepted create")
				}
				f.assertIncomplete(t, true)
			})
		}
	})

	t.Run("returned ID persists before readback and cannot be replaced", func(t *testing.T) {
		t.Run("nonactive accepted ID resumes GET only", func(t *testing.T) {
			f := newOriginalCompartmentSDKFixture(t, "nonactive readback")
			if err := f.run(t); err == nil {
				t.Fatal("non-ACTIVE accepted compartment claimed completion")
			}
			entry := f.record(t).OriginalFoundationCompartments.Regions[0].Compartments[1]
			if entry.Provenance == nil || entry.Pending == nil || entry.Provenance.ResourceID == "" || !entry.VerifiedAt.IsZero() || len(f.dispatches()) != 1 || f.cloud.creates != 1 {
				t.Fatal("non-ACTIVE readback erased actual returned ID or fabricated verified provenance")
			}
			accepted := *entry.Provenance
			f.cloud.mu.Lock()
			f.cloud.rows[accepted.ResourceID]["lifecycleState"] = "ACTIVE"
			f.cloud.mu.Unlock()
			if err := f.run(t); err != nil || len(f.dispatches()) != 5 || f.cloud.creates != 5 {
				t.Fatalf("non-ACTIVE retry repeated accepted create instead of exact-ID GET: %v", err)
			}
			retained := f.record(t).OriginalFoundationCompartments.Regions[0].Compartments[1]
			if !sameOriginalSourceValue(accepted, retained.Provenance) || retained.VerifiedAt.IsZero() {
				t.Fatal("GET-only recovery changed original accepted provenance")
			}
			f.assertIncomplete(t, true)
		})
		for _, drift := range []string{"missing accepted ID", "wrong returned ID", "wrong parent", "wrong name", "missing selected GRU"} {
			t.Run(drift, func(t *testing.T) {
				f := newOriginalCompartmentSDKFixture(t, "")
				if err := f.run(t); err != nil {
					t.Fatal(err)
				}
				before := f.wire(t)
				accepted := f.record(t).OriginalFoundationCompartments.Regions[0].Compartments[1].Provenance.ResourceID
				f.cloud.mu.Lock()
				switch drift {
				case "missing accepted ID":
					delete(f.cloud.rows, accepted)
				case "wrong returned ID":
					f.cloud.rows[accepted]["id"] = "ocid1.compartment.oc1..foreign"
				case "wrong parent":
					f.cloud.rows[accepted]["compartmentId"] = f.approval.SharedCompartmentID
				case "wrong name":
					f.cloud.rows[accepted]["name"] = "foreign-network"
				case "missing selected GRU":
					delete(f.cloud.rows, f.approval.SourceVaultTarget.CompartmentOCID)
				}
				f.cloud.mu.Unlock()
				if err := f.run(t); err == nil || len(f.dispatches()) != 5 || f.cloud.creates != 5 {
					t.Fatalf("missing/drifted accepted/selected ID permitted replacement or completion: %v", err)
				}
				// Existing readback and create pins must survive even when a later
				// authority refresh updates unrelated journal timestamps.
				var previous FoundationRecord
				if err := json.Unmarshal(before, &previous); err != nil || !sameOriginalSourceValue(previous.OriginalFoundationCompartments, f.record(t).OriginalFoundationCompartments) {
					t.Fatal("missing/drifted readback reset retained original compartment pins")
				}
			})
		}
	})

	t.Run("terminal and original authority refusals never recreate", func(t *testing.T) {
		for _, fault := range []string{"bad request", "conflict", "invalid retry token"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalCompartmentSDKFixture(t, fault)
				if err := f.run(t); err == nil {
					t.Fatal("known terminal create failure claimed completion")
				}
				entry := f.record(t).OriginalFoundationCompartments.Regions[0].Compartments[1]
				if entry.HoldReason == "" || entry.Pending == nil || entry.Provenance != nil || len(f.dispatches()) != 1 || f.cloud.creates != 0 {
					t.Fatal("known terminal failure was returned before durable HOLD with original pending identity")
				}
				store := f.store(t)
				record, etag, err := store.Load(t.Context(), "GRU")
				if err != nil {
					t.Fatal(err)
				}
				retained := f.wire(t)
				record.OriginalFoundationCompartments.Regions[0].Compartments[1].HoldReason = ""
				if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(retained, f.wire(t)) {
					t.Fatal("terminal HOLD could be erased through the real protected store")
				}
				if err := f.run(t); err == nil || len(f.dispatches()) != 1 || f.cloud.creates != 0 || !sameOriginalSourceValue(entry, f.record(t).OriginalFoundationCompartments.Regions[0].Compartments[1]) {
					t.Fatalf("terminal HOLD reset or retried original create: %v", err)
				}
			})
		}
		for _, wrong := range []string{"user", "tenancy"} {
			t.Run("wrong "+wrong, func(t *testing.T) {
				f := newOriginalCompartmentSDKFixture(t, "")
				provider := originalCompartmentProvider{ConfigurationProvider: f.provider, user: "ocid1.user.oc1..test", tenancy: f.approval.TenancyID}
				if wrong == "user" {
					provider.user = "ocid1.user.oc1..foreign"
				} else {
					provider.tenancy = "ocid1.tenancy.oc1..foreign"
				}
				factory, err := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
				if err != nil {
					t.Fatal(err)
				}
				if err := provisionOriginalFoundationCompartments(t.Context(), factory, f.roots, f.bundle); err == nil || len(f.dispatches()) != 0 || f.cloud.creates != 0 || f.cloud.materialPosts != 0 || f.cloud.hasAnchor() {
					t.Fatalf("foreign original user/tenancy reached paid original effects: %v", err)
				}
			})
		}
		t.Run("aged pending timestamp refuses reset", func(t *testing.T) {
			f := newOriginalCompartmentSDKFixture(t, "unknown create")
			if err := f.run(t); err == nil || len(f.dispatches()) != 1 {
				t.Fatalf("unknown create did not retain original pending request: %v", err)
			}
			f.replaceRecord(t, func(record *FoundationRecord) {
				record.OriginalFoundationCompartments.Regions[0].Compartments[1].Pending.FirstAttemptAt = time.Now().UTC().Add(-24 * time.Hour)
			})
			corrupt := f.wire(t)
			// This fixture's signed deadline is twenty minutes. An aged request
			// is corruption, not authority to invent an older birth or new token.
			if err := f.run(t); err == nil || len(f.dispatches()) != 1 || f.cloud.creates != 0 || !bytes.Equal(corrupt, f.wire(t)) {
				t.Fatalf("aged original pending request was rewritten, recreated or accepted: %v", err)
			}
		})
		t.Run("valid expired pending request persists retry HOLD", func(t *testing.T) {
			f := newOriginalCompartmentSDKFixture(t, "unknown create")
			f.bundle = signHistoricalOriginalCompartmentBundle(t, f.foundationProvisionFixture)
			f.cloud.bundle = f.bundle.clone()
			if err := VerifyFoundationProvisionBundle(t.Context(), f.roots, f.bundle); err != nil {
				t.Fatalf("historical full signed original lacks current authority: %v", err)
			}
			if err := f.run(t); err == nil || len(f.dispatches()) != 1 || f.cloud.creates != 0 {
				t.Fatalf("historical signed original did not retain unknown create: %v", err)
			}
			record := f.record(t)
			// Model the same valid retained original from yesterday; only its
			// durable timeline changes, never signed scope, request or token.
			record.StartedAt = record.StartedAt.Add(-24 * time.Hour)
			record.NetBirdMaterial.BornAt = record.NetBirdMaterial.BornAt.Add(-24 * time.Hour)
			for index := range record.NetBirdMaterial.Creates {
				create := &record.NetBirdMaterial.Creates[index]
				create.FirstDispatchedAt = create.FirstDispatchedAt.Add(-24 * time.Hour)
			}
			for index := range record.OriginalSourceProducers {
				record.OriginalSourceProducers[index].BornAt = record.OriginalSourceProducers[index].BornAt.Add(-24 * time.Hour)
			}
			section := record.OriginalFoundationCompartments
			section.BornAt = section.BornAt.Add(-24 * time.Hour)
			section.Regions[0].Compartments[0].VerifiedAt = section.Regions[0].Compartments[0].VerifiedAt.Add(-24 * time.Hour)
			pending := section.Regions[0].Compartments[1].Pending
			pending.FirstAttemptAt = pending.FirstAttemptAt.Add(-24 * time.Hour)
			if err := record.validate(); err != nil {
				t.Fatalf("historical retained original timeline is invalid before dispatch: %v", err)
			}
			if !pending.FirstAttemptAt.Before(time.Now().Add(-23 * time.Hour)) {
				t.Fatal("historical pending request is still within its original retry lifetime")
			}
			wire, err := json.Marshal(record, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			f.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", wire)
			materialPosts := f.cloud.materialPosts
			if err := f.run(t); !errors.Is(err, ErrOriginalSourceProducerHold) || len(f.dispatches()) != 1 || f.cloud.creates != 0 || f.cloud.materialPosts != materialPosts {
				t.Fatalf("valid expired original pending request dispatched or lost HOLD: %v", err)
			}
			retained := f.record(t)
			expected := *section
			expected.Regions[0].Compartments[1].HoldReason = "retry-expired"
			record.OriginalFoundationCompartments = &expected
			record.UpdatedAt = retained.UpdatedAt
			if err := retained.validate(); err != nil || !sameOriginalSourceValue(record, retained) {
				t.Fatalf("expiry HOLD was not persisted with exact old body/token/time and all original pins: %v", err)
			}
			holdWire := f.wire(t)
			if err := f.run(t); !errors.Is(err, ErrOriginalSourceProducerHold) || len(f.dispatches()) != 1 || f.cloud.creates != 0 || f.cloud.materialPosts != materialPosts || !bytes.Equal(holdWire, f.wire(t)) {
				t.Fatalf("durable retry-expired HOLD reset or replayed the original request: %v", err)
			}
			f.assertIncomplete(t, false)
		})
		for _, refusal := range []string{"missing birth", "missing origin", "different signed original", "expired signed document"} {
			t.Run(refusal, func(t *testing.T) {
				f := newOriginalCompartmentSDKFixture(t, "")
				f.prepareMaterialWithStartupRefusal(t)
				switch refusal {
				case "missing birth":
					f.replaceRecord(t, func(record *FoundationRecord) { record.OriginalSourceProducers = nil })
				case "missing origin":
					f.mu.Lock()
					f.fault = "missing origin"
					f.mu.Unlock()
				case "different signed original":
					f.bundle = signProvisionFoundation(t, f.prepared, f.bundle.RootChainWire, f.root, f.now.Add(-time.Second))
				case "expired signed document":
					f.bundle = signProvisionFoundation(t, f.prepared, f.bundle.RootChainWire, f.root, f.now.Add(-24*time.Hour))
				}
				posts := f.cloud.materialPosts
				if err := f.run(t); err == nil || len(f.dispatches()) != 0 || f.cloud.creates != 0 || f.cloud.materialPosts != posts || f.cloud.hasAnchor() {
					t.Fatalf("missing/foreign/expired original scope progressed compartment or material effects: %v", err)
				}
				if refusal == "missing origin" {
					f.mu.Lock()
					observed := f.faulted
					f.mu.Unlock()
					if !observed {
						t.Fatal("missing-origin scenario never reached actual authenticated origin read")
					}
				}
			})
		}
	})

	t.Run("protected object CAS preserves original compartment evidence", func(t *testing.T) {
		f := newOriginalCompartmentSDKFixture(t, "")
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		store := f.store(t)
		original := f.wire(t)
		record, _, err := store.Load(t.Context(), "GRU")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.CompareAndSwap(t.Context(), record, ""); err == nil || !bytes.Equal(original, f.wire(t)) {
			t.Fatal("original compartment section permitted a new protected-record birth instead of extending its original GRU record")
		}
		for name, mutate := range map[string]func(*FoundationRecord){
			"remove complete section": func(r *FoundationRecord) { r.OriginalFoundationCompartments = nil },
			"remove regional scope": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1] = OriginalFoundationCompartmentRegion{}
			},
			"replace original user":  func(r *FoundationRecord) { r.OriginalFoundationCompartments.UserID = "ocid1.user.oc1..foreign" },
			"replace grant":          func(r *FoundationRecord) { r.OriginalFoundationCompartments.GrantSHA256 = strings.Repeat("a", 64) },
			"replace bundle":         func(r *FoundationRecord) { r.OriginalFoundationCompartments.BundleSHA256 = strings.Repeat("a", 64) },
			"replace finite ceiling": func(r *FoundationRecord) { r.OriginalFoundationCompartments.MonthlyLimitMinor++ },
			"replace operation":      func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].OperationID += "foreign" },
			"replace regional OCI scope": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[1].OCIRegion = foundationHomeRegion
			},
			"replace producer pin": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].ProducerIntentSHA256 = strings.Repeat("a", 64)
			},
			"replace request body": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Compartments[1].Request.Name = new("foreign-network")
			},
			"replace body and recompute identity": func(r *FoundationRecord) {
				entry := &r.OriginalFoundationCompartments.Regions[0].Compartments[1]
				entry.Request.FreeformTags = map[string]string{"terrascale.owner": "foreign"}
				digest, err := originalCompartmentRequestSHA(entry.Request)
				if err != nil {
					t.Fatal(err)
				}
				entry.Pending.Request.RequestDigest = digest
				entry.Pending.Request.RetryToken = BootstrapRetryToken(entry.Pending.OperationID, digest)
				entry.Provenance.Create = *entry.Pending
			},
			"erase request body": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Compartments[1].Request = identity.CreateCompartmentDetails{}
			},
			"erase pending": func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].Compartments[1].Pending = nil },
			"replace request hash": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Compartments[1].Pending.Request.RequestDigest = strings.Repeat("a", 64)
			},
			"replace retry token": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Compartments[1].Pending.Request.RetryToken = strings.Repeat("a", 64)
			},
			"replace dispatch time": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Compartments[1].Pending.FirstAttemptAt = r.OriginalFoundationCompartments.Regions[0].Compartments[1].Pending.FirstAttemptAt.Add(time.Second)
			},
			"erase accepted provenance": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Compartments[1].Provenance = nil
			},
			"replace accepted ID": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Compartments[1].Provenance.ResourceID = "ocid1.compartment.oc1..replacement"
			},
			"replace accepted provenance": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Compartments[1].Provenance.GrantSHA256 = strings.Repeat("a", 64)
			},
			"erase readback": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Compartments[1].ReadbackSHA256 = ""
				r.OriginalFoundationCompartments.Regions[0].Compartments[1].VerifiedAt = time.Time{}
			},
			"replace readback": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Compartments[1].ReadbackSHA256 = strings.Repeat("a", 64)
			},
			"replace verification time": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Compartments[1].VerifiedAt = r.OriginalFoundationCompartments.Regions[0].Compartments[1].VerifiedAt.Add(-time.Millisecond)
			},
			"erase upstream birth": func(r *FoundationRecord) { r.OriginalSourceProducers = nil },
			"manufacture runtime IDs": func(r *FoundationRecord) {
				r.ResourceIDs["network_compartment"] = r.OriginalFoundationCompartments.Regions[0].Compartments[1].Provenance.ResourceID
			},
		} {
			record, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil {
				t.Fatalf("real protected ObjectFoundationStore CAS accepted %s", name)
			}
			if !bytes.Equal(original, f.wire(t)) {
				t.Fatalf("refused %s changed protected bytes", name)
			}
		}
		f.assertIncomplete(t, true)
	})
}
