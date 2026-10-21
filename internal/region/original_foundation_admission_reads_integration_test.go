package region

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
)

type originalAdmissionReadDispatch struct {
	body    []byte
	token   string
	pending PendingFoundationCreate
}

type originalAdmissionReadsSDKFixture struct {
	*originalSourceIAMSDKFixture
	reads                *originalActorReadsSDKFixture
	admissionMu          sync.Mutex
	fault                string
	faulted              bool
	rows                 map[string]map[string]any
	posts                []originalAdmissionReadDispatch
	gets                 map[string]int
	prior                []byte
	sources              []byte
	projectionWire       []byte
	decodedWire          []byte
	decodedRecord        FoundationRecord
	priorProjection      []byte
	sourceProjection     []byte
	expectedRejectedWire []byte
	journalRefusals      int
}

func originalAdmissionReadPrior(record FoundationRecord, sources bool) ([]byte, error) {
	section := *record.OriginalFoundationCompartments
	section.Publication = nil
	for index := range section.Regions {
		section.Regions[index].MaterialPublicationIAM = nil
		section.Regions[index].AdmissionReads = nil
		if !sources {
			section.Regions[index].SourceIAM = nil
		}
	}
	record.OriginalFoundationCompartments = &section
	record.UpdatedAt = time.Time{}
	return json.Marshal(record, json.Deterministic(true))
}

// projection reuses only a pure serialization; callers compare the expected bytes
// on every request.
func (f *originalAdmissionReadsSDKFixture) projection(record FoundationRecord, wire []byte, sources bool) ([]byte, error) {
	if !bytes.Equal(wire, f.projectionWire) {
		f.projectionWire = bytes.Clone(wire)
		f.priorProjection, f.sourceProjection = nil, nil
	}
	projection := &f.priorProjection
	if sources {
		projection = &f.sourceProjection
	}
	if *projection == nil {
		body, err := originalAdmissionReadPrior(record, sources)
		if err != nil {
			return nil, err
		}
		*projection = body
	}
	return *projection, nil
}

func newOriginalAdmissionReadsSDKFixture(t *testing.T, fault string, legacy bool) *originalAdmissionReadsSDKFixture {
	t.Helper()
	// Preserve the pinned loopback transport instead of the SDK's proxy clone.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	reads := newOriginalActorReadsSDKFixture(t, "", 0)
	// Existing stage fixtures represent signed grants from before material IAM.
	reads.prepared.Grant.OriginalMaterialPublicationIAM = nil
	if legacy {
		reads.prepared.Grant.OriginalActorAdmissionReads = nil
		reads.prepared.Grant.OriginalPublication = nil
	}
	return originalAdmissionReadsSDKFixtureFor(t, reads, fault)
}

func originalAdmissionReadsSDKFixtureFor(t *testing.T, reads *originalActorReadsSDKFixture, fault string) *originalAdmissionReadsSDKFixture {
	t.Helper()
	reads.bundle = signProvisionFoundation(t, reads.prepared, reads.bundle.RootChainWire, reads.root, reads.now)
	reads.cloud.bundle = reads.bundle.clone()
	var err error
	reads.publicBundle, err = json.Marshal(reads.bundle, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := reads.run(t); err != nil {
		t.Fatalf("genuine original actor/public-read stage: %v", err)
	}
	source := &originalSourceIAMSDKFixture{originalActorSDKFixture: reads.originalActorSDKFixture, rows: map[string]map[string]any{}, gets: map[string]int{}}
	source.upstream, err = originalSourceIAMUpstream(reads.record(t))
	if err != nil {
		t.Fatal(err)
	}
	f := &originalAdmissionReadsSDKFixture{originalSourceIAMSDKFixture: source, reads: reads, fault: fault,
		rows: map[string]map[string]any{}, gets: map[string]int{}}
	f.prior, err = originalAdmissionReadPrior(f.record(t), false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("admission read fixture requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("admission fixture refuses plaintext or proxy dialing")
	}
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

func (f *originalAdmissionReadsSDKFixture) run(t *testing.T) error {
	t.Helper()
	if f.prepared.Grant.OriginalActorAdmissionReads != nil {
		return ProvisionOriginalFoundationSourceIAM(t.Context(), f.factoryFor(), f.roots, f.bundle)
	}
	authority, _, err := newOperatorHomeIAMAuthority(t.Context(), f.factoryFor(), f.roots, f.bundle)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(t.Context(), authority.operator.deadline)
	defer cancel()
	ctx, release, err := authority.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	return provisionOriginalFoundationActorReads(ctx, authority)
}

func (f *originalAdmissionReadsSDKFixture) expectedPolicy(t *testing.T, record FoundationRecord, index int) map[string]any {
	t.Helper()
	region := record.OriginalFoundationCompartments.Regions[index]
	entry := region.AdmissionReads
	actor := region.Actor.Provenance.ResourceID
	principal := fmt.Sprintf("request.principal.type='instance', request.principal.id='%s'", actor)
	home := f.approval.HomeStorageDomain
	control, network := region.Actor.ControlCompartmentID, region.Network.CompartmentID
	imageCompartment := originalActorResources(*f.prepared.Grant.Regions[index].BootstrapMaterial.Startup).ImageCompartmentOCID
	image := f.prepared.Grant.Regions[index].BootstrapMaterial.Startup.ImageOCID
	statement := func(verb, resource, compartment, operation, permission, extra string) string {
		condition := principal + ", request.operation='" + operation + "'"
		if permission != "" {
			condition += ", request.permission='" + permission + "'"
		}
		return fmt.Sprintf("Allow any-user to %s %s in %s where all {%s%s}", verb, resource, compartment, condition, extra)
	}
	statements := []string{statement("read", "objectstorage-namespaces", "tenancy", "GetNamespace", "OBJECTSTORAGE_NAMESPACE_READ", "")}
	policyRead := statement("read", "policies", "compartment id "+deref(region.SourceIAM.Request.CompartmentId), "GetPolicy", "POLICY_READ", "")
	if entry.Recipe.Purpose == originalAdmissionReadPurpose {
		policyRead = statement("inspect", "policies", "compartment id "+f.approval.SourceVaultTarget.CompartmentOCID, "GetPolicy", "POLICY_READ", fmt.Sprintf(", target.policy.id='%s'", region.SourceIAM.Provenance.ResourceID))
	}
	for _, object := range []string{"orchestrator/regions/v1/GRU.json", "orchestrator/foundation/v1/root-chain.json", strings.TrimSuffix(home.Prefix, "/") + "/foundation-scope-v1.json"} {
		statements = append(statements, statement("read", "objects", "compartment id "+f.approval.SourceVaultTarget.CompartmentOCID, "GetObject", "OBJECT_READ", fmt.Sprintf(", target.bucket.name='%s', target.object.name='%s'", home.HeadBucket, object)))
	}
	statements = append(statements,
		statement("read", "buckets", "compartment id "+f.approval.SourceVaultTarget.CompartmentOCID, "GetBucket", "BUCKET_READ", fmt.Sprintf(", target.bucket.name='%s'", home.HeadBucket)),
		policyRead,
		statement("read", "instances", "compartment id "+control, "GetInstance", "INSTANCE_READ", ""),
		statement("inspect", "instances", "compartment id "+control, "ListVnicAttachments", "INSTANCE_INSPECT", ""),
		statement("inspect", "vnic-attachments", "compartment id "+control, "ListVnicAttachments", "VNIC_ATTACHMENT_READ", ""),
		statement("inspect", "vnics", "compartment id "+network, "GetVnic", "VNIC_READ", ""),
		statement("inspect", "subnets", "compartment id "+network, "GetSubnet", "SUBNET_READ", ""),
		statement("read", "all-resources", "compartment id "+control, "ListBootVolumeAttachments", "", ""),
		statement("inspect", "volumes", "compartment id "+control, "GetBootVolume", "VOLUME_INSPECT", ""),
		statement("inspect", "instance-images", "compartment id "+imageCompartment, "GetImage", "INSTANCE_IMAGE_INSPECT", fmt.Sprintf(", target.image.id='%s'", image)))
	return map[string]any{"compartmentId": f.approval.TenancyID, "name": "ts-original-admission-read-" + entry.IdentitySHA256[:32],
		"description": "Prospectively authorized original actor admission observations", "statements": statements,
		"freeformTags": map[string]any{}, "definedTags": map[string]any{}}
}

func (f *originalAdmissionReadsSDKFixture) rejectJournal(w http.ResponseWriter, wire []byte, cause any) {
	if f.expectedRejectedWire != nil && bytes.Equal(wire, f.expectedRejectedWire) {
		f.journalRefusals++
	} else {
		f.cloud.test.Error(cause)
	}
	originalCompartmentFailure(w, 400, "InvalidParameter")
}

func (f *originalAdmissionReadsSDKFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.admissionMu.Lock()
	defer f.admissionMu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
		f.cloud.test.Error("admission read request lacked real OCI SDK signing")
	}
	// Origin discovery reads signed object bytes, not regional journal state.
	originHome := f.approval.HomeStorageDomain
	if r.Method == http.MethodGet && strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") && r.Host == "objectstorage."+foundationHomeRegion+".oraclecloud.com" && r.URL.RawQuery == "" &&
		strings.HasPrefix(r.URL.Path, "/n/"+originHome.Namespace+"/b/"+originHome.HeadBucket+"/o/orchestrator/workload-genesis/v1/") {
		f.originalCompartmentSDKFixture.serveHTTP(w, r)
		return
	}
	f.cloud.mu.Lock()
	wire, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json"))
	var record FoundationRecord
	if err == nil && f.decodedWire != nil && bytes.Equal(wire, f.decodedWire) {
		// Identical bytes decode identically; serveHTTP only reads the record.
		record = f.decodedRecord
	} else if err == nil {
		err = json.Unmarshal(wire, &record)
		if err == nil && record.OriginalFoundationCompartments == nil {
			err = errors.New("admission journal omitted original compartments")
		}
		if err == nil {
			f.decodedWire, f.decodedRecord = bytes.Clone(wire), record
		}
	}
	f.cloud.mu.Unlock()
	if err != nil {
		f.projectionWire, f.priorProjection, f.sourceProjection = nil, nil, nil
		f.rejectJournal(w, wire, err)
		return
	}
	prior, err := f.projection(record, wire, false)
	if err != nil || !bytes.Equal(prior, f.prior) {
		f.rejectJournal(w, wire, "admission continuation changed an immutable original prerequisite")
		return
	}
	for _, regional := range record.OriginalFoundationCompartments.Regions {
		if regional.AdmissionReads != nil && f.sources == nil {
			sources, projectionErr := f.projection(record, wire, true)
			f.sources, err = bytes.Clone(sources), projectionErr
			if err != nil || completeOriginalAdmissionReadPrerequisites(record) != nil {
				f.cloud.test.Error("admission phase preceded genuine completed source policies")
			}
		}
	}
	if f.sources != nil {
		sources, err := f.projection(record, wire, true)
		if err != nil || !bytes.Equal(sources, f.sources) {
			f.cloud.test.Error("admission phase replaced retained source IAM")
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 2 && parts[1] == "policies" {
		if r.Host != "identity."+foundationHomeRegion+".oci.oraclecloud.com" {
			f.cloud.test.Error("admission policy escaped home IAM endpoint")
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		if r.Method == http.MethodGet && len(parts) == 3 {
			if row := f.reads.readsRows[parts[2]]; row != nil {
				json.MarshalWrite(w, row)
				return
			}
			if row := f.rows[parts[2]]; row != nil {
				known := false
				for _, regional := range record.OriginalFoundationCompartments.Regions {
					entry := regional.AdmissionReads
					known = known || entry != nil && entry.Provenance != nil && entry.Provenance.ResourceID == parts[2]
				}
				if !known {
					f.cloud.test.Error("admission policy GET preceded durable actual provider ID")
				}
				f.gets[parts[2]]++
				if f.fault == "readback unavailable" && !f.faulted {
					f.faulted = true
					originalCompartmentFailure(w, 503, "InternalError")
					return
				}
				row = maps.Clone(row)
				if f.fault == "readback conflict" {
					row["statements"] = []string{"Allow any-user to manage all-resources in tenancy"}
				}
				json.MarshalWrite(w, row)
				return
			}
		}
		if r.Method == http.MethodPost && len(parts) == 2 {
			body, canonical, err := originalNetworkBody(r)
			if err != nil {
				f.cloud.test.Error(err)
				originalCompartmentFailure(w, 400, "InvalidParameter")
				return
			}
			name, _ := body["name"].(string)
			if strings.HasPrefix(name, "ts-original-admission-read-") {
				f.create(w, r, record, body, canonical)
				return
			}
			// The source policy oracle receives the exact same canonical SDK body.
			r.Body = io.NopCloser(bytes.NewReader(canonical))
		}
	}
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json") {
		wire, err := io.ReadAll(io.LimitReader(r.Body, foundationJournalLimit+1))
		if err != nil {
			f.cloud.test.Error(err)
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		var next FoundationRecord
		if json.Unmarshal(wire, &next) != nil {
			f.cloud.test.Error("SDK checkpoint had invalid JSON")
		}
		newPending, newReceipt := false, false
		for index, regional := range next.OriginalFoundationCompartments.Regions {
			before, after := record.OriginalFoundationCompartments.Regions[index].AdmissionReads, regional.AdmissionReads
			newPending = newPending || after != nil && after.Pending != nil && (before == nil || before.Pending == nil)
			newReceipt = newReceipt || after != nil && after.Provenance != nil && (before == nil || before.Provenance == nil)
		}
		if !f.faulted && (f.fault == "reservation checkpoint" && newPending || f.fault == "receipt checkpoint" && newReceipt) {
			f.faulted = true
			originalCompartmentFailure(w, 503, "InternalError")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(wire))
	}
	if r.Method == http.MethodPut {
		home := f.approval.HomeStorageDomain
		for _, key := range []string{foundationRootChainObject, strings.TrimSuffix(home.Prefix, "/") + "/" + foundationGrantObject} {
			if r.URL.Path == "/n/"+home.Namespace+"/b/"+home.HeadBucket+"/o/"+key {
				if completeOriginalFoundationAdmissionReads(record) != nil || f.prepared.Grant.OriginalPublication == nil {
					f.cloud.test.Error("currentness publication preceded actual read policy completion or signed purpose")
					originalCompartmentFailure(w, 400, "InvalidParameter")
					return
				}
				f.originalCompartmentSDKFixture.serveHTTP(w, r)
				return
			}
		}
	}
	f.originalSourceIAMSDKFixture.serveHTTP(w, r)
}

func (f *originalAdmissionReadsSDKFixture) create(w http.ResponseWriter, r *http.Request, record FoundationRecord, body map[string]any, canonical []byte) {
	index := slices.IndexFunc(record.OriginalFoundationCompartments.Regions[:], func(regional OriginalFoundationCompartmentRegion) bool {
		return regional.AdmissionReads != nil && deref(regional.AdmissionReads.Request.Name) == body["name"]
	})
	if index < 0 || completeOriginalAdmissionReadPrerequisites(record) != nil {
		f.cloud.test.Error("admission policy lacked complete genuine original prerequisites")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	entry := record.OriginalFoundationCompartments.Regions[index].AdmissionReads
	if entry.Pending == nil || entry.Provenance != nil || entry.Pending.Request.RequestDigest != preparationDigest(canonical) ||
		entry.Pending.Request.RetryToken != r.Header.Get("opc-retry-token") || !sameOriginalSourceValue(body, f.expectedPolicy(f.cloud.test, record, index)) {
		f.cloud.test.Error("admission wire escaped signed finite scope or durable exact request")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	wire, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + homeIAMObject))
	var lease homeIAMRecord
	if err != nil || json.Unmarshal(wire, &lease) != nil || !lease.ReleasedAt.IsZero() || !time.Now().Before(lease.ExpiresAt) || lease.OperatorID != record.OriginalFoundationCompartments.UserID {
		f.cloud.test.Error("admission dispatch lacked live genuine original HomeWrite")
	}
	f.posts = append(f.posts, originalAdmissionReadDispatch{body: bytes.Clone(canonical), token: r.Header.Get("opc-retry-token"), pending: *entry.Pending})
	if f.fault == "create refused" {
		originalCompartmentFailure(w, 409, "Conflict")
		return
	}
	id := fmt.Sprintf("ocid1.policy.oc1..originaladmission%d", index+1)
	row := maps.Clone(body)
	row["id"], row["lifecycleState"] = id, "ACTIVE"
	f.rows[id] = row
	if f.fault == "lost response" && !f.faulted {
		f.faulted = true
		originalCompartmentFailure(w, 503, "InternalError")
		return
	}
	json.MarshalWrite(w, row)
}

func (f *originalAdmissionReadsSDKFixture) assertComplete(t *testing.T) {
	t.Helper()
	record := f.record(t)
	if record.validate() != nil || record.Stage != "original-foundation" || len(record.ResourceIDs) != 0 || len(record.SourcePolicyIDs) != 0 ||
		record.FoundationWriter != nil || record.NetBirdManager != nil || !record.CompletedAt.IsZero() || f.cloud.hasAnchor() || len(f.wire(t)) > foundationJournalLimit {
		t.Fatal("admission read policy fabricated ordinary startup/runtime authority")
	}
	for index, regional := range record.OriginalFoundationCompartments.Regions {
		entry := regional.AdmissionReads
		if entry == nil || entry.Pending == nil || entry.Provenance == nil || entry.VerifiedAt.IsZero() || entry.ReadbackSHA256 == "" || entry.HoldReason != "" || f.gets[entry.Provenance.ResourceID] == 0 {
			t.Fatal("admission policy lacks durable actual ID and authenticated readback")
		}
		body, err := foundationWriterPolicyBody(entry.Request)
		var actual map[string]any
		if err != nil || json.Unmarshal(body, &actual) != nil || !sameOriginalSourceValue(actual, f.expectedPolicy(t, record, index)) {
			t.Fatal("retained admission policy differs from independent finite statement oracle")
		}
	}
}

func TestOriginalFoundationAdmissionReadVersionsSDK(t *testing.T) {
	for _, version := range []string{originalAdmissionReadPurpose, originalAdmissionReadPurposeV2} {
		t.Run(version, func(t *testing.T) {
			t.Setenv(common.UsingExpectHeaderEnvVar, "false")
			reads := newOriginalActorReadsSDKFixture(t, "", 0)
			reads.prepared.Grant.OriginalMaterialPublicationIAM = nil
			recipes := *reads.prepared.Grant.OriginalActorAdmissionReads
			for index := range recipes {
				recipes[index].Purpose = version
			}
			reads.prepared.Grant.OriginalActorAdmissionReads = &recipes
			publication, err := originalFoundationPublicationIntent(reads.prepared.Grant, reads.approval.HomeStorageDomain)
			if err != nil {
				t.Fatal(err)
			}
			reads.prepared.Grant.OriginalPublication = &publication
			f := originalAdmissionReadsSDKFixtureFor(t, reads, "")
			if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
				t.Fatal(err)
			}
			f.assertComplete(t)
			before, posts := bytes.Clone(f.wire(t)), len(f.posts)
			for _, region := range f.record(t).OriginalFoundationCompartments.Regions {
				entry := region.AdmissionReads
				joined := strings.Join(entry.Request.Statements, "\n")
				if entry.Recipe.Purpose != version || strings.Contains(joined, "target.policy.id") != (version == originalAdmissionReadPurpose) {
					t.Fatal("admission policy changed versioned selector contract")
				}
			}
			if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) || len(f.posts) != posts || !bytes.Equal(before, f.wire(t)) {
				t.Fatal("versioned completed admission reads rewrote history", err)
			}
			if version == originalAdmissionReadPurpose {
				store := f.store(t)
				priorProjection, sourceProjection := f.priorProjection, f.sourceProjection
				if _, _, err := store.Load(t.Context(), "GRU"); err != nil || len(priorProjection) == 0 || len(sourceProjection) == 0 ||
					&priorProjection[0] != &f.priorProjection[0] || &sourceProjection[0] != &f.sourceProjection[0] {
					t.Fatal("unchanged actual SDK read did not reuse pure journal projections", err)
				}
				writeJournal := func(wire, expected []byte) {
					f.admissionMu.Lock()
					defer f.admissionMu.Unlock()
					f.cloud.mu.Lock()
					defer f.cloud.mu.Unlock()
					f.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", wire)
					f.expectedRejectedWire = bytes.Clone(expected)
				}
				t.Cleanup(func() { writeJournal(before, nil) })
				changed := f.record(t)
				changed.Stage = "changed-original-prerequisite"
				changedWire, err := json.Marshal(changed, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				for _, badWire := range [][]byte{[]byte("{malformed journal"), changedWire} {
					refusals := f.journalRefusals
					writeJournal(badWire, badWire)
					_, _, err := store.Load(t.Context(), "GRU")
					var serviceErr common.ServiceError
					ok := errors.As(err, &serviceErr)
					if !ok || serviceErr.GetHTTPStatusCode() != 400 || f.journalRefusals != refusals+1 ||
						!bytes.Equal(badWire, f.wire(t)) || len(f.posts) != posts {
						t.Fatal("changed journal escaped actual SDK refusal or changed durable/provider state", err)
					}
					writeJournal(before, nil)
					if _, _, err := store.Load(t.Context(), "GRU"); err != nil {
						t.Fatal("restored journal did not recover after refused bytes", err)
					}
				}
				if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) || len(f.posts) != posts || !bytes.Equal(before, f.wire(t)) {
					t.Fatal("journal refusal changed restart history or repeated a policy", err)
				}
			}
		})
	}
}

func TestOriginalFoundationAdmissionReadsSDK(t *testing.T) {
	t.Run("automatic finite policies and restart", func(t *testing.T) {
		f := newOriginalAdmissionReadsSDKFixture(t, "", false)
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
			t.Fatal(err)
		}
		f.assertComplete(t)
		before, creates := bytes.Clone(f.wire(t)), len(f.posts)
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) || len(f.posts) != creates || creates != 3 || !bytes.Equal(before, f.wire(t)) {
			t.Fatal("restart changed original journal or repeated an acknowledged policy")
		}
	})
	t.Run("legacy signed history gains no new permission", func(t *testing.T) {
		f := newOriginalAdmissionReadsSDKFixture(t, "", true)
		before := bytes.Clone(f.wire(t))
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationActorReadsPending) || len(f.posts) != 0 || len(f.originalSourceIAMSDKFixture.posts) != 0 || !bytes.Equal(before, f.wire(t)) {
			t.Fatal("old signed history acquired admission/source policy effects")
		}
		for _, regional := range f.record(t).OriginalFoundationCompartments.Regions {
			if regional.AdmissionReads != nil || regional.SourceIAM != nil {
				t.Fatal("old signed history acquired new journal authority")
			}
		}
	})
	for _, fault := range []string{"lost response", "receipt checkpoint", "readback unavailable"} {
		t.Run(fault+" resumes same original request", func(t *testing.T) {
			f := newOriginalAdmissionReadsSDKFixture(t, fault, false)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
				t.Fatal("injected failure became a completed policy stage")
			}
			if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
				t.Fatal(err)
			}
			f.assertComplete(t)
			if fault != "readback unavailable" && (len(f.posts) != 4 || f.posts[0].token != f.posts[1].token || !bytes.Equal(f.posts[0].body, f.posts[1].body) || !sameOriginalSourceValue(f.posts[0].pending, f.posts[1].pending)) {
				t.Fatal("unknown policy outcome generated a new request or retry identity")
			}
		})
	}
	for _, fault := range []string{"reservation checkpoint", "create refused", "readback conflict"} {
		t.Run(fault+" remains HOLD", func(t *testing.T) {
			f := newOriginalAdmissionReadsSDKFixture(t, fault, false)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
				t.Fatal("failed acknowledgement became admission authority")
			}
			if fault == "reservation checkpoint" && len(f.posts) != 0 {
				t.Fatal("policy wire preceded acknowledged reservation")
			}
			if fault != "reservation checkpoint" {
				posts := len(f.posts)
				if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) || len(f.posts) != posts {
					t.Fatal("held policy was recreated or admitted")
				}
			}
		})
	}
}

func TestOriginalFoundationAdmissionReadSignedContract(t *testing.T) {
	// These are prospective test-root signatures, before any original journal birth.
	for _, change := range []string{"operation", "scope", "object", "actor recipe", "cell"} {
		t.Run(change, func(t *testing.T) {
			t.Setenv(common.UsingExpectHeaderEnvVar, "false")
			f := newOriginalActorReadsSDKFixture(t, "", 0)
			if f.prepared.Grant.OriginalActorAdmissionReads == nil {
				t.Fatal("fresh preparation omitted mandatory prospective recipes")
			}
			prepared := f.prepared
			recipes := *prepared.Grant.OriginalActorAdmissionReads
			prepared.Grant.OriginalActorAdmissionReads = &recipes
			switch change {
			case "operation":
				recipes[0].Operations[9].Operation = "LaunchInstance"
			case "scope":
				recipes[0].Operations[9].Scope = "tenancy"
			case "object":
				recipes[0].Objects[0] = "orchestrator/regions/v1/SJC.json"
			case "actor recipe":
				recipes[0].ActorRecipeSHA256 = strings.Repeat("f", 64)
			case "cell":
				recipes[0].Cell = "SJC"
			}
			bundle := signProvisionFoundation(t, prepared, f.bundle.RootChainWire, f.root, f.now)
			objects := func() map[string]string {
				rows, err := os.ReadDir(f.cloud.directory)
				if err != nil {
					t.Fatal(err)
				}
				snapshot := make(map[string]string, len(rows))
				for _, row := range rows {
					wire, err := os.ReadFile(f.cloud.directory + "/" + row.Name())
					if err != nil {
						t.Fatal(err)
					}
					snapshot[row.Name()] = digestSource(wire)
				}
				return snapshot
			}
			before := objects()
			if err := VerifyFoundationProvisionBundle(t.Context(), f.roots, bundle); err == nil || f.cloud.creates != 0 || f.cloud.launchPosts != 0 {
				t.Fatal("root signature admitted an altered read contract or performed cloud effects")
			}
			if err := provisionOriginalFoundationCompartments(t.Context(), f.factoryFor(), f.roots, bundle); err == nil ||
				f.cloud.creates != 0 || f.cloud.launchPosts != 0 || f.cloud.materialPosts != 0 || len(f.readDispatches()) != 0 || f.cloud.hasAnchor() || !maps.Equal(before, objects()) {
				t.Fatal("owning original producer admitted an altered signed read contract or changed cloud/object state")
			}
			for _, cell := range [3]string{"GRU", "SJC", "FRA"} {
				if _, err := os.Stat(f.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + cell + ".json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("rejected signed read contract acquired a protected regional journal")
				}
			}
		})
	}
}

func TestOriginalFoundationAdmissionReadRetainedScope(t *testing.T) {
	f := newOriginalAdmissionReadsSDKFixture(t, "", false)
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
		t.Fatal(err)
	}
	before, store := bytes.Clone(f.wire(t)), f.store(t)
	posts, creates, launches, material := len(f.posts), f.cloud.creates, f.cloud.launchPosts, f.cloud.materialPosts
	for _, change := range []string{"actor", "source policy", "object", "statement", "receipt", "remove"} {
		t.Run(change, func(t *testing.T) {
			record, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			entry := record.OriginalFoundationCompartments.Regions[0].AdmissionReads
			switch change {
			case "actor":
				entry.ActorID = record.OriginalFoundationCompartments.Regions[1].Actor.Provenance.ResourceID
			case "source policy":
				entry.SourcePolicyID = record.OriginalFoundationCompartments.Regions[1].SourceIAM.Provenance.ResourceID
			case "object":
				entry.Recipe.Objects[0] = "orchestrator/regions/v1/SJC.json"
			case "statement":
				entry.Request.Statements = append(entry.Request.Statements, "Allow any-user to manage all-resources in tenancy")
			case "receipt":
				entry.Provenance.ResourceID = record.OriginalFoundationCompartments.Regions[1].AdmissionReads.Provenance.ResourceID
			case "remove":
				record.OriginalFoundationCompartments.Regions[0].AdmissionReads = nil
			}
			if err := record.retainOriginalFoundationAdmissionReads(f.record(t)); err == nil {
				t.Fatal("retained original read scope or provider receipt was replaced")
			}
			if change != "remove" && record.validate() == nil {
				t.Fatal("altered original read scope passed full protected record validation")
			}
			if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(before, f.wire(t)) ||
				len(f.posts) != posts || f.cloud.creates != creates || f.cloud.launchPosts != launches || f.cloud.materialPosts != material {
				t.Fatal("protected CAS accepted altered original admission scope or changed durable/provider state")
			}
		})
	}
	if !bytes.Equal(before, f.wire(t)) || len(f.posts) != 3 {
		t.Fatal("negative scope verification mutated durable history or dispatched policies")
	}
}

func TestOriginalFoundationAdmissionReadEffectPredecessors(t *testing.T) {
	for _, fault := range []string{"reservation checkpoint", "receipt checkpoint"} {
		t.Run(fault, func(t *testing.T) {
			f := newOriginalAdmissionReadsSDKFixture(t, fault, false)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) || !f.faulted {
				t.Fatal("fixture did not stop before the acknowledged effect predecessor")
			}
			store := f.store(t)
			record, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			entry := record.OriginalFoundationCompartments.Regions[0].AdmissionReads
			if entry == nil || entry.Provenance != nil || (entry.Pending == nil) != (fault == "reservation checkpoint") {
				t.Fatal("fixture retained an unexpected admission predecessor")
			}
			before, posts := bytes.Clone(f.wire(t)), len(f.posts)
			if entry.Pending == nil {
				body, err := foundationWriterPolicyBody(entry.Request)
				if err != nil {
					t.Fatal(err)
				}
				regional := record.OriginalFoundationCompartments.Regions[0]
				entry.Pending = &PendingFoundationCreate{OperationID: regional.OperationID, IntentDigest: regional.IntentSHA256,
					FirstAttemptAt: time.Now().UTC(), Request: originalAdmissionReadCreateIdentity(regional, digestSource(body))}
			}
			// Submit rejected receipt claims; these never establish production authority.
			entry.Provenance = &FoundationResourceProvenance{Create: *entry.Pending, ResourceID: "ocid1.policy.oc1..originaladmission1",
				Generation: entry.Generation, GrantSHA256: entry.GrantSHA256}
			if fault == "receipt checkpoint" {
				if f.rows[entry.Provenance.ResourceID] == nil || posts != 1 {
					t.Fatal("receipt boundary lacks the actual provider response")
				}
				entry.ReadbackSHA256, err = originalAdmissionReadback(*entry)
				if err != nil {
					t.Fatal(err)
				}
				entry.VerifiedAt = time.Now().UTC()
			} else if posts != 0 {
				t.Fatal("reservation boundary dispatched a policy")
			}
			record.UpdatedAt = time.Now().UTC()
			if err := record.validate(); err != nil {
				t.Fatalf("candidate must be structurally valid before checking its predecessor: %v", err)
			}
			if _, err := store.CompareAndSwap(t.Context(), record, etag); !errors.Is(err, ErrOriginalSourceProducerHold) || !bytes.Equal(before, f.wire(t)) || len(f.posts) != posts {
				t.Fatal("protected CAS accepted a skipped admission effect predecessor or changed durable history")
			}
		})
	}
}
