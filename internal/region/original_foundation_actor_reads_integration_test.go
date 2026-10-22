package region

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
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

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
)

type originalActorReadDispatch struct {
	cell, host, token string
	body              []byte
	pending           PendingFoundationCreate
}

type originalActorReadsSDKFixture struct {
	*originalActorSDKFixture
	readsMu       sync.Mutex
	readsFault    string
	readsSlot     int
	readsFaulted  bool
	readsPosts    []originalActorReadDispatch
	readsTokens   map[string]string
	readsRows     map[string]map[string]any
	readsGets     map[string]int
	readsUpstream []byte
	publicBundle  []byte
}

func newOriginalActorReadsSDKFixture(t *testing.T, fault string, slot int) *originalActorReadsSDKFixture {
	t.Helper()
	f := &originalActorReadsSDKFixture{originalActorSDKFixture: newOriginalActorSDKFixture(t, "", 0), readsFault: fault, readsSlot: slot,
		readsTokens: map[string]string{}, readsRows: map[string]map[string]any{}, readsGets: map[string]int{}}
	var err error
	f.publicBundle, err = json.Marshal(f.bundle, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("original actor READ fixture requires literal loopback TLS")
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

func (f *originalActorReadsSDKFixture) run(t *testing.T) error {
	t.Helper()
	if err := f.originalActorSDKFixture.run(t); err != nil {
		return err
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
	return retainOriginalFoundationActorReads(ctx, authority)
}

func originalActorReadsUpstream(record FoundationRecord) ([]byte, error) {
	section := *record.OriginalFoundationCompartments
	for index := range section.Regions {
		section.Regions[index].ActorReads = nil
	}
	return json.Marshal(struct {
		Material     *NetBirdMaterialJournal
		Births       *[3]OriginalSourceProducerBirth
		Compartments OriginalFoundationCompartments
	}{record.NetBirdMaterial, record.OriginalSourceProducers, section}, json.Deterministic(true))
}

func (f *originalActorReadsSDKFixture) currentActors() (FoundationRecord, bool) {
	wire, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json"))
	var record FoundationRecord
	if err != nil || json.Unmarshal(wire, &record) != nil || record.OriginalFoundationCompartments == nil {
		return record, false
	}
	for _, region := range record.OriginalFoundationCompartments.Regions {
		if region.Actor == nil || region.Actor.Provenance == nil || region.Actor.VerifiedAt.IsZero() {
			return record, false
		}
	}
	return record, true
}

// Inspect the accepted reservation before the producer receives its CAS response.
func (f *originalActorReadsSDKFixture) checkNetworkReservationRoundtrip() {
	record, _ := f.currentActors()
	if record.OriginalFoundationCompartments == nil {
		return
	}
	for _, region := range record.OriginalFoundationCompartments.Regions {
		network := region.Network
		if network == nil || network.Creates[0].Pending == nil || network.Creates[0].Provenance != nil {
			continue
		}
		request := network.Requests.VCN
		if request.CidrBlocks != nil || request.Ipv6PrivateCidrBlocks != nil || request.Byoipv6CidrDetails != nil ||
			request.DefinedTags != nil || request.FreeformTags != nil || request.SecurityAttributes != nil {
			f.cloud.test.Errorf("%s accepted VCN reservation changed nil optional SDK collections", region.Cell)
		}
		digest, err := originalNetworkRequestSHA("vcn", request)
		pending := network.Creates[0].Pending.Request
		if err != nil || digest != pending.RequestDigest || pending.RetryToken != BootstrapRetryToken(region.OperationID, digest) {
			f.cloud.test.Errorf("%s accepted VCN reservation changed SDK body digest or retry token: %v", region.Cell, err)
		}
	}
}

func (f *originalActorReadsSDKFixture) checkReadsPrerequisites(record FoundationRecord) {
	f.checkActorPrerequisites(record)
	if record.OriginalSourceProducers == nil || record.validateOriginalFoundationActors() != nil || f.cloud.creates < 30 {
		f.cloud.test.Error("public READ preceded complete genuine original prerequisites")
		return
	}
	for _, region := range record.OriginalFoundationCompartments.Regions {
		actor := region.Actor
		if actor == nil || actor.Pending == nil || actor.Provenance == nil || actor.VerifiedAt.IsZero() || actor.ReadbackSHA256 == "" || actor.HoldReason != "" {
			f.cloud.test.Error("public READ preceded all-three acknowledged actual actor IDs and physical proofs")
			continue
		}
		f.actorMu.Lock()
		observed := f.actorGets[actor.Provenance.ResourceID] > 0 && f.actorGets[actor.PrimaryVNICID] > 0 && f.actorGets[actor.BootVolumeID] > 0
		f.actorMu.Unlock()
		if !observed {
			f.cloud.test.Error("public READ lacked actual instance/VNIC/boot SDK observations")
		}
	}
	pins, err := originalActorReadsUpstream(record)
	if err != nil {
		f.cloud.test.Error(err)
	} else if f.readsUpstream == nil {
		f.readsUpstream = pins
	} else if !bytes.Equal(pins, f.readsUpstream) {
		f.cloud.test.Error("public READ changed immutable original material, births or physical prerequisites")
	}
}

// Project the contract from signed inputs and actual actor results, independently
// of the production scope and policy builders.
func (f *originalActorReadsSDKFixture) expectedReadPolicy(record FoundationRecord, index int) (map[string]any, release.WorkloadGenesis, string, string) {
	region := record.OriginalFoundationCompartments.Regions[index]
	birth := (*record.OriginalSourceProducers)[index]
	var origin release.WorkloadGenesis
	matches := 0
	for _, candidate := range f.prepared.Grant.WorkloadGenesis {
		if candidate.Cell == region.Cell && candidate.Environment == "production" && candidate.Role == "ts-auth" {
			origin = candidate
			matches++
		}
	}
	key, err := release.WorkloadGenesisObject(f.prepared.Grant.TenancyID, region.Cell, "production", "ts-auth")
	if err != nil || matches != 1 || !slices.Contains(birth.OriginObjects[:], key) || origin.Namespace != f.approval.HomeStorageDomain.Namespace || origin.Bucket != f.approval.HomeStorageDomain.HeadBucket {
		f.cloud.test.Fatal("fixture signed public origin is not unique and exact")
	}
	identity, err := json.Marshal([]string{birth.OriginalGrantSHA256, birth.OriginalBundleSHA256, region.Cell, region.Actor.Provenance.ResourceID, origin.Namespace, origin.Bucket, key}, json.Deterministic(true))
	if err != nil {
		f.cloud.test.Fatal(err)
	}
	identitySHA := preparationDigest(identity)
	statement := fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {request.principal.type='instance', request.principal.id='%s', target.bucket.name='%s', target.object.name='%s', request.permission='OBJECT_READ'}", f.approval.SourceVaultTarget.CompartmentOCID, region.Actor.Provenance.ResourceID, origin.Bucket, key)
	return map[string]any{"compartmentId": f.approval.SourceVaultTarget.CompartmentOCID, "name": "ts-original-actor-read-" + identitySHA[:32],
		"description": "Original actor reads one exact original public foundation bundle", "statements": []any{statement}, "freeformTags": map[string]any{}, "definedTags": map[string]any{}}, origin, key, identitySHA
}

func (f *originalActorReadsSDKFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.readsMu.Lock()
	defer f.readsMu.Unlock()
	policyRequest := strings.Contains(r.URL.Path, "/policies")
	checkpointRequest := r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json")
	storageFaultRequest := r.Method == http.MethodGet && (f.readsFault == "namespace" && r.URL.Path == "/n" ||
		strings.HasPrefix(f.readsFault, "bucket ") && r.URL.Path == "/n/ns/b/gru-1-head" ||
		slices.Contains([]string{"document missing", "document bytes", "document oversized"}, f.readsFault))
	if !policyRequest && !checkpointRequest && !storageFaultRequest {
		f.originalActorSDKFixture.serveHTTP(w, r)
		return
	}
	record, complete := f.currentActors()
	if complete && checkpointRequest {
		if f.readsCheckpointFault(w, r) {
			return
		}
	}
	if complete && r.Method == http.MethodGet && f.readsStorageFault(w, r, record) {
		return
	}
	if !policyRequest {
		if !complete && checkpointRequest {
			recorder := httptest.NewRecorder()
			f.originalActorSDKFixture.serveHTTP(recorder, r)
			if recorder.Code < 300 {
				f.checkNetworkReservationRoundtrip()
			}
			originalNetworkCopyResponse(w, recorder)
			return
		}
		f.originalActorSDKFixture.serveHTTP(w, r)
		return
	}
	if !complete || r.Host != "identity."+foundationHomeRegion+".oci.oraclecloud.com" || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") || r.URL.RawQuery != "" {
		f.cloud.test.Error("public READ policy escaped complete actors, authenticated home IAM or exact protocol")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	f.checkReadsPrerequisites(record)
	if r.Method == http.MethodPost && r.URL.Path == "/20160918/policies" {
		f.createReadPolicy(w, r, record)
		return
	}
	id, exact := strings.CutPrefix(r.URL.Path, "/20160918/policies/")
	if r.Method != http.MethodGet || !exact || id == "" || strings.Contains(id, "/") {
		f.cloud.test.Error("public READ attempted list/adoption, update, delete or another policy protocol")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	f.getReadPolicy(w, record, id)
}

func (f *originalActorReadsSDKFixture) readsCheckpointFault(w http.ResponseWriter, r *http.Request) bool {
	if f.readsFaulted {
		return false
	}
	body, _, err := originalNetworkBody(r)
	wire, marshalErr := json.Marshal(body)
	var next FoundationRecord
	if err != nil || marshalErr != nil || json.Unmarshal(wire, &next) != nil || next.OriginalFoundationCompartments == nil {
		f.cloud.test.Error("fixture could not inspect protected READ checkpoint")
		return false
	}
	entry := next.OriginalFoundationCompartments.Regions[f.readsSlot].ActorReads
	if entry == nil {
		return false
	}
	scope := entry.Pending == nil
	reserved := entry.Pending != nil && entry.Provenance == nil
	accepted := entry.Provenance != nil && entry.VerifiedAt.IsZero()
	verified := !entry.VerifiedAt.IsZero()
	stop := f.readsFault == "scope checkpoint" && scope || f.readsFault == "reservation checkpoint" && reserved ||
		(f.readsFault == "response before CAS" || f.readsFault == "lost accepted checkpoint") && accepted ||
		(f.readsFault == "readback checkpoint" || f.readsFault == "lost readback checkpoint") && verified || f.readsFault == "stale lease" && reserved
	if !stop {
		return false
	}
	f.readsFaulted = true
	if slices.Contains([]string{"lost accepted checkpoint", "lost readback checkpoint", "stale lease"}, f.readsFault) {
		recorder := httptest.NewRecorder()
		f.originalActorSDKFixture.serveHTTP(recorder, r)
		if recorder.Code >= 300 {
			f.cloud.test.Error("READ lost-ACK fault did not first accept the exact checkpoint")
		}
		if f.readsFault == "stale lease" {
			leaseWire, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + homeIAMObject))
			var lease homeIAMRecord
			if err != nil || json.Unmarshal(leaseWire, &lease) != nil {
				f.cloud.test.Error("READ lease fault lacks genuine acknowledged HomeWrite")
			} else {
				lease.UpdatedAt = time.Now().UTC()
				lease.ExpiresAt, lease.ReleasedAt = lease.UpdatedAt, lease.UpdatedAt
				wire, err := json.Marshal(lease)
				if err != nil {
					f.cloud.test.Error(err)
				} else {
					f.cloud.writeObject("gru-1-head/"+homeIAMObject, wire)
				}
			}
			originalNetworkCopyResponse(w, recorder)
			return true
		}
	}
	originalCompartmentFailure(w, 503, "InternalError")
	return true
}

func (f *originalActorReadsSDKFixture) readsStorageFault(w http.ResponseWriter, r *http.Request, record FoundationRecord) bool {
	storageFault := f.readsFault == "namespace" && r.URL.Path == "/n" ||
		strings.HasPrefix(f.readsFault, "bucket ") && r.URL.Path == "/n/ns/b/gru-1-head" ||
		slices.Contains([]string{"document missing", "document bytes", "document oversized"}, f.readsFault) && strings.HasPrefix(r.URL.Path, "/n/ns/b/gru-1-head/o/")
	if storageFault && (r.Host != "objectstorage."+foundationHomeRegion+".oraclecloud.com" || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ")) {
		f.cloud.test.Error("public READ storage fault bypassed authenticated exact home Object Storage")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return true
	}
	if f.readsFault == "namespace" && r.URL.Path == "/n" {
		json.MarshalWrite(w, "foreign")
		return true
	}
	bucket := r.URL.Path == "/n/ns/b/gru-1-head"
	public := false
	for _, origin := range f.prepared.Grant.WorkloadGenesis {
		if origin.Role != "ts-auth" {
			continue
		}
		key, err := release.WorkloadGenesisObject(origin.TenancyID, origin.Cell, origin.Environment, origin.Role)
		if err != nil {
			f.cloud.test.Error(err)
			continue
		}
		public = public || strings.HasSuffix(r.URL.Path, "/o/"+key)
	}
	if public && slices.Contains([]string{"document missing", "document bytes", "document oversized"}, f.readsFault) {
		if f.readsFault == "document missing" {
			originalCompartmentFailure(w, 404, "NotAuthorizedOrNotFound")
		} else if f.readsFault == "document bytes" {
			w.Write(append(bytes.Clone(f.publicBundle), '\n'))
		} else {
			w.Write(bytes.Repeat([]byte("x"), len(f.publicBundle)+1))
		}
		return true
	}
	if !bucket || !strings.HasPrefix(f.readsFault, "bucket ") {
		return false
	}
	var row map[string]any
	f.cloud.mu.Lock()
	for id, item := range f.cloud.rows {
		if f.cloud.collections[id] == "buckets" && item["name"] == "gru-1-head" {
			row = maps.Clone(item)
		}
	}
	f.cloud.mu.Unlock()
	if row == nil {
		f.cloud.test.Fatal("fixture lacks independently observed Home bucket")
	}
	switch f.readsFault {
	case "bucket identity":
		row["id"] = "ocid1.bucket.oc1.sa-saopaulo-1.foreign"
	case "bucket compartment":
		row["compartmentId"] = record.SharedCompartmentID
	case "bucket KMS":
		row["kmsKeyId"] = f.approval.HomeStorageDomain.LedgerKMSKeyOCID
	case "bucket namespace":
		row["namespace"] = "foreign"
	case "bucket name":
		row["name"] = "foreign"
	}
	json.MarshalWrite(w, row)
	return true
}

func (f *originalActorReadsSDKFixture) createReadPolicy(w http.ResponseWriter, r *http.Request, record FoundationRecord) {
	body, canonical, err := originalNetworkBody(r)
	if err != nil {
		f.cloud.test.Error(err)
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	index := -1
	for slot := range record.OriginalFoundationCompartments.Regions {
		expected, _, _, _ := f.expectedReadPolicy(record, slot)
		if body["name"] == expected["name"] {
			index = slot
		}
	}
	if index < 0 {
		f.cloud.test.Error("policy body has no independently derived exact original identity")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	region := record.OriginalFoundationCompartments.Regions[index]
	entry := region.ActorReads
	expected, origin, key, identitySHA := f.expectedReadPolicy(record, index)
	expectedWire, expectedErr := json.Marshal(expected, json.Deterministic(true))
	actualWire, actualErr := json.Marshal(originalNetworkPrune(body), json.Deterministic(true))
	if entry == nil || entry.Pending == nil || entry.Provenance != nil || expectedErr != nil || actualErr != nil || !bytes.Equal(expectedWire, actualWire) {
		f.cloud.test.Error("policy escaped sole exact OBJECT_READ body or acknowledged original reservation")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	birth, actor, pending := (*record.OriginalSourceProducers)[index], region.Actor, entry.Pending
	var releaseSHA string
	for _, authority := range f.prepared.Grant.ReleaseAuthorities {
		if authority.Role == "ts-auth" && authority.Environment == "production" && slices.Contains(authority.Cells, region.Cell) {
			wire, err := json.Marshal(authority, json.Deterministic(true))
			if err != nil {
				f.cloud.test.Fatal(err)
			}
			releaseSHA = preparationDigest(wire)
		}
	}
	if entry.GrantSHA256 != birth.OriginalGrantSHA256 || entry.BundleSHA256 != preparationDigest(f.publicBundle) || entry.BundleSHA256 != birth.OriginalBundleSHA256 ||
		entry.IntentSHA256 != region.IntentSHA256 || entry.Generation != region.Generation || entry.OperationID != region.OperationID || entry.ActorID != actor.Provenance.ResourceID ||
		entry.ActorRequestSHA256 != actor.Pending.Request.RequestDigest || entry.ActorReadbackSHA256 != actor.ReadbackSHA256 || entry.ReleaseAuthoritySHA256 != releaseSHA ||
		entry.Origin != origin || entry.ObjectKey != key || entry.IdentitySHA256 != identitySHA || entry.BucketID != birth.HeadBucketID || entry.BucketCompartmentID != f.approval.SourceVaultTarget.CompartmentOCID ||
		entry.KMSKeyID != f.approval.HomeStorageDomain.HeadKMSKeyOCID || entry.BundleBytes != int64(len(f.publicBundle)) || entry.DocumentReadbackSHA256 == "" ||
		pending.OperationID != region.OperationID || pending.IntentDigest != region.IntentSHA256 || pending.Request.Key != "actor-public-read" || pending.Request.Region != foundationHomeRegion ||
		pending.Request.RequestDigest != preparationDigest(canonical) || pending.Request.RetryToken != BootstrapRetryToken(region.OperationID, preparationDigest(canonical)) || r.Header.Get("opc-retry-token") != pending.Request.RetryToken ||
		pending.FirstAttemptAt.IsZero() || pending.FirstAttemptAt.Before(f.started) || pending.FirstAttemptAt.Before(actor.VerifiedAt) || pending.FirstAttemptAt.After(time.Now()) {
		f.cloud.test.Error("public READ escaped signed lineage, actual recipient, exact document or durable body/token/time")
	}
	for _, candidate := range record.OriginalFoundationCompartments.Regions {
		if candidate.ActorReads == nil || pending.FirstAttemptAt.Before(candidate.Actor.VerifiedAt) {
			f.cloud.test.Error("public READ dispatch preceded all-three scopes and physical actor completion")
		}
	}
	f.readsPosts = append(f.readsPosts, originalActorReadDispatch{region.Cell, r.Host, r.Header.Get("opc-retry-token"), canonical, *pending})
	fault := index == f.readsSlot && !f.readsFaulted
	if fault && slices.Contains([]string{"unknown create", "conflict", "bad request", "throttle", "timeout"}, f.readsFault) {
		f.readsFaulted = true
		status, code := 503, "InternalError"
		switch f.readsFault {
		case "conflict":
			status, code = 409, "Conflict"
		case "bad request":
			status, code = 400, "InvalidParameter"
		case "throttle":
			status, code = 429, "TooManyRequests"
		case "timeout":
			status, code = 408, "RequestTimeout"
		}
		originalCompartmentFailure(w, status, code)
		return
	}
	id := f.readsTokens[pending.Request.RetryToken]
	if id == "" {
		id = "ocid1.policy.oc1..originalactorread" + strings.ToLower(region.Cell)
		f.readsTokens[pending.Request.RetryToken] = id
		row := maps.Clone(body)
		row["id"], row["lifecycleState"] = id, "ACTIVE"
		f.readsRows[id] = row
		f.cloud.mu.Lock()
		f.cloud.creates++
		f.cloud.mu.Unlock()
	}
	if fault && f.readsFault == "lost create response" {
		f.readsFaulted = true
		originalCompartmentFailure(w, 503, "InternalError")
		return
	}
	row := maps.Clone(f.readsRows[id])
	if fault {
		switch f.readsFault {
		case "empty ID":
			row["id"] = ""
			f.readsFaulted = true
		case "wrong kind ID":
			row["id"] = "ocid1.instance.oc1.sa-saopaulo-1.foreign"
			f.readsFaulted = true
		case "duplicate ID":
			row["id"] = record.OriginalFoundationCompartments.Regions[0].ActorReads.Provenance.ResourceID
			f.readsFaulted = true
		}
	}
	json.MarshalWrite(w, row)
}

func (f *originalActorReadsSDKFixture) getReadPolicy(w http.ResponseWriter, record FoundationRecord, id string) {
	index := slices.IndexFunc(record.OriginalFoundationCompartments.Regions[:], func(region OriginalFoundationCompartmentRegion) bool {
		return region.ActorReads != nil && region.ActorReads.Provenance != nil && region.ActorReads.Provenance.ResourceID == id
	})
	if index < 0 || f.readsRows[id] == nil {
		f.cloud.test.Error("GetPolicy preceded acknowledged actual policy ID or escaped exact returned identity")
		originalCompartmentFailure(w, 404, "NotAuthorizedOrNotFound")
		return
	}
	entry := record.OriginalFoundationCompartments.Regions[index].ActorReads
	if entry.Pending == nil || !sameOriginalSourceValue(entry.Provenance.Create, *entry.Pending) || f.readsTokens[entry.Pending.Request.RetryToken] != id {
		f.cloud.test.Error("GetPolicy lost actual response/reservation provenance")
	}
	f.readsGets[id]++
	row := maps.Clone(f.readsRows[id])
	if index == f.readsSlot {
		switch f.readsFault {
		case "policy missing":
			originalCompartmentFailure(w, 404, "NotAuthorizedOrNotFound")
			return
		case "policy pending":
			row["lifecycleState"] = "CREATING"
		case "policy identity":
			row["id"] = "ocid1.policy.oc1..foreign"
		case "policy compartment":
			row["compartmentId"] = record.SharedCompartmentID
		case "policy name":
			row["name"] = "foreign"
		case "policy description":
			row["description"] = "foreign"
		case "policy extra statement":
			row["statements"] = append(slices.Clone(row["statements"].([]any)), "Allow any-user to manage all-resources in tenancy")
		case "policy object write":
			row["statements"] = []any{strings.Replace(row["statements"].([]any)[0].(string), "OBJECT_READ", "OBJECT_CREATE", 1)}
		case "policy tags":
			row["freeformTags"] = map[string]any{"foreign": "value"}
		case "policy defined tags":
			row["definedTags"] = map[string]any{"foreign": map[string]any{"value": "foreign"}}
		}
	}
	json.MarshalWrite(w, row)
}

func (f *originalActorReadsSDKFixture) readDispatches() []originalActorReadDispatch {
	f.readsMu.Lock()
	defer f.readsMu.Unlock()
	return slices.Clone(f.readsPosts)
}

func (f *originalActorReadsSDKFixture) assertReadsState(t *testing.T) {
	t.Helper()
	f.assertActorState(t)
	record := f.record(t)
	if err := record.validateOriginalFoundationActorReads(); err != nil {
		t.Fatal(err)
	}
	pins, err := originalActorReadsUpstream(record)
	if err != nil || !bytes.Equal(pins, f.readsUpstream) || len(f.wire(t)) > foundationJournalLimit {
		t.Fatal("READ progress replaced immutable original prerequisites or exceeded protected record bound")
	}
	seen := map[string]bool{}
	for index, region := range record.OriginalFoundationCompartments.Regions {
		entry := region.ActorReads
		if entry == nil || entry.Pending == nil || entry.Provenance == nil || entry.VerifiedAt.IsZero() || entry.ReadbackSHA256 == "" || entry.HoldReason != "" || seen[entry.Provenance.ResourceID] {
			t.Fatal("public READ lacks three unique actual policy IDs and acknowledged independent exact readbacks")
		}
		seen[entry.Provenance.ResourceID] = true
		if !sameOriginalSourceValue(entry.Provenance.Create, *entry.Pending) || f.readsGets[entry.Provenance.ResourceID] == 0 {
			t.Fatal("public READ completion lost SDK/CAS provenance")
		}
		expected, origin, key, identitySHA := f.expectedReadPolicy(record, index)
		if deref(entry.Request.Name) != expected["name"] || entry.Origin != origin || entry.ObjectKey != key || entry.IdentitySHA256 != identitySHA {
			t.Fatal("public READ completion changed exact original recipient/document")
		}
	}
}

func testOriginalFoundationActorReadsSDK(t *testing.T, part *originalSubtestPart) {
	tier.Integration(t)
	shared := newOriginalActorReadsSDKFixture(t, "", 0)
	// Every subtest starts after the genuine actor stage it does not exercise.
	if err := shared.originalActorSDKFixture.run(t); err != nil {
		t.Fatal(err)
	}
	state := snapshotOriginalFixture(t, shared)
	sharedFixture := func(t *testing.T, fault string, slot int) *originalActorReadsSDKFixture {
		t.Helper()
		state.restore(t)
		shared.readsFault, shared.readsSlot = fault, slot
		return shared
	}
	// Sequential: inherited fixtures own the process transport and signed roots.
	part.run(t, "three finite exact READ policies retain downstream HOLD and replay GET only", func(t *testing.T) {
		f := sharedFixture(t, "", 0)
		if err := f.run(t); err != nil {
			network, rules := f.effects()
			t.Fatalf("automatic coordinator did not retain explicit host-entry/custody/source/archive HOLD (compartments=%d network=%d NSG-adds=%d KMS=%d actors=%d READs=%d creates=%d launches=%d): %v", len(f.dispatches()), len(network), rules, len(f.kmsDispatches()), len(f.actorDispatches()), len(f.readDispatches()), f.cloud.creates, f.cloud.launchPosts, err)
		}
		posts := f.readDispatches()
		network, rules := f.effects()
		if len(posts) != 3 || len(f.actorDispatches()) != 3 || len(f.dispatches()) != 5 || len(network) != 18 || len(f.kmsDispatches()) != 4 || rules != 3 || f.cloud.creates != 33 || f.cloud.launchPosts != 3 {
			t.Fatal("READ continuation changed finite5 compartments+18network+4KMS+3actors+3policies or3NSG adds")
		}
		for index, post := range posts {
			if post.cell != []string{"GRU", "SJC", "FRA"}[index] {
				t.Fatal("public READ policy order escaped finite original cells")
			}
		}
		f.assertReadsState(t)
		before, material := f.wire(t), f.cloud.materialPosts
		gets := maps.Clone(f.readsGets)
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, f.wire(t)) || len(f.readDispatches()) != 3 || f.cloud.creates != 33 || f.cloud.materialPosts != material || f.cloud.launchPosts != 3 {
			t.Fatal("known policy replay changed history or repeated a create/material/launch")
		}
		for id, count := range gets {
			if f.readsGets[id] <= count {
				t.Fatal("known actual policy ID was not independently re-read")
			}
		}
		f.assertReadsState(t)
		var compressed bytes.Buffer
		writer := gzip.NewWriter(&compressed)
		if _, err := writer.Write(f.publicBundle); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		t.Logf("public canonical bundle sha256=%s bytes=%d gzip_bytes=%d gzip_base64_bytes=%d", preparationDigest(f.publicBundle), len(f.publicBundle), compressed.Len(), base64.StdEncoding.EncodedLen(compressed.Len()))
	})

	part.run(t, "durable reservations actual IDs and readbacks bound recovery", func(t *testing.T) {
		for slot := range 3 {
			for _, fault := range []string{"scope checkpoint", "reservation checkpoint", "stale lease", "unknown create", "lost create response", "response before CAS", "lost accepted checkpoint", "readback checkpoint", "lost readback checkpoint", "throttle", "timeout"} {
				part.run(t, fmt.Sprintf("%d/%s", slot, fault), func(t *testing.T) {
					f := sharedFixture(t, fault, slot)
					if err := f.run(t); err == nil {
						t.Fatal("interrupted READ operation reached downstream completion HOLD")
					}
					f.assertActorState(t)
					first, record := f.readDispatches(), f.record(t)
					entry := record.OriginalFoundationCompartments.Regions[slot].ActorReads
					if fault == "scope checkpoint" {
						if len(first) != 0 || f.cloud.creates != 30 {
							t.Fatal("unacknowledged READ scopes authorized policy create")
						}
						for _, region := range record.OriginalFoundationCompartments.Regions {
							if region.ActorReads != nil {
								t.Fatal("failed initial READ scopes checkpoint retained partial scopes")
							}
						}
					} else if fault == "reservation checkpoint" || fault == "stale lease" {
						if entry == nil || len(first) != slot || fault == "reservation checkpoint" && entry.Pending != nil || fault == "stale lease" && entry.Pending == nil {
							t.Fatal("policy escaped acknowledged reservation/live HomeWrite or fault lost durable state")
						}
					} else {
						if entry == nil || entry.Pending == nil || len(first) != slot+1 {
							t.Fatal("interrupted READ lost immutable request/token/first time or retried within same invocation")
						}
						id := "ocid1.policy.oc1..originalactorread" + strings.ToLower(record.OriginalFoundationCompartments.Regions[slot].Cell)
						if fault == "response before CAS" && entry.Provenance != nil || fault == "lost accepted checkpoint" && entry.Provenance == nil {
							t.Fatal("actual policy-ID CAS fault modeled wrong durable result")
						}
						if slices.Contains([]string{"response before CAS", "lost accepted checkpoint", "lost create response", "unknown create", "throttle", "timeout"}, fault) && f.readsGets[id] != 0 {
							t.Fatal("GetPolicy followed unacknowledged or absent actual-ID result")
						}
						if fault == "readback checkpoint" && !entry.VerifiedAt.IsZero() || fault == "lost readback checkpoint" && entry.VerifiedAt.IsZero() {
							t.Fatal("readback CAS fault modeled wrong durable proof")
						}
					}
					f.readsMu.Lock()
					f.readsFault = ""
					f.readsMu.Unlock()
					if err := f.run(t); err != nil {
						t.Fatalf("exact retained READ did not recover: %v", err)
					}
					after := f.readDispatches()
					replay := slices.Contains([]string{"unknown create", "lost create response", "response before CAS", "throttle", "timeout"}, fault)
					want := 3
					if replay {
						want++
						if !bytes.Equal(first[slot].body, after[slot+1].body) || first[slot].token != after[slot+1].token || !sameOriginalSourceValue(first[slot].pending, after[slot+1].pending) {
							t.Fatal("unknown response replay replaced body/token/original first-attempt time")
						}
					}
					if len(after) != want || f.cloud.creates != 33 || f.cloud.launchPosts != 3 {
						t.Fatal("recovery repeated known-ID create, lost a finite policy or relaunched an actor")
					}
					f.assertReadsState(t)
				})
			}
		}
	})

	part.run(t, "genuine historical unknown policy exceeds23h without replacement", func(t *testing.T) {
		f := newOriginalActorReadsSDKFixture(t, "unknown create", 0)
		f.bundle = signHistoricalOriginalCompartmentBundle(t, f.foundationProvisionFixture)
		f.cloud.bundle = f.bundle.clone()
		var err error
		f.publicBundle, err = json.Marshal(f.bundle, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyFoundationProvisionBundle(t.Context(), f.roots, f.bundle); err != nil {
			t.Fatal(err)
		}
		if err := f.run(t); err == nil || len(f.readDispatches()) != 1 {
			t.Fatal("historical READ setup did not retain one unknown actual policy result")
		}
		record := f.record(t)
		originalVaultAgeTimeline(t, &record)
		for index := range record.OriginalFoundationCompartments.Regions {
			region := &record.OriginalFoundationCompartments.Regions[index]
			actor := region.Actor
			network, err := json.Marshal(region.Network, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			vault, err := json.Marshal(region.Vault, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			actor.NetworkProofSHA256, actor.VaultProofSHA256 = preparationDigest(network), preparationDigest(vault)
			actor.Pending.FirstAttemptAt = actor.Pending.FirstAttemptAt.Add(-24 * time.Hour)
			actor.Provenance.Create = *actor.Pending
			actor.OriginalQuote.IssuedAt = actor.OriginalQuote.IssuedAt.Add(-24 * time.Hour)
			actor.OriginalQuote.ExpiresAt = actor.OriginalQuote.ExpiresAt.Add(-24 * time.Hour)
			actor.VerifiedAt = actor.VerifiedAt.Add(-24 * time.Hour)
			if region.ActorReads.Pending != nil {
				region.ActorReads.Pending.FirstAttemptAt = region.ActorReads.Pending.FirstAttemptAt.Add(-24 * time.Hour)
			}
		}
		if err := record.validate(); err != nil {
			t.Fatalf("historical READ timeline is not otherwise valid: %v", err)
		}
		entry := record.OriginalFoundationCompartments.Regions[0].ActorReads
		if entry.Pending == nil || !entry.Pending.FirstAttemptAt.Before(time.Now().Add(-23*time.Hour)) || !time.Now().Before(record.OriginalFoundationCompartments.Regions[0].Actor.Startup.FounderResources.LaunchDeadline) {
			t.Fatal("READ retry expiry lacks old actual attempt and current signed launch deadline")
		}
		wire, err := json.Marshal(record, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		// Model an otherwise valid historical provider journal, not a protected CAS rewrite.
		f.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", wire)
		f.upstream, err = originalNetworkUpstream(record)
		if err != nil {
			t.Fatal(err)
		}
		f.vaultUpstream, err = originalVaultUpstream(record)
		if err != nil {
			t.Fatal(err)
		}
		f.actorUpstream, err = originalActorUpstream(record)
		if err != nil {
			t.Fatal(err)
		}
		f.readsUpstream, err = originalActorReadsUpstream(record)
		if err != nil {
			t.Fatal(err)
		}
		creates, material := f.cloud.creates, f.cloud.materialPosts
		if err := f.run(t); !errors.Is(err, ErrOriginalSourceProducerHold) {
			t.Fatalf("expired unknown READ did not retain explicit retry HOLD: %v", err)
		}
		retained := f.record(t)
		entry.HoldReason = "retry-expired"
		record.UpdatedAt = retained.UpdatedAt
		if !sameOriginalSourceValue(record, retained) {
			t.Fatal("READ retry expiry changed history beyond monotone HOLD and checkpoint time")
		}
		before := f.wire(t)
		if err := f.run(t); !errors.Is(err, ErrOriginalSourceProducerHold) || !bytes.Equal(before, f.wire(t)) || len(f.readDispatches()) != 1 || f.cloud.creates != creates || f.cloud.materialPosts != material || f.cloud.launchPosts != 3 {
			t.Fatal("expired unknown READ reset token/time, replaced policy or repeated upstream effects")
		}
	})

	part.run(t, "definite refusal and invalid actual IDs retain permanent HOLD", func(t *testing.T) {
		for slot := range 3 {
			for _, fault := range []string{"conflict", "bad request", "empty ID", "wrong kind ID", "duplicate ID"} {
				if slot == 0 && fault == "duplicate ID" {
					continue
				}
				part.run(t, fmt.Sprintf("%d/%s", slot, fault), func(t *testing.T) {
					f := sharedFixture(t, fault, slot)
					if err := f.run(t); err == nil {
						t.Fatal("invalid/refused original policy acquired accepted readback")
					}
					entry := f.record(t).OriginalFoundationCompartments.Regions[slot].ActorReads
					if entry == nil || entry.Pending == nil || entry.Provenance != nil || entry.HoldReason == "" || !entry.VerifiedAt.IsZero() || len(f.readDispatches()) != slot+1 {
						t.Fatal("refusal lost reservation or accepted malformed actual identity")
					}
					before, posts, creates := f.wire(t), len(f.readDispatches()), f.cloud.creates
					if err := f.run(t); err == nil || !bytes.Equal(before, f.wire(t)) || len(f.readDispatches()) != posts || f.cloud.creates != creates {
						t.Fatal("terminal policy HOLD changed history or created another policy")
					}
					store := f.store(t)
					record, etag, err := store.Load(t.Context(), "GRU")
					if err != nil {
						t.Fatal(err)
					}
					record.OriginalFoundationCompartments.Regions[slot].ActorReads.HoldReason = ""
					if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(before, f.wire(t)) {
						t.Fatal("protected store erased terminal policy HOLD")
					}
				})
			}
		}
	})

	part.run(t, "known IDs never adopt repair or recreate conflicting policies", func(t *testing.T) {
		for _, fault := range []string{"policy missing", "policy pending", "policy identity", "policy compartment", "policy name", "policy description", "policy extra statement", "policy object write", "policy tags", "policy defined tags"} {
			part.run(t, fault, func(t *testing.T) {
				f := sharedFixture(t, fault, 0)
				if err := f.run(t); err == nil {
					t.Fatal("conflicting/missing exact GetPolicy accepted original public READ")
				}
				entry := f.record(t).OriginalFoundationCompartments.Regions[0].ActorReads
				if entry == nil || entry.Provenance == nil || entry.HoldReason == "" || !entry.VerifiedAt.IsZero() || len(f.readDispatches()) != 1 || f.readsGets[entry.Provenance.ResourceID] != 1 {
					t.Fatal("policy conflict lost actual ID or failed independent exact readback")
				}
				before, creates := f.wire(t), f.cloud.creates
				if err := f.run(t); err == nil || !bytes.Equal(before, f.wire(t)) || len(f.readDispatches()) != 1 || f.cloud.creates != creates {
					t.Fatal("known policy conflict reset history or adopted/recreated another policy")
				}
			})
		}
	})

	part.run(t, "exact document bucket and current physical identity precede any READ reservation", func(t *testing.T) {
		for _, fault := range []string{"namespace", "bucket identity", "bucket compartment", "bucket KMS", "bucket namespace", "bucket name", "document missing", "document bytes", "document oversized"} {
			part.run(t, fault, func(t *testing.T) {
				f := sharedFixture(t, fault, 0)
				if err := f.run(t); err == nil || len(f.readDispatches()) != 0 || f.cloud.creates != 30 {
					t.Fatal("foreign/missing public original storage acquired policy creation")
				}
				for _, region := range f.record(t).OriginalFoundationCompartments.Regions {
					if region.ActorReads != nil {
						t.Fatal("failed exact document prerequisites reserved a READ scope")
					}
				}
			})
		}
		for _, actorFault := range []string{"instance identity", "instance image", "instance missing", "VNIC public", "boot image"} {
			part.run(t, actorFault, func(t *testing.T) {
				f := newOriginalActorReadsSDKFixture(t, "scope checkpoint", 0)
				if err := f.run(t); err == nil || len(f.readDispatches()) != 0 {
					t.Fatal("current physical refusal setup did not stop before READ scope retention")
				}
				f.assertActorState(t)
				before := f.wire(t)
				f.actorMu.Lock()
				f.actorFault, f.actorSlot = actorFault, 0
				f.actorMu.Unlock()
				f.readsFault = ""
				if err := f.run(t); err == nil || !bytes.Equal(before, f.wire(t)) || len(f.readDispatches()) != 0 || f.cloud.creates != 30 {
					t.Fatal("stale actual physical proof acquired READ despite fresh independent SDK drift")
				}
			})
		}
	})

	part.run(t, "changed original authority cannot acquire public READ effects", func(t *testing.T) {
		for _, fault := range []string{"wrong user", "wrong tenancy", "expired original", "corrupt original"} {
			part.run(t, fault, func(t *testing.T) {
				f := newOriginalActorReadsSDKFixture(t, "scope checkpoint", 0)
				if err := f.run(t); err == nil || len(f.readDispatches()) != 0 || f.cloud.creates != 30 {
					t.Fatal("authority control lacks complete genuine actors before READ scopes")
				}
				f.assertActorState(t)
				before, material := f.wire(t), f.cloud.materialPosts
				var err error
				if fault == "wrong user" || fault == "wrong tenancy" {
					provider := originalCompartmentProvider{ConfigurationProvider: f.provider, user: "ocid1.user.oc1..test", tenancy: f.approval.TenancyID}
					if fault == "wrong user" {
						provider.user = "ocid1.user.oc1..foreign"
					} else {
						provider.tenancy = "ocid1.tenancy.oc1..foreign"
					}
					factory, factoryErr := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
					if factoryErr != nil {
						t.Fatal(factoryErr)
					}
					err = provisionOriginalFoundationCompartments(t.Context(), factory, f.roots, f.bundle)
				} else {
					if fault == "expired original" {
						f.bundle = signProvisionFoundation(t, f.prepared, f.bundle.RootChainWire, f.root, f.now.Add(-24*time.Hour))
					} else {
						f.bundle.GrantWire = []byte("invalid root-pinned original")
					}
					err = f.run(t)
				}
				if err == nil || !bytes.Equal(before, f.wire(t)) || len(f.readDispatches()) != 0 || f.cloud.creates != 30 || f.cloud.launchPosts != 3 || f.cloud.materialPosts != material {
					t.Fatalf("foreign/expired/corrupt original progressed READ or upstream effects: %v", err)
				}
			})
		}
	})

	part.run(t, "protected CAS retains every original READ binding and effect", func(t *testing.T) {
		f := sharedFixture(t, "", 0)
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		store, before := f.store(t), f.wire(t)
		for name, mutate := range map[string]func(*OriginalFoundationActorReads){
			"grant":          func(e *OriginalFoundationActorReads) { e.GrantSHA256 = strings.Repeat("a", 64) },
			"bundle":         func(e *OriginalFoundationActorReads) { e.BundleSHA256 = strings.Repeat("a", 64) },
			"actor":          func(e *OriginalFoundationActorReads) { e.ActorID = "ocid1.instance.oc1.sa-saopaulo-1.foreign" },
			"actor request":  func(e *OriginalFoundationActorReads) { e.ActorRequestSHA256 = strings.Repeat("a", 64) },
			"actor proof":    func(e *OriginalFoundationActorReads) { e.ActorReadbackSHA256 = strings.Repeat("a", 64) },
			"release":        func(e *OriginalFoundationActorReads) { e.ReleaseAuthoritySHA256 = strings.Repeat("a", 64) },
			"origin role":    func(e *OriginalFoundationActorReads) { e.Origin.Role = "terrabase" },
			"object":         func(e *OriginalFoundationActorReads) { e.ObjectKey += "foreign" },
			"bucket":         func(e *OriginalFoundationActorReads) { e.BucketID = "ocid1.bucket.oc1.sa-saopaulo-1.foreign" },
			"compartment":    func(e *OriginalFoundationActorReads) { e.BucketCompartmentID = "ocid1.compartment.oc1..foreign" },
			"KMS":            func(e *OriginalFoundationActorReads) { e.KMSKeyID = "ocid1.key.oc1.sa-saopaulo-1.foreign" },
			"length":         func(e *OriginalFoundationActorReads) { e.BundleBytes++ },
			"document proof": func(e *OriginalFoundationActorReads) { e.DocumentReadbackSHA256 = strings.Repeat("a", 64) },
			"identity":       func(e *OriginalFoundationActorReads) { e.IdentitySHA256 = strings.Repeat("a", 64) },
			"statement": func(e *OriginalFoundationActorReads) {
				e.Request.Statements[0] = "Allow any-user to manage all-resources in tenancy"
			},
			"pending": func(e *OriginalFoundationActorReads) { e.Pending = nil },
			"token":   func(e *OriginalFoundationActorReads) { e.Pending.Request.RetryToken += "foreign" },
			"first time": func(e *OriginalFoundationActorReads) {
				e.Pending.FirstAttemptAt = e.Pending.FirstAttemptAt.Add(time.Second)
			},
			"result":        func(e *OriginalFoundationActorReads) { e.Provenance.ResourceID = "ocid1.policy.oc1..foreign" },
			"erase result":  func(e *OriginalFoundationActorReads) { e.Provenance = nil },
			"readback":      func(e *OriginalFoundationActorReads) { e.ReadbackSHA256 = strings.Repeat("a", 64) },
			"verified time": func(e *OriginalFoundationActorReads) { e.VerifiedAt = e.VerifiedAt.Add(-time.Second) },
		} {
			part.run(t, name, func(t *testing.T) {
				record, etag, err := store.Load(t.Context(), "GRU")
				if err != nil {
					t.Fatal(err)
				}
				mutate(record.OriginalFoundationCompartments.Regions[0].ActorReads)
				if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(before, f.wire(t)) {
					t.Fatal("protected store replaced or removed original public READ history")
				}
			})
		}
		for _, erase := range []string{"one scope", "all scopes", "all upstream"} {
			part.run(t, erase, func(t *testing.T) {
				record, etag, err := store.Load(t.Context(), "GRU")
				if err != nil {
					t.Fatal(err)
				}
				switch erase {
				case "one scope":
					record.OriginalFoundationCompartments.Regions[0].ActorReads = nil
				case "all scopes":
					for index := range record.OriginalFoundationCompartments.Regions {
						record.OriginalFoundationCompartments.Regions[index].ActorReads = nil
					}
				case "all upstream":
					record.OriginalFoundationCompartments = nil
				}
				if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(before, f.wire(t)) {
					t.Fatal("protected store erased original READ scope or its prerequisites")
				}
			})
		}
	})

	part.run(t, "direct component requires the same live HomeWrite and rejects incomplete actors", func(t *testing.T) {
		f := newOriginalActorReadsSDKFixture(t, "scope checkpoint", 0)
		if err := f.run(t); err == nil || len(f.readDispatches()) != 0 {
			t.Fatal("lease test setup did not reach all-three actual actors before READ reservation")
		}
		f.assertActorState(t)
		stage, err := provisionFoundationMaterial(t.Context(), f.factoryFor(), f.roots, f.bundle)
		if err != nil {
			t.Fatal(err)
		}
		defer stage.cancel()
		before := f.wire(t)
		canceled, cancel := context.WithCancel(stage.ctx)
		cancel()
		if _, err := originalCompartmentScope(canceled, stage.authority); !errors.Is(err, context.Canceled) || !bytes.Equal(before, f.wire(t)) || len(f.readDispatches()) != 0 {
			t.Fatal("original scope accepted canceled authority or changed protected history")
		}
		reader := stage.authority.resolver.Footprint.(*SignedFootprint)
		if !bytes.Equal(reader.retainedGrant, f.bundle.GrantWire) {
			t.Fatal("original scope fixture lacks the exact retained grant")
		}
		if _, err := originalCompartmentScope(stage.ctx, stage.authority); err != nil {
			t.Fatal(err)
		}
		grantObject := strings.TrimSuffix(reader.storage.Prefix, "/") + "/" + foundationGrantObject
		if _, err := os.Stat(f.cloud.objectPath("gru-1-head/" + grantObject)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("non-retained scope control requires absent provider grant")
		}
		retained := reader.retainedGrant
		reader.retainedGrant = nil
		_, err = originalCompartmentScope(stage.ctx, stage.authority)
		reader.retainedGrant = retained
		if !errors.Is(err, ErrFoundationGrantPending) || !bytes.Equal(before, f.wire(t)) || len(f.readDispatches()) != 0 {
			t.Fatal("non-retained original scope bypassed provider grant refusal or changed protected history")
		}
		if err := retainOriginalFoundationActorReads(stage.ctx, stage.authority); err == nil || !bytes.Equal(before, f.wire(t)) || len(f.readDispatches()) != 0 {
			t.Fatal("direct READ component accepted absent HomeWrite lease")
		}
		other, err := provisionFoundationMaterial(t.Context(), f.factoryFor(), f.roots, f.bundle)
		if err != nil {
			t.Fatal(err)
		}
		defer other.cancel()
		ctx, releaseLease, err := stage.authority.HomeWrite(stage.ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := retainOriginalFoundationActorReads(ctx, other.authority); err == nil || !bytes.Equal(before, f.wire(t)) || len(f.readDispatches()) != 0 {
			releaseLease()
			t.Fatal("direct READ component accepted another genuine authority's live HomeWrite")
		}
		releaseLease()
		if err := retainOriginalFoundationActorReads(ctx, stage.authority); err == nil || !bytes.Equal(before, f.wire(t)) || len(f.readDispatches()) != 0 {
			t.Fatal("direct READ component accepted released HomeWrite")
		}
		record := f.record(t)
		for _, mutate := range []func(*FoundationRecord){
			func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[2].Actor.Provenance = nil },
			func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[2].Actor.VerifiedAt = time.Time{} },
			func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[2].Actor.ReadbackSHA256 = "" },
		} {
			wire, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			var changed FoundationRecord
			if err := json.Unmarshal(wire, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := originalActorReadsActors(changed); err == nil {
				t.Fatal("READ actor prerequisite accepted an incomplete actual identity/physical proof")
			}
		}
	})

	part.run(t, "full signed public selection rejects missing duplicate or foreign origins", func(t *testing.T) {
		f := newOriginalActorReadsSDKFixture(t, "scope checkpoint", 0)
		if err := f.run(t); err == nil || len(f.readDispatches()) != 0 {
			t.Fatal("selection controls lack genuine complete actors")
		}
		f.assertActorState(t)
		if err := ValidateContainerReleaseAuthorities(f.prepared.Grant, f.roots, f.approval.HomeStorageDomain, time.Now()); err != nil {
			t.Fatalf("unchanged genuine signed release scope is invalid: %v", err)
		}
		record := f.record(t)
		if _, _, err := originalActorReadOrigin(record, 0, f.prepared.Grant); err != nil {
			t.Fatalf("unchanged genuine original origin is invalid: %v", err)
		}
		for name, mutate := range map[string]func(*FoundationGrant){
			"missing release": func(g *FoundationGrant) { g.ReleaseAuthorities = nil },
			"foreign release cell": func(g *FoundationGrant) {
				for i := range g.ReleaseAuthorities {
					if g.ReleaseAuthorities[i].Role == "ts-auth" {
						g.ReleaseAuthorities[i].Cells = []string{"SJC", "FRA"}
					}
				}
			},
			"duplicate release": func(g *FoundationGrant) {
				for _, a := range g.ReleaseAuthorities {
					if a.Role == "ts-auth" {
						g.ReleaseAuthorities = append(g.ReleaseAuthorities, a)
						break
					}
				}
			},
			"missing origin": func(g *FoundationGrant) {
				g.WorkloadGenesis = slices.DeleteFunc(g.WorkloadGenesis, func(o release.WorkloadGenesis) bool { return o.Cell == "GRU" && o.Role == "ts-auth" })
			},
			"duplicate origin": func(g *FoundationGrant) {
				for _, o := range g.WorkloadGenesis {
					if o.Cell == "GRU" && o.Role == "ts-auth" {
						g.WorkloadGenesis = append(g.WorkloadGenesis, o)
						break
					}
				}
			},
			"foreign origin": func(g *FoundationGrant) {
				for i := range g.WorkloadGenesis {
					if g.WorkloadGenesis[i].Cell == "GRU" && g.WorkloadGenesis[i].Role == "ts-auth" {
						g.WorkloadGenesis[i].Namespace = "foreign"
					}
				}
			},
		} {
			part.run(t, name, func(t *testing.T) {
				wire, err := json.Marshal(f.prepared.Grant)
				if err != nil {
					t.Fatal(err)
				}
				var changed FoundationGrant
				if err := json.Unmarshal(wire, &changed); err != nil {
					t.Fatal(err)
				}
				mutate(&changed)
				_, _, releaseErr := originalActorReadRelease(changed, "GRU")
				_, _, originErr := originalActorReadOrigin(record, 0, changed)
				if releaseErr == nil && originErr == nil {
					t.Fatal("direct selection accepted missing/duplicate/foreign signed public scope")
				}
				before, material := f.wire(t), f.cloud.materialPosts
				preparation := f.prepared
				preparation.Grant = changed
				bundle := signProvisionFoundation(t, preparation, f.bundle.RootChainWire, f.root, f.now)
				if err := provisionOriginalFoundationCompartments(t.Context(), f.factoryFor(), f.roots, bundle); err == nil || !bytes.Equal(before, f.wire(t)) || len(f.readDispatches()) != 0 || f.cloud.creates != 30 || f.cloud.launchPosts != 3 || f.cloud.materialPosts != material {
					t.Fatal("changed full root-signed original acquired READ or upstream effects")
				}
			})
		}
	})
}

func TestOriginalFoundationActorReadsSDKPart1(t *testing.T) {
	testOriginalFoundationActorReadsSDK(t, newOriginalSubtestPart(1, 8, "durable reservations actual IDs and readbacks bound recovery", "definite refusal and invalid actual IDs retain permanent HOLD", "known IDs never adopt repair or recreate conflicting policies", "exact document bucket and current physical identity precede any READ reservation", "changed original authority cannot acquire public READ effects"))
}

func TestOriginalFoundationActorReadsSDKPart2(t *testing.T) {
	testOriginalFoundationActorReadsSDK(t, newOriginalSubtestPart(2, 8, "durable reservations actual IDs and readbacks bound recovery", "definite refusal and invalid actual IDs retain permanent HOLD", "known IDs never adopt repair or recreate conflicting policies", "exact document bucket and current physical identity precede any READ reservation", "changed original authority cannot acquire public READ effects"))
}

func TestOriginalFoundationActorReadsSDKPart3(t *testing.T) {
	testOriginalFoundationActorReadsSDK(t, newOriginalSubtestPart(3, 8, "durable reservations actual IDs and readbacks bound recovery", "definite refusal and invalid actual IDs retain permanent HOLD", "known IDs never adopt repair or recreate conflicting policies", "exact document bucket and current physical identity precede any READ reservation", "changed original authority cannot acquire public READ effects"))
}

func TestOriginalFoundationActorReadsSDKPart4(t *testing.T) {
	testOriginalFoundationActorReadsSDK(t, newOriginalSubtestPart(4, 8, "durable reservations actual IDs and readbacks bound recovery", "definite refusal and invalid actual IDs retain permanent HOLD", "known IDs never adopt repair or recreate conflicting policies", "exact document bucket and current physical identity precede any READ reservation", "changed original authority cannot acquire public READ effects"))
}

func TestOriginalFoundationActorReadsSDKPart5(t *testing.T) {
	testOriginalFoundationActorReadsSDK(t, newOriginalSubtestPart(5, 8, "durable reservations actual IDs and readbacks bound recovery", "definite refusal and invalid actual IDs retain permanent HOLD", "known IDs never adopt repair or recreate conflicting policies", "exact document bucket and current physical identity precede any READ reservation", "changed original authority cannot acquire public READ effects"))
}

func TestOriginalFoundationActorReadsSDKPart6(t *testing.T) {
	testOriginalFoundationActorReadsSDK(t, newOriginalSubtestPart(6, 8, "durable reservations actual IDs and readbacks bound recovery", "definite refusal and invalid actual IDs retain permanent HOLD", "known IDs never adopt repair or recreate conflicting policies", "exact document bucket and current physical identity precede any READ reservation", "changed original authority cannot acquire public READ effects"))
}

func TestOriginalFoundationActorReadsSDKPart7(t *testing.T) {
	testOriginalFoundationActorReadsSDK(t, newOriginalSubtestPart(7, 8, "durable reservations actual IDs and readbacks bound recovery", "definite refusal and invalid actual IDs retain permanent HOLD", "known IDs never adopt repair or recreate conflicting policies", "exact document bucket and current physical identity precede any READ reservation", "changed original authority cannot acquire public READ effects"))
}

func TestOriginalFoundationActorReadsSDKPart8(t *testing.T) {
	testOriginalFoundationActorReadsSDK(t, newOriginalSubtestPart(8, 8, "durable reservations actual IDs and readbacks bound recovery", "definite refusal and invalid actual IDs retain permanent HOLD", "known IDs never adopt repair or recreate conflicting policies", "exact document bucket and current physical identity precede any READ reservation", "changed original authority cannot acquire public READ effects"))
}
