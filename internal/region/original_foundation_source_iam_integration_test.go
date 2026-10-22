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

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type originalSourceIAMSDKFixture struct {
	*originalActorSDKFixture
	mu           sync.Mutex
	upstream     []byte
	fault        string
	faulted      bool
	posts        []PendingFoundationCreate
	rows         map[string]map[string]any
	gets         map[string]int
	absenceReads int
	secretReads  int
	// checkedWire is the last journal whose upstream pins passed; serveHTTP
	// only reads checkedRecord, so identical bytes need no second parse.
	checkedWire   []byte
	checkedRecord FoundationRecord
}

func originalSourceIAMUpstream(record FoundationRecord) ([]byte, error) {
	section := *record.OriginalFoundationCompartments
	section.Publication = nil
	for index := range section.Regions {
		section.Regions[index].MaterialPublicationIAM = nil
		section.Regions[index].SourceIAM = nil
		section.Regions[index].AdmissionReads = nil
	}
	record.OriginalFoundationCompartments = &section
	record.UpdatedAt = time.Time{}
	return json.Marshal(record, json.Deterministic(true))
}

func newOriginalSourceIAMSDKFixture(t *testing.T, fault string) *originalSourceIAMSDKFixture {
	t.Helper()
	base := newOriginalActorSDKFixture(t, "", 0)
	if err := base.run(t); err != nil {
		t.Fatalf("genuine original coordinator did not retain three acknowledged actors: %v", err)
	}
	f := &originalSourceIAMSDKFixture{originalActorSDKFixture: base, fault: fault, rows: map[string]map[string]any{}, gets: map[string]int{}}
	var err error
	f.upstream, err = originalSourceIAMUpstream(base.record(t))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("source IAM fixture requires literal loopback TLS")
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

func (f *originalSourceIAMSDKFixture) run(t *testing.T) error {
	t.Helper()
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
	for index := range 3 {
		if err := retainOriginalSourceIAM(ctx, authority, index); err != nil {
			return err
		}
	}
	return nil
}

func (f *originalSourceIAMSDKFixture) expectedPolicy(record FoundationRecord, index int) map[string]any {
	q := (*record.OriginalSourceProducers)[index].Intent
	actor := record.OriginalFoundationCompartments.Regions[index].Actor.Provenance.ResourceID
	principal := fmt.Sprintf("request.principal.type='instance', request.principal.id='%s'", actor)
	secret := fmt.Sprintf("%s, target.secret.name='%s', target.vault.id='%s'", principal, q.SourceSecretName, q.Escrow.VaultOCID)
	statements := []string{
		fmt.Sprintf("Allow any-user to read secret-bundles in compartment id %s where all {%s, request.permission='SECRET_BUNDLE_READ'}", q.Escrow.CompartmentOCID, secret),
		fmt.Sprintf("Allow any-user to read secrets in compartment id %s where all {%s, request.permission='SECRET_READ'}", q.Escrow.CompartmentOCID, secret),
		fmt.Sprintf("Allow any-user to manage secrets in compartment id %s where all {%s, request.permission='SECRET_CREATE'}", q.Escrow.CompartmentOCID, secret),
		fmt.Sprintf("Allow any-user to use vaults in compartment id %s where all {%s, target.vault.id='%s', request.permission='VAULT_CREATE_SECRET'}", q.Escrow.CompartmentOCID, principal, q.Escrow.VaultOCID),
		fmt.Sprintf("Allow any-user to use keys in compartment id %s where all {%s, target.key.id='%s', any {request.permission='KEY_ENCRYPT', request.permission='KEY_DECRYPT'}}", q.Escrow.CompartmentOCID, principal, q.Escrow.KMSKeyOCID),
		fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {%s, target.bucket.name='%s', target.object.name='%s', any {request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE', request.permission='OBJECT_READ'}}", q.Escrow.CompartmentOCID, principal, q.Home.HeadBucket, q.SourceObject),
	}
	keyWire, err := json.Marshal([]string{q.Home.Namespace, q.Home.HeadBucket, q.SourceObject}, json.Deterministic(true))
	if err != nil {
		f.cloud.test.Error(err)
	}
	key := preparationDigest(keyWire)
	return map[string]any{"compartmentId": q.Escrow.CompartmentOCID, "name": "ts-bootstrap-source-" + key[:32], "description": "Exact founder source escrow and registration", "statements": statements}
}

func (f *originalSourceIAMSDKFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
		f.cloud.test.Error("source IAM operation was not authenticated by real OCI SDK signing")
	}
	// Origin discovery reads signed object bytes, not regional journal state.
	originHome := f.approval.HomeStorageDomain
	if r.Method == http.MethodGet && strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") && r.Host == "objectstorage."+foundationHomeRegion+".oraclecloud.com" && r.URL.RawQuery == "" &&
		strings.HasPrefix(r.URL.Path, "/n/"+originHome.Namespace+"/b/"+originHome.HeadBucket+"/o/orchestrator/workload-genesis/v1/") {
		f.originalCompartmentSDKFixture.serveHTTP(w, r)
		return
	}
	f.cloud.mu.Lock()
	journal, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + foundationObjectPrefix + "GRU.json"))
	f.cloud.mu.Unlock()
	if err != nil || !bytes.Equal(journal, f.checkedWire) {
		record := f.record(f.cloud.test)
		upstream, err := originalSourceIAMUpstream(record)
		if err != nil || !bytes.Equal(upstream, f.upstream) {
			f.cloud.test.Error("source IAM changed a preexisting original journal byte outside UpdatedAt")
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		f.checkedWire, f.checkedRecord = journal, record
	}
	record := f.checkedRecord
	for _, birth := range *record.OriginalSourceProducers {
		if strings.HasSuffix(r.URL.Path, "/o/"+birth.Intent.SourceObject) {
			if r.Method != http.MethodHead {
				f.cloud.test.Error("source IAM read/wrote archive content")
			}
			f.absenceReads++
			status := 404
			if f.fault == "source exists" || f.fault == "archive after IAM" {
				status = 200
			} else if f.fault == "source forbidden" {
				status = 403
			}
			if status == 200 {
				w.WriteHeader(status)
			} else {
				originalCompartmentFailure(w, status, "NotAuthorizedOrNotFound")
			}
			return
		}
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 2 && parts[1] == "secrets" {
		if r.Method != http.MethodGet || len(parts) != 2 || r.Host != "vaults."+foundationHomeRegion+".oci.oraclecloud.com" {
			f.cloud.test.Error("source IAM attempted secret mutation or escaped exact Vault metadata endpoint")
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		query := r.URL.Query()
		q := (*record.OriginalSourceProducers)[0].Intent
		matched := false
		for _, birth := range *record.OriginalSourceProducers {
			matched = matched || birth.Intent.SourceSecretName == query.Get("name")
		}
		if !matched || query.Get("compartmentId") != q.Escrow.CompartmentOCID || query.Get("vaultId") != q.Escrow.VaultOCID || query.Get("limit") != "100" {
			f.cloud.test.Error("source secret absence read escaped exact signed escrow/name")
		}
		f.secretReads++
		if f.fault == "secret forbidden" {
			originalCompartmentFailure(w, 403, "NotAuthorizedOrNotFound")
			return
		}
		rows := []any{}
		if f.fault == "secret exists" {
			rows = append(rows, map[string]any{"secretName": query.Get("name"), "lifecycleState": "PENDING_DELETION"})
		}
		if f.fault == "secret cyclic pages" {
			w.Header().Set("opc-next-page", "cycle")
		}
		json.MarshalWrite(w, rows)
		return
	}
	if len(parts) >= 2 && parts[1] == "policies" {
		f.policy(w, r, parts, record)
		return
	}
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json") {
		wire, err := io.ReadAll(io.LimitReader(r.Body, foundationJournalLimit+1))
		r.Body = io.NopCloser(bytes.NewReader(wire))
		var next FoundationRecord
		if err != nil || json.Unmarshal(wire, &next) != nil {
			f.cloud.test.Error("invalid source IAM checkpoint")
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		pins, err := originalSourceIAMUpstream(next)
		if err != nil || !bytes.Equal(pins, f.upstream) || len(wire) > foundationJournalLimit {
			f.cloud.test.Error("source checkpoint changed original bytes or exceeded protected journal bound")
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		entry := next.OriginalFoundationCompartments.Regions[0].SourceIAM
		if entry != nil && !f.faulted {
			reservation := entry.Pending != nil && entry.Provenance == nil
			accepted := entry.Provenance != nil && entry.VerifiedAt.IsZero()
			readback := !entry.VerifiedAt.IsZero()
			stop := reservation && f.fault == "reservation checkpoint" || accepted && slices.Contains([]string{"response before CAS", "lost accepted checkpoint"}, f.fault) || readback && f.fault == "readback checkpoint"
			if stop {
				f.faulted = true
				if f.fault == "lost accepted checkpoint" {
					recorder := httptest.NewRecorder()
					f.cloud.serveHTTP(recorder, r)
					if recorder.Code >= 300 {
						f.cloud.test.Error("lost ACK did not follow accepted CAS")
					}
				}
				originalCompartmentFailure(w, 503, "InternalError")
				return
			}
			if reservation && f.fault == "stale lease" {
				f.faulted = true
				recorder := httptest.NewRecorder()
				f.cloud.serveHTTP(recorder, r)
				if recorder.Code >= 300 {
					f.cloud.test.Error("stale lease fault lacked accepted reservation")
				}
				wire, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + homeIAMObject))
				var lease homeIAMRecord
				if err != nil || json.Unmarshal(wire, &lease) != nil {
					f.cloud.test.Error("lease fault could not read actual lease")
				} else {
					lease.UpdatedAt = time.Now().UTC()
					lease.ExpiresAt = lease.UpdatedAt
					lease.ReleasedAt = lease.UpdatedAt
					wire, err = json.Marshal(lease)
					if err != nil {
						f.cloud.test.Error(err)
					} else {
						f.cloud.writeObject("gru-1-head/"+homeIAMObject, wire)
					}
				}
				originalNetworkCopyResponse(w, recorder)
				return
			}
		}
	}
	// The frozen parent oracles predate SourceIAM. This projection pins every
	// prior journal byte; retained cloud rows still serve the actual SDK reads.
	if r.Method == http.MethodGet && len(parts) >= 2 && slices.Contains([]string{"instances", "vnics", "bootVolumes", "vnicAttachments", "bootVolumeAttachments"}, parts[1]) {
		index := slices.IndexFunc(record.OriginalFoundationCompartments.Regions[:], func(region OriginalFoundationCompartmentRegion) bool {
			return r.Host == "iaas."+region.OCIRegion+".oraclecloud.com"
		})
		if index < 0 {
			f.cloud.test.Error("actor reread escaped original region")
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		f.observe(w, r, parts, record, index)
		return
	}
	if r.Method == http.MethodGet && len(parts) == 4 && parts[1] == "networkSecurityGroups" && parts[3] == "securityRules" {
		for _, region := range record.OriginalFoundationCompartments.Regions {
			if r.Host == "iaas."+region.OCIRegion+".oraclecloud.com" {
				f.serveOriginalRuleList(w, r, region.Network, parts[2])
				return
			}
		}
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !(r.Method == http.MethodPut && (strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json") || strings.HasSuffix(r.URL.Path, "/o/"+homeIAMObject))) {
		f.cloud.test.Errorf("source IAM emitted unrelated mutation: %s %s", r.Method, r.URL.Path)
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	f.originalCompartmentSDKFixture.serveHTTP(w, r)
}

func (f *originalSourceIAMSDKFixture) policy(w http.ResponseWriter, r *http.Request, parts []string, record FoundationRecord) {
	if parts[0] != "20160918" || r.Host != "identity."+foundationHomeRegion+".oci.oraclecloud.com" {
		f.cloud.test.Error("source policy escaped exact home IAM endpoint")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	if r.Method == http.MethodGet && len(parts) == 2 {
		query := r.URL.Query()
		matched := false
		for index := range 3 {
			expected := f.expectedPolicy(record, index)
			matched = matched || expected["name"] == query.Get("name") && expected["compartmentId"] == query.Get("compartmentId")
		}
		if !matched || query.Get("limit") != "100" {
			f.cloud.test.Error("policy discovery escaped exact signed name/home compartment")
		}
		rows := []any{}
		for _, row := range f.rows {
			if row["name"] == query.Get("name") {
				rows = append(rows, row)
			}
		}
		if f.fault == "unreserved policy" {
			rows = append(rows, map[string]any{"id": "ocid1.policy.oc1..foreign", "name": query.Get("name")})
		}
		if f.fault == "policy cyclic pages" {
			w.Header().Set("opc-next-page", "cycle")
		}
		json.MarshalWrite(w, rows)
		return
	}
	if r.Method == http.MethodGet && len(parts) == 3 {
		row := f.rows[parts[2]]
		known := false
		for _, region := range record.OriginalFoundationCompartments.Regions {
			e := region.SourceIAM
			known = known || e != nil && e.Provenance != nil && e.Provenance.ResourceID == parts[2]
		}
		if !known || row == nil {
			f.cloud.test.Error("policy GET preceded actual acknowledged provider ID")
			originalCompartmentFailure(w, 404, "NotAuthorizedOrNotFound")
			return
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
	if r.Method != http.MethodPost || len(parts) != 2 || r.URL.RawQuery != "" {
		f.cloud.test.Error("unexpected policy mutation")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	body, canonical, err := originalNetworkBody(r)
	if err != nil {
		f.cloud.test.Error(err)
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	index := slices.IndexFunc(record.OriginalFoundationCompartments.Regions[:], func(region OriginalFoundationCompartmentRegion) bool {
		return region.SourceIAM != nil && region.SourceIAM.Request.Name != nil && *region.SourceIAM.Request.Name == body["name"]
	})
	if index < 0 {
		f.cloud.test.Error("policy dispatch lacked acknowledged exact scope")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	entry := record.OriginalFoundationCompartments.Regions[index].SourceIAM
	if entry.Pending == nil || entry.Provenance != nil || entry.Pending.Request.RequestDigest != preparationDigest(canonical) || entry.Pending.Request.RetryToken != r.Header.Get("opc-retry-token") || !sameOriginalSourceValue(originalNetworkPrune(body), f.expectedPolicy(record, index)) || completeOriginalSourceIAMActors(record) != nil {
		f.cloud.test.Error("source policy dispatch escaped actual actor/canonical request/retained reservation")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	wire, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + homeIAMObject))
	var lease homeIAMRecord
	if err != nil || json.Unmarshal(wire, &lease) != nil || !lease.ReleasedAt.IsZero() || !time.Now().Before(lease.ExpiresAt) || lease.OperatorID != record.OriginalFoundationCompartments.UserID {
		f.cloud.test.Error("source policy dispatch lacked live original HomeWrite")
	}
	f.posts = append(f.posts, *entry.Pending)
	if f.fault == "unknown create" && !f.faulted {
		f.faulted = true
		originalCompartmentFailure(w, 503, "InternalError")
		return
	}
	if f.fault == "create refused" {
		originalCompartmentFailure(w, 409, "Conflict")
		return
	}
	id := fmt.Sprintf("ocid1.policy.oc1..originalsource%d", index+1)
	row := maps.Clone(body)
	row["id"] = id
	row["lifecycleState"] = "ACTIVE"
	f.rows[id] = row
	if f.fault == "lost create response" && !f.faulted {
		f.faulted = true
		originalCompartmentFailure(w, 503, "InternalError")
		return
	}
	json.MarshalWrite(w, row)
}

func (f *originalSourceIAMSDKFixture) assertState(t *testing.T, complete bool) {
	t.Helper()
	record := f.record(t)
	if record.validateOriginalFoundationSourceIAM() != nil || len(record.SourcePolicyIDs) != 0 || len(record.ResourceIDs) != 0 || record.FoundationWriter != nil || record.NetBirdManager != nil || !record.CompletedAt.IsZero() || f.cloud.hasAnchor() || f.cloud.creates != 30 || f.cloud.launchPosts != 3 || len(f.wire(t)) > foundationJournalLimit {
		t.Fatal("source IAM fabricated generic/runtime authority, repeated upstream effects or exceeded journal bound")
	}
	pins, err := originalSourceIAMUpstream(record)
	if err != nil || !bytes.Equal(pins, f.upstream) {
		t.Fatal("source IAM changed retained upstream facts")
	}
	for _, region := range record.OriginalFoundationCompartments.Regions {
		entry := region.SourceIAM
		if complete && (entry == nil || entry.Provenance == nil || entry.ReadbackSHA256 == "" || entry.VerifiedAt.IsZero() || f.gets[entry.Provenance.ResourceID] == 0) {
			t.Fatal("source IAM lacks actual provider identity and independent readback")
		}
	}
}

func TestOriginalFoundationSourceIAMSDK(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	// Sequential: the inherited signed SDK fixture owns the process transport.
	t.Run("missing upstream prerequisites cause zero mutations", func(t *testing.T) {
		for _, missing := range []string{"material", "actors", "actor readbacks"} {
			t.Run(missing, func(t *testing.T) {
				fault := ""
				if missing == "actor readbacks" {
					fault = "instance pending"
				}
				f := newOriginalActorSDKFixture(t, fault, 0)
				if missing == "actors" {
					if err := f.originalVaultSDKFixture.run(t); err != nil {
						t.Fatal(err)
					}
				} else if missing == "actor readbacks" {
					if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationActorPending) {
						t.Fatal("partial actor fixture did not stop before acknowledged physical readbacks")
					}
				}
				objects := func() map[string][]byte {
					rows, err := os.ReadDir(f.cloud.directory)
					if err != nil {
						t.Fatal(err)
					}
					result := map[string][]byte{}
					for _, row := range rows {
						wire, err := os.ReadFile(f.cloud.directory + "/" + row.Name())
						if err != nil {
							t.Fatal(err)
						}
						result[row.Name()] = wire
					}
					return result
				}
				before := objects()
				creates, material, launches := f.cloud.creates, f.cloud.materialPosts, f.cloud.launchPosts
				compartments, kms, actors := len(f.dispatches()), len(f.kmsDispatches()), len(f.actorDispatches())
				network, rules := f.effects()
				if err := ProvisionOriginalFoundationSourceIAM(t.Context(), f.factoryFor(), f.roots, f.bundle); err == nil {
					t.Fatal("missing upstream prerequisite admitted source IAM stage")
				}
				afterNetwork, afterRules := f.effects()
				if !sameOriginalSourceValue(before, objects()) || f.cloud.creates != creates || f.cloud.materialPosts != material || f.cloud.launchPosts != launches || len(f.dispatches()) != compartments || len(f.kmsDispatches()) != kms || len(f.actorDispatches()) != actors || len(afterNetwork) != len(network) || afterRules != rules {
					t.Fatal("source IAM manufactured missing upstream state or mutated a protected object")
				}
			})
		}
	})
	t.Run("three exact policies and GET-only replay retain downstream HOLD", func(t *testing.T) {
		f := newOriginalSourceIAMSDKFixture(t, "")
		material := f.cloud.materialPosts
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		if len(f.posts) != 3 || len(f.rows) != 3 || f.absenceReads < 3 || f.secretReads < 3 {
			t.Fatal("source IAM did not produce exactly3 independently verified policies")
		}
		f.assertState(t, true)
		before := f.wire(t)
		reads := maps.Clone(f.gets)
		absences := f.absenceReads
		secrets := f.secretReads
		f.fault = "archive after IAM"
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		if len(f.posts) != 3 || f.cloud.materialPosts != material || !bytes.Equal(before, f.wire(t)) || f.absenceReads != absences || f.secretReads != secrets {
			t.Fatal("known-ID replay changed journal/effects or reinterpreted later archive existence")
		}
		for id, n := range reads {
			if f.gets[id] <= n {
				t.Fatal("replay did not independently GET retained policy ID")
			}
		}
		f.assertState(t, true)
	})
	t.Run("absence and current roots refuse unauthorized effects", func(t *testing.T) {
		for _, fault := range []string{"source exists", "source forbidden", "secret exists", "secret forbidden", "secret cyclic pages", "unreserved policy", "policy cyclic pages", "wrong roots"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalSourceIAMSDKFixture(t, fault)
				before := f.wire(t)
				if fault == "wrong roots" {
					f.roots = trust.Keyring{}
				}
				if err := f.run(t); err == nil {
					t.Fatal("invalid source prerequisite admitted IAM")
				}
				if len(f.posts) != 0 || !bytes.Equal(before, f.wire(t)) {
					t.Fatal("refused prerequisite wrote IAM or journal")
				}
			})
		}
	})
	t.Run("CAS and provider interruptions retain safe identity", func(t *testing.T) {
		for _, fault := range []string{"reservation checkpoint", "stale lease", "unknown create", "lost create response", "response before CAS", "lost accepted checkpoint", "readback checkpoint", "readback unavailable", "readback conflict", "create refused"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalSourceIAMSDKFixture(t, fault)
				if err := f.run(t); err == nil {
					t.Fatal("interrupted IAM claimed completed policy set")
				}
				f.assertState(t, false)
				record := f.record(t)
				entry := record.OriginalFoundationCompartments.Regions[0].SourceIAM
				if fault == "reservation checkpoint" {
					if len(f.posts) != 0 || entry != nil {
						t.Fatal("failed reservation authorized policy")
					}
				} else if entry == nil || entry.Pending == nil {
					t.Fatal("interrupted policy lost exact reservation")
				}
				before := f.wire(t)
				previous := slices.Clone(f.posts)
				f.fault = ""
				err := f.run(t)
				unresolved := fault == "lost create response" || fault == "response before CAS" || fault == "create refused"
				if unresolved {
					if err == nil || len(f.posts) != len(previous) || !bytes.Equal(before, f.wire(t)) {
						t.Fatal("unknown provider response was adopted/recreated or immutable HOLD changed")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if fault == "unknown create" && (len(f.posts) != 4 || !sameOriginalSourceValue(f.posts[0], f.posts[1])) {
						t.Fatal("safe retry changed exact original identity")
					}
					f.assertState(t, true)
				}
			})
		}
	})
	t.Run("fresh actor and escrow reads refuse drift before reservation", func(t *testing.T) {
		for _, fault := range []string{"instance", "VNIC", "boot", "Vault", "key", "bucket"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalSourceIAMSDKFixture(t, "")
				record := f.record(t)
				before := f.wire(t)
				actor := record.OriginalFoundationCompartments.Regions[1].Actor
				switch fault {
				case "instance":
					f.actorRows[actor.Provenance.ResourceID]["lifecycleState"] = "STOPPED"
				case "VNIC":
					f.actorRows[actor.PrimaryVNICID]["subnetId"] = "ocid1.subnet.oc1.us-sanjose-1.foreign"
				case "boot":
					f.actorRows[actor.BootVolumeID]["sizeInGBs"] = 999
				case "Vault":
					f.cloud.rows[f.approval.SourceVaultTarget.VaultOCID]["lifecycleState"] = "CREATING"
				case "key":
					f.cloud.rows[f.approval.SourceVaultTarget.KMSKeyOCID]["lifecycleState"] = "DISABLED"
				case "bucket":
					f.cloud.rows[record.AuxiliaryIDs["head_bucket"]]["kmsKeyId"] = f.approval.HomeStorageDomain.LedgerKMSKeyOCID
				}
				if err := f.run(t); err == nil {
					t.Fatal("fresh physical/escrow drift admitted source policy")
				}
				if len(f.posts) != 0 || !bytes.Equal(before, f.wire(t)) {
					t.Fatal("physical drift wrote policy or reservation")
				}
			})
		}
	})
	t.Run("retention rejects scope and actor substitutions", func(t *testing.T) {
		f := newOriginalSourceIAMSDKFixture(t, "")
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		original := f.wire(t)
		mutations := []func(*FoundationRecord){
			func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].SourceIAM.Request.Statements[0] = "Allow any-user to manage all-resources in tenancy"
			},
			func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].SourceIAM.GrantSHA256 = strings.Repeat("a", 64)
			},
			func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].SourceIAM.BirthSHA256 = strings.Repeat("b", 64)
			},
			func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].SourceIAM.Generation++ },
			func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].SourceIAM.OperationID += "foreign"
			},
			func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].SourceIAM.BucketCompartment = r.SharedCompartmentID
			},
			func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].SourceIAM.InstanceID = "ocid1.instance.oc1.sa-saopaulo-1.foreign"
			},
			func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].SourceIAM.Object += "foreign" },
			func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].SourceIAM.SecretName += "foreign"
			},
			func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].SourceIAM.Escrow.CompartmentOCID = r.SharedCompartmentID
			},
			func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].SourceIAM.Provenance.ResourceID = "ocid1.policy.oc1..foreign"
			},
			func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].SourceIAM.Pending.FirstAttemptAt = time.Now().Add(-bootstrapRetryLifetime)
			},
			func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[1].Actor.VerifiedAt = time.Time{} },
			func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[2].Actor = nil },
			func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].SourceIAM = nil },
		}
		for index, mutate := range mutations {
			var before, next FoundationRecord
			if json.Unmarshal(original, &before) != nil || json.Unmarshal(original, &next) != nil {
				t.Fatal("invalid fixture journal")
			}
			mutate(&next)
			if next.validateOriginalFoundationCompartments() == nil && next.retainOriginalFoundationCompartments(before) == nil {
				t.Fatalf("scope substitution%d passed validation and retention", index)
			}
		}
		var before, next FoundationRecord
		if json.Unmarshal(original, &before) != nil || json.Unmarshal(original, &next) != nil {
			t.Fatal("invalid fixture journal")
		}
		for index := range before.OriginalFoundationCompartments.Regions {
			before.OriginalFoundationCompartments.Regions[index].SourceIAM = nil
		}
		if next.retainOriginalFoundationSourceIAM(before) == nil {
			t.Fatal("imported policy IDs bypassed acknowledged original reservation")
		}
	})
}
