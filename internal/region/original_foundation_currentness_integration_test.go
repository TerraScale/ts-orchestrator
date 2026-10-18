package region

import (
	"bytes"
	"context"
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
	"sync/atomic"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

type originalPublicationBoundarySigner struct {
	common.HTTPRequestSigner
	after func(*http.Request)
}

func (s originalPublicationBoundarySigner) Sign(request *http.Request) error {
	if err := s.HTTPRequestSigner.Sign(request); err != nil {
		return err
	}
	s.after(request)
	return nil
}

type originalPublicationSDKFixture struct {
	*originalAdmissionReadsSDKFixture
	publicationMu sync.Mutex
	fault         string
	faulted       bool
	puts          [2]int
	reads         [2]int
	reservations  []OriginalFoundationPublication
	completions   int
}

func newOriginalPublicationSDKFixture(t *testing.T, fault string) *originalPublicationSDKFixture {
	t.Helper()
	return originalPublicationSDKFixtureFor(t, newOriginalAdmissionReadsSDKFixture(t, "", false), fault)
}

func originalPublicationSDKFixtureFor(t *testing.T, admission *originalAdmissionReadsSDKFixture, fault string) *originalPublicationSDKFixture {
	t.Helper()
	f := &originalPublicationSDKFixture{originalAdmissionReadsSDKFixture: admission, fault: fault}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("publication fixture requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("publication fixture refuses plaintext and proxies")
	}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("publication fixture refuses network %q", network)
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	return f
}

func (f *originalPublicationSDKFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.publicationMu.Lock()
	defer f.publicationMu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
		f.cloud.test.Error("publication request lacks real OCI SDK authentication")
	}
	// Origin discovery reads signed object bytes, not regional journal state.
	originHome := f.approval.HomeStorageDomain
	if r.Method == http.MethodGet && strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") && r.Host == "objectstorage."+foundationHomeRegion+".oraclecloud.com" && r.URL.RawQuery == "" &&
		strings.HasPrefix(r.URL.Path, "/n/"+originHome.Namespace+"/b/"+originHome.HeadBucket+"/o/orchestrator/workload-genesis/v1/") {
		f.originalCompartmentSDKFixture.serveHTTP(w, r)
		return
	}
	record := f.record(f.cloud.test)
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json") {
		wire, err := io.ReadAll(io.LimitReader(r.Body, foundationJournalLimit+1))
		var next FoundationRecord
		if err != nil || json.Unmarshal(wire, &next) != nil {
			f.cloud.test.Error("publication checkpoint has invalid JSON")
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		var before, after *OriginalFoundationPublication
		if record.OriginalFoundationCompartments != nil {
			before = record.OriginalFoundationCompartments.Publication
		}
		if next.OriginalFoundationCompartments != nil {
			after = next.OriginalFoundationCompartments.Publication
		}
		reservation := before == nil && after != nil
		completion := after != nil && after.Readbacks != nil && (before == nil || before.Readbacks == nil)
		if reservation || completion {
			if r.Header.Get("If-Match") == "" || completeOriginalFoundationAdmissionReads(record) != nil || next.Stage != "original-foundation" {
				f.cloud.test.Error("publication bypassed protected original CAS or complete admission policies")
			}
			if reservation {
				f.reservations = append(f.reservations, *after)
			}
			if completion {
				f.completions++
				if before == nil || f.reads[0] == 0 || f.reads[1] == 0 {
					f.cloud.test.Error("completion preceded protected reservation or two real readbacks")
				}
			}
			fail := reservation && (f.fault == "reservation checkpoint" || f.fault == "lost reservation response") || completion && (f.fault == "completion checkpoint" || f.fault == "lost completion response")
			if fail && !f.faulted {
				f.faulted = true
				if strings.HasPrefix(f.fault, "lost ") {
					r.Body = io.NopCloser(bytes.NewReader(wire))
					recorder := httptest.NewRecorder()
					f.originalAdmissionReadsSDKFixture.serveHTTP(recorder, r)
					if recorder.Code >= 300 {
						f.cloud.test.Error("lost publication acknowledgement did not follow accepted CAS")
					}
				}
				originalCompartmentFailure(w, 503, "InternalError")
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(wire))
	}
	home := f.approval.HomeStorageDomain
	for index, name := range [2]string{"orchestrator/foundation/v1/root-chain.json", strings.TrimSuffix(home.Prefix, "/") + "/foundation-scope-v1.json"} {
		if !strings.HasSuffix(r.URL.Path, "/o/"+name) {
			continue
		}
		if r.Host != "objectstorage.sa-saopaulo-1.oraclecloud.com" || !strings.HasPrefix(r.URL.Path, "/n/"+home.Namespace+"/b/gru-1-head/o/") {
			f.cloud.test.Error("publication escaped exact signed HOME namespace and fixed bucket")
		}
		if r.Method == http.MethodPut {
			entry := record.OriginalFoundationCompartments.Publication
			if entry == nil || entry.PendingAt.IsZero() || entry.Readbacks != nil || entry.RequestSHA256 == "" || completeOriginalFoundationAdmissionReads(record) != nil || r.Header.Get("If-None-Match") != "*" || r.Header.Get("If-Match") != "" {
				f.cloud.test.Error("public effect preceded complete original reservation or escaped immutable create")
			}
			wire, err := io.ReadAll(r.Body)
			expected := [2][]byte{f.bundle.RootChainWire, f.bundle.GrantWire}[index]
			if err != nil || !bytes.Equal(wire, expected) {
				f.cloud.test.Error("publication differs from independently retained signed bytes")
			}
			r.Body = io.NopCloser(bytes.NewReader(wire))
			f.puts[index]++
			if f.fault == "lost object response" && !f.faulted {
				f.faulted = true
				recorder := httptest.NewRecorder()
				f.originalAdmissionReadsSDKFixture.serveHTTP(recorder, r)
				if recorder.Code >= 300 {
					f.cloud.test.Error("lost object response did not follow accepted immutable write")
				}
				originalCompartmentFailure(w, 503, "InternalError")
				return
			}
		} else if r.Method == http.MethodGet {
			if _, err := os.Stat(f.cloud.objectPath("gru-1-head/" + name)); err == nil {
				f.reads[index]++
				if f.fault == "readback missing" || f.fault == "readback forbidden" {
					status := 404
					if f.fault == "readback forbidden" {
						status = 403
					}
					originalCompartmentFailure(w, status, "NotAuthorizedOrNotFound")
					return
				}
				if f.fault == "readback conflict" || f.fault == "readback oversized" {
					wire := bytes.Clone([2][]byte{f.bundle.RootChainWire, f.bundle.GrantWire}[index])
					if f.fault == "readback oversized" {
						wire = append(wire, ' ')
					} else {
						wire[0] ^= 1
					}
					w.Header().Set("etag", "conflicting-object")
					w.Write(wire)
					return
				}
				if f.fault == "missing readback etag" {
					w.Write([2][]byte{f.bundle.RootChainWire, f.bundle.GrantWire}[index])
					return
				}
			}
		} else {
			f.cloud.test.Error("publication used a different public-object operation")
		}
	}
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationDiscoveryObject) {
		f.cloud.test.Error("original publication wrote ordinary discovery anchor")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	f.originalAdmissionReadsSDKFixture.serveHTTP(w, r)
}

func (f *originalPublicationSDKFixture) assertPublished(t *testing.T) {
	t.Helper()
	f.assertComplete(t)
	record := f.record(t)
	entry := record.OriginalFoundationCompartments.Publication
	if entry == nil || entry.Readbacks == nil || entry.PendingAt.IsZero() || entry.GrantSHA256 != digestSource(f.bundle.GrantWire) || entry.RootChainSHA256 != digestSource(f.bundle.RootChainWire) || f.completions == 0 {
		t.Fatal("original publication lacks protected exact signed-wire reservation and completion")
	}
	for index, name := range [2]string{"orchestrator/foundation/v1/root-chain.json", strings.TrimSuffix(f.approval.HomeStorageDomain.Prefix, "/") + "/foundation-scope-v1.json"} {
		wire, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + name))
		if err != nil || !bytes.Equal(wire, [2][]byte{f.bundle.RootChainWire, f.bundle.GrantWire}[index]) || f.reads[index] == 0 || (*entry.Readbacks)[index].ETag != digestSource(wire) {
			t.Fatal("publication completion lacks independent exact provider bytes and ETag")
		}
	}
}

func TestOriginalFoundationCurrentnessSDK(t *testing.T) {
	t.Run("automatic publication and unchanged restart", func(t *testing.T) {
		f := newOriginalPublicationSDKFixture(t, "")
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
			t.Fatal(err)
		}
		f.assertPublished(t)
		before, puts := bytes.Clone(f.wire(t)), f.puts
		if puts != [2]int{1, 1} {
			t.Fatal("automatic continuation did not publish exactly two immutable documents")
		}
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) || f.puts != puts || !bytes.Equal(before, f.wire(t)) {
			t.Fatal("completed replay repeated effects or changed protected publication history")
		}

		// Serve persisted bytes directly so corruption reaches production record validation.
		home := f.approval.HomeStorageDomain
		journalName := foundationObjectPrefix + "GRU.json"
		journalPath := f.cloud.objectPath(home.HeadBucket + "/" + journalName)
		var journalReads atomic.Int64
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/n/"+home.Namespace+"/b/"+home.HeadBucket+"/o/"+journalName ||
				r.URL.RawQuery != "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
				t.Error("journal validation requires an exact signed SDK GET")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			recorder := httptest.NewRecorder()
			f.cloud.serveHTTP(recorder, r)
			if recorder.Code != http.StatusOK {
				t.Errorf("journal oracle returned %d, expected actual persisted bytes", recorder.Code)
			} else {
				journalReads.Add(1)
			}
			originalNetworkCopyResponse(w, recorder)
		}))
		t.Cleanup(server.Close)
		objects, err := f.factoryFor().ObjectStorage()
		if err != nil {
			t.Fatal(err)
		}
		objects.HTTPClient = server.Client()
		ociclient.PinHost(&objects.BaseClient, server.URL)
		ociclient.ConfigureRequestCancellation(&objects.BaseClient)
		store, err := NewObjectFoundationStore(&objects, home.Namespace, home.HeadBucket)
		if err != nil {
			t.Fatal(err)
		}
		load := func() error {
			t.Helper()
			reads := journalReads.Load()
			_, _, err := store.Load(t.Context(), "GRU")
			if journalReads.Load() != reads+1 {
				t.Fatal("store validation did not consume exactly one actual HTTP 200 journal GET")
			}
			return err
		}
		if err := load(); err != nil {
			t.Fatal("genuine persisted publication failed production validation", err)
		}
		restore := func() {
			t.Helper()
			if err := os.WriteFile(journalPath, before, 0600); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(restore)
		completions := f.completions
		creates, material, launches := f.cloud.creates, f.cloud.materialPosts, f.cloud.launchPosts
		for _, mutation := range []struct {
			name  string
			apply func(*FoundationRecord)
		}{
			{"network request", func(record *FoundationRecord) {
				record.OriginalFoundationCompartments.Regions[0].Network.Requests.VCN.DisplayName = new("changed-network")
			}},
			{"vault request", func(record *FoundationRecord) {
				record.OriginalFoundationCompartments.Regions[0].Vault.Vault.Request.DisplayName = new("changed-vault")
			}},
			{"actor config", func(record *FoundationRecord) {
				record.OriginalFoundationCompartments.Regions[0].Actor.Config.Cell = "changed-cell"
			}},
			{"actor reads presence", func(record *FoundationRecord) { record.OriginalFoundationCompartments.Regions[0].ActorReads = nil }},
			{"source IAM scope", func(record *FoundationRecord) {
				record.OriginalFoundationCompartments.Regions[0].SourceIAM.Bucket = "changed-bucket"
			}},
		} {
			var changed FoundationRecord
			if err := json.Unmarshal(before, &changed); err != nil {
				t.Fatal(err)
			}
			mutation.apply(&changed)
			bad, err := json.Marshal(changed, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(journalPath, bad, 0600); err != nil {
				t.Fatal(err)
			}
			if err := load(); !errors.Is(err, ErrOriginalSourceProducerHold) {
				t.Fatal("actual SDK store accepted persisted corruption", mutation.name, err)
			}
			if !bytes.Equal(bad, f.wire(t)) || f.puts != puts || f.completions != completions ||
				f.cloud.creates != creates || f.cloud.materialPosts != material || f.cloud.launchPosts != launches {
				t.Fatal("refused journal corruption changed persisted bytes or emitted effects", mutation.name)
			}
			restore()
			if err := load(); err != nil {
				t.Fatal("actual SDK store did not recover restored journal", mutation.name, err)
			}
		}
	})
	t.Run("origin discovery reads current signed bytes", func(t *testing.T) {
		f := newOriginalPublicationSDKFixture(t, "")
		authority, _, err := newOperatorHomeIAMAuthority(t.Context(), f.factoryFor(), f.roots, f.bundle)
		if err != nil {
			t.Fatal(err)
		}
		origin := f.prepared.Grant.WorkloadGenesis[0]
		name, err := release.WorkloadGenesisObject(origin.TenancyID, origin.Cell, origin.Environment, origin.Role)
		if err != nil {
			t.Fatal(err)
		}
		path := f.cloud.objectPath(f.approval.HomeStorageDomain.HeadBucket + "/" + name)
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		restore := func() {
			t.Helper()
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(restore)
		before := bytes.Clone(f.wire(t))
		creates, material, launches := f.cloud.creates, f.cloud.materialPosts, f.cloud.launchPosts
		if err := authority.checkNetBirdMaterialOrigins(t.Context(), f.prepared.Grant); err != nil {
			t.Fatal("genuine signed origin discovery failed", err)
		}
		for _, refusal := range []string{"missing origin", "wrong scope", "bad signature"} {
			altered := f.bundle.clone()
			switch refusal {
			case "missing origin":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "wrong scope":
				altered.Namespace = strings.Repeat("x", len(altered.Namespace))
			case "bad signature":
				envelope, err := trust.DecodeEnvelope(altered.GrantWire)
				if err != nil {
					t.Fatal(err)
				}
				envelope.Signature = strings.Repeat("A", len(envelope.Signature))
				altered.GrantWire, err = trust.EncodeEnvelope(envelope)
				if err != nil {
					t.Fatal(err)
				}
			}
			if refusal != "missing origin" {
				wire, err := json.Marshal(altered, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, wire, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := authority.checkNetBirdMaterialOrigins(t.Context(), f.prepared.Grant)
			if err == nil {
				t.Fatal("actual SDK accepted changed on-disk origin", refusal)
			}
			if refusal == "missing origin" {
				var service common.ServiceError
				if !errors.As(err, &service) || service.GetHTTPStatusCode() != http.StatusNotFound {
					t.Fatal("missing origin did not reach actual SDK 404", err)
				}
			} else if !strings.Contains(err.Error(), "bytes differ") {
				t.Fatal("changed origin did not reach exact signed-byte comparison", err)
			}
			restore()
			if err := authority.checkNetBirdMaterialOrigins(t.Context(), f.prepared.Grant); err != nil {
				t.Fatal("actual SDK did not recover freshly restored origin bytes", err)
			}
		}
		if f.puts != [2]int{} || f.completions != 0 || f.cloud.hasAnchor() || !bytes.Equal(before, f.wire(t)) ||
			f.cloud.creates != creates || f.cloud.materialPosts != material || f.cloud.launchPosts != launches {
			t.Fatal("origin discovery changed protected publication history or emitted public effects")
		}
	})
	for _, boundary := range []string{"provider drift after signing", "operation cancellation after signing"} {
		t.Run(boundary, func(t *testing.T) {
			f := newOriginalPublicationSDKFixture(t, "lost reservation response")
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) || !f.faulted {
				t.Fatal("boundary setup did not lose the genuine durable reservation acknowledgement", err)
			}
			record := f.record(t)
			entry := record.OriginalFoundationCompartments.Publication
			if completeOriginalFoundationAdmissionReads(record) != nil || entry == nil || entry.Readbacks != nil || f.puts != [2]int{} {
				t.Fatal("signing boundary lacks complete genuine prerequisites and pending publication")
			}
			authority, _, err := newOperatorHomeIAMAuthority(t.Context(), f.factoryFor(), f.roots, f.bundle)
			if err != nil {
				t.Fatal(err)
			}
			lease, release, err := authority.HomeWrite(t.Context(), 0)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			operation, cancel := context.WithCancel(lease)
			defer cancel()
			before := bytes.Clone(f.wire(t))
			policyID := record.OriginalFoundationCompartments.Regions[0].SourceIAM.Provenance.ResourceID
			source := f.originalSourceIAMSDKFixture
			signed, readsAtSign := 0, 0
			authority.objects.Signer = originalPublicationBoundarySigner{HTTPRequestSigner: authority.objects.Signer, after: func(request *http.Request) {
				if request.Method != http.MethodPut || !strings.HasSuffix(request.URL.Path, "/o/"+foundationRootChainObject) {
					return
				}
				if !strings.HasPrefix(request.Header.Get("Authorization"), "Signature ") || request.Header.Get("If-None-Match") != "*" {
					t.Error("boundary did not follow genuine SDK signing of the immutable publication")
				}
				signed++
				if boundary == "operation cancellation after signing" {
					cancel()
					return
				}
				source.mu.Lock()
				readsAtSign = source.gets[policyID]
				source.rows[policyID]["statements"] = []string{"Allow any-user to manage all-resources in tenancy"}
				source.mu.Unlock()
			}}
			err = retainOriginalFoundationPublication(operation, authority)
			if !errors.Is(err, ErrOriginalSourceProducerHold) || signed != 1 || f.puts != [2]int{} || f.completions != 0 || f.cloud.hasAnchor() || !bytes.Equal(before, f.wire(t)) {
				t.Fatal("post-signing boundary reached the provider or changed protected pending publication", err)
			}
			if boundary == "operation cancellation after signing" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("post-signing operation cancellation was not retained", err)
				}
			} else {
				source.mu.Lock()
				readsAfter := source.gets[policyID]
				source.mu.Unlock()
				if readsAfter <= readsAtSign {
					t.Fatal("final guard did not freshly read the provider policy after signing")
				}
			}
		})
	}
	t.Run("lost object response recovers through exact readback", func(t *testing.T) {
		f := newOriginalPublicationSDKFixture(t, "lost object response")
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) || !f.faulted {
			t.Fatal("lost write acknowledgement did not recover exact immutable bytes", err)
		}
		f.assertPublished(t)
	})
	t.Run("completed receipt cannot replace current readback", func(t *testing.T) {
		f := newOriginalPublicationSDKFixture(t, "")
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
			t.Fatal(err)
		}
		before, puts := bytes.Clone(f.wire(t)), f.puts
		f.publicationMu.Lock()
		f.fault = "missing readback etag"
		f.publicationMu.Unlock()
		if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) || f.puts != puts || !bytes.Equal(before, f.wire(t)) {
			t.Fatal("retained completion substituted for authenticated current readback", err)
		}
	})
	for _, fault := range []string{"reservation checkpoint", "lost reservation response", "completion checkpoint", "lost completion response"} {
		t.Run(fault+" resumes original reservation", func(t *testing.T) {
			f := newOriginalPublicationSDKFixture(t, fault)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) || !f.faulted {
				t.Fatal("failed publication checkpoint became completed authority", err)
			}
			if strings.Contains(fault, "reservation") && f.puts != [2]int{} {
				t.Fatal("public effect preceded acknowledged durable reservation")
			}
			var pending *OriginalFoundationPublication
			if entry := f.record(t).OriginalFoundationCompartments.Publication; entry != nil {
				copy := *entry
				pending = &copy
			}
			if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
				t.Fatal(err)
			}
			f.assertPublished(t)
			if pending != nil {
				after := f.record(t).OriginalFoundationCompartments.Publication
				if !sameOriginalSourceValue(pending.scopeOnly(), after.scopeOnly()) || !pending.PendingAt.Equal(after.PendingAt) {
					t.Fatal("unknown checkpoint outcome changed the original reserved request")
				}
			}
		})
	}
	for _, fault := range []string{"readback missing", "readback forbidden", "readback conflict", "readback oversized", "missing readback etag"} {
		t.Run(fault+" cannot complete", func(t *testing.T) {
			f := newOriginalPublicationSDKFixture(t, fault)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
				t.Fatal("missing, uncertain or different current public authority became completion", err)
			}
			entry := f.record(t).OriginalFoundationCompartments.Publication
			if entry == nil || entry.Readbacks != nil || f.completions != 0 || f.cloud.hasAnchor() {
				t.Fatal("unsuccessful independent readback fabricated ordinary or original completion")
			}
		})
	}
}

func TestOriginalFoundationCurrentnessSignedAndRetainedContract(t *testing.T) {
	// Preserve the pinned loopback transport instead of the SDK's proxy clone.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	snapshot := func(t *testing.T, cloud *provisionCloud) []byte {
		t.Helper()
		cloud.mu.Lock()
		defer cloud.mu.Unlock()
		entries, err := os.ReadDir(cloud.directory)
		if err != nil {
			t.Fatal(err)
		}
		files := make(map[string][]byte, len(entries))
		for _, entry := range entries {
			wire, err := os.ReadFile(cloud.directory + "/" + entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			files[entry.Name()] = wire
		}
		wire, err := json.Marshal(files, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	for index, mutate := range []func(*OriginalFoundationPublicationIntent){
		func(q *OriginalFoundationPublicationIntent) { q.Purpose = "publish-everything" },
		func(q *OriginalFoundationPublicationIntent) { q.HomeRegion = "us-phoenix-1" },
		func(q *OriginalFoundationPublicationIntent) { q.Objects[0] = foundationDiscoveryObject },
		func(q *OriginalFoundationPublicationIntent) { q.Objects[1] = "latest/foundation-scope-v1.json" },
		func(q *OriginalFoundationPublicationIntent) { q.AdmissionRecipeSHA256[0] = strings.Repeat("0", 64) },
	} {
		t.Run(fmt.Sprintf("signed recipe %d", index), func(t *testing.T) {
			// Fresh prospective history avoids a same-generation replay refusal.
			f := newOriginalActorReadsSDKFixture(t, "", 0)
			prepared := f.prepared
			grant := prepared.Grant
			if grant.OriginalPublication == nil {
				t.Fatal("unsigned prospective preparation omitted publication purpose")
			}
			altered := *grant.OriginalPublication
			mutate(&altered)
			grant.OriginalPublication = &altered
			if validateOriginalFoundationPublicationIntent(grant, f.approval.HomeStorageDomain) == nil {
				t.Fatal("altered publication purpose or location passed exact signed recipe validation")
			}
			prepared.Grant = grant
			f.bundle = signProvisionFoundation(t, prepared, f.bundle.RootChainWire, f.root, f.now)
			f.cloud.bundle = f.bundle.clone()
			var err error
			f.publicBundle, err = json.Marshal(f.bundle, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, f.cloud)
			if f.cloud.creates != 0 || f.cloud.materialPosts != 0 || f.cloud.launchPosts != 0 || f.cloud.hasAnchor() {
				t.Fatal("signed mutation fixture already has adopted production history")
			}
			if err := provisionOriginalFoundationCompartments(t.Context(), f.factoryFor(), f.roots, f.bundle); err == nil {
				t.Fatal("actual original provisioning accepted altered signed publication authority")
			}
			if !bytes.Equal(before, snapshot(t, f.cloud)) || f.cloud.creates != 0 || f.cloud.materialPosts != 0 || f.cloud.launchPosts != 0 || len(f.dispatches()) != 0 || len(f.actorPosts) != 0 || len(f.readDispatches()) != 0 || f.cloud.hasAnchor() {
				t.Fatal("altered signed publication authority changed objects, journal, anchor or effects")
			}
		})
	}
	t.Run("historical absence", func(t *testing.T) {
		f := newOriginalActorReadsSDKFixture(t, "", 0)
		grant := f.prepared.Grant
		grant.OriginalPublication = nil
		if validateOriginalFoundationPublicationIntent(grant, f.approval.HomeStorageDomain) != nil {
			t.Fatal("historical absence was reinterpreted as malformed prospective authority")
		}
	})
	f := newOriginalPublicationSDKFixture(t, "")
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
		t.Fatal(err)
	}
	f.assertPublished(t)
	var completed FoundationRecord
	if err := json.Unmarshal(f.wire(t), &completed); err != nil {
		t.Fatal(err)
	}
	store := f.store(t)
	for _, mutate := range []func(*OriginalFoundationPublication){
		func(q *OriginalFoundationPublication) { q.RequestSHA256 = strings.Repeat("0", 64) },
		func(q *OriginalFoundationPublication) { q.BirthSHA256[0] = strings.Repeat("0", 64) },
		func(q *OriginalFoundationPublication) { q.AdmissionReadsSHA256[2] = strings.Repeat("0", 64) },
		func(q *OriginalFoundationPublication) { q.Readbacks = nil },
		func(q *OriginalFoundationPublication) { q.PendingAt = q.PendingAt.Add(1) },
	} {
		changed, etag, err := store.Load(t.Context(), "GRU")
		if err != nil || etag == "" {
			t.Fatal("actual store did not load a current retained publication", err)
		}
		before := snapshot(t, f.cloud)
		wire, puts, reservations, completions := bytes.Clone(f.wire(t)), f.puts, len(f.reservations), f.completions
		creates, material, launches, posts := f.cloud.creates, f.cloud.materialPosts, f.cloud.launchPosts, len(f.posts)
		mutate(changed.OriginalFoundationCompartments.Publication)
		if changed.validate() == nil && changed.retainOriginalFoundationPublication(completed) == nil {
			t.Fatal("protected publication identity or retained completion was mutable")
		}
		if _, err := store.CompareAndSwap(t.Context(), changed, etag); err == nil {
			t.Fatal("actual protected CAS accepted changed original publication history")
		}
		if !bytes.Equal(before, snapshot(t, f.cloud)) || !bytes.Equal(wire, f.wire(t)) || f.puts != puts || len(f.reservations) != reservations || f.completions != completions || f.cloud.creates != creates || f.cloud.materialPosts != material || f.cloud.launchPosts != launches || len(f.posts) != posts || f.cloud.hasAnchor() {
			t.Fatal("refused retained publication mutation changed durable objects, journal or effects")
		}
	}
}
