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
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
)

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
	})
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
