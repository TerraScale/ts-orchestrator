package app

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
)

// gatedFenceTest is newFenceTest with a canary: gate answers failing for
// each call, after gru-1-ctl-1 restarted or before.
func gatedFenceTest(t *testing.T, before, after map[string]string) (*releaseFence, *fenceCell, *fenceLB, canaryGate, *[]string) {
	fence, cell, balancer, _, intent := newFenceTest(t)
	spec, _ := fence.spec()
	spec.Canary = &cellspec.Canary{Project: "p"}
	var calls []string
	gate := func(_ context.Context, target canaryTarget) map[string]string {
		cell.mu.Lock()
		restarted := slices.Contains(cell.restarts, target.Node)
		others := len(cell.restarts) > 1
		cell.mu.Unlock()
		if others || target.Canary.Project != "p" || target.Address != fenceAddresses[target.Node] {
			t.Errorf("gated %+v after other nodes restarted (%v)", target, others)
		}
		if restarted {
			// The canary is still out of rotation.
			for _, backend := range balancer.sets["terrabase"] {
				if backend.IP == target.Address && backend.Serving() {
					t.Errorf("gated %s while it serves", target.Node)
				}
			}
			calls = append(calls, target.Node+" after")
			return after
		}
		calls = append(calls, target.Node+" before")
		return before
	}
	if err := fence.prepare(t.Context(), intent); err != nil {
		t.Fatal(err)
	}
	return fence, cell, balancer, gate, &calls
}

func TestReleaseCanaryGatesTheFirstNode(t *testing.T) {
	// A check that already failed before the canary changed is not blamed
	// on the release.
	down := map[string]string{checkDashboard: "unreachable"}
	fence, cell, _, gate, calls := gatedFenceTest(t, down, down)
	ctx := t.Context()
	intent := fenceIntent()
	if err := fence.sequence(ctx, intent, gate); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*calls, []string{"gru-1-ctl-1 before", "gru-1-ctl-1 after"}) || len(cell.restarts) != 3 {
		t.Fatalf("calls %q, restarts %q", *calls, cell.restarts)
	}
	// A rollback, or a release without a gate, is not gated.
	*calls = nil
	cell.release, intent.Generation = 8, 8
	if err := fence.prepare(ctx, intent); err != nil {
		t.Fatal(err)
	}
	cell.restarts = nil
	if err := fence.sequence(ctx, intent, nil); err != nil || len(*calls) != 0 {
		t.Fatalf("an ungated release: %v %q", err, *calls)
	}
}

func TestReleaseCanaryFailureStopsTheRelease(t *testing.T) {
	fence, cell, balancer, gate, calls := gatedFenceTest(t, nil, map[string]string{checkDocuments: "412 expected"})
	ctx := t.Context()
	intent := fenceIntent()
	err := fence.sequence(ctx, intent, gate)
	if !errors.Is(err, errBadRelease) || !strings.Contains(err.Error(), "failed release 7's gate") || !strings.Contains(err.Error(), "412 expected") {
		t.Fatalf("a failing canary: %v", err)
	}
	if !slices.Equal(cell.restarts, []string{"gru-1-ctl-1"}) || balancer.sets["terrabase"][0].Serving() {
		t.Fatalf("restarts %q, canary backend %+v", cell.restarts, balancer.sets["terrabase"][0])
	}
	want := []string{"gru-1-ctl-1 before"}
	for range canaryAttempts {
		want = append(want, "gru-1-ctl-1 after")
	}
	if !slices.Equal(*calls, want) {
		t.Fatalf("calls %q", *calls)
	}
	// A new leader resumes with the recorded baseline and gates the canary
	// again, never another node.
	record, err := fence.canary(ctx, "ts-auth", 7)
	if err != nil || record.Node != "gru-1-ctl-1" || record.Passed || len(record.Baseline) != 0 {
		t.Fatalf("canary record %+v %v", record, err)
	}
	*calls = nil
	if err := fence.sequence(ctx, intent, gate); err == nil || slices.Contains(*calls, "gru-1-ctl-1 before") {
		t.Fatalf("resumed: %v %q", err, *calls)
	}
}

func fenceIntent() delivery.Intent { return delivery.Intent{Role: "ts-auth", Generation: 7} }

// smokeCell fakes a cell for the smoke gate: ts-auth over plain HTTP,
// TerraBase over TLS with If-Match, and the dashboard.
type smokeCell struct {
	mu          sync.Mutex
	documents   map[string]int
	collections bool
	// ignoreIfMatch makes TerraBase accept a stale If-Match.
	ignoreIfMatch bool
	// hosted makes the dashboard redirect to ts-auth's hosted page.
	hosted bool
}

const smokeKey = "tsk_0123456789abcdefghjk_0123456789abcdefghjkmnpqrstvwxyz0123456789abcdefghjk"

func (c *smokeCell) auth(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/terrascale/.well-known/openid-configuration":
		fmt.Fprint(w, `{"issuer":"https://gru.auth.terrascale.tech/terrascale","token_endpoint":"x","jwks_uri":"y"}`)
	case "/terrascale/oauth/token":
		id, secret, ok := r.BasicAuth()
		if r.Method != http.MethodPost || !ok || id != smokeKey[:24] || secret != smokeKey ||
			r.FormValue("grant_type") != "client_credentials" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"access_token":"token","token_type":"Bearer","expires_in":900}`)
	default:
		http.NotFound(w, r)
	}
}

func (c *smokeCell) api(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if bearer := r.Header.Get("Authorization"); bearer != "Bearer token" && bearer != "Bearer tb_canary" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	const collections = "/v1/projects/p/databases/db/collections"
	if r.URL.Path == collections && r.Method == http.MethodPost {
		if c.collections {
			http.Error(w, "name_taken", http.StatusConflict)
			return
		}
		c.collections = true
		w.WriteHeader(http.StatusCreated)
		return
	}
	id, ok := strings.CutPrefix(r.URL.Path, collections+"/canary/documents/")
	if !ok || !c.collections {
		http.NotFound(w, r)
		return
	}
	version, exists := c.documents[id]
	etag := `"tbv1-` + strconv.Itoa(version) + `"`
	if match := r.Header.Get("If-Match"); match != "" && (!exists || match != etag) && !c.ignoreIfMatch {
		http.Error(w, "precondition_failed", http.StatusPreconditionFailed)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !exists {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", etag)
		fmt.Fprintf(w, `{"id":%q,"version":"v","state":"live","document":{"n":%d}}`, id, version)
	case http.MethodPut:
		if r.Header.Get("If-None-Match") == "*" && exists {
			http.Error(w, "precondition_failed", http.StatusPreconditionFailed)
			return
		}
		c.documents[id] = version + 1
		w.Header().Set("ETag", `"tbv1-`+strconv.Itoa(version+1)+`"`)
		if !exists {
			w.WriteHeader(http.StatusCreated)
		}
	case http.MethodDelete:
		delete(c.documents, id)
	}
}

func (c *smokeCell) dashboard(w http.ResponseWriter, r *http.Request) {
	if c.hosted {
		http.Redirect(w, r, "https://gru.auth.terrascale.tech/terrascale/oauth/authorize", http.StatusSeeOther)
		return
	}
	fmt.Fprint(w, `<form><input type="password"><a href="/login/code">code</a><a href="/login/sso">SSO</a></form>`)
}

func TestSmokeGateChecksTheCanary(t *testing.T) {
	cell := &smokeCell{documents: map[string]int{}}
	auth := httptest.NewServer(http.HandlerFunc(cell.auth))
	defer auth.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(cell.api))
	defer api.Close()
	dashboard := httptest.NewServer(http.HandlerFunc(cell.dashboard))
	defer dashboard.Close()
	apiURL, err := url.Parse(api.URL)
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := url.Parse(auth.URL)
	if err != nil {
		t.Fatal(err)
	}
	authPort, _ := strconv.Atoi(authURL.Port())
	apiPort, _ := strconv.Atoi(apiURL.Port())
	public := api.Client()
	public.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	key := smokeKey + "\n"
	gate := smokeGate{public: public, authPort: authPort,
		memberCA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}),
		credentials: func(context.Context, canaryTarget) (rootoci.NativeCanaryReceipt, error) {
			return rootoci.NativeCanaryReceipt{Value: key, ExpiresAt: time.Now().Add(time.Minute)}, nil
		}}
	canary := cellspec.Canary{Project: "p", Database: "db", AuthURL: auth.URL, APIURL: api.URL,
		DashboardLoginURL: dashboard.URL + "/login"}
	host, _, _ := net.SplitHostPort(apiURL.Host)
	profile := WorkloadProfile{Env: map[string]string{terrabase.EnvPeerPort: "9466", terrabase.EnvPeers: "gru-1-ctl-1=127.0.0.1:9466", terrabase.EnvClientPort: strconv.Itoa(apiPort)}}
	for _, role := range []string{tsauth.Role, terrabase.Role} {
		target := canaryTarget{Role: role, Node: "gru-1-ctl-1", Address: host, Canary: canary, Profile: profile}
		if failed := gate.check(t.Context(), target); len(failed) != 0 {
			t.Fatalf("%s canary: %v", role, failed)
		}
	}
	if len(cell.documents) != 0 {
		t.Fatalf("left documents %v", cell.documents)
	}
	target := canaryTarget{Role: terrabase.Role, Node: "gru-1-ctl-1", Address: host, Canary: canary, Profile: profile}
	cell.ignoreIfMatch, cell.hosted = true, true
	failed := gate.check(t.Context(), target)
	if !strings.Contains(failed[checkDocuments], "stale If-Match answered 200") ||
		!strings.Contains(failed[checkDashboard], "303") || len(failed) != 2 {
		t.Fatalf("failed %v", failed)
	}
	cell.ignoreIfMatch, cell.hosted = false, false
	// A member certificate the CA did not issue fails the member's checks.
	untrusted := gate
	untrusted.memberCA = nil
	if failed := untrusted.check(t.Context(), target); !strings.Contains(failed[checkDocuments], "member CA") {
		t.Fatalf("failed %v", failed)
	}
	// Without a ts-auth key the token endpoint must refuse an unknown one,
	// and documents are written with the TerraBase key (until TS-589).
	key = "tb_canary"
	if failed := gate.check(t.Context(), target); len(failed) != 0 {
		t.Fatalf("a tb_ key: %v", failed)
	}
	key = ""
	if failed := gate.check(t.Context(), target); len(failed) != 1 || !strings.Contains(failed[checkDocuments], "no TerraBase credential") {
		t.Fatalf("no credentials: %v", failed)
	}
	key = "tb_canary " + smokeKey[:76] + "x"
	failed = gate.check(t.Context(), target)
	if !strings.Contains(failed[checkAuthToken], "answered 401") || len(failed) != 1 {
		t.Fatalf("a wrong ts-auth key: %v", failed)
	}
	key = "not a key"
	failed = gate.check(t.Context(), target)
	if !strings.Contains(failed[checkDocuments], "something other") || !strings.Contains(failed[checkAuthToken], "something other") {
		t.Fatalf("failed %v", failed)
	}
	for _, reason := range failed {
		if strings.Contains(reason, smokeKey[25:]) {
			t.Fatalf("a reason holds the key: %q", reason)
		}
	}
}

func TestNativeCanaryUsesPredecessorAndSelectedPorts(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprintf("broken-candidate-%v", broken), func(t *testing.T) {
			fence, cell, _, _, intent := newFenceTest(t)
			cell.role, intent.Role = terrabase.Role, terrabase.Role
			a := &smokeCell{documents: map[string]int{}}
			b := &smokeCell{documents: map[string]int{}, ignoreIfMatch: broken}
			auth := httptest.NewServer(http.HandlerFunc(a.auth))
			defer auth.Close()
			var aCalls, bCalls, cCalls atomic.Int32
			serve := func(c *smokeCell, calls *atomic.Int32) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					c.api(w, r)
				}))
			}
			apiA, apiB := serve(a, &aCalls), serve(b, &bCalls)
			defer apiA.Close()
			defer apiB.Close()
			apiC := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				cCalls.Add(1)
				http.Error(w, "newest spec must not be probed", http.StatusServiceUnavailable)
			}))
			defer apiC.Close()
			profile := func(server *httptest.Server) WorkloadProfile {
				u, err := url.Parse(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				return WorkloadProfile{Env: map[string]string{terrabase.EnvPeerPort: "9466", terrabase.EnvPeers: "gru-1-ctl-1=127.0.0.1:9466", terrabase.EnvClientPort: u.Port()}}
			}
			profileA, profileB, profileC := profile(apiA), profile(apiB), profile(apiC)
			spec, _ := fence.spec()
			spec.Canary = &cellspec.Canary{Project: "p", Database: "db", AuthURL: auth.URL, APIURL: apiC.URL}
			smoke := newSmokeGate(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: apiA.Certificate().Raw}), nil)
			smoke.credentials = func(context.Context, canaryTarget) (rootoci.NativeCanaryReceipt, error) {
				return rootoci.NativeCanaryReceipt{Value: "tb_canary", ExpiresAt: time.Now().Add(time.Minute)}, nil
			}
			history := &nativeHistory{services: &specRegistry{fixed: map[string]WorkloadProfile{terrabase.Role: profileC}},
				canary: func(ctx context.Context, target canaryTarget) map[string]string {
					// Keep the fence's modeled private topology; probe real local endpoints.
					target.Address = "127.0.0.1"
					return smoke.check(ctx, target)
				}}
			selected := history.selectedCanaryGate(nativeReleaseHistory{Previous: &nativeGoodRelease{Binding: nativeReleaseBinding{Profile: profileA}}}, nativeReleaseBinding{Profile: profileB})
			// Adoption or mutation after selection cannot replace B's endpoint with C.
			profileB.Env[terrabase.EnvClientPort] = profileC.Env[terrabase.EnvClientPort]
			if err := fence.prepare(t.Context(), intent); err != nil {
				t.Fatal(err)
			}
			err := fence.sequence(t.Context(), intent, selected)
			if broken != errors.Is(err, errBadRelease) || !broken && err != nil {
				t.Fatalf("candidate broken=%v: %v", broken, err)
			}
			if aCalls.Load() == 0 || bCalls.Load() == 0 || cCalls.Load() != 0 {
				t.Fatalf("endpoint calls: predecessor=%d candidate=%d newest=%d", aCalls.Load(), bCalls.Load(), cCalls.Load())
			}
			if broken {
				record, err := fence.canary(t.Context(), intent.Role, intent.Generation)
				if err != nil || record.Passed || slices.Contains(record.Baseline, checkDocuments) || !slices.Equal(cell.restarts, []string{"gru-1-ctl-1"}) {
					t.Fatalf("candidate regression was suppressed by baseline: %+v, restarts=%v, err=%v", record, cell.restarts, err)
				}
			} else if len(cell.restarts) != 3 {
				t.Fatalf("healthy B did not finish the fence: %v", cell.restarts)
			}
		})
	}
}
