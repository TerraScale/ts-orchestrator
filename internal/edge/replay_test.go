package edge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

type fakeMesh struct {
	region string
	tls    *tls.Config
	rtt    map[string]time.Duration
}

func (m fakeMesh) Region() string                { return m.region }
func (m fakeMesh) TLS() *tls.Config              { return m.tls }
func (m fakeMesh) RTT() map[string]time.Duration { return m.rtt }

// region is one region's edge and fake TerraBase.
type region struct {
	edge    *Edge
	public  *httptest.Server // the client side, plain HTTP for the test
	backend *httptest.Server
	stop    func()
	dir     string // state directory
	plain   string // the :80 listener
	hits    atomic.Int32
}

const host = "api.edge.test"

// startRegions runs gru, sjc and fra with the mesh RTTs measured on
// 2026-10-22. answer is each region's TerraBase.
func startRegions(t *testing.T, answer func(name string, w http.ResponseWriter, r *http.Request)) map[string]*region {
	t.Helper()
	ca, err := mesh.DeriveCA(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	rtt := map[string]map[string]time.Duration{
		"gru": {"sjc": ms(168), "fra": ms(188)},
		"sjc": {"gru": ms(168), "fra": ms(138)},
		"fra": {"gru": ms(188), "sjc": ms(138)},
	}
	regions := map[string]*region{}
	// Every peer address is known before any edge serves.
	peerLns, peers := map[string]net.Listener{}, map[string]string{}
	for name := range rtt {
		peerLns[name] = listen(t)
		peers[name] = peerLns[name].Addr().String()
	}
	for name := range rtt {
		reg := &region{dir: t.TempDir()}
		reg.edge = newEdge(reg.dir, nil)
		reg.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reg.hits.Add(1)
			answer(name, w, r)
		}))
		t.Cleanup(reg.backend.Close)
		reg.edge.SetRoutes(map[string]int{host: reg.backend.Listener.Addr().(*net.TCPAddr).Port}, nil)
		reg.edge.SetMesh(fakeMesh{region: name, tls: ca.TLS(name + "." + mesh.Domain), rtt: rtt[name]})
		reg.edge.peerAddr = func(r string) string { return peers[r] }
		reg.public = httptest.NewServer(http.HandlerFunc(reg.edge.serveHTTPS))
		t.Cleanup(reg.public.Close)
		tlsLn := peerLns[name]
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		// stop returns once the edge has closed its listeners and connections.
		reg.stop = func() { cancel(); <-done }
		plainLn := listen(t)
		reg.plain = plainLn.Addr().String()
		go func() { reg.edge.serve(ctx, plainLn, tlsLn, listen(t)); close(done) }()
		t.Cleanup(reg.stop)
		regions[name] = reg
	}
	return regions
}

// terraBase answers like TerraBase for a database placed in gru and sjc: a
// region holding it serves it, any other asks for a replay to both.
func terraBase(name string, w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if r.Header.Get(replayFailedHeader) != "" {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "fallback in %s", name)
		return
	}
	if name == "gru" || name == "sjc" {
		fmt.Fprintf(w, "%s served %s %s src=%q xff=%q body=%s", name, r.Method, r.URL.RequestURI(), r.Header.Get(replaySrcHeader), r.Header.Get("X-Forwarded-For"), body)
		return
	}
	if r.Header.Get(replaySrcHeader) == "" {
		w.Header().Set(replayHeader, "region=gru,sjc;fallback=self")
	}
	w.WriteHeader(http.StatusMisdirectedRequest)
	fmt.Fprint(w, "wrong_region")
}

func call(t *testing.T, reg *region, method, path, body string, header ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, reg.public.URL+path, strings.NewReader(body))
	req.Host = host
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	t.Logf("%s %s via edge: %d in %s", method, path, resp.StatusCode, time.Since(start))
	return resp.StatusCode, string(got)
}

func TestReplayGoesToNearestHolder(t *testing.T) {
	regions := startRegions(t, terraBase)

	// fra holds nothing; sjc (138 ms) is nearer than gru (188 ms).
	code, body := call(t, regions["fra"], http.MethodPost, "/v1/db/docs?x=1", `{"a":1}`, replaySrcHeader, "region=spoofed")
	if want := `sjc served POST /v1/db/docs?x=1 src="region=fra" xff="127.0.0.1" body={"a":1}`; code != 200 || body != want {
		t.Fatalf("fra -> %d %q, want 200 %q", code, body, want)
	}
	// sjc holds it: answered locally.
	if code, body := call(t, regions["sjc"], http.MethodGet, "/v1/db/docs", ""); code != 200 || !strings.HasPrefix(body, `sjc served GET /v1/db/docs src=""`) {
		t.Fatalf("sjc -> %d %q", code, body)
	}

	// sjc's TerraBase stops: its edge answers down and fra replays to gru.
	regions["sjc"].backend.Close()
	if code, body := call(t, regions["fra"], http.MethodPost, "/v1/db/docs", "b"); code != 200 || !strings.HasPrefix(body, `gru served POST /v1/db/docs src="region=fra"`) {
		t.Fatalf("sjc backend down: fra -> %d %q", code, body)
	}
	// The whole sjc host stops.
	regions["sjc"].stop()
	if code, body := call(t, regions["fra"], http.MethodGet, "/v1/db/docs", ""); code != 200 || !strings.HasPrefix(body, "gru served") {
		t.Fatalf("sjc host down: fra -> %d %q", code, body)
	}
	// No holder answers: fallback=self asks fra's TerraBase again.
	regions["gru"].stop()
	if code, body := call(t, regions["fra"], http.MethodGet, "/v1/db/docs", ""); code != http.StatusServiceUnavailable || body != "fallback in fra" {
		t.Fatalf("all holders down: fra -> %d %q", code, body)
	}
}

// TerraBase takes transactions up to 2 MiB and import parts up to 4 MiB; a
// region that does not hold the database replays them from a spool file.
func TestReplaySpoolsLargeBodies(t *testing.T) {
	regions := startRegions(t, func(name string, w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if name != "sjc" && r.Header.Get(replaySrcHeader) == "" {
			w.Header().Set(replayHeader, "region=sjc")
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		fmt.Fprintf(w, "%s got %d %x", name, len(body), sha256.Sum256(body))
	})
	for _, size := range []int{2 << 20, 4<<20 + 100<<10, maxReplayBody} {
		body := strings.Repeat("x", size)
		code, got := call(t, regions["gru"], http.MethodPost, "/v1/db/import", body)
		if want := fmt.Sprintf("sjc got %d %x", size, sha256.Sum256([]byte(body))); code != 200 || got != want {
			t.Fatalf("%d B body: gru -> %d %q, want %q", size, code, got, want)
		}
	}
	// Past maxReplayBody the body streams to the local backend, whole.
	code, _ := call(t, regions["gru"], http.MethodPost, "/v1/db/import", strings.Repeat("x", maxReplayBody+1))
	if code != http.StatusMisdirectedRequest {
		t.Fatalf("oversize body: gru -> %d, want 421", code)
	}
	if left, _ := os.ReadDir(filepath.Join(regions["gru"].dir, "edge-spool")); len(left) != 0 {
		t.Fatalf("spool files left: %v", left)
	}
}

func TestReplayNeverLoops(t *testing.T) {
	// gru and sjc disagree and each names the other.
	regions := startRegions(t, func(name string, w http.ResponseWriter, r *http.Request) {
		w.Header().Set(replayHeader, map[string]string{"gru": "region=sjc", "sjc": "region=gru", "fra": "region=gru"}[name])
		w.WriteHeader(http.StatusMisdirectedRequest)
		fmt.Fprintf(w, "wrong_region in %s", name)
	})
	code, body := call(t, regions["gru"], http.MethodGet, "/", "")
	if code != http.StatusMisdirectedRequest || body != "wrong_region in sjc" {
		t.Fatalf("gru -> %d %q", code, body)
	}
	if gru, sjc := regions["gru"].hits.Load(), regions["sjc"].hits.Load(); gru != 1 || sjc != 1 {
		t.Fatalf("backend hits gru=%d sjc=%d, want 1 each", gru, sjc)
	}
	// Without fallback=self and no reachable holder, the client gets the first answer.
	regions["sjc"].stop()
	if code, body := call(t, regions["gru"], http.MethodGet, "/", ""); code != http.StatusMisdirectedRequest || body != "wrong_region in gru" {
		t.Fatalf("sjc down: gru -> %d %q", code, body)
	}
}

func TestReplayPortNeedsMeshCertificate(t *testing.T) {
	regions := startRegions(t, terraBase)
	tlsAddr := regions["gru"].edge.peerAddr("sjc")
	conn, err := tls.Dial("tcp", tlsAddr, &tls.Config{ServerName: replaySNI, InsecureSkipVerify: true})
	if err == nil {
		// TLS 1.3 reports a missing client certificate on the first read.
		_, err = conn.Read(make([]byte, 1))
		conn.Close()
	}
	if err == nil {
		t.Fatal("handshake without a mesh certificate succeeded")
	}
}

func TestChallengeComesFromThePeerHoldingIt(t *testing.T) {
	regions := startRegions(t, terraBase)
	// autocert keeps a pending HTTP-01 key authorization in its cache.
	if err := os.MkdirAll(filepath.Join(regions["gru"].dir, "edge-certs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(regions["gru"].dir, "edge-certs", "tok123+http-01"), []byte("tok123.thumb"), 0o600); err != nil {
		t.Fatal(err)
	}
	get := func(reg *region, token string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, "http://"+reg.plain+challengePath+token, nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	for _, name := range []string{"gru", "sjc", "fra"} {
		if code, body := get(regions[name], "tok123"); code != 200 || body != "tok123.thumb" {
			t.Fatalf("%s: challenge = %d %q", name, code, body)
		}
	}
	if code, _ := get(regions["fra"], "unknown"); code != http.StatusNotFound {
		t.Fatalf("unknown token = %d, want 404", code)
	}
}

func TestReadyzAnswersOnPlainHTTP(t *testing.T) {
	regions := startRegions(t, func(_ string, w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ready "+r.URL.Path) })
	req, _ := http.NewRequest(http.MethodGet, "http://"+regions["sjc"].plain+"/readyz", nil)
	req.Host = host
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ready /readyz" {
		t.Fatalf("readyz on :80 = %d %q", resp.StatusCode, body)
	}
	req, _ = http.NewRequest(http.MethodGet, "http://"+regions["sjc"].plain+"/v1/db", nil)
	req.Host = host
	if resp, err = http.DefaultTransport.RoundTrip(req); err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("other paths on :80 must redirect: %v %v", resp, err)
	}
	resp.Body.Close()
}

// While a region's TerraBase is handed off (its port held from the old task's
// SIGTERM until the new one is ready), its edge serves clients from the nearest
// region instead of holding them; a held peer answers down at once.
func TestHandoffFailsOverToNearestRegion(t *testing.T) {
	regions := startRegions(t, func(name string, w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s served %s src=%q", name, r.Method, r.Header.Get(replaySrcHeader))
	})
	port := func(name string) uint16 { return uint16(regions[name].backend.Listener.Addr().(*net.TCPAddr).Port) }
	handoff.Hold(port("gru"))
	defer handoff.Release(port("gru"))
	start := time.Now()
	if code, body := call(t, regions["gru"], http.MethodPost, "/v1/db/docs", "a"); code != 200 || body != `sjc served POST src="region=gru"` {
		t.Fatalf("gru held -> %d %q", code, body)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("failover took %s", elapsed)
	}
	// sjc is being handed off too: it answers down and fra serves.
	handoff.Hold(port("sjc"))
	defer handoff.Release(port("sjc"))
	if code, body := call(t, regions["gru"], http.MethodGet, "/readyz", ""); code != 200 || body != `fra served GET src="region=gru"` {
		t.Fatalf("gru and sjc held -> %d %q", code, body)
	}
	// No region serves: the request waits out the local handoff.
	handoff.Hold(port("fra"))
	go func() { time.Sleep(300 * time.Millisecond); handoff.Release(port("gru")) }()
	if code, body := call(t, regions["gru"], http.MethodGet, "/readyz", ""); code != 200 || body != `gru served GET src=""` {
		t.Fatalf("all held -> %d %q", code, body)
	}
	handoff.Release(port("fra"))
	if hits := regions["gru"].hits.Load(); hits != 1 {
		t.Fatalf("gru backend hits %d, want 1 (after its release)", hits)
	}
}

// The mesh replaces regions one at a time (TestMeshRollsRegionsOneAtATime): a
// probe of gru's edge every 20 ms with a 2 s timeout, as FR1's curl -m 2, sees
// only 200 while gru, then sjc, then fra hand their TerraBase off.
func TestRegionByRegionHandoffServesEveryProbe(t *testing.T) {
	regions := startRegions(t, func(name string, w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s ready", name)
	})
	client := &http.Client{Timeout: 2 * time.Second}
	var probes, failures atomic.Int32
	var failed atomic.Value
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			req, _ := http.NewRequest(http.MethodGet, regions["gru"].public.URL+"/readyz", nil)
			req.Host = host
			probes.Add(1)
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
			if err != nil || resp.StatusCode != http.StatusOK {
				failures.Add(1)
				failed.Store(fmt.Sprint(resp, err))
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	for _, name := range []string{"gru", "sjc", "fra"} {
		port := uint16(regions[name].backend.Listener.Addr().(*net.TCPAddr).Port)
		handoff.Hold(port)
		time.Sleep(1500 * time.Millisecond)
		handoff.Release(port)
		time.Sleep(500 * time.Millisecond)
	}
	close(stop)
	<-done
	t.Logf("%d probes, %d failed", probes.Load(), failures.Load())
	if probes.Load() < 150 || failures.Load() != 0 {
		t.Fatalf("%d probes, %d failed (last: %v); want >= 150 and 0", probes.Load(), failures.Load(), failed.Load())
	}
}

// A request to a regional host (fra.api...) that fra cannot serve replays to
// sjc as sjc.api...: each edge routes only its own region's name (TS-925).
func TestReplayRewritesRegionalHost(t *testing.T) {
	regions := startRegions(t, terraBase)
	for name, reg := range regions {
		port := reg.backend.Listener.Addr().(*net.TCPAddr).Port
		reg.edge.SetRoutes(map[string]int{host: port, name + "." + host: port}, nil)
	}
	req, _ := http.NewRequest(http.MethodPost, regions["fra"].public.URL+"/v1/db/tx", strings.NewReader(`{"tx":1}`))
	req.Host = "fra." + host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.HasPrefix(string(body), `sjc served POST /v1/db/tx src="region=fra"`) {
		t.Fatalf("fra.%s -> %d %q", host, resp.StatusCode, body)
	}
	if got := regionalHost("sjc.api.terrascale.tech:443", "sjc", "gru"); got != "gru.api.terrascale.tech:443" {
		t.Fatalf("regionalHost = %q", got)
	}
	if got := regionalHost("api.terrascale.tech", "sjc", "gru"); got != "api.terrascale.tech" {
		t.Fatalf("regionalHost of a global host = %q", got)
	}
}
