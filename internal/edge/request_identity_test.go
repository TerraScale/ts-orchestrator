package edge

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

func identityResponse(t *testing.T, client *http.Client, target string, headers http.Header) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host, req.Header = host, headers.Clone()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get(requestProofHeader) != "" || resp.Trailer.Get(requestProofHeader) != "" {
		t.Fatal("request proof escaped into a public response")
	}
	value := resp.Header.Get(requestIDHeader)
	id, err := ulid.ParseStrict(value)
	if err != nil || id.String() != value || len(resp.Header.Values(requestIDHeader)) != 1 {
		t.Fatalf("response request identity is not one canonical ULID: %q", value)
	}
	return resp.StatusCode, value, string(body)
}

func TestFirstPartyRequestProofAndRevocation(t *testing.T) {
	t.Parallel()
	key := strings.Repeat("aB", 32)
	id := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	proof := func(key, id string) string {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte("terrascale.request-id.v1\n" + id))
		return fmt.Sprintf("%X", mac.Sum(nil))
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(requestProofHeader) != proof(key, r.Header.Get(requestIDHeader)) {
			t.Error("backend did not receive a valid edge proof")
		}
		w.Header().Set(requestProofHeader, "must-never-escape")
		w.Header().Set("Trailer", requestProofHeader)
		io.WriteString(w, r.Header.Get(requestIDHeader))
		w.Header().Set(requestProofHeader, "trailer-must-never-escape")
	}))
	t.Cleanup(backend.Close)
	e := New(t.TempDir())
	if err := e.SetRequestProofSecret(key); err != nil {
		t.Fatal(err)
	}
	e.SetRoutes(map[string]int{host: backend.Listener.Addr().(*net.TCPAddr).Port}, nil)
	public := httptest.NewServer(http.HandlerFunc(e.serveHTTPS))
	t.Cleanup(public.Close)
	good := proof(key, id)
	for _, candidate := range []string{good, strings.ToLower(good), proof(strings.Repeat("c", 64), id), "bad", good + "," + good} {
		code, got, body := identityResponse(t, public.Client(), public.URL, http.Header{requestIDHeader: {id}, requestProofHeader: {candidate}})
		if code != 200 || body != got || (got == id) != (candidate == good) {
			t.Fatalf("first-party proof acceptance=%v, status=%d, identity preserved=%v", candidate == good, code, got == id)
		}
	}
	if err := e.SetRequestProofSecret(""); err != nil {
		t.Fatal(err)
	}
	e.SetRoutes(nil, nil)
	if _, got, _ := identityResponse(t, public.Client(), public.URL, http.Header{requestIDHeader: {id}, requestProofHeader: {good}}); got == id {
		t.Fatal("revoked credential still preserved public input")
	}
}

func TestPublicRequestIdentityReplacesSpoofedHeaders(t *testing.T) {
	t.Parallel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(requestIDHeader, "backend-spoof")
		if r.URL.Path == "/invalid" {
			w.WriteHeader(http.StatusBadRequest)
		}
		io.WriteString(w, r.Header.Get(requestIDHeader))
	}))
	t.Cleanup(backend.Close)
	e := New(t.TempDir())
	e.SetRoutes(map[string]int{host: backend.Listener.Addr().(*net.TCPAddr).Port}, nil)
	public := httptest.NewServer(http.HandlerFunc(e.serveHTTPS))
	t.Cleanup(public.Close)
	for _, supplied := range []string{ulid.Make().String(), strings.Repeat("x", 1024)} {
		for _, path := range []string{"/success", "/invalid"} {
			headers := http.Header{requestIDHeader: {supplied, "duplicate"}, "Connection": {requestIDHeader}, replaySrcHeader: {"region=spoofed"}}
			code, id, body := identityResponse(t, public.Client(), public.URL+path, headers)
			want := http.StatusOK
			if path == "/invalid" {
				want = http.StatusBadRequest
			}
			if code != want || id == supplied || body != id {
				t.Fatalf("%s: status=%d id=%q backend=%q", path, code, id, body)
			}
		}
	}
	e.SetRoutes(nil, nil)
	if code, _, _ := identityResponse(t, public.Client(), public.URL, nil); code != http.StatusNotFound {
		t.Fatalf("unknown route: %d", code)
	}
}

func TestAuthenticatedPeerRequestIdentity(t *testing.T) {
	t.Parallel()
	regions := startRegions(t, func(_ string, w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get(requestIDHeader))
	})
	config := regions["gru"].edge.meshNode().TLS().Clone()
	config.ServerName = replaySNI
	transport := &http.Transport{TLSClientConfig: config}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	canonical := ulid.Make().String()
	for _, input := range []string{canonical, strings.ToLower(canonical), "bad", canonical + "," + canonical} {
		code, id, body := identityResponse(t, client, "https://"+regions["gru"].edge.peerAddr("sjc"), http.Header{requestIDHeader: {input}})
		if code != http.StatusOK || body != id || (id == input) != (input == canonical) {
			t.Fatalf("peer input=%q status=%d id=%q backend=%q", input, code, id, body)
		}
	}
}

func TestRequestIdentitySurvivesReplayAndDependencyTimeout(t *testing.T) {
	t.Parallel()
	type observation struct{ region, id string }
	seen := make(chan observation, 4)
	regions := startRegions(t, func(name string, w http.ResponseWriter, r *http.Request) {
		seen <- observation{name, r.Header.Get(requestIDHeader)}
		if name == "gru" {
			w.Header().Set(replayHeader, "region=sjc")
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		if r.URL.Path == "/timeout" {
			<-r.Context().Done()
			return
		}
		io.WriteString(w, r.Header.Get(requestIDHeader))
	})
	// Exercise a real dependency header timeout without waiting the production 30s.
	transport := &http.Transport{ResponseHeaderTimeout: 100 * time.Millisecond}
	t.Cleanup(transport.CloseIdleConnections)
	regions["sjc"].edge.proxy.Transport = transport
	for _, path := range []string{"/success", "/timeout"} {
		code, id, body := identityResponse(t, http.DefaultClient, regions["gru"].public.URL+path, nil)
		want := http.StatusOK
		if path == "/timeout" {
			want = http.StatusBadGateway
		} else if body != id {
			t.Fatalf("replayed response lost identity: %q != %q", body, id)
		}
		if code != want {
			t.Fatalf("%s status=%d, want %d", path, code, want)
		}
		for _, name := range []string{"gru", "sjc"} {
			got := <-seen
			if got.region != name || got.id != id {
				t.Fatalf("%s observed %+v, response id=%q", path, got, id)
			}
		}
	}
}
