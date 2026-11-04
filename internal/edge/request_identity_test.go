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
	for _, candidate := range []string{good, proof(strings.Repeat("c", 64), id)} {
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
