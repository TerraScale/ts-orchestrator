package teardown

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

type netBirdTeardownHTTP struct {
	next     http.RoundTripper
	endpoint *url.URL
}

func (transport netBirdTeardownHTTP) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.URL.Scheme, copy.URL.Host = transport.endpoint.Scheme, transport.endpoint.Host
	return transport.next.RoundTrip(copy)
}

func TestNetBirdTeardownBlocksBeforeLegacyDeletion(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "malformed-current-authority", true: "unreadable-current-authority"}[missing], func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if request.Method != http.MethodGet || !strings.HasPrefix(request.Header.Get("Authorization"), "Signature ") {
					t.Errorf("teardown attempted an unsigned request or mutation: %s %s", request.Method, request.URL)
				}
				w.Header().Set("Content-Type", "application/json")
				if request.URL.Path == "/n" {
					io.WriteString(w, `"ns"`)
					return
				}
				if !strings.HasPrefix(request.URL.Path, "/n/ns/b/") {
					t.Errorf("legacy teardown accessed a resource before verifying current authority: %s", request.URL.Path)
				}
				if missing {
					w.WriteHeader(http.StatusNotFound)
					io.WriteString(w, `{"code":"ObjectNotFound","message":"unreadable authority"}`)
					return
				}
				io.WriteString(w, `{"untrusted":"not a signed foundation"}`)
			}))
			t.Cleanup(server.Close)
			provider := sdkProvider(t, server)
			endpoint, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			original := http.DefaultTransport
			http.DefaultTransport = netBirdTeardownHTTP{next: original, endpoint: endpoint}
			t.Cleanup(func() { http.DefaultTransport = original })
			var out strings.Builder
			err = provider.teardown(t.Context(), gruPlan(), true, &out)
			if err == nil || !strings.Contains(err.Error(), "GRU teardown blocked: current foundation authority") || requests.Load() < 2 {
				t.Fatalf("legacy apply bypassed current signed authority: requests=%d err=%v output=%s", requests.Load(), err, out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("legacy teardown printed a deletion diff before authority verification: %s", out.String())
			}
		})
	}
}
