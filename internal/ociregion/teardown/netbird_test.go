package teardown

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
)

// pinOCITLS routes every OCI SDK HTTPS dial to server. The SDK clones
// http.DefaultTransport, so the replacement must stay an *http.Transport.
func pinOCITLS(t *testing.T, server *httptest.Server) {
	t.Helper()
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.Proxy = nil
	dialer := tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("fixture refuses plaintext dialing")
	}
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
}

func TestNetBirdTeardownBlocksBeforeLegacyDeletion(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "malformed-current-authority", true: "unreadable-current-authority"}[missing], func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
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
			pinOCITLS(t, server)
			provider := sdkProvider(t, server)
			var out strings.Builder
			err := provider.teardown(t.Context(), gruPlan(), true, &out)
			if err == nil || !strings.Contains(err.Error(), "GRU teardown blocked: current foundation authority") || requests.Load() < 2 {
				t.Fatalf("legacy apply bypassed current signed authority: requests=%d err=%v output=%s", requests.Load(), err, out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("legacy teardown printed a deletion diff before authority verification: %s", out.String())
			}
		})
	}
}
