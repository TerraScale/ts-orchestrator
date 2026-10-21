package oci

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestTerminalSDKDeleteSocketBoundary(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	credentials := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test",
		"sa-saopaulo-1", "test", string(pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
		})), nil)
	compute, err := core.NewComputeClientWithConfigurationProvider(credentials)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := core.NewBlockstorageClientWithConfigurationProvider(credentials)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, id, path, etag, query string
		call                        func(*sdkProvider, context.Context, string, string) error
	}{
		{"TerminateInstance", "ocid1.instance.exact", "/20160918/instances/ocid1.instance.exact", "instance-etag",
			"preserveBootVolume=true&preserveDataVolumesCreatedAtLaunch=true", (*sdkProvider).TerminateTerminalInstance},
		{"DeleteBootVolume", "ocid1.bootvolume.exact", "/20160918/bootVolumes/ocid1.bootvolume.exact", "boot-etag", "", (*sdkProvider).DeleteBootVolume},
		{"DeleteVolume", "ocid1.volume.exact", "/20160918/volumes/ocid1.volume.exact", "data-etag", "", (*sdkProvider).DeleteVolume},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer r.Body.Close()
				calls.Add(1)
				if r.Method != http.MethodDelete || r.URL.Path != test.path || r.URL.RawQuery != test.query ||
					r.TLS == nil || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
					t.Errorf("unexpected signed TLS delete: %s %s", r.Method, r.URL)
					http.Error(w, "unexpected delete", http.StatusBadRequest)
					return
				}
				w.Header().Set("opc-request-id", "terminal-boundary")
				switch r.Header.Get("If-Match") {
				case test.etag:
					w.WriteHeader(http.StatusNoContent)
				case "stale-etag":
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusPreconditionFailed)
					if _, err := io.WriteString(w, `{"code":"PreconditionFailed","message":"ETag changed"}`); err != nil {
						t.Error(err)
					}
				default:
					t.Errorf("If-Match = %q, want %q or stale-etag", r.Header.Get("If-Match"), test.etag)
					http.Error(w, "missing exact ETag", http.StatusBadRequest)
				}
			}))
			defer server.Close()
			client := server.Client()
			defer client.CloseIdleConnections()
			client.Timeout = 5 * time.Second
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != server.Listener.Addr().String() {
					return nil, errors.New("terminal SDK fixture refuses non-loopback endpoints")
				}
				return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
			}
			provider := &sdkProvider{compute: compute, storage: storage}
			provider.compute.Host, provider.storage.Host = server.URL, server.URL
			provider.compute.HTTPClient, provider.storage.HTTPClient = client, client
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if err := test.call(provider, ctx, test.id, test.etag); err != nil {
				t.Fatalf("exact conditional delete: %v", err)
			}
			err := test.call(provider, ctx, test.id, "stale-etag")
			failure, ok := errors.AsType[interface {
				error
				common.ServiceError
			}](err)
			if !ok || failure.GetHTTPStatusCode() != http.StatusPreconditionFailed ||
				failure.GetCode() != "PreconditionFailed" || failure.GetOpcRequestID() != "terminal-boundary" {
				t.Fatalf("stale ETag lost the SDK response: %v", err)
			}
			if got := calls.Load(); got != 2 {
				t.Fatalf("delete requests = %d, want exactly one success and one rejection", got)
			}
		})
	}
}
