package ociclient_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func TestOperationTemplateThroughVerifiedTLSHTTP(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{"instance", "GET https://iaas.sa-saopaulo-1.oraclecloud.com/20160918/instances/ocid1.instance.oc1.sa-saopaulo-1.abc?page=9", "GET /instances/{id}"},
		{"softstop", "POST https://iaas.example/20160918/instances/ocid1.instance.oc1..x?action=SOFTSTOP", "POST /instances/{id}?action=SOFTSTOP"},
		{"unbounded_action", "POST https://iaas.example/20160918/instances/x?action=evil-value", "POST /instances/x?action={action}"},
		{"attachments", "GET https://iaas.example/20160918/volumeAttachments?compartmentId=ocid1.compartment.oc1..a", "GET /volumeAttachments"},
		{"numeric_instance", "GET https://iaas.example/20160918/instances/1234567890/vnics", "GET /instances/{id}/vnics"},
		{"object", "GET https://objects.example/n/secretNamespace/b/secretBucket/o/secret/object/name?versionId=secret", "GET /n/{id}/b/{id}/o/{id}"},
		{"multipart", "PUT https://objects.example/n/secretNamespace/b/secretBucket/u/secret/object/name?uploadId=secret", "PUT /n/{id}/b/{id}/u/{id}"},
		{"list_objects", "GET https://objects.example/n/secretNamespace/b/secretBucket/o?prefix=secret", "GET /n/{id}/b/{id}/o"},
		{"head_bucket", "HEAD https://objects.example/n/secretNamespace/b/secretBucket", "HEAD /n/{id}/b/{id}"},
		{"list_buckets", "GET https://objects.example/n/secretNamespace/b", "GET /n/{id}/b"},
		{"private_endpoint", "GET https://objects.example/n/secretNamespace/pe/secretEndpoint", "GET /n/{id}/pe/{id}"},
		{"preauthenticated_request", "GET https://objects.example/n/secretNamespace/b/secretBucket/p/secretToken", "GET /n/{id}/b/{id}/p/{id}"},
		{"reencrypt", "POST https://objects.example/n/secretNamespace/b/secretBucket/actions/reencrypt/secret/object/name", "POST /n/{id}/b/{id}/actions/reencrypt/{id}"},
	} {
		t.Run(test.name, func(t *testing.T) {
			method, rawURL, _ := strings.Cut(test.raw, " ")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			var received atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, incoming *http.Request) {
				received.Add(1)
				if incoming.TLS == nil || incoming.Method != method || incoming.Host != request.URL.Host || incoming.URL.RequestURI() != request.URL.RequestURI() {
					t.Errorf("TLS wire request = %s %s %s, want %s %s %s", incoming.Method, incoming.Host, incoming.URL.RequestURI(), method, request.URL.Host, request.URL.RequestURI())
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			client := server.Client()
			transport := client.Transport.(*http.Transport)
			defer transport.CloseIdleConnections()
			host, _, err := net.SplitHostPort(server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			// Keep the exact original URL while dialing only the verified local TLS fixture.
			transport.TLSClientConfig.ServerName = host
			transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return new(net.Dialer).DialContext(ctx, network, server.Listener.Addr().String())
			}
			service := "template-" + strings.ReplaceAll(t.Name(), "/", "-")
			response, err := ociclient.Instrument(client, service).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || response.StatusCode != http.StatusNoContent || received.Load() != 1 {
				t.Fatalf("HTTP result = %d, requests=%d, read=%v, close=%v", response.StatusCode, received.Load(), readErr, closeErr)
			}
			found := 0
			for _, operation := range ociclient.APIOperations() {
				if operation.Service != service {
					continue
				}
				found++
				if operation.Operation != test.want || operation.Calls != 1 || operation.Errors != 0 || operation.Throttled != 0 || operation.LastStatus != http.StatusNoContent {
					t.Errorf("API operation = %+v, want one successful %q", operation, test.want)
				}
			}
			if found != 1 {
				t.Fatalf("API operations for fixture service = %d, want 1", found)
			}
			var metrics bytes.Buffer
			ociclient.Metrics.WritePrometheus(&metrics)
			want := `ts_orch_oci_requests_total{service="` + service + `",operation="` + test.want + `",code="204"} 1`
			if !strings.Contains(metrics.String(), want) {
				t.Errorf("Prometheus output lacks %q", want)
			}
		})
	}
}
