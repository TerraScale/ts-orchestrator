package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestCapacityImageShapePaginationSDK(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("tenancy", "user", "sa-saopaulo-1", "fingerprint",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	shapeNames := []string{"VM.Standard.A1.Flex", "VM.Standard.A2.Flex", "VM.Standard.E5.Flex"}
	for _, scenario := range []struct {
		name       string
		pages      []string
		next       []*string
		wantShapes []string
		wantError  string
		outage     bool
		canceled   bool
	}{
		{name: "nil terminal", pages: []string{""}, next: []*string{nil}, wantShapes: shapeNames[:1]},
		{name: "empty terminal", pages: []string{""}, next: []*string{new("")}, wantShapes: shapeNames[:1]},
		{name: "two pages", pages: []string{"", "page-a"}, next: []*string{new("page-a"), nil}, wantShapes: shapeNames[:2]},
		{name: "self cycle", pages: []string{"", "page-a"}, next: []*string{new("page-a"), new("page-a")}, wantError: "pagination repeated"},
		{name: "two token cycle", pages: []string{"", "page-a", "page-b"}, next: []*string{new("page-a"), new("page-b"), new("page-a")}, wantError: "pagination repeated"},
		{name: "provider failure", pages: []string{""}, outage: true, wantError: "shape listing denied"},
		{name: "canceled context", canceled: true, wantError: "context canceled"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				index := int(requests.Add(1)) - 1
				if index >= len(scenario.pages) {
					t.Error("shape discovery exceeded its pagination request bound")
					http.Error(w, "unexpected extra page", http.StatusBadRequest)
					return
				}
				query := r.URL.Query()
				if r.Method != http.MethodGet || r.URL.Path != "/20160918/shapes" || r.Header.Get("Authorization") == "" ||
					query.Get("compartmentId") != "compartment" || query.Get("availabilityDomain") != "AD-1" ||
					query.Get("imageId") != "qualified-image" || query.Get("page") != scenario.pages[index] {
					t.Errorf("OCI shape request lost authentication, scope or page: %s %s", r.Method, r.URL)
					http.Error(w, "invalid shape request", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if scenario.outage {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"code":"NotAuthorizedOrNotFound","message":"shape listing denied"}`))
					return
				}
				if next := scenario.next[index]; next != nil {
					w.Header().Set("opc-next-page", *next)
				}
				if err := json.MarshalWrite(w, []core.Shape{{Shape: new(shapeNames[index])}, {}}); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(server.Close)
			client, err := core.NewComputeClientWithConfigurationProvider(provider)
			if err != nil {
				t.Fatal(err)
			}
			client.Host, client.HTTPClient = server.URL, server.Client()
			client.Configuration.RetryPolicy = new(common.NoRetryPolicy())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario.canceled {
				cancel()
			}
			shapes, err := capacityImageShapeNames(ctx, client, core.ListShapesRequest{CompartmentId: new("compartment"),
				AvailabilityDomain: new("AD-1"), ImageId: new("qualified-image")})
			if scenario.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), scenario.wantError) || shapes != nil {
					t.Fatalf("shape listing returned %v, %v; want no shapes and %q", shapes, err, scenario.wantError)
				}
			} else if err != nil || !slices.Equal(shapes, scenario.wantShapes) {
				t.Fatalf("shape listing returned %v, %v; want %v", shapes, err, scenario.wantShapes)
			}
			if got := int(requests.Load()); got != len(scenario.pages) {
				t.Fatalf("shape listing made %d requests; want exactly %d", got, len(scenario.pages))
			}
		})
	}
}
