package transitionreceipts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

func TestPublishPlanPinImmutableRecovery(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := provider.NewInstancePrincipalSigner("ST$test-only", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"create", "existing", "lost-response", "server-error", "conflict", "false-metadata", "ownership", "ownership-after", "future", "wrong-host", "cancelled", "redirect", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f := newReceiptFixture(t, true)
			for _, node := range []string{"gru-one", "gru-other", "sfo-one", "fra-one"} {
				t.Run(node, func(t *testing.T) {
					region, objectKey, err := PinObjectKey(f.plan, node)
					if err != nil {
						t.Fatal(err)
					}
					bucketPath := "/n/tenancy/b/" + region + "-control"
					objectPath := bucketPath + "/o/" + objectKey
					original := f.objects[objectPath]
					signed := original
					if mode == "future" {
						signed = f.future
					}
					if mode == "wrong-host" {
						node = "outside-plan"
					}
					var mu sync.Mutex
					var stored []byte
					puts, observations := 0, 0
					if mode == "existing" {
						stored = bytes.Clone(original)
					}
					if mode == "conflict" || mode == "false-metadata" {
						stored = bytes.Repeat([]byte("x"), len(original))
					}
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						defer mu.Unlock()
						if !strings.Contains(r.Header.Get("Authorization"), "Signature version=") {
							t.Error("unsigned request")
						}
						if r.URL.Path == bucketPath && r.Method == "GET" {
							observations++
							o := f.buckets[bucketPath]
							if mode == "ownership" || mode == "ownership-after" && observations > 1 {
								o.CompartmentID = "foreign"
							}
							raw, err := json.Marshal(o)
							if err != nil {
								t.Error(err)
							}
							w.Write(raw)
							return
						}
						if r.URL.Path != objectPath {
							t.Errorf("unexpected object %s", r.URL.Path)
							http.NotFound(w, r)
							return
						}
						if r.Method == "PUT" {
							puts++
							raw, err := io.ReadAll(r.Body)
							if err != nil {
								t.Error(err)
							}
							if r.Header.Get("If-None-Match") != "*" || !bytes.Equal(raw, original) || r.Header.Get("opc-meta-terrascale-sha256") != controltransition.Digest(original) {
								t.Error("unsafe upload")
							}
							if mode == "redirect" {
								http.Redirect(w, r, "/unexpected", 307)
								return
							}
							if mode == "missing" {
								w.WriteHeader(503)
								return
							}
							if stored != nil {
								w.WriteHeader(412)
								return
							}
							stored = bytes.Clone(raw)
							if mode == "lost-response" {
								conn, _, err := w.(http.Hijacker).Hijack()
								if err != nil {
									t.Error(err)
									return
								}
								conn.Close()
								return
							}
							if mode == "server-error" {
								w.WriteHeader(503)
								return
							}
							w.WriteHeader(200)
							return
						}
						if r.Method != "GET" {
							t.Errorf("unexpected method %s", r.Method)
						}
						if stored == nil {
							http.NotFound(w, r)
							return
						}
						digest := controltransition.Digest(stored)
						if mode == "false-metadata" {
							digest = controltransition.Digest(original)
						}
						w.Header().Set("Content-Length", fmt.Sprint(len(stored)))
						w.Header().Set("Etag", "receipt-etag")
						w.Header().Set("opc-meta-terrascale-sha256", digest)
						w.Write(stored)
					}))
					defer server.Close()
					endpoint, err := url.Parse(server.URL)
					if err != nil {
						t.Fatal(err)
					}
					client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						copy := r.Clone(r.Context())
						copy.URL = r.URL.Clone()
						copy.URL.Scheme = endpoint.Scheme
						copy.URL.Host = endpoint.Host
						return http.DefaultTransport.RoundTrip(copy)
					})}
					var o controltransition.ObjectLocation
					for _, d := range f.p.Destinations {
						if d.Region == region {
							o = d.Objects
						}
					}
					host, _ := provider.OCIServiceHost(provider.OCIServiceObjectStorage, o.OCIRegion)
					cfg, err := provider.NewOCIServiceTransportConfig(provider.OCIServiceObjectStorage, o.OCIRegion, "https://"+host)
					if err != nil {
						t.Fatal(err)
					}
					cfg.MaxRetries = 0
					transport, err := provider.NewOCIHTTPTransport(cfg, client, signer)
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					if mode == "cancelled" {
						cancel()
					}
					success := mode == "create" || mode == "existing" || mode == "lost-response" || mode == "server-error"
					for range 2 {
						err := PublishPlanPin(ctx, f.plan, node, signed, transport)
						if (err == nil) != success {
							t.Fatalf("success=%v error=%v", success, err)
						}
					}
					mu.Lock()
					defer mu.Unlock()
					if success && (!bytes.Equal(stored, original) || puts != 2) {
						t.Fatal("retry changed receipt or skipped verification")
					}
					if mode == "ownership" || mode == "future" || mode == "wrong-host" || mode == "cancelled" {
						if puts != 0 {
							t.Fatal("invalid authority reached PUT")
						}
					}
					if mode == "conflict" || mode == "false-metadata" {
						if bytes.Equal(stored, original) {
							t.Fatal("conflict overwritten")
						}
					}
				})
			}
		})
	}
}
