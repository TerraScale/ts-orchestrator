package attempt

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestPhaseStatusThroughSignedOCISDK(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	const tenancy = "ocid1.tenancy.oc1..status"
	const user = "ocid1.user.oc1..status"
	const fingerprint = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
	signatureRE := regexp.MustCompile(`^Signature version="1",headers="date \(request-target\) host",keyId="` + regexp.QuoteMeta(tenancy+"/"+user+"/"+fingerprint) + `",algorithm="rsa-sha256",signature="([A-Za-z0-9+/=]+)"$`)
	for _, scenario := range []struct {
		name, cell, failedPage string
	}{
		{"SFO current and retained names", catalog.SFO, ""},
		{"GRU retained controller names", catalog.GRU, ""},
		{"control later page error", catalog.SFO, "control:second-control"},
		{"workload later page error", catalog.SFO, "workload:second-workload"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			entry, _ := catalog.Lookup(scenario.cell)
			region := strings.ToLower(scenario.cell)
			type row struct {
				ID    string `json:"id"`
				Name  string `json:"displayName"`
				State string `json:"lifecycleState"`
			}
			pages := map[string][]row{
				"control:": {
					{"ocid1.instance.oc1..current-control", "ts-" + region + "-1", "RUNNING"},
					{"ocid1.instance.oc1..foreign", "ts-fra-1", "RUNNING"},
					{"ocid1.instance.oc1..data", "ts-" + region + "-1-data", "RUNNING"},
					{"ocid1.instance.oc1..terminated", "ts-" + region + "-9", "TERMINATED"},
					{"ocid1.instance.oc1..malformed", "ts-" + region + "-invalid", "RUNNING"},
				},
				"control:second-control": {
					{"ocid1.instance.oc1..legacy-control", region + "-1-ctl-1", "RUNNING"},
					{"ocid1.instance.oc1..legacy-terminated", region + "-1-ctl-9", "TERMINATED"},
					{"ocid1.instance.oc1..legacy-foreign", "fra-1-ctl-1", "RUNNING"},
				},
				"workload:": {
					{"ocid1.instance.oc1..current-workload", "ts-" + region + "-2", "STOPPED"},
				},
				"workload:second-workload": {
					{"ocid1.instance.oc1..legacy-workload", region + "-1-db-1", "RUNNING"},
					{"ocid1.instance.oc1..retained-prefix", region + "-1-retained-custom", "RUNNING"},
				},
			}
			var mu sync.Mutex
			var requests []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				match := signatureRE.FindStringSubmatch(r.Header.Get("Authorization"))
				if r.Method != http.MethodGet || match == nil {
					t.Errorf("expected signed read, got %s %s", r.Method, r.URL)
					http.Error(w, "expected signed GET", http.StatusBadRequest)
					return
				}
				signature, decodeErr := base64.StdEncoding.DecodeString(match[1])
				digest := sha256.Sum256([]byte("date: " + r.Header.Get("Date") + "\n(request-target): get " + r.URL.RequestURI() + "\nhost: " + r.Host))
				if decodeErr != nil || rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature) != nil {
					t.Error("OCI request signature did not verify with local credentials")
					http.Error(w, "invalid signature", http.StatusBadRequest)
					return
				}
				for _, bucket := range []string{"head", "ledger"} {
					if r.URL.Path == "/n/status-namespace/b/"+bucket+"/o" {
						requests = append(requests, "objects:"+bucket+":"+r.URL.Query().Get("prefix"))
						_, _ = io.WriteString(w, `{"objects":[]}`)
						return
					}
				}
				if r.URL.Path == "/20160918/instances" {
					compartment := strings.TrimPrefix(r.URL.Query().Get("compartmentId"), "ocid1.compartment.oc1..")
					page := compartment + ":" + r.URL.Query().Get("page")
					requests = append(requests, page)
					if page == scenario.failedPage {
						w.Header().Set("opc-request-id", "status-later-page")
						w.WriteHeader(http.StatusBadRequest)
						_, _ = io.WriteString(w, `{"code":"StatusPageFailed","message":"later page failed"}`)
						return
					}
					if items, ok := pages[page]; ok {
						if r.URL.Query().Get("page") == "" {
							w.Header().Set("opc-next-page", "second-"+compartment)
						}
						if err := json.MarshalWrite(w, items); err != nil {
							t.Errorf("write OCI page: %v", err)
						}
						return
					}
				}
				t.Errorf("unexpected OCI request: %s", r.URL)
				http.Error(w, "unexpected request", http.StatusNotFound)
			}))
			defer server.Close()

			dir := t.TempDir()
			writeJSON := func(path string, value any) {
				t.Helper()
				wire, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, wire, 0600); err != nil {
					t.Fatal(err)
				}
			}
			const deployment = "0000000000F9PR1WNVDTEXS31Z"
			config := filepath.Join(dir, "config.json")
			writeJSON(config, Object{"workdir": filepath.Join(dir, "work"), "deployment_id": deployment, "prefix": "status", "namespace": "status-namespace"})
			var output bytes.Buffer
			a, err := New(t.Context(), config, &output, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			writeJSON(a.Plan(), Object{"cell": scenario.cell,
				"foundation_buckets": Object{"head": "head", "ledger": "ledger"},
				"resource_ids":       Object{"control_compartment": "ocid1.compartment.oc1..control", "workload_compartment": "ocid1.compartment.oc1..workload"}})
			provider := common.NewRawConfigurationProvider(tenancy, user, entry.OCIRegion, fingerprint, string(pemKey), nil)
			factory, err := ociclient.New(provider, ociclient.Options{Region: entry.OCIRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
			if err != nil {
				t.Fatal(err)
			}
			compute, err := factory.Compute()
			if err != nil {
				t.Fatal(err)
			}
			objects, err := factory.ObjectStorage()
			if err != nil {
				t.Fatal(err)
			}
			ociclient.PinHost(&compute.BaseClient, server.URL)
			ociclient.PinHost(&objects.BaseClient, server.URL)
			a.Cloud = &sdkCloud{compute: compute, objects: objects}

			err = a.Phase("status")
			if scenario.failedPage == "" {
				if err != nil {
					t.Fatal(err)
				}
				var got []string
				for line := range strings.SplitSeq(output.String(), "\n") {
					if strings.HasPrefix(line, "instance ") {
						got = append(got, line)
					}
				}
				want := []string{
					fmt.Sprintf("instance ts-%s-1 RUNNING ocid1.instance.oc1..current-control", region),
					fmt.Sprintf("instance %s-1-ctl-1 RUNNING ocid1.instance.oc1..legacy-control", region),
					fmt.Sprintf("instance ts-%s-2 STOPPED ocid1.instance.oc1..current-workload", region),
					fmt.Sprintf("instance %s-1-db-1 RUNNING ocid1.instance.oc1..legacy-workload", region),
					fmt.Sprintf("instance %s-1-retained-custom RUNNING ocid1.instance.oc1..retained-prefix", region),
				}
				if !slices.Equal(got, want) {
					t.Errorf("status instances = %q, want %q", got, want)
				}
			} else if serviceErr, ok := errors.AsType[common.ServiceError](err); !ok || serviceErr.GetCode() != "StatusPageFailed" ||
				serviceErr.GetHTTPStatusCode() != http.StatusBadRequest || serviceErr.GetOpcRequestID() != "status-later-page" ||
				!strings.Contains(err.Error(), "list OCI instances:") {
				t.Errorf("later-page OCI error was not propagated: %v", err)
			}
			wantRequests := []string{
				"objects:head:status/bootstrap/v1/" + deployment + "/", "objects:head:status/bootstrap/v2/" + deployment + "/",
				"objects:ledger:status/bootstrap/v1/" + deployment + "/", "objects:ledger:status/bootstrap/v2/" + deployment + "/",
				"control:", "control:second-control",
			}
			if scenario.failedPage != "control:second-control" {
				wantRequests = append(wantRequests, "workload:", "workload:second-workload")
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(requests, wantRequests) {
				t.Errorf("OCI page chain = %q, want %q", requests, wantRequests)
			}
		})
	}
}
