package terrabase

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"debug/elf"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const restoreDocument = "/v1/projects/00000000000000000000000002/databases/atlas/collections/restore_canary/documents/by-key?id=00000000000000000000000005"

func restorePlan(t *testing.T) string {
	t.Helper()
	plan := filepath.Join(t.TempDir(), "plan.json")
	writeFile(t, plan, []byte(`{"cell":"GRU","availability_domain":"AD-1","volume_vpus_per_gb":10,
		"resource_ids":{"workload_compartment":"ocid1.compartment.workload"}}`))
	return plan
}

// fakeRelease writes an ELF-looking terrabase-linux-amd64 and its .sha256
// asset, enough for VerifyRelease.
func fakeRelease(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "terrabase-linux-amd64")
	data := append(elfHeader(elf.EM_X86_64), "restore-check fixture"...)
	sum := sha256.Sum256(data)
	writeFile(t, binary, data)
	writeFile(t, binary+".sha256", []byte(hex.EncodeToString(sum[:])+"  terrabase-linux-amd64\n"))
	return binary
}

func TestRestoreCheckPlanWithoutApply(t *testing.T) {
	binary := fakeRelease(t)
	plan := restorePlan(t)
	var output bytes.Buffer
	if err := runRestoreCheck(t.Context(), []string{"--plan", plan, "--binary", binary, "--organization", "00000000000000000000000001", "--database", "00000000000000000000000003",
		"--document", restoreDocument, "--scratch-instance", "ocid1.instance.scratch", "--restored-volume", "ocid1.volume.restored"}, &output); err != nil {
		t.Fatal(err)
	}
	var got restoreCheckRequest
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := restoreCheckRequest{Step: "plan", Plan: plan, Compartment: "ocid1.compartment.workload", Device: "/dev/oracleoci/oraclevdz",
		ScratchInstance: "ocid1.instance.scratch", RestoredVolume: "ocid1.volume.restored", Binary: binary,
		Document: restoreDocument, DatabaseID: "00000000000000000000000003", ReadyPath: "/readyz"}
	if got != want || !strings.Contains(output.String(), `"apply":false`) {
		t.Fatalf("plan = %s, want %+v", output.String(), want)
	}
}

// restoreServers are a fake member: a plain HTTP admin listener and a TLS
// client listener whose certificate comes from writeRestoreIdentity.
type restoreServers struct {
	readyStatus int
	keyStatus   int
	keySecret   string
	docStatus   int
	docID       string
}

func (s restoreServers) verify(t *testing.T, wait time.Duration) (string, error) {
	t.Helper()
	admin := http.NewServeMux()
	// Liveness on admin must never satisfy the readiness gate on client TLS.
	admin.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	admin.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("readiness was requested on the admin listener")
		w.WriteHeader(http.StatusOK)
	})
	admin.HandleFunc("POST /admin/api-keys", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name           string   `json:"name"`
			Scopes         []string `json:"scopes"`
			OrganizationID string   `json:"organizationId"`
			ProjectID      string   `json:"projectId"`
			DatabaseID     string   `json:"databaseId"`
		}
		if err := json.UnmarshalRead(r.Body, &body); err != nil || body.Name != "restore-check" ||
			!slices.Equal(body.Scopes, []string{"documents:read"}) || body.OrganizationID != "00000000000000000000000001" ||
			body.ProjectID != "00000000000000000000000002" || body.DatabaseID != "00000000000000000000000003" {
			t.Errorf("API key request = %+v, %v", body, err)
		}
		w.WriteHeader(s.keyStatus)
		if s.keyStatus != http.StatusCreated {
			fmt.Fprint(w, `{"error":"invalid scopes"}`)
			return
		}
		fmt.Fprintf(w, `{"id":"key-1","secret":%q}`, s.keySecret)
	})
	adminServer := httptest.NewServer(admin)
	defer adminServer.Close()

	layout := Layout(t.TempDir())
	if err := os.Mkdir(layout.TLS(), 0o700); err != nil {
		t.Fatal(err)
	}
	caPEM, err := writeRestoreIdentity(layout, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(layout.Certificate(), layout.Key())
	if err != nil {
		t.Fatal(err)
	}
	clientServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			if r.Header.Get("Authorization") != "" {
				t.Error("readiness should not need an API key")
			}
			w.WriteHeader(s.readyStatus)
			return
		}
		if r.URL.RequestURI() != restoreDocument || r.Header.Get("Authorization") != "Bearer s3cret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("ETag", `"v7"`)
		w.WriteHeader(s.docStatus)
		fmt.Fprintf(w, `{"id":%q,"data":{"name":"restored"}}`, s.docID)
	}))
	clientServer.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	clientServer.StartTLS()
	defer clientServer.Close()

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.CloseIdleConnections()
	request := restoreCheckRequest{Document: restoreDocument, ReadyPath: "/readyz", organization: "00000000000000000000000001",
		project: "00000000000000000000000002", DatabaseID: "00000000000000000000000003", id: "00000000000000000000000005", wait: wait}
	return verifyRestore(t.Context(), &http.Client{Transport: transport, Timeout: 5 * time.Second},
		adminServer.URL, clientServer.URL, request)
}

func TestVerifyRestoreReadsTheDocumentWithAReadOnlyKey(t *testing.T) {
	ok := restoreServers{readyStatus: http.StatusOK, keyStatus: http.StatusCreated, keySecret: "s3cret",
		docStatus: http.StatusOK, docID: "00000000000000000000000005"}
	etag, err := ok.verify(t, 5*time.Second)
	if err != nil || etag != `"v7"` {
		t.Fatalf("verify = %q, %v", etag, err)
	}
	for name, servers := range map[string]restoreServers{
		"wrong bearer": {readyStatus: http.StatusOK, keyStatus: http.StatusCreated, keySecret: "other", docStatus: http.StatusOK, docID: "00000000000000000000000005"},
	} {
		etag, err := servers.verify(t, 600*time.Millisecond)
		if err == nil {
			t.Errorf("%s verified with ETag %q", name, etag)
		} else if strings.Contains(err.Error(), servers.keySecret) {
			t.Errorf("%s error reveals the API key secret: %v", name, err)
		}
	}
}

// TestRestoreCheckRefusesLiveDevices never admits a non-block path or the
// disk the running system is on, which is mounted.
func TestRestoreCheckRefusesLiveDevices(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-device")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if device, err := admitRestoredDevice(file); err == nil {
		unix.Close(device)
		t.Fatal("admitted a regular file")
	}
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(info)) {
		fields := strings.Fields(line)
		if len(fields) > 4 && fields[4] == "/" {
			root := "/dev/block/" + fields[2]
			if _, err := os.Stat(root); err != nil {
				t.Skipf("root filesystem %s is not on a block device", fields[2])
			}
			if device, err := admitRestoredDevice(root); err == nil {
				unix.Close(device)
				t.Fatalf("admitted the mounted root device %s", root)
			}
			return
		}
	}
	t.Skip("no root mount in mountinfo")
}

// TestRestoreCheckRunsOnlyOnTheVerifiedScratchInstance compares this
// instance's OCID from instance metadata with --scratch-instance.
func TestRestoreCheckRunsOnlyOnTheVerifiedScratchInstance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer Oracle" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "ocid1.instance.scratch\n")
	}))
	defer server.Close()
	original := imdsInstanceIDURL
	imdsInstanceIDURL = server.URL
	t.Cleanup(func() { imdsInstanceIDURL = original })
	if err := requireScratchInstance(t.Context(), "ocid1.instance.scratch"); err != nil {
		t.Fatalf("the verified scratch instance was refused: %v", err)
	}
	if err := requireScratchInstance(t.Context(), "ocid1.instance.member"); err == nil {
		t.Fatal("ran on an instance other than the verified scratch instance")
	}
}
