package terrabase

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"debug/elf"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"golang.org/x/sys/unix"
)

const restoreDocument = "/v1/projects/00000000000000000000000002/databases/00000000000000000000000003/collections/00000000000000000000000004/documents/00000000000000000000000005"

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
	if err := runRestoreCheck(t.Context(), []string{"--plan", plan, "--binary", binary, "--organization", "00000000000000000000000001",
		"--document", restoreDocument, "--scratch-instance", "ocid1.instance.scratch", "--restored-volume", "ocid1.volume.restored"}, &output); err != nil {
		t.Fatal(err)
	}
	var got restoreCheckRequest
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := restoreCheckRequest{Step: "plan", Plan: plan, Compartment: "ocid1.compartment.workload", Device: "/dev/oracleoci/oraclevdz",
		ScratchInstance: "ocid1.instance.scratch", RestoredVolume: "ocid1.volume.restored", Binary: binary,
		Document: restoreDocument, ReadyPath: "/readyz"}
	if got != want || !strings.Contains(output.String(), `"apply":false`) {
		t.Fatalf("plan = %s, want %+v", output.String(), want)
	}
}

func TestRestoreCheckRejectsBadFlags(t *testing.T) {
	binary := fakeRelease(t)
	plan := restorePlan(t)
	unverified := filepath.Join(t.TempDir(), "terrabase-linux-amd64")
	writeFile(t, unverified, []byte("\x7fELF"))
	base := []string{"--plan", plan, "--binary", binary, "--organization", "00000000000000000000000001", "--scratch-instance", "ocid1.instance.scratch",
		"--restored-volume", "ocid1.volume.restored"}
	for name, args := range map[string][]string{
		"no binary":       {"--organization", "o", "--document", restoreDocument},
		"no organization": {"--binary", binary, "--document", restoreDocument},
		"no document":     base,
		"unknown flag":    append(slices.Clone(base), "--document", restoreDocument, "--format"),
		"extra argument":  append(slices.Clone(base), "--document", restoreDocument, "extra"),
		"no checksum":     {"--plan", plan, "--binary", unverified, "--organization", "o", "--document", restoreDocument, "--scratch-instance", "ocid1.instance.scratch", "--restored-volume", "ocid1.volume.restored"},
		"no scratch":      {"--binary", binary, "--organization", "o", "--document", restoreDocument},
		"not an instance": {"--binary", binary, "--organization", "o", "--document", restoreDocument, "--scratch-instance", "ocid1.volume.x"},
		"no plan":         {"--binary", binary, "--organization", "o", "--document", restoreDocument, "--scratch-instance", "ocid1.instance.scratch", "--restored-volume", "ocid1.volume.restored"},
		"no restored ID":  {"--plan", plan, "--binary", binary, "--organization", "o", "--document", restoreDocument, "--scratch-instance", "ocid1.instance.scratch"},
		"not a volume":    append(slices.Clone(base), "--document", restoreDocument, "--restored-volume", "ocid1.instance.scratch"),
		"bad volume ID":   append(slices.Clone(base), "--document", restoreDocument, "--restored-volume", "ocid1.volume.restore/other"),
		"traversal":       append(slices.Clone(base), "--document", "/v1/projects/p/databases/../collections/c/documents/x"),
		"dot segment":     append(slices.Clone(base), "--document", "/v1/projects/p/databases/d/collections/./documents/x"),
		"query":           append(slices.Clone(base), "--document", restoreDocument+"?x=1"),
		"fragment":        append(slices.Clone(base), "--document", restoreDocument+"#x"),
		"escaped":         append(slices.Clone(base), "--document", "/v1/projects/p/databases/d/collections/c/documents/%2e%2e"),
		"empty segment":   append(slices.Clone(base), "--document", "/v1/projects//databases/d/collections/c/documents/x"),
		"extra segment":   append(slices.Clone(base), "--document", restoreDocument+"/more"),
		"other prefix":    append(slices.Clone(base), "--document", "/v2/projects/p/databases/d/collections/c/documents/x"),
		"device flag":     append(slices.Clone(base), "--document", restoreDocument, "--device", "/dev/oracleoci/oraclevdb"),
		"bad ready path":  append(slices.Clone(base), "--document", restoreDocument, "--ready-path", "/../admin"),
		"no wait":         append(slices.Clone(base), "--document", restoreDocument, "--wait", "0s"),
	} {
		var output bytes.Buffer
		if err := runRestoreCheck(t.Context(), args, &output); err == nil {
			t.Errorf("%s was accepted: %s", name, output.String())
		}
	}
}

func TestRestoreCheckEnvHasOnlyHostPathsAndNoPeers(t *testing.T) {
	layout := Layout("/tmp/restore")
	got := restoreCheckEnv(layout, 1001, 1002)
	want := []string{"HOME=/", "LANG=C", "PATH=/usr/bin:/bin",
		"TERRABASE_DATA_DIRECTORY=/tmp/restore/data", "DOTNET_BUNDLE_EXTRACT_BASE_DIR=/tmp/restore/bundle",
		"TERRABASE_ADMIN_PORT=1001", "TERRABASE_CLIENT_PORT=1002",
		"TERRABASE_CLIENT_CERTIFICATE=/tmp/restore/tls/member.pem", "TERRABASE_CLIENT_PRIVATE_KEY=/tmp/restore/tls/member.key"}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("env = %q, want %q", got, want)
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
		if r.URL.Path != restoreDocument || r.Header.Get("Authorization") != "Bearer s3cret" {
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
		project: "00000000000000000000000002", database: "00000000000000000000000003", id: "00000000000000000000000005", wait: wait}
	return verifyRestore(t.Context(), &http.Client{Transport: transport, Timeout: 5 * time.Second},
		adminServer.URL, clientServer.URL, request)
}

func TestRestoreCheckProvenanceFailurePreventsMount(t *testing.T) {
	request := restoreCheckRequest{ScratchInstance: "ocid1.instance.scratch", RestoredVolume: "ocid1.volume.restored", Device: oci.RestoreVolumeDevice}
	for _, reason := range []string{"attached volume is ocid1.volume.swapped", "volume has member-data tag instead of member-data-restore"} {
		rejected := fmt.Errorf("%w: %s", oci.ErrForeignResource, reason)
		called := false
		err := mountRestoredDevice(t.Context(), request, -1, Layout(t.TempDir()),
			func(_ context.Context, scratchID, restoredID string) (oci.Attachment, error) {
				called = true
				if scratchID != request.ScratchInstance || restoredID != request.RestoredVolume {
					t.Fatalf("OCI read received scratch=%q volume=%q", scratchID, restoredID)
				}
				return oci.Attachment{}, rejected
			})
		if !called || !errors.Is(err, rejected) || !strings.Contains(err.Error(), "before mount") {
			t.Fatalf("provenance failure reached mount: %v", err)
		}
	}
}

func TestRestoreCheckReverifiesBeforeStartingMember(t *testing.T) {
	request := restoreCheckRequest{ScratchInstance: "ocid1.instance.scratch", RestoredVolume: "ocid1.volume.restored", Device: oci.RestoreVolumeDevice}
	rejected := fmt.Errorf("%w: restored attachment swapped after mount", oci.ErrForeignResource)
	called := false
	etag, err := checkMountedRestore(t.Context(), request, -1, Layout(t.TempDir()),
		func(_ context.Context, scratchID, restoredID string) (oci.Attachment, error) {
			called = true
			if scratchID != request.ScratchInstance || restoredID != request.RestoredVolume {
				t.Fatalf("OCI read received scratch=%q volume=%q", scratchID, restoredID)
			}
			return oci.Attachment{}, rejected
		})
	if !called || etag != "" || !errors.Is(err, rejected) || !strings.Contains(err.Error(), "before starting terrabase") {
		t.Fatalf("swapped mounted volume reached binary startup: %q, %v", etag, err)
	}
}

func TestRestoreCheckReopensDeviceAfterOCIRead(t *testing.T) {
	root := t.TempDir()
	original, replacement, path := filepath.Join(root, "original"), filepath.Join(root, "replacement"), filepath.Join(root, "restore-device")
	writeFile(t, original, nil)
	writeFile(t, replacement, nil)
	if err := os.Symlink(original, path); err != nil {
		t.Fatal(err)
	}
	pinned, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pinned)
	request := restoreCheckRequest{Device: path}
	verify := func(context.Context, string, string) (oci.Attachment, error) { return oci.Attachment{}, nil }
	if err := verifyRestoredDevice(t.Context(), request, pinned, verify); err != nil {
		t.Fatalf("unchanged device was refused: %v", err)
	}
	// Replace the consistent device path while the OCI read is in flight.
	verify = func(context.Context, string, string) (oci.Attachment, error) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(replacement, path); err != nil {
			t.Fatal(err)
		}
		return oci.Attachment{}, nil
	}
	if err := verifyRestoredDevice(t.Context(), request, pinned, verify); err == nil || !strings.Contains(err.Error(), "changed during OCI verification") {
		t.Fatalf("replaced device passed OCI verification: %v", err)
	}
}

func TestRestoreVolumeConfigUsesThePlanScope(t *testing.T) {
	plan := restorePlan(t)
	for _, compartment := range []string{"", "ocid1.compartment.override"} {
		config, err := restoreVolumeConfig(plan, compartment)
		want := "ocid1.compartment.workload"
		if compartment != "" {
			want = compartment
		}
		if err != nil || config.Region != oci.RegionGRU || config.AvailabilityDomain != "AD-1" || config.CompartmentID != want {
			t.Fatalf("scope = %+v, %v", config, err)
		}
	}
	for _, data := range []string{`{`, `{"cell":"GRU"}`, `{"cell":"unknown","availability_domain":"AD","resource_ids":{"workload_compartment":"c"}}`} {
		writeFile(t, plan, []byte(data))
		if _, err := restoreVolumeConfig(plan, ""); err == nil {
			t.Fatalf("accepted invalid restore scope %s", data)
		}
	}
}

func TestVerifyRestoreReadsTheDocumentWithAReadOnlyKey(t *testing.T) {
	ok := restoreServers{readyStatus: http.StatusOK, keyStatus: http.StatusCreated, keySecret: "s3cret",
		docStatus: http.StatusOK, docID: "00000000000000000000000005"}
	etag, err := ok.verify(t, 5*time.Second)
	if err != nil || etag != `"v7"` {
		t.Fatalf("verify = %q, %v", etag, err)
	}
	for name, servers := range map[string]restoreServers{
		"never ready":  {readyStatus: http.StatusServiceUnavailable, keyStatus: http.StatusCreated, keySecret: "s3cret", docStatus: http.StatusOK, docID: "00000000000000000000000005"},
		"key rejected": {readyStatus: http.StatusOK, keyStatus: http.StatusBadRequest, keySecret: "s3cret", docStatus: http.StatusOK, docID: "00000000000000000000000005"},
		"no document":  {readyStatus: http.StatusOK, keyStatus: http.StatusCreated, keySecret: "s3cret", docStatus: http.StatusNotFound, docID: "00000000000000000000000005"},
		"other id":     {readyStatus: http.StatusOK, keyStatus: http.StatusCreated, keySecret: "s3cret", docStatus: http.StatusOK, docID: "00000000000000000000000006"},
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
