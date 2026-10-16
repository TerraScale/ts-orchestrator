package imagequalification

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"golang.org/x/crypto/ssh"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type qualificationFixture struct {
	prepared            Prepared
	wire                []byte
	roots               trust.Keyring
	private             ed25519.PrivateKey
	disk, qualification string
	now                 time.Time
}

func fixture(t *testing.T) qualificationFixture {
	t.Helper()
	directory := t.TempDir()
	disk := []byte{'Q', 'F', 'I', 0xfb, 0, 0, 0, 3, 0, 1, 2, 3}
	q := release.Qualification{Schema: release.QualificationSchema, Repository: release.QualificationRepository,
		SourceRevision: strings.Repeat("a", 40), SourceTree: strings.Repeat("b", 40), GoVersion: release.DefaultGoVersion,
		GoModSHA256: hashBytes([]byte("gomod")), GoSumSHA256: hashBytes([]byte("gosum")),
		Verification: release.QualificationCheck{Workflow: release.QualificationWorkflow, Job: release.QualificationJob,
			RunID: 42, RunNumber: 21, Conclusion: "success"}}
	for _, arch := range []string{"amd64", "arm64"} {
		q.Artifacts = append(q.Artifacts, release.QualifiedArtifact{Architecture: arch, Name: "terrascale-orchestrator-linux-" + arch,
			Bytes: 100, SHA256: hashBytes([]byte("binary-" + arch))})
	}
	qualification, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	a := Approval{Schema: ApprovalSchema, RunID: "nativecase", Candidate: release.ProductionExpectation{
		SourceRevision: q.SourceRevision, ArtifactSHA256: hashBytes(disk), QualificationSHA256: hashBytes(qualification),
		Cell: "GRU", Environment: "production", Runtime: release.ProductionRuntime, Architecture: "arm64", Role: "orchestrator"},
		OCIRegion: "sa-saopaulo-1", Tenancy: "ocid1.tenancy.oc1..fixture", Principal: "ocid1.user.oc1..fixture",
		Compartment: "ocid1.compartment.oc1..disposable", Subnet: "ocid1.subnet.oc1..disposable", Namespace: "fixture", Bucket: "qualification",
		Group: "ocid1.group.oc1..fixture", PolicyID: "ocid1.policy.oc1..fixture", PolicyStatements: []string{"fixture-exact-confined-policy"},
		RunnerCIDR: "10.9.0.1/32", PeerCIDR: "10.8.0.0/24", VCNCIDR: "10.8.0.0/15", WorkloadImage: "example.invalid/probe@sha256:" + hashBytes([]byte("image")),
		WorkloadArchiveSHA256: hashBytes([]byte("archive")), ImageBytes: int64(len(disk)), MaxSpendMicros: 10_000_000,
		CleanupUntil: now.Add(2 * time.Hour), BinarySHA256: q.Artifacts[1].SHA256, KernelSHA256: hashBytes([]byte("kernel")),
		ContainerdSHA256: hashBytes([]byte("containerd")), RuncSHA256: hashBytes([]byte("runc")), RunnerSHA256: hashBytes([]byte("runner"))}
	for index := range 3 {
		a.Hosts = append(a.Hosts, HostSpec{Name: fmt.Sprintf("manager-%d", index+1), AvailabilityDomain: "fixture-ad",
			FaultDomain: fmt.Sprintf("FAULT-DOMAIN-%d", index+1), Shape: "VM.Standard.A1.Flex", OCPUs: 1, MemoryGB: 6, BootGB: 50})
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, ApprovalScope(a.RunID, a.Candidate), now.Add(-time.Minute), now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	diskPath, qualificationPath := filepath.Join(directory, "final.qcow2"), filepath.Join(directory, "qualification.json")
	if err := os.WriteFile(diskPath, disk, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(qualificationPath, qualification, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(wire, nil, roots, a.Candidate, a.RunID, diskPath, qualificationPath, now)
	if err != nil {
		t.Fatal(err)
	}
	return qualificationFixture{p, wire, roots, private, diskPath, qualificationPath, now}
}

func TestSignedRunRejectsChangedDiskSourceAndProductionAuthority(t *testing.T) {
	f := fixture(t)
	a := f.prepared.Approval()
	t.Run("different-source", func(t *testing.T) {
		candidate := a.Candidate
		candidate.SourceRevision = strings.Repeat("c", 40)
		if _, err := Prepare(f.wire, nil, f.roots, candidate, a.RunID, f.disk, f.qualification, f.now); err == nil {
			t.Fatal("changed source accepted")
		}
	})
	t.Run("production-signature", func(t *testing.T) {
		payload, _ := json.Marshal(a)
		envelope, err := trust.Sign(payload, release.ProductionQualificationScope(a.Candidate), f.now.Add(-time.Minute), f.now.Add(time.Hour), f.private)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := json.Marshal(envelope)
		if _, err := Prepare(wire, nil, f.roots, a.Candidate, a.RunID, f.disk, f.qualification, f.now); err == nil {
			t.Fatal("production qualification signature granted disposable privilege")
		}
	})
	t.Run("modified-qcow2", func(t *testing.T) {
		if err := os.WriteFile(f.disk, []byte("same-length!"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Prepare(f.wire, nil, f.roots, a.Candidate, a.RunID, f.disk, f.qualification, f.now); err == nil {
			t.Fatal("modified image accepted")
		}
	})
}

type cloudFixture struct {
	mu                         sync.Mutex
	image                      map[string]any
	hosts                      map[string]map[string]any
	tokens                     map[string]string
	object                     []byte
	metadata                   map[string]string
	creates, launches, deletes int
	failSecond                 bool
	requests                   []string
}

func (f *cloudFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("opc-request-id", "fixture-request")
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
		w.WriteHeader(401)
		return
	}
	reply := func(status int, value any) {
		w.WriteHeader(status)
		if value != nil {
			_ = json.MarshalWrite(w, value)
		}
	}
	if strings.HasPrefix(r.URL.Path, "/n/") {
		switch r.Method {
		case "HEAD":
			if f.object == nil {
				w.WriteHeader(404)
				return
			}
			for key, value := range f.metadata {
				w.Header().Set("opc-meta-"+key, value)
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(f.object)))
			w.WriteHeader(200)
		case "PUT":
			if f.object != nil {
				w.WriteHeader(412)
				return
			}
			f.object, _ = io.ReadAll(r.Body)
			f.metadata = map[string]string{"sha256": r.Header.Get("opc-meta-sha256"), "approval": r.Header.Get("opc-meta-approval")}
			w.WriteHeader(200)
		case "DELETE":
			f.object = nil
			f.deletes++
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
		return
	}
	if r.URL.Path == "/20160918/images" && r.Method == "POST" {
		if f.image == nil {
			if err := json.UnmarshalRead(r.Body, &f.image); err != nil {
				reply(400, map[string]string{"message": err.Error()})
				return
			}
			f.image["id"], f.image["lifecycleState"] = "ocid1.image.oc1..native", "AVAILABLE"
			f.creates++
		}
		reply(200, f.image)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/20160918/images/") {
		if f.image == nil {
			reply(404, map[string]string{"code": "NotAuthorizedOrNotFound"})
			return
		}
		if r.Method == "DELETE" {
			f.image = nil
			f.deletes++
			w.WriteHeader(204)
			return
		}
		reply(200, f.image)
		return
	}
	if r.URL.Path == "/20160918/instances" && r.Method == "POST" {
		var input map[string]any
		if err := json.UnmarshalRead(r.Body, &input); err != nil {
			reply(400, map[string]string{"message": err.Error()})
			return
		}
		if f.failSecond && len(f.hosts) == 1 {
			f.failSecond = false
			reply(503, map[string]string{"code": "ServiceUnavailable"})
			return
		}
		token := r.Header.Get("opc-retry-token")
		id := f.tokens[token]
		if id == "" {
			id = fmt.Sprintf("ocid1.instance.oc1..native%d", len(f.hosts)+1)
			input["id"], input["lifecycleState"], input["imageId"] = id, "RUNNING", "ocid1.image.oc1..native"
			f.hosts[id], f.tokens[token] = input, id
			f.launches++
		}
		reply(200, f.hosts[id])
		return
	}
	if strings.HasPrefix(r.URL.Path, "/20160918/instances/") {
		id := strings.TrimPrefix(r.URL.Path, "/20160918/instances/")
		host := f.hosts[id]
		if host == nil {
			reply(404, map[string]string{"code": "NotAuthorizedOrNotFound"})
			return
		}
		if r.Method == "DELETE" {
			host["lifecycleState"] = "TERMINATED"
			f.deletes++
			w.WriteHeader(204)
			return
		}
		reply(200, host)
		return
	}
	reply(404, map[string]string{"code": "NotAuthorizedOrNotFound"})
}

func sdkFactory(t *testing.T, a Approval) *ociclient.Factory {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider(a.Tenancy, a.Principal, a.OCIRegion, "00:00:00:00", string(pemKey), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: a.OCIRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

func publicSSHKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func TestSDKQualificationResumesExactResourcesAndCleansOnlyOwnedHosts(t *testing.T) {
	f := fixture(t)
	remote := &cloudFixture{hosts: map[string]map[string]any{}, tokens: map[string]string{}, failSecond: true}
	server := httptest.NewServer(http.HandlerFunc(remote.serve))
	defer server.Close()
	factory := sdkFactory(t, f.prepared.Approval())
	client, err := newCloud(f.prepared, factory, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "resources.json")
	publicKey := publicSSHKey(t)
	partial, err := client.prepareResources(t.Context(), path, publicKey)
	if err == nil || len(partial.Hosts) != 1 {
		t.Fatalf("partial launch result=%+v error=%v", partial, err)
	}
	client, err = newCloud(f.prepared, factory, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := client.prepareResources(t.Context(), path, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(complete.Hosts) != 3 || remote.creates != 1 || remote.launches != 3 {
		t.Fatalf("duplicate or missing resources: %+v", complete)
	}
	for _, host := range remote.hosts {
		vnic := host["createVnicDetails"].(map[string]any)
		if vnic["assignPublicIp"] != false || vnic["subnetId"] != f.prepared.approval.Subnet {
			t.Fatal("host escaped private approved network")
		}
		metadata := host["metadata"].(map[string]any)
		if len(metadata) != 2 || metadata["ssh_authorized_keys"] != publicKey {
			t.Fatal("unexpected launch credential metadata")
		}
	}
	firstID := complete.Hosts[f.prepared.approval.Hosts[0].Name]
	ownedTags := remote.hosts[firstID]["freeformTags"]
	remote.hosts[firstID]["freeformTags"] = map[string]any{runTag: "different-run"}
	if err := client.cleanup(t.Context(), path); err == nil || remote.deletes != 0 {
		t.Fatal("cleanup deleted an unowned host")
	}
	remote.hosts[firstID]["freeformTags"] = ownedTags
	client.now = func() time.Time { return f.prepared.expires.Add(time.Minute) }
	if _, err := client.prepareResources(t.Context(), path, publicKey); err == nil {
		t.Fatal("expired authority provisioned hosts")
	}
	if err := client.cleanup(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	retained, err := client.load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !retained.ImageDeleted || !retained.ObjectDeleted || len(retained.Terminated) != 3 || remote.object != nil {
		t.Fatalf("cleanup incomplete: %+v", retained)
	}
	if err := client.cleanup(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	if remote.deletes != 5 {
		t.Fatalf("cleanup replay deleted %d objects", remote.deletes)
	}
	for _, request := range remote.requests {
		if strings.Contains(request, "/users") || strings.Contains(request, "/vault") || strings.Contains(request, "netbird") {
			t.Fatalf("production privilege path used: %s", request)
		}
	}
}
