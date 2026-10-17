package imagequalification

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"golang.org/x/crypto/ssh"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
)

// These are signed test inputs and constructed reports, never executable image
// acceptance or production NetBird membership.
func netBirdFixture(t *testing.T) (qualificationFixture, netBirdPaths) {
	t.Helper()
	f := fixture(t)
	a := f.prepared.Approval()
	a.Candidate.Role, a.Candidate.Runtime = "netbird-manager", "netbird-containerd"
	a.MaterialFixtures, a.ProfileIdentity = nil, cellspec.Identity{}
	a.WorkloadImage, a.WorkloadArchiveSHA256 = "", ""
	a.Hosts = a.Hosts[:2]
	a.Hosts[0].Role, a.Hosts[1].Role = "netbird-primary", "netbird-replacement"
	directory := t.TempDir()
	paths := netBirdPaths{Journal: filepath.Join(directory, "resources.json"), EvidenceDirectory: filepath.Join(directory, "evidence"), Containerd: "/usr/bin/containerd", Runc: "/usr/bin/runc", Archives: map[string]string{}}
	write := func(name string) (string, string) {
		path := filepath.Join(directory, name)
		wire := []byte("signed local fixture artifact: " + name)
		if err := os.WriteFile(path, wire, 0600); err != nil {
			t.Fatal(err)
		}
		return path, hashBytes(wire)
	}
	paths.Worker, a.RunnerSHA256 = write("worker")
	paths.Client, a.ClientSHA256 = write("client")
	for _, role := range []string{"server", "dashboard", "ingress"} {
		path, digest := write(role + ".oci")
		paths.Archives[role] = path
		a.ContainerArtifacts = append(a.ContainerArtifacts, ContainerArtifactApproval{Role: role, Image: "example.invalid/netbird/" + role + "@sha256:" + hashBytes([]byte(role)), ArchiveSHA256: digest})
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "ephemeral qualification fixture")
	if err != nil {
		t.Fatal(err)
	}
	paths.PrivateKey = filepath.Join(directory, "ssh-key")
	if err := os.WriteFile(paths.PrivateKey, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, ApprovalScope(a.RunID, a.Candidate), f.now.Add(-1), f.prepared.expires, f.private)
	if err != nil {
		t.Fatal(err)
	}
	f.wire, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	f.prepared, err = Prepare(f.wire, nil, f.roots, a.Candidate, a.RunID, f.disk, f.qualification, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return f, paths
}

func TestNetBirdSignedInputsAndConfinementPrecedeCloud(t *testing.T) {
	for _, mode := range []string{"unsealed-confinement", "worker", "client", "server", "extra-archive", "insecure-key"} {
		t.Run(mode, func(t *testing.T) {
			f, paths := netBirdFixture(t)
			if mode == "insecure-key" {
				if err := os.Chmod(paths.PrivateKey, 0644); err != nil {
					t.Fatal(err)
				}
			} else if mode == "extra-archive" {
				paths.Archives["unexpected"] = paths.Worker
			} else if mode != "unsealed-confinement" {
				path := paths.Archives[mode]
				if mode == "worker" {
					path = paths.Worker
				} else if mode == "client" {
					path = paths.Client
				}
				if err := os.WriteFile(path, []byte("changed after independent approval"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := runNetBird(t.Context(), f.prepared, confinement.Verified{}, paths)
			if err == nil || result.Report.RunID != "" || result.ObservationsPath != "" {
				t.Fatal("changed artifacts or unsealed confinement entered native execution")
			}
			if _, err := os.Stat(paths.Journal); !os.IsNotExist(err) {
				t.Fatal("rejected input created a resource journal")
			}
		})
	}
}

func TestNetBirdPrimaryRemovalRequiresOwnedSDKTerminatedObservation(t *testing.T) {
	for _, mode := range []string{"terminated", "foreign-shape", "provider-404", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			f, paths := netBirdFixture(t)
			a := f.prepared.Approval()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			provider := common.NewRawConfigurationProvider(a.Tenancy, a.Principal, a.OCIRegion, "fixture-fingerprint", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
			factory, err := ociclient.New(provider, ociclient.Options{Region: a.OCIRegion})
			if err != nil {
				t.Fatal(err)
			}
			state, deletes := "RUNNING", 0
			primary := "ocid1.instance.oc1..netbirdprimary"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !authenticatedFixtureRequest(r, &key.PublicKey, a.Tenancy) || r.URL.Path != "/20160918/instances/"+primary {
					w.WriteHeader(403)
					return
				}
				if mode == "provider-404" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(404)
					_, _ = w.Write([]byte(`{"code":"NotAuthorizedOrNotFound"}`))
					return
				}
				if r.Method == http.MethodDelete {
					if r.URL.Query().Get("preserveBootVolume") != "false" {
						t.Error("primary removal preserved boot volume")
					}
					deletes++
					state = "TERMINATED"
					w.WriteHeader(204)
					return
				}
				spec := a.Hosts[0]
				shape := spec.Shape
				if mode == "foreign-shape" {
					shape = "VM.Standard.E4.Flex"
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.MarshalWrite(w, map[string]any{"id": primary, "compartmentId": a.Compartment, "imageId": "ocid1.image.oc1..netbird", "displayName": "ts-qualification-" + a.RunID + "-" + spec.Name, "freeformTags": map[string]string{runTag: a.RunID, approvalTag: f.prepared.approvalSHA256, imageimport.SHA256Tag: a.Candidate.ArtifactSHA256}, "shape": shape, "shapeConfig": map[string]any{"ocpus": spec.OCPUs, "memoryInGBs": spec.MemoryGB}, "availabilityDomain": spec.AvailabilityDomain, "faultDomain": spec.FaultDomain, "lifecycleState": state})
			}))
			defer server.Close()
			client, err := newCloud(f.prepared, factory, server.URL)
			if err != nil {
				t.Fatal(err)
			}
			j, err := client.load(paths.Journal)
			if err != nil {
				t.Fatal(err)
			}
			j.ImageID = "ocid1.image.oc1..netbird"
			j.Hosts[a.Hosts[0].Name], j.Hosts[a.Hosts[1].Name] = primary, "ocid1.instance.oc1..netbirdreplacement"
			if err := checkpoint(paths.Journal, j); err != nil {
				t.Fatal(err)
			}
			id := primary
			if mode == "replacement" {
				id = j.Hosts[a.Hosts[1].Name]
			}
			removed, err := client.removeNetBirdPrimary(t.Context(), paths.Journal, id)
			retained, loadErr := client.load(paths.Journal)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if mode == "terminated" {
				if err != nil || removed.InstanceID != primary || removed.State != "TERMINATED" || removed.ObservedAt.IsZero() || deletes != 1 || !retained.Terminated[a.Hosts[0].Name] || retained.Terminated[a.Hosts[1].Name] {
					t.Fatalf("authenticated primary removal/checkpoint differs: %+v deletes=%d err=%v", removed, deletes, err)
				}
			} else if err == nil || removed.State != "" || deletes != 0 || len(retained.Terminated) != 0 {
				t.Fatalf("unproven primary removal accepted: mode=%s removed=%+v deletes=%d err=%v", mode, removed, deletes, err)
			}
		})
	}
}
