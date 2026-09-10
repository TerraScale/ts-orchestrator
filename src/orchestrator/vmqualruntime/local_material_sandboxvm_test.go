//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/candidateplan"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"
)

// This fixture exercises offline declaration admission only. Production run
// settings and candidate preparation still need the scenario-owned runtime
// inputs and a live source before this inventory can launch guests.
func localMaterialIntent(t *testing.T) LocalQualificationMaterialInput {
	t.Helper()
	var artifacts []vmimage.GuestArtifact
	for _, name := range []string{"ts-node", "orchestrator", "terrabase"} {
		artifacts = append(artifacts, vmimage.GuestArtifact{Component: name, Architecture: vmimage.AMD64, Version: "release-1", Source: "https://releases.terrascale.tech/releases/" + name + "/release-1/" + name, SHA256: strings.Repeat("a", 64), Size: 1, Mode: 0755})
	}
	intent := localPublicMaterialIntent(t, artifacts)
	plan, err := vmnet.Plan(intent.NetworkConfig)
	if err != nil {
		t.Fatal(err)
	}
	control, err := BuildLocalQualificationControlPayload(plan, intent.RunDeclaration, intent.Artifacts, intent.Control)
	if err != nil {
		t.Fatal(err)
	}
	return LocalQualificationMaterialInput{Network: plan, NetworkConfig: intent.NetworkConfig, Architecture: intent.Architecture, Artifacts: intent.Artifacts, RunDeclaration: intent.RunDeclaration, ControlPayload: control}
}

func localPublicMaterialIntent(t *testing.T, artifacts []vmimage.GuestArtifact) LocalQualificationMaterialIntent {
	t.Helper()
	networkConfig := QualificationNetworkConfig(true, true, 1000, 1000)
	plan, err := vmnet.Plan(networkConfig)
	if err != nil {
		t.Fatal(err)
	}
	networkConfig.RunID = plan.RunID
	input := LocalQualificationMaterialIntent{NetworkConfig: networkConfig, Architecture: artifacts[0].Architecture, Artifacts: artifacts, RunDeclaration: vmcontrolseed.RunDeclaration{Version: 1}}
	control := LocalQualificationControlIntentRequest{StoreName: "source", CandidatePlan: candidateplan.Plan{SourceNodeID: "gru-member-1", TransitionID: "first-r3", TargetEpoch: 2, MinimumControlEpoch: 1}}
	manifest := hostmanifest.HostManifest{}
	for _, artifact := range artifacts {
		name := artifact.Component
		if name == "ts-node" {
			continue
		}
		spec, err := hostmanifest.NewComponentSpec(hostmanifest.ComponentSpec{Name: name, Version: artifact.Version, ArtifactURL: artifact.Source, SignatureURL: artifact.Source + ".sig", Sha256: artifact.SHA256, User: "terrascale-" + name, DataVolume: "/var/lib/terrascale/" + name, CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100})
		if err != nil {
			t.Fatal(err)
		}
		manifest.Components = append(manifest.Components, spec)
	}
	for _, region := range plan.Regions {
		if region.Code == vmnet.RegionCode("IAD") {
			continue
		}
		code := strings.ToLower(string(region.Code))
		binding := bootstrap.ControlRegionBinding{Code: code, OCIRegion: "local-" + code, CompartmentID: "ocid1.compartment.local.qualification"}
		for _, guest := range region.Guests {
			binding.MemberIDs = append(binding.MemberIDs, "ocid1.instance."+guest.ID)
			pair, err := nkeys.CreateUser()
			if err != nil {
				t.Fatal(err)
			}
			public, err := pair.PublicKey()
			pair.Wipe()
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(guest.ID))
			run := vmcontrolseed.RunAdmission{HostID: guest.ID, Generation: 1, Regional: vmcontrolseed.RunConnection{Connection: initialgrant.Connection{PublicNKey: public, TLS: initialgrant.TLSFiles{CertificateSHA256: hex.EncodeToString(sum[:])}}}}
			if guest.ID == "gru-member-1" {
				sum = sha256.Sum256([]byte(guest.ID + "-global"))
				run.Global = &vmcontrolseed.RunConnection{Connection: initialgrant.Connection{PublicNKey: public + "-distinct", TLS: initialgrant.TLSFiles{CertificateSHA256: hex.EncodeToString(sum[:])}}}
				control.StoreReader = nodeauthority.ReaderConfig{Endpoint: "tls://" + guest.Address + ":4222", ServerName: guest.ID}
			}
			input.RunDeclaration.Hosts = append(input.RunDeclaration.Hosts, run)
			if guest.ID == code+"-member-1" && code != "gru" {
				control.CandidatePlan.Candidates = append(control.CandidatePlan.Candidates, candidateplan.Entry{Manifest: manifest, BootstrapGrantID: guest.ID + "-candidate", Config: transitiongrant.Config{NodeID: guest.ID, Region: code, ServerName: guest.ID}})
			}
		}
		control.Regions = append(control.Regions, binding)
	}
	check := bootstrap.ControlStoreCheck{Store: "source", Region: "gru", AuthorityID: "gru-regional", LeaseKey: "authority.regional", Members: []string{"ocid1.instance.gru-member-1"}, Streams: []bootstrap.ControlStreamAssignment{{Name: "KV_ORCH_LEADERS", Replicas: 1, Servers: []string{"gru-member-1"}}, {Name: "KV_ORCH_RUNTIME", Replicas: 1, Servers: []string{"gru-member-1"}}}}
	control.Actions = []bootstrap.ControlRuntimeActionPlan{{Kind: bootstrap.ControlActionVerifyCandidate, Region: "gru", ExpectedEpoch: 1, TargetEpoch: 2, Checks: []bootstrap.ControlStoreCheck{check}}}
	control.Manifest = manifest
	now := time.Now()
	control.IssuedAt, control.ExpiresAt = now.Add(-time.Minute), now.Add(time.Hour)
	input.Control = control
	return input
}

func loadLocalMaterial(t *testing.T, root string, input LocalQualificationMaterialInput) (*qualificationControlAdmission, error) {
	t.Helper()
	pins := map[string]vmimage.GuestArtifact{}
	for _, artifact := range input.Artifacts {
		pins[artifact.Component] = artifact
	}
	return loadQualificationControlDeclaration(filepath.Join(root, "control-declaration.json"), input.Network, input.Architecture, pins)
}

func TestLocalQualificationMaterialLoaderAndDurableOwner(t *testing.T) {
	input := localMaterialIntent(t)
	root := filepath.Join(t.TempDir(), "material")
	if err := GenerateLocalQualificationMaterial(root, input); err != nil {
		t.Fatal(err)
	}
	retained, err := retainQualificationRunIdentity(filepath.Join(root, "state"), input.NetworkConfig)
	if err != nil || retained.NetworkRunID != input.Network.RunID || retained.StackRunID == "" {
		t.Fatalf("generated retained identity not reusable: %+v, %v", retained, err)
	}
	runtimeConfig := QualificationNetworkConfig(true, true, input.NetworkConfig.TAPUID, input.NetworkConfig.TAPGID)
	runtimeConfig.RunID = input.Network.RunID
	runtimeIdentity, err := retainQualificationRunIdentity(filepath.Join(root, "state"), runtimeConfig)
	if err != nil || runtimeIdentity != retained {
		t.Fatalf("independent runtime config did not reopen identity: %+v, %v", runtimeIdentity, err)
	}
	runtimeConfig.TAPUID++
	if _, err := retainQualificationRunIdentity(filepath.Join(root, "state"), runtimeConfig); err == nil {
		t.Fatal("mismatched runtime TAP accepted")
	}
	admission, err := loadLocalMaterial(t, root, input)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Clear()
	if len(admission.memberships) != 6 || len(admission.authorityReaders) != 6 {
		t.Fatal("incomplete membership or ordinary reader inventory")
	}
	state := filepath.Join(root, "state", "qualification-admission-"+input.Network.RunID)
	issuer, err := vmqualbootstrap.NewPersistentIssuer(state, input.Network.RunID)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	// A real grant from the reopened runtime issuer must use this declaration's
	// owner, rather than an independently generated lookalike signing key.
	grant, err := issuer.Grant("gru-member-1", admission.candidatePlan.Candidates[0].Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(grant.PublicKeyPEM, admission.ownerPublic) {
		t.Fatal("declaration owner differs from reopened runtime issuer")
	}
	if err := GenerateLocalQualificationMaterial(root, input); err == nil {
		t.Fatal("retry replaced admitted identity")
	}
}

func TestLocalQualificationMaterialRejectsNetworkConfigMismatch(t *testing.T) {
	input := localMaterialIntent(t)
	input.NetworkConfig.TAPUID++
	if err := GenerateLocalQualificationMaterial(filepath.Join(t.TempDir(), "material"), input); err == nil {
		t.Fatal("network config mismatch accepted")
	}
}

func TestLocalQualificationMaterialRejectsTampering(t *testing.T) {
	for _, mutation := range []string{"expiry", "artifact", "region", "duplicate", "lease", "membership-key", "permissions", "digest", "owner"} {
		t.Run(mutation, func(t *testing.T) {
			input := localMaterialIntent(t)
			root := filepath.Join(t.TempDir(), "material")
			if err := GenerateLocalQualificationMaterial(root, input); err != nil {
				t.Fatal(err)
			}
			outerPath := filepath.Join(root, "control-declaration.json")
			raw, err := os.ReadFile(outerPath)
			if err != nil {
				t.Fatal(err)
			}
			var outer qualificationControlDeclaration
			if err := json.Unmarshal(raw, &outer); err != nil {
				t.Fatal(err)
			}
			raw, err = os.ReadFile(outer.Payload.Source)
			if err != nil {
				t.Fatal(err)
			}
			var payload qualificationControlPayload
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "expiry":
				payload.ExpiresAt = time.Now().Add(-time.Hour)
			case "artifact":
				payload.Artifacts[0].SHA256 = strings.Repeat("b", 64)
			case "region":
				payload.Members[0].Member.Region = "sfo"
			case "duplicate":
				payload.Members[1] = payload.Members[0]
			case "lease":
				payload.Actions[0].Plan.Checks[0].AuthorityTerm = 7
			case "membership-key":
				payload.Members[0].MembershipKey = payload.Members[1].MembershipKey
			case "permissions":
				if err := os.Chmod(payload.Members[0].MembershipKey.Source, 0644); err != nil {
					t.Fatal(err)
				}
			case "digest":
				outer.Payload.SHA256 = strings.Repeat("b", 64)
			case "owner":
				outer.OwnerKey.SHA256 = strings.Repeat("b", 64)
			}
			if mutation != "permissions" && mutation != "digest" && mutation != "owner" {
				state, err := os.ReadFile(filepath.Join(root, "state", "qualification-admission-"+input.Network.RunID, "initial-issuer.json"))
				if err != nil {
					t.Fatal(err)
				}
				defer clear(state)
				var owner struct {
					Private []byte `json:"privatePem"`
				}
				if err := json.Unmarshal(state, &owner); err != nil {
					t.Fatal(err)
				}
				defer clear(owner.Private)
				block, _ := pem.Decode(owner.Private)
				parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				key := parsed.(*ecdsa.PrivateKey)
				defer key.D.SetInt64(0)
				raw, err = json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(outer.Payload.Source, raw, 0644); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(raw)
				outer.Payload.SHA256 = hex.EncodeToString(sum[:])
				digest := sha256.Sum256(append([]byte(qualificationControlDomain), raw...))
				outer.Signature, err = ecdsa.SignASN1(rand.Reader, key, digest[:])
				if err != nil {
					t.Fatal(err)
				}
			}
			raw, err = json.Marshal(outer)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(outerPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			admitted, err := loadLocalMaterial(t, root, input)
			if admitted != nil {
				admitted.Clear()
			}
			if err == nil {
				t.Fatal("mutated signed declaration accepted")
			}
		})
	}
}

func TestLocalQualificationMaterialDoesNotPublishInvalidRuntimeActions(t *testing.T) {
	input := localMaterialIntent(t)
	var payload qualificationControlPayload
	if err := json.Unmarshal(input.ControlPayload, &payload); err != nil {
		t.Fatal(err)
	}
	payload.Actions[0].Plan.Kind = "not-a-runtime-action"
	var err error
	input.ControlPayload, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "material")
	if err := GenerateLocalQualificationMaterial(root, input); err == nil {
		t.Fatal("loader-only action accepted")
	}
	if _, err := os.Stat(filepath.Join(root, "control-declaration.json")); !os.IsNotExist(err) {
		t.Fatalf("published a declaration before validating runtime actions: %v", err)
	}
}
