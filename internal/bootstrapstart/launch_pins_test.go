package bootstrapstart

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

func acceptedLaunchFixture(t *testing.T) (AcceptedIdentity, bakedStore, MarkerStore) {
	t.Helper()
	fixture := newAdmissionFlowFixture(t)
	if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
		t.Fatal(err)
	}
	accepted, err := fixture.gate.Markers.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return accepted, *fixture.gate.trustStore, fixture.gate.Markers
}

func TestAcceptedLaunchLoadersReadOnlyPinnedPublicInputs(t *testing.T) {
	accepted, store, markers := acceptedLaunchFixture(t)
	// Indirect retired files must never be opened, even when they exist.
	for _, name := range []string{identityFilename, anchorFilename} {
		if err := os.Symlink("/absent/retired", filepath.Join(store.directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(markers.directory, initialFormationName)); err != nil {
		t.Fatal(err)
	}
	receipt, delegation, err := store.loadAcceptedManagedImageMaterial(accepted, markers)
	if err != nil || digest(receipt) != accepted.LaunchMaterialSHA256[ManagedHostImageReceiptFilename] ||
		digest(delegation) != accepted.LaunchMaterialSHA256[ManagedHostImageDelegationFilename] {
		t.Fatalf("pinned image inputs: %v", err)
	}
	for _, name := range acceptedLaunchNames[2:] {
		if err := os.Remove(filepath.Join(store.directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	material, err := store.loadAcceptedHostLaunchMaterial(accepted, markers)
	if err != nil || len(material.Identity) != 0 || len(material.Anchor) != 0 ||
		digest(material.HostEnrollment) != accepted.LaunchMaterialSHA256[HostEnrollmentFilename] ||
		digest(material.OperatorSSHKey) != accepted.LaunchMaterialSHA256[OperatorSSHKeyFilename] {
		t.Fatalf("host-only launch input: %+v, %v", material, err)
	}
}

func TestAcceptedLaunchLoadersRejectIndirectWritableAndChangedFiles(t *testing.T) {
	for _, name := range acceptedLaunchNames {
		for _, fault := range []string{"symlink", "hardlink", "writable", "special mode", "changed", "FIFO"} {
			t.Run(name+"/"+fault, func(t *testing.T) {
				accepted, store, markers := acceptedLaunchFixture(t)
				path := filepath.Join(store.directory, name)
				switch fault {
				case "symlink":
					if err := os.Rename(path, path+".saved"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(path+".saved", path); err != nil {
						t.Fatal(err)
					}
				case "hardlink":
					if err := os.Link(path, path+".link"); err != nil {
						t.Fatal(err)
					}
				case "writable":
					if err := os.Chmod(path, 0o644); err != nil {
						t.Fatal(err)
					}
				case "special mode":
					if err := os.Chmod(path, os.ModeSetuid|0o444); err != nil {
						t.Fatal(err)
					}
				case "changed":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					writeBakedFixture(t, path, []byte("different exact public bytes"))
				case "FIFO":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := unix.Mkfifo(path, 0o444); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				if name == HostEnrollmentFilename || name == OperatorSSHKeyFilename {
					_, err = store.loadAcceptedHostLaunchMaterial(accepted, markers)
				} else {
					_, _, err = store.loadAcceptedManagedImageMaterial(accepted, markers)
				}
				if err == nil {
					t.Fatal("unsafe or changed public launch input admitted")
				}
			})
		}
	}
}

func TestAcceptedHostLaunchMaterialRequiresScopeLayoutAndSSH(t *testing.T) {
	for _, fault := range []string{"environment", "cell", "layout", "SSH"} {
		t.Run(fault, func(t *testing.T) {
			accepted, store, markers := acceptedLaunchFixture(t)
			name := HostEnrollmentFilename
			wire, err := os.ReadFile(filepath.Join(store.directory, name))
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := hostenroll.ParsePublicBundle(wire)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "environment":
				bundle.Environment = "canary"
			case "cell":
				bundle.Cell, bundle.Region = "sfo", "SFO"
			case "layout":
				bundle.InstallRoot = "/different/install/root"
			case "SSH":
				name, wire = OperatorSSHKeyFilename, []byte(testOperatorSSHKey+"\n")
			}
			if fault != "SSH" {
				wire, err = protocol.EncodeJSON(bundle)
				if err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(store.directory, name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			writeBakedFixture(t, path, wire)
			accepted.LaunchMaterialSHA256[name] = digest(wire)
			acceptedWire, err := EncodeAcceptedIdentity(accepted)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(markers.directory, markerName), acceptedWire, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := store.loadAcceptedHostLaunchMaterial(accepted, markers); err == nil {
				t.Fatal("invalid pinned public host input admitted")
			}
		})
	}
}

func TestAcceptedLaunchMaterialRequiresRootOwnedSnapshotAndJournal(t *testing.T) {
	accepted, store, markers := acceptedLaunchFixture(t)
	foreign := accepted.Clone()
	foreign.LaunchMaterialSHA256[OperatorSSHKeyFilename] = digest([]byte("invented pin"))
	if _, err := store.loadAcceptedHostLaunchMaterial(foreign, markers); err == nil {
		t.Fatal("caller-supplied pin replaced root-owned snapshot")
	}
	if _, err := store.loadAcceptedHostLaunchMaterial(AcceptedIdentity{}, markers); !errors.Is(err, ErrAcceptedIdentity) {
		t.Fatalf("zero identity: %v", err)
	}
	if err := os.WriteFile(filepath.Join(markers.directory, identityRekeyJournalName), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store.directory, HostEnrollmentFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.loadAcceptedHostLaunchMaterial(accepted, markers); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal was bypassed before public read: %v", err)
	}
}

func TestInitialLaunchMaterialUsesIndependentPinnedRegionImageAndCurrentProof(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	anchorEnvelope, err := trust.DecodeEnvelope(fixture.gate.AnchorWire)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, fixture.gate.Roots, fixture.gate.Expected, *fixture.now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	state := fixture.ledger.state
	observed, err := fixture.gate.observe(t.Context(), state.Result.InstanceOCID, state, anchor.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	manifest, _, _, err := fixture.gate.initialProofs(t.Context(), state, anchor, observed, *fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := fixture.gate.trustStore.measureInitialLaunchMaterial(manifest, fixture.gate.Roots, *fixture.now)
	if err != nil || len(pins) != 4 {
		t.Fatalf("measured initial pins: %v", err)
	}
	if _, err := fixture.gate.trustStore.measureInitialLaunchMaterial(manifest, fixture.gate.Roots, fixture.now.Add(2*time.Hour)); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("expired image qualification accepted: %v", err)
	}
	for _, fault := range []string{"image", "shape"} {
		payload := manifest.Manifest()
		for i, file := range payload.ControllerFiles {
			if file.Name != "oci-region.json" {
				continue
			}
			region, err := oci.ParseRegionConfig(file.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "image" {
				region.ImageID += "-other"
			} else {
				region.Shape = "VM.Standard.A1.Flex"
			}
			wire, err := protocol.EncodeJSON(region)
			if err != nil {
				t.Fatal(err)
			}
			payload.ControllerFiles[i].Bytes, payload.ControllerFiles[i].SHA256 = wire, digest(wire)
		}
		signed, err := bootstrap.SignManifest(payload, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.rootPrivate)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := anchor.ManifestExpectation(payload.Slot, payload.ImageOCID)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := bootstrap.VerifyManifest(signed, fixture.gate.Roots, expected, *fixture.now, bootstrap.ManifestTrustPolicy())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.gate.trustStore.measureInitialLaunchMaterial(verified, fixture.gate.Roots, *fixture.now); err == nil {
			t.Fatalf("%s from receipt replaced independently pinned launch expectation", fault)
		}
	}
}

func TestInitialAdmissionRequiresLaunchFilesBeforeEffectsAndRetainsExactPins(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	path := filepath.Join(fixture.gate.trustStore.directory, ManagedHostImageReceiptFilename)
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.gate.AdmitInitial(t.Context()); err == nil {
		t.Fatal("missing fixed qualification file admitted")
	}
	if fixture.material.initialCalls != 0 || fixture.credentials.calls != 0 {
		t.Fatal("missing launch inputs reached effects")
	}
	writeBakedFixture(t, path, wire)
	if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
		t.Fatal(err)
	}
	accepted, err := fixture.gate.Markers.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range acceptedLaunchNames {
		wire, err := os.ReadFile(filepath.Join(fixture.gate.trustStore.directory, name))
		if err != nil || accepted.LaunchMaterialSHA256[name] != digest(wire) {
			t.Fatalf("lost exact initial %s pin: %v", name, err)
		}
	}
	published, err := EncodeAcceptedIdentity(accepted)
	if err != nil || !bytes.Equal(published, fixture.ledger.published[0]) {
		t.Fatal("exported launch pins differ from root-owned snapshot")
	}
}

func TestSignedARMHostLaunchIsIndependentOfAMD64Controller(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
		t.Fatal(err)
	}
	accepted, err := fixture.gate.Markers.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(fixture.gate.AnchorWire)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(envelope, fixture.gate.Roots, fixture.gate.Expected, *fixture.now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	state := fixture.ledger.state
	observed, err := fixture.gate.observe(t.Context(), state.Result.InstanceOCID, state, anchor.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	manifest, _, controllerImage, err := fixture.gate.initialProofs(t.Context(), state, anchor, observed, *fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	hostImage := controllerImage.Receipt()
	hostImage.OCIImageOCID = "ocid1.image.oc1.sa-saopaulo-1.independent-arm-host"
	hostImage.Architecture = "arm64"
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	publicWire, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: 1, SubjectKeyID: id, SubjectPublicKey: publicWire,
		Capabilities: []trust.Capability{{Domain: release.ImageDomain, DeploymentID: entityid.Derive("build", hostImage.SourceRevision), Cell: accepted.Cell, Environment: accepted.Environment, Role: "oci-image", Slots: []string{hostImage.OCIImageOCID}, Actions: []string{"sign"}}}}, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := release.SignImageReceipt(hostImage, accepted.Environment, delegation, fixture.gate.Roots, key, *fixture.now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, name := range acceptedLaunchNames {
		files[name], err = os.ReadFile(filepath.Join(fixture.gate.trustStore.directory, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	files[ManagedHostImageReceiptFilename], files[ManagedHostImageDelegationFilename] = envelopeWire(t, receipt), envelopeWire(t, delegation)
	for _, name := range acceptedLaunchNames[2:] {
		path := filepath.Join(fixture.gate.trustStore.directory, name)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		writeBakedFixture(t, path, files[name])
	}
	payload := manifest.Manifest()
	region := oci.RegionConfig{Region: payload.Cell, ImageID: hostImage.OCIImageOCID, Shape: "VM.Standard.A1.Flex"}
	regionWire, err := protocol.EncodeJSON(region)
	if err != nil {
		t.Fatal(err)
	}
	for i, file := range payload.ControllerFiles {
		if file.Name == "oci-region.json" {
			payload.ControllerFiles[i].Bytes, payload.ControllerFiles[i].SHA256 = regionWire, digest(regionWire)
		}
	}
	signed, err := bootstrap.SignManifest(payload, fixture.now.Add(-time.Minute), fixture.now.Add(time.Hour), fixture.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := anchor.ManifestExpectation(payload.Slot, payload.ImageOCID)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := bootstrap.VerifyManifest(signed, fixture.gate.Roots, expected, *fixture.now, bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	pins, err := fixture.gate.trustStore.measureInitialLaunchMaterial(verified, fixture.gate.Roots, *fixture.now)
	if err != nil || len(pins) != 4 || payload.ImageOCID == hostImage.OCIImageOCID || payload.ImageArchitecture != "linux-amd64" {
		t.Fatalf("distinct signed ARM host qualification: %v", err)
	}
	accepted.LaunchMaterialSHA256, accepted.ConfigSHA256["oci-region.json"] = pins, digest(regionWire)
	inputs, err := fixture.gate.trustStore.loadTrustInputs(accepted)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyIdentityRekeyLaunchMaterial(accepted, inputs, regionWire, files, *fixture.now); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"sidecar pin", "host image", "host shape", "expired", "wrong root"} {
		t.Run(fault, func(t *testing.T) {
			record, wire, roots, now := accepted.Clone(), bytes.Clone(regionWire), inputs, *fixture.now
			switch fault {
			case "sidecar pin":
				wire = append(wire, ' ')
			case "host image", "host shape":
				changed := region
				if fault == "host image" {
					changed.ImageID += "-other"
				} else {
					changed.Shape = "VM.Standard.E5.Flex"
				}
				wire, err = protocol.EncodeJSON(changed)
				if err != nil {
					t.Fatal(err)
				}
				record.ConfigSHA256["oci-region.json"] = digest(wire)
			case "expired":
				now = now.Add(2 * time.Hour)
			case "wrong root":
				roots.Roots.Current = trust.Keyring{}
			}
			if err := verifyIdentityRekeyLaunchMaterial(record, roots, wire, files, now); err == nil {
				t.Fatal("invalid managed host launch proof admitted")
			}
		})
	}
}
