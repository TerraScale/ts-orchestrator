package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nkeys"
)

func acceptedDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func controllerAcceptedFixture(t *testing.T, baseline []byte) bootstrapstart.AcceptedIdentity {
	t.Helper()
	public := func(operator bool) string {
		var pair nkeys.KeyPair
		var err error
		if operator {
			pair, err = nkeys.CreateOperator()
		} else {
			pair, err = nkeys.CreateAccount()
		}
		if err != nil {
			t.Fatal(err)
		}
		defer pair.Wipe()
		key, err := pair.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	accepted := bootstrapstart.AcceptedIdentity{SchemaVersion: 1, Origin: identityrekey.AcceptanceOriginInitial, OperationID: entityid.Derive("accepted-operation"),
		DeploymentID: entityid.Derive("accepted-deployment"), ClusterID: entityid.Derive("accepted-cluster"),
		Environment: "canary", Cell: "GRU", Slot: "controller-a", SeedSlot: "controller-b",
		ControllerSlots: []string{"controller-a", "controller-b", "controller-c"},
		InstanceOCID:    "ocid1.instance.oc1.sa-saopaulo-1.existing0", ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.existing",
		PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1.existing0", PrimaryPrivateIP: "10.251.0.11",
		Binary:       identityrekey.BinaryPin{SHA256: acceptedDigest(baseline), Size: int64(len(baseline)), Architecture: runtime.GOARCH},
		Broker:       identityrekey.BrokerIdentity{Operator: public(true), SystemAccount: public(false), CellAccount: public(false), HostSigner: public(false), RoleSigner: public(false)},
		Store:        identityrekey.StoreIdentity{Directory: filepath.Join(t.TempDir(), "nats"), ServerName: "gru-1-ctl-1", RaftNodeID: "NODE0000", ServerNameSHA256: acceptedDigest([]byte("server")), NodeIdentitySHA256: acceptedDigest([]byte("node"))},
		ConfigSHA256: map[string]string{}, LaunchMaterialSHA256: map[string]string{
			"host-enrollment-public.json": acceptedDigest([]byte("host enrollment")), "operator-ssh-key.pub": acceptedDigest([]byte("operator SSH")),
			"managed-host-image-receipt.json": acceptedDigest([]byte("host image receipt")), "managed-host-image-delegation.json": acceptedDigest([]byte("host image delegation"))}, AcceptedAt: time.Now().UTC().Truncate(time.Second)}
	accepted.ControllerBindings = []bootstrapstart.ControllerBinding{{Slot: accepted.Slot, InstanceOCID: accepted.InstanceOCID, ImageOCID: accepted.ImageOCID,
		PrimaryVNICOCID: accepted.PrimaryVNICOCID, PrimaryPrivateIP: accepted.PrimaryPrivateIP, Binary: accepted.Binary, Store: accepted.Store}}
	for _, name := range []string{"controller.json", "oci-region.json", "oci-region-intent.json", "placement.json"} {
		accepted.ConfigSHA256[name] = acceptedDigest([]byte(name))
	}
	for name, purpose := range map[string]bootstrap.SecretPurpose{
		"operator.jwt": bootstrap.SecretRegionalShared, "system.jwt": bootstrap.SecretRegionalShared, "cell.jwt": bootstrap.SecretRegionalShared,
		"system.creds": bootstrap.SecretRegionalShared, "ca.pem": bootstrap.SecretRegionalShared, "route-password": bootstrap.SecretRegionalShared,
		"ticket.pub": bootstrap.SecretRegionalShared, "ticket.key": bootstrap.SecretRegionalShared,
		"host-nats-issuer.seed": bootstrap.SecretHostIssuer, "host-tls-issuer-cert.pem": bootstrap.SecretHostIssuer, "host-tls-issuer-key.pem": bootstrap.SecretHostIssuer,
		"controller-a.creds": bootstrap.SecretController, "controller-a-tls-cert.pem": bootstrap.SecretController, "controller-a-tls-key.pem": bootstrap.SecretController, "controller-a-response.key": bootstrap.SecretController,
	} {
		ref := bootstrap.SecretReference{Purpose: purpose, TargetFile: name, SHA256: acceptedDigest([]byte(name)),
			SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.existing", VersionNumber: 1, MaxBytes: 65536}
		if purpose == bootstrap.SecretController {
			ref.Slot = accepted.Slot
		}
		accepted.MaterialReferences = append(accepted.MaterialReferences, ref)
	}
	if err := accepted.Validate(); err != nil {
		t.Fatal(err)
	}
	return accepted
}

func useAcceptedController(t *testing.T, accepted bootstrapstart.AcceptedIdentity, roots trust.Keyring) {
	t.Helper()
	oldIdentity, oldTrust, oldGate, oldProbe := acceptedIdentity, acceptedTrustInputs, acceptedPrestart, checkAcceptedBinary
	oldPresent, oldCompletion := acceptedJournalPresent, completionProbe
	acceptedIdentity = func() (bootstrapstart.AcceptedIdentity, error) { return accepted.Clone(), nil }
	acceptedTrustInputs = func(record bootstrapstart.AcceptedIdentity) (bootstrapstart.TrustInputs, error) {
		if err := record.Validate(); err != nil {
			return bootstrapstart.TrustInputs{}, err
		}
		verified, err := trust.VerifyRootChain(roots, trust.ChainIdentity{DeploymentID: record.DeploymentID, Environment: record.Environment, Cell: strings.ToLower(record.Cell)}, trust.RootChain{Version: 1})
		return bootstrapstart.TrustInputs{ChainIdentity: trust.ChainIdentity{DeploymentID: record.DeploymentID, Environment: record.Environment, Cell: strings.ToLower(record.Cell)}, Genesis: roots, Chain: trust.RootChain{Version: 1}, Roots: verified}, err
	}
	acceptedPrestart = func(bootstrapstart.AcceptedIdentity) error { return nil }
	acceptedJournalPresent = func() (bool, error) { return false, nil }
	checkAcceptedBinary = func(context.Context, string, bootstrapstart.AcceptedIdentity) error { return nil }
	t.Cleanup(func() {
		acceptedIdentity, acceptedTrustInputs, acceptedPrestart, checkAcceptedBinary = oldIdentity, oldTrust, oldGate, oldProbe
		acceptedJournalPresent, completionProbe = oldPresent, oldCompletion
	})
}

func signAcceptedSuccessor(t *testing.T, data []byte, now time.Time, root ed25519.PrivateKey, roots trust.Keyring) ([]byte, []byte) {
	t.Helper()
	public, leaf, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Repeat("e", 40)
	delegation, err := release.SignUpdateDelegation(release.BinaryUpdateDelegation{
		Schema: release.UpdateDelegationSchema, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Environment: "canary", Architectures: []string{runtime.GOARCH}, Repository: release.QualificationRepository,
		Workflow: release.QualificationWorkflow, Ref: release.LineageRef, LineageBase: source,
	}, now.Add(-time.Minute), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	binary := release.BinaryReceipt{Schema: release.BinarySchema, SourceRevision: source, GoVersion: release.DefaultGoVersion, GOOS: "linux", GOARCH: runtime.GOARCH,
		ELFMachine: map[string]string{"amd64": "Advanced Micro Devices X86-64", "arm64": "AArch64"}[runtime.GOARCH], Static: true,
		Bytes: int64(len(data)), SHA256: acceptedDigest(data), QualificationSHA256: acceptedDigest([]byte("qualification"))}
	qualified := release.ProductionQualification{Schema: release.ProductionQualificationSchema,
		Candidate: release.ProductionExpectation{SourceRevision: source, ArtifactSHA256: binary.SHA256,
			QualificationSHA256: binary.QualificationSHA256, Cell: "GRU", Environment: "canary",
			Runtime: release.ProductionRuntime, Architecture: runtime.GOARCH, Role: "orchestrator"}}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		evidence := []byte("test-only " + gate + " evidence")
		qualified.Evidence = append(qualified.Evidence, release.ProductionGateEvidence{Gate: gate,
			SHA256: acceptedDigest(evidence), Bytes: int64(len(evidence)), CompletedAt: now.Add(-time.Second)})
	}
	payload, err := trust.EncodePayload(qualified)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := trust.Sign(payload, release.ProductionQualificationScope(qualified.Candidate), now, now.Add(30*time.Minute), root)
	if err != nil {
		t.Fatal(err)
	}
	proofWire, err := trust.EncodeEnvelope(proof)
	if err != nil {
		t.Fatal(err)
	}
	update := release.BinaryUpdateReceipt{Schema: release.UpdateReceiptSchema, Binary: binary, Cell: "GRU",
		DelegationSHA256: acceptedDigest(delegationWire), Production: &release.ProductionProof{Qualification: proofWire},
		Lineage: release.SourceLineage{Repository: release.QualificationRepository, Workflow: release.QualificationWorkflow,
			Ref: release.LineageRef, LineageBase: source, QualificationRunID: 10, QualificationRunNum: 5}}
	payload, err = trust.EncodePayload(update)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := trust.Sign(payload, release.UpdateReceiptScope(update, "canary"), now, now.Add(30*time.Minute), leaf)
	if err != nil {
		t.Fatal(err)
	}
	receiptWire, err := trust.EncodeEnvelope(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return receiptWire, delegationWire
}

func TestControllerRecoveryRollsBackDamageOnlyAfterTrustedCompletion(t *testing.T) {
	for _, step := range []string{"watchdog"} {
		for _, damage := range []string{"binary"} {
			for _, fence := range []string{"complete", "pending"} {
				t.Run(step+"/"+damage+"/"+fence, func(t *testing.T) {
					delegateMarker := filepath.Join(t.TempDir(), "delegated")
					t.Setenv("TS_ORCH_TEST_DELEGATE_MARKER", delegateMarker)
					baseline := []byte("#!/bin/sh\nprintf delegated > \"$TS_ORCH_TEST_DELEGATE_MARKER\"\n")
					accepted := controllerAcceptedFixture(t, baseline)
					public, private, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					roots, err := trust.ParseKeyring(public)
					if err != nil {
						t.Fatal(err)
					}
					useAcceptedController(t, accepted, roots)
					layout := selfupdate.Layout{Root: filepath.Join(t.TempDir(), "root"), Owner: os.Getuid()}
					binary := filepath.Join(t.TempDir(), "binary")
					if err := os.WriteFile(binary, baseline, 0o755); err != nil {
						t.Fatal(err)
					}
					previous, err := selfupdate.Seed(layout, binary)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(filepath.Join(layout.ReleaseDir(previous), "baked")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("releases/"+previous, filepath.Join(layout.Root, "known-good")); err != nil {
						t.Fatal(err)
					}
					now := time.Now().UTC()
					targetBytes := []byte("qualified successor")
					receipt, delegation := signAcceptedSuccessor(t, targetBytes, now, private, roots)
					target, err := selfupdate.Stage(layout, bytes.NewReader(targetBytes), receipt, delegation, selfupdate.ReceiptPolicy{Roots: roots, Environment: accepted.Environment, Cell: accepted.Cell, Architecture: runtime.GOARCH}, now)
					if err != nil {
						t.Fatal(err)
					}
					activation, err := selfupdate.Activate(layout, target, selfupdate.ControllerUnit, now, time.Minute)
					if err != nil {
						t.Fatal(err)
					}
					proofFile, keyFile := filepath.Join(t.TempDir(), "proof.json"), filepath.Join(t.TempDir(), "identity.key")
					proof, err := selfupdate.SignVersionProof(selfupdate.VersionProof{Schema: selfupdate.ProofSchema, ActivationID: activation.ActivationID,
						Unit: activation.Unit, BinarySHA256: target, ProcessID: int64(os.Getpid()), ObservedAt: now.Add(time.Second)}, private, now.Add(time.Second))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(proofFile, proof, 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(private)), 0o600); err != nil {
						t.Fatal(err)
					}

					{
						switch damage {
						case "binary":
							if err := os.Remove(layout.BinaryPath(target)); err != nil {
								t.Fatal(err)
							}

						}
					}

					activationBefore, err := os.ReadFile(filepath.Join(layout.Root, "activation.json"))
					if err != nil {
						t.Fatal(err)
					}
					checkAcceptedBinary = func(_ context.Context, path string, _ bootstrapstart.AcceptedIdentity) error {
						if damage == "contract" && path == layout.BinaryPath(target) || fence == "incompatible predecessor" && path == layout.BinaryPath(previous) {
							return errors.New("incompatible decoder")
						}
						return nil
					}
					acceptedJournalPresent = func() (bool, error) { return true, nil }
					probes := 0
					completionProbe = func(_ context.Context, path string) error {
						probes++
						if path != layout.BinaryPath(previous) {
							t.Fatal("completion probe selected damaged target")
						}
						if fence == "pending" {
							return bootstrapstart.ErrIdentityRekeyPending
						}
						return nil
					}
					oldInstall, oldReload := installGeneration, daemonReload
					installGeneration = func(time.Time) (string, error) { return "", nil }
					daemonReload = func(context.Context) error { return nil }
					t.Cleanup(func() { installGeneration, daemonReload = oldInstall, oldReload })
					restarts := 0
					c := command{ctx: t.Context(), output: &bytes.Buffer{}, now: func() time.Time { return now.Add(time.Second) }, restart: func(_ context.Context, unit string) error {
						if unit != selfupdate.ControllerUnit {
							t.Fatal("recovery restarted the wrong unit")
						}
						restarts++
						return nil
					}}
					inputs, err := acceptedTrustInputs(accepted)
					if err != nil {
						t.Fatal(err)
					}
					if err := c.checkControllerTransitions(layout, accepted, inputs, false, ""); err == nil && fence != "interrupted rollback" {
						t.Fatal("strict activation check permitted damaged target")
					}
					args := []string{"--unit", selfupdate.ControllerUnit, "--root", layout.Root, "--owner", fmt.Sprint(os.Getuid())}
					switch step {
					case "watchdog":
						err = c.watchdog(append(args, "--proof-file", proofFile, "--proof-key-file", keyFile))

					}
					if _, err := os.Stat(delegateMarker); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("rollback-only recovery delegated a root step: %v", err)
					}
					current, _ := layout.Current()
					if fence == "complete" || fence == "interrupted rollback" {
						wantRestarts := 0
						{
							wantRestarts = 1
						}
						if restarts != wantRestarts {
							t.Fatalf("recovery restarts = %d, want %d", restarts, wantRestarts)
						}
						if err != nil || current != previous || probes == 0 {
							t.Fatalf("trusted recovery: current=%s probes=%d err=%v", current, probes, err)
						}
						if _, pending, err := layout.Pending(); err != nil || pending {
							t.Fatalf("rollback left activation: %v %v", pending, err)
						}
						if bad, err := layout.KnownBad(); err != nil || !bad[target] {
							t.Fatalf("unauthenticated target was not rejected: %v %v", bad, err)
						}
						if damage == "unreadable" && fence != "interrupted rollback" {
							matches, err := filepath.Glob(filepath.Join(layout.Root, "activation.json.unreadable-*"))
							if err != nil || len(matches) != 1 {
								t.Fatalf("owned unreadable record was not quarantined: %v %v", matches, err)
							}
						}

					} else {
						if err == nil {
							t.Fatal("refused recovery returned success")
						}
						if current != target || restarts != 0 {
							t.Fatal("fenced recovery changed current or restarted")
						}
						after, readErr := os.ReadFile(filepath.Join(layout.Root, "activation.json"))
						if readErr != nil || !bytes.Equal(after, activationBefore) {
							t.Fatal("fenced recovery changed or quarantined activation")
						}
						if bad, err := layout.KnownBad(); err != nil || bad[target] {
							t.Fatalf("fenced recovery rejected target before authorization: %v %v", bad, err)
						}

					}
				})
			}
		}
	}
}
