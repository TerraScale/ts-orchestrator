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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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

func TestPendingCompletionHoldsRootMutationsAndAllowsNoEffectPrepare(t *testing.T) {
	baseline := []byte("accepted build")
	accepted := controllerAcceptedFixture(t, baseline)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	useAcceptedController(t, accepted, roots)
	acceptedJournalPresent = func() (bool, error) { return true, nil }
	probes := 0
	completionProbe = func(_ context.Context, binary string) error {
		probes++
		if filepath.Base(filepath.Dir(binary)) != accepted.Binary.SHA256 {
			t.Fatal("probe did not execute verified current binary")
		}
		return bootstrapstart.ErrIdentityRekeyPending
	}
	root := filepath.Join(t.TempDir(), "root")
	layout := selfupdate.Layout{Root: root, Owner: os.Getuid()}
	binary := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(binary, baseline, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := selfupdate.Seed(layout, binary); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/"+accepted.Binary.SHA256, filepath.Join(root, "known-good")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	common := []string{"--unit", selfupdate.ControllerUnit, "--root", root, "--owner", fmt.Sprint(os.Getuid())}
	var output bytes.Buffer
	if err := run(t.Context(), append([]string{"prepare"}, common...), &output, time.Now, func(context.Context, string) error { t.Fatal("held prepare restarted"); return nil }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "no effects") || probes != 1 {
		t.Fatalf("held prepare = %q; probes %d", output.String(), probes)
	}
	after, err := os.ReadDir(root)
	if err != nil || len(before) != len(after) {
		t.Fatal("held prepare created a root file")
	}
	if err := run(t.Context(), append([]string{"watchdog"}, common...), &output, time.Now, func(context.Context, string) error { t.Fatal("held watchdog restarted"); return nil }); !errors.Is(err, bootstrapstart.ErrIdentityRekeyPending) {
		t.Fatalf("held watchdog = %v", err)
	}
	if _, pending, err := layout.Pending(); err != nil || pending {
		t.Fatal("held root step created an activation")
	}
}

func TestCompletionSubprocessDropsRootAndUsesFixedCommand(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("credential drop requires root")
	}
	dir := t.TempDir()
	for _, path := range []string{dir, filepath.Dir(dir)} {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, "probe")
	id, err := exec.LookPath("id")
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("#!/bin/sh\n[ \"$(%q -u)\" = 65534 ] && [ \"$(%q -G)\" = 65534 ] && [ \"$1\" = identity-rekey-completion-check ] && [ \"$2\" = --config ] && [ \"$3\" = /etc/terrascale-orchestrator/controller.json ]\n", id, id)
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runCompletionProbeAs(t.Context(), binary, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runCompletionProbeAs(ctx, binary, 65534, 65534); err == nil {
		t.Fatal("canceled probe ran")
	}
	if err := runCompletionProbeAs(t.Context(), binary, 0, 0); err == nil {
		t.Fatal("privileged probe accepted")
	}
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

func TestControllerPrestartGateRefusesBeforeSelfupdateEffects(t *testing.T) {
	baseline := []byte("accepted build")
	accepted := controllerAcceptedFixture(t, baseline)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	useAcceptedController(t, accepted, roots)
	acceptedPrestart = func(bootstrapstart.AcceptedIdentity) error { return errors.New("pending journal diverges") }
	root := filepath.Join(t.TempDir(), "absent-root")
	err = run(t.Context(), []string{"prepare", "--unit", selfupdate.ControllerUnit, "--root", root, "--owner", fmt.Sprint(os.Getuid()), "--baked-binary", filepath.Join(t.TempDir(), "absent-binary")}, &bytes.Buffer{}, time.Now, func(context.Context, string) error { t.Fatal("restarted before gate"); return nil })
	if err == nil || !strings.Contains(err.Error(), "pending journal diverges") {
		t.Fatalf("gate error = %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("gate refusal created release root")
	}
}

func TestAcceptedControllerAllowsSuccessorAndRefusesIncompatibleRollback(t *testing.T) {
	baseline := []byte("accepted build")
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
	now := time.Now().UTC()
	target := []byte("legitimate signed successor")
	receipt, delegation := signAcceptedSuccessor(t, target, now, private, roots)
	next, err := selfupdate.Stage(layout, bytes.NewReader(target), receipt, delegation, selfupdate.ReceiptPolicy{Roots: roots, Environment: accepted.Environment, Cell: accepted.Cell, Architecture: runtime.GOARCH}, now)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := acceptedTrustInputs(accepted)
	if err != nil {
		t.Fatal(err)
	}
	c := command{ctx: t.Context()}
	if err := c.checkControllerRelease(layout, next, accepted, inputs); err != nil {
		t.Fatalf("valid successor differs from baseline: %v", err)
	}
	if _, err := selfupdate.Activate(layout, next, selfupdate.ControllerUnit, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	checkAcceptedBinary = func(_ context.Context, path string, _ bootstrapstart.AcceptedIdentity) error {
		if path == layout.BinaryPath(previous) {
			return errors.New("cannot read accepted contract")
		}
		return nil
	}
	if err := c.checkControllerTransitions(layout, accepted, inputs, true, ""); err == nil {
		t.Fatal("incompatible rollback predecessor accepted")
	}
	if current, err := layout.Current(); err != nil || current != next {
		t.Fatal("refusal rolled back current")
	}
}

func TestAcceptedIdentityDecoderProbeRejectsOldReaders(t *testing.T) {
	accepted := controllerAcceptedFixture(t, []byte("build"))
	wire, err := bootstrapstart.EncodeAcceptedIdentity(accepted)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkAcceptedIdentity(bytes.NewReader(wire), nil); err != nil {
		t.Fatal(err)
	}
	if err := checkAcceptedIdentity(strings.NewReader(`{}`), nil); err == nil {
		t.Fatal("decoder accepted an invalid record")
	}
	for _, body := range []string{"exit 0", "exit 1"} {
		binary := filepath.Join(t.TempDir(), "old-reader")
		if err := os.WriteFile(binary, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := checkAcceptedBinaryContract(t.Context(), binary, accepted); err == nil {
			t.Fatal("old reader passed the contract probe")
		}
	}
}

func TestIdentityRekeyBinariesRequireEverySelectedReleaseToReadProposedRecord(t *testing.T) {
	baseline := []byte("accepted build")
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
	inputs, err := acceptedTrustInputs(accepted)
	if err != nil {
		t.Fatal(err)
	}
	layout := selfupdate.Layout{Root: filepath.Join(t.TempDir(), "root"), Owner: os.Getuid()}
	binary := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(binary, baseline, 0o755); err != nil {
		t.Fatal(err)
	}
	previous, err := selfupdate.Seed(layout, binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyIdentityRekeyBinaries(t.Context(), accepted, inputs, layout); err == nil {
		t.Fatal("missing known-good accepted")
	}
	if err := os.Symlink("releases/"+previous, filepath.Join(layout.Root, "known-good")); err != nil {
		t.Fatal(err)
	}
	if err := verifyIdentityRekeyBinaries(t.Context(), accepted, inputs, layout); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	successor := []byte("signed successor")
	receipt, delegation := signAcceptedSuccessor(t, successor, now, private, roots)
	next, err := selfupdate.Stage(layout, bytes.NewReader(successor), receipt, delegation, selfupdate.ReceiptPolicy{Roots: roots, Environment: accepted.Environment, Cell: accepted.Cell, Architecture: runtime.GOARCH}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selfupdate.Activate(layout, next, selfupdate.ControllerUnit, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := verifyIdentityRekeyBinaries(t.Context(), accepted, inputs, layout); err != nil {
		t.Fatalf("compatible successor: %v", err)
	}
	before, err := os.ReadDir(layout.Root)
	if err != nil {
		t.Fatal(err)
	}
	checkAcceptedBinary = func(_ context.Context, path string, record bootstrapstart.AcceptedIdentity) error {
		if record.OperationID != accepted.OperationID {
			t.Fatal("probe did not receive proposed record")
		}
		if path == layout.BinaryPath(previous) {
			return errors.New("old contract reader")
		}
		return nil
	}
	if err := verifyIdentityRekeyBinaries(t.Context(), accepted, inputs, layout); err == nil {
		t.Fatal("incompatible known-good or rollback predecessor accepted")
	}
	inputs.ChainIdentity.DeploymentID = entityid.Derive("foreign deployment")
	if err := verifyIdentityRekeyBinaries(t.Context(), accepted, inputs, layout); err == nil {
		t.Fatal("foreign roots accepted")
	}
	after, err := os.ReadDir(layout.Root)
	if err != nil || len(before) != len(after) {
		t.Fatal("read-only check changed the release root")
	}
	if current, err := layout.Current(); err != nil || current != next {
		t.Fatal("read-only check changed current")
	}
}

func TestControllerRecoveryPreservesHostOwnedActivation(t *testing.T) {
	for _, record := range []string{"valid", "unreadable"} {
		t.Run(record, func(t *testing.T) {
			baseline := []byte("accepted controller baseline")
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
			if _, err := selfupdate.Seed(layout, binary); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			host := []byte("host release without accepted identity decoder")
			receipt, delegation := signAcceptedSuccessor(t, host, now, private, roots)
			target, err := selfupdate.Stage(layout, bytes.NewReader(host), receipt, delegation,
				selfupdate.ReceiptPolicy{Roots: roots, Environment: accepted.Environment, Cell: accepted.Cell, Architecture: runtime.GOARCH}, now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := selfupdate.Activate(layout, target, selfupdate.HostUnit, now, time.Minute); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(layout.Root, "activation.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if record == "unreadable" {
				before = bytes.Replace(before, []byte(`"schema"`), []byte(`"unexpected":true,"schema"`), 1)
				if err := os.WriteFile(path, before, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			probes := 0
			checkAcceptedBinary = func(_ context.Context, path string, _ bootstrapstart.AcceptedIdentity) error {
				if path == layout.BinaryPath(target) {
					probes++
					return errors.New("host has no controller decoder")
				}
				return nil
			}
			c := command{ctx: t.Context(), output: &bytes.Buffer{}, now: func() time.Time { return now.Add(time.Second) },
				restart: func(context.Context, string) error { t.Fatal("controller recovery restarted another unit"); return nil }}
			inputs, err := acceptedTrustInputs(accepted)
			if err != nil {
				t.Fatal(err)
			}
			if activation, err := c.controllerRollback(layout, accepted, inputs); err != nil || activation.Target != "" || probes != 0 {
				t.Fatalf("host activation classified as controller recovery: %+v %v probes=%d", activation, err, probes)
			}
			if recovered, err := c.recoverControllerActivation(layout, accepted, inputs); err != nil || recovered {
				t.Fatalf("host activation recovered by controller: %v %v", recovered, err)
			}
			if err := c.watchdog([]string{"--unit", selfupdate.ControllerUnit, "--root", layout.Root, "--owner", fmt.Sprint(os.Getuid())}); err == nil {
				t.Fatal("incompatible shared selection must refuse controller watchdog")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("controller changed host activation")
			}
			if current, err := layout.Current(); err != nil || current != target {
				t.Fatalf("controller rolled back host selection: %s %v", current, err)
			}
			if bad, err := layout.KnownBad(); err != nil || bad[target] {
				t.Fatalf("controller rejected host release: %v %v", bad, err)
			}
			if intents, err := layout.PendingRestores(); err != nil || len(intents) != 0 {
				t.Fatalf("controller started host restore: %v %v", intents, err)
			}
		})
	}
}

func TestControllerRecoveryRollsBackDamageOnlyAfterTrustedCompletion(t *testing.T) {
	for _, step := range []string{"prepare", "watchdog", "backstop"} {
		for _, damage := range []string{"binary", "receipt", "delegation", "unreadable", "contract"} {
			for _, fence := range []string{"complete", "interrupted rollback", "pending", "incompatible predecessor", "untrusted predecessor", "unsafe activation", "missing rollback pins"} {
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

					if fence == "interrupted rollback" {
						if err := os.WriteFile(filepath.Join(layout.Root, "known-bad.json"), []byte(`{"digests":["`+target+`"]}`), 0o644); err != nil {
							t.Fatal(err)
						}
					} else {
						switch damage {
						case "binary":
							if err := os.Remove(layout.BinaryPath(target)); err != nil {
								t.Fatal(err)
							}
						case "receipt":
							if err := os.Remove(filepath.Join(layout.ReleaseDir(target), "receipt.json")); err != nil {
								t.Fatal(err)
							}
						case "delegation":
							file := filepath.Join(layout.ReleaseDir(target), "delegation.json")
							if err := os.Chmod(file, 0o644); err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(file, []byte(`{}`), 0o444); err != nil {
								t.Fatal(err)
							}
						case "unreadable":
							file := filepath.Join(layout.Root, "activation.json")
							wire, err := os.ReadFile(file)
							if err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(file, bytes.Replace(wire, []byte(`"schema"`), []byte(`"unexpected":true,"schema"`), 1), 0o644); err != nil {
								t.Fatal(err)
							}
						}
					}
					if fence == "untrusted predecessor" {
						if err := os.Remove(layout.BinaryPath(previous)); err != nil {
							t.Fatal(err)
						}
					}
					if fence == "unsafe activation" {
						if err := os.Chmod(filepath.Join(layout.Root, "activation.json"), 0o666); err != nil {
							t.Fatal(err)
						}
					}
					if fence == "missing rollback pins" {
						if err := os.WriteFile(filepath.Join(layout.Root, "activation.json"), []byte(`{"target":"`+target+`"}`), 0o644); err != nil {
							t.Fatal(err)
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
					case "prepare":
						err = c.prepare(append(args, "--systemd-dir", t.TempDir()))
					case "watchdog":
						err = c.watchdog(append(args, "--proof-file", proofFile, "--proof-key-file", keyFile))
					case "backstop":
						err = c.backstopPrepare(layout, selfupdate.ControllerUnit)
					}
					if _, err := os.Stat(delegateMarker); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("rollback-only recovery delegated a root step: %v", err)
					}
					current, _ := layout.Current()
					if fence == "complete" || fence == "interrupted rollback" {
						wantRestarts := 0
						if step == "watchdog" {
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

func TestControllerFinishesRecordedRestoreOnlyAfterTrustedCompletion(t *testing.T) {
	for _, step := range []string{"prepare", "watchdog", "backstop"} {
		for _, fence := range []string{"complete", "pending", "unsafe intent", "foreign current", "incompatible destination", "wrong schema", "unknown member", "symlink intent"} {
			t.Run(step+"/"+fence, func(t *testing.T) {
				baseline := []byte("accepted baseline")
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
				baked := filepath.Join(t.TempDir(), "baked")
				if err := os.WriteFile(baked, baseline, 0o755); err != nil {
					t.Fatal(err)
				}
				if _, err := selfupdate.Seed(layout, baked); err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				stage := func(data []byte) string {
					receipt, delegation := signAcceptedSuccessor(t, data, now, private, roots)
					digest, err := selfupdate.Stage(layout, bytes.NewReader(data), receipt, delegation, selfupdate.ReceiptPolicy{Roots: roots, Environment: accepted.Environment, Cell: accepted.Cell, Architecture: runtime.GOARCH}, now)
					if err != nil {
						t.Fatal(err)
					}
					return digest
				}
				// Both selections are successors beyond the accepted baseline.
				destination, rejected := stage([]byte("confirmed successor")), stage([]byte("rejected successor"))
				if err := os.Remove(filepath.Join(layout.Root, "current")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("releases/"+rejected, filepath.Join(layout.Root, "current")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("releases/"+destination, filepath.Join(layout.Root, "known-good")); err != nil {
					t.Fatal(err)
				}
				intent := []byte(`{"schema":"terrascale.orchestrator.restore-intent.v1","unit":"` + selfupdate.ControllerUnit + `","target":"` + destination + `","rejected":"` + rejected + `"}`)
				intentPath := filepath.Join(layout.Root, "restore-"+selfupdate.ControllerUnit+".json")
				switch fence {
				case "wrong schema":
					intent = bytes.ReplaceAll(intent, []byte("restore-intent.v1"), []byte("restore-intent.v2"))
				case "unknown member":
					intent = bytes.Replace(intent, []byte("{"), []byte(`{"extra":true,`), 1)
				case "foreign current":
					if err := os.Remove(filepath.Join(layout.Root, "current")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("releases/"+accepted.Binary.SHA256, filepath.Join(layout.Root, "current")); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(intentPath, intent, 0o644); err != nil {
					t.Fatal(err)
				}
				if fence == "unsafe intent" {
					if err := os.Chmod(intentPath, 0o666); err != nil {
						t.Fatal(err)
					}
				}
				if fence == "symlink intent" {
					if err := os.Rename(intentPath, intentPath+".saved"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(intentPath+".saved", intentPath); err != nil {
						t.Fatal(err)
					}
				}
				bad := []byte(`{"digests":["` + rejected + `"]}`)
				if err := os.WriteFile(filepath.Join(layout.Root, "known-bad.json"), bad, 0o644); err != nil {
					t.Fatal(err)
				}
				checkAcceptedBinary = func(_ context.Context, path string, _ bootstrapstart.AcceptedIdentity) error {
					if fence == "incompatible destination" && path == layout.BinaryPath(destination) {
						return errors.New("incompatible decoder")
					}
					return nil
				}
				acceptedJournalPresent = func() (bool, error) { return true, nil }
				probes := 0
				completionProbe = func(_ context.Context, path string) error {
					probes++
					if path != layout.BinaryPath(destination) {
						t.Fatal("restore probe selected rejected release")
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
				c := command{ctx: t.Context(), output: &bytes.Buffer{}, now: func() time.Time { return now }, restart: func(context.Context, string) error { restarts++; return nil }}
				args := []string{"--unit", selfupdate.ControllerUnit, "--root", layout.Root, "--owner", fmt.Sprint(os.Getuid())}
				switch step {
				case "prepare":
					err = c.prepare(append(args, "--systemd-dir", t.TempDir()))
				case "watchdog":
					err = c.watchdog(args)
				case "backstop":
					err = c.backstopPrepare(layout, selfupdate.ControllerUnit)
				}
				current, readErr := layout.Current()
				if readErr != nil {
					t.Fatal(readErr)
				}
				if fence == "complete" {
					if err != nil || current != destination || probes == 0 {
						t.Fatalf("recorded restore current=%s probes=%d err=%v", current, probes, err)
					}
					if _, err := os.Lstat(intentPath); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("finished restore intent: %v", err)
					}
					wantRestarts := 0
					if step == "watchdog" {
						wantRestarts = 1
					}
					if restarts != wantRestarts {
						t.Fatalf("restarts=%d want=%d", restarts, wantRestarts)
					}
				} else {
					if err == nil || restarts != 0 || current == destination {
						t.Fatalf("fenced restore changed selection: %s %v", current, err)
					}
					retained, readErr := os.ReadFile(intentPath)
					if readErr != nil || !bytes.Equal(retained, intent) {
						t.Fatal("fenced restore changed intent")
					}
				}
			})
		}
	}
}

func TestControllerRootStepsRejectRetiredAcceptanceBeforeEffects(t *testing.T) {
	accepted := controllerAcceptedFixture(t, []byte("new baseline"))
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	useAcceptedController(t, accepted, roots)
	// A real retired marker shape, not a new snapshot with a missing journal.
	legacy, err := protocol.EncodeJSON(bootstrapstart.AcceptedInstall{SchemaVersion: 1,
		AnchorSHA256: strings.Repeat("a", 64), ManifestSHA256: strings.Repeat("b", 64), ReceiptSHA256: strings.Repeat("c", 64),
		ImageReceiptSHA256: strings.Repeat("d", 64), DeploymentID: "old-deployment", Cell: "gru", Slot: "controller-a", SeedSlot: "controller-b",
		ImageOCID: accepted.ImageOCID, InstanceOCID: accepted.InstanceOCID, PrimaryVNICOCID: accepted.PrimaryVNICOCID, PrimaryPrivateIP: accepted.PrimaryPrivateIP,
		HeadAttempt: 1, HeadGeneration: 1, ResultSHA256: strings.Repeat("e", 64), BinarySHA256: strings.Repeat("f", 64), MaterialSHA256: map[string]string{"cell.jwt": strings.Repeat("a", 64)}, AcceptedAt: accepted.AcceptedAt})
	if err != nil {
		t.Fatal(err)
	}
	acceptedIdentity = func() (bootstrapstart.AcceptedIdentity, error) { return bootstrapstart.DecodeAcceptedIdentity(legacy) }
	acceptedJournalPresent = func() (bool, error) { t.Fatal("retired marker was treated as absent"); return false, nil }
	checkAcceptedBinary = func(context.Context, string, bootstrapstart.AcceptedIdentity) error {
		t.Fatal("retired marker reached release selection")
		return nil
	}
	completionProbe = func(context.Context, string) error { t.Fatal("retired marker reached network probe"); return nil }
	for _, step := range []string{"prepare", "watchdog", "activate", "backstop"} {
		t.Run(step, func(t *testing.T) {
			layout := selfupdate.Layout{Root: filepath.Join(t.TempDir(), "root"), Owner: os.Getuid()}
			args := []string{"--unit", selfupdate.ControllerUnit, "--root", layout.Root, "--owner", fmt.Sprint(os.Getuid())}
			c := command{ctx: t.Context(), output: &bytes.Buffer{}, now: time.Now, restart: func(context.Context, string) error { t.Fatal("retired marker restarted controller"); return nil }}
			switch step {
			case "prepare":
				err = c.prepare(args)
			case "watchdog":
				err = c.watchdog(args)
			case "activate":
				err = c.activate(append(args, "--release", accepted.Binary.SHA256))
			case "backstop":
				err = c.backstopPrepare(layout, selfupdate.ControllerUnit)
			}
			if !errors.Is(err, bootstrapstart.ErrAcceptedIdentity) {
				t.Fatalf("retired acceptance gate: %v", err)
			}
			if step != "backstop" {
				if _, err := os.Stat(layout.Root); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("retired acceptance changed release layout")
				}
			} else {
				entries, err := os.ReadDir(layout.Root)
				if err != nil || len(entries) != 2 || entries[0].Name() != ".lock" || entries[1].Name() != "releases" {
					t.Fatalf("backstop changed selection: %v %v", entries, err)
				}
				if releases, err := os.ReadDir(filepath.Join(layout.Root, "releases")); err != nil || len(releases) != 0 {
					t.Fatal("retired acceptance published a release")
				}
			}
		})
	}
}
