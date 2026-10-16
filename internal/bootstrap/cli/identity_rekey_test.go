package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

type identityRekeyCLIFixture struct {
	directory      string
	now            time.Time
	key            ed25519.PrivateKey
	roots          trust.Keyring
	checkpoint     identityrekey.AcceptedIdentityCheckpoint
	expected       identityrekey.CheckpointExpectation
	observed       identityrekey.HostStateObservation
	plan           identityrekey.HostStateHandoffPlan
	reset          authority.IdentityReset
	target         authority.IdentityResetTarget
	accepted       bootstrapstart.AcceptedIdentity
	journal        bootstrapstart.IdentityRekeyJournal
	checkpointWire []byte
}

func newIdentityRekeyCLIFixture(t *testing.T) *identityRekeyCLIFixture {
	t.Helper()
	f := &identityRekeyCLIFixture{directory: t.TempDir(), now: time.Now().UTC().Truncate(time.Second)}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key = key
	f.roots, err = trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.path("root.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)
	writeFixture(t, f.path("root.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600)
	chainWire, err := trust.EncodeRootChain(trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.path("roots.json"), chainWire, 0o644)
	nkey := func(operator bool) string {
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
		public, err := pair.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		return public
	}
	f.checkpoint = identityrekey.AcceptedIdentityCheckpoint{SchemaVersion: 1,
		OperationID: entityid.New(), DeploymentID: entityid.New(), ClusterID: entityid.New(),
		Cell: "GRU", Environment: "canary", SeedSlot: "controller-a", MaterialGenerationSHA256: digest([]byte("material generation")),
		Broker: identityrekey.BrokerIdentity{Operator: nkey(true), SystemAccount: nkey(false), CellAccount: nkey(false),
			HostSigner: nkey(false), RoleSigner: nkey(false)}}
	for i := range 3 {
		slot := fmt.Sprintf("controller-%c", 'a'+i)
		purposes := map[string]bootstrap.SecretPurpose{
			"operator.jwt": bootstrap.SecretRegionalShared, "system.jwt": bootstrap.SecretRegionalShared,
			"cell.jwt": bootstrap.SecretRegionalShared, "system.creds": bootstrap.SecretRegionalShared,
			"ca.pem": bootstrap.SecretRegionalShared, "route-password": bootstrap.SecretRegionalShared,
			"ticket.pub": bootstrap.SecretRegionalShared, "ticket.key": bootstrap.SecretRegionalShared,
			"host-nats-issuer.seed": bootstrap.SecretHostIssuer, "host-tls-issuer-cert.pem": bootstrap.SecretHostIssuer,
			"host-tls-issuer-key.pem": bootstrap.SecretHostIssuer, slot + ".creds": bootstrap.SecretController,
			slot + "-tls-cert.pem": bootstrap.SecretController, slot + "-tls-key.pem": bootstrap.SecretController,
			slot + "-response.key": bootstrap.SecretController,
		}
		var references []bootstrap.SecretReference
		for _, name := range slices.Sorted(maps.Keys(purposes)) {
			ref := bootstrap.SecretReference{Purpose: purposes[name], SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1." + slot,
				VersionNumber: 1, MaxBytes: 64 << 10, TargetFile: name, SHA256: digest([]byte(name))}
			if ref.Purpose == bootstrap.SecretController {
				ref.Slot = slot
			}
			references = append(references, ref)
		}
		f.checkpoint.Slots = append(f.checkpoint.Slots, identityrekey.SlotBinding{Slot: slot,
			PreviousAcceptanceSHA256: digest([]byte("opaque old acceptance")),
			PreviousMaterialSHA256:   map[string]string{"installed": digest([]byte("old material chain")), "durable": digest([]byte("old material chain"))},
			InstanceOCID:             fmt.Sprintf("ocid1.instance.oc1.sa-saopaulo-1.controller%d", i),
			ImageOCID:                "ocid1.image.oc1.sa-saopaulo-1.current", PrimaryVNICOCID: fmt.Sprintf("ocid1.vnic.oc1.sa-saopaulo-1.controller%d", i),
			PrimaryPrivateIP: fmt.Sprintf("10.251.0.%d", i+11),
			Binary:           identityrekey.BinaryPin{SHA256: digest([]byte("binary")), Size: 4096, Architecture: "amd64"},
			ConfigSHA256: map[string]string{"controller.json": digest([]byte("config")), "placement.json": digest([]byte("placement")),
				"oci-region.json": digest([]byte("region")), "oci-region-intent.json": digest([]byte("intent"))},
			LaunchMaterialSHA256: map[string]string{"host-enrollment-public.json": digest([]byte("enrollment")),
				"operator-ssh-key.pub": digest([]byte("SSH")), "managed-host-image-receipt.json": digest([]byte("image")),
				"managed-host-image-delegation.json": digest([]byte("image grant"))},
			MaterialReferences: references,
			Store: identityrekey.StoreIdentity{Directory: "/var/lib/terrascale-orchestrator-controller/nats", ServerName: fmt.Sprintf("gru-1-ctl-%d", i+1),
				RaftNodeID: fmt.Sprintf("NODE000%d", i), ServerNameSHA256: digest([]byte(fmt.Sprintf("gru-1-ctl-%d\n", i+1))),
				NodeIdentitySHA256: digest([]byte(fmt.Sprintf("existing node %d", i)))}})
	}
	f.expected = identityrekey.CheckpointExpectation{OperationID: f.checkpoint.OperationID, DeploymentID: f.checkpoint.DeploymentID,
		ClusterID: f.checkpoint.ClusterID, Environment: f.checkpoint.Environment, Cell: f.checkpoint.Cell,
		SeedSlot: f.checkpoint.SeedSlot, MaterialGenerationSHA256: f.checkpoint.MaterialGenerationSHA256,
		Broker: f.checkpoint.Broker, Slot: f.checkpoint.Slots[0]}
	writeFixture(t, f.path("expected.json"), mustEncodePayload(t, f.expected), 0o644)
	writeFixture(t, f.path("checkpoint-candidate.json"), mustEncodePayload(t, f.checkpoint), 0o644)
	checkpointEnvelope, err := identityrekey.IssueAcceptedIdentityCheckpoint(f.checkpoint, f.now, f.now.Add(24*time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	f.checkpointWire = encodeEnvelope(t, checkpointEnvelope)
	writeFixture(t, f.path("checkpoint.json"), f.checkpointWire, 0o644)
	checkpoint, err := identityrekey.VerifyAcceptedIdentityCheckpoint(f.checkpointWire, f.roots, trust.RootChain{Version: 1}, f.expected, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.accepted, err = bootstrapstart.AcceptedIdentityFromCheckpoint(checkpoint, "controller-a", f.now)
	if err != nil {
		t.Fatal(err)
	}
	acceptedWire, err := bootstrapstart.EncodeAcceptedIdentity(f.accepted)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.path("accepted.json"), acceptedWire, 0o644)
	responseKey := func() string {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(public)
	}
	f.observed = identityrekey.HostStateObservation{OperationID: f.expected.OperationID, DeploymentID: f.expected.DeploymentID,
		ClusterID: f.expected.ClusterID, Cell: f.expected.Cell, Environment: f.expected.Environment, CheckpointSHA256: checkpoint.Fingerprint(),
		EpochFloor: 7, Epoch: 8, PreviousResponseKey: responseKey(), ResponseKey: responseKey(),
		AgentsStoppedAt: f.now.Add(-time.Minute), ObservedAt: f.now.Add(-time.Second)}
	f.observed.Preconditions = []identityrekey.HostStatePrecondition{{Bucket: "TS_HOST_STATE", Key: "retirement-cutover." + strings.ToLower(f.expected.Cell)}}
	f.plan, err = identityrekey.BuildHostStateHandoffPlan(f.observed, f.now)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.path("observation.json"), mustEncodePayload(t, f.observed), 0o644)
	writeFixture(t, f.path("host-candidate.json"), mustEncodePayload(t, f.plan), 0o644)
	hostEnvelope, err := identityrekey.SignHostStateHandoffPlan(f.plan, f.now, f.now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	hostWire := encodeEnvelope(t, hostEnvelope)
	writeFixture(t, f.path("host-plan.json"), hostWire, 0o644)
	hostPlan, err := identityrekey.VerifyHostStateHandoffPlan(hostEnvelope, f.roots, f.observed, f.now)
	if err != nil {
		t.Fatal(err)
	}
	values := [][]byte{[]byte("replacement service set"), chainWire, []byte("replacement material chain")}
	f.reset = authority.IdentityReset{Version: 1, OperationID: f.expected.OperationID, DeploymentID: f.expected.DeploymentID,
		ClusterID: f.expected.ClusterID, Scope: "gru", Environment: f.expected.Environment, CheckpointSHA256: checkpoint.Fingerprint(),
		HostStatePlanSHA256: hostPlan.Fingerprint(), LastSequence: 1, PreviousSequence: 1,
		PreviousSHA256: digest(identityRekeyOldLease), EpochFloor: 7, Epoch: 8}
	for i, destination := range [][2]string{{"TS_SERVICE_SET", "current"}, {"TS_TRUST_ROOTS", "chain"}, {"TS_TRUST_ROOTS", "material-generations"}} {
		f.reset.Records = append(f.reset.Records, authority.IdentityResetRecord{Action: authority.IdentityResetReplaceKV,
			Bucket: destination[0], Key: destination[1], SHA256: digest(values[i])})
	}
	f.reset.Records = append(f.reset.Records, hostPlan.IdentityResetRecords()...)
	values = append(values, hostPlan.Values()...)
	writeFixture(t, f.path("reset-candidate.json"), mustEncodePayload(t, f.reset), 0o644)
	resetEnvelope, err := authority.SignIdentityReset(f.reset, f.now, f.now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	f.target = authority.IdentityResetTarget{OperationID: f.reset.OperationID, DeploymentID: f.reset.DeploymentID,
		ClusterID: f.reset.ClusterID, Scope: f.reset.Scope, Environment: f.reset.Environment, CheckpointSHA256: f.reset.CheckpointSHA256,
		HostStatePlanSHA256: f.reset.HostStatePlanSHA256, Replicas: 1}
	roots, err := trust.VerifyRootChain(f.roots, trust.ChainIdentity{DeploymentID: f.expected.DeploymentID, Cell: "gru", Environment: f.expected.Environment}, trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	f.journal = bootstrapstart.IdentityRekeyJournal{Version: 1, AcceptedWire: acceptedWire, PreviousMaterialSHA256: maps.Clone(f.expected.Slot.PreviousMaterialSHA256),
		PreviousAcceptanceSHA256: f.expected.Slot.PreviousAcceptanceSHA256, CheckpointWire: f.checkpointWire,
		ResetWire: encodeEnvelope(t, resetEnvelope), HostPlanWire: hostWire, HostObservation: f.observed,
		RootChainWire: chainWire, GenesisSHA256: trust.RootSetDigest(f.roots), RootHead: roots.Head, Replicas: 1, Values: values}
	writeFixture(t, f.path("journal.json"), mustEncodePayload(t, f.journal), 0o644)
	return f
}

func (f *identityRekeyCLIFixture) path(name string) string { return filepath.Join(f.directory, name) }

func (f *identityRekeyCLIFixture) signArgs(candidate string) []string {
	return []string{"--candidate", f.path(candidate), "--expectation", f.path("expected.json"),
		"--root-key", f.path("root.pem"), "--root-chain", f.path("roots.json"), "--signing-key", f.path("root.key"),
		"--out", f.path("signed.json"), "--valid-for", "1h"}
}

func TestIdentityRekeyRootSigningExactV1(t *testing.T) {
	for _, kind := range []string{"checkpoint", "host", "reset"} {
		t.Run(kind, func(t *testing.T) {
			f := newIdentityRekeyCLIFixture(t)
			c := command{ctx: t.Context(), output: io.Discard}
			args := f.signArgs(kind + "-candidate.json")
			var commandName string
			switch kind {
			case "checkpoint":
				commandName = "sign-accepted-identity-checkpoint"
			case "host":
				commandName = "sign-host-state-handoff-plan"
				args = append(args, "--checkpoint", f.path("checkpoint.json"), "--observation", f.path("observation.json"))
			case "reset":
				commandName = "sign-identity-reset"
				args = append(args, "--checkpoint", f.path("checkpoint.json"), "--observation", f.path("observation.json"),
					"--host-plan", f.path("host-plan.json"), "--replicas", "1")
			}
			if err := c.runAt(append([]string{commandName}, args...), f.now); err != nil {
				t.Fatal(err)
			}
			wire, err := os.ReadFile(f.path("signed.json"))
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := trust.DecodeEnvelope(wire)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "checkpoint":
				_, err = identityrekey.VerifyAcceptedIdentityCheckpoint(wire, f.roots, trust.RootChain{Version: 1}, f.expected, f.now)
			case "host":
				_, err = identityrekey.VerifyHostStateHandoffPlan(envelope, f.roots, f.observed, f.now)
			case "reset":
				var reset authority.IdentityReset
				reset, err = authority.VerifyIdentityReset(envelope, f.roots, f.target, f.now)
				if reset.LastSequence != f.reset.LastSequence || reset.PreviousSequence != f.reset.PreviousSequence || reset.PreviousSHA256 != f.reset.PreviousSHA256 {
					t.Fatal("signer changed the reviewed predecessor")
				}
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIdentityRekeyRootSigningRejectsBeforeOutput(t *testing.T) {
	for _, name := range []string{"target mismatch", "legacy identity", "unknown field", "noncanonical", "wrong root", "insecure key", "excess lifetime"} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityRekeyCLIFixture(t)
			args := f.signArgs("checkpoint-candidate.json")
			switch name {
			case "target mismatch":
				f.expected.ClusterID = entityid.New()
				writeFixture(t, f.path("expected.json"), mustEncodePayload(t, f.expected), 0o644)
			case "legacy identity":
				f.checkpoint.DeploymentID = "old-deployment"
				writeFixture(t, f.path("checkpoint-candidate.json"), mustEncodePayload(t, f.checkpoint), 0o644)
			case "unknown field":
				wire := mustEncodePayload(t, f.checkpoint)
				writeFixture(t, f.path("checkpoint-candidate.json"), append(wire[:len(wire)-1], []byte(`,"allow_legacy":true}`)...), 0o644)
			case "noncanonical":
				writeFixture(t, f.path("checkpoint-candidate.json"), append([]byte(" "), mustEncodePayload(t, f.checkpoint)...), 0o644)
			case "wrong root":
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				der, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					t.Fatal(err)
				}
				writeFixture(t, f.path("root.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
			case "insecure key":
				if err := os.Chmod(f.path("root.key"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "excess lifetime":
				args[len(args)-1] = "9000h"
			}
			if err := (command{ctx: t.Context(), output: io.Discard}).signAcceptedIdentityCheckpointAt(args, f.now); err == nil {
				t.Fatal("invalid reviewed input was signed")
			}
			if _, err := os.Stat(f.path("signed.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected signing created output: %v", err)
			}
		})
	}
}

func TestIdentityRekeyHostSigningRequiresDrainAndIndependentTarget(t *testing.T) {
	for _, name := range []string{"short drain", "different inventory", "foreign checkpoint"} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityRekeyCLIFixture(t)
			switch name {
			case "short drain":
				f.observed.AgentsStoppedAt = f.observed.ObservedAt.Add(-31 * time.Second)
			case "different inventory":
				f.observed.Epoch++
			case "foreign checkpoint":
				f.observed.CheckpointSHA256 = strings.Repeat("a", 64)
			}
			writeFixture(t, f.path("observation.json"), mustEncodePayload(t, f.observed), 0o644)
			args := append(f.signArgs("host-candidate.json"), "--checkpoint", f.path("checkpoint.json"), "--observation", f.path("observation.json"))
			if err := (command{ctx: t.Context(), output: io.Discard}).signHostStateHandoffPlanAt(args, f.now); err == nil {
				t.Fatal("unsafe inventory was signed")
			}
			if _, err := os.Stat(f.path("signed.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected signing created output: %v", err)
			}
		})
	}
}

func TestIdentityRekeyRootSigningUsesCurrentDeploymentLineage(t *testing.T) {
	f := newIdentityRekeyCLIFixture(t)
	identity := trust.ChainIdentity{DeploymentID: f.expected.DeploymentID, Cell: "gru", Environment: f.expected.Environment}
	roots, err := trust.VerifyRootChain(f.roots, identity, trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	public, nextKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := trust.NextRotation(roots, public)
	if err != nil {
		t.Fatal(err)
	}
	var signed trust.SignedRotation
	for _, key := range []ed25519.PrivateKey{f.key, nextKey} {
		envelope, err := trust.SignRotation(rotation, identity, f.now, f.now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		signed.Signatures = append(signed.Signatures, envelope)
	}
	chain := trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{signed}}
	wire, err := trust.EncodeRootChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.path("roots.json"), wire, 0o644)
	c := command{ctx: t.Context(), output: io.Discard}
	args := f.signArgs("checkpoint-candidate.json")
	if err := c.signAcceptedIdentityCheckpointAt(args, f.now); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("retired genesis authorized current signing: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(nextKey)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.path("root.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	if err := c.signAcceptedIdentityCheckpointAt(args, f.now); err != nil {
		t.Fatalf("current root could not sign: %v", err)
	}
	checkpointWire, err := os.ReadFile(f.path("signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identityrekey.VerifyAcceptedIdentityCheckpoint(checkpointWire, f.roots, chain, f.expected, f.now); err != nil {
		t.Fatal(err)
	}
	f.expected.DeploymentID = entityid.New()
	writeFixture(t, f.path("expected.json"), mustEncodePayload(t, f.expected), 0o644)
	if err := c.signAcceptedIdentityCheckpointAt(args, f.now); !errors.Is(err, trust.ErrScopeMismatch) {
		t.Fatalf("foreign root lineage was accepted: %v", err)
	}
}

func TestIdentityRekeyResetSigningRejectsChangedPlanOrTarget(t *testing.T) {
	for _, name := range []string{"cluster", "checkpoint", "host plan", "epoch", "v2"} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityRekeyCLIFixture(t)
			switch name {
			case "cluster":
				f.reset.ClusterID = entityid.New()
			case "checkpoint":
				f.reset.CheckpointSHA256 = strings.Repeat("a", 64)
			case "host plan":
				f.reset.HostStatePlanSHA256 = strings.Repeat("a", 64)
			case "epoch":
				f.reset.Epoch++
			case "v2":
				f.reset.Version = 2
			}
			writeFixture(t, f.path("reset-candidate.json"), mustEncodePayload(t, f.reset), 0o644)
			args := append(f.signArgs("reset-candidate.json"), "--checkpoint", f.path("checkpoint.json"), "--observation", f.path("observation.json"),
				"--host-plan", f.path("host-plan.json"), "--replicas", "1")
			if err := (command{ctx: t.Context(), output: io.Discard}).signIdentityResetAt(args, f.now); err == nil {
				t.Fatal("changed reset authority was signed")
			}
			if _, err := os.Stat(f.path("signed.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected reset created output: %v", err)
			}
		})
	}
}

var identityRekeyOldLease = []byte(`{"version":1,"scope":"gru","candidate_id":"old-controller","owner_id":"old-owner","epoch":7}`)

func identityRekeyTestBroker(t *testing.T) (*natscell.Runtime, jetstream.Stream) {
	t.Helper()
	runtime, err := natscell.Start(t.Context(), natscell.Config{Cell: "gru", Instance: "controller-a", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{StoreDir: t.TempDir(), Host: "127.0.0.1", Port: -1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	for _, bucket := range []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS", "TS_HOST_STATE"} {
		if _, err := runtime.JetStream().CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: bucket, Storage: jetstream.FileStorage, Replicas: 1}); err != nil {
			t.Fatal(err)
		}
	}
	stream, err := runtime.JetStream().CreateStream(t.Context(), jetstream.StreamConfig{Name: authority.ControlStreamName,
		Subjects: []string{protocol.ControlStreamSubject()}, Retention: jetstream.LimitsPolicy,
		MaxConsumers: -1, MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1,
		Storage: jetstream.FileStorage, Replicas: 1, DenyDelete: true, DenyPurge: true,
		Metadata: map[string]string{"terrascale-contract": "authority-log-v1"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.JetStream().Publish(t.Context(), protocol.Control("gru", "lease"), identityRekeyOldLease); err != nil {
		t.Fatal(err)
	}
	return runtime, stream
}

func TestIdentityRekeyPrecommitOnlyHeldBarrierAndExactRetry(t *testing.T) {
	f := newIdentityRekeyCLIFixture(t)
	runtime, stream := identityRekeyTestBroker(t)
	envelope, err := trust.DecodeEnvelope(f.journal.ResetWire)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		sequence, err := authority.ResetIdentityLease(t.Context(), runtime.JetStream(), envelope, f.roots, f.target, f.now)
		if err != nil || sequence != 2 {
			t.Fatalf("barrier sequence=%d error=%v", sequence, err)
		}
	}
	info, err := stream.Info(t.Context())
	if err != nil || info.State.LastSeq != 2 || info.State.Msgs != 2 {
		t.Fatalf("precommit replaced records or duplicated barrier: %+v %v", info, err)
	}
	previous, err := stream.GetMsg(t.Context(), 1)
	if err != nil || !bytes.Equal(previous.Data, identityRekeyOldLease) {
		t.Fatalf("opaque predecessor changed: %v", err)
	}
	barrier, err := stream.GetMsg(t.Context(), 2)
	if err != nil {
		t.Fatal(err)
	}
	var current struct {
		Version             int    `json:"version"`
		DeploymentID        string `json:"deployment_id"`
		Released            bool   `json:"released"`
		IdentityResetSHA256 string `json:"identity_reset_sha256"`
	}
	if err := protocol.DecodeTolerant(barrier.Data, &current, 16<<10); err != nil || !current.Released ||
		current.DeploymentID != f.expected.DeploymentID || current.IdentityResetSHA256 == "" {
		t.Fatalf("missing held root barrier: %+v %v", current, err)
	}
	var legacy struct {
		Version       int    `json:"version"`
		Scope         string `json:"scope"`
		CandidateID   string `json:"candidate_id"`
		OwnerID       string `json:"owner_id"`
		Epoch         uint64 `json:"epoch"`
		LeaseDuration int64  `json:"lease_duration_ns"`
		TransitionID  string `json:"transition_id"`
		Released      bool   `json:"released"`
	}
	if err := protocol.DecodeStrict(barrier.Data, &legacy, 16<<10); err == nil {
		t.Fatal("old decoder admitted the deployment/reset-bound barrier")
	}
}

func TestIdentityRekeyPrecommitRejectsStaleAndUnrootedBeforeMutation(t *testing.T) {
	for _, name := range []string{"changed log", "changed lease", "changed target", "wrong root", "expired", "wrong stream policy"} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityRekeyCLIFixture(t)
			runtime, stream := identityRekeyTestBroker(t)
			envelope, err := trust.DecodeEnvelope(f.journal.ResetWire)
			if err != nil {
				t.Fatal(err)
			}
			now := f.now
			switch name {
			case "changed log":
				_, err = runtime.JetStream().Publish(t.Context(), protocol.Control("gru", "host", "registration", "changed"), []byte("another writer"))
			case "changed lease":
				_, err = runtime.JetStream().Publish(t.Context(), protocol.Control("gru", "lease"), []byte("another opaque lease"))
			case "changed target":
				f.target.ClusterID = entityid.New()
			case "wrong root":
				_, key, keyErr := ed25519.GenerateKey(rand.Reader)
				if keyErr != nil {
					t.Fatal(keyErr)
				}
				envelope, err = authority.SignIdentityReset(f.reset, now, now.Add(time.Hour), key)
			case "expired":
				now = envelope.ExpiresAt
			case "wrong stream policy":
				config := stream.CachedInfo().Config
				config.AllowDirect = true
				_, err = runtime.JetStream().UpdateStream(t.Context(), config)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := stream.Info(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authority.ResetIdentityLease(t.Context(), runtime.JetStream(), envelope, f.roots, f.target, now); err == nil {
				t.Fatal("unsafe reset admitted")
			}
			after, err := stream.Info(t.Context())
			if err != nil || after.State.LastSeq != before.State.LastSeq || after.State.Msgs != before.State.Msgs {
				t.Fatalf("rejected precommit mutated stream: %v", err)
			}
		})
	}
}

// The old bridge can close after the durable write, before its reply reaches
// the caller. The executor must report uncertainty rather than publish again.
type identityRekeyDisconnect struct {
	jetstream.JetStream
	conn      *nats.Conn
	publishes int
}

func (js *identityRekeyDisconnect) PublishMsg(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	js.publishes++
	if _, err := js.JetStream.PublishMsg(ctx, msg, opts...); err != nil {
		return nil, err
	}
	js.conn.Close()
	return nil, nats.ErrConnectionClosed
}

func TestIdentityRekeyPrecommitDisconnectDoesNotDuplicateReset(t *testing.T) {
	f := newIdentityRekeyCLIFixture(t)
	runtime, _ := identityRekeyTestBroker(t)
	conn, err := nats.Connect(runtime.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	disconnected := &identityRekeyDisconnect{JetStream: js, conn: conn}
	envelope, err := trust.DecodeEnvelope(f.journal.ResetWire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.ResetIdentityLease(t.Context(), disconnected, envelope, f.roots, f.target, f.now); !errors.Is(err, authority.ErrOutcomeUnknown) {
		t.Fatalf("lost old bridge reply must remain uncertain: %v", err)
	}
	if disconnected.publishes != 1 {
		t.Fatalf("retried through closed bridge: %d publishes", disconnected.publishes)
	}
	sequence, err := authority.ResetIdentityLease(t.Context(), runtime.JetStream(), envelope, f.roots, f.target, f.now)
	if err != nil || sequence != 2 {
		t.Fatalf("held broker readback did not recognize exact barrier: %d %v", sequence, err)
	}
}

func TestIdentityRekeyPrecommitConnectionRejectsLegacyAndServerModes(t *testing.T) {
	f := newIdentityRekeyCLIFixture(t)
	connection := app.IdentityRekeyConnection{Version: 1, NATS: natscell.Config{Cell: "gru", Instance: "controller-a", Replicas: 1,
		ClientRole: "controller", URL: "tls://127.0.0.1:4222", CredentialsFile: "existing.creds",
		TLS: natscell.TLSFiles{CAFile: "ca.pem", CertFile: "client.pem", KeyFile: "client.key"}}}
	if err := connection.Validate(f.accepted, 1); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"old version", "embedded", "lab", "wrong cell", "wrong slot", "wrong quorum", "no credentials"} {
		t.Run(name, func(t *testing.T) {
			changed := connection
			switch name {
			case "old version":
				changed.Version = 0
			case "embedded":
				changed.NATS.Embedded = &natscell.Embedded{}
			case "lab":
				changed.NATS.Lab = true
			case "wrong cell":
				changed.NATS.Cell = "sfo"
			case "wrong slot":
				changed.NATS.Instance = "controller-b"
			case "wrong quorum":
				changed.NATS.Replicas = 3
			case "no credentials":
				changed.NATS.CredentialsFile = ""
			}
			if err := changed.Validate(f.accepted, 1); err == nil {
				t.Fatal("unsafe connection mode admitted")
			}
		})
	}
	var decoded app.IdentityRekeyConnection
	if err := protocol.DecodeStrict([]byte(`{"version":1,"nats":{},"global":null}`), &decoded, 64<<10); err == nil {
		t.Fatal("legacy app config member accepted as connection input")
	}
}

func TestBootstrapRejectsUncheckedIdentityRekeyPrecommit(t *testing.T) {
	err := (command{ctx: t.Context(), output: io.Discard}).runAt([]string{"precommit-identity-rekey"}, time.Now())
	if err == nil || err.Error() != usage || strings.Contains(usage, "precommit-identity-rekey") {
		t.Fatalf("unchecked precommit is reachable: %v", err)
	}
}
