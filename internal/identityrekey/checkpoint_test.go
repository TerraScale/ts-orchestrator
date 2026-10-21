package identityrekey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nkeys"
)

func TestCheckpointIssueVerify(t *testing.T) {
	checkpoint, key, roots, now := checkpointFixture(t)
	envelope, wire := issueCheckpoint(t, checkpoint, key, now)
	for _, slot := range checkpoint.Slots {
		verified, err := VerifyAcceptedIdentityCheckpoint(wire, roots, trust.RootChain{Version: 1}, expectation(checkpoint, slot), now)
		if err != nil {
			t.Fatal(err)
		}
		if !verified.IsVerified() || verified.Fingerprint() != sha256Hex(wire) || !verified.ExpiresAt().Equal(envelope.ExpiresAt) ||
			!bytes.Equal(verified.Wire(), wire) {
			t.Fatal("verified checkpoint lost its proof identity")
		}
		copy := verified.Checkpoint()
		copy.Slots[0].ConfigSHA256["controller.json"] = "modified"
		copy.Slots[0].LaunchMaterialSHA256["operator-ssh-key.pub"] = "modified"
		copy.Slots[0].InstanceOCID = "modified"
		copy.Slots[0].MaterialReferences[0].SHA256 = "modified"
		copyWire := verified.Wire()
		copyWire[0] = 'x'
		if verified.Checkpoint().Slots[0].ConfigSHA256["controller.json"] == "modified" ||
			verified.Checkpoint().Slots[0].InstanceOCID == "modified" || verified.Checkpoint().Slots[0].LaunchMaterialSHA256["operator-ssh-key.pub"] == "modified" || !bytes.Equal(verified.Wire(), wire) {
			t.Fatal("verified checkpoint leaked mutable data")
		}
		if verified.Checkpoint().Slots[0].MaterialReferences[0].SHA256 == "modified" {
			t.Fatal("verified checkpoint leaked its material baseline")
		}
	}
	if (VerifiedIdentityCheckpoint{}).IsVerified() {
		t.Fatal("zero value grants authority")
	}
}

func TestCheckpointRejectsWrongExpectations(t *testing.T) {
	checkpoint, key, roots, now := checkpointFixture(t)
	_, wire := issueCheckpoint(t, checkpoint, key, now)
	for _, test := range []struct {
		name   string
		mutate func(*CheckpointExpectation)
	}{
		{"operation", func(e *CheckpointExpectation) { e.OperationID = entityid.Derive("other-operation") }},
		{"deployment", func(e *CheckpointExpectation) { e.DeploymentID = entityid.Derive("other-deployment") }},
		{"cluster", func(e *CheckpointExpectation) { e.ClusterID = entityid.Derive("other-cluster") }},
		{"environment", func(e *CheckpointExpectation) { e.Environment = "production" }},
		{"cell", func(e *CheckpointExpectation) { e.Cell = "SJC" }},
		{"slot", func(e *CheckpointExpectation) { e.Slot.Slot = "controller-b" }},
		{"unknown slot", func(e *CheckpointExpectation) { e.Slot.Slot = "controller-d" }},
		{"instance", func(e *CheckpointExpectation) { e.Slot.InstanceOCID += "other" }},
		{"image", func(e *CheckpointExpectation) { e.Slot.ImageOCID += "other" }},
		{"vnic", func(e *CheckpointExpectation) { e.Slot.PrimaryVNICOCID += "other" }},
		{"ip", func(e *CheckpointExpectation) { e.Slot.PrimaryPrivateIP = "10.251.0.99" }},
		{"binary digest", func(e *CheckpointExpectation) { e.Slot.Binary.SHA256 = sha256Hex([]byte("other")) }},
		{"binary size", func(e *CheckpointExpectation) { e.Slot.Binary.Size++ }},
		{"binary arch", func(e *CheckpointExpectation) { e.Slot.Binary.Architecture = "arm64" }},
		{"config digest", func(e *CheckpointExpectation) { e.Slot.ConfigSHA256["controller.json"] = sha256Hex([]byte("other")) }},
		{"launch digest", func(e *CheckpointExpectation) {
			e.Slot.LaunchMaterialSHA256["operator-ssh-key.pub"] = sha256Hex([]byte("other"))
		}},
		{"config inventory", func(e *CheckpointExpectation) { delete(e.Slot.ConfigSHA256, "placement.json") }},
		{"material generation", func(e *CheckpointExpectation) { e.MaterialGenerationSHA256 = sha256Hex([]byte("other")) }},
		{"old exact bytes", func(e *CheckpointExpectation) { e.Slot.PreviousAcceptanceSHA256 = sha256Hex([]byte("old\n")) }},
		{"store path", func(e *CheckpointExpectation) { e.Slot.Store.Directory += "-other" }},
		{"server name", func(e *CheckpointExpectation) { e.Slot.Store.ServerName += "-other" }},
		{"raft node", func(e *CheckpointExpectation) { e.Slot.Store.RaftNodeID = "OTHER001" }},
		{"server-name bytes", func(e *CheckpointExpectation) { e.Slot.Store.ServerNameSHA256 = sha256Hex([]byte("other")) }},
		{"node-identity bytes", func(e *CheckpointExpectation) { e.Slot.Store.NodeIdentitySHA256 = sha256Hex([]byte("other")) }},
		{"broker keys", func(e *CheckpointExpectation) { e.Broker.CellAccount = publicKey(t, false) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			expected := expectation(checkpoint, checkpoint.Slots[0])
			test.mutate(&expected)
			if _, err := VerifyAcceptedIdentityCheckpoint(wire, roots, trust.RootChain{Version: 1}, expected, now); err == nil {
				t.Fatal("accepted a different independently observed binding")
			}
		})
	}
}

func TestCheckpointRejectsInvalidSignedContracts(t *testing.T) {
	checkpoint, key, roots, now := checkpointFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*AcceptedIdentityCheckpoint)
	}{
		{"version zero", func(c *AcceptedIdentityCheckpoint) { c.SchemaVersion = 0 }},
		{"version two", func(c *AcceptedIdentityCheckpoint) { c.SchemaVersion = 2 }},
		{"legacy operation", func(c *AcceptedIdentityCheckpoint) { c.OperationID = "old-operation" }},
		{"legacy deployment", func(c *AcceptedIdentityCheckpoint) { c.DeploymentID = "bootstrap-gru" }},
		{"legacy cluster", func(c *AcceptedIdentityCheckpoint) { c.ClusterID = "gru-1" }},
		{"lowercase ULID", func(c *AcceptedIdentityCheckpoint) { c.ClusterID = strings.ToLower(c.ClusterID) }},
		{"zero ULID", func(c *AcceptedIdentityCheckpoint) { c.ClusterID = strings.Repeat("0", 26) }},
		{"prefixed ULID", func(c *AcceptedIdentityCheckpoint) { c.DeploymentID = "deployment:" + c.DeploymentID }},
		{"unsupported environment", func(c *AcceptedIdentityCheckpoint) { c.Environment = "test" }},
		{"unsupported cell", func(c *AcceptedIdentityCheckpoint) { c.Cell = "gru-1" }},
		{"missing seed slot", func(c *AcceptedIdentityCheckpoint) { c.SeedSlot = "" }},
		{"missing slot", func(c *AcceptedIdentityCheckpoint) { c.Slots = c.Slots[:2] }},
		{"extra slot", func(c *AcceptedIdentityCheckpoint) { c.Slots = append(c.Slots, c.Slots[0]) }},
		{"duplicate slot", func(c *AcceptedIdentityCheckpoint) { c.Slots[2].Slot = c.Slots[1].Slot }},
		{"reordered slots", func(c *AcceptedIdentityCheckpoint) { c.Slots[0], c.Slots[1] = c.Slots[1], c.Slots[0] }},
		{"duplicate instance", func(c *AcceptedIdentityCheckpoint) { c.Slots[2].InstanceOCID = c.Slots[0].InstanceOCID }},
		{"duplicate vnic", func(c *AcceptedIdentityCheckpoint) { c.Slots[2].PrimaryVNICOCID = c.Slots[0].PrimaryVNICOCID }},
		{"duplicate ip", func(c *AcceptedIdentityCheckpoint) { c.Slots[2].PrimaryPrivateIP = c.Slots[0].PrimaryPrivateIP }},
		{"duplicate server", func(c *AcceptedIdentityCheckpoint) { c.Slots[2].Store.ServerName = c.Slots[0].Store.ServerName }},
		{"duplicate raft node", func(c *AcceptedIdentityCheckpoint) { c.Slots[2].Store.RaftNodeID = c.Slots[0].Store.RaftNodeID }},
		{"wrong instance region", func(c *AcceptedIdentityCheckpoint) {
			c.Slots[0].InstanceOCID = "ocid1.instance.oc1.us-sanjose-1.target"
		}},
		{"wrong image region", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].ImageOCID = "ocid1.image.oc1.us-sanjose-1.target" }},
		{"wrong vnic type", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].PrimaryVNICOCID = c.Slots[0].InstanceOCID }},
		{"public ip", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].PrimaryPrivateIP = "8.8.8.8" }},
		{"noncanonical ip", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].PrimaryPrivateIP = "010.251.0.11" }},
		{"binary digest format", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Binary.SHA256 = strings.Repeat("A", 64) }},
		{"zero binary size", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Binary.Size = 0 }},
		{"oversized binary", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Binary.Size = 1 << 30 }},
		{"unsupported arch", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Binary.Architecture = "x86_64" }},
		{"no controller config", func(c *AcceptedIdentityCheckpoint) { delete(c.Slots[0].ConfigSHA256, "controller.json") }},
		{"missing sidecar", func(c *AcceptedIdentityCheckpoint) { delete(c.Slots[0].ConfigSHA256, "oci-region.json") }},
		{"no launch baseline", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].LaunchMaterialSHA256 = nil }},
		{"missing launch pin", func(c *AcceptedIdentityCheckpoint) {
			delete(c.Slots[0].LaunchMaterialSHA256, "managed-host-image-receipt.json")
		}},
		{"unknown launch pin", func(c *AcceptedIdentityCheckpoint) {
			c.Slots[0].LaunchMaterialSHA256["identity.json"] = sha256Hex([]byte("old"))
		}},
		{"malformed launch pin", func(c *AcceptedIdentityCheckpoint) {
			c.Slots[0].LaunchMaterialSHA256["host-enrollment-public.json"] = "bad"
		}},
		{"no material baseline", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].MaterialReferences = nil }},
		{"duplicate reference", func(c *AcceptedIdentityCheckpoint) {
			c.Slots[0].MaterialReferences = append(c.Slots[0].MaterialReferences, c.Slots[0].MaterialReferences[0])
		}},
		{"mutable Vault version", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].MaterialReferences[0].VersionNumber = 0 }},
		{"foreign material slot", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].MaterialReferences[0].Slot = "controller-b" }},
		{"obsolete founder purpose", func(c *AcceptedIdentityCheckpoint) {
			c.Slots[0].MaterialReferences[0].Purpose = bootstrap.SecretSeedFounder
		}},
		{"offline signing secret", func(c *AcceptedIdentityCheckpoint) {
			c.Slots[0].MaterialReferences[0].TargetFile = "issuer-operator.seed"
		}},
		{"config traversal", func(c *AcceptedIdentityCheckpoint) {
			c.Slots[0].ConfigSHA256["../controller.json"] = strings.Repeat("a", 64)
		}},
		{"config digest", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].ConfigSHA256["controller.json"] = "bad" }},
		{"material digest", func(c *AcceptedIdentityCheckpoint) { c.MaterialGenerationSHA256 = "old-material" }},
		{"old acceptance bytes", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].PreviousAcceptanceSHA256 = `{"deploymentId":"legacy"}` }},
		{"relative store", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Store.Directory = "jetstream" }},
		{"store traversal", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Store.Directory += "/../other" }},
		{"missing store bytes", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Store.NodeIdentitySHA256 = "" }},
		{"invalid broker key", func(c *AcceptedIdentityCheckpoint) { c.Broker.Operator = "old-operator" }},
		{"duplicate account", func(c *AcceptedIdentityCheckpoint) { c.Broker.CellAccount = c.Broker.SystemAccount }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneCheckpoint(checkpoint)
			test.mutate(&changed)
			if _, err := IssueAcceptedIdentityCheckpoint(changed, now, now.Add(time.Hour), key); err == nil {
				t.Fatal("issuer accepted an invalid v1 contract")
			}
			payload, err := trust.EncodePayload(changed)
			if err != nil {
				t.Fatal(err)
			}
			wire := rawSignedCheckpoint(t, payload, checkpoint.scope(), key, now, now.Add(time.Hour))
			if _, err := VerifyAcceptedIdentityCheckpoint(wire, roots, trust.RootChain{Version: 1}, expectation(checkpoint, checkpoint.Slots[0]), now); err == nil {
				t.Fatal("verifier admitted an invalid root-signed contract")
			}
		})
	}
}

func TestCheckpointRejectsWrongAuthorityScopeAndTime(t *testing.T) {
	checkpoint, key, roots, now := checkpointFixture(t)
	envelope, wire := issueCheckpoint(t, checkpoint, key, now)
	expected := expectation(checkpoint, checkpoint.Slots[0])
	_, otherKey, otherRoots, _ := checkpointFixture(t)
	if _, err := VerifyAcceptedIdentityCheckpoint(wire, otherRoots, trust.RootChain{Version: 1}, expected, now); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("wrong root: %v", err)
	}
	for _, test := range []struct {
		name string
		now  time.Time
		want error
	}{
		{"not yet valid", now.Add(-time.Nanosecond), trust.ErrNotYetValid},
		{"expires at boundary", envelope.ExpiresAt, trust.ErrExpired},
		{"expired", envelope.ExpiresAt.Add(time.Hour), trust.ErrExpired},
		{"zero clock", time.Time{}, trust.ErrInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyAcceptedIdentityCheckpoint(wire, roots, trust.RootChain{Version: 1}, expected, test.now); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	for _, mutate := range []func(*trust.Scope){
		func(s *trust.Scope) { s.Domain = "terrascale.bootstrap.install-continuity" },
		func(s *trust.Scope) { s.Role = "root" },
		func(s *trust.Scope) { s.Slot = "controller-a" },
	} {
		scope := checkpoint.scope()
		mutate(&scope)
		wrong := rawSignedCheckpoint(t, envelope.Payload, scope, key, now, now.Add(time.Hour))
		if _, err := VerifyAcceptedIdentityCheckpoint(wrong, roots, trust.RootChain{Version: 1}, expected, now); !errors.Is(err, trust.ErrScopeMismatch) {
			t.Fatalf("wrong scope: %v", err)
		}
	}
	for _, expiry := range []time.Time{now, now.Add(-time.Hour), now.Add(MaxCheckpointLifetime + time.Nanosecond)} {
		if _, err := IssueAcceptedIdentityCheckpoint(checkpoint, now, expiry, key); err == nil {
			t.Fatal("issuer accepted invalid/excessive validity")
		}
	}
	long := rawSignedCheckpoint(t, envelope.Payload, checkpoint.scope(), key, now, now.Add(MaxCheckpointLifetime+time.Nanosecond))
	if _, err := VerifyAcceptedIdentityCheckpoint(long, roots, trust.RootChain{Version: 1}, expected, now); err == nil {
		t.Fatal("verifier accepted excessive validity")
	}
	// Retired roots remain valid historical evidence but cannot sign checkpoints.
	id := trust.ChainIdentity{DeploymentID: checkpoint.DeploymentID, Cell: strings.ToLower(checkpoint.Cell), Environment: checkpoint.Environment}
	verifiedRoots, err := trust.VerifyRootChain(roots, id, trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := trust.NextRotation(verifiedRoots, otherKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	var signed trust.SignedRotation
	for _, signer := range []ed25519.PrivateKey{key, otherKey} {
		signature, err := trust.SignRotation(rotation, id, now, now.Add(time.Hour), signer)
		if err != nil {
			t.Fatal(err)
		}
		signed.Signatures = append(signed.Signatures, signature)
	}
	chain := trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{signed}}
	if _, err := VerifyAcceptedIdentityCheckpoint(wire, roots, chain, expected, now); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("retired root admitted: %v", err)
	}
	_, newWire := issueCheckpoint(t, checkpoint, otherKey, now)
	if _, err := VerifyAcceptedIdentityCheckpoint(newWire, roots, chain, expected, now); err != nil {
		t.Fatalf("current rotated root denied: %v", err)
	}
	wrongChainID := id
	wrongChainID.DeploymentID = entityid.Derive("other-chain")
	wrongSignature, err := trust.SignRotation(rotation, wrongChainID, now, now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	chain.Rotations[0].Signatures[0] = wrongSignature
	if _, err := VerifyAcceptedIdentityCheckpoint(newWire, roots, chain, expected, now); err == nil {
		t.Fatal("wrong deployment root chain admitted")
	}
}

func TestCheckpointStrictWireAndPayload(t *testing.T) {
	checkpoint, key, roots, now := checkpointFixture(t)
	envelope, wire := issueCheckpoint(t, checkpoint, key, now)
	expected := expectation(checkpoint, checkpoint.Slots[0])
	for name, wrong := range map[string][]byte{
		"empty":                     nil,
		"oversized":                 bytes.Repeat([]byte("x"), MaxCheckpointWireBytes+1),
		"leading whitespace":        append([]byte(" "), wire...),
		"unknown envelope member":   bytes.Replace(wire, []byte(`{"schemaVersion":`), []byte(`{"unknown":true,"schemaVersion":`), 1),
		"duplicate envelope member": bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1),
		"envelope v2":               bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":2`), 1),
		"tampered signature":        bytes.Replace(wire, []byte(checkpoint.ClusterID), []byte(entityid.Derive("tampered")), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyAcceptedIdentityCheckpoint(wrong, roots, trust.RootChain{Version: 1}, expected, now); err == nil {
				t.Fatal("accepted invalid envelope wire")
			}
		})
	}
	for name, payload := range map[string][]byte{
		"unknown member":       bytes.Replace(envelope.Payload, []byte(`{"schemaVersion":`), []byte(`{"oldDeploymentId":"legacy","schemaVersion":`), 1),
		"unknown slot member":  bytes.Replace(envelope.Payload, []byte(`"instanceOcid":`), []byte(`"launchHistory":{},"instanceOcid":`), 1),
		"unknown store member": bytes.Replace(envelope.Payload, []byte(`"directory":`), []byte(`"rebuild":true,"directory":`), 1),
		"reordered members":    nil,
		"oversized payload":    []byte(fmt.Sprintf(`{"padding":"%s"}`, strings.Repeat("x", MaxCheckpointBytes))),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "reordered members" {
				var object map[string]any
				if err := json.Unmarshal(envelope.Payload, &object); err != nil {
					t.Fatal(err)
				}
				var err error
				payload, err = json.Marshal(object, json.Deterministic(true))
				if err != nil || bytes.Equal(payload, envelope.Payload) {
					t.Fatal("test did not construct a distinct payload representation")
				}
			}
			wrong := rawSignedCheckpoint(t, payload, checkpoint.scope(), key, now, now.Add(time.Hour))
			if _, err := VerifyAcceptedIdentityCheckpoint(wrong, roots, trust.RootChain{Version: 1}, expected, now); err == nil {
				t.Fatal("accepted an unknown member or alternate payload representation")
			}
		})
	}
}

func TestSlotAcceptanceDigestIsAcyclicAndBindsIdentity(t *testing.T) {
	checkpoint, key, _, now := checkpointFixture(t)
	base, err := checkpoint.AcceptanceSHA256("controller-a")
	if err != nil {
		t.Fatal(err)
	}
	changed := cloneCheckpoint(checkpoint)
	changed.MaterialGenerationSHA256 = ""
	for i := range changed.Slots {
		changed.Slots[i].ConfigSHA256 = nil
		changed.Slots[i].LaunchMaterialSHA256 = nil
		changed.Slots[i].PreviousAcceptanceSHA256 = ""
		changed.Slots[i].MaterialReferences = nil
	}
	if got, err := changed.AcceptanceSHA256("controller-a"); err != nil || got != base {
		t.Fatalf("acceptance requires or binds the excluded fields: %s, %v", got, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*AcceptedIdentityCheckpoint)
	}{
		{"operation", func(c *AcceptedIdentityCheckpoint) { c.OperationID = entityid.Derive("other-op") }},
		{"deployment", func(c *AcceptedIdentityCheckpoint) { c.DeploymentID = entityid.Derive("other-deployment") }},
		{"cluster", func(c *AcceptedIdentityCheckpoint) { c.ClusterID = entityid.Derive("other-cluster") }},
		{"environment", func(c *AcceptedIdentityCheckpoint) { c.Environment = "production" }},
		{"seed slot", func(c *AcceptedIdentityCheckpoint) { c.SeedSlot = "controller-b" }},
		{"cell", func(c *AcceptedIdentityCheckpoint) {
			c.Cell = "SJC"
			for i := range c.Slots {
				c.Slots[i].InstanceOCID = strings.ReplaceAll(c.Slots[i].InstanceOCID, "sa-saopaulo-1", "us-sanjose-1")
				c.Slots[i].ImageOCID = strings.ReplaceAll(c.Slots[i].ImageOCID, "sa-saopaulo-1", "us-sanjose-1")
				c.Slots[i].PrimaryVNICOCID = strings.ReplaceAll(c.Slots[i].PrimaryVNICOCID, "sa-saopaulo-1", "us-sanjose-1")
			}
		}},
		{"instance", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].InstanceOCID += "other" }},
		{"image", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].ImageOCID += "other" }},
		{"vnic", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].PrimaryVNICOCID += "other" }},
		{"ip", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].PrimaryPrivateIP = "10.251.0.99" }},
		{"binary digest", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Binary.SHA256 = sha256Hex([]byte("other")) }},
		{"binary size", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Binary.Size++ }},
		{"binary arch", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Binary.Architecture = "arm64" }},
		{"broker", func(c *AcceptedIdentityCheckpoint) { c.Broker.CellAccount = publicKey(t, false) }},
		{"store directory", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Store.Directory += "-other" }},
		{"store server", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Store.ServerName += "-other" }},
		{"store node", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Store.RaftNodeID = "OTHER001" }},
		{"store server bytes", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Store.ServerNameSHA256 = sha256Hex([]byte("other")) }},
		{"store node bytes", func(c *AcceptedIdentityCheckpoint) { c.Slots[0].Store.NodeIdentitySHA256 = sha256Hex([]byte("other")) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneCheckpoint(checkpoint)
			test.mutate(&changed)
			got, err := changed.AcceptanceSHA256("controller-a")
			if err != nil || got == base {
				t.Fatalf("acceptance did not bind %s: %s, %v", test.name, got, err)
			}
		})
	}
	if other, err := checkpoint.AcceptanceSHA256("controller-b"); err != nil || other == base {
		t.Fatal("acceptance digest does not distinguish slots")
	}
	if _, err := checkpoint.AcceptanceSHA256("controller-d"); err == nil {
		t.Fatal("unknown slot has an acceptance digest")
	}
	changed = cloneCheckpoint(checkpoint)
	changed.Slots[1].Binary.Size++
	if other, err := changed.AcceptanceSHA256("controller-a"); err != nil || other != base {
		t.Fatal("another slot changed this slot's acceptance identity")
	}
	_, oldWire := issueCheckpoint(t, checkpoint, key, now)
	changed = cloneCheckpoint(checkpoint)
	changed.MaterialGenerationSHA256 = sha256Hex([]byte("fresh signed generation"))
	changed.Slots[0].ConfigSHA256["controller.json"] = sha256Hex([]byte("new controller config"))
	_, newWire := issueCheckpoint(t, changed, key, now)
	if other, err := changed.AcceptanceSHA256("controller-a"); err != nil || other != base || bytes.Equal(oldWire, newWire) {
		t.Fatal("acyclic exclusions are not covered by the complete signed checkpoint")
	}
}

func TestSlotAcceptanceWireVector(t *testing.T) {
	checkpoint, _, _, _ := checkpointFixture(t)
	keys := []*string{&checkpoint.Broker.Operator, &checkpoint.Broker.SystemAccount, &checkpoint.Broker.CellAccount,
		&checkpoint.Broker.HostSigner, &checkpoint.Broker.AccountSigner, &checkpoint.Broker.RoleSigner,
		&checkpoint.Broker.InterRegionAccount}
	for i, target := range keys {
		prefix := nkeys.PrefixByteAccount
		if i == 0 {
			prefix = nkeys.PrefixByteOperator
		}
		key, err := nkeys.FromRawSeed(prefix, bytes.Repeat([]byte{byte(i + 1)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		*target, err = key.PublicKey()
		key.Wipe()
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := checkpoint.AcceptanceSHA256("controller-a")
	if err != nil {
		t.Fatal(err)
	}
	const want = "b18704a6ac8f6e0384044fc78d8bcff26a7ff7c6f542d034bef58b9ec761f779"
	if got != want {
		t.Fatalf("v1 acceptance serialization changed: got %s, want %s", got, want)
	}
}

func checkpointFixture(t *testing.T) (AcceptedIdentityCheckpoint, ed25519.PrivateKey, trust.Keyring, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := AcceptedIdentityCheckpoint{SchemaVersion: 1, OperationID: entityid.Derive("rekey-operation"),
		DeploymentID: entityid.Derive("new-deployment"), ClusterID: entityid.Derive("new-cluster"), Environment: "canary", Cell: "GRU",
		SeedSlot:                 "controller-a",
		MaterialGenerationSHA256: sha256Hex([]byte("signed generation")), Broker: BrokerIdentity{
			Operator: publicKey(t, true), SystemAccount: publicKey(t, false), CellAccount: publicKey(t, false),
			HostSigner: publicKey(t, false), AccountSigner: publicKey(t, false), RoleSigner: publicKey(t, false),
			InterRegionAccount: publicKey(t, false)}}
	for i := range 3 {
		checkpoint.Slots = append(checkpoint.Slots, SlotBinding{Slot: "controller-" + string(rune('a'+i)),
			PreviousAcceptanceSHA256: sha256Hex([]byte(fmt.Sprintf("opaque legacy acceptance %d", i))),
			PreviousMaterialSHA256:   map[string]string{"installed": sha256Hex([]byte("old material chain")), "durable": sha256Hex([]byte("old material chain"))},
			InstanceOCID:             fmt.Sprintf("ocid1.instance.oc1.sa-saopaulo-1.existing%d", i),
			ImageOCID:                "ocid1.image.oc1.sa-saopaulo-1.observed-existing-image",
			PrimaryVNICOCID:          fmt.Sprintf("ocid1.vnic.oc1.sa-saopaulo-1.existing%d", i),
			PrimaryPrivateIP:         fmt.Sprintf("10.251.0.%d", 11+i),
			Binary:                   BinaryPin{SHA256: sha256Hex([]byte("approved executable")), Size: 4096, Architecture: "amd64"},
			ConfigSHA256: map[string]string{"controller.json": sha256Hex([]byte(fmt.Sprintf("installed config %d", i))),
				"placement.json":         sha256Hex([]byte("installed placement")),
				"oci-region.json":        sha256Hex([]byte("installed region")),
				"oci-region-intent.json": sha256Hex([]byte("installed intent"))},
			LaunchMaterialSHA256: map[string]string{"host-enrollment-public.json": sha256Hex([]byte("enrollment")), "operator-ssh-key.pub": sha256Hex([]byte("ssh")),
				"managed-host-image-receipt.json": sha256Hex([]byte("image receipt")), "managed-host-image-delegation.json": sha256Hex([]byte("image delegation"))},
			MaterialReferences: []bootstrap.SecretReference{{Purpose: bootstrap.SecretController,
				Slot: "controller-" + string(rune('a'+i)), TargetFile: "controller-" + string(rune('a'+i)) + ".creds",
				SecretOCID: fmt.Sprintf("ocid1.vaultsecret.oc1.sa-saopaulo-1.material%d", i), VersionNumber: 1,
				SHA256: sha256Hex([]byte(fmt.Sprintf("installed credential %d", i))), MaxBytes: 16 << 10}},
			Store: StoreIdentity{Directory: "/var/lib/terrascale-orchestrator", ServerName: fmt.Sprintf("gru-1-ctl-%d", i+1),
				RaftNodeID: fmt.Sprintf("NODE000%d", i), ServerNameSHA256: sha256Hex([]byte(fmt.Sprintf("gru-1-ctl-%d\n", i+1))),
				NodeIdentitySHA256: sha256Hex([]byte(fmt.Sprintf("existing node identity %d", i)))}})
	}
	return checkpoint, key, roots, now
}

func publicKey(t *testing.T, operator bool) string {
	t.Helper()
	var key nkeys.KeyPair
	var err error
	if operator {
		key, err = nkeys.CreateOperator()
	} else {
		key, err = nkeys.CreateAccount()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func expectation(checkpoint AcceptedIdentityCheckpoint, slot SlotBinding) CheckpointExpectation {
	slot.ConfigSHA256 = maps.Clone(slot.ConfigSHA256)
	slot.LaunchMaterialSHA256 = maps.Clone(slot.LaunchMaterialSHA256)
	slot.MaterialReferences = slices.Clone(slot.MaterialReferences)
	return CheckpointExpectation{OperationID: checkpoint.OperationID, DeploymentID: checkpoint.DeploymentID,
		ClusterID: checkpoint.ClusterID, Environment: checkpoint.Environment, Cell: checkpoint.Cell,
		SeedSlot: checkpoint.SeedSlot, ManagedMaterial: checkpoint.ManagedMaterial,
		MaterialGenerationSHA256: checkpoint.MaterialGenerationSHA256, Broker: checkpoint.Broker, Slot: slot}
}

func cloneCheckpoint(checkpoint AcceptedIdentityCheckpoint) AcceptedIdentityCheckpoint {
	checkpoint.Slots = slices.Clone(checkpoint.Slots)
	for i := range checkpoint.Slots {
		checkpoint.Slots[i].ConfigSHA256 = maps.Clone(checkpoint.Slots[i].ConfigSHA256)
		checkpoint.Slots[i].LaunchMaterialSHA256 = maps.Clone(checkpoint.Slots[i].LaunchMaterialSHA256)
		checkpoint.Slots[i].MaterialReferences = slices.Clone(checkpoint.Slots[i].MaterialReferences)
	}
	return checkpoint
}

func issueCheckpoint(t *testing.T, checkpoint AcceptedIdentityCheckpoint, key ed25519.PrivateKey, now time.Time) (trust.Envelope, []byte) {
	t.Helper()
	envelope, err := IssueAcceptedIdentityCheckpoint(checkpoint, now, now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return envelope, wire
}

func rawSignedCheckpoint(t *testing.T, payload []byte, scope trust.Scope, key ed25519.PrivateKey, now, expiry time.Time) []byte {
	t.Helper()
	envelope, err := trust.Sign(payload, scope, now, expiry, key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
