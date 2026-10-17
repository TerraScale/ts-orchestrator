package swarmruntime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nkeys"
)

// This covers actual upstream manager/Raft/native key custody and domain
// verification. The controlled callback does not mint APP process authority.
func TestManagerRuntimeNativeSigningIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native manager signing requires an actual root test process")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cfg := nodeFixtureConfig(t, "founder", "manager")
	cfg.Admission.Region, cfg.Admission.InstanceID = "sa-saopaulo-1", "ocid1.instance.oc1.sa-saopaulo-1.manager"
	node := nodeFixtureStart(t, ctx, cfg)
	control, err := node.ReadOnlyControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := control.ClusterIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	current, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()})
	if err != nil || current == nil || current.Node == nil {
		t.Fatalf("actual native manager unavailable: %v", err)
	}
	certificate := current.Node.Certificate.Certificate
	block, _ := pem.Decode(certificate)
	if block == nil {
		t.Fatal("actual native manager certificate unavailable")
	}
	digest := sha256.Sum256(block.Bytes)
	clusterDigest := sha256.Sum256(cluster.RootCACert)
	executable, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	binaryDigest := sha256.Sum256(executable)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	userPublic, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	requested := host.ManagerRuntimeBinding{Version: 1, DeploymentID: entityid.New(), ClusterID: entityid.New(), SwarmClusterID: cluster.ID,
		Environment: "production", Cell: "gru", OCIRegion: cfg.Admission.Region, NodeID: node.ID(), InstanceID: cfg.Admission.InstanceID,
		HostID: entityid.Derive("host", "gru", "manager"), HostNode: "manager", HostSessionID: entityid.New(), HostSessionEpoch: 1,
		RegistrationGeneration: 1, RegistrationRevision: 1, SourceRevision: 1, HostPublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: userPublic,
		RuntimeCandidateID: entityid.New(), BinarySHA256: hex.EncodeToString(binaryDigest[:]), AcceptanceSHA256: strings.Repeat("1", 64), AnchorSHA256: strings.Repeat("2", 64), SourceSHA256: strings.Repeat("3", 64),
		CertificateSHA256: hex.EncodeToString(digest[:]), ClusterCASHA256: hex.EncodeToString(clusterDigest[:]), IssuedAt: now, ExpiresAt: now.Add(5 * time.Second)}
	guardCalls := 0
	guard := func(check context.Context) error {
		guardCalls++
		actual, err := control.GetNode(check, &api.GetNodeRequest{NodeID: node.ID()})
		if err != nil || actual == nil || actual.Node == nil || !bytes.Equal(actual.Node.Certificate.Certificate, certificate) {
			return errors.New("original native certificate changed")
		}
		return check.Err()
	}
	signed, err := node.SignManagerRuntimeBinding(ctx, requested, guard)
	if err != nil || signed.Binding != requested || guardCalls != 3 {
		t.Fatalf("native signer changed payload or omitted admission: calls=%d err=%v", guardCalls, err)
	}
	if err := host.VerifySignedManagerRuntimeBinding(signed, certificate, cluster.RootCACert, cluster.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	changed := signed
	changed.Binding.RuntimeCandidateID = entityid.New()
	if host.VerifySignedManagerRuntimeBinding(changed, certificate, cluster.RootCACert, cluster.ID, time.Now()) == nil {
		t.Fatal("native signature accepted a different process candidate")
	}
	changed = signed
	changed.Binding.BinarySHA256 = strings.Repeat("0", 64)
	if host.VerifySignedManagerRuntimeBinding(changed, certificate, cluster.RootCACert, cluster.ID, time.Now()) == nil {
		t.Fatal("native signature accepted a different executable measurement")
	}
	for _, rejectAt := range []int{2, 3} {
		calls := 0
		rejected, err := node.SignManagerRuntimeBinding(ctx, requested, func(check context.Context) error {
			calls++
			if calls == rejectAt {
				return context.Canceled
			}
			return guard(check)
		})
		if err == nil || len(rejected.Signature) != 0 || calls != rejectAt {
			t.Fatalf("revocation at callback %d delivered a signature: calls=%d err=%v", rejectAt, calls, err)
		}
	}
	// These negatives extend the real native producer above; they do not claim
	// historical never-exposed custody or create an admitted APP caller/session.
	keyPath := filepath.Join(node.stateDir, "certificates", "swarm-node.key")
	t.Run("native identity is consumed and closed deterministically", func(t *testing.T) {
		key, _, err := node.nodeSigningKey()
		if err != nil {
			t.Fatal(err)
		}
		defer key.Close()
		signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil || len(signature) == 0 {
			t.Fatalf("actual native identity could not sign: %v", err)
		}
		if len(key.custody.files) != 0 || len(key.custody.directories) != 0 {
			t.Fatal("successful native signing retained file descriptors")
		}
		if signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil || len(signature) != 0 {
			t.Fatal("consumed native identity signed twice")
		}
		closed, _, err := node.nodeSigningKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := closed.Close(); err != nil {
			t.Fatal(err)
		}
		if err := closed.Close(); err != nil {
			t.Fatalf("native identity close is not idempotent: %v", err)
		}
		if signature, err := closed.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil || len(signature) != 0 {
			t.Fatal("closed native identity signed")
		}
	})
	t.Run("key ownership and permissions are required at load and use", func(t *testing.T) {
		for _, drift := range []struct {
			name    string
			change  func() error
			restore func() error
		}{
			{"permissions", func() error { return os.Chmod(keyPath, 0o644) }, func() error { return os.Chmod(keyPath, 0o600) }},
			{"owner", func() error { return os.Chown(keyPath, 65534, 65534) }, func() error { return os.Chown(keyPath, 0, 0) }},
		} {
			t.Run(drift.name, func(t *testing.T) {
				key, _, err := node.nodeSigningKey()
				if err != nil {
					t.Fatal(err)
				}
				defer key.Close()
				if err := drift.change(); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := drift.restore(); err != nil {
						t.Fatal(err)
					}
				}()
				if signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil || len(signature) != 0 {
					t.Fatal("changed native key custody delivered a signature")
				}
				if len(key.custody.files) != 0 || len(key.custody.directories) != 0 {
					t.Fatal("refused native signing retained file descriptors")
				}
				if loaded, _, err := node.nodeSigningKey(); err == nil {
					_ = loaded.Close()
					t.Fatal("unsafe native identity was loaded")
				}
			})
		}
	})
	t.Run("same bytes in a replacement inode do not preserve custody", func(t *testing.T) {
		key, _, err := node.nodeSigningKey()
		if err != nil {
			t.Fatal(err)
		}
		defer key.Close()
		wire, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wire)
		backup := keyPath + ".native-custody-test"
		if err := os.Rename(keyPath, backup); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Rename(backup, keyPath); err != nil {
				t.Fatal(err)
			}
		}()
		if err := os.WriteFile(keyPath, wire, 0o600); err != nil {
			t.Fatal(err)
		}
		if signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil || len(signature) != 0 {
			t.Fatal("replacement native key inode delivered a signature")
		}
	})
	t.Run("certificate directory permits public reads but rejects unsafe writes", func(t *testing.T) {
		directory := filepath.Dir(keyPath)
		original, err := os.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chmod(directory, original.Mode().Perm()); err != nil {
				t.Fatal(err)
			}
		}()
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		key, _, err := node.nodeSigningKey()
		if err != nil {
			t.Fatalf("safe root-owned public certificate directory rejected: %v", err)
		}
		defer key.Close()
		if err := os.Chmod(directory, 0o777); err != nil {
			t.Fatal(err)
		}
		if signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil || len(signature) != 0 {
			t.Fatal("unsafe native certificate directory delivered a signature")
		}
		if loaded, _, err := node.nodeSigningKey(); err == nil {
			_ = loaded.Close()
			t.Fatal("unsafe native certificate directory was loaded")
		}
	})
	t.Run("symlinked key and state path are refused", func(t *testing.T) {
		alias := filepath.Join(t.TempDir(), "node")
		if err := os.Symlink(node.stateDir, alias); err != nil {
			t.Fatal(err)
		}
		if custody, _, err := openNodeKeyCustody(alias); err == nil {
			_ = custody.close()
			t.Fatal("symlinked native state directory was accepted")
		}
		backup := keyPath + ".native-custody-test"
		if err := os.Rename(keyPath, backup); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Rename(backup, keyPath); err != nil {
				t.Fatal(err)
			}
		}()
		if err := os.Symlink(backup, keyPath); err != nil {
			t.Fatal(err)
		}
		if key, _, err := node.nodeSigningKey(); err == nil {
			_ = key.Close()
			t.Fatal("symlinked native private key was accepted")
		}
	})
	t.Run("stage requires genuine admitted caller and opaque ownhost", func(t *testing.T) {
		stage := managedmaterial.MaterialStage{}
		if signed, err := node.SignManagedMaterialStage(ctx, rootoci.Call{}, nil, nil, stage, guard); err == nil || len(signed.Signature) != 0 {
			t.Fatal("zero caller or ownhost delivered a native stage signature")
		}
		rootCall, err := rootoci.RootCall(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := rootCall.AuthorityBindingSHA256(ctx); err == nil {
			t.Fatal("synthetic bootstrap RootCall established an admitted stage caller")
		}
	})
	t.Run("stage structure has fixed bounds and separate semantic expiry", func(t *testing.T) {
		// This checks only the DTO boundary, using the real native public pins.
		// Placeholder source bodies cannot establish domain or caller authority.
		now := time.Now().UTC()
		semanticExpiry := now.Add(time.Minute)
		useExpiry := now.Add(5 * time.Second)
		nativeCertificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		database, partition := entityid.New(), entityid.New()
		spec := managedmaterial.InitialSpec{PlacementDatabaseID: database, PartitionID: partition}
		specWire, err := protocol.EncodeJSON(spec)
		if err != nil {
			t.Fatal(err)
		}
		operation := entityid.Derive("material-g1", string(specWire))
		stage := managedmaterial.MaterialStage{Version: 1, Action: managedmaterial.MaterialStagePreparation,
			Cell: "gru", DatabaseID: database, PartitionID: partition, OperationID: operation, RuntimeID: entityid.New(), Epoch: 1,
			AdmittedAt: now, OperationExpiresAt: semanticExpiry, GrantExpiresAt: semanticExpiry, SemanticSourceExpiresAt: semanticExpiry,
			CredentialExpiresAt: useExpiry, LeaseExpiresAt: useExpiry, OriginalContextExpiresAt: useExpiry, OriginalCallerExpiresAt: useExpiry,
			NativeCertificateExpiresAt: nativeCertificate.NotAfter, ExpiresAt: semanticExpiry, CallerAuthoritySHA256: strings.Repeat("1", 64),
			Native: managedmaterial.MaterialStageNative{NodeID: node.ID(), InstanceID: cfg.Admission.InstanceID, OCIRegion: cfg.Admission.Region,
				SwarmClusterID: cluster.ID, ClusterCASHA256: requested.ClusterCASHA256, CertificateSHA256: requested.CertificateSHA256},
			Evidence: managedmaterial.MaterialStageEvidence{Operator: &protocol.Envelope{OperationID: operation, Epoch: 1,
				Region: "gru", ExpiresAt: semanticExpiry, Payload: specWire}},
			Preparation: &managedmaterial.PreparationReceipt{Cell: "gru", PartitionID: partition, Spec: spec}}
		for _, name := range []managedmaterial.MaterialStageSourceName{
			managedmaterial.MaterialStageAcceptedIdentity, managedmaterial.MaterialStageControllerConfig, managedmaterial.MaterialStageControllerGeneration,
			managedmaterial.MaterialStageMaterialKeyReference, managedmaterial.MaterialStageRootHead, managedmaterial.MaterialStageServiceSpec,
			managedmaterial.MaterialStageOperatorPolicy, managedmaterial.MaterialStageLease, managedmaterial.MaterialStageOwnhost,
			managedmaterial.MaterialStageNativeManager, managedmaterial.MaterialStageNativeCluster, managedmaterial.MaterialStageMaterialDomain,
		} {
			stage.Sources = append(stage.Sources, managedmaterial.MaterialStageSource{Name: name, Payload: []byte("{}")})
		}
		slices.SortFunc(stage.Sources, func(a, b managedmaterial.MaterialStageSource) int {
			return strings.Compare(string(a.Name), string(b.Name))
		})
		wire, err := managedmaterial.MaterialStageSigningBytes(stage)
		if err != nil || !bytes.HasPrefix(wire, []byte("TS-MANAGED-MATERIAL-STAGE-V1\x00")) {
			t.Fatalf("finite stage structure or fixed domain rejected: %v", err)
		}
		changed := stage
		changed.ExpiresAt = useExpiry
		if _, err := managedmaterial.MaterialStageSigningBytes(changed); err == nil {
			t.Fatal("attempt transport expiry replaced the exact semantic ceiling")
		}
		changed = stage
		changed.Action = "arbitrary_sign"
		if _, err := managedmaterial.MaterialStageSigningBytes(changed); err == nil {
			t.Fatal("stage accepted an arbitrary signing action")
		}
		changed = stage
		changed.Sources = slices.Clone(stage.Sources)
		changed.Sources[0].Payload = bytes.Repeat([]byte("x"), (128<<10)+1)
		if _, err := managedmaterial.MaterialStageSigningBytes(changed); err == nil {
			t.Fatal("stage accepted an oversized source")
		}
		changed = stage
		changed.Sources = slices.Clone(stage.Sources)
		changed.Sources[1].Name = changed.Sources[0].Name
		if _, err := managedmaterial.MaterialStageSigningBytes(changed); err == nil {
			t.Fatal("stage accepted duplicate source names")
		}
		changed = stage
		changed.Preparation = new(*stage.Preparation)
		changed.Preparation.Signature = strings.Repeat("x", 256<<10)
		if _, err := managedmaterial.MaterialStageSigningBytes(changed); err == nil {
			t.Fatal("stage accepted an oversized candidate")
		}
		oversized := managedmaterial.SignedMaterialStage{Stage: stage, Signature: bytes.Repeat([]byte("x"), managedmaterial.MaxSignedMaterialStageBytes)}
		if managedmaterial.VerifySignedMaterialStage(oversized, certificate, cluster.RootCACert, cluster.ID, now) == nil {
			t.Fatal("native stage verifier accepted an oversized signed record")
		}
	})
}
