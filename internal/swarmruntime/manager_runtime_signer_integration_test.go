package swarmruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
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
		RuntimeCandidateID: entityid.New(), AcceptanceSHA256: strings.Repeat("1", 64), AnchorSHA256: strings.Repeat("2", 64), SourceSHA256: strings.Repeat("3", 64),
		CertificateSHA256: hex.EncodeToString(digest[:]), IssuedAt: now, ExpiresAt: now.Add(5 * time.Second)}
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
}
